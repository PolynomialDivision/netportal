//! The two legs. Each has one UDP socket bound to 0.0.0.0:5353 with `SO_REUSEADDR`, tied to its
//! interface with `SO_BINDTODEVICE`, member of 224.0.0.251 there: it sends (the source port 5353
//! is mandatory, receivers ignore other source ports, RFC 6762 §6) and keeps the group joined
//! (the switch's IGMP snooping forwards the group to us). Receiving goes through an `AF_PACKET`
//! socket (`SOCK_RAW`, protocol `ETH_P_IP`, CAP_NET_RAW): every datagram comes as the whole
//! Ethernet frame, so the sender's MAC is in it. The socket is not bound to the interface (that
//! needs a `sockaddr_ll`, which safe Rust cannot build); a classic BPF filter on the socket
//! selects the interface by index (`ld #ifidx`) and IPv4/UDP to port 5353 in the kernel, so
//! nothing else is copied to the process.
//!
//! Without CAP_NET_RAW the leg falls back to receiving on the UDP socket and looks the sender's
//! MAC up in the neighbour table (`/proc/net/arp`), which knows a sender only after unicast
//! traffic with it: good enough for `--probe`, not for the service. The tests use the UDP path
//! on loopback with a fixed MAC.

use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::time::Duration;

use socket2::{Domain, InterfaceIndexOrAddress, Protocol, SockFilter, Socket, Type};
use tokio::net::UdpSocket;

use crate::LOG;
use crate::frame::{Frame, MDNS_GROUP, MDNS_PORT, Mac, parse_ethernet};
use crate::proxy::{Outgoing, Target};

/// The receive buffer: mDNS messages are at most 9000 bytes (RFC 6762 §17), a frame a little more.
pub const MAX_DATAGRAM: usize = 16 * 1024;
/// A short pause after a receive error, so a broken socket never spins the loop.
pub const RECV_ERROR_PAUSE: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegKind {
    Residents,
    Iot,
}

impl LegKind {
    pub fn name(self) -> &'static str {
        match self {
            LegKind::Residents => "residents",
            LegKind::Iot => "iot",
        }
    }
}

enum Receiver {
    /// the whole Ethernet frame per datagram
    Packet(UdpSocket),
    /// the UDP socket itself; the MAC is fixed (tests) or from the neighbour table
    Udp { mac: Option<Mac> },
}

pub struct Leg {
    pub kind: LegKind,
    pub iface: String,
    pub ifindex: u32,
    /// the interface's IPv4 address, when it has one
    pub addr: Option<Ipv4Addr>,
    udp: Arc<UdpSocket>,
    receiver: Receiver,
    /// where "multicast" goes: the group, or a test's sink
    multicast_to: SocketAddrV4,
}

impl Leg {
    /// Opens a leg on an interface.
    pub fn open(kind: LegKind, iface: &str) -> io::Result<Leg> {
        let ifindex = ifindex(iface)?;
        let addr = interface_address(iface).ok();
        let udp = open_udp(iface, ifindex)?;
        let receiver = match open_packet(ifindex) {
            Ok(socket) => Receiver::Packet(socket),
            Err(e) => {
                tracing::warn!(
                    target: LOG,
                    "{iface}: no AF_PACKET socket ({e}; CAP_NET_RAW missing?): receiving on UDP, senders' MACs from the neighbour table"
                );
                Receiver::Udp { mac: None }
            }
        };
        Ok(Leg {
            kind,
            iface: iface.to_string(),
            ifindex,
            addr,
            udp: Arc::new(udp),
            receiver,
            multicast_to: SocketAddrV4::new(MDNS_GROUP, MDNS_PORT),
        })
    }

    /// A leg on a plain UDP socket (tests): every datagram is labelled with `mac`, "multicast"
    /// goes to `multicast_to`.
    pub fn from_udp(kind: LegKind, socket: StdUdpSocket, mac: Mac, multicast_to: SocketAddrV4) -> io::Result<Leg> {
        socket.set_nonblocking(true)?;
        let addr = match socket.local_addr()? {
            SocketAddr::V4(a) => Some(*a.ip()),
            SocketAddr::V6(_) => None,
        };
        Ok(Leg {
            kind,
            iface: "udp".to_string(),
            ifindex: 0,
            addr,
            udp: Arc::new(UdpSocket::from_std(socket)?),
            receiver: Receiver::Udp { mac: Some(mac) },
            multicast_to,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }

    /// For the start-up log.
    pub fn describe(&self) -> String {
        let addr = self.addr.map_or("no address".to_string(), |a| a.to_string());
        let how = match self.receiver {
            Receiver::Packet(_) => "AF_PACKET",
            Receiver::Udp { .. } => "UDP fallback",
        };
        format!("{} ({}, index {}, {addr}, {how})", self.iface, self.kind.name(), self.ifindex)
    }

    /// The next datagram to port 5353 (`None`: a frame that was something else).
    pub async fn recv<'a>(&self, buf: &'a mut [u8]) -> io::Result<Option<Frame<'a>>> {
        match &self.receiver {
            Receiver::Packet(socket) => {
                let n = socket.recv(buf).await?;
                let data: &'a [u8] = &buf[..n];
                Ok(parse_ethernet(data).filter(|f| f.dst.port() == MDNS_PORT))
            }
            Receiver::Udp { mac } => {
                let (n, from) = self.udp.recv_from(buf).await?;
                let SocketAddr::V4(src) = from else { return Ok(None) };
                let src_mac = match mac {
                    Some(mac) => *mac,
                    None => neighbour_mac(*src.ip(), &self.iface).unwrap_or(Mac::ZERO),
                };
                let data: &'a [u8] = &buf[..n];
                let dst = SocketAddrV4::new(self.addr.unwrap_or(Ipv4Addr::UNSPECIFIED), MDNS_PORT);
                Ok(Some(Frame { src_mac, src, dst, payload: data }))
            }
        }
    }

    fn resolve(&self, target: Target) -> SocketAddrV4 {
        match target {
            Target::Unicast(to) => to,
            Target::Multicast => self.multicast_to,
        }
    }

    /// Sends a datagram from port 5353; a delayed one from a task of its own.
    pub async fn send(&self, outgoing: Outgoing) -> io::Result<()> {
        let to = self.resolve(outgoing.target);
        if outgoing.delay.is_zero() {
            self.udp.send_to(&outgoing.payload, to).await?;
            return Ok(());
        }
        let udp = self.udp.clone();
        tokio::spawn(async move {
            tokio::time::sleep(outgoing.delay).await;
            if let Err(e) = udp.send_to(&outgoing.payload, to).await {
                tracing::warn!(target: LOG, "multicast answer not sent: {e}");
            }
        });
        Ok(())
    }

    /// A query to the group (the browser).
    pub async fn send_multicast(&self, payload: &[u8]) -> io::Result<()> {
        self.udp.send_to(payload, self.multicast_to).await?;
        Ok(())
    }
}

/// The error of one socket step with what was attempted, for the start-up error and the logs.
fn step<T>(what: &str, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|e| io::Error::new(e.kind(), format!("{what}: {e}")))
}

/// The interface index from sysfs.
fn ifindex(iface: &str) -> io::Result<u32> {
    let text = fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))?;
    text.trim().parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("{iface}: ifindex {text:?}")))
}

/// The interface's IPv4 address: a throwaway socket tied to the interface and "connected" to the
/// group (no packet leaves for a UDP connect) gets the address the kernel would send from.
fn interface_address(iface: &str) -> io::Result<Ipv4Addr> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    step("SO_BINDTODEVICE", socket.bind_device(Some(iface.as_bytes())))?;
    step("connect to the group", socket.connect(&SocketAddrV4::new(MDNS_GROUP, MDNS_PORT).into()))?;
    match socket.local_addr()?.as_socket_ipv4() {
        Some(addr) => Ok(*addr.ip()),
        None => Err(io::Error::new(io::ErrorKind::AddrNotAvailable, format!("{iface}: no IPv4 address"))),
    }
}

fn open_udp(iface: &str, ifindex: u32) -> io::Result<UdpSocket> {
    let socket = step("UDP socket", Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)))?;
    step("SO_REUSEADDR", socket.set_reuse_address(true))?;
    // answers leave through this leg, datagrams of the other leg's interface are not ours
    step("SO_BINDTODEVICE", socket.bind_device(Some(iface.as_bytes())))?;
    step("bind 0.0.0.0:5353", socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT).into()))?;
    step("join 224.0.0.251", socket.join_multicast_v4_n(&MDNS_GROUP, &InterfaceIndexOrAddress::Index(ifindex)))?;
    // no IP_MULTICAST_IF: SO_BINDTODEVICE already routes every datagram, multicast included,
    // through the interface (and an address that is not the interface's own, as the loopback
    // test showed, makes the kernel refuse the option)
    // mDNS datagrams carry TTL 255 (§11); our own multicast is not wanted back
    step("IP_MULTICAST_TTL", socket.set_multicast_ttl_v4(255))?;
    step("IP_MULTICAST_LOOP", socket.set_multicast_loop_v4(false))?;
    socket.set_nonblocking(true)?;
    step("UDP socket registration", UdpSocket::from_std(socket.into()))
}

/// One instruction of a classic BPF program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

const fn stmt(code: u32, k: u32) -> Insn {
    Insn { code: code as u16, jt: 0, jf: 0, k }
}

const fn jump(code: u32, k: u32, jt: u8, jf: u8) -> Insn {
    Insn { code: code as u16, jt, jf, k }
}

/// The filter of a leg's packet socket: this interface, IPv4, UDP, not a fragment, destination
/// port 5353 (offsets from the start of the Ethernet frame, as `SOCK_RAW` delivers it). The last
/// instruction drops, the one before accepts the whole frame; jump offsets count from the
/// following instruction.
pub fn mdns_filter(ifindex: u32) -> Vec<Insn> {
    use libc::{
        BPF_ABS, BPF_B, BPF_H, BPF_IND, BPF_JEQ, BPF_JMP, BPF_JSET, BPF_K, BPF_LD, BPF_LDX, BPF_MSH, BPF_RET, BPF_W,
    };
    // the ancillary load of the receiving interface's index (SKF_AD_OFF is negative: the offset
    // wraps on purpose, as the kernel's own macros do)
    let ifindex_load = (libc::SKF_AD_OFF + libc::SKF_AD_IFINDEX) as u32;
    vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, ifindex_load),    // 0: A = interface index
        jump(BPF_JMP | BPF_JEQ | BPF_K, ifindex, 0, 10), // 1: not this leg -> 12
        stmt(BPF_LD | BPF_H | BPF_ABS, 12),              // 2: A = ethertype
        jump(BPF_JMP | BPF_JEQ | BPF_K, 0x0800, 0, 8),   // 3: not IPv4 -> 12
        stmt(BPF_LD | BPF_B | BPF_ABS, 23),              // 4: A = IP protocol
        jump(BPF_JMP | BPF_JEQ | BPF_K, 17, 0, 6),       // 5: not UDP -> 12
        stmt(BPF_LD | BPF_H | BPF_ABS, 20),              // 6: A = flags and fragment offset
        jump(BPF_JMP | BPF_JSET | BPF_K, 0x3fff, 4, 0),  // 7: a fragment -> 12
        stmt(BPF_LDX | BPF_B | BPF_MSH, 14),             // 8: X = IP header length
        stmt(BPF_LD | BPF_H | BPF_IND, 16),              // 9: A = UDP destination port
        jump(BPF_JMP | BPF_JEQ | BPF_K, u32::from(MDNS_PORT), 0, 1), // 10: other port -> 12
        stmt(BPF_RET | BPF_K, u32::MAX),                 // 11: accept the whole frame
        stmt(BPF_RET | BPF_K, 0),                        // 12: drop
    ]
}

fn open_packet(ifindex: u32) -> io::Result<UdpSocket> {
    // packet sockets take the protocol in network byte order
    let protocol = i32::from((libc::ETH_P_IP as u16).to_be());
    let socket = step("AF_PACKET socket", Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(protocol))))?;
    let filter: Vec<SockFilter> =
        mdns_filter(ifindex).into_iter().map(|i| SockFilter::new(i.code, i.jt, i.jf, i.k)).collect();
    step("SO_ATTACH_FILTER", socket.attach_filter(&filter))?;
    step("SO_RCVBUF", socket.set_recv_buffer_size(1 << 20))?;
    socket.set_nonblocking(true)?;
    // a UdpSocket is a file descriptor to tokio; recv() is the same system call on a packet socket
    step("packet socket registration", UdpSocket::from_std(socket.into()))
}

/// The MAC of a neighbour from the text of `/proc/net/arp` (complete entries of the interface).
pub fn neighbour_in(table: &str, addr: Ipv4Addr, iface: &str) -> Option<Mac> {
    let wanted = addr.to_string();
    table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 || fields[0] != wanted || fields[5] != iface {
            return None;
        }
        // flags 0x2: the entry is complete
        if u32::from_str_radix(fields[2].trim_start_matches("0x"), 16).ok()? & 0x2 == 0 {
            return None;
        }
        Mac::parse(fields[3]).filter(|m| !m.is_zero())
    })
}

fn neighbour_mac(addr: Ipv4Addr, iface: &str) -> Option<Mac> {
    neighbour_in(&fs::read_to_string("/proc/net/arp").ok()?, addr, iface)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::testing::ethernet_frame;

    /// A classic-BPF interpreter for the instructions the filter uses, with the ancillary
    /// interface index: the kernel cannot run the filter here (CAP_NET_RAW), so the program is
    /// checked against frames the way it would run there.
    fn run_filter(program: &[Insn], frame: &[u8], ifindex: u32) -> u32 {
        use libc::{
            BPF_ABS, BPF_B, BPF_H, BPF_IND, BPF_JEQ, BPF_JMP, BPF_JSET, BPF_K, BPF_LD, BPF_LDX, BPF_MSH, BPF_RET, BPF_W,
        };
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        let byte = |at: usize| frame.get(at).copied().map(u32::from);
        let half = |at: usize| Some((byte(at)? << 8) | byte(at + 1)?);
        loop {
            let insn = program[pc];
            pc += 1;
            let code = u32::from(insn.code);
            let class = code & 0x07;
            if class == BPF_LD {
                let mode = code & 0xe0;
                let size = code & 0x18;
                let at = if mode == BPF_IND { x as usize + insn.k as usize } else { insn.k as usize };
                let value = if mode == BPF_ABS && insn.k == (libc::SKF_AD_OFF + libc::SKF_AD_IFINDEX) as u32 {
                    Some(ifindex)
                } else if size == BPF_W {
                    half(at).zip(half(at + 2)).map(|(high, low)| (high << 16) | low)
                } else if size == BPF_H {
                    half(at)
                } else if size == BPF_B {
                    byte(at)
                } else {
                    panic!("load size");
                };
                let Some(value) = value else { return 0 };
                a = value;
            } else if class == BPF_LDX {
                assert_eq!(code & 0xe0, BPF_MSH);
                let Some(b) = byte(insn.k as usize) else { return 0 };
                x = (b & 0x0f) * 4;
            } else if class == BPF_JMP {
                assert_eq!(code & 0x08, BPF_K);
                let taken = match code & 0xf0 {
                    op if op == BPF_JEQ => a == insn.k,
                    op if op == BPF_JSET => a & insn.k != 0,
                    _ => panic!("jump"),
                };
                pc += usize::from(if taken { insn.jt } else { insn.jf });
            } else if class == BPF_RET {
                return insn.k;
            } else {
                panic!("class {class}");
            }
        }
    }

    #[test]
    fn filter_accepts_mdns_of_the_leg_only() {
        let program = mdns_filter(7);
        let mac = Mac([1, 2, 3, 4, 5, 6]);
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 0, 30, 5), 5353);
        let group = SocketAddrV4::new(MDNS_GROUP, MDNS_PORT);
        let frame = ethernet_frame(mac, src, group, b"mdns");
        assert_eq!(run_filter(&program, &frame, 7), u32::MAX);
        assert_eq!(run_filter(&program, &frame, 8), 0, "another interface");
        let legacy = ethernet_frame(mac, SocketAddrV4::new(Ipv4Addr::new(10, 0, 30, 5), 40000), group, b"mdns");
        assert_eq!(run_filter(&program, &legacy, 7), u32::MAX, "the source port does not matter");
        let other_port = ethernet_frame(mac, src, SocketAddrV4::new(MDNS_GROUP, 1900), b"ssdp");
        assert_eq!(run_filter(&program, &other_port, 7), 0);
        let mut tcp = frame.clone();
        tcp[23] = 6;
        assert_eq!(run_filter(&program, &tcp, 7), 0);
        let mut arp = frame.clone();
        arp[12..14].copy_from_slice(&[0x08, 0x06]);
        assert_eq!(run_filter(&program, &arp, 7), 0);
        let mut fragment = frame.clone();
        fragment[20] = 0x20;
        assert_eq!(run_filter(&program, &fragment, 7), 0);
        // options in the IP header move the UDP header: the MSH load follows them
        let mut with_options = Vec::new();
        with_options.extend_from_slice(&frame[..14]);
        with_options.push(0x46);
        with_options.extend_from_slice(&frame[15..34]);
        with_options.extend_from_slice(&[1, 1, 1, 1]);
        with_options.extend_from_slice(&frame[34..]);
        assert_eq!(run_filter(&program, &with_options, 7), u32::MAX);
        assert_eq!(run_filter(&program, &frame[..20], 7), 0, "a short frame is dropped");
    }

    #[test]
    fn neighbour_table() {
        let table = "IP address       HW type     Flags       HW address            Mask     Device\n\
                     10.0.30.5        0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth1\n\
                     10.0.30.6        0x1         0x0         00:00:00:00:00:00     *        eth1\n\
                     10.0.40.9        0x1         0x2         11:22:33:44:55:66     *        eth2\n";
        assert_eq!(neighbour_in(table, Ipv4Addr::new(10, 0, 30, 5), "eth1"), Mac::parse("aa:bb:cc:dd:ee:ff"));
        assert_eq!(neighbour_in(table, Ipv4Addr::new(10, 0, 30, 6), "eth1"), None, "incomplete");
        assert_eq!(neighbour_in(table, Ipv4Addr::new(10, 0, 40, 9), "eth1"), None, "other interface");
        assert_eq!(neighbour_in(table, Ipv4Addr::new(10, 0, 40, 9), "eth2"), Mac::parse("11:22:33:44:55:66"));
    }

    /// Needs CAP_NET_RAW (the container, or `setcap cap_net_raw+ep` on the test binary): opens a
    /// real leg on the loopback interface and receives its own datagram through the AF_PACKET
    /// socket and the BPF filter (loopback frames carry the zero MAC). Only loopback works for
    /// this: a datagram to any local address travels over `lo`, whatever interface owns it.
    #[tokio::test]
    #[ignore = "needs CAP_NET_RAW: run in the container or after setcap on the test binary"]
    async fn packet_leg_on_loopback() {
        let leg = Leg::open(LegKind::Residents, "lo").expect("a leg with CAP_NET_RAW");
        assert!(leg.describe().contains("AF_PACKET"), "{}", leg.describe());
        let client = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let SocketAddr::V4(client_addr) = client.local_addr().unwrap() else { panic!("v4") };
        client.send_to(b"ping 5353", SocketAddrV4::new(Ipv4Addr::LOCALHOST, MDNS_PORT)).unwrap();
        client.send_to(b"ping 5354", SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5354)).unwrap();
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let seen = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(frame) = leg.recv(&mut buf).await.unwrap()
                    && frame.payload.starts_with(b"ping")
                {
                    return (frame.src_mac, frame.src, frame.dst, frame.payload.to_vec());
                }
            }
        })
        .await
        .expect("the datagram through the packet socket within 2 s");
        assert_eq!(seen.0, Mac::ZERO, "loopback frames carry no MAC");
        assert_eq!(seen.1, client_addr);
        assert_eq!(seen.2, SocketAddrV4::new(Ipv4Addr::LOCALHOST, MDNS_PORT));
        assert_eq!(seen.3, b"ping 5353", "the filter passes port 5353 only");
    }
}
