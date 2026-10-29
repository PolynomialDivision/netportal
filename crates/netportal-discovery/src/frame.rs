//! What a leg hands the engine: one UDP datagram to port 5353 with its sender's MAC. On the
//! AF_PACKET path the MAC is the Ethernet source address of the frame, which is parsed here down
//! to the UDP payload (IPv4 only: IPv6 is not routed between the VLANs, design 6.5); on the UDP
//! fallback path the socket layer fills it from the neighbour table.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};

/// The mDNS port (RFC 6762 §2): queries and answers come from it and go to it.
pub const MDNS_PORT: u16 = 5353;
/// The IPv4 mDNS group.
pub const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// A MAC address as the frames and the registry carry it (`aa:bb:cc:dd:ee:ff`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    /// The MAC of a datagram whose sender is unknown (the UDP fallback without a neighbour entry).
    pub const ZERO: Mac = Mac([0; 6]);

    pub fn is_zero(self) -> bool {
        self == Mac::ZERO
    }

    /// `aa:bb:cc:dd:ee:ff`, `AA-BB-CC-DD-EE-FF` or `aabbccddeeff`; `None` for anything else.
    pub fn parse(text: &str) -> Option<Mac> {
        let hex: String = text.trim().chars().filter(|c| !matches!(c, ':' | '-' | '.')).collect();
        if hex.len() != 12 {
            return None;
        }
        let mut out = [0u8; 6];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
        }
        Some(Mac(out))
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
    }
}

impl fmt::Debug for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// One datagram as a leg received it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub src_mac: Mac,
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub payload: &'a [u8],
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]))
}

fn ipv4_at(bytes: &[u8], at: usize) -> Option<Ipv4Addr> {
    Some(Ipv4Addr::from(<[u8; 4]>::try_from(bytes.get(at..at + 4)?).ok()?))
}

/// Parses an Ethernet frame, as an `AF_PACKET`/`SOCK_RAW` socket delivers it, down to the UDP
/// payload. `None` for anything but IPv4 over Ethernet (a VLAN tag is skipped) carrying one
/// unfragmented UDP datagram; the port is the caller's business (the BPF filter already chose
/// 5353). Trailing padding beyond the IP total length is cut off.
pub fn parse_ethernet(frame: &[u8]) -> Option<Frame<'_>> {
    let src_mac = Mac(<[u8; 6]>::try_from(frame.get(6..12)?).ok()?);
    let (ethertype, ip_at) = match u16_at(frame, 12)? {
        0x8100 => (u16_at(frame, 16)?, 18),
        other => (other, 14),
    };
    if ethertype != 0x0800 {
        return None;
    }
    let ip = frame.get(ip_at..)?;
    let first = *ip.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(first & 0x0f) * 4;
    if header_len < 20 {
        return None;
    }
    // a fragment (more-fragments set or an offset) carries no complete datagram; mDNS messages
    // stay below 9000 bytes and the kernel reassembles nothing for a packet socket
    if u16_at(ip, 6)? & 0x3fff != 0 {
        return None;
    }
    if *ip.get(9)? != 17 {
        return None;
    }
    let total_len = usize::from(u16_at(ip, 2)?);
    let src_ip = ipv4_at(ip, 12)?;
    let dst_ip = ipv4_at(ip, 16)?;
    let udp = ip.get(header_len..total_len)?;
    let src_port = u16_at(udp, 0)?;
    let dst_port = u16_at(udp, 2)?;
    let udp_len = usize::from(u16_at(udp, 4)?);
    let payload = udp.get(8..udp_len)?;
    Some(Frame { src_mac, src: SocketAddrV4::new(src_ip, src_port), dst: SocketAddrV4::new(dst_ip, dst_port), payload })
}

/// Hand-built frames for the tests of this crate.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// An Ethernet/IPv4/UDP frame with the given addresses and payload (no checksums: the
    /// parser and the filter never look at them).
    pub fn ethernet_frame(src_mac: Mac, src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut f = Vec::with_capacity(14 + total_len);
        f.extend_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]);
        f.extend_from_slice(&src_mac.0);
        f.extend_from_slice(&[0x08, 0x00]);
        f.push(0x45);
        f.push(0);
        f.extend_from_slice(&(total_len as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0]); // id, flags/fragment
        f.push(255);
        f.push(17);
        f.extend_from_slice(&[0, 0]); // checksum
        f.extend_from_slice(&src.ip().octets());
        f.extend_from_slice(&dst.ip().octets());
        f.extend_from_slice(&src.port().to_be_bytes());
        f.extend_from_slice(&dst.port().to_be_bytes());
        f.extend_from_slice(&(udp_len as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        f
    }
}

#[cfg(test)]
mod tests {
    use super::testing::ethernet_frame;
    use super::*;

    #[test]
    fn mac_text() {
        let mac = Mac::parse("AA-bb:cc:dd:ee:0f").unwrap();
        assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:0f");
        assert_eq!(Mac::parse("aabbccddee0f"), Some(mac));
        assert_eq!(Mac::parse("aa:bb:cc:dd:ee"), None);
        assert_eq!(Mac::parse("aa:bb:cc:dd:ee:gg"), None);
        assert!(Mac::ZERO.is_zero());
    }

    #[test]
    fn parses_a_frame() {
        let mac = Mac([0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 0, 30, 7), 5353);
        let dst = SocketAddrV4::new(MDNS_GROUP, 5353);
        let mut bytes = ethernet_frame(mac, src, dst, b"hello");
        bytes.extend_from_slice(&[0; 20]); // Ethernet padding
        let frame = parse_ethernet(&bytes).unwrap();
        assert_eq!(frame.src_mac, mac);
        assert_eq!(frame.src, src);
        assert_eq!(frame.dst, dst);
        assert_eq!(frame.payload, b"hello");
    }

    #[test]
    fn rejects_other_frames() {
        let mac = Mac([1, 2, 3, 4, 5, 6]);
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 0, 30, 7), 5353);
        let dst = SocketAddrV4::new(MDNS_GROUP, 5353);
        let good = ethernet_frame(mac, src, dst, b"x");
        assert!(parse_ethernet(&good[..30]).is_none(), "truncated");
        let mut arp = good.clone();
        arp[12] = 0x08;
        arp[13] = 0x06;
        assert!(parse_ethernet(&arp).is_none(), "not IPv4");
        let mut tcp = good.clone();
        tcp[23] = 6;
        assert!(parse_ethernet(&tcp).is_none(), "not UDP");
        let mut fragment = good.clone();
        fragment[20] = 0x20;
        assert!(parse_ethernet(&fragment).is_none(), "fragment");
        let mut tagged = Vec::new();
        tagged.extend_from_slice(&good[..12]);
        tagged.extend_from_slice(&[0x81, 0x00, 0x00, 0x1e]);
        tagged.extend_from_slice(&good[12..]);
        assert_eq!(parse_ethernet(&tagged).unwrap().payload, b"x", "VLAN tag skipped");
    }
}
