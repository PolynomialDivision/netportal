//! The discovery proxy (`netportal discovery`; house-infra docs/IOT-ACCESS.md, section 6.5):
//! learns the home devices' mDNS records on the IoT leg, answers the residents' queries on the
//! residents' leg through the access view, unicast to the querier for private devices,
//! multicast for house-visible ones. A responder with a cache, never a reflector: no packet
//! crosses from one leg to the other.
//!
//! Layout: [`frame`] (a datagram with its sender's MAC, parsed out of the Ethernet frame),
//! [`wire`] (the DNS wire format through hickory-proto and the mDNS conventions on top),
//! [`cache`] (the records learned per source MAC), [`registry`] (the snapshot of the registry
//! and the stale rule), [`answer`] (the pure decision: what to answer, to whom, how), [`proxy`]
//! (the engine without sockets: rate limits, the browser's queries, statistics), [`sockets`]
//! (the two legs) and [`run`] (the main loop, the heartbeat, `--probe`).

pub mod answer;
pub mod cache;
pub mod frame;
pub mod proxy;
pub mod registry;
pub mod run;
pub mod sockets;
pub mod wire;

pub use run::run;

pub(crate) const LOG: &str = "netportal.discovery";
