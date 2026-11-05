//! Test-only tooling for packetfin: capture-file builders, generated fixtures
//! and their stored expected (golden) output.
//!
//! This crate is development tooling. Production crates may depend on it only
//! as a dev-dependency.

mod wire;

pub mod compress;
pub mod export;
pub mod fixtures;
pub mod golden;
pub mod pcap;
pub mod pcapng;
pub mod tls;

pub use wire::{ByteOrder, Timestamp, TimestampResolution};
