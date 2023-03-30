#![allow(dead_code)]

//! A WireGuard implementation in Rust.
//!
//! WireTun is a WireGuard implementation in Rust. It is a library that can be used to build
//! WireGuard clients and servers.
//!
//! # Features
//! - support [`tokio`] runtime
//!
//! # Examples
//! ```toml
//! [dependencies]
//! wiretun = { version = "0.1", features = ["tun-native", "uapi"] }
//! ```

mod device;
mod noise;
mod time;
mod tun;

pub use device::{Cidr, Device, DeviceConfig, DeviceHandle, ParseCidrError, PeerConfig};
pub use tun::Error as TunError;
pub use tun::Tun;

#[cfg(feature = "tun-native")]
pub use tun::NativeTun;

#[cfg(feature = "tun-memory")]
pub use tun::MemoryTun;

#[cfg(feature = "uapi")]
pub mod uapi;
