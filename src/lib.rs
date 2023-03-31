#![allow(dead_code)]

//! # WireTun
//!
//! WireTun is a user-space WireGuard implementation in Rust.
//!
//! ## What is WireGuard?
//!
//! WireGuard is a modern, high-performance VPN protocol that is designed to be simple to use and easy to configure.
//! It is often used to create secure private networks and build reliable, low-latency connections.
//!
//! ## Features
//!
//! - Implementation of the [WireGuard](https://www.wireguard.com/) protocol in Rust.
//! - Asynchronous I/O using [Tokio](https://tokio.rs/).
//!
//! # Examples
//!
//! ```no_run
//! use wiretun::{Cidr, Device, DeviceConfig, PeerConfig, uapi};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!    let cfg = DeviceConfig::default()
//!        .listen_port(40001);
//!    let device = Device::native("utun88", cfg).await?;
//!    uapi::bind_and_handle(device.handle()).await?;
//!    Ok(())
//! }

mod device;
mod noise;
mod tun;

pub use device::{Cidr, Device, DeviceConfig, DeviceHandle, ParseCidrError, PeerConfig};
pub use tun::{Error as TunError, Tun};

#[cfg(feature = "native")]
/// Native tun implementation.
pub use tun::NativeTun;

#[cfg(feature = "uapi")]
pub mod uapi;
