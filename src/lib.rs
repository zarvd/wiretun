#![deny(
    warnings,
    rust_2018_idioms,
    clippy::clone_on_ref_ptr,
    clippy::dbg_macro,
    clippy::enum_glob_use,
    clippy::get_unwrap,
    clippy::macro_use_imports,
    clippy::str_to_string,
    clippy::inefficient_to_string,
    clippy::too_many_lines,
    clippy::or_fun_call
)]

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
//! use wiretun::{Cidr, Device, DeviceConfig, PeerConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!    let cfg = DeviceConfig::default()
//!        .listen_port(40001);
//!    let device = Device::native("utun88", cfg).await?;
//!    Ok(())
//! }

mod device;
pub mod noise;
mod tun;

pub use device::{Cidr, Device, DeviceConfig, DeviceHandle, ParseCidrError, PeerConfig};
pub use tun::{Error as TunError, Tun};

#[cfg(feature = "native")]
/// Native tun implementation.
pub use tun::NativeTun;

#[cfg(feature = "uapi")]
pub mod uapi;
