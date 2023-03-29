#![allow(dead_code)] // FIXME: Remove it before release

#[cfg(target_os = "macos")]
mod device;
mod listener;
mod noise;
mod tun;
mod uapi;

#[cfg(target_os = "macos")]
pub use device::{Device, DeviceConfig, PeerConfig};
pub use listener::Listener;
pub use tun::{NativeTun, Tun};
