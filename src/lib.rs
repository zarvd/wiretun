pub mod config;
mod device;

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "tun_darwin.rs"]
mod tun;

pub use device::Device;
pub use tun::Tun;
