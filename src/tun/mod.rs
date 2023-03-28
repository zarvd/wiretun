#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{Error, Tun};

#[cfg(not(target_os = "macos"))]
pub struct Tun {}
