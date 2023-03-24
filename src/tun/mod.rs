#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::Tun;

#[cfg(not(target_os = "macos"))]
pub struct Tun {}
