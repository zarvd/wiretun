mod error;
#[cfg(target_os = "macos")]
mod macos;
mod memory;

pub use error::Error;
#[cfg(target_os = "macos")]
pub use macos::Tun;

#[cfg(not(target_os = "macos"))]
pub struct Tun {}

use async_trait::async_trait;

#[async_trait]
pub trait Tunnel {
    fn mtu(&self) -> Result<u32, Error>;
    fn set_mtu(&mut self, mtu: u32) -> Result<(), Error>;
    async fn recv(&self) -> Result<Vec<u8>, Error>;
    async fn send(&self, buf: &[u8]) -> Result<(), Error>;
}
