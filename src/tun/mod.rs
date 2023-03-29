mod error;
#[cfg(target_os = "macos")]
mod macos;
mod memory;

pub use error::Error;
#[cfg(target_os = "macos")]
pub use macos::NativeTun;

#[cfg(not(target_os = "macos"))]
pub struct NativeTun {}

use async_trait::async_trait;

#[async_trait]
pub trait Tun: Send + Sync + Clone {
    fn name(&self) -> &str;
    fn mtu(&self) -> Result<u16, Error>;
    fn set_mtu(&self, mtu: u16) -> Result<(), Error>;
    async fn recv(&self) -> Result<Vec<u8>, Error>;
    async fn send(&self, buf: &[u8]) -> Result<(), Error>;
}
