use async_trait::async_trait;

use crate::tun::{Error, Tun};

#[derive(Clone)]
pub struct MemoryTun {
    name: String,
    mtu: u32,
}

impl MemoryTun {}

#[async_trait]
impl Tun for MemoryTun {
    fn name(&self) -> &str {
        todo!()
    }

    fn mtu(&self) -> Result<u16, Error> {
        todo!()
    }

    fn set_mtu(&self, _mtu: u16) -> Result<(), Error> {
        todo!()
    }

    async fn recv(&self) -> Result<Vec<u8>, Error> {
        todo!()
    }

    async fn send(&self, _buf: &[u8]) -> Result<(), Error> {
        todo!()
    }
}
