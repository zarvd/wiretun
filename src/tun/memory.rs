use async_trait::async_trait;

use crate::tun::{Error, Tunnel};

pub struct MemoryTun {
    name: String,
    mtu: u32,
}

impl MemoryTun {}

#[async_trait]
impl Tunnel for MemoryTun {
    fn mtu(&self) -> Result<u32, Error> {
        todo!()
    }

    fn set_mtu(&mut self, mtu: u32) -> Result<(), Error> {
        todo!()
    }

    async fn recv(&self) -> Result<Vec<u8>, Error> {
        todo!()
    }

    async fn send(&self, buf: &[u8]) -> Result<(), Error> {
        todo!()
    }
}
