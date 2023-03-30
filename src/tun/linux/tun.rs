use crate::tun::Error;
use crate::Tun;

const DEVICE_PATH: &str = "/dev/net/tun";

#[derive(Clone)]
pub struct NativeTun {}

impl NativeTun {
    pub fn new(name: &str) -> Result<Self, Error> {
        let nfd = unsafe { libc::open(DEVICE_PATH, libc::O_RDWR | libc::O_CLOEXEC, 0) };
    }
}

impl Tun for NativeTun {
    fn name(&self) -> &str {
        todo!()
    }

    fn mtu(&self) -> Result<u16, Error> {
        todo!()
    }

    fn set_mtu(&self, mtu: u16) -> Result<(), Error> {
        todo!()
    }

    async fn recv(&self) -> Result<Vec<u8>, Error> {
        todo!()
    }

    async fn send(&self, buf: &[u8]) -> Result<(), Error> {
        todo!()
    }
}
