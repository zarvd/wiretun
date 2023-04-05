use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;
use libc::{__c_anonymous_ifr_ifru, IFF_NO_PI, IFF_TUN, IFF_VNET_HDR};
use nix::fcntl::{self, OFlag};
use nix::sys::stat::Mode;
use tokio::io::unix::AsyncFd;
use tracing::debug;

use crate::tun::linux::sys::{self, get_mtu, ioctl_tun_set_iff, set_mtu, set_nonblocking};
use crate::tun::Error;
use crate::Tun;

const DEVICE_PATH: &str = "/dev/net/tun";

#[derive(Clone)]
pub struct NativeTun {
    fd: Arc<AsyncFd<OwnedFd>>,
    name: String,
}

impl NativeTun {
    pub fn new(name: &str) -> Result<Self, Error> {
        if name.len() > 16 {
            return Err(Error::InvalidName);
        }
        let fd = fcntl::open(DEVICE_PATH, OFlag::O_RDWR | OFlag::O_CLOEXEC, Mode::empty())
            .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
            .map_err(Error::Sys)?;

        let mut ifr = sys::new_ifreq(name);
        ifr.ifr_ifru = __c_anonymous_ifr_ifru {
            ifru_flags: (IFF_TUN | IFF_NO_PI) as _,
        };
        let _ = IFF_VNET_HDR; // TODO: enable

        unsafe { ioctl_tun_set_iff(fd.as_raw_fd(), &ifr) }?;
        set_nonblocking(fd.as_raw_fd())?;

        Ok(Self {
            fd: Arc::new(AsyncFd::new(fd)?),
            name: name.to_owned(),
        })
    }
}

#[async_trait]
impl Tun for NativeTun {
    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> Result<u16, Error> {
        get_mtu(&self.name)
    }

    fn set_mtu(&self, mtu: u16) -> Result<(), Error> {
        set_mtu(&self.name, mtu)
    }

    async fn recv(&self) -> Result<Vec<u8>, Error> {
        let mut buf = BytesMut::zeroed(1500);

        loop {
            let ret = {
                let mut guard = self.fd.readable().await?;
                guard.try_io(|inner| unsafe {
                    let ret = libc::read(inner.as_raw_fd(), buf.as_mut_ptr() as _, buf.len());
                    if ret < 0 {
                        Err::<usize, io::Error>(io::Error::last_os_error())
                    } else {
                        Ok(ret as usize)
                    }
                })
            };

            match ret {
                Ok(Ok(n)) => {
                    debug!("TUN read {} bytes", n);
                    buf.truncate(n);
                    return Ok(buf.freeze().to_vec());
                }
                Ok(Err(e)) => return Err(e.into()),
                _ => continue,
            }
        }
    }

    async fn send(&self, buf: &[u8]) -> Result<(), Error> {
        let mut guard = self.fd.writable().await?;
        let ret = guard.try_io(|inner| unsafe {
            let ret = libc::write(inner.as_raw_fd(), buf.as_ptr() as _, buf.len());
            if ret < 0 {
                Err::<usize, io::Error>(io::Error::last_os_error())
            } else {
                Ok(ret as usize)
            }
        });

        match ret {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(e)) => return Err(e.into()),
            _ => {}
        }

        Ok(())
    }
}
