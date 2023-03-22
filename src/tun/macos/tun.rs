use std::io;
use std::mem::{size_of, size_of_val};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use regex::Regex;

use super::sys;

#[inline]
fn parse_name(name: &str) -> Result<u32, Error> {
    if name == "utun" {
        return Ok(0);
    }
    let re = Regex::new(r"^utun([1-9]\d*|0)?$").unwrap();
    if !re.is_match(name) {
        return Err(Error::InvalidName);
    }
    name[4..]
        .parse()
        .map(|i: u32| i + 1)
        .map_err(|_| Error::InvalidName)
}

pub struct Tun {
    fd: OwnedFd,
    name: String,
}

impl Tun {
    pub fn new(name: &str) -> Result<Self, Error> {
        let idx = parse_name(name)?;

        let fd = match unsafe {
            libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL)
        } {
            -1 => return Err(io::Error::last_os_error().into()),
            fd => unsafe { OwnedFd::from_raw_fd(fd) },
        };

        let mut info = libc::ctl_info {
            ctl_id: 0,
            ctl_name: sys::CTRL_NAME,
        };

        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut info) } < 0 {
            return Err(io::Error::last_os_error().into());
        }

        let addr = libc::sockaddr_ctl {
            sc_len: size_of::<libc::sockaddr_ctl>() as _,
            sc_family: libc::AF_SYSTEM as _,
            ss_sysaddr: libc::AF_SYS_CONTROL as _,
            sc_id: info.ctl_id,
            sc_unit: idx,
            sc_reserved: Default::default(),
        };

        if unsafe {
            libc::connect(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_ctl as _,
                size_of_val(&addr) as _,
            )
        } < 0
        {
            return Err(io::Error::last_os_error().into());
        }

        let name = unsafe { sys::get_iface_name(fd.as_raw_fd()) }?;

        Ok(Self { fd, name })
    }

    pub fn set_mtu(&self, mtu: u16) -> Result<(), Error> {
        let mut req = sys::ifreq::new(&self.name);
        req.ifru.mtu = mtu as _;
        if unsafe { libc::ioctl(self.fd.as_raw_fd(), sys::SIOCSIFMTU, &req) } < 0 {
            return Err(io::Error::last_os_error().into());
        }

        Ok(())
    }

    pub fn mtu(&mut self) -> Result<u16, Error> {
        let req = sys::ifreq::new(&self.name);
        if unsafe { libc::ioctl(self.fd.as_raw_fd(), sys::SIOCGIFMTU, &req) } < 0 {
            return Err(io::Error::last_os_error().into());
        }

        Ok(unsafe { req.ifru.mtu as _ })
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Interface must be named utun[0-9]*")]
    InvalidName,
    #[error("System call failed: {0}")]
    IOError(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_name() {
        let success_cases = [("utun", 0), ("utun0", 1), ("utun42", 43)];

        for (input, expected) in success_cases {
            let rv = parse_name(input);
            assert!(rv.is_ok());
            assert_eq!(rv.unwrap(), expected);
        }

        let failure_cases = ["utun04", "utun007", "utun42foo", "utunfoo", "futun"];

        for input in failure_cases {
            assert!(parse_name(input).is_err())
        }
    }
}
