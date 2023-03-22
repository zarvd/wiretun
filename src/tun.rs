use std::io;
use std::mem::{size_of, size_of_val};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use libc::{
    c_char, connect, ctl_info, ioctl, sockaddr_ctl, socket, AF_SYSTEM, AF_SYS_CONTROL, CTLIOCGINFO,
    MAX_KCTL_NAME, PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL,
};
use regex::Regex;

const CTRL_NAME: [c_char; MAX_KCTL_NAME] = [
    b'c' as _, b'o' as _, b'm' as _, b'.' as _, b'a' as _, b'p' as _, b'p' as _, b'l' as _,
    b'e' as _, b'.' as _, b'n' as _, b'e' as _, b't' as _, b'.' as _, b'u' as _, b't' as _,
    b'u' as _, b'n' as _, b'_' as _, b'c' as _, b'o' as _, b'n' as _, b't' as _, b'r' as _,
    b'o' as _, b'l' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _,
    b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _,
    b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _,
    b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _,
    b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _,
    b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _,
    b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _,
    b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _,
    b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _, b'\0' as _,
];

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
}

impl Tun {
    pub fn new(name: &str, mtu: u16) -> Result<Self, Error> {
        let idx = parse_name(name)?;

        let fd = match unsafe { socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) } {
            -1 => return Err(Error::Socket(io::Error::last_os_error())),
            fd => unsafe { OwnedFd::from_raw_fd(fd) },
        };

        let mut info = ctl_info {
            ctl_id: 0,
            ctl_name: CTRL_NAME,
        };

        if unsafe { ioctl(fd.as_raw_fd(), CTLIOCGINFO, &mut info) } < 0 {
            return Err(Error::IOCtl(io::Error::last_os_error()));
        }

        let addr = sockaddr_ctl {
            sc_len: size_of::<sockaddr_ctl>() as _,
            sc_family: AF_SYSTEM as _,
            ss_sysaddr: AF_SYS_CONTROL as _,
            sc_id: info.ctl_id,
            sc_unit: idx,
            sc_reserved: Default::default(),
        };

        if unsafe {
            connect(
                fd.as_raw_fd(),
                &addr as *const sockaddr_ctl as _,
                size_of_val(&addr) as _,
            )
        } < 0
        {
            return Err(Error::Connect(io::Error::last_os_error()));
        }

        Ok(Self { fd })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Interface must be named utun[0-9]*")]
    InvalidName,
    #[error("Failed to create socket: {0}")]
    Socket(io::Error),
    #[error("Failed to get control info: {0}")]
    IOCtl(io::Error),
    #[error("Failed to connect to utun: {0}")]
    Connect(io::Error),
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match self {
            Error::InvalidName => match other {
                Error::InvalidName => true,
                _ => false,
            },
            Error::IOCtl(_) => match other {
                Error::IOCtl(_) => true,
                _ => false,
            },
            Error::Socket(_) => match other {
                Error::Socket(_) => true,
                _ => false,
            },
            Error::Connect(_) => match other {
                Error::Connect(_) => true,
                _ => false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ctrl_name() {
        let expected = {
            const CTRL_NAME_IN_BYTES: &[u8] = b"com.apple.net.utun_control";
            let mut name: [c_char; MAX_KCTL_NAME] = [0_i8; MAX_KCTL_NAME];
            name[..CTRL_NAME_IN_BYTES.len()].copy_from_slice(
                CTRL_NAME_IN_BYTES
                    .iter()
                    .map(|&x| x as _)
                    .collect::<Vec<_>>()
                    .as_slice(),
            );
            name
        };

        assert_eq!(CTRL_NAME, expected);
    }

    #[test]
    fn test_parse_name() {
        let cases = [
            ("utun", Ok(0)),
            ("utun0", Ok(0)),
            ("utun42", Ok(42)),
            ("utun04", Err(Error::InvalidName)),
            ("utun007", Err(Error::InvalidName)),
            ("utun42foo", Err(Error::InvalidName)),
            ("utunfoo", Err(Error::InvalidName)),
            ("futun", Err(Error::InvalidName)),
        ];

        for (input, expected) in cases {
            assert_eq!(parse_name(input), expected);
        }
    }
}
