use std::ffi::CStr;
use std::os::fd::RawFd;
use std::{io, mem, ptr};

use libc::*;

pub const SIOCSIFMTU: u64 = 0x80206934;
pub const SIOCGIFMTU: u64 = 0xc0206933;

pub const CTRL_NAME: [c_char; MAX_KCTL_NAME] = [
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

#[repr(C)]
#[derive(Copy, Clone)]
pub union ifrn {
    pub name: [c_char; IFNAMSIZ],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifdevmtu {
    pub current: c_int,
    pub min: c_int,
    pub max: c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ifku {
    pub ptr: *mut c_void,
    pub value: c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ifru {
    pub addr: sockaddr,
    pub dstaddr: sockaddr,
    pub broadaddr: sockaddr,

    pub flags: c_short,
    pub metric: c_int,
    pub mtu: c_int,
    pub phys: c_int,
    pub media: c_int,
    pub intval: c_int,
    pub data: *mut c_void,
    pub devmtu: ifdevmtu,
    pub wake_flags: c_uint,
    pub route_refcnt: c_uint,
    pub cap: [c_int; 2],
    pub functional_type: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifreq {
    pub ifrn: ifrn,
    pub ifru: ifru,
}

impl ifreq {
    pub fn new(name: &str) -> Self {
        let mut me: Self = unsafe { mem::zeroed() };
        unsafe {
            ptr::copy_nonoverlapping(
                name.as_ptr() as *const libc::c_char,
                me.ifrn.name.as_mut_ptr(),
                name.len(),
            )
        }
        me
    }
}

pub unsafe fn set_nonblocking(fd: RawFd) -> Result<(), io::Error> {
    match unsafe { libc::fcntl(fd, libc::F_GETFL) } {
        -1 => Err(io::Error::last_os_error()),
        flags => match unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        },
    }
}

pub unsafe fn get_iface_name(fd: RawFd) -> Result<String, io::Error> {
    const MAX_LEN: usize = 256;
    let mut name = [0u8; MAX_LEN];
    let mut name_len: libc::socklen_t = name.len() as _;
    if libc::getsockopt(
        fd,
        libc::SYSPROTO_CONTROL,
        libc::UTUN_OPT_IFNAME,
        name.as_mut_ptr() as _,
        &mut name_len,
    ) < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(CStr::from_ptr(name.as_ptr() as *const libc::c_char)
        .to_string_lossy()
        .into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ctrl_name() {
        let expected = {
            const CTRL_NAME_IN_BYTES: &[u8] = b"com.apple.net.utun_control";
            let mut name: [c_char; libc::MAX_KCTL_NAME] = [0_i8; libc::MAX_KCTL_NAME];
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
}
