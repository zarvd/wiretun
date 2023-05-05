use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use super::Cidr;
use crate::noise::crypto::LocalStaticSecret;

/// Configuration for a device.
///
/// # Examples
///
/// ```
/// use wiretun::{DeviceConfig, PeerConfig, Cidr};
///
/// let cfg = DeviceConfig::default()
///     .listen_port(40001)
///     .private_key([0; 32])
///     .peer(PeerConfig::default().public_key([0; 32]).allowed_ip("10.0.0.0/24".parse::<Cidr>().unwrap()));
/// ```
#[derive(Clone)]
pub struct DeviceConfig {
    pub private_key: [u8; 32],
    pub listen_addrs: (Ipv4Addr, Ipv6Addr),
    pub listen_port: u16,
    pub fwmark: u32,
    pub peers: HashMap<[u8; 32], PeerConfig>,
}

/// Configuration for a peer.
#[derive(Default, Clone)]
pub struct PeerConfig {
    pub public_key: [u8; 32],
    pub allowed_ips: HashSet<Cidr>,
    pub endpoint: Option<SocketAddr>,
    pub preshared_key: Option<[u8; 32]>,
    pub persistent_keepalive: Option<Duration>,
}

impl DeviceConfig {
    #[inline(always)]
    pub fn private_key(mut self, key: [u8; 32]) -> Self {
        self.private_key = key;
        self
    }

    #[inline(always)]
    pub fn listen_addr_v4(mut self, addr: Ipv4Addr) -> Self {
        self.listen_addrs.0 = addr;
        self
    }

    #[inline(always)]
    pub fn listen_addr_v6(mut self, addr: Ipv6Addr) -> Self {
        self.listen_addrs.1 = addr;
        self
    }

    #[inline(always)]
    pub fn listen_port(mut self, port: u16) -> Self {
        self.listen_port = port;
        self
    }

    #[inline(always)]
    pub fn peer(mut self, peer: PeerConfig) -> Self {
        self.peers.insert(peer.public_key, peer);
        self
    }

    #[inline(always)]
    pub fn local_secret(&self) -> LocalStaticSecret {
        LocalStaticSecret::new(self.private_key)
    }
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            private_key: [0; 32],
            listen_addrs: (Ipv4Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED),
            listen_port: 0,
            fwmark: 0,
            peers: HashMap::new(),
        }
    }
}

impl PeerConfig {
    #[inline(always)]
    pub fn public_key(mut self, key: [u8; 32]) -> Self {
        self.public_key = key;
        self
    }

    #[inline(always)]
    pub fn allowed_ips<T: Into<Cidr>>(mut self, ips: impl IntoIterator<Item = T>) -> Self {
        self.allowed_ips = ips.into_iter().map(|i| i.into()).collect();
        self
    }

    #[inline(always)]
    pub fn allowed_ip<I: Into<Cidr>>(mut self, ip: I) -> Self {
        self.allowed_ips.insert(ip.into());
        self
    }

    #[inline(always)]
    pub fn endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    #[inline(always)]
    pub fn preshared_key(mut self, key: [u8; 32]) -> Self {
        self.preshared_key = Some(key);
        self
    }

    #[inline(always)]
    pub fn persistent_keepalive(mut self, interval: Duration) -> Self {
        self.persistent_keepalive = Some(interval);
        self
    }
}
