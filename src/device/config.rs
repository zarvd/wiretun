use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Default, Clone)]
pub struct DeviceConfig {
    pub private_key: [u8; 32],
    pub listen_port: u16,
    pub peers: Vec<PeerConfig>,
}

#[derive(Default, Clone)]
pub struct PeerConfig {
    pub public_key: [u8; 32],
    pub allowed_ips: Vec<(IpAddr, u8)>,
    pub endpoint: Option<SocketAddr>,
    pub preshared_key: Option<[u8; 32]>,
    pub persistent_keepalive: Option<u16>,
}

impl DeviceConfig {
    #[inline(always)]
    pub fn private_key(mut self, key: [u8; 32]) -> Self {
        self.private_key = key;
        self
    }

    #[inline(always)]
    pub fn listen_port(mut self, port: u16) -> Self {
        self.listen_port = port;
        self
    }

    #[inline(always)]
    pub fn peers(mut self, peer: Vec<PeerConfig>) -> Self {
        self.peers = peer;
        self
    }

    #[inline(always)]
    pub fn peer(mut self, peer: PeerConfig) -> Self {
        self.peers.push(peer);
        self
    }
}

impl PeerConfig {
    #[inline(always)]
    pub fn public_key(mut self, key: [u8; 32]) -> Self {
        self.public_key = key;
        self
    }

    #[inline(always)]
    pub fn allowed_ips(mut self, ips: Vec<(IpAddr, u8)>) -> Self {
        self.allowed_ips = ips;
        self
    }

    #[inline(always)]
    pub fn allowed_ip(mut self, ip: IpAddr, mask: u8) -> Self {
        self.allowed_ips.push((ip, mask));
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
        self.persistent_keepalive = Some(interval.as_secs() as _);
        self
    }
}
