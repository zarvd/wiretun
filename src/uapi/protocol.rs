use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::SystemTime;

use bytes::{BufMut, Bytes, BytesMut};

use crate::noise::crypto;

pub enum Request {
    Get,
    Set,
}

pub enum Response {
    Get(DeviceInfo),
    Err,
}

pub struct DeviceInfo {
    pub private_key: [u8; 32],
    pub listen_port: u16,
    pub fwmark: u32,
    pub peers: Vec<PeerInfo>,
}

pub struct PeerInfo {
    pub public_key: [u8; 32],
    pub psk: [u8; 32],
    pub allowed_ips: Vec<(IpAddr, u8)>,
    pub endpoint: Option<SocketAddr>,
    pub last_handshake_at: SystemTime,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub persistent_keepalive_interval: u32,
}

impl Into<Bytes> for DeviceInfo {
    fn into(self) -> Bytes {
        let mut buf = KVBuffer::new();
        if self.private_key != [0u8; 32] {
            buf.encode_and_put("private_key", &self.private_key);
        }
        buf.put_u16("listen_port", self.listen_port);

        if self.fwmark != 0 {
            buf.put_u32("fwmark", self.fwmark);
        }

        for peer in self.peers {
            buf.encode_and_put("public_key", &peer.public_key);
            buf.encode_and_put("preshared_key", &peer.psk);
            for (ip, mask) in peer.allowed_ips {
                buf.put("allowed_ip", &format!("{}/{}", ip, mask));
            }
            if let Some(endpoint) = peer.endpoint {
                buf.put("endpoint", &endpoint.to_string());
            }
            let d = peer
                .last_handshake_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();
            buf.put_u64("last_handshake_time_sec", d.as_secs());
            buf.put_u32("last_handshake_time_nsec", d.subsec_nanos());
            buf.put_u64("tx_bytes", peer.tx_bytes);
            buf.put_u64("rx_bytes", peer.rx_bytes);
            buf.put_u32(
                "persistent_keepalive_interval",
                peer.persistent_keepalive_interval,
            );
        }
        buf.put_u32("protocol_version", 0);
        buf.put_u32("errno", 0);
        buf.freeze()
    }
}

struct KVBuffer(BytesMut);

impl KVBuffer {
    pub fn new() -> Self {
        KVBuffer(BytesMut::new())
    }

    #[inline]
    pub fn put(&mut self, key: &str, value: &str) {
        self.0.put(format!("{}={}\n", key, value).as_bytes());
    }

    #[inline]
    pub fn put_u16(&mut self, key: &str, value: u16) {
        self.0.put(format!("{}={}\n", key, value).as_bytes());
    }

    #[inline]
    pub fn put_u32(&mut self, key: &str, value: u32) {
        self.0.put(format!("{}={}\n", key, value).as_bytes());
    }

    #[inline]
    pub fn put_u64(&mut self, key: &str, value: u64) {
        self.0.put(format!("{}={}\n", key, value).as_bytes());
    }

    #[inline]
    pub fn encode_and_put(&mut self, key: &str, value: &[u8]) {
        self.put(key, &crypto::encode_to_hex(value));
    }

    #[inline]
    pub fn freeze(mut self) -> Bytes {
        self.0.put_slice(b"\n");
        self.0.freeze()
    }
}