use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::noise::crypto;
use bytes::{BufMut, BytesMut};
use rand_core::{OsRng, RngCore};
use tracing::warn;

use super::{LABEL_COOKIE, LABEL_MAC1};
use crate::noise::crypto::{hash, mac, xaead_encrypt, LocalStaticSecret, PeerStaticSecret};

const MESSAGE_TYPE_COOKIE_REPLY: u8 = 3u8;
const PACKET_SIZE: usize = 64;
const COOKIE_LIFETIME: Duration = Duration::from_secs(120);

pub struct MacGenerator {
    peer_mac1_hash: [u8; 32],   // pre-compute hash for generating mac1
    peer_cookie_hash: [u8; 32], // pre-compute hash for generating mac2
    last_cookie: Option<([u8; 16], Instant)>,
}

impl MacGenerator {
    #[inline]
    pub fn new(secret: &PeerStaticSecret) -> Self {
        let peer_pub = secret.public_key().as_bytes();
        Self {
            peer_mac1_hash: hash(&LABEL_MAC1, peer_pub),
            peer_cookie_hash: hash(&LABEL_COOKIE, peer_pub),
            last_cookie: None,
        }
    }

    /// Generate mac1 for handshake initiation and response.
    #[inline]
    pub fn generate_mac1(&self, payload: &[u8]) -> [u8; 16] {
        mac(&self.peer_mac1_hash, payload)
    }

    /// Generate mac2 for handshake initiation and response.
    #[inline]
    pub fn generate_mac2(&self, payload: &[u8]) -> [u8; 16] {
        if self.last_cookie.is_none() || self.last_cookie.unwrap().1.elapsed() >= COOKIE_LIFETIME {
            [0u8; 16]
        } else {
            mac(&self.peer_cookie_hash, payload)
        }
    }
}

pub struct Cookie {
    secret: Mutex<Option<([u8; 32], Instant)>>,
    cookie_hash: [u8; 32],
    mac1_hash: [u8; 32],
}

impl Cookie {
    pub fn new(secret: &LocalStaticSecret) -> Self {
        let cookie_hash = hash(&LABEL_COOKIE, secret.public_key().as_bytes());
        let mac1_hash = hash(&LABEL_MAC1, secret.public_key().as_bytes());

        Self {
            secret: Mutex::new(None),
            cookie_hash,
            mac1_hash,
        }
    }

    /// Validate mac1 of the payload.
    pub fn validate_mac1(&self, payload: &[u8]) -> bool {
        let (msg, macs) = payload.split_at(payload.len() - 32);
        let (mac1, _mac2) = macs.split_at(16);

        mac1 == mac(&self.mac1_hash, msg)
    }

    /// Validate mac2 of the payload.
    pub fn validate_mac2(&self, payload: &[u8]) -> bool {
        let (msg, macs) = payload.split_at(payload.len() - 32);
        let (_mac1, mac2) = macs.split_at(16);

        mac2 == mac(&self.cookie_hash, msg)
    }

    pub fn generate_cookie_reply(&self, payload: &[u8], dst: SocketAddr) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(PACKET_SIZE);

        buf.put_u32_le(MESSAGE_TYPE_COOKIE_REPLY as _);
        buf.put_slice(&payload[4..8]); // receiver index

        let nonce = Self::gen_nonce();
        buf.put_slice(&nonce);

        let mac1 = &payload[payload.len() - 32..payload.len() - 16];
        let msg = {
            let secret = self.refresh_secret();
            let dst = Self::encode_dst_addr(dst);
            mac(&secret, &dst)
        };

        let cookie = xaead_encrypt(&self.cookie_hash, &nonce, &msg, mac1).unwrap();
        buf.put_slice(&cookie);
        buf.freeze().to_vec()
    }

    // Refresh the secret if it's expired.
    fn refresh_secret(&self) -> [u8; 32] {
        let mut secret = self.secret.lock().unwrap();
        if let Some(v) = secret.as_ref() {
            if v.1.elapsed() < COOKIE_LIFETIME {
                return v.0;
            }
        }

        let mut rv = [0u8; 32];
        OsRng.fill_bytes(&mut rv);
        secret.replace((rv, Instant::now()));
        rv
    }

    #[inline]
    fn gen_nonce() -> [u8; 24] {
        let mut b = [0u8; 24];
        OsRng.fill_bytes(&mut b);
        b
    }

    #[inline]
    fn encode_dst_addr(addr: SocketAddr) -> Vec<u8> {
        let mut bytes = vec![];
        match addr {
            SocketAddr::V4(addr) => {
                bytes.extend_from_slice(&addr.ip().octets());
                bytes.extend_from_slice(&addr.port().to_le_bytes());
            }
            SocketAddr::V6(addr) => {
                bytes.extend_from_slice(&addr.ip().octets());
                bytes.extend_from_slice(&addr.port().to_le_bytes());
            }
        };
        bytes
    }
}

#[test]
fn test() {
    let x: &[u8] = &[1, 2, 3];
    let y: [u8; 3] = [1, 2, 3];
    assert_eq!(x, y);
    assert!(x == y);
}
