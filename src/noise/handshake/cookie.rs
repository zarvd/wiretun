use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};

use super::{LABEL_COOKIE, LABEL_MAC1};
use crate::noise::crypto::{hash, mac, xaead_encrypt, PeerStaticSecret};
use crate::noise::Error;

const COOKIE_LIFETIME: Duration = Duration::from_secs(120);

pub struct Cookie {
    secret: Option<([u8; 32], Instant)>,
    local_mac1_hash: [u8; 32],   // pre-compute hash for validating mac1
    local_cookie_hash: [u8; 32], // pre-compute hash for validating cookie
    peer_mac1_hash: [u8; 32],    // pre-compute hash for generating mac1
    peer_cookie_hash: [u8; 32],  // pre-compute hash for generating cookie
    last_cookie: Option<([u8; 16], Instant)>,
}

impl Cookie {
    #[inline]
    pub fn new(secret: &PeerStaticSecret) -> Self {
        let local_pub = secret.local().public_key().as_bytes();
        let peer_pub = secret.public_key().as_bytes();
        Self {
            secret: None,
            local_mac1_hash: hash(&LABEL_MAC1, local_pub),
            local_cookie_hash: hash(&LABEL_COOKIE, local_pub),
            peer_mac1_hash: hash(&LABEL_MAC1, peer_pub),
            peer_cookie_hash: hash(&LABEL_COOKIE, peer_pub),
            last_cookie: None,
        }
    }

    pub fn validate_mac(&self, payload: &[u8]) -> Result<(), Error> {
        let (msg, macs) = payload.split_at(payload.len() - 32);
        let (mac1, _mac2) = macs.split_at(16);

        // validate mac1
        {
            let expected_mac1 = mac(&self.local_mac1_hash, msg);
            if mac1 != expected_mac1 {
                return Err(Error::InvalidMac);
            }
        }

        if !self.is_under_load() {
            return Ok(());
        }

        todo!("validate mac2 and send cookie reply if mac2 is invalid");
    }

    #[inline]
    pub fn generate_mac1(&self, payload: &[u8]) -> [u8; 16] {
        mac(&self.peer_mac1_hash, payload)
    }

    #[inline]
    pub fn generate_mac2(&self, payload: &[u8]) -> [u8; 16] {
        if self.last_cookie.is_none() || self.last_cookie.unwrap().1.elapsed() >= COOKIE_LIFETIME {
            [0u8; 16]
        } else {
            mac(&self.peer_cookie_hash, payload)
        }
    }

    pub fn generate_cookie(&mut self, payload: &[u8], dst: SocketAddr) -> [u8; 32] {
        let nonce = self.next_nonce();
        let mac1 = &payload[payload.len() - 32..payload.len() - 16];

        let msg = {
            let secret = self.refresh_secret();
            let dst = Self::encode_dst_addr(dst);
            mac(&secret, &dst)
        };

        let cookie = xaead_encrypt(&self.local_cookie_hash, &nonce, &msg, mac1).unwrap();
        cookie.try_into().unwrap()
    }

    pub fn is_under_load(&self) -> bool {
        false
    }

    #[inline]
    fn next_nonce(&self) -> [u8; 24] {
        let mut b = [0u8; 24];
        OsRng.fill_bytes(&mut b);
        b
    }

    // Refresh the secret if it's expired.
    fn refresh_secret(&mut self) -> [u8; 32] {
        if let Some(secret) = self.secret {
            if secret.1.elapsed() < COOKIE_LIFETIME {
                return secret.0;
            }
        }
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        self.secret = Some((secret, Instant::now()));
        secret
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

// TODO: introduce rate limiter
