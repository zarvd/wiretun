use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::RwLock;

use bytes::Bytes;
use tracing::debug;

use super::session::{Session, SessionManager};
use super::Peer;
use crate::listener::Endpoint;
use crate::noise::crypto::LocalStaticSecret;
use crate::Tun;

pub struct Peers {
    tun: Tun,
    secret: LocalStaticSecret,
    session_mgr: SessionManager,
    by_static_public_key: RwLock<HashMap<[u8; 32], Peer>>,
    by_allowed_ips: RwLock<HashMap<IpAddr, Peer>>,
}

impl Peers {
    pub fn new(tun: Tun, secret: LocalStaticSecret) -> Self {
        Self {
            tun,
            secret,
            by_static_public_key: RwLock::new(HashMap::new()),
            by_allowed_ips: RwLock::new(HashMap::new()),
            session_mgr: SessionManager::new(),
        }
    }

    pub fn insert(
        &self,
        public_key: [u8; 32],
        allowed_ips: &[IpAddr],
        endpoint: Option<Endpoint>,
    ) -> Peer {
        let mut by_static_public_key = self.by_static_public_key.write().unwrap();
        let peer = by_static_public_key.entry(public_key).or_insert_with(|| {
            Peer::new(
                self.tun.clone(),
                self.secret.clone().with_peer(public_key),
                self.session_mgr.clone(),
                endpoint,
            )
        });

        let mut by_allowed_ips = self.by_allowed_ips.write().unwrap();
        for allowed_ip in allowed_ips {
            by_allowed_ips.insert(allowed_ip.clone(), peer.clone());
        }

        peer.clone()
    }

    /// Returns the peer that matches the given public key.
    pub fn by_static_public_key(&self, public_key: &[u8; 32]) -> Option<Peer> {
        let index = self.by_static_public_key.read().unwrap();
        index.get(public_key).cloned()
    }

    /// Returns the peer that matches the given IP address.
    pub fn by_allow_ip(&self, ip: IpAddr) -> Option<Peer> {
        let index = self.by_allowed_ips.read().unwrap();
        index.get(&ip).cloned()
    }

    /// Returns the peer that matches the index of the session.
    pub fn by_index(&self, i: u32) -> Option<(Session, Peer)> {
        match self.session_mgr.get_by_index(i) {
            Some((session, pub_key)) => self
                .by_static_public_key(&pub_key)
                .map(|peer| (session, peer)),
            None => None,
        }
    }
}
