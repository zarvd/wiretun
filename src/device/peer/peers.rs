use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;

use super::session::{Session, SessionManager};
use super::{Peer, PeerMetrics};
use crate::device::outbound::Endpoint;
use crate::noise::crypto::LocalStaticSecret;
use crate::Tun;

pub(crate) struct Peers<T>
where
    T: Tun + 'static,
{
    tun: T,
    secret: LocalStaticSecret,
    session_mgr: SessionManager,
    by_static_public_key: RwLock<HashMap<[u8; 32], Peer<T>>>,
    by_allowed_ips: RwLock<HashMap<IpAddr, Peer<T>>>,
}

impl<T> Peers<T>
where
    T: Tun + 'static,
{
    pub fn new(tun: T, secret: LocalStaticSecret) -> Self {
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
        allowed_ips: &[(IpAddr, u8)],
        endpoint: Option<Endpoint>,
    ) -> Peer<T> {
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
        for (ip, _mask) in allowed_ips {
            // FIXME: should store the mask as well
            by_allowed_ips.insert(*ip, peer.clone());
        }

        peer.clone()
    }

    /// Returns the peer that matches the given public key.
    pub fn by_static_public_key(&self, public_key: &[u8; 32]) -> Option<Peer<T>> {
        let index = self.by_static_public_key.read().unwrap();
        index.get(public_key).cloned()
    }

    /// Returns the peer that matches the given IP address.
    pub fn by_allow_ip(&self, ip: IpAddr) -> Option<Peer<T>> {
        let index = self.by_allowed_ips.read().unwrap();
        index.get(&ip).cloned()
    }

    /// Returns the peer that matches the index of the session.
    pub fn by_index(&self, i: u32) -> Option<(Session, Peer<T>)> {
        match self.session_mgr.get_by_index(i) {
            Some((session, pub_key)) => self
                .by_static_public_key(&pub_key)
                .map(|peer| (session, peer)),
            None => None,
        }
    }

    pub fn metrics(&self) -> HashMap<[u8; 32], PeerMetrics> {
        let rv = self.by_static_public_key.read().unwrap().clone();
        rv.into_iter()
            .map(|(pub_key, peer)| (pub_key, peer.metrics()))
            .collect()
    }
}

impl<T> Drop for Peers<T>
where
    T: Tun + 'static,
{
    fn drop(&mut self) {
        for peer in self.by_static_public_key.write().unwrap().values() {
            peer.stop();
        }
    }
}
