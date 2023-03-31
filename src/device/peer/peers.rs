use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::RwLock;

use super::cidr::{Cidr, CidrTable};
use super::session::{Session, SessionManager};
use super::{Peer, PeerMetrics};
use crate::device::outbound::Endpoint;
use crate::noise::crypto::LocalStaticSecret;
use crate::Tun;

#[derive(Clone)]
struct PeerEntry<T>
where
    T: Tun + 'static,
{
    peer: Peer<T>,
    allowed_ips: HashSet<Cidr>,
}

pub(crate) struct Peers<T>
where
    T: Tun + 'static,
{
    tun: T,
    secret: LocalStaticSecret,
    session_mgr: SessionManager,
    by_static_public_key: RwLock<HashMap<[u8; 32], PeerEntry<T>>>,
    by_allowed_ips: RwLock<CidrTable<Peer<T>>>,
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
            by_allowed_ips: RwLock::new(CidrTable::new()),
            session_mgr: SessionManager::new(),
        }
    }

    pub fn insert(
        &self,
        public_key: [u8; 32],
        allowed_ips: Vec<Cidr>,
        endpoint: Option<Endpoint>,
    ) -> Peer<T> {
        let mut by_static_public_key = self.by_static_public_key.write().unwrap();
        let entry = by_static_public_key.entry(public_key).or_insert_with(|| {
            let p = Peer::new(
                self.tun.clone(),
                self.secret.clone().with_peer(public_key),
                self.session_mgr.clone(),
                endpoint,
            );
            PeerEntry {
                peer: p,
                allowed_ips: allowed_ips.clone().into_iter().collect(),
            }
        });

        let mut by_allowed_ips = self.by_allowed_ips.write().unwrap();
        for cidr in allowed_ips {
            by_allowed_ips.insert(cidr, entry.peer.clone());
        }

        entry.peer.clone()
    }

    /// Returns the peer that matches the given public key.
    pub fn get_by_key(&self, public_key: &[u8; 32]) -> Option<Peer<T>> {
        let index = self.by_static_public_key.read().unwrap();
        index.get(public_key).cloned().map(|e| e.peer)
    }

    /// Returns the peer that matches the given IP address.
    pub fn get_by_allow_ip(&self, ip: IpAddr) -> Option<Peer<T>> {
        let index = self.by_allowed_ips.read().unwrap();
        index.get_by_ip(ip).cloned()
    }

    /// Returns the peer that matches the index of the session.
    pub fn get_session_by_index(&self, i: u32) -> Option<(Session, Peer<T>)> {
        match self.session_mgr.get_by_index(i) {
            Some((session, pub_key)) => self.get_by_key(&pub_key).map(|peer| (session, peer)),
            None => None,
        }
    }

    pub fn update_allowed_ips_by_key(&self, public_key: &[u8; 32], allowed_ips: Vec<Cidr>) -> bool {
        let allowed_ips = allowed_ips.into_iter().collect();

        let mut by_static_public_key = self.by_static_public_key.write().unwrap();
        match by_static_public_key.get_mut(public_key) {
            Some(entry) => {
                if entry.allowed_ips == allowed_ips {
                    return false;
                }
                let mut by_allowed_ips = self.by_allowed_ips.write().unwrap();
                by_allowed_ips.clear();
                for cidr in allowed_ips.clone() {
                    by_allowed_ips.insert(cidr, entry.peer.clone());
                }
                entry.allowed_ips = allowed_ips;
                true
            }
            None => false,
        }
    }

    pub fn remove_by_key(&self, public_key: &[u8; 32]) {
        let mut by_static_public_key = self.by_static_public_key.write().unwrap();
        if let Some(entry) = by_static_public_key.remove(public_key) {
            entry.peer.stop();

            {
                let mut by_allowed_ips = self.by_allowed_ips.write().unwrap();
                for cidr in entry.allowed_ips {
                    by_allowed_ips.remove(cidr);
                }
            }

            self.session_mgr.remove_by_key(public_key);
        }
    }

    pub fn clear(&self) {
        let mut by_static_public_key = self.by_static_public_key.write().unwrap();
        by_static_public_key
            .values()
            .for_each(|entry| entry.peer.stop());
        by_static_public_key.clear();
        let mut by_allowed_ips = self.by_allowed_ips.write().unwrap();
        by_allowed_ips.clear();
        self.session_mgr.clear();
    }

    pub fn metrics(&self) -> HashMap<[u8; 32], PeerMetrics> {
        let rv = self.by_static_public_key.read().unwrap().clone();
        rv.into_iter()
            .map(|(pub_key, entry)| (pub_key, entry.peer.metrics()))
            .collect()
    }
}

impl<T> Drop for Peers<T>
where
    T: Tun + 'static,
{
    fn drop(&mut self) {
        for entry in self.by_static_public_key.write().unwrap().values() {
            entry.peer.stop();
        }
    }
}
