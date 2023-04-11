use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::RwLock;

use tokio_util::sync::CancellationToken;

use super::cidr::{Cidr, CidrTable};
use super::session::{Session, SessionIndex};
use super::{Peer, PeerMetrics};
use crate::device::inbound::Endpoint;
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

pub(crate) struct PeerIndex<T>
where
    T: Tun + 'static,
{
    token: CancellationToken,
    tun: T,
    secret: LocalStaticSecret,
    sessions: SessionIndex,
    peers: RwLock<HashMap<[u8; 32], PeerEntry<T>>>,
    ips: RwLock<CidrTable<Peer<T>>>,
}

impl<T> PeerIndex<T>
where
    T: Tun + 'static,
{
    pub fn new(token: CancellationToken, tun: T, secret: LocalStaticSecret) -> Self {
        Self {
            token,
            tun,
            secret,
            peers: RwLock::new(HashMap::new()),
            sessions: SessionIndex::new(),
            ips: RwLock::new(CidrTable::new()),
        }
    }

    pub fn insert(
        &self,
        public_key: [u8; 32],
        allowed_ips: Vec<Cidr>,
        endpoint: Option<Endpoint>,
    ) -> Peer<T> {
        let mut peers = self.peers.write().unwrap();
        let entry = peers.entry(public_key).or_insert_with(|| {
            let p = Peer::new(
                self.token.child_token(),
                self.tun.clone(),
                self.secret.clone().with_peer(public_key),
                self.sessions.clone(),
                endpoint,
            );
            PeerEntry {
                peer: p,
                allowed_ips: allowed_ips.clone().into_iter().collect(),
            }
        });

        let mut ips = self.ips.write().unwrap();
        for cidr in allowed_ips {
            ips.insert(cidr, entry.peer.clone());
        }

        entry.peer.clone()
    }

    /// Returns the peer that matches the given public key.
    pub fn get_by_key(&self, public_key: &[u8; 32]) -> Option<Peer<T>> {
        self.peers
            .read()
            .unwrap()
            .get(public_key)
            .map(|e| e.peer.clone())
    }

    /// Returns the peer that matches the given IP address.
    pub fn get_by_ip(&self, ip: IpAddr) -> Option<Peer<T>> {
        self.ips.read().unwrap().get_by_ip(ip).cloned()
    }

    /// Returns the peer that matches the index of the session.
    pub fn get_session_by_index(&self, i: u32) -> Option<(Session, Peer<T>)> {
        match self.sessions.get_by_index(i) {
            Some(session) => self
                .get_by_key(session.secret().public_key().as_bytes())
                .map(|peer| (session, peer)),
            None => None,
        }
    }

    pub fn update_allowed_ips_by_key(&self, public_key: &[u8; 32], allowed_ips: Vec<Cidr>) -> bool {
        let allowed_ips = allowed_ips.into_iter().collect();

        match self.peers.write().unwrap().get_mut(public_key) {
            Some(entry) => {
                if entry.allowed_ips == allowed_ips {
                    return false;
                }
                let mut ips = self.ips.write().unwrap();
                ips.clear();
                for cidr in allowed_ips.clone() {
                    ips.insert(cidr, entry.peer.clone());
                }
                entry.allowed_ips = allowed_ips;
                true
            }
            None => false,
        }
    }

    pub fn remove_by_key(&self, public_key: &[u8; 32]) {
        let mut peers = self.peers.write().unwrap();
        if let Some(entry) = peers.remove(public_key) {
            entry.peer.stop();

            {
                let mut ips = self.ips.write().unwrap();
                for cidr in entry.allowed_ips {
                    ips.remove(cidr);
                }
            }

            self.sessions.remove_by_key(public_key);
        }
    }

    pub fn clear(&self) {
        let mut peers = self.peers.write().unwrap();
        let mut ips = self.ips.write().unwrap();

        peers.values().for_each(|entry| entry.peer.stop());
        peers.clear();

        ips.clear();

        self.sessions.clear();
    }

    pub fn metrics(&self) -> HashMap<[u8; 32], PeerMetrics> {
        self.peers
            .read()
            .unwrap()
            .iter()
            .map(|(pub_key, entry)| (*pub_key, entry.peer.metrics()))
            .collect()
    }
}

impl<T> Drop for PeerIndex<T>
where
    T: Tun + 'static,
{
    fn drop(&mut self) {
        self.token.cancel();
    }
}
