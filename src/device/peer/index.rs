use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use tokio_util::sync::CancellationToken;

use super::cidr::{Cidr, CidrTable};
use super::session::{Session, SessionIndex};
use super::{Peer, PeerMetrics};
use crate::device::inbound::Endpoint;
use crate::noise::crypto::PeerStaticSecret;
use crate::{PeerConfig, Tun};

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
    sessions: SessionIndex,
    peers: HashMap<[u8; 32], PeerEntry<T>>,
    ips: CidrTable<Peer<T>>,
}

impl<T> PeerIndex<T>
where
    T: Tun + 'static,
{
    pub fn new(token: CancellationToken, tun: T) -> Self {
        Self {
            token,
            tun,
            peers: HashMap::new(),
            sessions: SessionIndex::new(),
            ips: CidrTable::new(),
        }
    }

    pub fn metrics(&self) -> HashMap<[u8; 32], PeerMetrics> {
        self.peers
            .iter()
            .map(|(pub_key, entry)| (*pub_key, entry.peer.metrics()))
            .collect()
    }

    /// Returns the peer that matches the given public key.
    pub fn get_by_key(&self, public_key: &[u8; 32]) -> Option<Peer<T>> {
        self.peers.get(public_key).map(|e| e.peer.clone())
    }

    /// Returns the peer that matches the given IP address.
    pub fn get_by_ip(&self, ip: IpAddr) -> Option<Peer<T>> {
        self.ips.get_by_ip(ip).cloned()
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

    pub fn insert(
        &mut self,
        secret: PeerStaticSecret,
        allowed_ips: Vec<Cidr>,
        endpoint: Option<Endpoint>,
    ) -> Peer<T> {
        let entry = self
            .peers
            .entry(secret.public_key().to_bytes())
            .or_insert_with(|| PeerEntry {
                peer: Peer::new(
                    self.token.child_token(),
                    self.tun.clone(),
                    secret,
                    self.sessions.clone(),
                    endpoint,
                ),
                allowed_ips: allowed_ips.clone().into_iter().collect(),
            });

        for cidr in allowed_ips {
            self.ips.insert(cidr, entry.peer.clone());
        }

        entry.peer.clone()
    }

    pub fn update_allowed_ips_by_key(
        &mut self,
        public_key: &[u8; 32],
        allowed_ips: Vec<Cidr>,
    ) -> bool {
        let allowed_ips = allowed_ips.into_iter().collect();

        if let Some(entry) = self.peers.get_mut(public_key) {
            if entry.allowed_ips == allowed_ips {
                return false;
            }
            for cidr in &entry.allowed_ips {
                self.ips.remove(cidr);
            }
            for cidr in allowed_ips.clone() {
                self.ips.insert(cidr, entry.peer.clone());
            }
            entry.allowed_ips = allowed_ips;
            true
        } else {
            false
        }
    }

    pub fn remove_by_key(&mut self, public_key: &[u8; 32]) {
        if let Some(entry) = self.peers.remove(public_key) {
            entry.peer.stop();

            for cidr in entry.allowed_ips {
                self.ips.remove(&cidr);
            }

            self.sessions.remove_by_key(public_key);
        }
    }

    pub fn clear(&mut self) {
        self.peers.values().for_each(|entry| entry.peer.stop());
        self.peers.clear();
        self.ips.clear();
        self.sessions.clear();
    }

    pub fn to_vec(&self) -> Vec<PeerConfig> {
        self.peers
            .values()
            .map(|entry| PeerConfig {
                public_key: entry.peer.secret().public_key().to_bytes(),
                allowed_ips: entry.allowed_ips.clone().into_iter().collect(),
                endpoint: entry.peer.endpoint().map(|endpoint| endpoint.dst()),
                preshared_key: None,
                persistent_keepalive: None,
            })
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
