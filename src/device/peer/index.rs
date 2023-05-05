use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::cidr::{Cidr, CidrTable};
use super::session::{Session, SessionIndex};
use super::{Peer, PeerHandle, PeerMetrics};
use crate::device::inbound::{Endpoint, Transport};
use crate::noise::crypto::PeerStaticSecret;
use crate::{PeerConfig, Tun};

struct PeerEntry<T, I>
where
    T: Tun + 'static,
    I: Transport,
{
    peer: Arc<Peer<T, I>>,
    allowed_ips: HashSet<Cidr>,
    #[allow(unused)]
    handle: PeerHandle,
}

pub(crate) struct PeerIndex<T, I>
where
    T: Tun + 'static,
    I: Transport,
{
    token: CancellationToken,
    tun: T,
    sessions: SessionIndex,
    peers: HashMap<[u8; 32], PeerEntry<T, I>>,
    ips: CidrTable<Arc<Peer<T, I>>>,
}

impl<T, I> PeerIndex<T, I>
where
    T: Tun + 'static,
    I: Transport,
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
    pub fn get_by_key(&self, public_key: &[u8; 32]) -> Option<Arc<Peer<T, I>>> {
        self.peers.get(public_key).map(|e| Arc::clone(&e.peer))
    }

    /// Returns the peer that matches the given IP address.
    pub fn get_by_ip(&self, ip: IpAddr) -> Option<Arc<Peer<T, I>>> {
        self.ips.get_by_ip(ip).cloned()
    }

    /// Returns the peer that matches the index of the session.
    pub fn get_session_by_index(&self, i: u32) -> Option<(Session, Arc<Peer<T, I>>)> {
        match self.sessions.get_by_index(i) {
            Some(session) => self
                .get_by_key(session.secret().public_key().as_bytes())
                .map(|peer| (session, peer)),
            None => None,
        }
    }

    #[inline]
    pub fn all(&self) -> Vec<Arc<Peer<T, I>>> {
        self.peers
            .values()
            .map(|entry| Arc::clone(&entry.peer))
            .collect()
    }

    pub fn insert(
        &mut self,
        secret: PeerStaticSecret,
        allowed_ips: HashSet<Cidr>,
        endpoint: Option<Endpoint<I>>,
        persistent_keepalive_interval: Option<Duration>,
    ) -> Arc<Peer<T, I>> {
        let entry = self
            .peers
            .entry(secret.public_key().to_bytes())
            .or_insert_with(|| {
                let (inbound_tx, inbound_rx) = mpsc::channel(256);
                let (outbound_tx, outbound_rx) = mpsc::channel(256);
                let peer = Arc::new(Peer::new(
                    self.tun.clone(),
                    secret,
                    self.sessions.clone(),
                    endpoint,
                    inbound_tx,
                    outbound_tx,
                    persistent_keepalive_interval,
                ));
                let handle = PeerHandle::spawn(
                    self.token.child_token(),
                    Arc::clone(&peer),
                    inbound_rx,
                    outbound_rx,
                );
                PeerEntry {
                    peer,
                    allowed_ips,
                    handle,
                }
            });

        for &cidr in &entry.allowed_ips {
            self.ips.insert(cidr, Arc::clone(&entry.peer));
        }

        Arc::clone(&entry.peer)
    }

    pub fn update_allowed_ips_by_key(
        &mut self,
        public_key: &[u8; 32],
        allowed_ips: HashSet<Cidr>,
    ) -> bool {
        if let Some(entry) = self.peers.get_mut(public_key) {
            if entry.allowed_ips == allowed_ips {
                return false;
            }
            for cidr in &entry.allowed_ips {
                self.ips.remove(cidr);
            }
            for cidr in allowed_ips.clone() {
                self.ips.insert(cidr, Arc::clone(&entry.peer));
            }
            entry.allowed_ips = allowed_ips;
            true
        } else {
            false
        }
    }

    pub fn remove_by_key(&mut self, public_key: &[u8; 32]) {
        if let Some(entry) = self.peers.remove(public_key) {
            tokio::spawn(entry.handle.cancel(Duration::from_secs(5)));
            for cidr in entry.allowed_ips {
                self.ips.remove(&cidr);
            }
            self.sessions.remove_by_key(public_key);
        }
    }

    pub fn clear(&mut self) {
        self.peers.drain().for_each(|(_, entry)| {
            tokio::spawn(entry.handle.cancel(Duration::from_secs(5)));
        });
        self.ips.clear();
        self.sessions.clear();
    }

    pub fn to_config(&self) -> Vec<PeerConfig> {
        self.peers
            .values()
            .map(|entry| PeerConfig {
                public_key: entry.peer.secret().public_key().to_bytes(),
                allowed_ips: entry.allowed_ips.clone(),
                endpoint: entry.peer.endpoint().map(|endpoint| endpoint.dst()),
                preshared_key: Some(*entry.peer.secret().psk()),
                persistent_keepalive: None,
            })
            .collect()
    }
}

impl<T, P> Drop for PeerIndex<T, P>
where
    T: Tun + 'static,
    P: Transport,
{
    fn drop(&mut self) {
        self.token.cancel();
    }
}
