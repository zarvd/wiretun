use std::collections::HashMap;
use std::sync::RwLock;

use bytes::Bytes;

use super::Peer;

pub struct Peers {
    by_static_public_key: RwLock<HashMap<[u8; 32], Peer>>,
    by_allowed_ips: RwLock<HashMap<Bytes, Peer>>,
}

impl Peers {
    pub fn new() -> Self {
        Self {
            by_static_public_key: RwLock::new(HashMap::new()),
            by_allowed_ips: RwLock::new(HashMap::new()),
        }
    }

    pub fn insert(&self, public_key: &[u8; 32], allowed_ips: &[Bytes]) {
        let mut by_static_public_key = self.by_static_public_key.write().unwrap();
        let peer = by_static_public_key
            .entry(*public_key)
            .or_insert_with(Peer::new);

        let mut by_allowed_ips = self.by_allowed_ips.write().unwrap();
        for allowed_ip in allowed_ips {
            by_allowed_ips.insert(allowed_ip.clone(), peer.clone());
        }
    }

    pub fn by_static_public_key(&self, public_key: &[u8; 32]) -> Option<Peer> {
        let index = self.by_static_public_key.read().unwrap();
        index.get(public_key).cloned()
    }

    pub fn by_allow_ip(&self, ip: Bytes) -> Option<Peer> {
        let index = self.by_allowed_ips.read().unwrap();
        index.get(&ip).cloned()
    }

    pub async fn start_all(&self) {
        let peers = {
            let g = self.by_static_public_key.read().unwrap();
            g.values().cloned().collect::<Vec<_>>()
        };

        for peer in peers {
            peer.start().await;
        }
    }
}
