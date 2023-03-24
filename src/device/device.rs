use std::collections::HashMap;
use std::sync::RwLock;

use crate::{device::Peer, Tun};

const MAX_PEERS: usize = 1 << 16;

pub struct Device {
    tun: Tun,
    peers: RwLock<HashMap<[u8; 32], Peer>>,
}

impl Device {
    pub fn insert_peer(&self, public_key: [u8; 32]) -> Result<(), Error> {
        let peers = self.peers.write().unwrap();
        if peers.len() > MAX_PEERS {
            return Err(Error::TooManyPeers);
        }
        if peers.contains_key(&public_key) {
            return Err(Error::PeerAlreadyExists);
        }

        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Too many peers")]
    TooManyPeers,
    #[error("Peer already exists")]
    PeerAlreadyExists,
}
