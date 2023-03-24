use std::collections::HashMap;
use std::sync::{atomic::AtomicBool, Arc, RwLock};

use bytes::Bytes;
use tracing::{debug, error};

use crate::{device::Peer, Tun};

const MAX_PEERS: usize = 1 << 16;

type PublicKey = [u8; 32];

struct Inner {
    running: AtomicBool,
    tun: Tun,
    peers: RwLock<HashMap<PublicKey, Peer>>,
    allowed_ips: RwLock<HashMap<Bytes, Peer>>,
}

pub struct Device {
    inner: Arc<Inner>,
}

impl Device {
    pub fn insert_peer(&self, public_key: PublicKey) -> Result<(), Error> {
        let peers = self.inner.peers.write().unwrap();
        if peers.len() > MAX_PEERS {
            return Err(Error::TooManyPeers);
        }
        if peers.contains_key(&public_key) {
            return Err(Error::PeerAlreadyExists);
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn run_outbound_loop(&mut self) {
        const IPV4_HEADER_LEN: usize = 20;
        const IPV6_HEADER_LEN: usize = 40;

        // read from TUN -> encrypt -> send to peer
        loop {
            match self.inner.tun.read().await {
                Ok(buf) => {
                    let dst = {
                        match buf[0] & 0xF0 {
                            0x40 if buf.len() < IPV4_HEADER_LEN => continue,
                            0x40 => &buf[16..20],
                            0x60 if buf.len() < IPV6_HEADER_LEN => continue,
                            0x60 => &buf[24..40],
                            n => {
                                debug!("unknown IP version: {}", n);
                                continue;
                            }
                        }
                    };

                    let peer = {
                        let allowed_ips = self.inner.allowed_ips.read().unwrap();
                        allowed_ips.get(&Bytes::copy_from_slice(dst)).cloned()
                    };

                    if let Some(mut peer) = peer {
                        peer.stage_outbound(buf).await
                    }
                }
                Err(e) => {
                    error!("TUN read error: {}", e)
                }
            }
        }
    }

    fn run_inbound_loop() {
        // read from peer -> decrypt -> send to TUN
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Too many peers")]
    TooManyPeers,
    #[error("Peer already exists")]
    PeerAlreadyExists,
}
