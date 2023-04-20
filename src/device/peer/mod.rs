mod cidr;
mod handle;
pub mod handshake;
mod index;
mod monitor;
mod session;

pub use cidr::{Cidr, ParseCidrError};
pub use monitor::PeerMetrics;

pub(crate) use handle::PeerHandle;
pub(crate) use index::PeerIndex;
pub(crate) use session::Session;

use std::fmt::{Debug, Display, Formatter};
use std::sync::RwLock;

use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::device::inbound::Endpoint;
use crate::noise::crypto;
use crate::noise::crypto::PeerStaticSecret;
use crate::noise::handshake::IncomingInitiation;
use crate::noise::protocol;
use crate::Tun;
use handshake::Handshake;
use monitor::PeerMonitor;
use session::{ActiveSession, SessionIndex};

#[derive(Debug)]
pub(crate) enum OutboundEvent {
    Data(Vec<u8>),
}

#[derive(Debug)]
pub(crate) enum InboundEvent {
    HanshakeInitiation {
        endpoint: Endpoint,
        initiation: IncomingInitiation,
    },
    HandshakeResponse {
        endpoint: Endpoint,
        packet: protocol::HandshakeResponse,
        session: Session,
    },
    CookieReply {
        endpoint: Endpoint,
        packet: protocol::CookieReply,
        session: Session,
    },
    TransportData {
        endpoint: Endpoint,
        packet: protocol::TransportData,
        session: Session,
    },
}

pub(crate) type InboundTx = mpsc::Sender<InboundEvent>;
pub(crate) type InboundRx = mpsc::Receiver<InboundEvent>;
pub(crate) type OutboundTx = mpsc::Sender<OutboundEvent>;
pub(crate) type OutboundRx = mpsc::Receiver<OutboundEvent>;

pub(crate) struct Peer<T>
where
    T: Tun,
{
    tun: T,
    secret: PeerStaticSecret,
    sessions: RwLock<ActiveSession>,
    handshake: RwLock<Handshake>,
    endpoint: RwLock<Option<Endpoint>>,
    inbound: InboundTx,
    outbound: OutboundTx,
    monitor: PeerMonitor,
}

impl<T> Peer<T>
where
    T: Tun + 'static,
{
    pub(super) fn new(
        tun: T,
        secret: PeerStaticSecret,
        session_index: SessionIndex,
        endpoint: Option<Endpoint>,
        inbound: InboundTx,
        outbound: OutboundTx,
    ) -> Self {
        let handshake = RwLock::new(Handshake::new(secret.clone(), session_index.clone()));
        let sessions = RwLock::new(ActiveSession::new(session_index));
        let monitor = PeerMonitor::new();
        let endpoint = RwLock::new(endpoint);
        Self {
            tun,
            secret,
            handshake,
            sessions,
            inbound,
            outbound,
            endpoint,
            monitor,
        }
    }

    /// Stage inbound data from tun.
    #[inline]
    pub async fn handle_inbound(&self, e: InboundEvent) {
        if let Err(e) = self.inbound.send(e).await {
            warn!("{} not able to handle inbound: {}", self, e);
        }
    }

    /// Stage outbound data to be sent to the peer
    #[inline]
    pub async fn stage_outbound(&self, buf: Vec<u8>) {
        if let Err(e) = self.outbound.send(OutboundEvent::Data(buf)).await {
            warn!("{} not able to stage outbound: {}", self, e);
        }
    }

    /// Send keepalive packet to the peer if the traffic is idle.
    #[inline]
    pub async fn keepalive(&self) {
        if !self.monitor.can_keepalive() {
            return;
        }
        self.stage_outbound(vec![]).await;
    }

    /// Update the endpoint of the peer.
    /// Could be called by IPC or the inbound loop.
    #[inline]
    pub fn update_endpoint(&self, endpoint: Endpoint) {
        let mut guard = self.endpoint.write().unwrap();
        let _ = guard.insert(endpoint);
    }

    #[inline]
    pub fn endpoint(&self) -> Option<Endpoint> {
        let endpoint = self.endpoint.read().unwrap();
        endpoint.clone()
    }

    #[inline]
    pub fn metrics(&self) -> PeerMetrics {
        self.monitor.metrics()
    }

    #[inline]
    pub fn secret(&self) -> PeerStaticSecret {
        self.secret.clone()
    }

    // send outbound data
    #[inline]
    async fn send_outbound(&self, buf: &[u8]) {
        let endpoint = { self.endpoint.read().unwrap().clone() };
        if let Some(endpoint) = endpoint {
            endpoint.send(buf).await.unwrap();
        } else {
            debug!("no endpoint to send outbound packet to peer {self}");
        }
    }
}

impl<T> Display for Peer<T>
where
    T: Tun + 'static,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Peer({})",
            crypto::encode_to_hex(self.secret.public_key().as_bytes())
        )
    }
}

impl<T> Debug for Peer<T>
where
    T: Tun + 'static,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field(
                "public_key",
                &crypto::encode_to_hex(self.secret.public_key().as_bytes()),
            )
            .finish()
    }
}
