pub mod handshake;
mod monitor;
mod peer;
mod peers;
mod session;

pub use monitor::PeerMetrics;
pub(crate) use peer::Peer;
pub(crate) use peers::Peers;

use tokio::sync::mpsc;

use crate::listener::Endpoint;
use crate::noise::handshake::IncomingInitiation;
use crate::noise::protocol;
use monitor::PeerMonitor;
use session::Session;

#[derive(Debug)]
enum OutboundEvent {
    Data(Vec<u8>),
    EOF,
}

#[derive(Debug)]
enum InboundEvent {
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
    EOF,
}

type InboundTx = mpsc::Sender<InboundEvent>;
type InboundRx = mpsc::Receiver<InboundEvent>;
type OutboundTx = mpsc::Sender<OutboundEvent>;
type OutboundRx = mpsc::Receiver<OutboundEvent>;
