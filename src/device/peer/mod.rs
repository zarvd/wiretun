pub mod handshake;
mod jitter;
mod peer;
mod peers;
mod session;

pub use peer::Peer;
pub use peers::Peers;

use tokio::sync::mpsc;

use crate::listener::Endpoint;
use crate::noise::handshake::IncomingInitiation;
use crate::noise::protocol;
use jitter::Jitter;
use session::Session;

#[derive(Debug)]
enum OutboundEvent {
    Data(Vec<u8>),
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
}

type InboundTx = mpsc::Sender<InboundEvent>;
type InboundRx = mpsc::Receiver<InboundEvent>;
type OutboundTx = mpsc::Sender<OutboundEvent>;
type OutboundRx = mpsc::Receiver<OutboundEvent>;
