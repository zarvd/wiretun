pub mod handshake;
mod peer;
mod peers;
mod session;

pub use peer::Peer;
pub use peers::Peers;
pub use session::Session;

use tokio::sync::mpsc;

use crate::noise::handshake::IncomingInitiation;
use crate::noise::protocol;

#[derive(Debug)]
enum OutboundEvent {
    Data(Vec<u8>),
}

#[derive(Debug)]
enum InboundEvent {
    HanshakeInitiation(IncomingInitiation),
    HandshakeResponse(protocol::HandshakeResponse),
    CookieReply(protocol::CookieReply),
    TransportData(protocol::TransportData),
}

type InboundTx = mpsc::Sender<InboundEvent>;
type InboundRx = mpsc::Receiver<InboundEvent>;
type OutboundTx = mpsc::Sender<OutboundEvent>;
type OutboundRx = mpsc::Receiver<OutboundEvent>;
