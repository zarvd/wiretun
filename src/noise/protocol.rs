const MESSAGE_TYPE_HANDSHAKE_INITIATION: u8 = 1u8;
const MESSAGE_TYPE_HANDSHAKE_RESPONSE: u8 = 2u8;
const MESSAGE_TYPE_COOKIE_REPLY: u8 = 3u8;
const MESSAGE_TYPE_TRANSPORT_DATA: u8 = 4u8;

const HANDSHAKE_INITIATION_SIZE: usize = 148;
const HANDSHAKE_RESPONSE_SIZE: usize = 92;

#[derive(Debug)]
pub enum Message {
    HandshakeInitiation { packet: Vec<u8> },
    HandshakeResponse { packet: Vec<u8> },
    CookieReply { packet: Vec<u8> },
    TransportData { packet: Vec<u8> },
}
