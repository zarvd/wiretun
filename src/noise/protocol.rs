use bytes::{BufMut, Bytes, BytesMut};

const CONSTRUCTION: [u8; 37] = *b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: [u8; 34] = *b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: [u8; 8] = *b"mac1----";
const LABEL_COOKIE: [u8; 8] = *b"cookie--";

const MESSAGE_TYPE_HANDSHAKE_INITIATION: u8 = 1u8;
const MESSAGE_TYPE_HANDSHAKE_RESPONSE: u8 = 2u8;
const MESSAGE_TYPE_COOKIE_REPLY: u8 = 3u8;
const MESSAGE_TYPE_TRANSPORT_DATA: u8 = 4u8;

#[derive(Debug)]
pub enum Message {
    HandshakeInitiation(HandshakeInitiation),
    HandshakeResponse(HandshakeResponse),
    CookieReply(CookieReply),
    TransportData(Bytes),
}

impl Into<Bytes> for Message {
    fn into(self) -> Bytes {
        let mut buf = BytesMut::new();
        match self {
            Message::HandshakeInitiation(m) => {
                buf.put_u32_le(MESSAGE_TYPE_HANDSHAKE_INITIATION as _);
                buf.put_u32_le(m.sender_index);
                buf.put_slice(&m.ephemeral_key);
                buf.put_slice(&m.static_key);
                buf.put_slice(&m.timestamp);
                buf.put_slice(&m.mac1);
                buf.put_slice(&m.mac2);
            }
            _ => unimplemented!(),
        }

        buf.freeze()
    }
}

impl TryFrom<Bytes> for Message {
    type Error = ();

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        todo!()
    }
}

#[derive(Debug)]
pub struct HandshakeInitiation {
    pub sender_index: u32,
    pub ephemeral_key: [u8; 32],
    pub static_key: [u8; 48],
    pub timestamp: [u8; 28],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

#[derive(Debug)]
pub struct HandshakeResponse {
    pub sender_index: u32,
    pub receiver_index: u32,
    pub ephemeral_key: [u8; 32],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

#[derive(Debug)]
pub struct CookieReply {
    pub receiver_index: u32,
    pub nonce: Bytes,
    pub cookie: Bytes,
}

#[derive(Debug)]
pub struct TransportData {
    pub receiver_index: u32,
    pub counter: u64,
    pub packet: Bytes,
}
