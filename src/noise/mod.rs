mod crypto;
mod timestamp;

use bytes::{BufMut, Bytes, BytesMut};

const CONSTRUCTION: [u8; 37] = *b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: [u8; 34] = *b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: [u8; 8] = *b"mac1----";
const LABEL_COOKIE: [u8; 8] = *b"cookie--";

const MESSAGE_TYPE_HANDSHAKE_INITIATION: u8 = 1u8;
const MESSAGE_TYPE_HANDSHAKE_RESPONSE: u8 = 2u8;
const MESSAGE_TYPE_COOKIE_REPLY: u8 = 3u8;
const MESSAGE_TYPE_TRANSPORT_DATA: u8 = 4u8;

struct HandshakeInitiation {
    sender_index: u32,
    ephemeral_key: [u8; 32],
    static_key: [u8; 32 + 16],
    timestamp: [u8; 12 + 16],
    mac1: [u8; 16],
    mac2: [u8; 16],
}

impl Into<Bytes> for HandshakeInitiation {
    fn into(self) -> Bytes {
        let mut buf = BytesMut::with_capacity(4 + 4 + 32 + 32 + 12 + 16 + 16 + 16);
        buf.put_u32_le(MESSAGE_TYPE_HANDSHAKE_INITIATION as _);
        buf.put_u32_le(self.sender_index);
        buf.put_slice(&self.ephemeral_key);
        buf.put_slice(&self.static_key);
        buf.put_slice(&self.timestamp);
        buf.put_slice(&self.mac1);
        buf.put_slice(&self.mac2);
        buf.freeze()
    }
}

struct HandshakeResponse {
    sender_index: u32,
    receiver_index: u32,
    ephemeral_key: [u8; 32],
    mac1: [u8; 16],
    mac2: [u8; 16],
}

struct CookieReply {
    receiver_index: u32,
    nonce: Bytes,
    cookie: Bytes,
}

struct TransportData {
    receiver_index: u32,
    counter: u64,
    packet: Bytes,
}
