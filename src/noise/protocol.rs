use bytes::{Buf, BufMut, Bytes, BytesMut};
use x25519_dalek::{PublicKey, ReusableSecret, StaticSecret};

use super::crypto::{aead_decrypt, aead_encrypt, gen_ephemeral_key, hash, kdf1, kdf2, kdf3, mac};
use super::timestamp::Timestamp;
use super::Error;

const CONSTRUCTION: [u8; 37] = *b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: [u8; 34] = *b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: [u8; 8] = *b"mac1----";
const LABEL_COOKIE: [u8; 8] = *b"cookie--";

const MESSAGE_TYPE_HANDSHAKE_INITIATION: u8 = 1u8;
const MESSAGE_TYPE_HANDSHAKE_RESPONSE: u8 = 2u8;
const MESSAGE_TYPE_COOKIE_REPLY: u8 = 3u8;
const MESSAGE_TYPE_TRANSPORT_DATA: u8 = 4u8;

const HANDSHAKE_INITIATION_SIZE: usize = 148;

#[derive(Debug)]
pub enum Message {
    HandshakeInitiation { packet: Vec<u8> },
    HandshakeResponse { packet: Vec<u8> },
    CookieReply { packet: Vec<u8> },
    TransportData { packet: Vec<u8> },
}

pub struct HandshakeInitiationPacket {
    sender_index: u32,
    ephemeral_pub: [u8; 32],
    static_key: [u8; 48],
    timestamp: [u8; 28],
    mac1: [u8; 16],
    mac2: [u8; 16],
}

impl HandshakeInitiationPacket {
    pub fn try_parse(payload: &[u8]) -> Result<Self, Error> {
        if payload.len() != HANDSHAKE_INITIATION_SIZE {
            return Err(Error::InvalidKeyLength); // FIXME
        }
        if payload[0..4] != [MESSAGE_TYPE_HANDSHAKE_INITIATION, 0, 0, 0] {
            return Err(Error::InvalidKeyLength); // FIXME
        }

        Ok(Self {
            sender_index: u32::from_le_bytes(payload[4..8].try_into().unwrap()),
            ephemeral_pub: payload[8..40].try_into().unwrap(),
            static_key: payload[40..88].try_into().unwrap(),
            timestamp: payload[88..116].try_into().unwrap(),
            mac1: payload[116..132].try_into().unwrap(),
            mac2: payload[132..148].try_into().unwrap(),
        })
    }
}

// HandshakeInitiation represents the handshake initiation message that is sent by us.
pub struct HandshakeInitiation {
    hash: [u8; 32],
    chaining_key: [u8; 32],
    ephemeral_private_key: ReusableSecret,
    payload: Vec<u8>,
}

impl HandshakeInitiation {
    pub fn new(
        sender_index: u32,
        local_cert: (StaticSecret, PublicKey),
        peer_static_pub: PublicKey,
    ) -> Self {
        let mut buf = BytesMut::with_capacity(4 + 4 + 32 + (32 + 16) + (12 + 16) + 16 + 16);

        buf.put_u32_le(MESSAGE_TYPE_HANDSHAKE_INITIATION as _);
        buf.put_u32_le(sender_index);

        let ci = hash(&CONSTRUCTION, b"");
        let hi = hash(&hash(&ci, &IDENTIFIER), peer_static_pub.as_bytes());
        let (ephemeral_pri, ephemeral_pub) = gen_ephemeral_key();
        let ci = kdf1(ephemeral_pub.as_bytes(), &ci);
        buf.put_slice(ephemeral_pub.as_bytes()); // 32 bytes
        let hi = hash(&hi, ephemeral_pub.as_bytes());
        let (ci, k) = kdf2(
            ephemeral_pri.diffie_hellman(&peer_static_pub).as_bytes(),
            &ci,
        );
        let static_key = aead_encrypt(&k, 0, local_cert.1.as_bytes(), &hi).unwrap();
        buf.put_slice(&static_key); // 32 + 16 bytes
        let hi = hash(&hi, &static_key);
        let (ci, k) = kdf2(
            &ci,
            local_cert.0.diffie_hellman(&peer_static_pub).as_bytes(),
        );
        let timestamp = aead_encrypt(&k, 0, Timestamp::now().as_bytes(), &hi).unwrap();
        buf.put_slice(&timestamp); // 12 + 16 bytes
        let hi = hash(&hi, &timestamp);

        // mac1 and mac2
        let mac1 = mac(&hash(&LABEL_MAC1, local_cert.1.as_bytes()), &buf);
        buf.put_slice(&mac1); // 16 bytes
        let mac2 = [0u8; 16]; // TODO: calculate with cookie
        buf.put_slice(&mac2); // 16 bytes

        let payload = buf.freeze().to_vec();

        Self {
            hash: hi,
            chaining_key: ci,
            ephemeral_private_key: ephemeral_pri,
            payload,
        }
    }
}

// PeerHandshakeInitiation represents the handshake initiation message that is sent by peer.
pub struct PeerHandshakeInitiation {
    index: u32,
    hash: [u8; 32],
    chaining_key: [u8; 32],
    ephemeral_public_key: PublicKey,
}

impl PeerHandshakeInitiation {
    pub fn parse(
        data: Vec<u8>,
        local_cert: (StaticSecret, PublicKey),
        peer_static_pub: PublicKey,
        packet: HandshakeInitiationPacket,
    ) -> Result<(Self, Vec<u8>), Error> {
        let ci = hash(&CONSTRUCTION, b"");
        let hi = hash(&hash(&ci, &IDENTIFIER), local_cert.1.as_bytes());
        let peer_ephemeral_pub = PublicKey::from(packet.ephemeral_pub);
        let ci = kdf1(&packet.ephemeral_pub, &ci);
        let hi = hash(&hi, &packet.ephemeral_pub);
        let (ci, k) = kdf2(
            local_cert.0.diffie_hellman(&peer_ephemeral_pub).as_bytes(),
            &ci,
        );
        let static_key = aead_decrypt(&k, 0, &packet.static_key, &hi)?;
        let hi = hash(&hi, &packet.static_key);
        let (ci, k) = kdf2(
            &ci,
            local_cert.0.diffie_hellman(&peer_static_pub).as_bytes(),
        );
        let timestamp = aead_decrypt(&k, 0, &packet.timestamp, &hi)?;
        Err(Error::InvalidKeyLength) // TODO
    }
}

pub struct HandshakeResponse {
    hash: [u8; 32],
    chaining_key: [u8; 32],
    ephemeral_private_key: ReusableSecret,
    payload: Vec<u8>,
}

impl HandshakeResponse {
    pub fn new(
        local_index: u32,
        static_pub: StaticSecret,
        peer_static_pub: PublicKey,
        preshared_key: [u8; 32],
        PeerHandshakeInitiation {
            index: peer_index,
            ephemeral_public_key: peer_ephemeral_pub,
            hash: hi,
            chaining_key: ci,
        }: PeerHandshakeInitiation,
    ) -> Self {
        let mut buf = BytesMut::with_capacity(4 + 4 + 4 + 32 + 16 + 16 + 16);

        buf.put_u32_le(MESSAGE_TYPE_HANDSHAKE_RESPONSE as _);
        buf.put_u32_le(local_index);
        buf.put_u32_le(peer_index);
        let (ephemeral_pri, ephemeral_pub) = gen_ephemeral_key();
        buf.put_slice(ephemeral_pub.as_bytes()); // 32 bytes
        let hr = hash(&hi, ephemeral_pub.as_bytes());
        let cr = kdf1(
            ephemeral_pri.diffie_hellman(&peer_ephemeral_pub).as_bytes(),
            &ci,
        );
        let cr = kdf1(
            ephemeral_pri.diffie_hellman(&peer_static_pub).as_bytes(),
            &cr,
        );
        let (cr, t, k) = kdf3(&preshared_key, &cr);
        let hr = hash(&hr, &t);
        let empty = aead_encrypt(&k, 0, &[], &hr).unwrap();
        buf.put_slice(&empty); // 16 bytes
        let hr = hash(&hr, &empty);

        // mac1 and mac2
        let mac1 = mac(&hash(&LABEL_MAC1, &static_pub.to_bytes()), &buf);
        buf.put_slice(&mac1); // 16 bytes
        let mac2 = [0u8; 16]; // TODO: calculate with cookie
        buf.put_slice(&mac2); // 16 bytes

        let payload = buf.freeze().to_vec();

        Self {
            hash: hi,
            chaining_key: ci,
            ephemeral_private_key: ephemeral_pri,
            payload,
        }
    }
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
