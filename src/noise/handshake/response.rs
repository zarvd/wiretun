use bytes::{BufMut, BytesMut};

use super::{IncomingInitiation, OutgoingInitiation, LABEL_MAC1};
use crate::noise::{
    crypto::{
        aead_decrypt, aead_encrypt, gen_ephemeral_key, hash, kdf1, kdf3, mac, EphermealPrivateKey,
        PeerStaticSecret, PublicKey,
    },
    Error,
};

const MESSAGE_TYPE_HANDSHAKE_RESPONSE: u8 = 2u8;
const PACKET_SIZE: usize = 92;

pub struct OutgoingResponse {
    pub(super) hash: [u8; 32],
    pub(super) chaining_key: [u8; 32],
    pub(super) ephemeral_private_key: EphermealPrivateKey,
}

impl OutgoingResponse {
    pub fn new(
        initiation: &IncomingInitiation,
        local_index: u32,
        secret: &PeerStaticSecret,
    ) -> (Self, Vec<u8>) {
        let mut buf = BytesMut::with_capacity(PACKET_SIZE);

        buf.put_u32_le(MESSAGE_TYPE_HANDSHAKE_RESPONSE as _);
        buf.put_u32_le(local_index);
        buf.put_u32_le(initiation.index);
        let (ephemeral_pri, ephemeral_pub) = gen_ephemeral_key();
        buf.put_slice(ephemeral_pub.as_bytes()); // 32 bytes
        let c = kdf1(ephemeral_pub.as_bytes(), &initiation.chaining_key);
        let h = hash(&initiation.hash, ephemeral_pub.as_bytes());
        let c = kdf1(
            ephemeral_pri
                .diffie_hellman(&initiation.ephemeral_public_key)
                .as_bytes(),
            &c,
        );
        let c = kdf1(
            ephemeral_pri.diffie_hellman(secret.public_key()).as_bytes(),
            &c,
        );
        let (c, t, k) = kdf3(secret.psk(), &c);
        let h = hash(&h, &t);
        let empty = aead_encrypt(&k, 0, &[], &h).unwrap();
        buf.put_slice(&empty); // 16 bytes
        let h = hash(&h, &empty);

        // mac1 and mac2
        let mac1 = mac(
            &hash(&LABEL_MAC1, secret.local().public_key().as_bytes()),
            &buf,
        );
        buf.put_slice(&mac1); // 16 bytes
        let mac2 = [0u8; 16]; // TODO: calculate with cookie
        buf.put_slice(&mac2); // 16 bytes

        let payload = buf.freeze().to_vec();
        (
            Self {
                hash: h,
                chaining_key: c,
                ephemeral_private_key: ephemeral_pri,
            },
            payload,
        )
    }
}

struct Packet {
    sender_index: u32,
    receiver_index: u32,
    ephemeral_pub: [u8; 32],
    empty: [u8; 16],
    mac1: [u8; 16],
    mac2: [u8; 16],
}

impl Packet {
    pub fn parse(payload: &[u8]) -> Result<Self, Error> {
        if payload.len() != PACKET_SIZE {
            return Err(Error::InvalidKeyLength); // FIXME
        }
        if payload[0..4] != [MESSAGE_TYPE_HANDSHAKE_RESPONSE, 0, 0, 0] {
            return Err(Error::InvalidKeyLength); // FIXME
        }

        Ok(Self {
            sender_index: u32::from_le_bytes(payload[4..8].try_into().unwrap()),
            receiver_index: u32::from_le_bytes(payload[8..12].try_into().unwrap()),
            ephemeral_pub: payload[12..44].try_into().unwrap(),
            empty: payload[44..60].try_into().unwrap(),
            mac1: payload[60..76].try_into().unwrap(),
            mac2: payload[76..92].try_into().unwrap(),
        })
    }
}

pub struct IncomingResponse {
    pub(super) index: u32,
    pub(super) ephemeral_public_key: PublicKey,
    pub(super) hash: [u8; 32],
    pub(super) chaining_key: [u8; 32],
}

impl IncomingResponse {
    pub fn parse(
        initiation: &OutgoingInitiation,
        secret: &PeerStaticSecret,
        payload: &[u8],
    ) -> Result<Self, Error> {
        let packet = Packet::parse(payload)?;

        let peer_ephemeral_pub = PublicKey::from(packet.ephemeral_pub);
        let c = kdf1(peer_ephemeral_pub.as_bytes(), &initiation.chaining_key);
        let h = hash(&initiation.hash, peer_ephemeral_pub.as_bytes());
        let c = kdf1(
            initiation
                .ephemeral_private_key
                .diffie_hellman(&peer_ephemeral_pub)
                .as_bytes(),
            &c,
        );
        let c = kdf1(
            secret
                .local()
                .private_key()
                .diffie_hellman(&peer_ephemeral_pub)
                .as_bytes(),
            &c,
        );
        let (c, t, k) = kdf3(secret.psk(), &c);
        let h = hash(&h, &t);
        let empty = aead_decrypt(&k, 0, &packet.empty, &h)?;
        if !empty.is_empty() {
            return Err(Error::InvalidKeyLength); // FIXME
        }
        let h = hash(&h, &packet.empty);

        Ok(Self {
            index: packet.sender_index,
            ephemeral_public_key: peer_ephemeral_pub,
            hash: h,
            chaining_key: c,
        })
    }
}
