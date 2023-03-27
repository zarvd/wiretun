use bytes::{BufMut, BytesMut};

use super::{CONSTRUCTION, IDENTIFIER, LABEL_MAC1};
use crate::noise::crypto::{EphermealPrivateKey, LocalStaticSecret, PeerStaticSecret, PublicKey};
use crate::noise::protocol::HandshakeInitiation;
use crate::noise::{
    crypto::{aead_decrypt, aead_encrypt, gen_ephemeral_key, hash, kdf1, kdf2, mac},
    timestamp::Timestamp,
    Error,
};

const MESSAGE_TYPE_HANDSHAKE_INITIATION: u8 = 1u8;
const PACKET_SIZE: usize = 148;

pub struct OutgoingInitiation {
    pub index: u32,
    pub hash: [u8; 32],
    pub chaining_key: [u8; 32],
    pub ephemeral_private_key: EphermealPrivateKey,
}

impl OutgoingInitiation {
    pub fn new(sender_index: u32, secret: &PeerStaticSecret) -> (Self, Vec<u8>) {
        let mut buf = BytesMut::with_capacity(PACKET_SIZE);

        buf.put_u32_le(MESSAGE_TYPE_HANDSHAKE_INITIATION as _);
        buf.put_u32_le(sender_index);

        let c = hash(&CONSTRUCTION, b"");
        let h = hash(&hash(&c, &IDENTIFIER), secret.public_key().as_bytes());
        let (ephemeral_pri, ephemeral_pub) = gen_ephemeral_key();
        let c = kdf1(ephemeral_pub.as_bytes(), &c);
        buf.put_slice(ephemeral_pub.as_bytes()); // 32 bytes
        let h = hash(&h, ephemeral_pub.as_bytes());
        let (c, k) = kdf2(
            ephemeral_pri.diffie_hellman(secret.public_key()).as_bytes(),
            &c,
        );
        let static_key = aead_encrypt(&k, 0, secret.local().public_key().as_bytes(), &h).unwrap();
        buf.put_slice(&static_key); // 32 + 16 bytes
        let h = hash(&h, &static_key);
        let (c, k) = kdf2(
            &c,
            secret
                .local()
                .private_key()
                .diffie_hellman(secret.public_key())
                .as_bytes(),
        );
        let timestamp = aead_encrypt(&k, 0, Timestamp::now().as_bytes(), &h).unwrap();
        buf.put_slice(&timestamp); // 12 + 16 bytes
        let h = hash(&h, &timestamp);

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
                index: sender_index,
                hash: h,
                chaining_key: c,
                ephemeral_private_key: ephemeral_pri,
            },
            payload,
        )
    }
}

#[derive(Debug)]
pub struct IncomingInitiation {
    pub index: u32,
    pub hash: [u8; 32],
    pub chaining_key: [u8; 32],
    pub timestamp: Timestamp,
    pub ephemeral_public_key: PublicKey,
    pub static_public_key: PublicKey,
}

impl IncomingInitiation {
    pub fn parse(secret: &LocalStaticSecret, packet: &HandshakeInitiation) -> Result<Self, Error> {
        let c = hash(&CONSTRUCTION, b"");
        let h = hash(&hash(&c, &IDENTIFIER), secret.public_key().as_bytes());
        let peer_ephemeral_pub = PublicKey::from(packet.ephemeral_public_key);
        let c = kdf1(&packet.ephemeral_public_key, &c);
        let h = hash(&h, &packet.ephemeral_public_key);
        let (c, k) = kdf2(
            secret
                .private_key()
                .diffie_hellman(&peer_ephemeral_pub)
                .as_bytes(),
            &c,
        );
        let static_key: [u8; 32] = aead_decrypt(&k, 0, &packet.static_public_key, &h)?
            .try_into()
            .unwrap();
        let peer_static_pub = PublicKey::from(static_key);

        let h = hash(&h, &packet.static_public_key);
        let (c, k) = kdf2(
            &c,
            secret
                .private_key()
                .diffie_hellman(&peer_static_pub)
                .as_bytes(),
        );
        let timestamp: [u8; 12] = aead_decrypt(&k, 0, &packet.timestamp, &h)?
            .try_into()
            .unwrap();
        let timestamp = Timestamp::from(timestamp);
        let h = hash(&h, &packet.timestamp);
        Ok(Self {
            index: packet.sender_index,
            hash: h,
            chaining_key: c,
            timestamp,
            ephemeral_public_key: peer_ephemeral_pub,
            static_public_key: peer_static_pub,
        })
    }

    pub fn index(&self) -> u32 {
        self.index
    }
}