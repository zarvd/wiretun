use bytes::{BufMut, BytesMut};

use super::{Cookie, IncomingInitiation, OutgoingInitiation};
use crate::noise::protocol::HandshakeResponse;
use crate::noise::{
    crypto::{
        aead_decrypt, aead_encrypt, gen_ephemeral_key, hash, kdf1, kdf3, EphermealPrivateKey,
        PeerStaticSecret, PublicKey,
    },
    Error,
};

const MESSAGE_TYPE_HANDSHAKE_RESPONSE: u8 = 2u8;
const PACKET_SIZE: usize = 92;

pub struct OutgoingResponse {
    pub hash: [u8; 32],
    pub chaining_key: [u8; 32],
    pub ephemeral_private_key: EphermealPrivateKey,
}

impl OutgoingResponse {
    pub fn new(
        initiation: &IncomingInitiation,
        local_index: u32,
        secret: &PeerStaticSecret,
        cookie: &mut Cookie,
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
        buf.put_slice(&cookie.generate_mac1(&buf)); // 16 bytes
        buf.put_slice(&cookie.generate_mac2(&buf)); // 16 bytes

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

pub struct IncomingResponse {
    pub index: u32,
    pub ephemeral_public_key: PublicKey,
    pub hash: [u8; 32],
    pub chaining_key: [u8; 32],
}

impl IncomingResponse {
    pub fn parse(
        initiation: &OutgoingInitiation,
        secret: &PeerStaticSecret,
        packet: &HandshakeResponse,
    ) -> Result<Self, Error> {
        let peer_ephemeral_pub = PublicKey::from(packet.ephemeral_public_key);
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
