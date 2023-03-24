mod initiation;
mod response;

pub const CONSTRUCTION: [u8; 37] = *b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const IDENTIFIER: [u8; 34] = *b"WireGuard v1 zx2c4 Jason@zx2c4.com";
pub const LABEL_MAC1: [u8; 8] = *b"mac1----";
pub const LABEL_COOKIE: [u8; 8] = *b"cookie--";

pub use initiation::{IncomingInitiation, OutgoingInitiation};
pub use response::{IncomingResponse, OutgoingResponse};

use crate::noise::crypto::kdf2;
use crate::noise::session::Session;
use x25519_dalek::{PublicKey, StaticSecret};

use super::Error;

pub struct StaticKeyPair {
    local_private: StaticSecret,
    local_public: PublicKey,
    peer_public: PublicKey,
    psk: [u8; 32], // pre-shared key
}

enum State {
    Uninit,
    Initiation(OutgoingInitiation),
    Finialized {},
}

pub struct Handshake {
    state: State,
    static_key_pair: StaticKeyPair,
    local_index: u32,
}

impl Handshake {
    pub fn new(
        local_static_private_key: StaticSecret,
        peer_static_public_key: PublicKey,
        psk: [u8; 32],
    ) -> Self {
        let local_static_public_key = PublicKey::from(&local_static_private_key);
        Self {
            state: State::Uninit,
            local_index: 0,
            static_key_pair: StaticKeyPair {
                local_private: local_static_private_key,
                local_public: local_static_public_key,
                peer_public: peer_static_public_key,
                psk,
            },
        }
    }

    pub fn initiate(&mut self) -> Vec<u8> {
        let (state, payload) = OutgoingInitiation::new(self.local_index, &self.static_key_pair);
        self.state = State::Initiation(state);
        payload
    }

    pub fn respond(&mut self, payload: &[u8]) -> Result<(Session, Vec<u8>), Error> {
        let initiation = IncomingInitiation::parse(&self.static_key_pair, payload)?;
        let (state, payload) =
            OutgoingResponse::new(&initiation, self.local_index, &self.static_key_pair);
        let (sender_nonce, receiver_nonce) = (self.local_index, initiation.index);
        let (receiver_key, sender_key) = kdf2(&[], &state.chaining_key);
        let sess = Session::new(sender_nonce, sender_key, receiver_nonce, receiver_key);
        Ok((sess, payload))
    }

    pub fn finalize(&mut self, payload: &[u8]) -> Result<Session, Error> {
        match &self.state {
            State::Initiation(initiation) => {
                let state = IncomingResponse::parse(initiation, &self.static_key_pair, payload)?;
                let (sender_nonce, receiver_nonce) = (initiation.index, state.index);
                let (sender_key, receiver_key) = kdf2(&[], &state.chaining_key);
                let sess = Session::new(sender_nonce, sender_key, receiver_nonce, receiver_key);
                Ok(sess)
            }
            _ => Err(Error::InvalidKeyLength), // FIXME
        }
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;

    #[inline]
    fn gen_2_static_key() -> (StaticKeyPair, StaticKeyPair) {
        let p1_pri = StaticSecret::new(OsRng);
        let p1_pub = PublicKey::from(&p1_pri);

        let p2_pri = StaticSecret::new(OsRng);
        let p2_pub = PublicKey::from(&p2_pri);

        let psk = StaticSecret::new(OsRng).to_bytes();

        (
            StaticKeyPair {
                local_private: p1_pri,
                local_public: p1_pub,
                peer_public: p2_pub,
                psk,
            },
            StaticKeyPair {
                local_private: p2_pri,
                local_public: p2_pub,
                peer_public: p1_pub,
                psk,
            },
        )
    }

    #[test]
    fn handshake_initiation() {
        let (p1_key, p2_key) = gen_2_static_key();
        let (p1_i, p2_i) = (42, 88);

        let (init_out, payload) = OutgoingInitiation::new(p1_i, &p1_key);
        let init_in = IncomingInitiation::parse(&p2_key, &payload).unwrap();

        assert_eq!(init_in.index(), p1_i);
        assert_eq!(init_out.hash, init_in.hash);
        assert_eq!(init_out.chaining_key, init_in.chaining_key);
    }

    #[test]
    fn handshake_response() {
        let (p1_key, p2_key) = gen_2_static_key();
        let (p1_i, p2_i) = (42, 88);

        let (init_out, payload) = OutgoingInitiation::new(p1_i, &p1_key);
        let init_in = IncomingInitiation::parse(&p2_key, &payload).unwrap();

        assert_eq!(init_out.hash, init_in.hash);
        assert_eq!(init_out.chaining_key, init_in.chaining_key);

        let (resp_out, payload) = OutgoingResponse::new(&init_in, p2_i, &p2_key);
        let resp_in = IncomingResponse::parse(&init_out, &p1_key, &payload).unwrap();

        assert_eq!(resp_in.index, p2_i);
        assert_eq!(resp_out.chaining_key, resp_in.chaining_key);
        assert_eq!(resp_out.hash, resp_in.hash);
    }

    #[test]
    fn handshake() {
        let (p1_key, p2_key) = gen_2_static_key();
        let (p1_i, p2_i) = (42, 88);

        let mut p1 = Handshake::new(p1_key.local_private, p2_key.local_public, p1_key.psk);
        let mut p2 = Handshake::new(p2_key.local_private, p1_key.local_public, p2_key.psk);
        p1.local_index = p1_i;
        p2.local_index = p2_i;

        let payload = p1.initiate();
        let (p2_sess, payload) = p2.respond(&payload).unwrap();
        let p1_sess = p1.finalize(&payload).unwrap();

        assert_eq!(p1_sess.sender_nonce(), p1_i);
        assert_eq!(p1_sess.sender_nonce(), p2_sess.receiver_nonce());
        assert_eq!(p2_sess.sender_nonce(), p2_i);
        assert_eq!(p2_sess.sender_nonce(), p1_sess.receiver_nonce());
        assert_eq!(p1_sess.sender_key(), p2_sess.receiver_key());
        assert_eq!(p2_sess.sender_key(), p1_sess.receiver_key());
    }
}
