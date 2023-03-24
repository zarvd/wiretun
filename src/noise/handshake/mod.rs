mod initiation;
mod response;

pub const CONSTRUCTION: [u8; 37] = *b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const IDENTIFIER: [u8; 34] = *b"WireGuard v1 zx2c4 Jason@zx2c4.com";
pub const LABEL_MAC1: [u8; 8] = *b"mac1----";
pub const LABEL_COOKIE: [u8; 8] = *b"cookie--";

pub use initiation::{IncomingInitiation, OutgoingInitiation};
pub use response::{IncomingResponse, OutgoingResponse};

#[cfg(test)]
mod tests {
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;

    #[inline]
    fn gen_static_key() -> (StaticSecret, PublicKey) {
        let pri_key = StaticSecret::new(OsRng);
        let pub_key = PublicKey::from(&pri_key);
        (pri_key, pub_key)
    }

    #[test]
    fn handshake_initiation() {
        let (p1_key, p1_i) = (gen_static_key(), 42);
        let (p2_key, _p2_i) = (gen_static_key(), 88);
        let (init_out, payload) = OutgoingInitiation::new(p1_i, p1_key.clone(), p2_key.1);
        let init_in = IncomingInitiation::parse(p2_key, p1_key.1, &payload).unwrap();

        assert_eq!(init_in.index(), p1_i);
        assert_eq!(init_out.hash, init_in.hash);
        assert_eq!(init_out.chaining_key, init_in.chaining_key);
    }

    #[test]
    fn handshake_response() {
        let (p1_key, p1_i) = (gen_static_key(), 42);
        let (p2_key, p2_i) = (gen_static_key(), 88);
        let psk = [0u8; 32];

        let (init_out, payload) = OutgoingInitiation::new(p1_i, p1_key.clone(), p2_key.1);
        let init_in = IncomingInitiation::parse(p2_key.clone(), p1_key.1, &payload).unwrap();

        assert_eq!(init_out.hash, init_in.hash);
        assert_eq!(init_out.chaining_key, init_in.chaining_key);

        let (resp_out, payload) = OutgoingResponse::new(p2_i, p2_key, p1_key.1, psk, init_in);
        let resp_in = IncomingResponse::parse(init_out, p1_key, psk, &payload).unwrap();
    }
}
