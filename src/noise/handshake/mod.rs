mod cookie;
mod initiation;
mod response;

pub const CONSTRUCTION: [u8; 37] = *b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const IDENTIFIER: [u8; 34] = *b"WireGuard v1 zx2c4 Jason@zx2c4.com";
pub const LABEL_MAC1: [u8; 8] = *b"mac1----";
pub const LABEL_COOKIE: [u8; 8] = *b"cookie--";

pub use cookie::Cookie;
pub use initiation::{IncomingInitiation, OutgoingInitiation};
pub use response::{IncomingResponse, OutgoingResponse};

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::noise::crypto::{LocalStaticSecret, PeerStaticSecret};
    use crate::noise::protocol::{HandshakeInitiation, HandshakeResponse};

    #[inline]
    fn gen_2_static_key() -> (PeerStaticSecret, PeerStaticSecret) {
        let p1_local = LocalStaticSecret::new(x25519_dalek::StaticSecret::new(OsRng).to_bytes());
        let p2_local = LocalStaticSecret::new(x25519_dalek::StaticSecret::new(OsRng).to_bytes());
        let mut p1_secret = p1_local.clone().with_peer(p2_local.public_key().to_bytes());
        let mut p2_secret = p2_local.with_peer(p1_local.public_key().to_bytes());
        let psk = x25519_dalek::StaticSecret::new(OsRng).to_bytes();
        p1_secret.set_psk(psk);
        p2_secret.set_psk(psk);

        (p1_secret, p2_secret)
    }

    #[test]
    fn handshake_initiation() {
        let (p1_key, p2_key) = gen_2_static_key();
        let (p1_i, _p2_i) = (42, 88);
        let mut p1_cookie = Cookie::new(&p2_key);

        let (init_out, payload) = OutgoingInitiation::new(p1_i, &p1_key, &mut p1_cookie);
        let packet = HandshakeInitiation::try_from(payload.as_slice()).unwrap();
        let init_in = IncomingInitiation::parse(p2_key.local(), &packet).unwrap();

        assert_eq!(init_in.index, p1_i);
        assert_eq!(init_out.hash, init_in.hash);
        assert_eq!(init_out.chaining_key, init_in.chaining_key);
    }

    #[test]
    fn handshake_response() {
        let (p1_key, p2_key) = gen_2_static_key();
        let (p1_i, p2_i) = (42, 88);
        let mut p1_cookie = Cookie::new(&p2_key);
        let mut p2_cookie = Cookie::new(&p1_key);

        let (init_out, payload) = OutgoingInitiation::new(p1_i, &p1_key, &mut p1_cookie);
        let packet = HandshakeInitiation::try_from(payload.as_slice()).unwrap();
        let init_in = IncomingInitiation::parse(p2_key.local(), &packet).unwrap();

        assert_eq!(init_out.hash, init_in.hash);
        assert_eq!(init_out.chaining_key, init_in.chaining_key);

        let (resp_out, payload) = OutgoingResponse::new(&init_in, p2_i, &p2_key, &mut p2_cookie);
        let packet = HandshakeResponse::try_from(payload.as_slice()).unwrap();
        let resp_in = IncomingResponse::parse(&init_out, &p1_key, &packet).unwrap();

        assert_eq!(resp_in.index, p2_i);
        assert_eq!(resp_out.chaining_key, resp_in.chaining_key);
        assert_eq!(resp_out.hash, resp_in.hash);
    }

    // #[test]
    // fn handshake() {
    //     let (p1_key, p2_key) = gen_2_static_key();
    //     let (p1_i, p2_i) = (42, 88);
    //
    //     let mut p1 = Handshake::new(p1_key);
    //     let mut p2 = Handshake::new(p2_key);
    //     p1.local_index = p1_i;
    //     p2.local_index = p2_i;
    //
    //     let payload = p1.initiate();
    //     let (p2_sess, payload) = p2.respond(&payload).unwrap();
    //     let p1_sess = p1.finalize(&payload).unwrap();
    //
    //     assert_eq!(p1_sess.sender_nonce(), p1_i);
    //     assert_eq!(p1_sess.sender_nonce(), p2_sess.receiver_nonce());
    //     assert_eq!(p2_sess.sender_nonce(), p2_i);
    //     assert_eq!(p2_sess.sender_nonce(), p1_sess.receiver_nonce());
    //     assert_eq!(p1_sess.sender_key(), p2_sess.receiver_key());
    //     assert_eq!(p2_sess.sender_key(), p1_sess.receiver_key());
    // }
}
