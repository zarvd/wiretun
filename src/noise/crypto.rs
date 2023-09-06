use blake2::{
    digest::{FixedOutput, Mac, Update},
    Blake2s256, Blake2sMac, Digest,
};
use rand_core::OsRng;

use super::Error;

pub type PrivateKey = x25519_dalek::StaticSecret;
pub type PublicKey = x25519_dalek::PublicKey;
pub type EphemeralPrivateKey = x25519_dalek::ReusableSecret;

pub fn encode_to_hex(key: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(key.len() * 2);
    for &b in key {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn decode_from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[derive(Clone)]
pub struct LocalStaticSecret {
    private: PrivateKey,
    public: PublicKey,
}

impl LocalStaticSecret {
    #[inline(always)]
    pub fn random() -> Self {
        Self::new(PrivateKey::random_from_rng(OsRng).to_bytes())
    }

    #[inline(always)]
    pub fn new(private_key: [u8; 32]) -> Self {
        let private = PrivateKey::from(private_key);
        let public = PublicKey::from(&private);

        Self { private, public }
    }

    #[inline(always)]
    pub fn with_peer(self, peer_public_key: [u8; 32]) -> PeerStaticSecret {
        PeerStaticSecret::new(self, peer_public_key)
    }

    #[inline(always)]
    pub fn private_key(&self) -> &PrivateKey {
        &self.private
    }

    #[inline(always)]
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }
}

#[derive(Clone)]
pub struct PeerStaticSecret {
    local: LocalStaticSecret,
    public: PublicKey,
    psk: [u8; 32], // pre-shared key
}

impl PeerStaticSecret {
    #[inline(always)]
    pub fn new(local: LocalStaticSecret, public_key: [u8; 32]) -> Self {
        let public = PublicKey::from(public_key);
        let psk = [0u8; 32];

        Self { local, public, psk }
    }

    #[inline(always)]
    pub fn random_psk() -> [u8; 32] {
        x25519_dalek::StaticSecret::random_from_rng(OsRng).to_bytes()
    }

    #[inline(always)]
    pub fn set_psk(&mut self, psk: [u8; 32]) {
        self.psk = psk;
    }

    #[inline(always)]
    pub fn psk(&self) -> &[u8; 32] {
        &self.psk
    }

    #[inline(always)]
    pub fn local(&self) -> &LocalStaticSecret {
        &self.local
    }

    #[inline(always)]
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }
}

#[inline]
pub fn gen_ephemeral_key() -> (EphemeralPrivateKey, PublicKey) {
    let secret = EphemeralPrivateKey::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

#[inline]
pub fn hash(in1: &[u8], in2: &[u8]) -> [u8; 32] {
    Blake2s256::new().chain(in1).chain(in2).finalize().into()
}

#[inline]
pub fn mac(key: &[u8], in0: &[u8]) -> [u8; 16] {
    Blake2sMac::new_from_slice(key)
        .unwrap()
        .chain(in0)
        .finalize_fixed()
        .into()
}

#[inline]
pub fn hmac1(key: &[u8], in0: &[u8]) -> [u8; 32] {
    type HmacBlake2s = hmac::SimpleHmac<Blake2s256>;
    HmacBlake2s::new_from_slice(key)
        .unwrap()
        .chain(in0)
        .finalize_fixed()
        .into()
}

#[inline]
pub fn hmac2(key: &[u8], in0: &[u8], in1: &[u8]) -> [u8; 32] {
    type HmacBlake2s = hmac::SimpleHmac<Blake2s256>;
    HmacBlake2s::new_from_slice(key)
        .unwrap()
        .chain(in0)
        .chain(in1)
        .finalize_fixed()
        .into()
}

#[inline]
pub fn kdf1(key: &[u8], in0: &[u8]) -> [u8; 32] {
    hmac1(&hmac1(key, in0), &[0x1])
}

#[inline]
pub fn kdf2(key: &[u8], in0: &[u8]) -> ([u8; 32], [u8; 32]) {
    let prk = hmac1(key, in0);
    let t0 = hmac1(&prk, &[0x1]);
    let t1 = hmac2(&prk, &t0, &[0x2]);
    (t0, t1)
}

#[inline]
pub fn kdf3(key: &[u8], in0: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let prk = hmac1(key, in0);
    let t0 = hmac1(&prk, &[0x1]);
    let t1 = hmac2(&prk, &t0, &[0x2]);
    let t2 = hmac2(&prk, &t1, &[0x3]);
    (t0, t1, t2)
}

#[inline]
pub fn aead_encrypt(key: &[u8], counter: u64, msg: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, Nonce};
    let nonce = {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        nonce
    };

    chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::InvalidKeyLength)?
        .encrypt(Nonce::from_slice(&nonce), Payload { msg, aad })
        .map_err(Error::Encryption)
}

#[inline]
pub fn aead_decrypt(key: &[u8], counter: u64, msg: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, Nonce};
    let nonce = {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        nonce
    };
    chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::InvalidKeyLength)?
        .decrypt(Nonce::from_slice(&nonce), Payload { msg, aad })
        .map_err(|_| Error::Decryption)
}

#[inline]
pub fn xaead_encrypt(key: &[u8], nonce: &[u8], msg: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, XNonce};
    chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::InvalidKeyLength)?
        .encrypt(XNonce::from_slice(nonce), Payload { msg, aad })
        .map_err(Error::Encryption)
}

#[inline]
pub fn xaead_decrypt(key: &[u8], nonce: &[u8], msg: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, XNonce};
    chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::InvalidKeyLength)?
        .decrypt(XNonce::from_slice(nonce), Payload { msg, aad })
        .map_err(|_| Error::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        assert_eq!(
            hash(b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s", b""),
            [
                96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235,
                66, 6, 248, 114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
            ]
        )
    }

    #[test]
    fn test_kdf() {
        let cases = [
            (
                "746573742d6b6579",
                "746573742d696e707574",
                (
                    "6f0e5ad38daba1bea8a0d213688736f19763239305e0f58aba697f9ffc41c633",
                    "df1194df20802a4fe594cde27e92991c8cae66c366e8106aaa937a55fa371e8a",
                    "fac6e2745a325f5dc5d11a5b165aad08b0ada28e7b4e666b7c077934a4d76c24",
                ),
            ),
            (
                "776972656775617264",
                "776972656775617264",
                (
                    "491d43bbfdaa8750aaf535e334ecbfe5129967cd64635101c566d4caefda96e8",
                    "1e71a379baefd8a79aa4662212fcafe19a23e2b609a3db7d6bcba8f560e3d25f",
                    "31e1ae48bddfbe5de38f295e5452b1909a1b4e38e183926af3780b0c1e1f0160",
                ),
            ),
            (
                "",
                "",
                (
                    "8387b46bf43eccfcf349552a095d8315c4055beb90208fb1be23b894bc2ed5d0",
                    "58a0e5f6faefccf4807bff1f05fa8a9217945762040bcec2f4b4a62bdfe0e86e",
                    "0ce6ea98ec548f8e281e93e32db65621c45eb18dc6f0a7ad94178610a2f7338e",
                ),
            ),
        ];
        // test kdf1
        for (key, input, (t0, _, _)) in cases {
            let key = decode_from_hex(key);
            let input = decode_from_hex(input);
            let out = kdf1(&key, &input);
            assert_eq!(encode_to_hex(&out), t0);
        }

        // test kdf2
        for (key, input, (t0, t1, _)) in cases {
            let key = decode_from_hex(key);
            let input = decode_from_hex(input);
            let out = kdf2(&key, &input);
            assert_eq!(encode_to_hex(&out.0), t0);
            assert_eq!(encode_to_hex(&out.1), t1);
        }

        // test kdf3
        for (key, input, (t0, t1, t2)) in cases {
            let key = decode_from_hex(key);
            let input = decode_from_hex(input);
            let out = kdf3(&key, &input);
            assert_eq!(encode_to_hex(&out.0), t0);
            assert_eq!(encode_to_hex(&out.1), t1);
            assert_eq!(encode_to_hex(&out.2), t2);
        }
    }

    #[test]
    fn test_aead() {
        let key = b"0123456789abcdef0123456789abcdef";
        let aad = b"fedcba9876543210";
        let data = b"foobar";
        let counter = 42;
        let encrypted = aead_encrypt(key, counter, data, aad).unwrap();
        assert_eq!(
            "3b97d40eb9a5a78385054b7be7027c9661a2031f4f91",
            encode_to_hex(&encrypted),
        );
        let decrypted = aead_decrypt(key, counter, &encrypted, aad).unwrap();
        assert_eq!(data, &decrypted[..]);
    }

    #[test]
    fn test_xaead() {
        let key = b"0123456789abcdef0123456789abcdef";
        let aad = b"fedcba9876543210";
        let data = b"foobar";
        let nonce = b"0123456789abcdef01234567";
        let encrypted = xaead_encrypt(key, nonce, data, aad).unwrap();
        assert_eq!(
            "2f8312b423a80a32585bcf059fbcfeee8063d258f030",
            encode_to_hex(&encrypted),
        );
        let decrypted = xaead_decrypt(key, nonce, &encrypted, aad).unwrap();
        assert_eq!(data, &decrypted[..]);
    }
}
