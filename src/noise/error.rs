#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("encryption error")]
    Encryption(chacha20poly1305::aead::Error),
    #[error("wrong peer static key")]
    WrongPeerStaticKey,
    #[error("invalid packet")]
    InvalidPacket,
    #[error("invalid handshake state")]
    InvalidHandshakeState,
    #[error("invalid mac")]
    InvalidMac,
}
