#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("unable to encrypt")]
    Encryption(chacha20poly1305::aead::Error),
    #[error("unable to decrypt")]
    Decryption,
    #[error("invalid packet")]
    InvalidPacket,
    #[error("invalid handshake state")]
    InvalidHandshakeState,
    #[error("receiver index not match")]
    ReceiverIndexNotMatch,
}
