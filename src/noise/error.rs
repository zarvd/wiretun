#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("encryption error")]
    Encryption(chacha20poly1305::aead::Error),
}
