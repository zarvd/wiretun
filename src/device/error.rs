#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Too many peers")]
    TooManyPeers,
    #[error("Peer already exists")]
    PeerAlreadyExists,
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Noise protocol error: {0}")]
    Noise(#[from] crate::noise::Error),
}
