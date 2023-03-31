#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("IO Error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Noise protocol error: {0}")]
    Noise(#[from] crate::noise::Error),
    #[error("Tun error: {0}")]
    Tun(#[from] crate::tun::Error),
}
