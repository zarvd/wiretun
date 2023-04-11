#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid protocol")]
    InvalidProtocol,
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
}
