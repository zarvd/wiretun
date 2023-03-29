#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid protocol")]
    InvalidProtocol,
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
}
