#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Interface must be named utun[0-9]*")]
    InvalidName,
    #[error("System call failed: {0}")]
    IOError(#[from] std::io::Error),
}
