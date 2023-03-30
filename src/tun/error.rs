#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("interface must be named utun[0-9]*")]
    InvalidName,
    #[error("system call failed: {0}")]
    IOError(#[from] std::io::Error),
    #[error("invalid IP packet")]
    InvalidIpPacket,
    #[error("tun closed")]
    Closed,
}
