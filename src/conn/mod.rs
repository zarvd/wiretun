use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

pub struct Conn {
    v4_socket: UdpSocket,
    v6_socket: UdpSocket,
}

impl Conn {
    pub async fn new() -> Result<Self, io::Error> {
        Self::with_port(0).await
    }

    pub async fn with_port(port: u16) -> Result<Self, io::Error> {
        let v4_socket = UdpSocket::bind(SocketAddr::new("0.0.0.0".parse().unwrap(), port)).await?;
        let addr = v4_socket.local_addr()?;
        let v6_socket =
            UdpSocket::bind(SocketAddr::new("::".parse().unwrap(), addr.port())).await?;

        Ok(Self {
            v4_socket,
            v6_socket,
        })
    }
}
