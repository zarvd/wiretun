use std::fmt::{Debug, Display, Formatter};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use async_trait::async_trait;
use socket2::{Domain, Protocol, Type};
use tokio::net::UdpSocket;
use tracing::{error, info};

/// Transport is a trait that represents a network transport.
#[async_trait]
pub trait Transport: Clone + Sync + Send + Unpin + Display + 'static {
    /// Binds to the given port and returns a new transport.
    /// When the port is 0, the implementation should choose a random port.
    async fn bind(port: u16) -> Result<Self, io::Error>;

    /// Returns the port that the transport is bound to.
    fn port(&self) -> u16;

    /// Sends data to the given endpoint.
    async fn send_to(&self, data: &[u8], endpoint: &Endpoint<Self>) -> Result<(), io::Error>;

    /// Receives data from the transport.
    async fn recv_from(&mut self) -> Result<(Endpoint<Self>, Vec<u8>), io::Error>;
}

pub(super) struct Inbound<I>
where
    I: Transport,
{
    transport: I,
}

impl<I> Inbound<I>
where
    I: Transport,
{
    #[inline(always)]
    pub fn new(transport: I) -> Self {
        Self { transport }
    }

    #[inline(always)]
    pub fn port(&self) -> u16 {
        self.transport.port()
    }

    #[inline(always)]
    pub fn transport(&self) -> I {
        self.transport.clone()
    }

    #[inline(always)]
    pub fn endpoint_for(&self, dst: SocketAddr) -> Endpoint<I> {
        Endpoint::new(self.transport(), dst)
    }
}

#[derive(Clone)]
pub struct Endpoint<I> {
    transport: I,
    dst: SocketAddr,
}

impl<I> Endpoint<I>
where
    I: Transport,
{
    /// Creates a new endpoint with the given transport and destination.
    pub fn new(transport: I, dst: SocketAddr) -> Self {
        Self { transport, dst }
    }

    /// Sends data to the endpoint.
    #[inline]
    pub async fn send(&self, buf: &[u8]) -> Result<(), io::Error> {
        self.transport.send_to(buf, self).await
    }

    /// Returns the destination of the endpoint.
    #[inline(always)]
    pub fn dst(&self) -> SocketAddr {
        self.dst
    }
}

impl<I> Debug for Endpoint<I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("dst", &self.dst.to_string())
            .finish()
    }
}

impl<I> Display for Endpoint<I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Endpoint[{}]", self.dst)
    }
}

/// UdpTransport is a UDP transport that implements the [`Transport`] trait.
#[derive(Clone)]
pub struct UdpTransport {
    port: u16,
    ipv4: Arc<UdpSocket>,
    ipv6: Arc<UdpSocket>,
    ipv4_buf: Vec<u8>,
    ipv6_buf: Vec<u8>,
}

impl UdpTransport {
    async fn bind_socket(port: u16) -> Result<(Arc<UdpSocket>, Arc<UdpSocket>, u16), io::Error> {
        let max_retry = if port == 0 { 10 } else { 1 };
        let mut err = None;
        for _ in 0..max_retry {
            let ipv4 = match Self::bind_socket_v4(port).await {
                Ok(s) => s,
                Err(e) => {
                    err = Some(e);
                    continue;
                }
            };
            let port = ipv4.local_addr()?.port();
            let ipv6 = match Self::bind_socket_v6(port).await {
                Ok(s) => s,
                Err(e) => {
                    err = Some(e);
                    continue;
                }
            };

            return Ok((Arc::new(ipv4), Arc::new(ipv6), port));
        }
        let e = err.unwrap();
        error!("Inbound is not able to bind port {port}: {e}");
        Err(e)
    }

    async fn bind_socket_v4(port: u16) -> Result<UdpSocket, io::Error> {
        let socket = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
        UdpSocket::from_std(std::net::UdpSocket::from(socket))
    }

    async fn bind_socket_v6(port: u16) -> Result<UdpSocket, io::Error> {
        let socket = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(true)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        socket.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into())?;
        UdpSocket::from_std(std::net::UdpSocket::from(socket))
    }
}

impl Display for UdpTransport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UdpTransport[{}/{}]",
            self.ipv4.local_addr().unwrap(),
            self.ipv6.local_addr().unwrap()
        )
    }
}

#[async_trait]
impl Transport for UdpTransport {
    fn port(&self) -> u16 {
        self.port
    }

    async fn bind(port: u16) -> Result<Self, io::Error> {
        let (ipv4, ipv6, port) = Self::bind_socket(port).await?;
        info!(
            "Listening on {} / {}",
            ipv4.local_addr()?,
            ipv6.local_addr()?
        );
        Ok(Self {
            port,
            ipv4,
            ipv6,
            ipv4_buf: vec![],
            ipv6_buf: vec![],
        })
    }

    async fn send_to(&self, data: &[u8], endpoint: &Endpoint<Self>) -> Result<(), io::Error> {
        match endpoint.dst {
            SocketAddr::V4(_) => self.ipv4.send_to(data, endpoint.dst).await?,
            SocketAddr::V6(_) => self.ipv6.send_to(data, endpoint.dst).await?,
        };
        Ok(())
    }

    async fn recv_from(&mut self) -> Result<(Endpoint<Self>, Vec<u8>), io::Error> {
        if self.ipv4_buf.is_empty() {
            self.ipv4_buf = vec![0u8; 2048];
        }
        if self.ipv6_buf.is_empty() {
            self.ipv4_buf = vec![0u8; 2048];
        }

        let (data, addr) = tokio::select! {
            ret = self.ipv4.recv_from(&mut self.ipv4_buf) => {
                let (n, addr) = ret?;
                (self.ipv4_buf[..n].to_vec(), addr)
            },
            ret = self.ipv6.recv_from(&mut self.ipv6_buf) => {
                let (n, addr) = ret?;
                (self.ipv6_buf[..n].to_vec(), addr)
            },
        };

        Ok((Endpoint::new(self.clone(), addr), data))
    }
}
