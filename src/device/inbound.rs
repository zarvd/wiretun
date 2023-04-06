use std::fmt::{Debug, Display, Formatter};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::Stream;
use socket2::{Domain, Protocol, Type};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tracing::{debug, error, info};

async fn bind_v4(port: u16) -> Result<UdpSocket, io::Error> {
    let socket = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
    UdpSocket::from_std(std::net::UdpSocket::from(socket))
}

async fn bind_v6(port: u16) -> Result<UdpSocket, io::Error> {
    let socket = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into())?;
    UdpSocket::from_std(std::net::UdpSocket::from(socket))
}

pub(super) struct Inbound {
    ipv4: Arc<UdpSocket>,
    ipv6: Arc<UdpSocket>,
    port: u16,
}

impl Inbound {
    pub async fn bind(port: u16) -> Result<Self, io::Error> {
        let max_retry = if port == 0 { 10 } else { 1 };
        let mut err = None;
        for _ in 0..max_retry {
            let ipv4 = match bind_v4(port).await {
                Ok(s) => s,
                Err(e) => {
                    err = Some(e);
                    continue;
                }
            };
            let port = ipv4.local_addr()?.port();
            let ipv6 = match bind_v6(port).await {
                Ok(s) => s,
                Err(e) => {
                    err = Some(e);
                    continue;
                }
            };
            info!("Listening on {}", ipv4.local_addr()?);
            info!("Listening on {}", ipv6.local_addr()?);

            return Ok(Self {
                ipv4: Arc::new(ipv4),
                ipv6: Arc::new(ipv6),
                port,
            });
        }
        error!("Failed to bind to port {}", port);
        Err(err.unwrap())
    }

    #[inline]
    pub fn v4(&self) -> Listener {
        Listener {
            socket: Arc::clone(&self.ipv4),
        }
    }

    #[inline]
    pub fn v6(&self) -> Listener {
        Listener {
            socket: Arc::clone(&self.ipv6),
        }
    }

    #[inline]
    pub fn local_port(&self) -> u16 {
        self.port
    }

    #[inline]
    pub fn endpoint_for(&self, dst: SocketAddr) -> Endpoint {
        match dst {
            SocketAddr::V4(_) => {
                Endpoint::new(Arc::clone(&self.ipv4), self.ipv4.local_addr().unwrap(), dst)
            }
            SocketAddr::V6(_) => {
                Endpoint::new(Arc::clone(&self.ipv6), self.ipv6.local_addr().unwrap(), dst)
            }
        }
    }
}

pub(super) struct Listener {
    socket: Arc<UdpSocket>,
}

impl Stream for Listener {
    type Item = (Endpoint, Vec<u8>);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut data = vec![0u8; 65526];
        let mut buf = ReadBuf::new(&mut data);
        let dst = match Pin::new(&mut self.socket).poll_recv_from(cx, &mut buf) {
            Poll::Ready(Ok(dst)) => dst,
            Poll::Ready(Err(e)) => {
                debug!("failed to receive packet: {}", e);
                return Poll::Ready(None);
            }
            Poll::Pending => return Poll::Pending,
        };
        let src = self.socket.local_addr().unwrap();
        debug!("Listener received {} bytes", buf.filled().len());
        Poll::Ready(Some((
            Endpoint::new(Arc::clone(&self.socket), src, dst),
            buf.filled().to_vec(),
        )))
    }
}

impl Display for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Listener [local_addr = {}]",
            self.socket.local_addr().unwrap()
        )
    }
}

#[derive(Clone)]
pub(crate) struct Endpoint {
    socket: Arc<UdpSocket>,
    src: SocketAddr,
    dst: SocketAddr,
}

impl Endpoint {
    fn new(socket: Arc<UdpSocket>, src: SocketAddr, dst: SocketAddr) -> Self {
        Self { socket, src, dst }
    }

    #[inline]
    pub async fn send(&self, buf: &[u8]) -> Result<(), io::Error> {
        self.socket.send_to(buf, &self.dst).await?;
        Ok(())
    }

    #[inline]
    #[allow(dead_code)]
    pub fn dst(&self) -> SocketAddr {
        self.dst
    }

    #[inline]
    #[allow(dead_code)]
    pub fn src(&self) -> SocketAddr {
        self.src
    }
}

impl Debug for Endpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("src", &self.src.to_string())
            .field("dst", &self.dst.to_string())
            .finish()
    }
}
