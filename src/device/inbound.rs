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

pub(super) struct UdpListener {
    v4_addr: SocketAddr,
    v6_addr: SocketAddr,
    ipv4: Arc<UdpSocket>,
    ipv6: Arc<UdpSocket>,
    port: u16,
}

impl UdpListener {
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
            let v4_addr = ipv4.local_addr()?;
            let v6_addr = ipv6.local_addr()?;
            info!("Listening on {v4_addr}");
            info!("Listening on {v6_addr}");

            return Ok(Self {
                ipv4: Arc::new(ipv4),
                ipv6: Arc::new(ipv6),
                v4_addr,
                v6_addr,
                port,
            });
        }
        let e = err.unwrap();
        error!("Inbound is not able to bind port {port}: {e}");
        Err(e)
    }

    #[inline]
    pub fn v4(&self) -> UdpInbound {
        UdpInbound {
            socket: Arc::clone(&self.ipv4),
        }
    }

    #[inline]
    pub fn v6(&self) -> UdpInbound {
        UdpInbound {
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
            SocketAddr::V4(_) => Endpoint::new(self.v4(), self.v4_addr, dst),
            SocketAddr::V6(_) => Endpoint::new(self.v6(), self.v6_addr, dst),
        }
    }
}

#[derive(Clone)]
pub(super) struct UdpInbound {
    socket: Arc<UdpSocket>,
}

impl UdpInbound {
    async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> Result<(), io::Error> {
        self.socket.send_to(buf, dst).await?;
        Ok(())
    }
}

impl Stream for UdpInbound {
    type Item = (Endpoint, Vec<u8>);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut data = vec![0u8; 2048];
        let mut buf = ReadBuf::new(&mut data);
        let dst = match Pin::new(&mut self.socket).poll_recv_from(cx, &mut buf) {
            Poll::Ready(Ok(dst)) => dst,
            Poll::Ready(Err(e)) => {
                debug!("{self} failed to receive packet: {e}");
                return Poll::Ready(None);
            }
            Poll::Pending => return Poll::Pending,
        };
        let src = self.socket.local_addr().unwrap();
        debug!("{} <- {}: {} bytes", self, dst, buf.filled().len());
        Poll::Ready(Some((
            Endpoint::new(self.clone(), src, dst),
            buf.filled().to_vec(),
        )))
    }
}

impl Display for UdpInbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Inbound [{}]", self.socket.local_addr().unwrap())
    }
}

#[derive(Clone)]
pub(crate) struct Endpoint {
    inbound: UdpInbound,
    src: SocketAddr,
    dst: SocketAddr,
}

impl Endpoint {
    fn new(inbound: UdpInbound, src: SocketAddr, dst: SocketAddr) -> Self {
        Self { inbound, src, dst }
    }

    #[inline]
    pub async fn send(&self, buf: &[u8]) -> Result<(), io::Error> {
        self.inbound.send_to(buf, self.dst).await
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
