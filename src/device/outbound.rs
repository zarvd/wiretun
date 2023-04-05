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

#[derive(Clone)]
pub(super) struct Listener {
    socket: Arc<UdpSocket>,
}

impl Listener {
    pub async fn bind(port: u16) -> Result<(Self, Self), io::Error> {
        loop {
            let ipv4 = {
                let socket = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
                socket.set_nonblocking(true)?;
                socket.set_reuse_address(true)?;
                socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
                UdpSocket::from_std(std::net::UdpSocket::from(socket))?
            };
            info!("Listening on {}", ipv4.local_addr()?);

            let ipv6_socket = {
                let socket = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
                socket.set_only_v6(true)?;
                socket.set_nonblocking(true)?;
                socket.set_reuse_address(true)?;
                socket.bind(
                    &SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, ipv4.local_addr()?.port(), 0, 0)
                        .into(),
                )?;
                UdpSocket::from_std(std::net::UdpSocket::from(socket))
            };
            let ipv6 = match ipv6_socket {
                Ok(s) => s,
                Err(e) => {
                    if port != 0 {
                        error!("IPv6 listen port[{port}] already is use, failed to bind");
                        return Err(e);
                    }
                    debug!(
                        "failed to bind IPv6 socket, will retry with another port: {}",
                        e
                    );
                    continue;
                }
            };
            info!("Listening on {}", ipv6.local_addr()?);

            return Ok((
                Self {
                    socket: Arc::new(ipv4),
                },
                Self {
                    socket: Arc::new(ipv6),
                },
            ));
        }
    }

    pub fn listening_port(&self) -> u16 {
        self.socket.local_addr().unwrap().port()
    }

    pub fn endpoint_for(&self, dst: SocketAddr) -> Endpoint {
        let src = self.socket.local_addr().unwrap();
        Endpoint::new(Arc::clone(&self.socket), src, dst)
    }
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
