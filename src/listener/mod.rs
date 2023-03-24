use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::Stream;
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tracing::{debug, info};

pub struct Listener {
    socket: Arc<UdpSocket>,
}

impl Listener {
    pub async fn new() -> Result<Vec<Self>, io::Error> {
        Self::with_port(0).await
    }

    pub async fn with_port(port: u16) -> Result<Vec<Self>, io::Error> {
        loop {
            let ipv4 = UdpSocket::bind(SocketAddr::new("0.0.0.0".parse().unwrap(), port)).await?;
            let ipv6 = match UdpSocket::bind(SocketAddr::new(
                "::".parse().unwrap(),
                ipv4.local_addr()?.port(),
            ))
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    debug!(
                        "failed to bind IPv6 socket, will retry with another port: {}",
                        e
                    );
                    continue;
                }
            };

            info!("Listening on {}", ipv4.local_addr()?);
            info!("Listening on {}", ipv6.local_addr()?);

            return Ok(vec![
                Self {
                    socket: Arc::new(ipv4),
                },
                Self {
                    socket: Arc::new(ipv6),
                },
            ]);
        }
    }
}

impl Stream for Listener {
    type Item = (Endpoint, Vec<u8>);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut data = Vec::with_capacity(65536);
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
        Poll::Ready(Some((Endpoint::new(self.socket.clone(), src, dst), data)))
    }
}

#[derive(Clone)]
pub struct Endpoint {
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
}
