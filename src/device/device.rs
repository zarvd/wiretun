
use std::mem;
use std::sync::{Arc};
use std::time::Duration;

use bytes::Bytes;
use futures::future::join_all;
use futures::StreamExt;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

use super::peer::Peers;
use super::{Error};
use crate::noise::crypto::LocalStaticSecret;
use crate::noise::handshake::IncomingInitiation;
use crate::{noise, Listener, Tun};

const MAX_PEERS: usize = 1 << 16;

struct Inner {
    tun: Tun,
    secret: LocalStaticSecret,
    peers: Peers,
}

impl Inner {
    async fn up(&self) {
        debug!("device is up");
        self.peers.start_all().await;
    }

    fn down(&self) {}
}

pub struct Device {
    inner: Arc<Inner>,
}

impl Device {
    pub fn new() -> Self {
        unimplemented!()
    }

    pub async fn start(self) -> Result<Handle, Error> {
        let stop_notify = Arc::new(Notify::new());

        let listeners = Listener::new().await?;

        let mut handles = vec![
            tokio::spawn(loop_tun_events(self.inner.clone(), stop_notify.clone())),
            tokio::spawn(loop_outbound(self.inner.clone(), stop_notify.clone())),
        ];

        for listener in listeners {
            handles.push(tokio::spawn(loop_inbound(
                self.inner.clone(),
                listener,
                stop_notify.clone(),
            )));
        }

        Ok(Handle {
            handles,
            stop_notify,
        })
    }
}

async fn loop_tun_events(inner: Arc<Inner>, stop_notify: Arc<Notify>) {
    debug!("starting tun events loop");
    loop {
        tokio::select! {
            _ = stop_notify.notified() => {
                debug!("stopping tun events loop");
                return;
            }
            _ = tick_tun_events(inner.clone()) => {}
        }
    }
}

#[inline]
async fn tick_tun_events(_inner: Arc<Inner>) {
    tokio::time::sleep(Duration::from_secs(5)).await;
}

async fn loop_inbound(inner: Arc<Inner>, mut listener: Listener, stop_notify: Arc<Notify>) {
    debug!("starting inbound loop for {}", listener);
    loop {
        tokio::select! {
            _ = stop_notify.notified() => {
                debug!("stopping outbound loop for {}", listener);
                return;
            }
            _ = tick_inbound(inner.clone(), &mut listener) => {}
        }
    }
}

#[inline]
async fn tick_inbound(inner: Arc<Inner>, listener: &mut Listener) {
    match listener.next().await {
        Some((endpoint, data)) => {
            debug!("received packet from {:?}", endpoint.dst());

            match noise::MessageType::parse(&data) {
                Ok(noise::MessageType::HandshakeInitiation) => {
                    let initiation =
                        IncomingInitiation::parse(&inner.secret, &data).unwrap_or_else(|_| todo!());
                    match inner
                        .peers
                        .by_static_public_key(initiation.static_public_key.as_bytes())
                    {
                        Some(_peer) => {
                            // TODO: respond peer handshake
                        }
                        None => {
                            warn!(
                                "peer not found. expected static key = {:?}",
                                initiation.static_public_key
                            )
                        }
                    }
                }
                Ok(noise::MessageType::HandshakeResponse) => {}
                Ok(noise::MessageType::CookieReply) => {}
                Ok(noise::MessageType::TransportData) => {}
                Err(e) => {
                    warn!("failed to parse message type: {:?}", e);
                }
            }
        }
        None => {
            error!("listener error");
        }
    }
}

async fn loop_outbound(inner: Arc<Inner>, stop_notify: Arc<Notify>) {
    debug!("starting outbound loop");
    loop {
        tokio::select! {
            _ = stop_notify.notified() => {
                debug!("stopping inbound loop");
                return;
            }
            _ = tick_outbound(inner.clone()) => {}
        }
    }
}

#[inline]
async fn tick_outbound(inner: Arc<Inner>) {
    const IPV4_HEADER_LEN: usize = 20;
    const IPV6_HEADER_LEN: usize = 40;

    match inner.tun.read().await {
        Ok(buf) => {
            let dst = {
                match buf[0] & 0xF0 {
                    0x40 if buf.len() < IPV4_HEADER_LEN => return,
                    0x40 => &buf[16..20],
                    0x60 if buf.len() < IPV6_HEADER_LEN => return,
                    0x60 => &buf[24..40],
                    n => {
                        debug!("unknown IP version: {}", n);
                        return;
                    }
                }
            };

            let peer = inner.peers.by_allow_ip(Bytes::copy_from_slice(dst));

            if let Some(mut peer) = peer {
                peer.stage_outbound(buf).await
            }
        }
        Err(e) => {
            error!("TUN read error: {}", e)
        }
    }
}

pub struct Handle {
    handles: Vec<JoinHandle<()>>,
    stop_notify: Arc<Notify>,
}

impl Handle {
    pub async fn wait(mut self) {
        join_all(mem::take(&mut self.handles)).await;
    }

    pub async fn terminate(self) {
        self.stop_notify.notify_waiters();
        self.wait().await
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.stop_notify.notify_waiters();
    }
}
