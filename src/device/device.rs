use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
use futures::StreamExt;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

use super::peer::Peers;
use super::{DeviceConfig, Error};
use crate::listener::Endpoint;
use crate::noise::crypto::LocalStaticSecret;
use crate::noise::handshake::IncomingInitiation;
use crate::noise::protocol::Message;
use crate::{uapi, Listener, NativeTun, Tun};

const MAX_PEERS: usize = 1 << 16;

struct Inner<T>
where
    T: Tun + 'static,
{
    tun: T,
    secret: LocalStaticSecret,
    peers: Peers<T>,
    cfg: DeviceConfig,
}

pub struct Device<T>
where
    T: Tun + 'static,
{
    inner: Arc<Inner<T>>,
    handles: Vec<JoinHandle<()>>,
    stop: Arc<Notify>,
}

impl Device<NativeTun> {
    pub async fn native(name: &str, cfg: DeviceConfig) -> Result<Self, Error> {
        let tun = NativeTun::new(name).map_err(Error::Tun)?;
        Device::with_tun(tun, cfg).await
    }
}

impl<T> Device<T>
where
    T: Tun + 'static,
{
    pub async fn with_tun(tun: T, cfg: DeviceConfig) -> Result<Self, Error> {
        let inner = {
            let secret = LocalStaticSecret::new(cfg.private_key);
            let peers = Peers::new(tun.clone(), secret.clone());
            Arc::new(Inner {
                tun,
                secret,
                peers,
                cfg,
            })
        };

        let stop = Arc::new(Notify::new());
        let (listener_v4, listener_v6) = Listener::with_port(inner.cfg.listen_port).await?;
        let listener_uapi = uapi::Listener::bind(inner.tun.name());
        for cfg in &inner.cfg.peers {
            let endpoint = cfg.endpoint.map(|addr| listener_v4.endpoint_for(addr));
            inner
                .peers
                .insert(cfg.public_key, &cfg.allowed_ips, endpoint);
        }

        let handles = vec![
            tokio::spawn(loop_tun_events(inner.clone(), stop.clone())),
            tokio::spawn(loop_outbound(inner.clone(), stop.clone())),
            tokio::spawn(loop_inbound(inner.clone(), listener_v4, stop.clone())),
            tokio::spawn(loop_inbound(inner.clone(), listener_v6, stop.clone())),
            tokio::spawn(loop_uapi(inner.clone(), listener_uapi, stop.clone())),
        ];

        Ok(Device {
            inner,
            handles,
            stop,
        })
    }

    #[inline]
    pub fn handle(&self) -> Handle<T> {
        Handle {
            inner: self.inner.clone(),
        }
    }

    pub async fn terminate(mut self) {
        self.stop.notify_waiters();
        join_all(self.handles.drain(..)).await;
    }
}

impl<T> Drop for Device<T>
where
    T: Tun,
{
    fn drop(&mut self) {
        self.stop.notify_waiters();
        for handle in self.handles.drain(..) {
            handle.abort();
        }
    }
}

#[derive(Clone)]
pub struct Handle<T>
where
    T: Tun + 'static,
{
    inner: Arc<Inner<T>>,
}

impl<T> Handle<T>
where
    T: Tun + 'static,
{
    pub fn fetch_config(&self) -> DeviceConfig {
        todo!()
    }

    pub fn update_config(&self, _cfg: DeviceConfig) {}
}

async fn loop_tun_events<T>(inner: Arc<Inner<T>>, stop_notify: Arc<Notify>)
where
    T: Tun + 'static,
{
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
async fn tick_tun_events<T>(_inner: Arc<Inner<T>>)
where
    T: Tun + 'static,
{
    tokio::time::sleep(Duration::from_secs(5)).await;
}

async fn loop_inbound<T>(inner: Arc<Inner<T>>, mut listener: Listener, stop_notify: Arc<Notify>)
where
    T: Tun + 'static,
{
    debug!("starting inbound loop for {}", listener);
    loop {
        tokio::select! {
            _ = stop_notify.notified() => {
                debug!("stopping outbound loop for {}", listener);
                return;
            }
            data = listener.next() => {
                if let Some((endpoint, payload)) = data {
                    tick_inbound(inner.clone(), endpoint, payload).await;
                }
            }
        }
    }
}

async fn tick_inbound<T>(inner: Arc<Inner<T>>, endpoint: Endpoint, payload: Vec<u8>)
where
    T: Tun + 'static,
{
    match Message::parse(&payload) {
        Ok(Message::HandshakeInitiation(p)) => {
            let initiation =
                IncomingInitiation::parse(&inner.secret, &p).unwrap_or_else(|_| todo!());
            if let Some(peer) = inner
                .peers
                .by_static_public_key(initiation.static_public_key.as_bytes())
            {
                peer.handle_handshake_initiation(endpoint, &payload, initiation)
                    .await;
            }
        }
        Ok(msg) => {
            let receiver_index = match &msg {
                Message::HandshakeResponse(p) => p.receiver_index,
                Message::CookieReply(p) => p.receiver_index,
                Message::TransportData(p) => p.receiver_index,
                _ => unreachable!(),
            };
            if let Some((session, peer)) = inner.peers.by_index(receiver_index) {
                match msg {
                    Message::HandshakeResponse(p) => {
                        peer.handle_handshake_response(endpoint, p, &payload, session)
                            .await;
                    }
                    Message::CookieReply(p) => {
                        peer.handle_cookie_reply(endpoint, p, session).await;
                    }
                    Message::TransportData(p) => {
                        peer.handle_transport_data(endpoint, p, session).await;
                    }
                    _ => unreachable!(),
                }
            } else {
                warn!("received message for unknown peer {receiver_index}");
            }
        }
        Err(e) => {
            warn!("failed to parse message type: {:?}", e);
        }
    }
}

async fn loop_outbound<T>(inner: Arc<Inner<T>>, stop_notify: Arc<Notify>)
where
    T: Tun + 'static,
{
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

async fn tick_outbound<T>(inner: Arc<Inner<T>>)
where
    T: Tun + 'static,
{
    const IPV4_HEADER_LEN: usize = 20;
    const IPV6_HEADER_LEN: usize = 40;

    match inner.tun.recv().await {
        Ok(buf) => {
            let dst = {
                match buf[0] & 0xF0 {
                    0x40 if buf.len() < IPV4_HEADER_LEN => return,
                    0x40 => {
                        let addr: [u8; 4] = buf[16..20].try_into().unwrap();
                        IpAddr::from(Ipv4Addr::from(addr))
                    }
                    0x60 if buf.len() < IPV6_HEADER_LEN => return,
                    0x60 => {
                        let addr: [u8; 16] = buf[24..40].try_into().unwrap();
                        IpAddr::from(Ipv6Addr::from(addr))
                    }
                    n => {
                        debug!("unknown IP version: {}", n);
                        return;
                    }
                }
            };

            debug!("trying to send packet to {}", dst);

            let peer = inner.peers.by_allow_ip(dst);

            if let Some(peer) = peer {
                peer.stage_outbound(buf).await
            }
        }
        Err(e) => {
            error!("TUN read error: {}", e)
        }
    }
}

async fn loop_uapi<T>(inner: Arc<Inner<T>>, uapi: uapi::Listener, stop_notify: Arc<Notify>)
where
    T: Tun + 'static,
{
    debug!("starting uapi loop");
    loop {
        tokio::select! {
            _ = stop_notify.notified() => {
                debug!("stopping uapi loop");
                return;
            }
            conn = uapi.accept() => {
                match conn {
                    Ok(conn) => {
                        debug!("accepted uapi connection");
                        tokio::spawn(handle_uapi_conn(inner.clone(), conn, stop_notify.clone()));
                    }
                    Err(_) => {}
                }
            }
        }
    }
}

async fn handle_uapi_conn<T>(
    _inner: Arc<Inner<T>>,
    mut conn: uapi::Connection,
    stop_notify: Arc<Notify>,
) where
    T: Tun + 'static,
{
    loop {
        tokio::select! {
            _ = stop_notify.notified() => {
                debug!("stopping uapi connection");
                return;
            }
            op = conn.next() => {
                match op {
                    Ok(uapi::Operation::Get) => {
                        debug!("received uapi get config");
                    }
                    Ok(uapi::Operation::Set) => {
                        debug!("received uapi set config");
                    }
                    _ => break,
                }
            }
        }
    }
}
