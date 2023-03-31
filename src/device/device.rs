use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::future::join_all;
use futures::StreamExt;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

use super::outbound::{Endpoint, Listener};
use super::peer::Peers;
use super::rate_limiter::RateLimiter;
use super::{DeviceConfig, DeviceMetrics, Error, PeerConfig};
use crate::noise::crypto::LocalStaticSecret;
use crate::noise::handshake::{Cookie, IncomingInitiation};
use crate::noise::protocol::Message;
use crate::{Cidr, Tun};

const MAX_PEERS: usize = 1 << 16;

struct Inner<T>
where
    T: Tun + 'static,
{
    tun: T,
    secret: LocalStaticSecret,
    peers: Peers<T>,
    cfg: Mutex<DeviceConfig>,
    rate_limiter: RateLimiter,
    cookie: Cookie,
    listener_v4: Listener,
    listener_v6: Listener,
}

impl<T> Inner<T>
where
    T: Tun + 'static,
{
    pub fn metrics(&self) -> DeviceMetrics {
        let peers = self.peers.metrics();
        DeviceMetrics { peers }
    }

    pub fn config(&self) -> DeviceConfig {
        self.cfg.lock().unwrap().clone()
    }

    pub fn endpoint_for(&self, addr: SocketAddr) -> Endpoint {
        match addr {
            SocketAddr::V4(_) => self.listener_v4.endpoint_for(addr),
            SocketAddr::V6(_) => self.listener_v6.endpoint_for(addr),
        }
    }
}

/// A WireGuard device.
///
/// When enabled with the `tun-native` feature, you can create a native device using the method [`native`](`Device::native`).
///
/// # Examples
///
/// Using `native`:
/// ```no_run
/// use wiretun::{Device, DeviceConfig, uapi};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let cfg = DeviceConfig::default();
///     let device = Device::native("utun", cfg).await?;
///
///     uapi::bind_and_handle(device.handle()).await?;
/// }
/// ```
pub struct Device<T>
where
    T: Tun + 'static,
{
    inner: Arc<Inner<T>>,
    handles: Vec<JoinHandle<()>>,
    stop: Arc<Notify>,
}

#[cfg(feature = "tun-native")]
impl Device<crate::NativeTun> {
    pub async fn native(name: &str, cfg: DeviceConfig) -> Result<Self, Error> {
        let tun = crate::NativeTun::new(name).map_err(Error::Tun)?;
        Device::with_tun(tun, cfg).await
    }
}

impl<T> Device<T>
where
    T: Tun + 'static,
{
    pub async fn with_tun(tun: T, mut cfg: DeviceConfig) -> Result<Self, Error> {
        let stop = Arc::new(Notify::new());

        let (listener_v4, listener_v6) = Listener::bind(cfg.listen_port).await?;
        cfg.listen_port = listener_v4.listening_port(); // update cfg.listen_port in case it was 0

        let secret = LocalStaticSecret::new(cfg.private_key);

        let peers = {
            let peers = Peers::new(tun.clone(), secret.clone());
            cfg.peers.iter().for_each(|p| {
                peers.insert(
                    p.public_key,
                    p.allowed_ips.clone(),
                    p.endpoint.map(|addr| match addr {
                        SocketAddr::V4(_) => listener_v4.endpoint_for(addr),
                        SocketAddr::V6(_) => listener_v6.endpoint_for(addr),
                    }),
                );
            });
            peers
        };

        let cookie = Cookie::new(&secret);

        let rate_limiter = RateLimiter::new(1_000);
        let inner = {
            let cfg = Mutex::new(cfg);
            Arc::new(Inner {
                tun,
                secret,
                peers,
                cfg,
                cookie,
                rate_limiter,
                listener_v4: listener_v4.clone(),
                listener_v6: listener_v6.clone(),
            })
        };
        let handles = vec![
            tokio::spawn(loop_tun_events(inner.clone(), stop.clone())),
            tokio::spawn(loop_outbound(inner.clone(), stop.clone())),
            tokio::spawn(loop_inbound(inner.clone(), listener_v4, stop.clone())),
            tokio::spawn(loop_inbound(inner.clone(), listener_v6, stop.clone())),
        ];

        Ok(Device {
            inner,
            handles,
            stop,
        })
    }

    #[inline]
    pub fn handle(&self) -> DeviceHandle<T> {
        DeviceHandle {
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
pub struct DeviceHandle<T>
where
    T: Tun + 'static,
{
    inner: Arc<Inner<T>>,
}

impl<T> DeviceHandle<T>
where
    T: Tun + 'static,
{
    pub fn tun_name(&self) -> &str {
        self.inner.tun.name()
    }

    #[inline]
    pub fn config(&self) -> DeviceConfig {
        self.inner.config()
    }

    #[inline]
    pub fn metrics(&self) -> DeviceMetrics {
        self.inner.metrics()
    }

    pub fn peer_config(&self, public_key: &[u8; 32]) -> Option<PeerConfig> {
        self.inner
            .cfg
            .lock()
            .unwrap()
            .peers
            .iter()
            .find(|p| p.public_key == *public_key)
            .cloned()
    }

    pub fn insert_peer(
        &self,
        public_key: [u8; 32],
        allowed_ips: Vec<Cidr>,
        endpoint: Option<SocketAddr>,
    ) -> bool {
        if self.inner.peers.get_by_key(&public_key).is_some() {
            return false;
        }

        let mut cfg = self.inner.cfg.lock().unwrap();
        self.inner.peers.insert(
            public_key,
            allowed_ips.clone(),
            endpoint.map(|addr| self.inner.endpoint_for(addr)),
        );
        cfg.peers.push(PeerConfig {
            public_key: public_key,
            allowed_ips,
            endpoint,
            preshared_key: None,
            persistent_keepalive: None,
        });
        true
    }

    pub fn remove_peer(&self, public_key: &[u8; 32]) {
        let mut cfg = self.inner.cfg.lock().unwrap();
        self.inner.peers.remove_by_key(public_key);
        cfg.peers.retain(|p| p.public_key != *public_key);
    }

    pub fn update_peer_endpoint(&self, public_key: &[u8; 32], addr: SocketAddr) {
        self.inner
            .peers
            .get_by_key(public_key)
            .map(|p| p.update_endpoint(self.inner.endpoint_for(addr)));
    }

    pub fn list_allowed_ips_by_peer(&self, public_key: &[u8; 32]) -> Option<Vec<Cidr>> {
        self.inner.peers.list_allowed_ips_by_key(public_key)
    }

    pub fn update_allowed_ips_by_peer(&self, public_key: &[u8; 32], allowed_ips: Vec<Cidr>) {
        let mut cfg = self.inner.cfg.lock().unwrap();
        self.inner
            .peers
            .update_allowed_ips_by_key(public_key, allowed_ips.clone());
        cfg.peers
            .iter_mut()
            .find(|p| p.public_key == *public_key)
            .map(|p| p.allowed_ips = allowed_ips);
    }

    pub fn clear_peers(&self) {
        let mut cfg = self.inner.cfg.lock().unwrap();
        self.inner.peers.clear();
        cfg.peers.clear();
    }
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
    if Message::is_handshake(&payload) {
        if !inner.cookie.validate_mac1(&payload) {
            debug!("invalid mac1");
            return;
        }

        if !inner.rate_limiter.fetch_token() {
            debug!("rate limited");
            if !inner.cookie.validate_mac2(&payload) {
                debug!("invalid mac2");
                return;
            }
            debug!("try to send cookie reply");
            let reply = inner.cookie.generate_cookie_reply(&payload, endpoint.dst());
            endpoint.send(&reply).await.unwrap();
            return;
        }
    }

    match Message::parse(&payload) {
        Ok(Message::HandshakeInitiation(p)) => {
            let initiation =
                IncomingInitiation::parse(&inner.secret, &p).unwrap_or_else(|_| todo!());
            if let Some(peer) = inner
                .peers
                .get_by_key(initiation.static_public_key.as_bytes())
            {
                peer.handle_handshake_initiation(endpoint, initiation).await;
            }
        }
        Ok(msg) => {
            let receiver_index = match &msg {
                Message::HandshakeResponse(p) => p.receiver_index,
                Message::CookieReply(p) => p.receiver_index,
                Message::TransportData(p) => p.receiver_index,
                _ => unreachable!(),
            };
            if let Some((session, peer)) = inner.peers.get_session_by_index(receiver_index) {
                match msg {
                    Message::HandshakeResponse(p) => {
                        peer.handle_handshake_response(endpoint, p, session).await;
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

            let peer = inner.peers.get_by_allow_ip(dst);

            if let Some(peer) = peer {
                debug!("sending packet[{}] to {dst}", buf.len());
                peer.stage_outbound(buf).await
            } else {
                warn!("no peer found for {dst}");
            }
        }
        Err(e) => {
            error!("TUN read error: {}", e)
        }
    }
}
