mod config;
mod error;
mod inbound;
mod metrics;
mod peer;
mod rate_limiter;
mod time;

pub use config::{DeviceConfig, PeerConfig};
pub use error::Error;
pub use metrics::DeviceMetrics;
pub use peer::{Cidr, ParseCidrError, PeerMetrics};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use futures::future::join_all;
use futures::StreamExt;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

use crate::noise::crypto::LocalStaticSecret;
use crate::noise::handshake::{Cookie, IncomingInitiation};
use crate::noise::protocol;
use crate::noise::protocol::Message;
use crate::Tun;
use inbound::{Endpoint, Inbound, Listener};
use peer::PeerIndex;
use rate_limiter::RateLimiter;

struct Inner<T>
where
    T: Tun + 'static,
{
    tun: T,
    secret: LocalStaticSecret,
    peers: PeerIndex<T>,
    cfg: Mutex<DeviceConfig>,
    rate_limiter: RateLimiter,
    cookie: Cookie,
    inbound: Mutex<Inbound>,
}

impl<T> Inner<T>
where
    T: Tun + 'static,
{
    #[inline]
    pub fn metrics(&self) -> DeviceMetrics {
        let peers = self.peers.metrics();
        DeviceMetrics { peers }
    }

    #[inline]
    pub fn config(&self) -> DeviceConfig {
        self.cfg.lock().unwrap().clone()
    }

    #[inline]
    pub fn endpoint_for(&self, dst: SocketAddr) -> Endpoint {
        self.inbound.lock().unwrap().endpoint_for(dst)
    }
}

/// A WireGuard device.
///
/// When enabled with the `native` feature, you can create a native device using the method [`native`](`Device::native`).
///
/// # Examples
///
/// Using `native`:
/// ```no_run
/// use wiretun::{Device, DeviceConfig};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let cfg = DeviceConfig::default();
///     let device = Device::native("utun", cfg).await?;
///     Ok(())
/// }
/// ```
pub struct Device<T>
where
    T: Tun + 'static,
{
    inner: Arc<Inner<T>>,
    inbound_handles: Arc<Mutex<(CancellationToken, Vec<JoinHandle<()>>)>>,
    outbound_handles: Arc<Mutex<(CancellationToken, Vec<JoinHandle<()>>)>>,
    token: CancellationToken,
}

#[cfg(feature = "native")]
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
        let token = CancellationToken::new();

        let inbound = Inbound::bind(cfg.listen_port).await?;
        cfg.listen_port = inbound.local_port();

        let secret = LocalStaticSecret::new(cfg.private_key);

        let peers = PeerIndex::new(token.child_token(), tun.clone(), secret.clone());
        cfg.peers.iter().for_each(|p| {
            peers.insert(
                p.public_key,
                p.allowed_ips.clone(),
                p.endpoint.map(|addr| inbound.endpoint_for(addr)),
            );
        });

        let cookie = Cookie::new(&secret);
        let rate_limiter = RateLimiter::new(1_000);
        let listener_v4 = inbound.v4();
        let listener_v6 = inbound.v6();

        let inner = {
            let cfg = Mutex::new(cfg);
            Arc::new(Inner {
                tun,
                secret,
                peers,
                cfg,
                cookie,
                rate_limiter,
                inbound: Mutex::new(inbound),
            })
        };

        let outbound_handles = {
            let token = token.child_token();
            Arc::new(Mutex::new((
                token.clone(),
                vec![tokio::spawn(loop_outbound(Arc::clone(&inner), token))],
            )))
        };
        let inbound_handles = {
            let token = token.child_token();
            Arc::new(Mutex::new((
                token.clone(),
                vec![
                    tokio::spawn(loop_inbound(Arc::clone(&inner), listener_v4, token.clone())),
                    tokio::spawn(loop_inbound(Arc::clone(&inner), listener_v6, token)),
                ],
            )))
        };

        Ok(Device {
            inner,
            inbound_handles,
            outbound_handles,
            token,
        })
    }

    #[inline]
    pub fn handle(&self) -> DeviceHandle<T> {
        DeviceHandle {
            token: self.token.clone(),
            inner: Arc::clone(&self.inner),
            inbound_handles: Arc::clone(&self.inbound_handles),
        }
    }

    pub async fn terminate(self) {
        self.token.cancel();

        let mut handles = vec![];
        handles.extend(&mut self.inbound_handles.lock().unwrap().1.drain(..));
        handles.extend(&mut self.outbound_handles.lock().unwrap().1.drain(..));

        join_all(handles).await;
    }
}

impl<T> Drop for Device<T>
where
    T: Tun,
{
    fn drop(&mut self) {
        self.token.cancel();
    }
}

/// A handle to a device.
///
/// This handle can be cloned and sent to other threads.
///
/// # Examples
///
/// ```no_run
/// use wiretun::{Device, DeviceConfig};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let cfg = DeviceConfig::default();
///     let device = Device::native("utun", cfg).await?;
///
///     let handle = device.handle();
///
///     let _ = handle.tun_name();  // fetch the name of the underlying TUN device
///     let _ = handle.config();    // fetch the configuration of the device
///     let _ = handle.peer_config(&[0; 32]); // fetch the configuration of a peer by its public key
///     let _ = handle.metrics();   // fetch the metrics of the device
///     let _ = handle.insert_peer([0; 32], vec![], None); // insert a peer
///
///     Ok(())
/// }
#[derive(Clone)]
pub struct DeviceHandle<T>
where
    T: Tun + 'static,
{
    token: CancellationToken,
    inner: Arc<Inner<T>>,
    inbound_handles: Arc<Mutex<(CancellationToken, Vec<JoinHandle<()>>)>>,
}

impl<T> DeviceHandle<T>
where
    T: Tun + 'static,
{
    /// Returns the name of the underlying TUN device.
    #[inline(always)]
    pub fn tun_name(&self) -> &str {
        self.inner.tun.name()
    }

    /// Returns the configuration of the device.
    #[inline(always)]
    pub fn config(&self) -> DeviceConfig {
        self.inner.config()
    }

    /// Returns the metrics of the device.
    #[inline(always)]
    pub fn metrics(&self) -> DeviceMetrics {
        self.inner.metrics()
    }

    pub async fn update_listen_port(&self, port: u16) -> Result<(), Error> {
        {
            let inbound = self.inner.inbound.lock().unwrap();
            if inbound.local_port() == port {
                return Ok(());
            }
        }

        let new_inbound = Inbound::bind(port).await?;
        let mut inbound = self.inner.inbound.lock().unwrap();
        if inbound.local_port() == port {
            return Ok(());
        }
        *inbound = new_inbound;

        let v4 = inbound.v4();
        let v6 = inbound.v6();

        let mut handles = self.inbound_handles.lock().unwrap();
        handles.0.cancel();

        for peer in &self.inner.cfg.lock().unwrap().peers {
            let pk = peer.public_key;
            if let Some(peer) = self.inner.peers.get_by_key(&pk) {
                if let Some(endpoint) = peer.endpoint() {
                    peer.update_endpoint(inbound.endpoint_for(endpoint.dst()));
                }
            }
        }

        let token = self.token.child_token();
        *handles = (
            token.clone(),
            vec![
                tokio::spawn(loop_inbound(Arc::clone(&self.inner), v4, token.clone())),
                tokio::spawn(loop_inbound(Arc::clone(&self.inner), v6, token)),
            ],
        );

        Ok(())
    }

    /// Returns the configuration of a peer by its public key.
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

    /// Inserts a new peer into the device.
    /// Returns `true` if the peer was inserted, `false` if a peer with the same public key already exists.
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
            public_key,
            allowed_ips,
            endpoint,
            preshared_key: None,
            persistent_keepalive: None,
        });
        true
    }

    /// Removes a peer from the device.
    pub fn remove_peer(&self, public_key: &[u8; 32]) {
        let mut cfg = self.inner.cfg.lock().unwrap();
        self.inner.peers.remove_by_key(public_key);
        cfg.peers.retain(|p| p.public_key != *public_key);
    }

    /// Updates the endpoint of a peer.
    pub fn update_peer_endpoint(&self, public_key: &[u8; 32], addr: SocketAddr) {
        let mut cfg = self.inner.cfg.lock().unwrap();
        if let Some(p) = self.inner.peers.get_by_key(public_key) {
            p.update_endpoint(self.inner.endpoint_for(addr))
        }
        if let Some(p) = cfg.peers.iter_mut().find(|p| p.public_key == *public_key) {
            p.endpoint = Some(addr);
        }
    }

    /// Updates the allowed IPs of a peer.
    pub fn update_allowed_ips_by_peer(&self, public_key: &[u8; 32], allowed_ips: Vec<Cidr>) {
        let mut cfg = self.inner.cfg.lock().unwrap();
        self.inner
            .peers
            .update_allowed_ips_by_key(public_key, allowed_ips.clone());
        if let Some(p) = cfg.peers.iter_mut().find(|p| p.public_key == *public_key) {
            p.allowed_ips = allowed_ips;
        }
    }

    /// Removes all peers from the device.
    pub fn clear_peers(&self) {
        let mut cfg = self.inner.cfg.lock().unwrap();
        self.inner.peers.clear();
        cfg.peers.clear();
    }
}

async fn loop_inbound<T>(inner: Arc<Inner<T>>, mut listener: Listener, token: CancellationToken)
where
    T: Tun + 'static,
{
    debug!("starting inbound loop for {}", listener);
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                debug!("stopping outbound loop for {}", listener);
                return;
            }
            data = listener.next() => {
                if let Some((endpoint, payload)) = data {
                    tick_inbound(Arc::clone(&inner), endpoint, payload).await;
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
                        if p.counter > protocol::REJECT_AFTER_MESSAGES {
                            warn!("received too many messages from peer [index={receiver_index}]");
                            return;
                        }

                        peer.handle_transport_data(endpoint, p, session).await;
                    }
                    _ => unreachable!(),
                }
            } else {
                warn!("received message from unknown peer [index={receiver_index}]");
            }
        }
        Err(e) => {
            warn!("failed to parse message type: {:?}", e);
        }
    }
}

async fn loop_outbound<T>(inner: Arc<Inner<T>>, token: CancellationToken)
where
    T: Tun + 'static,
{
    debug!("starting outbound loop");
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                debug!("stopping inbound loop");
                return;
            }
            _ = tick_outbound(Arc::clone(&inner)) => {}
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

            let peer = inner.peers.get_by_ip(dst);

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
