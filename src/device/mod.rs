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
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

use crate::noise::crypto::LocalStaticSecret;
use crate::noise::handshake::{Cookie, IncomingInitiation};
use crate::noise::protocol;
use crate::noise::protocol::Message;
use crate::Tun;
use inbound::{Endpoint, Inbound, Listener};
use peer::{Peer, PeerIndex, Session};
use rate_limiter::RateLimiter;

struct Settings {
    secret: LocalStaticSecret,
    fwmark: u32,
    cookie: Arc<Cookie>,
    inbound: Inbound,
}

impl Settings {
    pub fn new(inbound: Inbound, private_key: [u8; 32], fwmark: u32) -> Self {
        let secret = LocalStaticSecret::new(private_key);
        let cookie = Arc::new(Cookie::new(&secret));

        Self {
            secret,
            fwmark,
            cookie,
            inbound,
        }
    }

    #[inline(always)]
    pub fn listen_port(&self) -> u16 {
        self.inbound.local_port()
    }
}

struct Inner<T>
where
    T: Tun + 'static,
{
    tun: T,
    settings: Mutex<Settings>,
    peers: Mutex<PeerIndex<T>>,
    rate_limiter: RateLimiter,
}

impl<T> Inner<T>
where
    T: Tun + 'static,
{
    #[inline]
    pub fn metrics(&self) -> DeviceMetrics {
        let peers = self.peers.lock().unwrap().metrics();
        DeviceMetrics { peers }
    }

    #[inline]
    pub fn reset_private_key(&self, private_key: [u8; 32]) {
        {
            let mut settings = self.settings.lock().unwrap();
            if settings.secret.private_key().to_bytes() == private_key {
                debug!("The private key is the same with the old one, skip updating");
                return;
            }
            settings.secret = LocalStaticSecret::new(private_key);
        }
        let peers = self.peers.lock().unwrap();
        self.reset_peers(peers.to_vec());
    }

    #[inline]
    pub fn get_peer_by_key(&self, public_key: &[u8; 32]) -> Option<Peer<T>> {
        let index = self.peers.lock().unwrap();
        index.get_by_key(public_key)
    }

    #[inline]
    pub fn get_session_by_index(&self, i: u32) -> Option<(Session, Peer<T>)> {
        let index = self.peers.lock().unwrap();
        index.get_session_by_index(i)
    }

    #[inline]
    pub fn reset_peers(&self, peers: Vec<PeerConfig>) {
        let settings = self.settings.lock().unwrap();
        let mut index = self.peers.lock().unwrap();
        index.clear();
        for p in peers {
            let secret = settings.secret.clone().with_peer(p.public_key);
            let endpoint = p.endpoint.map(|addr| settings.inbound.endpoint_for(addr));
            index.insert(secret, p.allowed_ips, endpoint);
        }
    }

    #[inline]
    pub fn insert_peer(&self, cfg: PeerConfig) {
        let settings = self.settings.lock().unwrap();
        let mut index = self.peers.lock().unwrap();
        let secret = settings.secret.clone().with_peer(cfg.public_key);
        let endpoint = cfg.endpoint.map(|addr| settings.inbound.endpoint_for(addr));
        index.insert(secret, cfg.allowed_ips, endpoint);
    }

    #[inline]
    pub fn remove_peer(&self, public_key: &[u8; 32]) {
        let mut peers = self.peers.lock().unwrap();
        peers.remove_by_key(public_key);
    }

    #[inline]
    pub fn update_peer_endpoint(&self, public_key: &[u8; 32], addr: SocketAddr) {
        let peers = self.peers.lock().unwrap();
        if let Some(p) = peers.get_by_key(public_key) {
            let settings = self.settings.lock().unwrap();
            let endpoint = settings.inbound.endpoint_for(addr);
            p.update_endpoint(endpoint);
        }
    }

    #[inline]
    pub fn update_peer_allowed_ips(&self, public_key: &[u8; 32], ips: Vec<Cidr>) {
        let mut peers = self.peers.lock().unwrap();
        peers.update_allowed_ips_by_key(public_key, ips);
    }
}

struct Handle {
    token: CancellationToken,
    inbound_handles: (CancellationToken, Vec<JoinHandle<()>>),
    outbound_handles: (CancellationToken, Vec<JoinHandle<()>>),
}

impl Handle {
    pub async fn spawn<T>(token: CancellationToken, inner: Arc<Inner<T>>) -> Self
    where
        T: Tun + 'static,
    {
        let mut me = Self {
            token: token.clone(),
            inbound_handles: (token.child_token(), vec![]),
            outbound_handles: (token.child_token(), vec![]),
        };
        me.restart_inbound(Arc::clone(&inner)).await;
        me.restart_outbound(Arc::clone(&inner)).await;
        me
    }

    pub async fn restart_inbound<T>(&mut self, inner: Arc<Inner<T>>)
    where
        T: Tun + 'static,
    {
        let handles: Vec<_> = self.inbound_handles.1.drain(..).collect();
        join_all(handles).await;

        let token = self.token.child_token();
        let handles = vec![
            tokio::spawn(loop_inbound_v4(Arc::clone(&inner), token.child_token())),
            tokio::spawn(loop_inbound_v6(Arc::clone(&inner), token.child_token())),
        ];
        self.inbound_handles = (token, handles);
    }

    pub async fn restart_outbound<T>(&mut self, inner: Arc<Inner<T>>)
    where
        T: Tun + 'static,
    {
        let handles: Vec<_> = self.outbound_handles.1.drain(..).collect();
        join_all(handles).await;

        let token = self.token.child_token();
        let handles = vec![tokio::spawn(loop_outbound(
            Arc::clone(&inner),
            token.child_token(),
        ))];
        self.outbound_handles = (token, handles);
    }

    pub fn abort(&self) {
        self.inbound_handles.0.cancel();
        self.outbound_handles.0.cancel();
    }

    pub async fn stop(&mut self) {
        self.abort();

        // Wait until all background tasks are done.
        let mut handles = vec![];
        handles.extend(&mut self.inbound_handles.1.drain(..));
        handles.extend(&mut self.outbound_handles.1.drain(..));

        join_all(handles).await;
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.token.cancel();
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
    token: CancellationToken, // The root token
    inner: Arc<Inner<T>>,
    handle: Arc<AsyncMutex<Handle>>,
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
    pub async fn with_tun(tun: T, cfg: DeviceConfig) -> Result<Self, Error> {
        let token = CancellationToken::new();
        let inner = {
            let inbound = Inbound::bind(cfg.listen_port).await?;
            let settings = Mutex::new(Settings::new(inbound, cfg.private_key, cfg.fwmark));
            let peers = Mutex::new(PeerIndex::new(token.child_token(), tun.clone()));
            let rate_limiter = RateLimiter::new(1_000);

            Arc::new(Inner {
                tun,
                settings,
                peers,
                rate_limiter,
            })
        };
        let handle = Arc::new(AsyncMutex::new(
            Handle::spawn(token.child_token(), Arc::clone(&inner)).await,
        ));

        inner.reset_peers(cfg.peers.into_values().collect());

        Ok(Device {
            token,
            inner,
            handle,
        })
    }

    #[inline]
    pub fn handle(&self) -> DeviceHandle<T> {
        DeviceHandle {
            inner: Arc::clone(&self.inner),
            handle: Arc::clone(&self.handle),
        }
    }

    pub async fn terminate(self) {
        self.token.cancel();

        let mut handle = self.handle.lock().await;
        handle.stop().await;
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
///     let _ = handle.metrics();   // fetch the metrics of the device
///
///     Ok(())
/// }
#[derive(Clone)]
pub struct DeviceHandle<T>
where
    T: Tun + 'static,
{
    inner: Arc<Inner<T>>,
    handle: Arc<AsyncMutex<Handle>>,
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
        let settings = self.inner.settings.lock().unwrap();
        let peers = self.inner.peers.lock().unwrap();
        DeviceConfig {
            private_key: settings.secret.private_key().to_bytes(),
            listen_port: settings.listen_port(),
            fwmark: settings.fwmark,
            peers: peers
                .to_vec()
                .into_iter()
                .map(|p| (p.public_key, p))
                .collect(),
        }
    }

    /// Returns the metrics of the device.
    #[inline(always)]
    pub fn metrics(&self) -> DeviceMetrics {
        self.inner.metrics()
    }

    pub fn update_private_key(&self, private_key: [u8; 32]) {
        self.inner.reset_private_key(private_key);
    }

    pub async fn update_listen_port(&self, port: u16) -> Result<(), Error> {
        {
            let settings = self.inner.settings.lock().unwrap();
            if settings.listen_port() == port {
                debug!("The listen port is the same with the old one, skip updating");
                return Ok(());
            }
        }
        {
            let inbound = Inbound::bind(port).await?;
            let mut settings = self.inner.settings.lock().unwrap();
            settings.inbound = inbound;
        }
        let mut handle = self.handle.lock().await;
        handle.restart_inbound(Arc::clone(&self.inner)).await;
        Ok(())
    }

    /// Inserts a new peer into the device.
    pub fn insert_peer(&self, cfg: PeerConfig) {
        self.inner.insert_peer(cfg);
    }

    /// Removes a peer from the device.
    pub fn remove_peer(&self, public_key: &[u8; 32]) {
        self.inner.remove_peer(public_key);
    }

    /// Updates the endpoint of a peer.
    pub fn update_peer_endpoint(&self, public_key: &[u8; 32], addr: SocketAddr) {
        self.inner.update_peer_endpoint(public_key, addr);
    }

    /// Updates the allowed IPs of a peer.
    pub fn update_peer_allowed_ips(&self, public_key: &[u8; 32], allowed_ips: Vec<Cidr>) {
        self.inner.update_peer_allowed_ips(public_key, allowed_ips);
    }

    /// Removes all peers from the device.
    pub fn clear_peers(&self) {
        self.inner.reset_peers(vec![]);
    }
}

#[inline(always)]
async fn loop_inbound_v4<T>(inner: Arc<Inner<T>>, token: CancellationToken)
where
    T: Tun + 'static,
{
    let listener = inner.settings.lock().unwrap().inbound.v4();

    loop_inbound(inner, listener, token).await;
}

#[inline(always)]
async fn loop_inbound_v6<T>(inner: Arc<Inner<T>>, token: CancellationToken)
where
    T: Tun + 'static,
{
    let listener = inner.settings.lock().unwrap().inbound.v6();
    loop_inbound(inner, listener, token).await;
}

async fn loop_inbound<T>(inner: Arc<Inner<T>>, mut listener: Listener, token: CancellationToken)
where
    T: Tun + 'static,
{
    debug!("starting inbound loop for {}", listener);
    let (secret, cookie) = {
        let settings = inner.settings.lock().unwrap();
        (settings.secret.clone(), Arc::clone(&settings.cookie))
    };

    loop {
        tokio::select! {
            _ = token.cancelled() => {
                debug!("stopping outbound loop for {}", listener);
                return;
            }
            data = listener.next() => {
                if let Some((endpoint, payload)) = data {
                    tick_inbound(Arc::clone(&inner), &secret, Arc::clone(&cookie), endpoint, payload).await;
                }
            }
        }
    }
}

async fn tick_inbound<T>(
    inner: Arc<Inner<T>>,
    secret: &LocalStaticSecret,
    cookie: Arc<Cookie>,
    endpoint: Endpoint,
    payload: Vec<u8>,
) where
    T: Tun + 'static,
{
    if Message::is_handshake(&payload) {
        if !cookie.validate_mac1(&payload) {
            debug!("invalid mac1");
            return;
        }

        if !inner.rate_limiter.fetch_token() {
            debug!("rate limited");
            if !cookie.validate_mac2(&payload) {
                debug!("invalid mac2");
                return;
            }
            debug!("try to send cookie reply");
            let reply = cookie.generate_cookie_reply(&payload, endpoint.dst());
            endpoint.send(&reply).await.unwrap();
            return;
        }
    }

    match Message::parse(&payload) {
        Ok(Message::HandshakeInitiation(p)) => {
            let initiation = IncomingInitiation::parse(secret, &p).unwrap_or_else(|_| todo!());
            if let Some(peer) = inner.get_peer_by_key(initiation.static_public_key.as_bytes()) {
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
            if let Some((session, peer)) = inner.get_session_by_index(receiver_index) {
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

            let peer = inner.peers.lock().unwrap().get_by_ip(dst);

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
