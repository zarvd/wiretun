mod config;
mod error;
mod handle;
mod inbound;
mod metrics;
mod peer;
mod rate_limiter;
mod time;

pub use config::{DeviceConfig, PeerConfig};
pub use error::Error;
pub use inbound::{Endpoint, Transport, UdpTransport};
pub use metrics::DeviceMetrics;
pub use peer::{Cidr, ParseCidrError, PeerMetrics};

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::noise::crypto::LocalStaticSecret;
use crate::noise::handshake::Cookie;
use crate::Tun;
use handle::DeviceHandle;
use inbound::Inbound;
use peer::{Peer, PeerIndex, Session};
use rate_limiter::RateLimiter;

struct Settings<I>
where
    I: Transport,
{
    secret: LocalStaticSecret,
    fwmark: u32,
    cookie: Arc<Cookie>,
    inbound: Inbound<I>,
}

impl<I> Settings<I>
where
    I: Transport,
{
    pub fn new(inbound: Inbound<I>, private_key: [u8; 32], fwmark: u32) -> Self {
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
        self.inbound.port()
    }
}

pub(super) struct DeviceInner<T, I>
where
    T: Tun + 'static,
    I: Transport,
{
    tun: T,
    settings: Mutex<Settings<I>>,
    peers: Mutex<PeerIndex<T, I>>,
    rate_limiter: RateLimiter,
}

impl<T, I> DeviceInner<T, I>
where
    T: Tun + 'static,
    I: Transport,
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
        self.reset_peers(peers.to_config());
    }

    #[inline]
    pub fn get_peer_by_key(&self, public_key: &[u8; 32]) -> Option<Arc<Peer<T, I>>> {
        let index = self.peers.lock().unwrap();
        index.get_by_key(public_key)
    }

    #[inline]
    pub fn get_session_by_index(&self, i: u32) -> Option<(Session, Arc<Peer<T, I>>)> {
        let index = self.peers.lock().unwrap();
        index.get_session_by_index(i)
    }

    #[inline]
    pub fn reset_peers(&self, peers: Vec<PeerConfig>) {
        let settings = self.settings.lock().unwrap();
        let mut index = self.peers.lock().unwrap();
        index.clear();
        for p in peers {
            let mut secret = settings.secret.clone().with_peer(p.public_key);
            if let Some(psk) = p.preshared_key {
                secret.set_psk(psk);
            }
            let endpoint = p.endpoint.map(|addr| settings.inbound.endpoint_for(addr));
            index.insert(secret, p.allowed_ips, endpoint);
        }
    }

    #[inline]
    pub fn insert_peer(&self, cfg: PeerConfig) {
        let settings = self.settings.lock().unwrap();
        let mut index = self.peers.lock().unwrap();
        let mut secret = settings.secret.clone().with_peer(cfg.public_key);
        if let Some(psk) = cfg.preshared_key {
            secret.set_psk(psk);
        }
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
    fn update_inbound(&self, inbound: Inbound<I>) {
        let mut settings = self.settings.lock().unwrap();
        let peers = self.peers.lock().unwrap();
        settings.inbound = inbound;
        for p in peers.all() {
            if let Some(endpoint) = p.endpoint() {
                p.update_endpoint(settings.inbound.endpoint_for(endpoint.dst()));
            }
        }
    }

    #[inline]
    pub fn update_peer_allowed_ips(&self, public_key: &[u8; 32], ips: HashSet<Cidr>) {
        let mut peers = self.peers.lock().unwrap();
        peers.update_allowed_ips_by_key(public_key, ips);
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
pub struct Device<T, I>
where
    T: Tun + 'static,
    I: Transport,
{
    token: CancellationToken, // The root token
    inner: Arc<DeviceInner<T, I>>,
    handle: Arc<AsyncMutex<DeviceHandle>>,
}

#[cfg(feature = "native")]
impl Device<crate::NativeTun, UdpTransport> {
    /// Creates a new device with the given configuration using [`crate::tun::NativeTun`].
    pub async fn native(name: &str, cfg: DeviceConfig) -> Result<Self, Error> {
        let tun = crate::NativeTun::new(name).map_err(Error::Tun)?;
        Device::with_udp(tun, cfg).await
    }
}

impl<T> Device<T, UdpTransport>
where
    T: Tun + 'static,
{
    /// Creates a new device with the given configuration.
    /// It uses UDP transport and binds to `cfg.listen_port`.
    pub async fn with_udp(tun: T, cfg: DeviceConfig) -> Result<Self, Error> {
        let transport =
            UdpTransport::bind(cfg.listen_addrs.0, cfg.listen_addrs.1, cfg.listen_port).await?;
        Self::with_transport(tun, transport, cfg).await
    }
}

impl<T, I> Device<T, I>
where
    T: Tun + 'static,
    I: Transport,
{
    /// Creates a new device with the given configuration.
    /// The `cfg.listen_port` is ignored if the transport is already bound.
    pub async fn with_transport(tun: T, transport: I, cfg: DeviceConfig) -> Result<Self, Error> {
        let token = CancellationToken::new();
        let inner = {
            let inbound = Inbound::new(transport);
            let settings = Mutex::new(Settings::new(inbound, cfg.private_key, cfg.fwmark));
            let peers = Mutex::new(PeerIndex::new(token.child_token(), tun.clone()));
            let rate_limiter = RateLimiter::new(1_000);

            Arc::new(DeviceInner {
                tun,
                settings,
                peers,
                rate_limiter,
            })
        };
        let handle = Arc::new(AsyncMutex::new(
            DeviceHandle::spawn(token.child_token(), Arc::clone(&inner)).await,
        ));

        inner.reset_peers(cfg.peers.into_values().collect());

        Ok(Device {
            token,
            inner,
            handle,
        })
    }

    /// Returns a control handle to the device.
    #[inline]
    pub fn control(&self) -> DeviceControl<T, I> {
        DeviceControl {
            inner: Arc::clone(&self.inner),
            handle: Arc::clone(&self.handle),
        }
    }

    /// Terminates the device and waits for it to stop.
    pub async fn terminate(self) {
        self.token.cancel();
        let mut handle = self.handle.lock().await;
        handle.stop().await;
    }
}

impl<T, I> Drop for Device<T, I>
where
    T: Tun,
    I: Transport,
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
///     let ctrl = device.control();
///
///     let _ = ctrl.tun_name();  // fetch the name of the underlying TUN device
///     let _ = ctrl.config();    // fetch the configuration of the device
///     let _ = ctrl.metrics();   // fetch the metrics of the device
///
///     Ok(())
/// }
#[derive(Clone)]
pub struct DeviceControl<T, I>
where
    T: Tun + 'static,
    I: Transport,
{
    inner: Arc<DeviceInner<T, I>>,
    handle: Arc<AsyncMutex<DeviceHandle>>,
}

impl<T, I> DeviceControl<T, I>
where
    T: Tun + 'static,
    I: Transport,
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
            listen_addrs: (settings.inbound.ipv4(), settings.inbound.ipv6()),
            listen_port: settings.listen_port(),
            fwmark: settings.fwmark,
            peers: peers
                .to_config()
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

    /// Updates the private key of the device.
    pub fn update_private_key(&self, private_key: [u8; 32]) {
        self.inner.reset_private_key(private_key);
    }

    /// Update the listen port of the device.
    pub async fn update_listen_port(&self, port: u16) -> Result<(), Error> {
        let (ipv4, ipv6) = {
            let settings = self.inner.settings.lock().unwrap();
            if settings.listen_port() == port {
                debug!("The listen port is the same with the old one, skip updating");
                return Ok(());
            }
            (settings.inbound.ipv4(), settings.inbound.ipv6())
        };
        let inbound = Inbound::new(<I as Transport>::bind(ipv4, ipv6, port).await?);
        self.inner.update_inbound(inbound);

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
    pub fn update_peer_allowed_ips(&self, public_key: &[u8; 32], allowed_ips: HashSet<Cidr>) {
        self.inner.update_peer_allowed_ips(public_key, allowed_ips);
    }

    /// Removes all peers from the device.
    pub fn clear_peers(&self) {
        self.inner.reset_peers(vec![]);
    }
}
