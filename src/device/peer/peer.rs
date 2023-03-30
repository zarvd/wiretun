use std::fmt::{Debug, Display, Formatter};
use std::sync::{
    atomic::{self, AtomicBool},
    Arc, RwLock,
};

use tokio::sync::mpsc;
use tokio::time;
use tracing::{debug, info, warn};

use super::session::{Session, SessionManager, Sessions};
use super::{
    handshake::Handshake, monitor, InboundEvent, InboundRx, InboundTx, OutboundEvent, OutboundRx,
    OutboundTx, PeerMetrics, PeerMonitor,
};
use crate::device::outbound::Endpoint;
use crate::noise::crypto::PeerStaticSecret;
use crate::noise::handshake::IncomingInitiation;
use crate::noise::protocol::{CookieReply, HandshakeResponse, TransportData};
use crate::noise::{crypto, protocol};
use crate::Tun;

#[derive(Clone)]
pub(crate) struct Peer<T>
where
    T: Tun,
{
    inner: Arc<Inner<T>>,
}

impl<T> Peer<T>
where
    T: Tun + 'static,
{
    pub(super) fn new(
        tun: T,
        secret: PeerStaticSecret,
        session_mgr: SessionManager,
        endpoint: Option<Endpoint>,
    ) -> Self {
        let inner = Inner::new(tun, secret, session_mgr);
        if let Some(endpoint) = endpoint {
            inner.update_endpoint(endpoint);
        }

        Self { inner }
    }

    #[inline]
    pub async fn handle_handshake_initiation(
        &self,
        endpoint: Endpoint,
        initiation: IncomingInitiation,
    ) {
        self.inner
            .stage_inbound(InboundEvent::HanshakeInitiation {
                endpoint,
                initiation,
            })
            .await;
    }

    #[inline]
    pub async fn handle_handshake_response(
        &self,
        endpoint: Endpoint,
        packet: protocol::HandshakeResponse,
        session: Session,
    ) {
        self.inner
            .stage_inbound(InboundEvent::HandshakeResponse {
                endpoint,
                packet,
                session,
            })
            .await;
    }

    #[inline]
    pub async fn handle_cookie_reply(
        &self,
        endpoint: Endpoint,
        packet: protocol::CookieReply,
        session: Session,
    ) {
        self.inner
            .stage_inbound(InboundEvent::CookieReply {
                endpoint,
                packet,
                session,
            })
            .await;
    }

    #[inline]
    pub async fn handle_transport_data(
        &self,
        endpoint: Endpoint,
        packet: protocol::TransportData,
        session: Session,
    ) {
        self.inner
            .stage_inbound(InboundEvent::TransportData {
                endpoint,
                packet,
                session,
            })
            .await;
    }

    /// Stage outbound data to be sent to the peer
    #[inline]
    pub async fn stage_outbound(&self, buf: Vec<u8>) {
        self.inner.stage_outbound(OutboundEvent::Data(buf)).await;
    }

    #[inline]
    pub fn metrics(&self) -> PeerMetrics {
        self.inner.monitor.metrics()
    }

    /// Stop the peer and all its associated tasks.
    /// The lifetime of the peer is managed by the [`Peers`].
    #[inline]
    pub(super) fn stop(&self) {
        self.inner.running.store(false, atomic::Ordering::SeqCst);
        let _ = self.inner.inbound.blocking_send(InboundEvent::EOF);
        let _ = self.inner.outbound.blocking_send(OutboundEvent::EOF);
    }
}

struct Inner<T> {
    running: AtomicBool,
    tun: T,
    secret: PeerStaticSecret,
    sessions: RwLock<Sessions>,
    handshake: RwLock<Handshake>,
    endpoint: RwLock<Option<Endpoint>>,
    inbound: InboundTx,
    outbound: OutboundTx,
    monitor: PeerMonitor,
}

impl<T> Inner<T>
where
    T: Tun + 'static,
{
    pub fn new(tun: T, secret: PeerStaticSecret, session_mgr: SessionManager) -> Arc<Self> {
        let (inbound_tx, inbound_rx) = mpsc::channel(256);
        let (outbound_tx, outbound_rx) = mpsc::channel(256);
        let handshake = RwLock::new(Handshake::new(secret.clone()));
        let sessions = RwLock::new(Sessions::new(secret.clone(), session_mgr));
        let me = Arc::new(Self {
            running: AtomicBool::new(true),
            tun,
            secret,
            handshake,
            sessions,
            endpoint: RwLock::new(None),
            inbound: inbound_tx,
            outbound: outbound_tx,
            monitor: PeerMonitor::new(),
        });

        tokio::spawn(loop_handshake(me.clone()));
        tokio::spawn(loop_inbound(me.clone(), inbound_rx));
        tokio::spawn(loop_outbound(me.clone(), outbound_rx));

        me
    }

    /// Stage inbound data from tun.
    #[inline]
    pub async fn stage_inbound(&self, e: InboundEvent) {
        self.inbound.send(e).await.unwrap();
    }

    /// Stage outbound data to be sent to the peer.
    #[inline]
    pub async fn stage_outbound(&self, e: OutboundEvent) {
        self.outbound.send(e).await.unwrap();
    }

    /// Send keepalive packet to the peer if the traffic is idle.
    #[inline]
    pub async fn keepalive(&self) {
        if !self.monitor.traffic().can_keepalive() {
            return;
        }
        self.outbound
            .send(OutboundEvent::Data(vec![]))
            .await
            .unwrap();
    }

    /// Update the endpoint of the peer.
    /// Could be called by IPC or the inbound loop.
    #[inline]
    pub fn update_endpoint(&self, endpoint: Endpoint) {
        let mut guard = self.endpoint.write().unwrap();
        let _ = guard.insert(endpoint);
    }

    /// Send outbound data to the peer.
    /// This method is called by the outbound loop and handshake loop.
    #[inline]
    async fn send_outbound(&self, buf: &[u8]) {
        let endpoint = { self.endpoint.read().unwrap().clone() };
        if let Some(endpoint) = endpoint {
            endpoint.send(buf).await.unwrap();
        } else {
            debug!("no endpoint to send outbound packet to peer {self}");
        }
    }
}

impl<T> Display for Inner<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Peer({})",
            crypto::encode_to_hex(&self.secret.public_key().to_bytes())
        )
    }
}

impl<T> Debug for Inner<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field(
                "public_key",
                &crypto::encode_to_hex(&self.secret.public_key().to_bytes()),
            )
            .finish()
    }
}

async fn loop_handshake<T>(inner: Arc<Inner<T>>)
where
    T: Tun + 'static,
{
    debug!("starting handshake loop for peer {inner}");
    while inner.running.load(atomic::Ordering::Relaxed) {
        if inner.monitor.handshake().can_initiation() {
            info!("initiating handshake");
            let packet = {
                let (next, packet) = inner.handshake.write().unwrap().initiate();
                let mut sessions = inner.sessions.write().unwrap();
                sessions.prepare_next(next);
                packet
            };

            inner.send_outbound(&packet).await; // send directly
            inner.monitor.handshake().initiated();
        }
        time::sleep_until(inner.monitor.handshake().initiation_at().into()).await;
    }
    debug!("exiting handshake loop for peer {inner}")
    // close all loop
}

// Send to endpoint if connected, otherwise queue for later
async fn loop_outbound<T>(inner: Arc<Inner<T>>, mut rx: OutboundRx)
where
    T: Tun + 'static,
{
    debug!("starting outbound loop for peer {inner}");

    loop {
        tokio::select! {
            _ = time::sleep(monitor::KEEPALIVE_TIMEOUT) => {
                inner.keepalive().await;
            }
            event = rx.recv() => {
                if let Some(OutboundEvent::Data(data)) = event {
                    tick_outbound(inner.clone(), data).await;
                } else {
                    break;
                }
            }
        }
    }

    debug!("exiting outbound loop for peer {inner}");
}

async fn tick_outbound<T>(inner: Arc<Inner<T>>, data: Vec<u8>)
where
    T: Tun + 'static,
{
    let session = { inner.sessions.read().unwrap().current().clone() };
    let session = if let Some(s) = session { s } else { return };

    match session.encrypt_data(&data) {
        Ok(packet) => {
            let buf = packet.to_bytes();
            inner.send_outbound(&buf).await;
            inner.monitor.traffic().outbound(buf.len());
        }
        Err(e) => {
            warn!("failed to encrypt packet: {}", e);
        }
    }
}

// Send to tun if we have a valid session
async fn loop_inbound<T>(inner: Arc<Inner<T>>, mut rx: InboundRx)
where
    T: Tun + 'static,
{
    debug!("starting inbound loop for peer {inner}");

    while let Some(event) = rx.recv().await {
        match event {
            InboundEvent::HanshakeInitiation {
                endpoint,
                initiation,
            } => handle_handshake_inititation(inner.clone(), endpoint, initiation).await,
            InboundEvent::HandshakeResponse {
                endpoint,
                packet,
                session,
            } => handle_handshake_response(inner.clone(), endpoint, packet, session).await,
            InboundEvent::CookieReply {
                endpoint,
                packet,
                session,
            } => handle_cookie_reply(inner.clone(), endpoint, packet, session).await,
            InboundEvent::TransportData {
                endpoint,
                packet,
                session,
            } => handle_transport_data(inner.clone(), endpoint, packet, session).await,
            InboundEvent::EOF => break,
        }
    }
    debug!("exiting inbound loop for peer {inner}");
}

async fn handle_handshake_inititation<T>(
    inner: Arc<Inner<T>>,
    endpoint: Endpoint,
    initiation: IncomingInitiation,
) where
    T: Tun + 'static,
{
    let ret = {
        let mut handshake = inner.handshake.write().unwrap();
        handshake.respond(&initiation)
    };
    match ret {
        Ok((session, packet)) => {
            {
                let mut sessions = inner.sessions.write().unwrap();
                sessions.prepare_next(session);
            }
            inner.update_endpoint(endpoint.clone());
            endpoint.send(&packet).await.unwrap();
        }
        Err(e) => debug!("failed to respond to handshake initiation: {e}"),
    }
}

async fn handle_handshake_response<T>(
    inner: Arc<Inner<T>>,
    endpoint: Endpoint,
    packet: HandshakeResponse,
    _session: Session,
) where
    T: Tun + 'static,
{
    let ret = {
        let mut handshake = inner.handshake.write().unwrap();
        handshake.finalize(&packet)
    };
    match ret {
        Ok(session) => {
            {
                let mut sessions = inner.sessions.write().unwrap();
                sessions.rotate(session);
            }
            inner.monitor.handshake().completed();
            info!("handshake completed");
            inner.update_endpoint(endpoint);
            inner.keepalive().await; // let the peer know the session is valid
        }
        Err(e) => debug!("failed to finalize handshake: {e}"),
    }
}

async fn handle_cookie_reply<T>(
    _inner: Arc<Inner<T>>,
    _endpoint: Endpoint,
    _packet: CookieReply,
    _session: Session,
) where
    T: Tun + 'static,
{
}

async fn handle_transport_data<T>(
    inner: Arc<Inner<T>>,
    endpoint: Endpoint,
    packet: TransportData,
    session: Session,
) where
    T: Tun + 'static,
{
    {
        let mut sessions = inner.sessions.write().unwrap();
        if sessions.try_rotate(session.clone()) {
            info!("handshake completed");
            inner.monitor.handshake().completed();
        }
    }
    if !session.can_accept(packet.counter) {
        debug!("dropping packet due to replay");
        return;
    }

    inner.update_endpoint(endpoint);
    match session.decrypt_data(&packet) {
        Ok(data) => {
            if data.is_empty() {
                // keepalive
                return;
            }

            debug!("recv data from peer and try to send it to TUN");
            inner.tun.send(&data).await.unwrap();
            session.aceept(packet.counter);
        }
        Err(e) => debug!("failed to decrypt packet: {e}"),
    }
}
