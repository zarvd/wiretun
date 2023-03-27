use std::io;
use std::sync::{
    atomic::{self, AtomicU64},
    Arc, RwLock,
};

use crate::device::peer::OutboundEvent;
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time;
use tracing::debug;

use super::session::{Session, SessionManager, Sessions};
use super::{
    handshake::Handshake, InboundEvent, InboundRx, InboundTx, Jitter, OutboundRx, OutboundTx,
};
use crate::listener::Endpoint;
use crate::noise::crypto::PeerStaticSecret;
use crate::noise::handshake::IncomingInitiation;
use crate::noise::protocol;
use crate::Tun;

struct Inner {
    tun: Tun,
    secret: PeerStaticSecret,
    sessions: RwLock<Sessions>,
    handshake: RwLock<Handshake>,
    endpoint: RwLock<Option<Endpoint>>,
    inbound: InboundTx,
    outbound: OutboundTx,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
}

impl Inner {
    pub fn new(tun: Tun, secret: PeerStaticSecret, session_mgr: SessionManager) -> Arc<Self> {
        let (inbound_tx, inbound_rx) = mpsc::channel(256);
        let (outbound_tx, outbound_rx) = mpsc::channel(256);
        let handshake = RwLock::new(Handshake::new(secret.clone()));
        let sessions = RwLock::new(Sessions::new(secret.clone(), session_mgr));
        let me = Arc::new(Self {
            tun,
            secret,
            handshake,
            sessions,
            endpoint: RwLock::new(None),
            inbound: inbound_tx,
            outbound: outbound_tx,
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
        });

        let jitter = Arc::new(Jitter::new());
        tokio::spawn(keepalive_loop(me.clone(), jitter.clone()));
        tokio::spawn(handshake_loop(me.clone(), jitter.clone()));
        tokio::spawn(inbound_loop(me.clone(), inbound_rx));
        tokio::spawn(outbound_loop(me.clone(), jitter, outbound_rx));

        me
    }

    #[inline]
    pub async fn stage_inbound(&self, e: InboundEvent) {
        self.inbound.send(e).await.unwrap();
    }

    #[inline]
    pub async fn stage_outbound(&self, e: OutboundEvent) {
        self.outbound.send(e).await.unwrap();
    }

    pub async fn send_buffer(&self, buf: &[u8]) -> Result<(), io::Error> {
        let endpoint = { self.endpoint.read().unwrap().clone() };
        match endpoint {
            Some(endpoint) => endpoint.send(buf).await?,
            None => return Err(io::Error::new(io::ErrorKind::Other, "not connected")),
        }
        self.tx_bytes
            .fetch_add(buf.len() as u64, atomic::Ordering::Relaxed);

        Ok(())
    }

    #[inline]
    fn update_endpoint(&self, endpoint: Endpoint) {
        let mut guard = self.endpoint.write().unwrap();
        let _ = guard.insert(endpoint);
    }
}

async fn handshake_loop(inner: Arc<Inner>, jitter: Arc<Jitter>) {
    todo!("stop when peer is dropped");
    loop {
        if jitter.can_send_handshake_initiation() {
            todo!("send handshake");

            jitter.mark_send_handshake_initiation();
        }
        time::sleep(jitter.handshake_initiation_timeout()).await;
    }
}

async fn keepalive_loop(inner: Arc<Inner>, jitter: Arc<Jitter>) {
    todo!("stop when peer is dropped");
    loop {
        if jitter.can_send_keepalive() {
            todo!("send keep alive");

            jitter.mark_send_data();
        }
        time::sleep(jitter.keepalive_timeout()).await;
    }
}

// Send to tun if we have a valid session
async fn inbound_loop(inner: Arc<Inner>, mut rx: InboundRx) {
    debug!("starting inbound loop for peer");

    while let Some(event) = rx.recv().await {
        match event {
            InboundEvent::HanshakeInitiation {
                endpoint,
                initiation,
            } => {
                let ret = {
                    let mut handshake = inner.handshake.write().unwrap();
                    handshake.respond(&initiation)
                };
                match ret {
                    Ok((session, packet)) => {
                        {
                            let mut sessions = inner.sessions.write().unwrap();
                            sessions.renew(session);
                        }
                        inner.update_endpoint(endpoint.clone());
                        endpoint.send(&packet).await.unwrap();
                    }
                    Err(e) => {
                        debug!("failed to respond to handshake initiation: {}", e);
                    }
                }
            }
            InboundEvent::HandshakeResponse {
                endpoint,
                packet,
                session,
            } => {
                let ret = {
                    let mut handshake = inner.handshake.write().unwrap();
                    handshake.finalize(&packet)
                };
                match ret {
                    Ok(session) => {
                        {
                            let mut sessions = inner.sessions.write().unwrap();
                            sessions.renew(session);
                        }
                        inner.update_endpoint(endpoint.clone());
                    }
                    Err(e) => {
                        debug!("failed to finalize handshake: {}", e);
                    }
                }
            }
            InboundEvent::CookieReply { .. } => {}
            InboundEvent::TransportData { .. } => {}
        }
    }
    debug!("exiting inbound loop for peer");
}

// Send to endpoint if connected, otherwise queue for later
async fn outbound_loop(inner: Arc<Inner>, jitter: Arc<Jitter>, mut rx: OutboundRx) {
    debug!("starting outbound loop for peer");

    while let Some(OutboundEvent::Data(data)) = rx.recv().await {
        let endpoint = { inner.endpoint.read().unwrap().clone() };
        if let Some(endpoint) = endpoint {
            endpoint.send(&data).await.unwrap();
        }
    }
    debug!("exiting outbound loop for peer");
}

#[derive(Clone)]
pub struct Peer {
    inner: Arc<Inner>,
}

impl Peer {
    pub(super) fn new(tun: Tun, secret: PeerStaticSecret, session_mgr: SessionManager) -> Self {
        Self {
            inner: Inner::new(tun, secret, session_mgr),
        }
    }

    pub fn secret(&self) -> &PeerStaticSecret {
        &self.inner.secret
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
        &mut self,
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
        &mut self,
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

    // Stage outbound data to be sent to the peer
    pub async fn stage_outbound(&mut self, _buf: Bytes) {}
}
