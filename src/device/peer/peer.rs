use std::sync::{
    atomic::{self, AtomicBool},
    Arc, RwLock,
};

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time;
use tracing::debug;

use super::session::{Session, SessionManager, Sessions};
use super::{
    handshake::Handshake, InboundEvent, InboundRx, InboundTx, Jitter, OutboundEvent, OutboundRx,
    OutboundTx,
};
use crate::listener::Endpoint;
use crate::noise::crypto::PeerStaticSecret;
use crate::noise::handshake::IncomingInitiation;
use crate::noise::protocol;
use crate::Tun;

#[derive(Clone)]
pub struct Peer {
    inner: Arc<Inner>,
}

impl Peer {
    pub(super) fn new(
        tun: Tun,
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

struct Inner {
    running: AtomicBool,
    tun: Tun,
    secret: PeerStaticSecret,
    sessions: RwLock<Sessions>,
    handshake: RwLock<Handshake>,
    endpoint: RwLock<Option<Endpoint>>,
    inbound: InboundTx,
    outbound: OutboundTx,
    jitter: Jitter,
}

impl Inner {
    pub fn new(tun: Tun, secret: PeerStaticSecret, session_mgr: SessionManager) -> Arc<Self> {
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
            jitter: Jitter::new(),
        });

        tokio::spawn(handshake_loop(me.clone()));
        tokio::spawn(inbound_loop(me.clone(), inbound_rx));
        tokio::spawn(outbound_loop(me.clone(), outbound_rx));

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

    #[inline]
    pub async fn send_outbound(&self, buf: &[u8]) {
        debug!("sending outbound packet to peer ({:?} bytes)", buf.len());
        let endpoint = { self.endpoint.read().unwrap().clone() };
        if let Some(endpoint) = endpoint {
            endpoint.send(buf).await.unwrap();
        } else {
            debug!("no endpoint to send outbound packet to peer");
        }
    }

    #[inline]
    pub async fn keepalive(&self) {
        if !self.jitter.can_keepalive() {
            return;
        }
        self.outbound
            .send(OutboundEvent::Data(vec![]))
            .await
            .unwrap();
    }

    #[inline]
    pub fn update_endpoint(&self, endpoint: Endpoint) {
        let mut guard = self.endpoint.write().unwrap();
        let _ = guard.insert(endpoint);
    }
}

async fn handshake_loop(inner: Arc<Inner>) {
    debug!("starting handshake loop for peer");
    while inner.running.load(atomic::Ordering::Relaxed) {
        if inner.jitter.can_handshake_initiation() {
            debug!("initiating handshake");
            let packet = inner.handshake.write().unwrap().initiate();
            inner.send_outbound(&packet).await; // send directly
            inner.jitter.mark_handshake_initiation();
        }
        debug!("waiting until next handshake initiation");
        time::sleep_until(inner.jitter.next_handshake_initiation_at().into()).await;
    }
    debug!("exiting handshake loop for peer")
    // close all loop
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
                            sessions.renew_current(session);
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
                session: _,
            } => {
                let ret = {
                    let mut handshake = inner.handshake.write().unwrap();
                    handshake.finalize(&packet)
                };
                match ret {
                    Ok(session) => {
                        {
                            let mut sessions = inner.sessions.write().unwrap();
                            sessions.prepare_next(session);
                        }
                        inner.update_endpoint(endpoint.clone());
                        inner.keepalive().await; // let the peer know the session is valid
                    }
                    Err(e) => {
                        debug!("failed to finalize handshake: {}", e);
                    }
                }
            }
            InboundEvent::CookieReply { .. } => {}
            InboundEvent::TransportData {
                endpoint,
                packet,
                session,
            } => {
                {
                    let mut sessions = inner.sessions.write().unwrap();
                    if sessions.rotate_next(session.clone()) {
                        // Handshake completed
                    }
                }
                if !session.can_accept(packet.counter) {
                    debug!("dropping packet due to replay");
                    continue;
                }
                inner.update_endpoint(endpoint.clone());

                match session.decrypt_data(&packet) {
                    Ok(data) => {
                        inner.tun.write(&data).await.unwrap();
                        session.aceept(packet.counter);
                    }
                    Err(e) => {
                        debug!("failed to decrypt packet: {}", e);
                    }
                }
            }
        }
    }
    debug!("exiting inbound loop for peer");
}

// Send to endpoint if connected, otherwise queue for later
async fn outbound_loop(inner: Arc<Inner>, mut rx: OutboundRx) {
    debug!("starting outbound loop for peer");

    while let Some(OutboundEvent::Data(data)) = rx.recv().await {
        let session = { inner.sessions.read().unwrap().current().clone() };
        if let Some(session) = session {
            match session.encrypt_data(&data) {
                Ok(packet) => {
                    let buf = packet.to_bytes();
                    inner.send_outbound(&buf).await;
                    inner.jitter.mark_outbound(buf.len() as _);
                }
                Err(_) => {}
            }
        }
    }
    debug!("exiting outbound loop for peer");
}
