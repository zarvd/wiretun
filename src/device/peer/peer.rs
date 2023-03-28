use std::sync::{
    atomic::{self, AtomicBool},
    Arc, RwLock,
};

use crate::device::peer::jitter;
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time;
use tracing::{debug, info, warn};

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
    #[inline]
    pub async fn stage_outbound(&self, buf: Bytes) {
        self.inner
            .stage_outbound(OutboundEvent::Data(buf.to_vec()))
            .await;
    }
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
        let endpoint = { self.endpoint.read().unwrap().clone() };
        if let Some(endpoint) = endpoint {
            endpoint.send(buf).await.unwrap();
        } else {
            debug!("no endpoint to send outbound packet to peer");
        }
    }

    #[inline]
    pub async fn keepalive(&self) {
        debug!("sending keepalive packet to peer");
        if !self.jitter.can_keepalive() {
            debug!("not sending keepalive packet yet");
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
            info!("initiating handshake");
            let packet = {
                let (next, packet) = inner.handshake.write().unwrap().initiate();
                let mut sessions = inner.sessions.write().unwrap();
                sessions.prepare_next(next);
                packet
            };

            inner.send_outbound(&packet).await; // send directly
            inner.jitter.mark_handshake_initiation();
        }
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
                debug!("handling handshake initiation from peer {}", endpoint.dst());
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
                debug!("handling handshake response from peer {}", endpoint.dst());
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
                        inner.jitter.mark_handshake_complete();
                        info!("handshake completed");
                        inner.update_endpoint(endpoint.clone());
                        inner.keepalive().await; // let the peer know the session is valid
                    }
                    Err(e) => {
                        debug!("failed to finalize handshake: {}", e);
                    }
                }
            }
            InboundEvent::CookieReply {
                endpoint,
                packet: _,
                session: _,
            } => {
                debug!("handling cookie reply from peer {}", endpoint.dst());
            }
            InboundEvent::TransportData {
                endpoint,
                packet,
                session,
            } => {
                debug!("handling transport data from peer {}", endpoint.dst());
                {
                    let mut sessions = inner.sessions.write().unwrap();
                    if sessions.try_rotate(session.clone()) {
                        info!("handshake completed");
                        inner.jitter.mark_handshake_complete();
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
                        if data.is_empty() {
                            // keepalive
                            debug!("received keepalive from peer");
                            continue;
                        }

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

    loop {
        tokio::select! {
            _ = time::sleep(jitter::KEEPALIVE_TIMEOUT) => {
                inner.keepalive().await;
            }
            event = rx.recv() => {
                if let Some(OutboundEvent::Data(data)) = event {
                    if data.is_empty() {
                        debug!("outbound loop: sending keepalive");
                    }
                    tick_outbound(inner.clone(), data).await;
                } else {
                    break;
                }
            }
        }
    }

    debug!("exiting outbound loop for peer");
}

async fn tick_outbound(inner: Arc<Inner>, data: Vec<u8>) {
    let session = { inner.sessions.read().unwrap().current().clone() };
    let session = if let Some(s) = session { s } else { return };

    match session.encrypt_data(&data) {
        Ok(packet) => {
            let buf = packet.to_bytes();
            inner.send_outbound(&buf).await;
            inner.jitter.mark_outbound(buf.len() as _);
        }
        Err(e) => {
            warn!("failed to encrypt packet: {}", e);
        }
    }
}
