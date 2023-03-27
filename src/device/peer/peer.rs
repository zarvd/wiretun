use std::io;
use std::sync::{
    atomic::{self, AtomicBool, AtomicU64},
    Arc,
};

use crate::device::peer::OutboundEvent;
use bytes::Bytes;
use futures::future::join_all;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tracing::debug;

use super::{handshake::Handshake, InboundEvent, InboundRx, InboundTx, OutboundRx, OutboundTx};
use crate::listener::Endpoint;
use crate::noise::crypto::PeerStaticSecret;
use crate::noise::handshake::IncomingInitiation;
use crate::noise::protocol;
use crate::Tun;

struct Inner {
    tun: Tun,
    secret: PeerStaticSecret,
    handshake: Handshake,
    endpoint: RwLock<Option<Endpoint>>,
    inbound: InboundTx,
    outbound: OutboundTx,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
}

impl Inner {
    pub fn new(tun: Tun, secret: PeerStaticSecret) -> Arc<Self> {
        let (inbound_tx, inbound_rx) = mpsc::channel(256);
        let (outbound_tx, outbound_rx) = mpsc::channel(256);
        let handshake = Handshake::new(secret.clone());
        let me = Arc::new(Self {
            tun,
            secret,
            handshake,
            endpoint: RwLock::new(None),
            inbound: inbound_tx,
            outbound: outbound_tx,
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
        });

        tokio::spawn(inbound_loop(me.clone(), inbound_rx));
        tokio::spawn(outbound_loop(me.clone(), outbound_rx));

        me
    }

    #[inline]
    pub async fn stage_inbound(&self, e: InboundEvent) {
        self.inbound.send(e).await.unwrap();
    }

    pub async fn send_buffer(&self, buf: &[u8]) -> Result<(), io::Error> {
        let endpoint = self.endpoint.read().await;
        match endpoint.as_ref() {
            Some(endpoint) => endpoint.send(buf).await?,
            None => return Err(io::Error::new(io::ErrorKind::Other, "not connected")),
        }
        self.tx_bytes
            .fetch_add(buf.len() as u64, atomic::Ordering::Relaxed);

        Ok(())
    }
}

// Send to tun if we have a valid session
async fn inbound_loop(inner: Arc<Inner>, mut rx: InboundRx) {
    debug!("starting inbound loop for peer");

    while let Some(event) = rx.recv().await {
        match event {
            InboundEvent::HanshakeInitiation(initiation) => {
                // if let Ok((session, response)) = inner.handshake.respond(&initiation) {
                // send directly?
                // }
            }
            InboundEvent::HandshakeResponse(p) => {}
            InboundEvent::CookieReply(p) => {}
            InboundEvent::TransportData(p) => {}
        }
    }
    debug!("exiting inbound loop for peer");
}

// Send to endpoint if connected, otherwise queue for later
async fn outbound_loop(inner: Arc<Inner>, mut rx: OutboundRx) {
    debug!("starting outbound loop for peer");

    while let Some(event) = rx.recv().await {
        match event {
            _ => {}
        }
    }
    debug!("exiting outbound loop for peer");
}

#[derive(Clone)]
pub struct Peer {
    inner: Arc<Inner>,
}

impl Peer {
    pub fn new(tun: Tun, secret: PeerStaticSecret) -> Self {
        Self {
            inner: Inner::new(tun, secret),
        }
    }

    pub fn secret(&self) -> &PeerStaticSecret {
        &self.inner.secret
    }

    #[inline]
    pub async fn handle_handshake_initiation(&self, initiation: IncomingInitiation) {
        self.inner
            .stage_inbound(InboundEvent::HanshakeInitiation(initiation))
            .await;
    }

    #[inline]
    pub async fn handle_handshake_response(&self, packet: protocol::HandshakeResponse) {
        self.inner
            .stage_inbound(InboundEvent::HandshakeResponse(packet))
            .await;
    }

    #[inline]
    pub async fn handle_cookie_reply(&mut self, packet: protocol::CookieReply) {
        self.inner
            .stage_inbound(InboundEvent::CookieReply(packet))
            .await;
    }

    #[inline]
    pub async fn handle_transport_data(&mut self, packet: protocol::TransportData) {
        self.inner
            .stage_inbound(InboundEvent::TransportData(packet))
            .await;
    }

    // Stage outbound data to be sent to the peer
    pub async fn stage_outbound(&mut self, buf: Bytes) {}
}
