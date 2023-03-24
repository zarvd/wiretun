use std::io;
use std::sync::{
    atomic::{self, AtomicBool, AtomicU64},
    Arc,
};

use bytes::Bytes;
use futures::future::join_all;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tracing::debug;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::listener::Endpoint;
use crate::noise::protocol::Message;

#[derive(Debug)]
enum Event {
    Message(Message),
    EOF,
}

type InboundTx = mpsc::UnboundedSender<Event>;
type InboundRx = mpsc::UnboundedReceiver<Event>;
type OutboundTx = mpsc::UnboundedSender<Event>;
type OutboundRx = mpsc::UnboundedReceiver<Event>;

struct HandleLoop {
    peer: Peer,
    handles: Vec<JoinHandle<()>>,
    inbound_tx: Option<InboundTx>,
    outbound_tx: Option<OutboundTx>,
}

impl HandleLoop {
    #[inline]
    pub fn new(peer: Peer) -> Self {
        Self {
            peer,
            handles: Vec::new(),
            inbound_tx: None,
            outbound_tx: None,
        }
    }

    #[inline]
    pub async fn start(&mut self) {
        self.shutdown_gracefully().await;

        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();

        self.handles
            .push(tokio::spawn(outbound_loop(self.peer.clone(), outbound_rx)));
        self.handles
            .push(tokio::spawn(inbound_loop(self.peer.clone(), inbound_rx)));
        self.inbound_tx = Some(inbound_tx.clone());
        self.outbound_tx = Some(outbound_tx.clone());
    }

    #[inline]
    pub fn shutdown(&mut self) {
        if let Some(tx) = self.inbound_tx.take() {
            tx.send(Event::EOF).unwrap();
        }
        if let Some(tx) = self.outbound_tx.take() {
            tx.send(Event::EOF).unwrap();
        }
    }

    #[inline]
    pub async fn shutdown_gracefully(&mut self) {
        if self.handles.is_empty() {
            return;
        }
        self.shutdown();
        join_all(self.handles.drain(..)).await;
    }
}

impl Drop for HandleLoop {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct Inner {
    running: AtomicBool,
    handle_loop: RwLock<HandleLoop>,
    endpoint: RwLock<Option<Endpoint>>,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
}

#[derive(Clone)]
pub struct Peer {
    inner: Arc<Inner>,
}

impl Peer {
    async fn send_buffer(&mut self, buf: &[u8]) -> Result<(), io::Error> {
        let endpoint = self.inner.endpoint.read().await;
        match endpoint.as_ref() {
            Some(endpoint) => endpoint.send(buf).await?,
            None => return Err(io::Error::new(io::ErrorKind::Other, "not connected")),
        }
        self.inner
            .tx_bytes
            .fetch_add(buf.len() as u64, atomic::Ordering::Relaxed);

        Ok(())
    }

    pub async fn start(&mut self) -> Result<(), ()> {
        debug!("starting peer");
        let mut handle_loop = self.inner.handle_loop.write().await;

        if self.inner.running.load(atomic::Ordering::Relaxed) {
            return Err(());
        }

        handle_loop.start().await;

        self.inner.running.store(true, atomic::Ordering::Relaxed);

        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), ()> {
        debug!("stopping peer");
        let mut handle = self.inner.handle_loop.write().await;
        if !self.inner.running.load(atomic::Ordering::Relaxed) {
            return Ok(());
        }

        handle.shutdown_gracefully().await;
        self.inner.running.store(true, atomic::Ordering::Relaxed);

        Ok(())
    }

    pub async fn send_keepalive(&mut self) {
        if !self.inner.running.load(atomic::Ordering::Relaxed) {
            return;
        }
    }

    pub async fn stage_outbound(&mut self, buf: Bytes) {}
}

async fn outbound_loop(mut peer: Peer, mut rx: OutboundRx) {
    debug!("outbound loop started");

    while let Some(x) = rx.recv().await {
        let buf = [0u8; 32];
        match peer.send_buffer(&buf).await {
            Ok(_) => {}
            Err(e) => {
                debug!("outbound loop error: {}", e);
                continue;
            }
        }
    }
}

async fn inbound_loop(mut peer: Peer, mut rx: InboundRx) {
    debug!("inbound loop started");

    while let Some(x) = rx.recv().await {}
}

type HashBytes = [u8; 32];

enum HandshakeState {
    Uninit,
    InitiationCreated {
        hash: HashBytes,
        index: u32,
        ephemeral_key: EphemeralSecret,
    },
    InitiationReceived {
        hash: HashBytes,
        remote_index: u32,
        remote_ephemeral_pub: PublicKey,
    },
    ResponseCreated,
    ResponseReceived,
}

struct Handshake {
    state: HandshakeState,
}

impl Handshake {}
