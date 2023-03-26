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

use crate::listener::Endpoint;
use crate::noise::crypto::{PeerStaticSecret};

#[derive(Debug)]
enum Event {
    Data(Vec<u8>),
    EOF,
}

type InboundTx = mpsc::Sender<Event>;
type InboundRx = mpsc::Receiver<Event>;
type OutboundTx = mpsc::Sender<Event>;
type OutboundRx = mpsc::Receiver<Event>;

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
        self.shutdown().await; // should return immediately

        let (inbound_tx, inbound_rx) = mpsc::channel(256);
        let (outbound_tx, outbound_rx) = mpsc::channel(256);

        self.handles
            .push(tokio::spawn(outbound_loop(self.peer.clone(), outbound_rx)));
        self.handles
            .push(tokio::spawn(inbound_loop(self.peer.clone(), inbound_rx)));
        self.inbound_tx = Some(inbound_tx);
        self.outbound_tx = Some(outbound_tx);
    }

    #[inline]
    pub async fn shutdown(&mut self) {
        if self.handles.is_empty() {
            return;
        }
        if let Some(tx) = self.inbound_tx.take() {
            tx.send(Event::EOF).await.unwrap();
        }
        if let Some(tx) = self.outbound_tx.take() {
            tx.send(Event::EOF).await.unwrap();
        }
        join_all(self.handles.drain(..)).await;
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
    pub fn new() -> Self {
        unimplemented!()
    }

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

    pub async fn start(&self) -> Result<(), ()> {
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

        handle.shutdown().await;
        self.inner.running.store(true, atomic::Ordering::Relaxed);

        Ok(())
    }

    pub fn secret(&self) -> &PeerStaticSecret {
        unimplemented!()
    }

    async fn send_keepalive(&mut self) {
        if !self.inner.running.load(atomic::Ordering::Relaxed) {}
    }

    // Stage outbound data to be sent to the peer
    pub async fn stage_outbound(&mut self, buf: Bytes) {
        let handle = self.inner.handle_loop.read().await;
        if let Some(tx) = handle.outbound_tx.as_ref() {
            tx.send(Event::Data(buf.to_vec())).await.unwrap(); // TODO try_send instead of blocking when channel is full
        }
    }
}

async fn outbound_loop(mut peer: Peer, mut rx: OutboundRx) {
    debug!("starting outbound loop for peer");

    while let Some(event) = rx.recv().await {
        match event {
            Event::Data(data) => {
                peer.send_buffer(&data).await.unwrap();
            }
            Event::EOF => {
                break;
            }
        }
    }
    debug!("exiting outbound loop for peer");
}

async fn inbound_loop(_peer: Peer, mut rx: InboundRx) {
    debug!("starting inbound loop for peer");

    while let Some(x) = rx.recv().await {
        match x {
            Event::Data(_msg) => {}
            Event::EOF => {
                break;
            }
        }
    }
    debug!("exiting inbound loop for peer");
}
