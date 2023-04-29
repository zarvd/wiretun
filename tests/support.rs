#![allow(unused)]

use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use rand_core::OsRng;
use tokio::sync::{mpsc, Mutex};

use wiretun::noise::crypto::LocalStaticSecret;
use wiretun::*;

pub struct TestKit {}

impl TestKit {
    #[inline(always)]
    pub fn gen_local_secret() -> LocalStaticSecret {
        let pri = x25519_dalek::StaticSecret::random_from_rng(OsRng).to_bytes();
        LocalStaticSecret::new(pri)
    }
}

#[derive(Clone)]
pub struct StubTun {
    inbound_sent: Arc<AtomicU64>,
    inbound_recording: Arc<StdMutex<Vec<Vec<u8>>>>,
    outbound_sent: Arc<AtomicU64>,
    outbound_recording: Arc<StdMutex<Vec<Vec<u8>>>>,

    outbound_tx: mpsc::Sender<Vec<u8>>,
    outbound_rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    inbound_rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
}

impl StubTun {
    pub fn new() -> Self {
        let (inbound_tx, inbound_rx) = mpsc::channel(256);
        let (outbound_tx, outbound_rx) = mpsc::channel(256);
        Self {
            inbound_sent: Arc::new(AtomicU64::new(0)),
            inbound_recording: Arc::new(StdMutex::new(vec![])),
            outbound_sent: Arc::new(AtomicU64::new(0)),
            outbound_recording: Arc::new(StdMutex::new(vec![])),

            outbound_tx,
            outbound_rx: Arc::new(Mutex::new(outbound_rx)),
            inbound_tx,
            inbound_rx: Arc::new(Mutex::new(inbound_rx)),
        }
    }

    #[inline(always)]
    pub fn inbound_sent(&self) -> u64 {
        self.outbound_sent.load(Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn outbound_sent(&self) -> u64 {
        self.outbound_sent.load(Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn inbound_recording(&self) -> Vec<Vec<u8>> {
        self.inbound_recording.lock().unwrap().clone()
    }

    #[inline(always)]
    pub fn outbound_recording(&self) -> Vec<Vec<u8>> {
        self.outbound_recording.lock().unwrap().clone()
    }

    pub async fn send_outbound(&self, data: &[u8]) {
        self.outbound_sent.fetch_add(1, Ordering::Relaxed);
        self.outbound_recording.lock().unwrap().push(data.to_vec());
        self.outbound_tx.send(data.to_vec()).await.unwrap();
    }

    pub async fn fetch_inbound(&self) -> Vec<u8> {
        let mut rx = self.inbound_rx.lock().await;
        rx.recv().await.unwrap()
    }
}

impl Default for StubTun {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tun for StubTun {
    fn name(&self) -> &str {
        "stub"
    }

    fn mtu(&self) -> Result<u16, TunError> {
        Ok(1500)
    }

    fn set_mtu(&self, _mtu: u16) -> Result<(), TunError> {
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>, TunError> {
        let mut rx = self.outbound_rx.lock().await;
        let data = rx.recv().await.unwrap();
        Ok(data)
    }

    async fn send(&self, buf: &[u8]) -> Result<(), TunError> {
        self.inbound_sent.fetch_add(1, Ordering::Relaxed);
        self.inbound_recording.lock().unwrap().push(buf.to_vec());
        self.inbound_tx.send(buf.to_vec()).await.unwrap();
        Ok(())
    }
}

type TransportPacket = (Endpoint<StubTransport>, Vec<u8>);

#[derive(Clone)]
pub struct StubTransport {
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
    port: u16,

    inbound_sent: Arc<AtomicU64>,
    inbound_recording: Arc<StdMutex<Vec<TransportPacket>>>,
    outbound_sent: Arc<AtomicU64>,
    outbound_recording: Arc<StdMutex<Vec<TransportPacket>>>,

    outbound_tx: mpsc::Sender<TransportPacket>,
    outbound_rx: Arc<Mutex<mpsc::Receiver<TransportPacket>>>,
    inbound_tx: mpsc::Sender<TransportPacket>,
    inbound_rx: Arc<Mutex<mpsc::Receiver<TransportPacket>>>,
}

impl StubTransport {
    #[inline(always)]
    pub fn inbound_sent(&self) -> u64 {
        self.inbound_sent.load(Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn outbound_sent(&self) -> u64 {
        self.outbound_sent.load(Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn inbound_recording(&self) -> Vec<(Endpoint<Self>, Vec<u8>)> {
        self.inbound_recording.lock().unwrap().clone()
    }

    #[inline(always)]
    pub fn outbound_recording(&self) -> Vec<(Endpoint<Self>, Vec<u8>)> {
        self.outbound_recording.lock().unwrap().clone()
    }

    pub async fn send_inbound(&self, data: &[u8], endpoint: &Endpoint<Self>) {
        self.inbound_sent.fetch_add(1, Ordering::Relaxed);
        self.inbound_recording
            .lock()
            .unwrap()
            .push((endpoint.clone(), data.to_vec()));
        self.inbound_tx
            .send((endpoint.clone(), data.to_vec()))
            .await
            .unwrap();
    }

    pub async fn fetch_outbound(&self) -> (Endpoint<Self>, Vec<u8>) {
        let mut rx = self.outbound_rx.lock().await;
        rx.recv().await.unwrap()
    }
}

impl Display for StubTransport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "StubTransport")
    }
}

#[async_trait]
impl Transport for StubTransport {
    async fn bind(ipv4: Ipv4Addr, ipv6: Ipv6Addr, port: u16) -> Result<Self, io::Error> {
        let (inbound_tx, inbound_rx) = mpsc::channel(256);
        let (outbound_tx, outbound_rx) = mpsc::channel(256);
        Ok(Self {
            ipv4,
            ipv6,
            port,

            inbound_sent: Arc::new(AtomicU64::new(0)),
            inbound_recording: Arc::new(StdMutex::new(vec![])),
            outbound_sent: Arc::new(AtomicU64::new(0)),
            outbound_recording: Arc::new(StdMutex::new(vec![])),

            outbound_tx,
            outbound_rx: Arc::new(Mutex::new(outbound_rx)),
            inbound_tx,
            inbound_rx: Arc::new(Mutex::new(inbound_rx)),
        })
    }

    fn ipv4(&self) -> Ipv4Addr {
        self.ipv4
    }

    fn ipv6(&self) -> Ipv6Addr {
        self.ipv6
    }

    fn port(&self) -> u16 {
        self.port
    }

    async fn send_to(&self, data: &[u8], endpoint: &Endpoint<Self>) -> Result<(), io::Error> {
        self.outbound_sent.fetch_add(1, Ordering::Relaxed);
        self.outbound_recording
            .lock()
            .unwrap()
            .push((endpoint.clone(), data.to_vec()));
        self.outbound_tx
            .send((endpoint.clone(), data.to_vec()))
            .await
            .unwrap();
        Ok(())
    }

    async fn recv_from(&mut self) -> Result<(Endpoint<Self>, Vec<u8>), io::Error> {
        let rv = self.inbound_rx.lock().await.recv().await.unwrap();
        Ok(rv)
    }
}
