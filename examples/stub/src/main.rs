use std::error::Error;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as base64Encoding;
use base64::Engine;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tracing::{debug, error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use wiretun::{uapi, Cidr, Device, DeviceConfig, PeerConfig, Tun, TunError};

fn decode_base64(s: &str) -> Vec<u8> {
    base64Encoding.decode(s).unwrap()
}

fn local_private_key() -> [u8; 32] {
    decode_base64("eMdnuqCl3u2WjK2Wzfw16y1ddgdkKkzmlXukKL3WnVU=")
        .try_into()
        .unwrap()
}

fn peer_public_key() -> [u8; 32] {
    decode_base64("Wv/8YAQITWMHhZ0a4qgNNy689546TXVgD+XJefKxzDw=")
        .try_into()
        .unwrap()
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cfg = DeviceConfig::default()
        .listen_port(40002)
        .private_key(local_private_key())
        .peer(
            PeerConfig::default()
                .public_key(peer_public_key())
                .allowed_ip("10.0.0.1".parse::<Cidr>()?),
        );
    let tun = StubTun::new();
    let device = Device::with_tun(tun, cfg).await?;

    uapi::bind_and_handle(device.control()).await?;

    Ok(())
}

#[derive(Clone)]
struct StubTun {
    tx: mpsc::Sender<Vec<u8>>,
    rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
}

impl StubTun {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(128);
        let rx = Arc::new(Mutex::new(rx));
        Self { tx, rx }
    }

    fn handle(&self, mut buf: Vec<u8>) -> Vec<u8> {
        use pnet::packet::ip::IpNextHeaderProtocols;
        use pnet::packet::ipv4::{checksum, MutableIpv4Packet};
        use pnet::packet::udp::{ipv4_checksum, MutableUdpPacket};
        use pnet::packet::Packet;
        let mut ipv4 = MutableIpv4Packet::new(&mut buf).unwrap();
        let src_ip = ipv4.get_source();
        let dst_ip = ipv4.get_destination();
        ipv4.set_source(dst_ip);
        ipv4.set_destination(src_ip);

        match ipv4.get_next_level_protocol() {
            IpNextHeaderProtocols::Udp => {
                let mut udp = MutableUdpPacket::owned(ipv4.payload().to_vec()).unwrap();
                let src_port = udp.get_source();
                let dst_port = udp.get_destination();
                udp.set_source(dst_port);
                udp.set_destination(src_port);
                udp.set_checksum(ipv4_checksum(&udp.to_immutable(), &dst_ip, &src_ip));
                ipv4.set_payload(udp.packet());
            }
            _ => {
                debug!("Unknown packet type!");
            }
        }

        ipv4.set_checksum(checksum(&ipv4.to_immutable()));

        ipv4.packet().to_vec()
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
        let mut rx = self.rx.lock().await;
        let rv = rx.recv().await.ok_or(TunError::Closed);

        match &rv {
            Ok(buf) => {
                info!("recv data[{}] from tun", buf.len());
            }
            Err(e) => {
                error!("failed to recv data from tun: {:?}", e);
            }
        }

        rv
    }

    async fn send(&self, buf: &[u8]) -> Result<(), TunError> {
        info!("recv data[{}] from outbound", buf.len());
        self.tx
            .send(self.handle(buf.to_vec()))
            .await
            .map_err(|_| TunError::Closed)
    }
}
