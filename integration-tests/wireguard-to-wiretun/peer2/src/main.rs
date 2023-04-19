mod packet;

use std::env;
use std::error::Error;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use wiretun::{uapi, Cidr, Device, DeviceConfig, PeerConfig, Tun, TunError};

use packet::echo_udp_packet;

fn decode_base64(s: String) -> [u8; 32] {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.decode(s).unwrap().try_into().unwrap()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let private_key = env::var("PEER2_KEY")
        .map(decode_base64)
        .expect("env PEER2_KEY is required");
    let peer_pub_key = env::var("PEER1_PUB")
        .map(decode_base64)
        .expect("env PEER1_PUB is required");

    let cfg = DeviceConfig::default()
        .private_key(private_key)
        .listen_port(45992)
        .peer(
            PeerConfig::default()
                .public_key(peer_pub_key)
                .endpoint("0.0.0.0:50081".parse()?)
                .allowed_ip("10.11.100.1/32".parse::<Cidr>().unwrap()),
        );

    info!("Starting Wiretun device (StubTun)...");

    let tun = StubTun::new();
    let device = Device::with_tun(tun, cfg).await?;
    uapi::bind_and_handle(device.handle()).await?;
    device.terminate().await;

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
            .send(echo_udp_packet(buf.to_vec()))
            .await
            .map_err(|_| TunError::Closed)
    }
}
