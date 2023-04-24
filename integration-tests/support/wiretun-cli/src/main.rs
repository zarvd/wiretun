mod packet;

use std::error::Error;
use std::sync::Arc;

use async_trait::async_trait;
use clap::{Parser, ValueEnum};
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use wiretun::{uapi, Device, DeviceConfig, Tun, TunError};

use packet::echo_udp_packet;

fn decode_base64(s: &str) -> Result<[u8; 32], String> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD
        .decode(s)
        .map_err(|e| format!("bad base64 format: {}", e))?
        .try_into()
        .map_err(|e| format!("invalid secret key: {:?}", e))
}

#[derive(Debug, Clone, ValueEnum)]
enum Mode {
    Native,
    Stub,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct App {
    #[arg(long)]
    mode: Mode,

    #[arg(long)]
    name: String,

    #[arg(long, value_parser = decode_base64)]
    private_key: [u8; 32],

    #[arg(long)]
    listen_port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app = App::parse();

    let cfg = DeviceConfig::default()
        .private_key(app.private_key)
        .listen_port(app.listen_port);

    match app.mode {
        Mode::Native => {
            info!("Starting Wiretun device with native tun {}", app.name);
            let device = Device::native(&app.name, cfg).await?;
            uapi::bind_and_handle(device.control()).await?;
            device.terminate().await;
        }
        Mode::Stub => {
            info!("Starting Wiretun device with stub tun {}", app.name);
            let device = Device::new(StubTun::new(&app.name), cfg).await?;
            uapi::bind_and_handle(device.control()).await?;
            device.terminate().await;
        }
    };

    Ok(())
}

#[derive(Clone)]
struct StubTun {
    name: String,
    tx: mpsc::Sender<Vec<u8>>,
    rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
}

impl StubTun {
    pub fn new(name: &str) -> Self {
        let (tx, rx) = mpsc::channel(128);
        let rx = Arc::new(Mutex::new(rx));
        let name = name.to_owned();
        Self { name, tx, rx }
    }
}

#[async_trait]
impl Tun for StubTun {
    fn name(&self) -> &str {
        &self.name
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
            .send(echo_udp_packet(buf.to_vec(), self.name.as_bytes()))
            .await
            .map_err(|_| TunError::Closed)
    }
}
