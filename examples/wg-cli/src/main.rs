use std::error::Error;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as base64Encoding;
use base64::Engine;
use tokio::time;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use wiretun::{Device, DeviceConfig, PeerConfig};

fn decode_base64(s: &str) -> Vec<u8> {
    base64Encoding.decode(s).unwrap()
}

fn local_private_key() -> [u8; 32] {
    decode_base64("GDE0rT7tfVGairGhTASn5+ck1mUSqLNyajyMSBFYpVQ=")
        .try_into()
        .unwrap()
}

fn peer_public_key() -> [u8; 32] {
    decode_base64("ArhPnhqqlroFdP4wca7Yu9PuUR1p+TfMhy9kBewLNjM=")
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
        .private_key(local_private_key())
        .peer(
            PeerConfig::default()
                .public_key(peer_public_key())
                .allowed_ip("10.0.0.1".parse()?, 32)
                .allowed_ip("10.0.0.2".parse()?, 32),
        );
    let device = Device::native("utun", cfg).await?;

    let _handle = device.handle();
    // use handle to fetch metrics and configure the device

    time::sleep(Duration::from_secs(60 * 60)).await;

    Ok(())
}
