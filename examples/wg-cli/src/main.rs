use std::error::Error;

use base64::engine::general_purpose::STANDARD as base64Encoding;
use base64::Engine;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use wiretun::{uapi, Cidr, Device, DeviceConfig, PeerConfig};

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
        .listen_port(40001)
        .private_key(local_private_key())
        .peer(
            PeerConfig::default()
                .public_key(peer_public_key())
                .endpoint("0.0.0.0:40002".parse()?)
                .allowed_ip("10.0.0.2".parse::<Cidr>()?),
        );
    let device = Device::native("utun", cfg).await?;

    uapi::bind_and_handle(device.handle()).await?;

    Ok(())
}
