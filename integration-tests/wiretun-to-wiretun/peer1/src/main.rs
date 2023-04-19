use std::env;
use std::error::Error;

use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use wiretun::{uapi, Cidr, Device, DeviceConfig, PeerConfig};

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

    let private_key = env::var("PEER1_KEY")
        .map(decode_base64)
        .expect("env PEER1_KEY is required");
    let peer_pub_key = env::var("PEER2_PUB")
        .map(decode_base64)
        .expect("env PEER2_PUB is required");

    let cfg = DeviceConfig::default()
        .private_key(private_key)
        .listen_port(45991)
        .peer(
            PeerConfig::default()
                .public_key(peer_pub_key)
                .endpoint("0.0.0.0:45992".parse()?)
                .allowed_ip("10.0.0.2/32".parse::<Cidr>().unwrap()),
        );

    info!("Starting Wiretun device (utun44)...");

    let device = Device::native("utun44", cfg).await?;

    uapi::bind_and_handle(device.control()).await?;
    device.terminate().await;

    Ok(())
}
