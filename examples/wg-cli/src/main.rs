use std::error::Error;
use std::time::Duration;

use tokio::time;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use wiretun::{Device, DeviceConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cfg = DeviceConfig::default();
    let device = Device::native("utun", cfg).await?;

    let handle = device.handle();

    time::sleep(Duration::from_secs(10)).await;
    device.terminate().await;
    tracing::info!("device terminated");

    Ok(())
}
