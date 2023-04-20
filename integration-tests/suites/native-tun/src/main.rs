use std::error::Error;

use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use wiretun::{NativeTun, Tun};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    test_set_mtu().await?;

    Ok(())
}

async fn test_set_mtu() -> Result<(), Box<dyn Error>> {
    info!("test_set_mtu");

    let name = "utun";
    let tun = NativeTun::new(name)?;
    tun.set_mtu(1400)?;
    assert_eq!(tun.mtu()?, 1400);
    tun.set_mtu(1500)?;
    assert_eq!(tun.mtu()?, 1500);

    Ok(())
}
