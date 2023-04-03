use std::error::Error;
use std::net::SocketAddr;

use rand_core::{OsRng, RngCore};
use tokio::net::UdpSocket;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let local_addr = "10.0.0.1:45999".parse::<SocketAddr>()?;
    let remote_addr = "10.0.0.2:46999".parse::<SocketAddr>()?;
    let socket = UdpSocket::bind(local_addr).await?;

    for i in 1..=500 {
        let mut output = [0u8; 1024];
        OsRng.fill_bytes(&mut output);

        info!("[{i}/500] Sending packet...");
        socket.send_to(&output, remote_addr).await?;

        info!("[{i}/500] Receiving packet...");
        let mut input = [0u8; 1024 + 100];
        let (len, addr) = socket.recv_from(&mut input).await?;

        info!("[{i}/500] Comparing packet...");
        assert_eq!(addr, remote_addr);
        assert_eq!(&input[..len], &output[..]);
    }

    Ok(())
}
