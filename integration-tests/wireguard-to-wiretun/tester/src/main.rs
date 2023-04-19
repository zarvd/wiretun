use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};

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

    let local_ip = IpAddr::V4(Ipv4Addr::new(10, 11, 100, 1));
    let remote_ip = IpAddr::V4(Ipv4Addr::new(10, 11, 100, 2));

    info!("==================");
    info!("Running test: simple_udp_echo");
    test_case::simple_udp_echo(local_ip, remote_ip).await?;

    info!("==================");
    info!("Running test: after_rekey_udp_echo");
    test_case::after_rekey_udp_echo(local_ip, remote_ip).await?;

    Ok(())
}

mod test_case {
    use std::error::Error;
    use std::net::{IpAddr, SocketAddr};
    use std::time::Duration;

    use rand_core::{OsRng, RngCore};
    use tokio::net::UdpSocket;
    use tokio::time;
    use tracing::{info, instrument};

    #[instrument(skip_all)]
    pub async fn simple_udp_echo(
        local_ip: IpAddr,
        remote_ip: IpAddr,
    ) -> Result<(), Box<dyn Error>> {
        let local_addr = SocketAddr::new(local_ip, 45999);
        let remote_addr = SocketAddr::new(remote_ip, 46999);

        let socket = UdpSocket::bind(local_addr).await?;
        for i in 1..=500 {
            info!("[{i}/500] Running test");
            let mut output = [0u8; 1024];
            OsRng.fill_bytes(&mut output);

            socket.send_to(&output, remote_addr).await?;

            let mut input = [0u8; 1024 + 100];
            let (len, addr) = time::timeout(Duration::from_secs(2), socket.recv_from(&mut input))
                .await
                .expect("should recv packet in 2 secs")?;

            assert_eq!(addr, remote_addr);
            assert_eq!(&input[..len], &output[..]);
            info!("[{i}/500] Test passed");
        }

        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn after_rekey_udp_echo(
        local_ip: IpAddr,
        remote_ip: IpAddr,
    ) -> Result<(), Box<dyn Error>> {
        let local_addr = SocketAddr::new(local_ip, 45999);
        let remote_addr = SocketAddr::new(remote_ip, 46999);

        let socket = UdpSocket::bind(local_addr).await?;
        time::sleep(Duration::from_secs(120)).await;

        for i in 1..=500 {
            info!("[{i}/500] Running test");
            let mut output = [0u8; 1024];
            OsRng.fill_bytes(&mut output);

            socket.send_to(&output, remote_addr).await?;

            let mut input = [0u8; 1024 + 100];
            let (len, addr) = time::timeout(Duration::from_secs(2), socket.recv_from(&mut input))
                .await
                .expect("should recv packet in 2 secs")?;

            assert_eq!(addr, remote_addr);
            assert_eq!(&input[..len], &output[..]);
            info!("[{i}/500] Test passed");
        }
        Ok(())
    }
}
