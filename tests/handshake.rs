mod support;

use std::net::SocketAddr;
use std::time::Duration;

use tokio::time;

use support::*;
use wiretun::noise::protocol::{HandshakeInitiation, TransportData};
use wiretun::*;

#[tokio::test]
async fn test_noop_when_no_endpoint() {
    let secret = TestKit::gen_local_secret();
    let tun = StubTun::new();
    let transport = StubTransport::bind(0).await.unwrap();
    let cfg = DeviceConfig::default()
        .private_key(secret.private_key().to_bytes())
        .peer(
            PeerConfig::default().public_key(TestKit::gen_local_secret().public_key().to_bytes()),
        );
    let device = Device::with_transport(tun.clone(), transport.clone(), cfg)
        .await
        .unwrap();

    let _ctrl = device.control();

    time::sleep(Duration::from_secs(30)).await;

    assert_eq!(transport.inbound_sent(), 0);
    assert_eq!(transport.outbound_sent(), 0);

    assert_eq!(tun.inbound_sent(), 0);
    assert_eq!(tun.outbound_sent(), 0);
}

#[tokio::test]
async fn test_keep_initiation_when_no_response() {
    let secret = TestKit::gen_local_secret();
    let tun = StubTun::new();
    let transport = StubTransport::bind(0).await.unwrap();
    let peer_pub = TestKit::gen_local_secret().public_key().to_bytes();
    let peer_endpoint = "10.0.0.1:80".parse().unwrap();
    let cfg = DeviceConfig::default()
        .private_key(secret.private_key().to_bytes())
        .peer(
            PeerConfig::default()
                .public_key(peer_pub)
                .endpoint(peer_endpoint),
        );
    let device = Device::with_transport(tun.clone(), transport.clone(), cfg)
        .await
        .unwrap();

    let _ctrl = device.control();

    time::sleep(Duration::from_secs(30)).await;

    assert_eq!(transport.inbound_sent(), 0);
    assert!(transport.outbound_sent() > 0);

    assert_eq!(tun.inbound_sent(), 0);
    assert_eq!(tun.outbound_sent(), 0);

    for _ in 0..transport.outbound_sent() {
        let (endpoint, data) = transport.fetch_outbound().await;
        assert_eq!(endpoint.dst(), peer_endpoint);
        let ret = HandshakeInitiation::try_from(data.as_slice());
        assert!(ret.is_ok());
    }
}

#[tokio::test]
async fn test_complete_handshake() {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let secret1 = TestKit::gen_local_secret();
    let endpoint1 = "10.10.0.1:6789".parse::<SocketAddr>().unwrap();
    let endpoint2 = "10.10.0.2:1245".parse::<SocketAddr>().unwrap();
    let secret2 = TestKit::gen_local_secret();
    let (_device1, tun1, transport1) = {
        let tun = StubTun::new();
        let transport = StubTransport::bind(0).await.unwrap();
        let cfg = DeviceConfig::default()
            .private_key(secret1.private_key().to_bytes())
            .peer(
                PeerConfig::default()
                    .public_key(secret2.public_key().to_bytes())
                    .allowed_ip(endpoint2.ip())
                    .endpoint(endpoint2),
            );
        let device = Device::with_transport(tun.clone(), transport.clone(), cfg)
            .await
            .unwrap();
        (device, tun, transport)
    };
    let (_device2, tun2, transport2) = {
        let tun = StubTun::new();
        let transport = StubTransport::bind(0).await.unwrap();
        let cfg = DeviceConfig::default()
            .private_key(secret2.private_key().to_bytes())
            .peer(
                PeerConfig::default()
                    .public_key(secret1.public_key().to_bytes())
                    .allowed_ip(endpoint1.ip())
                    .endpoint(endpoint1),
            );
        let device = Device::with_transport(tun.clone(), transport.clone(), cfg)
            .await
            .unwrap();
        (device, tun, transport)
    };

    {
        let (t1, t2) = (transport1.clone(), transport2.clone());
        tokio::spawn(async move {
            loop {
                let (endpoint, data) = t1.fetch_outbound().await;
                assert_eq!(endpoint.dst(), endpoint2);
                let endpoint = Endpoint::new(t2.clone(), endpoint1);
                t2.send_inbound(&data, &endpoint).await;
            }
        });
        let (t1, t2) = (transport1.clone(), transport2.clone());
        tokio::spawn(async move {
            loop {
                let (endpoint, data) = t2.fetch_outbound().await;
                assert_eq!(endpoint.dst(), endpoint1);
                let endpoint = Endpoint::new(t1.clone(), endpoint2);
                t1.send_inbound(&data, &endpoint).await;
            }
        });
    }

    time::sleep(Duration::from_secs(30)).await;
    assert_eq!(tun1.inbound_sent(), 0);
    assert_eq!(tun1.outbound_sent(), 0);
    assert_eq!(tun2.inbound_sent(), 0);
    assert_eq!(tun2.outbound_sent(), 0);

    assert!(transport1.inbound_sent() > 0);
    assert!(transport1.outbound_sent() > 0);
    assert!(transport2.inbound_sent() > 0);
    assert!(transport2.outbound_sent() > 0);

    let (mut d1_completed, mut d2_completed) = (false, false);

    for (_, data) in transport1.outbound_recording() {
        if TransportData::try_from(data.as_slice()).is_ok() {
            d1_completed = true;
            break;
        }
    }

    for (_, data) in transport2.outbound_recording() {
        if TransportData::try_from(data.as_slice()).is_ok() {
            d2_completed = true;
            break;
        }
    }

    assert!(d1_completed);
    assert!(d2_completed);
}
