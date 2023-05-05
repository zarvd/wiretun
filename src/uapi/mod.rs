mod connection;
mod error;
mod protocol;

pub use error::Error;

use connection::Connection;
use protocol::{GetDevice, GetPeer, Request, Response, SetDevice, SetPeer};

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::net::UnixListener;
use tracing::{debug, error};

use crate::device::Transport;
use crate::{DeviceControl, PeerConfig, Tun};

const SOCKET_DIR: &str = "/var/run/wireguard";

fn socket_path(iface: &str) -> PathBuf {
    Path::new(SOCKET_DIR).join(format!("{}.sock", iface))
}

pub async fn bind_and_handle<T, I>(device: DeviceControl<T, I>) -> Result<(), Error>
where
    T: Tun + 'static,
    I: Transport,
{
    let listener = {
        let path = socket_path(device.tun_name());
        debug!("binding uapi unix socket to {:?}", path);
        let _ = std::fs::remove_file(&path); // Remove existing socket
        let _ = std::fs::create_dir_all(path.parent().unwrap()); // Create socket dir
        UnixListener::bind(&path)?
    };

    loop {
        let (socket, _) = listener.accept().await?;
        let conn = Connection::new(socket);
        let device = device.clone();
        tokio::spawn(handle_connection(conn, device));
    }
}

async fn handle_connection<T, I>(mut conn: Connection, device: DeviceControl<T, I>)
where
    T: Tun + 'static,
    I: Transport,
{
    debug!("UAPI: accepting new connection");

    loop {
        match conn.next().await {
            Ok(Request::Get) => match handle_get(device.clone()).await {
                Ok(resp) => conn.write(resp).await,
                Err(e) => {
                    error!("Failed to handle get operation: {}", e);
                    conn.write(Response::Err).await;
                }
            },
            Ok(Request::Set(req)) => match handle_set(device.clone(), req).await {
                Ok(()) => {
                    conn.write(Response::Ok).await;
                }
                Err(e) => {
                    error!("Failed to handle set operation: {}", e);
                    conn.write(Response::Err).await;
                }
            },
            Err(e) => {
                debug!("UAPI connection error: {}", e);
                conn.write(Response::Err).await;
                break;
            }
        }
    }
}

async fn handle_get<T, I>(device: DeviceControl<T, I>) -> Result<Response, Error>
where
    T: Tun + 'static,
    I: Transport,
{
    debug!("UAPI: received GET request");
    let cfg = device.config();
    let mut metrics = device.metrics();
    let peers = cfg
        .peers
        .into_values()
        .map(|p| {
            let m = metrics.peers.remove(&p.public_key).unwrap();
            GetPeer {
                public_key: p.public_key,
                psk: p.preshared_key.unwrap_or_default(),
                allowed_ips: p.allowed_ips,
                endpoint: p.endpoint,
                last_handshake_at: m.last_handshake_at,
                tx_bytes: m.tx_bytes,
                rx_bytes: m.rx_bytes,
                persistent_keepalive_interval: p
                    .persistent_keepalive
                    .map(|v| v.as_secs() as u32)
                    .unwrap_or(0),
            }
        })
        .collect();

    Ok(Response::Get(GetDevice {
        private_key: cfg.private_key,
        listen_port: cfg.listen_port,
        fwmark: 0,
        peers,
    }))
}

async fn handle_set<T, I>(device: DeviceControl<T, I>, req: SetDevice) -> Result<(), Error>
where
    T: Tun + 'static,
    I: Transport,
{
    debug!("UAPI: received SET request");
    if req.replace_peers {
        device.clear_peers();
    }
    if let Some(private_key) = req.private_key {
        device.update_private_key(private_key);
    }
    if let Some(port) = req.listen_port {
        device.update_listen_port(port).await.map_err(|e| {
            error!("Failed to update listen_port: {}", e);
            Error::InvalidConfiguration(e.to_string())
        })?;
    }
    if let Some(_fwmark) = req.fwmark {
        // unsupoorted
    }

    let cfg = device.config();
    for peer in req.peers {
        if peer.remove {
            device.remove_peer(&peer.public_key);
            break;
        }
        match cfg.peers.get(&peer.public_key).cloned() {
            Some(mut cfg) => {
                // to update
                if let Some(endpoint) = peer.endpoint {
                    cfg.endpoint = Some(endpoint);
                }
                if peer.replace_allowed_ips {
                    cfg.allowed_ips.clear();
                }
                for ip in peer.allowed_ips {
                    cfg.allowed_ips.insert(ip);
                }
                if let Some(psk) = peer.psk {
                    cfg.preshared_key = Some(psk);
                }
                if let Some(interval) = peer.persistent_keepalive_interval {
                    cfg.persistent_keepalive = Some(Duration::from_secs(interval as u64));
                }

                device.remove_peer(&peer.public_key);
                device.insert_peer(cfg);
            }
            None if !peer.update_only => {
                device.insert_peer(PeerConfig {
                    public_key: peer.public_key,
                    allowed_ips: peer.allowed_ips,
                    endpoint: peer.endpoint,
                    preshared_key: peer.psk,
                    persistent_keepalive: peer
                        .persistent_keepalive_interval
                        .map(|v| Duration::from_secs(v as u64)),
                });
            }
            _ => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_path() {
        assert_eq!(
            socket_path("wg0").to_string_lossy().as_ref(),
            "/var/run/wireguard/wg0.sock",
        )
    }
}
