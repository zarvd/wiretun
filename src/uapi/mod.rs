mod connection;
mod error;
mod protocol;

use connection::Connection;
pub use error::Error;
use protocol::{GetDevice, GetPeer, Request, Response, SetDevice, SetPeer};
use std::collections::HashSet;

use std::path::{Path, PathBuf};

use tokio::net::UnixListener;
use tracing::debug;

use crate::{DeviceHandle, Tun};

const SOCKET_DIR: &str = "/var/run/wireguard";

fn socket_path(iface: &str) -> PathBuf {
    Path::new(SOCKET_DIR).join(format!("{}.sock", iface))
}

pub async fn bind_and_handle<T>(device: DeviceHandle<T>) -> Result<(), Error>
where
    T: Tun + 'static,
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

async fn handle_connection<T>(mut conn: Connection, device: DeviceHandle<T>)
where
    T: Tun + 'static,
{
    debug!("accepting new UAPI connection");

    loop {
        match conn.next().await {
            Ok(Request::Get) => {
                debug!("UAPI received GET request");
                let cfg = device.config();
                let mut metrics = device.metrics();
                let peers = cfg
                    .peers
                    .into_iter()
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
                            persistent_keepalive_interval: 0,
                        }
                    })
                    .collect();
                conn.write(Response::Get(GetDevice {
                    private_key: cfg.private_key,
                    listen_port: cfg.listen_port,
                    fwmark: 0,
                    peers,
                }))
                .await;
            }
            Ok(Request::Set(req)) => {
                debug!("UAPI received SET request");
                if req.replace_peers {
                    device.clear_peers();
                }
                if let Some(_private_key) = req.private_key {
                    // unsupoorted
                }
                if let Some(_port) = req.listen_port {
                    // unsupoorted
                }
                if let Some(_fwmark) = req.fwmark {
                    // unsupoorted
                }

                for peer in req.peers {
                    if peer.remove {
                        device.remove_peer(&peer.public_key);
                        break;
                    }
                    if device.peer_config(&peer.public_key).is_none() {
                        // to insert
                        if peer.update_only {
                            continue;
                        }
                        device.insert_peer(peer.public_key, peer.allowed_ips, peer.endpoint);
                    } else {
                        // to update
                        if let Some(endpoint) = peer.endpoint {
                            device.update_peer_endpoint(&peer.public_key, endpoint);
                        }

                        let mut allowed_ips = device
                            .list_allowed_ips_by_peer(&peer.public_key)
                            .unwrap()
                            .into_iter()
                            .collect::<HashSet<_>>();
                        if peer.replace_allowed_ips {
                            allowed_ips.clear();
                        }
                        for ip in peer.allowed_ips {
                            allowed_ips.insert(ip);
                        }
                        device.update_allowed_ips_by_peer(
                            &peer.public_key,
                            allowed_ips.into_iter().collect(),
                        );
                    }
                }
            }
            Err(e) => {
                debug!("UAPI connection error: {}", e);
                break;
            }
        }
    }
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
