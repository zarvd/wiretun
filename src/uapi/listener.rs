use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::noise::crypto;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf, SocketAddr};
use tokio::net::{UnixListener, UnixStream};
use tracing::debug;

use super::Error;

const SOCKET_DIR: &str = "/var/run/wireguard";

fn socket_path(iface: &str) -> PathBuf {
    Path::new(SOCKET_DIR).join(format!("{}.sock", iface))
}

pub struct Listener {
    path: PathBuf,
    socket: UnixListener,
}

impl Listener {
    pub fn bind(iface: &str) -> Self {
        let path = socket_path(iface);
        Self::bind_with_path(path)
    }

    pub fn bind_with_path<P: AsRef<Path>>(path: P) -> Self {
        let path = path.as_ref().to_path_buf();
        debug!("binding uapi unix socket to {:?}", path);
        let _ = std::fs::remove_file(&path); // Remove existing socket
        std::fs::create_dir_all(path.parent().unwrap()).expect("create wireguard socket dir");
        let socket = UnixListener::bind(&path).expect("bind uapi unix socket");

        Self { path, socket }
    }

    pub async fn accept(&self) -> Result<Connection, ()> {
        self.socket
            .accept()
            .await
            .map(|(socket, addr)| Connection::new(socket, addr))
            .map_err(|_| ())
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub enum Operation {
    Get,
    Set,
}

pub enum Response {
    Get(DeviceInfo),
    Err,
}

pub struct DeviceInfo {
    pub private_key: [u8; 32],
    pub listen_port: u16,
    pub fwmark: u32,
    pub peers: Vec<PeerInfo>,
}

pub struct PeerInfo {
    pub public_key: [u8; 32],
    pub psk: [u8; 32],
    pub allowed_ips: Vec<(IpAddr, u8)>,
    pub endpoint: Option<std::net::SocketAddr>,
    pub last_handshake_at: SystemTime,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub persistent_keepalive_interval: u32,
}

impl Into<Bytes> for DeviceInfo {
    fn into(self) -> Bytes {
        let mut buf = BytesMut::new();
        if self.private_key != [0u8; 32] {
            buf.put(
                format!("private_key={}\n", crypto::encode_to_hex(&self.private_key)).as_bytes(),
            );
        }
        buf.put(format!("listen_port={}\n", self.listen_port).as_bytes());

        if self.fwmark != 0 {
            buf.put(format!("fwmark={}\n", self.fwmark).as_bytes());
        }

        for peer in self.peers {
            buf.put(format!("public_key={}\n", crypto::encode_to_hex(&peer.public_key)).as_bytes());
            buf.put(format!("preshared_key={}\n", crypto::encode_to_hex(&peer.psk)).as_bytes());
            for (ip, mask) in peer.allowed_ips {
                buf.put(format!("allowed_ip={}/{}\n", ip, mask).as_bytes());
            }
            if let Some(endpoint) = peer.endpoint {
                buf.put(format!("endpoint={}\n", endpoint).as_bytes());
            }
            let d = peer
                .last_handshake_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();
            buf.put(format!("last_handshake_time_sec={}\n", d.as_secs()).as_bytes());
            buf.put(format!("last_handshake_time_nsec={}\n", d.subsec_nanos()).as_bytes());
            buf.put(format!("tx_bytes={}\n", peer.tx_bytes).as_bytes());
            buf.put(format!("rx_bytes={}\n", peer.rx_bytes).as_bytes());
            buf.put(
                format!(
                    "persistent_keepalive_interval={}\n",
                    peer.persistent_keepalive_interval
                )
                .as_bytes(),
            );
        }
        buf.put_slice(b"protocol_version=1\n");
        buf.put_slice(b"errno=0\n");
        buf.put_slice(b"\n");
        buf.freeze()
    }
}

pub struct Connection {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    addr: SocketAddr,
}

impl Connection {
    fn new(socket: UnixStream, addr: SocketAddr) -> Self {
        let (rh, wh) = socket.into_split();
        Self {
            reader: BufReader::new(rh),
            writer: wh,
            addr,
        }
    }

    /// ## Cancel Safety
    /// The method is not cancellation safe.
    pub async fn next(&mut self) -> Result<Operation, Error> {
        let mut op = vec![];
        self.reader.read_until(b'\n', &mut op).await?;

        match op.as_slice() {
            b"get=1\n" => {
                if self.reader.read_u8().await? != b'\n' {
                    return Err(Error::InvalidProtocol);
                }
                Ok(Operation::Get)
            }
            b"set=1\n" => {
                let mut kvs = HashMap::new();
                loop {
                    let mut buf = vec![];
                    self.reader.read_until(b'\n', &mut buf).await?;
                    if buf.len() == 1 {
                        break;
                    }
                    let s = unsafe { String::from_utf8_unchecked(buf).trim_end().to_string() };
                    s.split_once('=')
                        .map(|(k, v)| kvs.insert(k.to_string(), v.to_string()));
                }
                Ok(Operation::Set)
            }
            _ => Err(Error::InvalidProtocol),
        }
    }

    /// ## Cancel Safety
    /// The method is not cancellation safe.
    pub async fn write(&mut self, resp: Response) {
        match resp {
            Response::Get(info) => {
                let buf: Bytes = info.into();
                self.writer.write_all(buf.as_ref()).await.unwrap();
            }
            _ => {}
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
