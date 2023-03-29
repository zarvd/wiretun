use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

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
    DeviceInfo(DeviceInfo),
}

pub struct DeviceInfo {
    pub listen_port: u16,
    pub fwmark: u32,
    pub peers: Vec<PeerInfo>,
}

pub struct PeerInfo {
    pub public_key: [u8; 32],
    pub psk: [u8; 32],
    pub endpoint: Option<IpAddr>,
    pub last_handshake_at: SystemTime,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub persistent_keepalive_interval: u32,
}

impl Into<Bytes> for DeviceInfo {
    fn into(self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_slice(b"listen_port=");
        buf.put_slice(self.listen_port.to_string().as_bytes());
        buf.put_slice(b"fwmark=");
        buf.put_slice(self.fwmark.to_string().as_bytes());

        for peer in self.peers {
            buf.put_slice(b"public_key=");
            buf.put_slice(peer.public_key.as_ref()); // TODO hex
            buf.put_slice(b"preshared_key=");
            buf.put_slice(peer.psk.as_ref()); // TODO hex
            if let Some(endpoint) = peer.endpoint {
                buf.put_slice(b"endpoint=");
                buf.put_slice(endpoint.to_string().as_bytes());
            }
            let d = peer
                .last_handshake_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();
            buf.put_slice(b"last_handshake_time_sec=");
            buf.put_slice(d.as_secs().to_string().as_bytes());
            buf.put_slice(b"last_handshake_time_nsec=");
            buf.put_slice(d.subsec_nanos().to_string().as_bytes());
            buf.put_slice(b"tx_bytes=");
            buf.put_slice(peer.tx_bytes.to_string().as_bytes());
            buf.put_slice(b"rx_bytes=");
            buf.put_slice(peer.rx_bytes.to_string().as_bytes());
            buf.put_slice(b"persistent_keepalive_interval=");
            buf.put_slice(peer.persistent_keepalive_interval.to_string().as_bytes());
        }
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
            Response::DeviceInfo(info) => {
                let buf: Bytes = info.into();
                self.writer.write_all(buf.as_ref()).await.unwrap();
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
