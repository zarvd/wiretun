use bytes::Bytes;
use std::collections::HashSet;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tracing::debug;

use super::{Error, Request, Response, SetDevice, SetPeer};
use crate::noise::crypto;

pub struct Connection {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl Connection {
    pub(super) fn new(socket: UnixStream) -> Self {
        let (rh, wh) = socket.into_split();
        Self {
            reader: BufReader::new(rh),
            writer: wh,
        }
    }

    /// ## Cancel Safety
    /// The method is not cancellation safe.
    pub async fn next(&mut self) -> Result<Request, Error> {
        let mut op = vec![];
        self.reader.read_until(b'\n', &mut op).await?;

        match op.as_slice() {
            b"get=1\n" => {
                if self.reader.read_u8().await? != b'\n' {
                    return Err(Error::InvalidProtocol);
                }
                Ok(Request::Get)
            }
            b"set=1\n" => {
                let mut buf = vec![];
                while self.reader.read_until(b'\n', &mut buf).await? > 1 {}
                let s = unsafe { String::from_utf8_unchecked(buf).trim_end().to_owned() };

                Ok(Request::Set(parse_set_request(&s)?))
            }
            _ => Err(Error::InvalidProtocol),
        }
    }

    /// ## Cancel Safety
    /// The method is not cancellation safe.
    pub async fn write(&mut self, resp: Response) {
        match resp {
            Response::Ok => {
                debug!("UAPI: writing ok response");
                self.writer.write_all(b"errno=0\n\n").await.unwrap();
            }
            Response::Get(info) => {
                let buf: Bytes = info.into();
                self.writer.write_all(buf.as_ref()).await.unwrap();
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_lines)]
fn parse_set_request(s: &str) -> Result<SetDevice, Error> {
    debug!("UAPI: parsing set request: {:?}", s);

    let mut set_device = SetDevice {
        private_key: None,
        listen_port: None,
        fwmark: None,
        replace_peers: false,
        peers: vec![],
    };
    for line in s.split('\n') {
        let (k, v) = line.split_once('=').ok_or(Error::InvalidProtocol)?;

        match k {
            "private_key" => {
                let mut private_key = [0u8; 32];
                private_key.copy_from_slice(crypto::decode_from_hex(v).as_slice());
                set_device.private_key = Some(private_key);
            }
            "listen_port" => {
                set_device.listen_port = Some(v.parse().map_err(|_| Error::InvalidProtocol)?);
            }
            "fwmark" => {
                set_device.fwmark = Some(v.parse().map_err(|_| Error::InvalidProtocol)?);
            }
            "replace_peers" => {
                if v != "true" {
                    return Err(Error::InvalidProtocol);
                }
                set_device.replace_peers = true;
            }
            "public_key" => {
                set_device.peers.push(SetPeer {
                    public_key: [0u8; 32],
                    remove: false,
                    update_only: false,
                    psk: None,
                    endpoint: None,
                    persistent_keepalive_interval: None,
                    replace_allowed_ips: false,
                    allowed_ips: HashSet::new(),
                });

                set_device
                    .peers
                    .last_mut()
                    .ok_or(Error::InvalidProtocol)?
                    .public_key = crypto::decode_from_hex(v)
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidProtocol)?;
            }
            "remove" => {
                if v != "true" {
                    return Err(Error::InvalidProtocol);
                }

                set_device
                    .peers
                    .last_mut()
                    .ok_or(Error::InvalidProtocol)?
                    .remove = true;
            }
            "update_only" => {
                if v != "true" {
                    return Err(Error::InvalidProtocol);
                }

                set_device
                    .peers
                    .last_mut()
                    .ok_or(Error::InvalidProtocol)?
                    .update_only = true;
            }
            "preshared_key" => {
                set_device
                    .peers
                    .last_mut()
                    .ok_or(Error::InvalidProtocol)?
                    .psk = Some(
                    crypto::decode_from_hex(v)
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::InvalidProtocol)?,
                );
            }
            "endpoint" => {
                set_device
                    .peers
                    .last_mut()
                    .ok_or(Error::InvalidProtocol)?
                    .endpoint = Some(v.parse().map_err(|_| Error::InvalidProtocol)?);
            }
            "persistent_keepalive_interval" => {
                set_device
                    .peers
                    .last_mut()
                    .ok_or(Error::InvalidProtocol)?
                    .persistent_keepalive_interval =
                    Some(v.parse().map_err(|_| Error::InvalidProtocol)?);
            }
            "replace_allowed_ips" => {
                if v != "true" {
                    return Err(Error::InvalidProtocol);
                }
                set_device
                    .peers
                    .last_mut()
                    .ok_or(Error::InvalidProtocol)?
                    .replace_allowed_ips = true;
            }
            "allowed_ip" => {
                set_device
                    .peers
                    .last_mut()
                    .ok_or(Error::InvalidProtocol)?
                    .allowed_ips
                    .insert(v.parse().map_err(|_| Error::InvalidProtocol)?);
            }
            _ => return Err(Error::InvalidProtocol),
        }
    }

    Ok(set_device)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_parse_set_request() {
        let rv = parse_set_request(
            "private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a
fwmark=0
listen_port=12912
replace_peers=true
public_key=b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33
preshared_key=188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52
replace_allowed_ips=true
allowed_ip=192.168.4.4/32
endpoint=[abcd:23::33%2]:51820
public_key=58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376
replace_allowed_ips=true
allowed_ip=192.168.4.6/32
persistent_keepalive_interval=111
endpoint=182.122.22.19:3233
public_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58
endpoint=5.152.198.39:51820
replace_allowed_ips=true
allowed_ip=192.168.4.10/32
allowed_ip=192.168.4.11/32
public_key=e818b58db5274087fcc1be5dc728cf53d3b5726b4cef6b9bab8f8f8c2452c25c
remove=true",
        );

        assert!(rv.is_ok());
        let rv = rv.unwrap();
        assert_eq!(
            rv,
            SetDevice {
                private_key: Some(
                    crypto::decode_from_hex(
                        "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"
                    )
                    .try_into()
                    .unwrap()
                ),
                listen_port: Some(12912),
                fwmark: Some(0),
                replace_peers: true,
                peers: vec![
                    SetPeer {
                        public_key: crypto::decode_from_hex(
                            "b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33"
                        )
                        .try_into()
                        .unwrap(),
                        remove: false,
                        update_only: false,
                        psk: Some(
                            crypto::decode_from_hex(
                                "188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52"
                            )
                            .try_into()
                            .unwrap()
                        ),
                        endpoint: Some("[abcd:23::33%2]:51820".parse().unwrap()),
                        persistent_keepalive_interval: None,
                        replace_allowed_ips: true,
                        allowed_ips: ["192.168.4.4/32".parse().unwrap()].into_iter().collect(),
                    },
                    SetPeer {
                        public_key: crypto::decode_from_hex(
                            "58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376"
                        )
                        .try_into()
                        .unwrap(),
                        remove: false,
                        update_only: false,
                        psk: None,
                        endpoint: Some("182.122.22.19:3233".parse().unwrap()),
                        persistent_keepalive_interval: Some(111),
                        replace_allowed_ips: true,
                        allowed_ips: ["192.168.4.6/32".parse().unwrap()].into_iter().collect(),
                    },
                    SetPeer {
                        public_key: crypto::decode_from_hex(
                            "662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58"
                        )
                        .try_into()
                        .unwrap(),
                        remove: false,
                        update_only: false,
                        psk: None,
                        endpoint: Some("5.152.198.39:51820".parse().unwrap()),
                        persistent_keepalive_interval: None,
                        replace_allowed_ips: true,
                        allowed_ips: [
                            "192.168.4.10/32".parse().unwrap(),
                            "192.168.4.11/32".parse().unwrap(),
                        ]
                        .into_iter()
                        .collect(),
                    },
                    SetPeer {
                        public_key: crypto::decode_from_hex(
                            "e818b58db5274087fcc1be5dc728cf53d3b5726b4cef6b9bab8f8f8c2452c25c"
                        )
                        .try_into()
                        .unwrap(),
                        remove: true,
                        update_only: false,
                        psk: None,
                        endpoint: None,
                        persistent_keepalive_interval: None,
                        replace_allowed_ips: false,
                        allowed_ips: [].into_iter().collect(),
                    }
                ],
            }
        )
    }
}
