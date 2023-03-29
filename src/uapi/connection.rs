use std::collections::HashMap;

use bytes::Bytes;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;

use super::{Error, Request, Response};

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
                Ok(Request::Set)
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
