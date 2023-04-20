use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
use futures::StreamExt;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

use super::inbound::{Endpoint, UdpInbound};
use super::peer::InboundEvent;
use super::DeviceInner;
use crate::noise::crypto::LocalStaticSecret;
use crate::noise::handshake::{Cookie, IncomingInitiation};
use crate::noise::protocol;
use crate::noise::protocol::Message;
use crate::Tun;

pub(super) struct DeviceHandle {
    token: CancellationToken,
    inbound_handles: (CancellationToken, Vec<JoinHandle<()>>),
    outbound_handles: (CancellationToken, Vec<JoinHandle<()>>),
}

impl DeviceHandle {
    pub async fn spawn<T>(token: CancellationToken, inner: Arc<DeviceInner<T>>) -> Self
    where
        T: Tun + 'static,
    {
        let mut me = Self {
            token: token.clone(),
            inbound_handles: (token.child_token(), vec![]),
            outbound_handles: (token.child_token(), vec![]),
        };
        me.restart_inbound(Arc::clone(&inner)).await;
        me.restart_outbound(Arc::clone(&inner)).await;
        me
    }

    pub async fn restart_inbound<T>(&mut self, inner: Arc<DeviceInner<T>>)
    where
        T: Tun + 'static,
    {
        // Stop the previous tasks
        {
            let handles: Vec<_> = self.inbound_handles.1.drain(..).collect();
            let abort_handles: Vec<_> = handles.iter().map(|h| h.abort_handle()).collect();
            self.inbound_handles.0.cancel();
            if let Err(e) = tokio::time::timeout(Duration::from_secs(5), join_all(handles)).await {
                warn!("stopping device inbound loop timeout: {e}");
                for handle in abort_handles {
                    handle.abort();
                }
            }
        }

        let token = self.token.child_token();
        let handles = vec![
            tokio::spawn(loop_inbound_v4(Arc::clone(&inner), token.child_token())),
            tokio::spawn(loop_inbound_v6(Arc::clone(&inner), token.child_token())),
        ];
        self.inbound_handles = (token, handles);
    }

    pub async fn restart_outbound<T>(&mut self, inner: Arc<DeviceInner<T>>)
    where
        T: Tun + 'static,
    {
        let handles: Vec<_> = self.outbound_handles.1.drain(..).collect();
        join_all(handles).await;

        let token = self.token.child_token();
        let handles = vec![tokio::spawn(loop_outbound(
            Arc::clone(&inner),
            token.child_token(),
        ))];
        self.outbound_handles = (token, handles);
    }

    pub fn abort(&self) {
        self.inbound_handles.0.cancel();
        self.outbound_handles.0.cancel();
    }

    pub async fn stop(&mut self) {
        self.abort();

        // Wait until all background tasks are done.
        let mut handles = vec![];
        handles.extend(&mut self.inbound_handles.1.drain(..));
        handles.extend(&mut self.outbound_handles.1.drain(..));

        join_all(handles).await;
    }
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        self.token.cancel();
    }
}

#[inline(always)]
async fn loop_inbound_v4<T>(inner: Arc<DeviceInner<T>>, token: CancellationToken)
where
    T: Tun + 'static,
{
    let inbound = inner.settings.lock().unwrap().inbound.v4();
    loop_inbound(inner, inbound, token).await;
}

#[inline(always)]
async fn loop_inbound_v6<T>(inner: Arc<DeviceInner<T>>, token: CancellationToken)
where
    T: Tun + 'static,
{
    let inbound = inner.settings.lock().unwrap().inbound.v6();
    loop_inbound(inner, inbound, token).await;
}

async fn loop_inbound<T>(
    inner: Arc<DeviceInner<T>>,
    mut inbound: UdpInbound,
    token: CancellationToken,
) where
    T: Tun + 'static,
{
    debug!("Device Inbound loop for {inbound} is UP");
    let (secret, cookie) = {
        let settings = inner.settings.lock().unwrap();
        (settings.secret.clone(), Arc::clone(&settings.cookie))
    };

    loop {
        tokio::select! {
            _ = token.cancelled() => {
                debug!("Device Inbound loop for {inbound} is DOWN");
                return;
            }
            data = inbound.next() => {
                if let Some((endpoint, payload)) = data {
                    tick_inbound(Arc::clone(&inner), &secret, Arc::clone(&cookie), endpoint, payload).await;
                }
            }
        }
    }
}

async fn tick_inbound<T>(
    inner: Arc<DeviceInner<T>>,
    secret: &LocalStaticSecret,
    cookie: Arc<Cookie>,
    endpoint: Endpoint,
    payload: Vec<u8>,
) where
    T: Tun + 'static,
{
    if Message::is_handshake(&payload) {
        if !cookie.validate_mac1(&payload) {
            debug!("invalid mac1");
            return;
        }

        if !inner.rate_limiter.fetch_token() {
            debug!("rate limited");
            if !cookie.validate_mac2(&payload) {
                debug!("invalid mac2");
                return;
            }
            debug!("try to send cookie reply");
            let reply = cookie.generate_cookie_reply(&payload, endpoint.dst());
            endpoint.send(&reply).await.unwrap();
            return;
        }
    }

    match Message::parse(&payload) {
        Ok(Message::HandshakeInitiation(p)) => {
            let initiation = IncomingInitiation::parse(secret, &p).unwrap_or_else(|_| todo!());
            if let Some(peer) = inner.get_peer_by_key(initiation.static_public_key.as_bytes()) {
                peer.handle_inbound(InboundEvent::HanshakeInitiation {
                    endpoint,
                    initiation,
                })
                .await;
            }
        }
        Ok(msg) => {
            let receiver_index = match &msg {
                Message::HandshakeResponse(p) => p.receiver_index,
                Message::CookieReply(p) => p.receiver_index,
                Message::TransportData(p) => p.receiver_index,
                _ => unreachable!(),
            };
            if let Some((session, peer)) = inner.get_session_by_index(receiver_index) {
                match msg {
                    Message::HandshakeResponse(packet) => {
                        peer.handle_inbound(InboundEvent::HandshakeResponse {
                            endpoint,
                            packet,
                            session,
                        })
                        .await;
                    }
                    Message::CookieReply(packet) => {
                        peer.handle_inbound(InboundEvent::CookieReply {
                            endpoint,
                            packet,
                            session,
                        })
                        .await;
                    }
                    Message::TransportData(packet) => {
                        if packet.counter > protocol::REJECT_AFTER_MESSAGES {
                            warn!("received too many messages from peer [index={receiver_index}]");
                            return;
                        }

                        peer.handle_inbound(InboundEvent::TransportData {
                            endpoint,
                            packet,
                            session,
                        })
                        .await;
                    }
                    _ => unreachable!(),
                }
            } else {
                warn!("received message from unknown peer [index={receiver_index}]");
            }
        }
        Err(e) => {
            warn!("failed to parse message type: {:?}", e);
        }
    }
}

async fn loop_outbound<T>(inner: Arc<DeviceInner<T>>, token: CancellationToken)
where
    T: Tun + 'static,
{
    debug!("Device outbound loop is UP");
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                debug!("Device outbound loop is DOWN");
                return;
            }
            _ = tick_outbound(Arc::clone(&inner)) => {}
        }
    }
}

async fn tick_outbound<T>(inner: Arc<DeviceInner<T>>)
where
    T: Tun + 'static,
{
    const IPV4_HEADER_LEN: usize = 20;
    const IPV6_HEADER_LEN: usize = 40;

    match inner.tun.recv().await {
        Ok(buf) => {
            let dst = {
                match buf[0] & 0xF0 {
                    0x40 if buf.len() < IPV4_HEADER_LEN => return,
                    0x40 => {
                        let addr: [u8; 4] = buf[16..20].try_into().unwrap();
                        IpAddr::from(Ipv4Addr::from(addr))
                    }
                    0x60 if buf.len() < IPV6_HEADER_LEN => return,
                    0x60 => {
                        let addr: [u8; 16] = buf[24..40].try_into().unwrap();
                        IpAddr::from(Ipv6Addr::from(addr))
                    }
                    n => {
                        debug!("unknown IP version: {}", n);
                        return;
                    }
                }
            };

            debug!("trying to send packet to {}", dst);

            let peer = inner.peers.lock().unwrap().get_by_ip(dst);

            if let Some(peer) = peer {
                debug!("sending packet[{}] to {dst}", buf.len());
                peer.stage_outbound(buf).await
            } else {
                warn!("no peer found for {dst}");
            }
        }
        Err(e) => {
            error!("TUN read error: {}", e)
        }
    }
}
