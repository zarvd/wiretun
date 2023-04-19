use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::{monitor, InboundEvent, InboundRx, OutboundEvent, OutboundRx, Peer, Session};
use crate::device::Endpoint;
use crate::noise::handshake::IncomingInitiation;
use crate::noise::protocol::{
    self, CookieReply, HandshakeResponse, TransportData, COOKIE_REPLY_PACKET_SIZE,
    HANDSHAKE_RESPONSE_PACKET_SIZE,
};
use crate::Tun;

pub(crate) struct PeerHandle {
    token: CancellationToken,
    #[allow(unused)]
    handshake_loop: (CancellationToken, JoinHandle<()>),
    #[allow(unused)]
    inbound_loop: (CancellationToken, JoinHandle<()>),
    #[allow(unused)]
    outbound_loop: (CancellationToken, JoinHandle<()>),
}

impl PeerHandle {
    pub fn spawn<T>(
        token: CancellationToken,
        peer: Arc<Peer<T>>,
        inbound: InboundRx,
        outbound: OutboundRx,
    ) -> Self
    where
        T: Tun + 'static,
    {
        let handshake_loop = {
            let token = token.child_token();
            (
                token.clone(),
                tokio::spawn(loop_handshake(token, Arc::clone(&peer))),
            )
        };
        let inbound_loop = {
            let token = token.child_token();
            (
                token.clone(),
                tokio::spawn(loop_inbound(token, Arc::clone(&peer), inbound)),
            )
        };
        let outbound_loop = {
            let token = token.child_token();
            (
                token.clone(),
                tokio::spawn(loop_outbound(token, Arc::clone(&peer), outbound)),
            )
        };

        Self {
            token,
            handshake_loop,
            inbound_loop,
            outbound_loop,
        }
    }
}

impl Drop for PeerHandle {
    fn drop(&mut self) {
        self.token.cancel();
    }
}

async fn loop_handshake<T>(token: CancellationToken, peer: Arc<Peer<T>>)
where
    T: Tun + 'static,
{
    debug!("starting handshake loop for peer {peer}");
    while !token.is_cancelled() {
        if peer.monitor.can_handshake() {
            info!("initiating handshake");
            let packet = {
                let (next, packet) = peer.handshake.write().unwrap().initiate();
                let mut sessions = peer.sessions.write().unwrap();
                sessions.prepare_uninit(next);
                packet
            };

            peer.send_outbound(&packet).await; // send directly
            peer.monitor.handshake().initiated();
        }
        time::sleep_until(peer.monitor.handshake().will_initiate_in().into()).await;
    }
    debug!("exiting handshake loop for peer {peer}")
}

// Send to endpoint if connected, otherwise queue for later
async fn loop_outbound<T>(token: CancellationToken, peer: Arc<Peer<T>>, mut rx: OutboundRx)
where
    T: Tun + 'static,
{
    debug!("starting outbound loop for peer {peer}");

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            _ = time::sleep(monitor::KEEPALIVE_TIMEOUT) => {
                peer.keepalive().await;
            }
            event = rx.recv() => {
                match event {
                    Some(OutboundEvent::Data(data)) => {
                        tick_outbound(Arc::clone(&peer), data).await;
                    }
                    None => break,
                }
            }
        }
    }

    debug!("exiting outbound loop for peer {peer}");
}

async fn tick_outbound<T>(peer: Arc<Peer<T>>, data: Vec<u8>)
where
    T: Tun + 'static,
{
    let session = { peer.sessions.read().unwrap().current().clone() };
    let session = if let Some(s) = session { s } else { return };

    match session.encrypt_data(&data) {
        Ok(packet) => {
            let buf = packet.to_bytes();
            peer.send_outbound(&buf).await;
            peer.monitor.traffic().outbound(buf.len());
        }
        Err(e) => {
            warn!("failed to encrypt packet: {}", e);
        }
    }
}

// Send to tun if we have a valid session
async fn loop_inbound<T>(token: CancellationToken, peer: Arc<Peer<T>>, mut rx: InboundRx)
where
    T: Tun + 'static,
{
    debug!("starting inbound loop for peer {peer}");

    loop {
        tokio::select! {
            () = token.cancelled() => break,
            event = rx.recv() => {
                match event {
                    Some(event) => tick_inbound(Arc::clone(&peer), event).await,
                    None => break,
                }
            }
        }
    }

    debug!("exiting inbound loop for peer {peer}");
}

async fn tick_inbound<T>(peer: Arc<Peer<T>>, event: InboundEvent)
where
    T: Tun + 'static,
{
    match event {
        InboundEvent::HanshakeInitiation {
            endpoint,
            initiation,
        } => inbound::handle_handshake_initiation(Arc::clone(&peer), endpoint, initiation).await,
        InboundEvent::HandshakeResponse {
            endpoint,
            packet,
            session,
        } => inbound::handle_handshake_response(Arc::clone(&peer), endpoint, packet, session).await,
        InboundEvent::CookieReply {
            endpoint,
            packet,
            session,
        } => inbound::handle_cookie_reply(Arc::clone(&peer), endpoint, packet, session).await,
        InboundEvent::TransportData {
            endpoint,
            packet,
            session,
        } => inbound::handle_transport_data(Arc::clone(&peer), endpoint, packet, session).await,
    }
}

mod inbound {
    use super::*;

    pub(super) async fn handle_handshake_initiation<T>(
        peer: Arc<Peer<T>>,
        endpoint: Endpoint,
        initiation: IncomingInitiation,
    ) where
        T: Tun + 'static,
    {
        peer.monitor
            .traffic()
            .inbound(protocol::HANDSHAKE_INITIATION_PACKET_SIZE);
        let ret = {
            let mut handshake = peer.handshake.write().unwrap();
            handshake.respond(&initiation)
        };
        match ret {
            Ok((session, packet)) => {
                {
                    let mut sessions = peer.sessions.write().unwrap();
                    sessions.prepare_next(session);
                }
                peer.update_endpoint(endpoint.clone());
                endpoint.send(&packet).await.unwrap();
                peer.monitor.handshake().initiated();
            }
            Err(e) => debug!("failed to respond to handshake initiation: {e}"),
        }
    }

    pub(super) async fn handle_handshake_response<T>(
        peer: Arc<Peer<T>>,
        endpoint: Endpoint,
        packet: HandshakeResponse,
        _session: Session,
    ) where
        T: Tun + 'static,
    {
        peer.monitor
            .traffic()
            .inbound(HANDSHAKE_RESPONSE_PACKET_SIZE);
        let ret = {
            let mut handshake = peer.handshake.write().unwrap();
            handshake.finalize(&packet)
        };
        match ret {
            Ok(session) => {
                let ret = {
                    let mut sessions = peer.sessions.write().unwrap();
                    sessions.complete_uninit(session)
                };
                if !ret {
                    debug!("failed to complete handshake, session not found");
                    return;
                }

                peer.monitor.handshake().completed();
                info!("handshake completed");
                peer.update_endpoint(endpoint);
                peer.stage_outbound(vec![]).await; // let the peer know the session is valid
            }
            Err(e) => debug!("failed to finalize handshake: {e}"),
        }
    }

    pub(super) async fn handle_cookie_reply<T>(
        peer: Arc<Peer<T>>,
        _endpoint: Endpoint,
        _packet: CookieReply,
        _session: Session,
    ) where
        T: Tun + 'static,
    {
        peer.monitor.traffic().inbound(COOKIE_REPLY_PACKET_SIZE);
    }

    pub(super) async fn handle_transport_data<T>(
        peer: Arc<Peer<T>>,
        endpoint: Endpoint,
        packet: TransportData,
        session: Session,
    ) where
        T: Tun + 'static,
    {
        peer.monitor.traffic().inbound(packet.packet_len());
        {
            let mut sessions = peer.sessions.write().unwrap();
            if sessions.complete_next(session.clone()) {
                info!("handshake completed");
                peer.monitor.handshake().completed();
            }
        }
        if !session.can_accept(packet.counter) {
            debug!("dropping packet due to replay");
            return;
        }

        peer.update_endpoint(endpoint);
        match session.decrypt_data(&packet) {
            Ok(data) => {
                if data.is_empty() {
                    // keepalive
                    return;
                }

                debug!("recv data from peer and try to send it to TUN");
                peer.tun.send(&data).await.unwrap();
                session.aceept(packet.counter);
            }
            Err(e) => debug!("failed to decrypt packet: {e}"),
        }
    }
}
