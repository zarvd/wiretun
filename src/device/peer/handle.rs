use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
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
    handles: Vec<JoinHandle<()>>,
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
        let handshake_loop = tokio::spawn(loop_handshake(token.child_token(), Arc::clone(&peer)));
        let inbound_loop = tokio::spawn(loop_inbound(
            token.child_token(),
            Arc::clone(&peer),
            inbound,
        ));
        let outbound_loop = tokio::spawn(loop_outbound(
            token.child_token(),
            Arc::clone(&peer),
            outbound,
        ));

        Self {
            token,
            handles: vec![handshake_loop, inbound_loop, outbound_loop],
        }
    }

    /// Cancel the background tasks and wait until they are terminated.
    /// If the timeout is reached, the tasks are terminated immediately.
    pub async fn cancel(mut self, timeout: Duration) {
        self.token.cancel();
        let handles = self.handles.drain(..).collect::<Vec<_>>();
        let abort_handles = handles.iter().map(|h| h.abort_handle()).collect::<Vec<_>>();
        if let Err(e) = tokio::time::timeout(timeout, join_all(handles)).await {
            warn!(
                "failed to cancel peer tasks in {}ms: {}",
                timeout.as_millis(),
                e
            );
            for handle in abort_handles {
                handle.abort();
            }
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
    debug!("Handshake loop for {peer} is UP");
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
    debug!("Handshake loop for {peer} is DOWN");
}

// Send to endpoint if connected, otherwise queue for later
async fn loop_outbound<T>(token: CancellationToken, peer: Arc<Peer<T>>, mut rx: OutboundRx)
where
    T: Tun + 'static,
{
    debug!("Outbound loop for {peer} is UP");

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

    debug!("Outbound loop for {peer} is DOWN");
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
    debug!("Inbound loop for {peer} is UP");

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

    debug!("Inbound loop for {peer} is DOWN");
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
