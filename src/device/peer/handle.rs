use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::{InboundEvent, InboundRx, OutboundEvent, OutboundRx, Peer, Session};
use crate::device::{Endpoint, Transport};
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
    pub fn spawn<T, I>(
        token: CancellationToken,
        peer: Arc<Peer<T, I>>,
        inbound: InboundRx<I>,
        outbound: OutboundRx,
    ) -> Self
    where
        T: Tun + 'static,
        I: Transport,
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

async fn loop_handshake<T, I>(token: CancellationToken, peer: Arc<Peer<T, I>>)
where
    T: Tun + 'static,
    I: Transport,
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
async fn loop_outbound<T, I>(token: CancellationToken, peer: Arc<Peer<T, I>>, mut rx: OutboundRx)
where
    T: Tun + 'static,
    I: Transport,
{
    debug!("Outbound loop for {peer} is UP");

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            _ = time::sleep_until(peer.monitor.keepalive().next_attempt_in(peer.monitor.traffic()).into()) => {
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

async fn tick_outbound<T, I>(peer: Arc<Peer<T, I>>, data: Vec<u8>)
where
    T: Tun + 'static,
    I: Transport,
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
async fn loop_inbound<T, I>(token: CancellationToken, peer: Arc<Peer<T, I>>, mut rx: InboundRx<I>)
where
    T: Tun + 'static,
    I: Transport,
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

async fn tick_inbound<T, I>(peer: Arc<Peer<T, I>>, event: InboundEvent<I>)
where
    T: Tun + 'static,
    I: Transport,
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
    use tracing::error;

    pub(super) async fn handle_handshake_initiation<T, I>(
        peer: Arc<Peer<T, I>>,
        endpoint: Endpoint<I>,
        initiation: IncomingInitiation,
    ) where
        T: Tun + 'static,
        I: Transport,
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

    pub(super) async fn handle_handshake_response<T, I>(
        peer: Arc<Peer<T, I>>,
        endpoint: Endpoint<I>,
        packet: HandshakeResponse,
        _session: Session,
    ) where
        T: Tun + 'static,
        I: Transport,
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

    pub(super) async fn handle_cookie_reply<T, I>(
        peer: Arc<Peer<T, I>>,
        _endpoint: Endpoint<I>,
        _packet: CookieReply,
        _session: Session,
    ) where
        T: Tun + 'static,
        I: Transport,
    {
        peer.monitor.traffic().inbound(COOKIE_REPLY_PACKET_SIZE);
    }

    pub(super) async fn handle_transport_data<T, I>(
        peer: Arc<Peer<T, I>>,
        endpoint: Endpoint<I>,
        packet: TransportData,
        session: Session,
    ) where
        T: Tun + 'static,
        I: Transport,
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
                if let Err(e) = peer.tun.send(&data).await {
                    error!("{peer} failed to send data to tun: {e}");
                }
                session.aceept(packet.counter);
            }
            Err(e) => debug!("failed to decrypt packet: {e}"),
        }
    }
}
