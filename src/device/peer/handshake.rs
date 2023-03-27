use super::Session;
use crate::noise::protocol::{HandshakeInitiation, HandshakeResponse};
use crate::noise::{
    crypto::{kdf2, PeerStaticSecret},
    handshake::{IncomingInitiation, IncomingResponse, OutgoingInitiation, OutgoingResponse},
    Error,
};

enum State {
    Uninit,
    Initiation(OutgoingInitiation),
    Finialized {},
}

pub(super) struct Handshake {
    state: State,
    secret: PeerStaticSecret,
    pub(crate) local_index: u32,
}

impl Handshake {
    pub fn new(secret: PeerStaticSecret) -> Self {
        Self {
            state: State::Uninit,
            local_index: 0,
            secret,
        }
    }

    // Prepare HandshakeInitiation packet.
    pub fn initiate(&mut self) -> Vec<u8> {
        let (state, payload) = OutgoingInitiation::new(self.local_index, &self.secret);
        self.state = State::Initiation(state);
        payload
    }

    // Receive HandshakeInitiation packet from peer.
    pub fn respond(
        &mut self,
        initiation: &IncomingInitiation,
    ) -> Result<(Session, Vec<u8>), Error> {
        let (state, payload) = OutgoingResponse::new(initiation, self.local_index, &self.secret);
        let (sender_nonce, receiver_nonce) = (self.local_index, initiation.index);
        let (receiver_key, sender_key) = kdf2(&[], &state.chaining_key);
        let sess = Session::new(sender_nonce, sender_key, receiver_nonce, receiver_key);
        Ok((sess, payload))
    }

    pub fn finalize(&mut self, packet: &HandshakeResponse) -> Result<Session, Error> {
        match &self.state {
            State::Initiation(initiation) => {
                let state = IncomingResponse::parse(initiation, &self.secret, packet)?;
                let (sender_nonce, receiver_nonce) = (initiation.index, state.index);
                let (sender_key, receiver_key) = kdf2(&[], &state.chaining_key);
                let sess = Session::new(sender_nonce, sender_key, receiver_nonce, receiver_key);
                Ok(sess)
            }
            _ => Err(Error::InvalidKeyLength), // FIXME
        }
    }
}
