use super::{IncomingInitiation, IncomingResponse, OutgoingInitiation, OutgoingResponse};
use crate::noise::crypto::{kdf2, PrivateKey, PublicKey, StaticSecret};
use crate::noise::session::Session;
use crate::noise::Error;

enum State {
    Uninit,
    Initiation(OutgoingInitiation),
    Finialized {},
}

pub struct Handshake {
    state: State,
    static_secret: StaticSecret,
    pub(crate) local_index: u32,
}

impl Handshake {
    pub fn new(static_secret: StaticSecret) -> Self {
        Self {
            state: State::Uninit,
            local_index: 0,
            static_secret,
        }
    }

    // Prepare HandshakeInitiation packet.
    pub fn initiate(&mut self) -> Vec<u8> {
        let (state, payload) = OutgoingInitiation::new(self.local_index, &self.static_secret);
        self.state = State::Initiation(state);
        payload
    }

    // Receive HandshakeInitiation packet from peer.
    pub fn respond(&mut self, payload: &[u8]) -> Result<(Session, Vec<u8>), Error> {
        let initiation = IncomingInitiation::parse(&self.static_secret, payload)?;
        let (state, payload) =
            OutgoingResponse::new(&initiation, self.local_index, &self.static_secret);
        let (sender_nonce, receiver_nonce) = (self.local_index, initiation.index);
        let (receiver_key, sender_key) = kdf2(&[], &state.chaining_key);
        let sess = Session::new(sender_nonce, sender_key, receiver_nonce, receiver_key);
        Ok((sess, payload))
    }

    pub fn finalize(&mut self, payload: &[u8]) -> Result<Session, Error> {
        match &self.state {
            State::Initiation(initiation) => {
                let state = IncomingResponse::parse(initiation, &self.static_secret, payload)?;
                let (sender_nonce, receiver_nonce) = (initiation.index, state.index);
                let (sender_key, receiver_key) = kdf2(&[], &state.chaining_key);
                let sess = Session::new(sender_nonce, sender_key, receiver_nonce, receiver_key);
                Ok(sess)
            }
            _ => Err(Error::InvalidKeyLength), // FIXME
        }
    }
}
