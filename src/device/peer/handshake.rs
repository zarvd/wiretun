use rand_core::{OsRng, RngCore};

use super::session::Session;
use crate::noise::protocol::HandshakeResponse;
use crate::noise::{
    crypto::{kdf2, PeerStaticSecret},
    handshake::{
        Cookie, IncomingInitiation, IncomingResponse, OutgoingInitiation, OutgoingResponse,
    },
    Error,
};

enum State {
    Uninit,
    Initiation(OutgoingInitiation),
}

pub(super) struct Handshake {
    state: State,
    secret: PeerStaticSecret,
    local_index: u32,
    cookie: Cookie,
}

impl Handshake {
    pub fn new(secret: PeerStaticSecret) -> Self {
        let cookie = Cookie::new(&secret);
        Self {
            secret,
            cookie,
            state: State::Uninit,
            local_index: OsRng.next_u32(),
        }
    }

    fn tick_local_index(&mut self) -> u32 {
        // FIXME: use global index to avoid collision
        self.local_index = self.local_index.wrapping_add(1);
        self.local_index
    }

    // validate handshake packet:
    // - HandshakeInitiation
    // - HandshakeResponse
    pub fn validate_payload(&self, payload: &[u8]) -> Result<(), Error> {
        self.cookie.validate_mac(payload)
    }

    // Prepare HandshakeInitiation packet.
    pub fn initiate(&mut self) -> (Session, Vec<u8>) {
        let sender_index = self.tick_local_index();
        let (state, payload) =
            OutgoingInitiation::new(sender_index, &self.secret, &mut self.cookie);
        let pre = Session::new(sender_index, [0u8; 32], 0, [0u8; 32]);
        self.state = State::Initiation(state);

        (pre, payload)
    }

    // Receive HandshakeInitiation packet from peer.
    pub fn respond(
        &mut self,
        initiation: &IncomingInitiation,
    ) -> Result<(Session, Vec<u8>), Error> {
        self.tick_local_index();
        let (state, payload) =
            OutgoingResponse::new(initiation, self.local_index, &self.secret, &mut self.cookie);
        let (sender_index, receiver_index) = (self.local_index, initiation.index);
        let (receiver_key, sender_key) = kdf2(&state.chaining_key, &[]);
        let sess = Session::new(sender_index, sender_key, receiver_index, receiver_key);

        Ok((sess, payload))
    }

    pub fn finalize(&mut self, packet: &HandshakeResponse) -> Result<Session, Error> {
        match &self.state {
            State::Initiation(initiation) => {
                let state = IncomingResponse::parse(initiation, &self.secret, packet)?;
                let (sender_index, receiver_index) = (initiation.index, state.index);
                let (sender_key, receiver_key) = kdf2(&state.chaining_key, &[]);
                let sess = Session::new(sender_index, sender_key, receiver_index, receiver_key);

                Ok(sess)
            }
            _ => Err(Error::InvalidHandshakeState),
        }
    }
}
