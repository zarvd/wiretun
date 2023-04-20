use super::session::{Session, SessionIndex};
use crate::noise::protocol::HandshakeResponse;
use crate::noise::{
    crypto::{kdf2, PeerStaticSecret},
    handshake::{
        IncomingInitiation, IncomingResponse, MacGenerator, OutgoingInitiation, OutgoingResponse,
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
    macs: MacGenerator,
    session_index: SessionIndex,
}

impl Handshake {
    pub fn new(secret: PeerStaticSecret, session_index: SessionIndex) -> Self {
        let cookie = MacGenerator::new(&secret);
        Self {
            secret,
            session_index,
            macs: cookie,
            state: State::Uninit,
        }
    }

    // Prepare HandshakeInitiation packet.
    pub fn initiate(&mut self) -> (Session, Vec<u8>) {
        let sender_index = self.session_index.next_index();
        let (state, payload) = OutgoingInitiation::new(sender_index, &self.secret, &mut self.macs);
        let pre = Session::new(self.secret.clone(), sender_index, [0u8; 32], 0, [0u8; 32]);
        self.state = State::Initiation(state);

        (pre, payload)
    }

    // Receive HandshakeInitiation packet from peer.
    pub fn respond(
        &mut self,
        initiation: &IncomingInitiation,
    ) -> Result<(Session, Vec<u8>), Error> {
        let local_index = self.session_index.next_index();
        let (state, payload) =
            OutgoingResponse::new(initiation, local_index, &self.secret, &mut self.macs);
        let (sender_index, receiver_index) = (local_index, initiation.index);
        let (receiver_key, sender_key) = kdf2(&state.chaining_key, &[]);
        let sess = Session::new(
            self.secret.clone(),
            sender_index,
            sender_key,
            receiver_index,
            receiver_key,
        );

        Ok((sess, payload))
    }

    pub fn finalize(&mut self, packet: &HandshakeResponse) -> Result<Session, Error> {
        match &self.state {
            State::Initiation(initiation) => {
                let state = IncomingResponse::parse(initiation, &self.secret, packet)?;
                let (sender_index, receiver_index) = (initiation.index, state.index);
                let (sender_key, receiver_key) = kdf2(&state.chaining_key, &[]);
                let sess = Session::new(
                    self.secret.clone(),
                    sender_index,
                    sender_key,
                    receiver_index,
                    receiver_key,
                );

                Ok(sess)
            }
            _ => Err(Error::InvalidHandshakeState),
        }
    }
}
