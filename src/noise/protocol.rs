use std::fmt::{Debug, Formatter};

const MESSAGE_TYPE_HANDSHAKE_INITIATION: u8 = 1u8;
const MESSAGE_TYPE_HANDSHAKE_RESPONSE: u8 = 2u8;
const MESSAGE_TYPE_COOKIE_REPLY: u8 = 3u8;
const MESSAGE_TYPE_TRANSPORT_DATA: u8 = 4u8;
pub const HANDSHAKE_INITIATION_PACKET_SIZE: usize = 148;
pub const HANDSHAKE_RESPONSE_PACKET_SIZE: usize = 92;
pub const COOKIE_REPLY_PACKET_SIZE: usize = 64;

pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

const MIN_PACKET_SIZE: usize = 4; // TODO

use super::Error;

pub struct HandshakeInitiation {
    pub sender_index: u32,
    pub ephemeral_public_key: [u8; 32],
    pub static_public_key: [u8; 32 + 16],
    pub timestamp: [u8; 12 + 16],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

impl TryFrom<&[u8]> for HandshakeInitiation {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != HANDSHAKE_INITIATION_PACKET_SIZE
            || value[0..4] != [MESSAGE_TYPE_HANDSHAKE_INITIATION, 0, 0, 0]
        {
            return Err(Error::InvalidPacket);
        }
        Ok(Self {
            sender_index: u32::from_le_bytes(value[4..8].try_into().unwrap()),
            ephemeral_public_key: value[8..40].try_into().unwrap(),
            static_public_key: value[40..88].try_into().unwrap(),
            timestamp: value[88..116].try_into().unwrap(),
            mac1: value[116..132].try_into().unwrap(),
            mac2: value[132..148].try_into().unwrap(),
        })
    }
}

impl Debug for HandshakeInitiation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeInitiation")
            .field("sender_index", &self.sender_index)
            .finish()
    }
}

pub struct HandshakeResponse {
    pub sender_index: u32,
    pub receiver_index: u32,
    pub ephemeral_public_key: [u8; 32],
    pub empty: [u8; 16],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

impl TryFrom<&[u8]> for HandshakeResponse {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != HANDSHAKE_RESPONSE_PACKET_SIZE
            || value[0..4] != [MESSAGE_TYPE_HANDSHAKE_RESPONSE, 0, 0, 0]
        {
            return Err(Error::InvalidPacket);
        }
        Ok(Self {
            sender_index: u32::from_le_bytes(value[4..8].try_into().unwrap()),
            receiver_index: u32::from_le_bytes(value[8..12].try_into().unwrap()),
            ephemeral_public_key: value[12..44].try_into().unwrap(),
            empty: value[44..60].try_into().unwrap(),
            mac1: value[60..76].try_into().unwrap(),
            mac2: value[76..92].try_into().unwrap(),
        })
    }
}

impl Debug for HandshakeResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeResponse")
            .field("sender_index", &self.sender_index)
            .field("receiver_index", &self.receiver_index)
            .finish()
    }
}

pub struct CookieReply {
    pub receiver_index: u32,
    pub nonce: [u8; 24],
    pub cookie: [u8; 16 + 16],
}

impl TryFrom<&[u8]> for CookieReply {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != COOKIE_REPLY_PACKET_SIZE
            || value[0..4] != [MESSAGE_TYPE_COOKIE_REPLY, 0, 0, 0]
        {
            return Err(Error::InvalidPacket);
        }
        Ok(Self {
            receiver_index: u32::from_le_bytes(value[4..8].try_into().unwrap()),
            nonce: value[8..32].try_into().unwrap(),
            cookie: value[32..64].try_into().unwrap(),
        })
    }
}

impl Debug for CookieReply {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieReply")
            .field("index", &self.receiver_index)
            .field("nonce", &self.nonce)
            .finish()
    }
}

pub struct TransportData {
    pub receiver_index: u32,
    pub counter: u64,
    pub payload: Vec<u8>,
}

impl TransportData {
    #[inline]
    pub fn packet_len(&self) -> usize {
        self.payload.len() + 16
    }
}

impl TransportData {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.payload.len() + 16);
        bytes.extend_from_slice(&[MESSAGE_TYPE_TRANSPORT_DATA, 0, 0, 0]);
        bytes.extend_from_slice(&self.receiver_index.to_le_bytes());
        bytes.extend_from_slice(&self.counter.to_le_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }
}

impl Debug for TransportData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportData")
            .field("receiver", &self.receiver_index)
            .field("counter", &self.counter)
            .field("len(payload)", &self.payload.len())
            .finish()
    }
}

impl TryFrom<&[u8]> for TransportData {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < MIN_PACKET_SIZE || value[0..4] != [MESSAGE_TYPE_TRANSPORT_DATA, 0, 0, 0] {
            return Err(Error::InvalidPacket);
        }
        Ok(Self {
            receiver_index: u32::from_le_bytes(value[4..8].try_into().unwrap()),
            counter: u64::from_le_bytes(value[8..16].try_into().unwrap()),
            payload: value[16..].to_vec(),
        })
    }
}

#[derive(Debug)]
pub enum Message {
    HandshakeInitiation(HandshakeInitiation),
    HandshakeResponse(HandshakeResponse),
    CookieReply(CookieReply),
    TransportData(TransportData),
}

impl Message {
    pub fn parse(payload: &[u8]) -> Result<Message, Error> {
        if payload.len() < MIN_PACKET_SIZE {
            return Err(Error::InvalidPacket);
        }
        let message = match payload[0] {
            MESSAGE_TYPE_HANDSHAKE_INITIATION => {
                Message::HandshakeInitiation(HandshakeInitiation::try_from(payload)?)
            }
            MESSAGE_TYPE_HANDSHAKE_RESPONSE => {
                Message::HandshakeResponse(HandshakeResponse::try_from(payload)?)
            }
            MESSAGE_TYPE_COOKIE_REPLY => Message::CookieReply(CookieReply::try_from(payload)?),
            MESSAGE_TYPE_TRANSPORT_DATA => {
                Message::TransportData(TransportData::try_from(payload)?)
            }
            _ => return Err(Error::InvalidPacket),
        };

        Ok(message)
    }

    pub fn is_handshake(payload: &[u8]) -> bool {
        match payload[0] {
            MESSAGE_TYPE_HANDSHAKE_INITIATION
                if payload.len() == HANDSHAKE_INITIATION_PACKET_SIZE =>
            {
                true
            }
            MESSAGE_TYPE_HANDSHAKE_RESPONSE if payload.len() == HANDSHAKE_RESPONSE_PACKET_SIZE => {
                true
            }
            _ => false,
        }
    }
}
