

use super::Error;



const MESSAGE_TYPE_HANDSHAKE_INITIATION: u8 = 1u8;
const MESSAGE_TYPE_HANDSHAKE_RESPONSE: u8 = 2u8;
const MESSAGE_TYPE_COOKIE_REPLY: u8 = 3u8;
const MESSAGE_TYPE_TRANSPORT_DATA: u8 = 4u8;
const HANDSHAKE_INITIATION_PACKET_SIZE: usize = 148;
const HANDSHAKE_RESPONSE_PACKET_SIZE: usize = 92;
const COOKIE_REPLY_PACKET_SIZE: usize = 64;

const MIN_PACKET_SIZE: usize = 4; // TODO

pub enum MessageType {
    HandshakeInitiation,
    HandshakeResponse,
    CookieReply,
    TransportData,
}

impl MessageType {
    pub fn parse(payload: &[u8]) -> Result<MessageType, Error> {
        if payload.len() < MIN_PACKET_SIZE || payload[1..4] != [0, 0, 0] {
            return Err(Error::InvalidPacket);
        }

        match payload[0] {
            MESSAGE_TYPE_HANDSHAKE_INITIATION
                if payload.len() == HANDSHAKE_INITIATION_PACKET_SIZE =>
            {
                Ok(MessageType::HandshakeInitiation)
            }
            MESSAGE_TYPE_HANDSHAKE_RESPONSE if payload.len() == HANDSHAKE_RESPONSE_PACKET_SIZE => {
                Ok(MessageType::HandshakeResponse)
            }
            MESSAGE_TYPE_COOKIE_REPLY if payload.len() == COOKIE_REPLY_PACKET_SIZE => {
                Ok(MessageType::CookieReply)
            }
            MESSAGE_TYPE_TRANSPORT_DATA => Ok(MessageType::TransportData),
            _ => Err(Error::InvalidPacket),
        }
    }
}
