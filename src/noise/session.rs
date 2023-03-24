pub struct Session {
    sender_nonce: u32,
    sender_key: [u8; 32],
    receiver_nonce: u32,
    receiver_key: [u8; 32],
}

impl Session {
    pub fn new(
        sender_nonce: u32,
        sender_key: [u8; 32],
        receiver_nonce: u32,
        receiver_key: [u8; 32],
    ) -> Self {
        Self {
            sender_nonce,
            sender_key,
            receiver_nonce,
            receiver_key,
        }
    }

    #[inline]
    pub fn sender_nonce(&self) -> u32 {
        self.sender_nonce
    }

    #[inline]
    pub fn sender_key(&self) -> &[u8] {
        &self.sender_key
    }

    #[inline]
    pub fn receiver_nonce(&self) -> u32 {
        self.receiver_nonce
    }

    #[inline]
    pub fn receiver_key(&self) -> &[u8] {
        &self.receiver_key
    }
}
