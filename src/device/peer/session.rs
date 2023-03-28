use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use tracing::debug;

use crate::device::Error;
use crate::noise::crypto::PeerStaticSecret;
use crate::noise::{crypto, protocol};

#[derive(Clone, Debug)]
pub struct Session {
    sender_index: u32,
    sender_nonce: Arc<AtomicU64>,
    sender_key: [u8; 32],
    receiver_index: u32,
    receiver_key: [u8; 32],
    nonce_filter: Arc<Mutex<NonceFilter>>,
    created_at: Instant,
}

impl PartialEq for Session {
    fn eq(&self, other: &Self) -> bool {
        self.sender_index == other.sender_index
    }
}

impl Eq for Session {}

impl Session {
    #[inline]
    pub fn new(
        sender_index: u32,
        sender_key: [u8; 32],
        receiver_index: u32,
        receiver_key: [u8; 32],
    ) -> Self {
        Self {
            sender_index,
            sender_key,
            sender_nonce: Arc::new(AtomicU64::new(0)),
            receiver_index,
            receiver_key,
            nonce_filter: Arc::new(Mutex::new(NonceFilter::new())),
            created_at: Instant::now(),
        }
    }

    #[inline]
    fn noop() -> Self {
        Self::new(0, [0; 32], 0, [0; 32])
    }

    #[inline]
    pub fn can_accept(&self, nonce: u64) -> bool {
        self.nonce_filter.lock().unwrap().can_accept(nonce)
    }

    #[inline]
    pub fn aceept(&self, nonce: u64) {
        self.nonce_filter.lock().unwrap().accept(nonce)
    }

    #[inline]
    pub fn next_nonce(&self) -> u64 {
        self.sender_nonce
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    #[inline]
    pub fn encrypt_data(&self, data: &[u8]) -> Result<protocol::TransportData, Error> {
        let nonce = self.next_nonce();
        let payload =
            crypto::aead_encrypt(&self.sender_key, nonce, data, &[]).map_err(Error::Noise)?;
        Ok(protocol::TransportData {
            receiver_index: self.receiver_index,
            counter: nonce,
            payload,
        })
    }

    #[inline]
    pub fn decrypt_data(&self, packet: &protocol::TransportData) -> Result<Vec<u8>, Error> {
        crypto::aead_decrypt(&self.receiver_key, packet.counter, &packet.payload, &[])
            .map_err(Error::Noise)
    }

    #[inline]
    pub fn sender_index(&self) -> u32 {
        self.sender_index
    }

    #[inline]
    pub fn sender_key(&self) -> &[u8] {
        &self.sender_key
    }

    #[inline]
    pub fn receiver_index(&self) -> u32 {
        self.receiver_index
    }

    #[inline]
    pub fn receiver_key(&self) -> &[u8] {
        &self.receiver_key
    }

    #[inline]
    pub fn created_at(&self) -> Instant {
        self.created_at
    }
}

const MAX_REPLAY_SIZE: usize = 1 << 10;

struct NonceFilter {
    next: u64,
    accepted: u64,
    bitmap: ([u64; MAX_REPLAY_SIZE / 64], usize),
}

impl NonceFilter {
    pub fn new() -> Self {
        Self {
            next: 0,
            accepted: 0,
            bitmap: ([0u64; MAX_REPLAY_SIZE / 64], 0),
        }
    }

    #[inline]
    pub fn can_accept(&self, counter: u64) -> bool {
        if counter >= self.next {
            return true;
        }

        if counter + MAX_REPLAY_SIZE as u64 <= self.next {
            return false;
        }

        !self.is_set(counter)
    }

    #[inline]
    pub fn accept(&mut self, counter: u64) {
        self.accepted += 1;
        if counter < self.next {
            self.set(counter);
        } else if counter > self.next && (counter - self.next) as usize >= MAX_REPLAY_SIZE {
            self.bitmap = ([0u64; MAX_REPLAY_SIZE / 64], 0);
            self.next = counter + 1;
            self.set(counter);
        } else {
            while self.next < counter {
                self.advance();
            }
            self.advance();
            self.set(counter);
        }
    }

    #[inline]
    fn advance(&mut self) {
        if self.next > MAX_REPLAY_SIZE as u64 {
            self.unset(self.next - MAX_REPLAY_SIZE as u64);
        }
        self.next += 1;
        self.bitmap.1 = (self.bitmap.1 + 1) % MAX_REPLAY_SIZE;
    }

    #[inline]
    fn bitmap_index(&self, i: u64) -> (usize, usize) {
        let (_, next_idx) = &self.bitmap;
        let i = {
            let offset = (self.next - i) as usize;
            if *next_idx >= offset {
                *next_idx - offset
            } else {
                MAX_REPLAY_SIZE + *next_idx - offset
            }
        };
        let word_idx = i / 64;
        let bit_idx = i - word_idx * 64;
        (word_idx, bit_idx)
    }

    #[inline]
    fn is_set(&self, i: u64) -> bool {
        let (word_idx, bit_idx) = self.bitmap_index(i);
        self.bitmap.0[word_idx] & (1 << bit_idx) != 0
    }

    #[inline]
    fn set(&mut self, i: u64) {
        let (word_idx, bit_idx) = self.bitmap_index(i);
        println!(
            "set {} {} {} {} {}",
            self.next, self.bitmap.1, i, word_idx, bit_idx
        );
        self.bitmap.0[word_idx] |= 1 << bit_idx;
    }

    #[inline]
    fn unset(&mut self, i: u64) {
        let (word_idx, bit_idx) = self.bitmap_index(i);
        self.bitmap.0[word_idx] &= !(1 << bit_idx);
    }
}

impl fmt::Debug for NonceFilter {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("NonceFilter")
            .field("next", &self.next)
            .field("accepted", &self.accepted)
            .finish()
    }
}

pub(super) struct Sessions {
    mgr: SessionManager,
    secret: PeerStaticSecret,
    previous: Option<Session>,
    current: Option<Session>,
    next: Option<Session>,
}

impl Sessions {
    pub fn new(secret: PeerStaticSecret, mgr: SessionManager) -> Self {
        Self {
            secret,
            mgr,
            previous: None,
            current: None,
            next: None,
        }
    }

    pub fn current(&self) -> Option<Session> {
        self.current.clone()
    }

    pub fn prepare_next(&mut self, next: Session) {
        self.deactive_next();
        self.activiate(&next);
        self.next = Some(next);
    }

    pub fn rotate(&mut self, session: Session) {
        debug!("renew next session");
        self.deactive_previous();
        self.deactive_next();

        self.activiate(&session);
        self.previous = self.current.take();
        self.current = Some(session);
    }

    pub fn try_rotate(&mut self, session: Session) -> bool {
        if let Some(next) = self.next.as_ref() {
            if session.sender_index == next.sender_index {
                self.rotate(session);
                return true;
            }
        }
        false
    }

    #[inline]
    fn deactive_previous(&mut self) {
        if let Some(previous) = self.previous.take() {
            self.deactivate(&previous);
        }
    }

    #[inline]
    fn deactive_current(&mut self) {
        if let Some(current) = self.current.take() {
            self.deactivate(&current);
        }
    }

    #[inline]
    fn deactive_next(&mut self) {
        if let Some(next) = self.next.take() {
            self.deactivate(&next);
        }
    }

    #[inline]
    fn activiate(&self, session: &Session) {
        self.mgr
            .insert(session.clone(), self.secret.public_key().to_bytes());
    }

    #[inline]
    fn deactivate(&self, session: &Session) {
        self.mgr.remove(session);
    }
}

struct SessionManagerInner {
    by_index: HashMap<u32, (Session, [u8; 32])>,
}

impl SessionManagerInner {
    pub fn new() -> Self {
        Self {
            by_index: HashMap::new(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct SessionManager {
    inner: Arc<RwLock<SessionManagerInner>>,
}

impl SessionManager {
    pub fn new() -> Self {
        let inner = Arc::new(RwLock::new(SessionManagerInner::new()));
        Self { inner }
    }

    pub fn insert(&self, session: Session, peer_static_pub: [u8; 32]) {
        debug!("insert session: {}", session.sender_index);
        let mut inner = self.inner.write().unwrap();
        inner
            .by_index
            .insert(session.sender_index, (session, peer_static_pub));
    }

    pub fn get_by_index(&self, index: u32) -> Option<(Session, [u8; 32])> {
        debug!("get session by index: {}", index);
        let inner = self.inner.read().unwrap();
        inner.by_index.get(&index).cloned()
    }

    fn remove(&self, session: &Session) -> Option<(Session, [u8; 32])> {
        debug!("remove session: {}", session.sender_index);
        let mut inner = self.inner.write().unwrap();
        inner.by_index.remove(&session.sender_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_filter() {
        {
            let mut filter = NonceFilter::new();
            for i in 0..MAX_REPLAY_SIZE {
                let i = i as u64;
                assert!(filter.can_accept(i));
                filter.accept(i);
                assert!(!filter.can_accept(i));
                assert_eq!(filter.accepted, i + 1);
            }
            assert_eq!(filter.bitmap.0, [u64::MAX; MAX_REPLAY_SIZE / 64]);
        }

        {
            let mut filter = NonceFilter::new();
            for i in 0..MAX_REPLAY_SIZE * 2 {
                let i = i as u64;
                assert!(filter.can_accept(i));
                filter.accept(i);
                assert!(!filter.can_accept(i));
                assert_eq!(filter.accepted, i + 1);
            }
            for i in 0..MAX_REPLAY_SIZE {
                let i = i as u64;
                assert!(!filter.can_accept(i));
            }
        }

        {
            let mut filter = NonceFilter::new();
            for i in MAX_REPLAY_SIZE..MAX_REPLAY_SIZE * 2 {
                let i = i as u64;
                assert!(filter.can_accept(i));
                filter.accept(i);
                assert!(!filter.can_accept(i), "should not accept {} again", i);
            }
            for i in 0..MAX_REPLAY_SIZE {
                let i = i as u64;
                assert!(!filter.can_accept(i));
            }
        }
    }
}
