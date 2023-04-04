use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use tracing::debug;

use crate::device::Error;
use crate::noise;
use crate::noise::crypto::PeerStaticSecret;
use crate::noise::{crypto, protocol};

#[derive(Clone)]
pub(crate) struct Session {
    sender_index: u32,
    sender_nonce: Arc<AtomicU64>,
    sender_key: [u8; 32],
    receiver_index: u32,
    receiver_key: [u8; 32],
    nonce_filter: Arc<Mutex<NonceFilter>>,
    created_at: Instant,
}

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
        if self.sender_index != packet.receiver_index {
            return Err(Error::Noise(noise::Error::ReceiverIndexNotMatch));
        }

        debug!("try to decrypt data: {:?}", packet);
        crypto::aead_decrypt(&self.receiver_key, packet.counter, &packet.payload, &[])
            .map_err(Error::Noise)
    }
}

impl Debug for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("sender_index", &self.sender_index)
            .field("receiver_index", &self.receiver_index)
            .finish()
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
            // TODO perf: we can advance by 64 bits at a time
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
    uninit: Option<Session>,
    previous: Option<Session>,
    current: Option<Session>,
    next: Option<Session>,
}

impl Sessions {
    pub fn new(secret: PeerStaticSecret, mgr: SessionManager) -> Self {
        Self {
            secret,
            mgr,
            uninit: None,
            previous: None,
            current: None,
            next: None,
        }
    }

    pub fn current(&self) -> Option<Session> {
        self.current.clone()
    }

    /// Initiator prepares a half-initialized session.
    pub fn prepare_uninit(&mut self, session: Session) {
        if let Some(uninit) = self.uninit.take() {
            self.deactivate(&uninit);
        }
        self.activate(&session);
        self.uninit = Some(session);
    }

    /// Initiator completes the half-initialized session.
    pub fn complete_uninit(&mut self, session: Session) -> bool {
        match self.uninit.as_ref() {
            Some(uninit) if uninit.sender_index == session.sender_index => {
                self.deactivate(&uninit);
                self.activate(&session);
                self.deactive_previous();
                self.previous = self.current.take();
                self.current = Some(session);
                true
            }
            _ => false,
        }
    }

    /// Responder prepares the next session.
    pub fn prepare_next(&mut self, session: Session) {
        if let Some(next) = self.next.take() {
            self.deactive_previous();
            self.previous = Some(next);
        }
        self.activate(&session);
        self.next = Some(session);
    }

    /// Rotate with the given session and clear the next session.
    pub fn rotate(&mut self, session: Session) {
        self.deactive_previous();
        self.deactive_next();

        self.activate(&session);
        self.previous = self.current.take();
        self.current = Some(session);
    }

    /// Returns true if the given session is the next session.
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
    fn deactive_next(&mut self) {
        if let Some(next) = self.next.take() {
            self.deactivate(&next);
        }
    }

    #[inline]
    fn activate(&self, session: &Session) {
        debug!(
            "activate session: {} / {}",
            session.sender_index, session.receiver_index
        );
        self.mgr
            .insert(session.clone(), self.secret.public_key().to_bytes());
    }

    #[inline]
    fn deactivate(&self, session: &Session) {
        debug!(
            "deactivate session: {} / {}",
            session.sender_index, session.receiver_index
        );
        self.mgr.remove(session);
    }
}

struct SessionManagerInner {
    by_index: HashMap<u32, (Session, [u8; 32])>,
    by_key: HashMap<[u8; 32], HashSet<u32>>,
}

impl SessionManagerInner {
    pub fn new() -> Self {
        Self {
            by_index: HashMap::new(),
            by_key: HashMap::new(),
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
        let mut inner = self.inner.write().unwrap();
        let index = session.sender_index;
        inner.by_index.insert(index, (session, peer_static_pub));
        inner
            .by_key
            .entry(peer_static_pub)
            .or_default()
            .insert(index);
    }

    pub fn get_by_index(&self, index: u32) -> Option<(Session, [u8; 32])> {
        let inner = self.inner.read().unwrap();
        inner.by_index.get(&index).cloned()
    }

    pub fn remove(&self, session: &Session) -> Option<(Session, [u8; 32])> {
        let mut inner = self.inner.write().unwrap();
        if let Some((session, key)) = inner.by_index.remove(&session.sender_index) {
            inner
                .by_key
                .get_mut(&key)
                .unwrap()
                .remove(&session.sender_index);
            Some((session, key))
        } else {
            None
        }
    }

    pub fn remove_by_key(&self, key: &[u8; 32]) {
        let mut inner = self.inner.write().unwrap();
        if let Some(indices) = inner.by_key.remove(key) {
            for index in indices {
                inner.by_index.remove(&index);
            }
        }
    }

    pub fn clear(&self) {
        *self.inner.write().unwrap() = SessionManagerInner::new();
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
