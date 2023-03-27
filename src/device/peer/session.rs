use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use crate::noise::crypto::PeerStaticSecret;

#[derive(Clone, Debug)]
pub struct Session {
    sender_index: u32,
    sender_key: [u8; 32],
    receiver_index: u32,
    receiver_key: [u8; 32],
    created_at: Instant,
}

impl PartialEq for Session {
    fn eq(&self, other: &Self) -> bool {
        self.sender_index == other.sender_index
            && self.sender_key == other.sender_key
            && self.receiver_index == other.receiver_index
            && self.receiver_key == other.receiver_key
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
            receiver_index,
            receiver_key,
            created_at: Instant::now(),
        }
    }

    #[inline]
    fn noop() -> Self {
        Self::new(0, [0; 32], 0, [0; 32])
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

    pub fn renew_current(&mut self, session: Session) {
        if let Some(previous) = self.previous.take() {
            self.mgr.remove(&previous);
        }
        if let Some(current) = self.current.take() {
            self.mgr.remove(&current);
        }
        self.previous = self.next.take();

        self.renew(&session);
        self.current = Some(session);
    }

    pub fn prepare_next(&mut self, session: Session) {
        if let Some(previous) = self.previous.take() {
            self.mgr.remove(&previous);
        }
        if let Some(next) = self.next.take() {
            self.mgr.remove(&next);
        }

        self.renew(&session);
        self.next = Some(session);
    }

    pub fn rotate_next(&mut self, session: Session) -> bool {
        if let Some(next) = self.next.as_ref() {
            if session.eq(next) {
                if let Some(previous) = self.previous.take() {
                    self.mgr.remove(&previous);
                }
                self.previous = self.current.take();
                self.current = self.next.take();
                return true;
            }
        }
        false
    }

    #[inline]
    fn renew(&self, session: &Session) {
        self.mgr
            .insert(session.clone(), self.secret.public_key().to_bytes());
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
        let mut inner = self.inner.write().unwrap();
        inner
            .by_index
            .insert(session.sender_index, (session, peer_static_pub));
    }

    pub fn get_by_index(&self, index: u32) -> Option<(Session, [u8; 32])> {
        let inner = self.inner.read().unwrap();
        inner.by_index.get(&index).cloned()
    }

    fn remove(&self, session: &Session) -> Option<(Session, [u8; 32])> {
        let mut inner = self.inner.write().unwrap();
        inner.by_index.remove(&session.sender_index)
    }
}
