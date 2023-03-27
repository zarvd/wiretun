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
    secret: PeerStaticSecret,
    current: usize,
    sessions: [Session; 3],
    mgr: SessionManager,
}

impl Sessions {
    pub fn new(secret: PeerStaticSecret, mgr: SessionManager) -> Self {
        Self {
            secret,
            current: 0,
            sessions: [Session::noop(), Session::noop(), Session::noop()],
            mgr,
        }
    }

    pub fn renew(&mut self, session: Session) {
        self.mgr
            .remove_by_index(self.sessions[(self.current + 2) % 3].sender_index());
        self.current = (self.current + 1) % 3;

        self.mgr.insert_with_index(
            session.sender_index(),
            session.clone(),
            self.secret.public_key().to_bytes(),
        );
        self.sessions[(self.current + 1) % 3] = session;
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

    pub fn insert_with_index(&self, index: u32, session: Session, peer_static_pub: [u8; 32]) {
        let mut inner = self.inner.write().unwrap();
        inner.by_index.insert(index, (session, peer_static_pub));
    }

    pub fn get_by_index(&self, index: u32) -> Option<(Session, [u8; 32])> {
        let inner = self.inner.read().unwrap();
        inner.by_index.get(&index).cloned()
    }

    fn remove_by_index(&self, index: u32) -> Option<(Session, [u8; 32])> {
        let mut inner = self.inner.write().unwrap();
        inner.by_index.remove(&index)
    }
}
