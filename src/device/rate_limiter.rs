use std::sync::atomic::{AtomicI16, Ordering};
use std::time::Duration;

use super::time::AtomicInstant;

pub(crate) struct RateLimiter {
    tokens: u16,
    bucket: AtomicI16,
    last_at: AtomicInstant,
}

impl RateLimiter {
    pub fn new(tokens: u16) -> Self {
        Self {
            tokens,
            bucket: AtomicI16::new(tokens as _),
            last_at: AtomicInstant::now(),
        }
    }

    pub fn fetch_token(&self) -> bool {
        if self.last_at.elapsed() > Duration::from_secs(1) {
            self.bucket.store(self.tokens as i16 - 1, Ordering::Relaxed);
            self.last_at.set_now();
            true
        } else if self.bucket.load(Ordering::Relaxed) > 0 {
            self.bucket.fetch_sub(1, Ordering::Relaxed) > 0
        } else {
            false
        }
    }
}
