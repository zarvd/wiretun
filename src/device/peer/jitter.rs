use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) struct Jitter {
    epoch: Instant,
    last_sent_handshake_initiation_millis: AtomicU64,
    last_sent_data_millis: AtomicU64,
    tx_messages: AtomicU64,
    rx_messages: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
}

impl Jitter {
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
            last_sent_handshake_initiation_millis: AtomicU64::new(0),
            last_sent_data_millis: AtomicU64::new(0),
            tx_messages: AtomicU64::new(0),
            rx_messages: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn can_send_keepalive(&self) -> bool {
        let d = self.last_sent_data_millis.load(Ordering::Relaxed);

        d == 0 || self.since_epoch(d).elapsed() >= KEEPALIVE_TIMEOUT
    }

    #[inline]
    pub fn handshake_initiation_timeout(&self) -> Duration {
        todo!();
    }

    #[inline]
    pub fn keepalive_timeout(&self) -> Duration {
        let elapsed = self.last_send_data_at().elapsed();
        if elapsed > KEEPALIVE_TIMEOUT {
            Duration::new(0, 0)
        } else {
            KEEPALIVE_TIMEOUT - elapsed
        }
    }

    #[inline]
    pub fn mark_send_data(&self) {
        self.last_sent_data_millis
            .store(self.now_millis(), Ordering::Relaxed);
    }

    #[inline]
    pub fn can_send_handshake_initiation(&self) -> bool {
        let d = self
            .last_sent_handshake_initiation_millis
            .load(Ordering::Relaxed);
        d == 0 || self.since_epoch(d).elapsed() >= REKEY_TIMEOUT
    }

    #[inline]
    pub fn mark_send_handshake_initiation(&self) {
        self.last_sent_handshake_initiation_millis
            .store(self.now_millis(), Ordering::Relaxed);
    }

    #[inline]
    fn last_send_data_at(&self) -> Instant {
        self.since_epoch(self.last_sent_data_millis.load(Ordering::Relaxed))
    }

    #[inline]
    fn last_sent_handshake_initiation_at(&self) -> Instant {
        self.since_epoch(
            self.last_sent_handshake_initiation_millis
                .load(Ordering::Relaxed),
        )
    }

    fn now_millis(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    fn since_epoch(&self, millis: u64) -> Instant {
        let d = Duration::from_millis(millis);
        self.epoch + d
    }
}
