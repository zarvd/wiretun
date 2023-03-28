use std::sync::atomic::{AtomicU64, Ordering};

use std::time::{Duration, Instant};

const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

struct Timer {
    epoch: Instant,
    d: AtomicU64,
}

impl Timer {
    #[inline]
    pub fn new(epoch: Instant) -> Self {
        Self {
            epoch,
            d: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn with_duration(epoch: Instant, d: Duration) -> Self {
        Self {
            epoch,
            d: AtomicU64::new(d.as_millis() as _),
        }
    }

    #[inline]
    pub fn before(&self, other: Instant) -> bool {
        self.to_instant() < other
    }

    #[inline]
    pub fn after(&self, other: Instant) -> bool {
        self.to_instant() > other
    }

    #[inline]
    pub fn set_now(&self) {
        self.d
            .store(self.epoch.elapsed().as_millis() as _, Ordering::Relaxed);
    }

    #[inline]
    pub fn set_duration(&self, d: Duration) {
        let d = (self.epoch.elapsed() + d).as_millis();
        self.d.store(d as _, Ordering::Relaxed);
    }

    #[inline]
    pub fn elapsed(&self) -> Duration {
        self.to_instant().elapsed()
    }

    #[inline]
    fn to_instant(&self) -> Instant {
        self.epoch + Duration::from_millis(self.d.load(Ordering::Relaxed))
    }
}

struct HandshakeJitter {
    last_attempt_at: Timer,
    last_complete_at: Timer,
    attempt_before: Timer,
}

impl HandshakeJitter {
    #[inline]
    pub fn new(epoch: Instant) -> Self {
        Self {
            last_attempt_at: Timer::new(epoch),
            last_complete_at: Timer::new(epoch - REJECT_AFTER_TIME),
            attempt_before: Timer::with_duration(epoch, REKEY_ATTEMPT_TIME),
        }
    }

    #[inline]
    pub fn can_initiation(&self) -> bool {
        if self.last_complete_at.elapsed() < REKEY_AFTER_TIME {
            // An active session exists
            return false;
        }

        if self
            .attempt_before
            .before(self.last_complete_at.to_instant() + REKEY_AFTER_TIME)
        {
            self.reset_attempt();
        }

        self.last_attempt_at.elapsed() >= REKEY_TIMEOUT
    }

    #[inline]
    pub fn mark_initiation(&self) {
        self.last_attempt_at.set_now();
    }

    #[inline]
    pub fn next_initiation_at(&self) -> Instant {
        if self.is_max_attempt() || self.last_complete_at.elapsed() < REKEY_AFTER_TIME {
            return Instant::now() + REKEY_TIMEOUT;
        }

        self.last_attempt_at.to_instant() + REKEY_TIMEOUT
    }

    #[inline]
    pub fn mark_complete(&self) {
        self.last_complete_at.set_now();
        self.reset_attempt();
    }

    #[inline]
    pub fn reset_attempt(&self) {
        self.attempt_before.set_duration(REKEY_ATTEMPT_TIME);
    }

    #[inline]
    fn is_max_attempt(&self) -> bool {
        self.attempt_before.before(Instant::now())
    }
}

struct TransportDataJitter {
    last_sent_at: Timer,
    tx_messages: AtomicU64,
    rx_messages: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
}

impl TransportDataJitter {
    pub fn new(epoch: Instant) -> Self {
        Self {
            last_sent_at: Timer::new(epoch - KEEPALIVE_TIMEOUT),
            tx_messages: AtomicU64::new(0),
            rx_messages: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn can_keepalive(&self) -> bool {
        self.last_sent_at.elapsed() >= KEEPALIVE_TIMEOUT
    }

    #[inline]
    pub fn next_keepalive_at(&self) -> Instant {
        self.last_sent_at.to_instant() + KEEPALIVE_TIMEOUT
    }

    #[inline]
    pub fn prepare_outbound(&self, bytes: u64) {
        self.last_sent_at.set_now();
        self.tx_messages.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

pub(super) struct Jitter {
    handshake: HandshakeJitter,
    data: TransportDataJitter,
}

impl Jitter {
    pub fn new() -> Self {
        let epoch = Instant::now();
        Self {
            handshake: HandshakeJitter::new(epoch),
            data: TransportDataJitter::new(epoch),
        }
    }

    #[inline]
    pub fn can_keepalive(&self) -> bool {
        // TODO: should check if outbound queue is empty
        self.data.can_keepalive()
    }

    #[inline]
    pub fn next_keepalive_at(&self) -> Instant {
        self.data.next_keepalive_at()
    }

    #[inline]
    pub fn mark_outbound(&self, bytes: u64) {
        self.data.prepare_outbound(bytes);
    }

    #[inline]
    pub fn can_handshake_initiation(&self) -> bool {
        self.handshake.can_initiation()
    }

    #[inline]
    pub fn next_handshake_initiation_at(&self) -> Instant {
        self.handshake.next_initiation_at()
    }

    #[inline]
    pub fn mark_handshake_initiation(&self) {
        self.handshake.mark_initiation();
    }

    #[inline]
    pub fn mark_handshake_complete(&self) {
        self.handshake.mark_complete();
    }
}
