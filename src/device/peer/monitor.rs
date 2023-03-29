use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

struct AtomicInstant {
    epoch: Instant,
    d: AtomicU64,
}

impl AtomicInstant {
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

pub(super) struct HandshakeMonitor {
    last_attempt_at: AtomicInstant,
    last_complete_at: AtomicInstant,
    abs_last_complete_at: Mutex<SystemTime>,
    attempt_before: AtomicInstant,
}

impl HandshakeMonitor {
    #[inline]
    pub fn new(epoch: Instant) -> Self {
        Self {
            last_attempt_at: AtomicInstant::new(epoch),
            last_complete_at: AtomicInstant::new(epoch - REJECT_AFTER_TIME),
            attempt_before: AtomicInstant::with_duration(epoch, REKEY_ATTEMPT_TIME),
            abs_last_complete_at: Mutex::new(SystemTime::UNIX_EPOCH),
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
    pub fn initiated(&self) {
        self.last_attempt_at.set_now();
    }

    #[inline]
    pub fn initiation_at(&self) -> Instant {
        if self.is_max_attempt() || self.last_complete_at.elapsed() < REKEY_AFTER_TIME {
            return Instant::now() + REKEY_TIMEOUT;
        }

        self.last_attempt_at.to_instant() + REKEY_TIMEOUT
    }

    #[inline]
    pub fn completed(&self) {
        self.last_complete_at.set_now();
        *self.abs_last_complete_at.lock().unwrap() = SystemTime::now();
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

pub(super) struct TrafficMonitor {
    last_sent_at: AtomicInstant,
    tx_messages: AtomicU64,
    rx_messages: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
}

impl TrafficMonitor {
    pub fn new(epoch: Instant) -> Self {
        Self {
            last_sent_at: AtomicInstant::new(epoch - KEEPALIVE_TIMEOUT),
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
    pub fn keepalive_at(&self) -> Instant {
        self.last_sent_at.to_instant() + KEEPALIVE_TIMEOUT
    }

    #[inline]
    pub fn outbound(&self, bytes: usize) {
        let n = bytes as _;
        self.last_sent_at.set_now();
        self.tx_messages.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(n, Ordering::Relaxed);
    }
}

pub(super) struct PeerMonitor {
    handshake: HandshakeMonitor,
    traffic: TrafficMonitor,
}

impl PeerMonitor {
    pub fn new() -> Self {
        let epoch = Instant::now();
        Self {
            handshake: HandshakeMonitor::new(epoch),
            traffic: TrafficMonitor::new(epoch),
        }
    }

    #[inline]
    pub fn traffic(&self) -> &TrafficMonitor {
        &self.traffic
    }

    #[inline]
    pub fn handshake(&self) -> &HandshakeMonitor {
        &self.handshake
    }

    #[inline]
    pub fn metrics(&self) -> PeerMetrics {
        PeerMetrics {
            tx_messages: self.traffic.tx_messages.load(Ordering::Relaxed),
            rx_messages: self.traffic.rx_messages.load(Ordering::Relaxed),
            tx_bytes: self.traffic.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.traffic.rx_bytes.load(Ordering::Relaxed),
            last_handshake_at: *self.handshake.abs_last_complete_at.lock().unwrap(),
        }
    }
}

pub struct PeerMetrics {
    pub tx_messages: u64,
    pub rx_messages: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_handshake_at: SystemTime,
}
