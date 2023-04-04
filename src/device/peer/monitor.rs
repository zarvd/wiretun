use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use crate::device::time::{AtomicInstant, AtomicTimestamp};

const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) struct HandshakeMonitor {
    last_attempt_at: AtomicInstant,
    last_complete_at: AtomicInstant,
    last_complete_ts: AtomicTimestamp,
    attempt_before: AtomicInstant,
}

impl HandshakeMonitor {
    #[inline]
    pub fn new() -> Self {
        Self {
            last_attempt_at: AtomicInstant::now(),
            last_complete_at: AtomicInstant::from_std(Instant::now() - REJECT_AFTER_TIME),
            attempt_before: AtomicInstant::now() + REKEY_ATTEMPT_TIME,
            last_complete_ts: AtomicTimestamp::zeroed(),
        }
    }

    #[inline]
    pub fn initiated(&self) {
        self.last_attempt_at.set_now();
    }

    #[inline]
    pub fn will_initiate_in(&self) -> Instant {
        if self.is_max_attempt() || self.last_complete_at.elapsed() < REKEY_AFTER_TIME {
            return Instant::now() + REKEY_TIMEOUT;
        }

        self.last_attempt_at.to_std() + REKEY_TIMEOUT
    }

    #[inline]
    pub fn completed(&self) {
        self.last_complete_at.set_now();
        self.last_complete_ts.set_now();
        self.reset_attempt();
    }

    #[inline]
    pub fn reset_attempt(&self) {
        self.attempt_before.add_duration(REKEY_ATTEMPT_TIME);
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
    pub fn new() -> Self {
        Self {
            last_sent_at: AtomicInstant::from_std(Instant::now() - KEEPALIVE_TIMEOUT),
            tx_messages: AtomicU64::new(0),
            rx_messages: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn outbound(&self, bytes: usize) {
        let n = bytes as _;
        self.last_sent_at.set_now();
        self.tx_messages.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn inbound(&self, bytes: usize) {
        let n = bytes as _;
        self.rx_messages.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(n, Ordering::Relaxed);
    }
}

pub(super) struct PeerMonitor {
    handshake: HandshakeMonitor,
    traffic: TrafficMonitor,
}

impl PeerMonitor {
    pub fn new() -> Self {
        Self {
            handshake: HandshakeMonitor::new(),
            traffic: TrafficMonitor::new(),
        }
    }

    #[inline]
    pub fn can_keepalive(&self) -> bool {
        self.traffic.last_sent_at.elapsed() >= KEEPALIVE_TIMEOUT
    }

    #[inline]
    pub fn can_handshake(&self) -> bool {
        if self.traffic.tx_messages.load(Ordering::Relaxed) >= REKEY_AFTER_MESSAGES {
            return true;
        }

        if self.handshake.last_complete_at.elapsed() < REKEY_AFTER_TIME {
            // An active session exists
            return false;
        }

        if self
            .handshake
            .attempt_before
            .before(self.handshake.last_complete_at.to_std() + REKEY_AFTER_TIME)
        {
            self.handshake.reset_attempt();
        }

        self.handshake.last_attempt_at.elapsed() >= REKEY_TIMEOUT
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
            last_handshake_at: self.handshake.last_complete_ts.to_std(),
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
