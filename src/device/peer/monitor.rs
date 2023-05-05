use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use crate::device::time::{AtomicInstant, AtomicTimestamp};

const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

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
    last_recv_at: AtomicInstant,
    tx_messages: AtomicU64,
    rx_messages: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
}

impl TrafficMonitor {
    pub fn new() -> Self {
        Self {
            last_sent_at: AtomicInstant::from_std(Instant::now()),
            last_recv_at: AtomicInstant::from_std(Instant::now() - REKEY_TIMEOUT),
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

pub(super) struct KeepAliveMonitor {
    last_attempt_at: AtomicInstant,
    perisistent_keepalive_interval: Option<Duration>,
}

impl KeepAliveMonitor {
    pub fn new(persistent_keepalive_interval: Option<Duration>) -> Self {
        Self {
            last_attempt_at: AtomicInstant::now(),
            perisistent_keepalive_interval: persistent_keepalive_interval,
        }
    }

    #[inline]
    pub fn next_attempt_in(&self, traffic: &TrafficMonitor) -> Instant {
        if self.last_attempt_at.elapsed() >= KEEPALIVE_TIMEOUT
            && traffic.last_recv_at.to_std() > traffic.last_sent_at.to_std()
        {
            if traffic.last_recv_at.elapsed() > KEEPALIVE_TIMEOUT {
                return Instant::now();
            } else {
                return Instant::now() + KEEPALIVE_TIMEOUT - traffic.last_recv_at.elapsed();
            }
        }

        self.perisistent_keepalive_interval
            .map(|v| self.last_attempt_at.to_std() + v)
            .unwrap_or_else(|| Instant::now() + REKEY_AFTER_TIME)
    }

    #[inline]
    pub fn can(&self, traffic: &TrafficMonitor) -> bool {
        self.next_attempt_in(traffic) <= Instant::now()
    }

    #[inline]
    pub fn attempt(&self) {
        self.last_attempt_at.set_now();
    }
}

pub(super) struct PeerMonitor {
    handshake: HandshakeMonitor,
    traffic: TrafficMonitor,
    keepalive: KeepAliveMonitor,
}

impl PeerMonitor {
    pub fn new(persistent_keepalive_interval: Option<Duration>) -> Self {
        Self {
            handshake: HandshakeMonitor::new(),
            traffic: TrafficMonitor::new(),
            keepalive: KeepAliveMonitor::new(persistent_keepalive_interval),
        }
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
    pub fn keepalive(&self) -> &KeepAliveMonitor {
        &self.keepalive
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
