use std::ops::Add;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

pub(crate) struct AtomicTimestamp {
    secs: AtomicU64,
    nanos: AtomicU32,
}

impl AtomicTimestamp {
    #[inline(always)]
    pub fn zeroed() -> Self {
        Self {
            secs: AtomicU64::new(0),
            nanos: AtomicU32::new(0),
        }
    }

    #[inline(always)]
    pub fn from_std(t: SystemTime) -> Self {
        let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        Self {
            secs: AtomicU64::new(d.as_secs()),
            nanos: AtomicU32::new(d.subsec_nanos()),
        }
    }

    #[inline(always)]
    pub fn set_now(&self) {
        let now = SystemTime::UNIX_EPOCH.elapsed().expect("fetch system time");
        self.secs.store(now.as_secs(), Ordering::Relaxed);
        self.nanos.store(now.subsec_nanos(), Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn timestamp(&self) -> (u64, u32) {
        (
            self.secs.load(Ordering::Relaxed),
            self.nanos.load(Ordering::Relaxed),
        )
    }

    #[inline(always)]
    pub fn to_std(&self) -> SystemTime {
        let (secs, nanos) = self.timestamp();
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_nanos(nanos as _)
    }
}

impl From<AtomicTimestamp> for SystemTime {
    fn from(value: AtomicTimestamp) -> Self {
        value.to_std()
    }
}

impl From<SystemTime> for AtomicTimestamp {
    fn from(value: SystemTime) -> Self {
        Self::from_std(value)
    }
}

pub(crate) struct AtomicInstant {
    epoch: Instant,
    d: AtomicU64,
}

impl AtomicInstant {
    pub fn from_std(epoch: Instant) -> Self {
        Self {
            epoch,
            d: AtomicU64::new(0),
        }
    }

    #[inline(always)]
    pub fn now() -> Self {
        Self {
            epoch: Instant::now(),
            d: AtomicU64::new(0),
        }
    }

    #[inline(always)]
    pub fn set_now(&self) {
        self.d
            .store(self.epoch.elapsed().as_millis() as _, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn add_duration(&self, d: Duration) {
        let d = (self.epoch.elapsed() + d).as_millis();
        self.d.store(d as _, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn elapsed(&self) -> Duration {
        self.to_std().elapsed()
    }

    #[inline(always)]
    pub fn to_std(&self) -> Instant {
        self.epoch + Duration::from_millis(self.d.load(Ordering::Relaxed))
    }
}

impl From<AtomicInstant> for Instant {
    fn from(value: AtomicInstant) -> Self {
        value.to_std()
    }
}

impl From<Instant> for AtomicInstant {
    fn from(value: Instant) -> Self {
        Self::from_std(value)
    }
}

impl Add<Duration> for AtomicInstant {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        self.add_duration(rhs);
        self
    }
}

impl Eq for AtomicInstant {}

impl PartialEq<Self> for AtomicInstant {
    fn eq(&self, other: &Self) -> bool {
        self.to_std().eq(&other.to_std())
    }
}

impl PartialOrd<Self> for AtomicInstant {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.to_std().partial_cmp(&other.to_std())
    }
}

impl Ord for AtomicInstant {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_std().cmp(&other.to_std())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_timestamp() {
        let now = SystemTime::now();
        let ts = AtomicTimestamp::from_std(now);
        assert_eq!(ts.to_std(), now);
    }

    #[test]
    fn test_atomic_instant() {
        let now = Instant::now();
        let instant = AtomicInstant::from_std(now);
        assert_eq!(instant.to_std(), now);

        let now = now + Duration::from_secs(1);
        instant.add_duration(Duration::from_secs(1));
        assert_eq!(instant.to_std(), now);
        assert!(instant.to_std() >= now);
        assert!(instant.to_std() < now + Duration::from_secs(1));
        assert!(instant.to_std() > now - Duration::from_secs(1));
    }
}
