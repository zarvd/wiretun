use std::time::SystemTime;

const BASE: u64 = 0x400000000000000a;
const WHITENER_MASK: u32 = 0x1000000 - 1;

#[derive(Debug)]
pub struct Timestamp([u8; 12]);

impl Timestamp {
    fn stamp(t: SystemTime) -> Self {
        let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap();

        let secs = BASE + d.as_secs();
        let nanos = d.subsec_nanos() & !WHITENER_MASK;
        let b = {
            let mut dst = [0u8; 12];
            dst[..8].copy_from_slice(&secs.to_be_bytes());
            dst[8..].copy_from_slice(&nanos.to_be_bytes());
            dst
        };

        Self(b)
    }

    #[inline(always)]
    pub fn now() -> Self {
        Self::stamp(SystemTime::now())
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 12]> for Timestamp {
    fn from(b: [u8; 12]) -> Self {
        Self(b)
    }
}

impl PartialEq<Self> for Timestamp {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Timestamp {}

impl PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Timestamp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::noise::crypto;

    #[test]
    fn test_timestamp() {
        let t0 = SystemTime::UNIX_EPOCH
            .checked_add(Duration::new(0, 123456789))
            .unwrap();

        let ts0 = Timestamp::stamp(t0);
        assert_eq!(crypto::encode_to_hex(&ts0.0), "400000000000000a07000000");

        let ts1 = Timestamp::stamp(t0.checked_add(Duration::from_nanos(10)).unwrap());
        assert!(ts0 >= ts1);

        let ts2 = Timestamp::stamp(t0.checked_add(Duration::from_micros(10)).unwrap());
        assert!(ts0 >= ts2);

        let ts3 = Timestamp::stamp(t0.checked_add(Duration::from_millis(1)).unwrap());
        assert!(ts0 >= ts3);

        let ts4 = Timestamp::stamp(t0.checked_add(Duration::from_millis(10)).unwrap());
        assert!(ts0 >= ts4);

        let ts5 = Timestamp::stamp(t0.checked_add(Duration::from_millis(20)).unwrap());
        assert!(ts0 < ts5);
    }
}
