use chrono::{DateTime, NaiveDateTime, Utc};

const BASE: u64 = 0x400000000000000a;
const WHITENER_MASK: u32 = 0x1000000 - 1;

#[derive(Debug)]
pub struct Timestamp([u8; 12]);

impl Timestamp {
    fn stamp(t: DateTime<Utc>) -> Self {
        let secs = BASE + t.timestamp() as u64;
        let nanos = t.timestamp_subsec_nanos() & !WHITENER_MASK;
        let b = {
            let mut dst = [0u8; 12];
            dst[..8].copy_from_slice(&secs.to_be_bytes());
            dst[8..].copy_from_slice(&nanos.to_be_bytes());
            dst
        };

        Self(b)
    }

    pub fn now() -> Self {
        Self::stamp(Utc::now())
    }

    pub fn to_string(&self) -> String {
        let secs = u64::from_be_bytes(self.0[..8].try_into().unwrap()) - BASE;
        let nanos = u32::from_be_bytes(self.0[8..].try_into().unwrap());
        NaiveDateTime::from_timestamp_opt(secs as _, nanos as _)
            .map(|d| DateTime::<Utc>::from_utc(d, Utc).to_rfc3339())
            .unwrap_or_else(|| "invalid timestamp".to_string())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; 12] {
        self.0
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
        self.0.partial_cmp(&other.0)
    }
}

impl Ord for Timestamp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Add;

    use chrono::{Duration, NaiveDateTime, Utc};

    use super::*;
    use crate::noise::crypto;

    #[test]
    fn test_timestamp() {
        let t0 = &NaiveDateTime::from_timestamp_opt(0, 123456789)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();

        let ts0 = Timestamp::stamp(*t0);
        assert_eq!(crypto::encode_to_hex(&ts0.0), "400000000000000a07000000");
        assert_eq!(ts0.to_string(), "1970-01-01T00:00:00.117440512+00:00");

        let ts1 = Timestamp::stamp(t0.add(Duration::nanoseconds(10)));
        assert!(ts0 >= ts1);

        let ts2 = Timestamp::stamp(t0.add(Duration::microseconds(10)));
        assert!(ts0 >= ts2);

        let ts3 = Timestamp::stamp(t0.add(Duration::milliseconds(1)));
        assert!(ts0 >= ts3);

        let ts4 = Timestamp::stamp(t0.add(Duration::milliseconds(10)));
        assert!(ts0 >= ts4);

        let ts5 = Timestamp::stamp(t0.add(Duration::milliseconds(20)));
        assert!(ts0 < ts5);
    }
}
