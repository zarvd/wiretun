use std::time::{Duration, Instant};

const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Timer {
    session_created_at: Instant,
    sent_messages: u64,
}

impl Timer {}
