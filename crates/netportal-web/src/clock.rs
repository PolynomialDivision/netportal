//! The portal's wall clock: the session limits (8 h idle, 12 h after the login) and the
//! telemetry's "now" read it. Production uses the system clock; the crate's tests move a
//! [`TestClock`] forward to test the limits (the black-box suite cannot age a cookie).

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use time::OffsetDateTime;

/// What every request asks for the time.
pub type Clock = Arc<dyn Fn() -> OffsetDateTime + Send + Sync>;

/// The system clock.
pub fn system() -> Clock {
    Arc::new(OffsetDateTime::now_utc)
}

/// The system clock shifted by a settable number of seconds (tests).
#[derive(Clone, Default)]
pub struct TestClock {
    offset_s: Arc<AtomicI64>,
}

impl TestClock {
    pub fn new() -> TestClock {
        TestClock::default()
    }

    /// Move the clock forward (or back, negative) by `seconds`.
    pub fn advance(&self, seconds: i64) {
        self.offset_s.fetch_add(seconds, Ordering::SeqCst);
    }

    pub fn clock(&self) -> Clock {
        let offset = self.offset_s.clone();
        Arc::new(move || OffsetDateTime::now_utc() + time::Duration::seconds(offset.load(Ordering::SeqCst)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_moves() {
        let test = TestClock::new();
        let clock = test.clock();
        let before = clock();
        test.advance(3600);
        let after = clock();
        assert!((after - before).whole_seconds() >= 3600);
    }
}
