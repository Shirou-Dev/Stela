//! The timer of a poll that may be put off: `stela-boot` looks at the host's
//! USB controllers on it from a service turn, which must not wait for the
//! host drivers' lock while another processor holds it. A poll that could
//! not run stays due, so the next turn takes it instead of this one waiting.

/// When the poll last ran for every party, on a counter that may wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollTimer {
    interval: u64,
    last: u64,
}

impl PollTimer {
    /// A timer of `interval` ticks whose first poll is due that long after
    /// `now`.
    pub const fn new(interval: u64, now: u64) -> Self {
        Self {
            interval,
            last: now,
        }
    }

    /// Whether the poll is due at `now`.
    pub const fn due(&self, now: u64) -> bool {
        now.wrapping_sub(self.last) >= self.interval
    }

    /// The poll that was due at `now` ended; `put_off` when a party could
    /// not be polled, which leaves it due for the next turn.
    pub const fn ended(&mut self, now: u64, put_off: bool) {
        if !put_off {
            self.last = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_poll_is_due_once_its_interval_has_passed() {
        let timer = PollTimer::new(100, 1000);
        assert!(!timer.due(1000));
        assert!(!timer.due(1099));
        assert!(timer.due(1100));
    }

    #[test]
    fn a_poll_that_ran_waits_for_the_next_interval() {
        let mut timer = PollTimer::new(100, 1000);
        timer.ended(1100, false);
        assert!(!timer.due(1199));
        assert!(timer.due(1200));
    }

    #[test]
    fn a_poll_put_off_stays_due_until_it_runs() {
        let mut timer = PollTimer::new(100, 1000);
        timer.ended(1100, true);
        assert!(timer.due(1101));
        timer.ended(1101, true);
        assert!(timer.due(1102));
        timer.ended(1102, false);
        assert!(!timer.due(1103));
        assert!(timer.due(1202));
    }

    #[test]
    fn the_counter_may_wrap() {
        let mut timer = PollTimer::new(100, u64::MAX - 10);
        assert!(!timer.due(u64::MAX));
        assert!(!timer.due(88));
        assert!(timer.due(89));
        timer.ended(89, false);
        assert!(!timer.due(188));
        assert!(timer.due(189));
    }
}
