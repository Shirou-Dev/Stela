//! Naming the part of the host's service that held a processor too long.
//!
//! A PE that serves the host for seconds inside one exit ends the guest in
//! its watchdog's reset, and the periodic report then shows only the
//! longest time of each part. [`SlowParts`] decides when one part's time
//! is worth a line of its own, so that the line can carry where inside the
//! part the time went ([`Split`]) without a line for every slow turn.
use alloc::{format, string::String};
use core::sync::atomic::{AtomicU64, Ordering};

/// The longest time reported for each of `N` parts, in counter ticks.
pub struct SlowParts<const N: usize>([AtomicU64; N]);

impl<const N: usize> SlowParts<N> {
    pub const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; N])
    }

    /// Whether `part` taking `ticks` is reported: when it took `floor` or
    /// more and at least twice what was last reported for it. A part is so
    /// reported a few times a boot at most, each time for a clearly longer
    /// turn, and a call below `floor` costs one comparison. Of two
    /// processors with the same time one reports.
    pub fn worth(&self, part: usize, ticks: u64, floor: u64) -> bool {
        if ticks < floor {
            return false;
        }
        let slot = &self.0[part];
        let mut reported = slot.load(Ordering::Relaxed);
        loop {
            if reported != 0 && ticks < reported.saturating_mul(2) {
                return false;
            }
            match slot.compare_exchange_weak(reported, ticks, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(now) => reported = now,
            }
        }
    }
}

impl<const N: usize> Default for SlowParts<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Where one turn of a part went: the counter ticks of each of its `N`
/// named pieces, added up as the turn runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Split<const N: usize> {
    names: [&'static str; N],
    ticks: [u64; N],
}

impl<const N: usize> Split<N> {
    pub const fn new(names: [&'static str; N]) -> Self {
        Self {
            names,
            ticks: [0; N],
        }
    }

    /// Forget the last turn.
    pub const fn clear(&mut self) {
        self.ticks = [0; N];
    }

    /// `piece` ran from counter value `from` to `to`.
    pub const fn add(&mut self, piece: usize, from: u64, to: u64) {
        self.ticks[piece] = self.ticks[piece].saturating_add(to.wrapping_sub(from));
    }

    /// ` name=…` for each piece in microseconds of a counter of `hz`, then
    /// ` rest=…`: what of the turn's `total` ticks no piece covers.
    pub fn line(&self, total: u64, hz: u64) -> String {
        let micros = |ticks: u64| u128::from(ticks) * 1_000_000 / u128::from(hz.max(1));
        let mut line = String::new();
        let mut rest = total;
        for (name, &ticks) in self.names.iter().zip(&self.ticks) {
            line.push_str(&format!(" {name}={}", micros(ticks)));
            rest = rest.saturating_sub(ticks);
        }
        line.push_str(&format!(" rest={}", micros(rest)));
        line
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_part_below_the_floor_is_never_reported() {
        let slow = SlowParts::<2>::new();
        assert!(!slow.worth(0, 99, 100));
        assert!(!slow.worth(0, 0, 100));
        // And leaves the first slow turn its report.
        assert!(slow.worth(0, 100, 100));
    }

    #[test]
    fn a_slow_part_is_reported_once_until_one_takes_twice_as_long() {
        let slow = SlowParts::<2>::new();
        assert!(slow.worth(1, 130, 100));
        assert!(!slow.worth(1, 130, 100));
        assert!(!slow.worth(1, 259, 100));
        assert!(slow.worth(1, 260, 100));
        assert!(!slow.worth(1, 500, 100));
        // The seconds-long turn after many slow ones still gets its line.
        assert!(slow.worth(1, 5258, 100));
    }

    #[test]
    fn parts_are_reported_apart() {
        let slow = SlowParts::<2>::new();
        assert!(slow.worth(0, 1000, 100));
        assert!(slow.worth(1, 100, 100));
        assert!(!slow.worth(0, 1500, 100));
    }

    #[test]
    fn the_reports_of_a_part_are_few() {
        let slow = SlowParts::<1>::new();
        let reports = (100..100_000u64)
            .filter(|&ticks| slow.worth(0, ticks, 100))
            .count();
        assert_eq!(reports, 10);
    }

    #[test]
    fn a_split_names_each_piece_and_what_no_piece_covers() {
        let mut split = Split::new(["enter", "driver"]);
        split.add(0, 1000, 1010);
        split.add(1, 1010, 1510);
        split.add(0, 2000, 2020);
        // A counter of 1 MHz: ticks are microseconds.
        assert_eq!(
            split.line(5_000_000, 1_000_000),
            " enter=30 driver=500 rest=4999470"
        );
        split.clear();
        assert_eq!(split.line(7, 1_000_000), " enter=0 driver=0 rest=7");
    }

    #[test]
    fn a_split_survives_a_wrapping_counter_and_a_short_total() {
        let mut split = Split::new(["piece"]);
        split.add(0, u64::MAX - 1, 3);
        assert_eq!(split.line(2, 1_000_000), " piece=5 rest=0");
        assert_eq!(split.line(10, 0), " piece=5000000 rest=5000000");
    }
}
