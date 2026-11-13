//! Where to take pages by address when the firmware refuses a request its
//! own memory map can hold. Some firmware searches only part of its free
//! memory for an allocation at any address (older AMI cores stay below
//! 4 GiB), so a large request fails with most of the RAM free. GRUB and the
//! Linux EFI stub meet this the same way: they read the map and name the
//! address themselves.
use alloc::vec::Vec;

const PAGE: u64 = 4096;

/// Addresses tried before the firmware's refusal stands.
pub const ATTEMPTS: usize = 8;

/// The bases to ask for, highest first: the top `count` pages of each run of
/// free memory that holds them. `free` lists free ranges as `(start, pages)`
/// in any order; touching ranges count as one run. At most [`ATTEMPTS`].
pub fn placements(free: &[(u64, u64)], count: u64) -> Vec<u64> {
    let mut ranges: Vec<(u64, u64)> = free
        .iter()
        .filter_map(|&(start, pages)| {
            let end = start.checked_add(pages.checked_mul(PAGE)?)?;
            (pages != 0 && start.is_multiple_of(PAGE)).then_some((start, end))
        })
        .collect();
    ranges.sort_unstable();
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for (start, end) in ranges {
        match runs.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => runs.push((start, end)),
        }
    }
    let Some(bytes) = count.checked_mul(PAGE).filter(|&bytes| bytes != 0) else {
        return Vec::new();
    };
    runs.iter()
        .rev()
        .filter(|&&(start, end)| end - start >= bytes)
        .map(|&(_, end)| end - bytes)
        .take(ATTEMPTS)
        .collect()
}

/// The largest runs of free memory in pages, largest first, for the report
/// of a refusal that stands.
pub fn largest(free: &[(u64, u64)], runs: usize) -> Vec<u64> {
    let mut sizes: Vec<u64> = Vec::new();
    let mut ranges: Vec<(u64, u64)> = free
        .iter()
        .filter_map(|&(start, pages)| Some((start, start.checked_add(pages.checked_mul(PAGE)?)?)))
        .collect();
    ranges.sort_unstable();
    let mut current: Option<(u64, u64)> = None;
    for (start, end) in ranges {
        match &mut current {
            Some(run) if start <= run.1 => run.1 = run.1.max(end),
            _ => {
                sizes.extend(current.map(|(start, end)| (end - start) / PAGE));
                current = Some((start, end));
            }
        }
    }
    sizes.extend(current.map(|(start, end)| (end - start) / PAGE));
    sizes.sort_unstable_by(|a, b| b.cmp(a));
    sizes.truncate(runs);
    sizes
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    /// The Haswell board of issue 44: little left below 4 GiB, one large run
    /// above it. The request is placed at the top of the high run.
    #[test]
    fn a_request_is_placed_at_the_top_of_the_highest_run_that_holds_it() {
        let free = [
            (0x10_0000, 0x4_0000),
            (4 * GIB, 12 * GIB / PAGE),
            (0x8000_0000, 0x2_0000),
        ];
        let count = 2688 * 1024 * 1024 / PAGE;
        assert_eq!(placements(&free, count), [16 * GIB - count * PAGE]);
        assert_eq!(
            placements(&free, 0x1_0000),
            [
                16 * GIB - 0x1_0000 * PAGE,
                0x8000_0000 + 0x1_0000 * PAGE,
                0x10_0000 + 0x3_0000 * PAGE
            ]
        );
    }

    #[test]
    fn touching_ranges_hold_a_request_together() {
        let free = [(0x20_0000, 0x100), (0x10_0000, 0x100)];
        assert_eq!(placements(&free, 0x200), [0x10_0000]);
        assert!(placements(&free, 0x201).is_empty());
        assert_eq!(largest(&free, 3), [0x200]);
    }

    #[test]
    fn nothing_is_placed_for_an_empty_or_overflowing_request() {
        let free = [(0x10_0000, 0x100), (!0xfff, 0x100)];
        assert!(placements(&free, 0).is_empty());
        assert!(placements(&free, u64::MAX).is_empty());
        assert_eq!(placements(&free, 0x100), [0x10_0000]);
    }

    #[test]
    fn the_largest_runs_come_first() {
        let free = [(0x10_0000, 1), (0x40_0000, 9), (0x80_0000, 4)];
        assert_eq!(largest(&free, 2), [9, 4]);
    }
}
