//! The rules of the host's page window: the rest of the first 512 GiB of the
//! engine's window, past its image, stacks and MMIO aperture, inside the same
//! top-level entry and so in every root the engine builds. Scattered pages get
//! a contiguous CPU view there in the cache attribute their use needs, which the
//! aperture's uncached leaves cannot give: `vmap`, a GPU's write-combined BAR1,
//! and the buffers NVK maps.
//!
//! Pure functions over addresses and leaf values, and the allocator of the
//! window's pages.
use alloc::{collections::BTreeMap, vec::Vec};
use core::ops::Range;

pub use stela_contracts::bytes::HOST_PAGE_BYTES as PAGE;
/// Bytes one paging-structure entry's level covers, from the leaf up.
const DIRECTORY_BYTES: u64 = PAGE << 9;
const DIRECTORY_POINTER_BYTES: u64 = DIRECTORY_BYTES << 9;
const ENTRIES: u64 = 512;
/// The window's offset in the engine's: past `layout`'s fixed parts.
const OFFSET: u64 = 0x10_0000_0000;

const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const WRITE_THROUGH: u64 = 1 << 3;
const CACHE_DISABLE: u64 = 1 << 4;
/// PAT's selector bit in a 4 KiB leaf.
const PAT: u64 = 1 << 7;
const ACCESSED_DIRTY: u64 = 0x60;
const NO_EXECUTE: u64 = 1 << 63;

/// The IA32_PAT encoding of write-combining (Intel SDM Vol. 3A 12.12.2, AMD
/// APM Vol. 2 7.8.1 give the same table).
const WRITE_COMBINING: u64 = 1;
/// The PAT entry the window's write-combining leaves select. Nothing maps
/// through it at reset, as its entry mirrors one the lower four already offer.
pub const WRITE_COMBINING_INDEX: u32 = 5;

/// `pat` with [`WRITE_COMBINING_INDEX`] made write-combining. Every other
/// entry stays as firmware left it, so no existing mapping changes type.
pub fn with_write_combining(pat: u64) -> u64 {
    let shift = 8 * WRITE_COMBINING_INDEX;
    pat & !(0xff << shift) | WRITE_COMBINING << shift
}

/// How a window page is cached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cache {
    WriteBack,
    WriteCombining,
    Uncached,
}

/// The leaf that maps `physical`, writable and never executable.
pub fn leaf(physical: u64, cache: Cache) -> u64 {
    let attribute = match cache {
        Cache::WriteBack => 0,
        // PAT, PCD and PWT of 1, 0 and 1 select PAT entry 5.
        Cache::WriteCombining => PAT | WRITE_THROUGH,
        // Of 0, 1 and 1, entry 3, which firmware leaves uncached.
        Cache::Uncached => CACHE_DISABLE | WRITE_THROUGH,
    };
    physical | PRESENT | WRITABLE | NO_EXECUTE | ACCESSED_DIRTY | attribute
}

/// The leaf that maps `physical` write-back, writable and executable: generated
/// code, which its generator writes in place.
pub fn code_leaf(physical: u64) -> u64 {
    leaf(physical, Cache::WriteBack) & !NO_EXECUTE
}

/// What a mapping call returned, as Linux's `IS_ERR_VALUE` reads it: the
/// errno in the last page of the address space, or the mapping's address.
/// The window is in the upper half of the address space, so its addresses
/// are negative as an `i64` like an errno is.
pub fn mapped_address(result: i64) -> Result<u64, i64> {
    const MAX_ERRNO: i64 = 4095;
    if (-MAX_ERRNO..=0).contains(&result) {
        Err(result)
    } else {
        Ok(result as u64)
    }
}

/// Translate a Linux client protection into a leaf for the shared data window.
pub fn client_leaf(pfn: u64, prot: u64) -> Option<u64> {
    const MAX_PFN: u64 = (1 << (52 - 12)) - 1;
    if pfn > MAX_PFN || prot & (PRESENT | NO_EXECUTE) != PRESENT | NO_EXECUTE {
        return None;
    }
    let entry = leaf(pfn * PAGE, cache_of(prot));
    Some((entry & !WRITABLE) | (prot & WRITABLE))
}

/// The cache attribute of a page Linux's page protection `prot` asks for, in
/// the PWT and PCD bits its `pgprot_writecombine` and `pgprot_noncached` set.
pub fn cache_of(prot: u64) -> Cache {
    if prot & CACHE_DISABLE != 0 {
        Cache::Uncached
    } else if prot & WRITE_THROUGH != 0 {
        Cache::WriteCombining
    } else {
        Cache::WriteBack
    }
}

/// A window address's index in its directory-pointer, directory and page
/// tables.
pub fn indices(address: u64) -> [usize; 3] {
    [
        (address / DIRECTORY_POINTER_BYTES % ENTRIES) as usize,
        (address / DIRECTORY_BYTES % ENTRIES) as usize,
        (address / PAGE % ENTRIES) as usize,
    ]
}

/// Group the leaf slots of a validated page range by their parent table.
pub fn leaf_runs(address: u64, pages: usize) -> impl Iterator<Item = (usize, usize, Range<usize>)> {
    let mut offset = 0;
    core::iter::from_fn(move || {
        if offset == pages {
            return None;
        }
        let [pointer, directory, first] = indices(address + offset as u64 * PAGE);
        let count = (ENTRIES as usize - first).min(pages - offset);
        offset += count;
        Some((pointer, directory, first..first + count))
    })
}

/// The page window of the engine's window at `base`: the rest of the
/// directory-pointer table its fixed parts start.
pub fn span(base: u64) -> core::ops::Range<u64> {
    base + OFFSET..base + DIRECTORY_POINTER_BYTES * ENTRIES
}

/// The window's free pages, as runs by their first address. An unmapped run
/// comes back merged with its neighbours, so long-lived small mappings cannot
/// fragment the window into uselessness.
pub struct Free {
    runs: BTreeMap<u64, u64>,
}

impl Free {
    pub fn new(span: core::ops::Range<u64>) -> Self {
        let mut runs = BTreeMap::new();
        if span.end > span.start {
            runs.insert(span.start, (span.end - span.start) / PAGE);
        }
        Self { runs }
    }

    /// The first run of `pages` pages, lowest first so tables stay few.
    pub fn take(&mut self, pages: u64) -> Option<u64> {
        if pages == 0 {
            return None;
        }
        let (&start, &length) = self.runs.iter().find(|(_, length)| **length >= pages)?;
        self.runs.remove(&start);
        if length > pages {
            self.runs.insert(start + pages * PAGE, length - pages);
        }
        Some(start)
    }

    pub fn give(&mut self, start: u64, pages: u64) {
        let (mut start, mut pages) = (start, pages);
        if let Some((&before, &length)) = self.runs.range(..start).next_back()
            && before + length * PAGE == start
        {
            self.runs.remove(&before);
            start = before;
            pages += length;
        }
        if let Some(&length) = self.runs.get(&(start + pages * PAGE)) {
            self.runs.remove(&(start + pages * PAGE));
            pages += length;
        }
        self.runs.insert(start, pages);
    }
}

/// Window ranges whose old translations may still be held by a processor.
#[derive(Default)]
pub struct Retirements(Vec<Range<u64>>);

impl Retirements {
    pub fn overlaps(&self, range: &Range<u64>) -> bool {
        self.0
            .iter()
            .any(|active| range.start < active.end && active.start < range.end)
    }

    /// Keep a range reserved before clearing any of its entries.
    pub fn begin(&mut self, range: Range<u64>) -> bool {
        if range.is_empty() || self.overlaps(&range) || self.0.try_reserve(1).is_err() {
            return false;
        }
        self.0.push(range);
        true
    }

    /// Remove only an exact range after all required processors acknowledged.
    pub fn finish(&mut self, range: &Range<u64>) {
        let slot = self
            .0
            .iter()
            .position(|active| active == range)
            .expect("unowned window retirement");
        self.0.swap_remove(slot);
    }
}

/// Window ranges already unmapped on the processor that removed them, left
/// for one later shootdown to retire together, as Linux's lazy `vunmap`
/// purge does: a mapping's removal then costs no board-wide shootdown of its
/// own.
///
/// Invariant: no processor keeps a translation for an address the window
/// hands out again. A range enters [`Self::defer`] begun in [`Retirements`],
/// its entries cleared and flushed on the removing processor, so neither
/// [`Free::take`] nor an install reaches it. It returns to [`Free`] only
/// through [`finish_batch`], after a shootdown requested once it was taken
/// in a batch ([`Self::take`]) was acknowledged by every other processor.
/// A batch whose shootdown failed goes back ([`Self::restore`]) and stays
/// reserved until a later one succeeds.
#[derive(Default)]
pub struct Lazy {
    ranges: Vec<Range<u64>>,
    pages: u64,
}

impl Lazy {
    /// How many ranges, or pages, wait before a removal retires them.
    pub const RANGES: usize = 128;
    pub const PAGES: u64 = 2048;

    /// Leaves `range` for the next batch. Whether the batch is due, or the
    /// range back when it cannot be kept, to be retired at once.
    pub fn defer(&mut self, range: Range<u64>) -> Result<bool, Range<u64>> {
        if range.is_empty() || self.ranges.try_reserve(1).is_err() {
            return Err(range);
        }
        self.pages += (range.end - range.start).div_ceil(PAGE);
        self.ranges.push(range);
        Ok(self.ranges.len() >= Self::RANGES || self.pages >= Self::PAGES)
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// The waiting ranges, for one shootdown requested after this.
    pub fn take(&mut self) -> Vec<Range<u64>> {
        self.pages = 0;
        core::mem::take(&mut self.ranges)
    }

    /// A taken batch whose shootdown was not acknowledged: kept, reserved,
    /// for the next one.
    pub fn restore(&mut self, mut batch: Vec<Range<u64>>) {
        self.pages += batch
            .iter()
            .map(|range| (range.end - range.start).div_ceil(PAGE))
            .sum::<u64>();
        batch.append(&mut self.ranges);
        self.ranges = batch;
    }
}

/// After every other processor acknowledged the shootdown requested for
/// `batch`: its ranges are free again.
pub fn finish_batch(batch: &[Range<u64>], retiring: &mut Retirements, free: &mut Free) {
    for range in batch {
        retiring.finish(range);
        free.give(range.start, (range.end - range.start) / PAGE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mapping_in_the_upper_half_is_an_address_and_only_an_errno_is_an_error() {
        let upper = 0xffff_8010_0000_3000u64;
        assert_eq!(mapped_address(upper as i64), Ok(upper));
        assert_eq!(mapped_address(0x7000_0000), Ok(0x7000_0000));
        assert_eq!(mapped_address(-12), Err(-12));
        assert_eq!(mapped_address(-4095), Err(-4095));
        assert_eq!(mapped_address(-4096), Ok(-4096i64 as u64));
        assert_eq!(mapped_address(0), Err(0));
    }

    const GIB: u64 = 1 << 30;

    #[test]
    fn leaf_runs_cover_exactly_the_requested_slots_across_table_boundaries() {
        let address = GIB - 2 * PAGE;
        assert_eq!(
            leaf_runs(address, 516).collect::<Vec<_>>(),
            [(0, 511, 510..512), (1, 0, 0..512), (1, 1, 0..2)]
        );
        assert_eq!(leaf_runs(address, 0).next(), None);
        assert_eq!(
            leaf_runs(!(PAGE - 1), 1).collect::<Vec<_>>(),
            [(511, 511, 511..512)]
        );
    }

    #[test]
    fn retiring_ranges_remain_excluded_until_acknowledged() {
        let mut retiring = Retirements::default();
        assert!(retiring.begin(PAGE..4 * PAGE));
        assert!(retiring.overlaps(&(PAGE..2 * PAGE)));
        assert!(retiring.overlaps(&(3 * PAGE..5 * PAGE)));
        assert!(!retiring.overlaps(&(4 * PAGE..5 * PAGE)));
        assert!(!retiring.begin(2 * PAGE..3 * PAGE));
        assert!(retiring.begin(4 * PAGE..5 * PAGE));

        retiring.finish(&(PAGE..4 * PAGE));
        assert!(!retiring.overlaps(&(PAGE..4 * PAGE)));
        assert!(retiring.overlaps(&(4 * PAGE..5 * PAGE)));
        assert!(retiring.begin(PAGE..4 * PAGE));
    }

    /// A lazily removed range is handed out again only after its batch's
    /// shootdown was acknowledged; a failed one keeps it reserved.
    #[test]
    fn lazy_ranges_are_reused_only_after_their_batch_retires() {
        let span = 0x10000..0x10000 + 8 * PAGE;
        let mut free = Free::new(span.clone());
        let mut retiring = Retirements::default();
        let mut lazy = Lazy::default();
        let first = free.take(4).unwrap();
        let second = free.take(4).unwrap();
        assert_eq!(free.take(1), None);

        // Removal: reserve in `retiring`, clear, then defer.
        let range = first..first + 4 * PAGE;
        assert!(retiring.begin(range.clone()));
        assert_eq!(lazy.defer(range.clone()), Ok(false));
        assert!(!lazy.is_empty());
        // Not free, and no install may land in it.
        assert_eq!(free.take(1), None);
        assert!(retiring.overlaps(&(first..first + PAGE)));

        // A shootdown that was not acknowledged keeps it reserved.
        let batch = lazy.take();
        assert!(lazy.is_empty());
        lazy.restore(batch);
        assert_eq!(free.take(1), None);

        // A range deferred after a batch was taken waits for the next one.
        let batch = lazy.take();
        let later = second..second + 4 * PAGE;
        assert!(retiring.begin(later.clone()));
        assert_eq!(lazy.defer(later.clone()), Ok(false));
        finish_batch(&batch, &mut retiring, &mut free);
        assert_eq!(free.take(4), Some(first));
        assert_eq!(free.take(1), None);
        assert!(retiring.overlaps(&later));
        assert!(!retiring.overlaps(&range));

        finish_batch(&lazy.take(), &mut retiring, &mut free);
        assert_eq!(free.take(4), Some(second));
    }

    #[test]
    fn lazy_batches_fall_due_at_their_bounds() {
        let mut lazy = Lazy::default();
        for index in 0..Lazy::RANGES as u64 - 1 {
            assert_eq!(
                lazy.defer(index * 2 * PAGE..(index * 2 + 1) * PAGE),
                Ok(false)
            );
        }
        assert_eq!(lazy.defer(0x100_0000..0x100_1000), Ok(true));
        assert_eq!(lazy.take().len(), Lazy::RANGES);
        assert_eq!(lazy.defer(0..Lazy::PAGES * PAGE), Ok(true));
        assert_eq!(lazy.defer(PAGE..PAGE), Err(PAGE..PAGE));
    }

    #[test]
    fn only_the_write_combining_entry_changes() {
        // The reset value: WB, WT, UC-, UC twice over.
        let reset = 0x0007_0406_0007_0406;
        assert_eq!(with_write_combining(reset), 0x0007_0106_0007_0406);
        assert_eq!(
            with_write_combining(with_write_combining(reset)),
            0x0007_0106_0007_0406
        );
    }

    #[test]
    fn leaves_select_their_pat_entry() {
        let index = |leaf: u64| (leaf >> 3 & 1) | (leaf >> 4 & 1) << 1 | (leaf >> 7 & 1) << 2;
        assert_eq!(index(leaf(0x1000, Cache::WriteBack)), 0);
        assert_eq!(index(leaf(0x1000, Cache::Uncached)), 3);
        assert_eq!(
            index(leaf(0x1000, Cache::WriteCombining)),
            u64::from(WRITE_COMBINING_INDEX)
        );
        let value = leaf(0x7000, Cache::WriteBack);
        assert_eq!(value & 0x000f_ffff_ffff_f000, 0x7000);
        assert_eq!(
            value & (PRESENT | WRITABLE | NO_EXECUTE),
            PRESENT | WRITABLE | NO_EXECUTE
        );
    }

    #[test]
    fn client_leaves_preserve_data_protection() {
        let read_only = PRESENT | NO_EXECUTE;
        assert_eq!(
            client_leaf(7, read_only),
            Some(leaf(0x7000, Cache::WriteBack) & !WRITABLE)
        );
        assert_eq!(
            client_leaf(7, read_only | WRITABLE | CACHE_DISABLE),
            Some(leaf(0x7000, Cache::Uncached))
        );
        assert_eq!(client_leaf(7, PRESENT), None);
        assert_eq!(client_leaf(7, NO_EXECUTE), None);
        assert_eq!(client_leaf(1 << (52 - 12), read_only), None);
    }

    #[test]
    fn only_code_leaves_run() {
        let code = code_leaf(0x7000);
        assert_eq!(code & NO_EXECUTE, 0);
        assert_eq!(code | NO_EXECUTE, leaf(0x7000, Cache::WriteBack));
    }

    #[test]
    fn linux_protections_choose_the_cache() {
        assert_eq!(cache_of(0), Cache::WriteBack);
        assert_eq!(cache_of(WRITE_THROUGH), Cache::WriteCombining);
        assert_eq!(cache_of(CACHE_DISABLE), Cache::Uncached);
        assert_eq!(cache_of(CACHE_DISABLE | WRITE_THROUGH), Cache::Uncached);
    }

    #[test]
    fn the_window_fills_the_rest_of_its_table() {
        let window = span(0xffff_8000_0000_0000);
        assert_eq!(window.start, 0xffff_8000_0000_0000 + 64 * GIB);
        assert_eq!(window.end, 0xffff_8080_0000_0000);
        assert_eq!(indices(window.start)[0], 64);
        assert_eq!(
            indices(window.start + (GIB + 2 * (1 << 21) + 5 * PAGE)),
            [65, 2, 5]
        );
    }

    #[test]
    fn runs_split_and_merge() {
        let mut free = Free::new(0x10000..0x18000);
        assert_eq!(free.take(0), None);
        assert_eq!(free.take(9), None);
        let first = free.take(2).unwrap();
        let second = free.take(2).unwrap();
        let third = free.take(2).unwrap();
        assert_eq!([first, second, third], [0x10000, 0x12000, 0x14000]);
        // The hole is too small until its neighbour joins it.
        free.give(second, 2);
        assert_eq!(free.take(3), None);
        free.give(first, 2);
        assert_eq!(free.take(4), Some(0x10000));
        free.give(0x10000, 4);
        free.give(third, 2);
        assert_eq!(free.take(8), Some(0x10000));
    }
}
