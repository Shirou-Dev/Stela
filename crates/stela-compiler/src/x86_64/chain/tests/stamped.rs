//! Stamped tails against cell tails: for random ITLB, block table, cell and
//! control states, with pages put in, rekeyed and forgotten, cells changed
//! and relinked and contexts switched between runs, a stamped tail takes
//! the same transfer into the same block, or the same exit, as the cell
//! tail of its cell, and leaves the control the same, whatever stamps
//! earlier runs left. Then the same while another thread changes the cell.
use super::super::*;
use crate::GuestState;
use alloc::{boxed::Box, vec::Vec};
use core::ffi::c_void;
use core::sync::atomic::AtomicBool;
unsafe extern "C" {
    fn mmap(
        address: *mut c_void,
        bytes: usize,
        protection: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(address: *mut c_void, bytes: usize) -> i32;
}

const PAGE: usize = 4096;
const TAIL: usize = 16;
const PROBES: usize = 1024;
const REGION: usize = 2 * PAGE;
const BLOCKS: usize = 8;
const CONTEXTS: [u64; 3] = [
    5 << LOOKUP_SALT_BITS,
    9 << LOOKUP_SALT_BITS,
    13 << LOOKUP_SALT_BITS,
];
const KEYS: [u64; 2] = [block_key(0x8_0040_0000, 1), block_key(0x8_0040_0000, 2)];

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

struct Pages(*mut u8, usize);
// SAFETY: the mapping is only written before threads run it.
unsafe impl Send for Pages {}
// SAFETY: as above.
unsafe impl Sync for Pages {}
impl Drop for Pages {
    fn drop(&mut self) {
        // SAFETY: our mapping, nothing runs it any more.
        assert_eq!(unsafe { munmap(self.0.cast(), self.1) }, 0);
    }
}
fn pages(bytes: usize) -> Pages {
    // SAFETY: private anonymous memory, unmapped on drop.
    let base = unsafe { mmap(core::ptr::null_mut(), bytes, 7, 0x22, -1, 0) };
    assert_ne!(base as usize, usize::MAX);
    Pages(base.cast(), bytes)
}
fn put(pages: &Pages, offset: usize, bytes: &[u8]) {
    assert!(offset + bytes.len() <= pages.1);
    // SAFETY: inside the mapping; nothing runs it while it is written.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), pages.0.add(offset), bytes.len()) };
}

/// Blocks that return their marker in RAX and 99 in EDX.
fn blocks() -> Pages {
    let blocks = pages(PAGE);
    for block in 0..BLOCKS {
        let mut code = vec![0x48, 0xb8];
        code.extend((0x7700 + block as u64).to_le_bytes());
        code.extend([0xba, 99, 0, 0, 0, 0xc3]);
        put(&blocks, 64 * block, &code);
    }
    blocks
}

fn entry_of(blocks: &Pages, block: usize, pc: u64, key: u64) -> LookupEntry {
    LookupEntry {
        pc,
        key,
        entry: blocks.0 as u64 + 64 * block as u64,
        block: block as u32,
        targets: 0b1111,
    }
}

/// A region with `mov rax, rsi` and a tail at [`TAIL`], the BTYPE 0
/// probes at [`PROBES`].
fn region() -> Pages {
    let region = pages(REGION);
    put(&region, 0, &[0x48, 0x89, 0xf0, 0xe9]);
    put(&region, 4, &((TAIL - 8) as i32).to_le_bytes());
    put(&region, PROBES, &lookup_dispatcher(0).unwrap());
    region
}

fn run(region: &Pages, control: &mut ChainControl, target: u64) -> (u64, u64) {
    let mut frame = Box::new(GuestState::default());
    frame.anchors[Anchor::Control] = control as *mut ChainControl as u64;
    // SAFETY: the region holds the stub, a tail and probes with the block
    // ABI; they touch the frame's control, the tables and the blocks, which
    // outlive the call.
    let result = unsafe {
        let run: unsafe extern "sysv64" fn(*mut GuestState, u64) -> u128 =
            core::mem::transmute(region.0);
        run(&mut *frame, target)
    };
    (result as u64, (result >> 64) as u64)
}

/// The stamped tail (`Some`, when the cell held an entry at the link) or
/// the cell tail of `site`'s cell, in `region`.
fn tail(
    region: &Pages,
    table: &LookupTable,
    site: u64,
    pc: u64,
    linked: Option<LookupEntry>,
    ran: u32,
) {
    let number = table.site_cell_number(site).unwrap();
    let cell = LookupTable::cell_slot(&table.cells, number) as *const Slot as u64;
    let at = region.0 as u64 + TAIL as u64;
    let probe = region.0 as u64 + (PROBES + CELL_PROBE_ENTRY) as u64;
    let stamping = region.0 as u64 + (PROBES + STAMPING_PROBE_ENTRY) as u64;
    let kind = ExitWord::from(ExitKind::Direct);
    let code = match linked {
        Some(linked) => stamped_tail(
            at,
            cell,
            number,
            pc,
            kind,
            ran,
            linked.block,
            linked.entry,
            stamping,
        )
        .unwrap()
        .to_vec(),
        None => cell_tail(at, cell, kind, ran, probe).unwrap().to_vec(),
    };
    put(region, TAIL, &code);
}

/// Target PCs: two pages in each half.
fn pcs() -> [u64; 4] {
    [
        0x1_8000_0000,
        0x1_8000_1040,
        0xffff_fe00_1234_0010,
        0xffff_fe00_1235_0ff0,
    ]
}

#[test]
fn stamped_tails_transfer_as_their_cell_tails() {
    let pcs = pcs();
    let blocks = blocks();
    let (stamped, plain) = (region(), region());
    let mut table = LookupTable::with_entries(MIN_LOOKUP_ENTRIES);
    let mut itlb = LookupTable::itlb();
    let cells = table.stamped_cells();
    let stamps = table.new_stamps();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for (block, &pc) in pcs.iter().enumerate() {
        itlb.insert(
            itlb.page_slot(pc, CONTEXTS[half(pc)]),
            LookupEntry::page(pc & !0xfff, CONTEXTS[half(pc)], KEYS[0]),
        );
        table.insert(
            table.slot(pc, KEYS[0]),
            entry_of(&blocks, block, pc, KEYS[0]),
        );
    }
    // Each site: its target and the entry its cell held when it was linked.
    let mut sites: Vec<(u64, u64, Option<LookupEntry>)> = Vec::new();
    for (index, &pc) in pcs.iter().enumerate() {
        let site = 0x1000 + index as u64;
        let held = table.find(table.slot(pc, KEYS[0]), pc, KEYS[0]);
        table.link_cell(site, pc, Some(held));
        table.settle_heat(table.site_cell_number(site).unwrap());
        sites.push((site, pc, Some(held)));
    }
    let mut contexts = [CONTEXTS[0], CONTEXTS[1]];
    let mut keys = alloc::collections::BTreeMap::new();
    for &pc in &pcs {
        keys.insert((pc & !0xfff, CONTEXTS[half(pc)]), KEYS[0]);
    }
    let mut refilled = 0u32;
    let (mut hit, mut entered, mut exited) = (0u32, 0u32, 0u32);
    for trial in 0..200_000u32 {
        match rng.below(12) {
            0..=1 => {
                // A fill, of the key the page last had in the context, or
                // after a TLBI of the page a new one, as page tables change.
                let pc = pcs[rng.below(4) as usize];
                let context = CONTEXTS[rng.below(3) as usize];
                let page = pc & !0xfff;
                let held = keys.entry((page, context)).or_insert(KEYS[0]);
                if rng.below(3) == 0 {
                    itlb.forget_range_where(page..=page, |entry| entry.key == context);
                    *held = KEYS[usize::from(rng.below(2) == 0)];
                }
                itlb.insert(
                    itlb.page_slot(pc, context),
                    LookupEntry::page(page, context, *held),
                );
            }
            2 => {
                let pc = pcs[rng.below(4) as usize] & !0xfff;
                itlb.forget_range_where(pc..=pc, |_| rng.below(2) == 0);
            }
            3 => {
                let pc = pcs[rng.below(4) as usize];
                let key = KEYS[usize::from(rng.below(3) == 0)];
                let entry = entry_of(&blocks, rng.below(BLOCKS as u64) as usize, pc, key);
                table.insert(table.slot(pc, key), entry);
            }
            4 => {
                let frame = key_frame(KEYS[rng.below(2) as usize]);
                table.forget_frames(frame..=frame, |_| rng.below(3) == 0);
            }
            5 => {
                // A relink, with what the table holds now if anything.
                let index = rng.below(sites.len() as u64) as usize;
                let pc = pcs[rng.below(4) as usize];
                let key = KEYS[rng.below(2) as usize];
                let held = table.find(table.slot(pc, key), pc, key);
                let current = (held.pc == pc && held.key == key).then_some(held);
                table.link_cell(sites[index].0, pc, current);
                table.settle_heat(table.site_cell_number(sites[index].0).unwrap());
                sites[index] = (sites[index].0, pc, current);
            }
            6 => {
                // A context switch in one half.
                let at = rng.below(2) as usize;
                contexts[at] = CONTEXTS[rng.below(3) as usize];
            }
            7 if rng.below(40) == 0 => itlb.clear(),
            _ => {}
        }
        let (site, pc, linked) = sites[rng.below(sites.len() as u64) as usize];
        // A direct exit's target is its site's.
        let target = pc;
        let ran = 1 + rng.below(9) as u32;
        tail(&stamped, &table, site, pc, linked, ran);
        tail(&plain, &table, site, pc, None, ran);
        let base = ChainControl {
            budget: [0, 1, 2, 5, 9][rng.below(5) as usize],
            retired: 100,
            block: 7,
            contexts,
            table: table.address(),
            hits: 3,
            interrupt_epoch: u64::from(rng.below(12) == 0),
            itlb: itlb.address(),
            masks: [table.mask(), itlb.mask()],
            salts: contexts.map(|context| itlb.salt(context)),
            stamps,
            cells,
            ..ChainControl::default()
        };
        let number = table.site_cell_number(site).unwrap() as usize;
        let heat = table.cell_heat(number as u32);
        let stamped_first = rng.below(2) == 0;
        let (mut a, mut b) = (base, base);
        let (ra, rb) = if stamped_first {
            let ra = run(&stamped, &mut a, target);
            (ra, run(&plain, &mut b, target))
        } else {
            let rb = run(&plain, &mut b, target);
            (run(&stamped, &mut a, target), rb)
        };
        if stamped_first && table.cell_heat(number as u32) == heat {
            hit += 1;
        }
        // The one difference allowed: the cell probe missed a page this
        // ITLB put out for another (a capacity eviction, not a drop), and
        // the stamped tail entered the cell's block while the page tables
        // still map the page to the cell's key, as a refill would find.
        let context = contexts[half(pc)];
        let page = pc & !0xfff;
        let resident = itlb.find(itlb.page_slot(pc, context), page, context);
        let cell = table.site_cell(site).unwrap();
        let exit = (
            pc,
            u64::from(ExitWord::from(ExitKind::Direct).encoded() | ran << ExitWord::RAN_SHIFT),
        );
        let evicted = !(resident.pc == page && resident.key == context)
            && keys.get(&(page, context)) == Some(&cell.key)
            && rb == exit
            && linked.is_some_and(|linked| linked.entry == cell.entry)
            && (ra == (0x7700 + u64::from(cell.block), 99)
                // Or no budget: the stamped tail spent it, as a transfer.
                || (ra == exit && base.budget == 0 && a.budget == u64::MAX));
        if evicted {
            refilled += 1;
            continue;
        }
        assert_eq!(
            ra, rb,
            "trial {trial}: target {target:#x} linked {linked:?}"
        );
        assert_eq!(a, b, "trial {trial}: the controls differ");
        if ra.1 == 99 {
            entered += 1;
        } else {
            exited += 1;
        }
    }
    assert!(
        hit > 10_000 && entered > 10_000 && exited > 10_000,
        "{hit} {entered} {exited} {refilled}"
    );
}

/// A stamped tail's stamp, its drops and its promotion.
#[test]
fn stamps_go_with_drops_contexts_and_cell_changes() {
    let pc = 0xffff_fe00_1234_0010_u64;
    let blocks = blocks();
    let region = region();
    let mut table = LookupTable::with_entries(MIN_LOOKUP_ENTRIES);
    let mut itlb = LookupTable::itlb();
    let cells = table.stamped_cells();
    let stamps = table.new_stamps();
    let context = CONTEXTS[1];
    itlb.insert(
        itlb.page_slot(pc, context),
        LookupEntry::page(pc & !0xfff, context, KEYS[0]),
    );
    let held = entry_of(&blocks, 3, pc, KEYS[0]);
    table.insert(table.slot(pc, KEYS[0]), held);
    table.link_cell(0x1000, pc, Some(held));
    let number = table.site_cell_number(0x1000).unwrap();
    table.settle_heat(number);
    tail(&region, &table, 0x1000, pc, Some(held), 4);
    let mut control = ChainControl {
        budget: 100,
        contexts: [CONTEXTS[0], context],
        table: table.address(),
        itlb: itlb.address(),
        masks: [table.mask(), itlb.mask()],
        salts: [CONTEXTS[0], context].map(|context| itlb.salt(context)),
        stamps,
        cells,
        ..ChainControl::default()
    };
    let heat = |table: &LookupTable| table.cell_heat(number);
    // SAFETY: the table's stamps, which live.
    let counts = || unsafe { stamp_counts(stamps) };
    let count = |was: [u64; STAMP_COUNTS], count: StampCount| {
        counts()[count as usize] - was[count as usize]
    };
    // A transfer into a block was a stamp's hit or a counted miss that
    // went through the cell probe, which counts its heat.
    let through = |control: &mut ChainControl, table: &LookupTable| {
        let (before, was) = (heat(table), counts());
        let result = run(&region, control, pc);
        let probed = heat(table) != before;
        if result.1 == 99 {
            let missed = count(was, StampCount::Epoch)
                + count(was, StampCount::Context)
                + count(was, StampCount::Interrupted);
            assert_eq!(count(was, StampCount::Hits), u64::from(!probed));
            assert_eq!(missed, u64::from(probed));
        }
        (result, probed)
    };
    // The first transfer goes through the cell probe and stamps; the next
    // hits the stamp.
    assert_eq!(through(&mut control, &table), ((0x7703, 99), true));
    assert_eq!(through(&mut control, &table), ((0x7703, 99), false));
    assert_eq!((control.budget, control.retired, control.block), (98, 8, 3));
    assert_eq!(counts(), [1, 1, 0, 0, 1, 0, 0]);
    // A drop in the half: the probe again, which stamps again.
    itlb.forget_range_where(0..=0, |_| true);
    assert_eq!(through(&mut control, &table), ((0x7703, 99), false));
    itlb.insert(
        itlb.page_slot(pc + 0x1000, context),
        LookupEntry::page((pc + 0x1000) & !0xfff, context, KEYS[0]),
    );
    let next = (pc + 0x1000) & !0xfff;
    itlb.forget_range_where(next..=next, |_| true);
    assert_eq!(through(&mut control, &table), ((0x7703, 99), true));
    assert_eq!(through(&mut control, &table), ((0x7703, 99), false));
    // The page rekeyed: the probe finds no cell entry of the new key and
    // the table none either, so the exit returns.
    itlb.insert(
        itlb.page_slot(pc, context),
        LookupEntry::page(pc & !0xfff, context, KEYS[1]),
    );
    let word = u64::from(ExitWord::from(ExitKind::Direct).encoded() | 4 << ExitWord::RAN_SHIFT);
    assert_eq!(through(&mut control, &table), ((pc, word), false));
    itlb.insert(
        itlb.page_slot(pc, context),
        LookupEntry::page(pc & !0xfff, context, KEYS[0]),
    );
    assert_eq!(through(&mut control, &table), ((0x7703, 99), true));
    assert_eq!(through(&mut control, &table), ((0x7703, 99), false));
    // Another context, where the page has no entry: the probe's exit, and
    // no stamp; back: the stamp of the first still holds.
    control.contexts[1] = CONTEXTS[2];
    control.salts[1] = itlb.salt(CONTEXTS[2]);
    let was = counts();
    assert_eq!(through(&mut control, &table), ((pc, word), false));
    assert_eq!(count(was, StampCount::Context), 1);
    control.contexts[1] = context;
    control.salts[1] = itlb.salt(context);
    assert_eq!(through(&mut control, &table), ((0x7703, 99), false));
    // The cell takes another block of the PC: never the linked one again,
    // and no stamp while the cell differs from the link.
    table.insert(table.slot(pc, KEYS[0]), entry_of(&blocks, 5, pc, KEYS[0]));
    let was = counts();
    assert_eq!(through(&mut control, &table), ((0x7705, 99), true));
    assert_eq!(through(&mut control, &table), ((0x7705, 99), true));
    assert_eq!(count(was, StampCount::Changed), 2);
    assert_eq!(count(was, StampCount::Restamped), 0);
    // No budget on the stamp's path: the exit, the budget wrapped. The
    // table taking the entry the cell holds again changes nothing, so the
    // stamp holds.
    table.link_cell(0x1000, pc, Some(held));
    table.insert(table.slot(pc, KEYS[0]), held);
    let number = table.site_cell_number(0x1000).unwrap();
    table.settle_heat(number);
    tail(&region, &table, 0x1000, pc, Some(held), 4);
    let was = counts();
    assert_eq!(run(&region, &mut control, pc), (0x7703, 99));
    table.insert(table.slot(pc, KEYS[0]), held);
    assert_eq!(run(&region, &mut control, pc), (0x7703, 99));
    assert_eq!(count(was, StampCount::Restamped), 1);
    assert_eq!(count(was, StampCount::Hits), 1);
    control.budget = 0;
    assert_eq!(run(&region, &mut control, pc), (pc, word));
    assert_eq!(control.budget, u64::MAX);
    // A pending interruption: the probe's exit, nothing spent.
    control.budget = 10;
    control.interrupt_epoch = 1;
    let was = counts();
    assert_eq!(run(&region, &mut control, pc), (pc, word));
    assert_eq!(count(was, StampCount::Interrupted), 1);
    assert_eq!(control.budget, 10);
    control.interrupt_epoch = 0;
    // A cell made hot: its exit's link comes back from the sweep once.
    table.link_cell(0x1000, pc, Some(held));
    let number = table.site_cell_number(0x1000).unwrap();
    tail(&region, &table, 0x1000, pc, None, 4);
    control.budget = 1000;
    let link = CellLink {
        site: 0x1000,
        pc,
        retired: 4,
        word: ExitKind::Direct.into(),
        btype: 0,
    };
    table.note_link(number, link);
    for _ in 1..HOT_CELL {
        assert_eq!(run(&region, &mut control, pc), (0x7703, 99));
    }
    assert!(table.hot_links(0..STAMPED_CELLS as u32).is_empty());
    assert_eq!(run(&region, &mut control, pc), (0x7703, 99));
    assert_eq!(table.hot_links(0..STAMPED_CELLS as u32), [link]);
    table.settle_heat(number);
    assert!(table.hot_links(0..STAMPED_CELLS as u32).is_empty());
}

/// While another thread retires and relinks the cell's block, a thread
/// running the stamped tail never enters a block after the change it has
/// seen: the cell's `live` word and the stamps go before the change ends.
#[test]
fn a_cell_changed_on_another_core_ends_its_stamps_there() {
    let pc = 0x1_8000_0040_u64;
    let blocks = blocks();
    let region = region();
    let mut table = LookupTable::with_entries(MIN_LOOKUP_ENTRIES);
    let mut itlb = LookupTable::itlb();
    let cells = table.stamped_cells();
    let stamps = table.new_stamps();
    let context = CONTEXTS[0];
    itlb.insert(
        itlb.page_slot(pc, context),
        LookupEntry::page(pc & !0xfff, context, KEYS[0]),
    );
    let held = entry_of(&blocks, 1, pc, KEYS[0]);
    table.insert(table.slot(pc, KEYS[0]), held);
    table.link_cell(0x1000, pc, Some(held));
    table.settle_heat(table.site_cell_number(0x1000).unwrap());
    tail(&region, &table, 0x1000, pc, Some(held), 2);
    let (address, mask) = (table.address(), table.mask());
    let changed = AtomicBool::new(false);
    let done = AtomicBool::new(false);
    let finished = AtomicBool::new(false);
    let table = std::sync::Mutex::new(table);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for round in 0..2000u32 {
                if finished.load(Ordering::SeqCst) {
                    break;
                }
                let mut guard = table.lock().unwrap();
                // Retire block 1: the table and cell take block 2.
                let slot = guard.slot(pc, KEYS[0]);
                guard.insert(slot, entry_of(&blocks, 2, pc, KEYS[0]));
                changed.store(true, Ordering::SeqCst);
                drop(guard);
                while changed.load(Ordering::SeqCst) && !finished.load(Ordering::SeqCst) {
                    std::hint::spin_loop();
                }
                let mut guard = table.lock().unwrap();
                // Back to block 1, relinked as a new link would be.
                guard.insert(slot, held);
                guard.link_cell(0x1000, pc, Some(held));
                let number = guard.site_cell_number(0x1000).unwrap();
                guard.settle_heat(number);
                let _ = round;
            }
            done.store(true, Ordering::SeqCst);
        });
        let mut control = ChainControl {
            budget: u64::MAX / 2,
            contexts: [context, CONTEXTS[1]],
            table: address,
            itlb: itlb.address(),
            masks: [mask, itlb.mask()],
            salts: [context, CONTEXTS[1]].map(|context| itlb.salt(context)),
            stamps,
            cells,
            ..ChainControl::default()
        };
        // The writer stops waiting once this thread leaves, a failed
        // assertion included.
        struct Leaving<'a>(&'a AtomicBool);
        impl Drop for Leaving<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let _leaving = Leaving(&finished);
        let mut after = 0u32;
        while !done.load(Ordering::SeqCst) {
            // Relinks give a new cell number: the stamped tail follows.
            {
                let table = table.lock().unwrap();
                tail(&region, &table, 0x1000, pc, Some(held), 2);
            }
            let seen = changed.load(Ordering::SeqCst);
            let result = run(&region, &mut control, pc);
            if seen {
                assert_eq!(result, (0x7702, 99), "a stale stamp entered block 1");
                after += 1;
                changed.store(false, Ordering::SeqCst);
            } else {
                assert!(result == (0x7701, 99) || result == (0x7702, 99));
            }
        }
        assert!(after > 100, "{after}");
    });
}

/// Every stamped cell's tail fits, whatever its number's displacement, the
/// instructions it ran and how far its block is.
#[test]
fn stamped_tails_fit_for_every_cell_number() {
    let max_ran = (1 << (u32::BITS - ExitWord::RAN_SHIFT)) - 1;
    for number in [0, 1, 7, 8, 255, 4096, STAMPED_CELLS as u32 - 1] {
        for (ran, entry) in [(1, 0x1_0400), (max_ran, 0x7000_0000)] {
            let tail = stamped_tail(
                0x1_0000,
                0x2_0000,
                number,
                0x3000,
                ExitKind::Direct,
                ran,
                7,
                entry,
                0x1_0800,
            );
            assert!(tail.is_some(), "cell {number} ran {ran}");
        }
    }
}
