use super::*;
use crate::translations::pack::Arena;
use crate::translations::translator_id;
use alloc::collections::BTreeSet;
use stela_formats::journal::Target;

/// Counter ticks per second, and the steps a second of a boot gives.
const HZ: u64 = 1000;
const STEPS_PER_SECOND: u64 = 10;

/// A pack file in memory whose writes may be cut after a number of bytes,
/// as a power loss cuts a disk's: the cut write lands only partly.
struct Disk {
    bytes: Vec<u8>,
    /// Bytes still written before the cut; `None` for no cut.
    left: Option<u64>,
    cut: bool,
    written: u64,
    /// Writes that fail before touching the disk, as a busy queue's do.
    fail_writes: u32,
    /// A commit slot was written since the last flush, and the page keys
    /// each commit left, once durable.
    slot: bool,
    contents: Vec<BTreeSet<Digest>>,
    /// Whether each commit's keys are kept in `contents`.
    track: bool,
}

impl Disk {
    fn new(size: u64) -> Self {
        Self {
            bytes: vec![0; size as usize],
            left: None,
            cut: false,
            written: 0,
            fail_writes: 0,
            slot: false,
            contents: Vec::new(),
            track: true,
        }
    }
}

impl Target for Disk {
    type Error = String;
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<bool, String> {
        if self.fail_writes != 0 {
            self.fail_writes -= 1;
            return Err(String::from("the queue was busy"));
        }
        let take = match self.left {
            Some(left) => (left as usize).min(bytes.len()),
            None => bytes.len(),
        };
        let at = offset as usize;
        self.bytes[at..at + take].copy_from_slice(&bytes[..take]);
        self.written += take as u64;
        self.slot |= offset < DATA_START;
        if let Some(left) = &mut self.left {
            *left -= take as u64;
            if take < bytes.len() {
                self.cut = true;
                return Err(String::from("cut"));
            }
        }
        Ok(true)
    }
    fn flush(&mut self) -> Result<bool, String> {
        if self.cut {
            return Err(String::from("cut"));
        }
        if core::mem::take(&mut self.slot) && self.track {
            let found = keys(&self.bytes);
            self.contents.push(found);
        }
        Ok(true)
    }
}

/// What a boot's store hands the writer: entries added, keys found. Like
/// the store, it keeps at most `bound` entries between takes and counts
/// those it refused, and those it shed. Its heap, when measured, holds
/// `heap_total` bytes, of which the rest of the boot takes `filler` and
/// the writer's segments `resident`.
struct Boot {
    added: BTreeMap<Digest, Record>,
    found: Vec<Digest>,
    next: u32,
    total: u64,
    bound: usize,
    unkept: u64,
    heap_total: u64,
    filler: u64,
    resident: u64,
    shedding: bool,
    shed: u64,
    /// The code bytes of each entry added: 0 for records of none.
    entry_bytes: usize,
}

impl Boot {
    /// A boot whose pages are numbered from `seed` millions, that found
    /// every record in `found`.
    fn new(seed: u32, found: Vec<Digest>) -> Self {
        Self {
            added: BTreeMap::new(),
            found,
            next: seed * 1_000_000,
            total: 0,
            bound: usize::MAX,
            unkept: 0,
            heap_total: 0,
            filler: 0,
            resident: 0,
            shedding: false,
            shed: 0,
            entry_bytes: 0,
        }
    }

    /// The heap's room the boot measures: what the rest, the writer's
    /// segments and the entries added leave.
    fn room(&self) -> u64 {
        let added = self.added.len() as u64 * (ENTRY_HEAP_BYTES + self.entry_bytes as u64);
        self.heap_total
            .saturating_sub(self.filler + self.resident + added)
    }

    /// Add `count` entries of new pages: the keys of those kept.
    fn add(&mut self, count: u32) -> Vec<Digest> {
        let mut kept = Vec::new();
        for _ in 0..count {
            self.next += 1;
            kept.extend(self.add_page(self.next));
        }
        kept
    }

    /// Add an entry of page `page`: its key, when kept.
    fn add_page(&mut self, page: u32) -> Option<Digest> {
        if self.shedding {
            self.shed += 1;
            return None;
        }
        if self.added.len() >= self.bound {
            self.unkept += 1;
            return None;
        }
        let key = page_key(page);
        let mut record = Record::new(translator_id(), key);
        if self.entry_bytes != 0 {
            record.insert(entry(0, page as u8, self.entry_bytes));
        }
        self.added.insert(key, record);
        self.total += 1;
        Some(key)
    }
}

impl Entries for Boot {
    fn take_added(&mut self) -> BTreeMap<Digest, Record> {
        core::mem::take(&mut self.added)
    }
    fn found_keys(&mut self) -> Vec<Digest> {
        self.found.clone()
    }
    fn added(&mut self) -> u64 {
        self.total
    }
    fn pressed(&mut self) -> bool {
        !self.added.is_empty() && self.added.len().saturating_mul(2) >= self.bound
    }
    fn heap(&mut self) -> Option<Heap> {
        (self.heap_total != 0).then(|| Heap {
            total: self.heap_total,
            room: self.room(),
        })
    }
    fn shed(&mut self, shed: bool) {
        self.shedding = shed;
    }
    fn added_bytes(&mut self) -> u64 {
        self.added
            .values()
            .map(|record| record.retained_bytes() as u64)
            .sum()
    }
}

/// The key of page `page`'s record.
fn page_key(page: u32) -> Digest {
    Digest::of(&page.to_le_bytes())
}

/// The heap bytes an added entry of [`Boot::add`] takes beside its code.
const ENTRY_HEAP_BYTES: u64 = 256;

/// An entry at page offset `offset` whose code is `bytes` bytes of `fill`.
fn entry(offset: u16, fill: u8, bytes: usize) -> crate::translations::Entry {
    crate::translations::Entry {
        context: Digest::of(b"context"),
        offset,
        source_bytes: 4,
        input: vec![0; 4],
        code: vec![fill; bytes],
        relocations: Vec::new(),
        // A merge decodes what two segments hold with every check.
        source_map: vec![(offset, 0)],
        exits: Vec::new(),
        recovery: Vec::new(),
    }
}

/// The pack file as a boot's loader reads it: the newest commit, whose
/// blobs must read back whole, and its segments and lists.
fn load(disk: &[u8], limit: u64) -> File<'static> {
    let translator = translator_id();
    let size = disk.len() as u64;
    let committed = journal::candidates(&disk[..DATA_START as usize], JOURNAL_DOMAIN, size)
        .into_iter()
        .next();
    let mut segments = Vec::new();
    let mut used = Vec::new();
    if let Some(commit) = &committed {
        let blobs = journal::read_entries(commit, |offset, into| {
            let at = offset as usize;
            into.copy_from_slice(disk.get(at..at + into.len())?);
            Some(())
        })
        .expect("the newest commit's blobs read back whole");
        for (kind, bytes) in blobs {
            let bytes: &'static [u8] = Vec::leak(bytes);
            match kind {
                SEGMENT_BLOB => segments.push(Pack::parse(bytes, &translator).unwrap()),
                USED_BLOB => used.push(UsedKeys::parse(bytes, &translator).unwrap()),
                _ => panic!("an unknown blob"),
            }
        }
    }
    File {
        translator,
        limit,
        file_bytes: size,
        committed,
        segments,
        used,
        partial: false,
        arena: Arena::default(),
    }
}

/// The page keys the file's newest commit holds.
fn keys(disk: &[u8]) -> BTreeSet<Digest> {
    load(disk, u64::MAX)
        .segments
        .iter()
        .flat_map(|pack| pack.iter().map(|(key, _)| key).collect::<Vec<_>>())
        .collect()
}

/// A writer's boot: its clock, the store and the disk.
struct Run<'a> {
    writer: Writer<'a>,
    boot: Boot,
    now: u64,
    events: Vec<Event>,
    /// The most heap bytes the writer's segments held after a step.
    resident_peak: u64,
}

impl<'a> Run<'a> {
    /// A boot over `file` whose pages are numbered from `seed` millions,
    /// that uses every record the file holds.
    fn new(file: File<'a>, seed: u32) -> Self {
        let found = file
            .segments
            .iter()
            .flat_map(|pack| pack.iter().map(|(key, _)| key).collect::<Vec<_>>())
            .collect();
        Self {
            writer: Writer::new(file, HZ),
            boot: Boot::new(seed, found),
            now: 0,
            events: Vec::new(),
            resident_peak: 0,
        }
    }

    /// Step for `seconds` of the guest's time.
    fn run(&mut self, disk: &mut Disk, seconds: u64) -> Result<(), String> {
        for _ in 0..seconds * STEPS_PER_SECOND {
            let now = self.now;
            self.boot.resident = self.writer.resident();
            let events =
                self.writer
                    .step(&mut || now, now + 1, &mut self.boot, &mut |execution| {
                        Some(execution.advance(disk, PIECE_BYTES))
                    })?;
            self.events.extend(events);
            self.resident_peak = self.resident_peak.max(self.writer.resident());
            self.now += HZ / STEPS_PER_SECOND;
        }
        Ok(())
    }

    /// Step for `seconds` while the device takes no write.
    fn stall(&mut self, seconds: u64) {
        for _ in 0..seconds * STEPS_PER_SECOND {
            let now = self.now;
            let events = self
                .writer
                .step(&mut || now, now + 1, &mut self.boot, &mut |_| None)
                .unwrap();
            self.events.extend(events);
            self.now += HZ / STEPS_PER_SECOND;
        }
    }

    /// The triggers of the segments committed so far.
    fn triggers(&self) -> Vec<Trigger> {
        self.events
            .iter()
            .filter_map(|event| match event {
                Event::Segment { trigger, .. } => Some(*trigger),
                _ => None,
            })
            .collect()
    }

    fn stop(&mut self, disk: &mut Disk) -> Result<Stopped, String> {
        self.writer.stop(&mut self.boot, &mut |execution| {
            while !execution.advance(disk, PIECE_BYTES)? {}
            Ok(())
        })
    }
}

const FILE_BYTES: u64 = DATA_START + 4096 * journal::ALIGN;
/// The arena of a boot of [`boot_of`].
const BOOT_ARENA_BYTES: usize = 4 << 20;

/// A boot `seed` of entries added in bursts, each followed by its
/// seconds, and stopped: the keys it added.
fn boot_of(
    disk: &mut Disk,
    seed: u32,
    bursts: &[(u64, u32)],
) -> Result<(BTreeSet<Digest>, Stopped), String> {
    // The records of its segments move to an arena of its own, as a boot's
    // do outside the heap, so merges read them from there.
    let mut arena = vec![0u8; BOOT_ARENA_BYTES];
    let mut file: File<'_> = load(&disk.bytes.clone(), u64::MAX);
    file.arena = Arena::new(&mut arena);
    let mut run = Run::new(file, seed);
    let mut added = BTreeSet::new();
    for &(seconds, count) in bursts {
        added.extend(run.boot.add(count));
        run.run(disk, seconds)?;
    }
    let stopped = run.stop(disk)?;
    Ok((added, stopped))
}

#[test]
fn boots_commit_their_segments_and_lists_and_a_later_boot_merges_them() {
    let mut disk = Disk::new(FILE_BYTES);
    let mut all = BTreeSet::new();
    for boot in 0..5 {
        let bursts = [(30, 200), (100, 50), (200, 10)];
        let (added, stopped) = boot_of(&mut disk, boot + 1, &bursts).unwrap();
        all.extend(added);
        assert_eq!(keys(&disk.bytes), all, "boot {boot}");
        assert!(stopped.segments < MAX_SEGMENTS && stopped.lists <= MAX_USED_LISTS);
        assert!(!stopped.merge_left);
    }
    // A merge ran once segments or lists reached MERGE_AT: the file holds
    // fewer than five boots wrote.
    let file = load(&disk.bytes, u64::MAX);
    assert!(file.segments.len() < 5 * 3, "{}", file.segments.len());
    assert!(file.used.len() < 5);
}

#[test]
fn a_long_session_keeps_a_free_slot_and_commits_every_entry_in_bounded_time() {
    let mut disk = Disk::new(FILE_BYTES);
    let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 1);
    let mut pending: Vec<(u64, Vec<Digest>)> = Vec::new();
    // Three days of a burst every ten minutes.
    for _ in 0..3 * 24 * 6 {
        pending.push((run.now, run.boot.add(20)));
        run.run(&mut disk, 600).unwrap();
        let committed = keys(&disk.bytes);
        let file = load(&disk.bytes, u64::MAX);
        assert!(
            file.segments.len() < MAX_SEGMENTS,
            "{}",
            file.segments.len()
        );
        // Whatever was added a last delay and a merge ago is in the file.
        let bound = run.now.saturating_sub(HZ * (LAST_DELTA_SECONDS + 600));
        for (at, added) in &pending {
            if *at < bound {
                assert!(
                    added.iter().all(|key| committed.contains(key)),
                    "added at {at}"
                );
            }
        }
    }
    let stats = run.writer.stats();
    assert!(stats.pairs + stats.merges > 3, "{stats:?}");
    run.stop(&mut disk).unwrap();
    let committed = keys(&disk.bytes);
    assert!(
        pending
            .iter()
            .all(|(_, added)| added.iter().all(|key| committed.contains(key)))
    );
}

#[test]
fn a_stop_finishes_a_segment_in_flight_and_leaves_a_merge() {
    // A segment's write queued and not yet done: the stop finishes it.
    let mut disk = Disk::new(FILE_BYTES);
    let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 1);
    let added = run.boot.add(5000);
    run.stall(FIRST_DELTA_SECONDS);
    assert!(!run.writer.idle());
    assert!(keys(&disk.bytes).is_empty());
    let stopped = run.stop(&mut disk).unwrap();
    assert!(!stopped.merge_left);
    assert_eq!(keys(&disk.bytes), added.into_iter().collect());
    assert_eq!(stopped.segments, 1);

    // A merge in progress at the stop: the file keeps its segments, and
    // the stop adds its own beside them.
    let mut disk = Disk::new(FILE_BYTES);
    let mut all = BTreeSet::new();
    for seed in 0..MERGE_AT as u32 {
        all.extend(boot_of(&mut disk, seed + 1, &[(1, 100)]).unwrap().0);
    }
    // The boot's merge waits for its first segment's delay; then its write
    // never lands.
    let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 9);
    run.stall(FIRST_DELTA_SECONDS + 1);
    assert!(!run.writer.idle());
    assert!(
        run.events
            .iter()
            .any(|event| matches!(event, Event::Merged { full: true, .. })),
        "{:?}",
        run.events
    );
    all.extend(run.boot.add(30));
    let before = load(&disk.bytes, u64::MAX).segments.len();
    let stopped = run.stop(&mut disk).unwrap();
    assert!(stopped.merge_left);
    assert_eq!(stopped.segments, before + 1);
    assert_eq!(keys(&disk.bytes), all);
}

/// Records whose segment takes about `blocks` journal blocks.
fn records_for(blocks: u64) -> u32 {
    let translator = translator_id();
    let sample: Vec<(Digest, crate::translations::pack::Piece)> = (0u32..100)
        .map(|n| {
            let key = Digest::of(&n.to_le_bytes());
            let piece =
                crate::translations::pack::Piece::New(Record::new(translator, key).encode());
            (key, piece)
        })
        .collect();
    let per_record = Layout::new(&translator, sample).bytes() / 100;
    (blocks * journal::ALIGN / per_record) as u32
}

#[test]
fn a_write_that_fails_while_the_guest_runs_is_written_at_the_stop() {
    let mut disk = Disk::new(FILE_BYTES);
    let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 1);
    let added: BTreeSet<Digest> = run.boot.add(500).into_iter().collect();
    // The first write the guest's queue takes fails, as a busy USB's may.
    disk.fail_writes = 1;
    assert!(run.run(&mut disk, FIRST_DELTA_SECONDS + 1).is_err());
    assert!(run.writer.failed());
    assert!(keys(&disk.bytes).is_empty());
    // The stop carries the same write out on the partition directly, and
    // the pack keeps what the boot added.
    let stopped = run.stop(&mut disk).unwrap();
    assert!(!stopped.merge_left);
    assert_eq!(keys(&disk.bytes), added);
}

#[test]
fn a_segment_without_room_waits_for_a_merge_and_one_larger_than_the_file_is_left_out() {
    let mut disk = Disk::new(DATA_START + 64 * journal::ALIGN);
    let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 1);
    let first: BTreeSet<Digest> = run.boot.add(records_for(10)).into_iter().collect();
    run.run(&mut disk, FIRST_DELTA_SECONDS + 1).unwrap();
    assert_eq!(keys(&disk.bytes), first);
    // More than the room beside the first, and than any room a merge
    // leaves beside its segment.
    let second = run.boot.add(records_for(60));
    run.run(&mut disk, 2 * FIRST_DELTA_SECONDS + 10).unwrap();
    let position = |wanted: fn(&Event) -> bool| run.events.iter().position(wanted);
    let waiting = position(|event| matches!(event, Event::Waiting { .. })).unwrap();
    let merged = position(|event| *event == Event::MergeCommitted { full: true }).unwrap();
    let lost = position(|event| matches!(event, Event::Lost { .. })).unwrap();
    assert!(waiting < merged && merged < lost, "{:?}", run.events);
    // The writer goes on: the next segment commits.
    let third: BTreeSet<Digest> = run.boot.add(20).into_iter().collect();
    run.run(&mut disk, 4 * FIRST_DELTA_SECONDS + 10).unwrap();
    let committed = keys(&disk.bytes);
    assert!(committed.is_superset(&first) && committed.is_superset(&third));
    assert!(second.iter().all(|key| !committed.contains(key)));
    run.stop(&mut disk).unwrap();
}

/// Boots of a writer, the same each run: a first with two segments, three
/// short ones whose lists bring a merge, and one more.
fn scenario(disk: &mut Disk) -> Result<(), String> {
    let boots: [&[(u64, u32)]; 5] = [
        &[(70, 300), (130, 40)],
        &[(5, 20)],
        &[(5, 20)],
        &[(5, 20)],
        &[(90, 50)],
    ];
    for (seed, bursts) in boots.into_iter().enumerate() {
        boot_of(disk, seed as u32 + 1, bursts)?;
    }
    Ok(())
}

#[test]
fn a_cut_at_any_write_leaves_the_content_of_a_whole_commit() {
    const SIZE: u64 = DATA_START + 512 * journal::ALIGN;
    let mut disk = Disk::new(SIZE);
    scenario(&mut disk).unwrap();
    let contents = core::mem::take(&mut disk.contents);
    assert!(contents.len() > 8, "{}", contents.len());
    assert!(
        contents
            .iter()
            .any(|content| content.len() < contents.last().unwrap().len()),
        "commits before the last hold less"
    );
    let total = disk.written;
    let step = (total / 250).max(1);
    let mut cut = 0;
    while cut <= total {
        let mut disk = Disk::new(SIZE);
        disk.left = Some(cut);
        let _ = scenario(&mut disk);
        // The newest commit reads back whole (`load` checks it) and holds
        // what one of the uncut run's commits held.
        let found = keys(&disk.bytes);
        assert!(
            found.is_empty() || contents.contains(&found),
            "a cut after {cut} of {total} bytes left content no commit held"
        );
        cut += step;
    }
}

#[test]
fn entries_added_faster_than_their_bound_go_to_segments_before_any_is_refused() {
    // A boot's kernel adds entries for its first seconds far faster than the
    // bound the store keeps between segments: the writer takes them once
    // they reach half of it, so the store refuses none, and the next boot
    // finds all of them.
    let mut disk = Disk::new(FILE_BYTES);
    let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 1);
    run.boot.bound = 1000;
    let mut added = BTreeSet::new();
    for _ in 0..FIRST_DELTA_SECONDS {
        added.extend(run.boot.add(400));
        run.run(&mut disk, 1).unwrap();
    }
    assert_eq!(run.boot.unkept, 0);
    assert!(run.writer.stats().pressed >= 5, "{:?}", run.writer.stats());
    assert!(run.triggers().contains(&Trigger::Pressed));
    run.stop(&mut disk).unwrap();
    assert_eq!(keys(&disk.bytes), added);
    assert_eq!(added.len() as u64, 400 * FIRST_DELTA_SECONDS);
    // The pressed segments were merged as they came: fewer than the slots.
    assert!(load(&disk.bytes, u64::MAX).segments.len() < MAX_SEGMENTS);
}

#[test]
fn the_first_segment_comes_when_translation_goes_quiet_or_at_its_delay() {
    // A burst, then quiet: the first segment commits a few seconds after.
    let mut disk = Disk::new(FILE_BYTES);
    let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 1);
    let burst: BTreeSet<Digest> = run.boot.add(3000).into_iter().collect();
    run.run(&mut disk, QUIET_SECONDS + 2).unwrap();
    assert_eq!(run.triggers(), [Trigger::Quiet]);
    assert_eq!(keys(&disk.bytes), burst);
    run.stop(&mut disk).unwrap();

    // Translation that never goes quiet: the first segment at its delay.
    let mut disk = Disk::new(FILE_BYTES);
    let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 1);
    for second in 0..FIRST_DELTA_SECONDS + 2 {
        run.boot.add(2 * QUIET_RATE as u32);
        run.run(&mut disk, 1).unwrap();
        if second + 1 < FIRST_DELTA_SECONDS {
            assert!(run.triggers().is_empty(), "at {second} s");
        }
    }
    assert_eq!(run.triggers(), [Trigger::Due]);
    run.stop(&mut disk).unwrap();
}

#[test]
fn entries_that_press_while_a_write_waits_are_held_for_the_next_segment() {
    let mut disk = Disk::new(FILE_BYTES);
    let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 1);
    run.boot.bound = 1000;
    let mut added: BTreeSet<Digest> = run.boot.add(400).into_iter().collect();
    // The first segment starts once translation is quiet; its write waits.
    run.stall(QUIET_SECONDS + 2);
    assert!(!run.writer.idle());
    // More than the bound arrives while it waits: the writer takes a batch
    // once it presses, and the store refuses none.
    for _ in 0..3 {
        added.extend(run.boot.add(400));
        run.stall(1);
    }
    assert_eq!(run.boot.unkept, 0);
    assert_eq!(run.writer.stats().held, 1);
    run.run(&mut disk, 5).unwrap();
    run.stop(&mut disk).unwrap();
    assert_eq!(keys(&disk.bytes), added);
}

#[test]
fn a_filling_heap_sheds_the_stores_entries_and_then_lets_the_segments_go() {
    const HEAP: u64 = 8 << 20;
    let mut disk = Disk::new(FILE_BYTES);
    let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 1);
    run.boot.heap_total = HEAP;
    run.boot.filler = HEAP / 4;
    run.boot.bound = 2000;
    let shed = |run: &Run| {
        run.events
            .iter()
            .filter(|event| matches!(event, Event::Shed { .. }))
            .count()
    };

    // The heap's room dips under its shed share: the store keeps no entry
    // until the room is back a release share above it.
    let mut committed: BTreeSet<Digest> = run.boot.add(2000).into_iter().collect();
    run.run(&mut disk, QUIET_SECONDS + 2).unwrap();
    assert_eq!(keys(&disk.bytes), committed);
    run.boot.filler = HEAP - HEAP / SHED_SHARE - run.writer.resident() + 1;
    run.run(&mut disk, 1).unwrap();
    assert!(run.boot.shedding);
    assert_eq!(shed(&run), 1, "{:?}", run.events);
    assert!(run.boot.add(100).is_empty());
    run.boot.filler =
        HEAP - HEAP / SHED_SHARE - HEAP / RELEASE_SHARE - run.writer.resident() - (1 << 20);
    run.run(&mut disk, 1).unwrap();
    assert!(!run.boot.shedding);

    // Entries keep coming with room to spare: the segments laid out grow to
    // their share of the heap, then the store sheds; they never pass it by
    // more than the segment that reached it.
    run.boot.filler = HEAP / 4;
    let cap = HEAP / RESIDENT_SHARE;
    let mut most = 0;
    for _ in 0..4 * FIRST_DELTA_SECONDS {
        committed.extend(run.boot.add(3000));
        run.run(&mut disk, 1).unwrap();
        most = most.max(run.writer.resident());
    }
    assert!(run.boot.shedding && run.boot.shed > 100);
    assert!(most >= cap / 2 && most < cap * 2, "{most} of {cap}");
    assert_eq!(shed(&run), 1, "reported once: {:?}", run.events);
    assert!(run.writer.stats().sheds >= 2);
    let written = keys(&disk.bytes);
    assert!(!written.is_empty());

    // The rest of the boot fills the heap: the writer lets its segments go
    // and the store sheds for the rest of the boot, room or not.
    run.boot.filler = HEAP - HEAP / RELEASE_SHARE + 1;
    run.run(&mut disk, 1).unwrap();
    assert_eq!(run.writer.resident(), 0);
    assert!(
        run.events
            .iter()
            .any(|event| matches!(event, Event::Released { .. })),
        "{:?}",
        run.events
    );
    run.boot.filler = 0;
    run.run(&mut disk, 2 * FIRST_DELTA_SECONDS).unwrap();
    assert_eq!(run.writer.shedding(), (true, true));
    assert!(run.boot.add(100).is_empty());
    assert_eq!(run.writer.resident(), 0);

    // What the file held stays whole; the stop writes the boot's list.
    let stopped = run.stop(&mut disk).unwrap();
    assert!(keys(&disk.bytes).is_superset(&written));
    assert_eq!(stopped.lists, 1);
}

#[test]
fn a_first_boots_records_all_reach_the_file_while_the_heap_holds_their_index_alone() {
    // A first boot's offers, scaled to a 256 MiB heap as build 96's 600 MB
    // were to its 2.9 GB: about 54 MB of records in 8 KiB entries, added
    // faster than their bound, the store pressing every few seconds.
    const HEAP: u64 = 256 << 20;
    const ENTRY: usize = 8 << 10;
    let mut disk = Disk::new(DATA_START + 50_000 * journal::ALIGN);
    disk.track = false;
    let mut arena = vec![0u8; 72 << 20];
    let mut file: File<'_> = load(&disk.bytes.clone(), u64::MAX);
    file.arena = Arena::new(&mut arena);
    let mut run = Run::new(file, 1);
    run.boot.heap_total = HEAP;
    run.boot.filler = HEAP / 2;
    run.boot.bound = (HEAP / 32) as usize / ENTRY;
    run.boot.entry_bytes = ENTRY;
    let mut added = BTreeSet::new();
    for _ in 0..22 {
        added.extend(run.boot.add(300));
        run.run(&mut disk, 1).unwrap();
    }
    run.run(&mut disk, 2 * FIRST_DELTA_SECONDS).unwrap();
    assert_eq!(added.len(), 6600);
    // No entry was refused or shed: the heap never pressed.
    assert_eq!((run.boot.unkept, run.boot.shed), (0, 0));
    assert!(
        !run.events
            .iter()
            .any(|event| matches!(event, Event::Shed { .. } | Event::Released { .. })),
        "{:?}",
        run.events
    );
    // Written, every record moved to the arena; the heap held at most a
    // pressed segment not yet moved, and keeps the indexes alone.
    let (used, _) = run.writer.arena();
    assert!(used >= 6600 * ENTRY as u64, "{used}");
    let segment = run.boot.bound as u64 * (ENTRY as u64 + 512);
    // About a segment and a half: the one being written, and what of the
    // one before has not moved yet.
    assert!(
        run.resident_peak <= 2 * segment && run.resident_peak < HEAP / RESIDENT_SHARE,
        "{} over {}",
        run.resident_peak,
        2 * segment
    );
    assert!(
        run.writer.resident() < 6600 * 256,
        "{}",
        run.writer.resident()
    );
    assert!(run.writer.stats().pairs >= 2, "{:?}", run.writer.stats());
    run.stop(&mut disk).unwrap();
    assert_eq!(keys(&disk.bytes), added);
}

/// Layouts of `records` new records from `first`, each one entry at
/// `offset` of `bytes` code bytes.
fn layout_of(first: u32, records: u32, offset: u16, bytes: usize) -> Layout<'static> {
    let translator = translator_id();
    let records = (first..first + records)
        .map(|n| {
            let key = Digest::of(&n.to_le_bytes());
            let mut record = Record::new(translator, key);
            record.insert(entry(offset, n as u8, bytes));
            (key, crate::translations::pack::Piece::New(record.encode()))
        })
        .collect();
    Layout::new(&translator, records)
}

#[test]
fn a_merge_of_segments_moved_to_the_arena_equals_one_of_them_in_the_heap() {
    // Two segments sharing a third of their keys, those records holding
    // entries at other offsets: the merge keeps one and merges the shared.
    let translator = translator_id();
    let older = || layout_of(0, 300, 0, 3000);
    let newer = || layout_of(200, 300, 64, 2000);
    let merge = |segments: Vec<Segment<'_>>| {
        Merge::new(translator, segments, Vec::new(), u64::MAX)
            .finish()
            .layout
            .to_vec()
    };
    let in_heap = merge(vec![
        Segment::Laid(Arc::new(older())),
        Segment::Laid(Arc::new(newer())),
    ]);
    let mut bytes = vec![0u8; 4 << 20];
    let mut arena = Arena::new(&mut bytes);
    let mut settled = Vec::new();
    for mut layout in [older(), newer()] {
        let before = layout.to_vec();
        let owned = layout.owned();
        while layout.settle(&mut arena, 64 << 10) == crate::translations::pack::Settled::More {}
        assert!(layout.settled());
        assert_eq!(layout.to_vec(), before);
        assert!(layout.owned() < owned / 20, "{} of {owned}", layout.owned());
        settled.push(Segment::Laid(Arc::new(layout)));
    }
    assert!(arena.used() >= 300 * (3000 + 2000), "{}", arena.used());
    assert_eq!(merge(settled), in_heap);
    // A full arena keeps the rest in the heap.
    let mut small = [0u8; 10_000];
    let mut layout = older();
    assert_eq!(
        layout.settle(&mut Arena::new(&mut small), usize::MAX),
        crate::translations::pack::Settled::Full
    );
    assert!(!layout.settled());
    assert_eq!(layout.to_vec(), older().to_vec());
}

#[test]
fn boots_reading_their_pack_whole_converge_on_the_code_they_use() {
    // Every boot uses a base of 250 pages and the drift of the last two
    // boots, 100 new pages each: a used set of 450 records in a limit of
    // about 1000, which the pack keeps while each boot adds its new 100.
    const ENTRY: usize = 4 << 10;
    let record_bytes = {
        let mut record = Record::new(translator_id(), page_key(0));
        record.insert(entry(0, 0, ENTRY));
        record.encode().len() as u64 + 56
    };
    let limit = 1000 * record_bytes;
    let base: Vec<u32> = (0..250).collect();
    let drift = |boot: u32| -> Vec<u32> { (0..100).map(|n| boot * 1000 + n).collect() };
    let mut disk = Disk::new(DATA_START + 8 * limit.div_ceil(journal::ALIGN) * journal::ALIGN);
    disk.track = false;
    for boot in 1..=5u32 {
        let file = load(&disk.bytes.clone(), limit);
        let read: BTreeSet<Digest> = file
            .segments
            .iter()
            .flat_map(|pack| pack.iter().map(|(key, _)| key).collect::<Vec<_>>())
            .collect();
        let pack: u64 = file.segments.iter().map(|pack| pack.bytes() as u64).sum();
        // The loader reads all of it within the limit: no trim.
        assert!(
            pack <= limit / 8 * LEFT_EIGHTHS,
            "boot {boot}: {pack} of {limit}"
        );
        let used: BTreeSet<u32> = base
            .iter()
            .copied()
            .chain(drift(boot))
            .chain(if boot > 1 {
                drift(boot - 1)
            } else {
                Vec::new()
            })
            .collect();
        let found: Vec<Digest> = used
            .iter()
            .map(|&page| page_key(page))
            .filter(|key| read.contains(key))
            .collect();
        let loaded = found.len();
        let missing: Vec<u32> = used
            .iter()
            .copied()
            .filter(|&page| !read.contains(&page_key(page)))
            .collect();
        let mut arena = vec![0u8; limit as usize];
        let mut file: File<'_> = file;
        file.arena = Arena::new(&mut arena);
        let mut run = Run::new(file, boot);
        run.boot.found = found.clone();
        run.boot.entry_bytes = ENTRY;
        run.boot.bound = 200;
        for chunk in missing.chunks(50) {
            for &page in chunk {
                run.boot.add_page(page);
            }
            run.run(&mut disk, 2).unwrap();
        }
        run.run(&mut disk, 3 * FIRST_DELTA_SECONDS).unwrap();
        let merged = run
            .events
            .iter()
            .any(|event| matches!(event, Event::Merged { full: true, .. }));
        run.stop(&mut disk).unwrap();
        let kept = keys(&disk.bytes);
        let used_keys: BTreeSet<Digest> = used.iter().map(|&page| page_key(page)).collect();
        // Every page the boot used is in the file it leaves, and the pack
        // within its share of the limit.
        assert!(kept.is_superset(&used_keys), "boot {boot}");
        let left = load(&disk.bytes.clone(), limit);
        let left: u64 = left.segments.iter().map(|pack| pack.bytes() as u64).sum();
        assert!(left <= limit / 8 * LEFT_EIGHTHS, "boot {boot}: left {left}");
        // Records of pages it used never went while others stayed.
        let evicted_used = found.iter().any(|key| !kept.contains(key));
        let unused_kept = kept.iter().any(|key| !used_keys.contains(key));
        assert!(!(evicted_used && unused_kept), "boot {boot}");
        assert_eq!(run.boot.shed, 0, "boot {boot}");
        match boot {
            1 => assert_eq!((loaded, missing.len()), (0, 350)),
            2 => assert_eq!((loaded, missing.len()), (350, 100)),
            // From the third boot the pack passes the share a merge keeps:
            // a full merge runs and lets the drift this boot did not use
            // go, the oldest first: the last boot's within what the share
            // leaves, the one before's whole.
            _ => {
                assert_eq!((loaded, missing.len()), (350, 100), "boot {boot}");
                assert!(merged, "boot {boot}: {:?}", run.events);
                let kept_of = |pages: Vec<u32>| {
                    pages
                        .iter()
                        .filter(|&&page| kept.contains(&page_key(page)))
                        .count()
                };
                assert!(kept_of(drift(boot - 2)) < 100, "boot {boot}");
                if boot > 3 {
                    assert_eq!(kept_of(drift(boot - 3)), 0, "boot {boot}");
                }
            }
        }
    }
}

#[test]
fn a_first_boot_leaves_at_most_its_share_of_the_limit_and_sheds_the_rest() {
    const ENTRY: usize = 4 << 10;
    let record_bytes = {
        let mut record = Record::new(translator_id(), page_key(0));
        record.insert(entry(0, 0, ENTRY));
        record.encode().len() as u64 + 56
    };
    let limit = 1000 * record_bytes;
    let mut disk = Disk::new(DATA_START + 8 * limit.div_ceil(journal::ALIGN) * journal::ALIGN);
    disk.track = false;
    let mut arena = vec![0u8; limit as usize];
    let mut file: File<'_> = load(&disk.bytes.clone(), limit);
    file.arena = Arena::new(&mut arena);
    let mut run = Run::new(file, 1);
    run.boot.entry_bytes = ENTRY;
    run.boot.bound = 200;
    // It compiles more than the limit holds.
    for _ in 0..24 {
        run.boot.add(50);
        run.run(&mut disk, 2).unwrap();
    }
    run.run(&mut disk, 2 * FIRST_DELTA_SECONDS).unwrap();
    run.stop(&mut disk).unwrap();
    let left = load(&disk.bytes.clone(), limit);
    let left: u64 = left.segments.iter().map(|pack| pack.bytes() as u64).sum();
    assert!(left <= limit / 8 * LEFT_EIGHTHS, "{left} of {limit}");
    assert!(left > limit / 2, "{left} of {limit}");
    assert!(run.boot.shed > 0);
    let pack_sheds = run
        .events
        .iter()
        .filter(|event| {
            matches!(
                event,
                Event::Shed {
                    reason: ShedReason::Pack,
                    ..
                }
            )
        })
        .count();
    assert_eq!(pack_sheds, 1, "{:?}", run.events);
}

/// A second boot of 300 of the 600 pages the first left, each given
/// `phases` more entries of `entry_bytes` (`grow`) or its first again
/// (else), in an
/// arena of the limit less the pack read, as a boot's: the events, the
/// writer's stats, the arena bytes used, and the keys the file keeps.
fn boot_over_pack(
    grow: bool,
    phases: u16,
    entry_bytes: usize,
) -> (Vec<Event>, Stats, u64, BTreeSet<Digest>, Vec<Digest>) {
    const ENTRY: usize = 4 << 10;
    let record_bytes = {
        let mut record = Record::new(translator_id(), page_key(0));
        record.insert(entry(0, 0, ENTRY));
        record.encode().len() as u64 + 56
    };
    let limit = 1000 * record_bytes;
    let mut disk = Disk::new(DATA_START + 8 * limit.div_ceil(journal::ALIGN) * journal::ALIGN);
    disk.track = false;
    // The first boot leaves 600 pages.
    let mut arena = vec![0u8; limit as usize];
    let mut file: File<'_> = load(&disk.bytes.clone(), limit);
    file.arena = Arena::new(&mut arena);
    let mut run = Run::new(file, 1);
    run.boot.entry_bytes = ENTRY;
    run.boot.bound = 200;
    for chunk in (0..600).collect::<Vec<u32>>().chunks(50) {
        for &page in chunk {
            run.boot.add_page(page);
        }
        run.run(&mut disk, 2).unwrap();
    }
    run.run(&mut disk, 2 * FIRST_DELTA_SECONDS).unwrap();
    run.stop(&mut disk).unwrap();
    drop(run);
    // The second uses 300 of them and compiles each anew.
    let file = load(&disk.bytes.clone(), limit);
    let read: u64 = file.segments.iter().map(|pack| pack.bytes() as u64).sum();
    assert!(read > limit / 2, "{read} of {limit}");
    let mut arena = vec![0u8; (limit - read) as usize];
    let mut file: File<'_> = file;
    file.arena = Arena::new(&mut arena);
    let mut run = Run::new(file, 2);
    let used: Vec<Digest> = (0..300).map(page_key).collect();
    run.boot.found = used.clone();
    run.boot.bound = 200;
    for phase in 1..=phases {
        compile_again(&mut run, &mut disk, |page| {
            if grow {
                entry(4 * phase, page as u8 ^ 0xff, entry_bytes)
            } else {
                entry(0, page as u8, ENTRY)
            }
        });
    }
    run.run(&mut disk, 3 * FIRST_DELTA_SECONDS).unwrap();
    let (arena_used, _) = run.writer.arena();
    let stats = run.writer.stats();
    run.stop(&mut disk).unwrap();
    (run.events, stats, arena_used, keys(&disk.bytes), used)
}

/// Offer pages 0 to 300 again, an entry each, 50 every two seconds.
fn compile_again(
    run: &mut Run<'_>,
    disk: &mut Disk,
    entry_of: impl Fn(u32) -> crate::translations::Entry,
) {
    for chunk in (0..300).collect::<Vec<u32>>().chunks(50) {
        for &page in chunk {
            let key = page_key(page);
            let mut record = Record::new(translator_id(), key);
            record.insert(entry_of(page));
            run.boot.added.insert(key, record);
            run.boot.total += 1;
        }
        run.run(disk, 2).unwrap();
    }
}

/// A boot that compiles pages of the pack it read anew merges their
/// records anew: the arena, the limit less the pack read, takes back what
/// the merged records left behind and sheds nothing.
#[test]
fn records_merged_anew_leave_the_arena_room_once_compacted() {
    let (events, stats, _, kept, used) = boot_over_pack(true, 3, 1024);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::Merged { full: true, .. })),
        "{events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::Shed { .. })),
        "{events:?}"
    );
    assert!(stats.compactions > 0 && stats.compacted > 0, "{stats:?}");
    assert!(used.iter().all(|key| kept.contains(key)));
}

/// A merge whose record of a page is one of its holders' takes that
/// holder's bytes: compiled again the same, nothing is copied.
#[test]
fn a_merge_copies_no_record_a_holder_already_has() {
    let (events, stats, arena_used, kept, used) = boot_over_pack(false, 1, 4);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::Merged { full: true, .. })),
        "{events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::Shed { .. })),
        "{events:?}"
    );
    // Only the boot's segments moved to the arena, each record once.
    assert!(arena_used <= stats.delta_bytes, "{arena_used} {stats:?}");
    assert!(
        used.iter().all(|key| kept.contains(key)),
        "{} of {} kept, {} in all {events:?}",
        used.iter().filter(|key| kept.contains(key)).count(),
        used.len(),
        kept.len()
    );
}

/// Compacted, the arena holds the records the layouts given keep, at its
/// front and the same bytes, and gives back those of the rest.
#[test]
fn a_compacted_arena_keeps_the_records_of_the_layouts_given() {
    use crate::translations::pack::Settled;
    let mut bytes = vec![0u8; 4 << 20];
    let mut arena = Arena::new(&mut bytes);
    let mut layouts: Vec<_> = (0..3)
        .map(|index| {
            let mut layout =
                layout_of(index * 1000, 200, index as u16, 1000 + 500 * index as usize);
            while layout.settle(&mut arena, usize::MAX) == Settled::More {}
            assert!(layout.settled());
            layout
        })
        .collect();
    let gone = layouts.remove(1);
    let before: Vec<_> = layouts.iter().map(Layout::to_vec).collect();
    let used = arena.used();
    drop(gone);
    let mut held: Vec<&mut Layout<'_>> = layouts.iter_mut().collect();
    // SAFETY: these layouts hold every slice of the arena still in use.
    let given = unsafe { arena.compact(&mut held) };
    assert!(given > 200 * 1500 && given < used, "{given} of {used}");
    assert_eq!(arena.used(), used - given);
    assert_eq!(
        layouts.iter().map(Layout::to_vec).collect::<Vec<_>>(),
        before
    );
    // The room given back holds new records, the kept ones unchanged.
    let mut next = layout_of(5000, 200, 9, 1500);
    let expected = next.to_vec();
    while next.settle(&mut arena, usize::MAX) == Settled::More {}
    assert!(next.settled());
    assert_eq!(next.to_vec(), expected);
    assert_eq!(
        layouts.iter().map(Layout::to_vec).collect::<Vec<_>>(),
        before
    );
}

/// Batch after batch that presses while a write waits joins the batch held,
/// within its share of the heap: the store refuses none. Without a known
/// heap, one batch is held and the rest wait in the store's bound.
#[test]
fn batches_that_press_through_a_long_wait_join_the_batch_held() {
    for heap_total in [1u64 << 30, 0] {
        let mut disk = Disk::new(FILE_BYTES);
        let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 1);
        run.boot.heap_total = heap_total;
        run.boot.bound = 1000;
        let mut added: BTreeSet<Digest> = run.boot.add(400).into_iter().collect();
        run.stall(QUIET_SECONDS + 2);
        assert!(!run.writer.idle());
        for _ in 0..6 {
            added.extend(run.boot.add(600));
            run.stall(1);
        }
        if heap_total == 0 {
            assert_eq!(run.writer.stats().held, 1);
            assert!(run.boot.unkept > 0);
            continue;
        }
        assert_eq!(run.boot.unkept, 0);
        assert_eq!(run.writer.stats().held, 6);
        run.run(&mut disk, 10).unwrap();
        run.stop(&mut disk).unwrap();
        assert_eq!(keys(&disk.bytes), added);
    }
}

/// An arena too small for the boot's records sheds nothing: once full, it
/// says so once and the rest stay in the heap, within the heap's rules.
#[test]
fn a_full_arena_leaves_the_rest_in_the_heap_and_sheds_nothing() {
    let mut disk = Disk::new(FILE_BYTES);
    let mut arena = vec![0u8; 64 << 10];
    let mut file: File<'_> = load(&disk.bytes.clone(), u64::MAX);
    file.arena = Arena::new(&mut arena);
    let mut run = Run::new(file, 1);
    run.boot.heap_total = 1 << 30;
    run.boot.entry_bytes = 1 << 10;
    run.boot.bound = 400;
    let mut added = BTreeSet::new();
    for _ in 0..6 {
        added.extend(run.boot.add(200));
        run.run(&mut disk, 2).unwrap();
    }
    run.run(&mut disk, 2 * FIRST_DELTA_SECONDS).unwrap();
    let full = run
        .events
        .iter()
        .filter(|event| matches!(event, Event::ArenaFull { .. }))
        .count();
    assert_eq!(full, 1, "{:?}", run.events);
    assert!(
        !run.events
            .iter()
            .any(|event| matches!(event, Event::Shed { .. })),
        "{:?}",
        run.events
    );
    assert_eq!(run.boot.shed, 0);
    assert!(run.writer.resident() > 0);
    run.stop(&mut disk).unwrap();
    assert_eq!(keys(&disk.bytes), added);
}
