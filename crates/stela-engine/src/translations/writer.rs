//! The order in which a boot writes its pack file, a journal of segments and
//! used-key lists ([`super::pack`]), independent of the device: the boot
//! drives [`Writer::step`] on processors whose guest waits and
//! [`Writer::stop`] when the guest restarts or powers off, and hands each a
//! way to carry a journal plan out ([`Execution`]).
//!
//! While the guest runs, the entries the boot added go to the file as new
//! segments: the first once translation goes quiet (fewer than
//! [`QUIET_RATE`] entries a second for [`QUIET_SECONDS`]) or at
//! [`FIRST_DELTA_SECONDS`], whichever comes first, then at doubling
//! intervals; and whenever the entries held reach half their bound
//! ([`Entries::pressed`]), so none is refused for want of room while the
//! writer keeps up. Pressed while it writes or merges, it takes them at once
//! and holds them, one batch, for the segment it starts next.
//!
//! The newest two segments are merged, keeping every record and its age,
//! once the newer is at least half the older: segment sizes stay geometric,
//! so the slots ([`MAX_SEGMENTS`]) suffice for any amount and a record is
//! rewritten a logarithmic number of times. A full merge folds every
//! segment and used-key list into one, dropping records unused for too many
//! boots: once a boot when the file holds [`MERGE_AT`] of either (after the
//! boot's first segment came due, and while translation does not press),
//! when the segments fill half the file, when a new segment finds no room,
//! or when the slots run short. A merge reads segments from memory: those
//! the boot read and those it laid out, whose records it moves instead of
//! copying. Every merged segment lies beside the file's content, so it
//! commits once and a cut leaves the content before it whole; a full merge
//! stays within [`MERGED_SHARE`] of the file, so new segments find room
//! until the next. A new segment the file has no room for waits for a
//! merge; one that finds none even after it is too large for the file and
//! is left out.
//!
//! At a stop, a new segment's write in flight is finished, a merge not yet
//! committed is left, and what is left and the boot's used-key list are
//! written.
//!
//! Once a segment is written, its records move out of the heap to an arena
//! ([`Arena`]) outside it, as the pack the loader read is held, a step's
//! share ([`SETTLE_BYTES`]) at a time, whatever else it does: merges read
//! them there, and the heap keeps each laid-out segment's index alone. A
//! merge moves its inputs' records rather than copying them, and copies a
//! record several segments hold only when merging changes it; when the
//! arena fills, it is compacted to the records the segments keep, so it
//! holds what this boot added, not what merges left behind.
//!
//! A pack the next boot reads whole converges on the code boots use: a boot
//! leaves at most [`LEFT_EIGHTHS`] of the limit (the store sheds new entries
//! past it), so the next reads all of it and its arena, the limit less the
//! pack read, holds whatever it adds; and once a boot whose file held
//! records of earlier boots, a full merge keeps [`KEPT_EIGHTHS`] of the
//! limit, the records boots used most recently first, which leaves room for
//! the code the boot newly compiles.
//!
//! What stays in the heap, beside everything the guest and the GPU need
//! from it, the writer bounds by the heap
//! ([`Entries::heap`]): the store sheds new entries while the heap's room is
//! under [`SHED_SHARE`] or the laid-out segments reach [`RESIDENT_SHARE`]
//! of it, and once the room falls under [`RELEASE_SHARE`] the writer lets
//! every segment it holds go, for the rest of the boot: they stay in the
//! file, and no merge runs, as one would leave them out.
use super::pack::{
    Arena, Delta, JOURNAL_DOMAIN, Layout, MAX_SEGMENTS, MAX_USED_KEYS, MAX_USED_LISTS, Merge,
    Merged, Pack, SEGMENT_BLOB, Segment, Settled, USED_BLOB, UsedKeys,
};
use super::{Digest, Record};
use alloc::{boxed::Box, collections::BTreeMap, string::String, sync::Arc, vec, vec::Vec};
use stela_formats::journal::{self, Blob, Change, Commit, DATA_START, Entry, Execution, Step};

/// Segments or used-key lists at which a boot merges them in full, once.
pub const MERGE_AT: usize = 4;
/// Segments in the file at which a full merge runs whatever else: a new
/// segment and the stop's stay possible.
pub const MERGE_FULL: usize = MAX_SEGMENTS - 2;
/// A full merge runs once the segments take more than half the file's data
/// area, and its segment takes at most this share of it (in eighths): the
/// rest is room for the merge beside the content and for new segments.
pub const MERGED_SHARE: u64 = 3;
/// The first new segment comes at this many seconds, or earlier once fewer
/// than [`QUIET_RATE`] entries a second were added for [`QUIET_SECONDS`]. A
/// boot translates its kernel and first services in a burst of thousands of
/// entries a second; when that burst ends, the entries the next boot needs
/// first are all there, and a crash after it loses none of them. Twenty
/// seconds bounds the wait when a boot never goes quiet. The delay then
/// doubles with each segment, up to the last.
pub const FIRST_DELTA_SECONDS: u64 = 20;
pub const QUIET_RATE: u64 = 100;
pub const QUIET_SECONDS: u64 = 3;
pub const LAST_DELTA_SECONDS: u64 = 32 * 60;
/// How long the writer waits to look again when nothing was added.
const RECHECK_SECONDS: u64 = 10;
/// How often a second the writer asks the store how much it added: the
/// question takes every part's lock.
const LOOKS_PER_SECOND: u64 = 10;
/// The work a step does between looks at the clock: records encoded, page
/// keys merged, or records indexed.
pub const STEP_WORK: usize = 32;
/// The most bytes a write step queues.
pub const PIECE_BYTES: u64 = 512 << 10;
/// The record bytes a step moves to the arena.
pub const SETTLE_BYTES: usize = 4 << 20;
/// The eighths of the limit a full merge keeps, once the file holds records
/// of earlier boots, and the eighths the pack a boot leaves may take.
pub const KEPT_EIGHTHS: u64 = 4;
pub const LEFT_EIGHTHS: u64 = 6;
/// The share of the heap (a fraction's denominator) the segments laid out
/// this boot may hold.
pub const RESIDENT_SHARE: u64 = 16;
/// The store sheds new entries while the heap's room is under this share
/// of it, and keeps them again once the room is a [`RELEASE_SHARE`] more.
pub const SHED_SHARE: u64 = 16;
/// Under this share of room, the writer lets its laid-out segments go.
pub const RELEASE_SHARE: u64 = 32;

/// The heap the writer's segments and the store's entries share with the
/// rest of the boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heap {
    pub total: u64,
    /// The bytes a large request can still find.
    pub room: u64,
}

/// What the writer asks of the boot's store.
pub trait Entries {
    /// The entries added since the last take.
    fn take_added(&mut self) -> BTreeMap<Digest, Record>;
    /// The page keys looked up and found valid so far.
    fn found_keys(&mut self) -> Vec<Digest>;
    /// The entries added since the boot began.
    fn added(&mut self) -> u64;
    /// Whether the entries held for the next segment reached half the
    /// bound past which new ones are refused.
    fn pressed(&mut self) -> bool;
    /// The heap, when the boot measures it.
    fn heap(&mut self) -> Option<Heap>;
    /// Keep no new entry (`true`), the heap being short, or keep them again.
    fn shed(&mut self, shed: bool);
    /// The bytes of the entries added since the last take.
    fn added_bytes(&mut self) -> u64;
}

/// Why the store sheds new entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShedReason {
    /// The heap's room is short, or the laid-out segments hold their share.
    Heap,
    /// The pack reached the share of the limit a boot leaves.
    Pack,
}

/// Why a new segment started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// Its delay passed.
    Due,
    /// Translation went quiet before the first delay passed.
    Quiet,
    /// The entries held reached half their bound.
    Pressed,
}

/// What a step did that the boot reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A new segment of `records` was committed, `bytes` long.
    Segment {
        records: usize,
        bytes: u64,
        trigger: Trigger,
    },
    /// A merge laid out its segment within `bound`: in full, or of the
    /// newest two segments.
    Merged {
        full: bool,
        records: usize,
        bytes: u64,
        bound: u64,
        evicted: u64,
        expired: u64,
        invalid: u64,
    },
    /// A merge's segment was committed.
    MergeCommitted { full: bool },
    /// A new segment found no room: it waits for a merge.
    Waiting { records: usize },
    /// A waiting segment found no room after a merge either: it is larger
    /// than the file holds beside the merged content, and left out.
    Lost { records: usize },
    /// A full merge laid out its segment but the file had no room to commit
    /// it beside its content: the file keeps the segments it had, and no
    /// merge runs again this boot. New segments still find room.
    MergeLeftOut { records: usize, bytes: u64 },
    /// The store began shedding new entries for `reason`, the first time
    /// this boot for it: the heap's room when measured, the pack's bytes
    /// with those pending, and those the laid-out segments hold.
    Shed {
        reason: ShedReason,
        room: Option<u64>,
        pack: u64,
        resident: u64,
    },
    /// The arena, compacted, had no room for the next record, `used` bytes
    /// of it holding records: the rest of the boot's written records stay
    /// in the heap, within its share ([`RESIDENT_SHARE`]), as `resident`
    /// bytes did then. Reported once.
    ArenaFull { used: u64, resident: u64 },
    /// The heap's room fell under [`RELEASE_SHARE`]: the writer let its
    /// laid-out segments go (`bytes`), and the records of those not yet
    /// written and of the entries held (`lost`).
    Released { room: u64, bytes: u64, lost: usize },
}

/// What the writer did while the guest ran.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub deltas: u64,
    pub delta_records: u64,
    pub delta_bytes: u64,
    /// Segments started because the entries held pressed, and batches
    /// taken while the writer was busy.
    pub pressed: u64,
    pub held: u64,
    /// Merges of the newest two segments, and full merges.
    pub pairs: u64,
    pub merges: u64,
    /// Times the store began shedding, and the most bytes the laid-out
    /// segments held.
    pub sheds: u64,
    pub resident_peak: u64,
    /// Times the arena was compacted, and the bytes that gave back.
    pub compactions: u64,
    pub compacted: u64,
}

/// What [`Writer::stop`] wrote: the segments in the file after it, the
/// used-key lists, the records of its new segments, those no slot was left
/// for, and its bytes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stopped {
    pub segments: usize,
    pub lists: usize,
    pub records: usize,
    pub lost: usize,
    pub bytes: u64,
    /// A merge was in progress and left for the next boot.
    pub merge_left: bool,
}

/// A merge in progress: in full, or of the newest two segments, at these
/// offsets in the file.
enum Merging {
    Full,
    Pair([u64; 2]),
}

/// The writer's work in progress.
enum Task<'a> {
    Idle,
    /// A new segment of the entries taken, being laid out.
    Delta(Box<Delta>, Trigger),
    Merge(Box<Merge<'a>>, Merging),
    Write {
        execution: Box<Execution<'a>>,
        done: Done<'a>,
    },
}

/// What a finished write leaves in memory.
enum Done<'a> {
    Segment(Arc<Layout<'a>>, Trigger),
    Merge(Arc<Layout<'a>>, Merging),
}

/// A boot's writer of its pack file.
pub struct Writer<'a> {
    translator: Digest,
    /// The bound a merged segment stays within: what this PC can read.
    limit: u64,
    file_bytes: u64,
    committed: Option<Commit>,
    /// The file's segments as memory holds them, oldest first, and the
    /// used-key lists read: a merge's input.
    segments: Vec<Segment<'a>>,
    used: Vec<UsedKeys>,
    /// A segment was not read whole: only a full merge the file needs
    /// runs, as a merge leaves out what was not read.
    partial: bool,
    /// This boot's first full merge ran; its first segment came due.
    merged: bool,
    settled: bool,
    /// New segments laid out with no room yet in the file, and whether a
    /// merge committed since the first began to wait.
    waiting: Vec<Arc<Layout<'a>>>,
    merged_since_wait: bool,
    /// The keys of the entries this boot took for its segments: with those
    /// it found, its used keys. More than a list names counts every key.
    added_keys: Vec<Digest>,
    task: Task<'a>,
    /// Counter ticks per second, the counter value before which no new
    /// segment starts (0: not yet set), and the delay after the next.
    hz: u64,
    next_delta: u64,
    delta_interval: u64,
    /// The last look at the entries added: when, and how many since the
    /// boot began; whether they pressed then, and since when they came
    /// slower than [`QUIET_RATE`].
    looked: Option<(u64, u64)>,
    pressed: bool,
    /// Entries taken while pressed and busy, for the next segment.
    held: BTreeMap<Digest, Record>,
    held_bytes: u64,
    quiet_since: Option<u64>,
    /// The store sheds new entries, the reasons reported so far (a bit
    /// each), and whether the writer let its segments go.
    shedding: bool,
    reported: u8,
    released: bool,
    /// The bytes of the segments read: records of earlier boots.
    read_bytes: u64,
    /// The bytes of the entries a segment being laid out took.
    delta_bytes: u64,
    /// Where written records move, and whether it ran out of room.
    arena: Arena<'a>,
    arena_full: bool,
    arena_reported: bool,
    failed: bool,
    stats: Stats,
}

/// A boot's view of its pack file as the loader read it.
pub struct File<'a> {
    pub translator: Digest,
    /// The bound a merged segment stays within.
    pub limit: u64,
    pub file_bytes: u64,
    /// The file's newest commit, any translator's.
    pub committed: Option<Commit>,
    /// The segments and used-key lists read, oldest first.
    pub segments: Vec<Pack<'a>>,
    pub used: Vec<UsedKeys>,
    /// A segment was left out or cut.
    pub partial: bool,
    /// Where the records of the segments this boot writes move.
    pub arena: Arena<'a>,
}

impl<'a> Writer<'a> {
    pub fn new(mut file: File<'a>, hz: u64) -> Self {
        let segments = core::mem::take(&mut file.segments);
        let mut writer = Self {
            translator: file.translator,
            limit: file.limit,
            file_bytes: file.file_bytes,
            committed: file.committed,
            segments: Vec::new(),
            used: file.used,
            partial: file.partial,
            merged: false,
            settled: false,
            waiting: Vec::new(),
            merged_since_wait: false,
            added_keys: Vec::new(),
            task: Task::Idle,
            hz,
            next_delta: 0,
            delta_interval: hz * FIRST_DELTA_SECONDS,
            looked: None,
            pressed: false,
            held: BTreeMap::new(),
            held_bytes: 0,
            quiet_since: None,
            shedding: false,
            reported: 0,
            released: false,
            read_bytes: segments.iter().map(|pack| pack.bytes() as u64).sum(),
            delta_bytes: 0,
            arena: file.arena,
            arena_full: false,
            arena_reported: false,
            failed: false,
            stats: Stats::default(),
        };
        writer.segments = segments.into_iter().map(Segment::from).collect();
        writer
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    pub fn failed(&self) -> bool {
        self.failed
    }

    pub fn idle(&self) -> bool {
        matches!(self.task, Task::Idle)
    }

    /// The heap bytes of the segments laid out this boot that memory holds
    /// for merges and writes.
    pub fn resident(&self) -> u64 {
        let laid = self.segments.iter().filter_map(|segment| match segment {
            Segment::Laid(layout) => Some(layout.owned()),
            Segment::Packed(_) => None,
        });
        let waiting = self.waiting.iter().map(|layout| layout.owned());
        laid.chain(waiting).sum()
    }

    /// The arena's bytes holding records, and those left.
    pub fn arena(&self) -> (u64, u64) {
        (self.arena.used(), self.arena.left())
    }

    /// Move a step's share of the records of a segment written to the
    /// arena, until it has no room even compacted: the first time, the
    /// event that says so.
    fn settle(&mut self) -> Option<Event> {
        // Without an arena (none was set aside) the records stay.
        let (used, left) = self.arena();
        if self.arena_full || self.released || used + left == 0 {
            return None;
        }
        // Merges leave the records they merged anew or evicted behind in
        // the arena: compacted, it holds what the segments keep. The rest
        // stays in the heap until a merge or write in flight is done, and
        // the arena is full when compacted it still has no room, until the
        // next merge commits. Records past it stay in the heap, which its
        // own shares bound: the arena is the room the pack read leaves, and
        // a merge of read segments that hold one page each re-encodes that
        // page there while the read bytes stay for lookups.
        if self.settle_next() == Some(Settled::Full)
            && self.compact().is_some()
            && self.settle_next() == Some(Settled::Full)
        {
            self.arena_full = true;
            if !self.arena_reported {
                self.arena_reported = true;
                return Some(Event::ArenaFull {
                    used: self.arena.used(),
                    resident: self.resident(),
                });
            }
        }
        None
    }

    /// Move a step's share of the first segment written with records
    /// still in the heap: `None` when there is none.
    fn settle_next(&mut self) -> Option<Settled> {
        for segment in &mut self.segments {
            let Segment::Laid(layout) = segment else {
                continue;
            };
            if layout.settled() {
                continue;
            }
            // A write in flight shares its layout: it moves once written.
            let Some(layout) = Arc::get_mut(layout) else {
                continue;
            };
            return Some(layout.settle(&mut self.arena, SETTLE_BYTES));
        }
        None
    }

    /// Compact the arena to the records the segments keep, unless a merge or
    /// write in flight holds some of them: the bytes it gave back.
    fn compact(&mut self) -> Option<u64> {
        if matches!(self.task, Task::Merge(..) | Task::Write { .. }) {
            return None;
        }
        let mut layouts = Vec::with_capacity(self.segments.len() + self.waiting.len());
        for segment in &mut self.segments {
            if let Segment::Laid(layout) = segment {
                layouts.push(Arc::get_mut(layout)?);
            }
        }
        for layout in &mut self.waiting {
            layouts.push(Arc::get_mut(layout)?);
        }
        // SAFETY: with no merge or write in flight and every layout held
        // here alone, the segments hold every slice of the arena in use.
        let given = unsafe { self.arena.compact(&mut layouts) };
        self.stats.compactions += 1;
        self.stats.compacted += given;
        Some(given)
    }

    /// Whether the store sheds new entries, and whether the writer let its
    /// segments go.
    pub fn shedding(&self) -> (bool, bool) {
        (self.shedding, self.released)
    }

    /// Keep the store's entries and the segments laid out within the heap:
    /// shed new entries while its room or the segments press, and let the
    /// segments go once its room is nearly gone.
    fn govern(&mut self, entries: &mut dyn Entries) -> Option<Event> {
        let heap = entries.heap();
        let resident = self.resident();
        self.stats.resident_peak = self.stats.resident_peak.max(resident);
        if let Some(Heap { total, room }) = heap
            && !self.released
            && room < total / RELEASE_SHARE
        {
            return Some(self.release(entries, room, resident));
        }
        let left = self.left_bytes();
        let pack = self.pack_bytes(entries);
        let heap_short = heap.is_some_and(|Heap { total, room }| {
            room < total / SHED_SHARE || resident >= total / RESIDENT_SHARE
        });
        let reason = if heap_short {
            Some(ShedReason::Heap)
        } else if pack >= left {
            Some(ShedReason::Pack)
        } else {
            None
        };
        let heap_eased = heap
            .is_none_or(|Heap { total, room }| room >= total / SHED_SHARE + total / RELEASE_SHARE);
        let keep = reason.is_none() && heap_eased && pack < left.saturating_sub(self.limit / 16);
        if let Some(reason) = reason
            && !self.shedding
        {
            self.shedding = true;
            entries.shed(true);
            self.stats.sheds += 1;
            let bit = 1 << reason as u8;
            if self.reported & bit == 0 {
                self.reported |= bit;
                return Some(Event::Shed {
                    reason,
                    room: heap.map(|heap| heap.room),
                    pack,
                    resident,
                });
            }
        }
        if keep && self.shedding && !self.released {
            self.shedding = false;
            entries.shed(false);
        }
        None
    }

    /// The most bytes the pack a boot leaves may take.
    fn left_bytes(&self) -> u64 {
        self.limit / 8 * LEFT_EIGHTHS
    }

    /// The bytes the pack takes and will take: the file's segments, those
    /// laid out or being written, and the entries taken or added for the
    /// next (as the heap holds them, more than they take encoded).
    fn pack_bytes(&self, entries: &mut dyn Entries) -> u64 {
        let waiting: u64 = self.waiting.iter().map(|layout| layout.bytes()).sum();
        let task = match &self.task {
            Task::Delta(..) => self.delta_bytes,
            Task::Write {
                done: Done::Segment(layout, _),
                ..
            } => layout.bytes(),
            _ => 0,
        };
        self.segment_bytes() + waiting + task + self.held_bytes + entries.added_bytes()
    }

    /// Let every segment laid out go, with a merge in progress, the entries
    /// held and those the store holds, and shed new ones for the rest of
    /// the boot. A segment being laid out or written finishes; it is let go
    /// once written.
    fn release(&mut self, entries: &mut dyn Entries, room: u64, bytes: u64) -> Event {
        self.released = true;
        if !self.shedding {
            self.shedding = true;
            self.stats.sheds += 1;
        }
        entries.shed(true);
        let mut lost = self.waiting.iter().map(|layout| layout.records()).sum();
        self.waiting.clear();
        self.merged_since_wait = false;
        lost += self.held.len();
        self.held = BTreeMap::new();
        self.held_bytes = 0;
        lost += entries.take_added().len();
        if let Task::Merge(..) = self.task {
            self.task = Task::Idle;
        }
        self.segments
            .retain(|segment| matches!(segment, Segment::Packed(_)));
        // Merges read segments from memory: with some let go, none runs.
        self.partial = true;
        Event::Released { room, bytes, lost }
    }

    /// The file's newest commit, as the writer last committed or read it.
    pub fn committed(&self) -> Option<&Commit> {
        self.committed.as_ref()
    }

    /// The committed blobs of `kind` of this translator, in order.
    fn entries(&self, kind: u32) -> impl Iterator<Item = &Entry> + '_ {
        self.committed
            .iter()
            .filter(|commit| commit.key == self.translator.0)
            .flat_map(|commit| commit.entries.iter())
            .filter(move |entry| entry.kind == kind)
    }

    /// The committed blobs of `kind` of this translator.
    pub fn count(&self, kind: u32) -> usize {
        self.entries(kind).count()
    }

    /// The longest free run beside the file's content.
    fn free(&self) -> u64 {
        journal::largest_free(
            self.committed.as_ref(),
            JOURNAL_DOMAIN,
            self.translator.0,
            self.file_bytes,
        )
    }

    /// The data area's bytes.
    fn data_bytes(&self) -> u64 {
        (self.file_bytes / journal::ALIGN * journal::ALIGN).saturating_sub(DATA_START)
    }

    /// Note the keys of entries taken for a segment.
    fn note_added(&mut self, added: &BTreeMap<Digest, Record>) {
        if self.added_keys.len() <= MAX_USED_KEYS {
            self.added_keys.extend(added.keys().copied());
        }
    }

    /// This boot's used keys so far, as a list.
    fn used_list(&self, found: Vec<Digest>) -> Vec<u8> {
        if self.added_keys.len() > MAX_USED_KEYS {
            return UsedKeys::encode_every(&self.translator);
        }
        UsedKeys::encode(&self.translator, found.iter().chain(&self.added_keys))
    }

    /// Look at what the store added, at most [`LOOKS_PER_SECOND`] times a
    /// second: whether it presses, and since when it comes slowly.
    fn look(&mut self, now: u64, entries: &mut dyn Entries) {
        let Some((at, total)) = self.looked else {
            self.looked = Some((now, entries.added()));
            return;
        };
        if now < at + (self.hz / LOOKS_PER_SECOND).max(1) {
            return;
        }
        let added = entries.added();
        self.pressed = entries.pressed();
        let rate = added.saturating_sub(total) * self.hz / (now - at);
        if rate >= QUIET_RATE {
            self.quiet_since = None;
        } else if self.quiet_since.is_none() {
            self.quiet_since = Some(at);
        }
        self.looked = Some((now, added));
    }

    /// Why a new segment starts now, if one does.
    fn trigger(&self, now: u64) -> Option<Trigger> {
        if self.pressed {
            return Some(Trigger::Pressed);
        }
        if now >= self.next_delta {
            return Some(Trigger::Due);
        }
        let quiet = self
            .quiet_since
            .is_some_and(|since| now >= since + self.hz * QUIET_SECONDS);
        let added = self.looked.is_some_and(|(_, added)| added != 0);
        (!self.settled && quiet && added).then_some(Trigger::Quiet)
    }

    /// The bytes of the file's segments.
    fn segment_bytes(&self) -> u64 {
        self.entries(SEGMENT_BLOB).map(|entry| entry.length).sum()
    }

    /// Whether a full merge is due: the slots run short, the segments fill
    /// half the file, a new segment waits for room, or, once a boot when
    /// every segment was read, after its first segment came due and while
    /// translation does not press, enough segments or lists.
    fn full_merge_due(&self) -> bool {
        let segments = self.count(SEGMENT_BLOB);
        segments >= MERGE_FULL
            || self.segment_bytes() > self.data_bytes() / 2
            || !self.waiting.is_empty()
            || (!self.merged
                && !self.partial
                && self.settled
                && !self.pressed
                && (segments >= MERGE_AT
                    || self.count(USED_BLOB) >= MERGE_AT
                    || (self.read_bytes != 0 && self.segment_bytes() > self.kept_bytes())))
    }

    /// The most bytes a full merge keeps: once the file holds records of
    /// earlier boots, [`KEPT_EIGHTHS`] of the limit; before, the share a
    /// boot leaves, so a first boot's records all stay.
    fn kept_bytes(&self) -> u64 {
        if self.read_bytes != 0 {
            self.limit / 8 * KEPT_EIGHTHS
        } else {
            self.left_bytes()
        }
    }

    /// The offsets of the newest two segments when they are due to merge:
    /// the newer at least half the older, memory holding both as the file
    /// does, the two within what this PC reads, and room beside the content
    /// for both.
    fn pair_due(&self) -> Option<[u64; 2]> {
        if self.partial || self.segments.len() != self.count(SEGMENT_BLOB) {
            return None;
        }
        let segments: Vec<&Entry> = self.entries(SEGMENT_BLOB).collect();
        let [.., older, newer] = segments[..] else {
            return None;
        };
        let both = older.length + newer.length;
        (newer.length * 2 >= older.length && both <= self.limit && both <= self.free())
            .then_some([older.offset, newer.offset])
    }

    /// Write a waiting segment when it fits, else start a merge when one is
    /// due, else start a segment of the entries added when its time came.
    fn begin(&mut self, now: u64, entries: &mut dyn Entries) -> Option<Event> {
        if let Some(layout) = self.waiting.first().cloned() {
            if let Some(task) = self.write_segment(layout.clone(), Trigger::Due) {
                self.waiting.remove(0);
                self.task = task;
                return None;
            }
            if self.merged_since_wait {
                self.waiting.remove(0);
                self.merged_since_wait = false;
                return Some(Event::Lost {
                    records: layout.records(),
                });
            }
        }
        self.look(now, entries);
        if self.full_merge_due() && !self.segments.is_empty() && !self.released {
            self.merged = true;
            // Beside the file's content, so its commit keeps that content
            // until the merged segment is whole; within its share of the
            // file, so new segments find room until the next merge.
            let share = self.data_bytes() / 8 * MERGED_SHARE;
            let bound = self.kept_bytes().min(share).min(self.free());
            let protect = UsedKeys::parse(&self.used_list(entries.found_keys()), &self.translator);
            let segments = core::mem::take(&mut self.segments);
            let mut merge = Merge::new(self.translator, segments, self.used.clone(), bound);
            if let Some(protect) = protect {
                merge = merge.protect(protect);
            }
            self.task = Task::Merge(Box::new(merge), Merging::Full);
            return None;
        }
        if !self.waiting.is_empty() {
            return None;
        }
        // A batch taken while busy goes before any merge of the newest two.
        if !self.held.is_empty() && self.count(SEGMENT_BLOB) + 1 < MAX_SEGMENTS {
            let held = core::mem::take(&mut self.held);
            self.held_bytes = 0;
            return self.start_delta(now, held, entries, Trigger::Pressed);
        }
        if let Some(offsets) = self.pair_due() {
            let pair = self.segments.split_off(self.segments.len() - 2);
            let merge = Merge::new(self.translator, pair, Vec::new(), self.limit);
            self.task = Task::Merge(Box::new(merge), Merging::Pair(offsets));
            return None;
        }
        if self.next_delta == 0 {
            self.next_delta = now + self.delta_interval;
        }
        let trigger = self.trigger(now)?;
        // One segment stays free for the stop's.
        if self.count(SEGMENT_BLOB) + 1 >= MAX_SEGMENTS {
            return None;
        }
        let held = core::mem::take(&mut self.held);
        self.held_bytes = 0;
        self.start_delta(now, held, entries, trigger)
    }

    /// Start a segment of `held` and the entries added since.
    fn start_delta(
        &mut self,
        now: u64,
        mut added: BTreeMap<Digest, Record>,
        entries: &mut dyn Entries,
        trigger: Trigger,
    ) -> Option<Event> {
        self.settled = true;
        self.pressed = false;
        let taken = entries.take_added();
        self.note_added(&taken);
        join(&mut added, taken);
        if added.is_empty() {
            self.next_delta = self.next_delta.max(now + self.hz * RECHECK_SECONDS);
            return None;
        }
        if trigger == Trigger::Pressed {
            self.stats.pressed += 1;
        } else {
            self.next_delta = now + self.delta_interval;
            self.delta_interval = (self.delta_interval * 2).min(self.hz * LAST_DELTA_SECONDS);
        }
        self.stats.delta_records += added.len() as u64;
        self.delta_bytes = added
            .values()
            .map(|record| record.retained_bytes() as u64)
            .sum();
        self.task = Task::Delta(Box::new(Delta::new(self.translator, added)), trigger);
        None
    }

    /// While busy: take the entries added at once when they press, into
    /// the batch held for the next segment, while it stays within its share
    /// of the heap ([`RESIDENT_SHARE`]; one batch where the heap is not
    /// known), so a long merge or write does not leave the store's bound
    /// full and its new entries unkept.
    fn hold(&mut self, now: u64, entries: &mut dyn Entries) {
        self.look(now, entries);
        let share = entries
            .heap()
            .map_or(0, |Heap { total, .. }| total / RESIDENT_SHARE);
        if self.pressed && (self.held.is_empty() || self.held_bytes < share) {
            self.pressed = false;
            let taken = entries.take_added();
            self.note_added(&taken);
            self.stats.held += u64::from(!taken.is_empty());
            for (key, record) in taken {
                self.held_bytes += record.retained_bytes() as u64;
                match self.held.entry(key) {
                    alloc::collections::btree_map::Entry::Vacant(slot) => {
                        slot.insert(record);
                    }
                    alloc::collections::btree_map::Entry::Occupied(mut slot) => {
                        slot.get_mut().merge(record);
                    }
                }
            }
        }
    }

    /// The plan that writes `change`, which commits once beside the file's
    /// content: `None` when it does not fit so.
    fn plan(&self, change: Change<'a>) -> Option<Box<Execution<'a>>> {
        let plan = journal::plan(
            self.committed.as_ref(),
            JOURNAL_DOMAIN,
            self.translator.0,
            self.file_bytes,
            change,
        );
        let commits = plan
            .steps
            .iter()
            .filter(|step| matches!(step, Step::Commit(_)))
            .count();
        (plan.dropped.is_empty() && commits <= 1).then(|| Box::new(Execution::new(plan)))
    }

    /// The task that writes `layout` as a new segment, if it fits.
    fn write_segment(&self, layout: Arc<Layout<'a>>, trigger: Trigger) -> Option<Task<'a>> {
        let change = Change {
            replace: Vec::new(),
            remove: Vec::new(),
            blobs: vec![Blob {
                kind: SEGMENT_BLOB,
                source: layout.clone(),
            }],
        };
        let execution = self.plan(change)?;
        Some(Task::Write {
            execution,
            done: Done::Segment(layout, trigger),
        })
    }

    /// A write finished: its commit is the file's newest.
    fn finish(&mut self, execution: Box<Execution<'a>>, done: Done<'a>) -> Event {
        if let Some(last) = execution.last() {
            self.committed = Some(last);
        }
        drop(execution);
        match done {
            Done::Segment(layout, trigger) => {
                let (records, bytes) = (layout.records(), layout.bytes());
                self.stats.deltas += 1;
                self.stats.delta_bytes += bytes;
                if !self.released {
                    self.segments.push(Segment::Laid(layout));
                }
                Event::Segment {
                    records,
                    bytes,
                    trigger,
                }
            }
            Done::Merge(layout, Merging::Pair(_)) => {
                self.stats.pairs += 1;
                // Its inputs' records merged anew are the arena's to take back.
                self.arena_full = false;
                if !self.released {
                    self.segments.push(Segment::Laid(layout));
                }
                Event::MergeCommitted { full: false }
            }
            Done::Merge(layout, Merging::Full) => {
                self.stats.merges += 1;
                self.arena_full = false;
                self.merged_since_wait = !self.waiting.is_empty();
                self.segments = if self.released {
                    Vec::new()
                } else {
                    vec![Segment::Laid(layout)]
                };
                self.used.clear();
                Event::MergeCommitted { full: true }
            }
        }
    }

    /// Carry the work forward until `clock` passes `deadline`, or a write
    /// queued its piece (`advance` carries a plan out a piece at a time on
    /// the device, `None` while it cannot). Answers what it did to report.
    pub fn step(
        &mut self,
        clock: &mut dyn FnMut() -> u64,
        deadline: u64,
        entries: &mut dyn Entries,
        advance: &mut dyn FnMut(&mut Execution<'a>) -> Option<Result<bool, String>>,
    ) -> Result<Vec<Event>, String> {
        let mut events = Vec::new();
        if self.failed {
            return Ok(events);
        }
        events.extend(self.govern(entries));
        events.extend(self.settle());
        if self.idle() {
            events.extend(self.begin(clock(), entries));
        } else {
            self.hold(clock(), entries);
        }
        loop {
            self.task = match core::mem::replace(&mut self.task, Task::Idle) {
                Task::Idle => break,
                Task::Delta(mut delta, trigger) => {
                    if !delta.step(STEP_WORK) {
                        Task::Delta(delta, trigger)
                    } else {
                        match delta.finish() {
                            Some(layout) => {
                                let layout = Arc::new(layout);
                                match self.write_segment(layout.clone(), trigger) {
                                    Some(task) => task,
                                    None => {
                                        events.push(Event::Waiting {
                                            records: layout.records(),
                                        });
                                        self.waiting.push(layout);
                                        Task::Idle
                                    }
                                }
                            }
                            None => Task::Idle,
                        }
                    }
                }
                Task::Merge(mut merge, merging) => {
                    let merge_bound = merge.bound();
                    if !merge.step(STEP_WORK) {
                        Task::Merge(merge, merging)
                    } else {
                        let Merged {
                            layout,
                            evicted,
                            expired,
                            invalid,
                        } = merge.finish();
                        events.push(Event::Merged {
                            full: matches!(merging, Merging::Full),
                            records: layout.records(),
                            bytes: layout.bytes(),
                            bound: merge_bound,
                            evicted,
                            expired,
                            invalid,
                        });
                        let layout = Arc::new(layout);
                        // A full merge replaces every segment and list; a
                        // pair, the two it merged.
                        let (replace, remove) = match merging {
                            Merging::Full => (vec![SEGMENT_BLOB, USED_BLOB], Vec::new()),
                            Merging::Pair(offsets) => (Vec::new(), offsets.to_vec()),
                        };
                        let change = Change {
                            replace,
                            remove,
                            blobs: vec![Blob {
                                kind: SEGMENT_BLOB,
                                source: layout.clone(),
                            }],
                        };
                        match self.plan(change) {
                            Some(execution) => Task::Write {
                                execution,
                                done: Done::Merge(layout, merging),
                            },
                            // A pair's records grew past the room for both:
                            // memory holds them merged, the file as they
                            // were, and no pair merges again this boot.
                            None if matches!(merging, Merging::Pair(_)) => {
                                self.segments.push(Segment::Laid(layout));
                                Task::Idle
                            }
                            None => {
                                // The file's newest commit is untouched: only
                                // this boot's merge found no room. Keep the
                                // writer alive so the stop and later segments
                                // still reach the file, and merge no more.
                                self.partial = true;
                                events.push(Event::MergeLeftOut {
                                    records: layout.records(),
                                    bytes: layout.bytes(),
                                });
                                Task::Idle
                            }
                        }
                    }
                }
                Task::Write {
                    mut execution,
                    done,
                } => {
                    match advance(&mut execution) {
                        Some(Ok(true)) => events.push(self.finish(execution, done)),
                        Some(Err(error)) => {
                            // Keep the write: the stop carries the same
                            // execution out on the partition directly, where
                            // a queue that failed while the guest ran need
                            // not fail.
                            self.failed = true;
                            self.task = Task::Write { execution, done };
                            return Err(error);
                        }
                        None | Some(Ok(false)) => self.task = Task::Write { execution, done },
                    }
                    break;
                }
            };
            if clock() >= deadline {
                break;
            }
        }
        Ok(events)
    }

    /// At a stop: finish a new segment's write in flight (`run` carries a
    /// plan out whole), leave a merge not yet committed, then write a new
    /// segment of what is left with the waiting ones, while slots last, and
    /// this boot's used-key list.
    pub fn stop(
        &mut self,
        entries: &mut dyn Entries,
        run: &mut dyn FnMut(&mut Execution<'a>) -> Result<(), String>,
    ) -> Result<Stopped, String> {
        let mut stopped = Stopped::default();
        // A write that failed while the guest ran is carried out here, on
        // the partition directly: a queue that failed then need not fail
        // now, and the file keeps its newest commit whole if this fails too.
        let mut layouts: Vec<Layout<'a>> = Vec::new();
        match core::mem::replace(&mut self.task, Task::Idle) {
            Task::Write {
                mut execution,
                done: done @ Done::Segment(..),
            } => {
                run(&mut execution)?;
                self.finish(execution, done);
            }
            Task::Delta(delta, _) => layouts.extend(delta.finish()),
            Task::Merge(..) | Task::Write { .. } => stopped.merge_left = true,
            Task::Idle => {}
        }
        let mut added = core::mem::take(&mut self.held);
        self.held_bytes = 0;
        let taken = entries.take_added();
        self.note_added(&taken);
        join(&mut added, taken);
        layouts.extend(Delta::new(self.translator, added).finish());
        let mut change = Change::default();
        let room = MAX_SEGMENTS.saturating_sub(self.count(SEGMENT_BLOB));
        let waiting = core::mem::take(&mut self.waiting);
        let mut segments = waiting
            .iter()
            .map(|layout| Blob {
                kind: SEGMENT_BLOB,
                source: layout.clone(),
            })
            .chain(
                layouts
                    .into_iter()
                    .map(|layout| Blob::new(SEGMENT_BLOB, layout)),
            );
        for blob in segments.by_ref().take(room) {
            change.blobs.push(blob);
        }
        stopped.lost = segments.count();
        stopped.records = self.added_keys.len().min(MAX_USED_KEYS + 1);
        if self.count(USED_BLOB) < MAX_USED_LISTS {
            let list = self.used_list(entries.found_keys());
            change.blobs.push(Blob::new(USED_BLOB, list));
        }
        stopped.bytes = change.blobs.iter().map(Blob::length).sum();
        let mut execution = self
            .plan(change)
            .ok_or_else(|| String::from("the stop's blobs found no room in the file"))?;
        run(&mut execution)?;
        if let Some(last) = execution.last() {
            self.committed = Some(last);
        }
        stopped.segments = self.count(SEGMENT_BLOB);
        stopped.lists = self.count(USED_BLOB);
        Ok(stopped)
    }
}

#[cfg(test)]
mod tests;

/// Add `from`'s entries to `into`'s.
fn join(into: &mut BTreeMap<Digest, Record>, from: BTreeMap<Digest, Record>) {
    for (key, record) in from {
        match into.entry(key) {
            alloc::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(record);
            }
            alloc::collections::btree_map::Entry::Occupied(mut slot) => {
                slot.get_mut().merge(record)
            }
        }
    }
}
