//! `stela.efi`'s persistent translation store: the pack file `stela`
//! makes room for in `stela/store` on the boot USB's FAT32 data partition.
//!
//! The file is a journal (`stela_formats::journal`) of pack segments and of
//! used-key lists, one per boot (`translations::pack`): an update writes
//! only into space the newest commit does not use and then commits, so a
//! write cut by a power loss, a panic or a forced stop leaves the previous
//! content whole.
//!
//! Before boot services end, [`read`] finds the volume with `store.cfg`,
//! gives this translator the preallocated spare file when it has no pack
//! yet, reads the newest commit's segments and lists, as many segments as
//! this PC's RAM budget holds (the newest first), and notes the volume's GPT
//! partition. The engine reads blocks from the segments ([`install`]), a
//! key's record merged from all that hold it, and keeps the stored form of
//! each block it compiles anew. While the guest runs, [`step`] writes those
//! entries to the file as new segments and, every few boots, merges the
//! segments and lists into one, a bounded step at a time on processors whose
//! guest waits; when the guest restarts or powers off, [`write`] writes what
//! is left and this boot's used-key list. The pack is a cache: every failure
//! leaves the boot running without a store, or without writing it.
//!
//! When every PE runs on its own host core (the default), their machines
//! share the store ([`Shared`]), split by page key into parts behind locks
//! of their own, and it keeps the blocks any of them compiled for the others
//! to install ([`share`]).
use super::bundle::Bytes;
use super::store_file::{Direct, Held, Queued, Staged};
use crate::{firmware, handoff::Region, output, paging::PAGE};
use alloc::{boxed::Box, collections::BTreeMap, format, string::String, vec, vec::Vec};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
};
use stela_boot_core::host_memory::PACK_FLOOR;
use stela_crypto::{Sha256, digest::Digest as _};
use stela_drivers::block::BlockDevice;
use stela_engine::machine::Offer;
use stela_engine::machine::Translations;
use stela_engine::machine::engine::StoreEvent;
use stela_engine::translations;
use stela_engine::translations::Digest;
use stela_engine::translations::pack;
use stela_engine::translations::pack::{DecodedRecord, Pack, StagedOffer, Store, UsedKeys};
use stela_engine::translations::writer::{self, Entries, Event, Writer};
use stela_engine::translations::{Record, StoredRecord};
use stela_formats::journal::{self, Commit, DATA_START, SLOT_BYTES};
use stela_formats::payload::pieces::Extent;
use stela_runtime::pc::fat32::Fat32;
use stela_runtime::pc::gpt::Guid;
use stela_runtime::translation_store;
use uefi::{
    CString16, boot,
    proto::{
        device_path::{DevicePath, DevicePathNodeEnum, media::PartitionSignature},
        media::{
            file::{Directory, File as _, FileAttribute, FileInfo, FileMode, RegularFile},
            fs::SimpleFileSystem,
        },
    },
};

/// The handoff file holding the store's placement and what was read of its
/// pack file.
pub const FILE: &str = "translations";
/// The store's directory on its volume, and `stela`'s bound there.
pub(super) const DIRECTORY: &str = "stela\\store";
const CONFIG: &str = "store.cfg";
const BYTES_KEY: &str = "bytes";
const CONFIG_LIMIT: usize = 256;
/// A pack file's name: the first bytes of its translator id in hex, an 8.3
/// name the FAT32 reader finds.
const NAME_BYTES: usize = 4;
const PACK_EXTENSION: &str = "pak";
/// A blank, preallocated pack file `stela` keeps beside the packs: a
/// new translator's pack takes it by rename. The boot never grows a file,
/// which the firmware does by writing every byte.
const SPARE: &str = "spare.bin";
/// The pack is read in steps of this many bytes, each shown as progress.
const PROGRESS_STEP: usize = 16 << 20;
/// The journal's domain, and the kinds of its blobs: pack segments and
/// used-key lists.
const DOMAIN: [u8; 8] = pack::JOURNAL_DOMAIN;
const SEGMENT: u32 = pack::SEGMENT_BLOB;
const USED: u32 = pack::USED_BLOB;
/// The placement record at the start of the handoff file: magic, the bound
/// the engine writes within, partition GUID, flags, the commit's entry
/// count and the file's size. The commit's slot ([`SLOT_BYTES`], zeros for
/// none), the bytes held of each entry and those bytes, each from an 8-byte
/// boundary, follow.
const PLACEMENT_MAGIC: [u8; 8] = *b"STLTSTO2";
const PLACEMENT_BYTES: usize = 64;
/// The pack file holds the bound's bytes and its volume's partition is
/// known: the engine may write it.
const WRITABLE: u32 = 1;
/// A segment was left out or cut to the budget: a merge would lose what
/// was not read, so none runs.
const PARTIAL: u32 = 2;
/// The words of the buffer a renamed file's `FileInfo` is built in: its
/// fixed fields and an 8.3 name.
const FILE_INFO_WORDS: usize = 64;

/// The pack file's name in the store's directory.
fn pack_name(translator: &Digest) -> String {
    format!("{}.{PACK_EXTENSION}", hex(&translator.0[..NAME_BYTES]))
}

/// The pack file's path, with `separator` between components.
fn pack_path(translator: &Digest, separator: &str) -> String {
    format!(
        "{}{separator}{}",
        DIRECTORY.replace('\\', separator),
        pack_name(translator)
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn open(root: &mut Directory, path: &str, mode: FileMode) -> Option<RegularFile> {
    let path = CString16::try_from(path).ok()?;
    root.open(&path, mode, FileAttribute::empty())
        .ok()?
        .into_regular_file()
}

/// Read `buffer.len()` bytes from the current file position.
pub(super) fn read_exact(file: &mut RegularFile, buffer: &mut [u8]) -> Option<()> {
    let mut done = 0;
    while done < buffer.len() {
        let count = file.read(&mut buffer[done..]).ok()?;
        if count == 0 {
            return None;
        }
        done += count;
    }
    Some(())
}

/// `buffer.len()` bytes from `offset`.
fn read_at(file: &mut RegularFile, offset: u64, buffer: &mut [u8]) -> Option<()> {
    file.set_position(offset).ok()?;
    read_exact(file, buffer)
}

/// `store.cfg`'s bound.
pub(super) fn bound(root: &mut Directory) -> Option<u64> {
    let mut file = open(root, &format!("{DIRECTORY}\\{CONFIG}"), FileMode::Read)?;
    let mut text = vec![0; CONFIG_LIMIT];
    let mut done = 0;
    while done < text.len() {
        let count = file.read(&mut text[done..]).ok()?;
        if count == 0 {
            break;
        }
        done += count;
    }
    core::str::from_utf8(&text[..done])
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix(BYTES_KEY)?.trim().parse().ok())
}

/// The GPT partition GUID of the volume on `handle`.
pub(crate) fn partition(handle: uefi::Handle) -> Option<[u8; 16]> {
    // SAFETY: the path is only read, while no driver changes this handle.
    let path = unsafe {
        boot::open_protocol::<DevicePath>(
            boot::OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            boot::OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()?;
    path.node_iter().find_map(|node| match node.as_enum() {
        Ok(DevicePathNodeEnum::MediaHardDrive(drive)) => match drive.partition_signature() {
            PartitionSignature::Guid(guid) => Some(guid.to_bytes()),
            _ => None,
        },
        _ => None,
    })
}

/// What the loader read of the store's pack segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackRead {
    /// No pack yet, or one the engine would discard.
    None,
    /// All of the segments' `0` bytes.
    Whole(u64),
    /// `read` of their `held` bytes: the newest segments, and of the next
    /// the records that end within this PC's budget.
    Part { read: u64, held: u64 },
    /// None of it: this PC's budget holds less than the newest segment's
    /// index, or none at all. The pack stays on the volume, unwritten, for
    /// a PC with more RAM.
    Skipped,
}

/// The store the loader found: the handoff file's pages, whether the engine
/// can write its pack file, and what of the pack it read.
pub struct Opened {
    pub region: Region,
    pub writable: bool,
    pub pack: PackRead,
}

/// The store on the first volume with `store.cfg`, as the handoff file's
/// pages: run before boot services end, with no volume opened exclusively.
/// `budget` is the most of the pack this PC's RAM holds
/// (`host_memory::pack_budget`); the pack is read within it and the engine
/// merges it within it, so that it does not grow past what the next boot on
/// this PC can read. `None` when no volume has a store.
pub fn read(budget: u64) -> Option<Opened> {
    let translator = translations::translator_id();
    for handle in boot::find_handles::<SimpleFileSystem>().ok()? {
        let Ok(mut volume) = boot::open_protocol_exclusive::<SimpleFileSystem>(handle) else {
            continue;
        };
        let Ok(mut root) = volume.open_volume() else {
            continue;
        };
        // The file's size, which `stela` allocated.
        let Some(bound) = bound(&mut root) else {
            continue;
        };
        let limit = bound.min(budget);
        let path = pack_path(&translator, "\\");
        if open(&mut root, &path, FileMode::Read).is_none() {
            claim_spare(&mut root, &translator);
        }
        // A read-only volume's pack is read and never written; a missing
        // one leaves the boot's translations in memory.
        let opened = open(&mut root, &path, FileMode::ReadWrite)
            .map(|file| (file, true))
            .or_else(|| open(&mut root, &path, FileMode::Read).map(|file| (file, false)));
        let partition = partition(handle);
        let reading = output::now();
        let (loaded, size, allocated) = match opened {
            Some((mut file, writable)) => {
                let size = file
                    .get_boxed_info::<FileInfo>()
                    .map_or(0, |info| info.file_size());
                let allocated = writable && size >= bound;
                // A pack the boot may write gets the rest of its limit as
                // the arena its new segments' records move to.
                let arena = allocated && partition.is_some() && limit >= PACK_FLOOR;
                let loaded = read_journal(&mut file, &translator, size, limit, arena)?;
                (loaded, size, allocated)
            }
            None => (blank()?, 0, false),
        };
        let (read, held) = match loaded.pack {
            PackRead::None | PackRead::Skipped => (0, 0),
            PackRead::Whole(bytes) => (bytes, bytes),
            PackRead::Part { read, held } => (read, held),
        };
        output::arguments(format_args!(
            "TRANSLATIONS {path} bound={bound} budget={budget} file={size} segments={} of {} \
             lists={} pack={read} held={held} skipped={} allocated={allocated} partition={} \
             read_ms={}\n",
            loaded.segments.0,
            loaded.segments.1,
            loaded.lists,
            loaded.pack == PackRead::Skipped,
            partition.is_some(),
            output::millis_since(reading)
        ));
        // Below the floor, or with its pack left for a larger PC, the boot
        // keeps its translations in memory.
        let writable = allocated
            && partition.is_some()
            && limit >= PACK_FLOOR
            && loaded.pack != PackRead::Skipped;
        let flags = if writable { WRITABLE } else { 0 } | if loaded.partial { PARTIAL } else { 0 };
        // SAFETY: the exclusive loader allocation starts with the placement
        // header, which `read_journal` and `blank` left zero.
        let placement = unsafe {
            core::slice::from_raw_parts_mut(loaded.region.physical as *mut u8, PLACEMENT_BYTES)
        };
        placement[..8].copy_from_slice(&PLACEMENT_MAGIC);
        placement[8..16].copy_from_slice(&limit.to_le_bytes());
        placement[16..32].copy_from_slice(&partition.unwrap_or_default());
        placement[32..36].copy_from_slice(&flags.to_le_bytes());
        placement[40..48].copy_from_slice(&size.to_le_bytes());
        return Some(Opened {
            region: loaded.region,
            writable,
            pack: loaded.pack,
        });
    }
    None
}

/// Give `translator` the spare pack file by renaming it, when the store
/// has one: the file keeps its preallocated clusters.
fn claim_spare(root: &mut Directory, translator: &Digest) {
    let Some(mut file) = open(root, &format!("{DIRECTORY}\\{SPARE}"), FileMode::ReadWrite) else {
        return;
    };
    let Ok(info) = file.get_boxed_info::<FileInfo>() else {
        return;
    };
    let Ok(name) = CString16::try_from(pack_name(translator).as_str()) else {
        return;
    };
    let mut storage = vec![0u64; FILE_INFO_WORDS];
    // SAFETY: the words' bytes, 8-byte aligned as FileInfo requires.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), storage.len() * 8)
    };
    let Ok(renamed) = FileInfo::new(
        bytes,
        info.file_size(),
        info.physical_size(),
        *info.create_time(),
        *info.last_access_time(),
        *info.modification_time(),
        info.attribute(),
        &name,
    ) else {
        return;
    };
    let claimed = file.set_info(renamed).is_ok() && file.flush().is_ok();
    output::arguments(format_args!(
        "TRANSLATIONS spare {} as {name}\n",
        if claimed { "taken" } else { "refused" }
    ));
}

/// What [`read_journal`] read: the handoff region (its placement left
/// zero), the segments read of those committed, the used-key lists read,
/// and whether a segment was left out or cut.
struct Loaded {
    region: Region,
    pack: PackRead,
    segments: (usize, usize),
    lists: usize,
    partial: bool,
}

/// A handoff region of a placement and a blank commit slot.
fn blank() -> Option<Loaded> {
    let bytes = PLACEMENT_BYTES + SLOT_BYTES as usize;
    let physical = firmware::pages(bytes.div_ceil(PAGE)).ok()?;
    // SAFETY: firmware returned this exclusive allocation of `bytes` or more.
    unsafe { (physical as *mut u8).write_bytes(0, bytes) };
    Some(Loaded {
        region: Region {
            physical: physical as u64,
            bytes: bytes as u64,
        },
        pack: PackRead::None,
        segments: (0, 0),
        lists: 0,
        partial: false,
    })
}

/// Read the newest commit of the pack file of `size` bytes directly into
/// the handoff region: every used-key list, checked, and the segments, the
/// newest first, while they fit `limit`; of the first that does not, its
/// records that end within what is left, its index trimmed to name only
/// them (`translation_store::within`). Segments are not checked whole here:
/// a pack checks its index, and each record its own bytes when first used.
/// With `arena`, the region holds `limit` bytes of blobs in all: the room
/// the pack read leaves is the writer's arena ([`pack::Arena`]), outside
/// the heap as the pack is. `None` only when no memory is left for the
/// region.
fn read_journal(
    file: &mut RegularFile,
    translator: &Digest,
    size: u64,
    limit: u64,
    arena: bool,
) -> Option<Loaded> {
    let mut slots = vec![0; DATA_START as usize];
    let commit = if size >= DATA_START && read_exact(file, &mut slots).is_some() {
        journal::candidates(&slots, DOMAIN, size).into_iter().next()
    } else {
        None
    };
    drop(slots);
    let entries: &[journal::Entry] = match &commit {
        Some(commit) if commit.key == translator.0 => &commit.entries,
        _ => &[],
    };
    // What to hold of each entry: every list, and segments within the room
    // the lists leave, the newest first.
    let mut held: Vec<u64> = vec![0; entries.len()];
    let lists: u64 = entries
        .iter()
        .filter(|entry| entry.kind == USED)
        .map(|entry| entry.length)
        .sum();
    let mut room = limit.saturating_sub(lists);
    let mut partial = false;
    let mut trimmed: Option<(usize, Vec<u8>)> = None;
    for (index, entry) in entries.iter().enumerate().rev() {
        match entry.kind {
            USED => held[index] = entry.length,
            SEGMENT if partial => {}
            SEGMENT if entry.length <= room => {
                held[index] = entry.length;
                room -= entry.length;
            }
            SEGMENT => {
                partial = true;
                if let Some((length, prefix)) = segment_within(file, entry, translator, room) {
                    held[index] = length;
                    trimmed = Some((index, prefix));
                }
            }
            _ => {}
        }
    }
    let blobs: usize = held
        .iter()
        .map(|&length| (length as usize).next_multiple_of(8))
        .sum();
    let head = PLACEMENT_BYTES + SLOT_BYTES as usize + 8 * entries.len();
    let spare = if arena {
        usize::try_from(limit)
            .unwrap_or(usize::MAX)
            .saturating_sub(blobs)
            / PAGE
            * PAGE
    } else {
        0
    };
    let bytes = head + blobs + spare;
    let pages = bytes.div_ceil(PAGE);
    let physical = firmware::pages(pages).ok()?;
    // SAFETY: firmware returned this exclusive allocation of `bytes` or
    // more. Initialize it before taking a mutable slice.
    let region = unsafe {
        let start = physical as *mut u8;
        start.write_bytes(0, bytes);
        core::slice::from_raw_parts_mut(start, bytes)
    };
    if let Some(commit) = &commit {
        region[PLACEMENT_BYTES..PLACEMENT_BYTES + SLOT_BYTES as usize]
            .copy_from_slice(&commit.encode());
    }
    region[36..40].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    let total = blobs >> 20;
    let mut at = head;
    let mut done = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        let length = held[index] as usize;
        if length == 0 {
            continue;
        }
        let blob = &mut region[at..at + length];
        let mut from = 0;
        if let Some((_, prefix)) = trimmed.as_ref().filter(|(trim, _)| *trim == index) {
            blob[..prefix.len()].copy_from_slice(prefix);
            from = prefix.len();
        }
        let mut whole = true;
        for part in blob[from..].chunks_mut(PROGRESS_STEP) {
            if read_at(file, entry.offset + from as u64, part).is_none() {
                whole = false;
                break;
            }
            from += part.len();
            done += part.len();
            crate::status::progress(&format!("{} of {total} MB", done >> 20));
        }
        whole &= match entry.kind {
            USED => Sha256::digest(&*blob)[..] == entry.digest,
            _ => true,
        };
        if !whole {
            partial |= entry.kind == SEGMENT;
            held[index] = 0;
        } else if trimmed.as_ref().is_some_and(|(trim, _)| *trim == index) {
            translation_store::trim(blob);
        }
        at += length.next_multiple_of(8);
    }
    for (index, &length) in held.iter().enumerate() {
        let at = head - 8 * (entries.len() - index);
        region[at..at + 8].copy_from_slice(&length.to_le_bytes());
    }
    let segment = |index: usize| entries[index].kind == SEGMENT;
    let (mut read, mut whole, mut segments, mut committed) = (0, 0, 0, 0);
    for (index, &length) in held.iter().enumerate().filter(|(index, _)| segment(*index)) {
        committed += 1;
        whole += entries[index].length;
        if length != 0 {
            segments += 1;
            read += length;
        }
    }
    let pack = match () {
        () if committed == 0 => PackRead::None,
        () if segments == 0 => PackRead::Skipped,
        () if partial => PackRead::Part { read, held: whole },
        () => PackRead::Whole(read),
    };
    Some(Loaded {
        region: Region {
            physical: physical as u64,
            bytes: bytes as u64,
        },
        pack,
        segments: (segments, committed),
        lists: held
            .iter()
            .enumerate()
            .filter(|&(index, &length)| !segment(index) && length != 0)
            .count(),
        partial,
    })
}

/// Of the segment `entry` names, the bytes that hold its records ending
/// within `room`, and its header and index: `None` when none does or its
/// index fails the checks `Pack::parse` makes.
fn segment_within(
    file: &mut RegularFile,
    entry: &journal::Entry,
    translator: &Digest,
    room: u64,
) -> Option<(u64, Vec<u8>)> {
    let mut header = [0; pack::HEADER_BYTES];
    read_at(file, entry.offset, &mut header)?;
    let prefix_length = pack::prefix_bytes(&header, translator).ok()?;
    if prefix_length as u64 > room || prefix_length as u64 > entry.length {
        return None;
    }
    let mut prefix = vec![0; prefix_length];
    prefix[..header.len()].copy_from_slice(&header);
    read_exact(file, &mut prefix[header.len()..])?;
    let within = translation_store::within(&prefix, translator, room).ok()?;
    (within.records != 0 && within.length <= entry.length).then_some((within.length, prefix))
}

/// The boot's translator and the store's partition. Its parts ([`PARTS`])
/// hold the store itself.
struct Boot {
    translator: Digest,
    partition: Option<Box<dyn BlockDevice>>,
}

/// The parts a boot's store is split into by page key, each behind a lock
/// of its own, so that PEs looking up, sharing and offering blocks of
/// different pages do not wait for each other.
const PARTS: usize = 16;

/// A spin lock that counts how often it was found held and how long its
/// waiters spun.
#[repr(align(64))]
struct Lock<T> {
    held: AtomicBool,
    value: UnsafeCell<T>,
    acquired: AtomicU64,
    contended: AtomicU64,
    spun: AtomicU64,
}
// SAFETY: `with` holds `held` for every access to `value`.
unsafe impl<T> Sync for Lock<T> {}

impl<T> Lock<T> {
    const fn new(value: T) -> Self {
        Self {
            held: AtomicBool::new(false),
            value: UnsafeCell::new(value),
            acquired: AtomicU64::new(0),
            contended: AtomicU64::new(0),
            spun: AtomicU64::new(0),
        }
    }

    /// Run `f` on the value, alone. No interrupt handler reaches it.
    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        if self
            .held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            let started = output::now();
            while self
                .held
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                while self.held.load(Ordering::Relaxed) {
                    core::hint::spin_loop();
                }
            }
            self.contended.fetch_add(1, Ordering::Relaxed);
            self.spun
                .fetch_add(output::now().wrapping_sub(started), Ordering::Relaxed);
        }
        self.acquired.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `held` excludes every other access until it is released.
        let result = f(unsafe { &mut *self.value.get() });
        self.held.store(false, Ordering::Release);
        result
    }
}

static BOOT: Lock<Option<Boot>> = Lock::new(None);
static STORES: [Lock<Option<Store<'static>>>; PARTS] = [const { Lock::new(None) }; PARTS];

/// The part of the store that holds the page whose bytes hash to `key`.
fn part(key: &Digest) -> &'static Lock<Option<Store<'static>>> {
    &STORES[usize::from(key.0[2]) % PARTS]
}

/// Keep the store's capabilities off the locks' cache lines so a PE can
/// skip operations that have no backing without contending with its users.
#[repr(align(64))]
struct Available {
    capabilities: AtomicU8,
    /// A preflight limit for staging. Admission checks the live store bound.
    shared_bound: AtomicUsize,
    /// The fetch pages the machines keep in all ([`Translations::kept_pages`]).
    kept_pages: AtomicUsize,
    /// The writer sheds new entries, the heap being short
    /// ([`writer::Entries::shed`]): offers skip making their stored form.
    shed: AtomicBool,
}

static AVAILABLE: Available = Available {
    capabilities: AtomicU8::new(0),
    shared_bound: AtomicUsize::new(0),
    kept_pages: AtomicUsize::new(0),
    shed: AtomicBool::new(false),
};
const READ_PACK: u8 = 1 << 0;
const WRITE_PACK: u8 = 1 << 1;
const SHARE_BLOCKS: u8 = 1 << 2;

fn available(capabilities: u8) -> bool {
    AVAILABLE.capabilities.load(Ordering::Acquire) & capabilities != 0
}

/// What the machines' use of the store cost, beyond the parts' counters:
/// fetch pages read and hashed for their records and the engine counter
/// ticks that took, shared blocks found but not installed, and the TSC
/// ticks record lookups took through the store and decoding records.
struct Costs {
    page_reads: AtomicU64,
    page_ticks: AtomicU64,
    shared_rejected: AtomicU64,
    lookups: AtomicU64,
    lookup_ticks: AtomicU64,
    decode_ticks: AtomicU64,
}

static COSTS: Costs = Costs {
    page_reads: AtomicU64::new(0),
    page_ticks: AtomicU64::new(0),
    shared_rejected: AtomicU64::new(0),
    lookups: AtomicU64::new(0),
    lookup_ticks: AtomicU64::new(0),
    decode_ticks: AtomicU64::new(0),
};

/// What the store keeps beyond its pack, for an engine heap of `heap` bytes:
/// entries added during the boot, decoded records, and the fetch pages the
/// machines keep (a page and its bookkeeping
/// take about 4.5 KiB).
fn bounds(heap: usize) -> (pack::Bounds, usize) {
    const MIB: usize = 1 << 20;
    let defaults = pack::Bounds::default();
    let bounds = pack::Bounds {
        added: (heap / 32).clamp(defaults.added, 512 * MIB),
        decoded: (heap / 64).clamp(defaults.decoded, 128 * MIB),
    };
    (bounds, (heap / 64 / (4608)).max(4096))
}

/// Make `parts` the store's, over the segments read, sharing up to
/// `shared` bytes of blocks across PEs.
fn install_parts(translator: Digest, segments: Vec<Pack<'static>>, shared: usize) {
    let (bounds, kept_pages) = bounds(crate::ALLOCATOR.usage().total);
    AVAILABLE.kept_pages.store(kept_pages, Ordering::Release);
    let filters = pack::KeyFilters::new(&segments);
    for lock in &STORES {
        let evicted = lock.with(|store| {
            let store = store.get_or_insert_with(|| {
                Store::filtered(translator, segments.clone(), filters.clone())
            });
            store.share(shared / PARTS);
            store.set_bounds(bounds.share(PARTS))
        });
        drop(evicted);
    }
}

/// The engine's view of the boot's store, from any PE's machine.
pub struct Shared;

impl Shared {
    fn publish_shared(offer: Offer) {
        let bound = AVAILABLE.shared_bound.load(Ordering::Acquire) / PARTS;
        let lock = part(&offer.key());
        let Some(mut staged) = StagedOffer::new(offer, bound) else {
            return;
        };
        let retired = lock.with(|store| store.as_mut()?.accept_shared(&mut staged));
        drop(retired);
    }

    /// Keep the offer's stored form, made before the lock is taken, and
    /// share its block.
    fn publish_writable(offer: Offer) {
        let bound = AVAILABLE.shared_bound.load(Ordering::Acquire) / PARTS;
        let lock = part(&offer.key());
        if AVAILABLE.shed.load(Ordering::Relaxed) {
            lock.with(|store| {
                if let Some(store) = store {
                    store.count_shed(&offer);
                }
            });
        } else {
            let entry = offer.entry();
            lock.with(|store| {
                if let Some(store) = store {
                    store.keep(&offer, entry);
                }
            });
        }
        let Some(mut staged) = StagedOffer::new(offer, bound) else {
            return;
        };
        let retired = lock.with(|store| store.as_mut()?.accept_shared(&mut staged));
        drop(retired);
    }
}

impl Translations for Shared {
    /// The pack bytes outlive the lock, so other PEs can reach the store
    /// while a record is decoded. A writer also tracks absent keys.
    fn record(&mut self, key: &Digest) -> Option<alloc::sync::Arc<StoredRecord>> {
        if !available(READ_PACK | WRITE_PACK) {
            return None;
        }
        let started = output::now();
        COSTS.lookups.fetch_add(1, Ordering::Relaxed);
        let lock = part(key);
        let lookup = lock.with(|store| {
            let store = store.as_mut()?;
            if let Some(record) = store.cached_record(key) {
                return Some(Ok(record));
            }
            match store.stored(key) {
                Some(stored) => Some(Err((
                    stored,
                    *store.translator(),
                    store.take_decode_scratch(stored),
                ))),
                None => {
                    store.looked_up(key, false, false);
                    None
                }
            }
        });
        let (stored, translator, mut scratch) = match lookup {
            Some(Ok(record)) => {
                COSTS
                    .lookup_ticks
                    .fetch_add(output::now().wrapping_sub(started), Ordering::Relaxed);
                return Some(record);
            }
            Some(Err(source)) => source,
            None => {
                COSTS
                    .lookup_ticks
                    .fetch_add(output::now().wrapping_sub(started), Ordering::Relaxed);
                return None;
            }
        };
        let decoding = output::now();
        let decoded = DecodedRecord::decode(stored, &translator, key, &mut scratch);
        COSTS
            .decode_ticks
            .fetch_add(output::now().wrapping_sub(decoding), Ordering::Relaxed);
        let evicted = lock.with(|store| {
            let store = store.as_mut()?;
            Some(store.finish_decode(key, stored, &decoded, &mut scratch))
        });
        drop(evicted);
        COSTS
            .lookup_ticks
            .fetch_add(output::now().wrapping_sub(started), Ordering::Relaxed);
        decoded.ok().map(DecodedRecord::into_record)
    }

    fn prepared(
        &mut self,
        key: &Digest,
        pc: u64,
        context: &Digest,
    ) -> Option<alloc::sync::Arc<stela_engine::machine::engine::SharedTranslation>> {
        if !available(SHARE_BLOCKS) {
            return None;
        }
        part(key).with(|store| store.as_mut()?.prepared(key, pc, context))
    }

    fn offer(&mut self, offer: Offer) {
        let capabilities = AVAILABLE.capabilities.load(Ordering::Acquire);
        if capabilities & WRITE_PACK != 0 {
            Self::publish_writable(offer);
        } else if capabilities & SHARE_BLOCKS != 0 {
            Self::publish_shared(offer);
        }
    }

    fn note(&mut self, event: StoreEvent) {
        match event {
            StoreEvent::PageRead { ticks } => {
                COSTS.page_reads.fetch_add(1, Ordering::Relaxed);
                COSTS.page_ticks.fetch_add(ticks, Ordering::Relaxed);
            }
            StoreEvent::SharedRejected => {
                COSTS.shared_rejected.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn kept_pages(&mut self) -> Option<usize> {
        match AVAILABLE.kept_pages.load(Ordering::Acquire) {
            0 => None,
            pages => Some(pages),
        }
    }

    /// A 128th of the heap in page keys of 56 bytes: 2^18 keys (14.7 MB,
    /// the engine's most) from a 1.9 GB heap, enough for twice the distinct
    /// code pages a desktop boot reads.
    fn known_pages(&mut self) -> Option<usize> {
        Some(crate::ALLOCATOR.usage().total / 128 / 56)
    }
}

/// The store the engine uses, if the loader read one or the PEs share one.
pub fn store() -> Option<&'static mut Shared> {
    available(READ_PACK | WRITE_PACK | SHARE_BLOCKS).then(|| Box::leak(Box::new(Shared)))
}

/// Share compiled blocks between PEs, keeping up to `bound` bytes of buffers
/// and cache metadata in the loader's store or a store for this boot. Allocator
/// overhead and shared immutable preparation storage are outside this budget.
pub fn share(bound: usize) {
    BOOT.with(|boot| {
        let translator = boot
            .get_or_insert_with(|| Boot {
                translator: translations::translator_id(),
                partition: None,
            })
            .translator;
        install_parts(translator, Vec::new(), bound);
        AVAILABLE.shared_bound.store(bound, Ordering::Release);
        if bound != 0 {
            AVAILABLE
                .capabilities
                .fetch_or(SHARE_BLOCKS, Ordering::Release);
        } else {
            AVAILABLE
                .capabilities
                .fetch_and(!SHARE_BLOCKS, Ordering::Release);
        }
    });
}

/// Make the store of the handoff file `region` the engine's: the GPT
/// partition to open for writing it, when it can be written. What follows
/// its blobs is the writer's arena.
pub fn install(region: &'static mut [u8]) -> Option<Guid> {
    let head = PLACEMENT_BYTES + SLOT_BYTES as usize;
    if region.len() < head || region[..8] != PLACEMENT_MAGIC {
        return None;
    }
    let word = |at: usize| u32::from_le_bytes(region[at..at + 4].try_into().expect("a word"));
    let count = word(36) as usize;
    // The blobs end where their lengths, after the head, say.
    let lengths = head.checked_add(count.checked_mul(8)?)?;
    let blobs = region
        .get(head..lengths)?
        .as_chunks::<8>()
        .0
        .iter()
        .try_fold(lengths, |at, length| {
            at.checked_add(
                usize::try_from(u64::from_le_bytes(*length))
                    .ok()?
                    .next_multiple_of(8),
            )
        })?
        .min(region.len());
    let (contents, arena) = region.split_at_mut(blobs);
    let contents: &'static [u8] = contents;
    let field = |at: usize| u64::from_le_bytes(contents[at..at + 8].try_into().expect("a field"));
    let word = |at: usize| u32::from_le_bytes(contents[at..at + 4].try_into().expect("a word"));
    let (limit, flags, size) = (field(8), word(32), field(40));
    let translator = translations::translator_id();
    let slot = &contents[PLACEMENT_BYTES..head];
    let committed = (0..2).find_map(|index| Commit::decode(slot, index, DOMAIN, size));
    let mut segments = Vec::new();
    let mut used = Vec::new();
    let mut discarded = 0;
    if let Some(commit) = committed
        .as_ref()
        .filter(|commit| commit.key == translator.0 && commit.entries.len() == count)
    {
        let mut at = head + 8 * count;
        for (index, entry) in commit.entries.iter().enumerate() {
            let length = usize::try_from(field(head + 8 * index)).ok()?;
            let bytes = contents.get(at..at.checked_add(length)?)?;
            at += length.next_multiple_of(8);
            match entry.kind {
                SEGMENT if length != 0 => match Pack::parse(bytes, &translator) {
                    Ok(pack) => segments.push(pack),
                    Err(error) => {
                        output::arguments(format_args!(
                            "TRANSLATIONS segment discarded: {error:?}\n"
                        ));
                        discarded += 1;
                    }
                },
                USED if length != 0 => match UsedKeys::parse(bytes, &translator) {
                    Some(list) => used.push(list),
                    None => discarded += 1,
                },
                _ => {}
            }
        }
    }
    let partial = flags & PARTIAL != 0;
    output::arguments(format_args!(
        "TRANSLATIONS pack segments={} records={} bytes={} lists={} discarded={discarded} \
         partial={partial}\n",
        segments.len(),
        segments.iter().map(Pack::records).sum::<usize>(),
        segments.iter().map(Pack::bytes).sum::<usize>(),
        used.len(),
    ));
    let readable = if segments.is_empty() { 0 } else { READ_PACK };
    let file = writer::File {
        translator,
        limit,
        file_bytes: size,
        committed,
        segments: segments.clone(),
        used,
        partial,
        arena: pack::Arena::new(arena),
    };
    let held = PackWriter {
        writer: Writer::new(file, super::host::COUNTER_HZ),
        extents: None,
        queued: Queued::default(),
        steps: 0,
        longest: 0,
    };
    WRITER.holding(true, |slot| *slot = Some(held));
    BOOT.with(|boot| {
        for lock in &STORES {
            let old = lock.with(Option::take);
            drop(old);
        }
        install_parts(translator, segments, 0);
        *boot = Some(Boot {
            translator,
            partition: None,
        });
        AVAILABLE.shared_bound.store(0, Ordering::Release);
        AVAILABLE.capabilities.store(readable, Ordering::Release);
    });
    let partition = Guid(contents[16..32].try_into().expect("a GUID"));
    (flags & WRITABLE != 0).then_some(partition)
}

/// Whether the store's partition is staged ([`super::storage::try_stage`]):
/// its commands then queue, and processors step its I/O in bounded steps.
static PARTITION_STAGED: AtomicBool = AtomicBool::new(false);

/// Keep `partition`, the store's volume, for the writes, staged when a
/// slot is free, and find the pack file's device extents while its drivers
/// may still be called directly: the writes while the guest runs only
/// queue.
pub fn set_partition(partition: Box<dyn BlockDevice>) {
    let partition = match super::storage::try_stage(partition) {
        Ok(staged) => {
            PARTITION_STAGED.store(true, Ordering::Release);
            staged
        }
        Err(unstaged) => unstaged,
    };
    let translator = BOOT.with(|boot| {
        let boot = boot.as_mut()?;
        boot.partition = Some(partition);
        AVAILABLE
            .capabilities
            .fetch_or(WRITE_PACK, Ordering::Release);
        Some(boot.translator)
    });
    let Some(translator) = translator else {
        return;
    };
    let extents = with_store_file(&pack_name(&translator), |_, extents| extents.to_vec());
    WRITER.with(|held| match extents {
        Ok(extents) => held.extents = Some(extents),
        Err(error) => {
            output::arguments(format_args!(
                "TRANSLATIONS written only at a stop: {error}\n"
            ));
        }
    });
}

/// Run `f` on the store's partition with the device extents of `name`, a
/// file in the store's directory. Only while the engine may write the
/// store.
pub fn with_store_file<R>(
    name: &str,
    f: impl FnOnce(&mut dyn BlockDevice, &[Extent]) -> R,
) -> Result<R, String> {
    BOOT.with(|boot| {
        let boot = boot.as_mut().ok_or("no translation store")?;
        let partition = boot
            .partition
            .take()
            .ok_or("the store's partition is not open")?;
        let mut volume = Fat32::open(Bytes::new(partition)).map_err(|error| format!("{error}"))?;
        let file = volume.file(&format!("{}/{name}", DIRECTORY.replace('\\', "/")));
        let mut device = volume.into_inner().into_inner();
        let result = file
            .map(|file| f(&mut *device, &file.extents))
            .map_err(|error| format!("{error}"));
        boot.partition = Some(device);
        result
    })
}

/// Lend the store's partition to `f` while the guest runs, for background
/// writes: staged, so `f` only queues commands (`BlockDevice::start`) and
/// takes results (`finish`), never waiting for the disk. The pack file and
/// the pipeline store share it. `None` when it is absent, lent, or not
/// staged.
pub fn lend_staged_partition<R>(f: impl FnOnce(&mut dyn BlockDevice) -> R) -> Option<R> {
    if !PARTITION_STAGED.load(Ordering::Acquire) {
        return None;
    }
    BOOT.with(|boot| {
        let partition = boot.as_mut()?.partition.as_deref_mut()?;
        Some(f(partition))
    })
}

/// Milliseconds of `ticks` TSC ticks.
fn millis(ticks: u64) -> u64 {
    output::millis_since(output::now().wrapping_sub(ticks))
}

/// Report what the store did and cost this boot: lookups and their causes,
/// shared misses by reason, stored forms kept and checked, and lock waits.
fn report(counters: &pack::Counters) {
    let costs = &COSTS;
    let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
    output::arguments(format_args!(
        "TRANSLATIONS lookups={} repeated={} cached={} decoded={} lookup_ms={} decode_ms={} \
         pages={} page_ms={}\n",
        load(&costs.lookups),
        counters.repeated,
        counters.cached,
        counters.decoded,
        millis(load(&costs.lookup_ticks)),
        millis(load(&costs.decode_ticks)),
        load(&costs.page_reads),
        load(&costs.page_ticks) / (super::host::COUNTER_HZ / 1000),
    ));
    output::arguments(format_args!(
        "TRANSLATIONS shared hits={} rejected={} absent={} other_context={} evicted={} \
         in_flight={}\n",
        counters.shared_hits,
        load(&costs.shared_rejected),
        counters.shared_absent,
        counters.shared_other_context,
        counters.shared_evicted,
        counters.shared_in_flight,
    ));
    let (mut acquired, mut contended, mut spun) = (0, 0, 0);
    for lock in &STORES {
        acquired += load(&lock.acquired);
        contended += load(&lock.contended);
        spun += load(&lock.spun);
    }
    let checks = stela_engine::machine::entry_checks();
    output::arguments(format_args!(
        "TRANSLATIONS added={} unstorable={} unkept={} unkept_entries={} retaken={} shed={} \
         checked={} differed={} loaded={} absent={} invalid={} locks acquired={acquired} \
         contended={contended} spin_ms={}\n",
        counters.added,
        counters.unstorable,
        counters.unkept,
        counters.unkept_entries,
        counters.retaken,
        counters.shed,
        checks.checked,
        checks.differed,
        counters.loaded,
        counters.absent,
        counters.invalid,
        millis(spun),
    ));
}

/// How long a step may take, in microseconds.
const STEP_MICROS: u64 = 1000;

/// The pack file's writer (`translations::writer`) with what the boot adds:
/// the file's device extents, found while the drivers may be called, the
/// staged commands of the write in flight, and the steps it took.
struct PackWriter {
    writer: Writer<'static>,
    extents: Option<Vec<Extent>>,
    queued: Queued,
    steps: u64,
    longest: u64,
}

static WRITER: Held<PackWriter> = Held::new();

/// The store's parts, as the writer sees them.
struct Parts;

impl Entries for Parts {
    fn take_added(&mut self) -> BTreeMap<Digest, Record> {
        let mut added = BTreeMap::new();
        for lock in &STORES {
            let mut part =
                lock.with(|store| store.as_mut().map(Store::take_added).unwrap_or_default());
            added.append(&mut part);
        }
        added
    }

    fn found_keys(&mut self) -> Vec<Digest> {
        let mut keys = Vec::new();
        for lock in &STORES {
            lock.with(|store| {
                if let Some(store) = store {
                    keys.extend(store.used_keys().copied());
                }
            });
        }
        keys
    }

    fn added(&mut self) -> u64 {
        STORES
            .iter()
            .map(|lock| lock.with(|store| store.as_ref().map_or(0, |store| store.counters.added)))
            .sum()
    }

    fn pressed(&mut self) -> bool {
        STORES
            .iter()
            .any(|lock| lock.with(|store| store.as_ref().is_some_and(Store::added_pressed)))
    }

    fn heap(&mut self) -> Option<writer::Heap> {
        Some(writer::Heap {
            total: crate::ALLOCATOR.total() as u64,
            room: crate::ALLOCATOR.room() as u64,
        })
    }

    fn added_bytes(&mut self) -> u64 {
        STORES
            .iter()
            .map(|lock| lock.with(|store| store.as_ref().map_or(0, |store| store.added_bytes())))
            .sum::<usize>() as u64
    }

    fn shed(&mut self, shed: bool) {
        AVAILABLE.shed.store(shed, Ordering::Relaxed);
        for lock in &STORES {
            lock.with(|store| {
                if let Some(store) = store {
                    store.shed(shed);
                }
            });
        }
    }
}

/// Report what a writer step did.
fn report_event(event: &Event) {
    match event {
        Event::Segment {
            records,
            bytes,
            trigger,
        } => output::arguments(format_args!(
            "TRANSLATIONS segment records={records} bytes={bytes} trigger={trigger:?}\n"
        )),
        Event::Merged {
            full,
            records,
            bytes,
            bound,
            evicted,
            expired,
            invalid,
        } => output::arguments(format_args!(
            "TRANSLATIONS merged full={full} records={records} bytes={bytes} bound={bound} \
             evicted={evicted} expired={expired} invalid={invalid}\n"
        )),
        Event::MergeCommitted { full } => {
            output::arguments(format_args!("TRANSLATIONS merge written full={full}\n"))
        }
        Event::Waiting { records } => output::arguments(format_args!(
            "TRANSLATIONS segment of {records} records waits for a merge to make room\n"
        )),
        Event::Lost { records } => output::arguments(format_args!(
            "TRANSLATIONS segment of {records} records left out: larger than the file holds\n"
        )),
        Event::Shed {
            reason,
            room,
            pack,
            resident,
        } => output::arguments(format_args!(
            "TRANSLATIONS shed reason={reason:?} room={}M pack={}M resident={}M: new \
             translations are not kept {}\n",
            room.map_or(0, |room| room >> 20),
            pack >> 20,
            resident >> 20,
            match reason {
                writer::ShedReason::Heap => "while the heap is short",
                writer::ShedReason::Pack => "past the share of the pack a boot leaves",
            }
        )),
        Event::ArenaFull { used, resident } => output::arguments(format_args!(
            "TRANSLATIONS arena full used={}M resident={}M: written records stay in the heap, \
             within its share\n",
            used >> 20,
            resident >> 20
        )),
        Event::Released { room, bytes, lost } => output::arguments(format_args!(
            "TRANSLATIONS released room={}M bytes={}M lost={lost}: the heap is nearly full; \
             the segments stay in the file and no more are added this boot\n",
            room >> 20,
            bytes >> 20
        )),
    }
}

/// While the guest runs, from a processor whose guest waits and that holds
/// no device lock: carry the pack file's writer forward for a bounded time
/// ([`STEP_MICROS`]). Never waits for the disk.
pub fn step() {
    if !available(WRITE_PACK) {
        return;
    }
    let started = super::host::fresh_counter();
    WRITER.try_with(|held| {
        let Some(extents) = held.extents.as_deref() else {
            return;
        };
        if held.writer.failed() {
            return;
        }
        let idle = held.writer.idle();
        let deadline = started + super::host::COUNTER_HZ * STEP_MICROS / 1_000_000;
        let queued = &mut held.queued;
        let stepped = held.writer.step(
            &mut super::host::fresh_counter,
            deadline,
            &mut Parts,
            &mut |execution| {
                lend_staged_partition(|device| {
                    let mut target = Staged {
                        device,
                        extents,
                        queued: &mut *queued,
                    };
                    execution.advance(&mut target, writer::PIECE_BYTES)
                })
            },
        );
        match stepped {
            Ok(events) => events.iter().for_each(report_event),
            Err(error) => output::arguments(format_args!("TRANSLATIONS not written: {error}\n")),
        }
        if !idle || !held.writer.idle() {
            let took = super::host::fresh_counter().wrapping_sub(started);
            held.steps += 1;
            held.longest = held.longest.max(took);
        }
    });
}

/// At a quiescent point (the guest restarts or powers off): the writer's
/// stop ([`Writer::stop`]), carried out on the partition directly.
pub fn write() {
    AVAILABLE.capabilities.store(0, Ordering::SeqCst);
    AVAILABLE.shared_bound.store(0, Ordering::Release);
    let started = output::now();
    let held = WRITER.holding(true, Option::take).flatten();
    let writable = BOOT.with(|boot| boot.as_ref().is_some_and(|boot| boot.partition.is_some()));
    if let Some(mut held) = held.filter(|_| writable) {
        let stats = held.writer.stats();
        output::arguments(format_args!(
            "TRANSLATIONS writer steps={} longest_us={} segments={} records={} bytes={} \
             pressed={} held={} pairs={} merges={} sheds={} resident_peak={}M released={} \
             arena={}M/{}M compacted={}/{}M\n",
            held.steps,
            held.longest * 1_000_000 / super::host::COUNTER_HZ,
            stats.deltas,
            stats.delta_records,
            stats.delta_bytes,
            stats.pressed,
            stats.held,
            stats.pairs,
            stats.merges,
            stats.sheds,
            stats.resident_peak >> 20,
            held.writer.shedding().1,
            held.writer.arena().0 >> 20,
            (held.writer.arena().0 + held.writer.arena().1) >> 20,
            stats.compactions,
            stats.compacted >> 20,
        ));
        let name = pack_name(&translations::translator_id());
        let stopped = held.writer.stop(&mut Parts, &mut |execution| {
            with_store_file(&name, |device, extents| {
                let mut target = Direct { device, extents };
                while !execution.advance(&mut target, writer::PIECE_BYTES)? {}
                Ok::<(), String>(())
            })
            .and_then(|done| done)
        });
        match stopped {
            Ok(stopped) => output::arguments(format_args!(
                "TRANSLATIONS written segments={} lists={} records={} lost={} bytes={} \
                 merge_left={} ms={}\n",
                stopped.segments,
                stopped.lists,
                stopped.records,
                stopped.lost,
                stopped.bytes,
                stopped.merge_left,
                output::millis_since(started)
            )),
            Err(error) => output::arguments(format_args!("TRANSLATIONS not written: {error}\n")),
        }
    }
    let mut parts = STORES.iter().filter_map(|lock| lock.with(Option::take));
    if let Some(mut store) = parts.next() {
        for part in parts {
            store.absorb(part);
        }
        report(&store.counters);
    }
    let boot = BOOT.with(Option::take);
    drop(boot);
}
