//! LLB's boot choice, before boot services end: with `--preboot`,
//! `stela.efi` reads the persistent NOR's current NVRAM bank (`--nor
//! SERIAL:GUID`) through the firmware's block I/O, chooses macOS or
//! recoveryOS as `stela_loader::boot_selection` does, removes the one-shot
//! variables that boot consumes (the next bank is saved before the engine
//! reads the NOR, as LLB saves NVRAM before it boots) and hands the engine
//! the options for that boot. A macOS
//! boot whose Preboot disk holds no installed system boots System Recovery
//! instead (missing boot media), as a Mac with an erased disk does. A
//! recoveryOS boot takes the disk's own copy, the paired recoveryOS of the
//! Recovery volume and then System Recovery of the RecoveryOSContainer
//! (`stela_loader::recovery::find`), which the engine builds from the disk.
//! A disk that holds neither boots nothing ([`Refusal::NoRecovery`]): Stela
//! has no recoveryOS of its own, and only Install macOS restores the disk's.
//! NVRAM that holds the machine in iBoot's recovery mode, as an interrupted
//! restore leaves it, boots nothing ([`Refusal::RecoveryMode`]).
//!
//! Each partition is found as the engine finds it: exactly one whole disk
//! reports the serial, and exactly one of its GPT partitions has the GUID;
//! an EFI system partition is refused. A blank NOR partition holds no
//! variables yet: the engine initializes it. When `--nor` names the
//! `--storage` partition, the NOR is the start of that partition's tail
//! (`pc::machine_state`), and the Preboot disk is the rest, as the engine
//! splits it.
//!
//! Nothing here writes a disk: the firmware's block I/O only reads. What a
//! boot changes on a PC disk before the firmware exits is pending work
//! (`pc::disk_writes`), which Stela's drivers do after it: the partition
//! Install macOS's disk picker has just planned, which is not on its disk
//! yet, or not blank yet; the NVRAM bank saved without the consumed
//! variables; a failure record cleared. Every search here takes the pending
//! work and reads a partition as that work leaves it: where the plan puts
//! it, the blocks the plan zeroes reading as zero, and the bytes of the
//! pending updates in place. So a boot routed again after a refusal finds
//! the variables it consumed gone, as it would on the disk.
use crate::Result;
use crate::{
    output,
    payload::{Aligned, device_path, disk_serial},
};
use alloc::string::ToString;
use alloc::{format, string::String, vec, vec::Vec};
use stela_boot_core::chosen_disk::{self, Search, Stale};
use stela_contracts::refusal::Within;
use stela_contracts::refuse;
use stela_loader::{
    boot_selection::{self, BootVolume, Selection},
    mount_interface::ChoiceKind,
    recovery,
};
use uefi::{
    Handle,
    boot::{self, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol},
    proto::media::block::BlockIO,
};
use {
    stela_drivers::block::Extent, stela_formats::apfs, stela_formats::apfs::ApfsError,
    stela_formats::apfs::Container, stela_formats::payload::PayloadError,
    stela_formats::payload::ReadAt, stela_formats::payload::gpt, stela_formats::payload::gpt::Disk,
    stela_formats::payload::gpt::Role, stela_formats::preboot,
    stela_formats::preboot::PrebootError, stela_runtime::pc::disk_plan::Plan,
    stela_runtime::pc::disk_writes::Pending, stela_runtime::pc::disk_writes::Piece,
    stela_runtime::pc::disk_writes::Purpose, stela_runtime::pc::disk_writes::Update,
    stela_runtime::pc::failure_record, stela_runtime::pc::machine_state,
    stela_runtime::pc::storage::Target, stela_soc_data::nor::CAPACITY, stela_soc_data::nor::Image,
    stela_soc_data::nor::SECTOR_SIZE, stela_soc_data::nor::nvram::Variables,
    stela_soc_data::nor::nvram::empty_bank,
};

/// One GPT partition, or a part of it, read through its whole disk's block
/// I/O.
struct Partition<'a> {
    io: ScopedProtocol<BlockIO>,
    media: u32,
    block_bytes: u64,
    first_lba: u64,
    bytes: u64,
    /// The disk's blocks a pending plan zeroes, which read as zero already;
    /// empty for a partition found on its disk.
    zeroed: Vec<Extent>,
    /// The partition this is, or is a part of, and the pending work whose
    /// updates of it read as applied; `None` for a whole disk.
    named: Option<Named<'a>>,
}

/// A partition `stela.cfg` names, as a search found it.
struct Named<'a> {
    target: Target,
    /// The whole partition's first block on its disk.
    first_lba: u64,
    pending: &'a Pending,
}

/// Which part of a partition that also holds the machine state in its tail.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Part {
    Whole,
    /// The guest's namespace before the tail.
    Namespace,
    /// The machine state in the tail.
    State,
}

impl Partition<'_> {
    /// Confine the partition to `part`, as the engine splits it.
    fn confine(&mut self, part: Part) -> Result<()> {
        if part == Part::Whole {
            return Ok(());
        }
        let layout = machine_state::split(self.bytes)
            .map_err(|_| refuse!("the partition is too small to also hold the machine state"))?;
        if !machine_state::ALIGNMENT.is_multiple_of(self.block_bytes) {
            return Err(refuse!(
                "the partition's blocks do not divide the machine state's alignment"
            ));
        }
        if part == Part::State {
            self.first_lba += layout.namespace_bytes / self.block_bytes;
            self.bytes = layout.state_bytes;
        } else {
            self.bytes = layout.namespace_bytes;
        }
        Ok(())
    }

    fn read_blocks(&mut self, lba: u64, buffer: &mut [u8]) -> Result<()> {
        let mut aligned = Aligned::new(buffer.len());
        self.io
            .read_blocks(self.media, self.first_lba + lba, aligned.bytes())
            .map_err(|_| refuse!("cannot read the partition"))?;
        buffer.copy_from_slice(aligned.bytes());
        let first = self.first_lba + lba;
        let end = first + (buffer.len() as u64).div_ceil(self.block_bytes);
        for extent in &self.zeroed {
            let (from, to) = (extent.lba.max(first), (extent.lba + extent.blocks).min(end));
            if from < to {
                let bytes = |lba: u64| ((lba - first) * self.block_bytes) as usize;
                let to = bytes(to).min(buffer.len());
                buffer[bytes(from)..to].fill(0);
            }
        }
        if let Some(named) = &self.named {
            let offset = (first - named.first_lba) * self.block_bytes;
            named.pending.lay(&named.target, offset, buffer);
        }
        Ok(())
    }

    /// Where this part starts, in bytes from the start of the partition
    /// `stela.cfg` names.
    fn offset(&self) -> u64 {
        self.named.as_ref().map_or(0, |named| {
            (self.first_lba - named.first_lba) * self.block_bytes
        })
    }
}

/// The largest firmware read, so a large APFS read needs no huge buffer.
const TRANSFER_BYTES: u64 = 1 << 20;

impl ReadAt for Partition<'_> {
    type Error = stela_contracts::Refusal;

    fn len(&self) -> u64 {
        self.bytes
    }

    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        let end = offset
            .checked_add(buffer.len() as u64)
            .filter(|&end| end <= self.bytes)
            .ok_or(refuse!("read past the partition"))?;
        let mut at = offset;
        while at < end {
            let first = at / self.block_bytes;
            let span = (end - at).min(TRANSFER_BYTES);
            let last = (at + span).div_ceil(self.block_bytes);
            let mut blocks = vec![0u8; ((last - first) * self.block_bytes) as usize];
            self.read_blocks(first, &mut blocks)?;
            let within = (at - first * self.block_bytes) as usize;
            let done = (at - offset) as usize;
            buffer[done..done + span as usize]
                .copy_from_slice(&blocks[within..within + span as usize]);
            at += span;
        }
        Ok(())
    }
}

/// Open `handle`'s block I/O for reading. Not exclusive: the disk's other
/// partitions, such as the ESP this image was loaded from, stay connected.
fn block_io(handle: Handle) -> Option<ScopedProtocol<BlockIO>> {
    // SAFETY: Stela only reads through the protocol, and no driver's use of
    // the disk is disturbed by a read.
    unsafe {
        boot::open_protocol::<BlockIO>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()
}

/// A whole disk's serial, when it reports one, and its block I/O.
type WholeDisk = (Option<String>, ScopedProtocol<BlockIO>);

/// Every whole disk with media.
fn whole_disks() -> Result<Vec<WholeDisk>> {
    let handles = boot::find_handles::<BlockIO>().map_err(|_| refuse!("no block devices"))?;
    let mut disks = Vec::new();
    for handle in handles {
        let Some(io) = block_io(handle) else {
            continue;
        };
        let media = io.media();
        if media.is_logical_partition() || !media.is_media_present() {
            continue;
        }
        let path = device_path(handle).unwrap_or_default();
        disks.push((disk_serial(handle, &path), io));
    }
    Ok(disks)
}

/// The PCI controllers of the whole disks whose serials are among
/// `serials`, as the firmware's device paths give them: the functions a boot
/// on those disks cannot continue without.
pub(crate) fn disk_controllers(serials: &[&str]) -> Vec<stela_drivers::bus::pci::Address> {
    let Ok(handles) = boot::find_handles::<BlockIO>() else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for handle in handles {
        let Some(io) = block_io(handle) else {
            continue;
        };
        let media = io.media();
        if media.is_logical_partition() || !media.is_media_present() {
            continue;
        }
        drop(io);
        let path = device_path(handle).unwrap_or_default();
        if disk_serial(handle, &path).is_some_and(|serial| serials.contains(&serial.as_str()))
            && let Some(controller) = crate::pci_io::disk_controller(handle)
        {
            found.push(controller.address);
        }
    }
    found
}

/// The whole disk behind `io` and its GPT.
fn table<'a>(io: ScopedProtocol<BlockIO>) -> Result<(Partition<'a>, gpt::Table)> {
    let media = io.media();
    let disk = Disk {
        block_bytes: media.block_size() as u64,
        blocks: media.last_block() + 1,
    };
    let media = media.media_id();
    let mut whole = Partition {
        io,
        media,
        block_bytes: disk.block_bytes,
        first_lba: 0,
        bytes: disk.blocks * disk.block_bytes,
        zeroed: Vec::new(),
        named: None,
    };
    // The backup table stands in for a primary an interrupted write left
    // damaged (`gpt::read`); selecting a boot only reads.
    let found = gpt::read(disk, |lba, blocks| {
        let mut bytes = vec![0u8; (blocks * disk.block_bytes) as usize];
        whole
            .read_blocks(lba, &mut bytes)
            .map_err(|error| PayloadError::Io(error.to_string()))?;
        Ok(bytes)
    })
    .map_err(|_| refuse!("the disk's GPT is invalid"))?;
    let gpt::Found::Table { table, .. } = found else {
        return Err(refuse!("the disk has no valid GPT"));
    };
    Ok((whole, table))
}

/// The partition the pending `plan` makes, on the disk behind `io`: where
/// the plan puts it, with the blocks the plan zeroes reading as zero. The
/// disk must be as the picker saw it.
fn planned<'a>(io: ScopedProtocol<BlockIO>, plan: &Plan) -> Result<Partition<'a>> {
    let media = io.media();
    let disk = Disk {
        block_bytes: media.block_size() as u64,
        blocks: media.last_block() + 1,
    };
    if disk != plan.geometry {
        return Err(refuse!(
            "the chosen disk is not the size it was when it was chosen"
        ));
    }
    let media = media.media_id();
    Ok(Partition {
        io,
        media,
        block_bytes: disk.block_bytes,
        first_lba: plan.partition.first_lba,
        bytes: plan.partition.blocks * disk.block_bytes,
        zeroed: plan.zero.clone(),
        named: None,
    })
}

/// The partition `target` names, as the engine finds it, or what was found
/// instead (`chosen_disk::Search`); the partition the `pending` plan is
/// for, as the engine finds it once the plan is applied ([`planned`]).
/// Either reads with its pending updates applied. Fails only when the disks
/// cannot be listed or the plan's disk has changed.
fn search<'a>(
    target: &Target,
    pending: &'a Pending,
) -> Result<core::result::Result<Partition<'a>, Search>> {
    let named = |mut partition: Partition<'a>| {
        partition.named = Some(Named {
            target: target.clone(),
            first_lba: partition.first_lba,
            pending,
        });
        partition
    };
    let mut disks: Vec<_> = whole_disks()?
        .into_iter()
        .filter(|(serial, _)| serial.as_deref() == Some(target.serial.as_str()))
        .collect();
    let io = match disks.len() {
        0 => return Ok(Err(Search::NoDisk)),
        1 => disks.remove(0).1,
        _ => return Ok(Err(Search::SeveralDisks)),
    };
    if let Some(plan) = pending.plan.as_ref().filter(|plan| plan.is_for(target)) {
        return planned(io, plan).map(named).map(Ok);
    }
    // A table that cannot be read is a blank or wiped disk to a boot.
    let Ok((mut whole, table)) = table(io) else {
        return Ok(Err(Search::NoTable));
    };
    let matching: Vec<_> = table
        .partitions
        .iter()
        .filter(|p| p.unique_guid.0 == target.partition.0)
        .collect();
    let partition = match matching[..] {
        [partition] => partition,
        [] => return Ok(Err(Search::NoPartition)),
        _ => return Ok(Err(Search::SeveralPartitions)),
    };
    if partition.role() == Some(Role::Esp) {
        return Ok(Err(Search::EspPartition));
    }
    whole.first_lba = partition.first_lba;
    whole.bytes = partition.blocks() * whole.block_bytes;
    Ok(Ok(named(whole)))
}

fn find<'a>(target: &Target, pending: &'a Pending) -> Result<Partition<'a>> {
    search(target, pending)?.map_err(|found| match found {
        Search::NoDisk | Search::SeveralDisks => refuse!("not exactly one disk has the serial"),
        Search::NoTable => refuse!("the disk has no valid GPT"),
        Search::NoPartition | Search::SeveralPartitions => {
            refuse!("not exactly one partition has the GUID")
        }
        Search::EspPartition => refuse!("the partition is an EFI system partition"),
        Search::Found => refuse!("the partition was found"),
    })
}

/// The bytes zeroed to clear a failure record: its header, in whole blocks
/// of any disk (`failure_record::OFFSET`).
const RECORD_CLEAR_BYTES: usize = 4096;

/// Copy into the log the record a previous start left in the machine state
/// of the partition `options` name for it (`--storage` and `--nor` alike)
/// when the USB's own log was out of reach of Stela's drivers
/// (`failure_record`). Returns the update that clears it, which Stela's
/// drivers make when this boot starts them on that partition; a boot that
/// does not leaves the record, and the next start copies it again.
pub fn carry_failure_record(options: &[u8]) -> Option<Update> {
    let text = core::str::from_utf8(options).ok()?;
    let storage = option(text, "--storage");
    let target = storage
        .filter(|_| option(text, "--nor") == storage)
        .and_then(|name| name.parse::<Target>().ok())?;
    // Before the startup menu: nothing is pending yet.
    let pending = Pending::default();
    let mut partition = search(&target, &pending).ok()?.ok()?;
    partition.confine(Part::State).ok()?;
    let mut region = vec![0u8; failure_record::BYTES as usize];
    partition
        .read_at(failure_record::OFFSET, &mut region)
        .ok()?;
    let record = failure_record::decode(&region)?;
    output::arguments(format_args!(
        "PREVIOUS BOOT failed where the USB's log was out of reach; the chosen disk kept:\n"
    ));
    for line in record.lines() {
        output::arguments(format_args!("PREVIOUS BOOT {line}\n"));
    }
    // A zero header clears the record.
    Some(Update {
        target,
        purpose: Purpose::FailureRecord,
        pieces: vec![Piece {
            offset: partition.offset() + failure_record::OFFSET,
            bytes: vec![0; RECORD_CLEAR_BYTES],
        }],
    })
}

/// Whether the partition Install macOS chose before (`SERIAL:GUID`) is on
/// this PC: exactly one disk with its serial, and exactly one partition
/// with its GUID that is no EFI system partition. The menu asks about the
/// disk as it is, whatever is pending.
pub fn chosen_present(disk: &str) -> bool {
    disk.parse::<Target>()
        .is_ok_and(|target| matches!(search(&target, &Pending::default()), Ok(Ok(_))))
}

/// Why the partition `target` names is no longer there to boot, when it is
/// not (`chosen_disk::Stale::of`).
fn stale(target: &Target, pending: &Pending) -> Result<Option<Stale>> {
    Ok(search(target, pending)?.err().and_then(Stale::of))
}

/// The external disk's partition NVRAM's boot volume names, as the
/// `--preboot` target that boots it: a whole disk's own GPT partition, as
/// recoveryOS installs macOS on a Mac's external drive. `None` when no
/// disk's table holds it, as for the internal SSD's containers, which lie in
/// the Apple region's own table.
fn external(volume: &BootVolume) -> Result<Option<Target>> {
    let mut found = None;
    for (serial, io) in whole_disks()? {
        let Ok((_, table)) = table(io) else {
            continue;
        };
        if !table
            .partitions
            .iter()
            .any(|p| p.unique_guid.0 == volume.partition)
        {
            continue;
        }
        let serial = serial.ok_or(refuse!(
            "the boot volume's disk reports no serial number to find it by after boot"
        ))?;
        if found.is_some() {
            return Err(refuse!("several disks hold the boot volume's partition"));
        }
        found = Some(Target {
            serial,
            partition: stela_runtime::pc::gpt::Guid(volume.partition),
        });
    }
    Ok(found)
}

/// [`select`]; a store that cannot be read on a Preboot disk without a Mac
/// system container is an install that did not finish
/// (`chosen_disk::unreadable_store`), and any other stops the boot with
/// what to do.
fn select_or_unprepared(
    target: &Target,
    part: Part,
    save: Option<&mut Option<Update>>,
    (preboot, preboot_part): &(Target, Part),
    pending: &Pending,
) -> Result<Selection, Refusal> {
    let error = match select(target, part, save, pending) {
        Ok(selection) => return Ok(selection),
        Err(error) => error,
    };
    output::arguments(format_args!("NVRAM boot refusal: {error}\n"));
    match chosen_disk::unreadable_store(blank(preboot, *preboot_part, pending).ok()) {
        chosen_disk::Unreadable::Unprepared => Err(Refusal::Stale(Stale::NoMacOs)),
        chosen_disk::Unreadable::Fatal => Err(Refusal::Other(chosen_disk::UNREADABLE_STORE)),
    }
}

/// The boot NVRAM chooses. With `save`, its one-shot variables are consumed
/// and the bank without them is left there: the update of the NOR's next
/// bank, which Stela's drivers write before the engine reads the NOR.
fn select(
    target: &Target,
    part: Part,
    save: Option<&mut Option<Update>>,
    pending: &Pending,
) -> Result<Selection> {
    let mut nor = find(target, pending).within(|| refuse!("NOR partition"))?;
    nor.confine(part).within(|| refuse!("NOR partition"))?;
    if nor.io.media().is_read_only()
        || !SECTOR_SIZE.is_multiple_of(nor.block_bytes as usize)
        || nor.bytes < CAPACITY as u64
    {
        return Err(refuse!(
            "the NOR partition is read-only, smaller than the image or has odd blocks"
        ));
    }
    let mut bytes = vec![0u8; CAPACITY];
    nor.read_blocks(0, &mut bytes)?;
    let select = |variables: &Variables| Ok(boot_selection::select(variables)?);
    if bytes.iter().all(|&b| b == 0) {
        return select(&Variables::parse(&empty_bank())?);
    }
    let mut image = Image::from_bytes(bytes)?;
    let (_, proxy) = image.boot_bank()?;
    let mut variables = Variables::parse(&proxy)?;
    let selection = select(&variables)?;
    if let Some(save) = save
        && boot_selection::consume(&mut variables, &selection)?
    {
        let bank = variables.encode()?;
        let (written, sectors) = image.save_bank(&bank)?;
        let base = nor.offset();
        *save = Some(Update {
            target: target.clone(),
            purpose: Purpose::NvramBank,
            pieces: sectors
                .into_iter()
                .map(|offset| Piece {
                    offset: base + offset as u64,
                    bytes: image.bytes()[offset..offset + SECTOR_SIZE].to_vec(),
                })
                .collect(),
        });
        output::arguments(format_args!(
            "NVRAM consumed {} for bank {written}, which Stela's drivers save after the \
             firmware has exited\n",
            selection
                .consumed
                .iter()
                .map(|name| core::str::from_utf8(name).unwrap_or("?"))
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    Ok(selection)
}

/// Whether the Preboot disk holds an installed system to boot: a container
/// (the boot volume's, when NVRAM names one) whose Preboot volume has a
/// boot directory. Only a missing container, Preboot volume or boot
/// directory counts as absent; any other failure is reported.
fn installed(
    target: &Target,
    part: Part,
    volume: Option<&BootVolume>,
    pending: &Pending,
) -> Result<bool> {
    let mut disk = find(target, pending).within(|| refuse!("Preboot disk"))?;
    disk.confine(part).within(|| refuse!("Preboot disk"))?;
    let partitions = match apfs::container_partitions(&mut disk) {
        Ok(partitions) => partitions,
        Err(ApfsError::NotFound(_)) => return Ok(false),
        Err(error) => return Err(refuse!("Preboot disk: {error}", %error)),
    };
    for (offset, guid) in partitions {
        if volume.is_some_and(|v| guid.is_some_and(|g| g.0 != v.partition)) {
            continue;
        }
        let mut container = match Container::open(&mut disk, offset) {
            Ok(container) => container,
            Err(ApfsError::Malformed(_)) => continue,
            Err(error) => return Err(refuse!("container at {offset:#x}: {error}", offset, %error)),
        };
        match preboot::candidates(&mut container) {
            Ok(_) => return Ok(true),
            Err(PrebootError::NoBootDirectory | PrebootError::Apfs(ApfsError::NotFound(_))) => {}
            Err(error) => return Err(refuse!("container at {offset:#x}: {error}", offset, %error)),
        }
    }
    Ok(false)
}

/// Whether the Preboot disk holds a recoveryOS of `kind`
/// (`stela_loader::recovery::find`): a Recovery volume with a boot
/// directory. A disk that cannot be read for it is reported and counts as
/// holding none, so the boot falls back to the next recoveryOS.
fn holds_recovery(
    target: &Target,
    part: Part,
    kind: recovery::Kind,
    volume: Option<&BootVolume>,
    pending: &Pending,
) -> bool {
    let probe = || -> Result<bool> {
        let mut disk = find(target, pending).within(|| refuse!("Preboot disk"))?;
        disk.confine(part).within(|| refuse!("Preboot disk"))?;
        recovery::find(&mut disk, kind, volume)
            .map(|found| !found.is_empty())
            .map_err(|error| refuse!("recovery volume: {error}", %error))
    };
    match probe() {
        Ok(found) => found,
        Err(error) => {
            output::arguments(format_args!(
                "RECOVERY probe of the {} refused: {error}\n",
                kind.label()
            ));
            false
        }
    }
}

/// Whether the internal SSD lacks the iBootSystemContainer every boot of a
/// Mac reads (`apfs::require_system_container`), as a blank one does.
fn blank(target: &Target, part: Part, pending: &Pending) -> Result<bool> {
    let mut disk = find(target, pending).within(|| refuse!("internal SSD"))?;
    disk.confine(part).within(|| refuse!("internal SSD"))?;
    match apfs::require_system_container(&mut disk) {
        Ok(()) => Ok(false),
        Err(ApfsError::NotFound(_)) => Ok(true),
        Err(error) => Err(refuse!("internal SSD: {error}", %error)),
    }
}

/// The value after `name` in the options.
fn option<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let mut words = text.split_ascii_whitespace();
    words.find(|w| *w == name)?;
    words.next()
}

/// `text` with the value after `name` replaced by `value`.
fn replace(text: &str, name: &str, value: &str) -> String {
    let mut words: Vec<&str> = text.split_ascii_whitespace().collect();
    if let Some(at) = words.iter().position(|w| *w == name)
        && at + 1 < words.len()
    {
        words[at + 1] = value;
    }
    words.join(" ")
}

/// Whether a startup choice can start now ([`ready`]).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// It starts what it names: macOS from an installed system, or the
    /// disk's recoveryOS when NVRAM asks for it.
    Ready,
    /// A Mac choice whose startup disk holds no installed macOS, which
    /// would start the disk's System Recovery instead, or nothing without
    /// one.
    NotInstalled,
    /// Its SSD has no iBootSystemContainer yet, NVRAM holds the machine in
    /// recovery mode, as an unfinished restore leaves it, or NVRAM asks for
    /// a recoveryOS the disk does not hold: only Install macOS starts.
    Unprepared,
    /// The disk Install macOS chose is no longer there, or holds no macOS:
    /// only Install macOS starts, and it chooses again.
    Stale(Stale),
    /// The check could not be made; starting the choice reports why.
    Unknown,
}

/// Whether the startup choice `options` of `kind` can start now, with the
/// `pending` work done. Install and other choices are not checked
/// ([`Readiness::Unknown`]).
pub fn ready(options: &str, kind: ChoiceKind, pending: &Pending) -> Readiness {
    match kind {
        ChoiceKind::Mac => match route_checked(options.as_bytes().into(), None, pending) {
            Ok((_, true)) => Readiness::Ready,
            Ok((_, false)) | Err(Refusal::NoRecovery { installed: false }) => {
                Readiness::NotInstalled
            }
            Err(
                Refusal::BlankDisk
                | Refusal::RecoveryMode
                | Refusal::NoRecovery { installed: true },
            ) => Readiness::Unprepared,
            Err(Refusal::Stale(stale)) => Readiness::Stale(stale),
            Err(Refusal::Other(_)) => Readiness::Unknown,
        },
        _ => Readiness::Unknown,
    }
}

/// Why no boot options came out of [`route`].
pub enum Refusal {
    /// NVRAM holds the machine in iBoot's recovery mode
    /// (`boot_selection::Target::RecoveryMode`): it waits for a restore
    /// host, Stela's Install macOS startup choice.
    RecoveryMode,
    /// The internal SSD has no iBootSystemContainer yet: only Install macOS
    /// boots.
    BlankDisk,
    /// NVRAM boots recoveryOS, or the boot disk holds no installed system
    /// (`installed` false, missing boot media), and the disk holds no
    /// recoveryOS to boot: only Install macOS restores one.
    NoRecovery {
        installed: bool,
    },
    /// The disk or partition the options name is no longer there, or holds
    /// no macOS and no readable NVRAM: Install macOS chooses again.
    Stale(Stale),
    Other(&'static str),
}

/// The engine's options for this boot (`boot_selection::route`), with
/// NVRAM's one-shot choices consumed. `pending` is the disk work decided so
/// far, the disk picker's plan for these options with it; the save of the
/// bank without the consumed variables joins it, whether or not the boot is
/// then refused: the variables are consumed once they have been acted on.
pub fn route(options: Vec<u8>, pending: &mut Pending) -> Result<Vec<u8>, Refusal> {
    let mut save = None;
    let routed = route_checked(options, Some(&mut save), pending);
    pending.updates.extend(save);
    routed.map(|(routed, _)| routed)
}

/// Where [`route`] would send `options`, leaving NVRAM unchanged: the
/// check before the startup menu, which a chosen boot routes again.
pub fn peek(options: Vec<u8>, pending: &Pending) -> Result<Vec<u8>, Refusal> {
    route_checked(options, None, pending).map(|(routed, _)| routed)
}

/// [`route`] with a place for the NVRAM `save`, or [`peek`] without one,
/// and whether the boot disk holds an installed system: false when a Mac
/// boot falls back to recoveryOS for want of one. Nothing reads the NOR
/// after its choice is made, so the save need not be pending yet for the
/// rest of the routing.
fn route_checked(
    options: Vec<u8>,
    save: Option<&mut Option<Update>>,
    pending: &Pending,
) -> Result<(Vec<u8>, bool), Refusal> {
    let consume = save.is_some();
    let mut installed_system = true;
    let text =
        core::str::from_utf8(&options).map_err(|_| Refusal::Other("stela.cfg is not UTF-8"))?;
    let refuse = |error: stela_contracts::Refusal| {
        output::arguments(format_args!("NVRAM boot refusal: {error}\n"));
        Refusal::Other("NVRAM's boot choice could not be read or is not modeled")
    };
    let parse = |text: &str| text.parse::<Target>().map_err(Refusal::Other);
    let mut retargeted = None;
    let selection = match option(text, boot_selection::PREBOOT_OPTION) {
        Some(preboot) => {
            let nor = option(text, "--nor");
            // A disk or partition no longer there is a choice to make again,
            // not a store to read.
            let preboot_too = (nor != Some(preboot)).then_some(preboot);
            for name in nor.into_iter().chain(preboot_too) {
                if let Some(stale) = stale(&parse(name)?, pending).map_err(refuse)? {
                    return Err(Refusal::Stale(stale));
                }
            }
            // The engine splits a `--storage` partition that `--nor` also
            // names; the Preboot disk is then its namespace.
            let target = |name: Option<&str>| name.and_then(|name| name.parse::<Target>().ok());
            let (nor_target, storage) = (target(nor), target(option(text, "--storage")));
            let in_storage = |name: &str| {
                nor_target.is_some() && nor_target == storage && target(Some(name)) == storage
            };
            let mut selection = match nor {
                Some(nor) => {
                    let part = if in_storage(nor) {
                        Part::State
                    } else {
                        Part::Whole
                    };
                    let preboot_part = if in_storage(preboot) {
                        Part::Namespace
                    } else {
                        Part::Whole
                    };
                    let preboot = (parse(preboot)?, preboot_part);
                    select_or_unprepared(&parse(nor)?, part, save, &preboot, pending)?
                }
                None => boot_selection::select(&Variables::parse(&empty_bank()).map_err(refuse)?)
                    .map_err(|error| refuse(error.into()))?,
            };
            // A boot volume on an external disk boots from that disk.
            let outside = match &selection.volume {
                Some(volume) => external(volume).map_err(refuse)?,
                None => None,
            };
            let (disk, part) = match outside {
                Some(target) => {
                    let value = format!("{}:{}", target.serial, target.partition);
                    output::arguments(format_args!("BOOT volume on external disk {value}\n"));
                    retargeted = Some(replace(text, boot_selection::PREBOOT_OPTION, &value));
                    (target, Part::Whole)
                }
                None if in_storage(preboot) => (parse(preboot)?, Part::Namespace),
                None => (parse(preboot)?, Part::Whole),
            };
            // An internal SSD without its iBootSystemContainer boots nothing,
            // recoveryOS included: it waits for the restore that creates it.
            if retargeted.is_none() && blank(&disk, part, pending).map_err(refuse)? {
                return Err(Refusal::BlankDisk);
            }
            if matches!(selection.target, boot_selection::Target::MacOs { .. })
                && !installed(&disk, part, selection.volume.as_ref(), pending).map_err(refuse)?
            {
                selection.missing_boot_media();
                installed_system = false;
            }
            // A recoveryOS boot takes the disk's own copy first, as LLB does.
            let volume = selection.volume;
            match selection.target {
                boot_selection::Target::PairedRecovery => {
                    let holds = |kind| holds_recovery(&disk, part, kind, volume.as_ref(), pending);
                    selection.paired_on_disk = holds(recovery::Kind::Paired);
                    selection.system_on_disk =
                        !selection.paired_on_disk && holds(recovery::Kind::System);
                }
                boot_selection::Target::SystemRecovery => {
                    selection.system_on_disk = holds_recovery(
                        &disk,
                        part,
                        recovery::Kind::System,
                        volume.as_ref(),
                        pending,
                    );
                }
                _ => {}
            }
            let wants_recovery = matches!(
                selection.target,
                boot_selection::Target::PairedRecovery | boot_selection::Target::SystemRecovery
            );
            if wants_recovery && !selection.paired_on_disk && !selection.system_on_disk {
                if let Err(error) = boot_selection::route(text, Some(&selection)) {
                    output::arguments(format_args!("BOOT {error:#}\n"));
                }
                return Err(Refusal::NoRecovery {
                    installed: installed_system,
                });
            }
            Some(selection)
        }
        None => None,
    };
    let text = retargeted.as_deref().unwrap_or(text);
    if let Some(held) = selection
        .as_ref()
        .filter(|s| s.target == boot_selection::Target::RecoveryMode)
    {
        if let Err(error) = boot_selection::route(text, Some(held)) {
            output::arguments(format_args!("BOOT {error:#}\n"));
        }
        return Err(Refusal::RecoveryMode);
    }
    let (routed, log) = boot_selection::route(text, selection.as_ref()).map_err(|error| {
        output::arguments(format_args!("NVRAM boot refusal: {error:#}\n"));
        Refusal::Other("stela.cfg cannot boot what NVRAM chose")
    })?;
    // Only an installed-system boot has a choice to report, and only the
    // boot that uses it: a `peek` before the menu would repeat the line.
    if consume && selection.is_some() {
        output::arguments(format_args!("BOOT {log}\n"));
    }
    Ok((routed.into_bytes(), installed_system))
}
