//! The change to a PC disk that Install macOS's disk picker decided on,
//! which Stela's own drivers make after the firmware has exited.
//!
//! The picker runs while the firmware's boot services do and writes
//! nothing: a firmware disk driver gives its caller no say over timeouts or
//! recovery, so, as Linux does, only Stela's drivers write a PC disk. What
//! the picker decided is a [`Plan`] ([`plan`]): the disk as the picker saw
//! it, the partition table's blocks, the blocks to zero and the partition
//! macOS gets. The loader carries it in memory with the boot's other
//! pending disk work (`disk_writes`); once the drivers have started and
//! before the partition is looked up, the engine finds the disk
//! ([`Plan::locate`]) and makes the change ([`Plan::apply`]).
//!
//! A plan is made for one boot and never stored. A boot that stops before
//! it is applied leaves the disk as it was, and the next one finds no
//! chosen partition and chooses again.
use super::{
    gpt::{self, GptError, Guid},
    machine_state,
    storage::Target,
};
use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::fmt;
use stela_crypto::Sha256;
use stela_crypto::digest::Digest;
use stela_drivers::block::{BlockDevice, BlockError, Extent, Request};
use stela_formats::payload::{
    PayloadError,
    gpt::{self as shared, Disk, Partition, Role, Table, Write},
};

const MIB: u64 = 1 << 20;
/// The blocks from the disk's start whose bytes tell the disk the picker
/// saw from another ([`seen`]): the MBR, with its disk signature, and the
/// GPT header, with the disk's GUID and its entries' checksum.
pub const SEEN_BLOCKS: u64 = 2;
/// The most bytes one zeroing request covers, so a failure names a block
/// near it and no single request runs long.
const ZERO_BYTES: u64 = MIB;

/// The digest of a disk's first [`SEEN_BLOCKS`] blocks.
pub fn seen(first_blocks: &[u8]) -> [u8; 32] {
    Sha256::digest(first_blocks).into()
}

/// The partition macOS gets, as the disk holds it once the plan is applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Planned {
    pub guid: Guid,
    pub first_lba: u64,
    pub blocks: u64,
}

/// What Stela's drivers do to one disk before the engine looks up the
/// chosen partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// The disk's serial number, as the firmware reported it.
    pub serial: String,
    /// The disk's block size and count, as the picker saw them.
    pub geometry: Disk,
    /// [`seen`] of the disk's first blocks, as the picker read them.
    pub seen: [u8; 32],
    /// The partition table's blocks in the order to write them
    /// ([`shared::encode`]); none when the table stays as it is.
    pub table: Vec<Write>,
    /// The blocks to zero: the partition's first MiB and the machine
    /// state's tail, so the restore and the NOR start blank.
    pub zero: Vec<Extent>,
    pub partition: Planned,
}

/// Where the picker put macOS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    /// A new partition of `bytes` from block `first_lba`, in free space.
    Free { first_lba: u64, bytes: u64 },
    /// The Stela partition at this index of the disk's table.
    Reuse(usize),
}

/// What the picker's last page confirmed.
#[derive(Clone, Copy, Debug)]
pub struct Decision<'a> {
    pub serial: &'a str,
    pub geometry: Disk,
    /// [`seen`] of the disk's first blocks.
    pub seen: [u8; 32],
    /// The disk's GPT; `None` on a blank disk or one with another scheme.
    pub table: Option<&'a Table>,
    /// The table's partitions to delete, by index.
    pub deleted: &'a [usize],
    /// Every partition goes, as does another scheme's data.
    pub erased: bool,
    pub place: Place,
    /// A new partition's GPT name.
    pub name: &'a str,
}

/// Why a decision makes no plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanError {
    NoSerial,
    /// The block size does not divide a MiB.
    Blocks(u64),
    /// The reused partition is not in the table, is deleted too, or is not
    /// a Stela partition.
    NotReusable,
    /// A deleted partition is not in the table.
    NoPartition(usize),
    /// The new partition is not whole blocks, or overlaps one that stays.
    Overlap,
    /// The partition cannot hold a namespace and the machine state.
    TooSmall,
    /// The new table cannot be encoded.
    Table(&'static str),
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSerial => f.write_str("the disk reports no serial number"),
            Self::Blocks(bytes) => write!(f, "the disk's {bytes}-byte blocks do not divide a MiB"),
            Self::NotReusable => f.write_str("the partition chosen is not a Stela partition"),
            Self::NoPartition(index) => write!(f, "the disk has no partition {index} to delete"),
            Self::Overlap => f.write_str("the new partition overlaps one that stays"),
            Self::TooSmall => f.write_str("the partition is too small"),
            Self::Table(why) => write!(f, "the new partition table is invalid: {why}"),
        }
    }
}

/// The plan that carries out `decision`. `entropy` gives the new
/// partition's GUID, and the disk's on one without a table. The table is
/// written only when it changes: a reused partition with nothing deleted
/// has its blocks zeroed and nothing else.
pub fn plan(decision: &Decision<'_>, entropy: &mut dyn FnMut() -> Guid) -> Result<Plan, PlanError> {
    let Decision {
        serial,
        geometry,
        seen,
        table,
        deleted,
        erased,
        place,
        name,
    } = *decision;
    if serial.is_empty() {
        return Err(PlanError::NoSerial);
    }
    let block = geometry.block_bytes;
    if block == 0 || !MIB.is_multiple_of(block) {
        return Err(PlanError::Blocks(block));
    }
    let mut new = match table {
        Some(table) => table.clone(),
        None => Table {
            disk_guid: entropy(),
            partitions: Vec::new(),
        },
    };
    let (guid, first_lba, blocks) = match place {
        Place::Reuse(index) => {
            let partition = new
                .partitions
                .get(index)
                .filter(|partition| partition.role() == Some(Role::AppleRegion))
                .filter(|_| !erased && !deleted.contains(&index))
                .ok_or(PlanError::NotReusable)?;
            (
                partition.unique_guid,
                partition.first_lba,
                partition.blocks(),
            )
        }
        Place::Free { first_lba, bytes } => {
            if bytes == 0 || !bytes.is_multiple_of(block) {
                return Err(PlanError::Overlap);
            }
            (entropy(), first_lba, bytes / block)
        }
    };
    if erased {
        new.partitions.clear();
    } else {
        let mut deleted = deleted.to_vec();
        deleted.sort_unstable();
        deleted.dedup();
        for &index in deleted.iter().rev() {
            if index >= new.partitions.len() {
                return Err(PlanError::NoPartition(index));
            }
            new.partitions.remove(index);
        }
    }
    let changed = erased || !deleted.is_empty() || matches!(place, Place::Free { .. });
    if let Place::Free { .. } = place {
        let last_lba = first_lba + blocks - 1;
        if new
            .partitions
            .iter()
            .any(|kept| kept.first_lba <= last_lba && first_lba <= kept.last_lba)
        {
            return Err(PlanError::Overlap);
        }
        new.partitions.push(Partition {
            type_guid: Role::AppleRegion.type_guid(),
            unique_guid: guid,
            first_lba,
            last_lba,
            attributes: 0,
            name: name.into(),
        });
        new.partitions.sort_by_key(|partition| partition.first_lba);
    }
    let split = machine_state::split(blocks * block).map_err(|_| PlanError::TooSmall)?;
    let table = if changed {
        shared::encode(geometry, &new).map_err(|error| match error {
            PayloadError::Disk(why) => PlanError::Table(why),
            _ => PlanError::Table("it cannot be encoded"),
        })?
    } else {
        Vec::new()
    };
    Ok(Plan {
        serial: serial.into(),
        geometry,
        seen,
        table,
        zero: vec![
            Extent {
                lba: first_lba,
                blocks: MIB / block,
            },
            Extent {
                lba: first_lba + split.namespace_bytes / block,
                blocks: split.state_bytes / block,
            },
        ],
        partition: Planned {
            guid,
            first_lba,
            blocks,
        },
    })
}

/// A part of [`Plan::apply`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Telling that the disk is the one the picker saw.
    Identify,
    /// Writing the partition table.
    Table,
    /// Zeroing the partition's first MiB and the machine state.
    Zero,
    /// Making the writes durable.
    Flush,
    /// Reading the table and the zeroed blocks back.
    Verify,
}

impl Step {
    fn name(self) -> &'static str {
        match self {
            Self::Identify => "checking that it is the disk chosen",
            Self::Table => "writing the partition table",
            Self::Zero => "zeroing the partition's first MiB and machine state",
            Self::Flush => "making the writes durable",
            Self::Verify => "reading the partition table back",
        }
    }
}

/// What stopped a step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cause {
    /// The driver's error.
    Device(BlockError),
    /// The disk has another block size or count than the picker saw: a
    /// different disk answers to the serial.
    Geometry { found: Disk },
    /// The disk's first blocks are not what the picker read.
    Changed,
    /// The table read back cannot be used.
    Table(GptError),
    /// The table read back does not hold the chosen partition as planned.
    Missing,
    /// A block that was zeroed does not read as zero.
    NotZero,
}

/// Why a plan was not applied in full: the step, the block it was at when
/// it has one, and the cause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyError {
    pub step: Step,
    pub lba: Option<u64>,
    pub cause: Cause,
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.step.name())?;
        if let Some(lba) = self.lba {
            write!(f, " at block {lba}")?;
        }
        match &self.cause {
            Cause::Device(error) => write!(f, ": {error}"),
            Cause::Geometry { found } => write!(
                f,
                ": the disk has {} blocks of {} bytes, not what was chosen",
                found.blocks, found.block_bytes
            ),
            Cause::Changed => f.write_str(": the disk's first blocks are not what was chosen"),
            Cause::Table(error) => write!(f, ": {error}"),
            Cause::Missing => f.write_str(": the chosen partition is not in it"),
            Cause::NotZero => f.write_str(": a zeroed block does not read as zero"),
        }
    }
}

/// Why no disk is the plan's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocateError {
    /// No disk reports the serial, and none of the chosen size holds the
    /// first blocks the picker read.
    NoDisk,
    /// This many disks could be it.
    Ambiguous(usize),
}

impl fmt::Display for LocateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDisk => f.write_str("Stela's drivers found no disk that is the one chosen"),
            Self::Ambiguous(count) => write!(f, "{count} disks could be the one chosen"),
        }
    }
}

const MAGIC: &[u8; 8] = b"STELAPLN";

impl Plan {
    /// The partition as `stela.cfg`'s options name it.
    pub fn target(&self) -> Target {
        Target {
            serial: self.serial.clone(),
            partition: self.partition.guid,
        }
    }

    /// Whether the plan is for the partition `target` names.
    pub fn is_for(&self, target: &Target) -> bool {
        self.serial == target.serial && self.partition.guid == target.partition
    }

    fn geometry_of(device: &dyn BlockDevice) -> Disk {
        gpt::geometry(device.identity())
    }

    /// Whether `device` has the plan's geometry and first blocks.
    fn saw(&self, device: &mut dyn BlockDevice) -> Result<bool, BlockError> {
        if Self::geometry_of(device) != self.geometry {
            return Ok(false);
        }
        let mut first = vec![0; (SEEN_BLOCKS * self.geometry.block_bytes) as usize];
        device.read(0, &mut first)?;
        Ok(seen(&first) == self.seen)
    }

    /// The index in `devices` of the plan's disk: the one reporting its
    /// serial. The firmware read that serial; Stela's own driver may report
    /// the same disk under another (a USB bridge's INQUIRY serial against
    /// its USB string) or none. When no disk has the serial, the disk is
    /// the only one of the chosen size whose first blocks are what the
    /// picker read.
    pub fn locate(&self, devices: &mut [Box<dyn BlockDevice>]) -> Result<usize, LocateError> {
        let named: Vec<usize> = (0..devices.len())
            .filter(|&index| devices[index].identity().serial == self.serial)
            .collect();
        let found = if named.is_empty() {
            (0..devices.len())
                .filter(|&index| self.saw(&mut *devices[index]).unwrap_or(false))
                .collect()
        } else {
            named
        };
        match found[..] {
            [index] => Ok(index),
            [] => Err(LocateError::NoDisk),
            _ => Err(LocateError::Ambiguous(found.len())),
        }
    }

    /// Make the plan's change to `device`, the whole disk.
    ///
    /// Nothing is written unless the disk has the geometry and first blocks
    /// the picker saw. The table's blocks go in [`shared::encode`]'s order,
    /// the backup copy before the primary, each made durable before the
    /// next: until the primary's entries are written the disk reads as its
    /// earlier table, and from then on as the new one, from the backup
    /// while the primary header is still the earlier one's
    /// ([`shared::read`]). So a write that fails, or power lost, leaves one
    /// whole table or the other, never a mix. The table goes before the
    /// zeroes, so no block is zeroed that the table on the disk still gives
    /// to a partition being deleted. Then the ranges are zeroed, in pieces
    /// of [`ZERO_BYTES`], everything is made durable, and the table and
    /// each range's first block are read back.
    #[expect(
        clippy::result_large_err,
        reason = "the driver's error is kept whole for the stop's message, and one plan is applied a boot"
    )]
    pub fn apply(&self, device: &mut dyn BlockDevice) -> Result<(), ApplyError> {
        let failed = |step, lba| {
            move |error| ApplyError {
                step,
                lba,
                cause: Cause::Device(error),
            }
        };
        let found = Self::geometry_of(device);
        if found != self.geometry {
            return Err(ApplyError {
                step: Step::Identify,
                lba: None,
                cause: Cause::Geometry { found },
            });
        }
        if !self.saw(device).map_err(failed(Step::Identify, Some(0)))? {
            return Err(ApplyError {
                step: Step::Identify,
                lba: Some(0),
                cause: Cause::Changed,
            });
        }
        for write in &self.table {
            Request::Write {
                lba: write.lba,
                data: write.bytes.clone(),
                durable: false,
            }
            .run(device)
            .map_err(failed(Step::Table, Some(write.lba)))?;
            device
                .flush()
                .map_err(failed(Step::Table, Some(write.lba)))?;
        }
        let block = self.geometry.block_bytes;
        let piece = (ZERO_BYTES / block).max(1);
        for extent in &self.zero {
            let mut done = 0;
            while done < extent.blocks {
                let lba = extent.lba + done;
                let blocks = (extent.blocks - done).min(piece);
                Request::WriteZeroes {
                    lba,
                    blocks,
                    unmap: false,
                }
                .run(device)
                .map_err(failed(Step::Zero, Some(lba)))?;
                done += blocks;
            }
        }
        device.flush().map_err(failed(Step::Flush, None))?;
        let verify = |cause| ApplyError {
            step: Step::Verify,
            lba: None,
            cause,
        };
        let table = gpt::read(device).map_err(|error| verify(Cause::Table(error)))?;
        let mut matching = table
            .partitions
            .iter()
            .filter(|partition| partition.unique_guid == self.partition.guid);
        let planned = matching.next().is_some_and(|partition| {
            partition.first_lba == self.partition.first_lba
                && partition.blocks() == self.partition.blocks
                && partition.role() == Some(Role::AppleRegion)
        });
        if !planned || matching.next().is_some() {
            return Err(verify(Cause::Missing));
        }
        let mut first = vec![0; block as usize];
        for extent in &self.zero {
            device
                .read(extent.lba, &mut first)
                .map_err(failed(Step::Verify, Some(extent.lba)))?;
            if first.iter().any(|&byte| byte != 0) {
                return Err(ApplyError {
                    step: Step::Verify,
                    lba: Some(extent.lba),
                    cause: Cause::NotZero,
                });
            }
        }
        Ok(())
    }

    /// The plan as bytes, for the memory the loader hands the engine.
    pub fn encode(&self) -> Vec<u8> {
        fn number(bytes: &mut Vec<u8>, value: u64) {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        number(&mut bytes, self.geometry.block_bytes);
        number(&mut bytes, self.geometry.blocks);
        bytes.extend_from_slice(&self.seen);
        bytes.extend_from_slice(&self.partition.guid.0);
        number(&mut bytes, self.partition.first_lba);
        number(&mut bytes, self.partition.blocks);
        number(&mut bytes, self.serial.len() as u64);
        bytes.extend_from_slice(self.serial.as_bytes());
        number(&mut bytes, self.zero.len() as u64);
        for extent in &self.zero {
            number(&mut bytes, extent.lba);
            number(&mut bytes, extent.blocks);
        }
        number(&mut bytes, self.table.len() as u64);
        for write in &self.table {
            number(&mut bytes, write.lba);
            number(&mut bytes, write.bytes.len() as u64);
            bytes.extend_from_slice(&write.bytes);
        }
        bytes
    }

    /// The plan [`Self::encode`] made `bytes` from; `None` when they are
    /// not one whole plan.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut rest = Rest(bytes);
        if rest.take(MAGIC.len() as u64)? != MAGIC {
            return None;
        }
        let geometry = Disk {
            block_bytes: rest.number()?,
            blocks: rest.number()?,
        };
        let seen = rest.take(32)?.try_into().ok()?;
        let partition = Planned {
            guid: Guid(rest.take(16)?.try_into().ok()?),
            first_lba: rest.number()?,
            blocks: rest.number()?,
        };
        let serial_bytes = rest.number()?;
        let serial = String::from(core::str::from_utf8(rest.take(serial_bytes)?).ok()?);
        let mut zero = Vec::new();
        for _ in 0..rest.number()? {
            zero.push(Extent {
                lba: rest.number()?,
                blocks: rest.number()?,
            });
        }
        let mut table = Vec::new();
        for _ in 0..rest.number()? {
            let lba = rest.number()?;
            let length = rest.number()?;
            table.push(Write {
                lba,
                bytes: rest.take(length)?.to_vec(),
            });
        }
        rest.0.is_empty().then_some(Self {
            serial,
            geometry,
            seen,
            table,
            zero,
            partition,
        })
    }
}

/// The bytes of an encoded plan, or of the pending work around it
/// (`disk_writes`), not decoded yet.
pub(super) struct Rest<'a>(pub(super) &'a [u8]);

impl<'a> Rest<'a> {
    pub(super) fn take(&mut self, count: u64) -> Option<&'a [u8]> {
        let (taken, rest) = self.0.split_at_checked(usize::try_from(count).ok()?)?;
        self.0 = rest;
        Some(taken)
    }

    pub(super) fn number(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    /// A length and that many bytes.
    pub(super) fn counted(&mut self) -> Option<&'a [u8]> {
        let count = self.number()?;
        self.take(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_drivers::block::{Identity, RamDisk};

    const SERIAL: &str = "FAKE-SERIAL-0001";
    const NAME: &str = "Stela macOS";
    const NEW: &str = "CCCCCCCC-0000-0000-0000-000000000001";
    const DISK: &str = "DDDDDDDD-0000-0000-0000-000000000001";
    const LINUX: &str = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
    /// 64 MiB: room for an 18 MiB partition and others.
    const BYTES: u64 = 64 * MIB;

    fn guid(text: &str) -> Guid {
        text.parse().unwrap()
    }

    /// The GUIDs a plan draws, in order: a blank disk's own, then the new
    /// partition's.
    fn entropy(table: bool) -> impl FnMut() -> Guid {
        let mut drawn = if table {
            vec![guid(NEW)]
        } else {
            vec![guid(NEW), guid(DISK)]
        };
        move || drawn.pop().expect("no more GUIDs are drawn")
    }

    fn partition(kind: Guid, unique: &str, first_mib: u64, mib: u64, block: u64) -> Partition {
        Partition {
            type_guid: kind,
            unique_guid: guid(unique),
            first_lba: first_mib * MIB / block,
            last_lba: (first_mib + mib) * MIB / block - 1,
            attributes: 0,
            name: String::from("test"),
        }
    }

    /// A Linux partition at 1 MiB, another at 2 MiB and a Stela partition
    /// of 20 MiB at 40 MiB.
    fn layout(block: u64) -> Table {
        Table {
            disk_guid: guid(DISK),
            partitions: vec![
                partition(
                    guid(LINUX),
                    "AAAAAAAA-0000-0000-0000-000000000001",
                    1,
                    1,
                    block,
                ),
                partition(
                    guid(LINUX),
                    "AAAAAAAA-0000-0000-0000-000000000002",
                    2,
                    1,
                    block,
                ),
                partition(
                    Role::AppleRegion.type_guid(),
                    "AAAAAAAA-0000-0000-0000-000000000003",
                    40,
                    20,
                    block,
                ),
            ],
        }
    }

    /// A disk of `block`-byte blocks, every byte 0xa5 under `table`.
    fn disk(block: u64, table: Option<&Table>) -> RamDisk {
        let mut disk = RamDisk::new(SERIAL, BYTES / block, block as u32);
        disk.bytes.fill(0xa5);
        // No table: the ends a GPT would take are zero, as a blank disk's.
        let ends = (34 * block) as usize;
        disk.bytes[..ends].fill(0);
        let length = disk.bytes.len();
        disk.bytes[length - ends..].fill(0);
        if let Some(table) = table {
            for write in shared::encode(gpt::geometry(&disk.identity), table).unwrap() {
                disk.write(write.lba, &write.bytes).unwrap();
            }
        }
        disk
    }

    fn decision<'a>(disk: &RamDisk, table: Option<&'a Table>, place: Place) -> Decision<'a> {
        let block = u64::from(disk.identity.block_size);
        Decision {
            serial: SERIAL,
            geometry: gpt::geometry(&disk.identity),
            seen: seen(&disk.bytes[..(SEEN_BLOCKS * block) as usize]),
            table,
            deleted: &[],
            erased: false,
            place,
            name: NAME,
        }
    }

    fn free(first_mib: u64, mib: u64, block: u64) -> Place {
        Place::Free {
            first_lba: first_mib * MIB / block,
            bytes: mib * MIB,
        }
    }

    /// The table `plan`'s writes hold, read as a disk with only them would.
    fn planned_table(plan: &Plan) -> Table {
        let block = plan.geometry.block_bytes;
        let mut blank = RamDisk::new(SERIAL, plan.geometry.blocks, block as u32);
        for write in &plan.table {
            blank.write(write.lba, &write.bytes).unwrap();
        }
        gpt::read(&mut blank).unwrap()
    }

    fn zeroed(disk: &RamDisk, extent: Extent) -> bool {
        let block = u64::from(disk.identity.block_size);
        let span = (extent.lba * block) as usize..((extent.lba + extent.blocks) * block) as usize;
        disk.bytes[span].iter().all(|&byte| byte == 0)
    }

    #[test]
    fn a_new_partition_in_free_space_joins_the_table() {
        for block in [512, 4096] {
            let table = layout(block);
            let disk = disk(block, Some(&table));
            let made = plan(
                &decision(&disk, Some(&table), free(4, 18, block)),
                &mut entropy(true),
            )
            .unwrap();
            assert_eq!(
                made.partition,
                Planned {
                    guid: guid(NEW),
                    first_lba: 4 * MIB / block,
                    blocks: 18 * MIB / block,
                }
            );
            assert_eq!(
                made.target(),
                format!("{SERIAL}:{NEW}").parse::<Target>().unwrap()
            );
            // The first MiB, and the machine state: the last 16 MiB of an
            // 18 MiB partition, from a MiB boundary.
            assert_eq!(
                made.zero,
                [
                    Extent {
                        lba: 4 * MIB / block,
                        blocks: MIB / block
                    },
                    Extent {
                        lba: 6 * MIB / block,
                        blocks: 16 * MIB / block
                    },
                ]
            );
            // The backup copy first, the primary header after its entries.
            let last = BYTES / block - 1;
            let lbas: Vec<u64> = made.table.iter().map(|write| write.lba).collect();
            assert_eq!(lbas[1..], [last, 2, 1, 0], "{block}");
            let new = planned_table(&made);
            assert_eq!(new.disk_guid, guid(DISK));
            assert_eq!(new.partitions.len(), 4);
            assert_eq!(new.partitions[2].unique_guid, guid(NEW));
            assert_eq!(new.partitions[2].name, NAME);
            assert_eq!(new.partitions[2].role(), Some(Role::AppleRegion));
            for kept in &table.partitions {
                assert!(new.partitions.contains(kept));
            }
        }
    }

    #[test]
    fn deleted_partitions_leave_the_table_and_the_rest_stay() {
        let table = layout(512);
        let disk = disk(512, Some(&table));
        // Over both deleted partitions.
        let made = plan(
            &Decision {
                deleted: &[1, 0],
                ..decision(&disk, Some(&table), free(1, 20, 512))
            },
            &mut entropy(true),
        )
        .unwrap();
        let new = planned_table(&made);
        assert_eq!(new.partitions.len(), 2);
        assert_eq!(new.partitions[0].unique_guid, guid(NEW));
        assert_eq!(new.partitions[1], table.partitions[2]);
        // Over a partition that stays, nothing is planned.
        assert_eq!(
            plan(
                &Decision {
                    deleted: &[0],
                    ..decision(&disk, Some(&table), free(1, 20, 512))
                },
                &mut entropy(true),
            ),
            Err(PlanError::Overlap)
        );
        assert_eq!(
            plan(
                &Decision {
                    deleted: &[7],
                    ..decision(&disk, Some(&table), free(4, 18, 512))
                },
                &mut entropy(true),
            ),
            Err(PlanError::NoPartition(7))
        );
    }

    #[test]
    fn an_erased_disk_holds_only_the_new_partition() {
        let table = layout(512);
        let with_table = disk(512, Some(&table));
        let made = plan(
            &Decision {
                erased: true,
                ..decision(&with_table, Some(&table), free(1, 60, 512))
            },
            &mut entropy(true),
        )
        .unwrap();
        let new = planned_table(&made);
        assert_eq!(new.disk_guid, guid(DISK));
        assert_eq!(new.partitions.len(), 1);
        assert_eq!(new.partitions[0].unique_guid, guid(NEW));
        // A disk without a table gets one, with a GUID of its own.
        let blank = disk(512, None);
        let made = plan(
            &Decision {
                erased: true,
                ..decision(&blank, None, free(1, 60, 512))
            },
            &mut entropy(false),
        )
        .unwrap();
        let new = planned_table(&made);
        assert_eq!(new.disk_guid, guid(DISK));
        assert_eq!(new.partitions.len(), 1);
        assert_eq!(made.table.len(), 5);
    }

    #[test]
    fn a_reused_partition_writes_no_table() {
        for block in [512, 4096] {
            let table = layout(block);
            let disk = disk(block, Some(&table));
            let made = plan(&decision(&disk, Some(&table), Place::Reuse(2)), &mut || {
                panic!("a reused partition draws no GUID")
            })
            .unwrap();
            assert!(made.table.is_empty());
            assert_eq!(made.partition.guid, table.partitions[2].unique_guid);
            assert_eq!(made.partition.first_lba, 40 * MIB / block);
            assert_eq!(
                made.zero,
                [
                    Extent {
                        lba: 40 * MIB / block,
                        blocks: MIB / block
                    },
                    Extent {
                        lba: 44 * MIB / block,
                        blocks: 16 * MIB / block
                    },
                ]
            );
        }
        let table = layout(512);
        let disk = disk(512, Some(&table));
        // With another partition deleted the table is written, and the
        // reused partition keeps its GUID.
        let made = plan(
            &Decision {
                deleted: &[0],
                ..decision(&disk, Some(&table), Place::Reuse(2))
            },
            &mut || panic!("a reused partition draws no GUID"),
        )
        .unwrap();
        assert_eq!(made.table.len(), 5);
        assert_eq!(planned_table(&made).partitions, table.partitions[1..]);
        // Only a Stela partition that stays is reused.
        for (deleted, index) in [(&[][..], 0), (&[2][..], 2), (&[][..], 9)] {
            assert_eq!(
                plan(
                    &Decision {
                        deleted,
                        ..decision(&disk, Some(&table), Place::Reuse(index))
                    },
                    &mut entropy(true),
                ),
                Err(PlanError::NotReusable)
            );
        }
    }

    #[test]
    fn a_decision_that_cannot_be_carried_out_makes_no_plan() {
        let table = layout(512);
        let disk = disk(512, Some(&table));
        let refused = |decision: Decision<'_>| plan(&decision, &mut entropy(true)).unwrap_err();
        // Too small for a namespace and the machine state.
        assert_eq!(
            refused(decision(&disk, Some(&table), free(4, 16, 512))),
            PlanError::TooSmall
        );
        // Past the blocks a table leaves usable.
        assert_eq!(
            refused(decision(&disk, Some(&table), free(4, 60, 512))),
            PlanError::Overlap
        );
        assert_eq!(
            refused(Decision {
                erased: true,
                ..decision(&disk, Some(&table), free(4, 60, 512))
            }),
            PlanError::Table("partition outside the usable range")
        );
        assert_eq!(
            refused(Decision {
                serial: "",
                ..decision(&disk, Some(&table), free(4, 18, 512))
            }),
            PlanError::NoSerial
        );
        assert_eq!(
            refused(Decision {
                geometry: Disk {
                    block_bytes: 520,
                    blocks: 1 << 20
                },
                ..decision(&disk, Some(&table), free(4, 18, 512))
            }),
            PlanError::Blocks(520)
        );
    }

    #[test]
    fn applying_makes_the_partition_and_zeroes_only_its_ranges() {
        for block in [512, 4096] {
            let table = layout(block);
            let mut disk = disk(block, Some(&table));
            let made = plan(
                &decision(&disk, Some(&table), free(4, 18, block)),
                &mut entropy(true),
            )
            .unwrap();
            let before = disk.bytes.clone();
            made.apply(&mut disk).unwrap();
            let found = gpt::read(&mut disk).unwrap();
            assert_eq!(found, planned_table(&made));
            for extent in &made.zero {
                assert!(zeroed(&disk, *extent));
            }
            // Between the two ranges, and in every other partition, the
            // disk is as it was.
            let mib = MIB as usize;
            assert_eq!(disk.bytes[5 * mib..6 * mib], before[5 * mib..6 * mib]);
            assert_eq!(disk.bytes[mib..4 * mib], before[mib..4 * mib]);
            assert_eq!(disk.bytes[22 * mib..63 * mib], before[22 * mib..63 * mib]);
        }
    }

    #[test]
    fn applying_a_reused_partition_leaves_the_table_as_it_is() {
        let table = layout(512);
        let mut disk = disk(512, Some(&table));
        let made = plan(
            &decision(&disk, Some(&table), Place::Reuse(2)),
            &mut entropy(true),
        )
        .unwrap();
        let before = disk.bytes.clone();
        made.apply(&mut disk).unwrap();
        let mib = MIB as usize;
        assert_eq!(disk.bytes[..40 * mib], before[..40 * mib]);
        assert_eq!(disk.bytes[60 * mib..], before[60 * mib..]);
        assert_eq!(disk.bytes[41 * mib..44 * mib], before[41 * mib..44 * mib]);
        assert!(disk.bytes[40 * mib..41 * mib].iter().all(|&byte| byte == 0));
        assert!(disk.bytes[44 * mib..60 * mib].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn a_blank_or_foreign_disk_is_erased_into_one_table() {
        let mut blank = disk(512, None);
        // Another scheme's boot block.
        blank.bytes[..512].fill(0x5a);
        let made = plan(
            &Decision {
                erased: true,
                ..decision(&blank, None, free(1, 60, 512))
            },
            &mut entropy(false),
        )
        .unwrap();
        made.apply(&mut blank).unwrap();
        assert_eq!(gpt::read(&mut blank).unwrap().partitions.len(), 1);
    }

    #[test]
    fn another_disk_under_the_serial_is_not_written() {
        let table = layout(512);
        let chosen = disk(512, Some(&table));
        let made = plan(
            &decision(&chosen, Some(&table), free(4, 18, 512)),
            &mut entropy(true),
        )
        .unwrap();
        // Another size.
        let mut other = RamDisk::new(SERIAL, 2 * BYTES / 512, 512);
        let before = other.bytes.clone();
        assert_eq!(
            made.apply(&mut other),
            Err(ApplyError {
                step: Step::Identify,
                lba: None,
                cause: Cause::Geometry {
                    found: Disk {
                        block_bytes: 512,
                        blocks: 2 * BYTES / 512
                    }
                },
            })
        );
        assert_eq!(other.bytes, before);
        // Other blocks, the same disk seen with 4096-byte ones.
        let mut other = RamDisk::new(SERIAL, BYTES / 4096, 4096);
        assert!(matches!(
            made.apply(&mut other),
            Err(ApplyError {
                step: Step::Identify,
                cause: Cause::Geometry { .. },
                ..
            })
        ));
        // The same size with another table.
        let mut other = disk(
            512,
            Some(&Table {
                disk_guid: guid(NEW),
                ..table.clone()
            }),
        );
        let before = other.bytes.clone();
        let error = made.apply(&mut other).unwrap_err();
        assert_eq!(error.cause, Cause::Changed);
        assert_eq!(
            error.to_string(),
            "checking that it is the disk chosen at block 0: the disk's first blocks are not \
             what was chosen"
        );
        assert_eq!(other.bytes, before);
    }

    /// A disk whose write to one block fails.
    struct Failing {
        disk: RamDisk,
        at: u64,
    }

    impl BlockDevice for Failing {
        fn identity(&self) -> &Identity {
            &self.disk.identity
        }
        fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
            self.disk.read(lba, buffer)
        }
        fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
            let blocks = data.len() as u64 / u64::from(self.disk.identity.block_size);
            if (lba..lba + blocks).contains(&self.at) {
                return Err(BlockError::Timeout);
            }
            self.disk.write(lba, data)
        }
    }

    #[test]
    fn a_failed_write_names_its_step_and_block_and_leaves_one_whole_table() {
        let table = layout(512);
        let chosen = disk(512, Some(&table));
        let made = plan(
            &decision(&chosen, Some(&table), free(4, 18, 512)),
            &mut entropy(true),
        )
        .unwrap();
        let new = planned_table(&made);
        // Each of the table's writes failing in turn.
        for (index, write) in made.table.iter().enumerate() {
            let mut failing = Failing {
                disk: disk(512, Some(&table)),
                at: write.lba,
            };
            assert_eq!(
                made.apply(&mut failing),
                Err(ApplyError {
                    step: Step::Table,
                    lba: Some(write.lba),
                    cause: Cause::Device(BlockError::Timeout),
                })
            );
            // The earlier table until the primary's entries are written,
            // the new one after.
            let found = gpt::read(&mut failing.disk).unwrap();
            assert_eq!(
                found,
                if index < 3 {
                    table.clone()
                } else {
                    new.clone()
                }
            );
            // No block was zeroed.
            assert!(!zeroed(&failing.disk, made.zero[0]));
        }
        // A write of the zeroes failing, in the tail's third MiB.
        let at = 8 * MIB / 512 + 5;
        let mut failing = Failing {
            disk: disk(512, Some(&table)),
            at,
        };
        let error = made.apply(&mut failing).unwrap_err();
        assert_eq!(
            error,
            ApplyError {
                step: Step::Zero,
                lba: Some(8 * MIB / 512),
                cause: Cause::Device(BlockError::Timeout),
            }
        );
        assert_eq!(
            error.to_string(),
            format!(
                "zeroing the partition's first MiB and machine state at block {}: {}",
                8 * MIB / 512,
                BlockError::Timeout
            )
        );
        assert_eq!(gpt::read(&mut failing.disk).unwrap(), new);
    }

    #[test]
    fn a_plan_survives_its_bytes() {
        let table = layout(4096);
        let disk = disk(4096, Some(&table));
        for place in [free(4, 18, 4096), Place::Reuse(2)] {
            let made = plan(&decision(&disk, Some(&table), place), &mut entropy(true)).unwrap();
            let bytes = made.encode();
            assert_eq!(Plan::decode(&bytes), Some(made));
            // Cut short, grown or under another mark it is no plan.
            assert_eq!(Plan::decode(&bytes[..bytes.len() - 1]), None);
            assert_eq!(Plan::decode(&[&bytes[..], &[0]].concat()), None);
            assert_eq!(Plan::decode(&bytes[1..]), None);
        }
        assert_eq!(Plan::decode(&[]), None);
    }

    #[test]
    fn the_disk_is_found_by_its_serial_or_by_what_the_picker_read() {
        let table = layout(512);
        let chosen = disk(512, Some(&table));
        let made = plan(
            &decision(&chosen, Some(&table), free(4, 18, 512)),
            &mut entropy(true),
        )
        .unwrap();
        let renamed = |serial: &str, table: &Table| -> Box<dyn BlockDevice> {
            let mut disk = disk(512, Some(table));
            disk.identity.serial = serial.into();
            Box::new(disk)
        };
        let other = Table {
            disk_guid: guid(NEW),
            ..table.clone()
        };
        let mut devices = vec![renamed("FAKE-OTHER-0002", &other), renamed(SERIAL, &table)];
        assert_eq!(made.locate(&mut devices), Ok(1));
        // Two disks under the serial.
        devices.push(renamed(SERIAL, &other));
        assert_eq!(made.locate(&mut devices), Err(LocateError::Ambiguous(2)));
        // No disk under the serial: the one with the same size and first
        // blocks.
        let mut devices = vec![
            renamed("FAKE-OTHER-0002", &other),
            renamed("FAKE-BRIDGE-0003", &table),
            Box::new(RamDisk::new("FAKE-OTHER-0004", 16, 512)),
        ];
        assert_eq!(made.locate(&mut devices), Ok(1));
        devices.push(renamed("FAKE-BRIDGE-0005", &table));
        assert_eq!(made.locate(&mut devices), Err(LocateError::Ambiguous(2)));
        devices.truncate(1);
        assert_eq!(made.locate(&mut devices), Err(LocateError::NoDisk));
        assert_eq!(made.locate(&mut []), Err(LocateError::NoDisk));
    }
}
