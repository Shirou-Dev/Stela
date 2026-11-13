//! Every change to a PC disk that was decided while the firmware's boot
//! services ran, which Stela's own drivers make after the firmware has
//! exited.
//!
//! Before the exit Stela only reads a PC disk: a firmware disk driver gives
//! its caller no say over timeouts or recovery and fails writes an
//! operating system's driver completes, so, as Linux does, only Stela's
//! drivers write one. What was decided is [`Pending`]: the change Install
//! macOS's disk picker planned ([`Plan`]), and then the [`Update`]s of
//! partitions, such as the NVRAM bank a boot saves once it has consumed the
//! one-shot variables it acts on. The loader carries it in memory
//! ([`Pending::encode`]). Once the drivers have started, the engine applies
//! the plan, looks the boot's partitions up and applies each update
//! ([`Update::apply`]), before anything of the engine reads those
//! partitions.
//!
//! Until then the loader reads the disk as the pending work leaves it
//! ([`Pending::lay`]), so what it decides from the disk is what it would
//! decide had the work been done.
//!
//! The order is the plan's, then the updates' as they were decided. An
//! update is decided on its partition as the plan of that time leaves it:
//! when the plan is replaced or dropped ([`Pending::replace_plan`]), the
//! updates of the partitions the plans make go with it.
//!
//! Pending work is made for one boot and never stored. A boot that stops
//! before it is applied leaves the disk as it was.
use super::{
    disk_plan::{Plan, Rest},
    gpt::Guid,
    storage::{self, StorageError, Target},
};
use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::fmt;
use stela_drivers::block::{BlockDevice, BlockError, Request};

/// Bytes for one place of a partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Piece {
    /// Where they go, in bytes from the partition's start.
    pub offset: u64,
    pub bytes: Vec<u8>,
}

/// What an update is, for the log and for what a failed one means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// The NVRAM bank without the one-shot variables this boot consumed,
    /// in the NOR's next bank.
    NvramBank,
    /// The zero header that clears a failed start's record
    /// (`failure_record`) once the loader has copied it into the log.
    FailureRecord,
}

impl Purpose {
    const ALL: [Self; 2] = [Self::NvramBank, Self::FailureRecord];

    fn code(self) -> u64 {
        match self {
            Self::NvramBank => 1,
            Self::FailureRecord => 2,
        }
    }
}

/// Pieces written to one partition, in order, and made durable together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub target: Target,
    pub purpose: Purpose,
    pub pieces: Vec<Piece>,
}

/// Why an update was not applied in full.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateError {
    /// The partition is not on the disks.
    Partition(StorageError),
    /// The disk takes no writes.
    ReadOnly,
    /// A piece is not whole blocks of the disk, or reaches outside the
    /// partition. Nothing was written.
    Outside { offset: u64 },
    /// The driver's error writing the piece at this byte of the partition.
    Write { offset: u64, error: BlockError },
    /// The driver's error making the writes durable.
    Flush(BlockError),
    /// The driver's error reading the piece at this byte back.
    Read { offset: u64, error: BlockError },
    /// The piece at this byte does not read back as written.
    Mismatch { offset: u64 },
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Partition(error) => write!(f, "{error}"),
            Self::ReadOnly => f.write_str("the disk takes no writes"),
            Self::Outside { offset } => write!(
                f,
                "the bytes at {offset:#x} are not whole blocks inside the partition"
            ),
            Self::Write { offset, error } => write!(f, "writing at {offset:#x}: {error}"),
            Self::Flush(error) => write!(f, "making the writes durable: {error}"),
            Self::Read { offset, error } => write!(f, "reading back at {offset:#x}: {error}"),
            Self::Mismatch { offset } => {
                write!(f, "the bytes at {offset:#x} do not read back as written")
            }
        }
    }
}

impl Update {
    /// Write the pieces to the update's partition on its disk among
    /// `devices`, found as the boot's partitions are
    /// ([`storage::find_partition`]), make them durable and read each back.
    /// Every piece is checked against the partition before the first is
    /// written.
    pub fn apply(&self, devices: &mut [Box<dyn BlockDevice>]) -> Result<(), UpdateError> {
        let (index, partition) =
            storage::find_partition(devices, &self.target).map_err(UpdateError::Partition)?;
        let device = &mut *devices[index];
        if device.identity().read_only {
            return Err(UpdateError::ReadOnly);
        }
        let block = u64::from(device.identity().block_size);
        let bytes = partition.blocks() * block;
        for piece in &self.pieces {
            let length = piece.bytes.len() as u64;
            let inside = piece
                .offset
                .checked_add(length)
                .is_some_and(|end| end <= bytes);
            if block == 0
                || !piece.offset.is_multiple_of(block)
                || !length.is_multiple_of(block)
                || !inside
            {
                return Err(UpdateError::Outside {
                    offset: piece.offset,
                });
            }
        }
        let lba = |piece: &Piece| partition.first_lba + piece.offset / block;
        for piece in &self.pieces {
            Request::Write {
                lba: lba(piece),
                data: piece.bytes.clone(),
                durable: false,
            }
            .run(device)
            .map_err(|error| UpdateError::Write {
                offset: piece.offset,
                error,
            })?;
        }
        device.flush().map_err(UpdateError::Flush)?;
        for piece in &self.pieces {
            let mut read = vec![0; piece.bytes.len()];
            device
                .read(lba(piece), &mut read)
                .map_err(|error| UpdateError::Read {
                    offset: piece.offset,
                    error,
                })?;
            if read != piece.bytes {
                return Err(UpdateError::Mismatch {
                    offset: piece.offset,
                });
            }
        }
        Ok(())
    }
}

/// The disk work one boot decided before the firmware exited.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pending {
    /// The change Install macOS's disk picker planned, applied first.
    pub plan: Option<Plan>,
    /// The partition updates, applied in this order after the plan.
    pub updates: Vec<Update>,
}

const MAGIC: &[u8; 8] = b"STELAPND";

impl Pending {
    pub fn is_empty(&self) -> bool {
        self.plan.is_none() && self.updates.is_empty()
    }

    /// Take `plan` in place of the pending one. The updates decided so far
    /// for the partition either plan makes are dropped: they were decided
    /// on a partition the earlier plan would have made, or on one the new
    /// plan makes afresh.
    pub fn replace_plan(&mut self, plan: Option<Plan>) {
        let earlier = core::mem::replace(&mut self.plan, plan);
        self.updates.retain(|update| {
            ![&earlier, &self.plan]
                .into_iter()
                .flatten()
                .any(|plan| plan.is_for(&update.target))
        });
    }

    /// Lay the pending updates of `target`'s partition over `buffer`, which
    /// holds the partition's bytes from `offset` as the disk, or the plan,
    /// has them: the bytes the partition holds once the updates are
    /// applied.
    pub fn lay(&self, target: &Target, offset: u64, buffer: &mut [u8]) {
        let end = offset + buffer.len() as u64;
        let pieces = self
            .updates
            .iter()
            .filter(|update| update.target == *target)
            .flat_map(|update| &update.pieces);
        for piece in pieces {
            let from = piece.offset.max(offset);
            let to = (piece.offset + piece.bytes.len() as u64).min(end);
            if from < to {
                buffer[(from - offset) as usize..(to - offset) as usize].copy_from_slice(
                    &piece.bytes[(from - piece.offset) as usize..(to - piece.offset) as usize],
                );
            }
        }
    }

    /// The pending work as bytes, for the memory the loader hands the
    /// engine.
    pub fn encode(&self) -> Vec<u8> {
        fn number(bytes: &mut Vec<u8>, value: u64) {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        fn counted(bytes: &mut Vec<u8>, counted: &[u8]) {
            number(bytes, counted.len() as u64);
            bytes.extend_from_slice(counted);
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        // No plan encodes to no bytes: an encoded plan starts with its own
        // magic.
        counted(
            &mut bytes,
            &self.plan.as_ref().map(Plan::encode).unwrap_or_default(),
        );
        number(&mut bytes, self.updates.len() as u64);
        for update in &self.updates {
            counted(&mut bytes, update.target.serial.as_bytes());
            bytes.extend_from_slice(&update.target.partition.0);
            number(&mut bytes, update.purpose.code());
            number(&mut bytes, update.pieces.len() as u64);
            for piece in &update.pieces {
                number(&mut bytes, piece.offset);
                counted(&mut bytes, &piece.bytes);
            }
        }
        bytes
    }

    /// The pending work [`Self::encode`] made `bytes` from; `None` when
    /// they are not all of it.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut rest = Rest(bytes);
        if rest.take(MAGIC.len() as u64)? != MAGIC {
            return None;
        }
        let plan = match rest.counted()? {
            [] => None,
            plan => Some(Plan::decode(plan)?),
        };
        let mut updates = Vec::new();
        for _ in 0..rest.number()? {
            let serial = String::from(core::str::from_utf8(rest.counted()?).ok()?);
            let partition = Guid(rest.take(16)?.try_into().ok()?);
            let code = rest.number()?;
            let purpose = Purpose::ALL
                .into_iter()
                .find(|purpose| purpose.code() == code)?;
            let mut pieces = Vec::new();
            for _ in 0..rest.number()? {
                pieces.push(Piece {
                    offset: rest.number()?,
                    bytes: rest.counted()?.to_vec(),
                });
            }
            updates.push(Update {
                target: Target { serial, partition },
                purpose,
                pieces,
            });
        }
        rest.0.is_empty().then_some(Self { plan, updates })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        disk_plan::{self, Decision, Place, SEEN_BLOCKS},
        gpt, machine_state,
    };
    use super::*;
    use stela_drivers::block::{Identity, RamDisk};
    use stela_formats::payload::gpt::{self as shared, Partition, Role, Table};

    const MIB: u64 = 1 << 20;
    const SERIAL: &str = "FAKE-SERIAL-0001";
    const HELD: &str = "AAAAAAAA-0000-0000-0000-000000000003";
    const NEW: &str = "CCCCCCCC-0000-0000-0000-000000000001";
    /// The partition already on the disk: 20 MiB at 40 MiB.
    const HELD_MIB: u64 = 40;

    fn guid(text: &str) -> Guid {
        text.parse().unwrap()
    }

    fn target(partition: &str) -> Target {
        Target {
            serial: SERIAL.into(),
            partition: guid(partition),
        }
    }

    fn table(block: u64) -> Table {
        Table {
            disk_guid: guid("DDDDDDDD-0000-0000-0000-000000000001"),
            partitions: vec![Partition {
                type_guid: Role::AppleRegion.type_guid(),
                unique_guid: guid(HELD),
                first_lba: HELD_MIB * MIB / block,
                last_lba: (HELD_MIB + 20) * MIB / block - 1,
                attributes: 0,
                name: String::from("test"),
            }],
        }
    }

    /// A 64 MiB disk of `block`-byte blocks holding [`table`], every other
    /// byte 0xa5.
    fn disk(block: u64) -> RamDisk {
        let mut disk = RamDisk::new(SERIAL, 64 * MIB / block, block as u32);
        disk.bytes.fill(0xa5);
        for write in shared::encode(gpt::geometry(&disk.identity), &table(block)).unwrap() {
            disk.write(write.lba, &write.bytes).unwrap();
        }
        disk
    }

    fn boxed(disk: RamDisk) -> Vec<Box<dyn BlockDevice>> {
        vec![Box::new(disk)]
    }

    /// The bytes of `devices`' only disk at `offset` of the partition that
    /// starts at `first_mib`.
    fn held(
        devices: &mut [Box<dyn BlockDevice>],
        first_mib: u64,
        offset: u64,
        bytes: usize,
    ) -> Vec<u8> {
        let block = u64::from(devices[0].identity().block_size);
        let mut read = vec![0; bytes];
        devices[0]
            .read((first_mib * MIB + offset) / block, &mut read)
            .unwrap();
        read
    }

    /// A bank save as the loader queues one: two 4 KiB sectors of the
    /// machine state in the partition's tail, the later sector first.
    fn save(partition: &str, state_offset: u64) -> Update {
        Update {
            target: target(partition),
            purpose: Purpose::NvramBank,
            pieces: vec![
                Piece {
                    offset: state_offset + 0x3000,
                    bytes: vec![0x11; 4096],
                },
                Piece {
                    offset: state_offset + 0x2000,
                    bytes: vec![0x22; 4096],
                },
            ],
        }
    }

    fn state_offset(partition_mib: u64) -> u64 {
        machine_state::split(partition_mib * MIB)
            .unwrap()
            .state_offset()
    }

    #[test]
    fn a_bank_save_is_written_made_durable_and_read_back() {
        for block in [512, 4096] {
            let state = state_offset(20);
            let update = save(HELD, state);
            let mut devices = boxed(disk(block));
            update.apply(&mut devices).unwrap();
            assert_eq!(
                held(&mut devices, HELD_MIB, state + 0x2000, 8192),
                [vec![0x22; 4096], vec![0x11; 4096]].concat(),
                "{block}"
            );
            // Its neighbours stay.
            assert_eq!(
                held(&mut devices, HELD_MIB, state + 0x1000, 4096),
                vec![0xa5; 4096]
            );
            assert_eq!(
                held(&mut devices, HELD_MIB, state + 0x4000, 4096),
                vec![0xa5; 4096]
            );
        }
    }

    /// A disk whose write to one block fails, or whose writes are lost.
    struct Faulty {
        disk: RamDisk,
        fails_at: Option<u64>,
        loses: bool,
        flushes: usize,
    }

    impl BlockDevice for Faulty {
        fn identity(&self) -> &Identity {
            &self.disk.identity
        }
        fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
            self.disk.read(lba, buffer)
        }
        fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
            let blocks = data.len() as u64 / u64::from(self.disk.identity.block_size);
            if self
                .fails_at
                .is_some_and(|at| (lba..lba + blocks).contains(&at))
            {
                return Err(BlockError::Timeout);
            }
            if self.loses {
                return Ok(());
            }
            self.disk.write(lba, data)
        }
        fn flush(&mut self) -> Result<(), BlockError> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn a_failed_update_says_where_and_why() {
        let state = state_offset(20);
        let update = save(HELD, state);
        // The second piece's block refuses the write.
        let fails_at = (HELD_MIB * MIB + state + 0x2000) / 512;
        let mut devices: Vec<Box<dyn BlockDevice>> = vec![Box::new(Faulty {
            disk: disk(512),
            fails_at: Some(fails_at),
            loses: false,
            flushes: 0,
        })];
        let error = update.apply(&mut devices).unwrap_err();
        assert_eq!(
            error,
            UpdateError::Write {
                offset: state + 0x2000,
                error: BlockError::Timeout
            }
        );
        assert!(error.to_string().starts_with("writing at 0x"), "{error}");

        // Writes the disk accepts and does not keep are found reading back.
        let mut devices: Vec<Box<dyn BlockDevice>> = vec![Box::new(Faulty {
            disk: disk(512),
            fails_at: None,
            loses: true,
            flushes: 0,
        })];
        assert_eq!(
            update.apply(&mut devices).unwrap_err(),
            UpdateError::Mismatch {
                offset: state + 0x3000
            }
        );

        // A disk that takes no writes, and a partition that is not there.
        let mut read_only = disk(512);
        read_only.identity.read_only = true;
        let before = read_only.bytes.clone();
        let mut devices = boxed(read_only);
        assert_eq!(
            update.apply(&mut devices).unwrap_err(),
            UpdateError::ReadOnly
        );
        assert_eq!(held(&mut devices, 0, 0, before.len()), before);
        let mut devices = boxed(disk(512));
        assert_eq!(
            save(NEW, state).apply(&mut devices).unwrap_err(),
            UpdateError::Partition(StorageError::NoPartition(guid(NEW)))
        );
    }

    #[test]
    fn pieces_outside_the_partition_or_its_blocks_write_nothing() {
        let piece = |offset, bytes| Update {
            target: target(HELD),
            purpose: Purpose::FailureRecord,
            pieces: vec![
                Piece {
                    offset: 0,
                    bytes: vec![0; 4096],
                },
                Piece {
                    offset,
                    bytes: vec![0; bytes],
                },
            ],
        };
        for (block, offset, bytes) in [
            // Past the partition's end, and across it.
            (512, 20 * MIB, 512),
            (512, 20 * MIB - 512, 1024),
            // Not whole blocks.
            (512, 256, 512),
            (4096, 512, 4096),
            (4096, 4096, 512),
            (512, u64::MAX - 511, 512),
        ] {
            let mut devices = boxed(disk(block));
            let before = held(&mut devices, 0, 0, (64 * MIB) as usize);
            assert_eq!(
                piece(offset, bytes).apply(&mut devices).unwrap_err(),
                UpdateError::Outside { offset },
                "{block} {offset:#x} {bytes}"
            );
            assert_eq!(held(&mut devices, 0, 0, (64 * MIB) as usize), before);
        }
    }

    /// The plan that makes an 18 MiB partition [`NEW`] at 4 MiB of `disk`.
    fn plan(disk: &RamDisk) -> Plan {
        let block = u64::from(disk.identity.block_size);
        let table = table(block);
        disk_plan::plan(
            &Decision {
                serial: SERIAL,
                geometry: gpt::geometry(&disk.identity),
                seen: disk_plan::seen(&disk.bytes[..(SEEN_BLOCKS * block) as usize]),
                table: Some(&table),
                deleted: &[],
                erased: false,
                place: Place::Free {
                    first_lba: 4 * MIB / block,
                    bytes: 18 * MIB,
                },
                name: "Stela macOS",
            },
            &mut || guid(NEW),
        )
        .unwrap()
    }

    #[test]
    fn an_update_of_the_partition_the_plan_makes_follows_the_plan() {
        let disk = disk(512);
        let state = state_offset(18);
        let mut pending = Pending::default();
        pending.replace_plan(Some(plan(&disk)));
        pending.updates.push(save(NEW, state));
        let mut devices = boxed(disk);
        // Before the plan the partition is not there to update.
        assert_eq!(
            pending.updates[0].apply(&mut devices).unwrap_err(),
            UpdateError::Partition(StorageError::NoPartition(guid(NEW)))
        );
        // The engine's order: the plan, then the updates.
        let made = pending.plan.as_ref().unwrap();
        let index = made.locate(&mut devices).unwrap();
        made.apply(&mut *devices[index]).unwrap();
        for update in &pending.updates {
            update.apply(&mut devices).unwrap();
        }
        // The machine state the plan zeroed holds the save and nothing
        // else.
        assert_eq!(
            held(&mut devices, 4, state, 0x5000),
            [
                vec![0; 0x2000],
                vec![0x22; 4096],
                vec![0x11; 4096],
                vec![0; 4096]
            ]
            .concat()
        );
    }

    #[test]
    fn a_new_plan_drops_the_updates_decided_before_it_for_its_partition() {
        let disk = disk(512);
        let mut pending = Pending::default();
        pending.updates.push(save(HELD, 0));
        pending.updates.push(save(NEW, 0));
        // A plan for another partition leaves the held one's update, and
        // drops the one decided for the partition it makes afresh.
        pending.replace_plan(Some(plan(&disk)));
        assert_eq!(pending.updates, [save(HELD, 0)]);
        // An update decided on the planned partition goes with the plan.
        pending.updates.push(save(NEW, 0));
        pending.replace_plan(None);
        assert_eq!(pending.updates, [save(HELD, 0)]);
        assert!(!pending.is_empty());
        pending.updates.clear();
        assert!(pending.is_empty());
    }

    #[test]
    fn pending_updates_read_as_applied() {
        let mut pending = Pending::default();
        pending.updates.push(save(HELD, 0));
        // A later update of the same bytes wins, as it does on the disk.
        pending.updates.push(Update {
            target: target(HELD),
            purpose: Purpose::NvramBank,
            pieces: vec![Piece {
                offset: 0x3800,
                bytes: vec![0x33; 512],
            }],
        });
        let laid = |partition: &str, offset: u64, bytes: usize| {
            let mut buffer = vec![0xa5; bytes];
            pending.lay(&target(partition), offset, &mut buffer);
            buffer
        };
        // A read across the pieces' edges, from the middle of one.
        assert_eq!(
            laid(HELD, 0x1800, 0x3000),
            [
                vec![0xa5; 0x800],
                vec![0x22; 0x1000],
                vec![0x11; 0x800],
                vec![0x33; 0x200],
                vec![0x11; 0x600],
                vec![0xa5; 0x800]
            ]
            .concat()
        );
        // Reads beside the pieces, and another partition's, stay.
        assert_eq!(laid(HELD, 0, 0x2000), vec![0xa5; 0x2000]);
        assert_eq!(laid(HELD, 0x4000, 0x1000), vec![0xa5; 0x1000]);
        assert_eq!(laid(NEW, 0x2000, 0x2000), vec![0xa5; 0x2000]);
        // What is read is what the disk holds once they are applied.
        let mut devices = boxed(disk(512));
        for update in &pending.updates {
            update.apply(&mut devices).unwrap();
        }
        assert_eq!(
            held(&mut devices, HELD_MIB, 0x1800, 0x3000),
            laid(HELD, 0x1800, 0x3000)
        );
    }

    #[test]
    fn pending_work_survives_its_bytes() {
        let disk = disk(4096);
        let mut pending = Pending::default();
        assert_eq!(Pending::decode(&pending.encode()), Some(pending.clone()));
        pending.updates.push(save(HELD, 0x10000));
        pending.updates.push(Update {
            target: target(NEW),
            purpose: Purpose::FailureRecord,
            pieces: vec![Piece {
                offset: 0x2000,
                bytes: vec![0; 4096],
            }],
        });
        assert_eq!(Pending::decode(&pending.encode()), Some(pending.clone()));
        pending.plan = Some(plan(&disk));
        let bytes = pending.encode();
        assert_eq!(Pending::decode(&bytes), Some(pending));
        // Cut short, longer, or another magic: not pending work.
        for cut in [0, 7, 8, bytes.len() / 2, bytes.len() - 1] {
            assert_eq!(Pending::decode(&bytes[..cut]), None, "{cut}");
        }
        assert_eq!(Pending::decode(&[&bytes[..], &[0]].concat()), None);
        let mut other = bytes.clone();
        other[0] ^= 1;
        assert_eq!(Pending::decode(&other), None);
        // An unknown purpose is not guessed at.
        let mut unknown = Pending {
            plan: None,
            updates: vec![save(HELD, 0)],
        }
        .encode();
        let code = 8 + 8 + 8 + 8 + SERIAL.len() + 16;
        unknown[code] = 9;
        assert_eq!(Pending::decode(&unknown), None);
    }
}
