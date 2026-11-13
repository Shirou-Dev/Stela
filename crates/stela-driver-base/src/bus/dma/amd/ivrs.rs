// SPDX-License-Identifier: GPL-2.0-only
// Layouts and entry encodings from Linux drivers/iommu/amd/init.c,
// commit cc9de5d4b5ab6459f5774946aa3195ad51236fa8.
// Copyright (C) 2007-2010 Advanced Micro Devices, Inc.
// Original authors: Joerg Roedel <jroedel@suse.de>, Leo Duran <leo.duran@amd.com>.
//! Resource-bounded IVRS decoding. Firmware descriptions grant no ownership,
//! requester isolation, MMIO access or permission to change a remapping unit.
//! Framing, checksums, known entry encodings, range grammar and version identity
//! are checked for every block, including superseded IVHD versions. Raw policy
//! flags, UID formats and extension bytes remain firmware descriptions: MMIO
//! alignment, reserved bits and policy semantics require separate live admission
//! and explicit refusal of unresolved requirements. Range starts must be followed
//! immediately by their end; interleaved entries, including padding, are refused.
//! Blocks and fixed-length device entries of unknown types are stepped over by
//! their length, as Linux's `init_iommu_all` and `init_iommu_from_acpi` do, and
//! recorded in [`Ivrs::skipped`].
use alloc::vec::Vec;
use core::cmp::Reverse;

const TABLE_HEADER: usize = 48;
const BLOCK_HEADER: usize = 4;
const IVHD_SHORT: usize = 24;
const IVHD_LONG: usize = 40;
const IVMD_HEADER: usize = 32;
const HID_PREFIX: usize = 22;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseError {
    pub offset: usize,
    pub kind: ErrorKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Truncated,
    Signature,
    TableLength,
    Checksum,
    BlockLength,
    UnsupportedEntry(u8),
    DeviceRange,
    DuplicateVersion,
    UnitIdentity,
    AddressOverflow,
    ResourceLimit,
    OutOfMemory,
}

fn error(offset: usize, kind: ErrorKind) -> ParseError {
    ParseError { offset, kind }
}

fn read16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("checked field"))
}

fn read64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("checked field"))
}

/// A part of an IVRS table the parser stepped over, each once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Skipped {
    /// A block of this unknown type. It may describe a unit or memory this
    /// boot does not see.
    Block(u8),
    /// A fixed-length device entry of this unknown type. It may name
    /// requesters whose routing this boot does not see.
    Entry(u8),
}

fn skip(skipped: &mut Vec<Skipped>, kind: Skipped) -> Result<(), ParseError> {
    if !skipped.contains(&kind) {
        skipped
            .try_reserve(1)
            .map_err(|_| error(TABLE_HEADER, ErrorKind::OutOfMemory))?;
        skipped.push(kind);
    }
    Ok(())
}

/// An entire, checksum-validated IVRS table. Input must have its exact declared
/// length; callers with a larger firmware mapping must first bound that view.
#[derive(Debug)]
pub struct Ivrs<'a> {
    raw: &'a [u8],
    units: Vec<Ivhd<'a>>,
    skipped: Vec<Skipped>,
}

impl<'a> Ivrs<'a> {
    /// `maximum_hardware_blocks` is the caller's admission budget,
    /// including superseded versions. No implicit platform-sized limit applies.
    /// All framing/entry checks precede index allocation. A budget failure may
    /// reject an input before examining its remaining bytes, never admit it.
    pub fn parse(raw: &'a [u8], maximum_hardware_blocks: usize) -> Result<Self, ParseError> {
        if raw.len() < TABLE_HEADER {
            return Err(error(raw.len(), ErrorKind::Truncated));
        }
        if &raw[..4] != b"IVRS" {
            return Err(error(0, ErrorKind::Signature));
        }
        if u64::from(read32(raw, 4)) != raw.len() as u64 {
            return Err(error(4, ErrorKind::TableLength));
        }
        if raw.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0 {
            return Err(error(9, ErrorKind::Checksum));
        }
        let mut offset = TABLE_HEADER;
        let mut hardware_blocks = 0usize;
        let mut skipped = Vec::new();
        while offset < raw.len() {
            let remaining = &raw[offset..];
            if remaining.len() < BLOCK_HEADER {
                return Err(error(offset, ErrorKind::Truncated));
            }
            let length = usize::from(read16(remaining, 2));
            if length < BLOCK_HEADER {
                return Err(error(offset + 2, ErrorKind::BlockLength));
            }
            let block = remaining
                .get(..length)
                .ok_or_else(|| error(offset, ErrorKind::Truncated))?;
            match block[0] {
                0x10 | 0x11 | 0x40 => {
                    let header = if block[0] == 0x10 {
                        IVHD_SHORT
                    } else {
                        IVHD_LONG
                    };
                    if length < header {
                        return Err(error(offset + 2, ErrorKind::BlockLength));
                    }
                    validate_entries(&block[header..], offset + header, &mut skipped)?;
                    if hardware_blocks == maximum_hardware_blocks {
                        return Err(error(offset, ErrorKind::ResourceLimit));
                    }
                    hardware_blocks += 1;
                }
                0x20..=0x22 => {
                    if length < IVMD_HEADER {
                        return Err(error(offset + 2, ErrorKind::BlockLength));
                    }
                    if block[0] == 0x22 && read16(block, 4) > read16(block, 6) {
                        return Err(error(offset + 4, ErrorKind::DeviceRange));
                    }
                    read64(block, 16)
                        .checked_add(read64(block, 24))
                        .ok_or_else(|| error(offset + 16, ErrorKind::AddressOverflow))?;
                }
                other => skip(&mut skipped, Skipped::Block(other))?,
            }
            offset += length;
        }
        let mut units = Vec::new();
        units
            .try_reserve_exact(hardware_blocks)
            .map_err(|_| error(TABLE_HEADER, ErrorKind::OutOfMemory))?;
        units.extend(
            Blocks {
                remaining: &raw[TABLE_HEADER..],
                offset: TABLE_HEADER,
            }
            .filter_map(|block| match block {
                Block::Hardware(unit) => Some(unit),
                Block::Memory(_) => None,
            }),
        );
        // The complete table is validated. Sorting needs no further allocation;
        // adjacent checks cover every version of each capability instance.
        units.sort_unstable_by_key(|unit| (unit.instance(), Reverse(unit.version()), unit.offset));
        for pair in units.windows(2) {
            let [first, second] = [pair[0], pair[1]];
            if first.instance() == second.instance() {
                let offending = first.offset.max(second.offset);
                if first.version() == second.version() {
                    return Err(error(offending, ErrorKind::DuplicateVersion));
                }
                if first.mmio_address() != second.mmio_address() {
                    return Err(error(offending, ErrorKind::UnitIdentity));
                }
            }
        }
        let mut previous = None;
        units.retain(|unit| {
            let id = unit.instance();
            let selected = previous != Some(id);
            previous = Some(id);
            selected
        });
        units.sort_unstable_by_key(|unit| unit.offset);
        Ok(Self {
            raw,
            units,
            skipped,
        })
    }

    /// The unknown blocks and device entries stepped over, each type once.
    /// While any is listed, the table does not describe every unit and
    /// requester route.
    pub fn skipped(&self) -> &[Skipped] {
        &self.skipped
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    pub fn info(&self) -> u32 {
        read32(self.raw, 36)
    }

    pub fn revision(&self) -> u8 {
        self.raw[8]
    }

    pub fn blocks(&self) -> Blocks<'a> {
        Blocks {
            remaining: &self.raw[TABLE_HEADER..],
            offset: TABLE_HEADER,
        }
    }

    pub fn hardware_blocks(&self) -> impl Iterator<Item = Ivhd<'a>> {
        self.blocks().filter_map(|block| match block {
            Block::Hardware(unit) => Some(unit),
            Block::Memory(_) => None,
        })
    }

    /// One highest-version description per (segment, IOMMU device ID,
    /// capability offset), in table order. All lower versions were validated.
    /// Descriptions do not grant independent ownership of their PCI function
    /// or MMIO aperture; live admission must exclude resource overlap.
    pub fn units(&self) -> impl ExactSizeIterator<Item = Ivhd<'a>> + '_ {
        self.units.iter().copied()
    }

    pub fn memory_definitions(&self) -> impl Iterator<Item = Ivmd<'a>> {
        self.blocks().filter_map(|block| match block {
            Block::Memory(memory) => Some(memory),
            Block::Hardware(_) => None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequesterId {
    pub segment: u16,
    pub device_id: u16,
}

/// Version order is explicit, independently of firmware block ordering.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HardwareVersion {
    Type10,
    Type11,
    Type40,
}

#[derive(Clone, Copy, Debug)]
pub struct Ivhd<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> Ivhd<'a> {
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }

    pub fn offset(self) -> usize {
        self.offset
    }

    pub fn version(self) -> HardwareVersion {
        match self.raw[0] {
            0x10 => HardwareVersion::Type10,
            0x11 => HardwareVersion::Type11,
            0x40 => HardwareVersion::Type40,
            _ => unreachable!("validated IVHD type"),
        }
    }

    pub fn flags(self) -> u8 {
        self.raw[1]
    }

    /// PCI function containing the IOMMU capability. Multiple instances may
    /// share this function; the capability offset distinguishes them.
    pub fn id(self) -> RequesterId {
        RequesterId {
            segment: read16(self.raw, 16),
            device_id: read16(self.raw, 4),
        }
    }

    pub fn capability_offset(self) -> u16 {
        read16(self.raw, 6)
    }

    pub fn mmio_address(self) -> u64 {
        read64(self.raw, 8)
    }

    pub fn info(self) -> u16 {
        read16(self.raw, 18)
    }

    /// Type 10 feature reporting; type 11/40 EFR attributes. These different
    /// encodings are preserved rather than compared as common identity.
    pub fn feature_or_attributes(self) -> u32 {
        read32(self.raw, 20)
    }

    /// Exact firmware EFR/EFR2 images in the pinned driver's long header.
    pub fn extended_features(self) -> Option<(u64, u64)> {
        (self.version() != HardwareVersion::Type10)
            .then(|| (read64(self.raw, 24), read64(self.raw, 32)))
    }

    pub fn entries(self) -> DeviceEntries<'a> {
        let header = if self.version() == HardwareVersion::Type10 {
            IVHD_SHORT
        } else {
            IVHD_LONG
        };
        DeviceEntries {
            remaining: &self.raw[header..],
            segment: self.id().segment,
        }
    }

    fn instance(self) -> (u16, u16, u16) {
        // AMD 48882 rev 3.11 section 5.2.2.1: a function may contain multiple
        // capabilities. HT UnitID may be shared and is not an instance key.
        let id = self.id();
        (id.segment, id.device_id, self.capability_offset())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Block<'a> {
    Hardware(Ivhd<'a>),
    Memory(Ivmd<'a>),
}

pub struct Blocks<'a> {
    remaining: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for Blocks<'a> {
    type Item = Block<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.remaining.is_empty() {
                return None;
            }
            let length = usize::from(read16(self.remaining, 2));
            let (raw, rest) = self.remaining.split_at(length);
            let offset = self.offset;
            self.offset += length;
            self.remaining = rest;
            match raw[0] {
                0x10 | 0x11 | 0x40 => return Some(Block::Hardware(Ivhd { raw, offset })),
                0x20..=0x22 => return Some(Block::Memory(Ivmd { raw, offset })),
                // Recorded in `Ivrs::skipped` by the validating parse.
                _ => {}
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangePolicy {
    Plain,
    Alias(RequesterId),
    Extended(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceKind<'a> {
    Padding,
    NotUsed,
    All,
    Select(RequesterId),
    RangeStart {
        first: RequesterId,
        policy: RangePolicy,
    },
    RangeEnd(RequesterId),
    Alias {
        requester: RequesterId,
        target: RequesterId,
    },
    Extended {
        requester: RequesterId,
        data: u32,
    },
    Special {
        header_id: u16,
        requester: RequesterId,
        handle: u8,
        variety: u8,
    },
    Hid {
        requester: RequesterId,
        hid: &'a [u8; 8],
        cid: &'a [u8; 8],
        uid_format: u8,
        uid: &'a [u8],
    },
}

/// Original bytes and data-setting flags are held even for padding, range
/// ends and special entries. HID UID formats are raw firmware metadata, not an
/// assertion that an ACPI namespace or UID conversion service is implemented.
#[derive(Clone, Copy, Debug)]
pub struct DeviceEntry<'a> {
    raw: &'a [u8],
    pub kind: DeviceKind<'a>,
}

impl<'a> DeviceEntry<'a> {
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }

    pub fn flags(self) -> u8 {
        self.raw[3]
    }
}

pub struct DeviceEntries<'a> {
    remaining: &'a [u8],
    segment: u16,
}

/// The entry's length and whether its type is known. Fixed-length types
/// encode their length in the type; of the variable-length types only the
/// ACPI HID entry is defined, in any IVHD type as Linux reads it.
fn entry_length(raw: &[u8], offset: usize) -> Result<(usize, bool), ParseError> {
    let Some(&kind) = raw.first() else {
        return Err(error(offset, ErrorKind::Truncated));
    };
    let length = if kind < 0x80 {
        4usize << (kind >> 6)
    } else if kind == 0xf0 {
        let prefix = raw
            .get(..HID_PREFIX)
            .ok_or_else(|| error(offset, ErrorKind::Truncated))?;
        HID_PREFIX + usize::from(prefix[21])
    } else {
        return Err(error(offset, ErrorKind::UnsupportedEntry(kind)));
    };
    if length > raw.len() {
        return Err(error(offset, ErrorKind::Truncated));
    }
    Ok((
        length,
        matches!(kind, 0x00..=0x04 | 0x40..=0x43 | 0x46..=0x48 | 0xf0),
    ))
}

fn validate_entries(
    mut raw: &[u8],
    mut offset: usize,
    skipped: &mut Vec<Skipped>,
) -> Result<(), ParseError> {
    let mut range: Option<(u16, usize)> = None;
    while !raw.is_empty() {
        let (length, known) = entry_length(raw, offset)?;
        if !known {
            skip(skipped, Skipped::Entry(raw[0]))?;
        }
        match (range, raw[0]) {
            (None, 0x03 | 0x43 | 0x47) => range = Some((read16(raw, 1), offset)),
            (Some((start, _)), 0x04) if read16(raw, 1) >= start => range = None,
            (Some(_), _) | (None, 0x04) => return Err(error(offset, ErrorKind::DeviceRange)),
            _ => (),
        }
        raw = &raw[length..];
        offset += length;
    }
    if let Some((_, start)) = range {
        return Err(error(start, ErrorKind::DeviceRange));
    }
    Ok(())
}

impl<'a> Iterator for DeviceEntries<'a> {
    type Item = DeviceEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let raw = loop {
            if self.remaining.is_empty() {
                return None;
            }
            let (length, known) = entry_length(self.remaining, 0).expect("validated IVHD entry");
            let (raw, rest) = self.remaining.split_at(length);
            self.remaining = rest;
            // Unknown types are recorded in `Ivrs::skipped`.
            if known {
                break raw;
            }
        };
        let requester = RequesterId {
            segment: self.segment,
            device_id: read16(raw, 1),
        };
        let target = || RequesterId {
            segment: self.segment,
            device_id: read16(raw, 5),
        };
        let kind = match raw[0] {
            0x00 | 0x40 => DeviceKind::Padding,
            0x41 => DeviceKind::NotUsed,
            0x01 => DeviceKind::All,
            0x02 => DeviceKind::Select(requester),
            0x03 | 0x43 | 0x47 => DeviceKind::RangeStart {
                first: requester,
                policy: match raw[0] {
                    0x43 => RangePolicy::Alias(target()),
                    0x47 => RangePolicy::Extended(read32(raw, 4)),
                    _ => RangePolicy::Plain,
                },
            },
            0x04 => DeviceKind::RangeEnd(requester),
            0x42 => DeviceKind::Alias {
                requester,
                target: target(),
            },
            0x46 => DeviceKind::Extended {
                requester,
                data: read32(raw, 4),
            },
            0x48 => DeviceKind::Special {
                header_id: requester.device_id,
                requester: target(),
                handle: raw[4],
                variety: raw[7],
            },
            0xf0 => DeviceKind::Hid {
                requester,
                hid: raw[4..12].try_into().expect("validated HID"),
                cid: raw[12..20].try_into().expect("validated CID"),
                uid_format: raw[20],
                uid: &raw[HID_PREFIX..],
            },
            _ => unreachable!("validated device entry"),
        };
        Some(DeviceEntry { raw, kind })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryScope {
    AllDevices,
    Device(RequesterId),
    Range {
        first: RequesterId,
        last: RequesterId,
    },
}

/// Exact, unrounded firmware policy. Flags, scope and bytes are not a grant to
/// reserve or unity-map those addresses. Extension bytes remain in `raw`.
#[derive(Clone, Copy, Debug)]
pub struct Ivmd<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> Ivmd<'a> {
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }

    pub fn offset(self) -> usize {
        self.offset
    }

    pub fn flags(self) -> u8 {
        self.raw[1]
    }

    /// Defined only for per-device/range records. AMD 48882 rev 3.11 Table 112
    /// reserves this field for type 20; its scope is all devices in the system.
    pub fn segment(self) -> Option<u16> {
        match self.raw[0] {
            0x20 => None,
            0x21 | 0x22 => Some(read16(self.raw, 8)),
            _ => unreachable!("validated IVMD type"),
        }
    }

    /// Raw field: reserved for type 20, requester ID for type 21, range start
    /// for type 22. Reserved bytes do not narrow the reported scope.
    pub fn device_id(self) -> u16 {
        read16(self.raw, 4)
    }

    /// Raw field: reserved for types 20/21, inclusive range end for type 22.
    pub fn auxiliary(self) -> u16 {
        read16(self.raw, 6)
    }

    pub fn scope(self) -> MemoryScope {
        match self.raw[0] {
            0x20 => MemoryScope::AllDevices,
            0x21 => MemoryScope::Device(RequesterId {
                segment: read16(self.raw, 8),
                device_id: self.device_id(),
            }),
            0x22 => MemoryScope::Range {
                first: RequesterId {
                    segment: read16(self.raw, 8),
                    device_id: self.device_id(),
                },
                last: RequesterId {
                    segment: read16(self.raw, 8),
                    device_id: self.auxiliary(),
                },
            },
            _ => unreachable!("validated IVMD type"),
        }
    }

    pub fn start(self) -> u64 {
        read64(self.raw, 16)
    }

    pub fn length(self) -> u64 {
        read64(self.raw, 24)
    }

    pub fn end(self) -> u64 {
        self.start() + self.length()
    }
}

#[cfg(test)]
mod tests;
