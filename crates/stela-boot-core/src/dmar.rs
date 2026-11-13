//! DMAR units, PCI DMA routes and original interrupt-source metadata.
//! General parsing preserves firmware source identities for later ownership
//! checks. The flat-owner policy separately refuses routing it cannot resolve.
use crate::remapping::Scope;
use alloc::vec::Vec;

const HEADER: usize = 48;
const DRHD: u16 = 0;
const RMRR: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmarError {
    InvalidTable,
    InvalidStructure,
    UnsupportedStructure(u16),
    UnsupportedScope(u8),
    UnsupportedWidth,
    UnsupportedRouting,
    MissingUnit,
    MultipleUnits,
    DuplicateRequester(u16),
    MissingRequester(u16),
    UnlistedRequester(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardwareUnit {
    pub base: u64,
    pub bytes: usize,
    pub segment: u16,
    pub physical_bits: u8,
}

fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn quad(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

/// Firmware source classes outside PCI endpoint/subhierarchy DMA scopes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
    IoApic,
    Hpet,
    Namespace,
    Reserved(u8),
}

/// Original non-PCI scope metadata, before topology or source ownership checks.
/// IOAPIC paths require bridge resolution; HPET/namespace paths encode their
/// platform-assigned source ID. Parsing a scope grants no interrupt route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceScope {
    pub kind: SourceKind,
    pub flags: u8,
    pub reserved: u8,
    pub enumeration_id: u8,
    pub bus: u8,
    pub path: Vec<(u8, u8)>,
}

struct Scopes {
    pci: Vec<Scope>,
    sources: Vec<SourceScope>,
}

/// A remapping hardware unit (DRHD): its registers, segment and the PCI
/// requesters it translates, or every requester on the segment no other
/// unit lists when `include_all`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Drhd {
    pub base: u64,
    pub bytes: usize,
    pub segment: u16,
    pub include_all: bool,
    pub scopes: Vec<Scope>,
    pub sources: Vec<SourceScope>,
}

/// A reserved memory region (RMRR): memory the firmware keeps DMA-ing to
/// for the requesters in its scopes, which a translating unit must map one
/// to one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rmrr {
    pub segment: u16,
    pub base: u64,
    pub limit: u64,
    pub scopes: Vec<Scope>,
    pub sources: Vec<SourceScope>,
}

/// A part of a DMAR table the parser passed over, as Linux's
/// `dmar_table_init` and `dmar_parse_dev_scope` do. Each kind is recorded
/// once per table, for one report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Skipped {
    /// Reserved bits or bytes are set in the table header, a DRHD, an RMRR
    /// or a device scope. They are ignored.
    ReservedBits,
    /// An include-all DRHD lists PCI device scopes. It covers those
    /// requesters anyway; the scopes are ignored.
    IncludeAllScopes,
    /// A device scope has an odd length. Its last byte is ignored.
    OddScopeLength,
    /// An RMRR is not page-aligned. It is widened to whole pages.
    UnalignedRegion,
    /// A device scope names no path, or a device or function out of range.
    /// It is dropped, so the units' coverage is not fully known.
    UnusableScope,
    /// An RMRR is empty, wraps, or ends past the host address width. It is
    /// dropped, so the memory its requesters keep using is not fully known.
    UnusableRegion,
}

impl Skipped {
    /// Whether the routing or reserved memory the table describes is no
    /// longer fully known, so no unit may translate from it.
    pub fn incomplete(self) -> bool {
        matches!(self, Self::UnusableScope | Self::UnusableRegion)
    }
}

fn skip(skipped: &mut Vec<Skipped>, kind: Skipped) {
    if !skipped.contains(&kind) {
        skipped.push(kind);
    }
}

/// A parsed DMAR table: the host address width and the units and reserved
/// regions. ATSR, RHSA, ANDD, SATC and later structures describe ATS,
/// proximity and namespace devices. Their kinds remain recorded for policies
/// that require a complete interrupt-source inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Remapping {
    pub physical_bits: u8,
    /// Original DMAR platform flags; capability bits are not ownership grants.
    pub flags: u8,
    pub units: Vec<Drhd>,
    pub reserved: Vec<Rmrr>,
    /// Structures not interpreted by the DMA planner. Root-mode admission must
    /// account for them rather than assume a complete interrupt inventory.
    pub additional_structures: Vec<u16>,
    /// What the parser passed over, each kind once.
    pub skipped: Vec<Skipped>,
}

impl Remapping {
    /// Whether every unit's coverage and every reserved region is known.
    pub fn complete(&self) -> bool {
        !self.skipped.iter().any(|kind| kind.incomplete())
    }
}

/// Partition PCI DMA scopes from the remaining original firmware sources.
/// Only a scope too short to step over fails the structure. Reserved bytes,
/// an odd length and unusable paths are passed over as Linux does.
fn scopes(entry: &[u8], from: usize, skipped: &mut Vec<Skipped>) -> Result<Scopes, DmarError> {
    let mut found = Scopes {
        pci: Vec::new(),
        sources: Vec::new(),
    };
    let mut scope = from;
    while scope < entry.len() {
        let header = entry
            .get(scope..scope + 6)
            .ok_or(DmarError::InvalidStructure)?;
        let bytes = usize::from(header[1]);
        if bytes < 6 {
            return Err(DmarError::InvalidStructure);
        }
        let end = scope + bytes;
        let (hops, odd) = entry
            .get(scope + 6..end)
            .ok_or(DmarError::InvalidStructure)?
            .as_chunks::<2>();
        scope = end;
        if !odd.is_empty() {
            skip(skipped, Skipped::OddScopeLength);
        }
        let path = hops.iter().map(|hop| (hop[0], hop[1])).collect();
        let kind = match header[0] {
            1 | 2 => None,
            3 => Some(SourceKind::IoApic),
            4 => Some(SourceKind::Hpet),
            5 => Some(SourceKind::Namespace),
            other => Some(SourceKind::Reserved(other)),
        };
        // A reserved scope type keeps its unknown path for the policy.
        if !matches!(kind, Some(SourceKind::Reserved(_)))
            && (hops.is_empty() || hops.iter().any(|hop| hop[0] > 31 || hop[1] > 7))
        {
            skip(skipped, Skipped::UnusableScope);
            continue;
        }
        let Some(kind) = kind else {
            // Linux reads only the type, bus and path of a PCI scope.
            if header[2..5] != [0, 0, 0] {
                skip(skipped, Skipped::ReservedBits);
            }
            found.pci.push(Scope {
                bridge: header[0] == 2,
                bus: header[5],
                path,
            });
            continue;
        };
        // Flags and reserved bytes stay recorded: the policy refuses
        // sources whose meaning they could change.
        found.sources.push(SourceScope {
            kind,
            flags: header[2],
            reserved: header[3],
            enumeration_id: header[4],
            bus: header[5],
            path,
        });
    }
    Ok(found)
}

/// Parse a DMAR table, validating its checksum, width and the framing of
/// every structure. Like Linux's `dmar_walk_remapping_entries`, it steps over
/// structures of other types by their length and fails only on framing it
/// cannot step over or a register window it cannot use; what it passes over
/// is recorded in [`Remapping::skipped`].
pub fn parse(table: &[u8]) -> Result<Remapping, DmarError> {
    if table.len() < HEADER
        || &table[..4] != b"DMAR"
        || u32::from_le_bytes(table[4..8].try_into().unwrap()) as usize != table.len()
        || table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0
    {
        return Err(DmarError::InvalidTable);
    }
    let mut skipped = Vec::new();
    if table[37] & !7 != 0 || table[38..HEADER].iter().any(|byte| *byte != 0) {
        skip(&mut skipped, Skipped::ReservedBits);
    }
    let physical_bits = table[36]
        .checked_add(1)
        .filter(|bits| (32..=64).contains(bits))
        .ok_or(DmarError::UnsupportedWidth)?;
    let mut remapping = Remapping {
        physical_bits,
        flags: table[37],
        units: Vec::new(),
        reserved: Vec::new(),
        additional_structures: Vec::new(),
        skipped,
    };
    let mut offset = HEADER;
    while offset < table.len() {
        let header = table
            .get(offset..offset + 4)
            .ok_or(DmarError::InvalidStructure)?;
        let kind = word(header, 0);
        let length = usize::from(word(header, 2));
        let end = offset
            .checked_add(length)
            .filter(|_| length >= 4)
            .ok_or(DmarError::InvalidStructure)?;
        let entry = table.get(offset..end).ok_or(DmarError::InvalidStructure)?;
        match kind {
            DRHD => {
                if length < 16 {
                    return Err(DmarError::InvalidStructure);
                }
                if entry[4] & !1 != 0 || entry[5] & 0xf0 != 0 {
                    skip(&mut remapping.skipped, Skipped::ReservedBits);
                }
                let base = quad(entry, 8);
                let bytes = 1usize
                    .checked_shl(12 + u32::from(entry[5] & 0xf))
                    .ok_or(DmarError::InvalidStructure)?;
                if base == 0
                    || !base.is_multiple_of(bytes as u64)
                    || base.checked_add(bytes as u64).is_none()
                {
                    return Err(DmarError::InvalidStructure);
                }
                let mut scopes = scopes(entry, 16, &mut remapping.skipped)?;
                let include_all = entry[4] & 1 != 0;
                if include_all && !scopes.pci.is_empty() {
                    scopes.pci.clear();
                    skip(&mut remapping.skipped, Skipped::IncludeAllScopes);
                }
                remapping.units.push(Drhd {
                    base,
                    bytes,
                    segment: word(entry, 6),
                    include_all,
                    scopes: scopes.pci,
                    sources: scopes.sources,
                });
            }
            RMRR => {
                if length < 24 {
                    return Err(DmarError::InvalidStructure);
                }
                if entry[4..6] != [0, 0] {
                    skip(&mut remapping.skipped, Skipped::ReservedBits);
                }
                let (base, limit) = (quad(entry, 8), quad(entry, 16));
                // Linux's `rmrr_sanity_check` warns about an unaligned
                // region and maps the pages it touches.
                let (page, last) = (base & !0xfff, limit | 0xfff);
                if limit < base
                    || last
                        .checked_add(1)
                        .is_none_or(|end| physical_bits < 64 && end > 1u64 << physical_bits)
                {
                    skip(&mut remapping.skipped, Skipped::UnusableRegion);
                    offset = end;
                    continue;
                }
                if (page, last) != (base, limit) {
                    skip(&mut remapping.skipped, Skipped::UnalignedRegion);
                }
                let (base, limit) = (page, last);
                let scopes = scopes(entry, 24, &mut remapping.skipped)?;
                remapping.reserved.push(Rmrr {
                    segment: word(entry, 6),
                    base,
                    limit,
                    scopes: scopes.pci,
                    sources: scopes.sources,
                });
            }
            other => remapping.additional_structures.push(other),
        }
        offset = end;
    }
    if remapping.units.is_empty() {
        return Err(DmarError::MissingUnit);
    }
    Ok(remapping)
}

/// Validate the complete table before returning one owner of the live flat bus. No
/// unknown/RMRR structure is skipped in order to manufacture a usable domain.
pub fn single_flat_owner(
    table: &[u8],
    segment: u16,
    live_requesters: &[u16],
) -> Result<HardwareUnit, DmarError> {
    if live_requesters.is_empty() || live_requesters.iter().any(|requester| requester >> 8 != 0) {
        return Err(DmarError::UnsupportedRouting);
    }
    let mut expected = live_requesters.to_vec();
    expected.sort_unstable();
    if let Some(pair) = expected.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(DmarError::DuplicateRequester(pair[0]));
    }
    if table.len() < HEADER
        || &table[..4] != b"DMAR"
        || u32::from_le_bytes(table[4..8].try_into().unwrap()) as usize != table.len()
        || table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0
        || table[37] & !7 != 0
        || table[38..HEADER].iter().any(|byte| *byte != 0)
    {
        return Err(DmarError::InvalidTable);
    }
    let physical_bits = table[36]
        .checked_add(1)
        .filter(|bits| (32..=52).contains(bits))
        .ok_or(DmarError::UnsupportedWidth)?;
    let mut unit = None;
    let mut offset = HEADER;
    while offset < table.len() {
        let header = table
            .get(offset..offset + 4)
            .ok_or(DmarError::InvalidStructure)?;
        let kind = word(header, 0);
        let length = usize::from(word(header, 2));
        if length < 4 {
            return Err(DmarError::InvalidStructure);
        }
        let end = offset
            .checked_add(length)
            .ok_or(DmarError::InvalidStructure)?;
        let entry = table.get(offset..end).ok_or(DmarError::InvalidStructure)?;
        if kind != DRHD {
            return Err(DmarError::UnsupportedStructure(kind));
        }
        if length < 16 {
            return Err(DmarError::InvalidStructure);
        }
        if unit.is_some() {
            return Err(DmarError::MultipleUnits);
        }
        if entry[4] & !1 != 0 || word(entry, 6) != segment {
            return Err(DmarError::UnsupportedRouting);
        }
        let base = u64::from_le_bytes(entry[8..16].try_into().unwrap());
        let bytes = 1usize
            .checked_shl(12 + u32::from(entry[5]))
            .ok_or(DmarError::InvalidStructure)?;
        if base == 0
            || !base.is_multiple_of(4096)
            || base
                .checked_add(bytes as u64)
                .is_none_or(|end| end > 1u64 << physical_bits)
        {
            return Err(DmarError::InvalidStructure);
        }
        let mut scope = 16;
        let mut endpoints = Vec::new();
        while scope < length {
            let scope_header = entry
                .get(scope..scope + 6)
                .ok_or(DmarError::InvalidStructure)?;
            let scope_kind = scope_header[0];
            let scope_bytes = usize::from(scope_header[1]);
            if scope_bytes < 8 || !scope_bytes.is_multiple_of(2) || scope_header[2..4] != [0, 0] {
                return Err(DmarError::InvalidStructure);
            }
            let end = scope
                .checked_add(scope_bytes)
                .ok_or(DmarError::InvalidStructure)?;
            let contents = entry
                .get(scope + 6..end)
                .ok_or(DmarError::InvalidStructure)?;
            if !matches!(scope_kind, 1 | 3 | 4) {
                return Err(DmarError::UnsupportedScope(scope_kind));
            }
            if contents
                .as_chunks::<2>()
                .0
                .iter()
                .any(|path| path[0] > 31 || path[1] > 7)
            {
                return Err(DmarError::InvalidStructure);
            }
            if scope_bytes != 8 {
                return Err(DmarError::UnsupportedRouting);
            }
            if scope_kind == 1 {
                if scope_header[4] != 0 {
                    return Err(DmarError::InvalidStructure);
                }
                let requester = u16::from(scope_header[5]) << 8
                    | u16::from(contents[0]) << 3
                    | u16::from(contents[1]);
                if !expected.contains(&requester) {
                    return Err(DmarError::UnlistedRequester(requester));
                }
                if endpoints.contains(&requester) {
                    return Err(DmarError::DuplicateRequester(requester));
                }
                endpoints.push(requester);
            }
            // IOAPIC/HPET interrupt scopes do not change the flat DMA route;
            // this backend does not enable interrupt remapping.
            scope = end;
        }
        if entry[4] & 1 == 0 {
            for requester in &expected {
                if !endpoints.contains(requester) {
                    return Err(DmarError::MissingRequester(*requester));
                }
            }
        }
        unit = Some(HardwareUnit {
            base,
            bytes,
            segment,
            physical_bits,
        });
        offset = end;
    }
    unit.ok_or(DmarError::MissingUnit)
}

#[cfg(test)]
mod tests;
