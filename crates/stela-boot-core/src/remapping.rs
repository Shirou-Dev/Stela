//! Which DMA remapping units the mount takes over, and which requesters
//! each one isolates: the PCI functions present behind the root buses, the
//! units' device scopes resolved against them, and the policy that leaves a
//! unit untranslated when taking it would cut off DMA nothing re-maps.
//!
//! A unit is left untranslated when its scope holds a display controller no
//! driver claims (an integrated GPU's scanout reaches its stolen memory
//! through the unit, with the firmware's reserved regions mapped one to
//! one), or when a reserved region (DMAR RMRR, IVRS IVMD) names a requester
//! other than a USB host controller, whose reserved region serves only the
//! firmware's legacy USB emulation until the xHCI BIOS handoff (Linux's
//! `device_rmrr_is_relaxable`). A display driver that maps those regions
//! itself passes its function in `claimed_displays`, and the unit is taken.
use alloc::vec::Vec;
use core::{convert::Infallible, ops::Range};

pub mod initial;
use stela_drivers::bus::pci::EcamWindow;

/// The 4 KiB page span a DMA window needs, within the host's supported
/// physical-address width. This describes geometry, not permission to map it.
pub fn window_range(range: &Range<u64>, physical_bits: u8) -> Option<Range<u64>> {
    if !(32..=52).contains(&physical_bits) || range.start >= range.end {
        return None;
    }
    let end = range.end.checked_next_multiple_of(4096)?;
    if end > 1u64 << physical_bits {
        return None;
    }
    Some((range.start & !4095)..end)
}

/// One present PCI function: its requester ID, class code and, for a
/// PCI-to-PCI bridge, its secondary and subordinate buses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Present {
    pub rid: u16,
    /// Base class, subclass and programming interface.
    pub class: [u8; 3],
    pub bridge: Option<(u8, u8)>,
}

impl Present {
    pub fn display(&self) -> bool {
        self.class[0] == 0x03
    }
    pub fn usb(&self) -> bool {
        self.class[0] == 0x0c && self.class[1] == 0x03
    }
}

const VENDOR: u16 = 0x00;
const CLASS: u16 = 0x08;
const HEADER: u16 = 0x0c;
const BUSES: u16 = 0x18;

/// Every function behind `roots`, including every RID on each reached bus.
/// Function zero and its multifunction bit cannot establish absence of ARI
/// functions or the PF that supplies another function's VF identity. This
/// read-only inventory does not authorize attaching unsupported ARI devices.
/// `read32` reads a configuration dword, None where nothing answers.
pub fn enumerate(roots: &[u8], mut read32: impl FnMut(u16, u16) -> Option<u32>) -> Vec<Present> {
    try_enumerate(roots, |rid, offset| {
        Ok::<_, Infallible>(read32(rid, offset))
    })
    .unwrap_or_else(|never| match never {})
}

fn try_enumerate<E>(
    roots: &[u8],
    mut read32: impl FnMut(u16, u16) -> Result<Option<u32>, E>,
) -> Result<Vec<Present>, E> {
    let mut found = Vec::new();
    let mut seen = [false; 256];
    let mut pending: Vec<u8> = roots.to_vec();
    while let Some(bus) = pending.pop() {
        if core::mem::replace(&mut seen[usize::from(bus)], true) {
            continue;
        }
        for device in 0..32u16 {
            for function in 0..8u16 {
                let rid = u16::from(bus) << 8 | device << 3 | function;
                if read32(rid, VENDOR)?.is_none_or(|id| id as u16 == 0xffff) {
                    continue;
                }
                let class = read32(rid, CLASS)?.unwrap_or(0);
                let kind = read32(rid, HEADER)?.unwrap_or(0) >> 16 & 0x7f;
                let buses = if kind == 1 { read32(rid, BUSES)? } else { None };
                let bridge = buses
                    .map(|buses| ((buses >> 8) as u8, (buses >> 16) as u8))
                    .filter(|&(secondary, subordinate)| {
                        secondary > bus && subordinate >= secondary
                    });
                if let Some((secondary, _)) = bridge {
                    pending.push(secondary);
                }
                found.push(Present {
                    rid,
                    class: [(class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8],
                    bridge,
                });
            }
        }
    }
    found.sort_unstable_by_key(|function| function.rid);
    Ok(found)
}

/// Inventory each PCI segment across all of its ECAM windows before choosing
/// remapping units. `windows` are the platform's validated, non-overlapping
/// windows; the callback reads only the selected window's configuration space.
/// The result describes topology and grants no device or DMA ownership.
pub fn enumerate_segments(
    windows: &[EcamWindow],
    mut read32: impl FnMut(&EcamWindow, u16, u16) -> Option<u32>,
) -> Vec<(u16, Vec<Present>)> {
    try_enumerate_segments(windows, |window, rid, offset| {
        Ok::<_, Infallible>(read32(window, rid, offset))
    })
    .unwrap_or_else(|never| match never {})
}

/// Enumerate the complete admitted windows, stopping on the original read
/// error before returning any topology that could be mistaken for a census.
pub fn try_enumerate_segments<E>(
    windows: &[EcamWindow],
    mut read32: impl FnMut(&EcamWindow, u16, u16) -> Result<Option<u32>, E>,
) -> Result<Vec<(u16, Vec<Present>)>, E> {
    let mut segments: Vec<_> = windows.iter().map(|window| window.segment).collect();
    segments.sort_unstable();
    segments.dedup();
    segments
        .into_iter()
        .map(|segment| {
            let roots: Vec<_> = windows
                .iter()
                .filter(|window| window.segment == segment)
                .flat_map(|window| window.start_bus..=window.end_bus)
                .collect();
            let present = try_enumerate(&roots, |rid, offset| {
                let bus = (rid >> 8) as u8;
                let Some(window) = windows.iter().find(|window| {
                    window.segment == segment && (window.start_bus..=window.end_bus).contains(&bus)
                }) else {
                    return Ok(None);
                };
                read32(window, rid, offset)
            })?;
            Ok((segment, present))
        })
        .collect()
}

/// A device scope: an endpoint, or a bridge and every function behind it,
/// named by its start bus and (device, function) path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    pub bridge: bool,
    pub bus: u8,
    pub path: Vec<(u8, u8)>,
}

impl Scope {
    /// The present requesters the scope names: none when its path does not
    /// lead to a present function.
    pub fn resolve(&self, present: &[Present]) -> Vec<u16> {
        let find = |rid: u16| present.iter().find(|function| function.rid == rid);
        let mut bus = self.bus;
        let mut target = None;
        for (index, &(device, function)) in self.path.iter().enumerate() {
            let rid = u16::from(bus) << 8 | u16::from(device) << 3 | u16::from(function);
            let Some(found) = find(rid) else {
                return Vec::new();
            };
            if index + 1 == self.path.len() {
                target = Some(found);
            } else if let Some((secondary, _)) = found.bridge {
                bus = secondary;
            } else {
                return Vec::new();
            }
        }
        match target {
            None => Vec::new(),
            Some(found) if !self.bridge => alloc::vec![found.rid],
            Some(found) => {
                let Some((secondary, subordinate)) = found.bridge else {
                    return alloc::vec![found.rid];
                };
                present
                    .iter()
                    .filter(|function| {
                        function.rid == found.rid
                            || (secondary..=subordinate).contains(&((function.rid >> 8) as u8))
                    })
                    .map(|function| function.rid)
                    .collect()
            }
        }
    }
}

/// Why a unit is left untranslated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leave {
    /// No present requester sits in its scope.
    Empty,
    /// More than one firmware unit claims this requester.
    Ambiguous(u16),
    /// This display controller sits in its scope, and no driver maps the
    /// unit's reserved regions for it.
    Display(u16),
    /// A reserved region names this requester, which is not a USB host
    /// controller.
    Reserved(u16),
    /// Firmware identifies a DMA source without a native ownership resolver.
    UnsupportedSource(crate::dmar::SourceKind),
    /// A firmware structure constrains DMA semantics not implemented here.
    UnsupportedStructure(u16),
    /// The parser dropped a device scope or reserved region, so no unit's
    /// coverage or reserved memory is fully known.
    Incomplete,
}

/// The requesters a unit covers, sorted, when the policy takes it.
pub fn decide(
    covered: &[u16],
    reserved: &[u16],
    present: &[Present],
    claimed_displays: &[u16],
) -> Result<Vec<u16>, Leave> {
    let mut covered = covered.to_vec();
    covered.sort_unstable();
    covered.dedup();
    if covered.is_empty() {
        return Err(Leave::Empty);
    }
    let function = |rid: u16| present.iter().find(|function| function.rid == rid);
    if let Some(&display) = covered.iter().find(|&&rid| {
        function(rid).is_some_and(Present::display) && !claimed_displays.contains(&rid)
    }) {
        return Err(Leave::Display(display));
    }
    if let Some(&held) = reserved.iter().find(|&&rid| {
        covered.contains(&rid)
            && !function(rid).is_some_and(|function| {
                function.usb() || (function.display() && claimed_displays.contains(&rid))
            })
    }) {
        return Err(Leave::Reserved(held));
    }
    Ok(covered)
}

/// Unresolved namespace/unknown sources may share assigned identities with
/// PCI requesters. Until resolved, exclude their entire segment from grants.
fn unsupported_sources(remapping: &crate::dmar::Remapping, segment: u16) -> Option<Leave> {
    use crate::dmar::SourceKind;
    if !remapping.complete() {
        return Some(Leave::Incomplete);
    }
    if let Some(&kind) = remapping
        .additional_structures
        .iter()
        .find(|&&kind| kind >= 5)
    {
        return Some(Leave::UnsupportedStructure(kind));
    }
    for unit in remapping
        .units
        .iter()
        .filter(|unit| unit.segment == segment)
    {
        if let Some(source) = unit.sources.iter().find(|s| {
            s.flags != 0
                || s.reserved != 0
                || !matches!(s.kind, SourceKind::IoApic | SourceKind::Hpet)
        }) {
            return Some(Leave::UnsupportedSource(source.kind));
        }
    }
    remapping
        .reserved
        .iter()
        .filter(|region| region.segment == segment)
        .find_map(|region| {
            region
                .sources
                .first()
                .map(|source| Leave::UnsupportedSource(source.kind))
        })
}

/// The present requesters an include-all unit covers: those no other unit
/// on its segment lists.
pub fn remainder(present: &[Present], listed: &[u16]) -> Vec<u16> {
    present
        .iter()
        .map(|function| function.rid)
        .filter(|rid| !listed.contains(rid))
        .collect()
}

/// The requesters each firmware unit routes: explicit scopes precede the
/// include-all remainder. Policy refusals do not change hardware routing.
fn coverage(
    remapping: &crate::dmar::Remapping,
    segment: u16,
    present: &[Present],
) -> Vec<(usize, Vec<u16>)> {
    let on_segment = || {
        remapping
            .units
            .iter()
            .enumerate()
            .filter(|(_, unit)| unit.segment == segment)
    };
    let mut listed = Vec::new();
    let mut coverage = Vec::new();
    for (index, unit) in on_segment().filter(|(_, unit)| !unit.include_all) {
        let covered: Vec<u16> = unit
            .scopes
            .iter()
            .flat_map(|scope| scope.resolve(present))
            .collect();
        listed.extend_from_slice(&covered);
        coverage.push((index, covered));
    }
    for (index, _) in on_segment().filter(|(_, unit)| unit.include_all) {
        let covered = remainder(present, &listed);
        coverage.push((index, covered));
    }
    coverage
}

/// Resolve one present requester through firmware scopes, including scopes
/// that became resolvable after bridge adoption. A bridge's own unit need not
/// route a child. Ambiguous routing supplies no remapper or passthrough grant.
pub fn route(
    remapping: &crate::dmar::Remapping,
    segment: u16,
    present: &[Present],
    rid: u16,
) -> Result<Option<usize>, Leave> {
    if let Some(error) = unsupported_sources(remapping, segment) {
        return Err(error);
    }
    let coverage = coverage(remapping, segment, present);
    let mut matching = coverage.iter().filter(|(_, rids)| rids.contains(&rid));
    let selected = matching.next().map(|(index, _)| *index);
    if matching.next().is_some() {
        return Err(Leave::Ambiguous(rid));
    }
    Ok(selected)
}

/// Whether a firmware scope can cover future children of this bridge, and
/// whether its bridge scope covers the entire reserved downstream bus range.
fn prospective(scope: &Scope, present: &[Present], downstream: (u8, u8)) -> (bool, bool) {
    let (secondary, subordinate) = downstream;
    let mut bus = scope.bus;
    for (index, &(device, function)) in scope.path.iter().enumerate() {
        if (secondary..=subordinate).contains(&bus) {
            return (true, false);
        }
        let rid = u16::from(bus) << 8 | u16::from(device) << 3 | u16::from(function);
        let Some(found) = present.iter().find(|entry| entry.rid == rid) else {
            return (false, false);
        };
        if index + 1 == scope.path.len() {
            return found.bridge.filter(|_| scope.bridge).map_or(
                (false, false),
                |(first, last)| {
                    (
                        first <= subordinate && secondary <= last,
                        first <= secondary && subordinate <= last,
                    )
                },
            );
        }
        let Some((next, _)) = found.bridge else {
            return (false, false);
        };
        bus = next;
    }
    (false, false)
}

/// Every descriptor that could route a future child within the bridge's
/// reserved buses. An unresolved downstream endpoint scope still counts.
/// Unknown/unassigned bridge ranges return None, never an isolation grant.
/// This is conservative topology data, not permission to change PCI routing.
pub fn subtree_routes(
    remapping: &crate::dmar::Remapping,
    segment: u16,
    present: &[Present],
    bridge: u16,
) -> Option<Vec<usize>> {
    if unsupported_sources(remapping, segment).is_some() {
        return None;
    }
    let downstream = present.iter().find(|entry| entry.rid == bridge)?.bridge?;
    let mut selected = Vec::new();
    let mut complete = false;
    for (index, unit) in remapping
        .units
        .iter()
        .enumerate()
        .filter(|(_, unit)| unit.segment == segment && !unit.include_all)
    {
        for scope in &unit.scopes {
            let (possible, whole) = prospective(scope, present, downstream);
            if possible && !selected.contains(&index) {
                selected.push(index);
            }
            complete |= whole;
        }
    }
    if !complete {
        selected.extend(
            remapping
                .units
                .iter()
                .enumerate()
                .filter(|(_, unit)| unit.segment == segment && unit.include_all)
                .map(|(index, _)| index),
        );
    }
    Some(selected)
}

/// What the policy does with each unit of `remapping` on `segment`, by its
/// descriptor index. Explicit units precede include-all units. Overlapping
/// hardware coverage refuses every affected unit before register effects.
pub fn plan(
    remapping: &crate::dmar::Remapping,
    segment: u16,
    present: &[Present],
    claimed_displays: &[u16],
) -> Vec<(usize, Result<Vec<u16>, Leave>)> {
    if let Some(error) = unsupported_sources(remapping, segment) {
        return remapping
            .units
            .iter()
            .enumerate()
            .filter(|(_, unit)| unit.segment == segment)
            .map(|(index, _)| (index, Err(error)))
            .collect();
    }
    let reserved: Vec<u16> = remapping
        .reserved
        .iter()
        .filter(|region| region.segment == segment)
        .flat_map(|region| {
            region
                .scopes
                .iter()
                .flat_map(|scope| scope.resolve(present))
        })
        .collect();
    let coverage = coverage(remapping, segment, present);
    let mut counts = alloc::collections::BTreeMap::<u16, usize>::new();
    for (_, rids) in &coverage {
        let mut unique = rids.clone();
        unique.sort_unstable();
        unique.dedup();
        for rid in unique {
            *counts.entry(rid).or_default() += 1;
        }
    }
    coverage
        .iter()
        .map(|(index, rids)| {
            let decision = if let Some(&rid) = rids.iter().find(|rid| counts[rid] > 1) {
                Err(Leave::Ambiguous(rid))
            } else {
                decide(rids, &reserved, present, claimed_displays)
            };
            (*index, decision)
        })
        .collect()
}

#[cfg(test)]
mod tests;
