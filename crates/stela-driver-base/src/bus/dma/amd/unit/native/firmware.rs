//! Admission of the IVRS description of one AMD IOMMU unit.
use super::*;
use crate::bus::dma::amd::{
    device::REQUESTERS,
    ivrs::{DeviceKind, Ivhd, RangePolicy},
};

pub(super) struct Admission {
    pub(super) bits: u8,
    pub(super) segment: u16,
    pub(super) control: u64,
    pub(super) hardware_errors: bool,
    pub(super) policies: Vec<u8>,
    pub(super) coverage: Vec<bool>,
    /// IDs independently assigned by an IVHD entry, apart from alias targets.
    pub(super) sources: Vec<bool>,
    /// Each requester whose DMA arrives under another ID, with that ID.
    pub(super) aliases: Vec<(u16, u16)>,
}

pub(super) fn admit(
    inspection: &FunctionInspection<impl UnitConfig>,
    ivrs: &Ivrs<'_>,
    actual_bits: u8,
) -> Result<Admission, Error> {
    if inspection.native_firmware() != ivrs.raw() {
        return Err(Error::Firmware);
    }
    if inspection.profiles().len() != 1 {
        return Err(Error::Firmware);
    }
    let profile = inspection.profiles()[0];
    let address = inspection.address();
    let rid =
        u16::from(address.bus) << 8 | u16::from(address.device) << 3 | u16::from(address.function);
    // One IVHD per unit; a system with several units has one per function.
    let unit = ivrs
        .units()
        .find(|unit| {
            unit.id().segment == address.segment
                && unit.id().device_id == rid
                && unit.capability_offset() == profile.configuration.capability_offset
        })
        .ok_or(Error::Firmware)?;
    if unit.id().segment != address.segment
        || unit.id().device_id != rid
        || unit.capability_offset() != profile.configuration.capability_offset
        || unit.mmio_address() != profile.configuration.base()
        || unit.offset() != profile.firmware.offset
        || unit.version() != profile.firmware.version
        || unit.flags() != profile.firmware.flags
        || unit.info() != profile.firmware.info
        || unit.feature_or_attributes() != profile.firmware.feature_or_attributes
        || unit.extended_features() != profile.firmware.extended_features
        || ivrs.info() != profile.firmware.ivrs_info
    {
        return Err(Error::Firmware);
    }
    // Linux's `amd_iommu_init` masks what it does not use: reserved and
    // unrelated IVinfo and miscellaneous bits, the VA sizes and EFRSup.
    // A PA size bounds this unit's tables and payloads where it names a
    // width; a field outside 32..=52 names none and is left out.
    let info = ivrs.info();
    let width = |bits: u8| (32..=52).contains(&bits).then_some(bits);
    let pa = width(((info >> 8) & 127) as u8);
    let hardware_pa = width(((profile.configuration.miscellaneous >> 8) & 127) as u8);
    if !(32..=52).contains(&actual_bits) {
        return Err(Error::Profile);
    }
    let bits = [pa, hardware_pa]
        .into_iter()
        .flatten()
        .fold(actual_bits, u8::min);
    // The feature reports present: the unit's own register and the IVHD's
    // copy, which Linux prefers. Each one present must name invalidate-all
    // (IA), which the initial and final drains of every cache rely on, and
    // a host table depth (HATS 3 says host translation is off). SNPSup is
    // only a capability: SNP takes effect once software sets SYSCFG.SNPEn,
    // which this boot never does, and the platform keeps it absent.
    let hardware_features = profile
        .hardware_extended_features
        .map(|(features, _)| features);
    let firmware_features = unit.extended_features().map(|(features, _)| features);
    let reports = [hardware_features, firmware_features];
    if reports.iter().all(Option::is_none)
        || reports
            .into_iter()
            .flatten()
            .any(|features| features & (1 << 6) == 0 || (features >> 10) & 3 == 3)
    {
        return Err(Error::Profile);
    }
    let Routes {
        policies,
        coverage,
        sources,
        aliases,
    } = routes(unit)?;
    let flags = unit.flags();
    let control = IOMMU_ENABLE
        | EVENT_ENABLE
        | COMMAND_ENABLE
        | COHERENT
        | if flags & 1 != 0 { 1 << 1 } else { 0 }
        | if flags & 2 != 0 { 1 << 8 } else { 0 }
        | if flags & 4 != 0 { 1 << 9 } else { 0 }
        | if flags & 8 != 0 { 1 << 11 } else { 0 };
    Ok(Admission {
        bits,
        segment: address.segment,
        control,
        // The hardware error registers are read only where the unit's own
        // feature register says it has them.
        hardware_errors: hardware_features.is_some_and(|features| features & (1 << 8) != 0),
        policies,
        coverage,
        sources,
        aliases,
    })
}

/// What one IVHD's device entries route to its unit, from the IVRS alone.
pub(super) struct Routes {
    pub(super) policies: Vec<u8>,
    pub(super) coverage: Vec<bool>,
    pub(super) sources: Vec<bool>,
    pub(super) aliases: Vec<(u16, u16)>,
}

fn table<T: Clone>(value: T) -> Result<Vec<T>, Error> {
    let mut table = Vec::new();
    table
        .try_reserve_exact(REQUESTERS)
        .map_err(|_| Error::Memory(MemoryError::OutOfMemory))?;
    table.resize(REQUESTERS, value);
    Ok(table)
}

/// Read `unit`'s device entries. As Linux's `init_iommu_from_acpi`, padding
/// and the reserved bytes of a select-all or range-end entry are ignored, a
/// range takes its start's settings, and a later entry overrides an earlier
/// one. A range left open, or a unit that routes nothing, is refused.
pub(super) fn routes(unit: Ivhd<'_>) -> Result<Routes, Error> {
    let mut policies = table(0u8)?;
    let mut coverage = table(false)?;
    let mut sources = table(false)?;
    sources[usize::from(unit.id().device_id)] = true;
    let mut aliases = Vec::new();
    let mut start = None;
    // The device-setting flags (INITPass, EIntPass, NMIPass, SysMgt,
    // Lint0Pass, Lint1Pass) go into each DTE (`entry::Policy`); ATCPermit
    // stays metadata.
    for entry in unit.entries() {
        let (range, alias) = match entry.kind {
            DeviceKind::Padding | DeviceKind::NotUsed => continue,
            DeviceKind::Select(id) | DeviceKind::Extended { requester: id, .. } => {
                ((id.device_id, id.device_id, entry.flags()), None)
            }
            DeviceKind::Hid { requester, .. } => (
                (requester.device_id, requester.device_id, entry.flags()),
                None,
            ),
            DeviceKind::Alias { requester, target } => (
                (requester.device_id, requester.device_id, entry.flags()),
                Some(target.device_id),
            ),
            DeviceKind::All => ((0, u16::MAX, entry.flags()), None),
            DeviceKind::RangeStart { first, policy } => {
                let alias = match policy {
                    RangePolicy::Alias(target) => Some(target.device_id),
                    RangePolicy::Plain | RangePolicy::Extended(_) => None,
                };
                start = Some((first.device_id, entry.flags(), alias));
                continue;
            }
            DeviceKind::RangeEnd(last) => {
                let (first, flags, alias) = start.take().ok_or(Error::Firmware)?;
                ((first, last.device_id, flags), alias)
            }
            // IOAPIC and HPET entries name interrupt sources, which matter
            // only to interrupt remapping.
            DeviceKind::Special { .. } => continue,
        };
        let (first, last, flags) = range;
        for requester in first..=last {
            coverage[usize::from(requester)] = true;
            sources[usize::from(requester)] = true;
            policies[usize::from(requester)] = flags;
            aliases.retain(|&(source, _)| source != requester);
            if let Some(target) = alias.filter(|target| *target != requester) {
                // The alias carries the source's settings, as Linux's
                // set_dev_entry_from_acpi gives both.
                coverage[usize::from(target)] = true;
                policies[usize::from(target)] = flags;
                aliases
                    .try_reserve(1)
                    .map_err(|_| Error::Memory(MemoryError::OutOfMemory))?;
                aliases.push((requester, target));
            }
        }
    }
    if start.is_some() || !coverage.iter().any(|value| *value) {
        return Err(Error::Firmware);
    }
    Ok(Routes {
        policies,
        coverage,
        sources,
        aliases,
    })
}
