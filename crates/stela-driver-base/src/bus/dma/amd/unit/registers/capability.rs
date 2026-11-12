// SPDX-License-Identifier: GPL-2.0-only
// PCI capability encodings follow Linux include/uapi/linux/pci_regs.h at
// cc9de5d4b5ab6459f5774946aa3195ad51236fa8, Copyright 1994 Drew Eckhardt
// and 1997–1999 Martin Mares. AMD register layouts follow AMD 48882 rev 3.11.
//! Complete conventional capability framing for one remapper function.
use super::*;
use crate::bus::pci::{Capability, CapabilityError, capability};

pub(super) struct Capabilities {
    pub(super) entries: [Option<Configuration>; CAP_LIMIT],
    pub(super) count: usize,
    pub(super) has_msix: bool,
}

fn config32<C: ConfigSpace>(config: &C, offset: u16) -> Result<u32, Error> {
    let value = config.read32(offset).map_err(Error::Config)?;
    if value == u32::MAX {
        Err(Error::ReadFailed(offset))
    } else {
        Ok(value)
    }
}

/// The complete conventional list's headers, validated by the shared walk.
/// The secure device bodies, the only bodies this unit reads, are sized here
/// and checked against every other header. Another ID may repeat: the first
/// entry is the one a driver finds, as with Linux `pci_find_capability`.
pub(super) fn scan<C: ConfigSpace>(config: &C) -> Result<Capabilities, Error> {
    let mut result = Capabilities {
        entries: [None; CAP_LIMIT],
        count: 0,
        has_msix: false,
    };
    let entries = capability::capability_headers(config)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| match error {
            CapabilityError::Config { .. } => Error::PciCapability(error),
            CapabilityError::FailedRead { offset } => Error::ReadFailed(offset),
            error => Error::Capability(error.offset()),
        })?;
    for entry in &entries {
        let (offset, id) = (entry.offset, entry.id);
        let header = config32(config, offset)?;
        let bytes = capability_bytes(entry, header)?;
        if offset + bytes > CONFIG_LIMIT {
            return Err(Error::Capability(offset));
        }
        if let Some(other) = capability::overlap(entries.iter().map(|e| e.span()), offset, bytes) {
            return Err(Error::Capability(other));
        }
        result.has_msix |= id == 0x11;
        if id == SECURE_DEVICE {
            if result.count == CAP_LIMIT {
                return Err(Error::Capability(offset));
            }
            let range = config32(config, offset + 12)?;
            if range & RANGE_VALID != 0 && (range >> 16) as u8 > (range >> 24) as u8 {
                return Err(Error::Range(offset));
            }
            result.entries[result.count] = Some(Configuration {
                capability_offset: offset,
                header,
                base_low: config32(config, offset + 4)?,
                base_high: config32(config, offset + 8)?,
                range,
                miscellaneous: config32(config, offset + 16)?,
                miscellaneous_1: if header & CAP_EXTENDED != 0 {
                    Some(config32(config, offset + 20)?)
                } else {
                    None
                },
            });
            result.count += 1;
        }
    }
    Ok(result)
}

/// HyperTransport (PCI_CAP_ID_HT), which an AMD IOMMU lists for its MSI
/// mapping.
const HYPERTRANSPORT: u8 = 8;

fn capability_bytes(entry: &Capability, header: u32) -> Result<u16, Error> {
    let (offset, id) = (entry.offset, entry.id);
    let flags = (header >> 16) as u16;
    match id {
        SECURE_DEVICE => {
            // Revision 0, which QEMU's amd-iommu reports, frames revision 1's
            // registers.
            if (header >> 16) & 7 != IOMMU_TYPE || (header >> 19) & 31 > IOMMU_REVISION {
                return Err(Error::UnsupportedLayout(offset));
            }
            Ok(if header & CAP_EXTENDED != 0 { 24 } else { 20 })
        }
        1 if (1..=3).contains(&(flags & 7)) => Ok(entry.bytes),
        5 => {
            let maximum = (flags >> 1) & 7;
            let enabled = (flags >> 4) & 7;
            if flags & (1 << 10) != 0 || maximum > 5 || enabled > maximum {
                return Err(Error::Capability(offset));
            }
            Ok(entry.bytes)
        }
        HYPERTRANSPORT | 9 | 0x11 => Ok(entry.bytes),
        0x10 => {
            let version = flags & 15;
            let kind = (flags >> 4) & 15;
            if !matches!(version, 1 | 2) || !matches!(kind, 0 | 1 | 9) || flags & 0x100 != 0 {
                return Err(Error::UnsupportedLayout(offset));
            }
            Ok(entry.bytes)
        }
        1 => Err(Error::UnsupportedLayout(offset)),
        _ => Err(Error::UnsupportedCapability { offset, id }),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::bus::pci::{ConfigError, ConfigFailure, regs};
    use std::sync::Mutex;
    const CAP: u16 = 0x40;
    struct Config {
        words: [u32; 64],
        reads: Mutex<Vec<u16>>,
        denied_read: Option<u16>,
    }
    impl ConfigSpace for Config {
        fn read8(&self, offset: u16) -> Result<u8, ConfigError> {
            Ok((self.read32(offset & !3)? >> ((offset & 3) * 8)) as u8)
        }
        fn read16(&self, offset: u16) -> Result<u16, ConfigError> {
            Ok((self.read32(offset & !3)? >> ((offset & 3) * 8)) as u16)
        }
        fn write8(&mut self, _: u16, _: u8) -> Result<(), ConfigError> {
            Err(ConfigError::before_effect(
                ConfigFailure::UnqualifiedControl,
            ))
        }
        fn write16(&mut self, _: u16, _: u16) -> Result<(), ConfigError> {
            Err(ConfigError::before_effect(
                ConfigFailure::UnqualifiedControl,
            ))
        }
        fn read32(&self, offset: u16) -> Result<u32, ConfigError> {
            self.reads.lock().unwrap().push(offset);
            if self.denied_read == Some(offset)
                || !offset.is_multiple_of(4)
                || usize::from(offset / 4) >= self.words.len()
            {
                return Err(ConfigError::before_effect(ConfigFailure::Access {
                    offset,
                    width: 4,
                }));
            }
            Ok(self.words[usize::from(offset / 4)])
        }
        fn write32(&mut self, _: u16, _: u32) -> Result<(), ConfigError> {
            Err(ConfigError::before_effect(
                ConfigFailure::UnqualifiedControl,
            ))
        }
    }
    fn make_config(header: u32) -> Config {
        let mut config = Config {
            words: [0; 64],
            reads: Mutex::new(Vec::new()),
            denied_read: None,
        };
        config.words[1] = u32::from(regs::STATUS_CAP_LIST) << 16;
        config.words[usize::from(regs::CAPABILITY_LIST / 4)] = u32::from(CAP);
        config.words[usize::from(CAP / 4)] = header;
        config
    }
    fn secure_header() -> u32 {
        u32::from(SECURE_DEVICE) | IOMMU_TYPE << 16 | IOMMU_REVISION << 19
    }

    #[test]
    fn denied_body_read_keeps_precise_access_error_instead_of_allones_or_empty_capability() {
        let mut config = make_config(secure_header());
        config.denied_read = Some(CAP + 12);
        assert!(
            matches!(scan(&config),Err(Error::Config(ConfigError{reason:ConfigFailure::Access{offset,width:4},..}))if offset==CAP+12)
        );
    }

    #[test]
    fn capability_extents_and_reserved_optional_register_reads_are_bounded() {
        for extended in [false, true] {
            let config = make_config(secure_header() | if extended { CAP_EXTENDED } else { 0 });
            let result = scan(&config).unwrap();
            assert_eq!(result.count, 1);
            let reads = config.reads.lock().unwrap();
            assert_eq!(reads.contains(&(CAP + 20)), extended);
            assert!(!reads.contains(&(CAP + 24)));
        }
        let mut config = make_config(secure_header() | CAP_EXTENDED);
        config.words[0x34 / 4] = 0xec;
        config.words[0xec / 4] = secure_header() | CAP_EXTENDED;
        assert_eq!(scan(&config).err(), Some(Error::Capability(0xec)));
        assert!(!config.reads.lock().unwrap().contains(&0xf0));
    }

    #[test]
    fn full_chain_rejects_cycles_overlap_misalignment_and_unknown_layouts() {
        for (first, second, expected) in [
            (secure_header() | 0x4000, 0, Error::Capability(CAP)),
            (
                secure_header() | 0x4400,
                0x0001_0001,
                Error::Capability(0x44),
            ),
            (secure_header() | 0x6100, 0, Error::Capability(0x61)),
            (
                secure_header() | 0x6000,
                0x0000_000a,
                Error::UnsupportedCapability {
                    offset: 0x60,
                    id: 0x0a,
                },
            ),
            (
                secure_header() | 0x6000,
                0x0000_000f,
                Error::UnsupportedLayout(0x60),
            ),
            (secure_header() | 0x6000, u32::MAX, Error::ReadFailed(0x60)),
        ] {
            let mut config = make_config(first);
            config.words[0x60 / 4] = second;
            if ((first >> 8) & 0xff) == 0x44 {
                config.words[0x44 / 4] = second;
            }
            assert_eq!(scan(&config).err(), Some(expected));
        }
    }

    #[test]
    fn unread_bodies_are_framed_by_header_and_their_ids_may_repeat() {
        // QEMU's amd-iommu, newest entry first: msi_init's MSI, then
        // HyperTransport and a four-byte MSI entry, each right after the
        // last, and the secure device.
        let mut config = make_config(IOMMU_TYPE << 16 | u32::from(SECURE_DEVICE) | CAP_EXTENDED);
        config.words[0x34 / 4] = 0x60;
        config.words[0x60 / 4] = 0x0080_5c05;
        config.words[0x5c / 4] = 0x0000_5808;
        config.words[0x58 / 4] = 0x0000_4005;
        let result = scan(&config).unwrap();
        assert_eq!(result.count, 1);
        assert!(!result.has_msix);
    }
}
