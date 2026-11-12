// SPDX-License-Identifier: GPL-2.0-only
// PCI encodings follow Linux include/uapi/linux/pci_regs.h, copyright
// 1994 Drew Eckhardt and 1997-1999 Martin Mares; see NOTICE.
//! Extent-checked capabilities through the retained VMD child transport.
use super::*;
use crate::bus::pci::{self, capability::Transport};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Capabilities {
    pub pm: Option<u16>,
    msi: Option<u16>,
    msix: Option<u16>,
    pcie: Option<(u16, u16)>,
}

fn word<R: Registers>(config: &mut ChildConfig<'_, R>, offset: u16) -> Result<u16, Error> {
    let value = config.read(offset, 2)? as u16;
    (value != u16::MAX)
        .then_some(value)
        .ok_or(Error::ReadFailed)
}
impl Capabilities {
    pub(super) fn inspect<R: Registers>(
        config: &mut ChildConfig<'_, R>,
        bridge: bool,
    ) -> Result<Self, Error> {
        let mut result = Self {
            pm: None,
            msi: None,
            msix: None,
            pcie: None,
        };
        let standard =
            pci::Capabilities::new(Transport(|offset, bytes| config.read(offset, bytes)))
                .collect::<Result<Vec<_>, Error>>()?;
        let mut singleton = 0u32;
        for entry in standard {
            let (offset, id) = (entry.offset, entry.id);
            match id {
                1 => {
                    if !(1..=3).contains(&(word(config, offset + 2)? & 7)) {
                        return Err(Error::Capability);
                    }
                    result.pm = Some(offset);
                }
                5 => {
                    let control = word(config, offset + 2)?;
                    let supported = (control >> 1) & 7;
                    if control & (1 << 10) != 0
                        || control & 1 != 0
                        || supported > 5
                        || ((control >> 4) & 7) > supported
                    {
                        return Err(Error::ActiveChild);
                    }
                    result.msi = Some(offset);
                }
                9 => {}
                0x10 => {
                    let flags = word(config, offset + 2)?;
                    let version = flags & 15;
                    let kind = (flags >> 4) & 15;
                    if !matches!(version, 1 | 2)
                        || !(if bridge {
                            matches!(kind, 4..=6)
                        } else {
                            matches!(kind, 0 | 1 | 9)
                        })
                        || (!bridge && flags & 0x100 != 0)
                    {
                        return Err(Error::Capability);
                    }
                    // Keep coherent payload policy; do not silently admit
                    // NoSnoop, autonomous AtomicOp requests or ARI fanout.
                    if word(config, offset + 8)? & (1 << 11) != 0
                        || (version == 2 && word(config, offset + 0x28)? & 0x60 != 0)
                    {
                        return Err(Error::ActiveChild);
                    }
                    result.pcie = Some((offset, flags));
                }
                0x11 => {
                    if word(config, offset + 2)? & 0x8000 != 0 {
                        return Err(Error::ActiveChild);
                    }
                    result.msix = Some(offset);
                }
                _ => return Err(Error::Capability),
            }
            if id != 9 {
                let bit = 1u32 << id;
                if singleton & bit != 0 {
                    return Err(Error::Capability);
                }
                singleton |= bit;
            }
        }
        // Conventional functions remain explicit: the selected NVMe and every
        // path bridge must independently provide the admitted PCIe profile.
        result.extended(config)?;
        Ok(result)
    }
    pub(super) fn is_pcie(&self) -> bool {
        self.pcie.is_some()
    }

    fn extended<R: Registers>(&self, config: &mut ChildConfig<'_, R>) -> Result<(), Error> {
        if config.read(0x100, 4)? == u32::MAX {
            return Err(Error::ReadFailed);
        }
        let entries =
            pci::ExtendedCapabilities::new(Transport(|offset, bytes| config.read(offset, bytes)))
                .collect::<Result<Vec<_>, Error>>()?;
        // AER's extent depends on its control and the port type; check it
        // against every other entry before reading inside it.
        let free = |offset: u16, bytes: u16| {
            let end = offset + bytes;
            if end > 0x1000
                || entries.iter().any(|other| {
                    other.offset != offset
                        && other.offset < end
                        && offset < other.offset + other.bytes
                })
            {
                return Err(Error::Capability);
            }
            Ok(())
        };
        let mut seen = Vec::new();
        for entry in &entries {
            let (offset, id) = (entry.offset, entry.id);
            if seen.contains(&id) {
                return Err(Error::Capability);
            }
            seen.push(id);
            match (id, entry.version) {
                (1, 1 | 2) => {
                    free(offset, 0x2c)?;
                    let control = config.read(offset + 0x18, 4)?;
                    if control == u32::MAX {
                        return Err(Error::ReadFailed);
                    }
                    let root = self.pcie.is_some_and(|(_, flags)| (flags >> 4) & 15 == 4);
                    if root {
                        free(offset, 0x38)?;
                        if config.read(offset + 0x2c, 4)? & 7 != 0 {
                            return Err(Error::ActiveChild);
                        }
                    }
                    if control & (1 << 11) != 0 {
                        free(offset, 0x48)?;
                    }
                }
                (3, 1) => {} // Device serial number; no DMA control.
                (0xf, 1) => {
                    if word(config, offset + 6)? & 0x8000 != 0 {
                        return Err(Error::ActiveChild);
                    }
                }
                (0x13, 1) => {
                    if word(config, offset + 4)? & 3 != 0 || word(config, offset + 6)? & 0x100 == 0
                    {
                        return Err(Error::ActiveChild);
                    }
                }
                (0x18, 1) => {} // Read-only admission of kept LTR values.
                (0x1b, 1) => {
                    if word(config, offset + 6)? & 1 != 0 {
                        return Err(Error::ActiveChild);
                    }
                }
                // SR-IOV, unknown traffic-producing controls and other
                // unchecked capabilities are explicit profile refusals.
                _ => return Err(Error::Capability),
            }
        }
        Ok(())
    }
    pub(super) fn power_up<R: Registers>(
        &self,
        config: &mut ChildConfig<'_, R>,
        timer: &(impl crate::bus::pci::power::Timer + ?Sized),
    ) -> Result<(), Error> {
        timer.check()?;
        for (offset, enabled) in [(self.msi, 1), (self.msix, 0x8000)] {
            if let Some(offset) = offset
                && word(config, offset + 2)? & enabled != 0
            {
                return Err(Error::ActiveChild);
            }
        }
        let Some(pm) = self.pm else {
            return Ok(());
        };
        let control = word(config, pm + 4)?;
        // Do not replay PME_Status (W1C). Disable PME generation as well as
        // choosing D0; another owner's pending event is not acknowledged here.
        config.write(pm + 4, 2, u32::from(control & !0x8103))?;
        match control & 3 {
            3 => timer.wait_us(10_000)?,
            2 => timer.wait_us(200)?,
            _ => {}
        }
        if word(config, pm + 4)? & 0x103 != 0 {
            return Err(Error::Readback);
        }
        Ok(())
    }
    pub(super) fn check_d0<R: Registers>(
        &self,
        config: &mut ChildConfig<'_, R>,
    ) -> Result<(), Error> {
        if let Some(pm) = self.pm
            && word(config, pm + 4)? & 0x103 != 0
        {
            return Err(Error::Suspended);
        }
        Ok(())
    }
}
