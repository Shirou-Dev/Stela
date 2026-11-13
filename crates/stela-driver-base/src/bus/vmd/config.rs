// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2015, Intel Corporation.
//! Configuration access to devices on a VMD child bus.
use super::*;
use crate::bus::pci::regs;

/// Exclusive child configuration borrow. This supplies no
/// `pci::Address`: a 32-bit VMD domain cannot be truncated to an ACPI segment.
pub struct ChildConfig<'a, R: Registers> {
    pub(super) host: &'a mut Host<R>,
    pub(super) base: usize,
    pub(super) address: Address,
}
impl<R: Registers> ChildConfig<'_, R> {
    pub fn address(&self) -> Address {
        self.address
    }
    fn offset(&self, offset: u16, width: u8) -> Result<usize, Error> {
        if !matches!(width, 1 | 2 | 4)
            || !offset.is_multiple_of(u16::from(width))
            || usize::from(offset) + usize::from(width) > 4096
        {
            return Err(Error::Address);
        }
        self.base
            .checked_add(usize::from(offset))
            .ok_or(Error::Address)
    }
    pub fn read(&mut self, offset: u16, width: u8) -> Result<u32, Error> {
        self.host.check_live()?;
        let absolute = self.offset(offset, width)?;
        let result = self.host.io().child_read(absolute, width);
        if result.is_err() {
            self.host.poisoned = true;
        }
        result
    }
    pub fn write(&mut self, offset: u16, width: u8, value: u32) -> Result<(), Error> {
        self.host.check_live()?;
        let absolute = self.offset(offset, width)?;
        // Until the shared requester permission accepts synthetic domains, no
        // safe configuration API may enable child DMA. Also catch a byte write
        // of regs::COMMAND and DWORD writes covering regs::COMMAND/Status.
        if offset == regs::COMMAND && value & u32::from(regs::COMMAND_MASTER) != 0 {
            return Err(Error::ActiveChild);
        }
        let result = self.host.io().child_write(absolute, width, value);
        if result.is_err() {
            self.host.poisoned = true;
        }
        result
    }
    /// Exact ACPI companion address from pinned vmd_acpi_find_companion.
    pub fn acpi_address(&self) -> Option<u32> {
        let relative = self.address.bus.checked_sub(self.host.first_bus)?;
        (relative <= 31).then_some(
            u32::from(relative) << 24
                | u32::from(self.address.device * 8 + self.address.function) << 16
                | 0x8000_ffff,
        )
    }
}

impl<R: Registers> Host<R> {
    /// Stop `child` as firmware may have left it: Bus Master and the MSI and
    /// MSI-X enables cleared, INTx Disable set, each read back. Firmware
    /// commonly leaves the NVMe controller behind VMD mastering; Linux's vmd
    /// driver scans it as found and its NVMe driver resets the controller.
    /// Nothing behind VMD reaches memory while the parent's own Bus Master
    /// is clear, so children are stopped only in that state. A child whose
    /// bits stay set is refused and the host poisoned: it would master once
    /// the parent's Bus Master is set.
    pub(super) fn stop_child(&mut self, child: Address) -> Result<(), Error> {
        self.check_live()?;
        let parent = self.io().parent_read(regs::COMMAND, 2)?;
        if parent == u32::from(u16::MAX) {
            return Err(Error::ReadFailed);
        }
        if parent & u32::from(regs::COMMAND_MASTER) != 0 {
            return Err(Error::ActiveChild);
        }
        let mut config = self.config(child.bus, child.device, child.function)?;
        let word = |config: &mut ChildConfig<'_, R>, offset: u16| -> Result<u16, Error> {
            let value = config.read(offset, 2)? as u16;
            (value != u16::MAX)
                .then_some(value)
                .ok_or(Error::ReadFailed)
        };
        let unstopped = Error::UnstoppedChild(child.bus, child.device, child.function);
        let result = (|| {
            let command = word(&mut config, regs::COMMAND)?;
            let stopped = command & !regs::COMMAND_MASTER | regs::COMMAND_INTX_DISABLE;
            if command != stopped {
                config.write(regs::COMMAND, 2, u32::from(stopped))?;
                if word(&mut config, regs::COMMAND)?
                    & (regs::COMMAND_MASTER | regs::COMMAND_INTX_DISABLE)
                    != regs::COMMAND_INTX_DISABLE
                {
                    return Err(unstopped);
                }
            }
            let entries = Capabilities::new(Transport(|offset, bytes| config.read(offset, bytes)))
                .collect::<Result<Vec<_>, Error>>()?;
            for entry in entries {
                let enable = match entry.id {
                    5 => 1,          // MSI Enable
                    0x11 => 1 << 15, // MSI-X Enable; Function Mask is kept.
                    _ => continue,
                };
                let control = word(&mut config, entry.offset + 2)?;
                if control & enable != 0 {
                    config.write(entry.offset + 2, 2, u32::from(control & !enable))?;
                    if word(&mut config, entry.offset + 2)? & enable != 0 {
                        return Err(unstopped);
                    }
                }
            }
            Ok(())
        })();
        if result == Err(unstopped) {
            self.poisoned = true;
        }
        result
    }

    /// The bytes `child`'s memory BAR0 decodes, sized as Linux's
    /// `__pci_read_base` does: memory and I/O decode off while the BAR holds
    /// all ones, then the BAR and command register restored. The child is
    /// stopped first ([`Host::stop_child`]), so a Bus Master firmware left set
    /// stays clear.
    pub fn memory_bar_bytes(&mut self, child: Address) -> Result<u64, Error> {
        self.stop_child(child)?;
        let mut config = self.config(child.bus, child.device, child.function)?;
        let command = config.read(regs::COMMAND, 2)?;
        config.write(
            regs::COMMAND,
            2,
            command & !u32::from(regs::COMMAND_MEMORY | 1),
        )?;
        let size = |config: &mut ChildConfig<'_, R>, offset: u16| -> Result<(u32, u32), Error> {
            let value = config.read(offset, 4)?;
            config.write(offset, 4, u32::MAX)?;
            let mask = config.read(offset, 4)?;
            config.write(offset, 4, value)?;
            Ok((value, mask))
        };
        let sized = (|| {
            let (low, low_mask) = size(&mut config, 0x10)?;
            if low & 1 != 0 {
                return Err(Error::InvalidResource);
            }
            let high_mask = if low & 6 == 4 {
                size(&mut config, 0x14)?.1
            } else {
                0
            };
            let writable = u64::from(high_mask) << 32 | u64::from(low_mask & !15);
            Ok(writable.isolate_lowest_one())
        })();
        config.write(regs::COMMAND, 2, command)?;
        let bytes = sized?;
        if bytes == 0 {
            return Err(Error::InvalidResource);
        }
        Ok(bytes)
    }
}

// ChildConfig keeps the full synthetic VMD domain identity and its actual
// hierarchy borrow. It is not an ACPI-segment Function; do not truncate that
// domain to construct a different PCI/configuration owner.

pub(super) fn scan<R: Registers>(host: &mut Host<R>) -> Result<Vec<Child>, Error> {
    host.check_live()?;
    let mut found = Vec::new();
    for bus in host.buses() {
        for device in 0..32 {
            let mut functions = 1;
            let mut function = 0;
            while function < functions {
                let mut config = host.config(bus, device, function)?;
                let id = config.read(0, 4)?;
                if id as u16 != u16::MAX {
                    let header = config.read(0x0e, 1)? as u8;
                    if function == 0 && header & 0x80 != 0 {
                        functions = 8;
                    }
                    let class = config.read(8, 4)?;
                    found.push(Child {
                        address: config.address(),
                        vendor: id as u16,
                        device: (id >> 16) as u16,
                        class: [(class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8],
                        header: header & 0x7f,
                    });
                }
                function += 1;
            }
        }
    }
    Ok(found)
}
