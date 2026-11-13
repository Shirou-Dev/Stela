//! Exact PCI control writes derived from a read-only configuration census.
use super::{ATS, ClaimError, MSI, MSIX, PASID, PCIE, PRI};
use crate::bus::{
    mmio::owned::Error as MappingError,
    pci::{
        ConfigEffect, ConfigError, ConfigFailure, ConfigSpace,
        capability::{Capabilities, ExtendedCapabilities, Layout, Transport},
        regs,
    },
};
use alloc::vec::Vec;
use core::cell::RefCell;

/// The class and subclass of a host bridge.
const HOST_BRIDGE: u32 = 0x0600;
/// The class and subclass of an ISA bridge, which an LPC bridge reports.
const ISA_BRIDGE: u32 = 0x0601;

#[derive(Clone, Copy)]
struct Control {
    offset: u16,
    original: u16,
    disabled: u16,
    /// Bits of `disabled` the function may leave clear (see
    /// regs::command_optional_bits); every other bit must read back exactly.
    optional: u16,
    /// Bits of `original` that `disabled` clears and hardware may hold set:
    /// only the Bus Master bit of a root-bus host bridge or ISA bridge.
    hardwired: u16,
}

/// PCI Express capability device/port types (PCIe 6.0 section 7.5.3.2)
/// whose bridge may forward transactions under a requester ID of its own.
const PCIE_TO_PCI_BRIDGE: u8 = 0x7;
const PCI_TO_PCIE_BRIDGE: u8 = 0x8;

/// This plan describes PCI-level controls only. It conveys no physical
/// ownership, engine stop, or authority to release old DMA or IRQ state.
pub struct Plan {
    controls: Vec<Control>,
    /// The device/port type of the PCI Express capability, if any.
    express_port: Option<u8>,
}

impl Plan {
    /// Census the function `read` reaches. `root_bus`: it sits on a root
    /// complex's own bus, which no bridge forwards to.
    pub fn read(
        read: impl FnMut(u16, u8) -> Result<u32, ClaimError>,
        root_bus: bool,
    ) -> Result<Self, ClaimError> {
        let reader = RefCell::new(read);
        let read = |offset, width| reader.borrow_mut()(offset, width);
        let mut plan = Self {
            controls: Vec::new(),
            express_port: None,
        };
        let command = read(regs::COMMAND, 2)? as u16;
        if command == u16::MAX {
            return Err(ClaimError::ReadFailed {
                offset: regs::COMMAND,
            });
        }
        // INTx Disable is asked of every function and required of those with
        // an INTx pin; Bus Master is cleared on all of them and must read
        // back clear, except on a host bridge or an ISA bridge on a root bus
        // (the chipset's own functions). Intel hard-wires the Bus Master bit
        // of both set, AMD that of its FCH LPC bridge, and Linux never
        // writes either. An ISA bridge's bit covers only LPC masters and
        // 8237 DMA, which need the legacy DMA controller programmed, and
        // nothing here programs it. There a set bit that stays set is the
        // hardware's, and the seal proves it ([`Plan::seal`]). A function
        // of those classes behind a downstream port is contained like any
        // other.
        let class = read(regs::CLASS_REVISION, 4)? >> 8;
        let hardwired = if root_bus && matches!(class >> 8, HOST_BRIDGE | ISA_BRIDGE) {
            command & regs::COMMAND_MASTER
        } else {
            0
        };
        let pin = read(regs::INTERRUPT_PIN, 1)? as u8;
        plan.push(
            regs::COMMAND,
            command,
            command & !regs::COMMAND_MASTER | regs::COMMAND_INTX_DISABLE,
            regs::command_optional_bits(pin),
        )?;
        plan.controls[0].hardwired = hardwired;

        let mut seen = 0u32;
        for entry in Capabilities::new(Transport(read)) {
            let entry = entry?;
            let id = u16::from(entry.id);
            let (relative, mut clear, event) = match id {
                MSI => (2, 1, 0),
                MSIX => (2, 1 << 15, 0),
                PCIE => (8, 1 << 11, 0),
                _ => continue,
            };
            if entry.layout != Layout::Sized {
                return Err(ClaimError::UnsupportedCapability {
                    id,
                    extended: false,
                });
            }
            record_capability(&mut seen, id, entry.offset, relative, entry.bytes)?;
            if id == PCIE {
                let flags = read(entry.offset + 2, 2)?;
                plan.express_port = Some((flags >> 4 & 0xf) as u8);
                clear |= device_control_reset(flags as u16);
            }
            plan.disable(read, entry.offset + relative, clear, event)?;
        }

        if plan.express_port.is_some() && read(0x100, 4)? != u32::MAX {
            let mut seen = 0u32;
            for entry in ExtendedCapabilities::new(Transport(read)) {
                let entry = entry?;
                let (relative, clear, event) = match entry.id {
                    ATS => (6, 1 << 15, 0),
                    PASID => (6, 1, 0),
                    PRI => (4, 1, 2), // Reset is a command, not persistent state.
                    _ => continue,
                };
                if entry.version != 1 {
                    return Err(ClaimError::UnsupportedVersion {
                        id: entry.id,
                        version: entry.version,
                    });
                }
                if entry.layout != Layout::Sized {
                    return Err(ClaimError::MalformedCapability {
                        offset: entry.offset,
                    });
                }
                record_capability(&mut seen, entry.id, entry.offset, relative, entry.bytes)?;
                plan.disable(read, entry.offset + relative, clear, event)?;
            }
        }
        Ok(plan)
    }

    fn disable(
        &mut self,
        mut read: impl FnMut(u16, u8) -> Result<u32, ClaimError>,
        offset: u16,
        clear: u16,
        event: u16,
    ) -> Result<(), ClaimError> {
        let original = read(offset, 2)? as u16;
        if original == u16::MAX {
            return Err(ClaimError::ReadFailed { offset });
        }
        if original & event != 0 {
            return Err(ClaimError::Config(ConfigError::before_effect(
                ConfigFailure::UnqualifiedControl,
            )));
        }
        self.push(offset, original, original & !clear, 0)
    }

    fn push(
        &mut self,
        offset: u16,
        original: u16,
        disabled: u16,
        optional: u16,
    ) -> Result<(), ClaimError> {
        if self.controls.iter().any(|control| control.offset == offset) {
            return Err(ClaimError::MalformedCapability { offset });
        }
        self.controls
            .try_reserve(1)
            .map_err(|_| ClaimError::Mapping(MappingError::Exhausted))?;
        self.controls.push(Control {
            offset,
            original,
            disabled,
            optional,
            hardwired: 0,
        });
        Ok(())
    }

    /// Whether this function, as a bridge, passes on the requester ID of
    /// each function below it unchanged, so each keeps a remapping context
    /// of its own. A PCI Express root port, switch port or port of any other
    /// type does. A PCI Express to PCI/PCI-X bridge, a PCI/PCI-X to PCI
    /// Express bridge and a bridge without a PCI Express capability may
    /// take over the transactions of the functions below it under an ID of
    /// its own, as Linux's `pci_for_each_dma_alias` assumes.
    pub fn keeps_requester_ids(&self) -> bool {
        !matches!(
            self.express_port,
            None | Some(PCIE_TO_PCI_BRIDGE | PCI_TO_PCIE_BRIDGE)
        )
    }

    /// Does this exact write narrow one observed control?
    pub fn permits(&self, offset: u16, width: usize, value: u32) -> bool {
        width == 2
            && self.controls.iter().any(|control| {
                control.offset == offset
                    && control.original != control.disabled
                    && u32::from(control.disabled) == value
            })
    }

    /// Preflight every old control before issuing any write to this function.
    /// Recheck each changed word and retain the last write on a later refusal.
    pub fn apply(&self, config: &mut impl ConfigSpace) -> Result<ConfigEffect, ConfigError> {
        for &control in &self.controls {
            verify(
                control.offset,
                control.original,
                0,
                config.read16(control.offset)?,
            )?;
        }
        let mut effect = ConfigEffect::None;
        for &control in &self.controls {
            if control.original != control.disabled {
                config
                    .write16(control.offset, control.disabled)
                    .map_err(|error| with_prefix(error, effect))?;
                effect = ConfigEffect::WriteMayHaveApplied {
                    offset: control.offset,
                    width: 2,
                };
                config
                    .read16(control.offset)
                    .and_then(|observed| control.verify_disabled(observed))
                    .map_err(|error| with_prefix(error, effect))?;
            }
        }
        Ok(effect)
    }

    /// Whether a function whose COMMAND reads `command` masters no DMA
    /// this plan has not accounted for: its Bus Master bit reads clear, or
    /// it is a bit this plan lets hardware hold set (a root-bus host bridge
    /// or ISA bridge, see [`Plan::read`]). A function that fails its stop
    /// is judged by this, whatever else it left running.
    pub fn master_stopped(&self, command: u16) -> bool {
        command & regs::COMMAND_MASTER == 0
            || self.controls.iter().any(|control| {
                control.offset == regs::COMMAND && control.hardwired & regs::COMMAND_MASTER != 0
            })
    }

    /// Recheck the stopped controls with a read-only configuration view.
    pub fn check_disabled(
        &self,
        mut read: impl FnMut(u16) -> Result<u16, ConfigError>,
    ) -> Result<(), ConfigError> {
        for control in &self.controls {
            control.verify_disabled(read(control.offset)?)?;
        }
        Ok(())
    }

    /// Acknowledge a contained function: its controls read back stopped,
    /// then its Bus Master bit is sealed. A clear bit is sealed as clear.
    /// A set bit is accepted only where this plan lets hardware hold it
    /// (a root-bus host bridge or ISA bridge whose bit was set) and only
    /// once the seal proves it hard-wired; anything else is refused.
    pub fn seal(&self, config: &mut impl MasterSeal) -> Result<(), ConfigError> {
        self.check_disabled(|offset| config.read16(offset))?;
        let hardwired = self.controls.iter().find(|control| {
            control.offset == regs::COMMAND && control.hardwired & regs::COMMAND_MASTER != 0
        });
        if let Some(command) = hardwired
            && config.read16(regs::COMMAND)? & regs::COMMAND_MASTER != 0
        {
            config.seal_hardwired_bus_master(command.disabled)
        } else {
            config.seal_bus_master()
        }
    }
}

/// The Bus Master seal of a configuration owner: once sealed, no write
/// through the owner may set COMMAND's Bus Master bit.
pub trait MasterSeal: ConfigSpace {
    /// Seal a function whose Bus Master bit reads clear; refuse one whose
    /// bit reads set.
    fn seal_bus_master(&mut self) -> Result<(), ConfigError>;
    /// Seal a function whose Bus Master bit hardware holds set, proven
    /// by writing the plan's stopped COMMAND, `disabled`, again
    /// ([`hardwired_master`]): it cannot be cleared, and the chipset's own
    /// host bridge or ISA bridge masters no DMA Stela has not set up, so
    /// it is left as Linux leaves it. A bit that clears is sealed as clear
    /// instead.
    fn seal_hardwired_bus_master(&mut self, disabled: u16) -> Result<(), ConfigError>;
}

/// Whether COMMAND's Bus Master bit is hard-wired set: it reads set and
/// still reads set after COMMAND is written with `disabled`, the plan's
/// stopped value with that bit clear and the one write containment may
/// make. A writable bit is left clear by the same write.
pub fn hardwired_master(config: &mut impl ConfigSpace, disabled: u16) -> Result<bool, ConfigError> {
    if disabled & regs::COMMAND_MASTER != 0
        || config.read16(regs::COMMAND)? & regs::COMMAND_MASTER == 0
    {
        return Ok(false);
    }
    config.write16(regs::COMMAND, disabled)?;
    Ok(config.read16(regs::COMMAND)? & regs::COMMAND_MASTER != 0)
}

/// The Device Control bit 15 a stop clears, given the PCI Express
/// Capabilities register `flags`. On an endpoint, legacy endpoint or
/// root complex integrated endpoint it is Initiate Function Level Reset,
/// which reads 0: written back as read it could reset the function, and
/// written 0 it does nothing, so the stop clears it. On a PCI Express to
/// PCI bridge it is Bridge Configuration Retry Enable, and on the other
/// port types it is reserved and kept as read, so the stop keeps it.
/// Linux writes it on neither.
fn device_control_reset(flags: u16) -> u16 {
    const ENDPOINT: u16 = 0x0;
    const LEGACY_ENDPOINT: u16 = 0x1;
    const INTEGRATED_ENDPOINT: u16 = 0x9;
    match flags >> 4 & 0xf {
        ENDPOINT | LEGACY_ENDPOINT | INTEGRATED_ENDPOINT => 1 << 15,
        _ => 0,
    }
}

fn record_capability(
    seen: &mut u32,
    id: u16,
    offset: u16,
    relative: u16,
    bytes: u16,
) -> Result<(), ClaimError> {
    let bit = 1 << id;
    if relative + 2 > bytes || *seen & bit != 0 {
        return Err(ClaimError::MalformedCapability { offset });
    }
    *seen |= bit;
    Ok(())
}

impl Control {
    /// A stopped control reads back its disabled value; an optional bit may
    /// read back clear instead, and a hardwired bit set as found.
    fn verify_disabled(&self, observed: u16) -> Result<(), ConfigError> {
        verify(
            self.offset,
            self.disabled,
            self.optional | self.hardwired,
            observed,
        )
    }
}

/// Compare every bit outside `optional`.
fn verify(offset: u16, expected: u16, optional: u16, observed: u16) -> Result<(), ConfigError> {
    if (expected ^ observed) & !optional != 0 {
        return Err(ConfigError::before_effect(ConfigFailure::Readback {
            offset,
            width: 2,
            expected: u32::from(expected),
            observed: u32::from(observed),
        }));
    }
    Ok(())
}

fn with_prefix(error: ConfigError, prefix: ConfigEffect) -> ConfigError {
    match error.effect {
        ConfigEffect::None => ConfigError {
            effect: prefix,
            ..error
        },
        ConfigEffect::WriteMayHaveApplied { .. } => error,
    }
}
