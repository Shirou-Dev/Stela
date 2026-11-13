//! Linux `pci_parent_bus_reset`: a function with no reset of its own is
//! reset by Secondary Bus Reset on the bridge directly above it, when
//! nothing else sits on that bridge's secondary bus. Linux refuses when any
//! other function shares the bus. Here the other functions of the same
//! device are admitted when the caller owns them: the reset stops them too,
//! and their saved state is written back after it.
use super::{
    Address, BlockError, ConfigError, ConfigSpace, Function, HEADER_BRIDGE, SECONDARY_BUS, Saved,
    express_offset, owned::OwnedConfig, power, regs, wait_ready,
};
use alloc::vec::Vec;
use core::cell::Cell;

const BRIDGE_CONTROL: u16 = 0x3e;
const SECONDARY_BUS_RESET: u16 = 1 << 6;
/// The bridge's PCI Express capability: flags, link and slot registers.
const EXPRESS_FLAGS: u16 = 2;
const SLOT_IMPLEMENTED: u16 = 1 << 8;
const LINK_CAPABILITIES: u16 = 0x0c;
const MAX_LINK_SPEED: u32 = 0xf;
/// 5.0 GT/s, the fastest speed Linux waits for by time alone.
const SPEED_5GT: u32 = 2;
const LINK_ACTIVE_REPORTING: u32 = 1 << 20;
const LINK_STATUS: u16 = 0x12;
const LINK_ACTIVE: u16 = 1 << 13;
const SLOT_CAPABILITIES: u16 = 0x14;
const HOT_PLUG_CAPABLE: u32 = 1 << 6;
const SLOT_CONTROL: u16 = 0x18;
const PRESENCE_CHANGE_ENABLE: u16 = 1 << 3;
const LINK_CHANGE_ENABLE: u16 = 1 << 12;
const SLOT_STATUS: u16 = 0x1a;
const PRESENCE_CHANGED: u16 = 1 << 3;
const LINK_CHANGED: u16 = 1 << 8;

/// `pci_reset_secondary_bus`: twice the 1 ms minimum reset time.
const RESET_HOLD_US: u64 = 2_000;
/// The 100 ms a function gets after reset before it must answer.
const RESET_DELAY_US: u64 = 100_000;
/// `pcie_wait_for_link_delay`'s 20 ms before the first Link Status read,
/// its 1 ms poll and `PCIE_LINK_RETRAIN_TIMEOUT_MS`.
const LINK_SETTLE_US: u64 = 20_000;
const LINK_POLL_US: u64 = 1_000;
const LINK_TIMEOUT_US: u64 = 1_000_000;
/// `PCI_RESET_WAIT` and `PCIE_RESET_READY_POLL_MS`.
const RESET_WAIT_US: u64 = 1_000_000;
const READY_POLL_US: u64 = 60_000_000;

/// A bridge's configuration that can assert Secondary Bus Reset.
pub trait SecondaryBusReset: ConfigSpace {
    /// Assert or release Secondary Bus Reset, every other Bridge Control bit
    /// unchanged.
    ///
    /// # Safety
    /// As [`OwnedConfig::set_secondary_bus_reset`].
    unsafe fn set_secondary_bus_reset(&mut self, asserted: bool) -> Result<(), ConfigError>;
}

/// The configuration of a function its owner keeps contained, beside the
/// one a bus reset is for.
pub trait Contained: ConfigSpace {
    /// Admit exactly `writes`, each an offset, a width in bytes and a value:
    /// the state saved before the reset, which the restore after it writes
    /// back, each once.
    fn admit_restore(&mut self, writes: &[(u16, u8, u32)]) -> Result<(), ConfigError>;
}

impl SecondaryBusReset for OwnedConfig {
    unsafe fn set_secondary_bus_reset(&mut self, asserted: bool) -> Result<(), ConfigError> {
        // SAFETY: forwarded.
        unsafe { OwnedConfig::set_secondary_bus_reset(self, asserted) }
    }
}

/// Reset `function` and its `siblings`, the other functions of the same
/// device, by Secondary Bus Reset on `bridge`, as Linux's
/// `pci_bridge_secondary_bus_reset` with pciehp's `pciehp_reset_slot`
/// around it: the slot's presence and link change events are masked
/// through the reset and the changes it causes cleared before they are
/// enabled again. A reset link going down is no Surprise Down error, so
/// AER and DPC see no event. Each function's header and PCI Express
/// controls are saved before and written back after, as
/// [`Function::reset`] does; MSI and MSI-X come back off. `function` is
/// disabled before the reset; each sibling must already be contained, its
/// Bus Master bit clear, and is only saved.
///
/// `present` is every function answering on the bridge's secondary bus;
/// each must be `function` or one of `siblings`, all one device. Refused
/// before any effect otherwise, or when a function on the bus is a bridge,
/// or the bridge does not lead to the function's bus or already holds it
/// in reset. This sleeps at least 102 ms.
///
/// # Safety
/// `bridge` is the bridge directly above `function`. `present` is the
/// complete census of the bridge's secondary bus, and
/// `function` and `siblings` are the only owners of those functions, each
/// stopped or contained with its DMA accounted for. Nothing else resets or
/// reconfigures the bridge or the bus meanwhile. After a failure the
/// functions' state is unknown and the caller keeps them all refused.
pub unsafe fn reset_secondary_bus<B, C, S>(
    bridge: &mut B,
    function: &mut Function<C>,
    siblings: &mut [Function<S>],
    present: &[Address],
    timer: &(impl power::Timer + ?Sized),
) -> Result<(), BlockError>
where
    B: SecondaryBusReset,
    C: ConfigSpace,
    S: Contained,
{
    timer.check()?;
    // SAFETY: forwarded.
    unsafe {
        reset_with(bridge, function, siblings, present, |microseconds| {
            timer.wait_us(microseconds).map_err(BlockError::from)
        })
    }
}

/// # Safety
/// As [`reset_secondary_bus`].
unsafe fn reset_with<B, C, S>(
    bridge: &mut B,
    function: &mut Function<C>,
    siblings: &mut [Function<S>],
    present: &[Address],
    mut delay: impl FnMut(u64) -> Result<(), BlockError>,
) -> Result<(), BlockError>
where
    B: SecondaryBusReset,
    C: ConfigSpace,
    S: Contained,
{
    qualify(bridge, function, siblings, present)?;
    let express = express_offset(bridge)?;
    let mut saved = Vec::with_capacity(siblings.len());
    for sibling in siblings.iter() {
        let express = sibling.express_offset()?;
        saved.push(Saved::save(&sibling.config, express)?);
    }
    let own = function.express_offset()?;
    let first = Saved::save(&function.config, own)?;
    first.disable(&mut function.config)?;
    let slot = match express {
        Some(express) => mask_slot(bridge, express)?,
        None => None,
    };
    // SAFETY: the caller owns every function on the bus, all saved and
    // disabled above; the reset is released below on every path.
    let asserted = unsafe { bridge.set_secondary_bus_reset(true) };
    let held = match asserted {
        Ok(()) => delay(RESET_HOLD_US),
        Err(error) => Err(error.into()),
    };
    // SAFETY: as above.
    let released = unsafe { bridge.set_secondary_bus_reset(false) };
    held?;
    released?;
    let ready = wait_for_bus(bridge, express, function, siblings, &mut delay);
    let unmasked = slot.map_or(Ok(()), |slot| slot.restore(bridge));
    if !ready? {
        return Err(BlockError::Unsupported(
            "PCI function did not return from its bus reset",
        ));
    }
    unmasked?;
    first.restore(&mut function.config)?;
    for (sibling, saved) in siblings.iter_mut().zip(saved) {
        sibling.config.admit_restore(&saved.writes())?;
        saved.restore(&mut sibling.config)?;
    }
    Ok(())
}

/// `pci_parent_bus_reset`'s checks, with the device's own other functions
/// admitted when the caller owns them. Reads only.
fn qualify<B: ConfigSpace, C: ConfigSpace, S: ConfigSpace>(
    bridge: &B,
    function: &Function<C>,
    siblings: &[Function<S>],
    present: &[Address],
) -> Result<(), BlockError> {
    let at = function.address;
    if bridge.read8(regs::HEADER_TYPE)? & 0x7f != HEADER_BRIDGE
        || bridge.read8(SECONDARY_BUS)? != at.bus
    {
        return Err(BlockError::Unsupported(
            "PCI bridge does not lead to the function's bus",
        ));
    }
    if bridge.read16(BRIDGE_CONTROL)? & SECONDARY_BUS_RESET != 0 {
        return Err(BlockError::Unsupported(
            "PCI bridge already holds its secondary bus in reset",
        ));
    }
    let owners = || core::iter::once(at).chain(siblings.iter().map(|sibling| sibling.address));
    let alone = present.len() == siblings.len() + 1
        && present.iter().all(|address| {
            address.segment == at.segment
                && address.bus == at.bus
                && address.device == at.device
                && owners().filter(|owner| owner == address).count() == 1
        });
    if !alone {
        return Err(BlockError::Unsupported(
            "other functions share the PCI function's bus",
        ));
    }
    let mut headers = core::iter::once(function.header_type())
        .chain(siblings.iter().map(|sibling| sibling.header_type()));
    if headers.try_fold(false, |bridged, header| {
        Ok::<_, ConfigError>(bridged || header? != 0)
    })? {
        return Err(BlockError::Unsupported(
            "a bridge shares the PCI function's bus",
        ));
    }
    for sibling in siblings {
        if sibling.config.read16(regs::COMMAND)? & regs::COMMAND_MASTER != 0 {
            return Err(BlockError::Unsupported(
                "a function sharing the PCI function's bus is not contained",
            ));
        }
    }
    Ok(())
}

/// A hot-plug slot's change events, masked through the reset.
struct Slot {
    express: u16,
    masked: u16,
}
impl Slot {
    /// Clear the changes the reset caused, then enable their events again.
    fn restore<B: ConfigSpace>(self, bridge: &mut B) -> Result<(), ConfigError> {
        bridge.write16(self.express + SLOT_STATUS, PRESENCE_CHANGED | LINK_CHANGED)?;
        if self.masked != 0 {
            let control = bridge.read16(self.express + SLOT_CONTROL)?;
            bridge.write16(self.express + SLOT_CONTROL, control | self.masked)?;
        }
        Ok(())
    }
}

/// `pciehp_reset_slot`: mask a hot-plug slot's presence and link change
/// events. None when the bridge has no hot-plug slot.
fn mask_slot<B: ConfigSpace>(bridge: &mut B, express: u16) -> Result<Option<Slot>, ConfigError> {
    if bridge.read16(express + EXPRESS_FLAGS)? & SLOT_IMPLEMENTED == 0
        || bridge.read32(express + SLOT_CAPABILITIES)? & HOT_PLUG_CAPABLE == 0
    {
        return Ok(None);
    }
    let control = bridge.read16(express + SLOT_CONTROL)?;
    let masked = control & (PRESENCE_CHANGE_ENABLE | LINK_CHANGE_ENABLE);
    if masked != 0 {
        bridge.write16(express + SLOT_CONTROL, control & !masked)?;
    }
    Ok(Some(Slot { express, masked }))
}

/// `pci_bridge_wait_for_secondary_bus`: after the reset, wait for the link
/// and then for every function to answer. False when one never did.
fn wait_for_bus<B: ConfigSpace, C: ConfigSpace, S: ConfigSpace>(
    bridge: &B,
    express: Option<u16>,
    function: &Function<C>,
    siblings: &[Function<S>],
    delay: &mut impl FnMut(u64) -> Result<(), BlockError>,
) -> Result<bool, BlockError> {
    let ready = |delay: &mut dyn FnMut(u64) -> Result<(), BlockError>, limit| {
        answered(&function.config, siblings, delay, limit)
    };
    let Some(express) = express else {
        // A conventional bridge: Linux waits one second and the delay.
        delay(RESET_WAIT_US + RESET_DELAY_US)?;
        return ready(delay, RESET_WAIT_US);
    };
    let link = bridge.read32(express + LINK_CAPABILITIES)?;
    let reporting = link & LINK_ACTIVE_REPORTING != 0;
    let active =
        |bridge: &B| Ok::<_, BlockError>(bridge.read16(express + LINK_STATUS)? & LINK_ACTIVE != 0);
    if link & MAX_LINK_SPEED <= SPEED_5GT {
        delay(RESET_DELAY_US)?;
        if ready(delay, RESET_WAIT_US - RESET_DELAY_US)? {
            return Ok(true);
        }
        // A link that reports itself up gets the long wait.
        if !reporting || !active(bridge)? {
            return Ok(false);
        }
        return ready(delay, READY_POLL_US - RESET_WAIT_US);
    }
    if reporting {
        delay(LINK_SETTLE_US)?;
        let mut waited = 0;
        while !active(bridge)? {
            if waited >= LINK_TIMEOUT_US {
                return Err(BlockError::Unsupported(
                    "PCI link did not come back after its bus reset",
                ));
            }
            delay(LINK_POLL_US)?;
            waited += LINK_POLL_US;
        }
        delay(RESET_DELAY_US)?;
    } else {
        delay(LINK_TIMEOUT_US + RESET_DELAY_US)?;
    }
    ready(delay, READY_POLL_US - RESET_DELAY_US)
}

/// [`wait_ready`] for `function`, then each sibling, within `limit`
/// microseconds altogether.
fn answered<C: ConfigSpace, S: ConfigSpace>(
    function: &C,
    siblings: &[Function<S>],
    delay: &mut dyn FnMut(u64) -> Result<(), BlockError>,
    limit: u64,
) -> Result<bool, BlockError> {
    let waited = Cell::new(0);
    let mut counted = |microseconds| {
        waited.set(waited.get() + microseconds);
        delay(microseconds)
    };
    if !wait_ready(function, &mut counted, limit)? {
        return Ok(false);
    }
    for sibling in siblings {
        if !wait_ready(
            &sibling.config,
            &mut counted,
            limit.saturating_sub(waited.get()),
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests;
