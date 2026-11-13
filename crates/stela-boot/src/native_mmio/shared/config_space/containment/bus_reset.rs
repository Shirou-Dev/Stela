//! Secondary Bus Reset of a cold requester's own bus through the forwarding
//! bridge above it, with the device's other parked functions restored to
//! their contained state after it.
use super::*;
use stela_drivers::{
    block::BlockError,
    bus::pci::{ConfigSpace, Function, bus_reset, capability, power::Timer},
};

/// PCI Express device/port types whose link carries a single device: a
/// root port and a switch downstream port.
const ROOT_PORT: u16 = 4;
const DOWNSTREAM_PORT: u16 = 6;
const EXPRESS: u8 = 0x10;

/// A parked function of the reset device, attached for the reset. Its
/// custody admits the writes [`bus_reset::Contained::admit_restore`] names
/// beside the plan's own disabling writes.
struct Sibling {
    config: UnpublishedConfig,
    restore: Rc<RefCell<Vec<(u16, u8, u32)>>>,
}

impl ConfigSpace for Sibling {
    fn read8(&self, offset: u16) -> Result<u8, ConfigError> {
        self.config.try_read8(offset)
    }
    fn read16(&self, offset: u16) -> Result<u16, ConfigError> {
        self.config.try_read16(offset)
    }
    fn read32(&self, offset: u16) -> Result<u32, ConfigError> {
        self.config.try_read32(offset)
    }
    fn write8(&mut self, offset: u16, value: u8) -> Result<(), ConfigError> {
        self.config.try_write8(offset, value)
    }
    fn write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        self.config.try_write16(offset, value)
    }
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        self.config.try_write32(offset, value)
    }
}

impl bus_reset::Contained for Sibling {
    fn admit_restore(&mut self, writes: &[(u16, u8, u32)]) -> Result<(), ConfigError> {
        let mut restore = self.restore.borrow_mut();
        restore.clear();
        restore
            .try_reserve_exact(writes.len())
            .map_err(|_| mapping_error(Error::Exhausted))?;
        restore.extend_from_slice(writes);
        Ok(())
    }
}

/// Whether `bridge` is a PCI Express root or downstream port, whose
/// secondary bus holds the one device at the far end of its link.
fn single_device_link(bridge: &OwnedConfig) -> Result<bool, ConfigError> {
    for entry in capability::capabilities(bridge) {
        let Ok(entry) = entry else {
            return Ok(false);
        };
        if entry.id == EXPRESS {
            let kind = (bridge.try_read16(entry.offset + 2)? >> 4) & 0xf;
            return Ok(matches!(kind, ROOT_PORT | DOWNSTREAM_PORT));
        }
    }
    Ok(false)
}

/// The forwarding bridge above `address` and the device's other functions
/// on its bus, by slot index, when every one of them is parked, unclaimed
/// and unrefused and the bridge's link carries that one device.
fn members(fabric: &Fabric, address: Address) -> Result<(usize, Vec<usize>), &'static str> {
    let at = fabric
        .slots
        .binary_search_by_key(&address, |slot| slot.address)
        .map_err(|_| "the PCI function is outside the contained fabric")?;
    let slot = &fabric.slots[at];
    let topology::Parent::Bridge(bridge) = slot.route else {
        return Err("the PCI function sits on a root bus, with no bridge above it");
    };
    if slot.refusal.is_some() {
        return Err("the PCI function was refused");
    }
    let parent = fabric
        .slots
        .binary_search_by_key(&bridge, |slot| slot.address)
        .expect("original parent remains in the fabric");
    let Some(Forwarding::Open { config, .. }) = &fabric.slots[parent].forwarding else {
        return Err("the bridge above the PCI function does not forward");
    };
    if !single_device_link(config).map_err(|_| "the bridge above the PCI function is unreadable")? {
        return Err("the bridge above the PCI function is no PCI Express root or downstream port");
    }
    let mut siblings = Vec::new();
    for (index, other) in fabric.slots.iter().enumerate() {
        if other.route != slot.route || other.address == address {
            continue;
        }
        if other.refusal.is_some() {
            return Err("another function on the PCI function's bus was refused");
        }
        if other.header.bridge.is_some() || other.forwarding.is_some() {
            return Err("a bridge shares the PCI function's bus");
        }
        if other.configuration.is_none() {
            return Err("another driver claimed a function on the PCI function's bus");
        }
        siblings
            .try_reserve(1)
            .map_err(|_| "no memory for the PCI bus census")?;
        siblings.push(index);
    }
    Ok((parent, siblings))
}

impl Source {
    /// Whether [`Self::reset_parent_bus`] would find a bus it may reset for
    /// the cold requester at `address`. Reads only.
    pub(crate) fn parent_bus_reset_available(&self, address: Address) -> bool {
        let Ok(cohort) = self.pci_slots.0.try_borrow() else {
            return false;
        };
        let Cohort::Parked(fabric) = &*cohort else {
            return false;
        };
        members(fabric, address).is_ok_and(|(parent, _)| {
            fabric.slots[parent]
                .forwarding
                .as_ref()
                .is_some_and(|forwarding| forwarding.check().is_ok())
        })
    }

    /// Reset the bus of the cold requester at `address` by Secondary Bus
    /// Reset on the forwarding bridge above it, as Linux
    /// `pci_parent_bus_reset` ([`bus_reset::reset_secondary_bus`]). Linux
    /// refuses any other function on the bus. Here the device's other
    /// functions are admitted while parked, unclaimed and unrefused: each
    /// is attached, reset with the device, its saved state written back
    /// through a custody that admits exactly those writes, rechecked
    /// against its plan and parked again. The bridge's forwarding and
    /// routing seal are rechecked after. A sibling that does not come back
    /// contained stays refused; any failure is reported once.
    ///
    /// # Safety
    /// `function` is the cold owner of `address` this source promoted, its
    /// Bus Master sealed and its CPU views sealed. The caller keeps every
    /// other configuration and topology writer excluded.
    pub(crate) unsafe fn reset_parent_bus(
        &self,
        address: Address,
        function: &mut Function<OwnedConfig>,
        timer: &dyn Timer,
    ) -> Result<(), BlockError> {
        let refused = |why: &'static str| {
            crate::output::arguments(format_args!(
                "HOST PCI {address} bus reset refused: {why}\n"
            ));
            BlockError::Unsupported(why)
        };
        if function.address != address || function.config().address() != address {
            return Err(refused("the PCI function's owner does not match"));
        }
        let mut cohort = self
            .pci_slots
            .0
            .try_borrow_mut()
            .map_err(|_| refused("the PCI fabric is busy"))?;
        let Cohort::Parked(fabric) = &mut *cohort else {
            return Err(refused("the PCI fabric is not contained"));
        };
        let (parent, indices) = members(fabric, address).map_err(refused)?;
        let forwarding = fabric.slots[parent]
            .forwarding
            .as_ref()
            .expect("checked forwarding");
        if let Err(error) = forwarding.check() {
            crate::output::arguments(format_args!(
                "HOST PCI {address} bus reset refused: the bridge's forwarding changed: {error}\n"
            ));
            return Err(BlockError::Unsupported("the bridge's forwarding changed"));
        }

        // Reserve before any sibling leaves its slot, so no later refusal
        // strands one outside it.
        let (mut present, mut functions, mut slots) = (Vec::new(), Vec::new(), Vec::new());
        if present.try_reserve_exact(indices.len() + 1).is_err()
            || functions.try_reserve_exact(indices.len()).is_err()
            || slots.try_reserve_exact(indices.len()).is_err()
        {
            return Err(refused("no memory for the PCI bus census"));
        }
        present.push(address);
        // Attach every parked sibling, contained as parked.
        for index in indices {
            let slot = &mut fabric.slots[index];
            let prepared = slot.configuration.take().expect("checked parked sibling");
            match self.attach_sibling(slot, prepared) {
                Ok(sibling) => {
                    present.push(sibling.address);
                    functions.push(sibling);
                    slots.push(index);
                }
                Err(refusal) => {
                    report_sibling(&refusal.error, slot.address);
                    slot.refusal = Some(refusal);
                    for (index, sibling) in slots.into_iter().zip(functions) {
                        // SAFETY: the bounded checks above were its only accesses.
                        unsafe {
                            park_back(&mut fabric.slots[index], sibling.into_config().config)
                        };
                    }
                    return Err(refused(
                        "a function sharing the PCI function's bus could not be attached",
                    ));
                }
            }
        }

        let Some(Forwarding::Open { config: bridge, .. }) = &mut fabric.slots[parent].forwarding
        else {
            unreachable!("checked forwarding")
        };
        // SAFETY: the bridge is the original forwarding bridge directly above
        // `address`; `present` is every driven function on its single-device
        // link, owned here: the caller's sealed function and the parked
        // siblings attached above, each contained with Bus Master clear.
        let reset = unsafe {
            bus_reset::reset_secondary_bus(bridge, function, &mut functions, &present, timer)
        };
        let routing = bridge.seal_bus_routing();
        let forwarding = fabric.slots[parent]
            .forwarding
            .as_ref()
            .expect("checked forwarding")
            .check();

        // Restore each sibling's contained, parked state.
        for (index, sibling) in slots.into_iter().zip(functions) {
            let slot = &mut fabric.slots[index];
            let Sibling { config, restore } = sibling.into_config();
            restore.borrow_mut().clear();
            let contained = match &reset {
                Ok(()) => slot
                    .header
                    .verify(|offset| config.try_read32(offset))
                    .and_then(|()| slot.plan.check_disabled(|offset| config.try_read16(offset)))
                    .map_err(ContainmentError::from),
                Err(_) => Err(ContainmentError::from(Error::Unavailable)),
            };
            match contained {
                // SAFETY: the reset's bounded synchronous accesses ended.
                Ok(()) => unsafe { park_back(slot, config) },
                Err(error) => {
                    let refusal = SlotRefusal::unstopped(error, config, &slot.plan);
                    report_sibling(&refusal.error, slot.address);
                    if !refusal.master_stopped {
                        fabric.unstopped_master = fabric.unstopped_master.or(Some(slot.address));
                    }
                    slot.refusal = Some(refusal);
                }
            }
        }
        if let Err(error) = reset {
            crate::output::arguments(format_args!(
                "HOST PCI {address} bus reset failed: {error:?}\n"
            ));
            return Err(error);
        }
        if let Err(error) = routing {
            crate::output::arguments(format_args!(
                "HOST PCI {address} bus reset: the bridge's routing changed: {error}\n"
            ));
            return Err(BlockError::Unsupported("the bridge's routing changed"));
        }
        if let Err(error) = forwarding {
            crate::output::arguments(format_args!(
                "HOST PCI {address} bus reset: the bridge's forwarding changed: {error}\n"
            ));
            return Err(BlockError::Unsupported("the bridge's forwarding changed"));
        }
        Ok(())
    }

    /// Map a parked sibling and check it is still contained as parked.
    fn attach_sibling(
        &self,
        slot: &Slot,
        prepared: PreparedConfig<PrepublicationGrant>,
    ) -> Result<Function<Sibling>, SlotRefusal> {
        let mapping = match self.authority.map(
            prepared.configuration_resource().clone(),
            0,
            PAGE as usize,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        ) {
            Ok(mapping) => mapping,
            Err(error) => return Err(SlotRefusal::new(error, prepared.into_parts())),
        };
        let config = prepared
            .attach(mapping)
            .map_err(|(error, original)| SlotRefusal::new(error, original))?;
        if let Err(error) = slot
            .header
            .verify(|offset| config.try_read32(offset))
            .and_then(|()| slot.plan.check_disabled(|offset| config.try_read16(offset)))
        {
            return Err(SlotRefusal::unstopped(error, config, &slot.plan));
        }
        let sibling = Sibling {
            config,
            restore: slot.restore.clone(),
        };
        Function::new(slot.address, sibling).map_err(|refusal| {
            let error = match refusal.reason {
                stela_drivers::bus::pci::FunctionError::Access(error) => {
                    ContainmentError::from(error)
                }
                _ => ContainmentError::from(Error::InvalidPlatformReply),
            };
            SlotRefusal::unstopped(error, refusal.config.config, &slot.plan)
        })
    }
}

/// Park a sibling's configuration in its slot again, or refuse the slot
/// when the map cannot be withdrawn.
///
/// # Safety
/// Every access through `config` has ended.
unsafe fn park_back(slot: &mut Slot, config: UnpublishedConfig) {
    // SAFETY: forwarded; the source keeps the original decode.
    match unsafe { config.park() } {
        Ok(parked) => slot.configuration = Some(parked),
        Err((error, original)) => {
            let refusal = SlotRefusal::new(
                ContainmentError {
                    address: None,
                    cause: Cause::Claim(ClaimError::Mapping(error)),
                    effect: ConfigEffect::None,
                },
                original,
            );
            report_sibling(&refusal.error, slot.address);
            slot.refusal = Some(refusal);
        }
    }
}

fn report_sibling(error: &ContainmentError, address: Address) {
    crate::output::arguments(format_args!(
        "HOST PCI function {address} not contained after a bus reset: {error}; it stays undriven\n"
    ));
}
