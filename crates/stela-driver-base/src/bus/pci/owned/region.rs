//! Common exact config mapping/IO algorithms; phase-specific original grants.
use super::{
    ConfigRetention,
    grant::{self, Grant, Operation},
};
use crate::bus::{
    mmio::owned::{CacheAttribute, Error as MappingError, Mapping, Protection},
    pci::{Address, ConfigEffect, ConfigError, ConfigFailure, EcamWindow},
};
use core::{mem::size_of, ptr::NonNull};
const FUNCTION_BYTES: usize = 4096;
const BUS_SHIFT: u32 = 20;
const DEVICE_SHIFT: u32 = 15;
const FUNCTION_SHIFT: u32 = 12;
pub(super) fn validate_mapping(
    address: Address,
    window: EcamWindow,
    mapping: &Mapping,
    protection: Protection,
) -> Result<(), ConfigError> {
    if window.start_bus > window.end_bus
        || !window.base.is_multiple_of(1u64 << BUS_SHIFT)
        || window
            .base
            .checked_add((u64::from(window.end_bus) + 1) << BUS_SHIFT)
            .is_none()
    {
        return Err(ConfigError::before_effect(ConfigFailure::Window));
    }
    if address.segment != window.segment
        || address.bus < window.start_bus
        || address.bus > window.end_bus
        || address.device >= 32
        || address.function >= 8
    {
        return Err(ConfigError::before_effect(ConfigFailure::Address));
    }
    // MCFG bases are relative to bus zero, including windows whose first
    // admitted bus is nonzero. Never subtract start_bus from this offset.
    let physical = window
        .base
        .checked_add(u64::from(address.bus) << BUS_SHIFT)
        .and_then(|base| base.checked_add(u64::from(address.device) << DEVICE_SHIFT))
        .and_then(|base| base.checked_add(u64::from(address.function) << FUNCTION_SHIFT))
        .ok_or(ConfigError::before_effect(ConfigFailure::PhysicalSpan))?;
    let end = physical
        .checked_add(FUNCTION_BYTES as u64)
        .ok_or(ConfigError::before_effect(ConfigFailure::PhysicalSpan))?;
    let span = mapping
        .physical_span()
        .map_err(|error| ConfigError::before_effect(ConfigFailure::Mapping(error)))?;
    if span.start() != physical
        || span.end() != end
        || mapping
            .bytes()
            .map_err(|error| ConfigError::before_effect(ConfigFailure::Mapping(error)))?
            != FUNCTION_BYTES
    {
        return Err(ConfigError::before_effect(ConfigFailure::PhysicalSpan));
    }
    if mapping
        .attribute()
        .map_err(|error| ConfigError::before_effect(ConfigFailure::Mapping(error)))?
        != CacheAttribute::Uncached
    {
        return Err(ConfigError::before_effect(ConfigFailure::CacheAttribute));
    }
    if mapping
        .protection()
        .map_err(|error| ConfigError::before_effect(ConfigFailure::Mapping(error)))?
        != protection
    {
        return Err(ConfigError::before_effect(ConfigFailure::Protection));
    }
    let cpu = match protection {
        Protection::ReadOnly => mapping.address(0, FUNCTION_BYTES),
        // SAFETY: only check alignment here. The writable region's accesses
        // retain their exact configuration operation through postvalidation.
        Protection::ReadWrite => unsafe { mapping.configuration_address(0, FUNCTION_BYTES) },
    }
    .map_err(|error| ConfigError::before_effect(ConfigFailure::Mapping(error)))?;
    let base = cpu.as_ptr() as usize;
    if !base.is_multiple_of(FUNCTION_BYTES) || base.checked_add(FUNCTION_BYTES).is_none() {
        return Err(ConfigError::before_effect(ConfigFailure::CpuAddress));
    }
    Ok(())
}

/// # Safety
/// The owning source stopped and joined every actual user of this custody.
pub(super) unsafe fn retire_mapping<G: Grant>(
    grant: &G,
    mapping: Option<&mut Mapping>,
) -> Result<(), MappingError> {
    let state = grant.state();
    state.check_idle()?;
    grant.custody().retirement_context()?;
    if let Some(mapping) = mapping {
        if !mapping.owns_resource(grant.custody().resource())? {
            return Err(MappingError::InvalidPlatformReply);
        }
        // SAFETY: the exact original owner supplies complete retirement.
        unsafe { mapping.retire() }?;
    }
    state.close_metadata();
    state.dismiss_close();
    Ok(())
}

const ROUTING_BASE: u16 = 0x18;
const BRIDGE_CONTROL: u16 = 0x3e;
const SECONDARY_STATUS_WORD: usize = 1;
const DISCARD_TIMER_STATUS: u16 = 1 << 10;
const SECONDARY_BUS_RESET: u16 = 1 << 6;

#[derive(Clone, Copy)]
pub(super) struct RoutingSeal {
    words: [u32; 7],
    control: u16,
}

impl RoutingSeal {
    pub(super) fn check(
        self,
        mut read: impl FnMut(u16, u8) -> Result<u32, ConfigError>,
    ) -> Result<(), ConfigError> {
        if read(0x0e, 1)? & 0x7f != 1 {
            return Err(ConfigError::before_effect(ConfigFailure::Address));
        }
        for (index, expected) in self.words.into_iter().enumerate() {
            let offset = ROUTING_BASE + index as u16 * 4;
            // The upper half of 1Ch is Secondary Status, not the I/O window.
            let mask = if index == SECONDARY_STATUS_WORD {
                0xffff
            } else {
                u32::MAX
            };
            check_route_word(offset, 4, expected & mask, read(offset, 4)? & mask)?;
        }
        let mask = u32::from(!DISCARD_TIMER_STATUS);
        check_route_word(
            BRIDGE_CONTROL,
            2,
            u32::from(self.control) & mask,
            read(BRIDGE_CONTROL, 2)? & mask,
        )
    }
}

fn check_route_word(
    offset: u16,
    width: usize,
    expected: u32,
    observed: u32,
) -> Result<(), ConfigError> {
    if observed != expected {
        return Err(ConfigError::before_effect(ConfigFailure::Readback {
            offset,
            width,
            expected,
            observed,
        }));
    }
    Ok(())
}

pub(super) struct Region<G> {
    address: Address,
    window: EcamWindow,
    mapping: Mapping,
    grant: G,
}
impl Region<grant::PrepublicationGrant> {
    pub(super) fn qualify_promotion<P: grant::PrepublicationCustody + grant::DriverCustody>(
        &mut self,
        qualify: impl FnOnce(&mut P) -> Result<(), MappingError>,
    ) -> Result<(), MappingError> {
        self.check_transition()?;
        self.grant
            .update_typed(qualify)
            .ok_or(MappingError::InvalidPlatformReply)??;
        self.check_transition()
    }

    fn check_transition(&self) -> Result<(), MappingError> {
        self.grant.state().check_idle()?;
        self.grant.state().check_admission()?;
        self.grant.custody().retirement_context()?;
        self.mapping.check_exclusive()?;
        if !self
            .mapping
            .retains_resource(self.grant.custody().resource())?
        {
            return Err(MappingError::InvalidPlatformReply);
        }
        if let Some(seal) = self.grant.state().routing_seal.get() {
            self.check_routing(seal)
                .map_err(|error| match error.reason {
                    ConfigFailure::Mapping(error) => error,
                    _ => MappingError::InvalidPlatformReply,
                })?;
        }
        Ok(())
    }

    pub(super) unsafe fn withdraw_for_park(&mut self) -> Result<(), MappingError> {
        self.check_transition()?;
        // SAFETY: the caller ended every use through this exact map. The
        // grant stays in its envelope through all withdrawal callbacks.
        unsafe { self.mapping.retire() }
    }

    pub(super) fn into_parked(self) -> grant::PrepublicationGrant {
        self.grant
    }

    pub(super) fn into_promoted<P: grant::PrepublicationCustody + grant::DriverCustody>(
        self,
    ) -> Region<grant::DriverGrant> {
        Region::attached(
            self.grant.promote::<P>(),
            self.mapping,
            (self.address, self.window),
        )
    }
}

impl<G: Grant> Region<G> {
    /// Validate by borrowing the original grant and mapping in their envelope.
    pub fn validate_attachment(
        grant: &G,
        mapping: &Mapping,
    ) -> Result<(Address, EcamWindow), ConfigError> {
        let address = grant.custody().address();
        let window = grant.custody().window();
        grant.state().check_admission().map_err(Self::map_error)?;
        validate_mapping(address, window, mapping, Protection::ReadWrite)?;
        grant
            .custody()
            .retirement_context()
            .map_err(Self::map_error)?;
        if !mapping
            .retains_resource(grant.custody().resource())
            .map_err(Self::map_error)?
        {
            return Err(grant::foreign_grant());
        }
        Ok((address, window))
    }

    fn map_error(error: MappingError) -> ConfigError {
        ConfigError::before_effect(ConfigFailure::Mapping(error))
    }

    pub fn attached(grant: G, mapping: Mapping, (address, window): (Address, EcamWindow)) -> Self {
        Self {
            address,
            window,
            mapping,
            grant,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn kept_parts(&mut self) -> (&mut G, &mut Mapping) {
        (&mut self.grant, &mut self.mapping)
    }

    pub fn admission_close(
        &self,
    ) -> Result<crate::bus::pci::assignment::AdmissionClose, MappingError> {
        self.grant.state().admission_close()
    }
    pub fn address(&self) -> Address {
        self.address
    }

    pub fn window(&self) -> EcamWindow {
        self.window
    }

    /// Compare a consumed requester binding with this kept
    /// configuration mapping. Matching numeric BDF/physical addresses do not
    /// check. This establishes no current device quiescence.
    pub fn matches_binding(
        &self,
        binding: &crate::bus::pci::requester::RequesterBinding,
    ) -> Result<bool, MappingError> {
        if self.address != binding.address() {
            return Ok(false);
        }
        binding.matches_mapping(&self.mapping)
    }

    /// Compare the original retained configuration permission, not a BDF or
    /// physical label. This grants no device stop, drain or reset permission.
    pub fn matches_retention(&self, retained: &ConfigRetention) -> Result<bool, MappingError> {
        retained.matches_mapping(&self.mapping)
    }

    /// Keep a read-only epoch seal for this exact original configuration.
    /// It pins mapping retirement until dropped and exposes no register writer.
    pub fn retain_epoch(&self) -> Result<ConfigRetention, MappingError> {
        let custody = self.grant.custody().retain_epoch()?;
        Ok(ConfigRetention {
            custody,
            view: self.mapping.view(0..FUNCTION_BYTES)?,
        })
    }

    /// Transfer the original mapping back to its retirement owner. The unsafe
    /// attachment's epoch/context and access-drain obligations remain in force.
    #[cfg(test)]
    pub fn into_test_parts(self) -> (G, Mapping) {
        (self.grant, self.mapping)
    }
    /// # Safety
    /// All actual config/device/raw-pointer/DMA/IRQ/callback users have ended;
    /// no new access may start. No assignment/grant release is implied. Failure
    /// retains THIS same complete owner; never reconstruct it from descriptors.
    pub unsafe fn retire(&mut self) -> Result<(), MappingError> {
        // SAFETY: caller owns all-user retirement for this exact mapping.
        unsafe { retire_mapping(&self.grant, Some(&mut self.mapping)) }?;
        Ok(())
    }

    pub fn seal_bus_master(&mut self) -> Result<(), ConfigError> {
        if self.try_read16(4)? & 4 != 0 {
            return Err(ConfigError::before_effect(ConfigFailure::BusMasterSealed));
        }
        self.grant.state().master_sealed.set(true);
        Ok(())
    }
    /// Seal a function whose Bus Master bit hardware holds set, as
    /// `requester::containment::hardwired_master` proved just before: it
    /// cannot be cleared, and no later write through this owner may set it.
    /// A bit that reads clear is sealed as clear.
    pub(in crate::bus::pci) fn seal_hardwired_bus_master(&mut self) -> Result<(), ConfigError> {
        if self.try_read16(4)? & 4 == 0 {
            return self.seal_bus_master();
        }
        self.grant.state().master_sealed.set(true);
        Ok(())
    }
    /// # Safety
    /// The owning driver acknowledged actual stop/reset without restart, and
    /// its current root/configuration binding and required payload completion
    /// finished. Old descriptors cannot resume when new mappings are enabled.
    pub unsafe fn release_bus_master_seal(&mut self) {
        self.grant.state().master_sealed.set(false);
    }
    /// Reopen ONLY qualified Type1 upstream forwarding after global containment.
    /// # Safety
    /// The actual complete descendant/source cohort has been contained and
    /// retired, new roots are blocked, every leaf BME seal remains enforced,
    /// and the real bridge routing/assignment owner remains frozen. This does
    /// not authorize an endpoint engine or arbitrary bridge reconfiguration.
    pub unsafe fn release_bus_forwarding_seal(&mut self) -> Result<(), ConfigError> {
        let Some(seal) = self.grant.state().routing_seal.get() else {
            return Err(ConfigError::before_effect(ConfigFailure::Address));
        };
        self.check_routing(seal)?;
        self.seal_bus_master()?;
        self.grant.state().master_sealed.set(false);
        Ok(())
    }
    /// Freeze actual Type1 bus/routing windows for this root cohort. Driver
    /// control can move, but safe config writes cannot reassign source routes.
    pub fn seal_bus_routing(&mut self) -> Result<(), ConfigError> {
        if let Some(seal) = self.grant.state().routing_seal.get() {
            return self.check_routing(seal);
        }
        if self.try_read8(0x0e)? & 0x7f != 1 {
            return Err(ConfigError::before_effect(ConfigFailure::Address));
        }
        let mut words = [0; 7];
        for (index, word) in words.iter_mut().enumerate() {
            *word = self.try_read32(ROUTING_BASE + index as u16 * 4)?;
        }
        // A bridge holding Secondary Bus Reset keeps the buses below it in
        // reset. Their functions answered nothing to the census, so the
        // bridge is refused and the reset is left as found: releasing it
        // would bring up functions nobody has stopped.
        let control = self.try_read16(BRIDGE_CONTROL)?;
        if control & SECONDARY_BUS_RESET != 0 {
            return Err(ConfigError::before_effect(ConfigFailure::Readback {
                offset: BRIDGE_CONTROL,
                width: 2,
                expected: u32::from(control & !SECONDARY_BUS_RESET),
                observed: u32::from(control),
            }));
        }
        self.grant
            .state()
            .routing_seal
            .set(Some(RoutingSeal { words, control }));
        Ok(())
    }

    /// Assert or release Secondary Bus Reset on this routing-sealed bridge,
    /// writing the sealed Bridge Control word with only that bit changed
    /// (and Discard Timer Status, write-one-to-clear, left alone). The seal
    /// is unchanged, so released, the bridge passes its routing check again.
    ///
    /// # Safety
    /// The caller owns every function below the bridge: none can be in use
    /// by another owner, each is stopped or contained with its DMA
    /// accounted for, and the caller restores or keeps refusing each after
    /// the reset. The caller releases the reset it asserted.
    pub unsafe fn set_secondary_bus_reset(&mut self, asserted: bool) -> Result<(), ConfigError> {
        let Some(seal) = self.grant.state().routing_seal.get() else {
            return Err(ConfigError::before_effect(ConfigFailure::Address));
        };
        let control = seal.control & !(DISCARD_TIMER_STATUS | SECONDARY_BUS_RESET);
        let value = if asserted {
            control | SECONDARY_BUS_RESET
        } else {
            control
        };
        self.write16_with(
            BRIDGE_CONTROL,
            value,
            SECONDARY_BUS_RESET | DISCARD_TIMER_STATUS,
        )
    }

    fn check_routing(&self, seal: RoutingSeal) -> Result<(), ConfigError> {
        seal.check(|offset, width| match width {
            1 => self.try_read8(offset).map(u32::from),
            2 => self.try_read16(offset).map(u32::from),
            4 => self.try_read32(offset),
            _ => unreachable!("Type 1 routing register width"),
        })
    }

    /// `free`: Bridge Control bits that may differ from the routing seal.
    fn check_write(
        &self,
        offset: u16,
        value: u32,
        bytes: usize,
        free: u16,
    ) -> Result<(), ConfigError> {
        self.check_terminal()?;
        if self.grant.state().master_sealed.get() && offset == 4 && value & 4 != 0 {
            return Err(ConfigError::before_effect(ConfigFailure::BusMasterSealed));
        }
        if let Some(RoutingSeal { words, .. }) = &self.grant.state().routing_seal.get()
            && (0x18..0x34).contains(&offset)
        {
            let index = usize::from((offset - 0x18) / 4);
            let shift = u32::from(offset & 3) * 8;
            let mask = if bytes == 4 {
                u32::MAX
            } else {
                (1u32 << (bytes * 8)) - 1
            };
            if value & mask != (words[index] >> shift) & mask {
                return Err(ConfigError::before_effect(ConfigFailure::RoutingSealed));
            }
        }
        if let Some(RoutingSeal { control, .. }) = &self.grant.state().routing_seal.get() {
            // Secondary-bus reset and ISA/VGA routing live outside 18h..30h.
            // Freeze that actual bridge-control word, while ordinary Interrupt
            // Line metadata at3Ch remains writable.
            for byte in 0..bytes {
                let at = usize::from(offset) + byte;
                if !(0x3e..0x40).contains(&at) {
                    continue;
                }
                let shift = (at - 0x3e) * 8;
                let written = (value >> (byte * 8)) as u8;
                if (written ^ (*control >> shift) as u8) & !(free >> shift) as u8 != 0 {
                    return Err(ConfigError::before_effect(ConfigFailure::RoutingSealed));
                }
            }
        }
        Ok(())
    }
    fn try_register<T>(&self, offset: u16) -> Result<NonNull<T>, ConfigError> {
        self.check_terminal()?;
        let start = usize::from(offset);
        let width = size_of::<T>();
        if !start.is_multiple_of(width)
            || !start
                .checked_add(width)
                .is_some_and(|end| end <= FUNCTION_BYTES)
        {
            return Err(ConfigError::before_effect(ConfigFailure::Access {
                offset,
                width,
            }));
        }
        // Recheck live registry state for each operation instead of keeping
        // a raw pointer across a possible later mapping quarantine.
        // SAFETY: pointer observation only. All actual volatile accesses below
        // begin and retain the SAME counted operation through postvalidation.
        unsafe { self.mapping.configuration_address(start, width) }
            .map(NonNull::cast)
            .map_err(|error| ConfigError::before_effect(ConfigFailure::Mapping(error)))
    }

    fn check_terminal(&self) -> Result<(), ConfigError> {
        let state = self.grant.state();
        if let Some(error) = state.terminal.get() {
            return Err(error);
        }
        if let Some(waiting) = state.waiting.get() {
            let operation = state.operation.borrow();
            let observed = operation
                .as_ref()
                .expect("retained original operation")
                .failure();
            let error = match observed {
                crate::sync::FaultState::Ready(error) if !error.is_observation() => {
                    state.terminal.set(Some(error));
                    error
                }
                crate::sync::FaultState::Publishing => ConfigError {
                    reason: ConfigFailure::FaultPublishing,
                    effect: waiting.effect,
                },
                _ => waiting,
            };
            return Err(error);
        }
        Ok(())
    }
    fn run<T>(&self, action: impl FnOnce() -> Result<T, ConfigError>) -> Result<T, ConfigError> {
        self.check_terminal()?;
        let state = self.grant.state();
        if state.acting.replace(true) {
            let error = ConfigError {
                reason: ConfigFailure::Interrupted,
                effect: state.effect.get(),
            };
            state.close_metadata();
            if state.terminal.get().is_none() {
                state.terminal.set(Some(error));
            }
            return Err(error);
        }
        state.effect.set(ConfigEffect::None);
        let mut transaction = Transport {
            state,
            finished: false,
        };
        let result = action();
        transaction.finished = true;
        state.acting.set(false);
        if let Some(error) = state.terminal.get() {
            Err(error)
        } else {
            result
        }
    }
    fn begin_operation(&self, operation: Operation) -> Result<(), ConfigError> {
        let operation = self.grant.custody().begin(operation)?;
        let mut stored = self.grant.state().operation.borrow_mut();
        assert!(stored.is_none(), "one original configuration operation");
        *stored = Some(operation);
        drop(stored);
        self.check_terminal()
            .or_else(|error| self.retain_failure(error))
    }
    fn retain_failure<T>(&self, error: ConfigError) -> Result<T, ConfigError> {
        let state = self.grant.state();
        state.close_metadata();
        if !error.is_observation() && state.terminal.get().is_none() {
            state.terminal.set(Some(error));
        }
        state.waiting.set(Some(error));
        Err(state.terminal.get().unwrap_or(error))
    }
    fn record_write(&self, offset: u16, width: u8) {
        let state = self.grant.state();
        state
            .effect
            .set(ConfigEffect::WriteMayHaveApplied { offset, width });
        // SAFETY: called immediately after the exact bounded volatile store.
        unsafe {
            state
                .operation
                .borrow_mut()
                .as_mut()
                .expect("actual operation")
                .record_write(offset, width)
        };
    }
    fn postvalidate<T>(&self, offset: u16, width: u8, wrote: bool) -> Result<(), ConfigError> {
        if let Err(error) = self.try_register::<T>(offset).map(|_| ()) {
            return self.retain_failure(if wrote {
                ConfigError::write_may_have_applied(offset, width, error.reason)
            } else {
                error
            });
        }
        let state = self.grant.state();
        // The SAME complete guard stays in original State through this call.
        // SAFETY: actual bounded volatile operation/raw tail has ended; its
        // mandatory source/hardware postvalidation runs before count release.
        let result = unsafe {
            state
                .operation
                .borrow_mut()
                .as_mut()
                .expect("actual operation")
                .finish()
        };
        if let Err(error) = result {
            return self.retain_failure(error);
        }
        drop(state.operation.borrow_mut().take());
        Ok(())
    }
    pub fn try_read8(&self, offset: u16) -> Result<u8, ConfigError> {
        self.run(|| {
            let register = self.try_register::<u8>(offset)?;
            self.begin_operation(Operation::Read { offset, width: 1 })?;
            // SAFETY: exact checked native width, SAME counted operation held.
            let value = unsafe { register.as_ptr().read_volatile() };
            self.postvalidate::<u8>(offset, 1, false)?;
            Ok(value)
        })
    }
    pub fn try_read16(&self, offset: u16) -> Result<u16, ConfigError> {
        self.run(|| {
            let register = self.try_register::<u16>(offset)?;
            self.begin_operation(Operation::Read { offset, width: 2 })?;
            // SAFETY: exact checked native width, SAME counted operation held.
            let value = unsafe { register.as_ptr().read_volatile() };
            self.postvalidate::<u16>(offset, 2, false)?;
            Ok(u16::from_le(value))
        })
    }
    pub fn try_read32(&self, offset: u16) -> Result<u32, ConfigError> {
        self.run(|| {
            let register = self.try_register::<u32>(offset)?;
            self.begin_operation(Operation::Read { offset, width: 4 })?;
            // SAFETY: exact checked native width, SAME counted operation held.
            let value = unsafe { register.as_ptr().read_volatile() };
            self.postvalidate::<u32>(offset, 4, false)?;
            Ok(u32::from_le(value))
        })
    }
    pub fn try_write8(&mut self, offset: u16, value: u8) -> Result<(), ConfigError> {
        self.run(|| {
            self.check_write(offset, u32::from(value), 1, 0)?;
            let register = self.try_register::<u8>(offset)?;
            self.begin_operation(Operation::Write {
                offset,
                width: 1,
                value: u32::from(value),
            })?;
            // SAFETY: exact checked native width; no adjacent W1C replay.
            unsafe { register.as_ptr().write_volatile(value) };
            self.record_write(offset, 1);
            self.postvalidate::<u8>(offset, 1, true)
        })
    }
    pub fn try_write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        self.write16_with(offset, value, 0)
    }
    fn write16_with(&mut self, offset: u16, value: u16, free: u16) -> Result<(), ConfigError> {
        self.run(|| {
            self.check_write(offset, u32::from(value), 2, free)?;
            let register = self.try_register::<u16>(offset)?;
            self.begin_operation(Operation::Write {
                offset,
                width: 2,
                value: u32::from(value),
            })?;
            // SAFETY: exact checked native width; no adjacent W1C replay.
            unsafe { register.as_ptr().write_volatile(value.to_le()) };
            self.record_write(offset, 2);
            self.postvalidate::<u16>(offset, 2, true)
        })
    }
    pub fn try_write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        self.run(|| {
            self.check_write(offset, value, 4, 0)?;
            let register = self.try_register::<u32>(offset)?;
            self.begin_operation(Operation::Write {
                offset,
                width: 4,
                value,
            })?;
            // SAFETY: exact checked native width; no adjacent W1C replay.
            unsafe { register.as_ptr().write_volatile(value.to_le()) };
            self.record_write(offset, 4);
            self.postvalidate::<u32>(offset, 4, true)
        })
    }
}
/// No source callback, allocator or final destructor runs in transport unwind.
struct Transport<'a> {
    state: &'a super::grant::State,
    finished: bool,
}
impl Drop for Transport<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.state.close_metadata();
            if self.state.terminal.get().is_none() {
                self.state.terminal.set(Some(ConfigError {
                    reason: ConfigFailure::Interrupted,
                    effect: self.state.effect.get(),
                }));
            }
            self.state.acting.set(false);
        }
    }
}
