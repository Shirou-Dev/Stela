extern crate std;
use super::super::owned::test_support::{Counters, fixture};
use super::*;
use crate::bus::pci::regs;
use alloc::sync::Arc;
use core::{cell::Cell, sync::atomic::Ordering};

const PM: u16 = 1;
const PCIX: u16 = 7;

const ADDRESS: Address = Address {
    segment: 0xfffe,
    bus: 0xe7,
    device: 29,
    function: 6,
};

struct Config {
    words: [u32; 1024],
    last_read: Cell<u16>,
    /// COMMAND bits that ignore writes, as hardwired bits do.
    command_fixed: u16,
    /// Bus Master is sealed: a COMMAND write that sets it is refused.
    master_sealed: bool,
    /// Each COMMAND value written, in order.
    command_writes: alloc::vec::Vec<u16>,
}
impl ConfigSpace for Config {
    fn read32(&self, offset: u16) -> Result<u32, crate::bus::pci::ConfigError> {
        Ok({
            self.last_read.set(offset);
            self.words[usize::from(offset / 4)]
        })
    }
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), crate::bus::pci::ConfigError> {
        let index = usize::from(offset / 4);
        if self.master_sealed
            && index == usize::from(regs::COMMAND / 4)
            && value & u32::from(regs::COMMAND_MASTER) != 0
        {
            return Err(crate::bus::pci::ConfigError::before_effect(
                crate::bus::pci::ConfigFailure::BusMasterSealed,
            ));
        }
        let fixed = if index == usize::from(regs::COMMAND / 4) {
            self.command_writes.push(value as u16);
            u32::from(self.command_fixed)
        } else {
            0
        };
        self.words[index] = value & !fixed | self.words[index] & fixed;
        Ok(())
    }

    fn read8(&self, offset: u16) -> Result<u8, crate::bus::pci::ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 3) * 8)) as u8)
    }

    fn write8(&mut self, offset: u16, value: u8) -> Result<(), crate::bus::pci::ConfigError> {
        let shift = (offset & 3) * 8;
        let word = self.read32(offset & !3)? & !(0xff << shift) | u32::from(value) << shift;
        self.write32(offset & !3, word)
    }

    fn read16(&self, offset: u16) -> Result<u16, crate::bus::pci::ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 2) * 8)) as u16)
    }

    fn write16(&mut self, offset: u16, value: u16) -> Result<(), crate::bus::pci::ConfigError> {
        let shift = (offset & 2) * 8;
        let word = self.read32(offset & !3)? & !(0xffff << shift) | u32::from(value) << shift;
        self.write32(offset & !3, word)
    }
}
/// The configuration owner's seal, as `UnpublishedConfig` keeps it.
impl containment::MasterSeal for Config {
    fn seal_bus_master(&mut self) -> Result<(), crate::bus::pci::ConfigError> {
        if self.read16(regs::COMMAND)? & regs::COMMAND_MASTER != 0 {
            return Err(crate::bus::pci::ConfigError::before_effect(
                crate::bus::pci::ConfigFailure::BusMasterSealed,
            ));
        }
        self.master_sealed = true;
        Ok(())
    }
    fn seal_hardwired_bus_master(
        &mut self,
        disabled: u16,
    ) -> Result<(), crate::bus::pci::ConfigError> {
        if containment::hardwired_master(self, disabled)? {
            self.master_sealed = true;
            Ok(())
        } else {
            containment::MasterSeal::seal_bus_master(self)
        }
    }
}
fn configure<C: ConfigSpace>(config: &mut C) {
    config.write32(0, 0x2c05_10de).unwrap();
    config.write32(8, 0x0300_0000).unwrap();
    config
        .write16(regs::COMMAND, regs::COMMAND_INTX_DISABLE)
        .unwrap();
    // INTA, as a function that can raise INTx.
    config.write8(regs::INTERRUPT_PIN, 1).unwrap();
}
fn endpoint() -> Function<Config> {
    let mut config = Config {
        words: [0; 1024],
        last_read: Cell::new(0),
        command_fixed: 0,
        master_sealed: false,
        command_writes: alloc::vec::Vec::new(),
    };
    configure(&mut config);
    Function::new(ADDRESS, config).unwrap()
}
fn cap(function: &mut Function<Config>, offset: u16, id: u16, next: u16) {
    function
        .config()
        .write16(regs::STATUS, regs::STATUS_CAP_LIST)
        .unwrap();
    function.config().write8(0x34, offset as u8).unwrap();
    function.config().write16(offset, id | next << 8).unwrap();
    if id == PM {
        function.config().write16(offset + 2, 3).unwrap();
    }
}
/// An extended entry, on a function made PCI Express when it has no standard
/// list yet: only such a function has an extended list.
fn ext(function: &mut Function<Config>, offset: u16, id: u16, version: u32, next: u16) {
    if function.config().read8(0x34).unwrap() == 0 {
        cap(function, 0x40, PCIE, 0);
        function.config().write16(0x42, 2).unwrap();
    }
    function
        .config()
        .write32(
            offset,
            u32::from(id) | version << 16 | u32::from(next) << 20,
        )
        .unwrap();
}
fn release(function: Function<OwnedConfig>, counters: &Arc<Counters>) {
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    // SAFETY: fixture has no device, IRQ or workers and no config access
    // remains after consuming the original function owner.
    unsafe { super::super::owned::test_support::retire_owned(function.into_config()) }.unwrap();
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 1);
}

#[test]
fn owned_config_binds_full_segment_rid_and_keeps_original_epoch() {
    let (mut config, counters) = fixture(ADDRESS);
    configure(&mut config);
    let function = Function::new(ADDRESS, config).unwrap();
    // SAFETY: isolated RAM fixture has no active engine, alias, VF or IRQ;
    // its real registry owners are held, without native validation.
    let mut claim =
        match unsafe { StoppedRequester::from_stopped_pci(function, FunctionRole::Physical) } {
            Ok(claim) => claim,
            Err((error, _)) => panic!("valid owned endpoint: {error:?}"),
        };
    assert_eq!(claim.address(), ADDRESS);
    assert_eq!(claim.requester(), 0xe7ee);
    assert_eq!(claim.check_stopped(), Ok(()));
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
    release(claim.into_function(), &counters);
}

fn bound_fixture() -> (StoppedRequester, RequesterBinding, Arc<Counters>) {
    let (mut config, counters) = fixture(ADDRESS);
    configure(&mut config);
    let function = Function::new(ADDRESS, config).unwrap();
    // SAFETY: isolated registry-owned RAM; no device/IRQ/worker.
    let claim =
        match unsafe { StoppedRequester::from_stopped_pci(function, FunctionRole::Physical) } {
            Ok(claim) => claim,
            Err((error, _)) => panic!("fixture claim: {error:?}"),
        };
    let (function, binding) = match claim.into_dma_binding() {
        Ok(pair) => pair,
        Err((error, _)) => panic!("fixture binding: {error:?}"),
    };
    (function, binding, counters)
}

#[test]
fn binding_keeps_original_config_and_native_root_until_explicit_release() {
    let (mut claim, binding, counters) = bound_fixture();
    assert_eq!(claim.check_stopped(), Ok(()));
    let (error, claim) = match claim.into_dma_binding() {
        Err(error) => error,
        Ok(_) => panic!("second safe DMA binding accepted"),
    };
    assert_eq!(error, ClaimError::AlreadyBound);
    let mut function = claim.into_function();
    assert_eq!(binding.address(), ADDRESS);
    assert_eq!(binding.requester(), 0xe7ee);
    assert_eq!(binding.check_live(), Ok(()));
    assert_eq!(function.config().read32(0).unwrap(), 0x2c05_10de);
    let mut config = function.into_config();
    assert_eq!(config.matches_binding(&binding), Ok(true));
    // SAFETY: stopped synchronous fixture; Busy must refuse before unmap.
    assert_eq!(unsafe { config.retire() }, Err(MappingError::Busy));
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    let (other, other_counters) = fixture(ADDRESS);
    // Same BDF and even the fixture's same numeric root identity do not
    // reproduce the original Permission allocation.
    assert_eq!(other.matches_binding(&binding), Ok(false));
    drop(binding);
    // SAFETY: explicit fixture release follows the final binding.
    unsafe { super::super::owned::test_support::retire_owned(config) }.unwrap();
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
    // SAFETY: independent original synchronous fixture mapping.
    unsafe { super::super::owned::test_support::retire_owned(other) }.unwrap();
    assert_eq!(other_counters.unmaps.load(Ordering::Relaxed), 1);
}

#[test]
fn dropping_original_config_permanently_quarantines_the_bound_epoch() {
    let (function, binding, counters) = bound_fixture();
    drop(function);
    assert!(binding.check_live().is_err());
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    drop(binding);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
}

#[test]
fn binding_recheck_refusal_returns_the_unchanged_original_function() {
    let (mut config, counters) = fixture(ADDRESS);
    configure(&mut config);
    let function = Function::new(ADDRESS, config).unwrap();
    // SAFETY: isolated synchronous stopped fixture, as above.
    let mut claim =
        match unsafe { StoppedRequester::from_stopped_pci(function, FunctionRole::Physical) } {
            Ok(claim) => claim,
            Err((error, _)) => panic!("fixture claim: {error:?}"),
        };
    // Private test access models a changed hardware observation.
    claim
        .function
        .config()
        .write16(
            regs::COMMAND,
            regs::COMMAND_INTX_DISABLE | regs::COMMAND_MASTER,
        )
        .unwrap();
    let (error, claim) = match claim.into_dma_binding() {
        Err(error) => error,
        Ok(_) => panic!("active requester accepted"),
    };
    assert_eq!(
        error,
        ClaimError::Active {
            offset: regs::COMMAND
        }
    );
    let mut function = claim.into_function();
    assert_eq!(function.address, ADDRESS);
    assert_eq!(
        function.config().read16(regs::COMMAND).unwrap(),
        regs::COMMAND_INTX_DISABLE | regs::COMMAND_MASTER
    );
    function
        .config()
        .write16(regs::COMMAND, regs::COMMAND_INTX_DISABLE)
        .unwrap();
    release(function, &counters);
}

#[test]
fn rejected_roles_and_mutable_public_metadata_return_the_original_owner() {
    for role in [FunctionRole::Virtual, FunctionRole::Unverified] {
        let (mut config, counters) = fixture(ADDRESS);
        configure(&mut config);
        let function = Function::new(ADDRESS, config).unwrap();
        // SAFETY: fixture is drained; unsupported role makes no grant.
        let (error, function) = match unsafe { StoppedRequester::from_stopped_pci(function, role) }
        {
            Err(rejected) => rejected,
            Ok(_) => panic!("unsupported role admitted"),
        };
        assert_eq!(error, ClaimError::UnsupportedRole(role));
        release(function, &counters);
    }
    let (mut config, counters) = fixture(ADDRESS);
    configure(&mut config);
    let mut function = Function::new(ADDRESS, config).unwrap();
    function.address.bus ^= 1;
    // SAFETY: drained fixture, mismatched metadata must fail.
    let (error, function) =
        match unsafe { StoppedRequester::from_stopped_pci(function, FunctionRole::Physical) } {
            Err(rejected) => rejected,
            Ok(_) => panic!("forged metadata admitted"),
        };
    assert_eq!(error, ClaimError::IdentityChanged);
    release(function, &counters);
}

#[test]
fn device_identity_interrupt_gating_and_header_are_observed_not_assumed() {
    assert_eq!(validate_stopped(&mut endpoint()), Ok(()));
    for (offset, value, expected) in [
        (0, u32::MAX, ClaimError::ReadFailed { offset: 0 }),
        (0, 0x2c03_10de, ClaimError::IdentityChanged),
        (8, u32::MAX, ClaimError::ReadFailed { offset: 8 }),
        (8, 0x0400_0000, ClaimError::IdentityChanged),
        (4, 0x0404, ClaimError::Active { offset: 4 }),
        (4, 0, ClaimError::Active { offset: 4 }),
        (4, 0xffff, ClaimError::ReadFailed { offset: 4 }),
    ] {
        let mut function = endpoint();
        function.config().write32(offset, value).unwrap();
        assert_eq!(validate_stopped(&mut function), Err(expected));
    }
    // A conventional function has no extended space: its first extended
    // header reads all-ones.
    let mut function = endpoint();
    function.config().write32(0x100, u32::MAX).unwrap();
    assert_eq!(validate_stopped(&mut function), Ok(()));
    let mut function = endpoint();
    function.config().write8(0x0e, 1).unwrap();
    assert_eq!(
        validate_stopped(&mut function),
        Err(ClaimError::UnsupportedHeader(1))
    );
    // Without an INTx pin, INTx Disable may stay clear; Bus Master may not.
    let mut function = endpoint();
    function.config().write8(regs::INTERRUPT_PIN, 0).unwrap();
    function.config().write16(regs::COMMAND, 0).unwrap();
    assert_eq!(validate_stopped(&mut function), Ok(()));
    function.config().write16(regs::COMMAND, 4).unwrap();
    assert_eq!(
        validate_stopped(&mut function),
        Err(ClaimError::Active { offset: 4 })
    );
    let mut function = endpoint();
    function.class = [0xff; 3];
    function.config().write32(8, u32::MAX).unwrap();
    assert_eq!(
        validate_stopped(&mut function),
        Err(ClaimError::ReadFailed { offset: 8 })
    );
}

/// PCIe 4.0 added Extended Message Data Capable (bit 9) and Enable (bit 10)
/// to MSI Message Control. A function that only reports the capability, as
/// newer GPUs do, is stopped like any other; one with it enabled is refused.
#[test]
fn msi_extended_message_data_is_accepted_as_a_capability_and_refused_when_enabled() {
    for flags in [0x200, 0x380, 0xf980] {
        let mut function = endpoint();
        cap(&mut function, 0x40, MSI, 0);
        function.config().write16(0x42, flags).unwrap();
        assert_eq!(validate_stopped(&mut function), Ok(()), "{flags:#x}");
    }
    let mut function = endpoint();
    cap(&mut function, 0x40, MSI, 0);
    function.config().write16(0x42, 0x600).unwrap();
    assert_eq!(
        validate_stopped(&mut function),
        Err(ClaimError::MalformedCapability { offset: 0x40 })
    );
}

#[test]
fn msi_layouts_pcie_versions_and_no_snoop_require_complete_extents() {
    for (flags, length) in [(0, 10), (0x80, 14), (0x100, 20), (0x180, 24)] {
        let mut function = endpoint();
        cap(&mut function, 0x40, MSI, 0);
        function.config().write16(0x42, flags).unwrap();
        assert_eq!(validate_stopped(&mut function), Ok(()));
        function.config().write16(0x42, flags | 1).unwrap();
        assert_eq!(
            validate_stopped(&mut function),
            Err(ClaimError::Active { offset: 0x42 })
        );
        function.config().write16(0x42, flags).unwrap();
        let collision = 0x40 + ((length - 1) / 4) * 4;
        function
            .config()
            .write16(0x40, MSI | collision << 8)
            .unwrap();
        function.config().write16(collision, PM).unwrap();
        function.config().write16(collision + 2, 3).unwrap();
        assert_eq!(
            validate_stopped(&mut function),
            Err(ClaimError::MalformedCapability { offset: collision })
        );
    }
    for (kind, version, bytes) in [(0, 1, 20), (1, 2, 52), (9, 1, 12), (9, 2, 44)] {
        let mut function = endpoint();
        cap(&mut function, 0x40, PCIE, 0);
        function
            .config()
            .write16(0x42, version | kind << 4)
            .unwrap();
        assert_eq!(validate_stopped(&mut function), Ok(()));
        function.config().write16(0x48, 1 << 11).unwrap();
        assert_eq!(
            validate_stopped(&mut function),
            Err(ClaimError::Active { offset: 0x48 })
        );
        // A full layout one DWORD beyond the conventional region is refused
        // before Device Control could be read from unrelated space.
        let offset = 260 - bytes;
        let mut function = endpoint();
        cap(&mut function, offset, PCIE, 0);
        function
            .config()
            .write16(offset + 2, version | kind << 4)
            .unwrap();
        assert_eq!(
            validate_stopped(&mut function),
            Err(ClaimError::MalformedCapability { offset })
        );
        assert!(function.config().last_read.get() <= offset);
    }
    let mut function = endpoint();
    cap(&mut function, 0x40, MSIX, 0);
    function.config().write16(0x42, 0x8000).unwrap();
    assert_eq!(
        validate_stopped(&mut function),
        Err(ClaimError::Active { offset: 0x42 })
    );
}

#[test]
fn linked_zero_cycles_overlaps_unknowns_and_unmasked_pointers_are_refused() {
    for pointer in [0x3f, 0x41, 0xff] {
        let mut function = endpoint();
        function
            .config()
            .write16(regs::STATUS, regs::STATUS_CAP_LIST)
            .unwrap();
        function.config().write8(0x34, pointer).unwrap();
        assert!(matches!(
            validate_stopped(&mut function),
            Err(ClaimError::MalformedCapability { .. })
        ));
    }
    for (first, second) in [(0x40, 0x44), (0x44, 0x40), (0x40, 0x40)] {
        let mut function = endpoint();
        cap(&mut function, first, PM, second);
        if first != second {
            function.config().write16(second, PM).unwrap();
            function.config().write16(second + 2, 3).unwrap();
        }
        assert!(matches!(
            validate_stopped(&mut function),
            Err(ClaimError::MalformedCapability { .. })
        ));
    }
    // An ID with no control that can start a request is ignored, known or not.
    let mut unknown = endpoint();
    cap(&mut unknown, 0x40, 0x7f, 0);
    assert_eq!(validate_stopped(&mut unknown), Ok(()));
    let mut unknown = endpoint();
    ext(&mut unknown, 0x100, 0x7fff, 1, 0);
    assert_eq!(validate_stopped(&mut unknown), Ok(()));
    let mut gpu = endpoint();
    ext(&mut gpu, 0x100, 0, 1, 0x140);
    ext(&mut gpu, 0x140, 0x01, 2, 0x180);
    ext(&mut gpu, 0x180, 0x15, 1, 0x1c0);
    ext(&mut gpu, 0x1c0, 0x10, 1, 0);
    assert_eq!(validate_stopped(&mut gpu), Ok(()));
    gpu.config().write16(0x1c0 + 8, 1).unwrap();
    assert_eq!(
        validate_stopped(&mut gpu),
        Err(ClaimError::Active { offset: 0x1c8 })
    );
    for next in [0x104, 0x101, 0xfff, 0x100, 0x120] {
        let mut function = endpoint();
        ext(&mut function, 0x100, ATS, 1, next);
        assert!(validate_stopped(&mut function).is_err());
    }
}

#[test]
fn pcix_versioned_bodies_cannot_hide_an_overlapping_capability() {
    for version in 0..=2 {
        let mut function = endpoint();
        cap(&mut function, 0x40, PCIX, 0);
        function.config().write16(0x42, version << 12).unwrap();
        assert_eq!(validate_stopped(&mut function), Ok(()));
    }
    // A PCI-X version without a layout here is ignored: PCI-X starts no request.
    let mut function = endpoint();
    cap(&mut function, 0x40, PCIX, 0);
    function.config().write16(0x42, 3 << 12).unwrap();
    assert_eq!(validate_stopped(&mut function), Ok(()));
    for version in [1, 2] {
        for reverse in [false, true] {
            let mut function = endpoint();
            cap(&mut function, 0x40, PCIX, if reverse { 0 } else { 0x48 });
            function.config().write16(0x42, version << 12).unwrap();
            function
                .config()
                .write16(0x48, MSI | if reverse { 0x40 << 8 } else { 0 })
                .unwrap();
            if reverse {
                function.config().write8(0x34, 0x48).unwrap();
            }
            assert!(matches!(
                validate_stopped(&mut function),
                Err(ClaimError::MalformedCapability { .. })
            ));
        }
    }
    // Power management starts no request in any version or power state; Linux
    // skips only PM itself on a function with an unknown PM version.
    for version in 0..=7 {
        for state in 0..=3 {
            let mut function = endpoint();
            cap(&mut function, 0x40, PM, 0);
            function.config().write16(0x42, version).unwrap();
            function.config().write16(0x44, state | 1 << 8).unwrap();
            assert_eq!(validate_stopped(&mut function), Ok(()));
        }
    }
}

#[test]
fn translation_features_require_inactive_controls_and_stopped_pri() {
    for (id, control, active) in [(ATS, 6, 0x8000), (PRI, 4, 1), (PRI, 4, 2), (PASID, 6, 1)] {
        let mut function = endpoint();
        ext(&mut function, 0x100, id, 1, 0);
        if id == PRI {
            function.config().write16(0x106, 0x100).unwrap();
        }
        assert_eq!(validate_stopped(&mut function), Ok(()));
        function.config().write16(0x100 + control, active).unwrap();
        assert_eq!(
            validate_stopped(&mut function),
            Err(ClaimError::Active {
                offset: 0x100 + control
            })
        );
        function
            .config()
            .write16(0x100 + control, u16::MAX)
            .unwrap();
        assert_eq!(
            validate_stopped(&mut function),
            Err(ClaimError::ReadFailed {
                offset: 0x100 + control
            })
        );
    }
    let mut function = endpoint();
    ext(&mut function, 0x100, PRI, 1, 0);
    assert_eq!(
        validate_stopped(&mut function),
        Err(ClaimError::Active { offset: 0x106 })
    );
    for (id, bytes) in [(ATS, 8), (PRI, 16), (PASID, 8)] {
        let mut function = endpoint();
        ext(&mut function, 0x100, ATS, 1, 4100 - bytes);
        ext(&mut function, 4100 - bytes, id, 1, 0);
        assert!(matches!(
            validate_stopped(&mut function),
            Err(ClaimError::MalformedCapability { .. })
        ));
        let mut function = endpoint();
        ext(&mut function, 0x100, id, 2, 0);
        assert_eq!(
            validate_stopped(&mut function),
            Err(ClaimError::UnsupportedVersion { id, version: 2 })
        );
    }
}

/// A function with `class` and `header` type, its capability lists linked in
/// order: `standard` as (offset, ID, Message Control or flags word),
/// `extended` as (offset, ID, version).
fn listed(
    class: u32,
    header: u8,
    standard: &[(u16, u16, u16)],
    extended: &[(u16, u16, u32)],
) -> Function<Config> {
    let mut config = Config {
        words: [0; 1024],
        last_read: Cell::new(0),
        command_fixed: 0,
        master_sealed: false,
        command_writes: alloc::vec::Vec::new(),
    };
    configure(&mut config);
    config.write32(8, class << 8).unwrap();
    config.write8(0x0e, header).unwrap();
    config.write16(regs::STATUS, regs::STATUS_CAP_LIST).unwrap();
    config.write8(0x34, standard[0].0 as u8).unwrap();
    for (index, &(offset, id, word)) in standard.iter().enumerate() {
        let next = standard.get(index + 1).map_or(0, |entry| entry.0);
        config.write16(offset, id | next << 8).unwrap();
        config.write16(offset + 2, word).unwrap();
    }
    for (index, &(offset, id, version)) in extended.iter().enumerate() {
        let next = extended.get(index + 1).map_or(0, |entry| entry.0);
        config
            .write32(
                offset,
                u32::from(id) | version << 16 | u32::from(next) << 20,
            )
            .unwrap();
    }
    Function::new(ADDRESS, config).unwrap()
}

/// Controls of ignored capabilities set as a running system leaves them:
/// L1 substates, LTR, AER masks and severities, a Resizable BAR size.
fn set_ignored_controls(function: &mut Function<Config>, writes: &[(u16, u32)]) {
    for &(offset, value) in writes {
        function.config().write32(offset, value).unwrap();
    }
}

/// A current NVIDIA GeForce GPU, as lspci lists one: PM, 64-bit MSI, a
/// legacy PCI Express endpoint and a vendor-specific entry; then virtual
/// channels, LTR, L1 substates, power budgeting, AER, a vendor-specific
/// entry, secondary PCI Express, Resizable BAR, the 16 and 32 GT/s physical
/// layers, lane margining and data link features.
fn geforce() -> Function<Config> {
    let mut gpu = listed(
        0x03_0000,
        0,
        &[
            (0x60, PM, 3),
            (0x68, MSI, 0x80),
            (0x78, PCIE, 2 | 1 << 4),
            (0xb4, 9, 0x14),
        ],
        &[
            (0x100, 0x02, 1),
            (0x250, 0x18, 1),
            (0x258, 0x1e, 1),
            (0x128, 0x04, 1),
            (0x420, 0x01, 2),
            (0x600, 0x0b, 1),
            (0x900, 0x19, 1),
            (0xbb0, 0x15, 1),
            (0xc1c, 0x26, 1),
            (0xd00, 0x27, 1),
            (0xe00, 0x25, 1),
            (0xe10, 0x2a, 1),
        ],
    );
    set_ignored_controls(
        &mut gpu,
        &[
            (0x604, 0x024 << 20 | 1),
            (0x254, 0x1003_1003),
            (0x260, 0x4000_000f),
            (0x428, 0x0040_0000),
            (0x430, 0x0000_e000),
            (0xbb8, 0x0000_0e20),
        ],
    );
    gpu
}

/// A data centre NVMe disk: PM, 64-bit MSI with 32 messages, a PCI Express
/// endpoint, MSI-X and VPD; then AER, the serial number, power budgeting,
/// secondary PCI Express, the 16 GT/s physical layer, lane margining, LTR,
/// L1 substates, TPH, PTM, a DOE mailbox and data link features. VPD, TPH,
/// PTM and DOE each refused it before.
fn nvme() -> Function<Config> {
    let mut disk = listed(
        0x01_0802,
        0,
        &[
            (0x40, PM, 3),
            (0x50, MSI, 0x8a),
            (0x70, PCIE, 2),
            (0xb0, MSIX, 0x20),
            (0xd0, 0x03, 0),
        ],
        &[
            (0x100, 0x01, 2),
            (0x148, 0x03, 1),
            (0x158, 0x04, 1),
            (0x168, 0x19, 1),
            (0x188, 0x26, 1),
            (0x1ac, 0x27, 1),
            (0x214, 0x18, 1),
            (0x21c, 0x1e, 1),
            (0x300, 0x17, 1),
            (0x320, 0x1f, 1),
            (0x330, 0x2e, 1),
            (0x3a0, 0x25, 1),
        ],
    );
    set_ignored_controls(
        &mut disk,
        &[
            (0x218, 0x1003_1003),
            (0x224, 0x4000_000f),
            (0x108, 0x0040_0000),
            // TPH Requester Control: interrupt vector mode, requester enabled.
            (0x308, 0x0000_0101),
            // PTM Control: enabled.
            (0x328, 1),
            // DOE Control: interrupt enabled, as its MSI-X vector is off.
            (0x338, 2),
        ],
    );
    disk
}

/// Every capability without a control that starts a request is ignored, so
/// a GPU and an NVMe disk as they really list theirs are stopped; their
/// interrupt and translation controls still refuse them when set.
#[test]
fn real_gpu_and_nvme_capability_lists_are_stopped_unless_an_interrupt_is_enabled() {
    assert_eq!(validate_stopped(&mut geforce()), Ok(()));
    let mut gpu = geforce();
    gpu.config().write16(0x6a, 0x81).unwrap();
    assert_eq!(
        validate_stopped(&mut gpu),
        Err(ClaimError::Active { offset: 0x6a })
    );
    let mut gpu = geforce();
    gpu.config().write16(0x80, 1 << 11).unwrap();
    assert_eq!(
        validate_stopped(&mut gpu),
        Err(ClaimError::Active { offset: 0x80 })
    );

    assert_eq!(validate_stopped(&mut nvme()), Ok(()));
    let mut disk = nvme();
    disk.config().write16(0xb2, 0x8020).unwrap();
    assert_eq!(
        validate_stopped(&mut disk),
        Err(ClaimError::Active { offset: 0xb2 })
    );
    let mut disk = nvme();
    disk.config().write16(0x7a, 1 << 5).unwrap();
    assert_eq!(
        validate_stopped(&mut disk),
        Err(ClaimError::Active { offset: 0x7a })
    );
}

/// A PCIe root port and a switch downstream port list SSVID, HyperTransport,
/// ACS, DPC and PTM beside AER and the link layers. With DPC triggering, AER
/// root reporting and PME interrupts enabled, as firmware leaves ports, their
/// extended list passes: none of those controls is checked here. Ports are no
/// stopped requesters: the type 1 header is refused before any capability.
#[test]
fn real_port_capability_lists_pass_and_ports_stay_on_their_own_path() {
    let mut root = listed(
        0x06_0400,
        1,
        &[
            (0x50, PM, 3),
            (0x58, PCIE, 2 | 4 << 4 | 1 << 8),
            (0xa0, MSI, 0),
            (0xc0, 0x0d, 0),
            (0xc8, 0x08, 0xa803),
        ],
        &[
            (0x100, 0x0b, 1),
            (0x150, 0x01, 2),
            (0x270, 0x19, 1),
            (0x2a0, 0x0d, 1),
            (0x370, 0x1e, 1),
            (0x380, 0x1d, 1),
            (0x400, 0x25, 1),
            (0x410, 0x26, 1),
            (0x440, 0x27, 1),
            (0x4c0, 0x1f, 1),
        ],
    );
    set_ignored_controls(
        &mut root,
        &[
            (0x104, 0x010 << 20 | 1),
            // Root Control: PME and system error interrupts enabled.
            (0x74, 0x0000_000f),
            // AER Root Error Command: all three reporting enables.
            (0x17c, 7),
            // DPC Control: trigger on ERR_FATAL, interrupt enabled.
            (0x384, 0x0009_0000),
            // ACS Control: source validation, request and completion redirect.
            (0x2a4, 0x001d_0000),
            // PTM Control: enabled, root select.
            (0x4c8, 3),
        ],
    );
    assert_eq!(extended(&*root.config()), Ok(()));
    assert_eq!(
        validate_stopped(&mut root),
        Err(ClaimError::UnsupportedHeader(1))
    );

    let mut switch = listed(
        0x06_0400,
        1,
        &[
            (0x40, PM, 3),
            (0x48, MSI, 0x80),
            (0x68, PCIE, 2 | 6 << 4 | 1 << 8),
            (0xa4, 0x0d, 0),
        ],
        &[
            (0x100, 0x01, 2),
            (0x140, 0x02, 1),
            (0x200, 0x0d, 1),
            (0x220, 0x19, 1),
            (0x250, 0x1d, 1),
            (0x300, 0x1e, 1),
            (0x310, 0x1f, 1),
            (0x320, 0x25, 1),
            (0x330, 0x26, 1),
            (0x360, 0x27, 1),
        ],
    );
    set_ignored_controls(&mut switch, &[(0x254, 0x0009_0000), (0x204, 0x001d_0000)]);
    assert_eq!(extended(&*switch.config()), Ok(()));
    assert_eq!(
        validate_stopped(&mut switch),
        Err(ClaimError::UnsupportedHeader(1))
    );
}

/// A conventional function's Advanced Features report Transactions Pending
/// as PCI Express Device Status does, and refuse the claim the same way.
#[test]
fn advanced_features_transactions_pending_refuse_a_stopped_claim() {
    let mut function = listed(0x04_0300, 0, &[(0x50, PM, 3), (0x60, AF, 6 | 3 << 8)], &[]);
    assert_eq!(validate_stopped(&mut function), Ok(()));
    function.config().write16(0x64, 1 << 8).unwrap();
    assert_eq!(
        validate_stopped(&mut function),
        Err(ClaimError::Active { offset: 0x64 })
    );
}

/// A CXL device DVSEC with Cache_Enable lets the function read host memory
/// over CXL.cache, which Bus Master does not gate; Mem_Enable and any other
/// DVSEC are ignored.
#[test]
fn cxl_cache_enable_refuses_and_other_dvsecs_are_ignored() {
    let cxl = |vendor: u32, id: u16, length: u32, control: u16| {
        let mut function = endpoint();
        ext(&mut function, 0x100, 0x01, 2, 0x200);
        ext(&mut function, 0x200, DVSEC, 1, 0);
        function
            .config()
            .write32(0x204, vendor | 1 << 16 | length << 20)
            .unwrap();
        function.config().write16(0x208, id).unwrap();
        function.config().write16(0x20c, control).unwrap();
        function
    };
    // Mem_Enable only, IO_Enable reads set.
    assert_eq!(validate_stopped(&mut cxl(0x1e98, 0, 0x38, 6)), Ok(()));
    assert_eq!(
        validate_stopped(&mut cxl(0x1e98, 0, 0x38, 7)),
        Err(ClaimError::Active { offset: 0x20c })
    );
    // A CXL DVSEC of another ID, and another vendor's DVSEC 0.
    assert_eq!(validate_stopped(&mut cxl(0x1e98, 3, 0x38, 7)), Ok(()));
    assert_eq!(validate_stopped(&mut cxl(0x10de, 0, 0x38, 7)), Ok(()));
    // Too short to hold DVSEC CXL Control.
    assert_eq!(
        validate_stopped(&mut cxl(0x1e98, 0, 0x0c, 0)),
        Err(ClaimError::MalformedCapability { offset: 0x200 })
    );
}

#[test]
fn pcie_pending_transactions_refuse_a_stopped_claim_and_bounded_wait() {
    let mut function = endpoint();
    cap(&mut function, 0x40, PCIE, 0);
    function.config().write16(0x42, 2).unwrap();
    function.config().write16(0x4a, 1 << 5).unwrap();
    let mut checks = 0;
    assert_eq!(
        wait_for_pending_transactions(&*function.config(), || {
            checks += 1;
            checks >= 4
        }),
        Err(ClaimError::Active { offset: 0x4a })
    );
    assert_eq!(
        validate_stopped(&mut function),
        Err(ClaimError::Active { offset: 0x4a })
    );
    function.config().write16(0x4a, u16::MAX).unwrap();
    assert_eq!(
        wait_for_pending_transactions(&*function.config(), || true),
        Err(ClaimError::ReadFailed { offset: 0x4a })
    );
    function.config().write16(0x4a, 0).unwrap();
    assert_eq!(validate_stopped(&mut function), Ok(()));
    assert_eq!(
        wait_for_pending_transactions(&*function.config(), || panic!("idle status needs no wait")),
        Ok(())
    );
}

#[test]
fn pcie_pending_wait_observes_completion_before_admitting_the_requester() {
    struct Completing {
        config: Config,
        pending: Cell<u8>,
    }
    impl ConfigSpace for Completing {
        fn read32(&self, offset: u16) -> Result<u32, crate::bus::pci::ConfigError> {
            Ok({
                let word = self.config.read32(offset)?;
                if offset != 0x48 {
                    return Ok(word);
                }
                let pending = self.pending.get();
                self.pending.set(pending.saturating_sub(1));
                if pending != 0 {
                    word | (1 << 21)
                } else {
                    word & !(1 << 21)
                }
            })
        }
        fn write32(&mut self, offset: u16, value: u32) -> Result<(), crate::bus::pci::ConfigError> {
            self.config.write32(offset, value)?;
            Ok(())
        }

        fn read8(&self, offset: u16) -> Result<u8, crate::bus::pci::ConfigError> {
            Ok((self.read32(offset & !3)? >> ((offset & 3) * 8)) as u8)
        }

        fn write8(&mut self, offset: u16, value: u8) -> Result<(), crate::bus::pci::ConfigError> {
            let shift = (offset & 3) * 8;
            let word = self.read32(offset & !3)? & !(0xff << shift) | u32::from(value) << shift;
            self.write32(offset & !3, word)
        }

        fn read16(&self, offset: u16) -> Result<u16, crate::bus::pci::ConfigError> {
            Ok((self.read32(offset & !3)? >> ((offset & 2) * 8)) as u16)
        }

        fn write16(&mut self, offset: u16, value: u16) -> Result<(), crate::bus::pci::ConfigError> {
            let shift = (offset & 2) * 8;
            let word = self.read32(offset & !3)? & !(0xffff << shift) | u32::from(value) << shift;
            self.write32(offset & !3, word)
        }
    }
    let mut function = endpoint();
    cap(&mut function, 0x40, PCIE, 0);
    function.config().write16(0x42, 2).unwrap();
    let mut function = Function::new(
        ADDRESS,
        Completing {
            config: function.into_config(),
            pending: Cell::new(2),
        },
    )
    .unwrap();
    let mut checks = 0;
    assert_eq!(
        wait_for_pending_transactions(&*function.config(), || {
            checks += 1;
            checks >= 4
        }),
        Ok(())
    );
    assert_eq!(validate_stopped(&mut function), Ok(()));
}

fn containment_plan(config: &Config) -> Result<containment::Plan, ClaimError> {
    containment_plan_on(config, true)
}

/// The census of a function on a root bus, or behind a bridge.
fn containment_plan_on(config: &Config, root_bus: bool) -> Result<containment::Plan, ClaimError> {
    containment::Plan::read(
        |offset, width| {
            Ok(match width {
                1 => u32::from(config.read8(offset)?),
                2 => u32::from(config.read16(offset)?),
                4 => config.read32(offset)?,
                _ => panic!("unexpected PCI read width"),
            })
        },
        root_bus,
    )
}

/// Root, switch and other PCI Express ports pass requester IDs on. A
/// PCI Express to PCI bridge forwards under its secondary bus with device
/// and function 0; a PCI to PCI Express bridge and a bridge with no PCI
/// Express capability forward under their own ID.
#[test]
fn containment_plan_tells_under_which_id_a_bridge_forwards() {
    let mut conventional = endpoint();
    let plan = containment_plan(conventional.config()).unwrap();
    assert_eq!(plan.forwarded_requester(0x0010, 5), Some(0x0010));
    for (port, forwarded) in [
        (0x4, None),
        (0x5, None),
        (0x6, None),
        (0x0, None),
        (0xb, None),
        (0x7, Some(0x0500)),
        (0x8, Some(0x0010)),
    ] {
        let mut function = endpoint();
        cap(&mut function, 0x40, PCIE, 0);
        function.config().write16(0x42, 2 | port << 4).unwrap();
        let plan = containment_plan(function.config()).unwrap();
        assert_eq!(
            plan.forwarded_requester(0x0010, 5),
            forwarded,
            "port type {port:#x}"
        );
    }
}

/// A function's aliases are the IDs each forwarding bridge above it uses,
/// nearest first, without its own ID or repeats.
#[test]
fn requester_aliases_list_each_forwarded_id_once() {
    use containment::requester_aliases;
    assert!(requester_aliases(0x0628, []).is_empty());
    assert_eq!(requester_aliases(0x0628, [0x0600]), [0x0600]);
    // A device at the secondary bus's device 0 function 0 is its own alias.
    assert!(requester_aliases(0x0600, [0x0600]).is_empty());
    // A conventional bridge behind a PCI Express to PCI bridge: its own ID,
    // then the outer bridge's secondary bus ID.
    assert_eq!(
        requester_aliases(0x0708, [0x0620, 0x0600, 0x0600]),
        [0x0620, 0x0600]
    );
}

#[test]
fn containment_only_writes_the_exact_disabled_command_and_msi_controls() {
    use crate::bus::pci::ConfigEffect;

    let mut function = endpoint();
    cap(&mut function, 0x50, MSI, 0);
    let config = function.config();
    config.write16(regs::COMMAND, 7).unwrap();
    config.write16(0x52, 0x81).unwrap();
    let plan = containment_plan(config).unwrap();
    assert!(plan.permits(4, 2, 0x403));
    assert!(plan.permits(0x52, 2, 0x80));
    assert!(!plan.permits(4, 4, 0x403));
    assert!(!plan.permits(0x52, 2, 0x81));
    assert_eq!(
        plan.apply(config),
        Ok(ConfigEffect::WriteMayHaveApplied {
            offset: 0x52,
            width: 2
        })
    );
    assert_eq!(config.read16(regs::COMMAND), Ok(0x403));
    assert_eq!(config.read16(regs::STATUS), Ok(regs::STATUS_CAP_LIST));
    assert_eq!(config.read16(0x52), Ok(0x80));
}

#[test]
fn containment_readback_refuses_msi_reenabled_after_the_stop() {
    use crate::bus::pci::{ConfigEffect, ConfigFailure};

    let mut function = endpoint();
    cap(&mut function, 0x50, MSI, 0);
    let config = function.config();
    config.write16(regs::COMMAND, 7).unwrap();
    config.write16(0x52, 0x81).unwrap();
    let plan = containment_plan(config).unwrap();
    plan.apply(config).unwrap();
    assert_eq!(plan.check_disabled(|offset| config.read16(offset)), Ok(()));

    config.write16(0x52, 0x81).unwrap();
    let failure = plan
        .check_disabled(|offset| config.read16(offset))
        .unwrap_err();
    assert_eq!(failure.effect, ConfigEffect::None);
    assert!(matches!(
        failure.reason,
        ConfigFailure::Readback {
            offset: 0x52,
            expected: 0x80,
            observed: 0x81,
            ..
        }
    ));
    assert_eq!(config.read16(0x52), Ok(0x81));
}

#[test]
fn containment_refuses_changed_control_before_the_first_write() {
    use crate::bus::pci::{ConfigEffect, ConfigFailure};

    let mut function = endpoint();
    cap(&mut function, 0x50, MSI, 0);
    let config = function.config();
    config.write16(regs::COMMAND, 7).unwrap();
    config.write16(0x52, 1).unwrap();
    let plan = containment_plan(config).unwrap();
    config.write16(0x52, 0x81).unwrap();
    let failure = plan.apply(config).unwrap_err();
    assert_eq!(failure.effect, ConfigEffect::None);
    assert!(matches!(
        failure.reason,
        ConfigFailure::Readback { offset: 0x52, .. }
    ));
    assert_eq!(config.read16(regs::COMMAND), Ok(7));
}

#[test]
fn containment_clears_an_endpoints_reset_bit_and_keeps_a_ports_bit_15() {
    // An endpoint's Device Control bit 15 is Initiate FLR: the stop writes
    // it 0, never back as read.
    for kind in [0x0, 0x1, 0x9] {
        let mut function = endpoint();
        cap(&mut function, 0x40, PCIE, 0);
        let config = function.config();
        config.write16(0x42, 2 | kind << 4).unwrap();
        config.write16(0x48, 1 << 15 | 1 << 11 | 1).unwrap();
        let plan = containment_plan(config).unwrap();
        assert!(plan.permits(0x48, 2, 1));
        plan.apply(config).unwrap();
        assert_eq!(config.read16(0x48), Ok(1));
    }
    // A PCI Express to PCI bridge's Bridge Configuration Retry Enable, and
    // the reserved bit of the other ports, are kept as found.
    for kind in [0x4, 0x5, 0x6, 0x7, 0x8, 0xa] {
        let mut function = endpoint();
        cap(&mut function, 0x40, PCIE, 0);
        let config = function.config();
        config.write16(0x42, 2 | kind << 4).unwrap();
        config.write16(0x48, 1 << 15 | 1 << 11).unwrap();
        let plan = containment_plan(config).unwrap();
        assert!(plan.permits(0x48, 2, 1 << 15));
        plan.apply(config).unwrap();
        assert_eq!(config.read16(0x48), Ok(1 << 15));
    }
}

#[test]
fn containment_refuses_to_replay_a_pri_reset_command() {
    use crate::bus::pci::{ConfigError, ConfigFailure};

    let mut function = endpoint();
    cap(&mut function, 0x40, PCIE, 0);
    function.config().write16(0x42, 2).unwrap();
    let refused = ClaimError::Config(ConfigError::before_effect(
        ConfigFailure::UnqualifiedControl,
    ));
    ext(&mut function, 0x100, PRI, 1, 0);
    function.config().write16(0x104, 2).unwrap();
    assert!(matches!(containment_plan(function.config()), Err(error) if error == refused));
}

#[test]
fn containment_accepts_a_hardwired_clear_command_without_an_interrupt_pin() {
    use crate::bus::pci::ConfigEffect;

    // A host bridge implements no COMMAND bit and no INTx pin.
    let mut function = endpoint();
    let config = function.config();
    config.write8(regs::INTERRUPT_PIN, 0).unwrap();
    config.write16(regs::COMMAND, 0).unwrap();
    config.command_fixed = u16::MAX;
    let plan = containment_plan(config).unwrap();
    assert!(plan.permits(4, 2, u32::from(regs::COMMAND_INTX_DISABLE)));
    assert_eq!(
        plan.apply(config),
        Ok(ConfigEffect::WriteMayHaveApplied {
            offset: regs::COMMAND,
            width: 2
        })
    );
    assert_eq!(config.read16(regs::COMMAND), Ok(0));
    assert_eq!(plan.check_disabled(|offset| config.read16(offset)), Ok(()));
}

/// A function as the host bridge census reads it: class 0600, no INTx pin,
/// `command` as firmware left it, and `fixed` COMMAND bits hard-wired.
fn host_bridge(command: u16, fixed: u16) -> Function<Config> {
    let mut function = endpoint();
    let config = function.config();
    config.write32(8, 0x0600_0000).unwrap();
    config.write8(regs::INTERRUPT_PIN, 0).unwrap();
    config.write16(regs::COMMAND, command).unwrap();
    config.command_fixed = fixed;
    function
}

/// The containment acknowledge path: census, stop, then seal.
fn contain(config: &mut Config, root_bus: bool) -> Result<(), crate::bus::pci::ConfigError> {
    let plan = containment_plan_on(config, root_bus).unwrap();
    plan.apply(config)?;
    plan.seal(config)
}

/// A Q35-like host bridge on the root bus whose Bus Master bit firmware
/// left set and software can clear: it is cleared and sealed as every
/// other function is.
#[test]
fn containment_clears_and_seals_a_writable_host_bridge_bus_master() {
    let mut function = host_bridge(0x0107, 0);
    let config = function.config();
    assert_eq!(contain(config, true), Ok(()));
    assert_eq!(config.read16(regs::COMMAND), Ok(0x0503));
    assert!(config.master_sealed);
    assert!(config.write16(regs::COMMAND, 0x0507).is_err());
}

/// An Intel host bridge on the root bus: COMMAND reads 0x0006 with Bus
/// Master and Memory Space hard-wired set. The clear does not hold, the
/// seal proves the bit hard-wired and accepts it, and no write may set
/// it; any other control that changes is still refused.
#[test]
fn containment_seals_a_root_bus_host_bridge_whose_bus_master_is_hardwired() {
    let mut function = host_bridge(0x0006, u16::MAX);
    let config = function.config();
    config.command_writes.clear();
    let plan = containment_plan(config).unwrap();
    plan.apply(config).unwrap();
    assert_eq!(plan.seal(config), Ok(()));
    assert_eq!(config.read16(regs::COMMAND), Ok(0x0006));
    assert!(config.master_sealed);
    assert!(plan.master_stopped(0x0006));
    // The stop and the proof write only the stopped value, the one write
    // the containment owner permits.
    assert_eq!(config.command_writes, [0x0402, 0x0402]);
    assert!(plan.permits(regs::COMMAND, 2, 0x0402));
    assert!(config.write16(regs::COMMAND, 0x0006).is_err());
    // A hard-wired Memory Space bit that later reads clear is refused.
    config.command_fixed = 0;
    config.master_sealed = false;
    config.write16(regs::COMMAND, 0x0004).unwrap();
    assert!(plan.check_disabled(|offset| config.read16(offset)).is_err());
}

/// A class-0600 function behind a downstream port, and any other function,
/// whose Bus Master bit stays set is refused.
#[test]
fn containment_refuses_a_hardwired_bus_master_off_the_root_bus() {
    let mut function = host_bridge(0x0006, u16::MAX);
    let config = function.config();
    assert!(contain(config, false).is_err());
    assert!(!config.master_sealed);
    let mut function = host_bridge(0x0006, u16::MAX);
    let config = function.config();
    config.command_fixed = 0;
    config.write32(8, 0x0604_0000).unwrap();
    config.command_fixed = u16::MAX;
    assert!(contain(config, true).is_err());
    assert!(!config.master_sealed);
    // A root-bus host bridge whose bit read clear at the census may not
    // read set at the seal.
    let mut function = host_bridge(0x0002, 0);
    let config = function.config();
    let plan = containment_plan(config).unwrap();
    plan.apply(config).unwrap();
    config.write16(regs::COMMAND, 0x0406).unwrap();
    assert!(plan.seal(config).is_err());
    assert!(!config.master_sealed);
}

/// An ISA/LPC bridge on the root bus, class 0601 with no INTx pin, as the
/// chipsets report it. Intel's PCH reads 0x0007 and implements no INTx
/// Disable; AMD's FCH reads 0x040f. Both hold Bus Master set: the seal
/// proves it and accepts it. Behind a downstream port the same function
/// is refused, and one whose bit clears is sealed as clear.
#[test]
fn containment_seals_a_root_bus_isa_bridge_whose_bus_master_is_hardwired() {
    fn isa_bridge(command: u16, fixed: u16) -> Function<Config> {
        let mut function = host_bridge(0, 0);
        let config = function.config();
        config.write32(8, 0x0601_0000).unwrap();
        config.write16(regs::COMMAND, command).unwrap();
        config.command_fixed = fixed;
        function
    }
    for (found, stopped) in [(0x0007, 0x0403), (0x040f, 0x040b)] {
        let mut function = isa_bridge(found, u16::MAX);
        let config = function.config();
        config.command_writes.clear();
        assert_eq!(contain(config, true), Ok(()));
        assert_eq!(config.read16(regs::COMMAND), Ok(found));
        assert!(config.master_sealed);
        assert_eq!(config.command_writes, [stopped, stopped]);
        assert!(config.write16(regs::COMMAND, found).is_err());

        let mut function = isa_bridge(found, u16::MAX);
        let config = function.config();
        assert!(contain(config, false).is_err());
        assert!(!config.master_sealed);
    }
    let mut function = isa_bridge(0x0007, 0);
    let config = function.config();
    assert_eq!(contain(config, true), Ok(()));
    assert_eq!(config.read16(regs::COMMAND), Ok(0x0403));
    assert!(config.master_sealed);
}

#[test]
fn containment_sets_intx_disable_where_writable_even_without_a_pin() {
    let mut function = endpoint();
    let config = function.config();
    config.write8(regs::INTERRUPT_PIN, 0).unwrap();
    config.write16(regs::COMMAND, 6).unwrap();
    let plan = containment_plan(config).unwrap();
    plan.apply(config).unwrap();
    assert_eq!(config.read16(regs::COMMAND), Ok(0x402));
    assert_eq!(plan.check_disabled(|offset| config.read16(offset)), Ok(()));
}

#[test]
fn containment_stops_a_normal_endpoint_with_an_interrupt_pin() {
    let mut function = endpoint();
    let config = function.config();
    config.write16(regs::COMMAND, 6).unwrap();
    let plan = containment_plan(config).unwrap();
    plan.apply(config).unwrap();
    assert_eq!(config.read16(regs::COMMAND), Ok(0x402));
    assert_eq!(plan.check_disabled(|offset| config.read16(offset)), Ok(()));
    // A later clear of INTx Disable on a function with a pin is refused.
    config.write16(regs::COMMAND, 2).unwrap();
    assert!(plan.check_disabled(|offset| config.read16(offset)).is_err());
}

#[test]
fn containment_refuses_an_interrupt_pin_that_ignores_intx_disable() {
    use crate::bus::pci::{ConfigEffect, ConfigFailure};

    let mut function = endpoint();
    let config = function.config();
    config.write16(regs::COMMAND, 2).unwrap();
    config.command_fixed = regs::COMMAND_INTX_DISABLE;
    let plan = containment_plan(config).unwrap();
    let failure = plan.apply(config).unwrap_err();
    assert_eq!(
        failure.effect,
        ConfigEffect::WriteMayHaveApplied {
            offset: regs::COMMAND,
            width: 2
        }
    );
    assert_eq!(
        failure.reason,
        ConfigFailure::Readback {
            offset: regs::COMMAND,
            width: 2,
            expected: 0x402,
            observed: 2,
        }
    );
    // Its Bus Master bit cleared: refused alone, it masters nothing.
    assert!(plan.master_stopped(config.read16(regs::COMMAND).unwrap()));
}

#[test]
fn containment_refuses_bus_master_that_stays_set_without_a_pin() {
    use crate::bus::pci::ConfigFailure;

    let mut function = endpoint();
    let config = function.config();
    config.write8(regs::INTERRUPT_PIN, 0).unwrap();
    config.write16(regs::COMMAND, 4).unwrap();
    config.command_fixed = regs::COMMAND_MASTER;
    let plan = containment_plan(config).unwrap();
    let failure = plan.apply(config).unwrap_err();
    assert!(matches!(
        failure.reason,
        ConfigFailure::Readback {
            offset: regs::COMMAND,
            observed: 0x404,
            ..
        }
    ));
    // It may still master DMA, which its refusal alone does not stop.
    assert!(!plan.master_stopped(config.read16(regs::COMMAND).unwrap()));
}

#[test]
fn containment_plan_refuses_when_the_interrupt_pin_cannot_be_read() {
    let mut function = endpoint();
    let config = function.config();
    let refused = ClaimError::ReadFailed {
        offset: regs::INTERRUPT_PIN,
    };
    let result = containment::Plan::read(
        |offset, width| {
            if offset == regs::INTERRUPT_PIN {
                return Err(refused);
            }
            Ok(match width {
                1 => u32::from(config.read8(offset).unwrap()),
                2 => u32::from(config.read16(offset).unwrap()),
                _ => config.read32(offset).unwrap(),
            })
        },
        true,
    );
    assert!(matches!(result, Err(error) if error == refused));
}

/// Linux `__pci_find_next_cap_ttl` and `pci_find_next_ext_capability`: a
/// masked pointer, a vendor body that cannot be sized, a loop and an
/// extended vendor entry with no length leave the census planning every
/// control it reaches, with no refusal.
#[test]
fn containment_walks_an_odd_list_as_linux_does() {
    let mut function = endpoint();
    let config = function.config();
    config.write16(regs::STATUS, regs::STATUS_CAP_LIST).unwrap();
    config.write16(regs::COMMAND, 7).unwrap();
    config.write8(0x34, 0x43).unwrap();
    config.write16(0x40, 0x09 | 0x52 << 8).unwrap();
    config.write8(0x42, 0xf0).unwrap(); // a body past the list's end
    config.write16(0x50, MSI | 0x60 << 8).unwrap();
    config.write16(0x52, 0x81).unwrap();
    config.write16(0x60, PCIE | 0x40 << 8).unwrap(); // back to the start
    config.write16(0x62, 2).unwrap();
    config.write32(0x100, 0x0b | 1 << 16 | 0x202 << 20).unwrap();
    config.write32(0x200, u32::from(ATS) | 1 << 16).unwrap();
    config.write16(0x206, 1 << 15).unwrap();
    let plan = containment_plan(config).unwrap();
    assert_eq!(plan.refusal(), None);
    assert!(plan.permits(4, 2, 0x403));
    assert!(plan.permits(0x52, 2, 0x80));
    assert!(plan.permits(0x206, 2, 0));
}

/// A control the census cannot stop exactly is left as found: the plan
/// still clears Bus Master, which gates the function's MSI-X messages, and
/// names the refusal that keeps that one function from a driver.
#[test]
fn containment_leaves_an_unsizable_control_and_refuses_the_function_alone() {
    let mut function = endpoint();
    let config = function.config();
    config.write16(regs::STATUS, regs::STATUS_CAP_LIST).unwrap();
    config.write16(regs::COMMAND, 7).unwrap();
    config.write8(0x34, 0x50).unwrap();
    config.write16(0x50, MSI | 0xf8 << 8).unwrap();
    config.write16(0x52, 0x81).unwrap();
    config.write16(0xf8, MSIX).unwrap(); // a body past the list's end
    config.write16(0xfa, 1 << 15).unwrap();
    let plan = containment_plan(config).unwrap();
    assert_eq!(
        plan.refusal(),
        Some(ClaimError::UnsupportedCapability {
            id: MSIX,
            extended: false
        })
    );
    assert!(plan.permits(4, 2, 0x403));
    assert!(plan.permits(0x52, 2, 0x80));
    assert!(!plan.permits(0xfa, 2, 0));
    plan.apply(config).unwrap();
    assert_eq!(config.read16(regs::COMMAND), Ok(0x403));
    assert_eq!(config.read16(0xfa), Ok(1 << 15));

    // A second MSI capability is left as well.
    config.write16(0x50, MSI | 0x60 << 8).unwrap();
    config.write16(0x60, MSI).unwrap();
    let plan = containment_plan(config).unwrap();
    assert_eq!(
        plan.refusal(),
        Some(ClaimError::MalformedCapability { offset: 0x60 })
    );
}

/// A Bus Master bit hardware holds set gates nothing, so a control the
/// census cannot stop there still refuses the census.
#[test]
fn containment_refuses_an_unsizable_control_beside_a_hardwired_bus_master() {
    let mut function = host_bridge(regs::COMMAND_MASTER, regs::COMMAND_MASTER);
    let config = function.config();
    config.write16(regs::STATUS, regs::STATUS_CAP_LIST).unwrap();
    config.write8(0x34, 0xf8).unwrap();
    config.write16(0xf8, MSIX).unwrap();
    assert!(matches!(
        containment_plan_on(config, true),
        Err(ClaimError::UnsupportedCapability {
            id: MSIX,
            extended: false
        })
    ));
    assert!(
        containment_plan_on(config, false)
            .unwrap()
            .refusal()
            .is_some()
    );
}
