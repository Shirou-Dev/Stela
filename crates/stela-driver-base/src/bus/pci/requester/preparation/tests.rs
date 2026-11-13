//! Cold original-root receipts and unique attachment retirement controls.
extern crate std;
use super::*;
use crate::bus::{
    dma::{
        mapping::{Direction, DomainMapping},
        pages::DmaPages,
    },
    pci::{
        ConfigFailure,
        owned::test_support::{fixture, fixture_pointer},
        regs,
    },
};
use alloc::vec::Vec;
use core::{
    ops::Range,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use std::sync::Mutex;

const ADDRESS: Address = Address {
    segment: 0,
    bus: 1,
    device: 0,
    function: 0,
};
#[derive(Default)]
struct State {
    events: Mutex<Vec<&'static str>>,
    drops: AtomicUsize,
    panic_drain: AtomicBool,
    detach_error: AtomicBool,
    detachments: AtomicUsize,
    action_delivery: AtomicBool,
    action_epoch: AtomicU64,
    action_entries: Mutex<Vec<irq_actions::Entry>>,
    action_records: Mutex<Vec<u8>>,
    action_pins_released: AtomicUsize,
}
struct RootOwner(Arc<State>);
impl Drop for RootOwner {
    fn drop(&mut self) {
        self.0.drops.fetch_add(1, Ordering::Relaxed);
    }
}
struct OldRoot {
    owner: Arc<RootOwner>,
    drain_error: bool,
    bind_error: bool,
    bind_drift: Option<NonNull<u16>>,
}
struct Domain {
    binding: Mutex<Option<RequesterBinding>>,
    _owner: Arc<RootOwner>,
}
// SAFETY: these roots are isolated synchronous RAM fixtures; no real DMA,
// IRQ or firmware accessor exists. Events model independent old-root and
// new-domain completion; binding retains the original configuration epoch.
unsafe impl Root for OldRoot {
    fn drain(&self) -> Result<(), DmaError> {
        self.owner
            .0
            .events
            .lock()
            .unwrap()
            .push("old root completion");
        assert!(
            !self.owner.0.panic_drain.load(Ordering::Relaxed),
            "injected root drain unwind"
        );
        if self.drain_error {
            Err(DmaError::InvalidationFailed)
        } else {
            Ok(())
        }
    }
    unsafe fn bind(
        &self,
        binding: RequesterBinding,
    ) -> Result<Box<dyn crate::bus::pci::requester::preparation::AttachmentBackend>, DmaError> {
        assert_eq!(binding.address(), ADDRESS);
        binding.check_live().unwrap();
        self.owner
            .0
            .events
            .lock()
            .unwrap()
            .push("new domain attachment");
        if self.bind_error {
            return Err(DmaError::MappingFailed);
        }
        if let Some(command) = self.bind_drift {
            // SAFETY: the original model holds the exact isolated RAM
            // register. Simulate a hardware change during binding.
            unsafe {
                command
                    .as_ptr()
                    .write_volatile(regs::COMMAND_MASTER | regs::COMMAND_INTX_DISABLE);
            }
        }
        Ok(Box::new(Control {
            domain: Arc::new(Domain {
                binding: Mutex::new(Some(binding)),
                _owner: self.owner.clone(),
            }),
            detached: false,
        }))
    }
}
struct Control {
    domain: Arc<Domain>,
    detached: bool,
}
impl Drop for Control {
    fn drop(&mut self) {
        if !self.detached {
            core::mem::forget(self.domain.clone());
        }
    }
}
// SAFETY: this synchronous fixture has no hardware or active mappings.
// Its unique control retains the original binding on failure and makes
// every old domain reference stale before releasing configuration pins.
unsafe impl crate::bus::pci::requester::preparation::AttachmentBackend for Control {
    fn domain(&self) -> Arc<dyn DmaDomain> {
        self.domain.clone()
    }
    fn irq_owner(
        &mut self,
        _requester: &crate::bus::pci::requester::RequesterId,
        _config: Option<&crate::bus::pci::owned::ConfigRetention>,
    ) -> Result<Option<Box<dyn crate::bus::irq::posted_msi::RouteOwner>>, DmaError> {
        if !self.domain._owner.0.action_delivery.load(Ordering::Acquire) {
            return Ok(None);
        }
        irq_actions::owner(self.domain.clone()).map(Some)
    }
    unsafe fn detach(
        &mut self,
    ) -> Result<(), crate::bus::pci::requester::preparation::DetachError> {
        if self.detached {
            return Err(
                crate::bus::pci::requester::preparation::DetachError::Uncertain(DmaError::Unmapped),
            );
        }
        if self.domain._owner.0.detach_error.load(Ordering::Relaxed) {
            return Err(
                crate::bus::pci::requester::preparation::DetachError::Uncertain(
                    DmaError::InvalidationFailed,
                ),
            );
        }
        self.domain.binding.lock().unwrap().take();
        self.domain
            ._owner
            .0
            .detachments
            .fetch_add(1, Ordering::Relaxed);
        self.detached = true;
        Ok(())
    }
}
// SAFETY: this fixture maps nothing; it retains its configuration/root owners.
unsafe impl DmaDomain for Domain {
    unsafe fn map(&self, _: &DmaPages, _: Direction, _: u64) -> Result<DomainMapping, DmaError> {
        if self.binding.lock().unwrap().is_none() {
            Err(DmaError::Unmapped)
        } else {
            Err(DmaError::MappingFailed)
        }
    }
    unsafe fn unmap(&self, _: DomainMapping) -> Result<(), DmaError> {
        Err(DmaError::Unmapped)
    }
    unsafe fn sync_for_device(
        &self,
        _: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        Err(DmaError::Unmapped)
    }
    unsafe fn sync_for_cpu(
        &self,
        _: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        Err(DmaError::Unmapped)
    }
}
fn function(address: Address) -> Function<OwnedConfig> {
    let (mut config, _) = fixture(address);
    config.write32(0, 0x12348086).unwrap();
    config
        .write16(regs::COMMAND, regs::COMMAND_INTX_DISABLE)
        .unwrap();
    config.write32(8, 0x02800000).unwrap();
    config.write32(0x0c, 0).unwrap();
    config.write32(0x100, 0).unwrap();
    Function::new(address, config).unwrap()
}
fn preparing(drain_error: bool, bind_error: bool) -> (PreparingRequester, Arc<State>) {
    preparing_with_drift(drain_error, bind_error, false)
}
fn preparing_with_drift(
    drain_error: bool,
    bind_error: bool,
    drift: bool,
) -> (PreparingRequester, Arc<State>) {
    let state = Arc::new(State::default());
    let mut function = function(ADDRESS);
    let bind_drift = drift.then(|| fixture_pointer(function.config(), regs::COMMAND).cast());
    let root = Box::new(OldRoot {
        owner: Arc::new(RootOwner(state.clone())),
        drain_error,
        bind_error,
        bind_drift,
    });
    // SAFETY: exact isolated function/root, with no firmware/IRQ/work users;
    // the peer starts idle but this construction makes no engine-stop grant.
    let prepared = unsafe { PreparingRequester::new(function, FunctionRole::Physical, root) }
        .unwrap_or_else(|_| panic!("original fixture owners"));
    (prepared, state)
}
#[test]
fn old_root_completion_precedes_attachment_and_owners_follow_the_bound_domain() {
    let (mut prepared, state) = preparing(false, false);
    assert!(state.events.lock().unwrap().is_empty());
    let enabled = regs::COMMAND_INTX_DISABLE | regs::COMMAND_MASTER;
    assert_eq!(
        prepared
            .function_mut()
            .config()
            .write16(regs::COMMAND, enabled),
        Err(crate::bus::pci::ConfigError::before_effect(
            ConfigFailure::BusMasterSealed
        ))
    );
    // SAFETY: the synchronous fixture has no DMA engines, submissions or IRQ/work.
    let receipt = unsafe { prepared.acknowledge_quiescence() };
    assert!(state.events.lock().unwrap().is_empty());
    let mut bound = receipt
        .finalize()
        .unwrap_or_else(|f| panic!("{:?}", f.error));
    assert_eq!(
        *state.events.lock().unwrap(),
        ["old root completion", "new domain attachment"]
    );
    assert_eq!(state.drops.load(Ordering::Relaxed), 0);
    let old_domain = bound.attachment.domain();
    let (error, requester) = bound.requester.into_dma_binding().err().unwrap();
    assert_eq!(error, ClaimError::AlreadyBound);
    let mut config = requester.into_function().into_config();
    assert_eq!(config.read16(regs::COMMAND), Ok(regs::COMMAND_INTX_DISABLE));
    config.write16(regs::COMMAND, enabled).unwrap();
    config
        .write16(regs::COMMAND, regs::COMMAND_INTX_DISABLE)
        .unwrap();
    // SAFETY: isolated idle fixture; the retained binding must refuse reuse.
    assert_eq!(unsafe { config.retire() }, Err(MappingError::Busy));
    // SAFETY: no modeled DMA/IRQ/work user exists, and all original owners stay kept.
    unsafe { bound.attachment.detach() }.unwrap();
    // SAFETY: exact fixture detach acknowledged before mapping retirement.
    unsafe { crate::bus::pci::owned::test_support::retire_owned(config) }.unwrap();
    assert_eq!(state.detachments.load(Ordering::Relaxed), 1);
    drop(bound.attachment);
    assert_eq!(state.drops.load(Ordering::Relaxed), 0);
    drop(old_domain);
    assert_eq!(state.drops.load(Ordering::Relaxed), 1);
}
#[test]
fn foreign_configuration_is_rejected_before_any_root_operation() {
    for other in [
        Address {
            function: 1,
            ..ADDRESS
        },
        ADDRESS,
    ] {
        let (mut prepared, state) = preparing(false, false);
        let old = core::mem::replace(prepared.function_mut(), function(other));
        // SAFETY: both isolated fixture functions have no active DMA/IRQ/work.
        let receipt = unsafe { prepared.acknowledge_quiescence() };
        let failure = receipt.finalize().err().expect("foreign owner refused");
        assert_eq!(failure.error, Error::ForeignOwner);
        assert!(state.events.lock().unwrap().is_empty());
        drop(failure);
        drop(old);
        assert_eq!(
            state.drops.load(Ordering::Relaxed),
            0,
            "unknown owner graph remains kept"
        );
    }
}
#[test]
fn failed_old_root_or_binding_keeps_the_preparation_graph() {
    for (drain, bind, error, events) in [
        (true, false, DmaError::InvalidationFailed, 1),
        (false, true, DmaError::MappingFailed, 2),
    ] {
        let (prepared, state) = preparing(drain, bind);
        // SAFETY: synchronous idle fixture; no submissions or callbacks exist.
        let receipt = unsafe { prepared.acknowledge_quiescence() };
        let failure = receipt
            .finalize()
            .err()
            .expect("injected completion failure");
        assert_eq!(failure.error, Error::Dma(error));
        assert_eq!(state.events.lock().unwrap().len(), events);
        drop(failure);
        assert_eq!(state.drops.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn an_unmastered_function_keeps_its_seal_and_never_touches_the_root() {
    let (prepared, state) = preparing(false, false);
    let mut function = prepared.into_unmastered();
    let config = function.config();
    assert_eq!(
        config.write16(
            regs::COMMAND,
            regs::COMMAND_MASTER | regs::COMMAND_MEMORY | regs::COMMAND_INTX_DISABLE
        ),
        Err(crate::bus::pci::ConfigError::before_effect(
            ConfigFailure::BusMasterSealed
        ))
    );
    // Decode and interrupt controls stay the driver's.
    let decoding = regs::COMMAND_MEMORY | regs::COMMAND_INTX_DISABLE;
    config.write16(regs::COMMAND, decoding).unwrap();
    assert_eq!(config.read16(regs::COMMAND), Ok(decoding));
    // It is a stopped requester in every observation.
    // SAFETY: the isolated fixture has no engine, and its seal stays set.
    let requester = unsafe { StoppedRequester::from_stopped_pci(function, FunctionRole::Physical) }
        .unwrap_or_else(|(error, _)| panic!("{error:?}"));
    let mut config = requester.into_function().into_config();
    // SAFETY: isolated idle fixture; the kept retention must refuse retirement.
    assert_eq!(unsafe { config.retire() }, Err(MappingError::Busy));
    assert!(state.events.lock().unwrap().is_empty());
    assert_eq!(state.drops.load(Ordering::Relaxed), 0);
}
#[test]
fn abandoning_preparation_does_not_release_an_unstopped_owner() {
    let (prepared, state) = preparing(false, false);
    drop(prepared);
    assert!(state.events.lock().unwrap().is_empty());
    assert_eq!(state.drops.load(Ordering::Relaxed), 0);
}
#[test]
fn configuration_activity_is_rechecked_after_old_root_completion() {
    let (mut prepared, state) = preparing(false, false);
    let command = fixture_pointer(prepared.function_mut().config(), regs::COMMAND);
    // SAFETY: this isolated model is the sole owner of the original register
    // bytes. Model hardware drift without giving the software a writer.
    unsafe {
        command
            .cast::<u16>()
            .as_ptr()
            .write_volatile(regs::COMMAND_MASTER | regs::COMMAND_INTX_DISABLE);
    }
    // SAFETY: no modeled engine/submission/IRQ/work exists; the deliberately
    // enabled configuration bit must independently fail stopped validation.
    let receipt = unsafe { prepared.acknowledge_quiescence() };
    let failure = receipt.finalize().err().expect("bus mastering refused");
    assert_eq!(
        failure.error,
        Error::Claim(ClaimError::Active {
            offset: regs::COMMAND
        })
    );
    assert_eq!(*state.events.lock().unwrap(), ["old root completion"]);
}

#[test]
fn new_binding_does_not_release_the_seal_after_hardware_drift() {
    let (prepared, state) = preparing_with_drift(false, false, true);
    // SAFETY: the original fixture has no active device or callback; the
    // modeled register changes only during the later bind operation.
    let receipt = unsafe { prepared.acknowledge_quiescence() };
    let mut failure = receipt.finalize().err().expect("drift refused");
    assert_eq!(
        failure.error,
        Error::Claim(ClaimError::Active {
            offset: regs::COMMAND,
        })
    );
    assert_eq!(
        *state.events.lock().unwrap(),
        ["old root completion", "new domain attachment"]
    );
    let config = failure._owner.resources().function.config();
    assert_eq!(
        config.write16(
            regs::COMMAND,
            regs::COMMAND_INTX_DISABLE | regs::COMMAND_MASTER,
        ),
        Err(crate::bus::pci::ConfigError::before_effect(
            ConfigFailure::BusMasterSealed,
        ))
    );
    drop(failure);
    assert_eq!(state.drops.load(Ordering::Relaxed), 0);
}

#[test]
fn root_callback_unwind_keeps_the_whole_preparation_graph() {
    let (prepared, state) = preparing(false, false);
    state.panic_drain.store(true, Ordering::Relaxed);
    // SAFETY: isolated fixture with no DMA, IRQ/work or firmware producers.
    let receipt = unsafe { prepared.acknowledge_quiescence() };
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| receipt.finalize())).is_err());
    assert_eq!(*state.events.lock().unwrap(), ["old root completion"]);
    assert_eq!(state.drops.load(Ordering::Relaxed), 0);
}
#[test]
fn failed_or_abandoned_detach_keeps_the_binding_and_original_root() {
    for fail in [false, true] {
        let (prepared, state) = preparing(false, false);
        // SAFETY: isolated synchronous idle endpoint, without IRQ/work producers.
        let mut bound = unsafe { prepared.acknowledge_quiescence() }
            .finalize()
            .unwrap_or_else(|failure| panic!("{:?}", failure.error));
        if fail {
            state.detach_error.store(true, Ordering::Relaxed);
            // SAFETY: same stopped fixture; inject failure before any binding release.
            let detached = unsafe { bound.attachment.detach() };
            assert!(matches!(detached, Err(DmaError::InvalidationFailed)));
        }
        let mut config = bound.requester.into_function().into_config();
        drop(bound.attachment);
        // SAFETY: synchronous idle fixture; its live binding still prohibits retirement.
        assert_eq!(unsafe { config.retire() }, Err(MappingError::Busy));
        assert_eq!(state.drops.load(Ordering::Relaxed), 0);
        assert_eq!(state.detachments.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn issuing_an_unused_grant_can_cancel_but_abandonment_cannot_fake_no_route() {
    for abandon in [false, true] {
        let (prepared, state) = preparing(false, false);
        // SAFETY: exact original synchronous idle config/root peer.
        let mut bound = unsafe { prepared.acknowledge_quiescence() }
            .finalize()
            .unwrap_or_else(|e| panic!("{:?}", e.error));
        let grant = bound.attachment.irq_route().unwrap();
        assert!(grant.is_unavailable());
        assert!(grant.belongs_to(bound.attachment.requester()));
        // Merely issued ownership is not publication. Explicit checked return
        // permits detach; abandoning the grant cannot fabricate the return.
        if abandon {
            drop(grant);
        } else {
            bound
                .attachment
                .cancel_unpublished_irq(grant)
                .unwrap_or_else(|_| panic!("original unused grant"));
        }
        // SAFETY: exact idle fixture and no real IRQ programmer exists.
        let result = unsafe { bound.attachment.detach() };
        if abandon {
            assert!(matches!(result, Err(DmaError::DrainUnavailable)));
            assert_eq!(state.detachments.load(Ordering::Relaxed), 0);
        } else {
            assert!(result.is_ok());
            assert_eq!(state.detachments.load(Ordering::Relaxed), 1);
        }
    }
}

mod irq_actions;
