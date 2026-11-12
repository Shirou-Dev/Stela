// SPDX-License-Identifier: GPL-2.0-only
//! Original root, configuration and BAR retention through cold finalization.
use super::*;
use crate::bus::{
    dma::{
        mapping::{Direction, DmaDomain, DmaError, DomainMapping},
        pages::DmaPages,
    },
    pci::{
        owned::test_support::fixture,
        requester::{
            FunctionRole, RequesterBinding,
            preparation::{self, Root},
        },
    },
};
use alloc::vec;
use core::{ops::Range, sync::atomic::AtomicBool};

#[derive(Default)]
struct State {
    events: Mutex<Vec<&'static str>>,
    root_drops: AtomicUsize,
    fail_drain: AtomicBool,
    fail_bind: AtomicBool,
}
struct OldRoot(Arc<State>);
impl Drop for OldRoot {
    fn drop(&mut self) {
        self.0.root_drops.fetch_add(1, Ordering::Relaxed);
    }
}
struct Domain {
    binding: Mutex<Option<RequesterBinding>>,
    _root: Arc<State>,
}
// SAFETY: a synchronous symbolic root with no hardware effects. Its binding
// retains the original configuration; failures publish no new translation.
unsafe impl Root for OldRoot {
    fn drain(&self) -> Result<(), DmaError> {
        self.0.events.lock().unwrap().push("original drain");
        if self.0.fail_drain.load(Ordering::Relaxed) {
            Err(DmaError::InvalidationFailed)
        } else {
            Ok(())
        }
    }
    unsafe fn bind(
        &self,
        binding: RequesterBinding,
    ) -> Result<Box<dyn crate::bus::pci::requester::preparation::AttachmentBackend>, DmaError> {
        binding.check_live().unwrap();
        self.0.events.lock().unwrap().push("private bind");
        if self.0.fail_bind.load(Ordering::Relaxed) {
            return Err(DmaError::MappingFailed);
        }
        Ok(Box::new(Control(Arc::new(Domain {
            binding: Mutex::new(Some(binding)),
            _root: self.0.clone(),
        }))))
    }
}
struct Control(Arc<Domain>);
impl Drop for Control {
    fn drop(&mut self) {
        if self.0.binding.lock().unwrap().is_some() {
            core::mem::forget(self.0.clone());
        }
    }
}
// SAFETY: no mapping can be created by this model; detach makes the shared
// binding absent before releasing its original configuration retention.
unsafe impl crate::bus::pci::requester::preparation::AttachmentBackend for Control {
    fn domain(&self) -> Arc<dyn DmaDomain> {
        self.0.clone()
    }
    unsafe fn detach(
        &mut self,
    ) -> Result<(), crate::bus::pci::requester::preparation::DetachError> {
        self.0
            .binding
            .lock()
            .unwrap()
            .take()
            .ok_or(DmaError::Unmapped)?;
        Ok(())
    }
}
// SAFETY: this isolated peer rejects every map/lease operation and exposes
// no device address. It is not a native DMA or physical-remapping provider.
unsafe impl DmaDomain for Domain {
    unsafe fn map(&self, _: &DmaPages, _: Direction, _: u64) -> Result<DomainMapping, DmaError> {
        Err(DmaError::MappingFailed)
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
fn preparing(state: Arc<State>) -> preparation::PreparingRequester {
    let address = Address {
        segment: 0,
        bus: 2,
        device: 3,
        function: 0,
    };
    let (mut config, _) = fixture(address);
    config.write32(0, 0x165f_14e4).unwrap();
    config.write32(4, 0x402).unwrap();
    config.write32(8, 0x0200_0000).unwrap();
    config.write32(0x0c, 0).unwrap();
    config.write32(0x100, 0).unwrap();
    let function = Function::new(address, config).unwrap();
    // SAFETY: the exclusive symbolic fixture has no native firmware/IRQ/work
    // users; its original root and configuration are paired in this attempt.
    unsafe {
        preparation::PreparingRequester::new(
            function,
            FunctionRole::Physical,
            Box::new(OldRoot(state)),
        )
    }
    .unwrap_or_else(|_| panic!("isolated cold configuration"))
}
fn cold(state: Arc<State>, counts: Arc<Counts>) -> Cold {
    let owner = windows(counts);
    let (mac, ape) = pointers(&owner.lock().unwrap());
    // SAFETY: this fixture holds exact host RAM windows and exclusive symbolic
    // configuration. All device engines are absent; no native permission exists.
    unsafe { Cold::from_owned_windows(preparing(state), mac, 0x8000, Some((ape, 0x8440)), owner) }
        .unwrap_or_else(|_| panic!("valid cold windows"))
}

#[test]
fn original_drain_precedes_bind_and_paired_windows_reach_bound_registers() {
    let state = Arc::new(State::default());
    let counts = Arc::new(Counts::default());
    let mut original = cold(state.clone(), counts.clone());
    original.write32(0x7ffc, 0x1357_2468).unwrap();
    original.ape_write32(0x843c, 0x1234_5678).unwrap();
    assert!(state.events.lock().unwrap().is_empty());
    // SAFETY: this synchronous fixture has no engines, DMA, IRQs or workers.
    let mut bound =
        unsafe { original.bind() }.unwrap_or_else(|failure| panic!("{:?}", failure.error));
    assert_eq!(
        *state.events.lock().unwrap(),
        ["original drain", "private bind"]
    );
    assert_eq!(bound.registers.config_read32(0), Ok(0x165f_14e4));
    assert_eq!(bound.registers.read32(0x7ffc), Ok(0x1357_2468));
    assert_eq!(bound.registers.ape_read32(0x843c), Ok(0x1234_5678));
    assert_eq!(counts.mapping_drops.load(Ordering::Relaxed), 0);
    // SAFETY: no modeled mapping or asynchronous user was ever admitted.
    unsafe { bound.attachment.detach() }.unwrap();
    drop(bound);
    assert_eq!(counts.mapping_drops.load(Ordering::Relaxed), 1);
}

#[test]
fn abandoned_cold_owner_retains_both_bars_and_original_root_without_drain() {
    let state = Arc::new(State::default());
    let counts = Arc::new(Counts::default());
    drop(cold(state.clone(), counts.clone()));
    assert!(state.events.lock().unwrap().is_empty());
    assert_eq!(state.root_drops.load(Ordering::Relaxed), 0);
    assert_eq!(counts.mapping_drops.load(Ordering::Relaxed), 0);
}

#[test]
fn failed_old_drain_or_private_bind_keeps_original_root_and_windows() {
    for bind_failure in [false, true] {
        let state = Arc::new(State::default());
        state.fail_drain.store(!bind_failure, Ordering::Relaxed);
        state.fail_bind.store(bind_failure, Ordering::Relaxed);
        let counts = Arc::new(Counts::default());
        let original = cold(state.clone(), counts.clone());
        // SAFETY: absent model engines and no asynchronous users; the root
        // itself must refuse the injected completion/attachment failure.
        let failure = unsafe { original.bind() }.err().expect("root failure");
        assert_eq!(
            failure.error,
            preparation::Error::Dma(if bind_failure {
                DmaError::MappingFailed
            } else {
                DmaError::InvalidationFailed
            })
        );
        drop(failure);
        let expected = if bind_failure {
            vec!["original drain", "private bind"]
        } else {
            vec!["original drain"]
        };
        assert_eq!(*state.events.lock().unwrap(), expected);
        assert_eq!(state.root_drops.load(Ordering::Relaxed), 0);
        assert_eq!(counts.mapping_drops.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn a_chip_without_an_ape_has_no_ape_window_to_reach() {
    let owner = windows(Arc::new(Counts::default()));
    let (mac, _) = pointers(&owner.lock().unwrap());
    // SAFETY: this fixture holds an exact host RAM window and exclusive
    // symbolic configuration. No device engine or native permission exists.
    let mut cold = unsafe {
        Cold::from_owned_windows(
            preparing(Arc::new(State::default())),
            mac,
            0x8000,
            None,
            owner,
        )
    }
    .unwrap_or_else(|_| panic!("valid cold MAC window"));
    cold.write32(0x7ffc, 0x5a5a_a5a5).unwrap();
    assert_eq!(cold.read32(0x7ffc), Ok(0x5a5a_a5a5));
    assert_eq!(cold.ape_read32(0x2c), Err(Error::Bounds));
    assert_eq!(cold.ape_write32(0x2c, 0x1000), Err(Error::Bounds));
}
