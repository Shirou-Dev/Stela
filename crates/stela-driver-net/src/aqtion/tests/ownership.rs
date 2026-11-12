// SPDX-License-Identifier: GPL-2.0-only
//! Native cold/root/DMA retirement models with separate CPU, PA and IOVA values.
use super::*;
use crate::{
    aqtion::native as adapter,
    bus::pci::requester::{
        FunctionRole, RequesterBinding,
        preparation::{self, Root},
    },
};
mod domain;
mod model;
use model::*;

#[test]
fn original_reset_and_root_completion_precede_nonidentity_native_traffic() {
    if crate::test_process::isolate_model() {
        return;
    }
    for device in [0x07b1, 0x04c0] {
        let fixture = inputs(device);
        let mut owner = attach(fixture.inputs, &fixture.pages).unwrap();
        let state = &fixture.state;
        assert_eq!(
            &state.events.lock().unwrap()[..6],
            &["original drain", "bind", "map", "map", "map", "map"]
        );
        assert_eq!(state.old_backing.load(Ordering::Relaxed), 0x55aa);
        assert_ne!(fixture.peer.address(0x7c00), 0x4000_0000);
        assert!(fixture.peer.address(0x7c00) > u64::from(u32::MAX));
        if owner.profile().generation == Generation::Atlantic {
            fixture.peer.set(0x370, 0x100);
        } else {
            fixture.peer.set(0x13014, 0x830);
        }
        assert!(owner.carrier());
        owner.transmit(&[0x39; 60]).unwrap();
        assert_eq!(fixture.peer.sent.borrow().last().unwrap(), &[0x39; 60]);
        fixture.peer.receive(&[0x47; 60], 0, 3, 60);
        assert_eq!(owner.receive().unwrap().unwrap(), [0x47; 60]);
        owner.retire().unwrap();
        assert!(owner.function.is_none());
        assert!(state.binding.lock().unwrap().is_none());
        assert!(state.base.maps.lock().unwrap().is_empty());
        assert!(state.detached.load(Ordering::Relaxed));
        assert!(state.bar_retired.load(Ordering::Relaxed));
        assert_eq!(state.pm.unmaps.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.dropped.load(Ordering::Relaxed), 4);
        let events = state.events.lock().unwrap().clone();
        let last_unmap = events.iter().rposition(|event| *event == "unmap").unwrap();
        let detach = events.iter().position(|event| *event == "detach").unwrap();
        let bar = events
            .iter()
            .position(|event| *event == "bar retire")
            .unwrap();
        assert!(last_unmap < detach && detach < bar);
        let io = (
            fixture.peer.reads.borrow().len(),
            fixture.peer.writes.borrow().len(),
        );
        owner.retire().unwrap();
        assert_eq!(owner.restart(), Err(adapter::Error::Retired));
        assert_eq!(owner.resume(), Err(adapter::Error::Retired));
        assert_eq!(owner.suspend(), Err(adapter::Error::Retired));
        assert_eq!(owner.stop(), Err(adapter::Error::Retired));
        assert!(!owner.carrier());
        assert!(owner.transmit(&[0x39; 60]).is_err());
        assert!(owner.receive().is_err());
        assert_eq!(
            (
                fixture.peer.reads.borrow().len(),
                fixture.peer.writes.borrow().len()
            ),
            io
        );
        assert_eq!(*state.events.lock().unwrap(), events);
        drop(owner);
        assert_eq!(state.registers_dropped.load(Ordering::Relaxed), 1);
    }
}
#[test]
fn failed_original_completion_or_binding_keeps_cold_graph_without_allocating() {
    if crate::test_process::isolate_model() {
        return;
    }
    for device in [0x07b1, 0x04c0] {
        for failed in ["original drain", "bind"] {
            let fixture = inputs(device);
            *fixture.state.fail.lock().unwrap() = Some(failed);
            let failure = attach(fixture.inputs, &fixture.pages).err().unwrap();
            assert!(matches!(failure.error, adapter::Error::Preparation(_)));
            drop(failure);
            assert_eq!(fixture.state.base.next.load(Ordering::Relaxed), 0);
            assert!(fixture.state.binding.lock().unwrap().is_none());
            assert_eq!(fixture.state.registers_dropped.load(Ordering::Relaxed), 0);
            assert_eq!(fixture.state.pm.unmaps.load(Ordering::Relaxed), 0);
        }
    }
}
#[test]
fn engine_stop_and_clock_failures_cannot_reach_original_root_completion() {
    if crate::test_process::isolate_model() {
        return;
    }
    for device in [0x07b1, 0x04c0] {
        for clock_failed in [false, true] {
            let fixture = inputs(device);
            if clock_failed {
                fixture.peer.timing.set(false);
            } else {
                fixture.peer.fault.set(Fault::QueueStop);
            }
            let failure = attach(fixture.inputs, &fixture.pages).err().unwrap();
            assert!(matches!(failure.error, adapter::Error::Device(_)));
            drop(failure);
            assert!(fixture.state.events.lock().unwrap().is_empty());
            assert!(fixture.state.old_pending.load(Ordering::Relaxed));
            assert_eq!(fixture.state.base.next.load(Ordering::Relaxed), 0);
            assert_eq!(fixture.state.registers_dropped.load(Ordering::Relaxed), 0);
            assert_eq!(fixture.state.pm.unmaps.load(Ordering::Relaxed), 0);
        }
    }
}
#[test]
fn abandoning_an_active_native_owner_retains_pages_binding_and_registers() {
    if crate::test_process::isolate_model() {
        return;
    }
    for device in [0x07b1, 0x04c0] {
        let fixture = inputs(device);
        let owner = attach(fixture.inputs, &fixture.pages).unwrap();
        fixture.state.events.lock().unwrap().clear();
        drop(owner);
        // The drop stopped it: every queue off, bus mastering cleared and
        // posted writes drained.
        fixture.state.stopped();
        for queue in 0..32 {
            for field in [registers::TDM_TX_DESC_EN_SET, registers::RDM_RX_DESC_EN_SET] {
                assert_eq!(
                    fixture.peer.get(field.address + queue * field.stride) & field.mask,
                    0
                );
            }
        }
        assert_eq!(*fixture.state.events.lock().unwrap(), ["bound drain"]);
        assert!(fixture.state.binding.lock().unwrap().is_some());
        assert_eq!(fixture.state.base.maps.lock().unwrap().len(), 4);
        assert_eq!(fixture.dropped.load(Ordering::Relaxed), 0);
        assert_eq!(fixture.state.registers_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(fixture.state.pm.unmaps.load(Ordering::Relaxed), 0);
    }
}
/// A queue that never stops ends the drop's stop within its budget, before
/// bus mastering is cleared or any drain, and the owner stays whole; a
/// function that left the bus gets no register write.
#[test]
fn a_dropped_owner_that_cannot_stop_stays_whole_within_its_budget() {
    if crate::test_process::isolate_model() {
        return;
    }
    for device in [0x07b1, 0x04c0] {
        let fixture = inputs(device);
        let owner = attach(fixture.inputs, &fixture.pages).unwrap();
        fixture.peer.fault.set(Fault::QueueStop);
        fixture.state.events.lock().unwrap().clear();
        let before = fixture.peer.elapsed.get();
        drop(owner);
        let waited = fixture.peer.elapsed.get() - before;
        assert!(waited <= STOP_BUDGET_US, "{waited}");
        assert_ne!(fixture.state.pm.command() & 4, 0);
        assert!(fixture.state.events.lock().unwrap().is_empty());
        assert_eq!(fixture.state.base.maps.lock().unwrap().len(), 4);
        assert_eq!(fixture.state.registers_dropped.load(Ordering::Relaxed), 0);
        let fixture = inputs(device);
        let owner = attach(fixture.inputs, &fixture.pages).unwrap();
        // SAFETY: the model's own configuration RAM; nothing else accesses
        // it while the owner is dropped.
        unsafe {
            fixture
                .state
                .pm
                .pointer()
                .as_ptr()
                .add(4)
                .cast::<u16>()
                .write_volatile(u16::MAX)
        };
        let writes = fixture.peer.writes.borrow().len();
        drop(owner);
        assert_eq!(fixture.peer.writes.borrow().len(), writes);
    }
}
#[test]
fn each_native_retirement_failure_is_sticky_and_keeps_remaining_resources() {
    if crate::test_process::isolate_model() {
        return;
    }
    for device in [0x07b1, 0x04c0] {
        for failed in [
            "bound drain",
            "unmap",
            "detach",
            "bar retire",
            "configuration",
        ] {
            let fixture = inputs(device);
            let mut owner = attach(fixture.inputs, &fixture.pages).unwrap();
            let original_function = core::ptr::from_ref(owner.function.as_ref().unwrap());
            match failed {
                "unmap" => fixture.state.base.fail_unmap_at.store(2, Ordering::Relaxed),
                "configuration" => fixture.state.pm.fail_unmap.store(true, Ordering::Relaxed),
                _ => *fixture.state.fail.lock().unwrap() = Some(failed),
            }
            let error = owner.retire().unwrap_err();
            assert!(core::ptr::eq(
                original_function,
                owner.function.as_ref().unwrap()
            ));
            if failed == "configuration" {
                assert_eq!(
                    error,
                    adapter::Error::Configuration(owned::Error::UnmapFailed)
                );
                assert!(fixture.state.detached.load(Ordering::Relaxed));
                assert!(fixture.state.bar_retired.load(Ordering::Relaxed));
                let link_error =
                    LinkError::Pci(crate::block::BlockError::Mmio(owned::Error::UnmapFailed));
                assert_eq!(owner.transmit(&[0x39; 60]), Err(link_error.clone()));
                assert_eq!(owner.receive(), Err(link_error));
            }
            let io = (
                fixture.peer.reads.borrow().len(),
                fixture.peer.writes.borrow().len(),
            );
            let events = fixture.state.events.lock().unwrap().clone();
            let unmaps = fixture.state.base.unmap_calls.load(Ordering::Relaxed);
            let config = fixture.state.pm.unmaps.load(Ordering::Relaxed);
            assert_eq!(owner.retire(), Err(error.clone()));
            assert_eq!(owner.restart(), Err(error.clone()));
            assert_eq!(owner.resume(), Err(error.clone()));
            assert_eq!(owner.suspend(), Err(error.clone()));
            assert_eq!(owner.stop(), Err(error));
            assert!(!owner.carrier());
            assert!(owner.transmit(&[0x39; 60]).is_err());
            assert!(owner.receive().is_err());
            assert_eq!(
                (
                    fixture.peer.reads.borrow().len(),
                    fixture.peer.writes.borrow().len()
                ),
                io
            );
            assert_eq!(*fixture.state.events.lock().unwrap(), events);
            assert_eq!(
                fixture.state.base.unmap_calls.load(Ordering::Relaxed),
                unmaps
            );
            assert_eq!(fixture.state.pm.unmaps.load(Ordering::Relaxed), config);
            drop(owner);
            assert_eq!(fixture.state.registers_dropped.load(Ordering::Relaxed), 0);
            assert_eq!(
                fixture.state.pm.unmaps.load(Ordering::Relaxed),
                usize::from(failed == "configuration")
            );
            assert_eq!(
                fixture.state.binding.lock().unwrap().is_some(),
                matches!(failed, "bound drain" | "unmap" | "detach")
            );
        }
    }
}
#[test]
fn partial_native_allocation_keeps_successful_maps_and_original_binding() {
    if crate::test_process::isolate_model() {
        return;
    }
    for device in [0x07b1, 0x04c0] {
        let fixture = inputs(device);
        fixture.state.fail_map_at.store(3, Ordering::Relaxed);
        let failure = attach(fixture.inputs, &fixture.pages).err().unwrap();
        assert!(matches!(
            failure.error,
            adapter::Error::Device(Error::Dma(DmaError::MappingFailed))
        ));
        drop(failure);
        assert_eq!(fixture.state.base.maps.lock().unwrap().len(), 2);
        assert_eq!(fixture.state.base.unmap_calls.load(Ordering::Relaxed), 0);
        assert!(fixture.state.binding.lock().unwrap().is_some());
        assert_eq!(fixture.state.registers_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(fixture.state.pm.unmaps.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn changed_configuration_or_bar_refuses_before_vendor_register_access() {
    if crate::test_process::isolate_model() {
        return;
    }
    for identity in [false, true] {
        let mut fixture = inputs(0x07b1);
        fixture
            .inputs
            .requester
            .function_mut()
            .config()
            .write32(if identity { 0 } else { 0x10 }, 0x9100_0000)
            .unwrap();
        let failure = attach(fixture.inputs, &fixture.pages).err().unwrap();
        assert!(matches!(
            failure.error,
            adapter::Error::Bar { .. } | adapter::Error::ConfigurationEpoch
        ));
        drop(failure);
        assert!(fixture.peer.writes.borrow().is_empty());
        assert!(fixture.peer.reads.borrow().is_empty());
        assert!(fixture.state.events.lock().unwrap().is_empty());
        assert_eq!(fixture.state.registers_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(fixture.state.pm.unmaps.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn suspended_native_retirement_releases_owners_without_powered_mmio() {
    if crate::test_process::isolate_model() {
        return;
    }
    for device in [0x07b1, 0x04c0] {
        let fixture = inputs(device);
        let mut owner = attach(fixture.inputs, &fixture.pages).unwrap();
        owner.suspend().unwrap();
        assert_eq!(fixture.state.pm.power_state(), 3);
        let io = (
            fixture.peer.reads.borrow().len(),
            fixture.peer.writes.borrow().len(),
        );
        owner.retire().unwrap();
        assert_eq!(fixture.state.pm.power_state(), 3);
        assert_eq!(
            (
                fixture.peer.reads.borrow().len(),
                fixture.peer.writes.borrow().len()
            ),
            io
        );
        assert_eq!(fixture.state.pm.unmaps.load(Ordering::Relaxed), 1);
        assert!(fixture.state.binding.lock().unwrap().is_none());
        assert_eq!(fixture.dropped.load(Ordering::Relaxed), 4);
        drop(owner);
        assert_eq!(fixture.state.registers_dropped.load(Ordering::Relaxed), 1);
    }
}
