// SPDX-License-Identifier: GPL-2.0-only
//! Checked provider admission and reset/PM failure ownership.
//! Historical selector names remain; nominal rates never grant timing.
//! Explicit private models supply/refuse all minimum waits.
use super::*;

fn refused_minimum(
    mut old: Aqtion<Rc<Peer>, Rc<Peer>, ControlledConfig>,
    clock: Clock,
) -> Aqtion<Rc<Peer>, crate::timing::RefusedMinimum, ControlledConfig> {
    let hw = old.hardware.take().unwrap();
    Aqtion {
        function: old.function.take(),
        hardware: Some(Hardware {
            registers: hw.registers,
            timer: crate::timing::refused_model(clock),
            reset_ownership: hw.reset_ownership,
            budget: hw.budget,
        }),
        domain: old.domain.take(),
        memory: old.memory.take(),
        profile: old.profile,
        firmware: old.firmware,
        mac: old.mac,
        state: old.state,
        power: old.power,
        tx_tail: old.tx_tail,
        tx_head: old.tx_head,
        rx_head: old.rx_head,
        dropping: old.dropping,
    }
}
#[test]
fn invalid_native_clock_refuses_start_reset_and_pm_before_any_effect() {
    if crate::test_process::isolate_model() {
        return;
    }
    for device in [0x07b1, 0x04c0] {
        for rate in [0, 3_000, u64::MAX] {
            let (owner, peer, domain, dropped) = setup(device);
            let pm = peer.native_pm.borrow().as_ref().unwrap().clone();
            let mut owner = refused_minimum(
                owner,
                Clock {
                    ticks_per_microsecond: rate,
                },
            );
            let accesses = pm.accesses.lock().unwrap().len();
            let maps = domain.maps.lock().unwrap().len();
            assert_eq!(
                owner.start(),
                Err(Error::Pci(crate::block::BlockError::PciPower(
                    crate::bus::pci::power::Error::Clock
                )))
            );
            assert_eq!(
                owner.hw().reset(owner.profile),
                Err(Error::Pci(crate::block::BlockError::PciPower(
                    crate::bus::pci::power::Error::Clock
                )))
            );
            assert_eq!(
                power_up(
                    owner.function.as_mut().unwrap(),
                    &owner.hardware.as_ref().unwrap().timer,
                    &mut owner.power
                ),
                Err(Error::Pci(crate::block::BlockError::PciPower(
                    crate::bus::pci::power::Error::Clock
                )))
            );
            assert_eq!(owner.state(), State::Stopped);
            assert_eq!(owner.power, PciPower::D0);
            assert_eq!(pm.accesses.lock().unwrap().len(), accesses);
            assert!(peer.reads.borrow().is_empty() && peer.writes.borrow().is_empty());
            assert_eq!(domain.maps.lock().unwrap().len(), maps);
            assert_eq!(domain.engine_epoch.load(Ordering::Relaxed), 0);
            assert_eq!(dropped.load(Ordering::Relaxed), 0);
        }
    }
}
#[test]
fn kept_model_timer_preflight_preserves_running_and_suspended_epoch() {
    if crate::test_process::isolate_model() {
        return;
    }
    for device in [0x07b1, 0x04c0] {
        let (mut owner, peer, domain, dropped) = setup(device);
        let pm = peer.native_pm.borrow().as_ref().unwrap().clone();
        owner.start().unwrap();
        peer.timing.set(false);
        let before = (
            peer.reads.borrow().len(),
            peer.writes.borrow().len(),
            pm.accesses.lock().unwrap().len(),
        );
        assert_eq!(
            owner.stop(),
            Err(Error::Pci(crate::block::BlockError::PciPower(
                crate::bus::pci::power::Error::Clock
            )))
        );
        assert_eq!(owner.state(), State::Running);
        assert_eq!(
            (
                peer.reads.borrow().len(),
                peer.writes.borrow().len(),
                pm.accesses.lock().unwrap().len()
            ),
            before
        );
        peer.timing.set(true);
        owner.suspend().unwrap();
        let before = (
            peer.reads.borrow().len(),
            peer.writes.borrow().len(),
            pm.accesses.lock().unwrap().len(),
        );
        peer.timing.set(false);
        assert_eq!(
            owner.resume_owned(),
            Err(Error::Pci(crate::block::BlockError::PciPower(
                crate::bus::pci::power::Error::Clock
            )))
        );
        assert_eq!(owner.state(), State::Suspended);
        assert_eq!(owner.power, PciPower::D3hot);
        assert_eq!(
            (
                peer.reads.borrow().len(),
                peer.writes.borrow().len(),
                pm.accesses.lock().unwrap().len()
            ),
            before
        );
        assert_eq!(domain.maps.lock().unwrap().len(), 4);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        peer.timing.set(true);
        let waits = peer.waits.borrow().len();
        owner.resume_owned().unwrap();
        assert_eq!(
            peer.waits.borrow()[waits],
            10_000,
            "same retained provider executes actual PM D3 delay"
        );
        assert_eq!(domain.engine_epoch.load(Ordering::Relaxed), 2);
        if peer.profile.generation == Generation::Atlantic {
            peer.set(0x370, 0x100);
        } else {
            peer.set(0x13014, 0x830);
        }
        owner.transmit(&[0x52; 60]).unwrap();
        owner.retire().unwrap();
    }
}
#[test]
fn every_reset_wait_failure_preserves_issued_reset_or_releases_only_owned_locks() {
    if crate::test_process::isolate_model() {
        return;
    }
    for (device, flb) in [(0x07b1, false), (0x07b1, true)] {
        let (_, base, _, _) = setup(device);
        if device == 0x07b1 {
            firmware4(&base, flb);
        }
        hardware(&base).reset(base.profile).unwrap();
        let expected = base.waits.borrow().clone();
        assert!(!expected.is_empty());
        for failed in 1..=expected.len() {
            let (_, peer, _, _) = setup(device);
            if device == 0x07b1 {
                firmware4(&peer, flb);
            }
            peer.fail_wait.set(Some(failed));
            let hw = hardware(&peer);
            assert_eq!(
                hw.reset(peer.profile),
                Err(Error::Pci(crate::block::BlockError::PciPower(
                    crate::bus::pci::power::Error::Clock
                )))
            );
            assert_eq!(peer.waits.borrow().as_slice(), &expected[..failed]);
            if peer.reset_count.get() != 0 {
                assert!(reset_releases(&peer).is_empty());
                let effects = peer.writes.borrow().len();
                peer.fail_wait.set(None);
                assert!(hw.reset(peer.profile).is_err());
                assert_eq!(peer.writes.borrow().len(), effects);
            } else if device == 0x07b1 {
                assert_eq!(reset_releases(&peer), [0x3b0, 0x3ac]);
                assert!(peer.semaphores.borrow().values().all(|held| !*held));
            }
        }
    }
}
#[test]
fn wait_failure_acquiring_second_reset_semaphore_releases_only_first() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (_, peer, _, _) = setup(0x07b1);
    firmware4(&peer, false);
    peer.second_lock_busy.set(true);
    peer.fail_wait.set(Some(1));
    let hw = hardware(&peer);
    assert_eq!(
        hw.reset(peer.profile),
        Err(Error::Pci(crate::block::BlockError::PciPower(
            crate::bus::pci::power::Error::Clock
        )))
    );
    assert_eq!(reset_releases(&peer), [0x3ac]);
    assert_eq!(peer.semaphores.borrow().get(&0x3ac), Some(&false));
    assert_eq!(peer.reset_count.get(), 0);
    peer.second_lock_busy.set(false);
    peer.fail_wait.set(None);
    hw.reset(peer.profile).unwrap();
}

#[test]
fn antigua_reset_clock_failure_fences_retry_and_keeps_dma() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut owner, peer, domain, dropped) = setup(0x04c0);
    peer.fault.set(Fault::Reset);
    peer.fail_wait.set(Some(1));
    assert_eq!(
        owner.start(),
        Err(Error::Pci(crate::block::BlockError::PciPower(
            crate::bus::pci::power::Error::Clock
        )))
    );
    assert_eq!(peer.reset_count.get(), 1);
    assert_eq!(owner.state(), State::Faulted);
    assert_eq!(domain.engine_epoch.load(Ordering::Relaxed), 0);
    assert_eq!(domain.maps.lock().unwrap().len(), 4);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    peer.fault.set(Fault::None);
    peer.fail_wait.set(None);
    let effects = peer.writes.borrow().len();
    assert!(owner.hw().reset(owner.profile).is_err());
    assert_eq!(peer.writes.borrow().len(), effects);
    drop(owner);
    assert_eq!(domain.maps.lock().unwrap().len(), 4);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
}

#[test]
fn pm_wait_failure_keeps_unknown_power_and_original_owners_until_d0_retry() {
    if crate::test_process::isolate_model() {
        return;
    }
    for device in [0x07b1, 0x04c0] {
        let (mut owner, peer, domain, dropped) = setup(device);
        let pm = peer.native_pm.borrow().as_ref().unwrap().clone();
        owner.start().unwrap();
        owner.suspend().unwrap();
        let reads = peer.reads.borrow().len();
        let writes = peer.writes.borrow().len();
        peer.fail_wait.set(Some(peer.waits.borrow().len() + 1));
        assert_eq!(
            owner.resume_owned(),
            Err(Error::Pci(crate::block::BlockError::PciPower(
                crate::bus::pci::power::Error::Clock
            )))
        );
        assert_eq!(*peer.waits.borrow().last().unwrap(), 10_000);
        assert_eq!(
            pm.actual_state.load(Ordering::Relaxed),
            0,
            "actual PMCSR write reached hardware before failed wait"
        );
        assert_eq!(owner.power, PciPower::Unknown);
        assert_eq!(owner.state(), State::Suspended);
        assert_eq!(peer.reads.borrow().len(), reads);
        assert_eq!(peer.writes.borrow().len(), writes);
        assert_eq!(domain.maps.lock().unwrap().len(), 4);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        assert!(owner.restart().is_err());
        assert_eq!(peer.writes.borrow().len(), writes);
        peer.fail_wait.set(None);
        owner.resume_owned().unwrap();
        assert_eq!(owner.power, PciPower::D0);
        assert_eq!(domain.engine_epoch.load(Ordering::Relaxed), 2);
        owner.retire().unwrap();
    }
}
