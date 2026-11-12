// SPDX-License-Identifier: GPL-2.0-only
//! Original alive register distinguishes data from removal.
use super::*;
#[test]
fn allones_programmed_mac_padding_initializes_and_transfers_on_both_generations() {
    if crate::test_process::isolate_model() {
        return;
    }
    for device in [0x07b1, 0x04c0] {
        let (mut owner, peer, domain, dropped) = setup(device);
        if peer.profile.generation == Generation::Atlantic {
            peer.ram.borrow_mut().insert(0x100a0, 0x02ffffff);
            peer.ram.borrow_mut().insert(0x100a4, u32::MAX);
        } else {
            peer.set(0x12008, 0xffffff02);
            peer.set(0x1200c, u32::MAX);
        }
        owner.start().unwrap();
        assert_eq!(owner.mac(), Mac([2, 255, 255, 255, 255, 255]));
        if peer.profile.generation == Generation::Atlantic {
            peer.set(0x370, 0x100);
        } else {
            peer.set(0x13014, 0x830);
        }
        owner.transmit(&[0x59; 60]).unwrap();
        assert_eq!(peer.sent.borrow().last().unwrap(), &vec![0x59; 60]);
        peer.receive(&[0x63; 60], 0, 3, 60);
        assert_eq!(owner.receive().unwrap(), Some(vec![0x63; 60]));
        owner.retire().unwrap();
        assert!(domain.maps.lock().unwrap().is_empty());
        assert_eq!(dropped.load(Ordering::Relaxed), 4);
    }
}
#[test]
fn allones_data_requires_independent_alive_access_and_keeps_failed_initialization() {
    if crate::test_process::isolate_model() {
        return;
    }
    for device in [0x07b1, 0x04c0] {
        for unavailable in [false, true] {
            let (mut owner, peer, domain, dropped) = setup(device);
            if peer.profile.generation == Generation::Atlantic {
                peer.ram.borrow_mut().insert(0x100a4, u32::MAX);
            } else {
                peer.set(0x1200c, u32::MAX);
            }
            if unavailable {
                peer.fail_read.set(Some(0x10));
            } else {
                peer.set(0x10, u32::MAX);
            }
            assert_eq!(
                owner.start(),
                Err(if unavailable {
                    Error::Unsupported("injected native MMIO read failure")
                } else {
                    Error::Removed
                })
            );
            assert_eq!(owner.state(), State::Faulted);
            assert_eq!(domain.engine_epoch.load(Ordering::Relaxed), 0);
            assert_eq!(domain.maps.lock().unwrap().len(), 4);
            assert_eq!(dropped.load(Ordering::Relaxed), 0);
            assert!(peer.reads.borrow().contains(&0x10));
            assert!(owner.transmit(&[0x77; 60]).is_err());
            drop(owner);
            assert_eq!(domain.maps.lock().unwrap().len(), 4);
            assert_eq!(dropped.load(Ordering::Relaxed), 0);
        }
    }
}
#[test]
fn live_antigua_allones_boot_status_is_not_a_boot_started_acknowledgement() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut owner, peer, domain, dropped) = setup(0x04c0);
    peer.fault.set(Fault::BootAllOnes);
    assert_eq!(owner.start(), Err(Error::Timeout { register: 0x3040 }));
    assert_eq!(peer.elapsed.get(), 200_010);
    assert_eq!(owner.state(), State::Faulted);
    assert_eq!(domain.engine_epoch.load(Ordering::Relaxed), 0);
    assert_eq!(peer.reset_count.get(), 1);
    assert_eq!(domain.maps.lock().unwrap().len(), 4);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    let writes = peer.writes.borrow().len();
    peer.fault.set(Fault::None);
    assert!(owner.hw().reset(owner.profile).is_err());
    assert_eq!(peer.writes.borrow().len(), writes);
}
struct Probe {
    value: u32,
    alive: u32,
    reads: RefCell<Vec<usize>>,
}
// SAFETY: isolated synchronous raw32-bit register callback, with independent
// alive word and exact read-address capture. No physical resource is supplied.
unsafe impl Registers for Probe {
    fn read(&self, at: usize) -> Result<u32> {
        self.reads.borrow_mut().push(at);
        match at {
            32 => Ok(self.value),
            16 => Ok(self.alive),
            _ => panic!("unexpected live-read address"),
        }
    }
    fn write(&self, _: usize, _: u32) -> Result<()> {
        panic!("live-read comparison wrote registers")
    }
}
struct NoWait;
// SAFETY: scalar-only model; any attempted wait traps.
unsafe impl Timer for NoWait {
    fn check(&self) -> core::result::Result<(), crate::bus::pci::power::Error> {
        Ok(())
    }
    fn wait_us(&self, _: u64) -> core::result::Result<(), crate::bus::pci::power::Error> {
        panic!("live-read comparison waited")
    }
}
#[test]
#[ignore = "oracle: STELA_AQTION_LIVENESS_ORACLE"]
fn unchanged_linux_live_read_data_flags_and_exact_independent_alive_access_match_native() {
    if crate::test_process::isolate_model() {
        return;
    }
    let text =
        std::fs::read_to_string(std::env::var("STELA_AQTION_LIVENESS_ORACLE").unwrap()).unwrap();
    let mut count = 0;
    for line in text.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        assert_eq!(fields[0], "L");
        let n = |i: usize| fields[i].parse::<u32>().unwrap();
        assert!(n(1) < 2);
        let hw = Hardware {
            registers: Probe {
                value: n(2),
                alive: n(3),
                reads: RefCell::new(Vec::new()),
            },
            timer: NoWait,
            reset_ownership: Cell::new(firmware::ResetOwnership::default()),
            budget: Cell::new(None),
        };
        let actual = hw.read(32);
        // Native error is the explicit analogue of the original unplug flag;
        // unrelated original flags are preserved by the unchanged source helper.
        let unplug = n(6) & 0x40000000 != 0;
        assert_eq!(
            actual,
            if unplug {
                Err(Error::Removed)
            } else {
                Ok(n(5))
            }
        );
        assert_eq!(n(6) & !0x40000000, n(4));
        assert_eq!(fields.len(), 8 + n(7) as usize);
        assert_eq!(
            *hw.registers.reads.borrow(),
            (8..fields.len()).map(|i| n(i) as usize).collect::<Vec<_>>()
        );
        count += 1;
    }
    assert_eq!(count, 32);
}
