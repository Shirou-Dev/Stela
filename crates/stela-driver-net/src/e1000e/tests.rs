use super::*;
use crate::bus::{
    dma::RegionAllocator,
    pci::{Address, ConfigSpace},
};
use alloc::collections::BTreeMap;
use core::cell::{Cell, RefCell};

#[derive(Default)]
struct Model {
    registers: RefCell<BTreeMap<usize, u32>>,
    writes: RefCell<Vec<(usize, u32)>>,
    phy: RefCell<[u16; 32]>,
    ownership_blocked: bool,
    master_stuck: bool,
    reset_stuck: bool,
    mdic_timeout: bool,
    mdic_error: bool,
    wrong_register: bool,
    /// MDIO ownership claims refused before one is granted.
    ownership_refusals: Cell<usize>,
    /// Reads of the PHY control register that still show a PHY reset.
    phy_reset_polls: Cell<usize>,
    phy_reset_left: Cell<usize>,
}

impl Model {
    fn ready() -> Self {
        let model = Self::default();
        model.registers.borrow_mut().insert(EECD, EECD_AUTO_RD);
        model.phy.borrow_mut()[usize::from(PHY_ID1)] = (PHY_BM_REV2 >> 16) as u16;
        model.phy.borrow_mut()[usize::from(PHY_ID2)] = PHY_BM_REV2 as u16;
        model
    }
}

impl Registers for Model {
    fn read(&self, offset: usize) -> u32 {
        self.registers.borrow().get(&offset).copied().unwrap_or(0)
    }

    fn write(&self, offset: usize, mut value: u32) {
        self.writes.borrow_mut().push((offset, value));
        if offset == EXTCNF_CTRL && self.ownership_blocked {
            value &= !MDIO_OWN;
        }
        if offset == EXTCNF_CTRL && value & MDIO_OWN != 0 && self.ownership_refusals.get() != 0 {
            self.ownership_refusals
                .set(self.ownership_refusals.get() - 1);
            value &= !MDIO_OWN;
        }
        if offset == CTRL {
            if value & CTRL_RST != 0 && !self.reset_stuck {
                value &= !CTRL_RST;
            }
            if value & CTRL_MASTER_DISABLE != 0 && !self.master_stuck {
                self.registers.borrow_mut().insert(STATUS, 0);
            }
        }
        if offset == MDIC && !self.mdic_timeout {
            let register = ((value & MDIC_REGISTER) >> 16) as usize;
            if self.mdic_error {
                value |= MDIC_ERROR;
            } else if value & MDIC_READ != 0 {
                value |= u32::from(self.phy.borrow()[register]);
                if register == usize::from(PHY_CONTROL) && self.phy_reset_left.get() != 0 {
                    self.phy_reset_left.set(self.phy_reset_left.get() - 1);
                    value |= u32::from(PHY_RESET);
                }
            } else {
                let data = value as u16;
                if register == usize::from(PHY_CONTROL) && data & PHY_RESET != 0 {
                    self.phy_reset_left.set(self.phy_reset_polls.get());
                }
                self.phy.borrow_mut()[register] = if register == usize::from(PHY_CONTROL) {
                    data & !(PHY_RESET | PHY_RESTART)
                } else {
                    data
                };
            }
            if self.wrong_register {
                value ^= 1 << 16;
            }
            value |= MDIC_READY;
        }
        self.registers.borrow_mut().insert(offset, value);
    }
}

#[derive(Default)]
struct ModelTimer {
    delays: RefCell<Vec<u64>>,
    /// Each bounded wait's limit.
    waits: RefCell<Vec<u64>>,
}

impl ModelTimer {
    /// The longest the calls so far could have waited in all.
    fn bound_us(&self) -> u64 {
        self.delays.borrow().iter().sum::<u64>() + self.waits.borrow().iter().sum::<u64>()
    }
}

impl Timer for ModelTimer {
    fn delay(&self, microseconds: u64) -> Result<(), BlockError> {
        self.delays.borrow_mut().push(microseconds);
        Ok(())
    }

    fn wait(&self, microseconds: u64, mut ready: impl FnMut() -> bool) -> bool {
        self.waits.borrow_mut().push(microseconds);
        (0..4).any(|_| ready())
    }
}

/// A clock whose waits poll every 100 us of model time, as a real deadline
/// wait polls, counting the time waited.
#[derive(Default)]
struct PollingTimer {
    elapsed: Cell<u64>,
}

impl Timer for PollingTimer {
    fn delay(&self, microseconds: u64) -> Result<(), BlockError> {
        self.elapsed.set(self.elapsed.get() + microseconds);
        Ok(())
    }

    fn wait(&self, microseconds: u64, mut ready: impl FnMut() -> bool) -> bool {
        let mut waited = 0;
        loop {
            if ready() {
                return true;
            }
            if waited >= microseconds {
                return false;
            }
            waited += 100;
            self.elapsed.set(self.elapsed.get() + 100);
        }
    }
}

/// A reset task waiting on MDIO ownership firmware holds and on slow PHY
/// resets, about a second in all, runs in steps: none waits more than
/// 60 ms, and it makes the same register writes as the blocking one.
#[test]
fn a_stepped_reinitialization_matches_the_blocking_one_and_waits_little_per_step() {
    let run = |stepped: bool| {
        let model = Model::ready();
        model.ownership_refusals.set(1_500);
        model.phy_reset_polls.set(300);
        let timer = PollingTimer::default();
        let mut steps = 0;
        let result = if stepped {
            let slice = Allowance::new(STEP_US);
            let hardware = Hardware::new(&model, &timer).sliced(&slice);
            let mut task = core::pin::pin!(hardware.reinitialize());
            loop {
                slice.refill();
                let before = timer.elapsed.get();
                let step = stela_driver_base::stepped::poll_once(task.as_mut());
                let waited = timer.elapsed.get() - before;
                assert!(waited <= 60_000, "step {steps} waited {waited} us");
                steps += 1;
                if let Poll::Ready(result) = step {
                    break result;
                }
            }
        } else {
            block_on(Hardware::new(&model, &timer).reinitialize())
        };
        let writes = model.writes.borrow().clone();
        (result, steps, writes, timer.elapsed.get())
    };
    let (blocking, _, writes, waited) = run(false);
    let (stepped, steps, stepped_writes, stepped_waited) = run(true);
    assert_eq!(blocking, Ok(()));
    assert_eq!(stepped, Ok(()));
    assert_eq!(stepped_writes, writes);
    assert!(waited > 700_000, "{waited}");
    // A piece ends with one more poll at its expiry, so a little less.
    assert!(
        waited - stepped_waited < 10_000,
        "{stepped_waited} {waited}"
    );
    assert!(steps > 15, "{steps}");
}

/// A PHY check on ownership firmware holds runs in steps too.
#[test]
fn a_stepped_phy_check_waits_little_per_step() {
    let model = Model::ready();
    model.phy.borrow_mut()[usize::from(PHY_RECEIVE_ERRORS)] = u16::MAX;
    model.phy.borrow_mut()[usize::from(PHY_GIGABIT_STATUS)] = PHY_IDLE_ERRORS;
    model.ownership_refusals.set(1_500);
    let timer = PollingTimer::default();
    let slice = Allowance::new(STEP_US);
    let hardware = Hardware::new(&model, &timer).sliced(&slice);
    let mut task = core::pin::pin!(hardware.phy_hung());
    let mut steps = 0;
    let hung = loop {
        slice.refill();
        let before = timer.elapsed.get();
        let step = stela_driver_base::stepped::poll_once(task.as_mut());
        assert!(timer.elapsed.get() - before <= 60_000);
        steps += 1;
        if let Poll::Ready(hung) = step {
            break hung;
        }
    };
    assert!(hung);
    assert!(steps >= 4, "{steps}");
    assert_eq!(model.read(EXTCNF_CTRL) & MDIO_OWN, 0);
}

/// While a reset runs, every link call takes one step of at most 60 ms:
/// the carrier is down, frames are refused and received frames wait, and
/// neither ring moves. Here the bus master never drains, so it fails
/// after its 160 ms, as the blocking reset did.
#[test]
fn link_calls_take_a_reset_a_step_at_a_time_and_leave_the_rings_alone() {
    let mut fixture = Fixture::new();
    let _clock = crate::test_clock::virtualize();
    let nominal = Clock {
        ticks_per_microsecond: 1,
    };
    let (timing, minimum) = crate::timing::counted_model(nominal);
    fixture.net.clock = timing;
    fixture.net.transmit(&[1; 60]).unwrap();
    fixture.inject(0, 60, RX_DONE | RX_EOP, 0, 7);
    fixture.registers[STATUS / 4] = STATUS_LU | STATUS_MASTER;
    let spent = || nominal.now_us() + minimum.get();
    let before = spent();
    assert_eq!(fixture.net.reinitialize(), Ok(()));
    assert!(spent() - before <= 60_000);
    assert!(fixture.net.resetting());
    let (tail, head) = (fixture.registers[TDT / 4], fixture.registers[RDT / 4]);
    let receive = fixture.net.receive.descriptors.bytes().to_vec();
    let mut calls = 0;
    while fixture.net.resetting() {
        let before = spent();
        let result = match calls % 3 {
            0 => Ok(fixture.net.carrier()).map(|up| assert!(!up)),
            1 => fixture
                .net
                .transmit(&[2; 60])
                .map(|()| panic!("sent while resetting")),
            _ => fixture.net.receive().map(|frame| assert_eq!(frame, None)),
        };
        calls += 1;
        assert!(spent() - before <= 60_000, "call {calls}");
        match result {
            // The call that ends the reset reports its failure.
            Err(LinkError::Adapter(message)) => {
                assert!(message.contains("reinitialization failed"), "{message}");
                assert!(!fixture.net.resetting());
            }
            Err(LinkError::NoCarrier) | Ok(()) => {}
            other => panic!("{other:?}"),
        }
        if fixture.net.resetting() {
            assert_eq!(fixture.registers[TDT / 4], tail);
            assert_eq!(fixture.registers[RDT / 4], head);
            assert_eq!(fixture.net.receive.descriptors.bytes(), receive);
        }
    }
    assert!(calls >= 3, "{calls}");
}

#[test]
fn a_stop_drains_the_bus_master_resets_the_mac_and_hands_control_back() {
    let model = Model::ready();
    model.registers.borrow_mut().insert(STATUS, STATUS_MASTER);
    model
        .registers
        .borrow_mut()
        .insert(RCTL, RCTL_EN | RCTL_BAM);
    model
        .registers
        .borrow_mut()
        .insert(TCTL, TCTL_EN | TCTL_PSP);
    model
        .registers
        .borrow_mut()
        .insert(CTRL_EXT, CTRL_EXT_DRIVER | CTRL_EXT_LINK_82574);
    let timer = ModelTimer::default();
    assert_eq!(stop(&model, &timer), Ok(()));
    release_control(&model);
    let writes = model.writes.borrow();
    let at = |found: &dyn Fn(usize, u32) -> bool| {
        writes
            .iter()
            .position(|&(offset, value)| found(offset, value))
            .unwrap()
    };
    // e1000e_down: receive, then transmit, off before the reset drains the
    // bus master and resets the MAC.
    let receive = at(&|offset, value| offset == RCTL && value == RCTL_BAM);
    let transmit = at(&|offset, value| offset == TCTL && value == TCTL_PSP);
    let master = at(&|offset, value| offset == CTRL && value & CTRL_MASTER_DISABLE != 0);
    let reset = at(&|offset, value| offset == CTRL && value & CTRL_RST != 0);
    assert!(receive < transmit && transmit < master && master < reset);
    // e1000e_release_hw_control, and MDIO ownership given back.
    assert_eq!(model.read(CTRL_EXT), CTRL_EXT_LINK_82574);
    assert_eq!(model.read(EXTCNF_CTRL) & MDIO_OWN, 0);
    // Every wait fits a processor's exit, well inside half a second.
    assert!(timer.bound_us() <= 200_000, "{}", timer.bound_us());
    // A bus master that never drains fails the stop before any reset, so
    // the owner keeps the rings.
    let stuck = Model {
        master_stuck: true,
        ..Model::ready()
    };
    stuck.registers.borrow_mut().insert(STATUS, STATUS_MASTER);
    assert_eq!(
        stop(&stuck, &ModelTimer::default()),
        Err(BlockError::Timeout)
    );
    assert!(
        !stuck
            .writes
            .borrow()
            .iter()
            .any(|&(offset, value)| offset == CTRL && value & CTRL_RST != 0)
    );
}

#[test]
fn dropping_an_adapter_stops_it_and_a_lost_one_gets_no_write() {
    // A running adapter: its drop disables receive and asks for the reset.
    let mut fixture = Fixture::new();
    fixture.registers[STATUS / 4] = STATUS_LU;
    let Fixture {
        net,
        registers,
        _memory,
    } = fixture;
    drop(net);
    assert_eq!(registers[RCTL / 4] & RCTL_EN, 0);
    assert_eq!(registers[TCTL / 4] & TCTL_EN, 0);
    assert_ne!(registers[CTRL / 4] & CTRL_MASTER_DISABLE, 0);
    // A lost function reads all ones: nothing is written.
    let mut fixture = Fixture::new();
    fixture.registers[STATUS / 4] = u32::MAX;
    let Fixture {
        net,
        registers,
        _memory,
    } = fixture;
    let before = registers.clone();
    drop(net);
    assert_eq!(registers, before);
}

#[test]
fn reset_drains_dma_reloads_nvm_and_releases_mdio() {
    let model = Model::ready();
    model.registers.borrow_mut().insert(STATUS, STATUS_MASTER);
    model.registers.borrow_mut().insert(TCTL, TCTL_EN);
    let timer = ModelTimer::default();
    assert_eq!(reset(&model, &timer), Ok(()));
    assert_eq!(*timer.delays.borrow(), [10_000, 25_000]);
    assert_eq!(model.read(EXTCNF_CTRL) & MDIO_OWN, 0);
    assert_eq!(model.read(RCTL), 0);
    assert_eq!(model.read(TCTL) & TCTL_EN, 0);
    let writes = model.writes.borrow();
    let own = writes
        .iter()
        .position(|&(at, value)| at == EXTCNF_CTRL && value & MDIO_OWN != 0)
        .unwrap();
    let rst = writes
        .iter()
        .position(|&(at, value)| at == CTRL && value & CTRL_RST != 0)
        .unwrap();
    assert!(own < rst);
}

#[test]
fn a_bus_master_that_will_not_drain_is_not_reset() {
    let model = Model {
        master_stuck: true,
        ..Model::ready()
    };
    model.registers.borrow_mut().insert(STATUS, STATUS_MASTER);
    assert_eq!(
        reset(&model, &ModelTimer::default()),
        Err(BlockError::Timeout)
    );
    assert!(
        !model
            .writes
            .borrow()
            .iter()
            .any(|&(at, value)| at == CTRL && value & CTRL_RST != 0)
    );
}

#[test]
fn ownership_and_nvm_failures_do_not_look_successful() {
    let ownership = Model {
        ownership_blocked: true,
        ..Model::ready()
    };
    assert_eq!(
        reset(&ownership, &ModelTimer::default()),
        Err(BlockError::Timeout)
    );
    assert!(
        !ownership
            .writes
            .borrow()
            .iter()
            .any(|&(at, value)| at == CTRL && value & CTRL_RST != 0)
    );
    let nvm = Model::default();
    assert_eq!(
        reset(&nvm, &ModelTimer::default()),
        Err(BlockError::Timeout)
    );
    assert_eq!(nvm.read(EXTCNF_CTRL) & MDIO_OWN, 0);
    let stuck = Model {
        reset_stuck: true,
        ..Model::ready()
    };
    assert_eq!(
        reset(&stuck, &ModelTimer::default()),
        Err(BlockError::Timeout)
    );
    assert_eq!(stuck.read(EXTCNF_CTRL) & MDIO_OWN, 0);
}

#[test]
fn phy_setup_programs_autonegotiation_and_releases_the_firmware_lock() {
    let model = Model::ready();
    model.phy.borrow_mut()[usize::from(PHY_CONTROL)] = PHY_POWERDOWN | PHY_LOOPBACK | PHY_ISOLATE;
    assert_eq!(configure_phy(&model, &ModelTimer::default()), Ok(()));
    assert_eq!(model.read(EXTCNF_CTRL) & MDIO_OWN, 0);
    let phy = model.phy.borrow();
    assert_eq!(phy[usize::from(PHY_ADVERTISE)], 0x01e1);
    assert_eq!(phy[usize::from(PHY_GIGABIT)], 0x0200);
    assert_eq!(phy[usize::from(PHY_CONTROL)], PHY_AUTONEG);
    assert_eq!(
        phy[usize::from(PHY_SPECIFIC)] & (PHY_AUTO_MDIX | PHY_DOWNSHIFT),
        PHY_AUTO_MDIX | PHY_DOWNSHIFT
    );
    assert_eq!(phy[usize::from(PHY_BIAS1)], 3);
}

#[test]
fn mdio_timeout_error_wrong_response_and_unknown_phy_are_explicit() {
    for model in [
        Model {
            mdic_timeout: true,
            ..Model::ready()
        },
        Model {
            mdic_error: true,
            ..Model::ready()
        },
        Model {
            wrong_register: true,
            ..Model::ready()
        },
        Model::default(),
    ] {
        assert!(configure_phy(&model, &ModelTimer::default()).is_err());
        assert_eq!(model.read(EXTCNF_CTRL) & MDIO_OWN, 0);
    }
}

/// An empty receive enables the receive cause again, auto-cleared when
/// the vector fired.
#[test]
fn empty_receive_enables_the_receive_cause_again() {
    let mut fixture = Fixture::new();
    fixture.net.signalled = true;
    assert!(fixture.net.signals());
    assert_eq!(fixture.net.receive(), Ok(None));
    assert_eq!(fixture.registers[IMS / 4], IMS_RXQ0);
}

struct Fixture {
    net: E1000e,
    registers: Vec<u32>,
    _memory: Vec<u64>,
}

impl Fixture {
    fn new() -> Self {
        let mut registers = vec![0u32; REGISTER_BYTES as usize / 4];
        let mut memory = vec![u64::MAX; 200_000];
        let start = memory.as_mut_ptr() as u64;
        // SAFETY: the fixture owns the memory for the driver's whole lifetime.
        let mut allocator = unsafe { RegionAllocator::new(start..start + 1_600_000) };
        // SAFETY: this aligned backing covers every register used by the driver.
        let device =
            unsafe { Mmio::new(registers.as_mut_ptr() as u64, size_of_val(&registers[..])) };
        let mut net = E1000e {
            device,
            receive: ManuallyDrop::new(Ring::new(&mut allocator).unwrap()),
            transmit: ManuallyDrop::new(Ring::new(&mut allocator).unwrap()),
            dropping_receive: false,
            mac: Mac([2, 0, 0, 0, 0, 1]),
            clock: crate::timing::model(Clock {
                ticks_per_microsecond: 1,
            }),
            watchdog_at: u64::MAX,
            phy_hangs: 0,
            faulted: false,
            timing_failure: None,
            location: String::from("model"),
            signalled: false,
            work: None,
        };
        net.start();
        registers[STATUS / 4] = STATUS_LU;
        Self {
            net,
            registers,
            _memory: memory,
        }
    }

    fn inject(&mut self, index: usize, length: u16, status: u8, errors: u8, byte: u8) {
        self.net.receive.buffer(index).fill(byte);
        self.net
            .receive
            .descriptors
            .write(index * DESCRIPTOR + 8, length);
        self.net
            .receive
            .descriptors
            .write(index * DESCRIPTOR + 13, errors);
        // Hardware makes DD visible after the data and metadata writes.
        self.net
            .receive
            .descriptors
            .write(index * DESCRIPTOR + 12, status);
    }
}

#[test]
fn dma_rings_use_legacy_descriptors_and_a_single_empty_slot() {
    let mut fixture = Fixture::new();
    assert_eq!(
        fixture.registers[RDLEN / 4],
        (DESCRIPTORS * DESCRIPTOR) as u32
    );
    assert_eq!(
        fixture.registers[TDLEN / 4],
        (DESCRIPTORS * DESCRIPTOR) as u32
    );
    assert_eq!(fixture.registers[RDT / 4], (DESCRIPTORS - 1) as u32);
    assert_eq!(fixture.registers[RFCTL / 4] & RFCTL_EXTEN, 0);
    for _ in 0..DESCRIPTORS - 1 {
        fixture.net.transmit(&[7; 60]).unwrap();
    }
    let before = fixture.net.transmit.descriptors.bytes().to_vec();
    assert_eq!(fixture.net.transmit(&[8; 60]), Err(LinkError::Busy));
    assert_eq!(fixture.net.transmit.descriptors.bytes(), before);
    assert_eq!(fixture.net.transmit.next, DESCRIPTORS - 1);
    // Completion of the oldest descriptor permits only that buffer to be reused.
    fixture.net.transmit.descriptors.write(12, TX_DONE);
    fixture.net.transmit(&[9; 60]).unwrap();
    assert_eq!(fixture.net.transmit.next, 0);
    assert_eq!(fixture.net.transmit.clean, 1);
    assert!(!fixture.net.transmit.reclaim(transmitted));
}

#[test]
fn transmit_padding_descriptors_and_wrap_are_real_dma_state() {
    let mut fixture = Fixture::new();
    for index in 0..DESCRIPTORS * 3 {
        let descriptor = index % DESCRIPTORS;
        fixture.net.transmit(&[0xa5; 14]).unwrap();
        assert_eq!(&fixture.net.transmit.buffer(descriptor)[..14], &[0xa5; 14]);
        assert_eq!(&fixture.net.transmit.buffer(descriptor)[14..60], &[0; 46]);
        assert_eq!(
            fixture
                .net
                .transmit
                .descriptors
                .read::<u32>(descriptor * DESCRIPTOR + 8),
            60 | TX_EOP | TX_IFCS | TX_REPORT
        );
        fixture
            .net
            .transmit
            .descriptors
            .write(descriptor * DESCRIPTOR + 12, TX_DONE);
    }
    assert_eq!(fixture.net.transmit.next, 0);
    assert_eq!(fixture.registers[TDT / 4], 0);
    let before = fixture.net.transmit.next;
    for bad in [vec![], vec![0; 13], vec![0; MAX_FRAME + 1]] {
        assert!(matches!(
            fixture.net.transmit(&bad),
            Err(LinkError::Invalid(_))
        ));
        assert_eq!(fixture.net.transmit.next, before);
    }
}

#[test]
fn receive_drops_errors_oversize_and_entire_fragment_chains() {
    let mut fixture = Fixture::new();
    fixture.inject(0, 60, RX_DONE, 0, 1); // first fragment
    fixture.inject(1, 60, RX_DONE | RX_EOP, 0, 2); // not a standalone packet
    fixture.inject(2, 60, RX_DONE | RX_EOP, 1, 3); // bad FCS
    fixture.inject(3, 4096, RX_DONE | RX_EOP, 0, 4); // don't slice out of bounds
    fixture.inject(4, 60, RX_DONE | RX_EOP, 0, 5);
    // The stack's reused buffer takes only the good frame, in place.
    let mut reused = Vec::with_capacity(MAX_FRAME);
    let storage = reused.as_ptr();
    assert_eq!(fixture.net.receive_reusing(&mut reused), Ok(true));
    assert_eq!(reused, vec![5; 60]);
    assert_eq!(reused.as_ptr(), storage);
    assert_eq!(fixture.net.receive.next, 5);
    // The tail waits for a batch, or for the ring to run dry.
    assert_eq!(fixture.registers[RDT / 4], (DESCRIPTORS - 1) as u32);
    assert_eq!(
        fixture
            .net
            .receive
            .descriptors
            .read::<u64>(4 * DESCRIPTOR + 8),
        0
    );
    assert_eq!(fixture.net.receive().unwrap(), None);
    assert_eq!(fixture.registers[RDT / 4], 4);
}

#[test]
fn receive_wraps_and_reoffers_every_descriptor_before_the_doorbell() {
    let mut fixture = Fixture::new();
    for count in 0..DESCRIPTORS * 3 {
        let index = count % DESCRIPTORS;
        fixture.inject(index, 60, RX_DONE | RX_EOP, 0, count as u8);
        assert_eq!(fixture.net.receive().unwrap(), Some(vec![count as u8; 60]));
        assert_eq!(
            fixture
                .net
                .receive
                .descriptors
                .read::<u64>(index * DESCRIPTOR),
            fixture.net.receive.address(index)
        );
        assert_eq!(
            fixture
                .net
                .receive
                .descriptors
                .read::<u64>(index * DESCRIPTOR + 8),
            0
        );
        // Linux's E1000_RX_BUFFER_WRITE: one tail write per sixteen.
        if (count + 1) % 16 == 0 {
            assert_eq!(fixture.registers[RDT / 4], index as u32);
        }
    }
    assert_eq!(fixture.net.receive.next, 0);
}

#[test]
fn link_loss_discards_queued_transmit_work_and_refuses_new_frames() {
    let mut fixture = Fixture::new();
    for _ in 0..3 {
        fixture.net.transmit(&[1; 60]).unwrap();
    }
    assert_eq!(fixture.registers[TDT / 4], 3);
    fixture.registers[STATUS / 4] = 0;
    assert!(!fixture.net.carrier());
    assert!(!fixture.net.transmit.pending());
    assert_eq!(fixture.registers[TDT / 4], 0);
    assert!(fixture.registers[TCTL / 4] & TCTL_EN != 0);
    assert_eq!(fixture.net.transmit(&[1; 60]), Err(LinkError::NoCarrier));
    fixture.registers[STATUS / 4] = STATUS_LU;
    fixture.net.transmit(&[2; 60]).unwrap();
    assert_eq!(fixture.registers[TDT / 4], 1);
}

#[test]
fn an_absent_function_is_never_reported_as_linked() {
    let mut fixture = Fixture::new();
    fixture.registers[STATUS / 4] = u32::MAX;
    assert!(!fixture.net.carrier());
    assert!(matches!(
        fixture.net.transmit(&[1; 60]),
        Err(LinkError::Adapter(_))
    ));
    fixture.registers[STATUS / 4] = STATUS_LU;
    assert!(!fixture.net.carrier());
}

#[test]
fn a_phy_hangs_only_when_both_error_counters_saturate() {
    for (errors, idle, hung) in [
        (u16::MAX, PHY_IDLE_ERRORS, true),
        (u16::MAX, 0x7f, false),
        (0xfffe, PHY_IDLE_ERRORS, false),
    ] {
        let model = Model::ready();
        model.phy.borrow_mut()[usize::from(PHY_RECEIVE_ERRORS)] = errors;
        model.phy.borrow_mut()[usize::from(PHY_GIGABIT_STATUS)] = idle;
        assert_eq!(phy_hung(&model, &ModelTimer::default()), hung);
        assert_eq!(model.read(EXTCNF_CTRL) & MDIO_OWN, 0);
    }
}

#[test]
fn station_addresses_reject_invalid_zero_and_multicast_nvm() {
    assert_eq!(
        station(0x5634_1202, RAH_VALID | 0xbc9a),
        Some(Mac([2, 0x12, 0x34, 0x56, 0x9a, 0xbc]))
    );
    assert_eq!(station(0x5634_1202, 0xbc9a), None);
    assert_eq!(station(0, RAH_VALID), None);
    assert_eq!(station(u32::MAX, u32::MAX), None);
}

struct Config(u32, u32);

impl ConfigSpace for Config {
    fn read8(&self, offset: u16) -> Result<u8, crate::bus::pci::ConfigError> {
        Ok(((match offset & !3 {
            0 => self.0,
            8 => self.1,
            _ => 0,
        }) >> ((offset & 3) * 8)) as u8)
    }
    fn read16(&self, offset: u16) -> Result<u16, crate::bus::pci::ConfigError> {
        Ok(((match offset & !3 {
            0 => self.0,
            8 => self.1,
            _ => 0,
        }) >> ((offset & 3) * 8)) as u16)
    }
    fn read32(&self, offset: u16) -> Result<u32, crate::bus::pci::ConfigError> {
        Ok((match offset & !3 {
            0 => self.0,
            8 => self.1,
            _ => 0,
        }) >> ((offset & 3) * 8))
    }
    fn write8(&mut self, _: u16, _: u8) -> Result<(), crate::bus::pci::ConfigError> {
        Err(crate::bus::pci::ConfigError::before_effect(
            crate::bus::pci::ConfigFailure::UnqualifiedControl,
        ))
    }
    fn write16(&mut self, _: u16, _: u16) -> Result<(), crate::bus::pci::ConfigError> {
        Err(crate::bus::pci::ConfigError::before_effect(
            crate::bus::pci::ConfigFailure::UnqualifiedControl,
        ))
    }
    fn write32(&mut self, _: u16, _: u32) -> Result<(), crate::bus::pci::ConfigError> {
        Err(crate::bus::pci::ConfigError::before_effect(
            crate::bus::pci::ConfigFailure::UnqualifiedControl,
        ))
    }
}

#[test]
fn match_is_restricted_to_82574l_and_ethernet_class() {
    for (id, class, expected) in [
        (0x10d3_8086, 0x0200_0000, true),
        (0x10d3_8086, 0, false),
        (0x15b8_8086, 0x0200_0000, false),
        (0x10d3_1234, 0x0200_0000, false),
    ] {
        let function = crate::bus::pci::Function::new(
            Address {
                segment: 0,
                bus: 0,
                device: 1,
                function: 0,
            },
            Config(id, class),
        )
        .unwrap();
        assert_eq!(matches(&function), expected);
    }
}

#[test]
fn minimum_failure_during_reinitialization_is_typed_and_blocks_later_device_effects() {
    let mut fixture = Fixture::new();
    let (timing, failed) = crate::timing::controlled_model(Clock {
        ticks_per_microsecond: 1,
    });
    fixture.net.clock = timing;
    failed.set(true);
    let expected = BlockError::PciPower(crate::bus::pci::power::Error::Clock);
    assert_eq!(
        fixture.net.reinitialize(),
        Err(LinkError::Pci(expected.clone()))
    );
    // Completed RX and an IRQ-capable path must also remain fenced.
    fixture.inject(0, 60, RX_DONE | RX_EOP, 0, 7);
    fixture.net.signalled = true;
    let receive = fixture.net.receive.descriptors.bytes().to_vec();
    let observed = fixture.registers.clone();
    for _ in 0..3 {
        assert!(!fixture.net.carrier());
        assert_eq!(
            fixture.net.transmit(&[1; 60]),
            Err(LinkError::Pci(expected.clone()))
        );
        assert_eq!(fixture.net.receive(), Err(LinkError::Pci(expected.clone())));
    }
    assert_eq!(fixture.net.receive.descriptors.bytes(), receive);
    assert_eq!(fixture.registers, observed);
}
