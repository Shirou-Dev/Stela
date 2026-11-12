use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use core::cell::{Cell, RefCell};

#[derive(Default)]
pub(in super::super) struct State {
    pub(in super::super) registers: BTreeMap<usize, u32>,
    pub(in super::super) phy: BTreeMap<u16, u16>,
    mmd: BTreeMap<(u16, u16), u16>,
    mmd_control: u16,
    mmd_address: u16,
    writes: Vec<(usize, u32)>,
    nvm: Vec<u16>,
}
pub(in super::super) struct Model {
    pub(in super::super) state: RefCell<State>,
    reads: Cell<usize>,
    fail_read: Cell<Option<usize>>,
    pub(in super::super) mdio_count: Cell<usize>,
    mdio_fail: Cell<Option<usize>>,
    mdio_silent: Cell<bool>,
    master_stuck: Cell<bool>,
    reset_stuck: Cell<bool>,
    autoload_stuck: Cell<bool>,
    phy_reset_stuck: Cell<bool>,
    firmware_busy: Cell<bool>,
    software_busy: Cell<bool>,
    sw_semaphore_refused: Cell<bool>,
    elapsed: Cell<u64>,
}
impl Model {
    fn ready(flash: bool) -> Self {
        let mut state = State {
            nvm: vec![0; 64],
            ..State::default()
        };
        state
            .registers
            .insert(EECD, AUTO_READ_DONE | if flash { FLASH_PRESENT } else { 0 });
        state.registers.insert(PHPM, 1 << 8 | 1 << 5);
        state.registers.insert(CTRL, 0x18001f01);
        state.registers.insert(IPCNFG, 0xa51f);
        state.registers.insert(EEER, 0xa5071234);
        state.phy.extend([
            (0, 0x0800),
            (2, 0x67c9),
            (3, 0xdc01),
            (4, 0xafe1),
            (9, 0xf9ff),
        ]);
        state.mmd.insert((MMD_AN, MMD_MULTIGIG), 0x5501);
        state.nvm[63] = 0xbaba;
        Self {
            state: RefCell::new(state),
            reads: Cell::new(0),
            fail_read: Cell::new(None),
            mdio_count: Cell::new(0),
            mdio_fail: Cell::new(None),
            mdio_silent: Cell::new(false),
            master_stuck: Cell::new(false),
            reset_stuck: Cell::new(false),
            autoload_stuck: Cell::new(false),
            phy_reset_stuck: Cell::new(false),
            firmware_busy: Cell::new(false),
            software_busy: Cell::new(false),
            sw_semaphore_refused: Cell::new(false),
            elapsed: Cell::new(0),
        }
    }
}
impl Registers for Model {
    fn read(&self, register: usize) -> u32 {
        let count = self.reads.get() + 1;
        self.reads.set(count);
        if self.fail_read.get() == Some(count) {
            return u32::MAX;
        }
        if register == STATUS && self.master_stuck.get() {
            return MASTER_ENABLED;
        }
        if register == SWSM && self.software_busy.get() {
            return SMBI;
        }
        if register == SW_FW_SYNC && self.firmware_busy.get() {
            return PHY_SYNC << 16;
        }
        self.state
            .borrow()
            .registers
            .get(&register)
            .copied()
            .unwrap_or(0)
    }
    fn write(&self, register: usize, value: u32) {
        let mut state = self.state.borrow_mut();
        state.writes.push((register, value));
        state.registers.insert(register, value);
        if register == SWSM && self.sw_semaphore_refused.get() {
            state.registers.insert(SWSM, 0);
        }
        if register == CTRL && value & MAC_RESET != 0 && !self.reset_stuck.get() {
            state.registers.insert(CTRL, 0);
            let eecd = state.registers[&EECD];
            state.registers.insert(
                EECD,
                if self.autoload_stuck.get() {
                    eecd & !AUTO_READ_DONE
                } else {
                    eecd | AUTO_READ_DONE
                },
            );
        }
        if register == CTRL && value & PHY_RESET != 0 {
            state.mmd_control = 0;
            let phpm = state.registers[&PHPM];
            state.registers.insert(
                PHPM,
                if self.phy_reset_stuck.get() {
                    phpm & !(1 << 8)
                } else {
                    phpm | 1 << 8
                },
            );
        }
        if register == EERD {
            let word = ((value >> 2) & 0x3fff) as usize;
            let data = state.nvm[word];
            state
                .registers
                .insert(EERD, u32::from(data) << 16 | value | 2);
        }
        if register != MDIC {
            return;
        }
        let count = self.mdio_count.get() + 1;
        self.mdio_count.set(count);
        if self.mdio_silent.get() {
            return;
        }
        if self.mdio_fail.get() == Some(count) {
            state
                .registers
                .insert(MDIC, value | MDIC_READY | MDIC_ERROR);
            return;
        }
        assert_eq!(value & (31 << 21), 0, "real donor integrated PHY address");
        let reg = ((value >> 16) & 31) as u16;
        let data = if value & MDIC_WRITE != 0 {
            let data = value as u16;
            match reg {
                MMD_CONTROL => state.mmd_control = data,
                MMD_DATA if state.mmd_control & 0x4000 == 0 => state.mmd_address = data,
                MMD_DATA => {
                    let key = (state.mmd_control & 31, state.mmd_address);
                    state.mmd.insert(key, data);
                }
                _ => {
                    state.phy.insert(reg, data);
                }
            }
            data
        } else {
            match reg {
                MMD_CONTROL => state.mmd_control,
                MMD_DATA if state.mmd_control & 0x4000 != 0 => state
                    .mmd
                    .get(&(state.mmd_control & 31, state.mmd_address))
                    .copied()
                    .unwrap_or(0),
                _ => state.phy.get(&reg).copied().unwrap_or(0),
            }
        };
        state
            .registers
            .insert(MDIC, value & !0xffff | u32::from(data) | MDIC_READY);
    }
}
impl Timer for Model {
    fn delay(&self, microseconds: u64) -> Result<(), BlockError> {
        self.elapsed.set(self.elapsed.get() + microseconds);
        Ok(())
    }
}

#[test]
fn complete_initialization_replaces_inherited_phy_and_mac_state_for_all_declared_ids() {
    for device in super::super::DEVICES {
        for flash in [false, true] {
            let model = Model::ready(flash);
            let mut hw = Hardware::new(&model, &model).unwrap();
            assert_eq!(hw.initialize(), Ok(0x67c9dc01), "device {device:04x}");
            let state = model.state.borrow();
            assert_eq!(state.phy[&0] & 0x1a00, 0x1200);
            // Symmetric and asymmetric PAUSE, all 10/100 modes, other bits kept.
            assert_eq!(state.phy[&4], 0xafe1);
            assert_eq!(state.registers[&FCT], 0x8808);
            assert_eq!(state.registers[&FCAH], 0x0100);
            assert_eq!(state.registers[&FCAL], 0x00c2_8001);
            assert_eq!(state.registers[&FCTTV], 0xffff);
            assert_eq!(state.registers[&FCRTH], 23552);
            assert_eq!(state.registers[&FCRTL], 23536 | FCRTL_XONE);
            assert_eq!(state.phy[&9], 0xfaff); // No1G half duplex, 1G full.
            assert_eq!(state.mmd[&(7, 32)], 0x5581);
            assert_eq!(state.mmd_control, 0);
            assert_eq!(state.registers[&SW_FW_SYNC] & 3, 0);
            assert_eq!(state.registers[&SWSM] & 3, 0);
            assert_eq!(state.registers[&CTRL] & (0x18001f01 | MASTER_DISABLE), 0);
            assert_eq!(state.registers[&CTRL] & (1 << 6), 1 << 6);
            assert_eq!(state.registers[&IPCNFG], 0xa503);
            assert_eq!(state.registers[&EEER], 0xa5001234);
            assert_eq!(state.registers[&RXPBS], 0xa2);
            assert_eq!(state.registers[&TXPBS], 0x04000014);
            assert_eq!(state.registers[&RLPML], 1518);
            assert!(
                state
                    .writes
                    .iter()
                    .any(|&(r, v)| r == CTRL && v & MAC_RESET != 0)
            );
            assert!(
                !state
                    .writes
                    .iter()
                    .any(|&(r, v)| r == CTRL && v & (1 << 29) != 0)
            );
            for index in 1..16 {
                assert_eq!(state.registers[&(RAL + index * 8 + 4)], 0);
            }
            assert!(model.elapsed.get() >= 10_000);
        }
    }
}

#[test]
fn drain_mac_reset_autoload_and_phy_reset_deadlines_never_look_successful() {
    for failure in 0..3 {
        let model = Model::ready(false);
        match failure {
            0 => model.master_stuck.set(true),
            1 => model.reset_stuck.set(true),
            _ => model.autoload_stuck.set(true),
        }
        let mut hw = Hardware::new(&model, &model).unwrap();
        assert_eq!(hw.initialize(), Err(BlockError::Timeout));
        let state = model.state.borrow();
        assert!(!state.writes.iter().any(|&(r, _)| r == RXPBS));
        if failure == 0 {
            assert!(
                !state
                    .writes
                    .iter()
                    .any(|&(r, v)| r == CTRL && v & MAC_RESET != 0)
            );
        }
        assert!(model.elapsed.get() < 2_000_000);
    }
}

#[test]
fn a_phy_reset_completion_that_never_comes_is_waited_for_then_passed() {
    // igc_phy_hw_reset logs the missing PHY_RST_COMP and carries on; the
    // PHY identity read that follows still proves the PHY answers.
    let model = Model::ready(false);
    model.phy_reset_stuck.set(true);
    assert_eq!(
        Hardware::new(&model, &model).unwrap().initialize(),
        Ok(0x67c9_dc01)
    );
    assert!(model.elapsed.get() >= 10_000 && model.elapsed.get() < 2_000_000);
    // Powered up (BMCR power-down clear), autonegotiation restarted.
    assert_eq!(model.state.borrow().phy[&0] & 0x1a00, 0x1200);
}

#[test]
fn every_failed_register_read_refuses_initialization() {
    let model = Model::ready(true);
    Hardware::new(&model, &model).unwrap().initialize().unwrap();
    let reads = model.reads.get();
    for failure in 1..=reads {
        let model = Model::ready(true);
        model.fail_read.set(Some(failure));
        let result = Hardware::new(&model, &model).and_then(|mut h| h.initialize());
        assert!(result.is_err(), "failed read {failure}/{reads}");
    }
}

#[test]
fn mdio_failures_release_software_ownership() {
    let model = Model::ready(false);
    Hardware::new(&model, &model).unwrap().initialize().unwrap();
    for failure in 1..=model.mdio_count.get() {
        let model = Model::ready(false);
        model.mdio_fail.set(Some(failure));
        assert!(Hardware::new(&model, &model).unwrap().initialize().is_err());
        assert_eq!(model.state.borrow().registers[&SW_FW_SYNC] & PHY_SYNC, 0);
        assert!(!model.state.borrow().writes.iter().any(|&(r, _)| r == RXPBS));
    }
    let model = Model::ready(false);
    model.mdio_silent.set(true);
    assert_eq!(
        Hardware::new(&model, &model).unwrap().initialize(),
        Err(BlockError::Timeout)
    );
}

#[test]
fn management_owned_phy_is_neither_reset_nor_renegotiated() {
    // igc_check_reset_block: SOL/IDE-R firmware owns the PHY and its link;
    // Linux skips the PHY reset and the link setup and starts the MAC.
    let model = Model::ready(false);
    model
        .state
        .borrow_mut()
        .registers
        .insert(MANC, MANC_BLOCK_PHY_RESET);
    let advertised = model.state.borrow().phy[&4];
    assert_eq!(
        Hardware::new(&model, &model).unwrap().initialize(),
        Ok(0x67c9_dc01)
    );
    let state = model.state.borrow();
    assert!(
        !state
            .writes
            .iter()
            .any(|&(r, v)| r == CTRL && v & PHY_RESET != 0)
    );
    assert_eq!(state.phy[&4], advertised);
    // igc_power_up_link still powers the PHY up; autonegotiation is not
    // restarted under the firmware's link.
    assert_eq!(state.phy[&0], 0);
    assert!(state.writes.iter().any(|&(r, _)| r == RXPBS));
}

#[test]
fn firmware_management_and_semaphore_refusals_cannot_be_bypassed() {
    for failure in 1..4 {
        let model = Model::ready(false);
        match failure {
            1 => model.firmware_busy.set(true),
            2 => model.software_busy.set(true),
            _ => model.sw_semaphore_refused.set(true),
        }
        assert!(Hardware::new(&model, &model).unwrap().initialize().is_err());
        assert_eq!(model.mdio_count.get(), 0);
    }
}

#[test]
fn programmed_flash_checksum_and_observed_phy_identity_are_not_invented() {
    let model = Model::ready(true);
    model.state.borrow_mut().nvm[10] = 1;
    assert_eq!(
        Hardware::new(&model, &model).unwrap().initialize(),
        Err(BlockError::Unsupported("igc NVM checksum mismatch"))
    );
    assert_eq!(model.mdio_count.get(), 0);
    for upper in [0, 0xffff] {
        let model = Model::ready(false);
        model.state.borrow_mut().phy.insert(2, upper);
        assert!(Hardware::new(&model, &model).unwrap().initialize().is_err());
    }
}

pub(in super::super) fn linked(status: u32, partner: u16) -> Model {
    let model = Model::ready(false);
    {
        let mut state = model.state.borrow_mut();
        state
            .registers
            .extend([(STATUS, status), (RXPBS, 34 | 2 << 6)]);
        state.phy.extend([
            (PHY_STATUS, MII_LINK | MII_AUTONEG_COMPLETE),
            (PHY_ADVERTISEMENT, 0x0de0),
            (PHY_PARTNER, partner),
        ]);
    }
    model
}

#[test]
fn copper_link_check_resolves_pause_and_programs_ltr_from_the_negotiated_link() {
    let full = STATUS_FD | STATUS_SPEED_1000 | STATUS_SPEED_2500;
    for (partner, mode) in [
        (PAUSE, FlowControl::Full),
        (PAUSE | ASYMMETRIC_PAUSE, FlowControl::Full),
        (ASYMMETRIC_PAUSE, FlowControl::ReceivePause),
        // Linux's receive-pause fallback for a requested full mode.
        (0, FlowControl::ReceivePause),
    ] {
        let model = linked(full, partner);
        let mut hw = Hardware::new(&model, &model).unwrap();
        let link = hw.check_for_copper_link().unwrap().unwrap();
        assert_eq!(
            link,
            Negotiated {
                speed: 2500,
                full_duplex: true,
                flow_control: mode,
            }
        );
        let state = model.state.borrow();
        let ctrl = state.registers[&CTRL] & (CTRL_RFCE | CTRL_TFCE);
        let expected = match mode {
            FlowControl::Full => CTRL_RFCE | CTRL_TFCE,
            _ => CTRL_RFCE,
        };
        assert_eq!(ctrl, expected, "partner {partner:#x}");
        // 34 KiB at 2.5 Gb/s is 111411 ns: 108 units of 1024 ns, less one.
        assert_eq!(state.registers[&LTRMINV], LTR_SNOOP | 107 | 2 << 10);
        assert_eq!(state.registers[&LTRMAXV], LTR_SNOOP | 107 | 2 << 10);
        assert_eq!(state.registers[&SW_FW_SYNC] & PHY_SYNC, 0);
    }

    // Without receive-pause ability on our side, the partner's symmetric
    // and asymmetric bits select transmit pause.
    let model = linked(STATUS_FD | STATUS_SPEED_100, PAUSE | ASYMMETRIC_PAUSE);
    model
        .state
        .borrow_mut()
        .phy
        .insert(PHY_ADVERTISEMENT, ASYMMETRIC_PAUSE);
    let mut hw = Hardware::new(&model, &model).unwrap();
    let link = hw.check_for_copper_link().unwrap().unwrap();
    assert_eq!(
        (link.speed, link.flow_control),
        (100, FlowControl::TransmitPause)
    );
    assert_eq!(
        model.state.borrow().registers[&CTRL] & (CTRL_RFCE | CTRL_TFCE),
        CTRL_TFCE
    );

    // Half duplex never pauses; 10 Mb/s needs the 32768 ns scale.
    let model = linked(0, PAUSE);
    model
        .state
        .borrow_mut()
        .registers
        .insert(CTRL, CTRL_RFCE | CTRL_TFCE);
    let mut hw = Hardware::new(&model, &model).unwrap();
    let link = hw.check_for_copper_link().unwrap().unwrap();
    assert_eq!(
        (link.speed, link.full_duplex, link.flow_control),
        (10, false, FlowControl::None)
    );
    let state = model.state.borrow();
    assert_eq!(state.registers[&CTRL] & (CTRL_RFCE | CTRL_TFCE), 0);
    assert_eq!(state.registers[&LTRMINV], LTR_SNOOP | 849 | 3 << 10);
    drop(state);

    // Incomplete autonegotiation keeps the MAC's pause enables.
    let model = linked(STATUS_FD | STATUS_SPEED_1000, PAUSE);
    {
        let mut state = model.state.borrow_mut();
        state.phy.insert(PHY_STATUS, MII_LINK);
        state.registers.insert(CTRL, CTRL_TFCE);
    }
    let mut hw = Hardware::new(&model, &model).unwrap();
    let link = hw.check_for_copper_link().unwrap().unwrap();
    assert_eq!(
        (link.speed, link.flow_control),
        (1000, FlowControl::TransmitPause)
    );
    assert_eq!(model.state.borrow().registers[&CTRL], CTRL_TFCE);
}

#[test]
fn copper_link_check_reports_no_link_without_touching_pause_or_ltr() {
    let model = linked(STATUS_FD | STATUS_SPEED_1000, PAUSE);
    model.state.borrow_mut().phy.insert(PHY_STATUS, 0);
    let mut hw = Hardware::new(&model, &model).unwrap();
    assert_eq!(hw.check_for_copper_link(), Ok(None));
    let state = model.state.borrow();
    assert!(!state.registers.contains_key(&LTRMINV));
    assert!(!state.writes.iter().any(|&(r, _)| r == CTRL));
    drop(state);

    // A failed PHY exchange is no link; an absent function is an error.
    let model = linked(STATUS_FD | STATUS_SPEED_1000, PAUSE);
    model.mdio_fail.set(Some(1));
    let mut hw = Hardware::new(&model, &model).unwrap();
    assert_eq!(hw.check_for_copper_link(), Ok(None));
    assert_eq!(model.state.borrow().registers[&SW_FW_SYNC] & PHY_SYNC, 0);
    let model = linked(STATUS_FD | STATUS_SPEED_1000, PAUSE);
    model.software_busy.set(true);
    let mut hw = Hardware::new(&model, &model).unwrap();
    assert_eq!(hw.check_for_copper_link(), Ok(None));
    let model = linked(STATUS_FD | STATUS_SPEED_1000, PAUSE);
    let mut hw = Hardware::new(&model, &model).unwrap();
    model.fail_read.set(Some(model.reads.get() + 1));
    assert_eq!(
        hw.check_for_copper_link(),
        Err(BlockError::Device { status: u32::MAX })
    );

    let model = linked(STATUS_FD | STATUS_SPEED_1000, PAUSE);
    model.state.borrow_mut().phy.insert(PHY_GIGABIT_STATUS, 0);
    let mut hw = Hardware::new(&model, &model).unwrap();
    assert_eq!(hw.remote_receiver_ready(), Ok(false));
    model
        .state
        .borrow_mut()
        .phy
        .insert(PHY_GIGABIT_STATUS, REMOTE_RECEIVER_OK);
    assert_eq!(hw.remote_receiver_ready(), Ok(true));
}

#[test]
fn initialization_clears_every_linux_counter_and_statistics_accumulate_whole_octet_pairs() {
    // Linux's 67 counters, each read once; a failed read refuses
    // initialization like every other register read.
    let model = Model::ready(false);
    Hardware::new(&model, &model).unwrap().initialize().unwrap();
    let after = model.reads.get();
    assert_eq!(COUNTERS.len() + 1, 67);
    let model = Model::ready(false);
    model.fail_read.set(Some(after));
    assert!(Hardware::new(&model, &model).unwrap().initialize().is_err());

    let model = Model::ready(false);
    {
        let mut state = model.state.borrow_mut();
        state.registers.extend([
            (0x4000, 2),     // CRCERRS
            (MPC, 3),        // MPC
            (0x4074, 10),    // GPRC
            (0x4088, 5),     // GORCL
            (0x408c, 1),     // GORCH
            (0x4080, 7),     // GPTC
            (0x4090, 0x400), // GOTCL
            (0x4054, 4),     // XOFFTXC
        ]);
    }
    let mut statistics = Statistics::default();
    statistics.accumulate(&model).unwrap();
    statistics.accumulate(&model).unwrap();
    assert_eq!(statistics.crc_errors, 4);
    assert_eq!(statistics.missed, 6);
    assert_eq!(statistics.good_received, 20);
    assert_eq!(statistics.good_octets_received, 2 * (1 << 32 | 5));
    assert_eq!(statistics.good_transmitted, 14);
    assert_eq!(statistics.good_octets_transmitted, 0x800);
    assert_eq!(statistics.xoff_transmitted, 8);
    let before = statistics;
    model.state.borrow_mut().registers.insert(STATUS, u32::MAX);
    assert!(statistics.accumulate(&model).is_err());
    assert_eq!(statistics, before);
}

#[test]
fn stop_disables_both_directions_before_the_reset_and_release_returns_control() {
    let model = Model::ready(false);
    {
        let mut state = model.state.borrow_mut();
        state.registers.extend([
            (RCTL, RCTL_EN | 1 << 15),
            (TCTL, TCTL_EN | 1 << 3),
            (CTRL_EXT, DRV_LOAD | 1),
        ]);
    }
    let hw = Hardware::new(&model, &model).unwrap();
    hw.stop(DROP_MASTER_POLLS).unwrap();
    hw.release_control().unwrap();
    let state = model.state.borrow();
    let position = |entry| state.writes.iter().position(|&w| w == entry).unwrap();
    let reset = state
        .writes
        .iter()
        .position(|&(r, v)| r == CTRL && v & MAC_RESET != 0)
        .unwrap();
    assert!(position((RCTL, 1 << 15)) < reset);
    assert!(position((TCTL, 1 << 3)) < reset);
    assert_eq!(state.registers[&CTRL_EXT], 1);
    assert!(model.elapsed.get() >= 20_000);
    drop(state);

    // An incomplete drain or reset is never a stop, and a drop's stop ends
    // well inside a processor's exit.
    for stuck in [0, 1] {
        let model = Model::ready(false);
        if stuck == 0 {
            model.master_stuck.set(true);
        } else {
            model.reset_stuck.set(true);
        }
        assert_eq!(
            Hardware::new(&model, &model)
                .unwrap()
                .stop(DROP_MASTER_POLLS),
            Err(BlockError::Timeout)
        );
        assert!(model.elapsed.get() < 120_000, "{}", model.elapsed.get());
    }
}

#[test]
fn receive_fifo_flush_applies_the_ipv6_erratum_and_flushes_only_for_manageability() {
    let model = Model::ready(false);
    model.state.borrow_mut().registers.insert(RFCTL, 1 << 3);
    flush_receive_fifo(&model, &model).unwrap();
    let state = model.state.borrow();
    assert_eq!(state.writes, [(RFCTL, 1 << 3 | RFCTL_IPV6_EX_DIS)]);
    drop(state);

    let model = Model::ready(false);
    {
        let mut state = model.state.borrow_mut();
        state.registers.extend([
            (MANC, MANC_RCV_TCO_EN),
            (RFCTL, RFCTL_LEF),
            (RLPML, 1518),
            (RCTL, RCTL_SBP | 1 << 15),
            (rxdctl(0), RXDCTL_ENABLE | 0x0808),
            (rxdctl(2), RXDCTL_ENABLE),
        ]);
    }
    flush_receive_fifo(&model, &model).unwrap();
    let state = model.state.borrow();
    let rejecting = 1 << 15 | RCTL_LPE;
    let position = |entry| state.writes.iter().position(|&w| w == entry).unwrap();
    // Queues stop before receive briefly enables with every packet rejected.
    assert!(position((rxdctl(0), 0x0808)) < position((RCTL, rejecting)));
    assert!(position((RCTL, rejecting)) < position((RCTL, rejecting | RCTL_EN)));
    assert!(position((RLPML, 0)) < position((RCTL, rejecting | RCTL_EN)));
    assert!(position((RFCTL, RFCTL_IPV6_EX_DIS)) < position((RCTL, rejecting | RCTL_EN)));
    // Then every original setting returns, with the erratum kept.
    assert_eq!(state.registers[&rxdctl(0)], RXDCTL_ENABLE | 0x0808);
    assert_eq!(state.registers[&rxdctl(2)], RXDCTL_ENABLE);
    assert_eq!(state.registers[&RCTL], RCTL_SBP | 1 << 15);
    assert_eq!(state.registers[&RLPML], 1518);
    assert_eq!(state.registers[&RFCTL], RFCTL_LEF | RFCTL_IPV6_EX_DIS);
    assert!(model.elapsed.get() >= 3_000);
    drop(state);

    for failure in 1..=4 {
        let model = Model::ready(false);
        model
            .state
            .borrow_mut()
            .registers
            .insert(MANC, MANC_RCV_TCO_EN);
        model.fail_read.set(Some(failure));
        assert!(flush_receive_fifo(&model, &model).is_err());
    }
}

#[test]
#[ignore = "oracle: STELA_IGC_AUTONEG_ORACLE"]
fn unchanged_linux_advertisement_matches_real_mdio_and_mmd_operations() {
    extern crate std;
    let path = std::env::var("STELA_IGC_AUTONEG_ORACLE").unwrap();
    let trace = std::fs::read_to_string(path).unwrap();
    let mut cases = 0;
    for line in trace.lines() {
        let values: Vec<u16> = line
            .split_whitespace()
            .map(|v| u16::from_str_radix(v, 16).unwrap())
            .collect();
        assert_eq!(values.len(), 6);
        let model = Model::ready(false);
        {
            let mut state = model.state.borrow_mut();
            state.phy.insert(4, values[0]);
            state.phy.insert(9, values[1]);
            state.mmd.insert((7, 32), values[2]);
        }
        Hardware::new(&model, &model).unwrap().initialize().unwrap();
        let state = model.state.borrow();
        assert_eq!(
            [state.phy[&4], state.phy[&9], state.mmd[&(7, 32)]],
            values[3..]
        );
        cases += 1;
    }
    assert_eq!(cases, 4096);
}

/// The same initialization driven in slices, as a transmit-hang reset runs
/// it: every slice waits at most 60 ms, and the outcome matches the
/// blocking run's, for a clean start and for each stuck or busy step.
#[test]
fn a_sliced_initialization_matches_the_blocking_one_and_waits_little_per_call() {
    let models: [fn(&Model); 7] = [
        |_| {},
        |model| model.master_stuck.set(true),
        |model| model.reset_stuck.set(true),
        |model| model.phy_reset_stuck.set(true),
        |model| model.firmware_busy.set(true),
        |model| model.software_busy.set(true),
        |model| model.mdio_silent.set(true),
    ];
    for (case, prepare) in models.into_iter().enumerate() {
        for flash in [false, true] {
            let blocking = Model::ready(flash);
            prepare(&blocking);
            let expected = Hardware::new(&blocking, &blocking).unwrap().initialize();
            let model = Model::ready(flash);
            prepare(&model);
            let slice = Slice::new();
            let mut hw = Hardware::new(&model, &model).unwrap().sliced(&slice);
            let mut task = pin!(hw.initialize_steps());
            let mut context = Context::from_waker(Waker::noop());
            let mut calls = 0;
            let result = loop {
                slice.refill();
                let before = model.elapsed.get();
                let poll = task.as_mut().poll(&mut context);
                let waited = model.elapsed.get() - before;
                assert!(waited <= 60_000, "case {case}: {waited}");
                calls += 1;
                if let Poll::Ready(result) = poll {
                    break result;
                }
            };
            assert_eq!(result, expected, "case {case} flash {flash}");
            assert_eq!(model.elapsed.get(), blocking.elapsed.get(), "case {case}");
            if model.elapsed.get() > 100_000 {
                assert!(calls > 1, "case {case}");
            }
        }
    }
}
