// SPDX-License-Identifier: GPL-2.0-only
//! Cold engine containment returns registers only after all acknowledgements.
use super::*;

fn cold(asic: Asic) -> (Hardware<Reg, Timer>, Rc<RefCell<Model>>) {
    let (hardware, model) = model(asic, 0);
    {
        let mut state = model.borrow_mut();
        state.sram.insert(0xb54, FIRMWARE_MAGIC);
        state.sram.insert(0xb58, 0);
        for at in STOP_RX.into_iter().chain(STOP_TX).chain([
            MAC_RX_MODE,
            MAC_TX_MODE,
            HOSTCC_MODE,
            WDMAC_MODE,
        ]) {
            state.mac.insert(at, ENABLE | 0x100);
        }
        state.mac.insert(MAC_MODE, TRANSMIT_DATA_ENABLE);
    }
    (hardware, model)
}

#[test]
fn original_registers_return_after_engine_acknowledgements_without_reset_or_dma_start() {
    for asic in [Asic::Bcm5720, Asic::Bcm5761, Asic::Bcm5762] {
        let (hardware, model) = cold(asic);
        let registers = hardware
            .quiesce_cold()
            .unwrap_or_else(|(error, _)| panic!("{error:?}"));
        let state = model.borrow();
        assert_eq!(state.config[&4] & 0x406, 0x402);
        for at in STOP_RX.into_iter().chain(STOP_TX).chain([
            MAC_RX_MODE,
            MAC_TX_MODE,
            HOSTCC_MODE,
            WDMAC_MODE,
        ]) {
            assert_eq!(state.mac[&at] & ENABLE, 0, "{at:x}");
        }
        assert_eq!(state.mac[&MAC_MODE] & TRANSMIT_DATA_ENABLE, 0);
        assert!(!state.trace.iter().any(|event| matches!(
            event,
            Event::Write(0x6804, _) | Event::ConfigWrite16(4, 0x406)
        )));
        assert!(state.trace.contains(&Event::Write(FTQ_RESET, u32::MAX)));
        assert_eq!(state.dropped, 0);
        drop(state);
        drop(registers);
        assert_eq!(model.borrow().dropped, 1);
    }
}

#[test]
fn each_failed_engine_acknowledgement_retains_original_registers() {
    for stuck in STOP_RX
        .into_iter()
        .chain(STOP_TX)
        .chain([MAC_TX_MODE, HOSTCC_MODE, WDMAC_MODE])
    {
        let (hardware, model) = cold(Asic::Bcm5720);
        model.borrow_mut().stuck_stop = Some(stuck);
        let (error, hardware) = hardware
            .quiesce_cold()
            .err()
            .expect("failed stop must retain owner");
        assert_eq!(error, Error::StopTimeout(stuck));
        drop(hardware);
        assert_eq!(model.borrow().dropped, 0);
    }
}

#[test]
fn live_bus_master_or_failed_decode_never_reaches_vendor_engines() {
    for bus_master in [false, true] {
        let (hardware, model) = cold(Asic::Bcm5720);
        if bus_master {
            model.borrow_mut().config.insert(4, 4);
        } else {
            model.borrow_mut().ignored_config_write = Some(4);
        }
        let (error, hardware) = hardware.quiesce_cold().err().expect("uncontained config");
        assert_eq!(
            error,
            if bus_master {
                Error::UnsupportedBoard
            } else {
                Error::ConfigDidNotLatch
            }
        );
        assert!(
            !model
                .borrow()
                .trace
                .iter()
                .any(|event| matches!(event, Event::Write(_, _)))
        );
        drop(hardware);
        assert_eq!(model.borrow().dropped, 0);
    }
}

#[test]
fn managed_firmware_stops_inherited_engines_and_an_unsigned_board_refuses() {
    // ASF firmware no longer refuses containment: the engines it shares
    // still stop, as tg3_init_one halts a chip a previous driver left on.
    let (hardware, model) = cold(Asic::Bcm5720);
    model.borrow_mut().sram.insert(0xb58, 0x80);
    let registers = hardware
        .quiesce_cold()
        .unwrap_or_else(|(error, _)| panic!("{error:?}"));
    assert!(
        model
            .borrow()
            .trace
            .iter()
            .any(|event| matches!(event, Event::Write(FTQ_RESET, _)))
    );
    drop(registers);
    let (hardware, model) = cold(Asic::Bcm5720);
    model.borrow_mut().sram.insert(0xb54, 0);
    let (error, hardware) = hardware.quiesce_cold().err().expect("unsigned board");
    assert_eq!(error, Error::UnsignedBoard);
    assert!(
        !model
            .borrow()
            .trace
            .iter()
            .any(|event| matches!(event, Event::Write(FTQ_RESET, _)))
    );
    drop(hardware);
    assert_eq!(model.borrow().dropped, 0);
}

#[test]
fn any_cold_register_or_timer_error_retains_the_original_epoch() {
    let (hardware, model) = cold(Asic::Bcm5720);
    let registers = hardware
        .quiesce_cold()
        .unwrap_or_else(|(error, _)| panic!("{error:?}"));
    let operations = model.borrow().io_count;
    let waits = model.borrow().delay_count;
    drop(registers);
    for operation in 1..=operations {
        let (hardware, model) = cold(Asic::Bcm5720);
        model.borrow_mut().fail_at = Some(operation);
        let (_, hardware) = hardware
            .quiesce_cold()
            .err()
            .expect("injected access failure");
        drop(hardware);
        assert_eq!(model.borrow().dropped, 0, "operation {operation}");
    }
    for wait in 1..=waits {
        let (hardware, model) = cold(Asic::Bcm5720);
        model.borrow_mut().fail_delay = Some(wait);
        let (error, hardware) = hardware
            .quiesce_cold()
            .err()
            .expect("injected timer failure");
        assert_eq!(error, Error::Timing(crate::bus::pci::power::Error::Clock));
        drop(hardware);
        assert_eq!(model.borrow().dropped, 0, "wait {wait}");
    }
}

/// A function a previous OS left in `state` with PME armed, its power
/// management capability at 0x48 and two memory BARs.
fn powered_down(asic: Asic, state: u32) -> (Hardware<Reg, Timer>, Rc<RefCell<Model>>) {
    let (hardware, model) = cold(asic);
    {
        let mut m = model.borrow_mut();
        m.config.insert(4, 1 << 20);
        m.config.insert(0x34, 0x48);
        m.config.insert(0x48, 0xc803_0001);
        m.config.insert(0x4c, 0x0100 | state);
        m.config.insert(0x10, 0xfe40_0004);
        m.config.insert(0x18, 0xfe41_0004);
    }
    (hardware, model)
}

#[test]
fn a_function_left_in_d3hot_is_brought_to_d0_with_its_bars_before_mmio() {
    for asic in [Asic::Bcm5720, Asic::Bcm5761, Asic::Bcm5762] {
        let (hardware, model) = powered_down(asic, 3);
        let registers = hardware
            .quiesce_cold()
            .unwrap_or_else(|(error, _)| panic!("{error:?}"));
        let state = model.borrow();
        // pci_power_up: PMCSR written whole as zero (D0, PME off), the
        // D3hot recovery time waited, the soft-reset BARs written back.
        assert_eq!(state.config[&0x4c] & 0x103, 0);
        let at = |wanted: &Event| state.trace.iter().position(|event| event == wanted);
        let d0 = at(&Event::ConfigWrite16(0x4c, 0)).unwrap();
        let settled = at(&Event::Delay(10_000)).unwrap();
        let bar = at(&Event::ConfigWrite(0x10, 0xfe40_0004)).unwrap();
        assert!(at(&Event::ConfigWrite(0x18, 0xfe41_0004)).is_some());
        let first_mmio = state
            .trace
            .iter()
            .position(|event| matches!(event, Event::Read(..) | Event::Write(..)))
            .unwrap();
        assert!(d0 < settled && settled < bar && bar < first_mmio);
        drop(state);
        drop(registers);
    }
}

#[test]
fn d0_without_soft_reset_keeps_bars_and_a_refused_d0_stops_before_mmio() {
    let (hardware, model) = powered_down(Asic::Bcm5720, 3 | 8);
    let registers = hardware
        .quiesce_cold()
        .unwrap_or_else(|(error, _)| panic!("{error:?}"));
    assert!(
        !model
            .borrow()
            .trace
            .iter()
            .any(|event| matches!(event, Event::ConfigWrite(0x10..=0x24, _)))
    );
    drop(registers);
    let (hardware, model) = powered_down(Asic::Bcm5720, 3);
    model.borrow_mut().ignored_config_write = Some(0x4c);
    let (error, hardware) = hardware.quiesce_cold().err().expect("still in D3hot");
    assert_eq!(error, Error::ConfigDidNotLatch);
    assert!(
        !model
            .borrow()
            .trace
            .iter()
            .any(|event| matches!(event, Event::Read(..) | Event::Write(..)))
    );
    drop(hardware);
    assert_eq!(model.borrow().dropped, 0);
}
