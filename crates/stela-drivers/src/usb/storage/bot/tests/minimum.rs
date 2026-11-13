// SPDX-License-Identifier: GPL-2.0-or-later
//! Isolated BOT target timing effects; numeric scheduling alone cannot clear.
use super::*;
use crate::bus::pci::power::Error;
fn fixture(memory: &mut [u64]) -> (Bot<Model>, Rc<RefCell<State>>) {
    let start = memory.as_mut_ptr() as u64;
    let io = model(
        start,
        start + core::mem::size_of_val(memory) as u64,
        vec![unit(0)],
    );
    let state = io.0.clone();
    let bot = Bot::new(io, 3, endpoints(), &mut dma(memory)).unwrap();
    (bot, state)
}
#[test]
fn nominal_reset_deadline_cannot_substitute_for_required_minimum() {
    let mut memory = vec![0u64; 32 * 1024];
    let (mut bot, state) = fixture(&mut memory);
    state.borrow_mut().fault = Fault::Phase;
    assert!(bot.command(0, &[0; 6], Data::None).is_err());
    state.borrow_mut().fault = Fault::Minimum;
    state.borrow_mut().now += 100 * RESET_RECOVERY_US;
    assert!(!bot.busy());
    assert!(bot.poisoned());
    assert!(matches!(bot.recovery, Some(Recovery::Settling(..))));
    assert!(state.borrow().clears.is_empty());
    assert!(!state.borrow().reset_minimum);
    assert_eq!(
        state
            .borrow()
            .order
            .iter()
            .filter(|x| matches!(x, Order::Minimum(_)))
            .count(),
        1
    );
    let before = (state.borrow().controls.len(), state.borrow().transfers);
    state.borrow_mut().fault = Fault::None;
    assert_eq!(
        bot.command(0, &[0; 6], Data::None),
        Err(BlockError::PciPower(Error::Interrupted))
    );
    assert_eq!(
        before,
        (state.borrow().controls.len(), state.borrow().transfers)
    );
    assert!(bot.buffer.present() && bot.wrapper.present());
}
#[test]
fn go_slow_failure_never_submits_data_status_or_reset_after_acknowledged_cbw() {
    let mut memory = vec![0u64; 32 * 1024];
    let (mut bot, state) = fixture(&mut memory);
    bot.flags = quirks::Flags::from_id(0x05e3, 0x0702, 0x0010, true).unwrap();
    state.borrow_mut().fault = Fault::Minimum;
    assert_eq!(
        bot.command(0, &scsi::inquiry(), Data::In(36)),
        Err(BlockError::PciPower(Error::Interrupted))
    );
    assert_eq!(state.borrow().transfers, 1);
    assert!(!state.borrow().controls.iter().any(|x| x[1] == RESET));
    assert!(bot.poisoned());
    assert!(bot.begun.is_some());
    assert!(bot.buffer.present() && bot.wrapper.present());
    let before = state.borrow().transfers;
    state.borrow_mut().fault = Fault::None;
    assert_eq!(
        bot.command(0, &scsi::inquiry(), Data::In(36)),
        Err(BlockError::PciPower(Error::Interrupted))
    );
    assert_eq!(state.borrow().transfers, before);
}
