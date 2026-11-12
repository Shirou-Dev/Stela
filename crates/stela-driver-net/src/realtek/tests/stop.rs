// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! The stop a dropped adapter makes: Linux `rtl8169_cleanup`.
use super::*;

/// The model for `version`'s family, receiving and with its MAC enabled.
fn running(time: &Time, version: u8) -> Model {
    let model = match version {
        28 | 31 => Model::dp(time, version, false),
        61.. => Model::nbase(time),
        40.. => Model::modern(time),
        _ => Model::ready(time),
    };
    {
        let mut s = model.state.borrow_mut();
        Model::store32(&mut s, RX_CONFIG, RX_FIFO_THRESHOLD | RX_ACCEPT_MASK);
        s.bytes[COMMAND] = ENABLE;
        s.writes.clear();
    }
    model
}

fn implemented() -> impl Iterator<Item = u8> {
    (2..=70).filter(|&version| {
        Revision {
            version,
            ..revision(2)
        }
        .implemented()
    })
}

/// Interrupts are masked, then receive closed, before the reset; the
/// reset's completion is the stop's result. Every implemented revision
/// stops within 100 ms of waits, well inside a processor's exit.
#[test]
fn a_stop_masks_closes_receive_and_resets_the_mac_within_an_exit() {
    for version in implemented() {
        let time = Time::default();
        let model = running(&time, version);
        let hardware = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(hardware.stop(), Ok(()), "{version}");
        assert!(time.now() < 100_000, "{version}: {}", time.now());
        let s = model.state.borrow();
        assert_eq!(Model::raw32(&s, RX_CONFIG), RX_FIFO_THRESHOLD, "{version}");
        let at = |found: &dyn Fn(usize, u32) -> bool| {
            s.writes
                .iter()
                .position(|&(offset, value, _)| found(offset, value))
                .unwrap_or_else(|| panic!("{version}"))
        };
        let mask = if version >= 61 {
            NBASE_INTERRUPT_MASK
        } else {
            INTERRUPT_MASK
        };
        let masked = at(&|offset, value| offset == mask && value == 0);
        let closed = at(&|offset, _| offset == RX_CONFIG);
        let reset = at(&|offset, value| offset == COMMAND && value as u8 & RESET != 0);
        assert!(masked < closed && closed < reset, "{version}");
    }
}

/// Registers that read `value` at every offset and ignore every write.
struct Stuck(u32);
impl Registers for Stuck {
    fn read8(&self, _: usize) -> u8 {
        self.0 as u8
    }
    fn read16(&self, _: usize) -> u16 {
        self.0 as u16
    }
    fn read32(&self, _: usize) -> u32 {
        self.0
    }
    fn write8(&self, _: usize, _: u8) {}
    fn write16(&self, _: usize, _: u16) {}
    fn write32(&self, _: usize, _: u32) {}
}

/// A reset that never completes fails the stop, so the owner keeps the
/// rings; a silent chip's drain and reset waits still end within 100 ms,
/// and one that left the bus fails at its first read.
#[test]
fn a_stop_that_never_sees_the_reset_fails_within_an_exit() {
    for version in implemented() {
        let time = Time::default();
        let mut model = running(&time, version);
        model.stuck_reset = true;
        let hardware = Hardware::new(&model, &time, revision(version), 0);
        assert_eq!(hardware.stop(), Err(BlockError::Timeout), "{version}");
        for value in [0x10, 0x5a5a_5a5a] {
            let time = Time::default();
            let stuck = Stuck(value);
            let hardware = Hardware::new(&stuck, &time, revision(version), 0);
            assert_eq!(hardware.stop(), Err(BlockError::Timeout), "{version}");
            assert!(time.now() < 100_000, "{version} {value:#x}: {}", time.now());
        }
        let time = Time::default();
        let lost = Stuck(u32::MAX);
        let hardware = Hardware::new(&lost, &time, revision(version), 0);
        assert!(
            matches!(hardware.stop(), Err(BlockError::Device { .. })),
            "{version}"
        );
    }
}
