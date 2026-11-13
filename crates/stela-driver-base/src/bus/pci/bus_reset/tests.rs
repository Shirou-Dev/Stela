//! A simulated bridge whose Secondary Bus Reset empties the functions below
//! it, which stay silent for a few reads after.
use super::*;
use crate::bus::pci::ConfigError;
use alloc::{rc::Rc, vec, vec::Vec};
use core::cell::RefCell;

type Log = Rc<RefCell<Vec<&'static str>>>;

struct State {
    words: RefCell<[u32; 64]>,
    silence: Cell<u32>,
    /// The writes its owner admitted for the restore.
    admitted: RefCell<Vec<(u16, u8, u32)>>,
}

impl Contained for Child {
    fn admit_restore(&mut self, writes: &[(u16, u8, u32)]) -> Result<(), ConfigError> {
        self.0.admitted.borrow_mut().extend_from_slice(writes);
        Ok(())
    }
}

/// One function below the bridge.
#[derive(Clone)]
struct Child(Rc<State>);

impl ConfigSpace for Child {
    fn read32(&self, offset: u16) -> Result<u32, ConfigError> {
        if offset == 0 && self.0.silence.get() != 0 {
            self.0.silence.set(self.0.silence.get() - 1);
            return Ok(u32::MAX);
        }
        Ok(self.0.words.borrow()[usize::from(offset / 4)])
    }
    fn read16(&self, offset: u16) -> Result<u16, ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 2) * 8)) as u16)
    }
    fn read8(&self, offset: u16) -> Result<u8, ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 3) * 8)) as u8)
    }
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        self.0.words.borrow_mut()[usize::from(offset / 4)] = value;
        Ok(())
    }
    fn write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        let shift = (offset & 2) * 8;
        let word = &mut self.0.words.borrow_mut()[usize::from(offset / 4)];
        *word = *word & !(0xffff << shift) | u32::from(value) << shift;
        Ok(())
    }
    fn write8(&mut self, _: u16, _: u8) -> Result<(), ConfigError> {
        unreachable!("no byte writes")
    }
}

/// The bridge, a root port at 00:01.0 leading to bus 1, its PCI Express
/// capability at 0x40 with a hot-plug slot.
struct Bridge {
    words: [u32; 64],
    children: Vec<Child>,
    /// How long the children stay silent after the reset.
    silence: u32,
    /// Link Status reads that still find the link down.
    down: Cell<u32>,
    link_down: u32,
    log: Log,
}

const LINK_STATUS_AT: u16 = 0x52;
const SLOT_CONTROL_AT: u16 = 0x58;
const SLOT_STATUS_AT: u16 = 0x5a;

impl ConfigSpace for Bridge {
    fn read32(&self, offset: u16) -> Result<u32, ConfigError> {
        let word = self.words[usize::from(offset / 4)];
        if offset == LINK_STATUS_AT & !3 && self.down.get() != 0 {
            self.down.set(self.down.get() - 1);
            return Ok(word & !(u32::from(LINK_ACTIVE) << 16));
        }
        Ok(word)
    }
    fn read16(&self, offset: u16) -> Result<u16, ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 2) * 8)) as u16)
    }
    fn read8(&self, offset: u16) -> Result<u8, ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 3) * 8)) as u8)
    }
    fn write32(&mut self, _: u16, _: u32) -> Result<(), ConfigError> {
        unreachable!("no dword writes to the bridge")
    }
    fn write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        let shift = (offset & 2) * 8;
        let word = &mut self.words[usize::from(offset / 4)];
        let old = (*word >> shift) as u16;
        // Slot Status is write-one-to-clear.
        let new = if offset == SLOT_STATUS_AT {
            self.log.borrow_mut().push("clear");
            old & !value
        } else {
            value
        };
        *word = *word & !(0xffff << shift) | u32::from(new) << shift;
        match offset {
            BRIDGE_CONTROL => panic!("Bridge Control written outside the reset"),
            SLOT_CONTROL_AT if value & PRESENCE_CHANGE_ENABLE == 0 => {
                self.log.borrow_mut().push("mask")
            }
            SLOT_CONTROL_AT => self.log.borrow_mut().push("unmask"),
            _ => {}
        }
        Ok(())
    }
    fn write8(&mut self, _: u16, _: u8) -> Result<(), ConfigError> {
        unreachable!("no byte writes")
    }
}

impl SecondaryBusReset for Bridge {
    unsafe fn set_secondary_bus_reset(&mut self, asserted: bool) -> Result<(), ConfigError> {
        let control = &mut self.words[usize::from(BRIDGE_CONTROL / 4)];
        if asserted {
            *control |= u32::from(SECONDARY_BUS_RESET) << 16;
            self.log.borrow_mut().push("assert");
            // The link drops and the slot reports it, with no event.
            self.words[usize::from(SLOT_STATUS_AT / 4)] |=
                u32::from(PRESENCE_CHANGED | LINK_CHANGED) << 16;
            return Ok(());
        }
        if *control & u32::from(SECONDARY_BUS_RESET) << 16 != 0 {
            for child in &self.children {
                let mut words = child.0.words.borrow_mut();
                words[1] = 0x0010_0000;
                words[4] = 0;
                words[0x48 / 4] &= 0xffff_0000;
                child.0.silence.set(self.silence);
            }
            self.down.set(self.link_down);
        }
        *control &= !(u32::from(SECONDARY_BUS_RESET) << 16);
        self.log.borrow_mut().push("release");
        Ok(())
    }
}

fn address(bus: u8, device: u8, function: u8) -> Address {
    Address {
        segment: 0,
        bus,
        device,
        function,
    }
}

/// A function with a BAR and a PCI Express capability at 0x40.
fn child(at: Address, command: u32) -> Function<Child> {
    let mut words = [0; 64];
    words[0] = 0x1234_10de;
    words[1] = 0x0010_0000 | command;
    words[4] = 0xf000_0000;
    words[0x34 / 4] = 0x40;
    words[0x40 / 4] = 0x0002_0010;
    words[0x48 / 4] = 0x0000_2810;
    Function {
        address: at,
        vendor: 0x10de,
        device: 0x1234,
        class: [3, 0, 0],
        config: Child(Rc::new(State {
            words: RefCell::new(words),
            silence: Cell::new(0),
            admitted: RefCell::new(Vec::new()),
        })),
    }
}

/// `speed`: the port's Max Link Speed; `reporting`: Data Link Layer Link
/// Active reporting.
fn bridge(speed: u32, reporting: bool, children: Vec<Child>, log: &Log) -> Bridge {
    let mut words = [0; 64];
    words[0] = 0x1234_8086;
    words[1] = 0x0010_0007;
    words[2] = 0x0604_0000;
    words[3] = 1 << 16;
    words[6] = 0x0001_0100;
    words[0x34 / 4] = 0x40;
    // Root port with a slot; link capabilities; link up; hot-plug capable
    // slot with presence and link change events and their interrupt on.
    words[0x40 / 4] = (u32::from(SLOT_IMPLEMENTED) | 4 << 4) << 16 | 0x10;
    words[0x4c / 4] = speed | if reporting { LINK_ACTIVE_REPORTING } else { 0 };
    words[0x50 / 4] = u32::from(LINK_ACTIVE) << 16;
    words[0x54 / 4] = HOT_PLUG_CAPABLE;
    words[0x58 / 4] = u32::from(PRESENCE_CHANGE_ENABLE | LINK_CHANGE_ENABLE | 1 << 5);
    Bridge {
        words,
        children,
        silence: 2,
        down: Cell::new(0),
        link_down: 2,
        log: log.clone(),
    }
}

#[test]
fn a_bus_reset_resets_the_device_and_puts_every_function_back() {
    let log = Log::default();
    let mut gpu = child(address(1, 0, 0), 6);
    // The audio function, parked with INTx disabled.
    let mut audio = [child(address(1, 0, 1), 0x400)];
    audio[0].config.0.words.borrow_mut()[4] = 0xf100_0000;
    let mut port = bridge(
        3,
        true,
        vec![gpu.config.clone(), audio[0].config.clone()],
        &log,
    );
    let mut waits = Vec::new();
    // SAFETY: the simulated bus has no other owner.
    let reset = unsafe {
        reset_with(
            &mut port,
            &mut gpu,
            &mut audio,
            &[address(1, 0, 0), address(1, 0, 1)],
            |microseconds| {
                waits.push(microseconds);
                Ok(())
            },
        )
    };
    assert_eq!(reset, Ok(()));
    // The hold, the settle, two Link Status polls, the delay, then each
    // function's two silent reads.
    assert_eq!(
        waits,
        [
            2_000, 20_000, 1_000, 1_000, 100_000, 1_000, 2_000, 1_000, 2_000
        ]
    );
    assert_eq!(
        *log.borrow(),
        ["mask", "assert", "release", "clear", "unmask"]
    );
    let words = port.words;
    assert_eq!(words[usize::from(BRIDGE_CONTROL / 4)] >> 16, 0);
    assert_eq!(
        words[0x58 / 4] & 0xffff,
        u32::from(PRESENCE_CHANGE_ENABLE | LINK_CHANGE_ENABLE | 1 << 5)
    );
    assert_eq!(words[0x58 / 4] >> 16, 0);
    let gpu_admitted_nothing = gpu.config.0.admitted.borrow().is_empty();
    let gpu = gpu.config.0.words.borrow();
    assert_eq!(
        (gpu[1] & 0xffff, gpu[4], gpu[0x48 / 4]),
        (6, 0xf000_0000, 0x2810)
    );
    // The audio function's owner admitted exactly its saved state: the
    // header after COMMAND, the four PCI Express controls, then COMMAND.
    let admitted = audio[0].config.0.admitted.borrow().clone();
    assert_eq!(admitted.len(), 13 + 4 + 1);
    assert_eq!(admitted[0], (0x0c, 4, 0));
    assert_eq!(admitted[1], (0x10, 4, 0xf100_0000));
    assert_eq!(admitted[13], (0x48, 2, 0x2810));
    assert_eq!(admitted[17], (0x04, 2, 0x400));
    let audio = audio[0].config.0.words.borrow();
    assert_eq!((audio[1] & 0xffff, audio[4]), (0x400, 0xf100_0000));
    assert!(gpu_admitted_nothing);
}

#[test]
fn another_device_or_an_unowned_function_on_the_bus_refuses_before_any_effect() {
    for present in [
        [address(1, 0, 0), address(1, 1, 0)],
        [address(1, 0, 0), address(1, 0, 2)],
        [address(1, 0, 0), address(1, 0, 0)],
    ] {
        let log = Log::default();
        let mut gpu = child(address(1, 0, 0), 6);
        let mut port = bridge(3, true, vec![gpu.config.clone()], &log);
        let mut none: [Function<Child>; 0] = [];
        // SAFETY: refused before any effect.
        let reset = unsafe {
            reset_with(&mut port, &mut gpu, &mut none, &present, |_| {
                panic!("no wait")
            })
        };
        assert_eq!(
            reset,
            Err(BlockError::Unsupported(
                "other functions share the PCI function's bus"
            ))
        );
        assert!(log.borrow().is_empty());
        assert_eq!(gpu.config.0.words.borrow()[1] & 0xffff, 6);
    }
}

#[test]
fn a_bridge_elsewhere_or_already_in_reset_refuses() {
    let log = Log::default();
    let mut gpu = child(address(2, 0, 0), 6);
    let mut port = bridge(3, true, vec![gpu.config.clone()], &log);
    let mut none: [Function<Child>; 0] = [];
    // SAFETY: refused before any effect.
    let reset = unsafe {
        reset_with(&mut port, &mut gpu, &mut none, &[address(2, 0, 0)], |_| {
            panic!("no wait")
        })
    };
    assert_eq!(
        reset,
        Err(BlockError::Unsupported(
            "PCI bridge does not lead to the function's bus"
        ))
    );
    let mut gpu = child(address(1, 0, 0), 6);
    port.words[usize::from(BRIDGE_CONTROL / 4)] |= u32::from(SECONDARY_BUS_RESET) << 16;
    // SAFETY: refused before any effect.
    let reset = unsafe {
        reset_with(&mut port, &mut gpu, &mut none, &[address(1, 0, 0)], |_| {
            panic!("no wait")
        })
    };
    assert_eq!(
        reset,
        Err(BlockError::Unsupported(
            "PCI bridge already holds its secondary bus in reset"
        ))
    );
    assert!(log.borrow().is_empty());
}

#[test]
fn a_slow_link_waits_one_second_unless_it_reports_itself_up() {
    for (reporting, outcome) in [
        (true, Ok(())),
        (
            false,
            Err(BlockError::Unsupported(
                "PCI function did not return from its bus reset",
            )),
        ),
    ] {
        let log = Log::default();
        let mut gpu = child(address(1, 0, 0), 6);
        let mut port = bridge(1, reporting, vec![gpu.config.clone()], &log);
        // Silent through polls of 1 to 512 ms, past the first second, and
        // one more.
        port.silence = 12;
        port.link_down = 0;
        let mut none: [Function<Child>; 0] = [];
        let mut waited = 0;
        // SAFETY: the simulated bus has no other owner.
        let reset = unsafe {
            reset_with(
                &mut port,
                &mut gpu,
                &mut none,
                &[address(1, 0, 0)],
                |microseconds| {
                    waited += microseconds;
                    Ok(())
                },
            )
        };
        assert_eq!(reset, outcome);
        // The reset is released and the slot's events back on either way.
        assert_eq!(
            *log.borrow(),
            ["mask", "assert", "release", "clear", "unmask"]
        );
        let expected = 2_000 + 100_000 + 1_023_000 + if reporting { 1_000 } else { 0 };
        assert_eq!(waited, expected);
        assert_eq!(
            gpu.config.0.words.borrow()[4],
            if reporting { 0xf000_0000 } else { 0 }
        );
    }
}

#[test]
fn a_fast_link_that_never_comes_back_is_an_error() {
    let log = Log::default();
    let mut gpu = child(address(1, 0, 0), 6);
    let mut port = bridge(3, true, vec![gpu.config.clone()], &log);
    port.link_down = u32::MAX;
    let mut none: [Function<Child>; 0] = [];
    // SAFETY: the simulated bus has no other owner.
    let reset = unsafe {
        reset_with(&mut port, &mut gpu, &mut none, &[address(1, 0, 0)], |_| {
            Ok(())
        })
    };
    assert_eq!(
        reset,
        Err(BlockError::Unsupported(
            "PCI link did not come back after its bus reset"
        ))
    );
    assert_eq!(
        *log.borrow(),
        ["mask", "assert", "release", "clear", "unmask"]
    );
}

#[test]
fn a_sibling_that_can_still_master_refuses_before_any_effect() {
    let log = Log::default();
    let mut gpu = child(address(1, 0, 0), 6);
    let mut audio = [child(address(1, 0, 1), 0x404)];
    let mut port = bridge(3, true, vec![gpu.config.clone()], &log);
    // SAFETY: refused before any effect.
    let reset = unsafe {
        reset_with(
            &mut port,
            &mut gpu,
            &mut audio,
            &[address(1, 0, 0), address(1, 0, 1)],
            |_| panic!("no wait"),
        )
    };
    assert_eq!(
        reset,
        Err(BlockError::Unsupported(
            "a function sharing the PCI function's bus is not contained"
        ))
    );
    assert!(log.borrow().is_empty());
    assert_eq!(gpu.config.0.words.borrow()[1] & 0xffff, 6);
}
