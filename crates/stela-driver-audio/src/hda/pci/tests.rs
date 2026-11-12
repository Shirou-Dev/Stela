// SPDX-License-Identifier: GPL-2.0-only
use super::*;
use crate::bus::i2c::Timer as NominalTimer;
use crate::bus::pci::Address;
use crate::bus::pci::regs;
use alloc::{rc::Rc, vec::Vec};
use core::cell::Cell;

pub(in crate::hda) struct Clock(Rc<Cell<u64>>);
impl crate::bus::i2c::Timer for Clock {
    fn now_us(&self) -> u64 {
        self.0.get()
    }
    fn relax(&self) {
        self.0.set(self.0.get() + 10);
    }
}

pub(in crate::hda) struct Model {
    words: [u32; 64],
    reset_gate: Option<Rc<Cell<bool>>>,
    now: Rc<Cell<u64>>,
    ready_at: u64,
    previous_state: u16,
    reject_power: bool,
    reject_command: bool,
    reject_vendor_control: bool,
    fail_after_enable: bool,
    reject_snoop: bool,
    failed_snoop_read: bool,
    failed_interrupt_read: Option<u16>,
    writes: Vec<(u16, u8, u32, u64)>,
}
impl Model {
    fn get16(&self, offset: u16) -> u16 {
        (self.words[usize::from(offset / 4)] >> ((offset & 2) * 8)) as u16
    }
    fn set16(&mut self, offset: u16, value: u16) {
        let shift = (offset & 2) * 8;
        let index = usize::from(offset / 4);
        self.words[index] = self.words[index] & !(0xffff << shift) | u32::from(value) << shift;
    }
}
impl ConfigSpace for Model {
    fn read32(&self, offset: u16) -> Result<u32, crate::bus::pci::ConfigError> {
        let value = {
            let value = self.words[usize::from(offset / 4)];
            if self.failed_interrupt_read == Some(offset)
                && self
                    .writes
                    .iter()
                    .any(|(off, _, _, _)| *off == regs::COMMAND)
            {
                return Ok(u32::MAX);
            }
            if offset == SCH_HDA_DEVC
                && self.failed_snoop_read
                && self
                    .writes
                    .iter()
                    .any(|(off, _, _, _)| *off == SCH_HDA_DEVC)
            {
                return Ok(u32::MAX);
            }
            if offset == regs::COMMAND
                && self.fail_after_enable
                && self.writes.iter().any(|(off, _, value, _)| {
                    *off == regs::COMMAND && *value & u32::from(regs::COMMAND_MASTER) != 0
                })
            {
                return Ok(u32::MAX);
            }
            if offset == 0x54 && (self.reject_power || self.now.get() < self.ready_at) {
                value & !3 | u32::from(self.previous_state)
            } else {
                value
            }
        };
        Ok(value)
    }
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), crate::bus::pci::ConfigError> {
        if offset == CGCTL {
            if let Some(gate) = &self.reset_gate {
                gate.set(value & CGCTL_MISCBDCGE != 0);
            }
            self.writes.push((offset, 4, value, self.now.get()));
            self.words[usize::from(offset / 4)] = value;
            return Ok(());
        }
        // Other dword writes attachment needs are saved BAR restores.
        assert!((regs::BASE_ADDRESS_0..regs::BASE_ADDRESS_0 + 24).contains(&offset));
        assert!(self.now.get() >= self.ready_at);
        assert_eq!(
            self.get16(regs::COMMAND) & (regs::COMMAND_MEMORY | regs::COMMAND_MASTER),
            0
        );
        self.writes.push((offset, 4, value, self.now.get()));
        self.words[usize::from(offset / 4)] = value;

        Ok(())
    }
    fn write8(&mut self, offset: u16, value: u8) -> Result<(), crate::bus::pci::ConfigError> {
        assert!(matches!(
            offset,
            TCSEL | ATI_SNOOP_CONTROL | NVIDIA_TRANSREG | NVIDIA_ISTRM_COH | NVIDIA_OSTRM_COH
        ));
        assert_eq!(
            self.get16(regs::COMMAND) & (regs::COMMAND_MEMORY | regs::COMMAND_MASTER),
            0
        );
        self.writes
            .push((offset, 1, u32::from(value), self.now.get()));
        if self.reject_vendor_control {
            return Ok(());
        }
        let shift = (offset & 3) * 8;
        let index = usize::from(offset / 4);
        self.words[index] = self.words[index] & !(0xff << shift) | u32::from(value) << shift;

        Ok(())
    }
    fn write16(&mut self, offset: u16, value: u16) -> Result<(), crate::bus::pci::ConfigError> {
        assert!(matches!(
            offset,
            regs::COMMAND | 0x44 | 0x4a | 0x54 | 0x62 | 0x72 | 0xb2 | SCH_HDA_DEVC
        ));
        self.writes
            .push((offset, 2, u32::from(value), self.now.get()));
        if offset == SCH_HDA_DEVC {
            assert_eq!(
                self.get16(regs::COMMAND) & (regs::COMMAND_MEMORY | regs::COMMAND_MASTER),
                0
            );
            if self.reject_snoop {
                return Ok(());
            }
        }
        if offset == regs::COMMAND {
            if self.reject_command {
                return Ok(());
            }
            if value & regs::COMMAND_MASTER != 0 {
                assert!(self.now.get() >= self.ready_at);
            }
        }
        if offset == 0x54 {
            let old = self.get16(offset);
            self.previous_state = old & PM_STATE;
            self.ready_at = self.now.get()
                + match self.previous_state {
                    3 => 10_000,
                    2 => 200,
                    _ => 0,
                };
            if old & PM_STATE == 3 && old & PM_NO_SOFT_RESET == 0 {
                self.words[4..10].fill(0);
            }
            // Pending PME is W1C, not an ordinary stored bit.
            self.set16(
                offset,
                (value & !PM_PME_STATUS) | (old & !value & PM_PME_STATUS),
            );
            return Ok(());
        }
        self.set16(offset, value);

        Ok(())
    }

    fn read8(&self, offset: u16) -> Result<u8, crate::bus::pci::ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 3) * 8)) as u8)
    }

    fn read16(&self, offset: u16) -> Result<u16, crate::bus::pci::ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 2) * 8)) as u16)
    }
}

fn fixture(state: u16) -> (Function<Model>, Clock, Bar) {
    let now = Rc::new(Cell::new(0));
    let mut model = Model {
        words: [0; 64],
        reset_gate: None,
        now: now.clone(),
        ready_at: 0,
        previous_state: state,
        reject_power: false,
        reject_command: false,
        reject_vendor_control: false,
        fail_after_enable: false,
        reject_snoop: false,
        failed_snoop_read: false,
        failed_interrupt_read: None,
        writes: Vec::new(),
    };
    model.words[0] = 0x2668_8086;
    model.words[1] = 0xf910_0406; // W1C status, capabilities, decode/master.
    model.words[2] = 0x0403_0001;
    model.words[4] = 0xfebf_0000;
    model.words[5] = 0x1234_0000; // Exercise restoration of every BAR.
    model.words[13] = 0x50;
    model.words[17] = 0x5ac3_a5f7; // TCSEL byte plus adjacent vendor state.
    model.words[20] = 0x0003_6001; // PCI PMv3 -> MSI.
    model.words[21] = u32::from(state | PM_PME_ENABLE | PM_PME_STATUS);
    model.words[24] = 0x0001_7005; // Enabled MSI -> MSI-X.
    model.words[28] = 0x8000_0011; // Enabled MSI-X.
    let function = Function::new(
        Address {
            segment: 0,
            bus: 0,
            device: 27,
            function: 0,
        },
        model,
    )
    .unwrap();
    (
        function,
        Clock(now),
        Bar::Memory {
            address: 0xfebf_0000,
            size: 0x4000,
            prefetchable: false,
            wide: false,
        },
    )
}

/// Core-only profile fixture; mapped-entry tests exercise preparation.
pub(in crate::hda) fn modern_prepared_model(address: Address) -> Prepared {
    let selected = identity(INTEL, 0xa170, CLASS).unwrap();
    Prepared {
        identity: selected,
        address,
        base: 0xfebf_0000,
        bytes: 0x4000,
    }
}

fn set_identity(function: &mut Function<Model>, vendor: u16, device: u16) {
    function.vendor = vendor;
    function.device = device;
    function.config().words[0] = u32::from(vendor) | (u32::from(device) << 16);
}

fn prepare_model(
    function: &mut Function<Model>,
    timer: &Clock,
    bar: Bar,
) -> Result<Prepared, AttachError> {
    // SAFETY: the isolated stateful model has no real hardware/firmware owner.
    unsafe { prepare(function, bar, timer, Ownership::ExclusiveLegacy) }
}

fn pch_fixture(device: u16, version: u16, kind: u16) -> (Function<Model>, Clock, Bar) {
    let (mut function, timer, bar) = fixture(3);
    set_identity(&mut function, INTEL, device);
    // PM50 -> MSI60 -> PCIe70 -> MSI-Xb0. DEVC78 and Device Status7a
    // share a dword; the latter holds pending W1C evidence.
    function.config().words[28] = (u32::from(version | (kind << 4)) << 16) | 0xb010;
    function.config().words[30] = 0xf91f_7a55;
    function.config().words[44] = 0x8000_0011;
    (function, timer, bar)
}

pub(in crate::hda) fn modern_pci_model() -> (Function<Model>, Clock, Bar) {
    modern_pci_model_for(0xa170)
}
pub(in crate::hda) fn modern_pci_model_for(device: u16) -> (Function<Model>, Clock, Bar) {
    let (mut function, timer, bar) = pch_fixture(device, 2, 9);
    function.config().set16(0x54, PM_PME_ENABLE | PM_PME_STATUS);
    (function, timer, bar)
}

pub(in crate::hda) fn connect_reset_gate(function: &mut Function<Model>, gate: Rc<Cell<bool>>) {
    function.config().words[usize::from(CGCTL / 4)] = 0xa5a5_00c3;
    function.config().reset_gate = Some(gate);
}

#[derive(Clone)]
struct MappedModel {
    bytes: alloc::rc::Rc<core::cell::RefCell<Vec<u8>>>,
    reads: Rc<Cell<usize>>,
}
impl MappedModel {
    fn new() -> Self {
        let mut bytes = alloc::vec![0; 0x1000];
        bytes[0..4].copy_from_slice(&0x0100_2201u32.to_le_bytes());
        Self {
            bytes: Rc::new(core::cell::RefCell::new(bytes)),
            reads: Rc::new(Cell::new(0)),
        }
    }
    fn set(&self, offset: usize, value: u32) {
        self.bytes.borrow_mut()[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}
impl Registers for MappedModel {
    fn region_bytes(&self) -> usize {
        self.bytes.borrow().len()
    }
    fn read8(&mut self, offset: usize) -> u8 {
        self.reads.set(self.reads.get() + 1);
        self.bytes.borrow()[offset]
    }
    fn read16(&mut self, offset: usize) -> u16 {
        u16::from(self.read8(offset)) | u16::from(self.read8(offset + 1)) << 8
    }
    fn read32(&mut self, offset: usize) -> u32 {
        u32::from(self.read16(offset)) | u32::from(self.read16(offset + 2)) << 16
    }
    fn write8(&mut self, _: usize, _: u8) {
        panic!("preflight must not write MMIO")
    }
    fn write16(&mut self, _: usize, _: u16) {
        panic!("preflight must not write MMIO")
    }
    fn write32(&mut self, _: usize, _: u32) {
        panic!("preflight must not write MMIO")
    }
}

mod legacy;
mod minimum;

mod mapped;

mod pch;

mod amd;

mod owned_models;

mod access_failures;

// SAFETY: this private synchronous peripheral model measures virtual microseconds;
// no physical timer, CPU or native hardware permission follows from it.
unsafe impl crate::bus::pci::power::Timer for Clock {
    fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
        Ok(())
    }
    fn wait_us(&self, us: u64) -> Result<(), crate::bus::pci::power::Error> {
        self.0.set(
            self.0
                .get()
                .checked_add(us)
                .expect("bounded model minimum wait"),
        );
        Ok(())
    }
}
