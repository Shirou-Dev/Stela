// SPDX-License-Identifier: GPL-2.0-only
//! Authored register models. UNRUN: source-only driver assignment.
use super::*;
use alloc::{collections::BTreeMap, rc::Rc, vec::Vec};
use core::cell::RefCell;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Config(u16, u32),
    ConfigWrite(u16, u32),
    ConfigWrite16(u16, u16),
    Read(u32, u32),
    Write(u32, u32),
    ApeRead(u32, u32),
    ApeWrite(u32, u32),
    Delay(u64),
}
#[derive(Default)]
struct Model {
    config: BTreeMap<u16, u32>,
    mac: BTreeMap<u32, u32>,
    ape: BTreeMap<u32, u32>,
    sram: BTreeMap<u32, u32>,
    phy: BTreeMap<u8, u16>,
    trace: Vec<Event>,
    function: u8,
    command: u32,
    busy_reads: usize,
    force_busy: bool,
    force_read_failure: bool,
    no_grant: bool,
    competing_grant: bool,
    stuck_stop: Option<u32>,
    io_count: usize,
    fail_at: Option<usize>,
    dropped: usize,
    no_nvram_grant: bool,
    reset_pending: bool,
    reset_firmware_ack: bool,
    ignored_config_write: Option<u16>,
    delay_count: usize,
    fail_delay: Option<usize>,
    /// The APE firmware never takes a posted event.
    ape_busy: bool,
}
impl Model {
    fn event(&mut self, event: Event) -> Result<(), Error> {
        self.trace.push(event);
        self.io_count += 1;
        if self.fail_at == Some(self.io_count) {
            Err(Error::Access)
        } else {
            Ok(())
        }
    }
}
struct Reg(Rc<RefCell<Model>>);
impl Drop for Reg {
    fn drop(&mut self) {
        self.0.borrow_mut().dropped += 1;
    }
}
#[derive(Clone)]
struct Timer(Rc<RefCell<Model>>);
// SAFETY: isolated symbolic timer only; no production clock permission.
unsafe impl Delay for Timer {
    fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
        Ok(())
    }
    fn wait_us(&self, us: u64) -> Result<(), crate::bus::pci::power::Error> {
        let mut model = self.0.borrow_mut();
        model.delay_count += 1;
        model.trace.push(Event::Delay(us));
        if model.fail_delay == Some(model.delay_count) {
            Err(crate::bus::pci::power::Error::Clock)
        } else {
            Ok(())
        }
    }
}
// SAFETY: a symbolic isolated test device only; no production address/permission.
unsafe impl Registers for Reg {
    fn function_number(&self) -> u8 {
        self.0.borrow().function
    }
    fn config_read32(&mut self, at: u16) -> Result<u32, Error> {
        let mut m = self.0.borrow_mut();
        let value = *m.config.get(&at).unwrap_or(&0);
        m.event(Event::Config(at, value))?;
        Ok(value)
    }
    fn config_write32(&mut self, at: u16, value: u32) -> Result<(), Error> {
        let mut m = self.0.borrow_mut();
        m.event(Event::ConfigWrite(at, value))?;
        if m.ignored_config_write == Some(at) {
            return Ok(());
        }
        m.config.insert(at, value);
        Ok(())
    }
    fn config_write16(&mut self, at: u16, value: u16) -> Result<(), Error> {
        let mut m = self.0.borrow_mut();
        m.event(Event::ConfigWrite16(at, value))?;
        if m.ignored_config_write == Some(at) {
            return Ok(());
        }
        let shift = (at & 2) * 8;
        let previous = *m.config.get(&(at & !3)).unwrap_or(&0);
        m.config.insert(
            at & !3,
            (previous & !(0xffff << shift)) | (u32::from(value) << shift),
        );
        Ok(())
    }
    fn read32(&mut self, at: u32) -> Result<u32, Error> {
        let mut m = self.0.borrow_mut();
        if m.reset_pending && m.config.get(&4).copied().unwrap_or(0) & 2 == 0 {
            return Err(Error::Access); // Core reset temporarily removed MMIO decode.
        }
        let value = if at == MEM_DATA {
            let window = *m.mac.get(&MEM_BASE).unwrap_or(&0);
            *m.sram.get(&window).unwrap_or(&0)
        } else if at == MAC_MI_COM && m.command != 0 {
            if m.force_busy || m.busy_reads > 0 {
                m.busy_reads = m.busy_reads.saturating_sub(1);
                m.command
            } else {
                let register = ((m.command >> 16) & 31) as u8;
                let data = if m.command & MI_READ != 0 {
                    u32::from(*m.phy.get(&register).unwrap_or(&0))
                } else {
                    let command = m.command;
                    m.phy.insert(register, command as u16);
                    command & 0xffff
                };
                (m.command & !(MI_START | 0xffff))
                    | data
                    | if m.force_read_failure {
                        MI_READ_FAILED
                    } else {
                        0
                    }
            }
        } else {
            *m.mac.get(&at).unwrap_or(&0)
        };
        m.event(Event::Read(at, value))?;
        Ok(value)
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), Error> {
        let mut m = self.0.borrow_mut();
        m.event(Event::Write(at, value))?;
        if at == MEM_DATA {
            let window = *m.mac.get(&MEM_BASE).unwrap_or(&0);
            m.sram.insert(window, value);
        } else if at == MAC_MI_COM {
            m.command = value;
            m.busy_reads = 1;
        } else if at == 0x7020 && value == 2 {
            let grant = if m.no_nvram_grant { 0 } else { 0x200 };
            m.mac.insert(at, value | grant);
        } else if at == 0x6804 && value & 1 != 0 {
            m.reset_pending = true;
            let command = m.config.get(&4).copied().unwrap_or(0);
            m.config.insert(4, command & !2);
            let host = m.config.get(&MISC_HOST_CTRL).copied().unwrap_or(0);
            m.config.insert(MISC_HOST_CTRL, host & 0xffff_0000);
            m.config.insert(PCISTATE, 0);
            if m.reset_firmware_ack {
                m.sram.insert(FIRMWARE_MBOX, !FIRMWARE_MAGIC);
            }
            m.mac.insert(MEMARB_MODE, 0);
        } else if m.stuck_stop != Some(at) {
            m.mac.insert(at, value);
        }
        Ok(())
    }
    fn ape_read32(&mut self, at: u32) -> Result<u32, Error> {
        let mut m = self.0.borrow_mut();
        let value = *m.ape.get(&at).unwrap_or(&0);
        m.event(Event::ApeRead(at, value))?;
        Ok(value)
    }
    fn ape_write32(&mut self, at: u32, value: u32) -> Result<(), Error> {
        let mut m = self.0.borrow_mut();
        m.event(Event::ApeWrite(at, value))?;
        let request = if (APE_LOCK_REQ..APE_LOCK_REQ + 32).contains(&at) {
            Some(APE_LOCK_REQ)
        } else if (APE_PER_LOCK_REQ..APE_PER_LOCK_REQ + 32).contains(&at) {
            Some(APE_PER_LOCK_REQ)
        } else {
            None
        };
        if let Some(base) = request {
            let grant = at - base
                + if base == APE_LOCK_REQ {
                    APE_LOCK_GRANT
                } else {
                    APE_PER_LOCK_GRANT
                };
            let value = if m.no_grant {
                0
            } else if m.competing_grant {
                value | 1
            } else {
                value
            };
            m.ape.insert(grant, value);
        } else if (APE_LOCK_GRANT..APE_LOCK_GRANT + 32).contains(&at)
            || (APE_PER_LOCK_GRANT..APE_PER_LOCK_GRANT + 32).contains(&at)
        {
            m.ape.insert(at, 0); // Writing the owner's bit releases the grant.
        } else if at == 0x0c {
            // The APE firmware takes the posted event.
            if value == 1 && !m.ape_busy {
                let status = m.ape.get(&0x4300).copied().unwrap_or(0);
                m.ape.insert(0x4300, status & !0x8000_0000);
            }
        } else {
            m.ape.insert(at, value);
        }
        Ok(())
    }
}
fn model(asic: Asic, function: u8) -> (Hardware<Reg, Timer>, Rc<RefCell<Model>>) {
    let (device, revision, identity) = match asic {
        Asic::Bcm5761 => (0x1681u16, 0x0576_1000, 0xbc05_0fd3u32),
        Asic::Bcm5720 => (0x165f, 0x0572_0000, 0x5c0d_8b62),
        Asic::Bcm5762 => (0x1687, 0x0576_2000, 0x8580_3781),
    };
    let mut m = Model {
        function,
        ..Default::default()
    };
    m.config.insert(0, (u32::from(device) << 16) | 0x14e4);
    m.config.insert(8, 0x0200_0000);
    m.config.insert(MISC_HOST_CTRL, 0xf000_0000);
    m.config.insert(
        if asic == Asic::Bcm5761 {
            PRODID
        } else {
            GEN2_PRODID
        },
        revision,
    );
    m.phy.insert(2, ((identity >> 10) & 0xffff) as u16);
    m.phy
        .insert(3, (((identity >> 16) & 0xfc00) | (identity & 0x3ff)) as u16);
    m.phy.insert(7, 0xa55a);
    m.sram
        .insert(SRAM_CPMU_STATUS, (u32::from(function) << 30) | CPMU_STATUS);
    let m = Rc::new(RefCell::new(m));
    // SAFETY: both original owners belong to this isolated symbolic device.
    (
        unsafe { Hardware::new(Reg(m.clone()), Timer(m.clone())) },
        m,
    )
}
fn identified(asic: Asic, function: u8) -> (Hardware<Reg, Timer>, Rc<RefCell<Model>>) {
    let (mut hardware, m) = model(asic, function);
    hardware.identify().unwrap();
    m.borrow_mut().trace.clear();
    (hardware, m)
}

#[test]
fn config_revision_and_phy_oui_select_each_named_family() {
    for asic in [Asic::Bcm5761, Asic::Bcm5720, Asic::Bcm5762] {
        for function in 0..4 {
            let (mut hardware, _) = model(asic, function);
            let identity = hardware.identify().unwrap();
            assert_eq!(identity.asic, asic);
            assert_eq!(identity.function, function);
            assert_eq!(
                identity.phy_address,
                if asic == Asic::Bcm5720 {
                    function + 1
                } else {
                    1
                }
            );
            assert_ne!(hardware.read_phy_identity().unwrap() & 0xf, 0);
        }
    }
}

#[test]
fn a_candidate_id_cannot_authorize_wrong_asic_or_serdes() {
    let (mut hardware, m) = model(Asic::Bcm5720, 0);
    m.borrow_mut().config.insert(GEN2_PRODID, 0x0571_9000);
    assert_eq!(hardware.identify(), Err(Error::UnsupportedRevision));
    assert!(
        !m.borrow()
            .trace
            .iter()
            .any(|e| matches!(e, Event::Write(..) | Event::ApeWrite(..)))
    );
    let (mut hardware, m) = model(Asic::Bcm5720, 0);
    m.borrow_mut().mac.insert(SG_DIG_STATUS, SG_DIG_IS_SERDES);
    assert_eq!(hardware.identify(), Err(Error::UnsupportedMedia));
    assert_eq!(hardware.read_phy(2), Err(Error::Poisoned));
}

#[test]
fn mdio_takes_each_real_phy_grant_and_restores_autopoll_before_unlock() {
    for asic in [Asic::Bcm5761, Asic::Bcm5720, Asic::Bcm5762] {
        for function in 0..4 {
            let (mut hardware, m) = identified(asic, function);
            m.borrow_mut()
                .mac
                .insert(MAC_MI_MODE, MI_AUTO_POLL | 0xc0000);
            assert_eq!(hardware.read_phy(7), Ok(0xa55a));
            let m = m.borrow();
            let base = if asic == Asic::Bcm5761 {
                APE_LOCK_REQ
            } else {
                APE_PER_LOCK_REQ
            };
            let grant = if asic == Asic::Bcm5761 {
                APE_LOCK_GRANT
            } else {
                APE_PER_LOCK_GRANT
            };
            let offset = u32::from(PHY_LOCKS[usize::from(function)]) * 4;
            assert!(
                m.trace
                    .contains(&Event::ApeWrite(base + offset, APE_DRIVER))
            );
            assert_eq!(
                &m.trace[m.trace.len() - 4..],
                &[
                    Event::Write(MAC_MI_MODE, MI_AUTO_POLL | 0xc0000),
                    Event::Read(MAC_MI_MODE, MI_AUTO_POLL | 0xc0000),
                    Event::Delay(80),
                    Event::ApeWrite(grant + offset, APE_DRIVER),
                ]
            );
        }
    }
}

#[test]
fn lock_failure_is_bounded_and_never_issues_mdio() {
    for competing in [false, true] {
        let (mut hardware, m) = identified(Asic::Bcm5720, 2);
        m.borrow_mut().no_grant = !competing;
        m.borrow_mut().competing_grant = competing;
        assert_eq!(hardware.read_phy(2), Err(Error::ApeTimeout));
        assert_eq!(
            m.borrow()
                .trace
                .iter()
                .filter(|e| **e == Event::Delay(10))
                .count(),
            100
        );
        assert!(
            !m.borrow()
                .trace
                .iter()
                .any(|e| matches!(e, Event::Write(MAC_MI_COM, _)))
        );
        let events = m.borrow().trace.len();
        assert_eq!(hardware.read_phy(2), Err(Error::Poisoned));
        assert_eq!(m.borrow().trace.len(), events);
    }
}

#[test]
fn mdio_timeout_and_hardware_read_failure_are_sticky() {
    let (mut hardware, m) = identified(Asic::Bcm5762, 0);
    m.borrow_mut().force_busy = true;
    assert_eq!(hardware.read_phy(2), Err(Error::MdioTimeout));
    assert_eq!(
        m.borrow()
            .trace
            .iter()
            .filter(|e| **e == Event::Delay(10))
            .count(),
        5000
    );
    assert!(matches!(
        m.borrow().trace.last(),
        Some(Event::ApeWrite(_, APE_DRIVER))
    ));
    let (mut hardware, m) = identified(Asic::Bcm5762, 0);
    m.borrow_mut().force_read_failure = true;
    assert_eq!(hardware.read_phy(2), Err(Error::MdioReadFailed));
}

#[test]
fn every_successful_mdio_io_access_fault_poison_keeps_owner() {
    let (mut hardware, m) = identified(Asic::Bcm5720, 1);
    m.borrow_mut().mac.insert(MAC_MI_MODE, MI_AUTO_POLL);
    let before = m.borrow().io_count;
    hardware.read_phy(7).unwrap();
    let count = m.borrow().io_count - before;
    for failing in 1..=count {
        let (mut hardware, m) = identified(Asic::Bcm5720, 1);
        m.borrow_mut().mac.insert(MAC_MI_MODE, MI_AUTO_POLL);
        let before = m.borrow().io_count;
        m.borrow_mut().fail_at = Some(before + failing);
        assert_eq!(hardware.read_phy(7), Err(Error::Access), "access {failing}");
        let events = m.borrow().trace.len();
        assert_eq!(hardware.write_phy(7, 0), Err(Error::Poisoned));
        assert_eq!(m.borrow().trace.len(), events);
        drop(hardware);
        assert_eq!(m.borrow().dropped, 0);
    }
}

#[test]
fn sram_data_all_ones_is_valid_and_window_is_restored_on_every_path() {
    let (mut hardware, m) = identified(Asic::Bcm5761, 0);
    hardware.write_sram(0x1000, u32::MAX).unwrap();
    assert_eq!(hardware.read_sram(0x1000), Ok(u32::MAX));
    assert_eq!(m.borrow().mac[&MEM_BASE], 0);
    let (mut hardware, m) = identified(Asic::Bcm5761, 0);
    let before = m.borrow().io_count;
    m.borrow_mut().fail_at = Some(before + 3); // Data read.
    assert_eq!(hardware.read_sram(0x1000), Err(Error::Access));
    assert_eq!(m.borrow().mac[&MEM_BASE], 0);
}

#[test]
fn firmware_requires_the_inverted_bootcode_signature() {
    let (mut hardware, m) = identified(Asic::Bcm5761, 0);
    hardware.arm_firmware_handshake().unwrap();
    assert_eq!(m.borrow().sram[&FIRMWARE_MBOX], FIRMWARE_MAGIC);
    m.borrow_mut().sram.insert(FIRMWARE_MBOX, !FIRMWARE_MAGIC);
    hardware.wait_firmware().unwrap();
    let (mut hardware, _) = identified(Asic::Bcm5762, 0);
    assert_eq!(hardware.wait_firmware(), Err(Error::FirmwareTimeout));
    assert_eq!(hardware.failure(), Some(Error::FirmwareTimeout));
}

#[test]
fn engine_stop_observes_each_ack_and_never_counts_timeout_as_silent_success() {
    let (mut hardware, m) = identified(Asic::Bcm5720, 0);
    for at in STOP_RX
        .into_iter()
        .chain(STOP_TX)
        .chain([MAC_TX_MODE, HOSTCC_MODE, WDMAC_MODE])
    {
        m.borrow_mut().mac.insert(at, ENABLE | 0x100);
    }
    hardware.stop_engines().unwrap();
    assert!(hardware.engines_stopped());
    assert_eq!(hardware.read_phy(2), Err(Error::Stopped));
    assert!(
        m.borrow()
            .trace
            .contains(&Event::Write(FTQ_RESET, u32::MAX))
    );
    for stuck in STOP_RX
        .into_iter()
        .chain(STOP_TX)
        .chain([MAC_TX_MODE, HOSTCC_MODE, WDMAC_MODE])
    {
        let (mut hardware, m) = identified(Asic::Bcm5720, 0);
        m.borrow_mut().mac.insert(stuck, ENABLE);
        m.borrow_mut().stuck_stop = Some(stuck);
        assert_eq!(hardware.stop_engines(), Err(Error::StopTimeout(stuck)));
        assert!(!hardware.engines_stopped());
        drop(hardware);
        assert_eq!(m.borrow().dropped, 0);
    }
}

#[test]
fn bcm5720_internal_port_comes_from_signed_sram_then_live_fallback() {
    for signature_valid in [false, true] {
        let (mut hardware, m) = model(Asic::Bcm5720, 0);
        m.borrow_mut().sram.insert(
            SRAM_CPMU_STATUS,
            if signature_valid {
                (3 << 30) | CPMU_STATUS
            } else {
                0
            },
        );
        m.borrow_mut().mac.insert(CPMU_STATUS, 2 << 30);
        let identity = hardware.identify().unwrap();
        assert_eq!(identity.bdf_function, 0);
        assert_eq!(identity.function, if signature_valid { 3 } else { 2 });
        assert_eq!(identity.phy_address, identity.function + 1);
        m.borrow_mut().trace.clear();
        hardware.read_phy(7).unwrap();
        assert!(m.borrow().trace.contains(&Event::ApeWrite(
            APE_PER_LOCK_REQ + u32::from(PHY_LOCKS[usize::from(identity.function)]) * 4,
            APE_DRIVER
        )));
    }
}

#[test]
fn initial_mac_access_follows_observed_config_word_swap_and_sram_arbiter() {
    let (mut hardware, m) = model(Asic::Bcm5720, 1);
    hardware.identify().unwrap();
    let m = m.borrow();
    let config = m
        .trace
        .iter()
        .position(|e| *e == Event::ConfigWrite(MISC_HOST_CTRL, 0xf000_0000 | HOST_ACCESS))
        .unwrap();
    let first_mac = m
        .trace
        .iter()
        .position(|e| matches!(e, Event::Read(..) | Event::Write(..)))
        .unwrap();
    assert!(config < first_mac);
    let arbiter = m
        .trace
        .iter()
        .position(|e| *e == Event::Write(MEMARB_MODE, ENABLE))
        .unwrap();
    let sram = m
        .trace
        .iter()
        .position(|e| *e == Event::Write(MEM_BASE, SRAM_CPMU_STATUS))
        .unwrap();
    assert!(arbiter < sram);
    let allow = m
        .trace
        .iter()
        .position(|e| *e == Event::ConfigWrite(PCISTATE, ALLOW_APE))
        .unwrap();
    let first_ape = m
        .trace
        .iter()
        .position(|e| matches!(e, Event::ApeWrite(..)))
        .unwrap();
    assert!(allow < first_ape);
    assert_eq!(
        m.trace
            .iter()
            .filter(|e| matches!(e, Event::ApeWrite(..)))
            .count(),
        8
    );
}

#[test]
#[ignore = "oracle: STELA_TG3_TRANSPORT_ORACLE"]
fn unchanged_linux_ape_mdio_sram_transport() {
    extern crate std;
    use alloc::{format, string::String};
    let path =
        std::env::var("STELA_TG3_TRANSPORT_ORACLE").expect("fresh original Linux trace required");
    let source = std::fs::read_to_string(path).unwrap();
    let mut lines = source.lines();
    let mut cases = 0;
    while let Some(header) = lines.next() {
        let words: Vec<_> = header.split_whitespace().collect();
        let (mut hardware, m, write, sram) = if words[0] == "CASE" {
            let asic = match words[1] {
                "0" => Asic::Bcm5761,
                "1" => Asic::Bcm5720,
                "2" => Asic::Bcm5762,
                _ => panic!("unknown oracle ASIC"),
            };
            let function = words[2].parse().unwrap();
            let (hardware, m) = identified(asic, function);
            m.borrow_mut()
                .mac
                .insert(MAC_MI_MODE, if words[3] == "1" { MI_AUTO_POLL } else { 0 });
            (hardware, m, words[4] == "1", false)
        } else {
            assert_eq!(words[0], "SRAM");
            let (hardware, m) = identified(Asic::Bcm5761, 0);
            m.borrow_mut().sram.insert(0x1000, u32::MAX);
            (hardware, m, words[1] == "1", true)
        };
        let value = match (sram, write) {
            (false, false) => u32::from(hardware.read_phy(7).unwrap()),
            (false, true) => {
                hardware.write_phy(7, 0x1234).unwrap();
                0
            }
            (true, false) => hardware.read_sram(0x1000).unwrap(),
            (true, true) => {
                hardware.write_sram(0x1000, u32::MAX).unwrap();
                0
            }
        };
        let mut expected = Vec::new();
        let end = loop {
            let line = lines.next().expect("complete oracle case");
            if line.starts_with("END ") {
                break line;
            }
            expected.push(String::from(line));
        };
        let actual: Vec<_> = m
            .borrow()
            .trace
            .iter()
            .map(|event| {
                let (kind, at, value) = match *event {
                    Event::Read(at, value) => ('R', at, value),
                    Event::Write(at, value) => ('W', at, value),
                    Event::ApeRead(at, value) => ('A', at, value),
                    Event::ApeWrite(at, value) => ('G', at, value),
                    Event::Delay(us) => ('D', u32::try_from(us).unwrap(), 0),
                    _ => panic!("no config I/O in selected helper"),
                };
                format!("{kind} {at:08x} {value:08x}")
            })
            .collect();
        assert_eq!(actual, expected, "{header}");
        let result: Vec<_> = end.split_whitespace().collect();
        assert_eq!(result[1], "0", "{header}");
        assert_eq!(
            value,
            u32::from_str_radix(result[2], 16).unwrap(),
            "{header}"
        );
        cases += 1;
    }
    assert_eq!(cases, 50);
}

fn reset_model(asic: Asic) -> (Hardware<Reg, Timer>, Rc<RefCell<Model>>) {
    let (hardware, m) = identified(asic, 0);
    m.borrow_mut().config.insert(4, 0x0010_0016); // Capabilities, MWI, bus master, memory.
    m.borrow_mut().config.insert(0x34, 0x40);
    m.borrow_mut().config.insert(0x40, 0x10);
    m.borrow_mut().config.insert(0x48, 0x0810);
    m.borrow_mut().reset_firmware_ack = true;
    m.borrow_mut().sram.insert(0xb54, FIRMWARE_MAGIC);
    m.borrow_mut().sram.insert(0xb58, 0);
    (hardware, m)
}

#[test]
fn core_reset_uses_config_while_mmio_decode_is_gone() {
    for asic in [Asic::Bcm5761, Asic::Bcm5720, Asic::Bcm5762] {
        let (mut hardware, m) = reset_model(asic);
        hardware.reset_core().unwrap();
        assert!(hardware.core_reset_completed());
        assert_eq!(m.borrow().config[&4] & 0xffff, 2); // No unsolicited bus mastering/MWI.
        assert_eq!(m.borrow().config[&0x48] & 0xffff, 0); // Relaxed/no-snoop disabled.
        let m = m.borrow();
        let reset = m
            .trace
            .iter()
            .position(|e| *e == Event::Write(0x6804, 0x2000_0001))
            .unwrap();
        assert_eq!(
            &m.trace[reset + 1..reset + 4],
            &[
                Event::Delay(120),
                Event::Config(4, 0x0010_0000),
                Event::Delay(120)
            ]
        );
        assert!(m.trace.contains(&Event::Write(MAC_MI_MODE, 0x8000)));
        match asic {
            Asic::Bcm5761 => assert!(m.trace.contains(&Event::Write(0x7c00, 1 << 25))),
            Asic::Bcm5720 => assert!(m.trace.contains(&Event::Write(0x3624, 1 << 31))),
            Asic::Bcm5762 => assert!(m.trace.contains(&Event::Write(0x3628, 1 << 13))),
        }
    }
}

fn running_ape(m: &Rc<RefCell<Model>>) {
    m.borrow_mut().ape.insert(0x4000, 0x4150_4521);
    m.borrow_mut().ape.insert(0x400c, 0x100);
}
fn ape_writes(m: &Rc<RefCell<Model>>) -> Vec<(u32, u32)> {
    m.borrow()
        .trace
        .iter()
        .filter_map(|e| match e {
            Event::ApeWrite(at, value) => Some((*at, *value)),
            _ => None,
        })
        .collect()
}

#[test]
fn management_firmware_hears_the_driver_start_and_the_reset_carries_asf_state() {
    for (asic, function, lock, bit) in [
        (Asic::Bcm5761, 0, 0x2c + 16, 0x1000),
        (Asic::Bcm5720, 0, 0x8400 + 16, 0x1000),
        (Asic::Bcm5720, 2, 0x8400 + 16, 1 << 2),
        (Asic::Bcm5762, 0, 0x8400 + 16, 0x1000),
    ] {
        let (mut hardware, m) = identified(asic, function);
        for (at, value) in [(4, 0x0010_0016), (0x34, 0x40), (0x40, 0x10), (0x48, 0x0810)] {
            m.borrow_mut().config.insert(at, value);
        }
        m.borrow_mut().reset_firmware_ack = true;
        m.borrow_mut().sram.insert(0xb54, FIRMWARE_MAGIC);
        // ASF, and the APE bit Linux ignores for chips it knows have one.
        m.borrow_mut().sram.insert(0xb58, 0x0020_0080);
        m.borrow_mut().ape.insert(0x4208, 6);
        running_ape(&m);
        hardware.ape_driver_start().unwrap();
        // tg3_ape_driver_state_change(RESET_KIND_INIT), then the event under
        // the memory lock once the previous one was taken.
        assert_eq!(
            ape_writes(&m),
            [
                (0x4218, 0),
                (0x4200, 0x484f_5354),
                (0x4204, 0x20),
                (0x4208, 7),
                (0x420c, 0xf003_8900),
                (0x4210, 1),
                (0x421c, 1),
                (lock, bit),
                (0x4300, 0x8001_0510),
                (lock + 0x20, bit),
                (0x0c, 1),
            ]
        );
        // A second start in the same epoch tells the APE nothing new.
        m.borrow_mut().trace.clear();
        hardware.ape_driver_start().unwrap();
        assert!(ape_writes(&m).is_empty());
        hardware.reset_core().unwrap();
        assert!(hardware.core_reset_completed());
        assert!(hardware.management().asf);
        // tg3_write_sig_pre_reset: the ASF START state precedes the reset.
        let trace = m.borrow().trace.clone();
        let state = trace
            .iter()
            .position(|e| *e == Event::Write(MEM_BASE, 0xc04))
            .unwrap();
        let reset = trace
            .iter()
            .position(|e| *e == Event::Write(0x6804, 0x2000_0001))
            .unwrap();
        assert!(state < reset);
        assert_eq!(m.borrow().sram[&0xc04], 1);
        hardware.ape_driver_unload().unwrap();
        assert_eq!(m.borrow().ape[&0x421c], 2);
        assert_eq!(m.borrow().ape[&0x4300], 0x0002_0510);
    }
}

#[test]
fn an_event_the_ape_never_takes_is_dropped_after_twenty_milliseconds() {
    let (mut hardware, m) = identified(Asic::Bcm5720, 0);
    running_ape(&m);
    m.borrow_mut().ape.insert(0x4300, 0x8001_0510);
    m.borrow_mut().ape_busy = true;
    hardware.ape_driver_start().unwrap();
    let writes = ape_writes(&m);
    assert!(!writes.iter().any(|&(at, _)| at == 0x0c || at == 0x4300));
    // The lock is given back after every look, the last one included.
    let requests = writes.iter().filter(|&&w| w == (0x8410, 0x1000)).count();
    let releases = writes.iter().filter(|&&w| w == (0x8430, 0x1000)).count();
    assert_eq!((requests, releases), (2001, 2001));
    let waits = m
        .borrow()
        .trace
        .iter()
        .filter(|e| **e == Event::Delay(10))
        .count();
    assert_eq!(waits, 2000);
    assert_eq!(hardware.failure(), None);
    // An ungranted memory lock drops the event too, as Linux does.
    let (mut hardware, m) = identified(Asic::Bcm5720, 0);
    running_ape(&m);
    m.borrow_mut().no_grant = true;
    hardware.ape_driver_start().unwrap();
    assert!(!ape_writes(&m).iter().any(|&(at, _)| at == 0x0c));
    assert_eq!(hardware.failure(), None);
}

#[test]
fn without_running_ape_firmware_only_the_host_state_is_written() {
    for (signature, status) in [(0, 0x100), (0x4150_4521, 0)] {
        let (mut hardware, m) = identified(Asic::Bcm5762, 0);
        m.borrow_mut().ape.insert(0x4000, signature);
        m.borrow_mut().ape.insert(0x400c, status);
        hardware.ape_driver_start().unwrap();
        let writes = ape_writes(&m);
        assert_eq!(writes.last(), Some(&(0x421c, 1)));
        assert!(!writes.iter().any(|&(at, _)| at == 0x8410 || at == 0x0c));
    }
}

#[test]
fn nvram_and_firmware_timeouts_never_produce_reset_completion() {
    let (mut hardware, m) = reset_model(Asic::Bcm5720);
    m.borrow_mut().no_nvram_grant = true;
    assert_eq!(hardware.reset_core(), Err(Error::NvramTimeout));
    assert!(!hardware.core_reset_completed());
    assert!(!m.borrow().reset_pending);
    assert!(m.borrow().trace.contains(&Event::Write(0x7020, 0x20)));
    let (mut hardware, m) = reset_model(Asic::Bcm5762);
    m.borrow_mut().reset_firmware_ack = false;
    assert_eq!(hardware.reset_core(), Err(Error::FirmwareTimeout));
    assert!(!hardware.core_reset_completed());
    drop(hardware);
    assert_eq!(m.borrow().dropped, 0);
}

#[test]
fn every_core_reset_access_fault_keeps_the_epoch() {
    let (mut hardware, m) = reset_model(Asic::Bcm5720);
    let before = m.borrow().io_count;
    hardware.reset_core().unwrap();
    let count = m.borrow().io_count - before;
    for fail in 1..=count {
        let (mut hardware, m) = reset_model(Asic::Bcm5720);
        let before = m.borrow().io_count;
        m.borrow_mut().fail_at = Some(before + fail);
        assert_eq!(
            hardware.reset_core(),
            Err(Error::Access),
            "reset I/O {fail}"
        );
        assert!(!hardware.core_reset_completed());
        assert_eq!(hardware.read_phy(2), Err(Error::Poisoned));
        drop(hardware);
        assert_eq!(m.borrow().dropped, 0);
    }
}

#[test]
fn ignored_mandatory_reset_controls_never_count_as_completion() {
    for at in [MISC_HOST_CTRL, PCISTATE, 0x48] {
        let (mut hardware, m) = reset_model(Asic::Bcm5720);
        m.borrow_mut().ignored_config_write = Some(at);
        assert_eq!(
            hardware.reset_core(),
            Err(Error::ConfigDidNotLatch),
            "config {at:x}"
        );
        assert!(!hardware.core_reset_completed());
    }
    let (mut hardware, m) = reset_model(Asic::Bcm5720);
    m.borrow_mut().stuck_stop = Some(MEMARB_MODE);
    assert_eq!(hardware.reset_core(), Err(Error::ConfigDidNotLatch));
    assert!(!hardware.core_reset_completed());
}

#[test]
fn absent_or_invalid_board_ownership_evidence_refuses_before_reset() {
    for signature in [0, 1, u32::MAX, !FIRMWARE_MAGIC] {
        let (mut hardware, m) = reset_model(Asic::Bcm5762);
        m.borrow_mut().sram.insert(0xb54, signature);
        assert_eq!(hardware.reset_core(), Err(Error::UnsignedBoard));
        assert!(!hardware.core_reset_completed());
        assert!(
            !m.borrow()
                .trace
                .iter()
                .any(|e| matches!(e, Event::Write(0x6804, _) | Event::Write(MAC_RX_MODE, _)))
        );
    }
}

#[test]
fn unavailable_native_clock_refuses_before_identification_access_and_keeps_original_owner() {
    for asic in [Asic::Bcm5761, Asic::Bcm5720, Asic::Bcm5762] {
        for rate in [0, 3_000, u64::MAX] {
            let (mut previous, model) = model(asic, 0);
            let registers = previous.release_registers();
            // SAFETY: isolated original symbolic owner; invalid
            // timing must refuse before the first hardware observation.
            let mut hardware = unsafe {
                Hardware::new(
                    registers,
                    crate::timing::refused_model(crate::Clock {
                        ticks_per_microsecond: rate,
                    }),
                )
            };
            assert_eq!(
                hardware.identify(),
                Err(Error::Timing(crate::bus::pci::power::Error::Clock))
            );
            assert!(hardware.identity().is_none());
            assert!(model.borrow().trace.is_empty());
            drop(hardware);
            assert_eq!(model.borrow().dropped, 0);
        }
    }
}

#[test]
fn every_mdio_wait_failure_restores_autopoll_releases_original_grant_and_poison_keeps() {
    for asic in [Asic::Bcm5761, Asic::Bcm5720, Asic::Bcm5762] {
        let (mut hardware, model) = identified(asic, 1);
        model
            .borrow_mut()
            .mac
            .insert(MAC_MI_MODE, MI_AUTO_POLL | 0xc0000);
        let before = model.borrow().delay_count;
        hardware.read_phy(7).unwrap();
        let count = model.borrow().delay_count - before;
        assert!(
            count >= 4,
            "initial/poll/result/restore settling waits required"
        );
        for failing in 1..=count {
            let (mut hardware, model) = identified(asic, 1);
            {
                let mut model = model.borrow_mut();
                model.mac.insert(MAC_MI_MODE, MI_AUTO_POLL | 0xc0000);
                model.fail_delay = Some(model.delay_count + failing);
            }
            assert_eq!(
                hardware.read_phy(7),
                Err(Error::Timing(crate::bus::pci::power::Error::Clock)),
                "{asic:?} wait {failing}"
            );
            let grant = if asic == Asic::Bcm5761 {
                APE_LOCK_GRANT
            } else {
                APE_PER_LOCK_GRANT
            };
            let at = grant + u32::from(PHY_LOCKS[1]) * 4;
            assert_eq!(model.borrow().mac[&MAC_MI_MODE], MI_AUTO_POLL | 0xc0000);
            assert_eq!(model.borrow().ape.get(&at).copied().unwrap_or(0), 0);
            if failing == 1 {
                assert!(
                    !model
                        .borrow()
                        .trace
                        .iter()
                        .any(|event| matches!(event, Event::Write(MAC_MI_COM, _)))
                );
            } else {
                assert!(
                    matches!(model.borrow().trace.last(), Some(Event::ApeWrite(offset, APE_DRIVER)) if *offset == at)
                );
            }
            assert_eq!(
                hardware.failure(),
                Some(Error::Timing(crate::bus::pci::power::Error::Clock))
            );
            let effects = model.borrow().trace.len();
            assert_eq!(hardware.read_phy(7), Err(Error::Poisoned));
            assert_eq!(model.borrow().trace.len(), effects);
            drop(hardware);
            assert_eq!(model.borrow().dropped, 0);
        }
    }
}

#[test]
fn every_core_reset_wait_failure_prevents_completion_and_keeps_original_epoch() {
    for asic in [Asic::Bcm5761, Asic::Bcm5720, Asic::Bcm5762] {
        let (mut hardware, model) = reset_model(asic);
        let before = model.borrow().delay_count;
        hardware.reset_core().unwrap();
        let count = model.borrow().delay_count - before;
        assert!(count > 2);
        for failing in 1..=count {
            let (mut hardware, model) = reset_model(asic);
            let fail_at = model.borrow().delay_count + failing;
            model.borrow_mut().fail_delay = Some(fail_at);
            assert_eq!(
                hardware.reset_core(),
                Err(Error::Timing(crate::bus::pci::power::Error::Clock)),
                "{asic:?} wait {failing}"
            );
            assert!(!hardware.core_reset_completed());
            assert_eq!(
                hardware.failure(),
                Some(Error::Timing(crate::bus::pci::power::Error::Clock))
            );
            let effects = model.borrow().trace.len();
            assert_eq!(hardware.read_phy(2), Err(Error::Poisoned));
            assert_eq!(model.borrow().trace.len(), effects);
            drop(hardware);
            assert_eq!(model.borrow().dropped, 0);
        }
    }
}

mod cold;
