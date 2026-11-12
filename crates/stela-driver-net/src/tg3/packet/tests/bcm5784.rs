// SPDX-License-Identifier: GPL-2.0-only
//! A BCM5784 after AX on the 5761 path: no APE, 512-entry rings, the
//! 5787 NVRAM table, its OTP PHY trim, receive-only reset fix, APD and
//! read DMA corruption checks.
use super::*;

/// What the OTP returns for each of its two reads.
const OTP_WORD: u32 = 0x1234_5678;

impl Device {
    pub(super) fn is_5784(&self) -> bool {
        matches!(self.config[&0], 0x1698_14e4 | 0x1684_14e4)
    }
    /// The 5755_PLUS chips before 57765_PLUS: 5761 and 5784.
    pub(super) fn is_legacy(&self) -> bool {
        self.is_5761() || self.is_5784()
    }
    fn new_5784(device: u16, revision: u32) -> Self {
        let mut p = Self::new();
        p.config.insert(0, u32::from(device) << 16 | 0x14e4);
        p.config.insert(0xbc, revision);
        p.config.insert(0xf4, 0xdead_beef); // Must use the original PRODID.
        p.sram.insert(0xb58, 0x10);
        // TG3_PHY_ID_BCM5784, which tg3 takes from the signed SRAM.
        let id = 0xbc05_0fa1u32;
        p.phy.insert(2, (id >> 10) as u16);
        p.phy
            .insert(3, (((id >> 16) & 0xfc00) | (id & 0x3ff)) as u16);
        p.mac.insert(0x7508, 1); // OTP command done.
        p.mac.insert(0x7514, OTP_WORD);
        p.mac.insert(0x3600, 0x0001_0005); // CPMU, 10-Mb/s receive-only.
        for at in [0x6c, 0x4910, 0x2d00, 0x2448] {
            p.mac.insert(at, 0x0110_0080);
        }
        for index in 1..17 {
            p.sram.insert(0x200 + index * 16 + 8, 0xdec0_0000 + index);
        }
        for index in 1..4 {
            p.sram.insert(0x100 + index * 16 + 8, 0xdec0_0000 + index);
        }
        p
    }
    pub(super) fn require_5784_dma(&self) {
        // PCIe 1.0a post-reset fix, jitter DSP, 512-entry rings.
        self.require_bits(0x7c00, 0x0200_0000, 0x0200_0000);
        assert_eq!(self.dsp[&0xa], 0x010b);
        assert_eq!(self.mac[&0x2458], 512 << 16);
        assert_eq!(self.sram[&0x208], 512 << 16);
        // BD and mbuf corruption checks, IPv4 TSO2 only, no 5761 delay.
        self.require_bits(0x4800, 0x1800_3800, 0x0800_3800);
        self.require_bits(0x1000, 0x13, 0x2);
        self.require_bits(0x4900, 4, 4);
        self.require_bits(0x4400, 0x17, 6); // no MBLOW attention.
        for at in [0x6c, 0x4910, 0x2d00, 0x2448] {
            assert_eq!(self.mac[&at], 0x0110_0080, "modern-only control {at:x}");
        }
        for index in 1..17 {
            assert_eq!(self.sram[&(0x200 + index * 16 + 8)], 0xdec0_0000 + index);
        }
        for index in 1..4 {
            assert_eq!(self.sram[&(0x100 + index * 16 + 8)], 0xdec0_0000 + index);
        }
    }
}
fn attach(device: Device) -> (Packet<Reg, Timer>, Pages, Arc<Domain>, Arc<Mutex<Device>>) {
    let (hardware, pages, domain, peer) = parts();
    *peer.lock().unwrap() = device;
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
        Ok(packet) => packet,
        Err((e, _)) => panic!("5784 attach: {e:?}"),
    };
    (packet, pages, domain, peer)
}
/// The value of the last SCR5 shadow write.
fn scr5(p: &Device) -> u16 {
    p.phy_writes
        .iter()
        .rev()
        .find(|(at, value)| *at == 0x1c && value & 0x7c00 == 0x1400)
        .unwrap()
        .1
}

#[test]
fn a_5784_moves_frames_on_the_5761_path_with_its_own_phy_deltas() {
    if crate::test_process::isolate_model() {
        return;
    }
    for (device, revision) in [(0x1698, 0x0578_4100), (0x1684, 0x0578_4200)] {
        let (mut packet, _, domain, peer) = attach(Device::new_5784(device, revision));
        {
            let p = peer.lock().unwrap();
            assert!(p.ape.is_empty());
            assert_eq!(p.config.get(&0x70).copied().unwrap_or(0) & 0x7_0000, 0);
            // tg3_phy_apply_otp from the merged OTP halves, 0x5678_1234.
            for (at, value) in [
                (0x0001, 0x17),
                (0x001f, 0x100),
                (0x601f, 2),
                (0x0f75, 0x56),
                (0x0f96, 0x10),
                (0x0f97, 0xc18),
            ] {
                assert_eq!(p.dsp[&at], value, "OTP DSP {at:x}");
            }
            // The PHY reset ran with receive-only off; the CPMU is restored
            // and the PHY rejects 2-MHz energy.
            assert_eq!(p.dsp[&0x0f08], 0x201);
            assert_eq!(p.mac[&0x3600], 0x0001_0005);
            // No APD: SCR5 keeps DLLAPD. No EEE registers.
            assert_eq!(scr5(&p) & 2, 2);
            assert!(!p.mac.contains_key(&0x36b0));
        }
        assert!(packet.carrier());
        packet.transmit(&[0x5a; 60]).unwrap();
        peer.lock().unwrap().receive(&[0x6b; 60], 0, &domain);
        assert_eq!(packet.receive().unwrap(), Some(vec![0x6b; 60]));
        assert_eq!(peer.lock().unwrap().sent, [vec![0x5a; 60]]);
        assert!(packet.retire().is_ok());
    }
}

#[test]
fn a_5784_enabling_apd_keeps_its_dll_and_unreadable_otp_takes_the_default() {
    if crate::test_process::isolate_model() {
        return;
    }
    let mut device = Device::new_5784(0x1698, 0x0578_4100);
    device.sram.insert(0xd38, 0x4000); // APD_EN.
    device.mac.insert(0x7508, 0); // OTP never finishes.
    let (packet, _, _, peer) = attach(device);
    {
        let p = peer.lock().unwrap();
        assert_eq!(scr5(&p) & 2, 0);
        // TG3_OTP_DEFAULT, 0x286c_1640.
        assert_eq!(p.dsp[&0x0f75], 0x28);
        assert_eq!(p.dsp[&0x0f96], 0x10);
    }
    assert!(packet.retire().is_ok());
}

#[test]
fn a_5784_ax_or_an_aspm_workaround_board_never_publishes_dma() {
    if crate::test_process::isolate_model() {
        return;
    }
    for fault in 0..2 {
        let mut device = Device::new_5784(0x1698, 0x0578_4100);
        let expected = if fault == 0 {
            device.config.insert(0xbc, 0x0578_4001);
            Error::UnsupportedRevision
        } else {
            device.sram.insert(0xd3c, 2); // NIC_SRAM_ASPM_DEBOUNCE.
            Error::UnsupportedBoard
        };
        let (hardware, pages, domain, peer) = parts();
        *peer.lock().unwrap() = device;
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
            Ok(_) => panic!("fault {fault} attached"),
            Err((e, _)) => assert_eq!(e, expected),
        }
        let p = peer.lock().unwrap();
        assert_eq!(p.dma_effects, 0);
        assert_eq!(p.config[&4] & 4, 0);
    }
}

#[test]
fn the_5787_nvram_table_fixes_atmel_flash_at_264_byte_pages() {
    if crate::test_process::isolate_model() {
        return;
    }
    // Atmel buffered flash with a 512-byte strap, ST flash and an EEPROM:
    // the address comes from NVRAM at 0x7c either way below one page.
    for strap in [0x0340_0001u32 | 0x1000_0000, 0x0240_0000, 0x0300_0003] {
        let mut device = Device::new_5784(0x1698, 0x0578_4100);
        device.mac.insert(0x7014, strap);
        device.sram.insert(0xc14, 0);
        device.nvram.insert(0x7c, 0x0211);
        device.nvram.insert(0x80, 0x2233_4455);
        let (packet, _, _, _) = attach(device);
        assert_eq!(packet.mac(), Mac([2, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert!(packet.retire().is_ok());
    }
    // A strap outside the 5787 table is refused.
    let mut device = Device::new_5784(0x1698, 0x0578_4100);
    device.mac.insert(0x7014, 0x0080_0000);
    let (hardware, pages, domain, peer) = parts();
    *peer.lock().unwrap() = device;
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
        Ok(_) => panic!("unknown strap attached"),
        Err((e, _)) => assert_eq!(e, Error::UnsupportedBoard),
    }
}
