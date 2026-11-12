// SPDX-License-Identifier: GPL-2.0-only
//! A BCM57765-class function after A0: no APE, 512/1024 rings and tg3's
//! 57765_CLASS deltas.
use super::*;

impl Device {
    /// A 57765-class function: a 57765 or a 57766.
    pub(super) fn is_57765(&self) -> bool {
        crate::tg3::gen15_product((self.config[&0] >> 16) as u16)
    }
    /// A BCM57765 B0-class function with its BCM57765 PHY. The default
    /// NVRAM strap is the 57780 table's 376-kHz Microchip EEPROM.
    pub(super) fn new_57765(device: u16) -> Self {
        let mut p = Self::new();
        p.config.insert(0, u32::from(device) << 16 | 0x14e4);
        p.config.insert(0xf4, 0xdead_beef); // GEN2 is not this chip's register.
        p.config.insert(0xfc, 0x5778_5100);
        let id = 0x5c0d_8a41u32;
        p.phy.insert(2, (id >> 10) as u16);
        p.phy
            .insert(3, (((id >> 16) & 0xfc00) | (id & 0x3ff)) as u16);
        if crate::tg3::ten_hundred_only(device) {
            p.phy.insert(0x19, 0x500); // 100 full.
        }
        // Rings past the 57765's second send and fourth return RCB, and the
        // 5719/5720 LSO register, are not touched.
        for index in 2..4 {
            p.sram.insert(0x100 + index * 16 + 8, 0xdec0_0000 + index);
        }
        for index in 4..17 {
            p.sram.insert(0x200 + index * 16 + 8, 0xdec0_0000 + index);
        }
        p.mac.insert(0x4910, 0x0110_0080);
        p
    }
}
fn attach_57765(device: u16) -> (Packet<Reg, Timer>, Pages, Arc<Domain>, Arc<Mutex<Device>>) {
    let (hardware, pages, domain, peer) = parts();
    *peer.lock().unwrap() = Device::new_57765(device);
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
        Ok(packet) => packet,
        Err((e, _)) => panic!("57765 class {device:x} attach: {e:?}"),
    };
    (packet, pages, domain, peer)
}

#[test]
fn actual_57765_class_moves_frames_without_an_ape_on_its_own_rings() {
    if crate::test_process::isolate_model() {
        return;
    }
    for device in [0x16b4, 0x16b0, 0x16b5, 0x16b2] {
        let (mut packet, _, domain, peer) = attach_57765(device);
        {
            let p = peer.lock().unwrap();
            // No APE: no APE access, no APE space, no APE MAC bits.
            assert!(p.ape.is_empty(), "{device:x}");
            assert_eq!(p.config.get(&0x70).copied().unwrap_or(0) & 0x7_0000, 0);
            p.require_bits(0x400, 0x1800_0000, 0);
            // The debug UART is off; VMain needs no driver-present bits.
            p.require_bits(0x6808, 0x10, 0x10);
            assert!(!p.mac.contains_key(&0x344c));
            // 512-entry standard and 1024-entry return rings, the standard
            // ring's NIC address, two send and four return RCBs.
            assert_eq!(p.mac[&0x2458], (512 << 16) | (1536 << 2));
            assert_eq!(p.mac[&0x245c], 0x6000);
            assert_eq!(p.sram[&0x208], 1024 << 16);
            assert_eq!(p.sram[&0x118], 2);
            for index in 1..4 {
                assert_eq!(p.sram[&(0x200 + index * 16 + 8)], 2);
            }
            for index in 2..4 {
                assert_eq!(p.sram[&(0x100 + index * 16 + 8)], 0xdec0_0000 + index);
            }
            for index in 4..17 {
                assert_eq!(p.sram[&(0x200 + index * 16 + 8)], 0xdec0_0000 + index);
            }
            p.require_bits(0x2400, 0x10000, 0);
            assert_eq!(p.mac[&0x504], 1);
            assert_eq!(p.mac[&0x4910], 0x0110_0080);
            p.require_bits(0x3c00, 4, 0);
            assert_eq!(p.dsp[&0x1a], 0);
            // BCM57791/57795 have no gigabit control to write.
            let gigabit = p.phy_writes.iter().any(|(at, _)| *at == 9);
            assert_eq!(gigabit, !crate::tg3::ten_hundred_only(device), "{device:x}");
        }
        assert!(packet.carrier());
        packet.transmit(&[0x5a; 60]).unwrap();
        peer.lock().unwrap().receive(&[0x6b; 60], 0, &domain);
        assert_eq!(packet.receive().unwrap(), Some(vec![0x6b; 60]));
        assert_eq!(peer.lock().unwrap().sent, [vec![0x5a; 60]]);
        assert!(packet.retire().is_ok());
        assert!(peer.lock().unwrap().ape.is_empty());
    }
}

#[test]
fn the_1024_entry_return_ring_wraps() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut packet, _, domain, peer) = attach_57765(0x16b4);
    assert!(packet.carrier());
    for round in 0..1100u32 {
        let frame = vec![round as u8; 60];
        peer.lock().unwrap().receive(&frame, 0, &domain);
        assert_eq!(packet.receive().unwrap(), Some(frame), "{round}");
    }
    assert_eq!(peer.lock().unwrap().ret, 1100 - 1024);
    assert!(packet.retire().is_ok());
}

#[test]
fn a_57765_a0_never_publishes_dma() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (hardware, pages, domain, peer) = parts();
    *peer.lock().unwrap() = Device::new_57765(0x16b4);
    peer.lock().unwrap().config.insert(0xfc, 0x5778_5000);
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
        Ok(_) => panic!("57765 A0 attached"),
        Err((e, _)) => assert_eq!(e, Error::UnsupportedRevision),
    }
    let p = peer.lock().unwrap();
    assert_eq!(p.dma_effects, 0);
    assert_eq!(p.config[&4] & 4, 0);
}
