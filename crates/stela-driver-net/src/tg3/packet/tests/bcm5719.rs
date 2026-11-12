// SPDX-License-Identifier: GPL-2.0-only
//! A BCM5719 after A0: the 5720's 5717_PLUS path with tg3's 5719 deltas.
use super::*;

impl Device {
    pub(super) fn is_5719(&self) -> bool {
        self.config[&0] == 0x1657_14e4
    }
    /// A BCM5719 A1 function on internal port 2 of four, copper, with
    /// its own BCM5719C PHY and the ST serial flash code both NVRAM
    /// tables share.
    pub(super) fn new_5719() -> Self {
        let mut p = Self::new();
        p.config.insert(0, 0x1657_14e4);
        p.config.insert(0xf4, 0x0571_9001);
        p.sram.insert(0xe00, (2 << 30) | 0x362c);
        let id = 0x5c0d_8a21u32;
        p.phy.insert(2, (id >> 10) as u16);
        p.phy
            .insert(3, (((id >> 16) & 0xfc00) | (id & 0x3ff)) as u16);
        // Firmware-owned transmit length, mode and read DMA bits that only
        // 5720 and 5762 keep.
        p.mac.insert(0x464, 0x00ff_0000);
        p.mac.insert(0x45c, 0x00c0_0000);
        p
    }
}
fn parts_5719() -> (Hardware<Reg, Timer>, Pages, Arc<Domain>, Arc<Mutex<Device>>) {
    let (hardware, pages, domain, peer) = parts();
    *peer.lock().unwrap() = Device::new_5719();
    (hardware, pages, domain, peer)
}
fn attach_5719(
    peer_setup: impl FnOnce(&mut Device),
) -> (Packet<Reg, Timer>, Pages, Arc<Domain>, Arc<Mutex<Device>>) {
    let (hardware, pages, domain, peer) = parts_5719();
    peer_setup(&mut peer.lock().unwrap());
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
        Ok(packet) => packet,
        Err((e, _)) => panic!("5719 attach: {e:?}"),
    };
    (packet, pages, domain, peer)
}

#[test]
fn actual_5719_starts_with_its_own_power_source_phy_and_buffer_manager_and_moves_frames() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut packet, _, domain, peer) = attach_5719(|_| {});
    {
        let p = peer.lock().unwrap();
        // tg3_set_function_status: port 2's driver-present bits in the
        // APE's GPIO message word, never in the 5720's CPMU register.
        assert_eq!(p.ape[&0x8], 1 << (4 + 4 * 2));
        assert!(!p.mac.contains_key(&0x344c));
        // tg3_phy_autoneg_cfg clears TAP26 with nothing advertised, then
        // makes the CH34TP2 change it shares with 5720.
        assert_eq!(p.dsp[&0x1a], 0);
        assert_eq!(p.dsp[&0x4022] & 1, 1);
        // tg3_reset_hw: NO_TX_UNDERRUN; no statistics workaround after A0.
        p.require_bits(0x4400, 0x8000_0016, 0x8000_0006);
        p.require_bits(0x6800, 0x1000_0000, 0);
        p.require_bits(0x3c00, 4, 0);
        // The 5720's kept fields are rewritten from tg3's own values.
        assert_eq!(p.mac[&0x464] & 0x00ff_0000, 0);
        assert_eq!(p.mac[&0x45c] & 0x00c0_0000, 0);
        // 5719 shares the 5720's FIFO and 4K boundary fixes.
        p.require_bits(0x4900, 4, 4);
        p.require_bits(0x4910, 0xf0000, 0xf0000);
        assert_eq!(p.mac[&0x4910] & 0x0220_0000, 0);
    }
    assert!(packet.carrier());
    packet.transmit(&[0x5a; 60]).unwrap();
    peer.lock().unwrap().receive(&[0x6b; 60], 0, &domain);
    assert_eq!(packet.receive().unwrap(), Some(vec![0x6b; 60]));
    assert_eq!(peer.lock().unwrap().sent, [vec![0x5a; 60]]);
    // The status requests behind each poll carry no statistics attention.
    peer.lock().unwrap().require_bits(0x3c00, 4, 0);
    assert!(packet.retire().is_ok());
}

#[test]
fn a_long_residual_read_dma_length_sets_the_5719_workaround_bit() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (packet, _, _, peer) = attach_5719(|p| {
        p.mac.insert(0x4be8, 9001);
    });
    assert_eq!(peer.lock().unwrap().mac[&0x4910] & 0x0220_0000, 0x0200_0000);
    assert!(packet.retire().is_ok());
}

#[test]
fn a_5719_eeprom_is_decoded_from_the_5717_table() {
    if crate::test_process::isolate_model() {
        return;
    }
    // FLASH_5717VENDOR_ATMEL_EEPROM is an ST flash code on 5720. As an
    // EEPROM it reads unpaged, with the compatibility bypass cleared.
    let (packet, _, _, peer) = attach_5719(|p| {
        p.mac.insert(0x7014, 0x8200_0001);
        p.sram.insert(0xc14, 0);
        p.nvram.insert(0x7c + 0x18c, 0x0000_0211);
        p.nvram.insert(0x7c + 0x18c + 4, 0x2233_4466);
    });
    {
        let p = peer.lock().unwrap();
        assert_eq!(p.mac[&0x7014] & 0x8000_0000, 0);
        assert_eq!((p.mac[&0x410], p.mac[&0x414]), (0x0211, 0x2233_4466));
    }
    assert!(packet.retire().is_ok());
}

#[test]
fn a_5719_a0_or_a_5720_revision_never_publishes_dma() {
    if crate::test_process::isolate_model() {
        return;
    }
    for revision in [0x0571_9000, 0x0572_0000] {
        let (hardware, pages, domain, peer) = parts_5719();
        peer.lock().unwrap().config.insert(0xf4, revision);
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
            Ok(_) => panic!("{revision:x} attached"),
            Err((e, _)) => assert_eq!(e, Error::UnsupportedRevision, "{revision:x}"),
        }
        let p = peer.lock().unwrap();
        assert_eq!(p.dma_effects, 0);
        assert_eq!(p.config[&4] & 4, 0);
    }
}
