// SPDX-License-Identifier: GPL-2.0-only
//! Authored UNRUN BCM5762 device effects. Profile evidence comes from
//! config/PHY/NVM/register bytes, never a caller-supplied native capability.
use super::*;

impl Device {
    pub(super) fn new_5762() -> Self {
        let mut p = Self::new();
        p.config.insert(0, 0x1687_14e4);
        p.config.insert(0xf4, 0x0576_2000);
        p.config.insert(0x2c, 0x1234_14e4);
        p.sram.insert(0xb58, 0x10); // explicitly copper NIC, no managers/WP.
        let id = 0x8580_3783u32;
        p.phy.insert(2, (id >> 10) as u16);
        p.phy
            .insert(3, (((id >> 16) & 0xfc00) | (id & 0x3ff)) as u16);
        p.mac.insert(0x7014, 0x0080_0000); // 5762 MX25L100.
        p.mac.insert(0x7038, 0); // autosense density code0.
        p.nvram.insert(0, 0x6699_55aa);
        p.mac.insert(0x6808, 0x10); // UART selector kept.
        p.mac.insert(0x4890, 0x93db_a951);
        p.mac.insert(0x48a0, 0x0010_0080);
        p.mac.insert(0x4910, 0x0110_0080);
        // Higher RCBs are NOT implemented on5762. Writes there are forbidden.
        for index in 2..4 {
            p.sram.insert(0x100 + index * 16 + 8, 0xdec0_0000 + index);
        }
        for index in 4..17 {
            p.sram.insert(0x200 + index * 16 + 8, 0xdec0_0000 + index);
        }
        p
    }
    pub(super) fn require_5762_dma(&self) {
        assert_eq!(self.config[&0xf4], 0x0576_2000);
        assert_ne!(self.config[&0x2c], 0x07f0_1028);
        self.require_bits(0x3628, 0x2000, 0x2000); // 100Mb core clock fix.
        self.require_bits(0x6808, 0x0100_0018, 0x0100_0018);
        self.require_bits(0x6c, 1, 1); // x86 cache-alignment policy.
        self.require_bits(0x4890, 0xffef_fff4, 0x280c_0c04);
        self.require_bits(0x48a0, 0x000f_0000, 0x000f_0000);
        self.require_bits(0x468, 0x0200_0000, 0x0200_0000);
        assert_eq!(self.mac[&0x4900], 0x0123_0840, "no 5720 reserve write");
        assert_eq!(self.mac[&0x4910], 0x0110_0080, "no 5720 LSO write");
        assert_eq!(self.dsp[&0xffb], 0x4000);
        assert_eq!(self.mac[&0x245c], 0x6000);
        assert_eq!(self.mac[&0x2458], (2048 << 16) | (1536 << 2));
        assert_eq!(self.sram[&0x108], 512 << 16);
        assert_eq!(self.sram[&0x10c], 0x4000);
        assert_eq!(self.sram[&0x208], 4096 << 16);
        assert_eq!(self.sram[&0x20c], 0);
        assert_eq!(self.sram[&0x118], 2);
        for index in 1..4 {
            assert_eq!(self.sram[&(0x200 + index * 16 + 8)], 2);
        }
        for index in 2..4 {
            assert_eq!(self.sram[&(0x100 + index * 16 + 8)], 0xdec0_0000 + index);
        }
        for index in 4..17 {
            assert_eq!(self.sram[&(0x200 + index * 16 + 8)], 0xdec0_0000 + index);
        }
    }
}
fn parts_5762() -> (Hardware<Reg, Timer>, Pages, Arc<Domain>, Arc<Mutex<Device>>) {
    let (hardware, pages, domain, peer) = parts();
    *peer.lock().unwrap() = Device::new_5762();
    (hardware, pages, domain, peer)
}
pub(super) fn attach_5762() -> (Packet<Reg, Timer>, Pages, Arc<Domain>, Arc<Mutex<Device>>) {
    let (hardware, pages, domain, peer) = parts_5762();
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
        Ok(packet) => packet,
        Err((e, _)) => panic!("5762 attach: {e:?}"),
    };
    (packet, pages, domain, peer)
}
#[test]
fn actual_5762_alternate_registers_rings_and_retained_nonidentity_dma_transfer() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut packet, pages, domain, peer) = attach_5762();
    assert_eq!(
        packet.hardware.identity().unwrap().asic,
        super::super::super::Asic::Bcm5762
    );
    assert!(packet.carrier());
    packet.transmit(&[0x5a; 60]).unwrap();
    peer.lock().unwrap().receive(&[0x6b; 60], 0, &domain);
    assert_eq!(packet.receive().unwrap(), Some(vec![0x6b; 60]));
    {
        let p = peer.lock().unwrap();
        assert_eq!(p.sent, [vec![0x5a; 60]]);
        assert_eq!(p.mac[&0x4890], (0x93db_a951 & !0xffef_fff0) | 0x280c_0c04);
        assert_eq!(p.mac[&0x48a0], 0x001f_0080);
        assert!(
            !p.access
                .iter()
                .any(|(w, at, _)| !w && (0x4be0..0x4bf0).contains(at))
        );
        assert!(!p.access.iter().any(|(w, at, _)| *w && *at == 0x344c));
    }
    assert!(packet.retire().is_ok());
    assert_eq!(pages.drops.load(Ordering::Relaxed), 6);
    assert!(domain.maps.lock().unwrap().is_empty());
    assert_eq!(peer.lock().unwrap().drops, 1);
}
#[test]
fn actual_5762_all_admitted_nvm_straps_require_real_magic_and_fixed_mac_offset() {
    if crate::test_process::isolate_model() {
        return;
    }
    for strap in [
        0x0200_0001,
        0x0200_0003,
        0x0080_0000,
        0x0080_0002,
        0x0080_0001,
        0x0080_0003,
        0x0380_0002,
    ] {
        let (hardware, pages, domain, peer) = parts_5762();
        {
            let mut p = peer.lock().unwrap();
            p.mac.insert(0x7014, strap | 0x8000_0000); // compat bypass must really clear for EEPROM.
            p.sram.insert(0xc14, 0);
            p.nvram.insert(0x7c, 0x0211);
            p.nvram.insert(0x80, 0x2233_4455);
            // BDFfunction3 must not select the 5720 secondary MAC.
            p.nvram.insert(0x258, 0xdead_beef);
            p.nvram.insert(0x25c, 0xdead_beef);
        }
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        let packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
            Ok(packet) => packet,
            Err((e, _)) => panic!("strap {strap:x}: {e:?}"),
        };
        assert_eq!(packet.mac(), Mac([2, 0x11, 0x22, 0x33, 0x44, 0x55]));
        {
            let p = peer.lock().unwrap();
            assert!(
                p.access
                    .iter()
                    .any(|(w, at, v)| *w && *at == 0x700c && *v == 0x7c)
            );
            assert!(
                !p.access
                    .iter()
                    .any(|(w, at, v)| *w && *at == 0x700c && *v >= 0xcc)
            );
            if strap & 0x03e0_0003 == 0x0200_0001 || strap & 0x03e0_0003 == 0x0200_0003 {
                assert_eq!(p.mac[&0x7014] & 0x8000_0000, 0);
            }
        }
        assert!(packet.retire().is_ok());
    }
}
#[test]
fn actual_5762_static_revision_and_dell_denials_precede_any_mmio_effect() {
    if crate::test_process::isolate_model() {
        return;
    }
    for fault in 0..3 {
        let (hardware, pages, domain, peer) = parts_5762();
        {
            let mut p = peer.lock().unwrap();
            match fault {
                0 => {
                    p.config.insert(0xf4, 0x0576_2001);
                }
                1 => {
                    p.config.insert(0x2c, 0x07f0_1028);
                }
                _ => {
                    p.config.insert(0x2c, u32::MAX);
                }
            }
        }
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        let (_, packet) = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
            Err(value) => value,
            Ok(_) => panic!("unsupported profile admitted"),
        };
        assert_eq!(pages.allocated.get(), 0);
        assert_eq!(peer.lock().unwrap().config[&0x68], 0xf000_0000);
        assert!(
            peer.lock()
                .unwrap()
                .access
                .iter()
                .all(|(_, at, _)| *at >= 0x10000)
        );
        drop(packet);
        assert_eq!(peer.lock().unwrap().drops, 0);
    }
}
#[test]
fn actual_5762_unknown_unsigned_lom_nvm_and_phy_never_publish_dma() {
    if crate::test_process::isolate_model() {
        return;
    }
    for fault in 0..12 {
        let (hardware, pages, domain, peer) = parts_5762();
        {
            let mut p = peer.lock().unwrap();
            match fault {
                0 => {
                    p.mac.insert(0x7014, 0);
                }
                1 => {
                    p.mac.insert(0x7014, 0x0200_0000);
                } // 5720 ST, not5762 EEPROM.
                2 => {
                    p.nvram.insert(0, u32::MAX);
                }
                3 => {
                    p.nvram.insert(0, 0);
                }
                4 => {
                    p.sram.insert(0xb54, 0);
                } // unsigned board.
                5 => {
                    p.sram.insert(0xb54, !0x4b65_7654);
                }
                6 => {
                    p.sram.insert(0xb58, 0x110);
                } // EEPROM_WP/LOM.
                7 => {
                    p.sram.insert(0xb58, 0x20);
                } // fiber strap.
                8 => {
                    p.phy.insert(2, 0);
                    p.phy.insert(3, 0);
                }
                9 => {
                    p.sram.insert(0xb5c, 0);
                }
                10 => {
                    p.sram.insert(0xb58, 0);
                }
                _ => {
                    p.sram.insert(0xb58, 0x30);
                }
            }
        }
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        let (error, mut packet) = match unsafe { Packet::attach(hardware, &pages, domain.clone()) }
        {
            Err(value) => value,
            Ok(_) => panic!("fault {fault} admitted"),
        };
        if fault == 6 {
            assert_eq!(error, Error::UnsupportedBoard);
        }
        assert_eq!(pages.allocated.get(), 0);
        assert_eq!(peer.lock().unwrap().config[&4] & 4, 0);
        assert!(packet.transmit(&[0; 60]).is_err());
        assert_eq!(peer.lock().unwrap().dma_effects, 0);
        drop(packet);
        assert_eq!(peer.lock().unwrap().drops, 0);
    }
}
#[test]
fn actual_5762_changed_postreset_nvm_profile_is_not_reused() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (hardware, pages, domain, peer) = parts_5762();
    peer.lock().unwrap().reset_nvram = Some(0x0080_0002);
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let (error, packet) = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
        Err(value) => value,
        Ok(_) => panic!("changed NVM admitted"),
    };
    assert_eq!(error, Error::UnsupportedBoard);
    assert_eq!(pages.allocated.get(), 0);
    assert_eq!(peer.lock().unwrap().config[&4] & 4, 0);
    drop(packet);
    assert_eq!(peer.lock().unwrap().drops, 0);
}
#[test]
fn actual_5762_ignored_required_register_writes_cannot_advertise_attachment() {
    if crate::test_process::isolate_model() {
        return;
    }
    for at in [0x3628, 0x6808, 0x245c, 0x4890, 0x48a0, 0x468] {
        let (hardware, pages, domain, peer) = parts_5762();
        peer.lock().unwrap().ignore_write = Some(at);
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        let (error, mut packet) = match unsafe { Packet::attach(hardware, &pages, domain.clone()) }
        {
            Err(value) => value,
            Ok(_) => panic!("ignored {at:x} admitted"),
        };
        assert_eq!(error, Error::ConfigDidNotLatch);
        assert!(packet.transmit(&[0; 60]).is_err());
        assert_eq!(peer.lock().unwrap().dma_effects, 0);
        assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
        peer.lock().unwrap().ignore_write = None;
        // Some faults happen after BME. Only stop+domain drain retires.
        if packet.identified {
            assert!(packet.retire().is_ok());
        } else {
            assert!(packet.retire().is_err());
        }
    }
}
#[test]
fn actual_5762_each_alternate_fix_and_ring_word_is_required_for_every_dma_effect() {
    if crate::test_process::isolate_model() {
        return;
    }
    // A refusal leaves no DMA effect, so one attachment serves every case
    // once each is restored.
    let (packet, _pages, domain, peer) = attach_5762();
    for at in [0x3628, 0x4890, 0x48a0, 0x468, 0x245c] {
        let mut p = peer.lock().unwrap();
        let saved = p.mac[&at];
        p.mac.insert(at, 0);
        let before = p.dma_effects;
        let caught =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| p.publish_indices(&domain)));
        assert!(caught.is_err(), "absent {at:x} allowed status DMA");
        assert_eq!(p.dma_effects, before);
        p.mac.insert(at, saved);
    }
    for at in [0x108, 0x10c, 0x208, 0x20c, 0x118, 0x218, 0x228, 0x238] {
        let mut p = peer.lock().unwrap();
        let saved = p.sram[&at];
        p.sram.insert(at, saved ^ 1);
        let before = p.dma_effects;
        let caught =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| p.publish_indices(&domain)));
        assert!(caught.is_err(), "corrupt RCB {at:x} allowed DMA");
        assert_eq!(p.dma_effects, before);
        p.sram.insert(at, saved);
    }
    assert!(packet.retire().is_ok());
}
#[test]
fn actual_5762_link_loss_rebuilds_same_mappings_and_lowwater_does_not_fault_packets() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut packet, pages, domain, peer) = attach_5762();
    assert!(packet.carrier());
    let mappings: Vec<_> = domain.maps.lock().unwrap().keys().copied().collect();
    peer.lock().unwrap().phy.insert(1, 0);
    assert!(!packet.carrier());
    peer.lock().unwrap().phy.insert(1, 0x24);
    assert!(packet.carrier());
    assert_eq!(
        domain
            .maps
            .lock()
            .unwrap()
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        mappings
    );
    peer.lock().unwrap().mac.insert(0x3c48, 0x40);
    packet.transmit(&[0x5a; 60]).unwrap();
    assert_eq!(packet.mbuf_low_water_events(), 1);
    assert_eq!(peer.lock().unwrap().mac[&0x3c48], 0);
    assert_eq!(pages.allocated.get(), 6);
    assert!(packet.retire().is_ok());
}
#[test]
fn actual_5762_stop_drain_unmap_failure_retains_original_epoch() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut packet, pages, domain, peer) = attach_5762();
    assert!(packet.carrier());
    domain.defer.store(true, Ordering::Relaxed);
    peer.lock().unwrap().receive(&[0x42; 60], 0, &domain);
    peer.lock().unwrap().stop_stuck = Some(0x4800);
    let packet = match packet.retire() {
        Err((Error::StopTimeout(0x4800), p)) => p,
        _ => panic!("stop accepted"),
    };
    assert_eq!(domain.drains.load(Ordering::Relaxed), 0);
    peer.lock().unwrap().stop_stuck = None;
    domain.fail_drain.store(true, Ordering::Relaxed);
    let packet = match packet.retire() {
        Err((Error::Dma(DmaError::DrainUnavailable), p)) => p,
        _ => panic!("drain accepted"),
    };
    assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
    assert_eq!(domain.maps.lock().unwrap().len(), 6);
    domain.fail_drain.store(false, Ordering::Relaxed);
    domain.fail_unmap.store(true, Ordering::Relaxed);
    let packet = match packet.retire() {
        Err((Error::Dma(DmaError::InvalidationFailed), p)) => p,
        _ => panic!("unmap accepted"),
    };
    assert!(domain.posted.lock().unwrap().is_empty());
    assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
    domain.fail_unmap.store(false, Ordering::Relaxed);
    assert!(packet.retire().is_ok());
}

#[test]
fn actual_5762_transfers_and_fatal_dma_attention_preserve_ownership() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut packet, pages, domain, peer) = attach_5762();
    assert!(packet.carrier());
    // The 5762 shares the 5720's ring geometry, whose wrap
    // `wraps_tx_and_rx_producer_return_indices` covers; these frames
    // cross the 5762's own DMA prerequisites.
    for index in 0..8usize {
        let frame = vec![index as u8; 60];
        packet.transmit(&frame).unwrap();
        peer.lock().unwrap().receive(&frame, 0, &domain);
        assert_eq!(packet.receive().unwrap(), Some(frame));
    }
    assert_eq!(peer.lock().unwrap().tx, 8);
    assert_eq!(peer.lock().unwrap().ret, 8);
    peer.lock().unwrap().mac.insert(0x4804, 0x10);
    assert!(packet.transmit(&[0; 60]).is_err());
    assert!(matches!(
        packet.failure(),
        Some(Error::Attention { read_dma: 0x10, .. })
    ));
    assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
    assert_eq!(domain.maps.lock().unwrap().len(), 6);
    assert!(packet.retire().is_ok());
}

#[test]
#[ignore = "oracle: STELA_TG3_PACKET_ORACLE"]
fn unchanged_linux_5720_5762_selected_packet_setup_matches_registers() {
    if crate::test_process::isolate_model() {
        return;
    }
    let path = std::env::var("STELA_TG3_PACKET_ORACLE").expect("fresh original C trace required");
    let trace = std::fs::read_to_string(path).unwrap();
    let mut lines = trace.lines();
    let mut cases = 0;
    while let Some(header) = lines.next() {
        let fields: Vec<_> = header.split_whitespace().collect();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0], "CASE");
        let chip = u32::from_str_radix(fields[1], 16).unwrap();
        let reserve = u32::from_str_radix(fields[2], 16).unwrap();
        let corruption = u32::from_str_radix(fields[3], 16).unwrap();
        assert!(matches!(chip, 0x0572_0000 | 0x0576_2000));
        let (hardware, pages, domain, peer) = if chip == 0x0576_2000 {
            parts_5762()
        } else {
            parts()
        };
        let (rr, cr) = if chip == 0x0576_2000 {
            (0x4890, 0x48a0)
        } else {
            (0x4900, 0x4910)
        };
        {
            let mut p = peer.lock().unwrap();
            p.mac.insert(rr, reserve);
            p.mac.insert(cr, corruption);
        }
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        let packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
            Ok(p) => p,
            Err((e, _)) => panic!("actual profile: {e:?}"),
        };
        let mut expected = Vec::new();
        loop {
            let line = lines.next().expect("truncated original trace");
            if line == "END" {
                break;
            }
            let f: Vec<_> = line.split_whitespace().collect();
            assert_eq!(f.len(), 3);
            assert!(matches!(f[0], "M" | "S"));
            let at = u32::from_str_radix(f[1], 16).unwrap();
            let value = u32::from_str_radix(f[2], 16).unwrap();
            expected.push((f[0], at, value));
        }
        {
            let p = peer.lock().unwrap();
            for &(kind, at, value) in &expected {
                let actual = if kind == "M" { p.mac[&at] } else { p.sram[&at] };
                assert_eq!(
                    actual, value,
                    "chip {chip:x} initial {reserve:x}/{corruption:x} {kind} {at:x}"
                );
            }
            let actual_disabled: Vec<_> = p
                .sram
                .iter()
                .filter(|(at, value)| {
                    **value == 2
                        && ((0x118..0x140).contains(&**at) || (0x218..0x310).contains(&**at))
                })
                .map(|(&at, &value)| ("S", at, value))
                .collect();
            let mut expected_disabled: Vec<_> = expected
                .iter()
                .filter(|(kind, _, _)| *kind == "S")
                .copied()
                .collect();
            expected_disabled.sort_by_key(|(_, at, _)| *at);
            assert_eq!(actual_disabled, expected_disabled);
        }
        assert!(packet.retire().is_ok());
        cases += 1;
    }
    assert_eq!(cases, 32, "all original cases mandatory");
}

#[test]
fn actual_5762_register_access_removal_and_nvm_read_failures_retain_owners() {
    if crate::test_process::isolate_model() {
        return;
    }
    for at in [0x4890, 0x48a0, 0x3628, 0x245c, 0x468, 0x7014] {
        for fault in 0..3 {
            let (hardware, pages, domain, peer) = parts_5762();
            {
                let mut p = peer.lock().unwrap();
                match fault {
                    0 => p.fail_read_on = Some((at, 1)),
                    1 => p.fail_write = Some(at),
                    _ => p.removed_read = Some(at),
                }
                // The NVM write target is exercised by the EEPROM compat
                // transition, not an invented flash programming command.
                if at == 0x7014 {
                    p.mac.insert(at, 0x8200_0001);
                }
            }
            let (error, mut packet) =
                // SAFETY: the model device, its pages and its domain belong to this test alone; no
                // other driver, worker or DMA touches them.
                match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
                    Err(value) => value,
                    Ok(_) => panic!("access fault {at:x}/{fault} admitted"),
                };
            assert!(matches!(error, Error::Access | Error::Removed));
            assert!(packet.transmit(&[0; 60]).is_err());
            assert_eq!(peer.lock().unwrap().dma_effects, 0);
            assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
            drop(packet);
            assert_eq!(peer.lock().unwrap().drops, 0);
        }
    }
}
