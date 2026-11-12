// SPDX-License-Identifier: GPL-2.0-only
//! Separate BCM5761 A0 copper peer: 512-entry rings, source controls,
//! nonidentity requester DMA, and kept failure lifetimes.
use super::*;

const STRAPS: [u32; 16] = [
    0x0080_0003,
    0x0080_0000,
    0x0080_0002,
    0x0080_0001,
    0x0000_0003,
    0x0000_0000,
    0x0000_0002,
    0x0000_0001,
    0x0280_0001,
    0x0280_0000,
    0x0280_0002,
    0x0280_0003,
    0x0200_0001,
    0x0200_0000,
    0x0200_0002,
    0x0200_0003,
];

impl Device {
    pub(super) fn is_5761(&self) -> bool {
        matches!(
            self.config[&0],
            0x1680_14e4 | 0x1681_14e4 | 0x1688_14e4 | 0x1689_14e4
        )
    }
    fn new_5761(device: u16) -> Self {
        let mut p = Self::new();
        p.config.insert(0, u32::from(device) << 16 | 0x14e4);
        p.config.insert(0xbc, 0x0576_1000);
        p.config.insert(0xf4, 0xdead_beef); // Must use original PRODID.
        p.config.insert(0x2c, 0x1234_14e4);
        p.sram.insert(0xb58, 0x10);
        p.sram.insert(0xd3c, 0);
        let id = 0xbc05_0fd0u32;
        p.phy.insert(2, (id >> 10) as u16);
        p.phy
            .insert(3, (((id >> 16) & 0xfc00) | (id & 0x3ff)) as u16);
        p.nvram.insert(0, 0x6699_55aa);
        p.mac.insert(0x360c, 0xa011_0000);
        p.mac.insert(0x7e2c, 0x60);
        // Source branches must leave all these modern-only controls alone.
        for at in [0x6c, 0x4910, 0x4890, 0x48a0, 0x2d00, 0x2d04, 0x2c1c, 0x2448] {
            p.mac.insert(at, 0x0110_0080);
        }
        for index in 1..17 {
            p.sram.insert(0x100 + index * 16 + 8, 0xdec0_0000 + index);
            p.sram.insert(0x200 + index * 16 + 8, 0xdec0_0000 + index);
        }
        p
    }
    pub(super) fn require_5761_dma(&self) {
        assert_eq!(self.config[&0xbc], 0x0576_1000);
        assert_eq!(self.mac[&0x360c], 0xa000_0000);
        assert_eq!(self.mac[&0x7e2c], 0x20);
        self.require_bits(0x7c00, 0x0200_0000, 0x0200_0000);
        assert_eq!(self.dsp[&0xa], 0x010b);
        assert_eq!(self.mac[&0x4414], 0x10);
        assert_eq!(self.mac[&0x4418], 0x60);
        self.require_bits(0x4400, 0x17, 6); // no MBLOW attention.
        self.require_bits(0x6800, 0x1000_0000, 0); // no flow attention.
        self.require_bits(0x4900, 4, 4);
        self.require_bits(0x4800, 0x1800_0000, 0x0800_0000); // IPv4 TSO2, not IPv6.
        self.require_bits(0x1000, 0x13, 0x12); // source completion delay.
        assert_eq!(self.mac[&0x2c18], 16);
        assert_eq!(self.mac[&0x2458], 512 << 16);
        assert_eq!(self.mac[&0x245c], 0x6000);
        assert_eq!(self.sram[&0x108], 512 << 16);
        assert_eq!(self.sram[&0x10c], 0x4000);
        assert_eq!(self.sram[&0x208], 512 << 16);
        assert_eq!(self.sram[&0x20c], 0);
        for at in [0x6c, 0x4910, 0x4890, 0x48a0, 0x2d00, 0x2d04, 0x2c1c, 0x2448] {
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

pub(super) fn parts_5761(
    device: u16,
) -> (Hardware<Reg, Timer>, Pages, Arc<Domain>, Arc<Mutex<Device>>) {
    let (hardware, pages, domain, peer) = parts();
    *peer.lock().unwrap() = Device::new_5761(device);
    (hardware, pages, domain, peer)
}
pub(super) fn attach_5761() -> (Packet<Reg, Timer>, Pages, Arc<Domain>, Arc<Mutex<Device>>) {
    let (hardware, pages, domain, peer) = parts_5761(0x1680);
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
        Ok(packet) => packet,
        Err((e, _)) => panic!("5761 attach {e:?}"),
    };
    (packet, pages, domain, peer)
}

#[test]
fn actual_5761_512_rings_wrap_and_half_full_duplex_transfer_then_retire() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut packet, pages, domain, peer) = attach_5761();
    assert_eq!(packet.geometry.rx, 512);
    assert_eq!(packet.geometry.returns, 512);
    // The first mode crosses the 512-entry producer and return ring
    // boundaries; every other half and full duplex mode then transfers.
    for (mode, frames) in [(0x100, 513), (0x200, 4), (0x300, 4), (0x500, 4), (0x700, 4)] {
        peer.lock().unwrap().phy.insert(0x19, mode);
        assert!(packet.carrier());
        for n in 0..frames {
            let frame = vec![n as u8; 60];
            packet.transmit(&frame).unwrap();
            peer.lock().unwrap().receive(&frame, 0, &domain);
            assert_eq!(packet.receive().unwrap(), Some(frame));
        }
    }
    assert_eq!(peer.lock().unwrap().sent.len(), 529);
    assert_eq!(pages.allocated.get(), 6);
    assert!(packet.retire().is_ok());
    assert_eq!(pages.drops.load(Ordering::Relaxed), 6);
    assert!(domain.maps.lock().unwrap().is_empty());
    assert_eq!(peer.lock().unwrap().drops, 1);
}

#[test]
fn actual_5761_all_source_flash_straps_and_device_ids_use_direct_mac_offset() {
    if crate::test_process::isolate_model() {
        return;
    }
    for (index, strap) in STRAPS.into_iter().enumerate() {
        let device = [0x1680, 0x1681, 0x1688, 0x1689][index % 4];
        let (hardware, pages, domain, peer) = parts_5761(device);
        {
            let mut p = peer.lock().unwrap();
            p.mac.insert(0x7014, strap | 0x8000_0000);
            p.sram.insert(0xc14, 0);
            p.nvram.insert(0x7c, 0x0211);
            p.nvram.insert(0x80, 0x2233_4455);
        }
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        let mut packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
            Ok(packet) => packet,
            Err((e, _)) => panic!("strap {strap:x} {e:?}"),
        };
        assert_eq!(packet.mac(), Mac([2, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert!(packet.carrier());
        packet.transmit(&[0x46; 60]).unwrap();
        let p = peer.lock().unwrap();
        assert_eq!(p.mac[&0x7014], strap | 0x8000_0000);
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
        drop(p);
        assert!(packet.retire().is_ok());
    }
}

#[test]
fn actual_5761_unsupported_or_unsigned_board_media_clock_or_nvram_never_publish_dma() {
    if crate::test_process::isolate_model() {
        return;
    }
    for fault in 0..14 {
        let (hardware, pages, domain, peer) = parts_5761(0x1680);
        {
            let mut p = peer.lock().unwrap();
            match fault {
                0 => {
                    p.config.insert(0xbc, 0x0576_1001);
                }
                1 => {
                    p.config.insert(0x50, u32::MAX);
                }
                2 => {
                    p.sram.insert(0xb58, 0x110);
                }
                3 => {
                    p.sram.insert(0xb58, 0x20);
                }
                4 => {
                    p.sram.insert(0xb58, 0);
                }
                // ASF and running APE firmware no longer refuse; an
                // unsigned board still does.
                5 => {
                    p.sram.insert(0xb54, 0);
                }
                6 => {
                    p.sram.insert(0xb54, !0x4b65_7654);
                }
                7 => {
                    p.mac.insert(0x7014, 0x0800_0000);
                }
                8 => {
                    p.mac.insert(0x7014, 0x03e0_0003);
                }
                9 => {
                    p.nvram.insert(0, 0);
                }
                10 => {
                    p.sram.insert(0xb5c, 0);
                }
                11 => {
                    p.sram.insert(0xd3c, 0x0040_0000);
                }
                12 => {
                    // Another family's known PHY.
                    let id = 0x5c0d_8b62u32;
                    p.phy.insert(2, (id >> 10) as u16);
                    p.phy
                        .insert(3, (((id >> 16) & 0xfc00) | (id & 0x3ff)) as u16);
                }
                _ => {
                    p.bdf_function = Some(1);
                }
            }
        }
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        let (_, mut packet) = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
            Err(value) => value,
            Ok(_) => panic!("fault {fault} admitted"),
        };
        assert_eq!(pages.allocated.get(), 0);
        assert_eq!(peer.lock().unwrap().config[&4] & 4, 0);
        assert_eq!(peer.lock().unwrap().dma_effects, 0);
        if fault == 0 || fault == 13 {
            let p = peer.lock().unwrap();
            assert_eq!(
                p.access,
                [
                    (false, 0x10000, p.config[&0]),
                    (false, 0x100bc, p.config[&0xbc])
                ],
                "static denial must only observe PCI identity and PRODID"
            );
        }
        if fault == 7 {
            let p = peer.lock().unwrap();
            assert!(
                !p.access
                    .iter()
                    .any(|(w, at, _)| *w && [0x7024, 0x7000].contains(at)),
                "protected NVM must not be enabled or commanded"
            );
        }
        assert!(packet.transmit(&[0; 60]).is_err());
        drop(packet);
        assert_eq!(peer.lock().unwrap().drops, 0);
    }
}

#[test]
fn bcm5761_restart_drains_old_writes_before_reuse() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut packet, pages, domain, peer) = attach_5761();
    let addresses = packet.memory.as_ref().unwrap().addresses().unwrap();
    assert!(packet.carrier());
    domain.defer.store(true, Ordering::Relaxed);
    peer.lock().unwrap().receive(&[0x75; 60], 0, &domain);
    domain.fail_drain.store(true, Ordering::Relaxed);
    let resets = core_resets(&peer);
    assert!(packet.restart().is_err());
    assert_eq!(core_resets(&peer), resets);
    assert!(!domain.posted.lock().unwrap().is_empty());
    assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
    domain.fail_drain.store(false, Ordering::Relaxed);
    packet.restart().unwrap();
    assert_eq!(packet.rx_producer, 511);
    assert_eq!(
        packet.memory.as_ref().unwrap().addresses().unwrap(),
        addresses
    );
    assert_eq!(packet.receive().unwrap(), None);
    domain.defer.store(false, Ordering::Relaxed);
    assert!(packet.carrier());
    packet.transmit(&[0x86; 60]).unwrap();
    peer.lock().unwrap().receive(&[0x97; 60], 0, &domain);
    assert_eq!(packet.receive().unwrap(), Some(vec![0x97; 60]));
    packet.suspend_phy().unwrap();
    assert_eq!(peer.lock().unwrap().mac[&0x360c], 0xa011_0000);
    assert!(packet.retire().is_ok());
    assert_eq!(pages.drops.load(Ordering::Relaxed), 6);
}

#[test]
fn actual_5761_out_of_range_return_and_fatal_low_water_require_rebuild() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut packet, _, domain, peer) = attach_5761();
    assert!(packet.carrier());
    let status = peer.lock().unwrap().status();
    domain.store(status + 16, &512u32.to_le_bytes());
    assert!(packet.receive().is_err());
    assert_eq!(packet.failure(), Some(Error::RingCorrupt));
    packet.restart().unwrap();
    peer.lock().unwrap().mac.insert(0x3c48, 0x40);
    assert!(packet.receive().is_err());
    assert!(matches!(
        packet.failure(),
        Some(Error::Attention { flow: 0x40, .. })
    ));
    assert_eq!(packet.mbuf_low_water_events(), 0);
    peer.lock().unwrap().mac.insert(0x3c48, 0);
    packet.restart().unwrap();
    assert!(packet.carrier());
    packet.transmit(&[0x68; 60]).unwrap();
    assert!(packet.retire().is_ok());
}

#[test]
fn actual_5761_required_clock_and_fifo_readback_failures_never_allow_packet_io() {
    if crate::test_process::isolate_model() {
        return;
    }
    for at in [0x360c, 0x4900, 0x245c] {
        let (hardware, pages, domain, peer) = parts_5761(0x1680);
        peer.lock().unwrap().ignore_write = Some(at);
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        let (error, mut packet) = match unsafe { Packet::attach(hardware, &pages, domain.clone()) }
        {
            Err(value) => value,
            Ok(_) => panic!("ignored required {at:x} admitted"),
        };
        assert_eq!(error, Error::ConfigDidNotLatch);
        assert!(packet.transmit(&[0x64; 60]).is_err());
        assert_eq!(peer.lock().unwrap().dma_effects, 0);
        assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
        peer.lock().unwrap().ignore_write = None;
        if at == 0x360c {
            // A failed PHY reset-clock restoration is not cleared by a later
            // stop acknowledgement; the original hardware owner is held.
            assert_eq!(packet.stop(), Err(Error::Poisoned));
            drop(packet);
            assert_eq!(peer.lock().unwrap().drops, 0);
        } else {
            assert!(packet.retire().is_ok());
        }
    }
}

#[test]
fn actual_5761_changed_postreset_profile_and_unmap_failure_keep_original_owner() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (hardware, pages, domain, peer) = parts_5761(0x1680);
    peer.lock().unwrap().reset_nvram = Some(0x0080_0000);
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let (error, packet) = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
        Err(value) => value,
        Ok(_) => panic!("changed source NVM profile attached"),
    };
    assert_eq!(error, Error::UnsupportedBoard);
    assert_eq!(pages.allocated.get(), 0);
    assert_eq!(peer.lock().unwrap().dma_effects, 0);
    drop(packet);
    assert_eq!(peer.lock().unwrap().drops, 0);

    let (mut packet, pages, domain, peer) = attach_5761();
    assert!(packet.carrier());
    domain.defer.store(true, Ordering::Relaxed);
    peer.lock().unwrap().receive(&[0x53; 60], 0, &domain);
    peer.lock().unwrap().stop_stuck = Some(0x4800);
    let mut packet = match packet.retire() {
        Err((Error::StopTimeout(0x4800), p)) => p,
        _ => panic!("unacknowledged stop retired"),
    };
    assert_eq!(domain.drains.load(Ordering::Relaxed), 0);
    peer.lock().unwrap().stop_stuck = None;
    domain.fail_unmap_id.store(4, Ordering::Relaxed);
    packet = match packet.retire() {
        Err((Error::Dma(DmaError::InvalidationFailed), p)) => p,
        _ => panic!("unacknowledged unmap retired"),
    };
    assert!(domain.posted.lock().unwrap().is_empty());
    let maps = domain.maps.lock().unwrap().len();
    assert!(maps > 0 && maps < 6);
    let effects = peer.lock().unwrap().dma_effects;
    assert_eq!(packet.restart(), Err(Error::Stopped));
    assert_eq!(peer.lock().unwrap().dma_effects, effects);
    domain.fail_unmap_id.store(0, Ordering::Relaxed);
    assert!(packet.retire().is_ok());
    assert_eq!(pages.drops.load(Ordering::Relaxed), 6);
    assert_eq!(peer.lock().unwrap().drops, 1);
}

#[test]
fn phy_reset_uncertainty_poison_keeps_original_owner_before_any_allocation() {
    if crate::test_process::isolate_model() {
        return;
    }
    for profile in 0..3 {
        let (hardware, pages, domain, peer) = match profile {
            0 => parts(),
            1 => {
                let (hardware, pages, domain, peer) = parts();
                *peer.lock().unwrap() = Device::new_5762();
                (hardware, pages, domain, peer)
            }
            _ => parts_5761(0x1680),
        };
        peer.lock().unwrap().phy_stuck = true;
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        let (error, mut packet) = match unsafe { Packet::attach(hardware, &pages, domain.clone()) }
        {
            Err(value) => value,
            Ok(_) => panic!("unacknowledged PHY reset attached"),
        };
        assert_eq!(error, Error::PhyResetTimeout);
        assert_eq!(pages.allocated.get(), 0);
        peer.lock().unwrap().phy_stuck = false;
        assert_eq!(packet.stop(), Err(Error::Poisoned));
        assert!(packet.retire().is_err());
        assert_eq!(peer.lock().unwrap().drops, 0);
    }
}

fn core_resets(peer: &Arc<Mutex<Device>>) -> usize {
    peer.lock()
        .unwrap()
        .access
        .iter()
        .filter(|(write, at, value)| *write && *at == 0x6804 && value & 1 != 0)
        .count()
}

#[test]
#[ignore = "oracle: STELA_TG3_BCM5761_ORACLE"]
fn unchanged_linux_5761_initialization_selections_match_kept_packet_owner() {
    if crate::test_process::isolate_model() {
        return;
    }
    let trace = std::fs::read_to_string(
        std::env::var("STELA_TG3_BCM5761_ORACLE").expect("fresh original-source trace required"),
    )
    .unwrap();
    let mut lines = trace.lines();
    let mut cases = 0;
    while let Some(line) = lines.next() {
        let header: Vec<_> = line.split_whitespace().collect();
        assert_eq!(header.len(), 4);
        assert_eq!(header[0], "CASE");
        let hex = |s: &str| u32::from_str_radix(s, 16).unwrap();
        let (strap, reserve, clock) = (hex(header[1]), hex(header[2]), hex(header[3]));
        let (hardware, pages, domain, peer) = parts_5761(0x1680);
        {
            let mut p = peer.lock().unwrap();
            p.mac.insert(0x7014, strap | 0x8000_0000);
            p.mac.insert(0x4900, reserve);
            p.mac.insert(0x360c, clock);
        }
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        let packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
            Ok(packet) => packet,
            Err((e, _)) => panic!("source case {strap:x}/{reserve:x}/{clock:x}: {e:?}"),
        };
        let mut mmio = BTreeMap::new();
        let mut phy = Vec::new();
        let mut native_nvram_checked = false;
        {
            let p = peer.lock().unwrap();
            loop {
                let line = lines.next().expect("truncated source case");
                if line == "END" {
                    break;
                }
                let f: Vec<_> = line.split_whitespace().collect();
                match f[0] {
                    "M" => {
                        assert_eq!(f.len(), 3);
                        let (at, value) = (hex(f[1]), hex(f[2]));
                        assert!(
                            p.access
                                .iter()
                                .any(|(w, a, v)| *w && *a == at && *v == value),
                            "missing original write {at:x}={value:x}"
                        );
                        mmio.insert(at, value);
                    }
                    "W" => {
                        assert_eq!(f.len(), 3);
                        phy.push((hex(f[1]) as u8, hex(f[2]) as u16));
                    }
                    "N" => {
                        assert_eq!(f.len(), 5);
                        assert_eq!(hex(f[1]), 256);
                        assert!(matches!(hex(f[2]), 0x1f | 0x20));
                        assert!((0x40000..=0x200000).contains(&hex(f[3])));
                        assert!(matches!(hex(f[4]), 3 | 7));
                        assert_eq!(p.mac[&0x7014], strap | 0x8000_0000);
                        native_nvram_checked = true;
                    }
                    "S" => panic!("source 5761 unexpectedly disables a nonexistent extra RCB"),
                    _ => panic!("unexpected source row {line}"),
                }
            }
            for (&at, &value) in &mmio {
                assert_eq!(p.mac[&at], value, "source register {at:x}");
            }
            assert!(native_nvram_checked);
            assert!(!phy.is_empty());
            assert!(
                p.phy_writes.windows(phy.len()).any(|v| v == phy),
                "actual jitter/SM-DSP writes differ"
            );
            assert_eq!(p.mac[&0x360c], clock & !0x001f_0000);
            assert_eq!(p.mac[&0x2458], 512 << 16);
            assert_eq!(p.sram[&0x208], 512 << 16);
            assert!(
                !p.access
                    .iter()
                    .any(|(w, at, _)| *w && [0x2d00, 0x2d04, 0x2c1c, 0x4910].contains(at))
            );
        }
        assert!(packet.retire().is_ok());
        cases += 1;
    }
    assert_eq!(cases, 32);
}
