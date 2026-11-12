// SPDX-License-Identifier: GPL-2.0-only
//! A BCM57766-class function (BCM57762, 57766, 57782, 57786): the 57765
//! class with rings below 2 GiB and 2K send data reads.
use super::*;

const JMB_2K_MMRR: u32 = 0x0080_0000;

impl Device {
    /// A 57766 of `revision` whose PHY reports `phy`, with the 57765 PHY ID
    /// published in NIC SRAM.
    fn new_57766(device: u16, revision: u32, phy: u32) -> Self {
        let mut p = Self::new_57765(0x16b4);
        p.config.insert(0, u32::from(device) << 16 | 0x14e4);
        p.config.insert(0xfc, revision);
        p.phy.insert(2, (phy >> 10) as u16);
        p.phy
            .insert(3, (((phy >> 16) & 0xfc00) | (phy & 0x3ff)) as u16);
        let published = 0x5c0d_8a41u32;
        p.sram.insert(
            0xb74,
            ((published >> 10) & 0xffff) << 16 | ((published >> 16) & 0xfc00) | (published & 0x3ff),
        );
        p
    }
}
fn attach(
    device: Device,
    passthrough: bool,
) -> (Packet<Reg, Timer>, Pages, Arc<Domain>, Arc<Mutex<Device>>) {
    let (hardware, pages, domain, peer) = parts();
    *peer.lock().unwrap() = device;
    domain.passthrough.store(passthrough, Ordering::Relaxed);
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
        Ok(packet) => packet,
        Err((e, _)) => panic!("57766 attach: {e:?}"),
    };
    (packet, pages, domain, peer)
}

#[test]
fn every_57766_moves_frames_with_its_rings_below_2_gib_and_2k_send_reads() {
    if crate::test_process::isolate_model() {
        return;
    }
    // tg3 singles out no 57766 revision. A PHY whose ID tg3 does not know
    // is set up from the ID the bootcode published.
    for (device, revision, phy) in [
        (0x1686, 0x5776_6000, 0x5c0d_8a41),
        (0x1682, 0x5776_6001, 0x5c0d_8a41),
        (0x16b7, 0x5776_6001, 0x5c0d_8a51),
        (0x16b3, 0x5776_6100, 0x5c0d_8a51),
    ] {
        let (mut packet, _, domain, peer) = attach(Device::new_57766(device, revision, phy), false);
        {
            let p = peer.lock().unwrap();
            assert!(p.ape.is_empty(), "{device:x}");
            // The 57765 class's rings, UART and watermark.
            assert_eq!(p.mac[&0x2458], (512 << 16) | (1536 << 2));
            assert_eq!(p.sram[&0x208], 1024 << 16);
            assert_eq!(p.mac[&0x504], 1);
            p.require_bits(0x6808, 0x10, 0x10);
            p.require_bits(0x4800, JMB_2K_MMRR, JMB_2K_MMRR);
        }
        // The four rings and the status block are mapped below 2 GiB; the
        // packet buffers anywhere.
        let limits = domain.limits.lock().unwrap().clone();
        let low: Vec<_> = limits.iter().filter(|(_, l)| **l == 0x7fff_ffff).collect();
        assert_eq!(low.len(), 4, "{device:x}");
        assert!(low.iter().all(|(at, _)| **at < 0x8000_0000));
        assert_eq!(limits.values().filter(|l| **l == u64::MAX).count(), 2);
        assert!(packet.carrier());
        // A maximal frame is one send BD below tg3's 2K split.
        let frame = vec![0x5a; MAX_FRAME];
        const { assert!(MAX_FRAME < 2048) };
        packet.transmit(&frame).unwrap();
        peer.lock().unwrap().receive(&[0x6b; 60], 0, &domain);
        assert_eq!(packet.receive().unwrap(), Some(vec![0x6b; 60]));
        assert_eq!(peer.lock().unwrap().sent, [frame]);
        assert!(packet.retire().is_ok());
    }
}

#[test]
fn without_a_remapper_the_57766_rings_are_allocated_below_2_gib() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (packet, pages, _, _) = attach(Device::new_57766(0x1686, 0x5776_6001, 0x5c0d_8a41), true);
    assert_eq!(*pages.below.borrow(), [0x8000_0000; 4]);
    assert!(packet.retire().is_ok());
    // A 57765 keeps 64-bit rings and full send reads.
    let (packet, pages, domain, peer) = attach(Device::new_57765(0x16b4), true);
    assert!(pages.below.borrow().is_empty());
    assert!(
        domain
            .limits
            .lock()
            .unwrap()
            .values()
            .all(|l| *l == u64::MAX)
    );
    peer.lock().unwrap().require_bits(0x4800, JMB_2K_MMRR, 0);
    assert!(packet.retire().is_ok());
}
