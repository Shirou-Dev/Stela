// SPDX-License-Identifier: GPL-2.0-only
//! A function whose ASF and APE management firmware runs starts, shares the
//! port as Linux tg3 does and hands it back at stop.
use super::*;

/// A BCM5720 whose signed board enables ASF, with running APE firmware and
/// a receive rule of its own in rule 4.
fn managed() -> (Packet<Reg, Timer>, Pages, Arc<Domain>, Arc<Mutex<Device>>) {
    let (hardware, pages, domain, peer) = parts();
    {
        let mut p = peer.lock().unwrap();
        p.sram.insert(0xb58, 0x80);
        p.ape.insert(0x4000, 0x4150_4521);
        p.ape.insert(0x400c, 0x100);
        p.mac.insert(0x4a0, 0x8000_1234);
        p.mac.insert(0x4a4, 0x5678);
    }
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
        Ok(packet) => packet,
        Err((e, _)) => panic!("attach: {e:?}"),
    };
    (packet, pages, domain, peer)
}

fn returns(peer: &Arc<Mutex<Device>>) -> u64 {
    let p = peer.lock().unwrap();
    (u64::from(p.sram[&0x200]) << 32) | u64::from(p.sram[&0x204])
}

#[test]
fn a_managed_function_starts_and_shares_the_port_with_its_firmware() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut packet, _, domain, peer) = managed();
    {
        let p = peer.lock().unwrap();
        // tg3_ape_driver_state_change(INIT), taken by the firmware, and no
        // heartbeat expected from a polled link.
        assert_eq!(p.ape[&0x4200], 0x484f_5354);
        assert_eq!(p.ape[&0x421c], 1);
        assert_eq!(p.ape[&0x4300], 0x0001_0510);
        assert_eq!(p.ape[&0x4214], 0);
        // tg3_write_sig_post_reset(INIT).
        assert_eq!(p.sram[&0xc04], 0x8000_0001);
        // The APE sends and receives through the MAC.
        assert_eq!(p.mac[&0x400] & 0x1800_0000, 0x1800_0000);
        // ASF keeps receive rules 4 to 7.
        assert_eq!((p.mac[&0x4a0], p.mac[&0x4a4]), (0x8000_1234, 0x5678));
        // ASF has the MAC strip VLAN tags.
        assert_eq!(p.mac[&0x468] & 0x400, 0);
    }
    assert!(packet.carrier());
    // A stripped tag is put back where it was.
    let frame: Vec<u8> = (0..60).collect();
    peer.lock().unwrap().receive(&frame, 0, &domain);
    let at = returns(&peer);
    domain.store(at + 12, &0x44u32.to_le_bytes());
    domain.store(at + 20, &0x0123u32.to_le_bytes());
    let tagged = [&frame[..12], &[0x81, 0, 0x01, 0x23], &frame[12..]].concat();
    assert_eq!(packet.receive().unwrap(), Some(tagged));
    // A full-size frame whose tag no longer fits is dropped, as a raw
    // tagged frame above the maximum is.
    peer.lock().unwrap().receive(&[0x5a; 1514], 0, &domain);
    domain.store(at + 32 + 12, &0x44u32.to_le_bytes());
    domain.store(at + 32 + 20, &0x0123u32.to_le_bytes());
    assert_eq!(packet.receive().unwrap(), None);
    assert_eq!(packet.rx_dropped(), 1);
    // TG3_UCAST_ADDR_IDX and TG3_MAX_UCAST_ADDR: slot 1 is the firmware's.
    let extra = [Mac([2, 0, 0, 0, 0, 1]), Mac([2, 0, 0, 0, 0, 2])];
    packet
        .set_receive_filter(ReceiveFilter {
            unicast: extra.to_vec(),
            ..ReceiveFilter::default()
        })
        .unwrap();
    {
        let p = peer.lock().unwrap();
        assert_eq!((p.mac[&0x420], p.mac[&0x424]), (0x0200, 1));
        assert_eq!((p.mac[&0x428], p.mac[&0x42c]), (0x0200, 2));
        assert_eq!(p.mac[&0x468] & 0x100, 0);
    }
    packet
        .set_receive_filter(ReceiveFilter {
            unicast: [extra[0], extra[1], Mac([2, 0, 0, 0, 0, 3])].to_vec(),
            ..ReceiveFilter::default()
        })
        .unwrap();
    assert_eq!(peer.lock().unwrap().mac[&0x468] & 0x500, 0x100);
}

#[test]
fn a_stop_hands_the_port_back_and_the_firmware_keeps_its_phy() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut packet, _, _, peer) = managed();
    assert!(packet.carrier());
    let writes = peer.lock().unwrap().phy_writes.len();
    packet.suspend_phy().unwrap();
    {
        let p = peer.lock().unwrap();
        // tg3_halt(SHUTDOWN)'s ASF states and tg3_power_down_prepare's APE
        // UNLOAD, taken by the firmware.
        assert_eq!(p.sram[&0xc04], 0x8000_0002);
        assert_eq!(p.ape[&0x421c], 2);
        assert_eq!(p.ape[&0x4300], 0x0002_0510);
        // ASF keeps using the PHY, so it is not powered down.
        assert_eq!(p.phy_writes.len(), writes);
        assert_eq!(p.phy.get(&0).copied().unwrap_or(0) & 0x800, 0);
    }
    // A resume is a new driver start.
    packet.resume_phy().unwrap();
    {
        let p = peer.lock().unwrap();
        assert_eq!(p.ape[&0x421c], 1);
        assert_eq!(p.ape[&0x4300], 0x0001_0510);
        assert_eq!(p.sram[&0xc04], 0x8000_0001);
    }
    assert!(packet.carrier());
    assert!(packet.retire().is_ok());
    let p = peer.lock().unwrap();
    assert_eq!((p.sram[&0xc04], p.ape[&0x421c]), (0x8000_0002, 2));
}

#[test]
fn an_unmanaged_function_tells_the_ape_and_keeps_every_rule_and_raw_tags() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (packet, _, _, peer) = attach();
    {
        let p = peer.lock().unwrap();
        // ENABLE_APE holds for every named chip; with no APE firmware
        // running no event is posted, and no ASF state is written.
        assert_eq!(p.ape[&0x421c], 1);
        assert!(!p.ape.contains_key(&0x4300));
        assert!(!p.sram.contains_key(&0xc04));
        assert_eq!(p.mac[&0x468] & 0x400, 0x400);
        assert_eq!((p.mac[&0x4a0], p.mac[&0x4a4]), (0, 0));
    }
    assert!(packet.retire().is_ok());
    assert_eq!(peer.lock().unwrap().ape[&0x421c], 2);
}
