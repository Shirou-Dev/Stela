// SPDX-License-Identifier: GPL-2.0-only
//! Source 10/100 half-duplex negotiation reaches the native MAC and DMA.
use super::*;

fn attached(bcm5762: bool) -> (Packet<Reg, Timer>, Pages, Arc<Domain>, Arc<Mutex<Device>>) {
    if bcm5762 {
        bcm5762::attach_5762()
    } else {
        attach()
    }
}

#[test]
fn negotiated_duplex_modes_transfer_and_restore_mac() {
    if crate::test_process::isolate_model() {
        return;
    }
    for bcm5762 in [false, true] {
        let (mut packet, pages, domain, peer) = attached(bcm5762);
        assert_eq!(peer.lock().unwrap().phy[&4], 0x1e1);
        assert_eq!(peer.lock().unwrap().phy[&9], 0x200);
        for (aux, mode) in [
            (0x100, 6),
            (0x700, 8),
            (0x300, 6),
            (0x500, 4),
            (0x200, 4),
            (0x100, 6),
        ] {
            peer.lock().unwrap().phy.insert(0x19, aux);
            assert!(packet.carrier());
            assert_eq!(peer.lock().unwrap().mac[&0x400] & 14, mode);
            for n in 0..96 {
                let frame = vec![n as u8; 60 + n];
                packet.transmit(&frame).unwrap();
                peer.lock().unwrap().receive(&frame, 0, &domain);
                assert_eq!(packet.receive().unwrap(), Some(frame));
            }
        }
        assert_eq!(peer.lock().unwrap().sent.len(), 576);
        assert_eq!(packet.failure(), None);
        assert!(packet.retire().is_ok());
        assert_eq!(pages.drops.load(Ordering::Relaxed), 6);
    }
}

#[test]
fn mac_duplex_write_must_latch_before_packet_publication() {
    if crate::test_process::isolate_model() {
        return;
    }
    for bcm5762 in [false, true] {
        let (mut packet, pages, domain, peer) = attached(bcm5762);
        {
            let mut p = peer.lock().unwrap();
            p.phy.insert(0x19, 0x300);
            p.ignore_write = Some(0x400);
        }
        let effects = peer.lock().unwrap().dma_effects;
        assert!(!packet.carrier());
        assert_eq!(packet.failure(), Some(Error::ConfigDidNotLatch));
        assert!(packet.transmit(&[0x12; 60]).is_err());
        assert!(packet.receive().is_err());
        assert_eq!(peer.lock().unwrap().dma_effects, effects);
        assert_eq!(domain.maps.lock().unwrap().len(), 6);
        assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
        peer.lock().unwrap().ignore_write = None;
        packet.restart().unwrap();
        assert!(packet.carrier());
        packet.transmit(&[0x23; 60]).unwrap();
        assert_eq!(peer.lock().unwrap().mac[&0x400] & 14, 6);
        assert!(packet.retire().is_ok());
    }
}

#[test]
fn half_duplex_requires_real_link_and_completed_autonegotiation() {
    if crate::test_process::isolate_model() {
        return;
    }
    for bcm5762 in [false, true] {
        for status in [0, 4, 0x20] {
            let (mut packet, _, _, peer) = attached(bcm5762);
            peer.lock().unwrap().phy.insert(1, status);
            peer.lock().unwrap().phy.insert(0x19, 0x100);
            assert!(!packet.carrier());
            assert_eq!(packet.transmit(&[0; 60]), Err(LinkError::NoCarrier));
            assert!(peer.lock().unwrap().sent.is_empty());
            assert!(packet.retire().is_ok());
        }
    }
}

#[test]
fn unsupported_gigabit_half_and_reserved_phy_results_cannot_create_carrier() {
    if crate::test_process::isolate_model() {
        return;
    }
    for bcm5762 in [false, true] {
        for aux in [0, 0x400, 0x600] {
            let (mut packet, _, _, peer) = attached(bcm5762);
            peer.lock().unwrap().phy.insert(0x19, aux);
            assert!(!packet.carrier());
            assert_eq!(packet.transmit(&[0; 60]), Err(LinkError::NoCarrier));
            assert!(peer.lock().unwrap().sent.is_empty());
            assert!(packet.retire().is_ok());
        }
    }
}

#[test]
#[ignore = "oracle: STELA_TG3_PHY_LINK_ORACLE"]
fn unchanged_linux_aux_decode_and_mac_duplex_match_driver() {
    if crate::test_process::isolate_model() {
        return;
    }
    let path = std::env::var("STELA_TG3_PHY_LINK_ORACLE").expect("set original AUX/MAC trace");
    let trace = std::fs::read_to_string(path).unwrap();
    let lines: Vec<_> = trace.lines().collect();
    assert_eq!(lines.first().copied(), Some("TG3_PHY_LINK_V1 32"));
    assert_eq!(lines.last().copied(), Some("END 32"));
    assert_eq!(lines.len(), 34);
    for bcm5762 in [false, true] {
        let (mut packet, _, _, peer) = attached(bcm5762);
        let mut seen = alloc::collections::BTreeSet::new();
        for row in &lines[1..33] {
            let fields: Vec<_> = row.split_ascii_whitespace().collect();
            assert_eq!(fields.len(), 5);
            let n: Vec<u32> = fields.iter().map(|n| n.parse().unwrap()).collect();
            let (aux, before, speed, duplex, after) = (n[0], n[1], n[2], n[3], n[4]);
            assert!(seen.insert((aux, before)));
            {
                let mut p = peer.lock().unwrap();
                p.phy.insert(0x19, aux as u16);
                p.mac.insert(0x400, before);
            }
            let admitted = speed != u32::MAX && !(speed == 1000 && duplex == 0);
            assert_eq!(
                stela_driver_base::stepped::block_on(packet.hardware.packet_carrier()).unwrap(),
                admitted
            );
            assert_eq!(
                peer.lock().unwrap().mac[&0x400],
                if admitted { after } else { before }
            );
        }
        assert_eq!(seen.len(), 32);
        assert!(packet.retire().is_ok());
    }
}
