// SPDX-License-Identifier: GPL-2.0-only
//! Complete source RDMAC mode, checked alongside raw frame I/O.
use super::*;

fn parts_for(chip: u32) -> (Hardware<Reg, Timer>, Pages, Arc<Domain>, Arc<Mutex<Device>>) {
    if chip == 0x0576_1000 {
        bcm5761::parts_5761(0x1680)
    } else {
        let value = parts();
        if chip == 0x0576_2000 {
            *value.3.lock().unwrap() = Device::new_5762();
        } else if chip == 0x0571_9001 {
            *value.3.lock().unwrap() = Device::new_5719();
        } else {
            assert_eq!(chip, 0x0572_0000);
        }
        value
    }
}

#[test]
fn rdma_modes_match_source_for_every_asic() {
    if crate::test_process::isolate_model() {
        return;
    }
    for chip in [0x0571_9001, 0x0572_0000, 0x0576_1000, 0x0576_2000] {
        let (hardware, pages, domain, peer) = parts_for(chip);
        // These are firmware-observed control bits, with RESET/ENABLE clear.
        peer.lock().unwrap().mac.insert(0x4800, 0x3fff_fffc);
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        let mut packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
            Ok(packet) => packet,
            Err((e, _)) => panic!("source mode {chip:x}: {e:?}"),
        };
        assert_eq!(
            peer.lock().unwrap().mac[&0x4800],
            match chip {
                0x0576_1000 => 0x0803_03fe,
                // Only 5720 and 5762 keep the firmware's H2BNC_VLAN_DET.
                0x0571_9001 => 0x1803_03fe,
                _ => 0x3803_03fe,
            }
        );
        assert!(packet.carrier());
        packet.transmit(&[0x6a; 60]).unwrap();
        peer.lock().unwrap().receive(&[0x7b; 60], 0, &domain);
        assert_eq!(packet.receive().unwrap(), Some(vec![0x7b; 60]));
        assert_eq!(peer.lock().unwrap().sent, [vec![0x6a; 60]]);
        assert!(packet.retire().is_ok());
    }
}

#[test]
fn independent_peer_rejects_deleted_source_lso_mode_before_any_dma_effect() {
    if crate::test_process::isolate_model() {
        return;
    }
    for chip in [0x0572_0000, 0x0576_1000, 0x0576_2000] {
        let (hardware, pages, domain, peer) = parts_for(chip);
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        let packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
            Ok(packet) => packet,
            Err((e, _)) => panic!("source mode {chip:x}: {e:?}"),
        };
        let mut p = peer.lock().unwrap();
        let saved = p.mac[&0x4800];
        p.mac.insert(0x4800, saved & !0x0800_0000);
        let effects = p.dma_effects;
        let caught =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| p.publish_indices(&domain)));
        assert!(caught.is_err());
        assert_eq!(p.dma_effects, effects);
        p.mac.insert(0x4800, saved);
        drop(p);
        assert!(packet.retire().is_ok());
    }
}

#[test]
#[ignore = "oracle: STELA_TG3_RDMA_MODE_ORACLE"]
fn unchanged_linux_complete_rdma_mode_matches_register_and_raw_traffic() {
    if crate::test_process::isolate_model() {
        return;
    }
    let trace = std::fs::read_to_string(
        std::env::var("STELA_TG3_RDMA_MODE_ORACLE").expect("fresh original-source trace required"),
    )
    .unwrap();
    let mut lines = trace.lines();
    assert_eq!(lines.next(), Some("TG3_RDMA_MODE_V1 12"));
    let hex = |s: &str| u32::from_str_radix(s, 16).unwrap();
    let mut cases = 0;
    while let Some(line) = lines.next() {
        let header: Vec<_> = line.split_whitespace().collect();
        assert_eq!(header.len(), 3);
        assert_eq!(header[0], "CASE");
        let (chip, initial) = (hex(header[1]), hex(header[2]));
        let row: Vec<_> = lines
            .next()
            .expect("source publication")
            .split_whitespace()
            .collect();
        assert_eq!(row.len(), 3);
        assert_eq!(row[0], "M");
        assert_eq!(hex(row[1]), 0x4800);
        let expected = hex(row[2]);
        assert_eq!(lines.next(), Some("END"));
        let (hardware, pages, domain, peer) = parts_for(chip);
        peer.lock().unwrap().mac.insert(0x4800, initial);
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        let mut packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
            Ok(packet) => packet,
            Err((e, _)) => panic!("source mode {chip:x}/{initial:x}: {e:?}"),
        };
        {
            let p = peer.lock().unwrap();
            assert_eq!(p.mac[&0x4800], expected);
            assert!(p.access.contains(&(true, 0x4800, expected)));
        }
        assert!(packet.carrier());
        packet.transmit(&[0x8c; 60]).unwrap();
        peer.lock().unwrap().receive(&[0x9d; 60], 0, &domain);
        assert_eq!(packet.receive().unwrap(), Some(vec![0x9d; 60]));
        assert!(packet.retire().is_ok());
        cases += 1;
    }
    assert_eq!(cases, 12);
}
