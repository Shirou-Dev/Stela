// SPDX-License-Identifier: GPL-2.0-only
//! Source PHY power writes through the packet/DMA owner.
use super::*;

fn attached(bcm5762: bool) -> (Packet<Reg, Timer>, Pages, Arc<Domain>, Arc<Mutex<Device>>) {
    if bcm5762 {
        bcm5762::attach_5762()
    } else {
        attach()
    }
}

fn power_writes(peer: &Arc<Mutex<Device>>, from: usize) -> Vec<(u8, u16)> {
    peer.lock().unwrap().phy_writes[from..]
        .iter()
        .copied()
        // Exclude the AUX shadow selector used solely for extra readback.
        .filter(|(at, value)| !(*at == 0x18 && *value == 0x2007))
        .collect()
}

#[test]
fn phy_low_power_resume_restores_traffic() {
    if crate::test_process::isolate_model() {
        return;
    }
    for bcm5762 in [false, true] {
        let (mut packet, pages, domain, peer) = attached(bcm5762);
        let addresses = packet.memory.as_ref().unwrap().addresses().unwrap();
        for _ in 0..3 {
            assert!(packet.carrier());
            peer.lock().unwrap().hold_tx = true;
            packet.transmit(&[0x23; 60]).unwrap();
            domain.defer.store(true, Ordering::Relaxed);
            peer.lock().unwrap().receive(&[0x34; 60], 0, &domain);
            let start = peer.lock().unwrap().phy_writes.len();
            packet.suspend_phy().unwrap();
            assert_eq!(
                power_writes(&peer, start),
                [(0x10, 8), (0x18, 0x1b2), (0, 0x800)]
            );
            assert!(packet.state == State::PhySuspended);
            assert_eq!(peer.lock().unwrap().phy[&0], 0x800);
            assert_eq!(peer.lock().unwrap().auxiliary[&2] & 0x1b0, 0x1b0);
            assert_eq!(peer.lock().unwrap().phy[&0x10] & 8, 8);
            assert!(domain.posted.lock().unwrap().is_empty());
            let accesses = peer.lock().unwrap().access.len();
            assert!(!packet.carrier());
            assert!(packet.transmit(&[0x45; 60]).is_err());
            assert_eq!(packet.receive().unwrap(), None);
            packet.stop().unwrap();
            packet.suspend_phy().unwrap();
            assert_eq!(peer.lock().unwrap().access.len(), accesses);
            assert_eq!(domain.maps.lock().unwrap().len(), 6);
            assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
            domain.defer.store(false, Ordering::Relaxed);
            peer.lock().unwrap().hold_tx = false;
            packet.resume_phy().unwrap();
            assert!(packet.state == State::Running);
            assert_eq!(
                packet.memory.as_ref().unwrap().addresses().unwrap(),
                addresses
            );
            assert_eq!(peer.lock().unwrap().phy[&0] & 0x800, 0);
            assert_eq!(peer.lock().unwrap().auxiliary[&2], 0);
            assert_eq!(peer.lock().unwrap().phy[&0x10] & 8, 0);
            assert_eq!(packet.receive().unwrap(), None);
            packet.transmit(&[0x56; 60]).unwrap();
            peer.lock().unwrap().receive(&[0x67; 60], 0, &domain);
            assert_eq!(packet.receive().unwrap(), Some(vec![0x67; 60]));
        }
        assert_eq!(peer.lock().unwrap().sent, vec![vec![0x56; 60]; 3]);
        assert_eq!(pages.allocated.get(), 6);
        assert!(packet.retire().is_ok());
        assert_eq!(pages.drops.load(Ordering::Relaxed), 6);
    }
}

#[test]
fn stopped_suspended_owner_can_retire_without_waking_phy_or_repeating_stop() {
    if crate::test_process::isolate_model() {
        return;
    }
    for bcm5762 in [false, true] {
        let (mut packet, pages, domain, peer) = attached(bcm5762);
        packet.suspend_phy().unwrap();
        let accesses = peer.lock().unwrap().access.len();
        assert!(packet.retire().is_ok());
        assert_eq!(peer.lock().unwrap().access.len(), accesses);
        assert_eq!(pages.drops.load(Ordering::Relaxed), 6);
        assert!(domain.maps.lock().unwrap().is_empty());
    }
}

#[test]
fn phy_suspend_never_precedes_engine_stop_and_posted_payload_drain() {
    if crate::test_process::isolate_model() {
        return;
    }
    for bcm5762 in [false, true] {
        for stop_failure in [false, true] {
            let (mut packet, pages, domain, peer) = attached(bcm5762);
            let start = peer.lock().unwrap().phy_writes.len();
            if stop_failure {
                peer.lock().unwrap().stop_stuck = Some(0x4800);
            } else {
                domain.fail_drain.store(true, Ordering::Relaxed);
            }
            assert_eq!(
                packet.suspend_phy(),
                Err(if stop_failure {
                    Error::StopTimeout(0x4800)
                } else {
                    Error::Dma(DmaError::DrainUnavailable)
                })
            );
            assert!(power_writes(&peer, start).is_empty());
            assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
            assert!(!packet.carrier());
            peer.lock().unwrap().stop_stuck = None;
            domain.fail_drain.store(false, Ordering::Relaxed);
            packet.suspend_phy().unwrap();
            packet.resume_phy().unwrap();
            assert!(packet.retire().is_ok());
        }
    }
}

#[test]
fn link_flap_avoidance_policy_refuses_phy_mutation_and_allows_retirement() {
    if crate::test_process::isolate_model() {
        return;
    }
    for bcm5762 in [false, true] {
        let (mut packet, pages, _, peer) = attached(bcm5762);
        peer.lock().unwrap().sram.insert(0xd3c, 0x0040_0000);
        let start = peer.lock().unwrap().phy_writes.len();
        assert_eq!(packet.suspend_phy(), Err(Error::UnsupportedBoard));
        assert!(power_writes(&peer, start).is_empty());
        assert!(!packet.carrier());
        assert!(packet.retire().is_ok());
        assert_eq!(pages.drops.load(Ordering::Relaxed), 6);
    }
}

#[test]
fn each_ignored_phy_power_write_is_detected_and_preserves_original_uncertain_owner() {
    if crate::test_process::isolate_model() {
        return;
    }
    for bcm5762 in [false, true] {
        for ignored in [(0x10, 8), (0x18, 0x1b2), (0, 0x800)] {
            let (mut packet, pages, domain, peer) = attached(bcm5762);
            peer.lock().unwrap().ignore_phy_write = Some(ignored);
            assert_eq!(packet.suspend_phy(), Err(Error::ConfigDidNotLatch));
            assert_eq!(packet.failure(), Some(Error::ConfigDidNotLatch));
            assert!(packet.state == State::Faulted);
            assert_eq!(domain.maps.lock().unwrap().len(), 6);
            assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
            assert!(packet.transmit(&[0x78; 60]).is_err());
            peer.lock().unwrap().ignore_phy_write = None;
            assert_eq!(packet.restart(), Err(Error::Poisoned));
            drop(packet);
            assert_eq!(peer.lock().unwrap().drops, 0);
            assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
        }
    }
}

#[test]
fn uncertain_mdio_reply_during_phy_suspend_cannot_be_cleared_by_resume() {
    if crate::test_process::isolate_model() {
        return;
    }
    for bcm5762 in [false, true] {
        let (mut packet, pages, _, peer) = attached(bcm5762);
        {
            let mut p = peer.lock().unwrap();
            let next = p.read_counts.get(&0x44c).copied().unwrap_or(0) + 1;
            p.fail_read_on = Some((0x44c, next));
        }
        assert_eq!(packet.suspend_phy(), Err(Error::Access));
        peer.lock().unwrap().fail_read_on = None;
        assert_eq!(packet.resume_phy(), Err(Error::Stopped));
        assert_eq!(packet.restart(), Err(Error::Poisoned));
        drop(packet);
        assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
        assert_eq!(peer.lock().unwrap().drops, 0);
    }
}

#[test]
fn independent_peer_refuses_power_writes_with_live_dma_or_missing_drain() {
    if crate::test_process::isolate_model() {
        return;
    }
    for engines_running in [false, true] {
        let (mut packet, _, domain, peer) = attach();
        if !engines_running {
            stela_driver_base::stepped::block_on(packet.hardware.packet_stop()).unwrap();
        }
        let mut p = peer.lock().unwrap();
        let before = p.phy_writes.len();
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            p.phy_write(0, 0x800, &domain);
        }));
        assert!(refused.is_err());
        assert_eq!(p.phy_writes.len(), before);
        drop(p);
        assert!(packet.retire().is_ok());
    }
}

#[test]
#[ignore = "oracle: STELA_TG3_PHY_POWER_ORACLE"]
fn unchanged_linux_phy_power_writes_match_kept_driver() {
    if crate::test_process::isolate_model() {
        return;
    }
    let path = std::env::var("STELA_TG3_PHY_POWER_ORACLE").expect("set original PHY power trace");
    let trace = std::fs::read_to_string(path).unwrap();
    let mut lines = trace.lines();
    assert_eq!(lines.next(), Some("TG3_PHY_POWER_V1 2"));
    for bcm5762 in [false, true] {
        let (mut packet, _, _, peer) = attached(bcm5762);
        let chip = packet.hardware.identity().unwrap().chip_revision;
        assert_eq!(lines.next(), Some(format!("CASE {chip}").as_str()));
        let mut expected = Vec::new();
        loop {
            let line = lines.next().expect("complete source case");
            if line == "END" {
                break;
            }
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            assert_eq!(fields.len(), 3);
            assert_eq!(fields[0], "W");
            expected.push((
                fields[1].parse::<u8>().unwrap(),
                fields[2].parse::<u16>().unwrap(),
            ));
        }
        assert_eq!(expected.len(), 3);
        let start = peer.lock().unwrap().phy_writes.len();
        packet.suspend_phy().unwrap();
        assert_eq!(power_writes(&peer, start), expected);
        assert!(packet.retire().is_ok());
    }
    assert_eq!(lines.next(), None);
}
