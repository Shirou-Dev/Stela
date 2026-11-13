// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Fp firmware cases.
use super::*;

#[test]
fn fp_mac_only_firmware_executes_after_mac_pulse_before_exit_l1_and_dma() {
    let bytes: Vec<_> = [0x4000_0001u32, 0x801f_0e00, 0x80d6_a55a]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let script = Script::parse(&bytes).unwrap();
    for xid in [0x54a, 0x54b] {
        let time = Time::default();
        let model = Model::ep(&time, 52, false);
        model.state.borrow_mut().ephy.fill(0xabcd);
        let rev = revision::detect(xid << 20).unwrap();
        let mut hw = Hardware::new(&model, &time, rev, 0);
        hw.initialize_modern().unwrap();
        hw.ep_start().unwrap();
        hw.configure_phy(Some(&script), false).unwrap();
        assert!(!model.state.borrow().mac.contains_key(&0xe0d6));
        hw.configure_mac(Some(&script)).unwrap();
        let s = model.state.borrow();
        assert_eq!(s.ephy[0x19], 0xbb8d);
        let ephy: Vec<_> = s
            .writes
            .iter()
            .filter(|(r, v, _)| *r == EPHY_ACCESS && *v & ACCESS != 0)
            .collect();
        assert_eq!(ephy.len(), 2); // Donor19/59 both encode wire register19.
        assert_eq!(s.mac[&0xea80], 3);
        if xid == 0x54a {
            assert_eq!(s.mac[&0xe0d6], 0xa55a);
            let at = |value| {
                s.writes
                    .iter()
                    .position(|(r, v, _)| *r == MAC_OCP && *v == value)
                    .unwrap()
            };
            assert!(at(0xf31f_0000) < at(0xf06b_a55a)); // E63E reset pulse before script.
            assert!(at(0xf06b_a55a) < at(0xe056_1f80)); // Script before exit-L1 C0AC.
        } else {
            assert!(!s.mac.contains_key(&0xe0d6));
        }
        assert_eq!(s.bytes[CONFIG_LOCK], 0);
        assert!(
            !s.writes
                .iter()
                .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
        );
    }
}

#[test]
fn ep_failed_notification_and_fp_missing_or_failed_mac_firmware_never_publish_dma() {
    for version in [51, 52] {
        for nth in 1..=4 {
            let time = Time::default();
            let mut model = Model::ep(&time, version, true);
            model.fail_eri_at = nth;
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(hw.ep_start(), Err(BlockError::Timeout));
            assert!(
                !model
                    .state
                    .borrow()
                    .writes
                    .iter()
                    .any(|(r, _, _)| matches!(*r, PHY_OCP | TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
            );
            assert!(time.now() < 20_000);
        }
    }
    let bytes: Vec<_> = [0x4000_0001u32, 0x801f_0e00, 0x80d6_a55a]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let script = Script::parse(&bytes).unwrap();
    // Linux rtl_hw_start_8117: without its file the MAC starts in full.
    let time = Time::default();
    let model = Model::ep(&time, 52, false);
    let mut hw = Hardware::new(&model, &time, revision(52), 0);
    hw.configure_mac(None).unwrap();
    assert!(model.state.borrow().mac.contains_key(&0xc0ac));
    for fault in 1..3 {
        let time = Time::default();
        let mut model = Model::ep(&time, 52, false);
        if fault == 1 {
            model.fail_mac_address = Some(0xe0d6);
        }
        if fault == 2 {
            model.stuck_phy_reset = true;
            model.state.borrow_mut().phy_ocp.insert(0xa400, PHY_RESET);
        }
        let mut hw = Hardware::new(&model, &time, revision(52), 0);
        let result = hw.configure_mac(Some(&script));
        assert_eq!(
            result,
            Err(match fault {
                1 => Error::Device(BlockError::Device { status: 255 }),
                _ => Error::Device(BlockError::Timeout),
            })
        );
        let s = model.state.borrow();
        assert_eq!(s.bytes[CONFIG_LOCK], 0);
        assert!(!s.mac.contains_key(&0xc0ac));
        assert!(
            !s.writes
                .iter()
                .any(|(r, _, _)| matches!(*r, RX_MAXIMUM | TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
        );
    }
}

#[test]
fn ep_fp_mac_masks_and_ring_publication_follow_complete_backend_setup() {
    use crate::bus::dma::TestRegion;
    for xid in [0x502, 0x54b] {
        let rev = revision::detect(xid << 20).unwrap();
        let time = Time::default();
        let model = Model::ep(&time, rev.version, true);
        {
            let mut s = model.state.borrow_mut();
            s.ephy.fill(0xffff);
            s.eri
                .extend([(0xcc, 0xaabb_ccdd), (0xd0, 0x1122_3344), (0x1b0, 0x1003)]);
            s.mac
                .extend([(0xd3e2, 0xffff), (0xd3e4, 0xffff), (0xe860, 0x1234)]);
        }
        let mut hw = Hardware::new(&model, &time, rev, 0);
        hw.initialize_modern().unwrap();
        hw.ep_start().unwrap();
        hw.configure_phy(None, false).unwrap();
        hw.configure_mac(None).unwrap();
        {
            let s = model.state.borrow();
            assert_eq!(s.eri[&0xcc], 0xaabb_cc2f);
            assert_eq!(s.eri[&0xd0], 0x1122_335f);
            assert_eq!(s.eri[&0x1b0] & 3, 0);
            if rev.version == 51 {
                assert_eq!(s.ephy[0], 0xffff);
                assert_eq!(s.ephy[0xd], 0xfeff);
                assert_eq!(s.ephy[0x19], 0x7fde);
                assert_eq!(s.mac[&0xd3e2], 0xf271);
                assert_eq!(s.mac[&0xd3e4], 0xff00);
                assert_eq!(s.mac[&0xe860], 0x12b4);
                assert_eq!(s.eri[&0x2fc], 1);
            } else {
                assert_eq!(s.eri[&0xd4] & 0x10, 0x10);
            }
            assert_eq!(s.writes.iter().filter(|(r, _, _)| *r == IBISR0).count(), 2);
            assert!(
                !s.writes
                    .iter()
                    .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
            );
        }
        let mut dma = TestRegion::new(200_000 * 8);
        let mut rx = Ring::new(&mut dma, true).unwrap();
        let mut tx = Ring::new(&mut dma, true).unwrap();
        rx.initialize(true);
        tx.initialize(false);
        publish(&hw, &rx, &tx, read_station(&hw).unwrap()).unwrap();
        assert_eq!(
            model.read32(RX_CONFIG),
            (1 << 15) | (1 << 11) | (7 << 8) | 0xe
        );
        for id in [0xc912, 0xc913] {
            let model = Model::ep(&time, rev.version, false);
            model.state.borrow_mut().phy_ocp.insert(0xa406, id);
            let mut hw = Hardware::new(&model, &time, rev, 0);
            assert_eq!(
                hw.configure_phy(None, false),
                Err(Error::UnsupportedPhy(0x001c_0000 | u32::from(id)))
            );
        }
    }
}
