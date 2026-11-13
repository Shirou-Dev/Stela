// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! G revisions cases.
use super::*;

#[test]
fn g_phy_mask_branches_and_post_reset_eee_cleanup_use_real_ocp_state() {
    let script_bytes = 0x8016_a55au32.to_le_bytes();
    let script = Script::parse(&script_bytes).unwrap();
    for version in [40, 42, 44] {
        for capability in [0, 0x100] {
            let time = Time::default();
            let model = Model::modern(&time);
            {
                let mut s = model.state.borrow_mut();
                s.phy_ocp.extend([
                    (0xa460, capability),
                    (0xa466, capability),
                    (0xbcc4, 0xffff),
                    (0xc41a, 0xffff),
                    (0xbcc8, 0xffff),
                    (0xc422, 0xffff),
                    (0xa5d0, 0xffff),
                ]);
                s.g_parameters.insert(0x8084, 0xffff);
            }
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(hw.configure_phy(Some(&script), false).unwrap(), None);
            let s = model.state.borrow();
            assert_eq!(s.phy_ocp[&0xa42c], 0xa55a); // standard PHY reg22.
            assert_eq!(s.phy_ocp[&0xa400], 0x1200);
            assert_eq!(s.phy_ocp[&0xa5d0], 0);
            assert_eq!(s.phy_ocp[&0xa432] & 0x10, 0x10);
            if version == 40 {
                assert_eq!(
                    s.phy_ocp[&0xbcc4] & 0x8000,
                    if capability == 0 { 0x8000 } else { 0 }
                );
                assert_eq!(s.phy_ocp[&0xc41a] & 2, if capability == 0 { 0 } else { 2 });
                assert_eq!(s.phy_ocp[&0xbcc8], 0xfeff);
                assert_eq!(s.g_parameters[&0x8084], 0x9fff);
                assert_eq!(s.g_parameters[&0x8012] & 0x8000, 0x8000);
                assert_eq!(s.phy_ocp[&0xc422], 0xdfff);
                assert_eq!(s.phy_ocp[&0xbcd8], 0x1065);
            } else {
                assert_eq!(s.phy_ocp[&0xbcc4], 0xffff);
                assert!(!s.g_parameters.contains_key(&0x8012));
            }
            let reset = s
                .writes
                .iter()
                .rposition(|(r, v, _)| {
                    *r == PHY_OCP && (*v >> 15) as u16 & !1 == 0xa400 && *v & (1 << 15) != 0
                })
                .unwrap();
            let eee = s
                .writes
                .iter()
                .position(|(r, v, _)| *r == PHY_OCP && *v == 0xd2e8_0000)
                .unwrap();
            assert!(reset < eee);
        }
    }
}

#[test]
fn g_mac_sequences_include_exact_8411b_rx_fix_before_any_descriptor_publication() {
    use crate::bus::dma::TestRegion;
    for version in [40, 42, 44] {
        let time = Time::default();
        let model = Model::modern(&time);
        {
            let mut s = model.state.borrow_mut();
            s.ephy.fill(0xffff);
            s.bytes[CONFIG3] = 0x7f;
            s.eri
                .extend([(0xcc, 0xaabb_ccdd), (0xd0, 0x1122_3344), (0x1b0, 0xffff)]);
            s.mac.insert(0xc0ac, 0x8000);
        }
        let mut hw = Hardware::new(&model, &time, revision(version), 0);
        hw.initialize_modern().unwrap();
        hw.configure_mac(None).unwrap();
        {
            let s = model.state.borrow();
            assert_eq!(s.bytes[CONFIG_LOCK], 0);
            assert_eq!(s.bytes[CONFIG3] & 2, 0);
            assert_eq!(s.eri[&0xc8], 0x0008_0002);
            assert_eq!(s.eri[&0xe8], 0x0010_0006);
            assert_eq!(s.eri[&0xcc], 0xaabb_cc38);
            assert_eq!(s.eri[&0xd0], 0x1122_3348);
            assert_eq!(s.eri[&0x2f8], 0x1d8f);
            assert_eq!(s.eri[&0x1b0] & 0x1003, 0);
            assert_eq!(s.mac[&0xc0ac], 0x9f80);
            assert!(
                !s.writes
                    .iter()
                    .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
            );
            if version == 44 {
                assert_eq!(s.ephy[0xc], 0xc82f);
                assert_eq!(s.mac[&0xf800], 0xe008);
                assert_eq!(s.mac[&0xf8dc], 0x0132);
                assert_eq!(s.mac.range(0xf800..=0xf8dc).count(), 111);
                assert_eq!(s.mac[&0xfc26], 0x8000);
                assert_eq!(s.mac[&0xfc36], 0x012d);
                let at = |value| {
                    s.writes
                        .iter()
                        .position(|(r, v, _)| *r == MAC_OCP && *v == value)
                        .unwrap()
                };
                assert!(at(0xfe13_0000) < at(0xfc00_e008)); // FC26 off before first patch word.
                assert!(at(0xfc6e_0132) < at(0xfe13_8000)); // Last word before enabling fix.
            } else if version == 42 {
                assert_eq!(s.ephy[0], 0x10a3);
                assert_eq!(s.ephy[0x1e], 0x20eb);
                assert!(!s.mac.contains_key(&0xfc26));
            } else {
                assert_eq!(s.ephy[0xc], 0xc82f);
                assert_eq!(s.ephy[0x19], 0x7fff);
            }
        }
        let mut dma = TestRegion::new(200_000 * 8);
        let mut rx = Ring::new(&mut dma, true).unwrap();
        let mut tx = Ring::new(&mut dma, true).unwrap();
        rx.initialize(true);
        tx.initialize(false);
        let mac = read_station(&hw).unwrap();
        publish(&hw, &rx, &tx, mac).unwrap();
        assert_eq!(
            model.read32(RX_CONFIG),
            (1 << 15) | (1 << 11) | (7 << 8) | 0x0e
        );
        assert_eq!(
            model.read32(RX_HIGH),
            (rx.descriptors.physical() >> 32) as u32
        );
    }
}
