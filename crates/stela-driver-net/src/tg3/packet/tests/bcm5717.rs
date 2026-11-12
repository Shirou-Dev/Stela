// SPDX-License-Identifier: GPL-2.0-only
//! A BCM5717 or BCM5718 after A0: the 5717_PLUS path with tg3's 5717
//! deltas.
use super::*;

impl Device {
    pub(super) fn is_5717(&self) -> bool {
        matches!(self.config[&0], 0x1655_14e4 | 0x1656_14e4 | 0x1665_14e4)
    }
    /// A BCM5717 B0 (or 5718) function on the given internal port, copper,
    /// with its BCM5718C PHY.
    pub(super) fn new_5717(device: u16, port: u32) -> Self {
        let mut p = Self::new();
        p.config.insert(0, u32::from(device) << 16 | 0x14e4);
        p.config.insert(0xf4, 0x0571_7100);
        p.sram.insert(0xe00, (port << 29) | 0x362c);
        let id = 0x5c0d_8a01u32;
        p.phy.insert(2, (id >> 10) as u16);
        p.phy
            .insert(3, (((id >> 16) & 0xfc00) | (id & 0x3ff)) as u16);
        // The 5719/5720 LSO boundary register is not touched on 5717.
        p.mac.insert(0x4910, 0x0110_0080);
        p
    }
}
fn attach_5717(
    device: u16,
    port: u32,
) -> (Packet<Reg, Timer>, Pages, Arc<Domain>, Arc<Mutex<Device>>) {
    let (hardware, pages, domain, peer) = parts();
    *peer.lock().unwrap() = Device::new_5717(device, port);
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
        Ok(packet) => packet,
        Err((e, _)) => panic!("5717 attach: {e:?}"),
    };
    (packet, pages, domain, peer)
}

#[test]
fn actual_5717_and_5718_start_with_their_own_clock_power_source_and_read_dma() {
    if crate::test_process::isolate_model() {
        return;
    }
    for device in [0x1655, 0x1656, 0x1665] {
        let (mut packet, _, domain, peer) = attach_5717(device, 1);
        {
            let p = peer.lock().unwrap();
            // tg3_override_clk around the core reset, then tg3_restore_clk.
            assert!(p.access.contains(&(true, 0x3628, 1 << 13)));
            assert_eq!(p.mac[&0x3628] & (1 << 13), 0);
            assert!(!p.access.iter().any(|(w, at, _)| *w && *at == 0x3624));
            // Port 1's driver-present bits in the APE's GPIO message word.
            assert_eq!(p.ape[&0x8], 1 << (4 + 4));
            assert!(!p.mac.contains_key(&0x344c));
            assert_eq!(p.dsp[&0x1a], 0);
            // tg3_reset_hw: MULT_DMA_RD_DIS, the statistics workaround,
            // and none of the 5719/5720 LSO or channel length fixes.
            p.require_bits(0x4800, 0x0100_0000, 0x0100_0000);
            p.require_bits(0x4400, 0x8000_0016, 0x16);
            p.require_bits(0x6800, 0x1000_0000, 0x1000_0000);
            assert_eq!(p.mac[&0x4910], 0x0110_0080);
            assert!(
                !p.access
                    .iter()
                    .any(|(_, at, _)| (0x4be0..0x4bf0).contains(at))
            );
        }
        assert!(packet.carrier());
        packet.transmit(&[0x5a; 60]).unwrap();
        peer.lock().unwrap().receive(&[0x6b; 60], 0, &domain);
        assert_eq!(packet.receive().unwrap(), Some(vec![0x6b; 60]));
        assert_eq!(peer.lock().unwrap().sent, [vec![0x5a; 60]]);
        assert!(packet.retire().is_ok());
    }
}

#[test]
fn a_5717_port_0_phy_stays_powered_through_a_suspend() {
    if crate::test_process::isolate_model() {
        return;
    }
    for port in [0, 1] {
        let (mut packet, _, domain, peer) = attach_5717(0x1655, port);
        assert!(packet.carrier());
        let start = peer.lock().unwrap().phy_writes.len();
        packet.suspend_phy().unwrap();
        {
            let p = peer.lock().unwrap();
            let writes: Vec<_> = p.phy_writes[start..]
                .iter()
                .copied()
                .filter(|(at, value)| !(*at == 0x18 && *value == 0x2007))
                .collect();
            // tg3_power_down_phy's low-power writes, then tg3_phy_power_bug
            // stops port 0 short of BMCR power down.
            if port == 0 {
                assert_eq!(writes, [(0x10, 8), (0x18, 0x1b2)]);
                assert_eq!(p.phy.get(&0).copied().unwrap_or(0) & 0x800, 0);
            } else {
                assert_eq!(writes, [(0x10, 8), (0x18, 0x1b2), (0, 0x800)]);
            }
        }
        packet.resume_phy().unwrap();
        assert!(packet.carrier());
        peer.lock().unwrap().receive(&[0x7c; 60], 0, &domain);
        assert_eq!(packet.receive().unwrap(), Some(vec![0x7c; 60]));
        assert!(packet.retire().is_ok());
    }
}

#[test]
fn a_5717_a0_never_publishes_dma() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (hardware, pages, domain, peer) = parts();
    *peer.lock().unwrap() = Device::new_5717(0x1655, 0);
    peer.lock().unwrap().config.insert(0xf4, 0x0571_7000);
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
        Ok(_) => panic!("5717 A0 attached"),
        Err((e, _)) => assert_eq!(e, Error::UnsupportedRevision),
    }
    let p = peer.lock().unwrap();
    assert_eq!(p.dma_effects, 0);
    assert_eq!(p.config[&4] & 4, 0);
}
