// SPDX-License-Identifier: GPL-2.0-only
//! Original FLB/RBL writes and fixed settling through Hardware.
use super::*;
struct Boundary {
    peer: Rc<Peer>,
    gsr: u32,
    effects: RefCell<Vec<(u32, u32, u32)>>,
}
// SAFETY: synchronous device model; exact register effects delegate to
// the independent DMA peer. Reset control/status read bits are immutable
// device-owned observations across the two possible reset stores.
unsafe impl Registers for Rc<Boundary> {
    fn read(&self, at: usize) -> Result<u32> {
        if at == 0 {
            Ok(self.gsr)
        } else {
            self.peer.read(at)
        }
    }
    fn write(&self, at: usize, value: u32) -> Result<()> {
        self.effects.borrow_mut().push((0, at as u32, value));
        self.peer.write(at, value)
    }
}
// SAFETY: explicit symbolic same-peer elapsed time, no native timing assertion.
unsafe impl Timer for Boundary {
    fn check(&self) -> core::result::Result<(), crate::bus::pci::power::Error> {
        self.peer.check()
    }
    fn wait_us(&self, us: u64) -> core::result::Result<(), crate::bus::pci::power::Error> {
        self.effects
            .borrow_mut()
            .push((1, 0, u32::try_from(us).unwrap()));
        self.peer.wait_us(us)
    }
}
fn reset(flb: bool, gsr: u32, spi: bool, seed: bool) -> Vec<(u32, u32, u32)> {
    let (_, peer, _, _) = setup(0x07b1);
    peer.set(0x388, u32::from(!flb));
    peer.set(0x53c, if spi { 0x13579bcd } else { 0 });
    for at in [0x5000, 0x7000, 0x4000] {
        peer.set(at, 0x20000000 | if seed { 0x05030201 } else { 0 });
    }
    let boundary = Rc::new(Boundary {
        peer: peer.clone(),
        gsr,
        effects: RefCell::new(Vec::new()),
    });
    let hw = Hardware {
        registers: boundary.clone(),
        timer: boundary.clone(),
        reset_ownership: Cell::new(firmware::ResetOwnership::default()),
        budget: Cell::new(None),
    };
    hw.reset(peer.profile).unwrap();
    boundary.effects.take()
}
#[test]
fn reset_keeps_source_control_bits() {
    if crate::test_process::isolate_model() {
        return;
    }
    for flb in [false, true] {
        for gsr in [0, 0x55aa1234, 0x00ff4444, 0xdeadbeef] {
            let effects = reset(flb, gsr, true, true);
            let stores: Vec<_> = effects
                .iter()
                .filter_map(|&(kind, at, value)| (kind == 0 && at == 0).then_some(value))
                .collect();
            let preserve = if flb { 0xbfff } else { 0xffffbfff };
            assert_eq!(
                stores,
                vec![(gsr & preserve) | 0x8000; if flb { 2 } else { 1 }]
            );
            let waits: Vec<_> = effects
                .iter()
                .filter_map(|&(kind, _, value)| (kind == 1).then_some(value))
                .collect();
            assert_eq!(
                waits,
                if flb {
                    vec![50_000, 10_000, 50_000, 15_000]
                } else {
                    vec![15_000]
                }
            );
        }
    }
}
#[test]
#[ignore = "oracle: STELA_AQTION_RESET_ORACLE"]
fn unchanged_linux_flb_rbl_complete_reset_writes_and_settling_match_hardware() {
    if crate::test_process::isolate_model() {
        return;
    }
    let text =
        std::fs::read_to_string(std::env::var("STELA_AQTION_RESET_ORACLE").unwrap()).unwrap();
    let mut count = 0;
    for line in text.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        assert_eq!(fields[0], "R");
        let n = |i: usize| fields[i].parse::<u32>().unwrap();
        assert_eq!(n(5), 0);
        let expected: Vec<_> = (0..n(6) as usize)
            .map(|i| (n(7 + i * 3), n(8 + i * 3), n(9 + i * 3)))
            .collect();
        assert_eq!(fields.len(), 7 + expected.len() * 3);
        assert_eq!(
            reset(n(1) != 0, n(2), n(3) != 0, n(4) != 0),
            expected,
            "source case {count}"
        );
        count += 1;
    }
    assert_eq!(count, 32);
}
