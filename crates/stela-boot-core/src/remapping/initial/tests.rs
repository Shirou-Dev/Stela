//! The IOMMU states real PCs boot in: off, on and translating, on with
//! units left untranslated, AMD-Vi with the GPU behind the only unit, and
//! VT-d with an integrated GPU on its own unit.
use super::*;
use crate::dmar::{Drhd, Remapping, Rmrr};
use crate::remapping::{Scope, decide, plan, route};
use alloc::vec;

const HOST: (u16, [u8; 3], (u16, u16)) = (0x0000, [6, 0, 0], (0x8086, 0x4660));
const IGPU: (u16, [u8; 3], (u16, u16)) = (0x0010, [3, 0, 0], (0x8086, 0x4680));
const VMD: (u16, [u8; 3], (u16, u16)) = (0x0070, [1, 4, 0], (0x8086, 0x467f));
const XHCI: (u16, [u8; 3], (u16, u16)) = (0x00a0, [0x0c, 3, 0x30], (0x8086, 0x7ae0));
const EHCI_HOST: (u16, [u8; 3], (u16, u16)) = (0x00e8, [0x0c, 3, 0x20], (0x8086, 0x1c26));
const AUDIO: (u16, [u8; 3], (u16, u16)) = (0x00fb, [4, 3, 0], (0x8086, 0x7ad0));
const SMBUS: (u16, [u8; 3], (u16, u16)) = (0x00fc, [0x0c, 5, 0], (0x8086, 0x7aa3));
const NVME: (u16, [u8; 3], (u16, u16)) = (0x0100, [1, 8, 2], (0x144d, 0xa80a));
const GPU: (u16, [u8; 3], (u16, u16)) = (0x0300, [3, 0, 0], (0x1002, 0x73bf));
const SATA: (u16, [u8; 3], (u16, u16)) = (0x0400, [1, 6, 1], (0x1022, 0x7901));

type Function = (u16, [u8; 3], (u16, u16));

fn present(functions: &[Function]) -> Vec<Present> {
    functions
        .iter()
        .map(|&(rid, class, _)| Present {
            rid,
            class,
            bridge: None,
        })
        .collect()
}

fn census(functions: &[Function]) -> (Vec<Present>, Vec<Requester>) {
    let present = present(functions);
    let requesters = requesters(0, &present, |rid| {
        functions
            .iter()
            .find(|function| function.0 == rid)
            .map(|function| function.2)
    });
    (present, requesters)
}

fn rids(functions: &[Function]) -> Vec<u16> {
    functions.iter().map(|function| function.0).collect()
}

fn unit(include_all: bool, endpoints: &[u16]) -> Drhd {
    Drhd {
        base: 0xfed9_0000,
        bytes: 4096,
        segment: 0,
        include_all,
        scopes: endpoints
            .iter()
            .map(|&rid| Scope {
                bridge: false,
                bus: (rid >> 8) as u8,
                path: vec![((rid >> 3 & 31) as u8, (rid & 7) as u8)],
            })
            .collect(),
        sources: vec![],
    }
}

fn dmar(units: Vec<Drhd>, reserved: Vec<Rmrr>) -> Remapping {
    Remapping {
        physical_bits: 39,
        flags: 0,
        additional_structures: vec![],
        skipped: vec![],
        units,
        reserved,
    }
}

/// The VT-d planner's candidates: blockable without an RMRR for their
/// requesters, as `Remappers::take` decides.
fn intel(remapping: &Remapping, present: &[Present]) -> Vec<Candidate> {
    plan(remapping, 0, present, &[])
        .into_iter()
        .map(|(_, decision)| Candidate {
            segment: 0,
            blockable: decision.as_ref().is_ok_and(|requesters| {
                !remapping.reserved.iter().any(|region| {
                    region.scopes.iter().any(|scope| {
                        scope
                            .resolve(present)
                            .iter()
                            .any(|rid| requesters.contains(rid))
                    })
                })
            }),
            decision,
        })
        .collect()
}

fn reach(remapping: &Remapping, present: &[Present], modes: &[Mode], rid: u16) -> Access {
    access(modes, route(remapping, 0, present, rid).unwrap())
}

#[test]
fn needs_follow_the_driver_probe_attaches() {
    let need = |(rid, class, (vendor, device)): Function| {
        Need::of(&Identity {
            address: stela_drivers::bus::pci::Address {
                segment: 0,
                bus: (rid >> 8) as u8,
                device: (rid >> 3 & 31) as u8,
                function: (rid & 7) as u8,
            },
            vendor,
            device,
            class,
        })
    };
    for physical in [NVME, XHCI, SATA] {
        assert_eq!(need(physical), Need::Physical, "{physical:x?}");
    }
    for native in [VMD, EHCI_HOST] {
        assert_eq!(need(native), Need::Native, "{native:x?}");
    }
    for nothing in [HOST, IGPU, AUDIO, SMBUS, GPU] {
        assert_eq!(need(nothing), Need::Nothing, "{nothing:x?}");
    }
}

#[test]
fn off_no_unit_leaves_every_requester_untranslated() {
    let (_, requesters) = census(&[HOST, NVME, XHCI]);
    let modes = modes(&[], &requesters, true, false);
    assert!(modes.is_empty());
    assert!(none_taken(&modes));
    assert_eq!(access(&modes, None), Access::Untranslated);
    assert!(access(&modes, None).reaches_pool());
}

#[test]
fn on_and_translating_windows_the_unit_the_pool_drivers_sit_behind() {
    // QEMU q35 with `intel-iommu` and no display: one include-all unit.
    let functions = [HOST, XHCI, NVME, SATA];
    let (present, requesters) = census(&functions);
    let remapping = dmar(vec![unit(true, &[])], vec![]);
    let modes = modes(&intel(&remapping, &present), &requesters, true, false);
    assert_eq!(modes, [Mode::Window]);
    for (rid, _, _) in functions {
        let reached = reach(&remapping, &present, &modes, rid);
        assert_eq!(reached, Access::Window);
        assert!(reached.reaches_pool());
    }
    assert!(!none_taken(&modes));
}

#[test]
fn on_and_translating_without_pool_drivers_blocks_the_whole_fabric() {
    let (present, requesters) = census(&[HOST, SMBUS, AUDIO]);
    let remapping = dmar(vec![unit(false, &[AUDIO.0]), unit(true, &[])], vec![]);
    let modes = modes(&intel(&remapping, &present), &requesters, true, false);
    assert_eq!(modes, [Mode::Blocked, Mode::Blocked]);
    assert_eq!(
        reach(&remapping, &present, &modes, AUDIO.0),
        Access::Blocked
    );
}

#[test]
fn a_unit_without_pool_drivers_stays_blocked_beside_a_windowed_one() {
    let (present, requesters) = census(&[HOST, AUDIO, NVME]);
    let remapping = dmar(vec![unit(false, &[AUDIO.0]), unit(true, &[])], vec![]);
    let modes = modes(&intel(&remapping, &present), &requesters, true, false);
    assert_eq!(modes, [Mode::Blocked, Mode::Window]);
    assert_eq!(reach(&remapping, &present, &modes, NVME.0), Access::Window);
    assert_eq!(
        reach(&remapping, &present, &modes, AUDIO.0),
        Access::Blocked
    );
}

#[test]
fn an_rmrr_windows_its_unit_as_before() {
    let (present, requesters) = census(&[HOST, XHCI]);
    let reserved = Rmrr {
        segment: 0,
        base: 0x7a00_0000,
        limit: 0x7a01_ffff,
        scopes: unit(false, &[XHCI.0]).scopes,
        sources: vec![],
    };
    let remapping = dmar(vec![unit(true, &[])], vec![reserved]);
    let candidates = intel(&remapping, &present);
    assert!(!candidates[0].blockable);
    assert_eq!(modes(&candidates, &requesters, true, false), [Mode::Window]);
}

#[test]
fn on_with_untranslated_passthrough_leaves_requesters_on_physical_addresses() {
    // An RMRR names a requester other than a USB host: the unit stays off.
    let (present, requesters) = census(&[HOST, NVME, SATA]);
    let reserved = Rmrr {
        segment: 0,
        base: 0x7a00_0000,
        limit: 0x7a01_ffff,
        scopes: unit(false, &[SATA.0]).scopes,
        sources: vec![],
    };
    let remapping = dmar(vec![unit(true, &[])], vec![reserved]);
    let modes = modes(&intel(&remapping, &present), &requesters, true, false);
    assert_eq!(modes, [Mode::Left(Left::Policy(Leave::Reserved(SATA.0)))]);
    assert!(none_taken(&modes));
    for rid in [NVME.0, SATA.0] {
        assert_eq!(
            reach(&remapping, &present, &modes, rid),
            Access::Untranslated
        );
    }
}

#[test]
fn amd_vi_with_the_gpu_on_its_only_unit_leaves_the_machine_untranslated() {
    // One IVHD covers everything, the discrete GPU included, with no IVMD.
    let functions = [HOST, GPU, NVME, SATA, XHCI, AUDIO];
    let (present, requesters) = census(&functions);
    let covered = rids(&functions);
    let candidates = [Candidate {
        segment: 0,
        decision: decide(&covered, &[], &present, &[]),
        blockable: true,
    }];
    let modes = modes(&candidates, &requesters, true, false);
    assert_eq!(modes, [Mode::Left(Left::Policy(Leave::Display(GPU.0)))]);
    assert!(none_taken(&modes));
    assert_eq!(access(&modes, Some(0)), Access::Untranslated);
}

#[test]
fn amd_vi_with_the_gpu_on_one_of_several_units_leaves_every_unit() {
    // Threadripper: the GPU behind one IOMMU, the disks behind another.
    let (present, requesters) = census(&[HOST, GPU, NVME, SATA, XHCI]);
    let candidates = [
        Candidate {
            segment: 0,
            decision: decide(&rids(&[HOST, GPU]), &[], &present, &[]),
            blockable: true,
        },
        Candidate {
            segment: 0,
            decision: decide(&rids(&[NVME, SATA, XHCI]), &[], &present, &[]),
            blockable: true,
        },
    ];
    let modes = modes(&candidates, &requesters, true, false);
    assert_eq!(
        modes,
        [
            Mode::Left(Left::Policy(Leave::Display(GPU.0))),
            Mode::Left(Left::Beside)
        ]
    );
    assert!(none_taken(&modes));
    assert_eq!(access(&modes, Some(1)), Access::Untranslated);
}

#[test]
fn without_proof_the_units_are_off_a_left_unit_keeps_the_others_taken() {
    let (present, requesters) = census(&[HOST, GPU, NVME]);
    let candidates = [
        Candidate {
            segment: 0,
            decision: decide(&rids(&[HOST, GPU]), &[], &present, &[]),
            blockable: false,
        },
        Candidate {
            segment: 0,
            decision: decide(&rids(&[NVME]), &[], &present, &[]),
            blockable: false,
        },
    ];
    assert_eq!(
        modes(&candidates, &requesters, false, false),
        [
            Mode::Left(Left::Policy(Leave::Display(GPU.0))),
            Mode::Window
        ]
    );
}

#[test]
fn intel_with_an_integrated_gpu_leaves_the_include_all_unit() {
    let functions = [HOST, IGPU, XHCI, AUDIO, NVME];
    let (present, requesters) = census(&functions);
    let remapping = dmar(vec![unit(false, &[IGPU.0]), unit(true, &[])], vec![]);
    let modes = modes(&intel(&remapping, &present), &requesters, true, false);
    assert_eq!(
        modes,
        [
            Mode::Left(Left::Policy(Leave::Display(IGPU.0))),
            Mode::Left(Left::Beside)
        ]
    );
    for (rid, _, _) in functions {
        assert_eq!(
            reach(&remapping, &present, &modes, rid),
            Access::Untranslated
        );
    }
}

/// `count` units on segment 0 over the host bridge and the pool drivers'
/// functions, the first holding `display` when given.
fn units(count: usize, display: Option<Function>) -> (Vec<Requester>, Vec<Candidate>) {
    let mut functions = vec![HOST, NVME, SATA, XHCI, AUDIO];
    functions.extend(display);
    let (present, requesters) = census(&functions);
    let candidates = (0..count)
        .map(|index| {
            let mut covered = match (count, index) {
                (1, _) => vec![HOST, NVME, SATA, XHCI, AUDIO],
                (_, 0) => vec![HOST],
                (_, 1) => vec![NVME],
                (_, 2) => vec![SATA, AUDIO],
                _ => vec![XHCI],
            };
            if index == 0 {
                covered.extend(display);
            }
            Candidate {
                segment: 0,
                decision: decide(&rids(&covered), &[], &present, &[]),
                blockable: true,
            }
        })
        .collect();
    (requesters, candidates)
}

#[test]
fn a_display_behind_one_of_one_two_or_four_units_leaves_them_all() {
    for count in [1, 2, 4] {
        for display in [GPU, IGPU] {
            let (requesters, candidates) = units(count, Some(display));
            let modes = modes(&candidates, &requesters, true, false);
            assert_eq!(
                modes[0],
                Mode::Left(Left::Policy(Leave::Display(display.0))),
                "{count} units"
            );
            assert!(
                modes[1..]
                    .iter()
                    .all(|mode| *mode == Mode::Left(Left::Beside)),
                "{count} units: {modes:?}"
            );
            assert!(none_taken(&modes));
        }
    }
}

#[test]
fn without_a_display_one_two_or_four_units_are_all_taken() {
    for count in [1, 2, 4] {
        let (requesters, candidates) = units(count, None);
        let modes = modes(&candidates, &requesters, true, false);
        assert_eq!(modes.len(), count);
        assert!(
            modes.iter().all(|mode| !matches!(mode, Mode::Left(_))),
            "{count} units: {modes:?}"
        );
        // The disk's unit starts in the drivers' window.
        assert_eq!(modes[count.min(2) - 1], Mode::Window, "{count} units");
    }
}

#[test]
fn a_unit_with_no_requester_leaves_the_others_off() {
    let (present, requesters) = census(&[HOST, NVME]);
    let candidates = [
        Candidate {
            segment: 0,
            decision: decide(&[], &[], &present, &[]),
            blockable: true,
        },
        Candidate {
            segment: 0,
            decision: decide(&rids(&[HOST, NVME]), &[], &present, &[]),
            blockable: true,
        },
    ];
    assert_eq!(
        modes(&candidates, &requesters, true, false),
        [
            Mode::Left(Left::Policy(Leave::Empty)),
            Mode::Left(Left::Beside)
        ]
    );
}

#[test]
fn a_unit_refused_before_the_policy_leaves_the_others_off() {
    let (requesters, candidates) = units(2, None);
    assert_eq!(
        modes(&candidates, &requesters, true, true),
        [Mode::Left(Left::Beside), Mode::Left(Left::Beside)]
    );
    // Without proof the refused unit is off, the others are taken.
    let taken = modes(&candidates, &requesters, false, true);
    assert!(taken.iter().all(|mode| !matches!(mode, Mode::Left(_))));
}

#[test]
fn a_unit_refused_before_the_policy_keeps_a_blocked_fabric_from_completing() {
    let (present, requesters) = census(&[HOST, AUDIO]);
    let candidates = [Candidate {
        segment: 0,
        decision: decide(&rids(&[HOST, AUDIO]), &[], &present, &[]),
        blockable: true,
    }];
    assert_eq!(
        modes(&candidates, &requesters, true, false),
        [Mode::Blocked]
    );
    assert_eq!(
        modes(&candidates, &requesters, true, true),
        [Mode::Left(Left::Beside)]
    );
}

#[test]
fn intel_with_an_integrated_gpu_and_a_vmd_disk_takes_no_unit() {
    // RST laptops: the disk is behind VMD, whose driver attaches natively.
    let (present, requesters) = census(&[HOST, IGPU, VMD, XHCI, AUDIO]);
    let remapping = dmar(vec![unit(false, &[IGPU.0]), unit(true, &[])], vec![]);
    let modes = modes(&intel(&remapping, &present), &requesters, true, false);
    assert_eq!(
        modes,
        [
            Mode::Left(Left::Policy(Leave::Display(IGPU.0))),
            Mode::Left(Left::Native {
                segment: 0,
                rid: VMD.0
            })
        ]
    );
    assert!(none_taken(&modes));
    for rid in [VMD.0, XHCI.0] {
        assert_eq!(
            reach(&remapping, &present, &modes, rid),
            Access::Untranslated
        );
    }
}

#[test]
fn an_ehci_host_keeps_its_handoff_by_leaving_every_unit() {
    let (present, requesters) = census(&[HOST, EHCI_HOST, XHCI, NVME]);
    let remapping = dmar(vec![unit(true, &[])], vec![]);
    let modes = modes(&intel(&remapping, &present), &requesters, true, false);
    assert_eq!(
        modes,
        [Mode::Left(Left::Native {
            segment: 0,
            rid: EHCI_HOST.0
        })]
    );
}

#[test]
fn without_proof_the_units_are_off_a_native_device_does_not_leave_them() {
    let (present, requesters) = census(&[HOST, VMD, XHCI]);
    let remapping = dmar(vec![unit(true, &[])], vec![]);
    let modes = modes(&intel(&remapping, &present), &requesters, false, false);
    assert_eq!(modes, [Mode::Window]);
}

#[test]
fn a_native_device_on_a_complete_blocked_fabric_keeps_it() {
    // No pool driver anywhere: VMD prepares through its blocked context.
    let (present, requesters) = census(&[HOST, VMD, AUDIO]);
    let remapping = dmar(vec![unit(true, &[])], vec![]);
    let modes = modes(&intel(&remapping, &present), &requesters, true, false);
    assert_eq!(modes, [Mode::Blocked]);
}

#[test]
fn an_uncovered_requester_keeps_the_fabric_from_completing() {
    // No include-all unit: the NVMe disk is routed by none.
    let (present, requesters) = census(&[HOST, AUDIO, NVME]);
    let remapping = dmar(vec![unit(false, &[AUDIO.0])], vec![]);
    let candidates = intel(&remapping, &present);
    let modes = modes(&candidates, &requesters, true, false);
    assert_eq!(modes, [Mode::Blocked]);
    assert_eq!(
        reach(&remapping, &present, &modes, NVME.0),
        Access::Untranslated
    );
}
