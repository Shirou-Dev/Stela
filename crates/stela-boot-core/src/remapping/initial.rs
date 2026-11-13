//! The mode each remapping unit starts in, decided from the drivers of the
//! devices behind it, and so the path each requester's DMA takes before its
//! driver attaches.
//!
//! Most host drivers program physical addresses in the drivers' DMA pool:
//! NVMe, AHCI, xHCI, the Ethernet adapters, and every USB controller's
//! firmware handoff. They work only where that pool reaches memory
//! unchanged: through a unit's window, which maps the pool one to one, or
//! untranslated. A few drivers attach only through a cold preparation of
//! their original requester (VMD, EHCI), which needs every unit blocked
//! from the start or none taken at all.
//!
//! So a unit starts blocked only when no device behind it needs the pool,
//! starts in the window when one does, and is left untranslated when
//! taking any unit would refuse a native driver the machine needs.
//!
//! The IOAPICs and every native attachment need the whole machine's
//! interrupt and DMA state accounted for: a complete blocked fabric, or no
//! unit taken with every unit off. Units taken in any other mix (one beside
//! a left unit, one in the window, a requester no unit covers) give
//! neither, so when every unit is off and the units cannot form a complete
//! blocked fabric, the policy leaves them all and the machine runs
//! untranslated, as with no IOMMU described. Units the boot could not
//! prove off keep the mix: leaving them gains nothing.
use super::{Leave, Present};
use alloc::vec::Vec;
use stela_drivers::bus::pci::Identity;

/// EHCI's class code: its firmware handoff runs in its native attach.
const EHCI: [u8; 3] = [0x0c, 0x03, 0x20];

/// What the driver of a present function needs from its initial DMA path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Need {
    /// No driver here takes it, or one that is not needed to boot and is
    /// refused when its unit is translated (HD Audio, Wi-Fi).
    Nothing,
    /// Its driver uses physical addresses in the drivers' DMA pool, or a
    /// firmware handoff through the original PCI view.
    Physical,
    /// Its driver attaches only through a cold preparation of its original
    /// requester, and the machine needs it: the boot disk behind Intel VMD,
    /// or the EHCI handoff that releases the firmware's legacy USB.
    Native,
}

impl Need {
    /// What `function`'s driver needs, from the identity probe matches.
    pub fn of(function: &Identity) -> Self {
        if function.class == EHCI
            || stela_drivers::bus::vmd::Profile::identify(function.vendor, function.device).is_ok()
        {
            Self::Native
        } else if stela_drivers::audio::hda::pci::identify_identity(function).is_ok() {
            Self::Nothing
        } else if stela_drivers::probe::claims_identity(function) {
            Self::Physical
        } else {
            Self::Nothing
        }
    }
}

/// One present function on `segment` and what its driver needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Requester {
    pub segment: u16,
    pub rid: u16,
    pub need: Need,
}

/// A firmware unit as the policy found it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub segment: u16,
    /// The requesters it covers ([`super::decide`]), or why it is left.
    pub decision: Result<Vec<u16>, Leave>,
    /// Whether its requesters may start blocked: no reserved region (RMRR,
    /// IVMD) they still use, and on AMD-Vi a firmware state the boot proved.
    pub blockable: bool,
}

/// Why the policy leaves a unit it could take untranslated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Left {
    /// [`super::decide`]'s refusal.
    Policy(Leave),
    /// This requester's driver attaches only on a machine whose units are
    /// all blocked or all left, and the units form no complete blocked
    /// fabric.
    Native { segment: u16, rid: u16 },
    /// The units form no complete blocked fabric (another unit is left, a
    /// requester no unit covers, one needs the drivers' pool or a reserved
    /// region), and with every unit off such a machine is accounted for
    /// only when it takes none.
    Incomplete,
}

/// How a unit starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Every requester's context is absent until its own driver attaches.
    Blocked,
    /// Every requester sees the drivers' pool and its reserved regions one
    /// to one until its own driver attaches.
    Window,
    /// Not taken: off since ExitBootServices.
    Left(Left),
}

/// How a requester's DMA reaches memory before its driver attaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// No taken unit routes it: physical addresses reach memory.
    Untranslated,
    /// Its unit maps the drivers' pool one to one.
    Window,
    /// Its unit blocks it until its own driver attaches.
    Blocked,
}

impl Access {
    /// Whether a driver that programs physical addresses in the drivers'
    /// pool reaches it.
    pub fn reaches_pool(self) -> bool {
        self != Self::Blocked
    }
}

/// The mode of each of `candidates`, in order. `requesters` lists every
/// present function the units must cover for a complete blocked fabric
/// (an AMD-Vi unit's own function is not one). `units_off` says whether the
/// boot proved every described unit off since ExitBootServices, without
/// which leaving them all gains a native driver nothing. `refused` says
/// whether a described unit that is not a candidate was left off before
/// the policy ran.
pub fn modes(
    candidates: &[Candidate],
    requesters: &[Requester],
    units_off: bool,
    refused: bool,
) -> Vec<Mode> {
    let covered = |requester: &Requester| {
        candidates.iter().any(|candidate| {
            candidate.segment == requester.segment
                && candidate
                    .decision
                    .as_ref()
                    .is_ok_and(|rids| rids.contains(&requester.rid))
        })
    };
    let physical = |segment: u16, rids: &[u16]| {
        requesters.iter().any(|requester| {
            requester.need == Need::Physical
                && requester.segment == segment
                && rids.contains(&requester.rid)
        })
    };
    let any_physical = requesters
        .iter()
        .any(|requester| requester.need == Need::Physical);
    let fabric = !candidates.is_empty()
        && !refused
        && !any_physical
        && candidates
            .iter()
            .all(|candidate| candidate.decision.is_ok() && candidate.blockable)
        && requesters.iter().all(covered);
    // Taken units short of a complete blocked fabric leave the IOAPICs and
    // every native attachment refused; with every unit off, leaving all of
    // them does not.
    let leave_all = units_off && !fabric;
    let native = requesters
        .iter()
        .find(|requester| requester.need == Need::Native);
    candidates
        .iter()
        .map(|candidate| match &candidate.decision {
            Err(leave) => Mode::Left(Left::Policy(*leave)),
            Ok(_) if fabric => Mode::Blocked,
            Ok(_) if leave_all => {
                Mode::Left(native.map_or(Left::Incomplete, |native| Left::Native {
                    segment: native.segment,
                    rid: native.rid,
                }))
            }
            Ok(rids) if !candidate.blockable || physical(candidate.segment, rids) => Mode::Window,
            Ok(_) => Mode::Blocked,
        })
        .collect()
}

/// The access of a requester the unit at index `route` of `modes` routes,
/// none when no unit routes it.
pub fn access(modes: &[Mode], route: Option<usize>) -> Access {
    match route.and_then(|index| modes.get(index)) {
        Some(Mode::Blocked) => Access::Blocked,
        Some(Mode::Window) => Access::Window,
        Some(Mode::Left(_)) | None => Access::Untranslated,
    }
}

/// Whether `modes` take no unit, so that with every unit off the machine
/// is as untranslated as one that describes none.
pub fn none_taken(modes: &[Mode]) -> bool {
    modes.iter().all(|mode| matches!(mode, Mode::Left(_)))
}

/// The requesters of `present` on `segment` with what their drivers need,
/// from `identity`, which reads a function's vendor and device IDs.
pub fn requesters(
    segment: u16,
    present: &[Present],
    mut identity: impl FnMut(u16) -> Option<(u16, u16)>,
) -> Vec<Requester> {
    present
        .iter()
        .map(|function| {
            let need = identity(function.rid).map_or(Need::Nothing, |(vendor, device)| {
                Need::of(&Identity {
                    address: stela_drivers::bus::pci::Address {
                        segment,
                        bus: (function.rid >> 8) as u8,
                        device: (function.rid >> 3 & 31) as u8,
                        function: (function.rid & 7) as u8,
                    },
                    vendor,
                    device,
                    class: function.class,
                })
            });
            Requester {
                segment,
                rid: function.rid,
                need,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests;
