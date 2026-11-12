//! How the mount connects the firmware's drivers to the PC's devices before
//! it reads its settings, and which connections it reports as slow.
//!
//! A firmware that boots fast connects only the path to the boot loader,
//! and the bundle, the install medium and the host disks lie on other
//! partitions and devices, so every controller is connected with its
//! children, as a boot manager does before it lists boot options. Each
//! connection is timed, and one that takes [`SLOW_MILLIS`] or more is
//! reported with the controller it was for, so a boot log names the device
//! whose firmware driver stalled.
use alloc::vec::Vec;

/// A connection that takes this long or longer is reported with the
/// controller it was for.
pub const SLOW_MILLIS: u64 = 1000;

/// What a handle is, for a report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// A PCI root bridge.
    RootBridge,
    /// A PCI function and its class code (base class, subclass and
    /// programming interface, as configuration bytes 0x0b, 0x0a, 0x09),
    /// or `None` when its configuration could not be read.
    Pci(Option<u32>),
    /// A handle whose device path has a MAC address node: a network
    /// interface a driver has already started.
    Network,
    /// Any other handle: a child of a controller, a non-PCI device, an
    /// image or a service.
    Other,
}

/// The firmware calls [`connect`] makes.
pub trait Firmware {
    type Handle: Copy + Eq;
    /// Every handle there is now.
    fn handles(&mut self) -> Vec<Self::Handle>;
    fn kind(&mut self, handle: Self::Handle) -> Kind;
    /// Connect the drivers that take `handle`, and with `recursive` its
    /// children's. A controller no driver takes stays as it was.
    fn connect(&mut self, handle: Self::Handle, recursive: bool);
    /// Milliseconds on a clock that only moves forward.
    fn millis(&mut self) -> u64;
    /// Connecting `handle` took `millis`, [`SLOW_MILLIS`] or more.
    fn slow(&mut self, handle: Self::Handle, kind: Kind, millis: u64);
}

/// What [`connect`] did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Summary {
    /// Handles there were at the start.
    pub handles: usize,
    /// Handles connected.
    pub connected: usize,
    /// Connections reported as slow.
    pub slow: usize,
}

/// Connect every handle with its children, in the firmware's order, and
/// report each connection that took [`SLOW_MILLIS`] or more once.
pub fn connect<F: Firmware>(firmware: &mut F) -> Summary {
    let handles = firmware.handles();
    let mut summary = Summary {
        handles: handles.len(),
        ..Summary::default()
    };
    for handle in handles {
        let start = firmware.millis();
        firmware.connect(handle, true);
        let millis = firmware.millis().saturating_sub(start);
        summary.connected += 1;
        if millis >= SLOW_MILLIS {
            summary.slow += 1;
            let kind = firmware.kind(handle);
            firmware.slow(handle, kind, millis);
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    const USB: u32 = 0x0c0330;
    const ETHERNET: u32 = 0x020000;
    const AUDIO: u32 = 0x040300;

    #[derive(Default)]
    struct Fake {
        kinds: Vec<Kind>,
        millis: Vec<u64>,
        clock: u64,
        connected: Vec<(usize, bool)>,
        slow: Vec<(usize, Kind, u64)>,
    }

    impl Firmware for Fake {
        type Handle = usize;

        fn handles(&mut self) -> Vec<usize> {
            (0..self.kinds.len()).collect()
        }

        fn kind(&mut self, handle: usize) -> Kind {
            self.kinds[handle]
        }

        fn connect(&mut self, handle: usize, recursive: bool) {
            self.connected.push((handle, recursive));
            self.clock += self.millis[handle];
        }

        fn millis(&mut self) -> u64 {
            self.clock
        }

        fn slow(&mut self, handle: usize, kind: Kind, millis: u64) {
            self.slow.push((handle, kind, millis));
        }
    }

    fn fake(handles: &[(Kind, u64)]) -> Fake {
        Fake {
            kinds: handles.iter().map(|&(kind, _)| kind).collect(),
            millis: handles.iter().map(|&(_, millis)| millis).collect(),
            ..Fake::default()
        }
    }

    #[test]
    fn a_slow_controller_is_reported_once_with_its_time() {
        let mut fake = fake(&[
            (Kind::RootBridge, 5),
            (Kind::Pci(Some(USB)), 2),
            (Kind::Pci(Some(ETHERNET)), 40_000),
            (Kind::Pci(Some(AUDIO)), SLOW_MILLIS - 1),
            (Kind::Other, SLOW_MILLIS),
        ]);
        let summary = connect(&mut fake);
        assert_eq!(
            fake.slow,
            vec![
                (2, Kind::Pci(Some(ETHERNET)), 40_000),
                (4, Kind::Other, SLOW_MILLIS)
            ]
        );
        assert_eq!(
            summary,
            Summary {
                handles: 5,
                connected: 5,
                slow: 2
            }
        );
    }

    #[test]
    fn a_normal_boot_reports_nothing() {
        let mut fake = fake(&[(Kind::RootBridge, 100), (Kind::Pci(Some(USB)), 60)]);
        let summary = connect(&mut fake);
        assert_eq!(summary.slow, 0);
        assert!(fake.slow.is_empty());
        assert_eq!(fake.connected, vec![(0, true), (1, true)]);
    }
}
