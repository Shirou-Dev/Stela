//! Which controllers the mount connects the firmware's drivers to before it
//! reads its settings, in what order, and which connections it reports as
//! slow.
//!
//! A firmware that boots fast connects only the path to the boot loader.
//! Before boot services end the mount still needs, through the firmware:
//! file systems and block I/O on the USB and on every internal disk (the
//! bundle, the install medium, the translation store and the chosen macOS
//! disk lie on other partitions and devices), so USB, NVMe, AHCI, SD and
//! other storage controllers with every child bus under them; the display's
//! graphics output and EDID; keyboards for the boot screen, on USB or on
//! the LPC bridge's PS/2 port; PCI I/O on every function for the census;
//! and the random number and processor services, which are not devices.
//!
//! Nothing before boot services end uses the firmware's network stack:
//! online setup and every later download run on Stela's own network
//! drivers. A network controller is therefore left alone, as boot loaders
//! that connect nothing leave it, and its firmware drivers (an option ROM,
//! a PXE, HTTP or iSCSI boot stack, DHCP on start) never run. A network
//! interface a driver already started, such as the one the firmware booted
//! the mount from, keeps what it has.
//!
//! The PCI root bridges are connected first and alone, so their bus driver
//! lists every function under them without starting the functions'
//! drivers; then each function is connected with its children by what the
//! boot needs first; then every other handle. A function that appears only
//! after that, such as one behind a bridge a driver opened, is taken in a
//! later round, a bounded number of times.
use alloc::vec::Vec;

/// A connection that takes this long or longer is reported with the
/// controller it was for, so a boot log names the device that stalled.
pub const SLOW_MILLIS: u64 = 1000;

/// Rounds that look for PCI functions that appeared after the last one.
pub const ROUNDS: usize = 4;

/// What a handle is, for the choice of whether and when to connect it.
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

/// When a handle is connected, earliest first.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Rank {
    /// Root bridges, alone, so the functions under them appear.
    RootBridge,
    /// Storage, USB and other serial-bus controllers and SD hosts: the USB
    /// stick and the disks.
    BootMedia,
    /// The display, for graphics output and EDID.
    Display,
    /// Input devices, serial ports and bridges, among them the LPC bridge
    /// with PS/2 keyboards and serial ports.
    Console,
    /// Any other PCI function, or one whose class could not be read.
    OtherPci,
    /// Any other handle.
    OtherHandle,
}

impl Kind {
    /// When to connect the handle, or `None` to leave it alone.
    pub fn rank(self) -> Option<Rank> {
        match self {
            Self::RootBridge => Some(Rank::RootBridge),
            Self::Network => None,
            Self::Other => Some(Rank::OtherHandle),
            Self::Pci(None) => Some(Rank::OtherPci),
            Self::Pci(Some(class)) => {
                let base = (class >> 16) as u8;
                let sub = (class >> 8) as u8;
                match (base, sub) {
                    // Network controllers, and the wireless class's
                    // 802.11 Ethernet subclasses.
                    (0x02, _) | (0x0d, 0x20 | 0x21) => None,
                    (0x01 | 0x0c, _) | (0x08, 0x05) => Some(Rank::BootMedia),
                    (0x03, _) => Some(Rank::Display),
                    (0x06 | 0x07 | 0x09, _) => Some(Rank::Console),
                    _ => Some(Rank::OtherPci),
                }
            }
        }
    }

    /// Whether the handle's children are connected with it. A root bridge's
    /// are not: each function under it is connected on its own, or left
    /// alone.
    pub fn recursive(self) -> bool {
        !matches!(self, Self::RootBridge)
    }

    /// Whether the handle is a PCI function or root bridge, which a later
    /// round looks for.
    fn pci(self) -> bool {
        matches!(self, Self::RootBridge | Self::Pci(_))
    }
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
    /// Handles there were at the end.
    pub handles: usize,
    /// Handles connected.
    pub connected: usize,
    /// Network controllers and interfaces left alone.
    pub network: usize,
    /// Connections reported as slow.
    pub slow: usize,
}

/// Connect what the boot needs, each handle at most once, and report each
/// connection that took [`SLOW_MILLIS`] or more once.
pub fn connect<F: Firmware>(firmware: &mut F) -> Summary {
    let mut seen: Vec<F::Handle> = Vec::new();
    let mut summary = Summary::default();
    let mut handles = firmware.handles();
    for round in 0..=ROUNDS {
        let mut plan = Vec::new();
        for &handle in &handles {
            if seen.contains(&handle) {
                continue;
            }
            let kind = firmware.kind(handle);
            // The first round takes only root bridges, so the functions
            // under them appear before anything is connected; the next
            // takes every handle; later ones only PCI functions and root
            // bridges that appeared since. Children of connected
            // controllers were connected with them.
            let taken = match round {
                0 => kind == Kind::RootBridge,
                1 => true,
                _ => kind.pci(),
            };
            if !taken {
                continue;
            }
            seen.push(handle);
            match kind.rank() {
                Some(rank) => plan.push((rank, handle, kind)),
                None => summary.network += 1,
            }
        }
        if round > 1 && plan.is_empty() {
            break;
        }
        // Stable, so handles of one rank keep the firmware's order.
        plan.sort_by_key(|&(rank, ..)| rank);
        for (_, handle, kind) in plan {
            let start = firmware.millis();
            firmware.connect(handle, kind.recursive());
            let millis = firmware.millis().saturating_sub(start);
            summary.connected += 1;
            if millis >= SLOW_MILLIS {
                summary.slow += 1;
                firmware.slow(handle, kind, millis);
            }
        }
        handles = firmware.handles();
    }
    summary.handles = handles.len();
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    const USB: u32 = 0x0c0330;
    const NVME: u32 = 0x010802;
    const AHCI: u32 = 0x010601;
    const ETHERNET: u32 = 0x020000;
    const WIFI: u32 = 0x028000;
    const VGA: u32 = 0x030000;
    const AUDIO: u32 = 0x040300;
    const HOST_BRIDGE: u32 = 0x060000;
    const LPC: u32 = 0x060100;
    const PCI_BRIDGE: u32 = 0x060400;
    const SD: u32 = 0x080501;
    const RNG: u32 = 0x00ff00;

    /// One handle of the fake firmware: what it is, the handles its
    /// connection creates, and how long the connection takes.
    struct Entry {
        kind: Kind,
        hidden: bool,
        creates: Vec<usize>,
        millis: u64,
    }

    #[derive(Default)]
    struct Fake {
        entries: Vec<Entry>,
        clock: u64,
        connected: Vec<(usize, bool)>,
        slow: Vec<(usize, Kind, u64)>,
    }

    impl Fake {
        fn add(&mut self, kind: Kind, hidden: bool) -> usize {
            self.entries.push(Entry {
                kind,
                hidden,
                creates: Vec::new(),
                millis: 1,
            });
            self.entries.len() - 1
        }

        fn shown(&mut self, kind: Kind) -> usize {
            self.add(kind, false)
        }

        /// A handle that appears when `parent` is connected.
        fn child(&mut self, parent: usize, kind: Kind) -> usize {
            let child = self.add(kind, true);
            self.entries[parent].creates.push(child);
            child
        }

        fn order(&self) -> Vec<usize> {
            self.connected.iter().map(|&(handle, _)| handle).collect()
        }

        fn recursive(&self, handle: usize) -> bool {
            self.connected
                .iter()
                .find(|&&(connected, _)| connected == handle)
                .unwrap()
                .1
        }
    }

    impl Firmware for Fake {
        type Handle = usize;

        fn handles(&mut self) -> Vec<usize> {
            (0..self.entries.len())
                .filter(|&handle| !self.entries[handle].hidden)
                .collect()
        }

        fn kind(&mut self, handle: usize) -> Kind {
            self.entries[handle].kind
        }

        fn connect(&mut self, handle: usize, recursive: bool) {
            self.connected.push((handle, recursive));
            self.clock += self.entries[handle].millis;
            for child in self.entries[handle].creates.clone() {
                self.entries[child].hidden = false;
            }
        }

        fn millis(&mut self) -> u64 {
            self.clock
        }

        fn slow(&mut self, handle: usize, kind: Kind, millis: u64) {
            self.slow.push((handle, kind, millis));
        }
    }

    /// A PC: a root bridge with a host bridge, a network controller,
    /// storage, USB, a display, audio, an LPC bridge and a PCI bridge with
    /// Wi-Fi and an SD host behind it; an image handle and a service.
    struct Pc {
        fake: Fake,
        root: usize,
        host: usize,
        ethernet: usize,
        nvme: usize,
        usb: usize,
        vga: usize,
        audio: usize,
        lpc: usize,
        bridge: usize,
        wifi: usize,
        sd: usize,
        image: usize,
        service: usize,
    }

    fn pc() -> Pc {
        let mut fake = Fake::default();
        let image = fake.shown(Kind::Other);
        let root = fake.shown(Kind::RootBridge);
        let service = fake.shown(Kind::Other);
        let pci = |fake: &mut Fake, class| fake.child(root, Kind::Pci(Some(class)));
        let host = pci(&mut fake, HOST_BRIDGE);
        let ethernet = pci(&mut fake, ETHERNET);
        let nvme = pci(&mut fake, NVME);
        let usb = pci(&mut fake, USB);
        let vga = pci(&mut fake, VGA);
        let audio = pci(&mut fake, AUDIO);
        let lpc = pci(&mut fake, LPC);
        let bridge = pci(&mut fake, PCI_BRIDGE);
        let wifi = pci(&mut fake, WIFI);
        let sd = pci(&mut fake, SD);
        Pc {
            fake,
            root,
            host,
            ethernet,
            nvme,
            usb,
            vga,
            audio,
            lpc,
            bridge,
            wifi,
            sd,
            image,
            service,
        }
    }

    #[test]
    fn ranks_follow_what_the_boot_needs() {
        let rank = |class| Kind::Pci(Some(class)).rank();
        assert_eq!(rank(ETHERNET), None);
        assert_eq!(rank(WIFI), None);
        assert_eq!(rank(0x0d2000), None);
        assert_eq!(rank(0x0d1100), Some(Rank::OtherPci), "Bluetooth");
        for storage in [NVME, AHCI, USB, SD, 0x010000, 0x010400, 0x0c0a00] {
            assert_eq!(rank(storage), Some(Rank::BootMedia), "{storage:06x}");
        }
        assert_eq!(rank(VGA), Some(Rank::Display));
        assert_eq!(rank(0x038000), Some(Rank::Display));
        for console in [LPC, PCI_BRIDGE, HOST_BRIDGE, 0x070002, 0x090000] {
            assert_eq!(rank(console), Some(Rank::Console), "{console:06x}");
        }
        assert_eq!(rank(AUDIO), Some(Rank::OtherPci));
        assert_eq!(rank(RNG), Some(Rank::OtherPci));
        assert_eq!(Kind::Pci(None).rank(), Some(Rank::OtherPci));
        assert_eq!(Kind::Network.rank(), None);
        assert_eq!(Kind::Other.rank(), Some(Rank::OtherHandle));
        assert_eq!(Kind::RootBridge.rank(), Some(Rank::RootBridge));
        assert!(!Kind::RootBridge.recursive());
        assert!(Kind::Pci(Some(USB)).recursive());
        assert!(Kind::Other.recursive());
    }

    #[test]
    fn connects_root_bridges_alone_then_media_display_console_and_the_rest() {
        let mut pc = pc();
        let summary = connect(&mut pc.fake);
        assert_eq!(
            pc.fake.order(),
            vec![
                pc.root, pc.nvme, pc.usb, pc.sd, pc.vga, pc.host, pc.lpc, pc.bridge, pc.audio,
                pc.image, pc.service
            ]
        );
        assert!(!pc.fake.recursive(pc.root));
        for handle in [pc.nvme, pc.usb, pc.sd, pc.vga, pc.lpc, pc.audio, pc.image] {
            assert!(pc.fake.recursive(handle));
        }
        assert!(!pc.fake.order().contains(&pc.ethernet));
        assert!(!pc.fake.order().contains(&pc.wifi));
        assert_eq!(
            summary,
            Summary {
                handles: 13,
                connected: 11,
                network: 2,
                slow: 0
            }
        );
        assert!(pc.fake.slow.is_empty());
    }

    #[test]
    fn children_of_connected_controllers_are_not_connected_again() {
        let mut pc = pc();
        let stick = pc.fake.child(pc.usb, Kind::Other);
        let partition = pc.fake.child(stick, Kind::Other);
        let disk = pc.fake.child(pc.nvme, Kind::Other);
        let output = pc.fake.child(pc.vga, Kind::Other);
        connect(&mut pc.fake);
        for child in [stick, partition, disk, output] {
            assert!(!pc.fake.order().contains(&child), "{child}");
        }
        let order = pc.fake.order();
        let mut sorted = order.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), order.len(), "a handle connected twice");
    }

    #[test]
    fn a_network_interface_a_driver_started_is_left_alone() {
        let mut fake = Fake::default();
        let started = fake.shown(Kind::Network);
        let usb = fake.shown(Kind::Pci(Some(USB)));
        let summary = connect(&mut fake);
        assert_eq!(fake.order(), vec![usb]);
        assert!(!fake.order().contains(&started));
        assert_eq!(summary.network, 1);
    }

    #[test]
    fn a_function_that_appears_later_is_taken_in_a_later_round() {
        let mut pc = pc();
        // A function behind the bridge that only its driver lists, and one
        // behind that, which needs another round.
        let late = pc.fake.child(pc.bridge, Kind::Pci(Some(AHCI)));
        let later = pc.fake.child(late, Kind::Pci(Some(USB)));
        let late_network = pc.fake.child(pc.bridge, Kind::Pci(Some(ETHERNET)));
        let summary = connect(&mut pc.fake);
        let order = pc.fake.order();
        assert_eq!(&order[order.len() - 2..], &[late, later]);
        assert!(!order.contains(&late_network));
        assert_eq!(summary.network, 3);
    }

    #[test]
    fn rounds_are_bounded() {
        // Each function's driver lists one more function under it, without end.
        let mut fake = Fake::default();
        let mut parent = fake.shown(Kind::RootBridge);
        for _ in 0..20 {
            parent = fake.child(parent, Kind::Pci(Some(PCI_BRIDGE)));
        }
        let summary = connect(&mut fake);
        assert_eq!(summary.connected, ROUNDS + 1);
    }

    #[test]
    fn a_slow_controller_is_reported_once_with_its_time() {
        let mut pc = pc();
        pc.fake.entries[pc.usb].millis = 40_000;
        pc.fake.entries[pc.vga].millis = SLOW_MILLIS - 1;
        pc.fake.entries[pc.audio].millis = SLOW_MILLIS;
        let summary = connect(&mut pc.fake);
        assert_eq!(
            pc.fake.slow,
            vec![
                (pc.usb, Kind::Pci(Some(USB)), 40_000),
                (pc.audio, Kind::Pci(Some(AUDIO)), SLOW_MILLIS)
            ]
        );
        assert_eq!(summary.slow, 2);
    }

    #[test]
    fn a_normal_boot_reports_nothing() {
        let mut pc = pc();
        let summary = connect(&mut pc.fake);
        assert_eq!(summary.slow, 0);
        assert!(pc.fake.slow.is_empty());
    }

    #[test]
    fn a_firmware_without_root_bridges_still_connects_its_functions() {
        let mut fake = Fake::default();
        let net = fake.shown(Kind::Pci(Some(ETHERNET)));
        let other = fake.shown(Kind::Other);
        let vga = fake.shown(Kind::Pci(Some(VGA)));
        let nvme = fake.shown(Kind::Pci(Some(NVME)));
        let unknown = fake.shown(Kind::Pci(None));
        connect(&mut fake);
        assert_eq!(fake.order(), vec![nvme, vga, unknown, other]);
        assert!(!fake.order().contains(&net));
    }
}
