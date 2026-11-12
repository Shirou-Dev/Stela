//! Which PCI functions did not finish starting on an earlier boot, read from
//! the USB's boot log (`boot_log`): the system engine writes a [`START`]
//! marker line, stored on the stick before each function's driver runs,
//! and [`STARTED`] once every function's start has ended. A boot whose last
//! [`START`] has no later [`STARTED`] stopped inside that start. A boot
//! that skips such a function writes [`SKIPPED`] for it, so later boots go
//! on skipping it while the same device is at that address; `stela
//! repair` and `stela update` write [`CLEARED`].
//!
//! The markers name the function by its PCI address and vendor:device ID
//! only: no serial, MAC or other identifier.
use alloc::{format, string::String};
use stela_drivers::bus::pci::Address;

/// Before a function's driver runs.
pub const START: &str = "HOST DEVICE START";
/// Once every function's start has ended.
pub const STARTED: &str = "HOST DEVICES STARTED";
/// A function this boot skipped.
pub const SKIPPED: &str = "HOST DEVICE SKIPPED";
/// Every skip ends: `stela repair` or `stela update` wrote it.
pub const CLEARED: &str = "HOST DEVICE SKIPS CLEARED";

/// The most functions a boot skips; a stall record names at most one
/// function per boot, so this many takes several boots to reach.
pub const MOST: usize = 8;

/// One PCI function, by its address and IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Function {
    pub address: Address,
    pub vendor: u16,
    pub device: u16,
}

impl From<&stela_drivers::bus::pci::Identity> for Function {
    fn from(identity: &stela_drivers::bus::pci::Identity) -> Self {
        Self {
            address: identity.address,
            vendor: identity.vendor,
            device: identity.device,
        }
    }
}

impl Function {
    /// `marker`'s line for this function, without its newline.
    pub fn line(&self, marker: &str) -> String {
        format!(
            "{marker} pci={} id={:04x}:{:04x}",
            self.address, self.vendor, self.device
        )
    }

    /// The function a [`Self::line`] of `marker` names.
    fn parse(line: &str, marker: &str) -> Option<Self> {
        let rest = line.strip_prefix(marker)?.strip_prefix(" pci=")?;
        let (address, id) = rest.split_once(" id=")?;
        let (vendor, device) = id.trim_end().split_once(':')?;
        Some(Self {
            address: Address::parse(address)?,
            vendor: u16::from_str_radix(vendor, 16).ok()?,
            device: u16::from_str_radix(device, 16).ok()?,
        })
    }
}

/// The functions to skip: those an earlier boot did not finish starting,
/// or skipped and nothing cleared since.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Skips {
    functions: [Option<Function>; MOST],
}

impl Skips {
    pub const EMPTY: Self = Self {
        functions: [None; MOST],
    };

    pub fn iter(&self) -> impl Iterator<Item = &Function> {
        self.functions.iter().flatten()
    }

    pub fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }

    /// Whether `function` is one to skip: the same address and IDs. Another
    /// device at the address is not.
    pub fn holds(&self, function: &Function) -> bool {
        self.iter().any(|skip| skip == function)
    }

    fn add(&mut self, function: Function) {
        if self.holds(&function) {
            return;
        }
        if let Some(free) = self.functions.iter_mut().find(|slot| slot.is_none()) {
            *free = Some(function);
        }
    }
}

/// The functions a boot cannot continue without, which it never skips:
/// the controllers of the disks macOS and its state are on. The controller
/// of the USB's log, the disk Stela started from, is the first function
/// started and is needed too ([`decide`]); a display GPU is never started
/// through a driver here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Needed {
    addresses: [Option<Address>; MOST],
}

impl Needed {
    pub const EMPTY: Self = Self {
        addresses: [None; MOST],
    };

    pub fn add(&mut self, address: Address) {
        if self.holds(address) {
            return;
        }
        if let Some(free) = self.addresses.iter_mut().find(|slot| slot.is_none()) {
            *free = Some(address);
        }
    }

    pub fn holds(&self, address: Address) -> bool {
        self.addresses.contains(&Some(address))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Address> {
        self.addresses.iter().flatten()
    }
}

/// What a boot does with a function before its driver runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Start,
    /// It did not finish starting on an earlier boot, or was skipped since:
    /// left untouched.
    Skip,
    /// It did not finish starting on an earlier boot, but the boot cannot
    /// continue without it: started again.
    Retry,
}

/// What a boot does with `function`, given the earlier boots' `skips`, the
/// functions it `needs` and the `first` function it starts, the controller
/// of the disk it started from.
pub fn decide(
    skips: &Skips,
    needs: &Needed,
    first: Option<Address>,
    function: &Function,
) -> Decision {
    if !skips.holds(function) {
        Decision::Start
    } else if needs.holds(function.address) || first == Some(function.address) {
        Decision::Retry
    } else {
        Decision::Skip
    }
}

/// The screen's and the log's line for a skipped function.
pub fn skipped_line(function: &Function) -> String {
    format!(
        "PCI {} {:04x}:{:04x} skipped: it did not finish starting on an earlier boot. \
         Run stela repair to try it again.",
        function.address, function.vendor, function.device
    )
}

/// The screen's and the log's line for a function started again although
/// it did not finish starting on an earlier boot.
pub fn retried_line(function: &Function) -> String {
    format!(
        "PCI {} {:04x}:{:04x} did not finish starting on an earlier boot. The boot needs it, \
         so it is started again. If the boot stops here, `stela log --output log.txt` on \
         another computer saves the USB's log; include that file in a report.",
        function.address, function.vendor, function.device
    )
}

/// The skips the log's newest boot with a device-start marker gives. A log
/// without markers, such as one Stela 0.3.0 wrote, gives none.
pub fn read(stream: &[u8]) -> Skips {
    let text = String::from_utf8_lossy(stream);
    let mut boots: alloc::vec::Vec<&str> = text.split("=== STELA BOOT ").collect();
    while let Some(boot) = boots.pop() {
        if let Some(skips) = boot_skips(boot) {
            return skips;
        }
    }
    Skips::default()
}

/// Whether the newest bytes of a stream, `newest`, give what [`read`] gives
/// for the whole stream: they hold a whole boot with a device-start marker.
/// The bytes before their first boot line may be the end of a cut boot.
pub fn settled(newest: &[u8]) -> bool {
    String::from_utf8_lossy(newest)
        .split("=== STELA BOOT ")
        .skip(1)
        .any(|boot| boot_skips(boot).is_some())
}

/// One boot's skips, or `None` when it has no device-start marker.
fn boot_skips(boot: &str) -> Option<Skips> {
    let mut marked = false;
    let mut skips = Skips::default();
    let mut pending = None;
    for line in boot.lines() {
        if let Some(function) = Function::parse(line, START) {
            pending = Some(function);
        } else if line.starts_with(STARTED) {
            pending = None;
        } else if let Some(function) = Function::parse(line, SKIPPED) {
            skips.add(function);
        } else if line.starts_with(CLEARED) {
            skips = Skips::default();
            pending = None;
        } else {
            continue;
        }
        marked = true;
    }
    if let Some(function) = pending {
        skips.add(function);
    }
    marked.then_some(skips)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn function(bus: u8, vendor: u16, device: u16) -> Function {
        Function {
            address: Address {
                segment: 0,
                bus,
                device: 0,
                function: 0,
            },
            vendor,
            device,
        }
    }

    fn boot(lines: &[String]) -> String {
        let mut text = String::from("=== STELA BOOT 7 ===\n");
        for line in lines {
            text.push_str(line);
            text.push('\n');
        }
        text
    }

    #[test]
    fn a_start_without_its_end_is_a_stall_and_one_with_it_is_not() {
        let nvme = function(5, 0x144d, 0xa808);
        let lan = function(7, 0x10ec, 0x8125);
        // The log ends inside the second start, as a stalled boot leaves it.
        let truncated = boot(&[
            nvme.line(START),
            String::from("HOST DEVICE PCI 0000:05:00.0 start"),
            lan.line(START),
        ]);
        let skips = read(truncated.as_bytes());
        assert!(skips.holds(&lan));
        assert!(!skips.holds(&nvme));
        assert_eq!(skips.iter().count(), 1);
        let finished = boot(&[nvme.line(START), lan.line(START), String::from(STARTED)]);
        assert!(read(finished.as_bytes()).is_empty());
    }

    #[test]
    fn a_skip_is_carried_until_cleared_and_only_for_the_same_device() {
        let lan = function(7, 0x10ec, 0x8125);
        let mut text = boot(&[lan.line(START)]);
        // The next boot skips it and finishes.
        text.push_str(&boot(&[lan.line(SKIPPED), String::from(STARTED)]));
        let skips = read(text.as_bytes());
        assert!(skips.holds(&lan));
        // Another card at the address is started.
        assert!(!skips.holds(&function(7, 0x8086, 0x15f3)));
        // A boot that never reached the device start keeps the record.
        text.push_str("=== STELA BOOT 9 ===\nSTEP Reading Stela's settings\n");
        assert!(read(text.as_bytes()).holds(&lan));
        // `stela repair` writes the clearing line into the newest boot.
        text.push_str(CLEARED);
        text.push_str(" by stela repair\n");
        assert!(read(text.as_bytes()).is_empty());
        // A boot without a skip line, once the ID changed, ends it too.
        let mut changed = boot(&[lan.line(START)]);
        changed.push_str(&boot(&[
            function(7, 0x8086, 0x15f3).line(START),
            String::from(STARTED),
        ]));
        assert!(read(changed.as_bytes()).is_empty());
    }

    #[test]
    fn a_function_the_boot_needs_is_started_again_and_never_skipped() {
        let nvme = function(5, 0x144d, 0xa808);
        let stick = function(0x0b, 0x1022, 0x15b6);
        let lan = function(7, 0x10ec, 0x8125);
        let mut skips = Skips::default();
        for stalled in [nvme, stick, lan] {
            skips.add(stalled);
        }
        let mut needs = Needed::default();
        needs.add(nvme.address);
        let first = Some(stick.address);
        // The controller of macOS's disk and that of the USB are retried.
        assert_eq!(decide(&skips, &needs, first, &nvme), Decision::Retry);
        assert_eq!(decide(&skips, &needs, first, &stick), Decision::Retry);
        // Any other is skipped.
        assert_eq!(decide(&skips, &needs, first, &lan), Decision::Skip);
        // Another device at the address, and a function with no record,
        // start as usual.
        let other = function(7, 0x8086, 0x15f3);
        assert_eq!(decide(&skips, &needs, first, &other), Decision::Start);
        assert_eq!(
            decide(&Skips::EMPTY, &Needed::EMPTY, None, &lan),
            Decision::Start
        );
        // The lines name only the address and IDs.
        assert_eq!(
            skipped_line(&lan),
            "PCI 0000:07:00.0 10ec:8125 skipped: it did not finish starting on an earlier \
             boot. Run stela repair to try it again."
        );
        assert!(retried_line(&nvme).contains("log.txt"));
    }

    #[test]
    fn the_newest_bytes_settle_once_they_hold_a_whole_marked_boot() {
        let lan = function(7, 0x10ec, 0x8125);
        let mut text = boot(&[lan.line(START)]);
        text.push_str("=== STELA BOOT 8 ===\nSTEP Reading Stela's settings\n");
        // Only the unmarked newest boot, or a cut marked one: read further.
        let unmarked = text.find("=== STELA BOOT 8").unwrap();
        assert!(!settled(&text.as_bytes()[unmarked..]));
        assert!(!settled(&text.as_bytes()[5..]));
        assert!(settled(text.as_bytes()));
        // An older boot before it changes nothing.
        let mut older = boot(&[function(5, 0x144d, 0xa808).line(SKIPPED)]);
        older.push_str(&text);
        assert_eq!(read(older.as_bytes()), read(text.as_bytes()));
        assert!(read(text.as_bytes()).holds(&lan));
    }

    #[test]
    fn a_log_without_markers_reads_as_no_stall() {
        // As Stela 0.3.0 wrote it: start lines, no markers.
        let text = "=== STELA BOOT 3 ===\nHOST DEVICE PCI 0000:07:00.0 start\n\
                    STEP Starting the PC's disks and USB devices\n";
        assert!(read(text.as_bytes()).is_empty());
        assert!(read(b"").is_empty());
    }

    #[test]
    fn a_marker_names_the_function_by_address_and_ids_only() {
        let lan = function(0x85, 0x10ec, 0x8125);
        assert_eq!(
            lan.line(START),
            "HOST DEVICE START pci=0000:85:00.0 id=10ec:8125"
        );
        assert_eq!(Function::parse(&lan.line(SKIPPED), SKIPPED), Some(lan));
        assert_eq!(
            Function::parse("HOST DEVICE START pci=junk id=1:2", START),
            None
        );
    }
}
