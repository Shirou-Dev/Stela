//! Classify the configuration words the census reads, as Linux's scan does:
//! what counts as no function, which header layouts the fabric can drive,
//! and which bridge bus fields it can trust.
use core::ops::RangeInclusive;

/// What the vendor ID of a function says.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Presence {
    /// Nothing answers (0xffff).
    Absent,
    /// The function asks for the request to be retried (0x0001, CRS): it
    /// is not ready. Linux waits for it, then gives up and treats it as absent.
    NotReady,
    /// A vendor ID of 0x0000, which no vendor has. Linux treats an all-zero
    /// identity as absent.
    NoVendor,
    Present,
}

pub fn presence(identity: u32) -> Presence {
    match identity as u16 {
        u16::MAX => Presence::Absent,
        1 => Presence::NotReady,
        0 => Presence::NoVendor,
        _ => Presence::Present,
    }
}

/// The header layout of the dword at offset 0x0c.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Layout {
    Endpoint,
    Bridge,
    CardBus,
    Unknown(u8),
}

pub fn layout(word: u32) -> Layout {
    match ((word >> 16) & 0x7f) as u8 {
        0 => Layout::Endpoint,
        1 => Layout::Bridge,
        2 => Layout::CardBus,
        kind => Layout::Unknown(kind),
    }
}

/// Function 0's multifunction bit, in the dword at offset 0x0c.
pub fn multifunction(word: u32) -> bool {
    word & 0x0080_0000 != 0
}

/// The PCI-to-PCI bridge class code, from the dword at offset 8.
pub fn bridge_class(class_revision: u32) -> bool {
    class_revision >> 16 == 0x0604
}

/// A function the fabric does not drive may be left alone only while it
/// cannot reach memory or raise INTx: Bus Master is clear, and INTx is
/// disabled or not asserted. `command_status` is the dword at offset 4,
/// which every header layout shares. A bridge with Bus Master clear also
/// forwards no memory request, MSI included, from the buses behind it.
pub fn quiet(command_status: u32) -> bool {
    const MASTER: u32 = 1 << 2;
    const INTX_DISABLE: u32 = 1 << 10;
    const INTX_STATUS: u32 = 1 << 19;
    command_status & MASTER == 0
        && (command_status & INTX_DISABLE != 0 || command_status & INTX_STATUS == 0)
}

/// What the primary, secondary and subordinate bus fields at offset 0x18
/// of a bridge on `bus` say. Type 1 and CardBus headers share them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Route {
    /// Secondary and subordinate are zero: the bridge forwards nothing.
    Unconfigured,
    /// The bridge forwards these buses. `primary` is false when the primary
    /// field does not name `bus`; no routing uses it, so it is tolerated.
    Forwards {
        buses: RangeInclusive<u8>,
        primary: bool,
    },
    /// Secondary is not below `bus` or subordinate is below secondary.
    Invalid,
}

pub fn route(bus: u8, buses: u32) -> Route {
    let [primary, secondary, subordinate, _] = buses.to_le_bytes();
    if secondary == 0 && subordinate == 0 {
        Route::Unconfigured
    } else if secondary <= bus || subordinate < secondary {
        Route::Invalid
    } else {
        Route::Forwards {
            buses: secondary..=subordinate,
            primary: primary == bus,
        }
    }
}

/// Header dwords a function that decodes every function number repeats on
/// each of them: identity, class, layout and the six dwords after them
/// (BARs, or a bridge's BARs, buses and windows).
pub const ALIAS_OFFSETS: [u16; 9] = [0, 8, 0x0c, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24];

/// A function other than 0 of a device whose function 0 has no
/// multifunction bit, and which repeats function 0's `ALIAS_OFFSETS` words,
/// is function 0 again. Linux never reads it. A function that differs, such
/// as an ARI function, is a function of its own and stays in the census.
pub fn alias(first: &[u32; 9], candidate: &[u32; 9]) -> bool {
    !multifunction(first[2]) && first == candidate
}

/// Census oddities that leave the segment usable. Each is logged once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Oddity {
    NoVendor,
    NotReady,
    Alias,
    UnsupportedHeader,
    BridgeClass,
    PrimaryBus,
}

impl Oddity {
    pub fn bit(self) -> u8 {
        1 << self as u8
    }

    /// A plain sentence for the boot log, after the function's address.
    pub fn message(self) -> &'static str {
        match self {
            Self::NoVendor => "reads vendor ID 0000; treated as absent",
            Self::NotReady => "is not ready (retry status); treated as absent",
            Self::Alias => "repeats function 0, which has no multifunction bit; treated as absent",
            Self::UnsupportedHeader => {
                "has a CardBus or unknown header with Bus Master clear; it and the \
                 buses behind it stay idle and undriven"
            }
            Self::BridgeClass => "has a header type that does not match its class code",
            Self::PrimaryBus => {
                "is a bridge whose primary bus field is not its own bus; its secondary \
                 and subordinate buses are used"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_ids_ffff_0001_and_0000_are_no_function() {
        assert_eq!(presence(0xffff_ffff), Presence::Absent);
        assert_eq!(presence(0x1234_0001), Presence::NotReady);
        assert_eq!(presence(0x0000_0000), Presence::NoVendor);
        assert_eq!(presence(0x2204_10de), Presence::Present);
    }

    #[test]
    fn header_layouts_and_multifunction_bit() {
        assert_eq!(layout(0x0080_0000), Layout::Endpoint);
        assert_eq!(layout(0x0081_0010), Layout::Bridge);
        assert_eq!(layout(0x0002_0000), Layout::CardBus);
        assert_eq!(layout(0x007f_0000), Layout::Unknown(0x7f));
        assert!(multifunction(0x0080_0000));
        assert!(!multifunction(0x0001_0000));
        assert!(bridge_class(0x0604_0001));
        assert!(!bridge_class(0x0607_0000));
    }

    #[test]
    fn only_a_function_without_bus_master_and_asserted_intx_is_quiet() {
        assert!(quiet(0x0000_0003));
        assert!(!quiet(0x0000_0007));
        // INTx asserted, not disabled.
        assert!(!quiet(0x0008_0003));
        // INTx asserted but disabled.
        assert!(quiet(0x0008_0403));
    }

    #[test]
    fn a_wrong_primary_bus_is_tolerated_but_secondary_and_subordinate_are_not() {
        let buses = |primary: u8, secondary: u8, subordinate: u8| {
            u32::from_le_bytes([primary, secondary, subordinate, 0])
        };
        assert_eq!(route(3, buses(3, 0, 0)), Route::Unconfigured);
        assert_eq!(
            route(3, buses(3, 4, 6)),
            Route::Forwards {
                buses: 4..=6,
                primary: true
            }
        );
        assert_eq!(
            route(3, buses(0, 4, 4)),
            Route::Forwards {
                buses: 4..=4,
                primary: false
            }
        );
        assert_eq!(route(3, buses(3, 3, 6)), Route::Invalid);
        assert_eq!(route(3, buses(3, 2, 6)), Route::Invalid);
        assert_eq!(route(3, buses(3, 6, 5)), Route::Invalid);
    }

    #[test]
    fn a_repeat_of_single_function_zero_is_an_alias_and_a_distinct_function_is_not() {
        let first = [
            0x1234_8086,
            0x0200_0001,
            0x0000_0010,
            0xfe00_0000,
            0,
            0,
            0,
            0,
            0,
        ];
        assert!(alias(&first, &first));
        let mut other = first;
        other[3] = 0xfe10_0000;
        assert!(!alias(&first, &other));
        let mut multi = first;
        multi[2] |= 0x0080_0000;
        assert!(!alias(&multi, &multi));
    }

    #[test]
    fn oddities_have_distinct_bits() {
        let all = [
            Oddity::NoVendor,
            Oddity::NotReady,
            Oddity::Alias,
            Oddity::UnsupportedHeader,
            Oddity::BridgeClass,
            Oddity::PrimaryBus,
        ];
        let bits = all.iter().fold(0u8, |bits, oddity| {
            assert_eq!(bits & oddity.bit(), 0);
            bits | oddity.bit()
        });
        assert_eq!(bits.count_ones(), 6);
    }
}
