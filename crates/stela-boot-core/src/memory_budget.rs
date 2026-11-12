//! Memory budgets for allocations made while UEFI still owns boot services.
use core::fmt;
use stela_contracts::bytes::HOST_PAGE_BYTES as PAGE;
const MIB: u64 = 1024 * 1024;
const MINIMUM: u64 = 16 * MIB;
const MAXIMUM: u64 = 384 * MIB;

/// The persistent translation pack file `stela` allocates by default:
/// the store's room on the USB. The boot reads and writes at most what the
/// PC's RAM leaves it (`host_memory::pack_budget`), which may be less.
pub const DEFAULT_TRANSLATION_PACK_BYTES: u64 = 1024 * MIB;

/// The least free firmware RAM the boot heap's budget needs.
pub const MINIMUM_FREE: u64 = MINIMUM * 16;

/// Too little free firmware RAM: `free` bytes, of [`MINIMUM_FREE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InsufficientMemory {
    pub free: u64,
}
impl fmt::Display for InsufficientMemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "this PC has {} MB of RAM free in firmware; Stela needs at least {} MB to start",
            self.free / 1_000_000,
            MINIMUM_FREE.div_ceil(1_000_000)
        )
    }
}
impl core::error::Error for InsufficientMemory {}

/// At most one sixteenth of the currently free conventional RAM, up to the
/// loader's 384 MiB working-set ceiling. Firmware boot-service allocations
/// remain live and are excluded from the supplied free-byte count.
pub fn bootstrap_heap(free: u64) -> Result<u64, InsufficientMemory> {
    let budget = (free / 16).min(MAXIMUM) / PAGE * PAGE;
    if budget < MINIMUM {
        return Err(InsufficientMemory { free });
    }
    Ok(budget)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pressure_reduces_the_heap_without_consuming_firmware_reserves() {
        assert_eq!(
            bootstrap_heap(256 * MIB - 1),
            Err(InsufficientMemory {
                free: 256 * MIB - 1
            })
        );
        assert_eq!(
            InsufficientMemory { free: 200 * MIB }.to_string(),
            "this PC has 209 MB of RAM free in firmware; Stela needs at least 269 MB to start"
        );
        assert_eq!(bootstrap_heap(256 * MIB), Ok(16 * MIB));
        assert_eq!(bootstrap_heap(1024 * MIB), Ok(64 * MIB));
        assert_eq!(bootstrap_heap(8 * 1024 * MIB), Ok(384 * MIB));
        assert_eq!(bootstrap_heap(u64::MAX), Ok(384 * MIB));
        for free in (256 * MIB..1024 * MIB).step_by(9973) {
            let heap = bootstrap_heap(free).unwrap();
            assert!(heap.is_multiple_of(PAGE));
            assert!(heap <= free / 16);
        }
    }
}
