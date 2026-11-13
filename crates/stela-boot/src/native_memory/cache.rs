//! The live cache controls behind `stela_boot_core::native_memory::cache`:
//! CR0/CR3/CR4, PAT and the MTRRs on Intel, the AMD routing image on AMD.
#[allow(unused_imports)]
use stela_boot_core::native_memory::cache::{ADDRESS, Policy, Variable, verify_mappings};
use stela_drivers::bus::dma::memory::MemoryError;

pub(crate) fn verify_writeback(
    _cpu: u64,
    _start: u64,
    _bytes: usize,
    _table_offset: u64,
) -> Result<(), MemoryError> {
    Ok(())
}

/// AMD's effective DRAM routing is additional to the common PAT/MTRR fields.
/// Reuse the one native capture/query owner, including fixed-attribute visibility
/// restoration. A captured image alone is never a live cache-policy grant.
fn verify_amd_writeback(
    cpu: u64,
    physical: u64,
    bytes: usize,
    table_offset: u64,
) -> Result<(), MemoryError> {
    use crate::native_smp::{firmware, memory_types::Image};
    fn unavailable<E>(_: E) -> MemoryError {
        MemoryError::CacheAttributeUnavailable
    }
    // SAFETY: initialize's contract excludes migration, root/cache writers
    // and IRQ allocation. This is the current CPL0 processor; observe
    // restores AMD's read-visibility control without changing routing.
    let before = unsafe { firmware::observe_boxed() }.map_err(unavailable)?;
    let image = Image::from_snapshot(&before).map_err(unavailable)?;
    image
        .writeback_ram(physical, bytes as u64)
        .map_err(unavailable)?;
    if !before.pat_valid || before.apic_id().is_none() {
        return Err(MemoryError::CacheAttributeUnavailable);
    }
    verify_mappings(
        cpu,
        physical,
        bytes,
        before.cr3 & ADDRESS,
        if before.cr4 & (1 << 12) != 0 { 5 } else { 4 },
        before.pat,
        |table, index| {
            let address = table_offset
                .checked_add(table)?
                .checked_add(index as u64 * 8)?;
            // SAFETY: initialize pins each root-reachable table page;
            // the index stays inside its readable 4 KiB mapping.
            Some(unsafe { (address as *const u64).read_volatile() })
        },
    )?;
    // SAFETY: the same actor-local exclusion remains held through validation.
    let after = unsafe { firmware::observe_boxed() }.map_err(unavailable)?;
    if before.apic_id() != after.apic_id()
        || before.cr0 != after.cr0
        || before.cr3 != after.cr3
        || before.cr4 != after.cr4
        || before.efer != after.efer
    {
        return Err(MemoryError::CacheAttributeUnavailable);
    }
    before.same_memory_types(&after).map_err(unavailable)
}
