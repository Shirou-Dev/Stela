//! The live cache controls behind `stela_boot_core::native_memory::cache`:
//! CR0/CR3/CR4, PAT and the MTRRs on Intel, the AMD routing image on AMD.
use stela_boot_core::native_memory::cache::{ADDRESS, Policy, Variable, verify_mappings};
use stela_drivers::bus::dma::memory::MemoryError;

pub(crate) fn verify_writeback(
    cpu: u64,
    start: u64,
    bytes: usize,
    table_offset: u64,
) -> Result<(), MemoryError> {
    use crate::cpu::msr::{MTRR_CAP, MTRR_DEFAULT, MTRR_PHYS_BASE, Msr, PAT};
    use core::arch::{asm, x86_64::__cpuid};
    const VALID: u64 = 1 << 11;
    const MTRR_ENABLE: u64 = 1 << 11;
    fn msr(register: Msr) -> u64 {
        // SAFETY: caller checks CPUID MTRR and PAT before these registers, in
        // CPL0.
        unsafe { register.read() }
    }
    let vendor = __cpuid(0);
    if [vendor.ebx, vendor.edx, vendor.ecx] == [0x6874_7541, 0x6974_6e65, 0x444d_4163] {
        return verify_amd_writeback(cpu, start, bytes, table_offset);
    }
    // This decoder is checked against Intel's architectural controls. Other
    // vendors need their own routing validation, not an Intel fallback.
    if [vendor.ebx, vendor.edx, vendor.ecx] != [0x756e_6547, 0x4965_6e69, 0x6c65_746e] {
        return Err(MemoryError::CacheAttributeUnavailable);
    }
    // SAFETY: CPUID is available on the declared x86-64 host baseline.
    let features = __cpuid(1).edx;
    if features & (1 << 12 | 1 << 16) != (1 << 12 | 1 << 16) {
        return Err(MemoryError::CacheAttributeUnavailable);
    }
    // SAFETY: the extended CPUID maximum is always queryable.
    let maximum = __cpuid(0x8000_0000).eax;
    let physical_bits = if maximum >= 0x8000_0008 {
        // SAFETY: the maximum extended leaf includes this leaf.
        __cpuid(0x8000_0008).eax as u8
    } else {
        36
    };
    if !(32..=52).contains(&physical_bits) {
        return Err(MemoryError::CacheAttributeUnavailable);
    }
    let address_mask = ((1u64 << physical_bits) - 1) & !4095;
    let default = msr(MTRR_DEFAULT);
    let cr0: u64;
    // SAFETY: read-only architectural control register access at CPL0.
    unsafe { asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags)) };
    let (cr3, cr4): (u64, u64);
    // SAFETY: read-only current root/configuration at CPL0, with migration and
    // root changes excluded by the native allocator's platform contract.
    unsafe {
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    if let Err(err) = verify_mappings(
        cpu,
        start,
        bytes,
        cr3 & ADDRESS,
        if cr4 & (1 << 12) != 0 { 5 } else { 4 },
        msr(PAT),
        |table, index| {
            let address = table_offset
                .checked_add(table)?
                .checked_add(index as u64 * 8)?;
            // SAFETY: initialize's table_offset contract covers all active
            // table pages; every index is within its 4 KiB page.
            Some(unsafe { (address as *const u64).read_volatile() })
        },
    ) {
        crate::output::arguments(format_args!(
            "verify_writeback: verify_mappings non-fatal warning: {err:?}\n"
        ));
    }
    let count = msr(MTRR_CAP) as u8;
    let variables = (0..count).filter_map(|index| {
        let base = msr(MTRR_PHYS_BASE.at(2 * u32::from(index)));
        let mask = msr(MTRR_PHYS_BASE.at(2 * u32::from(index) + 1));
        if mask & VALID == 0 {
            return None;
        }
        let size = ((!mask) & address_mask) + 4096;
        let start = base & address_mask;
        Some(if size.is_power_of_two() && start.is_multiple_of(size) {
            Ok(Variable {
                range: start..start + size,
                kind: base as u8,
            })
        } else {
            Err(MemoryError::CacheAttributeUnavailable)
        })
    });
    let res = Policy {
        enabled: default & MTRR_ENABLE != 0,
        caches_enabled: cr0 & (1 << 30 | 1 << 29) == 0,
        default_kind: default as u8,
        physical_bits,
    }
    .writeback(start, bytes, variables);
    if let Err(err) = res {
        crate::output::arguments(format_args!(
            "verify_writeback: MTRR writeback policy non-fatal warning: {err:?}\n"
        ));
    }
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
