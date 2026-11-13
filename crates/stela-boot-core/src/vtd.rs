// SPDX-License-Identifier: GPL-2.0-only
// Copyright © 2006-2015 Intel Corporation.
// Register definitions and legacy invalidation/context sequencing adapted from
// Linux drivers/iommu/intel/{iommu.h,iommu.c,dmar.c}, commit
// a804c5742bff224d4cb4d25dd383554d598be32b. Source hashes and license terms:
// NOTICE and LICENSES/GPL-2.0-only.txt.
//! Exclusive legacy VT-d unit with distinct owned requester contexts/domains.
//! Requesters start blocked or in the explicitly supplied initial window
//! domain (DID 1). Attaching a requester moves it to its own domain.
//! Noncoherent table walks use CPUID-checked CLFLUSH plus MFENCE.
//! This never attaches by guessing a DMAR scope or changes active firmware
//! domains. ATS, scalable mode, RMRR preservation, peer groups and AMD-Vi need
//! their platform owners and are not supplied by this backend.
use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::{
    cell::UnsafeCell,
    mem::ManuallyDrop,
    ops::Range,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
};
use stela_drivers::bus::dma::{
    mapping::{Direction, DmaDomain, DmaError, DomainMapping},
    memory::{CacheAttribute, CpuMapping, PageSource, PinnedPages},
    pages::DmaPages,
};
use stela_drivers::bus::mmio::owned::{Mapping, Protection, ResourceKind};

use crate::requester::RequesterClaim;

pub mod interrupt;
mod requester;
pub use requester::BoundRequester;
use requester::{RequesterActor, RequesterLifetime, RequesterUnwind};

const PAGE: usize = 4096;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const READ: u64 = 1;
const WRITE: u64 = 2;
const CAP: usize = 0x08;
const ECAP: usize = 0x10;
const GCMD: usize = 0x18;
const GSTS: usize = 0x1c;
const RTADDR: usize = 0x20;
const CCMD: usize = 0x28;
const FSTS: usize = 0x34;
const FECTL: usize = 0x38;
const PMEN: usize = 0x64;
const TRANSLATION: u32 = 1 << 31;
const ROOT_POINTER: u32 = 1 << 30;
const WRITE_BUFFER: u32 = 1 << 27;
const QUEUED_INVALIDATION: u32 = 1 << 26;
const INTERRUPT_REMAP: u32 = 1 << 25;
const CONTEXT_INVALIDATE: u64 = 1 << 63;
const CONTEXT_GLOBAL: u64 = 1 << 61;
const IOTLB_INVALIDATE: u64 = 1 << 63;
const IOTLB_GLOBAL: u64 = 1 << 60;
const IOTLB_DOMAIN: u64 = 2 << 60;
const IOTLB_PAGE: u64 = 3 << 60;
const IOTLB_DOMAIN_SHIFT: u32 = 32;
/// Page-selective invalidation (PSI), and the largest address mask it
/// takes (MAMV).
const CAP_PAGE_SELECTIVE: u64 = 1 << 39;
const CAP_MAX_ADDRESS_MASK_SHIFT: u32 = 48;
const IOTLB_WRITE_DRAIN: u64 = 1 << 48;
const IOTLB_READ_DRAIN: u64 = 1 << 49;
const CAP_WRITE_DRAIN: u64 = 1 << 54;
const CAP_READ_DRAIN: u64 = 1 << 55;
/// The unit needs its write buffer flushed after table updates (RWBF).
const CAP_WRITE_BUFFER: u64 = 1 << 4;
/// The unit may cache not-present entries (CM), so a new entry needs an
/// IOTLB invalidation too.
const CAP_CACHING_MODE: u64 = 1 << 7;
const MSI_START: u64 = 0xfee0_0000;
const MSI_END: u64 = 0xfef0_0000;

static QUARANTINED_DOMAINS: AtomicU64 = AtomicU64::new(0);

pub fn quarantined_domains() -> u64 {
    QUARANTINED_DOMAINS.load(Ordering::Relaxed)
}

static QUARANTINED_UNITS: AtomicU64 = AtomicU64::new(0);

pub fn quarantined_units() -> u64 {
    QUARANTINED_UNITS.load(Ordering::Relaxed)
}

/// Why [`Unit::take_over`] refused a unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TakeOverError {
    pub error: VtdError,
    /// Whether it had written the unit's registers. False: the unit is as
    /// it was found, and no table of this takeover was published to it.
    pub started: bool,
}

impl TakeOverError {
    /// Whether a unit proven off before the takeover still is: nothing was
    /// written, and the unit read neither on ([`VtdError::Busy`]) nor
    /// unreadable ([`VtdError::RegisterRead`]).
    pub fn leaves_unit_off(self) -> bool {
        !self.started && !matches!(self.error, VtdError::Busy | VtdError::RegisterRead)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VtdError {
    Config(stela_drivers::bus::pci::ConfigError),
    PciCapability(stela_drivers::bus::pci::CapabilityError),
    Busy,
    Unsupported,
    RegisterRange,
    RegisterRead,
    Memory,
    Timeout,
    Invalidation,
    Exhausted,
    FaultOverflow,
}
impl From<stela_drivers::bus::pci::ConfigError> for VtdError {
    fn from(error: stela_drivers::bus::pci::ConfigError) -> Self {
        Self::Config(error)
    }
}
impl From<stela_drivers::bus::pci::CapabilityError> for VtdError {
    fn from(error: stela_drivers::bus::pci::CapabilityError) -> Self {
        Self::PciCapability(error)
    }
}
/// Exact original requester/unit custody survives failed or unwinding attach.
pub struct AttachRequesterFailure<R: Registers> {
    pub error: VtdError,
    _retained: ManuallyDrop<Box<RequesterActor<R>>>,
}
impl<R: Registers> core::fmt::Debug for AttachRequesterFailure<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AttachRequesterFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultRecord {
    pub index: usize,
    pub address: u64,
    pub requester: u16,
    pub reason: u8,
    pub read: bool,
}

/// An exclusive, mapped VT-d register window and monotonic deadline.
///
/// # Safety
/// All register accesses have their real effects, obey width/order and stay
/// within an exclusively owned UC mapping. Its lifetime includes uncertain
/// hardware teardown. The clock must advance while polling on this CPU.
pub unsafe trait Registers: Send + Sync {
    fn bytes(&self) -> usize;
    fn read32(&self, offset: usize) -> u32;
    fn read64(&self, offset: usize) -> u64;
    fn write32(&self, offset: usize, value: u32);
    fn write64(&self, offset: usize, value: u64);
    fn ticks(&self) -> u64;
    fn timeout_ticks(&self) -> u64;
    /// Evict dirty WB table lines for a noncoherent walker.
    ///
    /// # Safety
    /// The whole CPU span is held mapped WB RAM, line-aligned, and
    /// CLFLUSH/`line` have been checked by CPUID on this CPU.
    unsafe fn flush_table(&self, cpu: NonNull<u8>, bytes: usize, line: usize) {
        // SAFETY: caller supplied the checked, kept CPU span.
        unsafe { flush_table(cpu, bytes, line) };
    }
}

unsafe fn flush_table(cpu: NonNull<u8>, bytes: usize, line: usize) {
    for offset in (0..bytes).step_by(line) {
        // SAFETY: caller keeps the complete checked WB CPU span.
        unsafe {
            core::arch::asm!("clflush [{}]", in(reg) cpu.as_ptr().add(offset), options(nostack, preserves_flags));
        }
    }
}

fn qualified_flush_line(edx: u32, ebx: u32) -> Result<usize, VtdError> {
    let line = ((ebx >> 8) & 255) as usize * 8;
    if edx & (1 << 19) == 0 || !line.is_power_of_two() || !(8..=PAGE).contains(&line) {
        Err(VtdError::Unsupported)
    } else {
        Ok(line)
    }
}

/// Physical MMIO, kept valid by its owned mapping or exclusive fixture owner.
pub struct MmioRegisters {
    base: UcAddress,
    bytes: usize,
    clock: fn() -> u64,
    timeout: u64,
    mapping: Option<Mapping>,
}

struct UcAddress(NonNull<u8>);
// SAFETY: this is an exclusive root-stable UC register address with no CPU
// memory references. Its original mapping is kept by the register owner.
unsafe impl Send for UcAddress {}
// SAFETY: Unit serializes writes. Its direct-delivery pin allows only
// concurrent lock-free hardware reads of the frozen mode and root.
unsafe impl Sync for UcAddress {}

impl MmioRegisters {
    /// # Safety
    /// `base..base+bytes` is the real exclusively owned UC register window,
    /// stable across roots and kept until successful shutdown or quarantine.
    /// `clock` is monotonic and `timeout` is nonzero and less than half its wrap.
    pub unsafe fn new(
        base: NonNull<u8>,
        bytes: usize,
        clock: fn() -> u64,
        timeout: u64,
    ) -> Result<Self, VtdError> {
        if bytes < 4096
            || (base.as_ptr() as usize).checked_add(bytes).is_none()
            || !(base.as_ptr() as usize).is_multiple_of(8)
            || timeout == 0
            || timeout > u64::MAX / 2
        {
            return Err(VtdError::RegisterRange);
        }
        Ok(Self {
            base: UcAddress(base),
            bytes,
            clock,
            timeout,
            mapping: None,
        })
    }

    /// Keep the actual original UC register mapping in the remapping unit.
    ///
    /// # Safety
    /// The mapping is the unit's exclusive register window and stays reachable
    /// in every admitted CPU root. No separate alias issues register accesses.
    pub unsafe fn from_mapping(
        mapping: Mapping,
        clock: fn() -> u64,
        timeout: u64,
    ) -> Result<Self, VtdError> {
        if mapping.kind() != Ok(ResourceKind::Registers)
            || mapping.attribute() != Ok(CacheAttribute::Uncached)
            || mapping.protection() != Ok(Protection::ReadWrite)
        {
            return Err(VtdError::RegisterRange);
        }
        let bytes = mapping.bytes().map_err(|_| VtdError::RegisterRange)?;
        let base = mapping
            .address(0, bytes)
            .map_err(|_| VtdError::RegisterRange)?;
        // SAFETY: actual UC register owner and all-root context checked above
        // and by the caller. Keep that same mapping before returning.
        let mut registers = unsafe { Self::new(base, bytes, clock, timeout) }?;
        registers.mapping = Some(mapping);
        Ok(registers)
    }

    fn address<T>(&self, offset: usize) -> *mut T {
        assert!(offset.is_multiple_of(core::mem::align_of::<T>()));
        assert!(
            offset
                .checked_add(size_of::<T>())
                .is_some_and(|end| end <= self.bytes)
        );
        // SAFETY: the full checked register access is in the mapping.
        unsafe { self.base.0.as_ptr().add(offset).cast() }
    }
}

impl Drop for MmioRegisters {
    fn drop(&mut self) {
        if let Some(mapping) = &mut self.mapping {
            // SAFETY: the original register owner has no raw callers left.
            // Unit keeps the registers if shutdown is uncertain. Retirement
            // itself checks the actual mapping context and quarantines failure.
            let _ = unsafe { mapping.retire() };
        }
    }
}
// SAFETY: construction requires the UC mapping and monotonic clock.
unsafe impl Registers for MmioRegisters {
    fn bytes(&self) -> usize {
        self.bytes
    }
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: `address` checks the access lies inside the uncached register mapping.
        unsafe { self.address::<u32>(offset).read_volatile() }
    }
    fn read64(&self, offset: usize) -> u64 {
        // SAFETY: `address` checks the access lies inside the uncached register mapping.
        unsafe { self.address::<u64>(offset).read_volatile() }
    }
    fn write32(&self, offset: usize, value: u32) {
        // SAFETY: `address` checks the access lies inside the uncached register mapping.
        unsafe { self.address::<u32>(offset).write_volatile(value) }
    }
    fn write64(&self, offset: usize, value: u64) {
        // SAFETY: `address` checks the access lies inside the uncached register mapping.
        unsafe { self.address::<u64>(offset).write_volatile(value) }
    }
    fn ticks(&self) -> u64 {
        (self.clock)()
    }
    fn timeout_ticks(&self) -> u64 {
        self.timeout
    }
}

struct Table {
    pages: PinnedPages,
    cpu: CpuMapping,
}

impl Table {
    fn new(source: &dyn PageSource, physical_bits: u8) -> Result<Self, VtdError> {
        let pages = source
            .allocate(PAGE, PAGE, CacheAttribute::WriteBack)
            .map_err(|_| VtdError::Memory)?;
        if pages.bytes() != PAGE
            || pages.page_shift() != 12
            || pages.physical_pages().len() != 1
            || pages.physical_pages()[0] >= (1u64 << physical_bits)
        {
            return Err(VtdError::Memory);
        }
        let cpu = pages
            .cpu_mapping(CacheAttribute::WriteBack)
            .map_err(|_| VtdError::Memory)?;
        Ok(Self { pages, cpu })
    }
    fn physical(&self) -> u64 {
        self.pages.physical_pages()[0]
    }
    fn pointer(&self, index: usize) -> *mut u64 {
        self.cpu
            .address(index * 8, 8)
            .expect("bounded page-table entry")
            .as_ptr()
            .cast()
    }
    fn read(&self, index: usize) -> u64 {
        // SAFETY: live coherent table page, accessed with the unit lock held.
        unsafe { self.pointer(index).read_volatile() }
    }
    fn write(&self, index: usize, value: u64) {
        // SAFETY: unique software table owner under the unit lock; publication
        // and acknowledged invalidations precede device use/page release.
        unsafe { self.pointer(index).write_volatile(value) };
    }

    fn flush<R: Registers>(&self, registers: &R, line: usize) {
        let pointer = self.cpu.address(0, PAGE).expect("retained table page");
        // SAFETY: checked CLFLUSH/line; page-aligned WB RAM.
        unsafe { registers.flush_table(pointer, PAGE, line) };
    }
}

struct LiveMapping {
    info: DomainMapping,
    direction: Direction,
    _pages: DmaPages,
    leaves: Vec<(usize, usize)>,
}

struct DomainState {
    did: u16,
    /// The other requester IDs a bridge forwards this requester's DMA
    /// under, whose context entries lead to the same tables.
    aliases: Vec<u16>,
    generation: u64,
    lifetime: Arc<RequesterLifetime>,
    tables: Vec<Table>,
    table_index: BTreeMap<u64, usize>,
    mappings: BTreeMap<u64, LiveMapping>,
    quarantined: bool,
}
/// The window domain: one to one second-level tables over the drivers'
/// shared DMA region, shared by every covered requester without a domain of
/// its own.
struct Window {
    tables: Vec<Table>,
}
const WINDOW_DID: u16 = 1;

struct State {
    root: Table,
    window: Option<Window>,
    /// Each allowed requester bus's context table, under its root entry.
    contexts: BTreeMap<u8, Table>,
    allowed: Vec<u16>,
    domains: BTreeMap<u16, DomainState>,
    next_id: u64,
    next_generation: u64,
    initial_block: InitialState,
    poisoned: bool,
    shutdown: bool,
}

/// A single exclusive hardware remapping owner. All operations and final Drop
/// require process/deferred context; the lock is not a hard-IRQ service.
pub struct Unit<R: Registers> {
    registers: ManuallyDrop<R>,
    // Persistent GCMD controls only; one-shot SRTP/SIRTP/WBF are never saved.
    command: AtomicU32,
    /// Acquired under the Unit lock. Released without I/O by the exact pin.
    direct_delivery: AtomicBool,
    interrupts: ManuallyDrop<UnsafeCell<Option<interrupt::State>>>,
    ecap: u64,
    source: &'static (dyn PageSource + Sync),
    held: AtomicBool,
    state: ManuallyDrop<UnsafeCell<State>>,
    levels: u8,
    physical_bits: u8,
    iotlb: usize,
    cap: u64,
    max_domains: u32,
    table_cacheline: Option<usize>,
}

// SAFETY: mutable state and register writes use the acquire/release lock.
// The direct-delivery pin permits only IRQ-safe register observation with
// the original root and mode frozen; platform ownership changes are excluded.
unsafe impl<R: Registers> Sync for Unit<R> {}

enum InitialState {
    Open,
    Closed,
    Issued(Vec<(u16, bool)>),
}

/// The original blocked root and its exact, drained initial requester cohort.
pub struct InitialBlock<R: Registers> {
    unit: Arc<Unit<R>>,
}

/// One original requester in the blocked cohort, with the IDs a bridge
/// forwards its DMA under. It retains the same unit and supplies no
/// configuration, IRQ, or engine-stop authority.
pub struct BlockedRequester<R: Registers> {
    unit: Arc<Unit<R>>,
    rid: u16,
    aliases: Vec<u16>,
}

impl<R: Registers> InitialBlock<R> {
    /// Claim requester `rid` of the cohort and each of its `aliases`, the
    /// other IDs its DMA may arrive under. An alias is either a requester
    /// of the cohort no one claimed, whose function then stays parked with
    /// its Bus Master clear since it can never claim it, or an ID this unit
    /// allows that no function of the cohort has. Each stays blocked until
    /// the requester attaches, and nothing else can claim or attach it.
    pub fn claim(&self, rid: u16, aliases: &[u16]) -> Result<BlockedRequester<R>, DmaError> {
        let aliases = distinct_aliases(rid, aliases).map_err(|_| DmaError::IommuUnavailable)?;
        let mut guard = self.unit.lock();
        let state = guard.state();
        for &id in core::iter::once(&rid).chain(&aliases) {
            self.unit.check_blocked_requester(state, id)?;
        }
        if *state.initial_claim(rid)? {
            return Err(DmaError::IommuUnavailable);
        }
        let InitialState::Issued(claims) = &mut state.initial_block else {
            return Err(DmaError::IommuUnavailable);
        };
        claims
            .try_reserve(aliases.len())
            .map_err(|_| DmaError::MappingFailed)?;
        for &alias in &aliases {
            if let Ok(index) = claims.binary_search_by_key(&alias, |&(id, _)| id)
                && claims[index].1
            {
                return Err(DmaError::IommuUnavailable);
            }
        }
        for &id in core::iter::once(&rid).chain(&aliases) {
            match claims.binary_search_by_key(&id, |&(id, _)| id) {
                Ok(index) => claims[index].1 = true,
                Err(index) => claims.insert(index, (id, true)),
            }
        }
        Ok(BlockedRequester {
            unit: self.unit.clone(),
            rid,
            aliases,
        })
    }
}

/// `aliases` without `rid`, refused when one repeats.
fn distinct_aliases(rid: u16, aliases: &[u16]) -> Result<Vec<u16>, VtdError> {
    let mut distinct = Vec::new();
    distinct
        .try_reserve_exact(aliases.len())
        .map_err(|_| VtdError::Exhausted)?;
    for &alias in aliases {
        if distinct.contains(&alias) {
            return Err(VtdError::Unsupported);
        }
        if alias != rid {
            distinct.push(alias);
        }
    }
    Ok(distinct)
}

impl<R: Registers> BlockedRequester<R> {
    pub fn requester(&self) -> u16 {
        self.rid
    }

    /// The other IDs claimed with the requester.
    pub fn aliases(&self) -> &[u16] {
        &self.aliases
    }

    /// Check this kept, one-shot owner's original blocked context without
    /// draining it or authorizing a new domain or configuration operation.
    pub fn check(&self) -> Result<(), DmaError> {
        self.with_blocked(|_, _| Ok(()))
    }

    pub fn drain(&self) -> Result<(), DmaError> {
        self.with_blocked(Unit::drain_initial)
    }

    fn with_blocked(
        &self,
        action: impl FnOnce(&Unit<R>, &mut State) -> Result<(), DmaError>,
    ) -> Result<(), DmaError> {
        let mut guard = self.unit.lock();
        let state = guard.state();
        for &id in core::iter::once(&self.rid).chain(&self.aliases) {
            self.unit.check_blocked_requester(state, id)?;
            if !*state.initial_claim(id)? {
                return Err(DmaError::IommuUnavailable);
            }
        }
        action(&self.unit, state)
    }
}

struct Guard<'a, R: Registers>(&'a Unit<R>);
impl<R: Registers> Guard<'_, R> {
    fn state(&mut self) -> &mut State {
        // SAFETY: only one guard owns the unit's acquire/release lock; the
        // mutable borrow cannot escape the guard or overlap another borrow.
        unsafe { &mut *self.0.state.get() }
    }
}
impl<R: Registers> Drop for Guard<'_, R> {
    fn drop(&mut self) {
        self.0.held.store(false, Ordering::Release);
    }
}

pub fn publish() {
    // SAFETY: MFENCE is in the x86-64 baseline. The default memory clobber
    // prevents compiler motion; the coherent platform makes WB stores
    // visible before subsequent UC register/descriptor publication.
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
}

impl<R: Registers> Unit<R> {
    /// Snapshot real primary fault records while fault interrupts are masked.
    /// This polled path does not supply a native interrupt handler.
    pub fn pending_faults(&self) -> Result<Vec<FaultRecord>, VtdError> {
        let _guard = self.lock();
        let status = self.registers.read32(FSTS);
        if status & 1 != 0 {
            return Err(VtdError::FaultOverflow);
        }
        let mut faults = Vec::new();
        if status & 2 == 0 {
            return Ok(faults);
        }
        let base = ((self.cap >> 24) & 0x3ff) as usize * 16;
        let count = ((self.cap >> 40) & 255) as usize + 1;
        if base < 0x80
            || base
                .checked_add(count * 16)
                .is_none_or(|end| end > self.registers.bytes())
        {
            return Err(VtdError::RegisterRange);
        }
        for index in 0..count {
            let register = base + index * 16;
            let high = self.registers.read32(register + 12);
            if high & (1 << 31) == 0 {
                continue;
            }
            let requester = self.registers.read32(register + 8) as u16;
            let address = self.registers.read64(register) & !4095;
            faults.push(FaultRecord {
                index,
                address,
                requester,
                reason: high as u8,
                read: high & (1 << 30) != 0,
            });
        }
        Ok(faults)
    }

    /// Acknowledge an observed record only after its owner recorded/handled it.
    pub fn acknowledge_fault(&self, index: usize) -> Result<(), VtdError> {
        let _guard = self.lock();
        let base = ((self.cap >> 24) & 0x3ff) as usize * 16;
        let count = ((self.cap >> 40) & 255) as usize + 1;
        if index >= count
            || base < 0x80
            || base
                .checked_add(count * 16)
                .is_none_or(|end| end > self.registers.bytes())
        {
            return Err(VtdError::RegisterRange);
        }
        self.registers.write32(base + index * 16 + 12, 1 << 31);
        self.registers.write32(FSTS, 1 | 2 | 1 << 7);
        Ok(())
    }
    /// Take ownership of an inactive unit, not an active firmware domain.
    /// With `window` ranges, every requester starts in the window domain,
    /// which maps them one to one; without, every context is absent.
    ///
    /// # Safety
    /// Platform discovery has resolved the unit's scope to `requesters`
    /// ([`crate::remapping::plan`]), and every reserved region a requester
    /// still uses lies in `window`. Requesters behind the unit DMA only to
    /// the window until attached, with ATS/PRI/PASID and device NoSnoop
    /// disabled. No other CPU/firmware/SMM owner can change it. Native
    /// WB RAM DMA is coherent independently of the ECAP table-walk coherency
    /// bit. Bus mastering remains stopped until real mapping publication.
    /// The register mapping and source's backing mappings stay valid across
    /// roots and uncertain failures. No operation/final release runs in an IRQ.
    pub unsafe fn take_over(
        registers: R,
        source: &'static (dyn PageSource + Sync),
        requesters: &[u16],
        physical_bits: u8,
        window: &[Range<u64>],
    ) -> Result<Arc<Self>, TakeOverError> {
        let unit = Self::prepare(registers, source, requesters, physical_bits, window).map_err(
            |error| TakeOverError {
                error,
                started: false,
            },
        )?;
        let started = |error| TakeOverError {
            error,
            started: true,
        };
        let mut guard = unit.lock();
        let state = guard.state();
        unit.publish_tables(state);
        // Mask fault interrupts; fault delivery needs its own registered IRQ
        // owner, never a firmware handler kept across ownership transfer.
        unit.registers.write32(FECTL, 1 << 31);
        unit.registers.write64(RTADDR, state.root.physical());
        unit.write_command(ROOT_POINTER).map_err(started)?;
        unit.wait32(GSTS, ROOT_POINTER, true).map_err(started)?;
        unit.invalidate(true).map_err(started)?;
        unit.command.store(TRANSLATION, Ordering::Relaxed);
        unit.write_command(0).map_err(started)?;
        unit.wait32(GSTS, TRANSLATION, true).map_err(started)?;
        drop(guard);
        Ok(unit)
    }

    /// Check the unit and build its tables, writing no register.
    fn prepare(
        registers: R,
        source: &'static (dyn PageSource + Sync),
        requesters: &[u16],
        physical_bits: u8,
        window: &[Range<u64>],
    ) -> Result<Arc<Self>, VtdError> {
        let mut allowed = requesters.to_vec();
        allowed.sort_unstable();
        if allowed.is_empty() || allowed.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(VtdError::Unsupported);
        }
        if !(32..=52).contains(&physical_bits) || registers.bytes() < 4096 {
            return Err(VtdError::Unsupported);
        }
        let cap = registers.read64(CAP);
        let ecap = registers.read64(ECAP);
        let status = registers.read32(GSTS);
        let protected = registers.read32(PMEN);
        if cap == u64::MAX || ecap == u64::MAX || status == u32::MAX || protected == u32::MAX {
            return Err(VtdError::RegisterRead);
        }
        if status & (TRANSLATION | QUEUED_INVALIDATION | INTERRUPT_REMAP) != 0
            || protected & (1 << 31 | 1) != 0
        {
            return Err(VtdError::Busy);
        }
        let table_cacheline = if ecap & 1 == 0 {
            let cpu = core::arch::x86_64::__cpuid(1);
            Some(qualified_flush_line(cpu.edx, cpu.ebx)?)
        } else {
            None
        };
        let nd = (cap & 7) as u32;
        if nd > 6 {
            return Err(VtdError::Unsupported);
        }
        let max_domains = 1u32.checked_shl(4 + 2 * nd).ok_or(VtdError::Unsupported)?;
        let widths = (cap >> 8) & 31;
        let maximum = ((cap >> 16) & 63) + 1;
        let levels = if widths & 4 != 0 && maximum >= 48 {
            4
        } else if widths & 2 != 0 && maximum >= 39 {
            3
        } else {
            return Err(VtdError::Unsupported);
        };
        let iotlb = ((ecap >> 8) & 0x3ff) as usize * 16 + 8;
        if iotlb < 0x80
            || iotlb
                .checked_add(8)
                .is_none_or(|end| end > registers.bytes())
        {
            return Err(VtdError::RegisterRange);
        }
        let root = Table::new(source, physical_bits)?;
        let window = (!window.is_empty())
            .then(|| Window::new(source, physical_bits, levels, window))
            .transpose()?;
        // Initial takeover is TE-off; each context is absent or the window's.
        // Dynamic context publication separately flushes the child before
        // Present.
        let mut contexts = BTreeMap::new();
        for bus in allowed.iter().map(|rid| (rid >> 8) as u8) {
            if let alloc::collections::btree_map::Entry::Vacant(entry) = contexts.entry(bus) {
                let context = Table::new(source, physical_bits)?;
                // Legacy root entries are 128 bits; Table indexes u64 words.
                root.write(usize::from(bus) * 2, context.physical() | 1);
                entry.insert(context);
            }
        }
        if let Some(window) = &window {
            for &rid in &allowed {
                let index = usize::from(rid & 0xff) * 2;
                let context = &contexts[&((rid >> 8) as u8)];
                context.write(
                    index + 1,
                    u64::from(WINDOW_DID) << 8 | u64::from(levels - 2),
                );
                context.write(index, window.tables[0].physical() | 1);
            }
        }
        Ok(Arc::new(Self {
            registers: ManuallyDrop::new(registers),
            command: AtomicU32::new(0),
            direct_delivery: AtomicBool::new(false),
            interrupts: ManuallyDrop::new(UnsafeCell::new(None)),
            ecap,
            source,
            held: AtomicBool::new(false),
            state: ManuallyDrop::new(UnsafeCell::new(State {
                root,
                window,
                contexts,
                allowed,
                domains: BTreeMap::new(),
                next_id: 1,
                next_generation: 1,
                initial_block: InitialState::Open,
                poisoned: false,
                shutdown: false,
            })),
            levels,
            physical_bits,
            iotlb,
            cap,
            max_domains,
            table_cacheline,
        }))
    }

    /// Whether requester `rid` may attach to this unit.
    pub fn allows(&self, rid: u16) -> bool {
        self.lock().state().allowed.binary_search(&rid).is_ok()
    }

    /// Confirm the installed legacy root is still blocking the exact original
    /// cohort and obtain checked global context and read/write drain completion.
    /// Only the first successful acknowledgment issues a cohort. The caller
    /// retains its independent PCI, engine, IRQ and bypass exclusions.
    pub fn acknowledge_initial_block(
        self: &Arc<Self>,
        requesters: &[u16],
    ) -> Result<InitialBlock<R>, DmaError> {
        let mut guard = self.lock();
        let state = guard.state();
        if !matches!(state.initial_block, InitialState::Open)
            || state.next_generation != 1
            || !state.domains.is_empty()
            || state.window.is_some()
            || state.allowed != requesters
        {
            return Err(DmaError::IommuUnavailable);
        }
        self.check_installed_root(state)?;
        if self.registers.read32(GSTS) & (QUEUED_INVALIDATION | INTERRUPT_REMAP) != 0 {
            return Err(DmaError::IommuUnavailable);
        }
        if self.cap & (CAP_READ_DRAIN | CAP_WRITE_DRAIN) != CAP_READ_DRAIN | CAP_WRITE_DRAIN {
            return Err(DmaError::DrainUnavailable);
        }
        for bus in 0..=u8::MAX {
            let index = usize::from(bus) * 2;
            let context = state.contexts.get(&bus);
            let expected = context.map_or(0, |table| table.physical() | 1);
            if state.root.read(index) != expected
                || state.root.read(index + 1) != 0
                || context.is_some_and(|table| (0..PAGE / 8).any(|at| table.read(at) != 0))
            {
                return Err(DmaError::IommuUnavailable);
            }
        }
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(requesters.len())
            .map_err(|_| DmaError::MappingFailed)?;
        pending.extend(requesters.iter().map(|&rid| (rid, false)));
        // Keep the unit closed through every hardware callback, including an
        // unwind before the acknowledgment can be issued.
        state.poisoned = true;
        self.invalidate(true)
            .map_err(|_| DmaError::InvalidationFailed)?;
        self.check_root_registers(state)?;
        state.initial_block = InitialState::Issued(pending);
        state.poisoned = false;
        Ok(InitialBlock { unit: self.clone() })
    }

    fn check_installed_root(&self, state: &State) -> Result<(), DmaError> {
        if state.shutdown || state.poisoned {
            return Err(DmaError::IommuUnavailable);
        }
        self.check_root_registers(state)
    }

    fn check_root_registers(&self, state: &State) -> Result<(), DmaError> {
        let status = self.registers.read32(GSTS);
        if status == u32::MAX
            || status & (ROOT_POINTER | TRANSLATION) != ROOT_POINTER | TRANSLATION
            || self.registers.read64(RTADDR) != state.root.physical()
        {
            return Err(DmaError::IommuUnavailable);
        }
        Ok(())
    }

    fn check_blocked_requester(&self, state: &State, rid: u16) -> Result<(), DmaError> {
        self.check_installed_root(state)?;
        if state.window.is_some() || state.held(rid) || !state.allowed.contains(&rid) {
            return Err(DmaError::IommuUnavailable);
        }
        let (table, index) = state.context(rid);
        let root_index = usize::from(rid >> 8) * 2;
        if state.root.read(root_index) != table.physical() | 1
            || state.root.read(root_index + 1) != 0
            || table.read(index) != 0
            || table.read(index + 1) != 0
        {
            return Err(DmaError::IommuUnavailable);
        }
        Ok(())
    }

    /// Complete earlier translated payload writes before a covered requester
    /// leaves its initial window/blocked context. This grants no engine,
    /// IRQ/work or bypass quiescence, and refuses an already attached domain.
    pub fn drain_initial_requester(&self, rid: u16) -> Result<(), DmaError> {
        let mut guard = self.lock();
        let state = guard.state();
        if state.shutdown || state.poisoned || !state.allowed.contains(&rid) || state.held(rid) {
            return Err(DmaError::IommuUnavailable);
        }
        self.drain_initial(state)
    }

    fn drain_initial(&self, state: &mut State) -> Result<(), DmaError> {
        if self.cap & CAP_WRITE_DRAIN == 0 {
            return Err(DmaError::DrainUnavailable);
        }
        // VT-d 6.5.4's DW acknowledgement covers this original root's
        // translated writes; use the same checked completion as live domains.
        state.poisoned = true;
        self.invalidate(false)
            .map_err(|_| DmaError::InvalidationFailed)?;
        state.poisoned = false;
        Ok(())
    }

    /// Allow requester `rid`, which arrived below a covered bridge after this
    /// unit was taken. It has no context entry until it attaches, so its
    /// requests fault until then.
    pub fn admit_requester(&self, rid: u16) -> Result<(), VtdError> {
        let mut guard = self.lock();
        let state = guard.state();
        if state.shutdown || state.poisoned {
            return Err(VtdError::Busy);
        }
        let Err(at) = state.allowed.binary_search(&rid) else {
            return Ok(());
        };
        let bus = (rid >> 8) as u8;
        if matches!(state.initial_block, InitialState::Open) {
            state.initial_block = InitialState::Closed;
        }
        if !state.contexts.contains_key(&bus) {
            let context = Table::new(self.source, self.physical_bits)?;
            // Complete and visible before the root entry that leads to it.
            if let Some(line) = self.table_cacheline {
                context.flush(&*self.registers, line);
            }
            publish();
            state
                .root
                .write(usize::from(bus) * 2, context.physical() | 1);
            state.contexts.insert(bus, context);
            if let Some(line) = self.table_cacheline {
                state.root.flush(&*self.registers, line);
            }
            publish();
            if let Err(error) = self.invalidate(true) {
                state.poisoned = true;
                return Err(error);
            }
        }
        state.allowed.insert(at, rid);
        Ok(())
    }

    /// Publish one owned stopped requester into this already owned unit,
    /// with a context entry for its own ID and one for each of `aliases`,
    /// the other IDs a bridge forwards its DMA under, all leading to the
    /// same domain. Aliases need a blocked root ([`InitialBlock::claim`]
    /// claimed each of them with the requester); detach clears them all.
    ///
    /// # Safety
    /// The claim's engine/reset/IRQ/work epoch is stopped and drained,
    /// its coherent-DMA/config/root ownership grant remains valid, and no other
    /// owner can resume it before this returned domain's mapping publication.
    pub unsafe fn attach_requester(
        self: &Arc<Self>,
        claim: RequesterClaim,
        aliases: &[u16],
    ) -> Result<BoundRequester<R>, AttachRequesterFailure<R>> {
        let mut original = RequesterActor::prepare(self.clone(), claim);
        let mut unwind = RequesterUnwind::new(original.lifetime.clone());
        let result = (|| -> Result<(), VtdError> {
            let rid = {
                let mut slot = original
                    .claim
                    .try_borrow_mut()
                    .map_err(|_| VtdError::Busy)?;
                let claim = slot.as_mut().expect("original requester claim");
                claim.check_stopped()?;
                claim.requester()
            };
            let aliases = distinct_aliases(rid, aliases)?;
            let (did, generation) = {
                let mut guard = self.lock();
                self.requester_slot(guard.state(), rid, &aliases)?
            };
            // Page providers can reenter the unit. Keep the claim and root in
            // the parked actor while preparing outside its hardware lock.
            original.staged = ManuallyDrop::new(Some(Table::new(self.source, self.physical_bits)?));
            let physical = original
                .staged
                .as_ref()
                .expect("prepared requester root")
                .physical();
            original.domain = Some(Arc::new(RequesterDomain {
                unit: ManuallyDrop::new(original.unit.take().expect("original unit")),
                rid,
                did,
                generation,
                lifetime: original.lifetime.clone(),
            }));
            let mut table_index = BTreeMap::new();
            table_index.insert(physical, 0);
            let mut tables = Vec::with_capacity(1);
            let mut guard = self.lock();
            let state = guard.state();
            // A concurrent attachment or provider callback can consume a DID
            // or change admission while the root is being prepared.
            if self.requester_slot(state, rid, &aliases)? != (did, generation) {
                return Err(VtdError::Busy);
            }
            if let InitialState::Issued(claims) = &mut state.initial_block {
                claims.retain(|(id, _)| *id != rid && !aliases.contains(id));
            }
            let ids: Vec<u16> = core::iter::once(rid)
                .chain(aliases.iter().copied())
                .collect();
            state.next_generation = generation + 1;
            tables.push(original.staged.take().expect("prepared requester root"));
            state.domains.insert(
                rid,
                DomainState {
                    did,
                    aliases,
                    generation,
                    lifetime: original.lifetime.clone(),
                    tables,
                    table_index,
                    mappings: BTreeMap::new(),
                    quarantined: false,
                },
            );
            // Close the whole unit before the first publication callback. A
            // caught unwind cannot resume sibling contexts after an uncertain
            // table flush, context store, or invalidation. Only full success
            // reopens admission under this same held unit lock.
            state.poisoned = true;
            // Even an unsolicited access while TE is active must never walk stale
            // child contents. Publish this complete zero root before its context.
            if let Some(line) = self.table_cacheline {
                state.domains[&rid].tables[0].flush(&*self.registers, line);
            }
            publish();
            let (context, index) = state.context(rid);
            if context.read(index) & 1 != 0 {
                // VT-d 6.5.3.3: a present context entry is cleared and its cached
                // copies and the window's translations invalidated before it is
                // rewritten.
                context.write(index, 0);
                if let Some(line) = self.table_cacheline {
                    context.flush(&*self.registers, line);
                }
                publish();
                if let Err(error) = self.invalidate(true) {
                    state.poisoned = true;
                    return Err(error);
                }
            }
            // Each alias's entry was checked blocked under its claim.
            for &id in &ids {
                let (context, index) = state.context(id);
                context.write(index + 1, u64::from(did) << 8 | u64::from(self.levels - 2));
                if let Some(line) = self.table_cacheline {
                    context.flush(&*self.registers, line);
                }
                publish();
                context.write(index, physical | 1);
                if let Some(line) = self.table_cacheline {
                    context.flush(&*self.registers, line);
                }
                publish();
            }
            if let Err(error) = self.invalidate(true) {
                state.poisoned = true;
                return Err(error);
            }
            state.poisoned = false;
            Ok(())
        })();
        match result {
            Ok(()) => {
                unwind.dismiss();
                Ok(BoundRequester::new(original))
            }
            Err(error) => Err(AttachRequesterFailure {
                error,
                _retained: original,
            }),
        }
    }

    /// Read-only admission preflight; no provider, allocation or register IO.
    /// Each of `aliases` must be claimed with the requester under a
    /// blocked root, allowed here and held by no domain.
    fn requester_slot(
        &self,
        state: &State,
        rid: u16,
        aliases: &[u16],
    ) -> Result<(u16, u64), VtdError> {
        if state.shutdown || state.poisoned || !state.allowed.contains(&rid) || state.held(rid) {
            return Err(VtdError::Busy);
        }
        if !aliases.is_empty() {
            let InitialState::Issued(claims) = &state.initial_block else {
                return Err(VtdError::Unsupported);
            };
            let claimed = |id: u16| {
                claims
                    .binary_search_by_key(&id, |&(id, _)| id)
                    .is_ok_and(|index| claims[index].1)
            };
            if state.window.is_some()
                || aliases
                    .iter()
                    .any(|&id| !state.allowed.contains(&id) || state.held(id) || !claimed(id))
            {
                return Err(VtdError::Unsupported);
            }
        }
        let first = if state.window.is_some() {
            u32::from(WINDOW_DID) + 1
        } else {
            1
        };
        let did = (first..self.max_domains)
            .find(|did| {
                !state
                    .domains
                    .values()
                    .any(|domain| u32::from(domain.did) == *did)
            })
            .ok_or(VtdError::Busy)? as u16;
        state
            .next_generation
            .checked_add(1)
            .ok_or(VtdError::Unsupported)?;
        Ok((did, state.next_generation))
    }

    fn lock(&self) -> Guard<'_, R> {
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Guard(self)
    }
    /// Evict the tables holding `leaves`, the entries one mapping changed;
    /// every new intermediate table was evicted as it was linked ([`leaf`]).
    ///
    /// [`leaf`]: DomainState::leaf
    fn publish_leaves(&self, domain: &DomainState, leaves: &[(usize, usize)]) {
        if let Some(line) = self.table_cacheline {
            let mut tables: Vec<usize> = leaves.iter().map(|&(table, _)| table).collect();
            tables.sort_unstable();
            tables.dedup();
            for table in tables {
                domain.tables[table].flush(&*self.registers, line);
            }
        }
        // Orders dirty-line eviction before UC command submission.
        publish();
    }
    /// Make entries that were not present visible to the walker. Without
    /// Caching Mode the unit caches no not-present entry, so VT-d 6.1 needs
    /// only the write-buffer flush, as Linux's `__mapping_notify_one` does.
    fn publish_new_entries(&self, did: u16, address: u64, bytes: usize) -> Result<(), VtdError> {
        if self.cap & CAP_CACHING_MODE != 0 {
            return self.invalidate_pages(did, address, bytes);
        }
        self.flush_write_buffer()
    }
    /// Invalidate the IOTLB entries for `bytes` from `address` in one
    /// domain, as Linux `iommu_flush_iotlb_psi` does: the naturally aligned
    /// power-of-two block of pages covering them, or the whole domain when
    /// the unit has no page-selective invalidation or that block exceeds its
    /// largest address mask.
    fn invalidate_pages(&self, did: u16, address: u64, bytes: usize) -> Result<(), VtdError> {
        let first = address >> 12;
        let last = (address + bytes.max(1) as u64 - 1) >> 12;
        // The smallest mask whose aligned block holds both ends.
        let mask = u64::BITS - (first ^ last).leading_zeros();
        let largest = (self.cap >> CAP_MAX_ADDRESS_MASK_SHIFT) & 0x3f;
        if self.cap & CAP_PAGE_SELECTIVE == 0 || u64::from(mask) > largest {
            return self.invalidate_domain(did);
        }
        if self.queued_iotlb(3, did, first >> mask << mask << 12, mask as u8)? {
            return Ok(());
        }
        publish();
        self.flush_write_buffer()?;
        let mut request = IOTLB_INVALIDATE | IOTLB_PAGE | u64::from(did) << IOTLB_DOMAIN_SHIFT;
        if self.cap & CAP_WRITE_DRAIN != 0 {
            request |= IOTLB_WRITE_DRAIN;
        }
        if self.cap & CAP_READ_DRAIN != 0 {
            request |= IOTLB_READ_DRAIN;
        }
        self.wait64(self.iotlb, IOTLB_INVALIDATE)?;
        // IVA, just below the IOTLB register: the block's address and mask.
        self.registers.write64(
            self.iotlb - 8,
            (first >> mask << mask << 12) | u64::from(mask),
        );
        self.registers.write64(self.iotlb, request);
        let value = self.wait64(self.iotlb, IOTLB_INVALIDATE)?;
        // The unit may grant a page, domain or global invalidation.
        if (value >> 57) & 3 == 0 {
            return Err(VtdError::Invalidation);
        }
        Ok(())
    }
    fn flush_write_buffer(&self) -> Result<(), VtdError> {
        self.check_interrupt_state()?;
        if self.cap & CAP_WRITE_BUFFER != 0 {
            self.write_command(WRITE_BUFFER)?;
            self.wait32(GSTS, WRITE_BUFFER, false)?;
        }
        Ok(())
    }
    /// Invalidate one domain's IOTLB entries, draining its queued DMA: the
    /// unit may grant the global invalidation instead.
    fn invalidate_domain(&self, did: u16) -> Result<(), VtdError> {
        if self.queued_iotlb(2, did, 0, 0)? {
            return Ok(());
        }
        publish();
        self.flush_write_buffer()?;
        let mut request = IOTLB_INVALIDATE | IOTLB_DOMAIN | u64::from(did) << IOTLB_DOMAIN_SHIFT;
        if self.cap & CAP_WRITE_DRAIN != 0 {
            request |= IOTLB_WRITE_DRAIN;
        }
        if self.cap & CAP_READ_DRAIN != 0 {
            request |= IOTLB_READ_DRAIN;
        }
        self.wait64(self.iotlb, IOTLB_INVALIDATE)?;
        self.registers.write64(self.iotlb, request);
        let value = self.wait64(self.iotlb, IOTLB_INVALIDATE)?;
        if !matches!((value >> 57) & 3, 1 | 2) {
            return Err(VtdError::Invalidation);
        }
        Ok(())
    }
    fn publish_tables(&self, state: &State) {
        if let Some(line) = self.table_cacheline {
            state.root.flush(&*self.registers, line);
            for context in state.contexts.values() {
                context.flush(&*self.registers, line);
            }
            for table in state.window.iter().flat_map(|window| &window.tables) {
                table.flush(&*self.registers, line);
            }
            for domain in state.domains.values() {
                for table in &domain.tables {
                    table.flush(&*self.registers, line);
                }
            }
        }
        // Orders dirty-line eviction before UC command submission.
        publish();
    }
    fn wait32(&self, register: usize, mask: u32, set: bool) -> Result<(), VtdError> {
        let start = self.registers.ticks();
        loop {
            let value = self.registers.read32(register);
            if value == u32::MAX {
                return Err(VtdError::RegisterRead);
            }
            if (value & mask != 0) == set {
                return Ok(());
            }
            if self.registers.ticks().wrapping_sub(start) >= self.registers.timeout_ticks() {
                return Err(VtdError::Timeout);
            }
            core::hint::spin_loop();
        }
    }
    fn wait64(&self, register: usize, mask: u64) -> Result<u64, VtdError> {
        let start = self.registers.ticks();
        loop {
            let value = self.registers.read64(register);
            if value & mask == 0 {
                return Ok(value);
            }
            if self.registers.ticks().wrapping_sub(start) >= self.registers.timeout_ticks() {
                return Err(VtdError::Timeout);
            }
            core::hint::spin_loop();
        }
    }
    fn invalidate(&self, context: bool) -> Result<(), VtdError> {
        if self.queued_global(context)? {
            return Ok(());
        }
        publish();
        if context {
            self.wait64(CCMD, CONTEXT_INVALIDATE)?;
            self.registers
                .write64(CCMD, CONTEXT_INVALIDATE | CONTEXT_GLOBAL);
            let value = self.wait64(CCMD, CONTEXT_INVALIDATE)?;
            if (value >> 59) & 3 != 1 {
                return Err(VtdError::Invalidation);
            }
        }
        let mut request = IOTLB_INVALIDATE | IOTLB_GLOBAL;
        if self.cap & CAP_WRITE_DRAIN != 0 {
            request |= IOTLB_WRITE_DRAIN;
        }
        if self.cap & CAP_READ_DRAIN != 0 {
            request |= IOTLB_READ_DRAIN;
        }
        self.wait64(self.iotlb, IOTLB_INVALIDATE)?;
        self.registers.write64(self.iotlb, request);
        let value = self.wait64(self.iotlb, IOTLB_INVALIDATE)?;
        if (value >> 57) & 3 != 1 {
            return Err(VtdError::Invalidation);
        }
        if self.cap & CAP_WRITE_BUFFER != 0 {
            self.write_command(WRITE_BUFFER)?;
            self.wait32(GSTS, WRITE_BUFFER, false)?;
        }
        Ok(())
    }

    /// Disable after device-specific stop, completion and worker/IRQ drain.
    /// The unit remains held on any failed hardware acknowledgement.
    ///
    /// # Safety
    /// Every requester is stopped/drained and cannot issue further DMA. The
    /// caller owns the platform exclusion against submissions and IRQ workers.
    pub unsafe fn shut_down(&self) -> Result<(), VtdError> {
        let mut guard = self.lock();
        let state = guard.state();
        if state.shutdown {
            return Ok(());
        }
        if self.direct_delivery.load(Ordering::Acquire) || !state.domains.is_empty() {
            return Err(VtdError::Busy);
        }
        self.interrupt_shutdown_ready()?;
        // Latch before any disable/invalidation effect, including unwind. A
        // failed shutdown must not permit a new requester/map on that root.
        state.poisoned = true;
        self.stop_interrupt_remapping()?;
        self.invalidate(true)?;
        self.command.store(0, Ordering::Relaxed);
        self.write_command(0)?;
        self.wait32(GSTS, TRANSLATION, false)?;
        state.shutdown = true;
        Ok(())
    }
}

impl<R: Registers> Drop for Unit<R> {
    fn drop(&mut self) {
        // SAFETY: final owner, so no lock/operation can still borrow state.
        let shutdown = unsafe { &*self.state.get() }.shutdown;
        if shutdown {
            // SAFETY: device quiescence, all mappings retired, IOTLB
            // acknowledgement and TE-off acknowledgement preceded shutdown.
            unsafe {
                ManuallyDrop::drop(&mut self.state);
                ManuallyDrop::drop(&mut self.interrupts);
                ManuallyDrop::drop(&mut self.registers);
            }
        } else {
            // Hardware may still hold any of these PA references. Deliberately
            // keep the register owner, tables and pins, including map errors.
            let _ = QUARANTINED_UNITS.try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_add(1))
            });
        }
    }
}

impl State {
    /// Whether a domain holds `rid`'s context entry, as its own or an alias.
    fn held(&self, rid: u16) -> bool {
        self.domains.contains_key(&rid)
            || self
                .domains
                .values()
                .any(|domain| domain.aliases.contains(&rid))
    }

    fn initial_claim(&mut self, rid: u16) -> Result<&mut bool, DmaError> {
        let InitialState::Issued(claims) = &mut self.initial_block else {
            return Err(DmaError::IommuUnavailable);
        };
        let index = claims
            .binary_search_by_key(&rid, |&(rid, _)| rid)
            .map_err(|_| DmaError::IommuUnavailable)?;
        Ok(&mut claims[index].1)
    }

    /// The context table and entry index of requester `rid`, whose bus
    /// every allowed requester's has.
    fn context(&self, rid: u16) -> (&Table, usize) {
        (
            &self.contexts[&((rid >> 8) as u8)],
            usize::from(rid & 0xff) * 2,
        )
    }
}

impl Window {
    /// Tables mapping every page of `ranges` to itself, read and write.
    fn new(
        source: &dyn PageSource,
        physical_bits: u8,
        levels: u8,
        ranges: &[Range<u64>],
    ) -> Result<Self, VtdError> {
        let mut pages = Vec::new();
        for range in ranges {
            let range = crate::remapping::window_range(range, physical_bits)
                .ok_or(VtdError::Unsupported)?;
            let (start, end) = (range.start, range.end);
            if start >= end
                || end > 1u64 << physical_bits
                || end > 1u64 << (12 + 9 * u32::from(levels))
                || (start < MSI_END && end > MSI_START)
            {
                return Err(VtdError::Unsupported);
            }
            pages.push(start..end);
        }
        let mut tables = vec![Table::new(source, physical_bits)?];
        let mut index = BTreeMap::new();
        index.insert(tables[0].physical(), 0);
        for page in pages.into_iter().flat_map(|range| range.step_by(PAGE)) {
            let mut table = 0;
            for level in (1..levels).rev() {
                let slot = ((page >> (12 + 9 * u32::from(level))) & 511) as usize;
                let entry = tables[table].read(slot);
                table = if entry & (READ | WRITE) == 0 {
                    let child = Table::new(source, physical_bits)?;
                    let physical = child.physical();
                    tables[table].write(slot, physical | READ | WRITE);
                    tables.push(child);
                    index.insert(physical, tables.len() - 1);
                    tables.len() - 1
                } else {
                    index[&(entry & ADDRESS)]
                };
            }
            tables[table].write(((page >> 12) & 511) as usize, page | READ | WRITE);
        }
        Ok(Self { tables })
    }
}

impl DomainState {
    fn iova(&self, bytes: usize, limit: u64, width: u8) -> Result<u64, DmaError> {
        let limit = limit.min((1u64 << (12 + 9 * u32::from(width))) - 1);
        let mut candidate = PAGE as u64;
        for live in self.mappings.values() {
            let mut end = candidate
                .checked_add(bytes as u64)
                .ok_or(DmaError::AddressLimit)?;
            if candidate < MSI_END && end > MSI_START {
                candidate = MSI_END;
                end = candidate
                    .checked_add(bytes as u64)
                    .ok_or(DmaError::AddressLimit)?;
            }
            if end - 1 <= limit && end <= live.info.address {
                return Ok(candidate);
            }
            candidate = candidate.max(live.info.address + live.info.bytes as u64);
        }
        let mut end = candidate
            .checked_add(bytes as u64)
            .ok_or(DmaError::AddressLimit)?;
        if candidate < MSI_END && end > MSI_START {
            candidate = MSI_END;
            end = candidate
                .checked_add(bytes as u64)
                .ok_or(DmaError::AddressLimit)?;
        }
        if end - 1 > limit {
            Err(DmaError::AddressLimit)
        } else {
            Ok(candidate)
        }
    }

    fn leaf<R: Registers>(
        &mut self,
        source: &dyn PageSource,
        levels: u8,
        physical_bits: u8,
        iova: u64,
        registers: &R,
        table_cacheline: Option<usize>,
    ) -> Result<(usize, usize), VtdError> {
        let mut table = 0;
        for level in (1..levels).rev() {
            let index = ((iova >> (12 + 9 * u32::from(level))) & 511) as usize;
            let entry = self.tables[table].read(index);
            if entry & (READ | WRITE) == 0 {
                let child = Table::new(source, physical_bits)?;
                let physical = child.physical();
                // The walker can follow this branch as soon as Present is
                // visible, including an unsolicited device access before map
                // returns. Evict the complete zeroed child before exposing
                // its parent; eventual final invalidation is insufficient.
                if let Some(line) = table_cacheline {
                    child.flush(registers, line);
                }
                publish();
                let next = self.tables.len();
                self.tables.push(child);
                self.table_index.insert(physical, next);
                publish();
                self.tables[table].write(index, physical | READ | WRITE);
                if let Some(line) = table_cacheline {
                    self.tables[table].flush(registers, line);
                }
                publish();
                table = next;
            } else {
                table = *self
                    .table_index
                    .get(&(entry & ADDRESS))
                    .ok_or(VtdError::Memory)?;
            }
        }
        Ok((table, ((iova >> 12) & 511) as usize))
    }

    fn mapping(
        &self,
        info: DomainMapping,
        range: &Range<usize>,
        direction: Direction,
    ) -> Result<&LiveMapping, DmaError> {
        let live = self
            .mappings
            .get(&info.address)
            .filter(|live| live.info == info)
            .ok_or(DmaError::Unmapped)?;
        if range.start > range.end || range.end > live.info.bytes || live.direction != direction {
            return Err(DmaError::InvalidRange);
        }
        Ok(live)
    }
}

/// One requester context, hardware DID and non-reused software epoch.
/// It keeps physical hardware/table resources and a deny-only lifecycle; the
/// affine configuration claim belongs only to BoundRequester.
/// Final release is process/deferred context, never an IRQ callback.
pub struct RequesterDomain<R: Registers> {
    unit: ManuallyDrop<Arc<Unit<R>>>,
    rid: u16,
    did: u16,
    generation: u64,
    lifetime: Arc<RequesterLifetime>,
}
impl<R: Registers> RequesterDomain<R> {
    pub fn requester(&self) -> u16 {
        self.rid
    }
    pub fn domain_id(&self) -> u16 {
        self.did
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    fn domain<'a>(
        &self,
        state: &'a mut State,
        live: bool,
    ) -> Result<&'a mut DomainState, DmaError> {
        if !self.lifetime.is_live() {
            return Err(DmaError::Unmapped);
        }
        if state.shutdown || (live && state.poisoned) {
            return Err(DmaError::MappingFailed);
        }
        state
            .domains
            .get_mut(&self.rid)
            .filter(|d| {
                d.did == self.did
                    && d.generation == self.generation
                    && Arc::ptr_eq(&d.lifetime, &self.lifetime)
                    && !d.quarantined
            })
            .ok_or(DmaError::Unmapped)
    }
    /// Observe this exact retained domain's mapping inventory without changing
    /// a context, command queue or configuration. Callers retain their actual
    /// original process/root context; this supplies no detach/stop receipt.
    pub fn has_live_mappings(&self) -> Result<bool, DmaError> {
        let mut guard = self.unit.lock();
        Ok(!self.domain(guard.state(), false)?.mappings.is_empty())
    }
}
impl<R: Registers> Drop for RequesterDomain<R> {
    fn drop(&mut self) {
        self.lifetime.close();
        if self.lifetime.is_detached() {
            // SAFETY: removal and invalidation were acknowledged before the
            // original local actor released its claim. No callback or I/O.
            unsafe {
                ManuallyDrop::drop(&mut self.unit);
            }
        }
    }
}

// SAFETY: the platform's takeover contract establishes exclusive
// requester ownership, coherent WB DMA and stopped ATS/NoSnoop. Real native
// pages and hardware tables are held through acknowledged invalidation;
// every failed/abandoned hardware lifetime preserves its backing. All mutable
// operations are serialized outside hard IRQ context.
unsafe impl<R: Registers + 'static> DmaDomain for RequesterDomain<R> {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        direction: Direction,
        address_limit: u64,
    ) -> Result<DomainMapping, DmaError> {
        if pages.cache_attribute() != CacheAttribute::WriteBack
            || pages.page_shift() < 12
            || pages.physical_pages().iter().any(|pa| {
                pa.checked_add(1u64 << pages.page_shift())
                    .is_none_or(|end| end > 1u64 << self.unit.physical_bits)
            })
        {
            return Err(DmaError::MappingFailed);
        }
        let mut guard = self.unit.lock();
        let state = guard.state();
        if state.shutdown || state.poisoned {
            return Err(DmaError::MappingFailed);
        }
        let id = state.next_id;
        state.next_id = id.checked_add(1).ok_or(DmaError::MappingFailed)?;
        let domain = self.domain(state, true)?;
        let address = domain.iova(pages.bytes(), address_limit, self.unit.levels)?;
        let info = DomainMapping {
            id,
            address,
            bytes: pages.bytes(),
        };
        let mut leaves = Vec::with_capacity(pages.bytes() / PAGE);
        // Build all required table paths first. No leaf may be published until
        // the owned mapping/pin and complete leaf inventory have been kept.
        for offset in (0..pages.bytes()).step_by(PAGE) {
            leaves.push(
                domain
                    .leaf(
                        self.unit.source,
                        self.unit.levels,
                        self.unit.physical_bits,
                        address + offset as u64,
                        &*self.unit.registers,
                        self.unit.table_cacheline,
                    )
                    .map_err(|_| DmaError::MappingFailed)?,
            );
        }
        domain.mappings.insert(
            address,
            LiveMapping {
                info,
                direction,
                _pages: pages.clone(),
                leaves,
            },
        );
        let rights = match direction {
            Direction::ToDevice => READ,
            Direction::FromDevice => WRITE,
            Direction::Bidirectional => READ | WRITE,
        };
        let live = &domain.mappings[&address];
        let native_size = 1usize << pages.page_shift();
        for (page, &(table, index)) in live.leaves.iter().enumerate() {
            let offset = page * PAGE;
            let physical =
                pages.physical_pages()[offset / native_size] + (offset % native_size) as u64;
            domain.tables[table].write(index, physical | rights);
        }
        self.unit.publish_leaves(domain, &live.leaves);
        if self
            .unit
            .publish_new_entries(self.did, info.address, info.bytes)
            .is_err()
        {
            // An unacknowledged translation is never returned as a live lease;
            // keep its pin/table inventory and poison further submissions.
            state.poisoned = true;
            return Err(DmaError::InvalidationFailed);
        }
        Ok(info)
    }

    unsafe fn unmap(&self, info: DomainMapping) -> Result<(), DmaError> {
        let mut guard = self.unit.lock();
        let state = guard.state();
        if state.shutdown {
            return Err(DmaError::Unmapped);
        }
        let domain = self.domain(state, false)?;
        let live = domain
            .mappings
            .get(&info.address)
            .filter(|live| live.info == info)
            .ok_or(DmaError::Unmapped)?;
        for &(table, index) in &live.leaves {
            domain.tables[table].write(index, 0);
        }
        self.unit.publish_leaves(domain, &live.leaves);
        if self
            .unit
            .invalidate_pages(self.did, info.address, info.bytes)
            .is_err()
        {
            state.poisoned = true;
            return Err(DmaError::InvalidationFailed);
        }
        self.domain(state, false)?.mappings.remove(&info.address);
        // Once poisoned, this initial backend requires full platform recovery;
        // another mapping cannot assume an unrelated failed map was retired.
        Ok(())
    }

    unsafe fn sync_for_device(
        &self,
        info: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> Result<(), DmaError> {
        let mut guard = self.unit.lock();
        self.domain(guard.state(), true)?
            .mapping(info, &range, direction)?;
        // DMA coherence is an explicit platform/requester validation, not
        // inferred from ECAP page-table coherency or WB CPU attributes alone.
        publish();
        Ok(())
    }

    unsafe fn sync_for_cpu(
        &self,
        info: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> Result<(), DmaError> {
        let mut guard = self.unit.lock();
        self.domain(guard.state(), true)?
            .mapping(info, &range, direction)?;
        // Caller has observed hardware completion before this acquire
        // boundary; no completion or cache invalidation is invented here.
        publish();
        Ok(())
    }

    unsafe fn read_coherent_u32(
        &self,
        info: DomainMapping,
        offset: usize,
        direction: Direction,
    ) -> Result<u32, DmaError> {
        let end = offset.checked_add(4).ok_or(DmaError::InvalidRange)?;
        if !offset.is_multiple_of(4) || direction == Direction::ToDevice {
            return Err(DmaError::InvalidRange);
        }
        let mut guard = self.unit.lock();
        let live = self
            .domain(guard.state(), true)?
            .mapping(info, &(offset..end), direction)?;
        // The takeover/claim contracts independently check coherent WB
        // payload DMA and exclude ATS/NoSnoop and incompatible aliases. ECAP
        // table-walk coherency is not that grant. Scatter mappings do not
        // manufacture a contiguous CPU view.
        let pages = live
            ._pages
            .as_single()
            .ok_or(DmaError::CoherenceUnavailable)?;
        let cpu = pages
            .cpu_mapping(CacheAttribute::WriteBack)
            .map_err(|_| DmaError::CoherenceUnavailable)?;
        let pointer = cpu.address(offset, 4).map_err(|_| DmaError::InvalidRange)?;
        if !(pointer.as_ptr() as usize).is_multiple_of(4) {
            return Err(DmaError::InvalidRange);
        }
        publish();
        // SAFETY: this live domain keeps its aligned WB allocation;
        // only raw access is exposed. The checked platform supports these
        // per-word observations during device writes, not atomic whole frames.
        let value = unsafe { pointer.as_ptr().cast::<u32>().read_volatile() };
        publish();
        Ok(u32::from_le(value))
    }

    unsafe fn drain_posted_writes(&self) -> Result<(), DmaError> {
        let mut guard = self.unit.lock();
        let state = guard.state();
        self.domain(state, true)?;
        if self.unit.cap & CAP_WRITE_DRAIN == 0 {
            return Err(DmaError::DrainUnavailable);
        }
        // VT-d section 6.5.4: with DWD support, the DW invalidation
        // completes queued translated writes through this root path before
        // returning. It neither establishes device stop nor drains peer DMA.
        // The existing operation verifies completion/granularity and performs
        // the real write-buffer flush where the unit requires it.
        if self.unit.invalidate(false).is_err() {
            state.poisoned = true;
            return Err(DmaError::InvalidationFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
