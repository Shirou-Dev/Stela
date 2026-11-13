// SPDX-License-Identifier: GPL-2.0-only
// Command/register sequencing adapted from Linux drivers/iommu/amd at
// a804c5742bff224d4cb4d25dd383554d598be32b, AMD copyright 2007-2010.
//! Cold, exclusive AMDv1 requester ownership. This is process
//! local: the original PCI/UC/root owner is not promoted to Send/Sync. Native
//! provisioning and a cross-thread process-context adapter remain platform work.
//!
//! Each unit is one IVHD's remapper, with its device entries' coverage,
//! aliases and DTE settings; ATS/PASID/PRI, guest translation and
//! interrupt-table owners stay absent. A unit can give its covered
//! requesters a window domain that maps given memory one to one
//! ([`Unit::window`]), which a requester leaves when it attaches.
//! Faults keep every original owner; they never disable translation into
//! bypass. Matched invalidations followed by exact completion stores drain
//! translated payloads through this root path, not endpoint engines, peer
//! traffic or posted interrupts. The platform supplies the DmaDomain adapter.
//! Healthy retirement releases internal RAM after engines stop and register
//! pointers clear. Original PCI/UC mappings have no consuming handback yet;
//! their registry quarantine remains boot-lifetime, not hotplug reclamation.
mod buffer;
mod firmware;
mod queue;
mod requester;

use super::registers::{self, FunctionInspection, UnitConfig};
use crate::{
    Clock,
    bus::dma::{
        amd::{
            device::{DeviceTable, DeviceTableError, DeviceTableHardware},
            format::{Command, DomainId, PhysicalAddress, TableLevel},
            ivrs::Ivrs,
            memory::TableVisibility,
            tables::{PageTables, TableHardware, TranslationError},
        },
        mapping::{Direction, DmaError},
        memory::{CacheAttribute, MemoryError, PageGeometry, PageSource, PinnedPages},
        pages::DmaPages,
    },
    bus::{mmio::owned::MappingView, pci::owned::OwnedConfig},
};
use alloc::{rc::Rc, sync::Arc, vec::Vec};
use buffer::Buffer;
use core::{
    cell::{Cell, RefCell},
    mem::ManuallyDrop,
    ops::Range,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
pub use requester::{Mapping, Requester};

const DEVICE_TABLE: usize = 0;
const COMMAND_BASE: usize = 8;
const EVENT_BASE: usize = 16;
const CONTROL: usize = 24;
const EXCLUSION_BASE: usize = 32;
const EXCLUSION_LIMIT: usize = 40;
const HARDWARE_EVENT_STATUS: usize = 0x50;
const COMMAND_HEAD: usize = 0x2000;
const COMMAND_TAIL: usize = 0x2008;
const EVENT_HEAD: usize = 0x2010;
const EVENT_TAIL: usize = 0x2018;
const STATUS: usize = 0x2020;
const IOMMU_ENABLE: u64 = 1;
const EVENT_ENABLE: u64 = 1 << 2;
const COHERENT: u64 = 1 << 10;
const COMMAND_ENABLE: u64 = 1 << 12;
const EVENT_RUNNING: u64 = 1 << 3;
const COMMAND_RUNNING: u64 = 1 << 4;
const RUNNING: u64 = EVENT_RUNNING | COMMAND_RUNNING;
const RING_BYTES: usize = 8192;
const RING_LENGTH: u64 = 9 << 56;
const COMMAND_BYTES: usize = 16;
static QUARANTINED_UNITS: AtomicU64 = AtomicU64::new(0);

/// Exposed cold-unit owners kept on uncertain Drop. Not reset evidence.
pub fn quarantined_units() -> u64 {
    QUARANTINED_UNITS.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Config(crate::bus::pci::ConfigError),
    PciCapability(crate::bus::pci::CapabilityError),
    Firmware,
    Profile,
    /// A register the firmware left set that a stopped unit's reset did not
    /// clear, or one that says the unit runs: its offset and value.
    NotCold {
        register: usize,
        value: u64,
    },
    Busy,
    Requester,
    Exhausted,
    Fault,
    Timeout,
    Poisoned,
    Mapping,
    Memory(MemoryError),
    Register(registers::Error),
    DeviceTable(DeviceTableError),
    Translation(TranslationError),
    Dma(DmaError),
}

fn invalidation_error(error: Error) -> DmaError {
    match error {
        Error::Dma(error) => error,
        _ => DmaError::InvalidationFailed,
    }
}

/// Native context/cache/RAM services, not numeric attestations.
///
/// # Safety
/// The implementor owns the original unit's root/bridge/reset/configuration,
/// firmware and all covered requester/IRQ/deferred/prior-DMA epochs. The cold
/// entry grant is independently established by reset and stopped/drained
/// requesters, not by a zero control register. All software/firmware unit/table
/// writers remain excluded until explicit final retirement. The kept
/// FunctionInspection is the original unit for this same epoch; native aligned
/// UC read64/write64 and coherent WB command/completion/event DMA are checked.
/// Unencrypted RAM and host-only AMDv1 tables are checked at physical_bits();
/// SNP, ATS (including integrated alternate signaling), PASID/PRI,
/// hardware table updates, guest and IRQ-remapping owners are absent and cannot
/// become enabled. Requesters cannot issue DMA while a new DTE is being
/// attached or detached. No driver may use this owner to reset another domain.
/// Every allocation is fresh zeroed CPU-exclusive RAM with true physical pins.
/// `enter` keeps checked process/root/current-CPU/CX16/cache context, prevents
/// migration when required, and excludes external writers. Nested entry on the
/// same process is supported, never waits on its own nonreentrant lock, permits
/// completion progress, and no callback may reenter this backend. This backend
/// is !Send/!Sync and serializes its own queue separately. `clock` is the
/// checked nonzero monotonic TSC clock for this context. Visibility and sync
/// perform real hardware ordering/cache work; unsupported work returns failure.
pub unsafe trait ColdPlatform: PageSource + TableVisibility {
    type Access<'a>
    where
        Self: 'a;
    fn enter(&self) -> Result<Self::Access<'_>, DmaError>;
    fn clock(&self) -> Clock;
    fn physical_bits(&self) -> u8;
    fn admit_payload(&self, pages: &DmaPages, direction: Direction) -> Result<bool, DmaError>;
    /// # Safety
    /// Kept pages, bounded range and original mapping direction. CPU
    /// ownership for a CPU sync and stopped writers are established by caller.
    unsafe fn sync(
        &self,
        pages: &DmaPages,
        range: Range<usize>,
        direction: Direction,
        for_cpu: bool,
    ) -> Result<(), DmaError>;
    /// Allow real hardware/IRQ progress. No completion permission is returned.
    fn relax(&self) {
        crate::waiting();
        core::hint::spin_loop();
    }
}

/// Bounded translation and wait resources; no implicit host-sized allocation.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub table_pages: usize,
    pub table_backing_bytes: usize,
    pub mappings: usize,
    pub wait_us: u64,
}

struct Resources<P, C> {
    inspection: FunctionInspection<C>,
    platform: P,
    command: Buffer,
    completion: Buffer,
    event: Buffer,
}

struct Queue {
    tail: usize,
    sequence: u64,
}

struct Engine<P, C> {
    resources: ManuallyDrop<Resources<P, C>>,
    queue: RefCell<Queue>,
    poisoned: Cell<bool>,
    exposed: Cell<bool>,
    retired: Cell<bool>,
    control: u64,
    hardware_errors: bool,
    wait_us: u64,
    table_base: Cell<u64>,
}

impl<P, C> Drop for Engine<P, C> {
    fn drop(&mut self) {
        if self.exposed.get() && !self.retired.get() {
            let _ = QUARANTINED_UNITS.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
            // Keep original PCI/UC/root/platform owners and all possible DMA
            // targets together. Drop cannot establish cold/reset or DMA stop.
        } else {
            // SAFETY: no register exposure, or explicit acknowledged final
            // retirement. ManuallyDrop owns this unique resources object.
            unsafe { ManuallyDrop::drop(&mut self.resources) };
        }
    }
}

struct Hardware<P, C> {
    engine: Rc<Engine<P, C>>,
    domain: Option<DomainId>,
    // A poisoned/exposed tree keeps its original requester configuration
    // together with the original unit/root and payload/table pins.
    requester: Option<Rc<requester::Owner>>,
}
impl<P, C> Clone for Hardware<P, C> {
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
            domain: self.domain,
            requester: self.requester.clone(),
        }
    }
}
impl<P: ColdPlatform, C: UnitConfig> PageSource for Hardware<P, C> {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        self.engine.resources.platform.page_geometry()
    }
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        self.engine
            .resources
            .platform
            .allocate(bytes, alignment, attribute)
    }
    fn allocate_below(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
        physical_end_exclusive: u64,
    ) -> Result<PinnedPages, MemoryError> {
        self.engine.resources.platform.allocate_below(
            bytes,
            alignment,
            attribute,
            physical_end_exclusive,
        )
    }
}
// SAFETY: the original unsafe platform supplies table visibility; this
// adapter preserves the exact bytes and original unit context.
unsafe impl<P: ColdPlatform, C: UnitConfig> TableVisibility for Hardware<P, C> {
    unsafe fn publish(&self, cpu: NonNull<u8>, bytes: usize) -> Result<(), MemoryError> {
        // SAFETY: inherited exact WB span contract, forwarded without escape.
        unsafe { self.engine.resources.platform.publish(cpu, bytes) }
    }
}
// SAFETY: one closed, externally exclusive unit; enter keeps its CX16
// execution context. Queue completion is a real exact-sequence coherent store.
unsafe impl<P: ColdPlatform, C: UnitConfig> DeviceTableHardware for Hardware<P, C> {
    type Access<'a>
        = P::Access<'a>
    where
        Self: 'a;
    fn enter(&self) -> Result<Self::Access<'_>, DmaError> {
        self.engine.resources.platform.enter()
    }
    fn invalidate(&self, requester: u16, old_domain: Option<DomainId>) -> Result<(), DmaError> {
        let commands = [
            Command::invalidate_device(requester),
            old_domain
                .map(|id| Command::invalidate_domain(id, true))
                .unwrap_or_else(|| Command::invalidate_device(requester)),
        ];
        self.engine
            .execute(&commands)
            .map_err(|_| DmaError::InvalidationFailed)
    }
}
// SAFETY: every tree is bound to its reserved domain and original requester;
// full-domain invalidation includes PDE caches and exact completion. Payload
// cache/encryption admission is supplied by the native platform.
unsafe impl<P: ColdPlatform, C: UnitConfig> TableHardware for Hardware<P, C> {
    fn invalidate(&self, _: u64, _: usize) -> Result<(), DmaError> {
        let id = self.domain.ok_or(DmaError::IommuUnavailable)?;
        self.engine
            .execute(&[Command::invalidate_domain(id, true)])
            .map_err(|_| DmaError::InvalidationFailed)
    }
    fn admit_payload(&self, pages: &DmaPages, direction: Direction) -> Result<bool, DmaError> {
        self.engine
            .resources
            .platform
            .admit_payload(pages, direction)
    }
}

/// The window domain: one to one page tables shared by the requesters that
/// have no domain of their own.
struct Window<P: ColdPlatform, C: UnitConfig> {
    id: DomainId,
    root: PhysicalAddress,
    level: TableLevel,
    tree: PageTables<Hardware<P, C>>,
    requesters: Vec<u16>,
}

/// The original cold AMD unit's direct interrupt format, without a
/// reference to its process-local command engine or configuration owner.
pub struct DirectDelivery {
    _mapping: MappingView,
    valid: Arc<AtomicBool>,
    base: usize,
    table: u64,
    control: u64,
}

impl DirectDelivery {
    /// # Safety
    /// The caller has checked the original IRQ CPU and admitted root. That
    /// context keeps the retained UC register aperture reachable, including
    /// in an IRQ. This reads only immutable mode and root register fields.
    pub unsafe fn check(&self) -> Result<(), Error> {
        if !self.valid.load(Ordering::Acquire) {
            return Err(Error::Fault);
        }
        // SAFETY: caller's current root keeps this aligned, retained aperture.
        let table = unsafe { ((self.base + DEVICE_TABLE) as *const u64).read_volatile() };
        // SAFETY: same original retained mapping and bounded 64-bit register.
        let control = unsafe { ((self.base + CONTROL) as *const u64).read_volatile() };
        if u64::from_le(table) != self.table || u64::from_le(control) != self.control {
            self.valid.store(false, Ordering::Release);
            return Err(Error::Fault);
        }
        if !self.valid.load(Ordering::Acquire) {
            return Err(Error::Fault);
        }
        Ok(())
    }
}

/// Original cold unit plus complete blocked DTE table and bounded RID policy.
/// Requesters and their page trees keep this exact engine independently.
pub struct Unit<P: ColdPlatform, C: UnitConfig = OwnedConfig> {
    engine: Rc<Engine<P, C>>,
    table: Rc<RefCell<DeviceTable<Hardware<P, C>>>>,
    coverage: Vec<bool>,
    /// IDs independently assigned by firmware or observed on a PCI function.
    sources: Vec<bool>,
    aliases: Vec<(u16, u16)>,
    window: Option<Window<P, C>>,
    active: Rc<RefCell<Vec<u16>>>,
    direct_delivery: Arc<AtomicBool>,
    next_domain: Cell<u32>,
    segment: u16,
    physical_bits: u8,
    limits: Limits,
}

impl<P: ColdPlatform, C: UnitConfig> Unit<P, C> {
    /// # Safety
    /// `platform` is the original cold/exclusive native owner described by
    /// ColdPlatform, for this exact inspection and complete original IVRS. No
    /// DMA or external writer can start before initialization finishes. This
    /// does not derive cold/reset permission from register observations. Failure
    /// after first publication quarantines original resources.
    pub unsafe fn cold(
        inspection: FunctionInspection<C>,
        ivrs: &Ivrs<'_>,
        platform: P,
        limits: Limits,
    ) -> Result<Self, Error> {
        if limits.table_pages == 0
            || limits.table_backing_bytes < 4096
            || limits.mappings == 0
            || limits.wait_us == 0
            || limits.wait_us > 1_000_000
            || platform.clock().ticks_per_microsecond == 0
        {
            return Err(Error::Profile);
        }
        let guard = platform.enter().map_err(Error::Dma)?;
        let admitted = firmware::admit(&inspection, ivrs, platform.physical_bits())?;
        let command = Buffer::allocate(&platform, RING_BYTES, admitted.bits)?;
        let completion = Buffer::allocate(&platform, 4096, admitted.bits)?;
        let event = Buffer::allocate(&platform, RING_BYTES, admitted.bits)?;
        drop(guard);
        let engine = Rc::new(Engine {
            resources: ManuallyDrop::new(Resources {
                inspection,
                platform,
                command,
                completion,
                event,
            }),
            queue: RefCell::new(Queue {
                tail: 0,
                sequence: 0,
            }),
            poisoned: Cell::new(false),
            exposed: Cell::new(false),
            retired: Cell::new(false),
            control: admitted.control,
            hardware_errors: admitted.hardware_errors,
            wait_us: limits.wait_us,
            table_base: Cell::new(0),
        });
        let hardware = Hardware {
            engine: engine.clone(),
            domain: None,
            requester: None,
        };
        // SAFETY: complete effective plain policy and original cold ownership
        // were checked before allocation; all context stays held.
        let mut table = unsafe { DeviceTable::new(hardware, &admitted.policies, admitted.bits) }
            .map_err(Error::DeviceTable)?;
        let _guard = engine.resources.platform.enter().map_err(Error::Dma)?;
        engine.reset_stopped()?;
        engine.check_cold()?;
        let base = table
            .register_for_publication()
            .map_err(Error::DeviceTable)?;
        // Arm before even the first store/callback can unwind or fail.
        engine.exposed.set(true);
        if let Err(error) = engine.initialize(base) {
            // A unit that did not start is turned off again, as far as its
            // registers still answer: left on, its table blocks every
            // device behind it, the boot's own disks included.
            let _ = engine.write(CONTROL, 0);
            return Err(error);
        }
        drop(_guard);
        Ok(Self {
            engine,
            table: Rc::new(RefCell::new(table)),
            coverage: admitted.coverage,
            sources: admitted.sources,
            aliases: admitted.aliases,
            window: None,
            active: Rc::new(RefCell::new(Vec::new())),
            direct_delivery: Arc::new(AtomicBool::new(true)),
            next_domain: Cell::new(1),
            segment: admitted.segment,
            physical_bits: admitted.bits,
            limits,
        })
    }

    /// A scalar read through the original function observation retained by
    /// this exact unit. No new configuration mapping or writer is issued.
    pub fn read_original_config(
        &self,
        offset: u16,
        width: u8,
    ) -> Result<u32, crate::bus::pci::ConfigError> {
        let _guard = self.engine.resources.platform.enter().map_err(|_| {
            crate::bus::pci::ConfigError::before_effect(
                crate::bus::pci::ConfigFailure::UnqualifiedControl,
            )
        })?;
        self.engine.resources.inspection.read_config(offset, width)
    }

    /// Pin the original cold unit's direct interrupt format. The private
    /// table starts with IV clear for every DTE. Its only live entry updates
    /// preserve IV and its interrupt fields (AMD 48882 §2.2.2, Table 9).
    pub fn pin_direct_delivery(&self) -> Result<DirectDelivery, Error> {
        let _guard = self.engine.resources.platform.enter().map_err(Error::Dma)?;
        self.engine.health()?;
        if self.table.borrow().is_poisoned() || !self.direct_delivery.load(Ordering::Acquire) {
            return Err(Error::Poisoned);
        }
        let view = self
            .engine
            .resources
            .inspection
            .native_view(CONTROL + 8)
            .map_err(Error::Register)?;
        let base = view
            .address(0, CONTROL + 8)
            .map_err(|error| Error::Register(registers::Error::Mapping(error)))?;
        Ok(DirectDelivery {
            _mapping: view,
            valid: self.direct_delivery.clone(),
            base: base.as_ptr() as usize,
            table: self.engine.table_base.get(),
            control: self.engine.control,
        })
    }

    /// Whether the unit's IVHD covers requester `rid` on `segment`.
    pub fn covers(&self, segment: u16, rid: u16) -> bool {
        segment == self.segment && self.coverage[usize::from(rid)]
    }

    /// The requester IDs `rid`'s DMA arrives under: its own and its alias.
    fn group(&self, rid: u16) -> Vec<u16> {
        let mut group = alloc::vec![rid];
        group.extend(
            self.aliases
                .iter()
                .filter(|&&(source, _)| source == rid)
                .map(|&(_, target)| target),
        );
        group
    }

    /// Whether another requester can address a member of this group, either
    /// through a firmware alias or by using its own independently routed ID.
    fn shared(&self, rid: u16, group: &[u16]) -> bool {
        group
            .iter()
            .any(|&member| member != rid && self.sources[usize::from(member)])
            || self.aliases.iter().any(|&(source, target)| {
                source != rid && (group.contains(&target) || group.contains(&source))
            })
    }

    /// Observe a real stopped arrival before it can use DMA. An arrival
    /// sharing an already-private group must stay stopped and unadmitted.
    pub fn admit_requester(&mut self, rid: u16) -> Result<(), Error> {
        if !self.covers(self.segment, rid) {
            return Err(Error::Requester);
        }
        // Keep the observation even if this function must stay stopped. A
        // later attachment cannot reuse its RID after the current owner retires.
        self.sources[usize::from(rid)] = true;
        let group = self.group(rid);
        if self.active.borrow().iter().copied().any(|active| {
            active != rid
                && (group.contains(&active)
                    || self
                        .aliases
                        .iter()
                        .any(|&(source, target)| source == active && group.contains(&target)))
        }) {
            return Err(Error::Requester);
        }
        Ok(())
    }

    /// Give `requesters`, with their aliases, the window domain, which maps
    /// each of `ranges` (one physically contiguous run each) at its own
    /// physical address.
    ///
    /// # Safety
    /// `requesters` is the complete original set of present covered PCI
    /// requesters. Each DMAs only to `ranges` until it attaches, and each
    /// range is memory the platform admits for device DMA and keeps for the
    /// boot. Later arrivals stay stopped until `admit_requester` accepts them.
    pub unsafe fn window(
        &mut self,
        requesters: &[u16],
        ranges: Vec<DmaPages>,
    ) -> Result<(), Error> {
        if self.engine.retired.get() || self.engine.poisoned.get() {
            return Err(Error::Poisoned);
        }
        if self.window.is_some() || ranges.is_empty() || !self.active.borrow().is_empty() {
            return Err(Error::Busy);
        }
        let mut covered = Vec::new();
        for &rid in requesters {
            if !self.coverage[usize::from(rid)] {
                return Err(Error::Requester);
            }
            self.sources[usize::from(rid)] = true;
            for member in self.group(rid) {
                if !covered.contains(&member) {
                    covered.push(member);
                }
            }
        }
        let mut end = 0u64;
        let mut leaves = 0usize;
        for pages in &ranges {
            let size = 1u64 << pages.page_shift();
            let first = *pages.physical_pages().first().ok_or(Error::Mapping)?;
            if pages
                .physical_pages()
                .iter()
                .enumerate()
                .any(|(index, &page)| page != first + index as u64 * size)
            {
                return Err(Error::Mapping);
            }
            end = end.max(first + pages.bytes() as u64);
            leaves += pages.bytes().div_ceil(1 << 21) + 1;
        }
        let bits = (u64::BITS - (end - 1).leading_zeros()).max(21) as u8;
        let mode = (1..=4u8)
            .find(|mode| 12 + 9 * u32::from(*mode) >= u32::from(bits))
            .ok_or(Error::Profile)?;
        let level = TableLevel::new(mode).map_err(|_| Error::Profile)?;
        let next = self.next_domain.get();
        let id = u16::try_from(next)
            .ok()
            .and_then(DomainId::new)
            .ok_or(Error::Exhausted)?;
        self.next_domain.set(next + 1);
        let hardware = Hardware {
            engine: self.engine.clone(),
            domain: Some(id),
            requester: None,
        };
        let pages = leaves * usize::from(mode) + 1;
        let _guard = self.engine.resources.platform.enter().map_err(Error::Dma)?;
        self.engine.health()?;
        // SAFETY: the level covers every range's physical address, within
        // the admitted host translation; the tree is this domain's alone.
        let mut tree = unsafe {
            PageTables::new(
                hardware,
                level,
                self.physical_bits,
                level.address_bits() as u8,
                pages,
                pages * 4096,
            )
        }
        .map_err(Error::Translation)?;
        for range in ranges {
            let address = range.physical_pages()[0];
            // SAFETY: a fresh tree no device walks yet; each range maps at
            // its own address, and the ranges are the caller's.
            unsafe { tree.map(address, range, Direction::Bidirectional) }
                .map_err(Error::Translation)?;
        }
        let root = tree.root_for_publication().map_err(Error::Translation)?;
        for &rid in &covered {
            // SAFETY: forwarded: the requester DMAs only to the ranges.
            unsafe { self.table.borrow_mut().translate(rid, root, level, id) }
                .map_err(Error::DeviceTable)?;
        }
        drop(_guard);
        self.window = Some(Window {
            id,
            root,
            level,
            tree,
            requesters: covered,
        });
        Ok(())
    }

    /// Poll without clearing event/fault evidence. A fault poisons this exact
    /// owner; translation stays enabled and all live RAM/root owners remain.
    pub fn check_health(&self) -> Result<(), Error> {
        let _guard = self.engine.resources.platform.enter().map_err(Error::Dma)?;
        self.engine.health()
    }

    /// Drain the original window/blocked path before a private attachment.
    /// A private DTE, including one reached through an alias, cannot be
    /// mistaken for this requester's original cold path.
    pub fn drain_initial_requester(&self, rid: u16) -> Result<(), DmaError> {
        self.check_initial_entries(rid)?;
        self.drain_posted_writes()
    }

    /// Observe the original cold blocked entries without any unit command.
    pub fn check_blocked_requester(&self, rid: u16) -> Result<(), DmaError> {
        if self.window.is_some() || self.active.borrow().contains(&rid) {
            return Err(DmaError::IommuUnavailable);
        }
        self.check_health().map_err(invalidation_error)?;
        self.check_initial_entries(rid)
    }

    fn check_initial_entries(&self, rid: u16) -> Result<(), DmaError> {
        if !self.coverage[usize::from(rid)] {
            return Err(DmaError::IommuUnavailable);
        }
        {
            let table = self.table.borrow();
            for member in self.group(rid) {
                let expected = self
                    .window
                    .as_ref()
                    .filter(|window| window.requesters.contains(&member))
                    .map(|window| (window.root, window.level, window.id));
                table
                    .check_cold_entry(member, expected)
                    .map_err(|error| match error {
                        DeviceTableError::ConcurrentWriter => DmaError::IommuUnavailable,
                        _ => DmaError::InvalidationFailed,
                    })?;
            }
        }
        Ok(())
    }

    /// Complete earlier translated payload transactions through this unit.
    /// AMD 48882 rev. 3.11 sections 1.3.3 and 2.4.11 require matching
    /// invalidations to drain fabric transactions before COMPLETION_WAIT.
    /// IASup is part of this unit's admitted profile. This does not stop
    /// endpoints or cover bypass, peer traffic, posted MSIs or future DMA.
    pub fn drain_posted_writes(&self) -> Result<(), DmaError> {
        if self.table.borrow().is_poisoned()
            || self
                .window
                .as_ref()
                .is_some_and(|window| window.tree.is_poisoned())
        {
            return Err(DmaError::InvalidationFailed);
        }
        self.engine
            .execute(&[Command::invalidate_all()])
            .map_err(invalidation_error)
    }

    /// # Safety
    /// Every requester covered by the original cold grant is again stopped,
    /// with payload/IRQ/work/prior-DMA drains complete. No requester may
    /// resume after this operation: disabling translation would enable bypass.
    /// All Requester owners must have completed detach, not been dropped.
    /// Success retires internal walker/command/event targets, not PCI mappings;
    /// their original native platform retirement obligations still apply.
    pub unsafe fn retire(&mut self) -> Result<(), Error> {
        if !self.active.borrow().is_empty()
            || Rc::strong_count(&self.table) != 1
            || Arc::strong_count(&self.direct_delivery) != 1
        {
            return Err(Error::Busy);
        }
        let _guard = self.engine.resources.platform.enter().map_err(Error::Dma)?;
        if let Some(window) = &mut self.window {
            for &rid in &window.requesters {
                // SAFETY: forwarded: every covered requester is stopped.
                unsafe { self.table.borrow_mut().block(rid) }.map_err(Error::DeviceTable)?;
            }
            // SAFETY: every DTE that named the tree is blocked and invalidated.
            unsafe { window.tree.retire() };
            self.window = None;
        }
        self.engine.execute(&[Command::invalidate_all()])?;
        self.engine.poisoned.set(true);
        self.engine.write(CONTROL, 0)?;
        let deadline = self
            .engine
            .resources
            .platform
            .clock()
            .deadline(self.limits.wait_us);
        loop {
            // Its rings have stopped; an event bit left set runs nothing.
            if self.engine.read(STATUS)? & RUNNING == 0 && self.engine.read(CONTROL)? == 0 {
                break;
            }
            if deadline.passed() {
                return Err(Error::Timeout);
            }
            self.engine.resources.platform.relax();
        }
        // Both engines are stopped. Remove every stale RAM pointer
        // before releasing its pin; a later cold owner cannot inherit pointers
        // into a previous allocator epoch. Never perform this on a fault path.
        for offset in [
            DEVICE_TABLE,
            COMMAND_BASE,
            EVENT_BASE,
            COMMAND_HEAD,
            COMMAND_TAIL,
            EVENT_HEAD,
            EVENT_TAIL,
        ] {
            self.engine.write(offset, 0)?;
            if self.engine.read(offset)? != 0 {
                return Err(Error::Fault);
            }
        }
        drop(_guard);
        // SAFETY: all external requesters/drains are a real caller obligation;
        // final full invalidation/store plus observed engine stop completed.
        unsafe { self.table.borrow_mut().retire() };
        self.engine.retired.set(true);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
