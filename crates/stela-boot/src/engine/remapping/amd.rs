//! AMD-Vi units ([`stela_drivers::bus::dma::amd`]): one per IVHD, each its
//! own PCI function. The units are process local; the boot processor, which
//! runs the host drivers, owns them, and their domains refuse other
//! processors and interrupt handlers.
use super::{CLAIMED_DISPLAYS, InactiveFirmwareUnits};
use crate::Result;
use crate::{native_mmio, output};
use alloc::{boxed::Box, format, rc::Rc, sync::Arc, vec, vec::Vec};
use core::{cell::RefCell, mem::ManuallyDrop, ops::Range, ptr::NonNull};
use stela_boot_core::remapping::initial::{self, Candidate, Left, Mode};
use stela_boot_core::remapping::{self, Present};
use stela_contracts::refuse;
use stela_drivers::{
    Clock,
    bus::{
        dma::{
            amd::{
                ivrs::{Ivrs, MemoryScope},
                memory::TableVisibility,
                unit::{
                    native::{
                        ColdPlatform, DirectDelivery, Error, Limits, Mapping, Requester, Unit,
                    },
                    registers::{FunctionInspection, Inputs},
                },
            },
            mapping::{Direction, DmaDomain, DmaError, DomainMapping},
            memory::{
                CacheAttribute, MemoryError, PageBacking, PageGeometry, PageSource, PinnedPages,
            },
            pages::DmaPages,
        },
        mmio::owned::{PhysicalSpan, Protection},
        pci::{Address, Function, owned::ObservedConfig, requester::RequesterBinding},
    },
};

const PAGE: u64 = 4096;
/// The register apertures an AMD-Vi unit decodes: without and with its
/// performance counters.
const APERTURES: [u64; 2] = [16 << 10, 512 << 10];
/// The most IVHD blocks one IVRS may hold.
pub(super) const MAXIMUM_BLOCKS: usize = 64;

/// Whether the BSP's processor-local record is active outside interrupts.
fn on_boot_processor() -> bool {
    crate::engine::host::local::processor() == 0 && !crate::engine::host::in_interrupt()
}

/// The boot processor's cold-unit services: the native allocator's pages,
/// coherent table walks (the unit's control sets Coherent) and the TSC.
pub(super) struct Platform {
    tsc_hz: u64,
    physical_bits: u8,
}

pub(super) struct Access;

impl PageSource for Platform {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        crate::native_memory::SOURCE.page_geometry()
    }
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        crate::native_memory::SOURCE.allocate(bytes, alignment, attribute)
    }
    fn allocate_below(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
        physical_end_exclusive: u64,
    ) -> Result<PinnedPages, MemoryError> {
        crate::native_memory::AMD_TABLES.allocate_below(
            bytes,
            alignment,
            attribute,
            physical_end_exclusive,
        )
    }
}

// SAFETY: the unit walks its tables coherently (control bit Coherent), so a
// store ordered by MFENCE before the unit's command is visible to it.
unsafe impl TableVisibility for Platform {
    unsafe fn publish(&self, _: NonNull<u8>, _: usize) -> Result<(), MemoryError> {
        crate::native_dma::vtd::publish();
        Ok(())
    }
}

// SAFETY: the boot processor alone, outside interrupts, reaches the unit;
// its pages are the native allocator's zeroed write-back RAM, which the
// unit reaches coherently; the clock is the invariant TSC.
unsafe impl ColdPlatform for Platform {
    type Access<'a> = Access;
    fn enter(&self) -> Result<Self::Access<'_>, DmaError> {
        if !on_boot_processor() {
            return Err(DmaError::IommuUnavailable);
        }
        Ok(Access)
    }
    fn clock(&self) -> Clock {
        Clock {
            ticks_per_microsecond: (self.tsc_hz / 1_000_000).max(1),
        }
    }
    fn physical_bits(&self) -> u8 {
        self.physical_bits
    }
    fn admit_payload(&self, pages: &DmaPages, _: Direction) -> Result<bool, DmaError> {
        if pages.cache_attribute() != CacheAttribute::WriteBack {
            return Err(DmaError::CoherenceUnavailable);
        }
        Ok(true)
    }
    unsafe fn sync(
        &self,
        _: &DmaPages,
        _: Range<usize>,
        _: Direction,
        _: bool,
    ) -> Result<(), DmaError> {
        // Device DMA to write-back RAM is snooped; the fence drains
        // write-combining buffers before the device reads.
        crate::native_dma::vtd::publish();
        Ok(())
    }
}

/// Memory the window maps that no allocator owns: the drivers' DMA region
/// and firmware reserved regions. The window never maps it for the CPU.
struct Borrowed {
    pages: Vec<u64>,
}

// SAFETY: the pages are kept for the boot by their owner (the loader's DMA
// allocation, firmware reservations); `cpu_base` is the physmap address
// of the first page, which the unit's tables never dereference.
unsafe impl PageBacking for Borrowed {
    fn cpu_base(&self) -> NonNull<u8> {
        NonNull::new(crate::layout::physical(self.pages[0]) as *mut u8).expect("physmap")
    }
    fn physical_pages(&self) -> &[u64] {
        &self.pages
    }
    fn page_shift(&self) -> u8 {
        12
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}

fn borrowed(range: &Range<u64>, physical_bits: u8) -> Option<DmaPages> {
    let range = remapping::window_range(range, physical_bits)?;
    let count = usize::try_from((range.end - range.start) / PAGE).ok()?;
    let bytes = count.checked_mul(PAGE as usize)?;
    let mut pages = Vec::new();
    pages.try_reserve_exact(count).ok()?;
    pages.extend(range.step_by(PAGE as usize));
    PinnedPages::new(Box::new(Borrowed { pages }), bytes, PAGE as usize)
        .ok()
        .map(DmaPages::from)
}

/// The present requesters an IVMD names.
fn named(scope: MemoryScope, segment: u16, present: &[Present]) -> Vec<u16> {
    present
        .iter()
        .map(|function| function.rid)
        .filter(|&rid| match scope {
            MemoryScope::AllDevices => true,
            MemoryScope::Device(id) => id.segment == segment && id.device_id == rid,
            MemoryScope::Range { first, last } => {
                first.segment == segment && (first.device_id..=last.device_id).contains(&rid)
            }
        })
        .collect()
}

pub(super) struct Taken {
    unit: Rc<RefCell<Unit<Platform, ObservedConfig>>>,
    segment: u16,
    own: Address,
    claims: Option<RefCell<Vec<(u16, bool)>>>,
    requesters: RefCell<Vec<u16>>,
}

/// Read the unit's identity and capability list from its original ECAM page.
/// # Safety
/// This boot owns the function's bus through inspection and unit retirement.
/// Firmware, SMM and other native writers cannot alter the function.
unsafe fn config(mmio: &native_mmio::Source, address: Address) -> Result<Function<ObservedConfig>> {
    // SAFETY: forwarded; this boot owns the original function for inspection.
    let (window, mapping) = unsafe { mmio.observe_config_page(address) }
        .map_err(|error| refuse!("IOMMU ECAM mapping: {error}", ?error))?;
    // SAFETY: the source issued this exact original UC read-only page;
    // the caller keeps configuration and decode stable through retirement.
    let config = match unsafe { ObservedConfig::attach(address, window, mapping) } {
        Ok(config) => config,
        Err((error, mut mapping)) => {
            // SAFETY: the rejected attachment published no view or reader.
            unsafe { mapping.retire() }
                .map_err(|error| refuse!("IOMMU ECAM retirement: {error}", ?error))?;
            return Err(refuse!("IOMMU ECAM geometry: {error}", ?error));
        }
    };
    match Function::new(address, config) {
        Ok(function) => Ok(function),
        Err(mut refusal) => {
            refusal
                .config
                .retire()
                .map_err(|error| refuse!("IOMMU ECAM retirement: {error}", ?error))?;
            let error = refusal.reason;
            Err(refuse!("IOMMU function observation: {error}", ?error))
        }
    }
}

/// Inspect the unit at `function` with its register aperture mapped.
///
/// # Safety
/// The mount owns the unit's function and registers.
unsafe fn inspect(
    mmio: &native_mmio::Source,
    mut function: Function<ObservedConfig>,
    base: u64,
    ivrs: &Ivrs<'_>,
) -> Result<FunctionInspection<ObservedConfig>> {
    let mut refusals = Vec::new();
    for bytes in APERTURES {
        let span =
            PhysicalSpan::new(base, bytes).map_err(|error| refuse!("span {error}", ?error))?;
        // SAFETY: forwarded; the IVHD names these registers.
        let resource = match unsafe { mmio.claim_platform(span) } {
            Ok(resource) => resource,
            Err(error) => {
                refusals.push(format!("{bytes:#x} bytes: {error:?}"));
                continue;
            }
        };
        let mapping = mmio
            .authority()
            .map(
                resource.clone(),
                0,
                bytes as usize,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
            .map_err(|error| refuse!("mapping {error}", ?error))?;
        let inputs = Inputs {
            function,
            mappings: vec![mapping],
        };
        // SAFETY: forwarded: the function and registers are the mount's.
        match unsafe { FunctionInspection::inspect(inputs, ivrs) } {
            Ok(inspection) => return Ok(inspection),
            Err((error, inputs)) => {
                refusals.push(format!("{bytes:#x} bytes: {error:?}"));
                function = inputs.function;
                // Release the aperture so the next size can claim it.
                for mut mapping in inputs.mappings {
                    // SAFETY: the refused inspection was the mapping's only use.
                    unsafe { mapping.retire() }
                        .map_err(|error| refuse!("unmap {error}", ?error))?;
                }
                let authority = mmio.authority();
                authority
                    .register_resource(resource)
                    .map_err(|refusal| refusal.error)
                    .and_then(|id| authority.unregister_resource(id))
                    .map_err(|error| refuse!("release {error}", ?error))?;
            }
        }
    }
    function
        .config()
        .retire()
        .map_err(|error| refuse!("IOMMU ECAM retirement: {error}", ?error))?;
    Err(refuse!(
        "its function or registers did not match the IVRS: {refusals}",
        ?refusals
    ))
}

/// What [`take`] did with the IVRS's units.
pub(super) struct Outcome {
    pub(super) units: Vec<Taken>,
    /// Whether the units started blocked as one fabric, and whether that
    /// fabric is complete; none when they did not start blocked.
    pub(super) fabric: Option<bool>,
    /// Whether a unit was left in a state no proof covers: it went cold and
    /// then did not stop.
    pub(super) uncertain: bool,
}

/// A unit brought up cold, whose coverage the policy now decides on.
struct Cold {
    unit: Unit<Platform, ObservedConfig>,
    segment: u16,
    base: u64,
    own: Address,
    decision: core::result::Result<Vec<u16>, remapping::Leave>,
    reserved: Vec<(u16, Range<u64>)>,
}

/// Stop a cold unit the policy does not take and give back its function's
/// configuration page and its register mapping: a unit dropped with them
/// keeps both claimed, and the check that reopens the PCI bridges then
/// cannot map the configuration space. False when it did not stop or a
/// mapping did not retire.
fn retire(mut unit: Unit<Platform, ObservedConfig>) -> bool {
    // SAFETY: no requester was attached and the unit blocks nothing it
    // translated; retiring stops it.
    if unsafe { unit.retire() }.is_err() {
        return false;
    }
    let Some(mut inputs) = unit.into_inputs() else {
        return false;
    };
    let mut retired = true;
    for mapping in &mut inputs.mappings {
        // SAFETY: the stopped unit was the mapping's only user.
        retired &= unsafe { mapping.retire() }.is_ok();
    }
    retired & inputs.function.config().retire().is_ok()
}

/// Take every unit of `table` (an IVRS) the policy allows, each in the
/// mode [`initial::modes`] gives it from the drivers of the `requesters`
/// behind it.
///
/// # Safety
/// As for [`super::Remappers::take`].
#[expect(
    clippy::too_many_arguments,
    reason = "the IVRS takeover joins the census, the drivers' pool and the platform's proof"
)]
pub(super) unsafe fn take(
    table: &[u8],
    inventories: &[(u16, Vec<Present>)],
    requesters: &[initial::Requester],
    drivers: &Range<u64>,
    mmio: &native_mmio::Source,
    inactive_firmware_units: Option<&InactiveFirmwareUnits>,
    tsc_hz: u64,
    physical_bits: u8,
) -> Outcome {
    let mut outcome = Outcome {
        units: Vec::new(),
        fabric: None,
        uncertain: false,
    };
    let ivrs = match Ivrs::parse(table, MAXIMUM_BLOCKS) {
        Ok(ivrs) => ivrs,
        Err(error) => {
            output::arguments(format_args!(
                "UNSUPPORTED host IVRS unreadable ({error:?}): host DMA stays untranslated\n"
            ));
            return outcome;
        }
    };
    // Off now, whether the firmware left them so or the boot turned them
    // off at its exit; found off is what a blocked start needs.
    let units_off = inactive_firmware_units.is_some_and(|units| units.off_amd(&ivrs));
    let found_off = inactive_firmware_units.is_some_and(|units| units.matches_amd(&ivrs));
    // Requesters may start blocked only from a proven firmware state and
    // with no reserved region a requester still uses.
    let blockable = found_off && ivrs.memory_definitions().next().is_none();
    let left = |base: u64, why: &dyn core::fmt::Debug| {
        output::arguments(format_args!(
            "HOST IOMMU AMD-Vi unit {base:#x} left untranslated: {why:?}\n"
        ));
    };
    // Bring each unit up cold, which reads its coverage, before deciding
    // how any starts.
    let mut cold = Vec::new();
    for description in ivrs.units() {
        let id = description.id();
        let base = description.mmio_address();
        let Some((_, present)) = inventories
            .iter()
            .find(|(segment, _)| *segment == id.segment)
        else {
            continue;
        };
        let address = Address {
            segment: id.segment,
            bus: (id.device_id >> 8) as u8,
            device: (id.device_id >> 3 & 31) as u8,
            function: (id.device_id & 7) as u8,
        };
        if blockable && !present.iter().any(|function| function.rid == id.device_id) {
            left(
                base,
                &"its function was absent from the original stopped PCI census",
            );
            continue;
        }
        // SAFETY: forwarded; no driver claims an IOMMU function.
        let function = match unsafe { config(mmio, address) } {
            Ok(function) => function,
            Err(error) => {
                left(base, &error);
                continue;
            }
        };
        // SAFETY: forwarded.
        let inspection = match unsafe { inspect(mmio, function, base, &ivrs) } {
            Ok(inspection) => inspection,
            Err(why) => {
                left(base, &why);
                continue;
            }
        };
        let platform = Platform {
            tsc_hz,
            physical_bits,
        };
        let limits = Limits {
            table_pages: 513,
            table_backing_bytes: 513 * PAGE as usize,
            mappings: 4096,
            wait_us: 100_000,
        };
        // SAFETY: forwarded: the firmware's translation was turned off at
        // ExitBootServices and no driver has started.
        let unit = match unsafe { Unit::cold(inspection, &ivrs, platform, limits) } {
            Ok(unit) => unit,
            Err(error) => {
                // A failure after its first publication leaves it quarantined.
                outcome.uncertain = true;
                left(base, &error);
                continue;
            }
        };
        let covered: Vec<u16> = present
            .iter()
            .map(|function| function.rid)
            .filter(|&rid| rid != id.device_id && unit.covers(id.segment, rid))
            .collect();
        let reserved: Vec<(u16, Range<u64>)> = ivrs
            .memory_definitions()
            .flat_map(|region| {
                named(region.scope(), id.segment, present)
                    .into_iter()
                    .map(move |rid| (rid, region.start()..region.end()))
            })
            .collect();
        let held: Vec<u16> = reserved.iter().map(|(rid, _)| *rid).collect();
        let decision = remapping::decide(&covered, &held, present, CLAIMED_DISPLAYS);
        cold.push(Cold {
            unit,
            segment: id.segment,
            base,
            own: address,
            decision,
            reserved,
        });
    }
    let candidates: Vec<Candidate> = cold
        .iter()
        .map(|unit| Candidate {
            segment: unit.segment,
            decision: unit.decision.clone(),
            blockable,
        })
        .collect();
    // The units' own functions are not requesters any unit must cover.
    let own: Vec<(u16, u16)> = ivrs
        .units()
        .map(|unit| (unit.id().segment, unit.id().device_id))
        .collect();
    let covering: Vec<initial::Requester> = requesters
        .iter()
        .filter(|requester| !own.contains(&(requester.segment, requester.rid)))
        .copied()
        .collect();
    let modes = initial::modes(&candidates, &covering, units_off);
    let fabric = modes.iter().all(|mode| *mode == Mode::Blocked);
    for (cold, mode) in cold.into_iter().zip(modes) {
        let Cold {
            mut unit,
            segment,
            base,
            own,
            decision,
            reserved,
        } = cold;
        let requesters = match (decision, mode) {
            (Ok(requesters), Mode::Blocked | Mode::Window) => requesters,
            (_, Mode::Left(Left::Native { segment, rid })) => {
                output::arguments(format_args!(
                    "HOST IOMMU AMD-Vi unit {base:#x} left untranslated: {} attaches only natively, which a taken unit beside the drivers' window refuses\n",
                    super::address(segment, rid)
                ));
                outcome.uncertain |= !retire(unit);
                continue;
            }
            (Err(why), _) | (_, Mode::Left(Left::Policy(why))) => {
                left(base, &why);
                if !retire(unit) {
                    outcome.uncertain = true;
                    left(base, &"and it did not stop");
                }
                continue;
            }
        };
        let claims = if mode == Mode::Blocked {
            // Publish no shared window. Retain the real complete stopped
            // cohort and verify each original DTE before the unit-wide drain.
            let checked = requesters
                .iter()
                .try_for_each(|&rid| {
                    unit.admit_requester(rid)?;
                    unit.check_blocked_requester(rid).map_err(Error::Dma)
                })
                .and_then(|()| unit.drain_posted_writes().map_err(Error::Dma));
            if let Err(error) = checked {
                left(base, &error);
                outcome.uncertain |= !retire(unit);
                continue;
            }
            output::arguments(format_args!(
                "HOST IOMMU AMD-Vi unit {base:#x} blocked and drained {} initial requesters\n",
                requesters.len()
            ));
            Some(RefCell::new(
                requesters.iter().map(|&rid| (rid, false)).collect(),
            ))
        } else {
            let mut window = vec![drivers.clone()];
            window.extend(
                reserved
                    .iter()
                    .filter(|(rid, _)| requesters.contains(rid))
                    .map(|(_, range)| range.clone()),
            );
            let Some(ranges) = window
                .iter()
                .map(|range| borrowed(range, physical_bits))
                .collect::<Option<Vec<_>>>()
            else {
                left(
                    base,
                    &"a DMA window range is empty, out of bounds or cannot be allocated",
                );
                outcome.uncertain |= !retire(unit);
                continue;
            };
            // SAFETY: forwarded: the requesters DMA only to the drivers' region
            // and their reserved regions until they attach.
            if let Err(error) = unsafe { unit.window(&requesters, ranges) } {
                left(base, &error);
                outcome.uncertain |= !retire(unit);
                continue;
            }
            output::arguments(format_args!(
                "HOST IOMMU AMD-Vi unit {base:#x} maps the drivers' DMA pool and {} reserved regions for {} requesters\n",
                window.len() - 1,
                requesters.len()
            ));
            None
        };
        outcome.units.push(Taken {
            unit: Rc::new(RefCell::new(unit)),
            segment,
            own,
            claims,
            requesters: RefCell::new(requesters),
        });
    }
    let taken = &outcome.units;
    let complete = fabric
        && !taken.is_empty()
        && taken.len() == ivrs.units().count()
        && inventories.iter().all(|(segment, functions)| {
            functions.iter().all(|function| {
                let address = super::address(*segment, function.rid);
                taken.iter().any(|unit| unit.own == address)
                    || taken
                        .iter()
                        .filter(|unit| unit.covers(*segment, function.rid))
                        .count()
                        == 1
            })
        });
    let started_blocked = taken.iter().any(|unit| unit.claims.is_some());
    outcome.fabric = started_blocked.then_some(complete);
    outcome
}

impl Taken {
    pub(super) fn read_original_config(
        &self,
        address: Address,
        offset: u16,
        width: u8,
    ) -> Option<Result<u32, super::ConfigError>> {
        (self.own == address).then(|| {
            self.unit
                .try_borrow()
                .map_err(|_| super::ConfigError::before_effect(super::ConfigFailure::Busy))?
                .read_original_config(offset, width)
        })
    }

    pub(super) fn pin_direct_delivery(&self) -> Result<DirectDelivery, Error> {
        self.unit
            .try_borrow()
            .map_err(|_| Error::Busy)?
            .pin_direct_delivery()
    }

    /// Full IVRS routing coverage, including still-blocked future arrivals.
    pub(super) fn routes(&self, segment: u16, rid: u16) -> Result<bool, Error> {
        let unit = self.unit.try_borrow().map_err(|_| Error::Busy)?;
        Ok(unit.covers(segment, rid))
    }

    pub(super) fn covers(&self, segment: u16, rid: u16) -> bool {
        self.segment == segment && self.requesters.borrow().contains(&rid)
    }

    /// Whether its requesters started in the drivers' window rather than
    /// blocked.
    pub(super) fn windowed(&self) -> bool {
        self.claims.is_none()
    }

    /// Cover requester `rid`, which arrived below a covered bridge. Its
    /// device table entry is left as it was until it attaches.
    pub(super) fn admit(&self, rid: u16) -> Result<(), Error> {
        self.unit
            .try_borrow_mut()
            .map_err(|_| Error::Busy)?
            .admit_requester(rid)?;
        let mut requesters = self.requesters.borrow_mut();
        if !requesters.contains(&rid) {
            requesters.push(rid);
        }
        Ok(())
    }

    /// Claim one original blocked entry for this exact parked function.
    pub(super) fn preparation(
        &self,
        address: Address,
        lines: native_mmio::InitialPciLines,
    ) -> Result<ColdRoot, DmaError> {
        let rid = super::requester(address);
        if !on_boot_processor() || !self.covers(address.segment, rid) {
            return Err(DmaError::IommuUnavailable);
        }
        let mut claims = self
            .claims
            .as_ref()
            .ok_or(DmaError::DrainUnavailable)?
            .try_borrow_mut()
            .map_err(|_| DmaError::IommuUnavailable)?;
        let claimed = claims
            .iter_mut()
            .find(|(member, _)| *member == rid)
            .ok_or(DmaError::IommuUnavailable)?;
        if claimed.1 {
            return Err(DmaError::IommuUnavailable);
        }
        let root = ColdRoot {
            address,
            unit: self.unit.clone(),
            _lines: lines,
        };
        root.check()?;
        claimed.1 = true;
        Ok(root)
    }

    /// A domain of its own for `binding`'s requester.
    pub(super) fn domain(&self, binding: RequesterBinding) -> Result<Arc<dyn DmaDomain>, Error> {
        attach_domain(&self.unit, binding).map(|domain| domain as Arc<dyn DmaDomain>)
    }
}

fn attach_domain(
    unit: &Rc<RefCell<Unit<Platform, ObservedConfig>>>,
    binding: RequesterBinding,
) -> Result<Arc<Domain>, Error> {
    if !on_boot_processor() {
        return Err(Error::Dma(DmaError::IommuUnavailable));
    }
    let original = unit.clone();
    let mut unit = unit.try_borrow_mut().map_err(|_| Error::Busy)?;
    // SAFETY: the caller owns the paired stopped binding and completed the
    // original root drain before changing its DTE; routing remains frozen.
    let requester = unsafe { unit.attach_binding(binding) }?;
    Ok(Arc::new(Domain {
        inner: ManuallyDrop::new(RefCell::new(Inner {
            _unit: original,
            requester,
            mappings: Vec::new(),
            next: 1,
        })),
    }))
}

pub(super) struct ColdRoot {
    address: Address,
    unit: Rc<RefCell<Unit<Platform, ObservedConfig>>>,
    _lines: native_mmio::InitialPciLines,
}
impl ColdRoot {
    pub(super) fn check(&self) -> Result<(), DmaError> {
        self.unit
            .try_borrow()
            .map_err(|_| DmaError::IommuUnavailable)?
            .check_blocked_requester(super::requester(self.address))
    }
}
// SAFETY: the paired original IVRS unit and blocked table and DMA backing are retained.
// It is process-local and every operation checks BSP/non-IRQ execution. The
// consuming receipt supplies independent endpoint/IRQ/work/bypass retirement;
// failure retains hardware resources through the unit's native owners.
unsafe impl stela_drivers::bus::pci::requester::preparation::Root for ColdRoot {
    fn drain(&self) -> Result<(), DmaError> {
        if !on_boot_processor() {
            return Err(DmaError::IommuUnavailable);
        }
        let unit = self
            .unit
            .try_borrow()
            .map_err(|_| DmaError::IommuUnavailable)?;
        unit.drain_initial_requester(super::requester(self.address))
    }
    unsafe fn bind(
        &self,
        binding: RequesterBinding,
    ) -> Result<Box<dyn stela_drivers::bus::pci::requester::preparation::AttachmentBackend>, DmaError>
    {
        if !on_boot_processor() || binding.address() != self.address {
            return Err(DmaError::IommuUnavailable);
        }
        // The Root contract supplies this exact paired stopped receipt,
        // completed original-path drain and unchanged routing/config epoch.
        let domain = attach_domain(&self.unit, binding).map_err(failed)?;
        Ok(Box::new(Attachment { domain }))
    }
}

struct Attachment {
    domain: Arc<Domain>,
}
// SAFETY: the original process-local requester and full unit/window graph
// remain in this exact domain. Current owner/context guards precede access.
// Backend detach blocks all aliases, completes invalidation and releases the
// shared configuration binding only after success. Retired requesters reject
// all later methods; failure/Drop keeps uncertain trees and their binding.
unsafe impl stela_drivers::bus::pci::requester::preparation::AttachmentBackend for Attachment {
    fn irq_owner(
        &mut self,
        _requester: &stela_drivers::bus::pci::requester::RequesterId,
        _config: Option<&stela_drivers::bus::pci::owned::ConfigRetention>,
    ) -> Result<Option<Box<dyn stela_drivers::bus::irq::posted_msi::RouteOwner>>, DmaError> {
        // Explicit capability refusal: no original boot root/context and exact
        // source grant have been supplied to this attached owner. A retained
        // DMA root, SID, numeric message or fresh BDF lookup cannot mint one.
        Ok(None)
    }

    fn domain(&self) -> Arc<dyn DmaDomain> {
        self.domain.clone()
    }
    unsafe fn detach(
        &mut self,
    ) -> Result<(), stela_drivers::bus::pci::requester::preparation::DetachError> {
        let mut inner = self.domain.inner()?;
        if !inner.mappings.is_empty() {
            return Err(
                stela_drivers::bus::pci::requester::preparation::DetachError::Unexposed(
                    DmaError::MappingFailed,
                ),
            );
        }
        // SAFETY: paired driver supplies halt and payload/IRQ/work drainage
        // under the retained root/epoch. Both mapping inventories refuse live
        // leases before DTE effects; wrapper inventory is empty above.
        unsafe { inner.requester.detach() }.map_err(|error| {
            stela_drivers::bus::pci::requester::preparation::DetachError::Uncertain(failed(error))
        })
    }
}

struct Inner {
    _unit: Rc<RefCell<Unit<Platform, ObservedConfig>>>,
    requester: Requester<Platform, ObservedConfig>,
    mappings: Vec<(DomainMapping, Mapping)>,
    next: u64,
}

/// A requester's own AMD-Vi domain, reached from the boot processor alone.
struct Domain {
    inner: ManuallyDrop<RefCell<Inner>>,
}

impl Drop for Domain {
    fn drop(&mut self) {
        if on_boot_processor() {
            // SAFETY: the owner processor, outside interrupts, has exclusive
            // final access. Off-owner release keeps the process-local Rc
            // graph intact rather than racing its owner's reference counts.
            unsafe { ManuallyDrop::drop(&mut self.inner) };
        }
    }
}

// SAFETY: methods and final release touch the process-local requester only
// on the boot processor outside an interrupt handler; other final releases
// retain the complete graph without accessing its non-atomic owners.
unsafe impl Send for Domain {}
// SAFETY: as above.
unsafe impl Sync for Domain {}

fn failed(error: Error) -> DmaError {
    match error {
        Error::Dma(error) => error,
        _ => DmaError::MappingFailed,
    }
}

impl Domain {
    fn inner(&self) -> Result<core::cell::RefMut<'_, Inner>, DmaError> {
        if !on_boot_processor() {
            return Err(DmaError::IommuUnavailable);
        }
        self.inner
            .try_borrow_mut()
            .map_err(|_| DmaError::IommuUnavailable)
    }
}

// SAFETY: the requester's own AMD-Vi domain maps the ordered pages with the
// direction's rights and completes the invalidation before map returns.
unsafe impl DmaDomain for Domain {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        direction: Direction,
        address_limit: u64,
    ) -> Result<DomainMapping, DmaError> {
        let mut inner = self.inner()?;
        let mapping = inner
            .requester
            .map(pages.clone(), direction, address_limit)
            .map_err(failed)?;
        let info = DomainMapping {
            id: inner.next,
            address: mapping.address(),
            bytes: mapping.bytes(),
        };
        inner.next += 1;
        inner.mappings.push((info, mapping));
        Ok(info)
    }
    unsafe fn unmap(&self, mapping: DomainMapping) -> Result<(), DmaError> {
        let mut inner = self.inner()?;
        let index = inner
            .mappings
            .iter()
            .position(|(info, _)| *info == mapping)
            .ok_or(DmaError::Unmapped)?;
        let Inner {
            requester,
            mappings,
            ..
        } = &mut *inner;
        // SAFETY: forwarded: the device's accesses to it have completed.
        unsafe { requester.unmap(&mappings[index].1) }.map_err(failed)?;
        mappings.swap_remove(index);
        Ok(())
    }
    unsafe fn drain_posted_writes(&self) -> Result<(), DmaError> {
        let inner = self.inner()?;
        inner.requester.drain_posted_writes()
    }
    unsafe fn sync_for_device(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        let inner = self.inner()?;
        let (_, live) = inner
            .mappings
            .iter()
            .find(|(info, _)| *info == mapping)
            .ok_or(DmaError::Unmapped)?;
        // SAFETY: forwarded.
        unsafe { inner.requester.sync(live, range, false) }.map_err(failed)
    }
    unsafe fn sync_for_cpu(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        let inner = self.inner()?;
        let (_, live) = inner
            .mappings
            .iter()
            .find(|(info, _)| *info == mapping)
            .ok_or(DmaError::Unmapped)?;
        // SAFETY: forwarded.
        unsafe { inner.requester.sync(live, range, true) }.map_err(failed)
    }
}
