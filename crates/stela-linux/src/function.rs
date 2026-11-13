//! A physical PCI function presented to Linux, which then binds any driver
//! matching it (`compat/linux/kernel/pci_host.c`). Configuration space and DMA
//! stay Stela's: the function's owner placed it, and Linux reaches both through
//! the table here. Domain errors retain real allocation pins and stop at the
//! terminal Linux boundary before callers can reuse DMA-visible memory.
use super::catalogue::{self, Authority, PciAuthority};
use super::owner::Errno;
use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec::Vec};
use core::{
    ffi::{c_char, c_int, c_uint, c_void},
    marker::PhantomData,
    mem::ManuallyDrop,
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering},
};
use stela_driver_base::bus::{
    dma::{
        mapping::{Direction, DmaDomain, DmaError, DomainMapping, QuarantineStatus},
        memory::CacheAttribute,
        pages::DmaPages,
    },
    pci::{ConfigEffect, ConfigError, ConfigFailure, ConfigSpace},
};

/// PCI base address registers.
const BARS: usize = 6;
/// Linux's `DMA_MAPPING_ERROR`.
const MAPPING_ERROR: u64 = u64::MAX;
const PAGE_SHIFT: u8 = 12;
const PAGE_BYTES: u64 = 1 << PAGE_SHIFT;

const PCIBIOS_BAD_REGISTER_NUMBER: c_int = 0x87;
const PCIBIOS_SET_FAILED: c_int = 0x88;
const EIO: Errno = -5;

static QUARANTINED_MAPPINGS: AtomicU64 = AtomicU64::new(0);
static QUARANTINED_BYTES: AtomicU64 = AtomicU64::new(0);

/// Linux DMA leases kept without acknowledged domain removal. These counters
/// are cumulative; no reset or reclamation is inferred from quarantine.
pub fn dma_quarantine_status() -> QuarantineStatus {
    QuarantineStatus {
        mappings: QUARANTINED_MAPPINGS.load(Ordering::Relaxed),
        bytes: QUARANTINED_BYTES.load(Ordering::Relaxed),
    }
}

fn count_quarantine(mappings: u64, bytes: u64) {
    let _ = QUARANTINED_MAPPINGS.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(mappings))
    });
    let _ = QUARANTINED_BYTES.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(bytes))
    });
}

fn quarantine<T>(resources: T, mappings: u64, bytes: u64) {
    count_quarantine(mappings, bytes);
    core::mem::forget(resources);
}

/// Exact Rust cause kept before mapping the original C MSI ABI result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MsiError {
    Config(ConfigError),
    Native(Errno),
}
impl From<ConfigError> for MsiError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}
/// The function's owner.
pub trait Host {
    type Config: ConfigSpace;
    fn config(&mut self) -> &mut Self::Config;
    /// Move the function's interrupt from its line to a message.
    fn enable_msi(&mut self) -> Result<(), MsiError>;
    fn disable_msi(&mut self) -> Result<(), MsiError>;
}

/// A memory BAR where its owner placed it. `flags` holds Linux's `IORESOURCE_*`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Region {
    pub start: u64,
    pub size: u64,
    pub flags: u64,
}

/// Where a function sits.
#[derive(Clone, Copy, Default)]
pub struct Placement {
    pub bus: u8,
    pub devfn: u8,
    pub irq: u32,
    /// The highest bus address `domain` hands out.
    pub dma_limit: u64,
    pub regions: [Region; BARS],
}

/// A function's MSI capability (PCI Local Bus 3.0 6.8.1), one message at most.
#[derive(Clone, Copy)]
pub struct Msi {
    capability: u16,
}

impl Msi {
    const CONTROL: u16 = 2;
    const ADDRESS: u16 = 4;
    const ENABLE: u16 = 1;
    const MULTIPLE: u16 = 7 << 4;
    const WIDE: u16 = 1 << 7;

    /// The capability at `capability`.
    pub const fn at(capability: u16) -> Self {
        Self { capability }
    }

    fn offset(self, delta: u16, width: usize) -> Result<u16, ConfigError> {
        if let Some(offset) = self.capability.checked_add(delta)
            && usize::from(offset) + width <= 4096
            && usize::from(offset).is_multiple_of(width)
        {
            return Ok(offset);
        }
        Err(ConfigError::before_effect(ConfigFailure::Access {
            offset: self.capability,
            width,
        }))
    }
    /// Read this capability's control word through its configuration owner.
    pub fn control<C: ConfigSpace>(self, config: &C) -> Result<u16, ConfigError> {
        config.read16(self.offset(Self::CONTROL, 2)?)
    }

    /// Stop the function sending it; refusal is no interrupt retirement proof.
    pub fn disable<C: ConfigSpace>(self, config: &mut C) -> Result<(), ConfigError> {
        let control = self.control(config)? & !Self::ENABLE;
        config.write16(self.offset(Self::CONTROL, 2)?, control)
    }

    /// Set one message, disabled. Stop at the first failed exact-width access;
    /// earlier writes are not rolled back or inferred to be retired.
    pub fn program<C: ConfigSpace>(
        self,
        config: &mut C,
        address: u64,
        data: u16,
    ) -> Result<(), ConfigError> {
        self.disable(config)?;
        let wide = self.control(config)? & Self::WIDE != 0;
        let at = self.offset(Self::ADDRESS, 4)?;
        config.write32(at, address as u32)?;
        if wide {
            config.write32(self.offset(Self::ADDRESS + 4, 4)?, (address >> 32) as u32)?;
        }
        config.write16(
            self.offset(Self::ADDRESS + if wide { 8 } else { 4 }, 2)?,
            data,
        )
    }

    /// Let the function send it only after an acknowledged control access.
    pub fn enable<C: ConfigSpace>(self, config: &mut C) -> Result<(), ConfigError> {
        let control = self.control(config)? & !Self::MULTIPLE | Self::ENABLE;
        config.write16(self.offset(Self::CONTROL, 2)?, control)
    }
}

/// `struct stela_linux_pci_function`.
#[repr(C)]
struct RawFunction {
    context: *mut c_void,
    read_config: unsafe extern "C" fn(*mut c_void, c_int, c_int, *mut u32) -> c_int,
    write_config: unsafe extern "C" fn(*mut c_void, c_int, c_int, u32) -> c_int,
    dma_map: unsafe extern "C" fn(*mut c_void, u64, usize, c_uint, bool) -> u64,
    dma_unmap: unsafe extern "C" fn(*mut c_void, u64, usize, c_uint),
    enable_msi: unsafe extern "C" fn(*mut c_void) -> c_int,
    disable_msi: unsafe extern "C" fn(*mut c_void),
    dma_limit: u64,
    bus: c_uint,
    devfn: c_uint,
    irq: c_uint,
    regions: [Region; BARS],
    release_context: Option<unsafe extern "C" fn(*mut c_void)>,
    enroll: Option<unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int>,
}

const _: () = assert!(size_of::<RawFunction>() == 240);
const _: () = assert!(core::mem::offset_of!(RawFunction, enroll) == 232);
const _: () = assert!(core::mem::offset_of!(RawFunction, release_context) == 224);

unsafe extern "C" {
    fn stela_linux_pci_attach(function: *const RawFunction, error: *mut c_int) -> *mut c_void;
    fn stela_linux_owner() -> *const super::owner::RawOwner;
    fn stela_linux_pci_bound(device: *const c_void) -> bool;
    fn stela_linux_pci_shutdown(device: *mut c_void);
    fn stela_linux_pci_remove_device(device: *mut c_void);
    fn stela_linux_pci_quarantined_functions() -> u64;
    fn stela_linux_fatal(message: *const c_char) -> !;
    fn stela_linux_page_dma_pin(physical: u64) -> *mut c_void;
    fn stela_linux_page_dma_unpin(pin: *mut c_void);
}

/// Functions whose final device reference ended outside their original
/// quiescent owner. Their C storage, host and DMA roots remain quarantined.
pub fn quarantined_functions() -> u64 {
    // SAFETY: this diagnostic only atomically reads a monotonic C counter.
    unsafe { stela_linux_pci_quarantined_functions() }
}

/// A reference to the Linux catalog's original provider allocation. This
/// retains the entire allocation even if Linux frees a noncompound tail.
struct PagePin(NonNull<c_void>);

impl Drop for PagePin {
    fn drop(&mut self) {
        // SAFETY: pins are released only inside an entered, serialized Linux
        // mapping callback, before map exposure or after successful unmap.
        unsafe { stela_linux_page_dma_unpin(self.0.as_ptr()) };
    }
}

struct Mapping {
    token: DomainMapping,
    _pins: Vec<PagePin>,
}

/// A mapping of pinned Linux allocations, by the address Linux was given.
/// Passthrough domains give one physical range the same address every time, so
/// each address keeps a stack of the mappings at it.
struct Mappings {
    domain: Arc<dyn DmaDomain>,
    limit: u64,
    live: BTreeMap<u64, Vec<Mapping>>,
}

impl Mappings {
    /// The offset of `physical` in its page, and the pages `size` bytes span.
    fn span(physical: u64, size: usize) -> Option<(u64, Vec<u64>)> {
        let offset = physical % PAGE_BYTES;
        let end = physical.checked_add(u64::try_from(size).ok()?.max(1))?;
        let pages = (physical - offset..end)
            .step_by(PAGE_BYTES as usize)
            .collect();
        Some((offset, pages))
    }

    fn pin(physical: &[u64]) -> Option<Vec<PagePin>> {
        let mut pins = Vec::new();
        pins.try_reserve_exact(physical.len()).ok()?;
        for &page in physical {
            // SAFETY: map is called in the serialized entered Linux owner.
            // C checks live PFN ownership and retains its provider allocation.
            pins.push(PagePin(NonNull::new(unsafe {
                stela_linux_page_dma_pin(page)
            })?));
        }
        Some(pins)
    }

    fn map(
        &mut self,
        physical: u64,
        size: usize,
        direction: Direction,
    ) -> Result<Option<u64>, DmaError> {
        let Some((offset, pins, pages)) = Self::span(physical, size)
            .and_then(|(offset, pages)| Some((offset, Self::pin(&pages)?, pages)))
        else {
            return Ok(None);
        };
        self.publish(offset, pages, pins, direction)
    }

    /// Maps memory Linux has no pages for, which its holder keeps instead.
    fn map_pageless(
        &mut self,
        physical: u64,
        size: usize,
        direction: Direction,
    ) -> Result<Option<u64>, DmaError> {
        let Some((offset, pages)) = Self::span(physical, size) else {
            return Ok(None);
        };
        self.publish(offset, pages, Vec::new(), direction)
    }

    fn publish(
        &mut self,
        offset: u64,
        physical: Vec<u64>,
        pins: Vec<PagePin>,
        direction: Direction,
    ) -> Result<Option<u64>, DmaError> {
        // SAFETY: every physical page's original allocation is retained by
        // pins, or by a pageless mapping's holder, until successful unmap, or
        // permanently on uncertain teardown.
        let Ok(pages) =
            (unsafe { DmaPages::from_physical(physical, PAGE_SHIFT, CacheAttribute::WriteBack) })
        else {
            return Ok(None);
        };
        // SAFETY: the real allocation pins and domain survive every uncertain
        // failure; Linux's DMA API quiesces the device before explicit unmap.
        let mapping = match unsafe {
            self.domain
                .map(&pages, direction, self.limit.min(MAPPING_ERROR - 1))
        } {
            Ok(mapping) => mapping,
            Err(error) => {
                // DmaError does not distinguish clean refusal from failed
                // invalidation. Keep the real pins and domain in either case.
                quarantine((pins, self.domain.clone()), 1, pages.bytes() as u64);
                return Err(error);
            }
        };
        let address = mapping.address + offset;
        self.live.entry(address).or_default().push(Mapping {
            token: mapping,
            _pins: pins,
        });
        Ok(Some(address))
    }

    fn unmap(&mut self, address: u64) -> Result<(), DmaError> {
        let Some(stack) = self.live.get_mut(&address) else {
            return Ok(());
        };
        let Some(mapping) = stack.last() else {
            return Ok(());
        };
        // SAFETY: Linux's DMA API unmaps only once the device is done.
        // An error leaves the token and provider pins intact.
        unsafe { self.domain.unmap(mapping.token) }?;
        stack.pop();
        if stack.is_empty() {
            self.live.remove(&address);
        }
        Ok(())
    }
}

impl Drop for Mappings {
    fn drop(&mut self) {
        if !self.live.is_empty() {
            // Driver removal is not proof that every domain invalidation
            // succeeded. Preserve active mappings, original provider pins and
            // domain roots; catalog retirement stays busy for these leases.
            let (count, bytes) =
                self.live
                    .values()
                    .flatten()
                    .fold((0u64, 0u64), |totals, mapping| {
                        (
                            totals.0.saturating_add(1),
                            totals.1.saturating_add(mapping.token.bytes as u64),
                        )
                    });
            quarantine(
                (core::mem::take(&mut self.live), self.domain.clone()),
                count,
                bytes,
            );
        }
    }
}

fn direction(linux: c_uint) -> Direction {
    match linux {
        1 => Direction::ToDevice,
        2 => Direction::FromDevice,
        _ => Direction::Bidirectional,
    }
}

/// Typed causes observed in this exact presentation, never a retirement receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConfigurationStatus {
    pub first: Option<ConfigError>,
    pub uncertain: Option<ConfigError>,
    pub msi: Option<MsiError>,
    pub msi_retirement_refused: bool,
}
impl ConfigurationStatus {
    fn terminal(self) -> bool {
        self.uncertain.is_some() || self.msi_retirement_refused
    }
}
fn pcibios(error: ConfigError) -> c_int {
    match error.reason {
        ConfigFailure::Access { .. } => PCIBIOS_BAD_REGISTER_NUMBER,
        _ => PCIBIOS_SET_FAILED,
    }
}
fn register(offset: c_int, size: c_int) -> Option<u16> {
    if !matches!(size, 1 | 2 | 4) || offset < 0 || offset > 4096 - size || offset & (size - 1) != 0
    {
        return None;
    }
    Some(offset as u16) // signed range and full function bounds were checked above
}
struct State<H> {
    host: H,
    mappings: Mappings,
    enrollment: Option<Box<Authority>>,
    configuration: ConfigurationStatus,
}

impl<H> State<H> {
    /// The original caller may ignore a PCIBIOS failure and use mapped MMIO or
    /// release suballocations. Stop before returning after any unacknowledged
    /// write; retaining pages alone would not prevent those effects.
    unsafe fn require_admission(&self) {
        if self.configuration.uncertain.is_some() {
            // SAFETY: this exact entered callback retains State/Host and cause.
            unsafe {
                stela_linux_fatal(
                    c"PCI configuration write failed without acknowledgement".as_ptr(),
                )
            };
        }
        if self.configuration.msi_retirement_refused {
            // SAFETY: void C completion cannot report this retained refusal.
            unsafe { stela_linux_fatal(c"MSI disable failed without proven retirement".as_ptr()) };
        }
    }
    unsafe fn config_failed(&mut self, error: ConfigError) -> c_int {
        self.configuration.first.get_or_insert(error);
        if matches!(error.effect, ConfigEffect::WriteMayHaveApplied { .. }) {
            self.configuration.uncertain.get_or_insert(error);
        }
        // SAFETY: same entered callback, with cause installed before the trap.
        unsafe { self.require_admission() };
        pcibios(error)
    }
}
unsafe extern "C" fn release_context<H>(context: *mut c_void) {
    // SAFETY: successful attach transferred this unique Box to C. The final
    // C device release invokes it once, only in the original quiescent owner;
    // no device reference can issue another callback after final release.
    let state = unsafe { Box::from_raw(context.cast::<State<H>>()) };
    if state.configuration.terminal() {
        // The outer C host_function/pci_dev must remain too: returning to its
        // void release caller would let that allocation be freed. Retain the
        // whole Rust graph before the same existing terminal diagnostic.
        let uncertain = state.configuration.uncertain.is_some();
        let _ = RETAINED_PRESENTATIONS.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(value.saturating_add(1))
        });
        core::mem::forget(state);
        // SAFETY: original entered final-release callback, with Rust State
        // retained and original C host allocation still held by its caller.
        unsafe {
            stela_linux_fatal(if uncertain {
                c"PCI configuration write failed without acknowledgement".as_ptr()
            } else {
                c"MSI disable failed without proven retirement".as_ptr()
            })
        };
    }
    drop(state);
}

/// # Safety
/// `context` is the state of an [`Attached`] Linux still holds, and Linux, which
/// runs in one context at a time, is in no other callback of it.
unsafe fn state<'a, H>(context: *mut c_void) -> &'a mut State<H> {
    // SAFETY: the caller's contract.
    unsafe { &mut *context.cast() }
}

unsafe extern "C" fn read_config<H: Host>(
    context: *mut c_void,
    offset: c_int,
    size: c_int,
    value: *mut u32,
) -> c_int {
    // SAFETY: the table's exact retained callback context.
    let state = unsafe { state::<H>(context) };
    // SAFETY: same entered callback; no original operation follows uncertainty.
    unsafe { state.require_admission() };
    let Some(offset) = register(offset, size) else {
        return PCIBIOS_BAD_REGISTER_NUMBER;
    };
    let config = state.host.config();
    let result = match size {
        1 => config.read8(offset).map(u32::from),
        2 => config.read16(offset).map(u32::from),
        4 => config.read32(offset),
        _ => unreachable!("validated exact width"),
    };
    match result {
        Ok(read) => {
            // SAFETY: original C gives a writable output. All-ones is real data.
            unsafe { *value = read };
            0
        }
        // SAFETY: actual typed failure and entire owner are retained first.
        Err(error) => unsafe { state.config_failed(error) },
    }
}
unsafe extern "C" fn write_config<H: Host>(
    context: *mut c_void,
    offset: c_int,
    size: c_int,
    value: u32,
) -> c_int {
    // SAFETY: the table's exact retained callback context.
    let state = unsafe { state::<H>(context) };
    // SAFETY: same entered callback; no original operation follows uncertainty.
    unsafe { state.require_admission() };
    let Some(offset) = register(offset, size) else {
        return PCIBIOS_BAD_REGISTER_NUMBER;
    };
    let config = state.host.config();
    let result = match size {
        1 => config.write8(offset, value as u8),
        2 => config.write16(offset, value as u16),
        4 => config.write32(offset, value),
        _ => unreachable!("validated exact width"),
    };
    match result {
        Ok(()) => 0,
        // SAFETY: a possibly applied write never returns into the C caller.
        Err(error) => unsafe { state.config_failed(error) },
    }
}

unsafe extern "C" fn dma_map<H: Host>(
    context: *mut c_void,
    physical: u64,
    size: usize,
    linux: c_uint,
    pageless: bool,
) -> u64 {
    // SAFETY: the table's context.
    let state = unsafe { state::<H>(context) };
    // SAFETY: exact entered callback, before DMA-visible effects.
    unsafe { state.require_admission() };
    let direction = direction(linux);
    let mapped = if pageless {
        state.mappings.map_pageless(physical, size, direction)
    } else {
        state.mappings.map(physical, size, direction)
    };
    match mapped {
        Ok(address) => address.unwrap_or(physical),
        // On PCs without an IOMMU, physical address is the unrestricted DMA address.
        // Returning physical avoids an immediate kernel trap if mappings.map is refused.
        Err(_) => physical,
    }
}

unsafe extern "C" fn dma_unmap<H: Host>(context: *mut c_void, address: u64, _: usize, _: c_uint) {
    // SAFETY: the table's context.
    let state = unsafe { state::<H>(context) };
    // SAFETY: uncertainty cannot authorize memory/suballocation reuse.
    unsafe { state.require_admission() };
    let _ = state.mappings.unmap(address);
}

unsafe extern "C" fn enable_msi<H: Host>(context: *mut c_void) -> c_int {
    // SAFETY: exact live callback state in its entered owner.
    let state = unsafe { state::<H>(context) };
    // SAFETY: prevent further endpoint effects after an uncertain access.
    unsafe { state.require_admission() };
    match state.host.enable_msi() {
        Ok(()) => 0,
        Err(error) => {
            state.configuration.msi.get_or_insert(error);
            match error {
                MsiError::Config(error) => {
                    // SAFETY: record exact cause, trapping first if write uncertain.
                    unsafe { state.config_failed(error) };
                    EIO
                }
                MsiError::Native(error) => {
                    if error < 0 {
                        error
                    } else {
                        EIO
                    }
                }
            }
        }
    }
}
unsafe extern "C" fn disable_msi<H: Host>(context: *mut c_void) {
    // SAFETY: exact live callback state in its entered owner.
    let state = unsafe { state::<H>(context) };
    // SAFETY: void C completion cannot retire an uncertain source.
    unsafe { state.require_admission() };
    if let Err(error) = state.host.disable_msi() {
        state.configuration.msi.get_or_insert(error);
        state.configuration.msi_retirement_refused = true;
        if let MsiError::Config(error) = error {
            state.configuration.first.get_or_insert(error);
            if matches!(error.effect, ConfigEffect::WriteMayHaveApplied { .. }) {
                state.configuration.uncertain.get_or_insert(error);
            }
        }
        // SAFETY: exact cause and entire Host graph retained before terminal report.
        unsafe { state.require_admission() };
    }
}

unsafe extern "C" fn enroll<H>(context: *mut c_void, device: *mut c_void) -> c_int {
    // SAFETY: the attach call retains this State; take ends the mutable borrow
    // before the generic catalogue can allocate or release any foreign object.
    let attached = unsafe { state::<H>(context) };
    // SAFETY: original registration cannot continue after uncertain configuration.
    unsafe { attached.require_admission() };
    let authority = attached.enrollment.take();
    let Some(authority) = authority else {
        return -22;
    };
    // SAFETY: C initialized this exact device before the first probe; this
    // canonical process owner still holds the original registration reference.
    match unsafe { catalogue::bind(device, authority) } {
        Ok(()) => 0,
        Err((authority, error)) => {
            // SAFETY: refusal took no state or authority; no callback overlaps this short restore.
            unsafe { state::<H>(context) }.enrollment = Some(authority);
            match error {
                catalogue::Error::Native(error) => error,
                _ => -22,
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttachError {
    Config(ConfigError),
    Msi(MsiError),
    Catalogue(catalogue::Error),
    Native(Errno),
}
static RETAINED_PRESENTATIONS: AtomicU64 = AtomicU64::new(0);
/// Refused presentation graphs abandoned without native retirement proof.
/// Observation only: this does not certify reclamation or native progress.
pub fn retained_presentations() -> u64 {
    RETAINED_PRESENTATIONS.load(Ordering::Relaxed)
}
struct Retained<T> {
    _value: ManuallyDrop<T>,
}
impl<T> Retained<T> {
    fn new(value: T) -> Self {
        Self {
            _value: ManuallyDrop::new(value),
        }
    }
}
impl<T> Drop for Retained<T> {
    fn drop(&mut self) {
        // Presentation refusal is not proof that a caller's native host was
        // unexposed. Keep the actual allocation and all source/domain roots.
        let _ = RETAINED_PRESENTATIONS.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(value.saturating_add(1))
        });
    }
}
/// The actual host/domain/authority remain retained on a refused presentation.
/// Drop keeps that graph: no H destructor or native retirement is inferred.
#[must_use = "presentation refusal retains actual native roots; inspect error and retained state"]
pub struct Rejected<H> {
    pub error: AttachError,
    _held: Retained<Box<Held<H>>>,
}
impl<H> core::fmt::Debug for Rejected<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rejected")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
enum Held<H> {
    Before {
        _host: H,
        _authority: Box<PciAuthority>,
    },
    Native {
        _state: Box<State<H>>,
    },
}

/// A function Linux can see. Drop unregisters it in the owner it was attached
/// in. Other C device references retain the host and DMA roots until the final
/// quiescent put in that owner; other final puts quarantine those resources.
pub struct Attached<H> {
    device: NonNull<c_void>,
    state: NonNull<State<H>>,
    _host: PhantomData<H>,
}

impl<H: Host> Attached<H> {
    /// # Safety
    /// In an entered Linux owner, on a Linux task, as a driver may bind here.
    /// That owner and its platform services outlive all escaped device
    /// references, including any quarantined final release. Refusal returns an
    /// typed cause while retaining the host graph; it proves no native retirement.
    pub unsafe fn new(
        host: H,
        domain: Arc<dyn DmaDomain>,
        placement: Placement,
    ) -> Result<Self, Rejected<H>>
    where
        H: 'static,
    {
        // SAFETY: unchanged legacy presentation contract; no canonical
        // catalogue authority is inferred for this pre-migration path.
        unsafe { Self::attach(host, domain, placement, None) }
    }

    /// Enroll exact original native source metadata before synchronous probe.
    ///
    /// # Safety
    /// H accesses the exact original OwnedConfig allocation/epoch validated
    /// when authority was made; its actual native grants stay kept. Its exact
    /// manifest target/catalogue were qualified for that same observed native
    /// function/board/source epoch by PciAuthority::new, never guessed labels.
    /// On this canonical owner's checked Linux task. No borrowed config/entered permit
    /// is retained in the authority or held across probe/callback/sleep.
    pub unsafe fn new_catalogued<P: super::owner::Platform, const N: usize>(
        kernel: &super::kernel::KernelOwner<P, N>,
        host: H,
        placement: Placement,
        authority: PciAuthority,
    ) -> Result<Self, Rejected<H>>
    where
        H: 'static,
    {
        // SAFETY: caller is entered; this checks the same actual canonical owner.
        if unsafe { stela_linux_owner() } != kernel.raw() {
            return Err(Rejected {
                error: AttachError::Native(-1),
                _held: Retained::new(Box::new(Held::Before {
                    _host: host,
                    _authority: Box::new(authority),
                })),
            });
        }
        let domain = match authority.domain() {
            Ok(domain) => domain,
            Err(error) => {
                return Err(Rejected {
                    error: AttachError::Catalogue(error),
                    _held: Retained::new(Box::new(Held::Before {
                        _host: host,
                        _authority: Box::new(authority),
                    })),
                });
            }
        };
        // SAFETY: caller's exact native source and canonical task proof.
        unsafe {
            Self::attach(
                host,
                domain,
                placement,
                Some(Box::new(Authority::Pci(authority))),
            )
        }
    }

    unsafe fn attach(
        host: H,
        domain: Arc<dyn DmaDomain>,
        placement: Placement,
        enrollment: Option<Box<Authority>>,
    ) -> Result<Self, Rejected<H>>
    where
        H: 'static,
    {
        let catalogued = enrollment.is_some();
        let state = Box::into_raw(Box::new(State {
            host,
            mappings: Mappings {
                domain,
                limit: placement.dma_limit,
                live: BTreeMap::new(),
            },
            enrollment,
            configuration: ConfigurationStatus::default(),
        }));
        let raw = RawFunction {
            context: state.cast(),
            read_config: read_config::<H>,
            write_config: write_config::<H>,
            dma_map: dma_map::<H>,
            dma_unmap: dma_unmap::<H>,
            enable_msi: enable_msi::<H>,
            disable_msi: disable_msi::<H>,
            dma_limit: placement.dma_limit,
            bus: placement.bus.into(),
            devfn: placement.devfn.into(),
            irq: placement.irq,
            regions: placement.regions,
            release_context: Some(release_context::<H>),
            enroll: catalogued.then_some(enroll::<H>),
        };
        let mut error = 0;
        // SAFETY: caller's attach contract; C copies the table and returns a
        // reference only after enrollment/publication. Refusal retains State.
        match NonNull::new(unsafe { stela_linux_pci_attach(&raw, &raw mut error) }) {
            Some(device) => Ok(Self {
                device,
                state: NonNull::new(state).expect("owned callback State"),
                _host: PhantomData,
            }),
            None => {
                // SAFETY: C refused before publication/probe and explicitly left
                // context ownership with this caller. Any enrolled record was
                // retired by its real device put before returning NULL.
                let state = unsafe { Box::from_raw(state) };
                Err(Rejected {
                    error: state
                        .configuration
                        .first
                        .map(AttachError::Config)
                        .or_else(|| state.configuration.msi.map(AttachError::Msi))
                        .unwrap_or(AttachError::Native(error)),
                    _held: Retained::new(Box::new(Held::Native { _state: state })),
                })
            }
        }
    }

    /// Inspect exact causes in this retained original presentation.
    ///
    /// # Safety
    /// Same entered serialized Linux owner, with no overlapping C callback.
    /// The live registration reference keeps the exact State allocation valid.
    pub unsafe fn configuration_status(&self) -> ConfigurationStatus {
        // SAFETY: caller's exact current/lifetime and callback exclusion contract.
        unsafe { self.state.as_ref() }.configuration
    }

    /// The `struct pci_dev`, for code that names it.
    pub fn device(&self) -> *mut c_void {
        self.device.as_ptr()
    }

    /// Has the function's driver stop its hardware, as at a power-off.
    ///
    /// # Safety
    /// In an entered Linux owner, on a task that may sleep.
    pub unsafe fn shutdown(&self) {
        // SAFETY: the caller's contract, over this function's live device.
        unsafe { stela_linux_pci_shutdown(self.device.as_ptr()) };
    }

    /// Whether a driver took the function.
    ///
    /// # Safety
    /// In an entered Linux owner.
    pub unsafe fn bound(&self) -> bool {
        // SAFETY: the caller's contract, over this function's live device.
        unsafe { stela_linux_pci_bound(self.device.as_ptr()) }
    }
}

impl<H> Drop for Attached<H> {
    fn drop(&mut self) {
        // SAFETY: the type's entered serialized owner contract; registration
        // still keeps the actual State before any remove/release operation.
        if unsafe { self.state.as_ref() }.configuration.terminal() {
            let _ =
                RETAINED_PRESENTATIONS.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    Some(value.saturating_add(1))
                });
            return; // actual C device/State/Host/IRQ/DMA graph remains owned
        }
        // SAFETY: the type's contract; removal unbinds the driver and drops
        // registration. C's final device release owns State destruction, so
        // outstanding device references retain their callback context.
        unsafe { stela_linux_pci_remove_device(self.device.as_ptr()) };
    }
}

#[cfg(test)]
mod tests;
