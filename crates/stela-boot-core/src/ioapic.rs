// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 1997, 1998, 1999, 2000, 2009 Ingo Molnar, Hajnalka Szabo
// Multiple IO-APIC support (C) 1999 Ken-ichi Yaku and Hidemi Kishimoto;
// further tested and cleaned up by Zach Brown and Ingo Molnar.
//! Legacy IOAPIC ownership and redirection ordering. Protocol references:
//! Linux a804c5742bff224d4cb4d25dd383554d598be32b, arch/x86/kernel/apic/io_apic.c
//! and arch/x86/include/asm/io_apic.h (Ingo Molnar and contributors), recorded
//! in NOTICE. CPU/IDT/AP bootstrap is never
//! owned here.
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    cell::{Cell, UnsafeCell},
    mem::ManuallyDrop,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
};
use stela_drivers::bus::irq::{
    ChipEoi, CpuTarget, FIRST_VECTOR, IrqError, LineRoute, Platform, Polarity, RegistryIdentity,
    Route, Source, Target, Trigger, VECTOR_COUNT,
    posted_msi::{self, NotificationDomain},
};

const MASK: u32 = 1 << 16;
const REMOTE_IRR: u32 = 1 << 14;
const DELIVERY: u32 = 1 << 12;
const DELIVERY_MODE: u32 = 7 << 8;
const LOWEST_PRIORITY: u32 = 1 << 8;
const CONFIG: u32 = 0xff | 7 << 8 | 1 << 11 | 1 << 13 | 1 << 15 | MASK;
const EXT_INT: u32 = 7 << 8;

/// Whether firmware may have left this redirection entry unmasked for the
/// initial containment to mask, as Linux's clear_IO_APIC masks every pin at
/// boot: fixed and lowest-priority routes with any vector (firmware leaves
/// ISA lines such as the i8042's at low vectors), and the 8259 virtual-wire
/// ExtINT route. SMI, NMI, INIT and reserved modes stay refused: they are
/// not ordinary device routes this containment may take over.
fn maskable_firmware_mode(low: u32) -> bool {
    matches!(low & DELIVERY_MODE, 0 | LOWEST_PRIORITY | EXT_INT)
}

/// Verify `line` against the firmware plan of the cohort unit whose
/// version-reported pins hold it, and return that unit's index. `spans`
/// and `routes` are the same complete original cohort in the same order;
/// a platform may have several IOAPICs (AMD places a second one behind the
/// southbridge's), so ownership comes from the GSI spans, never from unit 0.
pub fn verify_owned_line<R: Registers, P: Platform>(
    routing: &crate::madt::Routing,
    spans: &[(crate::madt::Unit, u16)],
    routes: &[FirmwareRoutes<R, P>],
    line: LineRoute,
) -> Result<usize, IrqError> {
    if spans.len() != routes.len() {
        return Err(IrqError::Route);
    }
    let owner = routing.owner(line, spans).map_err(|_| IrqError::Route)?;
    let index = spans
        .iter()
        .position(|(unit, _)| *unit == owner)
        .ok_or(IrqError::Route)?;
    let plan = &routes[index];
    if plan.unit.gsi_base != owner.gsi_base || plan.unit.id != owner.id {
        return Err(IrqError::Route);
    }
    plan.verify_line(line.gsi)?;
    Ok(index)
}
const MAX_PINS: usize = 120;

/// # Safety
/// Real IOREGSEL/IOWIN accesses to the one kept, root-stable UC mapping.
/// No other firmware/CPU/controller owner may touch the selector/window.
/// Every index passed here is <= 0xff. Operations must order MMIO.
pub unsafe trait Registers: Send + Sync {
    fn read(&self, index: u8) -> u32;
    fn write(&self, index: u8, value: u32);
    /// Actual direct MMIO EOI register, not an IOREGSEL/IOWIN index.
    /// The caller checked this controller's version is at least 0x20.
    fn write_eoi(&self, vector: u8);
}

pub struct Mmio(usize);
impl Mmio {
    /// # Safety
    /// `base` is an exclusive UC IOAPIC mapping of at least 68 bytes,
    /// aligned to 4 KiB and kept across all roots through final release or
    /// permanent quarantine. No WB/WC alias exists. No IRQ-context release.
    pub unsafe fn new(base: usize) -> Result<Self, IrqError> {
        if base == 0 || base & 4095 != 0 || base.checked_add(68).is_none() {
            return Err(IrqError::Route);
        }
        Ok(Self(base))
    }
}
// SAFETY: `new` admits only the aligned uncached IOAPIC window, kept mapped for the unit's
// life, and `Unit` serializes each selector/window pair with interrupts saved and disabled.
unsafe impl Registers for Mmio {
    fn read(&self, index: u8) -> u32 {
        // SAFETY: the unit lock and IRQ save serialize this selector/window pair on the owning CPU.
        unsafe {
            (self.0 as *mut u32).write_volatile(u32::from(index));
            ((self.0 + 16) as *const u32).read_volatile()
        }
    }
    fn write(&self, index: u8, value: u32) {
        // SAFETY: the unit lock and IRQ save serialize this selector/window pair on the owning CPU.
        unsafe {
            (self.0 as *mut u32).write_volatile(u32::from(index));
            ((self.0 + 16) as *mut u32).write_volatile(value);
        }
    }
    fn write_eoi(&self, vector: u8) {
        // SAFETY: original complete UC controller mapping; Unit serializes
        // access and checked version >=0x20 before this direct register write.
        unsafe { ((self.0 + 0x40) as *mut u32).write_volatile(u32::from(vector)) };
    }
}

/// Real contributors to one physical line, kept by the CPU-local pin source.
/// # Safety
/// Every physical sharer, SCI fixed/GPE source or PCI INTx contributor is
/// owned/kept here. Mask and stop acknowledge real device effects, drain
/// workers/timers/posted writes and exclude new causes until enable. No final
/// release in IRQ context. No missing sharer may keep this line asserted.
/// SharedHandlers membership and this source group must describe the same
/// pre-bound lifetime; dynamic join/remove is unavailable. IRQ publication
/// carries the controller and EOI endpoint separately from these owners.
pub unsafe trait Devices {
    fn mask(&mut self) -> Result<(), IrqError>;
    fn quiesce(&mut self) -> Result<(), IrqError>;
    /// # Safety
    /// The owned route and every callback are fully published.
    unsafe fn enable(&mut self) -> Result<(), IrqError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct State {
    pub masked: bool,
    pub remote_irr: bool,
    pub delivery_pending: bool,
}

/// The initial redirection words from one exact controller. This is a
/// prepublication plan and grants no ownership of the physical contributors.
pub struct FirmwareRoutes<R: Registers, P: Platform> {
    unit: Arc<Unit<R, P>>,
    entries: Vec<(u32, u32)>,
    phase: Cell<FirmwarePhase>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FirmwarePhase {
    Planned,
    Uncertain,
    Contained,
}

impl<R: Registers, P: Platform> FirmwareRoutes<R, P> {
    /// Mask the firmware routes on this same original controller.
    ///
    /// # Safety
    /// The original controller and firmware route exclusion used for the
    /// snapshot still hold. Keep all old contributors and their backing
    /// until their independent stop and delivery obligations are satisfied.
    pub unsafe fn contain(&self) -> Result<(), IrqError> {
        if self.phase.get() != FirmwarePhase::Planned {
            return Err(IrqError::Unavailable);
        }
        let unit = &self.unit;
        unit.platform.check_process()?;
        unit.domain.check().map_err(IrqError::Delivery)?;
        let _guard = unit.lock();
        for (pin, &entry) in (0..unit.pins as u8).zip(&self.entries) {
            if unit.firmware_entry(pin)? != entry {
                return Err(IrqError::Route);
            }
        }
        self.phase.set(FirmwarePhase::Uncertain);
        for (pin, &(low, high)) in (0..unit.pins as u8).zip(&self.entries) {
            if low & MASK != 0 {
                continue;
            }
            let masked = low | MASK;
            unit.registers.write(0x10 + pin * 2, masked);
            let actual = unit.firmware_entry(pin)?;
            if actual != (masked, high) {
                return Err(IrqError::Mask);
            }
        }
        self.check_masked()?;
        self.phase.set(FirmwarePhase::Contained);
        Ok(())
    }

    /// Check that every original entry is still masked and has no delivery
    /// pending at either the controller or the admitted receiving CPU.
    pub fn verify_contained(&self) -> Result<(), IrqError> {
        if self.phase.get() != FirmwarePhase::Contained {
            return Err(IrqError::Unavailable);
        }
        let unit = &self.unit;
        unit.platform.check_process()?;
        unit.domain.check().map_err(IrqError::Delivery)?;
        let _guard = unit.lock();
        self.phase.set(FirmwarePhase::Uncertain);
        self.check_masked()?;
        self.phase.set(FirmwarePhase::Contained);
        Ok(())
    }

    /// Verify the exact original masked route before giving this line to a
    /// new contributor. Other lines may already have independent owners.
    pub fn verify_line(&self, gsi: u32) -> Result<(), IrqError> {
        if self.phase.get() != FirmwarePhase::Contained {
            return Err(IrqError::Unavailable);
        }
        let unit = &self.unit;
        unit.platform.check_process()?;
        unit.domain.check().map_err(IrqError::Delivery)?;
        let pin = gsi.checked_sub(unit.gsi_base).ok_or(IrqError::Route)?;
        let &(low, high) = self.entries.get(pin as usize).ok_or(IrqError::Route)?;
        let _guard = unit.lock();
        if unit.firmware_entry(pin as u8)? != (low | MASK, high) {
            return Err(IrqError::Route);
        }
        Ok(())
    }

    fn check_masked(&self) -> Result<(), IrqError> {
        let unit = &self.unit;
        for (pin, &(low, high)) in (0..unit.pins as u8).zip(&self.entries) {
            if unit.firmware_entry(pin)? != (low | MASK, high) {
                return Err(IrqError::Route);
            }
        }
        Ok(())
    }
}

pub struct Unit<R: Registers, P: Platform> {
    registers: R,
    platform: P,
    domain: Arc<dyn NotificationDomain>,
    registry: RegistryIdentity,
    version: u8,
    id: u8,
    gsi_base: u32,
    pins: u16,
    held: AtomicBool,
    claims: UnsafeCell<[bool; MAX_PINS]>,
    epochs: UnsafeCell<[u64; MAX_PINS]>,
    next_epoch: UnsafeCell<u64>,
    quarantined: AtomicU64,
}
// SAFETY: all selector/window and claim access is serialized by IRQ-save lock.
// The platform confines operations to the owning CPU. Arc lifetime is held
// through every route or quarantined route; no hard-IRQ allocation/release.
unsafe impl<R: Registers, P: Platform> Sync for Unit<R, P> {}

impl<R: Registers, P: Platform> Unit<R, P> {
    /// # Safety
    /// Exclusive selector/window owner, matched MADT physical unit and
    /// ID. CPU adapter is initialized on the same BSP; local APIC EOI broadcast
    /// suppression is disabled and remains disabled through final retirement.
    /// No other CPU/SMM/firmware can program these redirection entries. Pin
    /// ownership/quiescence must separately be proved for each claim.
    /// `domain` is the actual retained CPU/root/controller-format owner, not
    /// a target-derived permission; it excludes live remapping-mode changes.
    pub unsafe fn attach(
        registers: R,
        platform: P,
        domain: Arc<dyn NotificationDomain>,
        registry: RegistryIdentity,
        id: u8,
        gsi_base: u32,
    ) -> Result<Arc<Self>, IrqError> {
        platform.check_process()?;
        domain.check().map_err(IrqError::Delivery)?;
        let saved = platform.save_and_disable();
        let version = registers.read(1);
        // SAFETY: `saved` came from `save_and_disable` on this CPU above.
        unsafe { platform.restore(saved) };
        if version == u32::MAX {
            return Err(IrqError::FailedRead);
        }
        // Versions below0x20 require mask/edge/restore for explicit EOI.
        // Later versions expose the direct EOI register. The MADT's ID is the
        // unit's, as Linux keeps it on x86-64; firmware need not program the
        // ID register to match.
        let pins = ((version >> 16) & 255) as u16 + 1;
        if pins as usize > MAX_PINS || gsi_base.checked_add(u32::from(pins)).is_none() {
            return Err(IrqError::Unsupported);
        }
        Ok(Arc::new(Self {
            registers,
            platform,
            domain,
            registry,
            version: version as u8,
            id,
            gsi_base,
            pins,
            held: AtomicBool::new(false),
            claims: UnsafeCell::new([false; MAX_PINS]),
            epochs: UnsafeCell::new([0; MAX_PINS]),
            next_epoch: UnsafeCell::new(1),
            quarantined: AtomicU64::new(0),
        }))
    }
    pub fn id(&self) -> u8 {
        self.id
    }
    pub fn gsi_base(&self) -> u32 {
        self.gsi_base
    }
    pub fn pins(&self) -> u16 {
        self.pins
    }
    pub fn quarantine_count(&self) -> u64 {
        self.quarantined.load(Ordering::Relaxed)
    }

    /// Snapshot every former route before the first RTE is changed.
    ///
    /// # Safety
    /// This is the exclusive initial controller handoff, with no driver
    /// claims or competing CPU, firmware or SMM route writers. The caller has
    /// excluded MADT IOAPIC NMI sources and verified the legacy RTE format.
    pub unsafe fn firmware_routes(self: &Arc<Self>) -> Result<FirmwareRoutes<R, P>, IrqError> {
        self.platform.check_process()?;
        self.domain.check().map_err(IrqError::Delivery)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(usize::from(self.pins))
            .map_err(|_| IrqError::Exhausted)?;
        let _guard = self.lock();
        for pin in 0..self.pins as u8 {
            let (low, high) = self.firmware_entry(pin)?;
            if low & MASK == 0 && !maskable_firmware_mode(low) {
                return Err(IrqError::Unsupported);
            }
            entries.push((low, high));
        }
        Ok(FirmwareRoutes {
            unit: self.clone(),
            entries,
            phase: Cell::new(FirmwarePhase::Planned),
        })
    }

    fn firmware_entry(&self, pin: u8) -> Result<(u32, u32), IrqError> {
        // SAFETY: the caller holds the selector and claims lock.
        if unsafe { (*self.claims.get())[usize::from(pin)] } {
            return Err(IrqError::Route);
        }
        let low = self.low(pin)?;
        let high = self.registers.read(0x11 + pin * 2);
        if high == u32::MAX {
            return Err(IrqError::FailedRead);
        }
        if low & (REMOTE_IRR | DELIVERY) != 0 {
            return Err(IrqError::Drain);
        }
        // An Intel PCH keeps an Extended Destination ID in bits 55:48, and
        // firmware leaves one in entries it masked. Such an entry delivers
        // nothing, and a claim writes the whole high word.
        let reserved = if low & MASK != 0 {
            0x0000_ffff
        } else {
            0x00ff_ffff
        };
        if low & !CONFIG != 0 || high & reserved != 0 {
            return Err(IrqError::Unsupported);
        }
        let vector = low as u8;
        if matches!(low & DELIVERY_MODE, 0 | LOWEST_PRIORITY)
            && vector >= 16
            && self.platform.pending(vector)?
        {
            return Err(IrqError::Drain);
        }
        Ok((low, high))
    }
    pub fn state(&self, gsi: u32) -> Result<State, IrqError> {
        self.platform.check_cpu()?;
        let pin = gsi
            .checked_sub(self.gsi_base)
            .filter(|p| *p < u32::from(self.pins))
            .ok_or(IrqError::Route)? as u8;
        let _guard = self.lock();
        let low = self.low(pin)?;
        Ok(State {
            masked: low & MASK != 0,
            remote_irr: low & REMOTE_IRR != 0,
            delivery_pending: low & DELIVERY != 0,
        })
    }
    /// Mask an unclaimed firmware route before another subsystem takes it.
    ///
    /// # Safety
    /// The caller has the exclusive handoff of this physical line and its
    /// former firmware consumers; no registered contributor owns it.
    pub unsafe fn mask_unclaimed(&self, gsi: u32) -> Result<(), IrqError> {
        self.platform.check_cpu()?;
        let pin = gsi
            .checked_sub(self.gsi_base)
            .filter(|pin| *pin < u32::from(self.pins))
            .ok_or(IrqError::Route)? as u8;
        let _guard = self.lock();
        // SAFETY: the selector/claims lock protects this pin's metadata.
        if unsafe { (*self.claims.get())[usize::from(pin)] } {
            return Err(IrqError::Route);
        }
        let low = self.low(pin)?;
        self.registers.write(0x10 + pin * 2, low | MASK);
        if self.low(pin)? & MASK == 0 {
            return Err(IrqError::Mask);
        }
        Ok(())
    }
    fn lock(&self) -> Guard<'_, R, P> {
        let saved = self.platform.save_and_disable();
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Guard { unit: self, saved }
    }
    fn low(&self, pin: u8) -> Result<u32, IrqError> {
        let raw = self.registers.read(0x10 + pin * 2);
        if raw == u32::MAX {
            Err(IrqError::FailedRead)
        } else {
            Ok(raw)
        }
    }
    /// # Safety
    /// On the owning CPU in process context. Validated MADT electrical route,
    /// no NMI/PIRQ alias and ownership
    /// of every physical sharer. All contributors are stopped/drained with no
    /// old firmware/CPU callback, pending interrupt or worker. The initially
    /// masked entry is not evidence of this grant. Complete group retirement
    /// is required before reconfiguration or membership changes.
    pub unsafe fn claim(
        self: &Arc<Self>,
        line: LineRoute,
        devices: Box<dyn Devices>,
    ) -> Result<Pin<R, P>, IrqError> {
        self.platform.check_process()?;
        // A level line drains through Remote IRR and its EOI. An edge line
        // (the ISA keyboard's and mouse's IRQ 1 and 12) has no Remote IRR:
        // it drains once Delivery Status is idle and the CPU holds its vector
        // neither requested nor in service, which `synchronize` checks.
        let pin = line
            .gsi
            .checked_sub(self.gsi_base)
            .filter(|p| *p < u32::from(self.pins))
            .ok_or(IrqError::Route)? as u8;
        let _guard = self.lock();
        let low = self.low(pin)?;
        if low & MASK == 0 || low & (REMOTE_IRR | DELIVERY) != 0 {
            return Err(IrqError::Drain);
        }
        // SAFETY: the unit lock held above serializes the claim table.
        let claims = unsafe { &mut *self.claims.get() };
        if claims[usize::from(pin)] {
            return Err(IrqError::Exhausted);
        }
        // Selector lock also owns the fixed pin metadata. Never wrap and make
        // an old handler's parent-mask endpoint valid for a later claim.
        // SAFETY: the unit lock held above serializes the epoch counter.
        let next_epoch = unsafe { &mut *self.next_epoch.get() };
        let epoch = *next_epoch;
        *next_epoch = next_epoch.checked_add(1).ok_or(IrqError::Exhausted)?;
        // SAFETY: the unit lock held above serializes the epoch table.
        unsafe { (*self.epochs.get())[usize::from(pin)] = epoch };
        claims[usize::from(pin)] = true;
        Ok(Pin {
            unit: ManuallyDrop::new(self.clone()),
            devices: ManuallyDrop::new(devices),
            line,
            pin,
            epoch,
            target: None,
            retired: true,
            lifetime: Arc::new(PinLifetime {
                phase: AtomicU8::new(CLAIMED),
                failed: AtomicBool::new(false),
            }),
        })
    }
}
struct Guard<'a, R: Registers, P: Platform> {
    unit: &'a Unit<R, P>,
    saved: u64,
}
impl<R: Registers, P: Platform> Drop for Guard<'_, R, P> {
    fn drop(&mut self) {
        self.unit.held.store(false, Ordering::Release);
        // SAFETY: `saved` came from `save_and_disable` when this guard locked the unit.
        unsafe { self.unit.platform.restore(self.saved) };
    }
}

/// Process/deferred source; real callback/source group is owned by Registry.
/// An abandoned programmed pin keeps/quarantines its unit, contributors and
/// claim rather than permitting uncertain delivery into a reused vector.
pub struct Pin<R: Registers, P: Platform> {
    unit: ManuallyDrop<Arc<Unit<R, P>>>,
    devices: ManuallyDrop<Box<dyn Devices>>,
    line: LineRoute,
    pin: u8,
    epoch: u64,
    target: Option<Target>,
    retired: bool,
    lifetime: Arc<PinLifetime>,
}
const CLAIMED: u8 = 0;
const PROGRAMMED: u8 = 1;
const RETIRED: u8 = 2;
const RELEASED: u8 = 3;
struct PinLifetime {
    phase: AtomicU8,
    failed: AtomicBool,
}
struct PinDomain<R: Registers, P: Platform> {
    unit: ManuallyDrop<Arc<Unit<R, P>>>,
    lifetime: ManuallyDrop<Arc<PinLifetime>>,
}
impl<R: Registers, P: Platform> Drop for PinDomain<R, P> {
    fn drop(&mut self) {
        if self.unit.platform.check_process().is_err() {
            return;
        }
        // SAFETY: original process context; Slot/caller owns no in-flight
        // reference when this final process-owned endpoint is released.
        unsafe {
            ManuallyDrop::drop(&mut self.lifetime);
            ManuallyDrop::drop(&mut self.unit);
        }
    }
}
// SAFETY: original Unit/root domain and the actual private claim allocation
// remain held. Checks use immutable/atomic metadata only, without Unit locks,
// raw source access, allocation or release in IRQ context.
unsafe impl<R: Registers, P: Platform> NotificationDomain for PinDomain<R, P> {
    fn check(&self) -> Result<(), posted_msi::Error> {
        self.unit.domain.check()?;
        if self.lifetime.failed.load(Ordering::Acquire)
            || self.lifetime.phase.load(Ordering::Acquire) == RELEASED
        {
            return Err(posted_msi::Error::RootFailed);
        }
        Ok(())
    }
}

struct PinEoi<R: Registers, P: Platform> {
    unit: ManuallyDrop<Arc<Unit<R, P>>>,
    lifetime: ManuallyDrop<Arc<PinLifetime>>,
    pin: u8,
    epoch: u64,
    target: Target,
    line: LineRoute,
}
impl<R: Registers, P: Platform> Drop for PinEoi<R, P> {
    fn drop(&mut self) {
        if self.unit.platform.check_process().is_err() {
            return;
        }
        // SAFETY: only process-owned final release may end kept controller
        // resources; a foreign/ISR default Drop instead retains both fields.
        unsafe {
            ManuallyDrop::drop(&mut self.lifetime);
            ManuallyDrop::drop(&mut self.unit);
        }
    }
}
impl<R: Registers, P: Platform> PinEoi<R, P> {
    fn acknowledge(&self, observed: Trigger) -> Result<(), IrqError> {
        self.unit.platform.check_cpu()?;
        self.unit.domain.check().map_err(IrqError::Delivery)?;
        let phase = self.lifetime.phase.load(Ordering::Acquire);
        if !matches!(phase, PROGRAMMED | RETIRED) || self.lifetime.failed.load(Ordering::Acquire) {
            return Err(IrqError::Unregistered);
        }
        let _guard = self.unit.lock();
        // SAFETY: original selector/claim lock. Retirement disarms handler
        // endpoints before final Slot withdrawal, but keeps this physical pin
        // owned until every captured chip EOI and the Source finally release.
        let epoch = unsafe { (*self.unit.epochs.get())[usize::from(self.pin)] };
        if epoch != self.epoch && !(phase == RETIRED && epoch == 0) {
            return Err(IrqError::Unregistered);
        }
        let low = self.unit.low(self.pin)?;
        let high = self.unit.registers.read(0x11 + self.pin * 2);
        let level = self.line.trigger == Trigger::Level;
        let expected = u32::from(self.target.vector)
            | if level { 1 << 15 } else { 0 }
            | if self.line.polarity == Polarity::Low {
                1 << 13
            } else {
                0
            };
        if low & (CONFIG & !MASK) != expected || high != u32::from(self.target.destination) << 24 {
            return Err(IrqError::Route);
        }
        // An edge line keeps no Remote IRR, so the local EOI completes it;
        // a level line seen as level completed through the EOI broadcast.
        if !level || observed == Trigger::Level {
            return Ok(());
        }
        // Intel SDM12.8.4: an edge seen by the CPU has no EOI broadcast.
        // Linux __eoi_ioapic_pin handles this with direct EOI or a masked
        // edge/level transition on older controllers; never a selector0x40.
        if self.unit.version >= 0x20 {
            self.unit.registers.write_eoi(self.target.vector);
        } else {
            let masked = low | MASK;
            self.unit.registers.write(0x10 + self.pin * 2, masked);
            if self.unit.low(self.pin)? & CONFIG != masked & CONFIG {
                return Err(IrqError::Mask);
            }
            let edge = masked & !(1 << 15);
            self.unit.registers.write(0x10 + self.pin * 2, edge);
            if self.unit.low(self.pin)? & CONFIG != edge & CONFIG {
                return Err(IrqError::Route);
            }
            self.unit.registers.write(0x10 + self.pin * 2, low);
            if self.unit.low(self.pin)? & CONFIG != low & CONFIG {
                return Err(IrqError::Route);
            }
        }
        Ok(())
    }
}
// SAFETY: endpoint captures only the original checked Registry reservation;
// no access is admitted until actual masked route programming has completed.
// Slot retains original Unit/claim/lifetime through local+chip EOI inflight.
// Same-CPU IRQ-save selector locking is independent of the !Send Source.
unsafe impl<R: Registers, P: Platform> ChipEoi for PinEoi<R, P> {
    fn after_local_eoi(&self, observed: Trigger) -> Result<(), IrqError> {
        let result = self.acknowledge(observed);
        if result.is_err() {
            self.lifetime.failed.store(true, Ordering::Release);
        }
        result
    }
}
impl<R: Registers, P: Platform> Pin<R, P> {
    /// Pre-bind a real parent mask endpoint in process context before callback
    /// publication. It never enables/programs a route or acquires a new pin.
    pub fn parent_mask(&self) -> Result<ParentMask<R, P>, IrqError> {
        self.unit.platform.check_cpu()?;
        let _guard = self.unit.lock();
        // SAFETY: the unit lock held above serializes the epoch table.
        if unsafe { (*self.unit.epochs.get())[usize::from(self.pin)] } != self.epoch {
            return Err(IrqError::Unregistered);
        }
        Ok(ParentMask {
            unit: Arc::clone(&self.unit),
            pin: self.pin,
            epoch: self.epoch,
            lifetime: self.lifetime.clone(),
        })
    }
}

/// Constructorless pin/epoch endpoint, kept by the fixed callback
/// group. Final Drop remains process/deferred, even though mask is IRQ-safe.
pub struct ParentMask<R: Registers, P: Platform> {
    unit: Arc<Unit<R, P>>,
    pin: u8,
    epoch: u64,
    lifetime: Arc<PinLifetime>,
}
impl<R: Registers, P: Platform> ParentMask<R, P> {
    /// Rearm the same claimed route after its deferred source has been drained.
    /// This does not enable contributors or create another route.
    ///
    /// # Safety
    /// Process context on the owning CPU. The native callback has returned and
    /// its pending flag is clear. The source handler acknowledged or locally
    /// masked every contributor it observed; any outstanding deferred worker
    /// keeps its disabled contributor until that device's work completes.
    /// No callback/source-owner retirement overlaps this operation. A new
    /// physical event after unmask is handled by the same callback.
    pub unsafe fn rearm(&self) -> Result<(), IrqError> {
        self.unit.platform.check_cpu()?;
        if self.lifetime.failed.load(Ordering::Acquire) {
            return Err(IrqError::Drain);
        }
        let _guard = self.unit.lock();
        // SAFETY: the lock serializes claim/epoch checks with route retirement.
        if unsafe { (*self.unit.epochs.get())[usize::from(self.pin)] } != self.epoch {
            return Err(IrqError::Unregistered);
        }
        let low = self.unit.low(self.pin)?;
        let vector = low as u8;
        if low & MASK == 0
            || vector < FIRST_VECTOR
            || usize::from(vector - FIRST_VECTOR) >= VECTOR_COUNT
        {
            return Err(IrqError::Route);
        }
        if low & (REMOTE_IRR | DELIVERY) != 0 || self.unit.platform.pending(vector)? {
            return Err(IrqError::Drain);
        }
        self.unit.registers.write(0x10 + self.pin * 2, low & !MASK);
        if self.unit.low(self.pin)? & MASK != 0 {
            return Err(IrqError::Mask);
        }
        Ok(())
    }
}
// SAFETY: Pin alone creates this endpoint from its Unit/claim. The
// existing IRQ-save selector lock checks the nonwrapping epoch and performs
// MASK/readback without allocation, callbacks or final owner release.
unsafe impl<R: Registers, P: Platform> stela_drivers::bus::irq::ParentMask for ParentMask<R, P> {
    fn mask(&self) -> Result<(), IrqError> {
        self.unit.platform.check_cpu()?;
        let _guard = self.unit.lock();
        // SAFETY: the unit lock held above serializes the epoch table.
        if unsafe { (*self.unit.epochs.get())[usize::from(self.pin)] } != self.epoch {
            return Err(IrqError::Unregistered);
        }
        let low = self.unit.low(self.pin)?;
        self.unit.registers.write(0x10 + self.pin * 2, low | MASK);
        if self.unit.low(self.pin)? & MASK == 0 {
            Err(IrqError::Mask)
        } else {
            Ok(())
        }
    }
}
// SAFETY: devices and unit are held, physical ownership comes from claim's
// explicit grant. The canonical registry alone publishes/releases callbacks.
unsafe impl<R: Registers + 'static, P: Platform + 'static> Source for Pin<R, P> {
    fn notification_domain(&self) -> Result<Arc<dyn NotificationDomain>, IrqError> {
        self.unit.platform.check_process()?;
        self.unit.domain.check().map_err(IrqError::Delivery)?;
        Ok(Arc::new(PinDomain {
            unit: ManuallyDrop::new(Arc::clone(&self.unit)),
            lifetime: ManuallyDrop::new(self.lifetime.clone()),
        }))
    }
    fn eoi_endpoint(
        &mut self,
        target: &CpuTarget<'_>,
    ) -> Result<Option<Arc<dyn ChipEoi>>, IrqError> {
        self.unit.platform.check_process()?;
        target.check_current()?;
        if !target.belongs_to(self.unit.registry) {
            return Err(IrqError::Route);
        }
        let actual = target.descriptor();
        if self.lifetime.failed.load(Ordering::Acquire) {
            return Err(IrqError::Route);
        }
        Ok(Some(Arc::new(PinEoi {
            unit: ManuallyDrop::new(Arc::clone(&self.unit)),
            lifetime: ManuallyDrop::new(self.lifetime.clone()),
            pin: self.pin,
            epoch: self.epoch,
            target: actual,
            line: self.line,
        })))
    }
    fn mask(&mut self) -> Result<(), IrqError> {
        self.unit.platform.check_process()?;
        let result = {
            let _guard = self.unit.lock();
            let low = self.unit.low(self.pin)?;
            self.unit.registers.write(0x10 + self.pin * 2, low | MASK);
            if self.unit.low(self.pin)? & MASK == 0 {
                Err(IrqError::Mask)
            } else {
                Ok(())
            }
        };
        // Controller masks first, so a contributor cannot arrive during stop.
        result?;
        self.devices.mask()
    }
    fn quiesce(&mut self) -> Result<(), IrqError> {
        self.unit.platform.check_process()?;
        self.devices.quiesce()
    }
    fn route_kind(&self) -> stela_drivers::bus::irq::RouteKind {
        stela_drivers::bus::irq::RouteKind::Line
    }
    fn requester(&self) -> Option<&stela_drivers::bus::pci::requester::RequesterId> {
        None
    }
    unsafe fn program(
        &mut self,
        route: &stela_drivers::bus::irq::AllocatedRoute<'_>,
    ) -> Result<(), IrqError> {
        self.unit.platform.check_process()?;
        if !route.belongs_to(self.unit.registry) {
            return Err(IrqError::Route);
        }
        let Route::Line { target, line } = route.programming() else {
            return Err(IrqError::Route);
        };
        if line != self.line
            || target.destination == 255
            || target.vector < FIRST_VECTOR
            || usize::from(target.vector - FIRST_VECTOR) >= VECTOR_COUNT
        {
            return Err(IrqError::Route);
        }
        let _guard = self.unit.lock();
        // SAFETY: the unit lock held above serializes the epoch table.
        if unsafe { (*self.unit.epochs.get())[usize::from(self.pin)] } != self.epoch {
            return Err(IrqError::Unregistered);
        }
        let low = self.unit.low(self.pin)?;
        if low & MASK == 0 || low & (REMOTE_IRR | DELIVERY) != 0 {
            return Err(IrqError::Drain);
        }
        // From this point failure keeps the complete route claim. LOW MASK
        // was acknowledged before any HIGH/destination change (Linux mask_entry).
        self.retired = false;
        self.target = Some(target);
        let expected = MASK
            | u32::from(target.vector)
            | if line.polarity == Polarity::Low {
                1 << 13
            } else {
                0
            }
            | if line.trigger == Trigger::Level {
                1 << 15
            } else {
                0
            };
        self.unit
            .registers
            .write(0x11 + self.pin * 2, u32::from(target.destination) << 24);
        self.unit.registers.write(0x10 + self.pin * 2, expected);
        let high = self.unit.registers.read(0x11 + self.pin * 2);
        let actual = self.unit.low(self.pin)?;
        if high == u32::MAX {
            return Err(IrqError::FailedRead);
        }
        if actual & CONFIG != expected
            || high >> 24 != u32::from(target.destination)
            || actual & (REMOTE_IRR | DELIVERY) != 0
        {
            return Err(IrqError::Route);
        }
        self.lifetime.phase.store(PROGRAMMED, Ordering::Release);
        Ok(())
    }
    unsafe fn unmask(&mut self) -> Result<(), IrqError> {
        self.unit.platform.check_process()?;
        if self.target.is_none() || self.retired {
            return Err(IrqError::Route);
        }
        // Contributors may assert while IOAPIC is still masked; enabling the
        // final route observes an already asserted level and delivers it. An
        // edge that arrived while masked is lost, as on hardware: the
        // contributor's owner reads its device once after the route opens.
        // SAFETY: `program` published the route and every callback before unmask.
        unsafe { self.devices.enable() }?;
        let _guard = self.unit.lock();
        let low = self.unit.low(self.pin)?;
        if low & MASK == 0 || low & (REMOTE_IRR | DELIVERY) != 0 {
            return Err(IrqError::Drain);
        }
        self.unit.registers.write(0x10 + self.pin * 2, low & !MASK);
        if self.unit.low(self.pin)? & MASK != 0 {
            return Err(IrqError::Mask);
        }
        Ok(())
    }
    unsafe fn synchronize(&mut self) -> Result<(), IrqError> {
        self.unit.platform.check_process()?;
        if self.lifetime.failed.load(Ordering::Acquire) {
            return Err(IrqError::Drain);
        }
        self.devices.quiesce()?;
        let start = self.unit.platform.ticks();
        loop {
            let low = {
                let _guard = self.unit.lock();
                self.unit.low(self.pin)?
            };
            if low & MASK == 0 {
                return Err(IrqError::Mask);
            }
            if low & (REMOTE_IRR | DELIVERY) == 0 {
                break;
            }
            if self.unit.platform.ticks().wrapping_sub(start) >= self.unit.platform.timeout_ticks()
            {
                return Err(IrqError::Drain);
            }
            core::hint::spin_loop();
        }
        if let Some(target) = self.target
            && self.unit.platform.pending(target.vector)?
        {
            return Err(IrqError::Drain);
        }
        self.retired = true;
        // Controller and callback retirement completed. Keep the physical pin
        // claim until Source Drop, while refusing every old handler endpoint.
        let _guard = self.unit.lock();
        // SAFETY: the unit lock held above serializes the epoch table.
        unsafe { (*self.unit.epochs.get())[usize::from(self.pin)] = 0 };
        self.lifetime.phase.store(RETIRED, Ordering::Release);
        Ok(())
    }
}
impl<R: Registers, P: Platform> Drop for Pin<R, P> {
    fn drop(&mut self) {
        if !self.retired
            || self.lifetime.failed.load(Ordering::Acquire)
            || self.unit.platform.check_process().is_err()
        {
            self.unit.quarantined.fetch_add(1, Ordering::Relaxed);
            return;
        }
        {
            let _guard = self.unit.lock();
            self.lifetime.phase.store(RELEASED, Ordering::Release);
            // SAFETY: the unit lock and IRQ save serialize this selector/window pair on the owning
            // CPU.
            unsafe {
                (*self.unit.claims.get())[usize::from(self.pin)] = false;
                (*self.unit.epochs.get())[usize::from(self.pin)] = 0;
            }
        }
        // Registry retirement proved callback lifetime + CPU/IOAPIC
        // drain; only this process-context final release frees contributors.
        // SAFETY: the unit lock and IRQ save serialize this selector/window pair on the owning CPU.
        unsafe {
            ManuallyDrop::drop(&mut self.devices);
            ManuallyDrop::drop(&mut self.unit);
        }
    }
}

#[cfg(test)]
mod tests;
