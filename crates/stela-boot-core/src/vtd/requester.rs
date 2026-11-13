//! CPU-local requester control and its shared deny-only DMA lifecycle.
use super::*;
use core::cell::RefCell;
use core::ops::Deref;

pub(super) struct RequesterLifetime {
    closed: AtomicBool,
    detached: AtomicBool,
    quarantined: AtomicBool,
}
impl RequesterLifetime {
    fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            detached: AtomicBool::new(false),
            quarantined: AtomicBool::new(false),
        }
    }
    pub(super) fn is_live(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
    }
    pub(super) fn is_detached(&self) -> bool {
        self.detached.load(Ordering::Acquire)
    }
    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
    fn quarantine(&self) {
        self.close();
        if !self.is_detached() && !self.quarantined.swap(true, Ordering::AcqRel) {
            let _ = QUARANTINED_DOMAINS.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1))
            });
        }
    }
    fn acknowledge_detach(&self) {
        self.closed.store(true, Ordering::Release);
        self.detached.store(true, Ordering::Release);
    }
}
pub(super) struct RequesterUnwind {
    lifetime: Arc<RequesterLifetime>,
    finished: bool,
}
impl RequesterUnwind {
    pub(super) fn new(lifetime: Arc<RequesterLifetime>) -> Self {
        Self {
            lifetime,
            finished: false,
        }
    }
    pub(super) fn dismiss(&mut self) {
        self.finished = true;
    }
}
impl Drop for RequesterUnwind {
    fn drop(&mut self) {
        if !self.finished {
            self.lifetime.quarantine();
        }
    }
}
/// This entire actor is parked before invoking any external claim callback.
/// Nothing reachable from the shared Unit points back to it.
pub(super) struct RequesterActor<R: Registers> {
    pub(super) unit: ManuallyDrop<Option<Arc<Unit<R>>>>,
    pub(super) claim: RefCell<ManuallyDrop<Option<RequesterClaim>>>,
    pub(super) domain: Option<Arc<RequesterDomain<R>>>,
    pub(super) lifetime: Arc<RequesterLifetime>,
    pub(super) staged: ManuallyDrop<Option<Table>>,
}
impl<R: Registers> RequesterActor<R> {
    pub(super) fn prepare(unit: Arc<Unit<R>>, claim: RequesterClaim) -> ManuallyDrop<Box<Self>> {
        let claim = ManuallyDrop::new(claim);
        let unit = ManuallyDrop::new(unit);
        let lifetime = Arc::new(RequesterLifetime::new());
        ManuallyDrop::new(Box::new(Self {
            unit: ManuallyDrop::new(Some(ManuallyDrop::into_inner(unit))),
            claim: RefCell::new(ManuallyDrop::new(Some(ManuallyDrop::into_inner(claim)))),
            domain: None,
            lifetime,
            staged: ManuallyDrop::new(None),
        }))
    }
}
/// Affine configuration/source owner for a requester. Cloning through Deref
/// yields only the shared DMA projection, never this actor or command authority.
/// Default Drop only closes metadata and retains this whole typed actor.
///
/// The configuration owner cannot move to a different CPU/thread:
/// ```compile_fail
/// use stela_boot_core::vtd::{BoundRequester, MmioRegisters};
/// fn send<T: Send>() {}
/// send::<BoundRequester<MmioRegisters>>();
/// ```
/// Nor can its local command authority be shared between threads:
/// ```compile_fail
/// use stela_boot_core::vtd::{BoundRequester, MmioRegisters};
/// fn sync<T: Sync>() {}
/// sync::<BoundRequester<MmioRegisters>>();
/// ```
pub struct BoundRequester<R: Registers> {
    actor: ManuallyDrop<Box<RequesterActor<R>>>,
}
impl<R: Registers> BoundRequester<R> {
    pub(super) fn new(actor: ManuallyDrop<Box<RequesterActor<R>>>) -> Self {
        Self { actor }
    }
    pub fn domain(&self) -> Arc<RequesterDomain<R>> {
        self.deref().clone()
    }
    /// # Safety
    /// Preserve the original process/config/reset epoch. Enabling requires all
    /// reachable DMA addresses already published; disabling is not a stop ACK.
    pub unsafe fn set_bus_master(&self, enabled: bool) -> Result<(), VtdError> {
        let mut claim = self
            .actor
            .claim
            .try_borrow_mut()
            .map_err(|_| VtdError::Busy)?;
        let claim = claim.as_mut().ok_or(VtdError::Busy)?;
        let mut unwind = RequesterUnwind::new(self.actor.lifetime.clone());
        {
            let mut guard = self.unit.lock();
            self.deref()
                .domain(guard.state(), enabled)
                .map_err(|_| VtdError::Busy)?;
        }
        // No Unit guard survives a configuration callback.
        claim.set_bus_master(enabled)?;
        {
            let mut guard = self.unit.lock();
            self.deref()
                .domain(guard.state(), enabled)
                .map_err(|_| VtdError::Busy)?;
        }
        unwind.dismiss();
        Ok(())
    }
    /// # Safety
    /// Engines, posted requests, IRQ/work/reset and submissions for this exact
    /// source epoch are stopped/joined and cannot restart. All mapping leases
    /// have acknowledged unmap. A BME bit or numeric RID is no such proof.
    pub unsafe fn detach(&self) -> Result<RequesterClaim, VtdError> {
        let mut claim = self
            .actor
            .claim
            .try_borrow_mut()
            .map_err(|_| VtdError::Busy)?;
        let original = claim.as_mut().ok_or(VtdError::Busy)?;
        // Refused live mappings do not close a healthy requester.
        {
            let mut guard = self.unit.lock();
            let state = guard.state();
            let current = state
                .domains
                .get(&self.rid)
                .filter(|d| d.did == self.did && d.generation == self.generation && !d.quarantined)
                .ok_or(VtdError::Busy)?;
            if state.shutdown || !current.mappings.is_empty() {
                return Err(VtdError::Busy);
            }
        }
        self.actor.lifetime.close();
        // This callback may fail/unwind: the same boxed claim stays parked and
        // global mapping admission is already denied. A retry keeps this owner.
        original.check_stopped()?;
        let mut guard = self.unit.lock();
        let state = guard.state();
        let current = state
            .domains
            .get(&self.rid)
            .filter(|d| d.did == self.did && d.generation == self.generation && !d.quarantined)
            .ok_or(VtdError::Busy)?;
        if state.shutdown || !current.mappings.is_empty() {
            return Err(VtdError::Busy);
        }
        // The requester's own entry and each alias's lead to this domain.
        let ids: Vec<u16> = core::iter::once(self.rid)
            .chain(current.aliases.iter().copied())
            .collect();
        // Poison before the first publication callback, including caught unwind.
        let was_poisoned = state.poisoned;
        state.poisoned = true;
        for &id in &ids {
            let (context, index) = state.context(id);
            context.write(index, 0);
            if let Some(line) = self.unit.table_cacheline {
                context.flush(&*self.unit.registers, line);
            }
        }
        publish();
        self.unit.invalidate(true)?;
        for &id in &ids {
            let (context, index) = state.context(id);
            context.write(index + 1, 0);
            if let Some(line) = self.unit.table_cacheline {
                context.flush(&*self.unit.registers, line);
            }
        }
        publish();
        state.poisoned = was_poisoned;
        // Source callbacks and checked handoff run outside the hardware lock.
        drop(guard);
        original.check_stopped()?;
        let mut guard = self.unit.lock();
        let state = guard.state();
        let current = state
            .domains
            .get(&self.rid)
            .filter(|d| d.did == self.did && d.generation == self.generation && !d.quarantined)
            .ok_or(VtdError::Busy)?;
        if !current.mappings.is_empty() {
            return Err(VtdError::Busy);
        }
        for &id in &ids {
            let (context, index) = state.context(id);
            if context.read(index) != 0 || context.read(index + 1) != 0 {
                return Err(VtdError::Invalidation);
            }
        }
        state
            .domains
            .remove(&self.rid)
            .expect("same detached context");
        self.actor.lifetime.acknowledge_detach();
        Ok(claim.take().expect("same original requester claim"))
    }
}
impl<R: Registers> Deref for BoundRequester<R> {
    type Target = Arc<RequesterDomain<R>>;
    fn deref(&self) -> &Self::Target {
        self.actor.domain.as_ref().expect("published requester")
    }
}
impl<R: Registers> Drop for BoundRequester<R> {
    fn drop(&mut self) {
        self.actor.lifetime.quarantine();
        if self.actor.lifetime.is_detached() {
            // SAFETY: explicit detach extracted the claim in its original scope.
            // The remaining actor contains only a retired shared projection.
            unsafe {
                ManuallyDrop::drop(&mut self.actor);
            }
        }
    }
}

impl<R: Registers> Drop for AttachRequesterFailure<R> {
    fn drop(&mut self) {
        self._retained.lifetime.quarantine();
    }
}
