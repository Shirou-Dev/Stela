use super::*;

#[test]
fn rejected_and_published_requester_failures_keep_original_claim_and_unit() {
    for published in [false, true] {
        let registers = ModelRegisters::new();
        let pages = source();
        // SAFETY: isolated unit/register/table peer with no native DMA/IRQ users.
        let unit = unsafe { Unit::take_over(registers.clone(), pages, &[8], 48, &[]) }.unwrap();
        let released = Arc::new(AtomicU64::new(0));
        if published {
            registers.0.lock().unwrap().block_context = true;
        }
        let rid = if published { 8 } else { 0x300 };
        let before = Arc::strong_count(&unit);
        // SAFETY: explicit stopped isolated claim; this grants no native receipt.
        let failure = match unsafe {
            unit.attach_requester(RequesterClaim::model(rid, released.clone()), &[])
        } {
            Err(failure) => failure,
            Ok(_) => panic!("injected requester failure was ignored"),
        };
        assert_eq!(
            failure.error,
            if published {
                VtdError::Timeout
            } else {
                VtdError::Busy
            }
        );
        assert_eq!(released.load(Ordering::Relaxed), 0);
        assert_eq!(Arc::strong_count(&unit), before + 1);
        if published {
            let mut guard = unit.lock();
            let state = guard.state();
            assert!(state.poisoned && state.domains.contains_key(&rid));
        }
        drop(failure);
        assert_eq!(released.load(Ordering::Relaxed), 0);
        assert_eq!(
            Arc::strong_count(&unit),
            before + 1,
            "dropping refusal cannot release original unit custody"
        );
    }
}

#[derive(Clone)]
struct InterruptedContext {
    original: ModelRegisters,
    armed: Arc<core::sync::atomic::AtomicBool>,
}
// SAFETY: the same synchronous register/table model is retained unchanged.
// The deliberate post-store panic models loss of completion acknowledgement.
unsafe impl Registers for InterruptedContext {
    fn bytes(&self) -> usize {
        self.original.bytes()
    }
    fn read32(&self, offset: usize) -> u32 {
        self.original.read32(offset)
    }
    fn read64(&self, offset: usize) -> u64 {
        self.original.read64(offset)
    }
    fn write32(&self, offset: usize, value: u32) {
        self.original.write32(offset, value);
    }
    fn write64(&self, offset: usize, value: u64) {
        self.original.write64(offset, value);
        if offset == CCMD && self.armed.swap(false, Ordering::Relaxed) {
            panic!("interrupted actual context invalidation store");
        }
    }
    fn ticks(&self) -> u64 {
        self.original.ticks()
    }
    fn timeout_ticks(&self) -> u64 {
        self.original.timeout_ticks()
    }
    unsafe fn flush_table(&self, cpu: NonNull<u8>, bytes: usize, line: usize) {
        // SAFETY: exact caller-kept table span forwarded to the original peer.
        unsafe { self.original.flush_table(cpu, bytes, line) };
    }
}

#[test]
fn context_publication_unwind_closes_sibling_admission_and_retains_the_unit() {
    let original = ModelRegisters::new();
    let armed = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let registers = InterruptedContext {
        original: original.clone(),
        armed: armed.clone(),
    };
    let pages = source();
    // SAFETY: isolated model unit, no production hardware/IRQ/DMA authority.
    let unit = unsafe { Unit::take_over(registers, pages, &[8, 16], 48, &[]) }.unwrap();
    let released = Arc::new(AtomicU64::new(0));
    armed.store(true, Ordering::Relaxed);
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: the model claim is stopped; fault interrupts real publication.
        let _ = unsafe { unit.attach_requester(RequesterClaim::model(8, released.clone()), &[]) };
    }));
    assert!(caught.is_err());
    assert_eq!(released.load(Ordering::Relaxed), 0);
    {
        let mut guard = unit.lock();
        let state = guard.state();
        assert!(state.poisoned && state.domains.contains_key(&8));
    }
    let effects = original.0.lock().unwrap().writes.len();
    let allocation = pages.next.load(Ordering::Relaxed);
    for rid in [8, 16] {
        // SAFETY: separate stopped model claims must be rejected before effects.
        let refusal = match unsafe {
            unit.attach_requester(RequesterClaim::model(rid, released.clone()), &[])
        } {
            Err(failure) => failure,
            Ok(_) => panic!("resumed after interrupted context publication"),
        };
        assert_eq!(refusal.error, VtdError::Busy);
        drop(refusal);
    }
    drop(unit);
    assert_eq!(original.0.lock().unwrap().writes.len(), effects);
    assert_eq!(pages.next.load(Ordering::Relaxed), allocation);
    assert_eq!(released.load(Ordering::Relaxed), 0);
    assert_eq!(pages.released.load(Ordering::Relaxed), 0);
}
