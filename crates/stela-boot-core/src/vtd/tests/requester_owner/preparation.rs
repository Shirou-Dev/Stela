//! Reentrant page-provider and prepublication unwind controls.
use super::*;

struct ReentrantSource {
    original: &'static Source,
    callback: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl PageSource for ReentrantSource {
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        let callback = self.callback.lock().unwrap().take();
        if let Some(callback) = callback {
            callback();
        }
        self.original.allocate(bytes, alignment, attribute)
    }
}

#[test]
fn root_provider_reentry_rechecks_generation_and_shutdown_before_publication() {
    for shutdown in [false, true] {
        let registers = ModelRegisters::new();
        let provider = Box::leak(Box::new(ReentrantSource {
            original: source(),
            callback: Mutex::new(None),
        }));
        // SAFETY: independent stopped model unit and real allocated table RAM.
        let unit =
            unsafe { Unit::take_over(registers.clone(), provider, &[8, 16], 48, &[]) }.unwrap();
        let original = unit.clone();
        let observed = registers.clone();
        let effects = Arc::new(AtomicU64::new(0));
        let seen = effects.clone();
        *provider.callback.lock().unwrap() = Some(Box::new(move || {
            assert!(!original.held.load(Ordering::Acquire));
            if shutdown {
                // SAFETY: no attached requester or live mapping exists yet.
                unsafe { original.shut_down() }.unwrap();
            } else {
                let released = Arc::new(AtomicU64::new(0));
                // SAFETY: distinct stopped model requester, no IRQ/work users.
                let sibling = unsafe {
                    original.attach_requester(RequesterClaim::model(16, released.clone()), &[])
                }
                .unwrap();
                // SAFETY: the sibling has no mappings, engine or posted work.
                drop(unsafe { sibling.detach() }.unwrap());
                drop(sibling);
                assert_eq!(released.load(Ordering::Relaxed), 1);
            }
            seen.store(
                observed.0.lock().unwrap().writes.len() as u64,
                Ordering::Relaxed,
            );
        }));
        let released = Arc::new(AtomicU64::new(0));
        // SAFETY: independent stopped model claim; provider changes unit state.
        let failure =
            unsafe { unit.attach_requester(RequesterClaim::model(8, released.clone()), &[]) }
                .err()
                .expect("stale preparation must not publish");
        assert_eq!(failure.error, VtdError::Busy);
        assert!(unit.lock().state().domains.is_empty());
        assert_eq!(
            registers.0.lock().unwrap().writes.len() as u64,
            effects.load(Ordering::Relaxed)
        );
        let retained = provider.original.released.load(Ordering::Relaxed);
        drop(failure);
        assert_eq!(released.load(Ordering::Relaxed), 0);
        assert_eq!(provider.original.released.load(Ordering::Relaxed), retained);
    }
}

#[test]
fn source_check_unwind_before_publication_retains_the_whole_preparation() {
    let registers = ModelRegisters::new();
    let pages = source();
    // SAFETY: independent stopped model controller and table storage.
    let unit = unsafe { Unit::take_over(registers.clone(), pages, &[8], 48, &[]) }.unwrap();
    let released = Arc::new(AtomicU64::new(0));
    let original = unit.clone();
    let claim = RequesterClaim::model_with_check(
        8,
        released.clone(),
        Box::new(move || {
            assert!(!original.held.load(Ordering::Acquire));
            panic!("lost stopped-source validation");
        }),
    );
    let before = Arc::strong_count(&unit);
    let effects = registers.0.lock().unwrap().writes.len();
    let allocations = pages.next.load(Ordering::Relaxed);
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: same stopped model source; validation deliberately unwinds.
        let _ = unsafe { unit.attach_requester(claim, &[]) };
    }));
    assert!(caught.is_err());
    assert_eq!(released.load(Ordering::Relaxed), 0);
    assert_eq!(Arc::strong_count(&unit), before + 1);
    assert_eq!(registers.0.lock().unwrap().writes.len(), effects);
    assert_eq!(pages.next.load(Ordering::Relaxed), allocations);
    assert!(unit.lock().state().domains.is_empty());
}
