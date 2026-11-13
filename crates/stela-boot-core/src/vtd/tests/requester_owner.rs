//! Ownership controls for the local actor/shared domain boundary.
use super::*;

mod preparation;

#[test]
fn shared_dma_projection_is_send_sync_without_the_config_actor() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<Unit<ModelRegisters>>();
    send_sync::<RequesterDomain<ModelRegisters>>();
    send_sync::<Arc<dyn DmaDomain>>();
    let registers = ModelRegisters::new();
    // SAFETY: isolated stopped register/table peer, no native resources.
    let unit = unsafe { Unit::take_over(registers.clone(), source(), &[8], 48, &[]) }.unwrap();
    let released = Arc::new(AtomicU64::new(0));
    // SAFETY: independently owned stopped model claim.
    let owner =
        unsafe { unit.attach_requester(RequesterClaim::model(8, released.clone()), &[]) }.unwrap();
    let projection = owner.domain();
    let effects = registers.0.lock().unwrap().writes.len();
    std::thread::spawn(move || drop(projection)).join().unwrap();
    assert_eq!(registers.0.lock().unwrap().writes.len(), effects);
    assert_eq!(released.load(Ordering::Relaxed), 0);
    // SAFETY: no model engines, IRQ/work, or mapping leases exist.
    drop(unsafe { owner.detach() }.unwrap());
    assert_eq!(released.load(Ordering::Relaxed), 1);
    drop(owner);
    // SAFETY: the only context is now acknowledged absent.
    unsafe { unit.shut_down() }.unwrap();
}

#[test]
fn abandoned_actor_closes_clones_without_taking_the_unit_lock() {
    let registers = ModelRegisters::new();
    let pages = source();
    // SAFETY: isolated stopped model unit.
    let unit = unsafe { Unit::take_over(registers.clone(), pages, &[8], 48, &[]) }.unwrap();
    let released = Arc::new(AtomicU64::new(0));
    // SAFETY: isolated stopped model source.
    let owner =
        unsafe { unit.attach_requester(RequesterClaim::model(8, released.clone()), &[]) }.unwrap();
    let projection = owner.domain();
    let before = Arc::strong_count(&unit);
    let effects = registers.0.lock().unwrap().writes.len();
    {
        let mut held = unit.lock();
        drop(owner);
        assert!(!held.state().domains[&8].lifetime.is_live());
        assert_eq!(released.load(Ordering::Relaxed), 0);
    }
    assert_eq!(Arc::strong_count(&unit), before);
    assert_eq!(registers.0.lock().unwrap().writes.len(), effects);
    assert!(matches!(
        DmaMapping::map(
            projection.clone(),
            super::pages(PAGE, 12, 0x19000000, Arc::new(AtomicU64::new(0))),
            Direction::Bidirectional,
            u64::MAX
        ),
        Err(DmaError::Unmapped)
    ));
    drop(projection);
    assert_eq!(released.load(Ordering::Relaxed), 0);
    // SAFETY: this negative control cannot retire the abandoned source owner.
    assert_eq!(unsafe { unit.shut_down() }, Err(VtdError::Busy));
}

#[test]
fn global_drop_after_ack_is_metadata_only_and_cannot_detach_twice() {
    let registers = ModelRegisters::new();
    // SAFETY: stopped independent model root.
    let unit = unsafe { Unit::take_over(registers.clone(), source(), &[8], 48, &[]) }.unwrap();
    let released = Arc::new(AtomicU64::new(0));
    // SAFETY: same isolated claim, no concurrent producer.
    let owner =
        unsafe { unit.attach_requester(RequesterClaim::model(8, released.clone()), &[]) }.unwrap();
    let projection = owner.domain();
    // SAFETY: all model source/mapping/IRQ/work joins are empty.
    drop(unsafe { owner.detach() }.unwrap());
    assert_eq!(released.load(Ordering::Relaxed), 1);
    let effects = registers.0.lock().unwrap().writes.len();
    // SAFETY: duplicate exact actor use must refuse before any hardware effect.
    assert_eq!(unsafe { owner.detach() }.unwrap_err(), VtdError::Busy);
    drop(owner);
    let before = Arc::strong_count(&unit);
    {
        let _held = unit.lock();
        drop(projection);
    }
    assert_eq!(Arc::strong_count(&unit), before - 1);
    assert_eq!(registers.0.lock().unwrap().writes.len(), effects);
    // SAFETY: acknowledged absent context, no retained live mapping.
    unsafe { unit.shut_down() }.unwrap();
}

#[test]
fn original_config_checks_never_run_under_the_unit_lock() {
    let registers = ModelRegisters::new();
    // SAFETY: isolated register/table peer.
    let unit = unsafe { Unit::take_over(registers, source(), &[8], 48, &[]) }.unwrap();
    let checks = Arc::new(AtomicU64::new(0));
    let released = Arc::new(AtomicU64::new(0));
    let seen = checks.clone();
    let original = unit.clone();
    let claim = RequesterClaim::model_with_check(
        8,
        released.clone(),
        Box::new(move || {
            assert!(!original.held.load(Ordering::Acquire));
            seen.fetch_add(1, Ordering::Relaxed);
        }),
    );
    // SAFETY: this same claim has no real engine or pending IRQ/work.
    let owner = unsafe { unit.attach_requester(claim, &[]) }.unwrap();
    // SAFETY: no actual DMA can issue from the isolated peer.
    unsafe { owner.set_bus_master(false) }.unwrap();
    // SAFETY: all model source/mapping joins are empty.
    drop(unsafe { owner.detach() }.unwrap());
    assert_eq!(checks.load(Ordering::Relaxed), 4);
    assert_eq!(released.load(Ordering::Relaxed), 1);
    drop(owner);
    // SAFETY: acknowledged absent context.
    unsafe { unit.shut_down() }.unwrap();
}

#[test]
fn source_callback_unwind_keeps_the_actor_and_denies_global_clones() {
    let registers = ModelRegisters::new();
    // SAFETY: isolated register/table peer.
    let unit = unsafe { Unit::take_over(registers.clone(), source(), &[8], 48, &[]) }.unwrap();
    let released = Arc::new(AtomicU64::new(0));
    let armed = Arc::new(AtomicBool::new(false));
    let inject = armed.clone();
    let original = unit.clone();
    let claim = RequesterClaim::model_with_check(
        8,
        released.clone(),
        Box::new(move || {
            assert!(!original.held.load(Ordering::Acquire));
            if inject.swap(false, Ordering::AcqRel) {
                panic!("lost actual config completion");
            }
        }),
    );
    // SAFETY: same stopped model source with no IRQ/work or hidden producer.
    let owner = unsafe { unit.attach_requester(claim, &[]) }.unwrap();
    let projection = owner.domain();
    armed.store(true, Ordering::Release);
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: isolated source; callback deliberately loses completion.
        let _ = unsafe { owner.set_bus_master(false) };
    }));
    assert!(caught.is_err());
    assert_eq!(released.load(Ordering::Relaxed), 0);
    assert!(!projection.lifetime.is_live());
    let effects = registers.0.lock().unwrap().writes.len();
    assert!(matches!(
        DmaMapping::map(
            projection.clone(),
            pages(PAGE, 12, 0x19000000, Arc::new(AtomicU64::new(0))),
            Direction::Bidirectional,
            u64::MAX
        ),
        Err(DmaError::Unmapped)
    ));
    drop(owner);
    drop(projection);
    assert_eq!(released.load(Ordering::Relaxed), 0);
    assert_eq!(registers.0.lock().unwrap().writes.len(), effects);
}
