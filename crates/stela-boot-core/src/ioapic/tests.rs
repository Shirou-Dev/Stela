use super::*;
extern crate std;
use core::sync::atomic::{AtomicPtr, AtomicUsize};
use std::sync::Mutex;
use stela_drivers::bus::irq::{Disposition, Handler, Registry, SharedHandlers};
struct Hardware {
    regs: [u32; 256],
    asserted: u32,
    pending: bool,
    fail_read: bool,
    refuse_mask: bool,
    broken_eoi: bool,
    /// Reserved bits every redirection entry reads back set.
    reserved_low: u32,
    reserved_high: u32,
    tmr: Trigger,
    events: alloc::vec::Vec<&'static str>,
}
const EXT_INT: u32 = 7 << 8;
impl Hardware {
    fn service(&mut self) {
        let low = self.regs[0x22]; // GSI9, true level state, one pending vector.
        if self.asserted != 0 && low & (MASK | REMOTE_IRR) == 0 {
            assert_ne!(
                low & (1 << 15),
                0,
                "fixture must be genuinely level-triggered"
            );
            self.regs[0x22] |= REMOTE_IRR;
            self.pending = true;
            self.tmr = Trigger::Level;
            self.events.push("deliver");
        }
    }
    fn eoi(&mut self) -> Trigger {
        let observed = self.tmr;
        self.pending = false;
        self.events.push("eoi");
        if observed == Trigger::Level && !self.broken_eoi {
            self.regs[0x22] &= !REMOTE_IRR;
            self.service();
        }
        observed
    }
}
struct Board {
    hw: Mutex<Hardware>,
    ticks: AtomicU64,
    drops: AtomicUsize,
    calls: AtomicUsize,
    registry: AtomicPtr<Registry<Cpu>>,
    vector: core::sync::atomic::AtomicU8,
    domain_live: AtomicBool,
    arming_old_edge: AtomicBool,
    in_interrupt: AtomicBool,
}
impl Board {
    fn new() -> Arc<Self> {
        let mut regs = [0; 256];
        regs[1] = 0x11 | 23 << 16;
        for pin in 0..24 {
            regs[0x10 + pin * 2] = MASK;
        }
        Arc::new(Self {
            hw: Mutex::new(Hardware {
                regs,
                asserted: 0,
                pending: false,
                fail_read: false,
                refuse_mask: false,
                broken_eoi: false,
                reserved_low: 0,
                reserved_high: 0,
                tmr: Trigger::Edge,
                events: alloc::vec::Vec::new(),
            }),
            ticks: AtomicU64::new(0),
            drops: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            registry: AtomicPtr::new(core::ptr::null_mut()),
            vector: core::sync::atomic::AtomicU8::new(0),
            domain_live: AtomicBool::new(true),
            arming_old_edge: AtomicBool::new(false),
            in_interrupt: AtomicBool::new(false),
        })
    }
}
struct Io(Arc<Board>);
// SAFETY: the board model is the only selector/window this test unit uses.
unsafe impl Registers for Io {
    fn read(&self, i: u8) -> u32 {
        let h = self.0.hw.lock().unwrap();
        if h.fail_read {
            u32::MAX
        } else if i < 0x10 {
            h.regs[usize::from(i)]
        } else if i.is_multiple_of(2) {
            h.regs[usize::from(i)] | h.reserved_low
        } else {
            h.regs[usize::from(i)] | h.reserved_high
        }
    }
    fn write(&self, i: u8, v: u32) {
        let mut h = self.0.hw.lock().unwrap();
        let i = usize::from(i);
        if i >= 0x10 && i % 2 == 1 {
            assert_ne!(
                h.regs[i - 1] & MASK,
                0,
                "destination changed before acknowledged mask"
            );
            assert_eq!(
                h.regs[i - 1] & (REMOTE_IRR | DELIVERY),
                0,
                "live route was reprogrammed"
            );
            h.events.push("destination");
            h.regs[i] = v;
        } else if i >= 0x10 {
            let old = h.regs[i];
            if h.refuse_mask && v & MASK != 0 {
                return;
            }
            let changed = (old ^ v) & CONFIG & !MASK;
            if changed != 0 {
                assert_ne!(old & MASK, 0, "electrical/vector changed before mask");
                // While Remote IRR is set only the trigger may change: the
                // switch to level before an EOI, or a level-to-edge write,
                // which releases Remote IRR.
                assert!(
                    old & REMOTE_IRR == 0 || changed == LEVEL || old & LEVEL != 0 && v & LEVEL == 0,
                    "pending route reprogrammed: {old:#x} -> {v:#x}"
                );
            }
            // Hardware does not allow software to clear RO RemoteIRR.
            h.regs[i] = (v & !(REMOTE_IRR | DELIVERY)) | old & (REMOTE_IRR | DELIVERY);
            if old & (1 << 15) != 0 && v & (1 << 15) == 0 && !h.broken_eoi {
                h.regs[i] &= !REMOTE_IRR;
                h.events.push("edge-eoi");
            }
            h.events.push(if v & MASK != 0 { "mask" } else { "unmask" });
            h.service();
        }
    }
    fn write_eoi(&self, vector: u8) {
        let mut h = self.0.hw.lock().unwrap();
        assert!(h.regs[1] as u8 >= 0x20);
        // The EOI register releases Remote IRR on each level entry holding
        // the vector.
        let pins = ((h.regs[1] >> 16) & 255) as usize + 1;
        let entries: alloc::vec::Vec<usize> = (0..pins)
            .map(|pin| 0x10 + pin * 2)
            .filter(|&i| h.regs[i] as u8 == vector && h.regs[i] & LEVEL != 0)
            .collect();
        assert!(!entries.is_empty(), "EOI for a vector no level entry holds");
        h.events.push("direct-eoi");
        if !h.broken_eoi {
            for i in entries {
                h.regs[i] &= !REMOTE_IRR;
            }
            h.service();
        }
    }
}
struct Domain(Arc<Board>);
// SAFETY: the original independent board peer owns this exact CPU/controller
// mode. Domain loss is controlled independently from RTE/pending/TMR effects.
unsafe impl NotificationDomain for Domain {
    fn check(&self) -> Result<(), posted_msi::Error> {
        if self.0.domain_live.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(posted_msi::Error::RootFailed)
        }
    }
}
struct Cpu(Arc<Board>);
// SAFETY: the board model is the single CPU this test unit runs on.
unsafe impl Platform for Cpu {
    fn check_cpu(&self) -> Result<(), IrqError> {
        Ok(())
    }
    fn check_process(&self) -> Result<(), stela_drivers::bus::irq::IrqError> {
        if self.0.in_interrupt.load(Ordering::Acquire) {
            return Err(IrqError::WrongCpu);
        }
        self.check_cpu()
    }
    fn save_and_disable(&self) -> u64 {
        0
    }
    unsafe fn restore(&self, s: u64) {
        assert_eq!(s, 0);
    }
    fn target(&self, v: u8) -> Result<Target, IrqError> {
        self.0.vector.store(v, Ordering::Relaxed);
        Ok(Target {
            destination: 3,
            vector: v,
        })
    }
    fn pending(&self, _: u8) -> Result<bool, IrqError> {
        Ok(self.0.hw.lock().unwrap().pending)
    }
    fn eoi(&self, _: u8) -> Result<Trigger, IrqError> {
        Ok(self.0.hw.lock().unwrap().eoi())
    }
    fn ticks(&self) -> u64 {
        self.0.ticks.fetch_add(1, Ordering::Relaxed)
    }
    fn timeout_ticks(&self) -> u64 {
        8
    }
    unsafe fn interrupt_window(&self) {
        // SAFETY: the fixture publishes its registry before any interrupt window and keeps it
        // alive.
        let r = unsafe { &*self.0.registry.load(Ordering::Relaxed) };
        assert!(r.dispatch(self.0.vector.load(Ordering::Relaxed)));
    }
}
struct Contributors(Arc<Board>);
// SAFETY: the board model owns the line's only contributor, which masks and quiesces in the
// model.
unsafe impl Devices for Contributors {
    fn mask(&mut self) -> Result<(), IrqError> {
        self.0.hw.lock().unwrap().events.push("device_mask");
        Ok(())
    }
    fn quiesce(&mut self) -> Result<(), IrqError> {
        let mut h = self.0.hw.lock().unwrap();
        h.asserted = 0;
        h.events.push("stopped");
        drop(h);
        if self.0.arming_old_edge.swap(false, Ordering::AcqRel) {
            {
                let mut hardware = self.0.hw.lock().unwrap();
                hardware.pending = true;
                hardware.tmr = Trigger::Edge;
                hardware.events.push("old-edge-arming");
            }
            // SAFETY: fixture publishes the original permanent Registry first.
            let registry = unsafe { &*self.0.registry.load(Ordering::Acquire) };
            assert!(registry.dispatch(self.0.vector.load(Ordering::Relaxed)));
        }
        Ok(())
    }
    unsafe fn enable(&mut self) -> Result<(), IrqError> {
        self.0.hw.lock().unwrap().events.push("device_enable");
        Ok(())
    }
}
impl Drop for Contributors {
    fn drop(&mut self) {
        self.0.drops.fetch_add(1, Ordering::Relaxed);
    }
}
struct Member(Arc<Board>, u32, bool);
impl Handler for Member {
    fn handle(&self) -> Disposition {
        let mut h = self.0.hw.lock().unwrap();
        self.0.calls.fetch_add(1, Ordering::Relaxed);
        if h.asserted & self.1 == 0 {
            return Disposition::NotMine;
        }
        if self.2 {
            h.asserted &= !self.1;
            h.events.push("cause_ack");
        }
        Disposition::Handled
    }
}
type Fixture = (
    Arc<Board>,
    Arc<Unit<Io, Cpu>>,
    &'static Registry<Cpu>,
    LineRoute,
);
fn fixture() -> Fixture {
    fixture_version(0x11)
}
fn fixture_version(version: u8) -> Fixture {
    let b = Board::new();
    b.hw.lock().unwrap().regs[1] = u32::from(version) | 23 << 16;
    let r = Box::leak(Box::new(Registry::new(Cpu(b.clone()))));
    b.registry.store(r, Ordering::Relaxed);
    // SAFETY: the model board is this unit's only selector/window owner.
    let u = unsafe {
        Unit::attach(
            Io(b.clone()),
            Cpu(b.clone()),
            Arc::new(Domain(b.clone())),
            r.identity(),
            0,
            0,
        )
    }
    .unwrap();
    (
        b,
        u,
        r,
        LineRoute {
            gsi: 9,
            polarity: Polarity::Low,
            trigger: Trigger::Level,
        },
    )
}

#[test]
fn firmware_containment_clears_every_pin_to_a_masked_edge_entry() {
    let (board, unit, _, _) = fixture();
    {
        let mut hardware = board.hw.lock().unwrap();
        hardware.regs[0x12] = 0x38;
        hardware.regs[0x13] = 2 << 24;
        hardware.regs[0x16] = LOWEST_PRIORITY | 0x42;
        hardware.regs[0x17] = 3 << 24;
        hardware.regs[0x18] = MASK | LEVEL | 1 << 13 | 0x45;
    }
    // SAFETY: sole controller, CPU and original firmware route model.
    let plan = unsafe { unit.firmware_routes() }.unwrap();
    assert!(board.hw.lock().unwrap().events.is_empty());
    // SAFETY: the fixture retains the exact original controller and its sources.
    unsafe { plan.contain() }.unwrap();
    plan.verify_contained().unwrap();
    assert_eq!(plan.withheld().count(), 0);
    for gsi in [1, 3, 4, 5] {
        plan.verify_line(unit.gsi_base() + gsi).unwrap();
    }
    {
        let mut hardware = board.hw.lock().unwrap();
        for pin in [1, 3, 4] {
            assert_eq!(&hardware.regs[0x10 + pin * 2..0x12 + pin * 2], &[MASK, 0]);
        }
        hardware.regs[0x13] = 4 << 24;
    }
    assert_eq!(plan.verify_line(unit.gsi_base() + 1), Err(IrqError::Route));
    plan.verify_line(unit.gsi_base() + 3).unwrap();
}

/// Linux clear_IO_APIC_pin: a stuck Remote IRR is released by switching the
/// masked pin to level and issuing an EOI, through the direct EOI register
/// from version 0x20 and by the edge/level flip before it.
#[test]
fn firmware_containment_releases_a_stuck_remote_irr() {
    for version in [0x11, 0x20] {
        for low in [LEVEL | 0x41, MASK | LEVEL | 0x41, 0x41, MASK | 0x41] {
            let (board, unit, _, _) = fixture_version(version);
            {
                let mut hardware = board.hw.lock().unwrap();
                hardware.regs[0x14] = low | REMOTE_IRR;
                hardware.regs[0x15] = 2 << 24;
                hardware.regs[0x16] = 0x38;
            }
            // SAFETY: sole controller, CPU and original firmware route model.
            let plan = unsafe { unit.firmware_routes() }.unwrap();
            // SAFETY: the fixture retains the exact original controller.
            unsafe { plan.contain() }.unwrap();
            assert_eq!(plan.withheld().count(), 0, "{version:#x} {low:#x}");
            plan.verify_line(2).unwrap();
            plan.verify_line(3).unwrap();
            plan.verify_contained().unwrap();
            let hardware = board.hw.lock().unwrap();
            assert_eq!(&hardware.regs[0x14..0x16], &[MASK, 0]);
            let kind = if version < 0x20 {
                "edge-eoi"
            } else {
                "direct-eoi"
            };
            assert!(hardware.events.contains(&kind), "{:?}", hardware.events);
        }
    }
}

/// A Remote IRR that no EOI releases leaves that one pin masked and
/// withheld after a bounded number of tries; every other pin is contained.
#[test]
fn a_remote_irr_that_stays_set_withholds_only_its_pin() {
    for version in [0x11, 0x20] {
        let (board, unit, _, line) = fixture_version(version);
        {
            let mut hardware = board.hw.lock().unwrap();
            hardware.regs[0x14] = MASK | LEVEL | 0x41 | REMOTE_IRR;
            hardware.regs[0x15] = 2 << 24;
            hardware.regs[0x16] = 0x38;
            hardware.regs[0x17] = 2 << 24;
            hardware.broken_eoi = true;
        }
        // SAFETY: sole controller, CPU and original firmware route model.
        let plan = unsafe { unit.firmware_routes() }.unwrap();
        // SAFETY: the fixture retains the exact original controller.
        unsafe { plan.contain() }.unwrap();
        assert_eq!(
            plan.withheld().collect::<alloc::vec::Vec<_>>(),
            [(2, IrqError::Drain)]
        );
        assert_eq!(plan.verify_line(2), Err(IrqError::Drain));
        plan.verify_line(3).unwrap();
        plan.verify_contained().unwrap();
        {
            let hardware = board.hw.lock().unwrap();
            assert_ne!(hardware.regs[0x14] & MASK, 0);
            assert_eq!(&hardware.regs[0x16..0x18], &[MASK, 0]);
            if version >= 0x20 {
                let eois = hardware
                    .events
                    .iter()
                    .filter(|event| **event == "direct-eoi")
                    .count();
                assert_eq!(eois, CLEAR_TRIES);
            }
            assert!(hardware.events.len() <= 6 * CLEAR_TRIES);
        }
        let stuck = LineRoute { gsi: 2, ..line };
        assert!(matches!(
            // SAFETY: the fixture owns this line and its only contributor.
            unsafe { unit.claim(stuck, Box::new(Contributors(board.clone()))) },
            Err(IrqError::Drain)
        ));
        // SAFETY: the fixture owns this line and its only contributor.
        let pin = unsafe { unit.claim(line, Box::new(Contributors(board.clone()))) }.unwrap();
        drop(pin);
    }
}

/// A Delivery Status that stays set, or the old vector still pending at the
/// CPU, withholds that pin alone.
#[test]
fn a_pending_delivery_or_cpu_vector_withholds_only_its_pin() {
    for (low, cpu_pending, cleared) in [
        (DELIVERY | 0x05, false, MASK | DELIVERY),
        (MASK | DELIVERY | LEVEL | 0x05, false, MASK | DELIVERY),
        (0x42, true, MASK),
        (LOWEST_PRIORITY | 0x42, true, MASK),
    ] {
        let (board, unit) = cohort_unit(24, 0, 0);
        {
            let mut hardware = board.hw.lock().unwrap();
            hardware.regs[0x14] = low;
            hardware.regs[0x16] = 0x06;
            hardware.pending = cpu_pending;
        }
        // SAFETY: sole controller, CPU and original firmware route model.
        let plan = unsafe { unit.firmware_routes() }.unwrap();
        // SAFETY: the fixture retains the exact original controller.
        unsafe { plan.contain() }.unwrap();
        assert_eq!(
            plan.withheld().collect::<alloc::vec::Vec<_>>(),
            [(2, IrqError::Drain)],
            "{low:#x}"
        );
        assert_eq!(plan.verify_line(2), Err(IrqError::Drain));
        plan.verify_line(3).unwrap();
        plan.verify_contained().unwrap();
        assert_eq!(board.hw.lock().unwrap().regs[0x14], cleared);
        // SAFETY: the fixture hands off this unclaimed line.
        assert_eq!(unsafe { unit.mask_unclaimed(2) }, Err(IrqError::Drain));
    }
}

#[test]
fn firmware_containment_refuses_a_changed_destination_and_failed_mask_readback() {
    let (board, unit, _, _) = fixture();
    board.hw.lock().unwrap().regs[0x12] = 0x38;
    // SAFETY: sole controller, CPU and original firmware route model.
    let plan = unsafe { unit.firmware_routes() }.unwrap();
    board.hw.lock().unwrap().regs[0x3f] = 2 << 24;
    // SAFETY: the fixture keeps the source, simulating a stale hardware reply.
    let result = unsafe { plan.contain() };
    assert_eq!(result, Err(IrqError::Route));
    {
        let mut hardware = board.hw.lock().unwrap();
        assert!(hardware.events.is_empty());
        hardware.regs[0x3f] = 0;
        hardware.refuse_mask = true;
    }
    // SAFETY: the fixture retains the exact controller and simulates a refusal.
    let result = unsafe { plan.contain() };
    assert_eq!(result, Err(IrqError::Mask));
    assert_eq!(plan.verify_contained(), Err(IrqError::Unavailable));
    board.hw.lock().unwrap().refuse_mask = false;
    // SAFETY: same original model; the uncertain first write bars replay.
    let replay = unsafe { plan.contain() };
    assert_eq!(replay, Err(IrqError::Unavailable));
    assert!(board.hw.lock().unwrap().events.is_empty());
}

#[test]
fn local_contributors_require_process_context_before_device_access() {
    struct Local(alloc::rc::Rc<()>, Contributors);
    // SAFETY: this wrapper owns the fixture's same contributor and delegates
    // all device effects to it while holding the local ownership marker.
    unsafe impl Devices for Local {
        fn mask(&mut self) -> Result<(), IrqError> {
            assert_eq!(alloc::rc::Rc::strong_count(&self.0), 2);
            self.1.mask()
        }
        fn quiesce(&mut self) -> Result<(), IrqError> {
            self.1.quiesce()
        }
        unsafe fn enable(&mut self) -> Result<(), IrqError> {
            // SAFETY: the enclosing source supplies the published route.
            unsafe { self.1.enable() }
        }
    }
    let (board, unit, _, line) = fixture();
    let local = alloc::rc::Rc::new(());
    let devices = Box::new(Local(local.clone(), Contributors(board.clone())));
    // SAFETY: the fixture owns this stopped line and its only contributor.
    let mut pin = unsafe { unit.claim(line, devices) }.unwrap();
    let before = board.hw.lock().unwrap().events.len();
    board.in_interrupt.store(true, Ordering::Release);
    assert_eq!(pin.mask(), Err(IrqError::WrongCpu));
    assert_eq!(pin.quiesce(), Err(IrqError::WrongCpu));
    assert_eq!(board.hw.lock().unwrap().events.len(), before);
    board.in_interrupt.store(false, Ordering::Release);
    pin.mask().unwrap();
    pin.quiesce().unwrap();
    drop(pin);
    assert_eq!(alloc::rc::Rc::strong_count(&local), 1);
}

#[test]
fn old_edge_during_arming_gets_only_local_eoi_before_pin_programming() {
    let (board, unit, registry, line) = fixture_version(0x20);
    // SAFETY: original fixture owns this exact stopped physical source.
    let pin = unsafe { unit.claim(line, Box::new(Contributors(board.clone()))) }.unwrap();
    board.arming_old_edge.store(true, Ordering::Release);
    let mut registration = registry
        .request(stela_drivers::bus::irq::Request {
            source: Box::new(pin),
            handler: Arc::new(Member(board.clone(), 1, true)),
            routing: stela_drivers::bus::irq::RouteRequest::Line(line),
        })
        .unwrap();
    assert_eq!(board.calls.load(Ordering::Relaxed), 0);
    {
        let hardware = board.hw.lock().unwrap();
        assert!(!hardware.pending);
        let old = hardware
            .events
            .iter()
            .position(|event| *event == "old-edge-arming")
            .unwrap();
        let local = hardware
            .events
            .iter()
            .position(|event| *event == "eoi")
            .unwrap();
        let destination = hardware
            .events
            .iter()
            .position(|event| *event == "destination")
            .unwrap();
        assert!(old < local && local < destination);
        assert!(!hardware.events.contains(&"direct-eoi"));
        assert!(!hardware.events.contains(&"edge-eoi"));
    }
    {
        let mut hardware = board.hw.lock().unwrap();
        hardware.asserted = 1;
        hardware.service();
    }
    assert!(registry.dispatch(registration.vector()));
    assert_eq!(board.calls.load(Ordering::Relaxed), 1);
    assert_eq!(board.hw.lock().unwrap().regs[0x22] & REMOTE_IRR, 0);
    finish(registration.retire().unwrap());
    assert_eq!(board.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn actual_registry_route_refuses_different_electrical_line_before_programming() {
    let (board, unit, registry, line) = fixture();
    // SAFETY: actual stopped fixture group owns precisely this claimed GSI.
    let pin = unsafe { unit.claim(line, Box::new(Contributors(board.clone()))) }.unwrap();
    let high = board.hw.lock().unwrap().regs[0x23];
    assert!(
        registry
            .request(stela_drivers::bus::irq::Request {
                source: Box::new(pin),
                handler: Arc::new(Member(board.clone(), 1, true)),
                routing: stela_drivers::bus::irq::RouteRequest::Line(LineRoute { gsi: 8, ..line }),
            })
            .is_err()
    );
    assert_eq!(board.hw.lock().unwrap().regs[0x23], high);
    assert_eq!(board.hw.lock().unwrap().regs[0x22] & 255, 0);
}

#[test]
fn foreign_registry_reservation_refuses_before_any_route_programming() {
    let (board, unit, _, line) = fixture();
    let foreign = Box::leak(Box::new(Registry::new(Cpu(board.clone()))));
    // SAFETY: actual fixture owns this stopped physical source.
    let pin = unsafe { unit.claim(line, Box::new(Contributors(board.clone()))) }.unwrap();
    let high_before = board.hw.lock().unwrap().regs[0x23];
    assert!(
        foreign
            .request(stela_drivers::bus::irq::Request {
                source: Box::new(pin),
                handler: Arc::new(Member(board.clone(), 1, true)),
                routing: stela_drivers::bus::irq::RouteRequest::Line(line),
            })
            .is_err()
    );
    assert_eq!(board.hw.lock().unwrap().regs[0x23], high_before);
    assert_eq!(board.hw.lock().unwrap().regs[0x22] & 255, 0);
}

#[test]
fn pin_domain_refuses_revoked_root_without_waiting_for_controller_lock() {
    let (board, unit, _, line) = fixture();
    // SAFETY: bounded source and genuine original board domain.
    let pin = unsafe { unit.claim(line, Box::new(Contributors(board.clone()))) }.unwrap();
    let domain = pin.notification_domain().unwrap();
    let _held = unit.lock();
    board.domain_live.store(false, Ordering::Release);
    // Independent original-root revocation is checked before any selector lock.
    assert_eq!(domain.check(), Err(posted_msi::Error::RootFailed));
    board.domain_live.store(true, Ordering::Release);
}

#[test]
fn old_edge_notification_clears_current_level_remote_irr_with_real_chip_eoi() {
    struct Deferred(Arc<ParentMask<Io, Cpu>>);
    impl Handler for Deferred {
        fn handle(&self) -> Disposition {
            stela_drivers::bus::irq::ParentMask::mask(&*self.0).unwrap();
            Disposition::Handled
        }
    }
    for version in [0x11, 0x20, 0x21] {
        for deferred in [false, true] {
            let (board, unit, registry, line) = fixture_version(version);
            // SAFETY: this exact board owns the stopped physical source group.
            let pin = unsafe { unit.claim(line, Box::new(Contributors(board.clone()))) }.unwrap();
            let parent = Arc::new(pin.parent_mask().unwrap());
            let handler: Arc<dyn Handler> = if deferred {
                Arc::new(Deferred(parent))
            } else {
                Arc::new(Member(board.clone(), 1, true))
            };
            let mut route = registry
                .request(stela_drivers::bus::irq::Request {
                    source: Box::new(pin),
                    handler,
                    routing: stela_drivers::bus::irq::RouteRequest::Line(line),
                })
                .unwrap();
            {
                let mut h = board.hw.lock().unwrap();
                h.asserted = 1;
                h.service();
                assert_ne!(h.regs[0x22] & REMOTE_IRR, 0);
                // Independent accepted old edge notification changes CPU TMR;
                // controller RemoteIRR and current source cause remain real.
                h.tmr = Trigger::Edge;
                h.events.clear();
            }
            assert!(registry.dispatch(route.vector()));
            {
                let h = board.hw.lock().unwrap();
                assert_eq!(h.regs[0x22] & REMOTE_IRR, 0);
                assert_eq!(h.regs[0x22] & MASK != 0, deferred);
                let kind = if version < 0x20 {
                    "edge-eoi"
                } else {
                    "direct-eoi"
                };
                let local = h.events.iter().position(|event| *event == "eoi").unwrap();
                let chip = h.events.iter().position(|event| *event == kind).unwrap();
                assert!(local < chip);
            }
            finish(route.retire().unwrap());
        }
    }
}

#[test]
fn captured_chip_endpoint_remains_valid_through_retired_source_then_cannot_touch_reuse() {
    let (board, unit, _, line) = fixture_version(0x20);
    // SAFETY: same independent stopped board source and bounded programming peer.
    let mut pin = unsafe { unit.claim(line, Box::new(Contributors(board.clone()))) }.unwrap();
    let target = Target {
        destination: 3,
        vector: 0x51,
    };
    // Independent bounded hardware peer: do not invent a Registry reservation.
    // This fixture tests endpoint lifetime after the real pin state was installed.
    pin.target = Some(target);
    pin.retired = false;
    pin.lifetime.phase.store(PROGRAMMED, Ordering::Release);
    {
        let mut hardware = board.hw.lock().unwrap();
        hardware.regs[0x22] = MASK | u32::from(target.vector) | (1 << 13) | (1 << 15);
        hardware.regs[0x23] = u32::from(target.destination) << 24;
    }
    let domain = pin.notification_domain().unwrap();
    let endpoint = PinEoi {
        unit: ManuallyDrop::new(unit.clone()),
        lifetime: ManuallyDrop::new(pin.lifetime.clone()),
        pin: pin.pin,
        epoch: pin.epoch,
        target,
        line,
    };
    // SAFETY: original CPU callback/work peer is fully stopped and source masked.
    unsafe { pin.synchronize() }.unwrap();
    domain.check().unwrap();
    endpoint.after_local_eoi(Trigger::Edge).unwrap();
    drop(pin);
    assert_eq!(board.drops.load(Ordering::Relaxed), 1);
    assert_eq!(domain.check(), Err(posted_msi::Error::RootFailed));
    // SAFETY: the exact old board group has retired before this fresh claim.
    let replacement = unsafe { unit.claim(line, Box::new(Contributors(board.clone()))) }.unwrap();
    let writes = board.hw.lock().unwrap().events.len();
    assert_eq!(
        endpoint.after_local_eoi(Trigger::Edge),
        Err(IrqError::Unregistered)
    );
    assert_eq!(board.hw.lock().unwrap().events.len(), writes);
    drop(replacement);
}

#[test]
fn chip_eoi_fault_keeps_source_and_forbids_deferred_rearm() {
    let (board, unit, registry, line) = fixture_version(0x20);
    // SAFETY: this exact stopped board group belongs to the fixture.
    let pin = unsafe { unit.claim(line, Box::new(Contributors(board.clone()))) }.unwrap();
    let parent = pin.parent_mask().unwrap();
    let mut route = registry
        .request(stela_drivers::bus::irq::Request {
            source: Box::new(pin),
            handler: Arc::new(Member(board.clone(), 1, true)),
            routing: stela_drivers::bus::irq::RouteRequest::Line(line),
        })
        .unwrap();
    {
        let mut h = board.hw.lock().unwrap();
        h.asserted = 1;
        h.service();
        h.tmr = Trigger::Edge;
        h.fail_read = true;
    }
    assert!(registry.dispatch(route.vector()));
    board.hw.lock().unwrap().fail_read = false;
    // SAFETY: original process peer; a failed chip acknowledgement cannot rearm.
    assert_eq!(unsafe { parent.rearm() }, Err(IrqError::Drain));
    assert!(route.retire().is_err());
    drop(route);
    assert_eq!(board.drops.load(Ordering::Relaxed), 0);
}
#[test]
fn real_parent_mask_contains_asserted_level_and_stale_endpoint_cannot_mask_reused_pin() {
    struct FailedDemux(Arc<ParentMask<Io, Cpu>>);
    impl Handler for FailedDemux {
        fn handle(&self) -> Disposition {
            // Callback cannot ACK its device. It must acknowledge
            // parent MASK before Registry's EOI instead of returning live.
            stela_drivers::bus::irq::ParentMask::mask(&*self.0).unwrap();
            Disposition::Handled
        }
    }
    let (b, u, r, line) = fixture();
    // SAFETY: the fixture owns the stopped line and its contributors.
    let pin = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
    let endpoint = Arc::new(pin.parent_mask().unwrap());
    let mut registration = r
        .request(stela_drivers::bus::irq::Request {
            source: Box::new(pin),
            handler: Arc::new(FailedDemux(endpoint.clone())),
            routing: stela_drivers::bus::irq::RouteRequest::Line(line),
        })
        .unwrap();
    {
        let mut h = b.hw.lock().unwrap();
        h.asserted = 1;
        h.service();
    }
    assert!(r.dispatch(registration.vector()));
    {
        let h = b.hw.lock().unwrap();
        assert_eq!(
            h.asserted, 1,
            "test must retain the unacknowledged child cause"
        );
        assert_ne!(h.regs[0x22] & MASK, 0);
        assert_eq!(h.regs[0x22] & REMOTE_IRR, 0);
        assert!(!h.pending, "masked parent must not retrigger after EOI");
    }
    finish(registration.retire().unwrap());
    assert_eq!(
        stela_drivers::bus::irq::ParentMask::mask(&*endpoint),
        Err(IrqError::Unregistered)
    );
    // SAFETY: the fixture owns the stopped line and its contributors.
    let replacement = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
    let replacement_mask = replacement.parent_mask().unwrap();
    let mut replacement = r
        .request(stela_drivers::bus::irq::Request {
            source: Box::new(replacement),
            handler: Arc::new(Member(b.clone(), 1, true)),
            routing: stela_drivers::bus::irq::RouteRequest::Line(line),
        })
        .unwrap();
    assert_eq!(
        stela_drivers::bus::irq::ParentMask::mask(&*endpoint),
        Err(IrqError::Unregistered)
    );
    assert_eq!(
        b.hw.lock().unwrap().regs[0x22] & MASK,
        0,
        "stale endpoint changed the new live route"
    );
    assert_eq!(
        stela_drivers::bus::irq::ParentMask::mask(&replacement_mask),
        Ok(())
    );
    finish(replacement.retire().unwrap());
}

#[test]
fn deferred_rearm_checks_drain_epoch_and_retirement() {
    struct Deferred(Arc<ParentMask<Io, Cpu>>);
    impl Handler for Deferred {
        fn handle(&self) -> Disposition {
            stela_drivers::bus::irq::ParentMask::mask(&*self.0).unwrap();
            Disposition::Handled
        }
    }
    let (board, unit, registry, line) = fixture();
    // SAFETY: the fixture owns the stopped line and its contributors.
    let pin = unsafe { unit.claim(line, Box::new(Contributors(board.clone()))) }.unwrap();
    let parent = Arc::new(pin.parent_mask().unwrap());
    let mut route = registry
        .request(stela_drivers::bus::irq::Request {
            source: Box::new(pin),
            handler: Arc::new(Deferred(parent.clone())),
            routing: stela_drivers::bus::irq::RouteRequest::Line(line),
        })
        .unwrap();
    // A still-live unmasked route cannot be rearmed as if it was drained.
    // SAFETY: the test is the parent mask's only caller, in process context.
    assert_eq!(unsafe { parent.rearm() }, Err(IrqError::Route));
    {
        let mut hw = board.hw.lock().unwrap();
        hw.asserted = 1;
        hw.service();
    }
    assert!(registry.dispatch(route.vector()));
    {
        let mut hw = board.hw.lock().unwrap();
        hw.asserted = 0;
        hw.regs[0x22] |= REMOTE_IRR;
    }
    // SAFETY: the test is the parent mask's only caller, in process context.
    assert_eq!(unsafe { parent.rearm() }, Err(IrqError::Drain));
    {
        let mut hw = board.hw.lock().unwrap();
        hw.regs[0x22] &= !REMOTE_IRR;
        hw.pending = true;
    }
    // SAFETY: the test is the parent mask's only caller, in process context.
    assert_eq!(unsafe { parent.rearm() }, Err(IrqError::Drain));
    board.hw.lock().unwrap().pending = false;
    // SAFETY: the modeled child is acknowledged, EOI/IRR are drained,
    // and no deferred producer remains on this owning fixture CPU.
    unsafe { parent.rearm() }.unwrap();
    assert_eq!(board.hw.lock().unwrap().regs[0x22] & MASK, 0);
    finish(route.retire().unwrap());
    // SAFETY: the test is the parent mask's only caller, in process context.
    assert_eq!(unsafe { parent.rearm() }, Err(IrqError::Unregistered));
}

#[test]
fn parent_mask_readback_failures_are_errors_and_claim_epochs_never_wrap() {
    let (b, u, r, line) = fixture();
    // SAFETY: the fixture owns the stopped line and its contributors.
    let pin = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
    let endpoint = pin.parent_mask().unwrap();
    let mut registration = r
        .request(stela_drivers::bus::irq::Request {
            source: Box::new(pin),
            handler: Arc::new(Member(b.clone(), 1, true)),
            routing: stela_drivers::bus::irq::RouteRequest::Line(line),
        })
        .unwrap();
    b.hw.lock().unwrap().refuse_mask = true;
    assert_eq!(
        stela_drivers::bus::irq::ParentMask::mask(&endpoint),
        Err(IrqError::Mask)
    );
    b.hw.lock().unwrap().fail_read = true;
    assert_eq!(
        stela_drivers::bus::irq::ParentMask::mask(&endpoint),
        Err(IrqError::FailedRead)
    );
    {
        let mut h = b.hw.lock().unwrap();
        h.fail_read = false;
        h.refuse_mask = false;
    }
    finish(registration.retire().unwrap());
    {
        let _guard = u.lock();
        // SAFETY: the unit lock held above serializes the epoch counter.
        unsafe { *u.next_epoch.get() = u64::MAX };
    }
    assert!(matches!(
        // SAFETY: the fixture owns the stopped line and its contributors.
        unsafe { u.claim(line, Box::new(Contributors(b.clone()))) },
        Err(IrqError::Exhausted)
    ));
    assert_eq!(
        stela_drivers::bus::irq::ParentMask::mask(&endpoint),
        Err(IrqError::Unregistered)
    );
}

#[test]
fn true_level_retriggers_after_eoi_until_cause_ack_then_shared_group_retires() {
    let (b, u, r, line) = fixture();
    // SAFETY: the fixture owns the stopped line and its contributors.
    let pin = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
    let first: Arc<dyn Handler> = Arc::new(Member(b.clone(), 1, false));
    let second: Arc<dyn Handler> = Arc::new(Member(b.clone(), 2, true));
    let group = Arc::new(SharedHandlers::new(alloc::vec![first.clone(), second.clone()]).unwrap());
    let mut registration = r
        .request(stela_drivers::bus::irq::Request {
            source: Box::new(pin),
            handler: group.clone(),
            routing: stela_drivers::bus::irq::RouteRequest::Line(line),
        })
        .unwrap();
    {
        let mut h = b.hw.lock().unwrap();
        h.asserted = 3;
        h.service();
    }
    assert!(r.dispatch(registration.vector()));
    {
        let h = b.hw.lock().unwrap();
        assert_eq!(h.asserted, 1);
        assert!(h.pending);
        assert_ne!(h.regs[0x22] & REMOTE_IRR, 0);
    }
    assert_eq!(registration.handled(), Ok(1));
    assert_eq!(Arc::strong_count(&group), 2);
    assert_eq!(Arc::strong_count(&first), 2);
    // A second delivery remains possible; removal must mask first,
    // stop every contributor, then drain CPU EOI and IOAPIC RemoteIRR.
    finish(registration.retire().unwrap());
    let h = b.hw.lock().unwrap();
    assert!(!h.pending);
    assert_eq!(h.regs[0x22] & REMOTE_IRR, 0);
    assert_ne!(h.regs[0x22] & MASK, 0);
    let mask = h.events.iter().rposition(|s| *s == "mask").unwrap();
    let stop = h.events.iter().rposition(|s| *s == "stopped").unwrap();
    assert!(mask < stop);
    assert_eq!(
        b.calls.load(Ordering::Relaxed),
        2,
        "closing delivery must never enter members"
    );
    drop(h);
    assert_eq!(b.drops.load(Ordering::Relaxed), 1);
    assert_eq!(Arc::strong_count(&group), 1);
    // SAFETY: the fixture owns the stopped line and its contributors.
    let reused = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
    drop(reused);
}
#[test]
fn failed_controller_eoi_or_read_keeps_route_and_contributors_for_real_retry() {
    let (b, u, r, line) = fixture();
    // SAFETY: the fixture owns the stopped line and its contributors.
    let pin = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
    let mut registration = r
        .request(stela_drivers::bus::irq::Request {
            source: Box::new(pin),
            handler: Arc::new(Member(b.clone(), 1, true)),
            routing: stela_drivers::bus::irq::RouteRequest::Line(line),
        })
        .unwrap();
    {
        let mut h = b.hw.lock().unwrap();
        h.asserted = 1;
        h.service();
        h.broken_eoi = true;
    }
    assert!(matches!(registration.retire(), Err(IrqError::Drain)));
    assert_eq!(b.drops.load(Ordering::Relaxed), 0);
    assert!(matches!(
        // SAFETY: the fixture owns the stopped line and its contributors.
        unsafe { u.claim(line, Box::new(Contributors(b.clone()))) },
        Err(IrqError::Drain)
    ));
    {
        let mut h = b.hw.lock().unwrap();
        h.fail_read = true;
    }
    assert!(matches!(registration.retire(), Err(IrqError::FailedRead)));
    {
        let mut h = b.hw.lock().unwrap();
        h.fail_read = false;
        h.broken_eoi = false;
        h.eoi();
    }
    finish(registration.retire().unwrap());
    assert_eq!(u.quarantine_count(), 0);
}
#[test]
fn electrical_route_mismatch_duplicate_claim_mask_failure_and_abandoned_pin_are_kept() {
    let (b, u, r, line) = fixture();
    // SAFETY: the fixture owns the stopped line and its contributors.
    let pin = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
    assert!(matches!(
        // SAFETY: the fixture owns the stopped line and its contributors.
        unsafe { u.claim(line, Box::new(Contributors(b.clone()))) },
        Err(IrqError::Exhausted)
    ));
    let mut registration = r
        .request(stela_drivers::bus::irq::Request {
            source: Box::new(pin),
            handler: Arc::new(Member(b.clone(), 1, true)),
            routing: stela_drivers::bus::irq::RouteRequest::Line(line),
        })
        .unwrap();
    b.hw.lock().unwrap().refuse_mask = true;
    assert!(matches!(registration.retire(), Err(IrqError::Mask)));
    let before = b.drops.load(Ordering::Relaxed);
    drop(registration);
    assert_eq!(r.quarantine_count(), 1);
    assert_eq!(b.drops.load(Ordering::Relaxed), before);
    // Raw source owner also cannot silently free a programmed pin without
    // the unsafe completed-synchronization proof supplied by Registry.
    b.hw.lock().unwrap().refuse_mask = false;
    let other = LineRoute { gsi: 10, ..line };
    // SAFETY: the fixture owns the stopped line and its contributors.
    let mut pin = unsafe { u.claim(other, Box::new(Contributors(b.clone()))) }.unwrap();
    // Independent physical peer: hardware publication has already occurred.
    // No fabricated Registry reservation or completion receipt is constructed.
    pin.target = Some(Target {
        destination: 3,
        vector: FIRST_VECTOR + 1,
    });
    pin.retired = false;
    pin.lifetime.phase.store(PROGRAMMED, Ordering::Release);
    drop(pin);
    assert_eq!(u.quarantine_count(), 1);
}

/// An edge line (the ISA keyboard's IRQ 1) is programmed edge-triggered,
/// completes with the local EOI alone and drains without Remote IRR.
#[test]
fn an_edge_line_completes_with_the_local_eoi_alone() {
    for version in [0x11, 0x20] {
        let (b, u, r, line) = fixture_version(version);
        let edge = LineRoute {
            polarity: Polarity::High,
            trigger: Trigger::Edge,
            ..line
        };
        // SAFETY: the fixture owns the stopped line and its contributors.
        let pin = unsafe { u.claim(edge, Box::new(Contributors(b.clone()))) }.unwrap();
        let mut registration = r
            .request(stela_drivers::bus::irq::Request {
                source: Box::new(pin),
                handler: Arc::new(Member(b.clone(), 1, true)),
                routing: stela_drivers::bus::irq::RouteRequest::Line(edge),
            })
            .unwrap();
        let low = b.hw.lock().unwrap().regs[0x22];
        assert_eq!(low & (MASK | 1 << 15 | 1 << 13), 0, "{low:#x}");
        for _ in 0..2 {
            {
                let mut h = b.hw.lock().unwrap();
                h.asserted = 1;
                h.pending = true;
                h.tmr = Trigger::Edge;
            }
            assert!(r.dispatch(registration.vector()));
        }
        assert_eq!(registration.handled(), Ok(2));
        {
            let h = b.hw.lock().unwrap();
            assert!(!h.events.contains(&"direct-eoi"));
            assert!(!h.events.contains(&"edge-eoi"));
            assert!(!h.pending);
        }
        finish(registration.retire().unwrap());
        assert_eq!(b.drops.load(Ordering::Relaxed), 1);
        assert_eq!(u.quarantine_count(), 0);
    }
}

fn finish(retired: stela_drivers::bus::irq::RetiredSource<dyn stela_drivers::bus::irq::Source>) {
    // SAFETY: this model's exact line route completed on its owner CPU.
    let (source, callback, route) =
        unsafe { retired.into_parts() }.unwrap_or_else(|_| panic!("model owner changed"));
    drop(source);
    drop(callback);
    drop(route);
}

/// A cohort unit with `pins` version-reported pins, all masked.
fn cohort_unit(pins: u16, id: u8, gsi_base: u32) -> (Arc<Board>, Arc<Unit<Io, Cpu>>) {
    let b = Board::new();
    {
        let mut hardware = b.hw.lock().unwrap();
        hardware.regs[1] = 0x21 | u32::from(pins - 1) << 16;
        for pin in 0..usize::from(pins) {
            hardware.regs[0x10 + pin * 2] = MASK;
        }
    }
    let r = Box::leak(Box::new(Registry::new(Cpu(b.clone()))));
    b.registry.store(r, Ordering::Relaxed);
    // SAFETY: each model board is its unit's only selector/window owner.
    let u = unsafe {
        Unit::attach(
            Io(b.clone()),
            Cpu(b.clone()),
            Arc::new(Domain(b.clone())),
            r.identity(),
            id,
            gsi_base,
        )
    }
    .unwrap();
    (b, u)
}

/// An AMD desktop MADT: the FCH IOAPIC (24 pins at GSI 0), a second IOAPIC
/// at GSI 24, the timer override and an active-low level SCI on IRQ 9.
fn amd_madt() -> alloc::vec::Vec<u8> {
    let mut b = alloc::vec![0u8; 44];
    b[40] = 1; // PCAT_COMPAT: an 8259 pair exists beside the IOAPICs.
    b.extend_from_slice(&[1, 12, 0x21, 0, 0, 0, 0xc0, 0xfe, 0, 0, 0, 0]);
    b.extend_from_slice(&[1, 12, 0x22, 0, 0, 0x10, 0xc0, 0xfe, 24, 0, 0, 0]);
    b.extend_from_slice(&[2, 10, 0, 0, 2, 0, 0, 0, 0, 0]);
    b.extend_from_slice(&[2, 10, 0, 9, 9, 0, 0, 0, 0x0f, 0]);
    b[..4].copy_from_slice(b"APIC");
    let length = b.len() as u32;
    b[4..8].copy_from_slice(&length.to_le_bytes());
    b[9] = 0u8.wrapping_sub(b.iter().fold(0u8, |s, x| s.wrapping_add(*x)));
    b
}

#[test]
fn amd_two_ioapic_cohort_masks_firmware_unmasked_legacy_pins_and_verifies_i8042_lines() {
    let routing = crate::madt::Routing::parse(&amd_madt(), 48).unwrap();
    assert!(routing.has_legacy_pic());
    let [first, second] = routing.units[..] else {
        panic!("two MADT IOAPICs")
    };
    let (fch, fch_unit) = cohort_unit(24, first.id, first.gsi_base);
    let (other, other_unit) = cohort_unit(32, second.id, second.gsi_base);
    {
        // Firmware left the 8259 virtual wire, both i8042 lines (one at a
        // low ISA vector) and one line of the second unit unmasked.
        let mut hardware = fch.hw.lock().unwrap();
        hardware.regs[0x10] = EXT_INT;
        hardware.regs[0x12] = 0x31;
        hardware.regs[0x28] = LOWEST_PRIORITY | 0x0c;
        hardware.regs[0x29] = 1 << 24;
        other.hw.lock().unwrap().regs[0x16] = 1 << 15 | 1 << 13 | 0x41;
    }
    let spans = [(first, fch_unit.pins()), (second, other_unit.pins())];
    routing.validate_units(&spans).unwrap();
    // SAFETY: sole controllers, CPU and original firmware route models.
    let routes = unsafe {
        [
            fch_unit.firmware_routes().unwrap(),
            other_unit.firmware_routes().unwrap(),
        ]
    };
    let keyboard = routing.isa(1).unwrap();
    let mouse = routing.isa(12).unwrap();
    // Nothing is verified before the cohort is contained.
    assert_eq!(
        verify_owned_line(&routing, &spans, &routes, keyboard),
        Err(IrqError::Unavailable)
    );
    for plan in &routes {
        // SAFETY: the fixture retains each exact original controller.
        unsafe { plan.contain() }.unwrap();
    }
    assert_eq!(
        verify_owned_line(&routing, &spans, &routes, keyboard),
        Ok(0)
    );
    assert_eq!(verify_owned_line(&routing, &spans, &routes, mouse), Ok(0));
    let second_line = LineRoute {
        gsi: 27,
        polarity: Polarity::Low,
        trigger: Trigger::Level,
    };
    assert_eq!(
        verify_owned_line(&routing, &spans, &routes, second_line),
        Ok(1)
    );
    for (board, pins) in [(&fch, 24), (&other, 32)] {
        let hardware = board.hw.lock().unwrap();
        for pin in 0..pins {
            assert_ne!(hardware.regs[0x10 + pin * 2] & MASK, 0, "pin {pin} masked");
        }
    }
    assert_eq!(fch.hw.lock().unwrap().regs[0x10], MASK);
    assert_eq!(&fch.hw.lock().unwrap().regs[0x28..0x2a], &[MASK, 0]);
    // A GSI past both units, or plans out of cohort order, verify nothing.
    let outside = LineRoute {
        gsi: 56,
        ..second_line
    };
    assert_eq!(
        verify_owned_line(&routing, &spans, &routes, outside),
        Err(IrqError::Route)
    );
    let [a, b] = routes;
    let swapped = [b, a];
    assert_eq!(
        verify_owned_line(&routing, &spans, &swapped, keyboard),
        Err(IrqError::Route)
    );
    assert_eq!(
        verify_owned_line(&routing, &spans[..1], &swapped[..1], keyboard),
        Err(IrqError::Route)
    );
}

/// Reserved bits are compared nowhere, as in Linux: chips read some back
/// set, and an Intel PCH keeps an Extended Destination ID in bits 55:48
/// that firmware (ASUS B660, AMI) leaves behind, which containment clears.
#[test]
fn firmware_containment_compares_only_defined_bits() {
    let (board, unit) = cohort_unit(24, 0, 0);
    {
        let mut hw = board.hw.lock().unwrap();
        hw.regs[0x12] = MASK | 0x31;
        hw.regs[0x13] = 0x00ab_0000;
        hw.regs[0x14] = 0x31;
        hw.regs[0x15] = 0x01ab_0000;
        hw.reserved_low = 0xfffe_0000;
        hw.reserved_high = 0x0000_ffff;
    }
    // SAFETY: sole controller, CPU and original firmware route model.
    let plan = unsafe { unit.firmware_routes() }.unwrap();
    // SAFETY: the fixture retains the exact original controller.
    unsafe { plan.contain() }.unwrap();
    assert_eq!(plan.withheld().count(), 0);
    plan.verify_contained().unwrap();
    plan.verify_line(1).unwrap();
    plan.verify_line(2).unwrap();
    {
        let mut hw = board.hw.lock().unwrap();
        assert_eq!(&hw.regs[0x12..0x16], &[MASK, 0, MASK, 0]);
        // A defined bit still counts.
        hw.regs[0x13] = 0x0001_0000;
    }
    assert_eq!(plan.verify_line(1), Err(IrqError::Route));
}

/// Linux clear_IO_APIC_pin leaves an SMI pin alone, masked or not, and
/// masks and clears a pin in every other mode. The SMI pin is kept out of
/// the lines handed to devices; the rest proceed.
#[test]
fn firmware_containment_leaves_smi_pins_alone_and_clears_every_other_mode() {
    for masked in [0, MASK] {
        let (board, unit) = cohort_unit(24, 0, 0);
        let others = [
            (2, 0),
            (3, LOWEST_PRIORITY),
            (4, 3 << 8),
            (5, 4 << 8),
            (6, 5 << 8),
            (7, 6 << 8),
            (8, EXT_INT),
        ];
        {
            let mut hw = board.hw.lock().unwrap();
            hw.regs[0x12] = masked | SMI | 0x31;
            hw.regs[0x13] = 1 << 24;
            for (pin, mode) in others {
                hw.regs[0x10 + pin * 2] = mode | 0x01;
            }
        }
        // SAFETY: sole controller, CPU and original firmware route model.
        let plan = unsafe { unit.firmware_routes() }.unwrap();
        // SAFETY: the fixture retains the exact original controller.
        unsafe { plan.contain() }.unwrap();
        {
            let hw = board.hw.lock().unwrap();
            assert_eq!(&hw.regs[0x12..0x14], &[masked | SMI | 0x31, 1 << 24]);
            for (pin, mode) in others {
                let entry = &hw.regs[0x10 + pin * 2..0x12 + pin * 2];
                assert_eq!(entry, &[MASK, 0], "mode {mode:#x}");
            }
        }
        assert_eq!(
            plan.withheld().collect::<alloc::vec::Vec<_>>(),
            [(1, IrqError::Unsupported)]
        );
        assert_eq!(plan.verify_line(1), Err(IrqError::Unsupported));
        for (pin, _) in others {
            plan.verify_line(pin as u32).unwrap();
        }
        plan.verify_contained().unwrap();
        let smi = LineRoute {
            gsi: 1,
            polarity: Polarity::High,
            trigger: Trigger::Edge,
        };
        assert!(matches!(
            // SAFETY: the fixture owns this line and its only contributor.
            unsafe { unit.claim(smi, Box::new(Contributors(board.clone()))) },
            Err(IrqError::Unsupported)
        ));
        assert_eq!(
            // SAFETY: the fixture hands off this unclaimed line.
            unsafe { unit.mask_unclaimed(1) },
            Err(IrqError::Unsupported)
        );
        assert_eq!(board.hw.lock().unwrap().regs[0x12], masked | SMI | 0x31);
        // Another writer turning the SMI pin into a device route is caught.
        board.hw.lock().unwrap().regs[0x12] = MASK | 0x31;
        assert_eq!(plan.verify_contained(), Err(IrqError::Route));
    }
}
