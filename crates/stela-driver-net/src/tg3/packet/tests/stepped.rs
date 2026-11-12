// SPDX-License-Identifier: GPL-2.0-only
//! Runtime calls bounded on a model clock: link checks rate-limited and run
//! in steps, so no call holds the processor long.
use super::*;
use stela_driver_base::stepped::block_on;

/// No runtime call may wait longer than this on the model clock.
const CALL_US: u64 = 60_000;

/// A model clock: every wait advances it, and intervals end on it.
#[derive(Clone)]
struct ModelClock(Rc<Cell<u64>>);
impl ModelClock {
    fn now(&self) -> u64 {
        self.0.get()
    }
    fn advance(&self, microseconds: u64) {
        self.0.set(self.0.get() + microseconds);
    }
}
// SAFETY: isolated virtual-time model only; no native timing permission.
unsafe impl Delay for ModelClock {
    fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
        Ok(())
    }
    fn wait_us(&self, microseconds: u64) -> Result<(), crate::bus::pci::power::Error> {
        self.advance(microseconds);
        Ok(())
    }
    fn begin_interval(
        &self,
        microseconds: u64,
    ) -> Result<Option<Box<dyn crate::bus::pci::power::Interval>>, crate::bus::pci::power::Error>
    {
        Ok(Some(Box::new(Due {
            clock: self.0.clone(),
            at: self.now() + microseconds,
        })))
    }
}
struct Due {
    clock: Rc<Cell<u64>>,
    at: u64,
}
impl crate::bus::pci::power::Interval for Due {
    fn elapsed(&self) -> Result<bool, crate::bus::pci::power::Error> {
        Ok(self.clock.get() >= self.at)
    }
}

struct Clocked {
    packet: Packet<Reg, ModelClock>,
    clock: ModelClock,
    domain: Arc<Domain>,
    peer: Arc<Mutex<Device>>,
    _pages: Pages,
}

/// The ordinary model adapter, attached on the model clock.
fn clocked(prepare: impl FnOnce(&mut Device)) -> Clocked {
    let (mut hardware, pages, domain, peer) = parts();
    prepare(&mut peer.lock().unwrap());
    let clock = ModelClock(Rc::new(Cell::new(0)));
    let registers = hardware.release_registers();
    // SAFETY: the same isolated peer's original register owner, on the model clock.
    let hardware = unsafe { Hardware::new(registers, clock.clone()) };
    // SAFETY: the model device, its pages and its domain belong to this test alone.
    let packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
        Ok(packet) => packet,
        Err((error, _)) => panic!("attach: {error:?}"),
    };
    Clocked {
        packet,
        clock,
        domain,
        peer,
        _pages: pages,
    }
}

fn phy_accesses(peer: &Arc<Mutex<Device>>) -> usize {
    peer.lock()
        .unwrap()
        .access
        .iter()
        .filter(|&&(_, at, _)| at == 0x44c)
        .count()
}

/// One carrier, receive or transmit call in turn while work holds the
/// hardware: each waits at most [`CALL_US`], the carrier is down, receive
/// finds nothing and transmit has no carrier. Returns the calls' total wait
/// and their number once no work is under way.
fn step_until_idle(fixture: &mut Clocked) -> (u64, usize) {
    let (mut total, mut calls) = (0, 0);
    loop {
        let before = fixture.clock.now();
        match calls % 3 {
            0 => {
                let up = fixture.packet.carrier();
                assert!(!up || fixture.packet.work.is_none());
            }
            1 => {
                let received = fixture.packet.receive();
                if fixture.packet.work.is_some() {
                    assert_eq!(received, Ok(None));
                }
            }
            _ => {
                let sent = fixture.packet.transmit(&[0x5a; 60]);
                if fixture.packet.work.is_some() {
                    assert_eq!(sent, Err(LinkError::NoCarrier));
                }
            }
        }
        let waited = fixture.clock.now() - before;
        assert!(waited <= CALL_US, "call {calls} waited {waited} us");
        total += waited;
        calls += 1;
        if fixture.packet.work.is_none() {
            return (total, calls);
        }
    }
}

#[test]
fn ordinary_calls_between_link_checks_make_no_phy_access() {
    if crate::test_process::isolate_model() {
        return;
    }
    let mut f = clocked(|_| {});
    assert!(f.packet.carrier());
    let accesses = phy_accesses(&f.peer);
    let at = f.clock.now();
    for _ in 0..3 {
        f.packet.transmit(&[0x5a; 60]).unwrap();
    }
    f.peer.lock().unwrap().receive(&[0x33; 60], 0, &f.domain);
    assert_eq!(f.packet.receive().unwrap(), Some(vec![0x33; 60]));
    assert_eq!(f.packet.receive().unwrap(), None);
    assert!(f.packet.carrier());
    assert_eq!(phy_accesses(&f.peer), accesses);
    assert_eq!(f.clock.now(), at);
    // A lost link is seen at the next check, a second after the last.
    f.peer.lock().unwrap().phy.insert(1, 0);
    assert!(f.packet.carrier());
    assert_eq!(phy_accesses(&f.peer), accesses);
    f.clock.advance(LINK_POLL_US);
    assert!(!f.packet.carrier());
    step_until_idle(&mut f);
    assert!(phy_accesses(&f.peer) > accesses);
    assert_eq!(f.domain.drains.load(Ordering::Relaxed), 1);
    assert_eq!(f.packet.failure(), None);
}

/// A PHY that takes almost Linux's whole 50 ms per MDIO command: a link
/// check of four reads runs over several calls, none waiting more than
/// 60 ms, and waits in all what the same check waits run at once.
#[test]
fn a_slow_link_check_runs_in_steps_within_linux_bounds() {
    if crate::test_process::isolate_model() {
        return;
    }
    let mut blocking = clocked(|_| {});
    assert!(blocking.packet.carrier());
    blocking.peer.lock().unwrap().mdio_slow = 4990;
    let before = blocking.clock.now();
    assert_eq!(
        block_on(blocking.packet.hardware.packet_carrier()),
        Ok(true)
    );
    let expected = blocking.clock.now() - before;
    assert!(expected > 4 * 49_000, "{expected}");

    let mut f = clocked(|_| {});
    assert!(f.packet.carrier());
    f.peer.lock().unwrap().mdio_slow = 4990;
    f.clock.advance(LINK_POLL_US);
    let (total, calls) = step_until_idle(&mut f);
    assert_eq!(total, expected);
    assert!(calls > 4, "{calls}");
    assert!(f.packet.carrier());
    assert_eq!(f.packet.failure(), None);
}

/// A link-loss restart, clean and with each part that never finishes: on
/// the model clock no call waits more than 60 ms, the calls together wait
/// what the blocking link check and restart wait, and the outcome is the
/// same, recovered or the same fault.
#[test]
fn a_link_loss_restart_runs_in_steps_with_the_blocking_totals_and_outcome() {
    if crate::test_process::isolate_model() {
        return;
    }
    type Case = (&'static str, fn(&mut Device), Option<Error>);
    let cases: [Case; 6] = [
        ("clean", |_| {}, None),
        (
            "engine never stops",
            |device| device.stop_stuck = Some(0x4800),
            Some(Error::StopTimeout(0x4800)),
        ),
        (
            "APE never takes an event",
            |device| {
                device.ape.insert(0x4000, 0x4150_4521);
                device.ape.insert(0x400c, 0x100);
                device.ape_busy = true;
            },
            None,
        ),
        (
            "firmware never answers",
            |device| device.reset_ack = false,
            Some(Error::FirmwareTimeout),
        ),
        (
            "PHY never leaves reset",
            |device| device.phy_stuck = true,
            Some(Error::PhyResetTimeout),
        ),
        (
            "NVRAM lock held",
            |device| device.nvram_held = true,
            Some(Error::NvramTimeout),
        ),
    ];
    for (name, case, expected) in cases {
        let mut blocking = clocked(|_| {});
        case(&mut blocking.peer.lock().unwrap());
        blocking.peer.lock().unwrap().phy.insert(1, 0);
        let before = blocking.clock.now();
        let link = block_on(blocking.packet.hardware.packet_carrier());
        assert_eq!(link, Ok(false), "{name}");
        let result = blocking.packet.restart();
        let waited = blocking.clock.now() - before;
        assert_eq!(result.err(), expected, "{name}");
        assert_eq!(blocking.packet.failure(), expected, "{name}");

        let mut f = clocked(|_| {});
        assert!(f.packet.carrier(), "{name}");
        case(&mut f.peer.lock().unwrap());
        f.peer.lock().unwrap().phy.insert(1, 0);
        f.clock.advance(LINK_POLL_US);
        let (total, calls) = step_until_idle(&mut f);
        assert_eq!(total, waited, "{name}");
        assert!(calls as u64 > total / (CALL_US - 15_000), "{name}: {calls}");
        assert_eq!(f.packet.failure(), expected, "{name}");
        assert_eq!(
            f.domain.drains.load(Ordering::Relaxed),
            blocking.domain.drains.load(Ordering::Relaxed),
            "{name}"
        );
        if expected.is_none() {
            f.peer.lock().unwrap().phy.insert(1, 0x24);
            assert!(f.packet.carrier(), "{name}");
            f.packet.transmit(&[0x22; 60]).unwrap();
        } else {
            assert!(!f.packet.carrier(), "{name}");
            assert!(f.packet.transmit(&[0x22; 60]).is_err(), "{name}");
        }
    }
}
