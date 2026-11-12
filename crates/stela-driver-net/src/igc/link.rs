// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2018 Intel Corporation
//! Polled carrier supervision after Linux igc_has_link and igc_watchdog_task.
//! The masked interrupt cause register still latches link status changes;
//! each one requests a PHY link check, as Linux's LSC handler does.
//!
//! PHY reads wait on the semaphore firmware shares and on the management
//! bus, for up to a second in Linux's bounds. They run as stepped work that
//! waits at most [`STEP_US`] per poll; the carrier keeps its state until the
//! read completes, as it does while Linux's watchdog task runs.
use super::hardware::{Hardware, Negotiated, Registers, STEP_US, Timer};
use crate::block::BlockError;
use alloc::rc::Rc;
use core::task::Poll;
use stela_driver_base::stepped::{Allowance, Stepped};

const ICR: usize = 0x1500;
const ICR_LSC: u32 = 1 << 2;
/// IGC_FLAG_NEED_LINK_UPDATE: an I225 link change seen while the carrier
/// was up holds the carrier down for one second.
const SETTLE_US: u64 = 1_000_000;
/// igc_watchdog_task's twenty 100 ms reads of the remote receiver status.
const GIGABIT_WAIT_US: u64 = 2_000_000;

/// A PHY read a poll needs.
#[derive(Clone, Copy)]
enum Read {
    /// igc_check_for_copper_link, reading the MII status this many times.
    Link(usize),
    /// The remote receiver status a 1 Gb/s carrier waits on.
    Receiver,
}

/// A completed PHY read.
enum Outcome {
    Link(Result<Option<Negotiated>, BlockError>),
    Receiver(Result<bool, BlockError>),
}

/// A PHY read under way, holding its semaphores until it completes.
struct Work {
    task: Stepped<'static, Outcome>,
}

/// What one poll changed about the reported carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Change {
    None,
    Up(Negotiated),
    Down,
}

pub(super) struct Supervisor {
    /// hw->mac.get_link_status: a PHY link check is due.
    check: bool,
    /// The last check found no link and no link change arrived since, so
    /// its read cleared the latched-low MII link bit.
    latch_cleared: bool,
    /// When the pending link update began, while it holds the carrier down.
    settle: Option<u64>,
    /// When a 1 Gb/s link began waiting for the remote receiver.
    gigabit: Option<u64>,
    /// The last negotiated link; `None` until the PHY first reports one.
    link: Option<Negotiated>,
    carrier: bool,
    /// The PHY read under way, if any.
    work: Option<Work>,
    /// A link change arrived while a read was under way: its result is
    /// stale and the check runs again.
    stale: bool,
    /// Each poll's share of waiting, across every read it steps.
    slice: Rc<Allowance>,
}

impl Supervisor {
    /// A freshly initialized controller: carrier down, link check due.
    pub(super) fn new() -> Self {
        Self {
            check: true,
            latch_cleared: false,
            settle: None,
            gigabit: None,
            link: None,
            carrier: false,
            work: None,
            stale: false,
            slice: Rc::new(Allowance::new(STEP_US)),
        }
    }

    /// The negotiated link while the carrier is reported up.
    pub(super) fn carrier(&self) -> Option<Negotiated> {
        self.link.filter(|_| self.carrier)
    }

    /// A link status change cause read outside `poll`: the next poll checks
    /// the PHY, reading the latched-low link bit twice.
    pub(super) fn link_changed(&mut self) {
        self.check = true;
        self.latch_cleared = false;
        self.stale |= self.work.is_some();
    }

    /// Whether a PHY read is under way.
    pub(super) fn reading(&self) -> bool {
        self.work.is_some()
    }

    /// One more step of a read under way, for a stop that resets the
    /// controller next.
    pub(super) fn settle(&mut self) {
        if let Some(work) = &mut self.work {
            self.slice.refill();
            if work.task.step().is_ready() {
                self.work = None;
            }
        }
    }

    /// Start `read` and take its first step: its outcome if that completed
    /// it, otherwise `None` with the rest left for later polls.
    fn start<R, T>(&mut self, registers: &R, timer: &T, read: Read) -> Option<Outcome>
    where
        R: Registers + Clone + 'static,
        T: Timer + Clone + 'static,
    {
        let (registers, timer) = (registers.clone(), timer.clone());
        let shared = self.slice.clone();
        let mut task = Stepped::new(async move {
            let hardware = Hardware::new(&registers, &timer).map(|hw| hw.sliced(&shared));
            match read {
                Read::Link(reads) => Outcome::Link(match hardware {
                    Ok(mut hardware) => hardware.copper_link(reads).await,
                    Err(error) => Err(error),
                }),
                Read::Receiver => Outcome::Receiver(match hardware {
                    Ok(mut hardware) => hardware.remote_receiver_ready_steps().await,
                    Err(error) => Err(error),
                }),
            }
        });
        match task.step() {
            Poll::Ready(outcome) => Some(outcome),
            Poll::Pending => {
                self.work = Some(Work { task });
                None
            }
        }
    }

    /// One watchdog pass at `now` microseconds. Errors are failed register
    /// reads: the function is gone and needs a fresh attachment.
    pub(super) fn poll<R, T>(
        &mut self,
        registers: &R,
        timer: &T,
        now: u64,
    ) -> Result<Change, BlockError>
    where
        R: Registers + Clone + 'static,
        T: Timer + Clone + 'static,
    {
        let cause = registers.read(ICR);
        if cause == u32::MAX {
            return Err(BlockError::Device { status: cause });
        }
        if cause & ICR_LSC != 0 {
            self.link_changed();
        }
        // The next step of a read under way; nothing changes until it ends.
        // A read this poll then starts spends what is left of its share.
        self.slice.refill();
        let mut done = match &mut self.work {
            None => None,
            Some(work) => {
                let Poll::Ready(outcome) = work.task.step() else {
                    return Ok(Change::None);
                };
                self.work = None;
                (!core::mem::take(&mut self.stale)).then_some(outcome)
            }
        };
        // igc_has_link.
        let mut link = true;
        if self.check {
            let outcome = match done.take() {
                Some(outcome @ Outcome::Link(_)) => Some(outcome),
                _ => {
                    let reads = if self.latch_cleared { 1 } else { 2 };
                    self.start(registers, timer, Read::Link(reads))
                }
            };
            let negotiated = match outcome {
                Some(Outcome::Link(negotiated)) => negotiated?,
                _ => return Ok(Change::None),
            };
            self.latch_cleared = negotiated.is_none();
            if let Some(negotiated) = negotiated {
                self.check = false;
                self.link = Some(negotiated);
            }
            link = !self.check;
            if !self.carrier {
                self.settle = None;
            } else if self.settle.is_none() {
                self.settle = Some(now);
            }
        }
        // igc_watchdog_task.
        if let Some(start) = self.settle {
            if now.saturating_sub(start) > SETTLE_US {
                self.settle = None;
            } else {
                link = false;
            }
        }
        match (link, self.carrier) {
            (true, false) => {
                let negotiated = self.link.expect("a completed link check");
                if negotiated.speed == 1000 {
                    let start = *self.gigabit.get_or_insert(now);
                    let outcome = match done.take() {
                        Some(outcome @ Outcome::Receiver(_)) => Some(outcome),
                        _ => self.start(registers, timer, Read::Receiver),
                    };
                    let Some(Outcome::Receiver(ready)) = outcome else {
                        return Ok(Change::None);
                    };
                    // Linux reports the carrier after two seconds either way,
                    // and when the status cannot be read.
                    let ready = ready.or_else(|error| match error {
                        BlockError::Device { status: u32::MAX } | BlockError::PciPower(_) => {
                            Err(error)
                        }
                        _ => Ok(true),
                    })?;
                    if !ready && now.saturating_sub(start) < GIGABIT_WAIT_US {
                        return Ok(Change::None);
                    }
                }
                self.gigabit = None;
                self.carrier = true;
                Ok(Change::Up(negotiated))
            }
            (false, true) => {
                self.carrier = false;
                self.gigabit = None;
                Ok(Change::Down)
            }
            (false, false) => {
                self.gigabit = None;
                Ok(Change::None)
            }
            (true, true) => Ok(Change::None),
        }
    }
}

#[cfg(test)]
impl Supervisor {
    /// A supervisor whose carrier is already up on `link`.
    pub(super) fn established(link: Negotiated) -> Self {
        Self {
            check: false,
            latch_cleared: false,
            settle: None,
            gigabit: None,
            link: Some(link),
            carrier: true,
            work: None,
            stale: false,
            slice: Rc::new(Allowance::new(STEP_US)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::hardware::{FlowControl, tests::Model},
        *,
    };

    fn linked(status: u32, partner: u16) -> Rc<Model> {
        Rc::new(super::super::hardware::tests::linked(status, partner))
    }

    const LINK_2500: u32 = 1 | 1 << 7 | 1 << 22;
    const LINK_1000: u32 = 1 | 1 << 7;

    fn set_link(model: &super::super::hardware::tests::Model, up: bool) {
        model
            .state
            .borrow_mut()
            .phy
            .insert(1, if up { 1 << 2 | 1 << 5 } else { 0 });
    }

    fn lsc(model: &super::super::hardware::tests::Model) {
        model.state.borrow_mut().registers.insert(ICR, ICR_LSC);
    }

    #[test]
    fn carrier_follows_the_phy_and_a_link_change_while_up_holds_it_down_one_second() {
        let model = linked(LINK_2500, 1 << 10);
        let mut supervisor = Supervisor::new();
        set_link(&model, false);
        assert_eq!(supervisor.poll(&model, &model, 0), Ok(Change::None));
        assert_eq!(supervisor.carrier(), None);
        set_link(&model, true);
        let up = Negotiated {
            speed: 2500,
            full_duplex: true,
            flow_control: FlowControl::Full,
        };
        // Link is reported as soon as the PHY has it, with no settle.
        assert_eq!(supervisor.poll(&model, &model, 10), Ok(Change::Up(up)));
        assert_eq!(supervisor.carrier(), Some(up));
        // A stable link needs no PHY traffic.
        let exchanges = model.mdio_count.get();
        assert_eq!(supervisor.poll(&model, &model, 20), Ok(Change::None));
        assert_eq!(model.mdio_count.get(), exchanges);

        // A flap the poller never saw still latches LSC: one second down.
        lsc(&model);
        assert_eq!(supervisor.poll(&model, &model, 1_000), Ok(Change::Down));
        model.state.borrow_mut().registers.insert(ICR, 0);
        assert_eq!(supervisor.poll(&model, &model, 1_000_000), Ok(Change::None));
        assert_eq!(supervisor.carrier(), None);
        assert_eq!(
            supervisor.poll(&model, &model, 1_001_001),
            Ok(Change::Up(up))
        );

        // A real loss reports down at once and up again with the PHY.
        lsc(&model);
        set_link(&model, false);
        assert_eq!(supervisor.poll(&model, &model, 2_000_000), Ok(Change::Down));
        model.state.borrow_mut().registers.insert(ICR, 0);
        assert_eq!(supervisor.poll(&model, &model, 2_500_000), Ok(Change::None));
        set_link(&model, true);
        assert_eq!(
            supervisor.poll(&model, &model, 2_600_000),
            Ok(Change::Up(up))
        );
    }

    #[test]
    fn without_a_cable_each_repeated_check_reads_the_phy_status_once() {
        let model = linked(LINK_2500, 1 << 10);
        let mut supervisor = Supervisor::new();
        set_link(&model, false);
        let exchanges = |supervisor: &mut Supervisor, now| {
            let before = model.mdio_count.get();
            assert_eq!(supervisor.poll(&model, &model, now), Ok(Change::None));
            model.mdio_count.get() - before
        };
        // The first check reads the latched-low bit twice, later ones once.
        let first = exchanges(&mut supervisor, 0);
        let repeated = exchanges(&mut supervisor, 10);
        assert_eq!(first, repeated + 1);
        assert_eq!(exchanges(&mut supervisor, 20), repeated);
        // A link change cause makes the next check read twice again.
        lsc(&model);
        assert_eq!(exchanges(&mut supervisor, 30), first);
        model.state.borrow_mut().registers.insert(ICR, 0);
        assert_eq!(exchanges(&mut supervisor, 40), repeated);
        supervisor.link_changed();
        assert_eq!(exchanges(&mut supervisor, 50), first);
    }

    #[test]
    fn gigabit_carrier_waits_for_the_remote_receiver_for_at_most_two_seconds() {
        for ready_at in [Some(500_000), None] {
            let model = linked(LINK_1000, 1 << 10);
            let mut supervisor = Supervisor::new();
            let mut now = 0;
            let up = loop {
                if Some(now) == ready_at {
                    model.state.borrow_mut().phy.insert(10, 1 << 12);
                }
                match supervisor.poll(&model, &model, now).unwrap() {
                    Change::Up(link) => break link,
                    change => assert_eq!(change, Change::None),
                }
                now += 100_000;
            };
            assert_eq!(up.speed, 1000);
            assert_eq!(now, ready_at.unwrap_or(GIGABIT_WAIT_US));
        }
    }

    /// Drive polls until one reports a change, checking that none waits
    /// more than 60 ms of model time, and return it with the polls taken.
    fn stepped_poll(supervisor: &mut Supervisor, model: &Rc<Model>, now: u64) -> (Change, usize) {
        let mut polls = 0;
        loop {
            let before = model.elapsed.get();
            let change = supervisor.poll(model, model, now).unwrap();
            polls += 1;
            let waited = model.elapsed.get() - before;
            assert!(waited <= 60_000, "poll {polls} waited {waited} us");
            if change != Change::None || !supervisor.reading() {
                return (change, polls);
            }
            assert_eq!(supervisor.carrier(), None);
        }
    }

    /// A link check behind firmware's PHY semaphore and a slow management
    /// bus, Linux's waits of up to a second, runs a step per poll: no poll
    /// waits more than 60 ms, and it reports the link and leaves the
    /// registers an uncontended check does.
    #[test]
    fn a_link_check_waiting_on_firmware_and_the_bus_runs_in_steps() {
        let up = Negotiated {
            speed: 2500,
            full_duplex: true,
            flow_control: FlowControl::Full,
        };
        let quick = linked(LINK_2500, 1 << 10);
        let mut supervisor = Supervisor::new();
        assert_eq!(
            stepped_poll(&mut supervisor, &quick, 0),
            (Change::Up(up), 1)
        );

        let model = linked(LINK_2500, 1 << 10);
        model.firmware_busy_until.set(300_000);
        model.mdio_cycle_us.set(20_000);
        let mut supervisor = Supervisor::new();
        let (change, polls) = stepped_poll(&mut supervisor, &model, 0);
        assert_eq!(change, Change::Up(up));
        assert!(polls > 8, "{polls}");
        assert!(model.elapsed.get() > 300_000);
        assert_eq!(supervisor.carrier(), Some(up));
        assert_eq!(
            model.state.borrow().registers,
            quick.state.borrow().registers
        );

        // A link change during the check makes its result stale: the check
        // runs again, reading the latched-low bit twice.
        let model = linked(LINK_2500, 1 << 10);
        model.firmware_busy_until.set(100_000);
        let mut supervisor = Supervisor::new();
        assert_eq!(supervisor.poll(&model, &model, 0), Ok(Change::None));
        assert!(supervisor.reading());
        lsc(&model);
        set_link(&model, false);
        let (change, _) = stepped_poll(&mut supervisor, &model, 0);
        assert_eq!(change, Change::None);
        assert_eq!(supervisor.carrier(), None);
        assert!(supervisor.check);
    }

    /// A 1 Gb/s carrier's remote receiver read on a slow management bus
    /// runs in steps too, after the link check's, and the carrier comes up
    /// when it completes.
    #[test]
    fn a_remote_receiver_read_on_a_slow_bus_runs_in_steps() {
        let model = linked(LINK_1000, 1 << 10);
        model.state.borrow_mut().phy.insert(10, 1 << 12);
        model.mdio_cycle_us.set(70_000);
        let mut supervisor = Supervisor::new();
        let (mut polls, mut receiver_steps) = (0, 0);
        while supervisor.carrier().is_none() {
            let before = model.elapsed.get();
            assert!(supervisor.poll(&model, &model, 0).is_ok());
            assert!(model.elapsed.get() - before <= 60_000);
            if supervisor.link.is_some() && supervisor.reading() {
                receiver_steps += 1;
            }
            polls += 1;
            assert!(polls < 100);
        }
        assert!(receiver_steps > 1, "{receiver_steps}");
        assert_eq!(supervisor.carrier().map(|link| link.speed), Some(1000));
    }

    #[test]
    fn a_lost_function_is_an_error_not_a_link_state() {
        let model = linked(LINK_2500, 1 << 10);
        let mut supervisor = Supervisor::new();
        model.state.borrow_mut().registers.insert(ICR, u32::MAX);
        assert_eq!(
            supervisor.poll(&model, &model, 0),
            Err(BlockError::Device { status: u32::MAX })
        );
    }
}
