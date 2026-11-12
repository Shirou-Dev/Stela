// SPDX-License-Identifier: GPL-2.0-only
//! Single-queue BCM5720/5761/5762 A0 copper Ethernet backend.
use super::{Delay, Error, Hardware, ReceiveFilter, Registers};
use crate::bus::pci::requester::preparation::Attachment;
use crate::{
    HEADER, Link, LinkError, MAX_FRAME, MIN_FRAME, Mac,
    bus::dma::{
        mapping::DmaDomain,
        memory::{MemoryError, PageSource},
    },
    check_frame,
};
use alloc::{boxed::Box, rc::Rc, sync::Arc, vec::Vec};
use core::{
    ops::{Deref, DerefMut},
    task::Poll,
};
use stela_driver_base::stepped::{Allowance, Stepped, block_on};
mod memory;
use super::geometry::Geometry;
#[cfg(test)]
use memory::RX;
use memory::{Memory, TX};

const SD_STATUS_ERROR: u32 = 4;
/// Each runtime call's share of waiting for work in steps: up to this, plus
/// the one delay that crosses it. Between two 10-us waits a poll makes a
/// few register accesses, which can double a step's real time; a
/// processor's exit must end well inside half a second.
const STEP_US: u64 = 20_000;
/// `tg3_timer`'s once-a-second link check.
const LINK_POLL_US: u64 = 1_000_000;

/// The hardware, which work in steps holds while it runs.
struct Held<T>(Option<T>);
impl<T> Held<T> {
    fn take(&mut self) -> T {
        self.0.take().expect("hardware is held")
    }
    fn put(&mut self, value: T) {
        self.0 = Some(value);
    }
}
impl<T> Deref for Held<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.0.as_ref().expect("no work holds the hardware")
    }
}
impl<T> DerefMut for Held<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.0.as_mut().expect("no work holds the hardware")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// The copper link check.
    Link,
    /// A restart, after a lost link or for a PHY resume.
    Restart,
    /// The PHY suspend.
    Suspend,
}
/// Hardware work run a step per runtime call. It owns the hardware until
/// it ends, so meanwhile the carrier is down, receive finds nothing and
/// transmit has no carrier.
struct Work<R: Registers, D: Delay> {
    kind: Kind,
    task: Stepped<'static, Finished<R, D>>,
}
struct Finished<R: Registers, D: Delay> {
    hardware: Hardware<R, D>,
    /// The rings, which a restart holds.
    memory: Option<Memory>,
    result: Result<bool, Error>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Building,
    Running,
    Faulted,
    Stopped,
    PhySuspended,
}
/// PCI/config/MMIO ownership, isolated requester domain and pinned rings
/// form one lifetime. An uncertain epoch keeps all of them. No IRQs or worker
/// callbacks are registered by this polled backend.
pub struct Packet<R: Registers, D: Delay> {
    hardware: Held<Hardware<R, D>>,
    /// Work in steps under way, holding the hardware.
    work: Option<Work<R, D>>,
    /// Each runtime call's share of waiting for that work.
    allowance: Rc<Allowance>,
    /// When the next link check is due; none when it is due now, and on a
    /// timer that keeps no interval, where every call checks.
    link_due: Option<Box<dyn crate::bus::pci::power::Interval>>,
    memory: Option<Memory>,
    domain: Arc<dyn DmaDomain>,
    attachment: Option<Attachment>,
    mac: Mac,
    board: Option<super::transport::board::Board>,
    carrier_up: bool,
    state: State,
    failure: Option<Error>,
    mbuf_low_water_events: u64,
    rx_dropped: u64,
    tx_producer: usize,
    tx_consumer: usize,
    rx_producer: usize,
    rx_consumer: usize,
    /// True only after all preconditions for attempted device containment have
    /// been observed; arbitrary unsupported hardware is never stopped here.
    identified: bool,
    /// An attach error can keep partial DMA allocations. Only a fully
    /// initialized packet owner may rebuild those rings for another epoch.
    restartable: bool,
    geometry: Geometry,
    receive_filter: ReceiveFilter,
    /// The last received frame. The stack's path swaps it with its own
    /// buffer, so steady-state receive allocates nothing, and a failed
    /// receive never touches the caller's buffer.
    received: Vec<u8>,
}
impl<R: Registers + 'static, D: Delay + 'static> Packet<R, D> {
    /// Attach an exclusively owned stopped requester, with real NVM
    /// bootcode already present. Errors return the whole epoch.
    ///
    /// # Safety
    /// `hardware` owns the BCM5720/5761/5762 function/config/UC MAC/APE resources
    /// described by `Registers`, powered in PCI D0. `domain` is the
    /// isolated requester domain for that function/aliases; it keeps its root
    /// and performs real invalidation, coherence and payload write drain.
    /// `pages` supplies kept pins, never synthetic physical addresses.
    /// Inherited DMA is stopped/drained, BusMaster clear, MSI/MSI-X disabled and
    /// posted messages/CPU vectors/workers drained before this call. Those
    /// original interrupt exclusions remain held in the register
    /// owner through retirement; no other provider may re-enable them.
    /// The kept timer is the original provider's calibrated clock;
    /// its rate and CPU/power context remain valid through all settling waits.
    /// All calls/releases run in the original provider's checked context.
    /// A numeric BDF, arbitrary Arc or fake domain cannot grant this permission.
    #[allow(
        clippy::result_large_err,
        reason = "attach failure returns the complete original hardware/DMA epoch without a fallible error-path allocation"
    )]
    pub unsafe fn attach(
        hardware: Hardware<R, D>,
        pages: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<Self, (Error, Self)> {
        let mut value = Self {
            hardware: Held(Some(hardware)),
            work: None,
            allowance: Rc::new(Allowance::new(STEP_US)),
            link_due: None,
            memory: None,
            domain,
            attachment: None,
            mac: Mac::default(),
            board: None,
            carrier_up: false,
            state: State::Building,
            failure: None,
            mbuf_low_water_events: 0,
            rx_dropped: 0,
            tx_producer: 0,
            tx_consumer: 0,
            rx_producer: Geometry::of(super::Asic::Bcm5720).rx - 1,
            rx_consumer: 0,
            identified: false,
            restartable: false,
            geometry: Geometry::of(super::Asic::Bcm5720),
            receive_filter: ReceiveFilter::default(),
            received: Vec::new(),
        };
        let result = (|| {
            let board = block_on(value.hardware.packet_prepare())?;
            value.identified = true;
            value.mac = board.mac;
            value.board = Some(board);
            let asic = value.hardware.identity().ok_or(Error::NotIdentified)?.asic;
            value.geometry = Geometry::of(asic);
            value.rx_producer = value.geometry.rx - 1;
            block_on(value.hardware.packet_reset(board))?;
            let ring_limit = Geometry::ring_limit(asic);
            match Memory::new(pages, value.domain.clone(), value.geometry, ring_limit) {
                Ok(memory) => value.memory = Some(memory),
                Err((error, memory)) => {
                    value.memory = Some(memory);
                    return Err(error);
                }
            }
            let addresses = value.memory.as_ref().unwrap().addresses()?;
            block_on(
                value
                    .hardware
                    .packet_start(board, addresses, &value.receive_filter),
            )?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                value.restartable = true;
                value.state = State::Running;
                Ok(value)
            }
            Err(error) => {
                value.fault(error);
                Err((error, value))
            }
        }
    }
    /// Attach through the unique control produced by cold original-root
    /// finalization. Retirement detaches it after every DMA mapping retires.
    /// # Safety
    /// All `attach` requirements hold, and `attachment` is paired with this
    /// exact original hardware/configuration epoch. The inherited interrupt
    /// exclusions remain held through detach; this backend installs no IRQs.
    #[expect(
        clippy::result_large_err,
        reason = "attach errors retain the complete original hardware and attachment"
    )]
    pub unsafe fn attach_bound(
        hardware: Hardware<R, D>,
        pages: &dyn PageSource,
        attachment: Attachment,
    ) -> Result<Self, (Error, Self)> {
        // SAFETY: the caller supplies the same original stopped hardware,
        // IRQ/work exclusion and unique attachment. Keep it through all errors.
        match unsafe { Self::attach(hardware, pages, attachment.domain()) } {
            Ok(mut packet) => {
                packet.attachment = Some(attachment);
                Ok(packet)
            }
            Err((error, mut packet)) => {
                packet.attachment = Some(attachment);
                Err((error, packet))
            }
        }
    }

    /// Program an acknowledged hardware receive policy in this live epoch.
    /// Already completed frames are not retracted. On error, the uncertain
    /// original epoch is held and packet publication remains fenced.
    pub fn set_receive_filter(&mut self, filter: ReceiveFilter) -> Result<(), Error> {
        // Work under way holds the hardware; it takes this call's step.
        self.allowance.refill();
        if self.advance().is_pending() {
            return Err(Error::Stopped);
        }
        self.check()?;
        filter.validate()?;
        match block_on(self.hardware.packet_receive_filter(&filter)) {
            Ok(()) => {
                self.receive_filter = filter;
                Ok(())
            }
            Err(error) => Err(self.fault(error)),
        }
    }
    /// Last acknowledged request; multicast collisions/unused unicast slots
    /// still have the pinned hardware semantics described by ReceiveFilter.
    pub fn receive_filter(&self) -> &ReceiveFilter {
        &self.receive_filter
    }
    pub fn failure(&self) -> Option<Error> {
        self.failure
    }
    /// Successfully handled BCM5720/5762 A0 MBUF low-water discard indications,
    /// acknowledged through the real W1C register. Multiple drops can coalesce
    /// into one event; this is not an exact packet-loss counter. Faulted cause
    /// or acknowledgement observations remain in `failure`. Saturates at u64::MAX.
    pub fn mbuf_low_water_events(&self) -> u64 {
        self.mbuf_low_water_events
    }
    /// Received frames dropped as damaged (CRC, alignment, length or
    /// fragment errors), as Linux counts them in `rx_errors`. Saturates.
    pub fn rx_dropped(&self) -> u64 {
        self.rx_dropped
    }
    fn fault(&mut self, error: Error) -> Error {
        self.failure.get_or_insert(error);
        self.state = State::Faulted;
        error
    }
    fn check(&self) -> Result<(), Error> {
        if self.state == State::Running {
            Ok(())
        } else {
            Err(Error::Stopped)
        }
    }
    /// Hand the hardware to `kind` of work, which runs `run` on it a step
    /// at a time within each call's share of waiting.
    fn begin<F>(&mut self, kind: Kind, run: impl FnOnce(Hardware<R, D>) -> F)
    where
        F: core::future::Future<Output = Finished<R, D>> + 'static,
    {
        let mut hardware = self.hardware.take();
        hardware.steps(Some(self.allowance.clone()));
        self.work = Some(Work {
            kind,
            task: Stepped::new(run(hardware)),
        });
    }
    /// The copper link check, as work in steps.
    fn begin_link(&mut self) {
        self.begin(Kind::Link, |mut hardware| async move {
            let result = hardware.packet_carrier().await;
            Finished {
                hardware,
                memory: None,
                result,
            }
        });
    }
    /// One step of the work under way, and of any work its end starts, in
    /// this call's share: pending while it continues, otherwise the result
    /// of the work that ended last (`Ok` when there was none).
    fn advance(&mut self) -> Poll<Result<(), Error>> {
        while let Some(work) = &mut self.work {
            let Poll::Ready(mut finished) = work.task.step() else {
                return Poll::Pending;
            };
            let kind = work.kind;
            self.work = None;
            finished.hardware.steps(None);
            self.hardware.put(finished.hardware);
            if finished.memory.is_some() {
                self.memory = finished.memory;
            }
            let result = self.finished(kind, finished.result);
            if result.is_err() || self.work.is_none() {
                return Poll::Ready(result);
            }
        }
        Poll::Ready(Ok(()))
    }
    /// The work under way run to its end in this call, as attachment and
    /// teardown may.
    fn finish(&mut self) -> Result<(), Error> {
        loop {
            self.allowance.refill();
            if let Poll::Ready(result) = self.advance() {
                return result;
            }
        }
    }
    /// What ended work leaves behind.
    fn finished(&mut self, kind: Kind, result: Result<bool, Error>) -> Result<(), Error> {
        match (kind, result) {
            (Kind::Link, Ok(carrier)) => {
                let due = self.hardware.begin_interval(LINK_POLL_US);
                self.link_due = due.map_err(|error| self.fault(error))?;
                if !carrier && self.carrier_up {
                    self.carrier_up = false;
                    return self.begin_restart().map_err(|error| self.fault(error));
                }
                self.carrier_up = carrier;
                Ok(())
            }
            (Kind::Restart, Ok(_)) => {
                self.tx_producer = 0;
                self.tx_consumer = 0;
                self.rx_producer = self.geometry.rx - 1;
                self.rx_consumer = 0;
                self.failure = None;
                self.state = State::Running;
                // The restarted link is checked at the next call.
                self.link_due = None;
                Ok(())
            }
            (Kind::Suspend, Ok(_)) => {
                self.state = State::PhySuspended;
                Ok(())
            }
            (_, Err(error)) => Err(self.fault(error)),
        }
    }
    /// Whether the link check is due: once a second, as `tg3_timer` checks
    /// it, or at every call on a timer that keeps no interval.
    fn link_due(&mut self) -> Result<bool, Error> {
        match &self.link_due {
            None => Ok(true),
            Some(interval) => interval.elapsed().map_err(Error::Timing),
        }
    }
    fn poll(&mut self) -> Result<usize, Error> {
        self.check()?;
        self.hardware.asf_heartbeat()?;
        self.hardware.request_status()?;
        let (flags, tx, rx) = self.memory.as_ref().unwrap().status()?;
        if flags & SD_STATUS_ERROR != 0 && self.hardware.packet_attention()? {
            self.mbuf_low_water_events = self.mbuf_low_water_events.saturating_add(1);
        }
        if tx >= TX || rx >= self.geometry.returns {
            return Err(Error::RingCorrupt);
        }
        let done = (tx + TX - self.tx_consumer) % TX;
        let pending = (self.tx_producer + TX - self.tx_consumer) % TX;
        if done > pending {
            return Err(Error::RingCorrupt);
        }
        for _ in 0..done {
            self.memory
                .as_ref()
                .unwrap()
                .complete_tx(self.tx_consumer)?;
            self.tx_consumer = (self.tx_consumer + 1) % TX;
        }
        Ok(rx)
    }
    /// Stop MAC/DMA engines, observe BusMaster clear and complete the original
    /// remapper's posted payload drain. A failed attempt remains retryable only
    /// for containment; it can never resume submission or invent completion.
    /// It runs to completion, as teardown may.
    pub fn stop(&mut self) -> Result<(), Error> {
        // Work under way ends first; its failure faults the epoch.
        let _ = self.finish();
        let Some(clean) = self.halt_plan()? else {
            return Ok(());
        };
        match block_on(Self::halt(&mut self.hardware, &*self.domain, clean)) {
            Ok(()) => {
                self.state = State::Stopped;
                Ok(())
            }
            Err(error) => Err(self.fault(error)),
        }
    }
    /// What stopping takes: `None` for an epoch already stopped, otherwise
    /// a halt that tells the management firmware when the epoch is clean.
    /// The epoch is faulted until the halt ends.
    fn halt_plan(&mut self) -> Result<Option<bool>, Error> {
        if matches!(self.state, State::Stopped | State::PhySuspended) {
            return Ok(None);
        }
        self.state = State::Faulted;
        if !self.identified {
            return Err(self.failure.unwrap_or(Error::NotIdentified));
        }
        // The management firmware hears of the stop only from an epoch
        // whose every operation was observed.
        Ok(Some(
            self.failure.is_none() && self.hardware.failure().is_none(),
        ))
    }
    /// `tg3_halt`: the management firmware told of the unload when `clean`,
    /// engines stopped, BusMaster clear and posted writes drained.
    async fn halt(
        hardware: &mut Hardware<R, D>,
        domain: &dyn DmaDomain,
        clean: bool,
    ) -> Result<(), Error> {
        let unload = if clean {
            hardware.packet_unload_begin().await
        } else {
            Ok(())
        };
        hardware.packet_stop().await?;
        // SAFETY: real engines acknowledged stopped, original BME clear;
        // isolated domain and every packet/status target remain.
        unsafe {
            domain.drain_posted_writes()?;
        }
        unload?;
        if clean {
            hardware.packet_unload_end().await?;
        }
        Ok(())
    }
    /// Stop/drain packets and put the admitted copper PHY into its real low
    /// power state. The original PCI function stays in D0 with every mapping
    /// kept. This supplies no PCI/system sleep or wake-on-LAN operation.
    /// It runs to completion, as teardown may.
    pub fn suspend_phy(&mut self) -> Result<(), Error> {
        let _ = self.finish();
        self.begin_suspend_phy()?;
        self.finish()
    }
    /// The PHY suspend as work in steps.
    fn begin_suspend_phy(&mut self) -> Result<(), Error> {
        if self.state == State::PhySuspended {
            return Ok(());
        }
        if !self.restartable {
            return Err(Error::Stopped);
        }
        let halt = self.halt_plan()?;
        self.carrier_up = false;
        let domain = self.domain.clone();
        self.begin(Kind::Suspend, move |mut hardware| async move {
            let result = async {
                if let Some(clean) = halt {
                    Self::halt(&mut hardware, &*domain, clean).await?;
                }
                hardware.power_down_packet_phy().await
            }
            .await;
            Finished {
                hardware,
                memory: None,
                result: result.map(|()| true),
            }
        });
        Ok(())
    }
    /// Restore this same PHY and packet epoch through the full PHY/core reset
    /// and queue rebuild. The kept platform owner must still hold PCI D0.
    /// It runs to completion, as teardown may.
    pub fn resume_phy(&mut self) -> Result<(), Error> {
        let _ = self.finish();
        if self.state != State::PhySuspended {
            return Err(Error::Stopped);
        }
        self.begin_restart()?;
        self.finish()
    }
    /// Release only after stop/drain and acknowledged removal of every real
    /// mapping. An unmap error returns this same epoch with original owners.
    #[allow(
        clippy::result_large_err,
        reason = "failed retirement must return the same retained hardware/DMA epoch for retry without allocating"
    )]
    pub fn retire(mut self) -> Result<R, (Error, Self)> {
        let result = self.stop().and_then(|()| {
            // Unmap can succeed for some rings before another mapping fails.
            // That owner is retryable only for retirement, never restart.
            self.restartable = false;
            if let Some(memory) = &mut self.memory {
                memory.retire()?;
            }
            if let Some(attachment) = &mut self.attachment {
                // SAFETY: stop observed vendor engine/BME retirement and the
                // original-root payload drain, every mapping is now unmapped,
                // and inherited IRQ/work exclusions remain held by the owner.
                unsafe {
                    attachment.detach()?;
                }
            }
            Ok(())
        });
        match result {
            Ok(()) => {
                self.memory.take();
                self.attachment.take();
                Ok(self.hardware.release_registers())
            }
            Err(error) => {
                self.failure.get_or_insert(error);
                Err((error, self))
            }
        }
    }
    /// Rebuild an explicitly stopped or failed packet queue in the same held-D0
    /// hardware owner. Outstanding frames are discarded only after
    /// engine stop, BusMaster-clear readback and posted-write drain. A failure
    /// keeps every mapping and prohibits packet I/O; another containment or
    /// restart attempt cannot bypass uncertain transport/reset ownership.
    /// It runs to completion, as teardown may; a lost link restarts in steps.
    pub fn restart(&mut self) -> Result<(), Error> {
        let _ = self.finish();
        self.begin_restart()?;
        self.finish()
    }
    /// The restart as work in steps: halt, core reset and PHY setup, and
    /// the rings rebuilt on their existing buffers. It holds the rings too.
    fn begin_restart(&mut self) -> Result<(), Error> {
        if !self.restartable {
            return Err(Error::Stopped);
        }
        let halt = self.halt_plan()?;
        self.carrier_up = false;
        let domain = self.domain.clone();
        let board = self.board;
        let filter = self.receive_filter.clone();
        let mut memory = self.memory.take();
        self.begin(Kind::Restart, move |mut hardware| async move {
            let result = async {
                if let Some(clean) = halt {
                    Self::halt(&mut hardware, &*domain, clean).await?;
                }
                let board = board.ok_or(Error::NotIdentified)?;
                hardware.packet_reset(board).await?;
                let memory = memory.as_mut().ok_or(Error::NotIdentified)?;
                // SAFETY: the old epoch is fully stopped/drained and the chip
                // reset; the same real mappings remain, with no intervening
                // new DMA source.
                unsafe {
                    memory.reset_after_drain()?;
                }
                let addresses = memory.addresses()?;
                hardware.packet_start(board, addresses, &filter).await
            }
            .await;
            Finished {
                hardware,
                memory,
                result: result.map(|()| true),
            }
        });
        Ok(())
    }
    fn transmit_inner(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.poll()?;
        if (self.tx_producer + 1) % TX == self.tx_consumer {
            return Err(Error::RingFull);
        }
        self.memory.as_ref().unwrap().tx(self.tx_producer, frame)?;
        self.tx_producer = (self.tx_producer + 1) % TX;
        self.hardware.tx_producer(self.tx_producer)
    }
    /// Whether a frame arrived; it is left in `self.received`.
    fn receive_inner(&mut self) -> Result<bool, Error> {
        let producer = self.poll()?;
        let restore_tag = self.hardware.management().asf;
        // A finite pass drops damaged frames without blocking on new traffic.
        for _ in 0..self.geometry.returns {
            if self.rx_consumer == producer {
                return Ok(false);
            }
            let (_, frame) = self.memory.as_mut().unwrap().receive(
                self.rx_consumer,
                &mut self.received,
                restore_tag,
            )?;
            // The next spare producer slot must really be CPU-owned; the
            // memory layer refuses an out-of-order return which violates it.
            self.memory.as_mut().unwrap().offer(self.rx_producer)?;
            self.rx_producer = (self.rx_producer + 1) % self.geometry.rx;
            self.hardware.rx_producer(self.rx_producer)?;
            self.rx_consumer = (self.rx_consumer + 1) % self.geometry.returns;
            self.hardware.rx_consumer(self.rx_consumer)?;
            if frame {
                return Ok(true);
            }
            self.rx_dropped = self.rx_dropped.saturating_add(1);
        }
        // A whole pass of damaged frames: the rest wait for the next call.
        Ok(false)
    }
    /// Runs one receive; `Ok(true)` leaves the frame in `self.received`.
    fn receive_checked(&mut self) -> Result<bool, LinkError> {
        if !self.carrier() {
            return if let Some(error) = self.failure {
                Err(error.into_link())
            } else {
                Ok(false)
            };
        }
        self.receive_inner().map_err(|error| {
            self.fault(error);
            error.into_link()
        })
    }
}
impl<R: Registers + 'static, D: Delay + 'static> Link for Packet<R, D> {
    fn mac(&self) -> Mac {
        self.mac
    }
    /// The last link check's carrier. A check runs when one is due, as
    /// work in steps; calls in between make no PHY access. While work holds
    /// the hardware the carrier is down.
    fn carrier(&mut self) -> bool {
        self.allowance.refill();
        let busy = self.work.is_some();
        if self.advance().is_pending() || self.check().is_err() {
            return false;
        }
        // Work that ended in this call had its share; a due check waits
        // for the next call.
        match self.link_due() {
            Ok(false) => return self.carrier_up,
            Ok(true) if busy => return self.carrier_up,
            Ok(true) => {}
            Err(error) => {
                self.fault(error);
                return false;
            }
        }
        self.begin_link();
        if self.advance().is_pending() {
            return false;
        }
        self.check().is_ok() && self.carrier_up
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        check_frame(frame)?;
        if !self.carrier() {
            return if let Some(error) = self.failure {
                Err(error.into_link())
            } else {
                Err(LinkError::NoCarrier)
            };
        }
        match self.transmit_inner(frame) {
            Ok(()) => Ok(()),
            Err(Error::RingFull) => Err(LinkError::Busy),
            Err(error) => {
                self.fault(error);
                Err(error.into_link())
            }
        }
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        Ok(self
            .receive_checked()?
            .then(|| core::mem::take(&mut self.received)))
    }
    /// The stack's path: the received frame and the caller's buffer trade
    /// places, so a received frame allocates nothing once both have grown.
    fn receive_reusing(&mut self, frame: &mut Vec<u8>) -> Result<bool, LinkError> {
        let received = self.receive_checked()?;
        if received {
            core::mem::swap(frame, &mut self.received);
        }
        Ok(received)
    }
}
#[cfg(test)]
mod tests;
