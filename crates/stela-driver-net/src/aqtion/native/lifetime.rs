// SPDX-License-Identifier: GPL-2.0-only
//! One AQtion owner keeps its stopped-root receipt and native retirement graph.
use super::{Error, Failure, RetirableRegisters, cold::Bound};
use crate::aqtion::{Aqtion, Mac, PciPower, STOP_BUDGET_US, State, Timer, memory::Memory};
use crate::{
    Link, LinkError,
    bus::{
        dma::memory::PageSource,
        pci::{ConfigSpace, owned::ConfigRetention, regs, requester::preparation::Attachment},
    },
};
use alloc::{boxed::Box, vec::Vec};
use core::{mem::ManuallyDrop, ops::Deref};

struct Resources<R: RetirableRegisters, T: Timer + 'static> {
    core: Aqtion<R, T>,
    attachment: Attachment,
    retention: Option<ConfigRetention>,
}
/// The unique attachment and configuration seal cannot be separated from the
/// device. Mutable operations delegate individually; no mutable core escapes.
pub struct Attached<
    R: RetirableRegisters = super::MappedRegisters,
    T: Timer + 'static = alloc::rc::Rc<dyn Timer>,
> {
    resources: Option<Box<Resources<R, T>>>,
    completed: bool,
    failure: Option<Error>,
}
impl<R: RetirableRegisters, T: Timer + 'static> Drop for Attached<R, T> {
    /// An owner that was not retired is stopped first, as Linux's close
    /// (`aq_nic_stop`) stops it: interrupts masked, every queue off, the
    /// link dropped through firmware, bus mastering cleared and posted
    /// writes drained, its register polls within [`STOP_BUDGET_US`]. It is
    /// then kept whole: only [`Self::retire`] releases its pages, binding
    /// and registers. A function that left the bus gets no write.
    ///
    /// This drives the controller's registers, so the owner drops it where
    /// its MMIO window is mapped; anywhere else the first read faults.
    fn drop(&mut self) {
        if !self.completed {
            if self.live().is_ok() {
                let _ = self.core_mut().stop_within(STOP_BUDGET_US);
            }
            core::mem::forget(self.resources.take());
        }
    }
}
impl<R: RetirableRegisters, T: Timer + 'static> Deref for Attached<R, T> {
    type Target = Aqtion<R, T>;
    fn deref(&self) -> &Self::Target {
        &self.resources.as_ref().unwrap().core
    }
}

#[expect(
    clippy::result_large_err,
    reason = "return the original owner and precise failure without allocating during refusal or retirement"
)]
pub(super) fn attach<R: RetirableRegisters, T: Timer + 'static>(
    bound: Bound<R, T>,
    pages: &dyn PageSource,
) -> Result<Attached<R, T>, Failure> {
    // Keep a bound owner even if a provider unwinds before the outer guard exists.
    let bound = ManuallyDrop::new(bound);
    let domain = bound.attachment.domain();
    let Bound {
        requester,
        attachment,
        hardware,
        profile,
        firmware,
    } = ManuallyDrop::into_inner(bound);
    let core = Aqtion {
        function: Some(requester.into_function()),
        hardware: Some(hardware),
        domain: Some(domain),
        memory: None,
        profile,
        firmware: None,
        mac: Mac::default(),
        state: State::Faulted,
        power: PciPower::D0,
        tx_tail: 0,
        tx_head: 0,
        rx_head: 0,
        dropping: false,
    };
    let mut attached = Attached {
        resources: Some(Box::new(Resources {
            core,
            attachment,
            retention: None,
        })),
        completed: false,
        failure: None,
    };
    let result = (|| {
        let resources = attached.resources.as_deref_mut().unwrap();
        resources.retention = Some(
            resources
                .core
                .function
                .as_mut()
                .unwrap()
                .config()
                .retain_epoch()
                .map_err(Error::Configuration)?,
        );
        resources.core.hw().check_timing()?;
        resources.core.memory = Some(Memory::new(
            pages,
            resources.core.domain.as_ref().unwrap().clone(),
        )?);
        resources.core.start_queues(firmware)?;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(attached),
        Err(error) => Err(Failure {
            error,
            _owner: Box::new(attached),
        }),
    }
}

impl<R: RetirableRegisters, T: Timer + 'static> Attached<R, T> {
    fn live(&self) -> Result<(), Error> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if self.completed {
            return Err(Error::Retired);
        }
        Ok(())
    }
    fn live_link(&self) -> Result<(), LinkError> {
        self.live().map_err(|error| match error {
            Error::Configuration(error) => LinkError::Pci(crate::block::BlockError::Mmio(error)),
            Error::Config(error) => LinkError::Pci(crate::block::BlockError::Config(error)),
            Error::Power(error) => LinkError::Pci(error),
            Error::Device(error) => crate::aqtion::adapter(error),
            Error::Retired => LinkError::NoCarrier,
            error => LinkError::Adapter(alloc::format!("AQtion native: {error:?}")),
        })
    }
    fn core_mut(&mut self) -> &mut Aqtion<R, T> {
        &mut self.resources.as_deref_mut().unwrap().core
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        self.live()?;
        Ok(self.core_mut().stop()?)
    }
    pub fn restart(&mut self) -> Result<(), Error> {
        self.live()?;
        Ok(self.core_mut().restart()?)
    }
    pub fn suspend(&mut self) -> Result<(), Error> {
        self.live()?;
        Ok(self.core_mut().suspend()?)
    }
    pub fn resume(&mut self) -> Result<(), Error> {
        self.live()?;
        Ok(self.core_mut().resume_owned()?)
    }

    /// Stop/drain, unmap all DMA, detach the requester, then retire BAR and
    /// configuration. A failure is sticky and keeps the remaining graph;
    /// repeated acknowledged retirement performs no new I/O.
    pub fn retire(&mut self) -> Result<(), Error> {
        if self.completed {
            return Ok(());
        }
        self.live()?;
        let result = (|| {
            let resources = self.resources.as_deref_mut().unwrap();
            let function = resources.core.function.as_mut().unwrap();
            if !function
                .config()
                .matches_retention(resources.retention.as_ref().unwrap())
                .map_err(Error::Configuration)?
            {
                return Err(Error::ConfigurationEpoch);
            }
            resources.core.retire()?;
            let command = resources
                .core
                .function
                .as_mut()
                .unwrap()
                .config()
                .read16(regs::COMMAND)?;
            if command == u16::MAX || command & regs::COMMAND_MASTER != 0 {
                return Err(Error::BusMaster(command));
            }
            // SAFETY: the same core acknowledged engine/IRQ-source/BME stop
            // and bound-root payload drain; every DMA mapping is now unmapped.
            // There are no registered IRQ/work users or competing PCI writers.
            unsafe { resources.attachment.detach() }.map_err(Error::Detach)?;
            resources.retention.take();
            // SAFETY: all device/DMA/IRQ/work and CPU register users retired,
            // and this unique attachment acknowledged requester detach.
            unsafe { resources.core.hardware.as_mut().unwrap().registers.retire() }?;
            // SAFETY: detach released its config binding, the own seal is gone,
            // remaining configuration users must be joined by the mapping, and the
            // device cannot resume. Busy/context/unmap refusal retains this owner.
            // Keep the same typed function, configuration custody and grant
            // until the borrowed retirement acknowledges alias/unmap/TLB/cache.
            // Refusal leaves that complete graph inside this sticky owner.
            unsafe { resources.core.function.as_mut().unwrap().config().retire() }
                .map_err(Error::Configuration)?;
            drop(resources.core.function.take());
            // The protocol core conservatively keeps suspended owners on Drop.
            // Native BAR/config retirement has now discharged that obligation;
            // release these owners while preserving the real D3hot state.
            drop(resources.core.hardware.take());
            drop(resources.core.domain.take());
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.completed = true;
                Ok(())
            }
            Err(error) => {
                self.failure = Some(error.clone());
                Err(error)
            }
        }
    }
}
impl<R: RetirableRegisters, T: Timer + 'static> Link for Attached<R, T> {
    fn mac(&self) -> Mac {
        self.resources.as_ref().unwrap().core.mac()
    }
    fn carrier(&mut self) -> bool {
        self.live().is_ok() && self.core_mut().carrier()
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        self.live_link()?;
        self.core_mut().transmit(frame)
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        self.live_link()?;
        self.core_mut().receive()
    }
}
