// SPDX-License-Identifier: GPL-2.0-only
//! AQtion firmware reset and queue stop through the original DMA root.
use super::{Error, Failure, Inputs, RetirableRegisters};
use crate::aqtion::{self, Hardware, Profile, Timer, firmware};
use crate::bus::pci::{
    ConfigSpace, regs,
    requester::{
        StoppedRequester,
        preparation::{self, Attachment},
    },
};
use alloc::boxed::Box;
use core::{cell::Cell, mem::ManuallyDrop};

struct Resources<R: RetirableRegisters, T: Timer + 'static> {
    requester: preparation::PreparingRequester,
    hardware: Hardware<R, T>,
}
struct Owner<R: RetirableRegisters, T: Timer + 'static>(Option<Box<Resources<R, T>>>);
impl<R: RetirableRegisters, T: Timer + 'static> Drop for Owner<R, T> {
    fn drop(&mut self) {
        core::mem::forget(self.0.take());
    }
}
struct FailedBinding<R: RetirableRegisters, T: Timer + 'static> {
    _root: preparation::Failure,
    _hardware: ManuallyDrop<Hardware<R, T>>,
}
pub(super) struct Bound<R: RetirableRegisters, T: Timer + 'static> {
    pub requester: StoppedRequester,
    pub attachment: Attachment,
    pub hardware: Hardware<R, T>,
    pub profile: Profile,
    pub firmware: firmware::Firmware,
}

/// # Safety
/// As native::attach. No new DMA allocation/publication occurs in this phase.
#[expect(
    clippy::result_large_err,
    reason = "return the original owner and precise failure without allocating during refusal or retirement"
)]
pub(super) unsafe fn prepare<R: RetirableRegisters, T: Timer + 'static>(
    inputs: Inputs<R, T>,
) -> Result<Bound<R, T>, Failure> {
    let Inputs {
        requester,
        registers,
        timer,
    } = inputs;
    let mut owner = Owner(Some(Box::new(Resources {
        requester,
        hardware: Hardware {
            registers,
            timer,
            reset_ownership: Cell::new(firmware::ResetOwnership::default()),
            budget: Cell::new(None),
        },
    })));
    let result = (|| {
        let resources = owner.0.as_deref_mut().unwrap();
        let function = resources.requester.function_mut();
        let profile = Profile::identify(function.vendor, function.device)
            .filter(|_| function.class == [2, 0, 0])
            .ok_or(Error::Profile {
                vendor: function.vendor,
                device: function.device,
                class: function.class,
            })?;
        if function.config().read32(0)?
            != u32::from(function.vendor) | u32::from(function.device) << 16
        {
            return Err(Error::ConfigurationEpoch);
        }
        resources.hardware.check_timing()?;
        let command = function.config().read16(regs::COMMAND)?;
        if command == u16::MAX || function.config().read16(regs::STATUS)? == u16::MAX {
            return Err(Error::Device(aqtion::Error::Removed));
        }
        if command & regs::COMMAND_MASTER != 0 {
            return Err(Error::BusMaster(command));
        }
        function
            .power_up(&resources.hardware.timer)
            .map_err(Error::Power)?;
        let span = resources.hardware.registers.physical_span()?;
        let low = function.config().read32(0x10)?;
        let wide = low & 6 == 4;
        let high = if wide {
            function.config().read32(0x14)?
        } else {
            0
        };
        let base = u64::from(low & !15) | u64::from(high) << 32;
        let required = if profile.generation == aqtion::Generation::Antigua {
            0x14800
        } else {
            0x10000
        };
        if low == u32::MAX
            || low & 1 != 0
            || !matches!(low & 6, 0 | 4)
            || base != span.start()
            || span.bytes() < required
        {
            return Err(Error::Bar {
                base: span.start(),
                bytes: span.bytes(),
            });
        }
        let command = function.config().read16(regs::COMMAND)?;
        if command == u16::MAX || command & regs::COMMAND_MASTER != 0 {
            return Err(Error::BusMaster(command));
        }
        function.config().write16(
            regs::COMMAND,
            command | regs::COMMAND_MEMORY | regs::COMMAND_INTX_DISABLE,
        )?;
        let observed = function.config().read16(regs::COMMAND)?;
        if observed & 0x406 != 0x402 {
            return Err(Error::BusMaster(observed));
        }
        resources.hardware.mask_interrupts()?;
        // Firmware reset owns the stopped DMA engine, including queues left
        // active by the previous owner. Keep their old backing until root drain.
        resources.hardware.stop_queues()?;
        resources.hardware.reset(profile)?;
        resources.hardware.stop_queues()?;
        let firmware = resources.hardware.firmware(profile)?;
        Ok((profile, firmware))
    })();
    let (profile, firmware) = match result {
        Ok(value) => value,
        Err(error) => {
            return Err(Failure {
                error,
                _owner: Box::new(owner),
            });
        }
    };
    let Resources {
        requester,
        hardware,
    } = *owner.0.take().unwrap();
    let hardware = ManuallyDrop::new(hardware);
    // SAFETY: the same vendor reset and every queue-stop acknowledgement
    // completed with BME clear, prior IRQ/work/bypass excluded and all backing
    // kept. Finalization independently drains the original root before binding.
    let receipt = unsafe { requester.acknowledge_quiescence() };
    match receipt.finalize() {
        Ok(preparation::BoundRequester {
            requester,
            attachment,
        }) => Ok(Bound {
            requester,
            attachment,
            hardware: ManuallyDrop::into_inner(hardware),
            profile,
            firmware,
        }),
        Err(root) => Err(Failure {
            error: Error::Preparation(root.error),
            _owner: Box::new(FailedBinding {
                _root: root,
                _hardware: hardware,
            }),
        }),
    }
}
