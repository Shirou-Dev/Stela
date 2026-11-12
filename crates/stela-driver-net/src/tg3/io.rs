// SPDX-License-Identifier: GPL-2.0-only
//! Native same-function MAC and APE mappings; no physical-address casts.
use super::{Error, Registers};
use crate::bus::pci::{ConfigSpace, Function};
use alloc::sync::Arc;
use core::ptr::NonNull;

struct Window {
    base: NonNull<u8>,
    bytes: usize,
}
impl Window {
    fn new(base: NonNull<u8>, bytes: usize, minimum: usize) -> Result<Self, Error> {
        if base.as_ptr() as usize & 3 != 0
            || bytes < minimum
            || (base.as_ptr() as usize).checked_add(bytes).is_none()
        {
            return Err(Error::Bounds);
        }
        Ok(Self { base, bytes })
    }
    fn pointer(&self, at: u32) -> Result<*mut u32, Error> {
        let at = at as usize;
        if at & 3 != 0 || at.checked_add(4).is_none_or(|end| end > self.bytes) {
            return Err(Error::Bounds);
        }
        // SAFETY: constructor's mapping and complete bounds.
        Ok(unsafe { self.base.as_ptr().add(at).cast() })
    }
    fn read(&self, at: u32) -> Result<u32, Error> {
        // SAFETY: pointer checks alignment and the entire native access.
        Ok(u32::from_le(unsafe { self.pointer(at)?.read_volatile() }))
    }
    fn write(&mut self, at: u32, value: u32) -> Result<(), Error> {
        // SAFETY: same UC mapping and checked aligned word.
        unsafe { self.pointer(at)?.write_volatile(value.to_le()) };
        Ok(())
    }
}

/// The APE window of a chip that has one ([`super::ape`]).
fn ape_window(ape: Option<(NonNull<u8>, usize)>) -> Result<Option<Window>, Error> {
    ape.map(|(base, bytes)| Window::new(base, bytes, 0x8440))
        .transpose()
}
/// A chip without an APE has no APE space to reach.
fn ape(window: &mut Option<Window>) -> Result<&mut Window, Error> {
    window.as_mut().ok_or(Error::Bounds)
}

pub struct Mmio<C: ConfigSpace> {
    function: Function<C>,
    mac: Window,
    ape: Option<Window>,
    _owner: Arc<dyn core::any::Any>,
}
/// Validation failure and the same original configuration and mapping/power
/// owners. No failure-path Drop certifies completion of their device lifetime.
pub type WindowFailure<C> = (Error, Function<C>, Arc<dyn core::any::Any>);

impl<C: ConfigSpace> Mmio<C> {
    /// # Safety
    /// `function` is the exclusively reserved powered PCI function.
    /// `mac` and `ape` are its complete UC BAR0/BAR2 mappings, and `owner`
    /// keeps both mappings, PCI reservation and power. The whole `Registers`
    /// contract holds. Firmware and IRQ users are excluded. Config access must
    /// remain usable while core reset temporarily disables MAC memory decoding.
    /// The function and mapped windows must never be rebound by another owner.
    /// Validation failure returns these same original owners without dropping
    /// either. The caller keeps their DMA/IRQ/power obligations.
    pub unsafe fn from_owned_windows(
        function: Function<C>,
        mac: NonNull<u8>,
        mac_bytes: usize,
        ape: NonNull<u8>,
        ape_bytes: usize,
        owner: Arc<dyn core::any::Any>,
    ) -> Result<Self, WindowFailure<C>> {
        let windows = (|| {
            Ok((
                Window::new(mac, mac_bytes, 0x8000)?,
                Window::new(ape, ape_bytes, 0x8440)?,
            ))
        })();
        match windows {
            Ok((mac, ape)) => Ok(Self {
                function,
                mac,
                ape: Some(ape),
                _owner: owner,
            }),
            Err(error) => Err((error, function, owner)),
        }
    }
}

#[cfg(test)]
mod tests;
// SAFETY: construction requires the same-function ownership;
// consuming it keeps the sole config access and checked UC windows together.
unsafe impl<C: ConfigSpace> Registers for Mmio<C> {
    fn function_number(&self) -> u8 {
        self.function.address.function
    }
    fn config_read32(&mut self, at: u16) -> Result<u32, Error> {
        if at & 3 != 0 || at > 4092 {
            return Err(Error::Bounds);
        }
        self.function.config().read32(at).map_err(Error::Config)
    }
    fn config_write32(&mut self, at: u16, value: u32) -> Result<(), Error> {
        if at & 3 != 0 || at > 4092 {
            return Err(Error::Bounds);
        }
        self.function.config().write32(at, value)?;
        match self.config_read32(0) {
            Ok(u32::MAX) => return Err(Error::Removed),
            Err(Error::Config(error)) => {
                return Err(Error::Config(
                    crate::bus::pci::ConfigError::write_may_have_applied(at, 4, error.reason),
                ));
            }
            Err(error) => return Err(error),
            Ok(_) => {}
        }
        Ok(())
    }
    fn config_write16(&mut self, at: u16, value: u16) -> Result<(), Error> {
        if at & 1 != 0 || at > 4094 {
            return Err(Error::Bounds);
        }
        // Native ConfigSpace overrides this with a narrow store,
        // never a dword RMW that could acknowledge adjacent W1C status.
        self.function.config().write16(at, value)?;
        match self.config_read32(0) {
            Ok(u32::MAX) => return Err(Error::Removed),
            Err(Error::Config(error)) => {
                return Err(Error::Config(
                    crate::bus::pci::ConfigError::write_may_have_applied(at, 2, error.reason),
                ));
            }
            Err(error) => return Err(error),
            Ok(_) => {}
        }
        Ok(())
    }
    fn read32(&mut self, at: u32) -> Result<u32, Error> {
        self.mac.read(at)
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), Error> {
        self.mac.write(at, value)
    }
    fn ape_read32(&mut self, at: u32) -> Result<u32, Error> {
        ape(&mut self.ape)?.read(at)
    }
    fn ape_write32(&mut self, at: u32, value: u32) -> Result<(), Error> {
        ape(&mut self.ape)?.write(at, value)
    }
}

mod cold;
pub use cold::{BindFailure, Bound, Cold};
