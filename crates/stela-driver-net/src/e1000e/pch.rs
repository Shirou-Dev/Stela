// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 1999 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
//! Owned PCH PHY transport for the 82579 and I217/I218/I219 paths.
//!
//! SWFLAG, MDIC, HV paging, debug ports and host-wakeup access follow the
//! pinned Linux e1000e shared code. [`cold`] composes the declared unmanaged
//! 82579, LPT and I219 reset/NVM/PHY/MAC/queue profiles behind owned unsafe
//! grants, and [`cold::attach`] admits exactly those PCI IDs to the network
//! probe. Other generations remain unclaimed. It never applies the
//! discrete 82574L's PHY page or RAR policy to an integrated PCH controller.

pub mod cold;
pub mod io;
pub mod nvm;

use alloc::rc::Rc;
use stela_driver_base::stepped::{Allowance, block_on};

const MDIC: u32 = 0x20;
const FWSM: u32 = 0x5b54;
const EXTCNF_CTRL: u32 = 0xf00;
const SWFLAG: u32 = 1 << 5;
const FW_VALID: u32 = 1 << 15;
const RESET_PERMITTED: u32 = 1 << 6;
const MDIC_READ: u32 = 1 << 27;
const MDIC_WRITE: u32 = 1 << 26;
const MDIC_READY: u32 = 1 << 28;
const MDIC_ERROR: u32 = 1 << 30;
const MDIC_REG_MASK: u32 = 0x1f << 16;
const MDIC_POLLS: usize = 640 * 3;
const PHY_PAGE: u16 = 31;
const PORT_PAGE: u16 = 769;
const WAKE_PAGE: u16 = 800;
const WAKE_ENABLE: u16 = 17;
const WAKE_ADDRESS: u16 = 17;
const WAKE_DATA: u16 = 18;
const WAKE_ACCESS: u16 = 1 << 2;
const WAKE_ME_HOST: u16 = (1 << 4) | (1 << 5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    I82579,
    I217,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    Minimum(crate::bus::pci::power::Error),
    Access,
    OutsideBar,
    Misaligned,
    Removed,
    /// The Intel ME took a shared receive address slot this driver needs.
    FirmwareOwned,
    SemaphoreBusy,
    SemaphoreTimeout,
    SemaphoreLost,
    MdicTimeout,
    MdicResponse(u32),
    WrongPhy(u32),
    InvalidRegister,
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    pub primary: Fault,
    pub cleanup: Option<Fault>,
}
impl From<Fault> for Error {
    fn from(primary: Fault) -> Self {
        Self {
            primary,
            cleanup: None,
        }
    }
}
impl core::fmt::Display for Fault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Minimum(error) => write!(f, "the delay clock failed ({error})"),
            Self::Access => f.write_str("a register access was refused"),
            Self::OutsideBar => f.write_str("a register lies outside the adapter's BAR"),
            Self::Misaligned => f.write_str("a register access is misaligned"),
            Self::Removed => f.write_str("the adapter stopped answering (reads all ones)"),
            Self::FirmwareOwned => f.write_str("the Intel ME holds a shared receive address slot"),
            Self::SemaphoreBusy => f.write_str("the PHY semaphore stays taken by firmware"),
            Self::SemaphoreTimeout => f.write_str("the PHY semaphore was not granted"),
            Self::SemaphoreLost => f.write_str("the PHY semaphore was lost"),
            Self::MdicTimeout => {
                f.write_str("the PHY does not answer on its management bus (MDIO timeout)")
            }
            Self::MdicResponse(response) => {
                write!(f, "the PHY answered with an error (MDIC {response:#010x})")
            }
            Self::WrongPhy(id) => write!(f, "the PHY is not the expected one (ID {id:#010x})"),
            Self::InvalidRegister => f.write_str("an invalid PHY register was named"),
            Self::Poisoned => f.write_str("an earlier PHY failure left it unusable"),
        }
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.primary.fmt(f)?;
        if let Some(cleanup) = self.cleanup {
            write!(f, ", then {cleanup}")?;
        }
        Ok(())
    }
}
impl core::error::Error for Error {}

/// Complete PCH MAC register accesses with the real reservation kept.
///
/// # Safety
/// The implementation owns the powered, exclusively claimed PCH MAC,
/// uncached mapping and PCI resource through its lifetime, with DMA/IRQ/work
/// already stopped. No SMM, firmware or other user accesses these registers or
/// resets the PHY concurrently. Accesses are bounded, aligned, little-endian,
/// volatile and ordered; an error never invents an observation or successful
/// write. Reads flush this function's posted writes. Resource release must not
/// abandon pending native CPU accesses. An unrelated token is insufficient.
pub unsafe trait Registers: 'static {
    fn read32(&mut self, offset: u32) -> Result<u32, Fault>;
    fn write32(&mut self, offset: u32, value: u32) -> Result<(), Fault>;
}

/// Minimum hardware delays; polling is additionally bounded by count.
pub use crate::bus::pci::power::Timer as Delay;

/// A checked HV register. Wakeup registers use the source's extended u16 index;
/// all other pages expose only their 32 MDIO register lanes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Register {
    page: u16,
    index: u16,
}
impl Register {
    pub fn new(page: u16, index: u16) -> Result<Self, Fault> {
        if page > 2047 || (page != WAKE_PAGE && index > 31) {
            return Err(Fault::InvalidRegister);
        }
        Ok(Self { page, index })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub kind: Kind,
    pub id: u32,
    pub revision: u8,
}

/// One exclusive PHY-access epoch. Any hardware/control failure poisons it;
/// Drop keeps the register owner after an uncertain operation. A fresh
/// object requires the constructor's reset/quiescence ownership grant.
pub struct Phy<R: Registers, D: Delay> {
    io: Option<R>,
    delay: Option<D>,
    minimum_failure: Option<crate::bus::pci::power::Error>,
    kind: Kind,
    poisoned: bool,
    retry_count: u8,
    retry_enabled: bool,
    /// The wait share of the stepped work running this PHY's operations,
    /// if any: its delays end a step once the share is spent.
    allowance: Option<Rc<Allowance>>,
}
impl<R: Registers, D: Delay> Phy<R, D> {
    /// # Safety
    /// `kind` describes the observed PCH PCI cohort: 82579 (PCH2) or
    /// I217/I218/I219 using the I217 PHY. The caller owns the exact physical
    /// requester's reset epoch exclusively, has drained DMA/IRQ/work and has
    /// not reused a prior failed PHY access epoch without real reset/recovery.
    /// `delay` must provide the requested minimum elapsed hardware time.
    /// This grant neither proves full MAC initialization nor admits network I/O.
    pub unsafe fn new(kind: Kind, io: R, delay: D) -> Self {
        Self {
            io: Some(io),
            delay: Some(delay),
            minimum_failure: None,
            kind,
            poisoned: false,
            retry_count: 0,
            retry_enabled: false,
            allowance: None,
        }
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn check_minimum(&mut self) -> Result<(), Fault> {
        if let Some(error) = self.minimum_failure {
            return Err(Fault::Minimum(error));
        }
        if self.poisoned {
            return Err(Fault::Poisoned);
        }
        match self
            .delay
            .as_ref()
            .expect("kept PHY minimum provider")
            .check()
        {
            Ok(()) => Ok(()),
            Err(error) => {
                self.minimum_failure = Some(error);
                self.poisoned = true;
                Err(Fault::Minimum(error))
            }
        }
    }
    fn wait_minimum(&mut self, us: u64) -> Result<(), Fault> {
        self.check_minimum()?;
        match self
            .delay
            .as_ref()
            .expect("kept PHY minimum provider")
            .wait_us(us)
        {
            Ok(()) => Ok(()),
            Err(error) => {
                self.minimum_failure = Some(error);
                self.poisoned = true;
                Err(Fault::Minimum(error))
            }
        }
    }
    /// [`Self::wait_minimum`], then the step ends if it spent its share.
    async fn pause(&mut self, us: u64) -> Result<(), Fault> {
        self.wait_minimum(us)?;
        if let Some(allowance) = &self.allowance {
            allowance.spent(us).await;
        }
        Ok(())
    }
    fn read_mac(&mut self, at: u32) -> Result<u32, Fault> {
        self.check_minimum()?;
        let value = self
            .io
            .as_mut()
            .expect("live PHY register owner")
            .read32(at)?;
        if value == u32::MAX {
            Err(Fault::Removed)
        } else {
            Ok(value)
        }
    }
    fn write_mac(&mut self, at: u32, value: u32) -> Result<(), Fault> {
        self.check_minimum()?;
        self.io
            .as_mut()
            .expect("live PHY register owner")
            .write32(at, value)
    }

    /// `e1000_acquire_swflag_ich8lan`: the software flag the Intel ME
    /// honours as well, so a managed adapter's PHY is shared through it.
    fn acquire(&mut self) -> Result<(), Error> {
        block_on(self.acquire_steps())
    }
    async fn acquire_steps(&mut self) -> Result<(), Error> {
        let mut value = 0;
        let mut available = false;
        for _ in 0..100 {
            value = self.read_mac(EXTCNF_CTRL)?;
            if value & SWFLAG == 0 {
                available = true;
                break;
            }
            self.pause(1000).await?;
        }
        if !available {
            return Err(Fault::SemaphoreBusy.into());
        }
        self.write_mac(EXTCNF_CTRL, value | SWFLAG)?;
        for _ in 0..1000 {
            if self.read_mac(EXTCNF_CTRL)? & SWFLAG != 0 {
                return Ok(());
            }
            self.pause(1000).await?;
        }
        // An unacknowledged claim is uncertain. Try the source's clear, keep
        // the owner on the final failure, and never retry this access epoch.
        let cleanup = (|| {
            let value = self.read_mac(EXTCNF_CTRL)?;
            self.write_mac(EXTCNF_CTRL, value & !SWFLAG)
        })();
        Err(Error {
            primary: Fault::SemaphoreTimeout,
            cleanup: cleanup.err(),
        })
    }

    fn release(&mut self) -> Result<(), Fault> {
        let value = self.read_mac(EXTCNF_CTRL)?;
        if value & SWFLAG == 0 {
            return Err(Fault::SemaphoreLost);
        }
        self.write_mac(EXTCNF_CTRL, value & !SWFLAG)?;
        if self.read_mac(EXTCNF_CTRL)? & SWFLAG != 0 {
            return Err(Fault::SemaphoreLost);
        }
        Ok(())
    }

    fn transaction<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, Fault>,
    ) -> Result<T, Error> {
        block_on(self.transaction_steps(async move |this: &mut Self| operation(this)))
    }
    /// The semaphore held around `operation`, which may wait across steps.
    async fn transaction_steps<T>(
        &mut self,
        operation: impl AsyncFnOnce(&mut Self) -> Result<T, Fault>,
    ) -> Result<T, Error> {
        if let Some(error) = self.minimum_failure {
            return Err(Fault::Minimum(error).into());
        }
        if self.poisoned {
            return Err(Fault::Poisoned.into());
        }
        self.check_minimum()?;
        if let Err(error) = self.acquire_steps().await {
            self.poisoned = true;
            return Err(error);
        }
        let result = operation(self).await;
        let cleanup = self.release();
        match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(primary), cleanup) => {
                self.poisoned = true;
                Err(Error {
                    primary,
                    cleanup: cleanup.err(),
                })
            }
            (Ok(_), Err(primary)) => {
                self.poisoned = true;
                Err(primary.into())
            }
        }
    }

    fn mdic(&mut self, address: u8, index: u16, write: Option<u16>) -> Result<u16, Fault> {
        block_on(self.mdic_steps(address, index, write))
    }
    async fn mdic_steps(
        &mut self,
        address: u8,
        index: u16,
        write: Option<u16>,
    ) -> Result<u16, Fault> {
        let retries = if self.retry_enabled {
            self.retry_count
        } else {
            0
        };
        for attempt in 0..=retries {
            match self.mdic_once(address, index, write).await {
                Err(Fault::MdicTimeout | Fault::MdicResponse(_)) if attempt < retries => {
                    self.pause(10_000).await?;
                }
                result => return result,
            }
        }
        unreachable!("bounded MDIC loop returns its last actual outcome")
    }
    async fn mdic_once(
        &mut self,
        address: u8,
        index: u16,
        write: Option<u16>,
    ) -> Result<u16, Fault> {
        if address > 31 || index > 31 {
            return Err(Fault::InvalidRegister);
        }
        let command = (u32::from(address) << 21)
            | (u32::from(index) << 16)
            | write.map_or(MDIC_READ, |value| MDIC_WRITE | u32::from(value));
        self.write_mac(MDIC, command)?;
        let mut response = 0;
        let mut ready = false;
        for _ in 0..MDIC_POLLS {
            self.pause(50).await?;
            response = self.read_mac(MDIC)?;
            if response & MDIC_READY != 0 {
                ready = true;
                break;
            }
        }
        // 82579 requires this quiet interval even when the transaction fails.
        if self.kind == Kind::I82579 {
            self.pause(100).await?;
        }
        if !ready {
            return Err(Fault::MdicTimeout);
        }
        if response & MDIC_ERROR != 0 || response & MDIC_REG_MASK != command & MDIC_REG_MASK {
            return Err(Fault::MdicResponse(response));
        }
        Ok(response as u16)
    }

    fn page(&mut self, page: u16) -> Result<(), Fault> {
        block_on(self.page_steps(page))
    }
    async fn page_steps(&mut self, page: u16) -> Result<(), Fault> {
        self.mdic_steps(1, PHY_PAGE, Some(page << 5))
            .await
            .map(|_| ())
    }

    fn access(&mut self, register: Register, value: Option<u16>) -> Result<u16, Fault> {
        block_on(self.access_steps(register, value))
    }
    async fn access_steps(&mut self, register: Register, value: Option<u16>) -> Result<u16, Fault> {
        let Register { page, index } = register;
        if page == WAKE_PAGE {
            return self.wakeup(index, value).await;
        }
        if page > 0 && page < 768 {
            // All supported PHY types use I82577's debug address/data pair.
            self.mdic_steps(2, 16, Some(((page << 5) | index) & 0x3f))
                .await?;
            return self.mdic_steps(2, 17, value).await;
        }
        let address = if page >= 768 { 1 } else { 2 };
        if index > 15 {
            self.page_steps(if page == 768 { 0 } else { page }).await?;
        }
        self.mdic_steps(address, index, value).await
    }

    async fn wakeup(&mut self, index: u16, value: Option<u16>) -> Result<u16, Fault> {
        self.page_steps(PORT_PAGE).await?;
        let saved = self.mdic_steps(1, WAKE_ENABLE, None).await?;
        self.mdic_steps(1, WAKE_ENABLE, Some((saved | WAKE_ACCESS) & !WAKE_ME_HOST))
            .await?;
        self.page_steps(WAKE_PAGE).await?;
        self.mdic_steps(1, WAKE_ADDRESS, Some(index)).await?;
        let result = self.mdic_steps(1, WAKE_DATA, value).await?;
        self.page_steps(PORT_PAGE).await?;
        self.mdic_steps(1, WAKE_ENABLE, Some(saved)).await?;
        Ok(result)
    }

    pub fn read(&mut self, register: Register) -> Result<u16, Error> {
        block_on(self.read_steps(register))
    }
    pub fn write(&mut self, register: Register, value: u16) -> Result<(), Error> {
        block_on(self.write_steps(register, value))
    }
    async fn read_steps(&mut self, register: Register) -> Result<u16, Error> {
        self.transaction_steps(async |this: &mut Self| this.access_steps(register, None).await)
            .await
    }
    async fn write_steps(&mut self, register: Register, value: u16) -> Result<(), Error> {
        self.transaction_steps(async |this: &mut Self| {
            this.access_steps(register, Some(value)).await.map(|_| ())
        })
        .await
    }
    /// Change `register` of a PHY that may not answer: a PHY that does not
    /// answer is an answer (`false`), not a failure of the transport.
    pub fn modify_if_answering(
        &mut self,
        register: Register,
        clear: u16,
        set: u16,
    ) -> Result<bool, Error> {
        self.transaction(|this| {
            let changed = (|| {
                let value = this.access(register, None)?;
                this.access(register, Some((value & !clear) | set))
            })();
            match changed {
                Ok(_) => Ok(true),
                Err(Fault::MdicTimeout | Fault::MdicResponse(_)) => Ok(false),
                Err(error) => Err(error),
            }
        })
    }
    /// `e1000_phy_is_accessible_pchlan`'s identity read: whether the PHY
    /// answers with a valid ID, tried twice with MDIC retries off. A PHY that
    /// does not answer is an answer, not a failure of the transport.
    pub fn accessible(&mut self) -> Result<bool, Error> {
        self.transaction(|this| {
            let retry = core::mem::replace(&mut this.retry_enabled, false);
            let mut found = false;
            let mut outcome = Ok(());
            for _ in 0..2 {
                let read = (|| {
                    let high = this.access(Register { page: 0, index: 2 }, None)?;
                    let low = this.access(Register { page: 0, index: 3 }, None)?;
                    Ok((u32::from(high) << 16) | u32::from(low))
                })();
                match read {
                    Ok(raw) if raw >> 16 != 0xffff && raw & 0xffff != 0xffff => {
                        // At start Linux holds no PHY ID yet and takes any
                        // valid one; `identify` names a wrong PHY after.
                        found = true;
                        break;
                    }
                    Ok(_) | Err(Fault::MdicTimeout | Fault::MdicResponse(_)) => {}
                    Err(error) => {
                        outcome = Err(error);
                        break;
                    }
                }
            }
            this.retry_enabled = retry;
            outcome.map(|()| found)
        })
    }
    fn expected_id(&self) -> u32 {
        match self.kind {
            Kind::I82579 => 0x0154_0090,
            Kind::I217 => 0x0154_00a0,
        }
    }
    pub fn identify(&mut self) -> Result<Identity, Error> {
        self.transaction(|this| {
            let high = this.access(Register { page: 0, index: 2 }, None)?;
            let low = this.access(Register { page: 0, index: 3 }, None)?;
            let raw = (u32::from(high) << 16) | u32::from(low);
            if raw & !0xf != this.expected_id() {
                return Err(Fault::WrongPhy(raw));
            }
            Ok(Identity {
                kind: this.kind,
                id: raw & !0xf,
                revision: (raw & 0xf) as u8,
            })
        })
    }
}
impl<R: Registers, D: Delay> Drop for Phy<R, D> {
    fn drop(&mut self) {
        if self.poisoned {
            // Preserve the reservation/mapping, including an uncertain
            // semaphore/page state. Only an external real reset can recover it.
            if let Some(owner) = self.io.take() {
                core::mem::forget(owner);
            }
            if let Some(minimum) = self.delay.take() {
                core::mem::forget(minimum);
            }
        }
    }
}

#[cfg(test)]
mod tests;
