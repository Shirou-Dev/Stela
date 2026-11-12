// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 1999 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
//! Cold PCH MAC/PHY/NVM composition. Linux e1000e at the pinned revision is
//! the register-sequencing reference; no Linux execution ABI is used. LPT is
//! restricted to the exact [`lpt`] cohort and ownership contract. I219 is
//! restricted to the exact [`i219`] and [`mtp`] PCI cohorts. An adapter the
//! Intel ME manages starts as `e1000_init_phy_workarounds_pchlan` starts it:
//! the ME takes the PHY out of ULP on request, shares it through the
//! software flag, and a PHY reset it blocks is left out. Unlisted MACs and
//! unimplemented low-power variants remain refused.
use super::{Delay, Fault, Identity, Kind, Phy, Register, Registers, nvm};
use alloc::{rc::Rc, vec::Vec};
use core::cell::RefCell;

pub mod attach;
pub mod i219;
pub mod lpt;
pub mod mtp;
pub mod queue;
pub mod spt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Profile {
    I82579,
    Lpt(lpt::Limits),
    I219(lpt::Limits, i219::Family),
    Mtp(lpt::Limits, mtp::Family, bool),
}
impl Profile {
    fn is_lpt_or_newer(self) -> bool {
        matches!(self, Self::Lpt(_) | Self::I219(_, _) | Self::Mtp(_, _, _))
    }
}

const CTRL: u32 = 0;
const STATUS: u32 = 8;
const STRAP: u32 = 0xc;
const FEXTNVM: u32 = 0x28;
const FEXTNVM3: u32 = 0x3c;
const ICR: u32 = 0xc0;
const IMC: u32 = 0xd8;
const RCTL: u32 = 0x100;
const TCTL: u32 = 0x400;
const EXTCNF_SIZE: u32 = 0xf08;
const PHY_CTRL: u32 = 0xf10;
const KABGTXD: u32 = 0x3004;
const PBA: u32 = 0x1000;
const RX_ALLOCATION_KIB: u32 = 26;
const LEDCTL: u32 = 0xe00;
const MASTER_DISABLE: u32 = 1 << 2;
const MASTER_ENABLED: u32 = 1 << 19;
const RESET: u32 = 1 << 26;
const PHY_RESET: u32 = 1 << 31;
const INIT_DONE: u32 = 1 << 9;
const PHY_RESET_ASSERTED: u32 = 1 << 10;
const PAD_SHORT: u32 = 1 << 3;
const GATE_PHY: u32 = 1 << 7;
const CONFIG_COUNTER: u32 = 3 << 26;
const CONFIG_50MS: u32 = 2 << 26;
const SW_CONFIG: u32 = 1 << 27;
const CONFIG_BASE: u32 = 0x0fff_0000;
const CONFIG_COUNT: u32 = 0x00ff_0000;
const BGSQLBIAS: u32 = 0x50000;
const MDIO_SLOW: u16 = 1 << 10;
const HOST_WAKE: u16 = 1 << 4;
const SMB_ADDRESS: u16 = 0x7f;
const SMB_ENABLE: u16 = 0x280;
const OEM_LPLU: u16 = 4;
const OEM_GBE_DISABLE: u16 = 0x40;
const OEM_RESTART: u16 = 0x400;
const PHY_D0_LPLU: u32 = 2;
const PHY_GBE_DISABLE: u32 = 0x40;
/// `E1000_H2ME`: requests from the host to the Intel ME.
const H2ME: u32 = 0x5b50;
const H2ME_ULP: u32 = 1 << 11;
const H2ME_ENFORCE_SETTINGS: u32 = 1 << 12;
/// `E1000_FWSM_ULP_CFG_DONE`: the ME is still configuring ULP.
const ULP_CONFIG_DONE: u32 = 1 << 10;
const CTRL_EXT: u32 = 0x18;
const FORCE_SMBUS: u32 = 1 << 11;
/// `E1000_CTRL_EXT_LPCD`: the LANPHYPC power cycle is done.
const POWER_CYCLE_DONE: u32 = 4;
const LANPHYPC_OVERRIDE: u32 = 1 << 16;
const LANPHYPC_VALUE: u32 = 1 << 17;
const SMB_CONTROL: Register = Register {
    page: 769,
    index: 23,
};
const MSE_THRESHOLD: u16 = 0x084f;
const MSE_LINK_DOWN: u16 = 0x2411;
const LPI_UPDATE_TIMER: u16 = 0x4805;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    UnsupportedDevice(u16),
    Phy(super::Error),
    Nvm(nvm::Error),
    MasterTimeout,
    ResetStuck,
    InitTimeout,
    ResetNotObserved,
    Configuration,
    LtrLimit(u16),
    HostIdentityNotObserved,
    SmbusMode,
    PowerCycleTimeout,
    UlpState,
    /// The Intel ME did not take the PHY out of ULP when asked.
    MeUlpTimeout,
    /// The PHY does not answer and the Intel ME blocks the LANPHYPC toggle
    /// that would wake it.
    RecoveryBlocked,
    /// The PHY does not answer, even after the LANPHYPC toggle.
    PhyInaccessible,
    /// The Intel ME blocked the PHY after its reset.
    BlockedAfterReset,
    DescriptorFlushRequired,
    Dma(crate::block::BlockError),
    Stopped,
    Poisoned,
}

impl From<super::Error> for Error {
    fn from(value: super::Error) -> Self {
        Self::Phy(value)
    }
}
impl From<Fault> for Error {
    fn from(value: Fault) -> Self {
        Self::Phy(value.into())
    }
}
impl From<nvm::Error> for Error {
    fn from(value: nvm::Error) -> Self {
        Self::Nvm(value)
    }
}
impl Error {
    fn minimum_cause(&self) -> Option<crate::bus::pci::power::Error> {
        match self {
            Self::Phy(error) => match error.primary {
                Fault::Minimum(cause) => Some(cause),
                _ => match error.cleanup {
                    Some(Fault::Minimum(cause)) => Some(cause),
                    _ => None,
                },
            },
            Self::Nvm(error) => error.minimum_cause(),
            _ => None,
        }
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedDevice(device) => write!(f, "device {device:04x} is not supported"),
            Self::Phy(error) => error.fmt(f),
            Self::Nvm(error) => write!(f, "its NVM is unreadable ({error})"),
            Self::MasterTimeout => f.write_str("its DMA master did not stop"),
            Self::ResetStuck => f.write_str("its reset did not complete"),
            Self::InitTimeout => f.write_str("its configuration did not finish after reset"),
            Self::ResetNotObserved => f.write_str("its PHY reset was not observed"),
            Self::Configuration => f.write_str("its NVM configuration is invalid"),
            Self::LtrLimit(value) => write!(f, "its LTR limit {value:#06x} is invalid"),
            Self::HostIdentityNotObserved => {
                f.write_str("this PC's SMBIOS identity, which it needs, was not read")
            }
            Self::SmbusMode => f.write_str("the PHY stays in SMBus mode"),
            Self::PowerCycleTimeout => f.write_str("the PHY power cycle (LANPHYPC) did not finish"),
            Self::UlpState => f.write_str("the PHY stays in its ultra-low-power state"),
            Self::MeUlpTimeout => {
                f.write_str("the Intel ME did not take the PHY out of its low-power state")
            }
            Self::RecoveryBlocked => f.write_str(
                "the PHY does not answer, and the Intel ME blocks the power cycle that would wake it",
            ),
            Self::PhyInaccessible => {
                f.write_str("the PHY does not answer, even after a power cycle (LANPHYPC)")
            }
            Self::BlockedAfterReset => f.write_str("the Intel ME blocked the PHY after its reset"),
            Self::DescriptorFlushRequired => {
                f.write_str("the firmware left its rings needing a flush")
            }
            Self::Dma(error) => write!(f, "its DMA memory failed ({error})"),
            Self::Stopped => f.write_str("it is stopped"),
            Self::Poisoned => f.write_str("an earlier failure left it unusable"),
        }
    }
}
impl core::error::Error for Error {}

/// One function, shared only by the two serialized private transports.
/// Neither adapter escapes the controller, so another user cannot reset it or
/// sequence flash while a PHY operation is in progress.
struct Bus<R>(Rc<RefCell<R>>);
fn qualified_bus<R, D: Delay>(io: R, delay: D) -> Result<(Bus<R>, D), Error> {
    match delay.check() {
        Ok(()) => Ok((Bus(Rc::new(RefCell::new(io))), delay)),
        Err(error) => {
            core::mem::forget((io, delay));
            Err(Fault::Minimum(error).into())
        }
    }
}
impl<R> Clone for Bus<R> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
// SAFETY: the owning constructor requires one same-function owner and
// complete serialization. Each short borrow performs exactly one real access.
unsafe impl<R: Registers> Registers for Bus<R> {
    fn read32(&mut self, at: u32) -> Result<u32, Fault> {
        self.0.borrow_mut().read32(at)
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), Fault> {
        self.0.borrow_mut().write32(at, value)
    }
}
// SAFETY: the same owner implements both window contracts;
// private adapters never issue overlapping operations or expose another user.
unsafe impl<R: nvm::Registers> nvm::Registers for Bus<R> {
    fn read_mac32(&mut self, at: u32) -> Result<u32, nvm::Error> {
        self.0.borrow_mut().read_mac32(at)
    }
    fn read16(&mut self, at: u32) -> Result<u16, nvm::Error> {
        self.0.borrow_mut().read16(at)
    }
    fn read32(&mut self, at: u32) -> Result<u32, nvm::Error> {
        self.0.borrow_mut().read32(at)
    }
    fn write16(&mut self, at: u32, value: u16) -> Result<(), nvm::Error> {
        self.0.borrow_mut().write16(at, value)
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), nvm::Error> {
        self.0.borrow_mut().write32(at, value)
    }
}

type ConfigRead<R> = fn(&mut R, u16) -> Result<u16, Fault>;

/// One stopped, initialized declared PCH profile. Packet queues are owned by
/// the network backend; this constructor never enables receive or transmit.
pub struct Controller<R: Registers + nvm::Registers, D: Delay + Clone> {
    phy: Phy<Bus<R>, D>,
    nvm: nvm::Nvm<Bus<R>, D>,
    station: crate::Mac,
    identity: Identity,
    poisoned: bool,
    profile: Profile,
    config_read: Option<ConfigRead<R>>,
    /// The PHY's ULP exit failed and the start went on without it.
    ulp_exit_failed: bool,
}
impl<R: Registers + nvm::Registers, D: Delay + Clone> Controller<R, D> {
    /// # Safety
    /// `device` is the PCI device ID of an exclusively claimed Intel
    /// Ethernet function (vendor 8086, class 020000). Both register traits on
    /// `io` access the same powered MAC/flash function and keep its
    /// real reservation/mappings. Native DMA, IRQs, firmware/SMM and all other
    /// users are already excluded/drained. This is a new cold reset epoch;
    /// `delay` and its clones provide real minimum elapsed hardware delays.
    /// The 82579's initial PHY must be accessible; its SMBus/LANPHYPC
    /// recovery is not admitted (the I219 cohorts toggle LANPHYPC before
    /// their first PHY read). This does not authorize LPT/SPT by PHY-ID
    /// similarity.
    pub unsafe fn new(device: u16, io: R, delay: D) -> Result<Self, Error> {
        if !matches!(device, 0x1502 | 0x1503) {
            return Err(Error::UnsupportedDevice(device));
        }
        let (bus, delay) = qualified_bus(io, delay)?;
        // SAFETY: the constructor supplies one real same-function reset grant;
        // only these two private serialized adapters keep it.
        let nvm = unsafe { nvm::Nvm::new(nvm::Layout::Pch2, bus.clone(), delay.clone()) }?;
        // SAFETY: exact PCI cohort and the same grant as the NVM.
        let phy = unsafe { Phy::new(Kind::I82579, bus, delay) };
        let mut this = Self {
            phy,
            nvm,
            station: crate::Mac([0; 6]),
            identity: Identity {
                kind: Kind::I82579,
                id: 0,
                revision: 0,
            },
            poisoned: false,
            profile: Profile::I82579,
            config_read: None,
            ulp_exit_failed: false,
        };
        if let Err(error) = this.initialize() {
            this.poisoned = true;
            this.phy.poisoned = true;
            return Err(error);
        }
        Ok(this)
    }
    pub fn station(&self) -> crate::Mac {
        self.station
    }
    pub fn identity(&self) -> Identity {
        self.identity
    }
    fn minimum_failure(&self) -> Option<crate::bus::pci::power::Error> {
        self.phy
            .minimum_failure
            .or_else(|| self.nvm.minimum_failure())
    }
    /// Whether the PHY did not leave ULP when asked, which Linux logs as
    /// "Failed to disable ULP" before it goes on to its PHY access checks.
    pub fn ulp_exit_failed(&self) -> bool {
        self.ulp_exit_failed
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned || self.phy.is_poisoned() || self.nvm.is_poisoned()
    }

    fn read(&mut self, at: u32) -> Result<u32, Error> {
        Ok(self.phy.read_mac(at)?)
    }
    fn write(&mut self, at: u32, value: u32) -> Result<(), Error> {
        Ok(self.phy.write_mac(at, value)?)
    }
    /// Whether the Intel ME manages the adapter (FWSM firmware valid).
    fn managed(&mut self) -> Result<bool, Error> {
        Ok(self.read(super::FWSM)? & super::FW_VALID != 0)
    }
    /// `e1000_check_reset_block_ich8lan`: whether the Intel ME blocks a PHY
    /// reset, after waiting up to 300 ms for it to permit one.
    fn reset_blocked(&mut self) -> Result<bool, Error> {
        for attempt in 0..=30 {
            if self.read(super::FWSM)? & super::RESET_PERMITTED != 0 {
                return Ok(false);
            }
            if attempt < 30 {
                self.phy.wait_minimum(10_000)?;
            }
        }
        Ok(true)
    }
    /// The PHY hardware reset, unless the Intel ME blocks it, as
    /// `e1000e_phy_hw_reset_generic` leaves it out. Whether it ran.
    fn reset_phy(&mut self) -> Result<bool, Error> {
        if self.reset_blocked()? {
            return Ok(false);
        }
        self.phy_reset()?;
        Ok(true)
    }
    /// `e1000_disable_ulp_lpt_lp` for an adapter the Intel ME manages: ask
    /// the ME to take the PHY out of ULP and wait up to 2.5 s for it.
    fn me_ulp_exit(&mut self) -> Result<(), Error> {
        let request = self.read(H2ME)?;
        self.write(H2ME, (request & !H2ME_ULP) | H2ME_ENFORCE_SETTINGS)?;
        let mut done = false;
        for attempt in 0..=250 {
            if self.read(super::FWSM)? & ULP_CONFIG_DONE == 0 {
                done = true;
                break;
            }
            if attempt < 250 {
                self.phy.wait_minimum(10_000)?;
            }
        }
        if !done {
            return Err(Error::MeUlpTimeout);
        }
        let request = self.read(H2ME)?;
        self.write(H2ME, request & !H2ME_ENFORCE_SETTINGS)
    }
    /// `e1000_toggle_lanphypc_pch_lpt`: power-cycle the PHY interconnect,
    /// which brings a PHY out of SMBus mode.
    fn toggle_lanphypc(&mut self) -> Result<(), Error> {
        let lpt = self.profile.is_lpt_or_newer();
        self.phy.transaction(|p| {
            let value = p.read_mac(FEXTNVM3)?;
            p.write_mac(FEXTNVM3, (value & !CONFIG_COUNTER) | CONFIG_50MS)?;
            let value = (p.read_mac(CTRL)? | LANPHYPC_OVERRIDE) & !LANPHYPC_VALUE;
            p.write_mac(CTRL, value)?;
            p.read_mac(STATUS)?;
            p.wait_minimum(10)?;
            p.write_mac(CTRL, value & !LANPHYPC_OVERRIDE)?;
            p.read_mac(STATUS)?;
            if lpt {
                for _ in 0..=20 {
                    p.wait_minimum(5_000)?;
                    if p.read_mac(CTRL_EXT)? & POWER_CYCLE_DONE != 0 {
                        break;
                    }
                }
                p.wait_minimum(30_000)?;
            } else {
                p.wait_minimum(50_000)?;
            }
            Ok(())
        })?;
        Ok(())
    }
    /// `e1000_phy_is_accessible_pchlan`: whether the PHY answers, retried in
    /// MDIO slow mode on an 82579. On LPT and newer, an answering PHY of an
    /// adapter the ME does not manage is taken out of forced SMBus mode in
    /// the PHY and the MAC.
    fn phy_accessible(&mut self, managed: bool) -> Result<bool, Error> {
        let mut accessible = self.phy.accessible()?;
        // `e1000_set_mdio_slow_mode_hv` on a PHY that does not answer fails
        // too, and Linux then takes the PHY as inaccessible.
        if !accessible
            && !self.profile.is_lpt_or_newer()
            && self
                .phy
                .modify_if_answering(Register::new(769, 16)?, 0, MDIO_SLOW)?
        {
            accessible = self.phy.accessible()?;
        }
        if accessible && self.profile.is_lpt_or_newer() && !managed {
            self.phy.transaction(|p| {
                let retry = core::mem::replace(&mut p.retry_enabled, false);
                // Switching the interface answers with an MDI error, which
                // the readback below settles.
                let result = (|| {
                    let value = p.access(SMB_CONTROL, None)?;
                    match p.access(SMB_CONTROL, Some(value & !1)) {
                        Ok(_) | Err(Fault::MdicTimeout | Fault::MdicResponse(_)) => Ok(()),
                        Err(error) => Err(error),
                    }
                })();
                p.retry_enabled = retry;
                result
            })?;
            let value = self.read(CTRL_EXT)?;
            self.write(CTRL_EXT, value & !FORCE_SMBUS)?;
        }
        Ok(accessible)
    }
    /// `e1000_init_phy_workarounds_pchlan` after its ULP exit: a PHY that
    /// does not answer is looked for again with the MAC forced to SMBus
    /// mode, then woken with a LANPHYPC toggle unless the Intel ME blocks
    /// it, then, on LPT and newer, with the MAC back out of SMBus mode.
    fn recover_phy_access(&mut self, managed: bool) -> Result<(), Error> {
        let lpt = self.profile.is_lpt_or_newer();
        if self.phy_accessible(managed)? {
            return Ok(());
        }
        if lpt {
            let value = self.read(CTRL_EXT)?;
            self.write(CTRL_EXT, value | FORCE_SMBUS)?;
            self.phy.wait_minimum(50_000)?;
            if self.phy_accessible(managed)? {
                return Ok(());
            }
        }
        if self.reset_blocked()? {
            return Err(Error::RecoveryBlocked);
        }
        self.toggle_lanphypc()?;
        if !lpt || self.phy_accessible(managed)? {
            return Ok(());
        }
        let value = self.read(CTRL_EXT)?;
        self.write(CTRL_EXT, value & !FORCE_SMBUS)?;
        if self.phy_accessible(managed)? {
            return Ok(());
        }
        Err(Error::PhyInaccessible)
    }
    /// `e1000_init_phy_workarounds_pchlan`'s close: the PHY is reset unless
    /// the ME blocks it, and an ME that blocks it right after is a failure.
    fn reset_phy_after_workarounds(&mut self) -> Result<bool, Error> {
        let reset = self.reset_phy()?;
        if reset {
            self.configuration_done(true)?;
            if self.reset_blocked()? {
                return Err(Error::BlockedAfterReset);
            }
        }
        Ok(reset)
    }
    fn gate(&mut self, enabled: bool) -> Result<(), Error> {
        let value = self.read(super::EXTCNF_CTRL)?;
        self.write(
            super::EXTCNF_CTRL,
            if enabled {
                value | GATE_PHY
            } else {
                value & !GATE_PHY
            },
        )
    }
    fn initialize(&mut self) -> Result<(), Error> {
        self.validate_nvm()?;
        self.station = self.nvm.station()?;
        // `e1000_init_phy_workarounds_pchlan` for the 82579: gate the PHY's
        // own configuration, wake a PHY left in SMBus mode, reset it, and
        // ungate it again only when the ME does not manage the adapter.
        let managed = self.managed()?;
        self.gate(true)?;
        self.recover_phy_access(managed)?;
        self.identity = self.phy.identify()?;
        self.reset_phy_after_workarounds()?;
        if !managed {
            self.phy.wait_minimum(10_000)?;
            self.gate(false)?;
        }
        self.identity = self.phy.identify()?;
        // e1000e_reset sets the ordinary-MTU PCH2 allocation before invoking
        // reset_hw. Hardware derives the complementary TX allocation.
        self.write(PBA, RX_ALLOCATION_KIB)?;
        let reset = self.global_reset()?;
        self.configuration_done(reset)?;
        self.post_reset()?;
        self.write(IMC, u32::MAX)?;
        self.read(ICR)?;
        let bias = self.read(KABGTXD)?;
        self.write(KABGTXD, bias | BGSQLBIAS)?;
        self.identity = self.phy.identify()?;
        Ok(())
    }
    fn phy_reset(&mut self) -> Result<(), Error> {
        self.phy.transaction(|p| {
            let ctrl = p.read_mac(CTRL)?;
            p.write_mac(CTRL, ctrl | PHY_RESET)?;
            p.read_mac(STATUS)?;
            p.wait_minimum(100)?;
            p.write_mac(CTRL, ctrl)?;
            p.read_mac(STATUS)?;
            p.wait_minimum(150)?;
            Ok(())
        })?;
        Ok(())
    }
    /// `e1000_reset_hw_ich8lan`: the full reset, with the PHY's unless the
    /// Intel ME blocks it. Whether the PHY was reset too.
    fn global_reset(&mut self) -> Result<bool, Error> {
        let ctrl = self.read(CTRL)?;
        self.write(CTRL, ctrl | MASTER_DISABLE)?;
        let mut drained = false;
        for _ in 0..800 {
            if self.read(STATUS)? & MASTER_ENABLED == 0 {
                drained = true;
                break;
            }
            self.phy.wait_minimum(100)?;
        }
        if !drained {
            return Err(Error::MasterTimeout);
        }
        self.write(IMC, u32::MAX)?;
        self.write(RCTL, 0)?;
        self.write(TCTL, PAD_SHORT)?;
        self.read(STATUS)?;
        self.phy.wait_minimum(10_000)?;
        let phy = !self.reset_blocked()?;
        let ctrl = self.read(CTRL)? | if phy { PHY_RESET } else { 0 };
        if phy && !self.profile.is_lpt_or_newer() && !self.managed()? {
            self.gate(true)?;
        }
        self.phy.acquire()?;
        // Global reset invalidates SWFLAG. Do not call transaction/release:
        // it would access a reset-invalid semaphore. Even an uncertain failed
        // store must observe the full no-register-access quiet interval.
        let reset = self.phy.write_mac(CTRL, ctrl | RESET);
        self.phy.wait_minimum(20_000)?;
        reset?;
        if self.read(CTRL)? & RESET != 0 {
            return Err(Error::ResetStuck);
        }
        if !self.profile.is_lpt_or_newer() {
            let value = self.read(FEXTNVM3)?;
            self.write(FEXTNVM3, (value & !CONFIG_COUNTER) | CONFIG_50MS)?;
        }
        Ok(phy)
    }
    fn validate_nvm(&mut self) -> Result<(), Error> {
        if self.mtp_family().is_some() {
            self.nvm.validate_i219(nvm::I219Validation::Adp)?;
            return Ok(());
        }
        match self.i219_family() {
            Some(i219::Family::Tgp) => self.nvm.validate_i219(nvm::I219Validation::Tgp)?,
            Some(i219::Family::Adp) => self.nvm.validate_i219(nvm::I219Validation::Adp)?,
            _ => self.nvm.validate()?,
        }
        Ok(())
    }
    /// `e1000_get_cfg_done_ich8lan` after a reset; a PHY reset is observed
    /// only when `phy_reset` says one ran.
    fn configuration_done(&mut self, phy_reset: bool) -> Result<(), Error> {
        self.phy.wait_minimum(10_000)?;
        let mut ready = false;
        for _ in 0..1500 {
            let status = self.read(STATUS)?;
            self.phy.wait_minimum(100)?;
            if status & INIT_DONE != 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            return Err(Error::InitTimeout);
        }
        let status = self.read(STATUS)?;
        self.write(STATUS, status & !INIT_DONE)?;
        let status = self.read(STATUS)?;
        if phy_reset {
            if status & PHY_RESET_ASSERTED == 0 {
                return Err(Error::ResetNotObserved);
            }
            self.write(STATUS, status & !PHY_RESET_ASSERTED)?;
        }
        // The flash itself is immutable in this exclusive epoch. Validate its
        // selected bank/checksum again after reset; no erased-bank fallback.
        self.validate_nvm()?;
        Ok(())
    }
    fn modify(&mut self, page: u16, index: u16, clear: u16, set: u16) -> Result<(), Error> {
        let reg = Register::new(page, index)?;
        let value = self.phy.read(reg)?;
        Ok(self.phy.write(reg, (value & !clear) | set)?)
    }
    fn emi(p: &mut Phy<Bus<R>, D>, at: u16, data: u16) -> Result<(), Fault> {
        p.access(Register { page: 0, index: 16 }, Some(at))?;
        p.access(Register { page: 0, index: 17 }, Some(data))?;
        Ok(())
    }
    fn post_reset(&mut self) -> Result<(), Error> {
        self.phy.wait_minimum(10_000)?;
        if !self.profile.is_lpt_or_newer() {
            self.modify(769, 16, 0, MDIO_SLOW)?;
            self.phy.transaction(|p| {
                Self::emi(p, MSE_THRESHOLD, 0x34)?;
                Self::emi(p, MSE_LINK_DOWN, 5)
            })?;
        }
        self.modify(769, 17, HOST_WAKE, 0)?;
        self.lcd()?;
        self.oem()?;
        // `e1000_post_phy_reset_ich8lan` ungates only an unmanaged 82579.
        if !self.profile.is_lpt_or_newer() && !self.managed()? {
            self.phy.wait_minimum(10_000)?;
            self.gate(false)?;
        }
        if !self.profile.is_lpt_or_newer() {
            self.phy
                .transaction(|p| Self::emi(p, LPI_UPDATE_TIMER, 0x1387))?;
        }
        Ok(())
    }
    fn lcd(&mut self) -> Result<(), Error> {
        if self.read(FEXTNVM)? & SW_CONFIG == 0 {
            return Ok(());
        }
        let control = self.read(super::EXTCNF_CTRL)?;
        let count = (self.read(EXTCNF_SIZE)? & CONFIG_COUNT) >> 16;
        if count == 0 {
            return Ok(());
        }
        let base = ((control & CONFIG_BASE) >> 16) * 2;
        let length = count * 2;
        if base
            .checked_add(length)
            .is_none_or(|end| end > self.nvm.geometry().bank_words.min(2048))
        {
            return Err(Error::Configuration);
        }
        let mut words = Vec::new();
        words
            .try_reserve_exact(length as usize)
            .map_err(|_| nvm::Error::Allocation)?;
        words.resize(length as usize, 0);
        self.nvm.read(base as u16, &mut words)?;
        // Prevalidate the complete immutable LCD script before its first PHY
        // write. This strengthens donor streaming error behavior.
        let mut page = 0u16;
        for pair in words.as_chunks::<2>().0 {
            if pair[1] == 31 {
                if pair[0] & 31 != 0 {
                    return Err(Error::Configuration);
                }
                page = pair[0] >> 5;
            } else {
                Register::new(page, pair[1] & 31)?;
            }
        }
        let strap = self.read(STRAP)?;
        let led = self.read(LEDCTL)? as u16;
        let lpt = self.profile.is_lpt_or_newer();
        let frequency = ((strap >> 12) & 3) as u16;
        if lpt && frequency == 0 {
            return Err(Error::Configuration);
        }
        self.phy.transaction(|p| {
            let smb = Register {
                page: 768,
                index: 26,
            };
            let mut value = p.access(smb, None)?;
            if lpt {
                let frequency = frequency - 1;
                value = (value & !0x1100) | ((frequency & 1) << 8) | ((frequency & 2) << 11);
            }
            p.access(
                smb,
                Some((value & !SMB_ADDRESS) | ((strap >> 17) as u16 & SMB_ADDRESS) | SMB_ENABLE),
            )?;
            p.access(
                Register {
                    page: 768,
                    index: 30,
                },
                Some(led),
            )?;
            let mut page = 0;
            for pair in words.as_chunks::<2>().0 {
                if pair[1] == 31 {
                    page = pair[0] >> 5;
                } else {
                    p.access(
                        Register {
                            page,
                            index: pair[1] & 31,
                        },
                        Some(pair[0]),
                    )?;
                }
            }
            Ok(())
        })?;
        Ok(())
    }
    fn oem(&mut self) -> Result<(), Error> {
        // Source D0 policy: apply MAC-strapped LPLU/Gbe-disable bits.
        // Never manufacture a faster mode by ignoring an OEM restriction.
        // Autonegotiation restarts only where the ME permits a PHY reset.
        let restart = if self.reset_blocked()? {
            0
        } else {
            OEM_RESTART
        };
        self.phy.transaction(|p| {
            if p.read_mac(FEXTNVM)? & SW_CONFIG == 0 {
                return Ok(());
            }
            let control = p.read_mac(PHY_CTRL)?;
            let reg = Register {
                page: 768,
                index: 25,
            };
            let mut value = p.access(reg, None)? & !(OEM_LPLU | OEM_GBE_DISABLE);
            if control & PHY_D0_LPLU != 0 {
                value |= OEM_LPLU;
            }
            if control & PHY_GBE_DISABLE != 0 {
                value |= OEM_GBE_DISABLE;
            }
            p.access(reg, Some(value | restart))?;
            Ok(())
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
