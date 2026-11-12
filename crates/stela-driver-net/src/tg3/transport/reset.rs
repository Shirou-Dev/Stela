// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2001-2004 David S. Miller
// Copyright (C) 2001-2003 Jeff Garzik
// Copyright (C) 2004 Sun Microsystems Inc.
// Copyright (C) 2005-2018 Broadcom
//! Core reset: no DMA rings or packet-ready state is implied.
use super::*;
use crate::block::BlockError;
use crate::bus::pci::regs;
use crate::bus::pci::{
    Capabilities, ConfigError, ConfigFailure, ConfigSpace, capability::Transport,
};
use core::cell::{Cell, RefCell};
use stela_driver_base::stepped::block_on;

const PCI_STATUS_CAP_LIST: u32 = 1 << 20;
const PCI_EXPRESS: u8 = 0x10;
const GRC_MISC_CFG: u32 = 0x6804;
const GRC_MODE: u32 = 0x6800;
const GRC_FASTBOOT_PC: u32 = 0x6894;
const NVRAM_SWARB: u32 = 0x7020;
const SWARB_REQUEST: u32 = 2;
const SWARB_RELEASE: u32 = 0x20;
const SWARB_GRANTED: u32 = 0x200;
const CPMU_CLOCK_OVERRIDE: u32 = 0x3624;
const CPMU_CLOCK_OVERRIDE_ENABLE: u32 = 0x3628;
const CLOCK_OVERRIDE: u32 = 1 << 31;
const MAC_OVERRIDE_ENABLE: u32 = 1 << 13;
const MAC_DATA_SWAP: u32 = 0x34;
const RESET_PCIE_CLOCK: u32 = 1 << 29;
const CORE_RESET: u32 = 1;
const PHY_TEST_CONTROL: u32 = 0x7e2c;
const PCIE10_PSCRAM: u32 = 0x60;
const PSCRAM: u32 = 0x20;
const POST_RESET_PCIE: u32 = 0x7c00;
const PCIE_POST_RESET_FIX: u32 = 1 << 25;

impl<R: Registers, D: Delay> Hardware<R, D> {
    /// This reports the completed chip/bootcode reset only. PHY calibration,
    /// MAC initialization, DMA setup and packet readiness remain separate.
    pub fn core_reset_completed(&self) -> bool {
        self.core_reset_complete && self.failure.is_none()
    }
    pub(super) fn pcie_capability(&mut self) -> Result<u16, Error> {
        let command_status = Self::checked(self.regs().config_read32(regs::COMMAND)?)?;
        if command_status & PCI_STATUS_CAP_LIST == 0 {
            return Err(Error::UnsupportedPcie);
        }
        let registers = self.regs();
        let read = |offset: u16, bytes: u8| -> Result<u32, Error> {
            let word = Self::checked(registers.config_read32(offset & !3)?)?;
            let value = word >> ((offset & 3) * 8);
            Ok(match bytes {
                1 => value & 0xff,
                2 => value & 0xffff,
                _ => value,
            })
        };
        Capabilities::new(Transport(read))
            .find_map(|entry| match entry {
                Ok(entry) if entry.id == PCI_EXPRESS => Some(Ok(entry.offset)),
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .unwrap_or(Err(Error::UnsupportedPcie))
    }
    /// `pci_power_up`, as `pci_enable_device` runs it before `tg3_init_one`
    /// touches MMIO: a function a previous OS or firmware left in D1-D3hot
    /// (Windows fast startup does) is brought to D0 by the shared PCI
    /// power-up over this register owner's configuration transport. MMIO in
    /// D3hot reads all ones.
    pub(super) fn power_up(&mut self) -> Result<(), Error> {
        let Self {
            registers, delay, ..
        } = self;
        let mut config = Config {
            registers: RefCell::new(registers.as_mut().expect("retained hardware registers")),
            first: Cell::new(None),
        };
        let result = crate::bus::pci::power_up_config(&mut config, |microseconds| {
            delay.wait_us(microseconds).map_err(BlockError::from)
        });
        let kept = config.first.take();
        result.map_err(|error| {
            kept.unwrap_or(match error {
                BlockError::Config(error) => Error::Config(error),
                BlockError::PciPower(error) => Error::Timing(error),
                BlockError::PciCapability(error) => Error::PciCapability(error),
                BlockError::Unsupported("PCI function does not answer") => Error::Removed,
                _ => Error::ConfigDidNotLatch,
            })
        })
    }
    pub(super) async fn nvram_lock(&mut self) -> Result<(), Error> {
        self.write(NVRAM_SWARB, SWARB_REQUEST)?;
        let result = async {
            for _ in 0..8000 {
                if self.read(NVRAM_SWARB)? & SWARB_GRANTED != 0 {
                    return Ok(());
                }
                self.wait(20).await?;
            }
            Err(Error::NvramTimeout)
        }
        .await;
        if result.is_err() {
            let cleanup = self.flush(NVRAM_SWARB, SWARB_RELEASE);
            self.cleanup(cleanup);
        }
        result
    }
    async fn firmware_after_reset(&mut self) -> Result<(), Error> {
        for _ in 0..100_000 {
            if self.sram(FIRMWARE_MBOX, None)? == !FIRMWARE_MAGIC {
                return Ok(());
            }
            self.wait(10).await?;
        }
        Err(Error::FirmwareTimeout)
    }
    /// Execute the Linux tg3_chip_reset ordinary PCIe/CPMU sequence for
    /// a named ASIC, with `tg3_write_sig_pre_reset`'s firmware signature and
    /// ASF START state before it. Bus mastering stays disabled: no rings
    /// exist. The firmware inversion, config restoration and APE release
    /// must all be observed before `core_reset_completed` is true. Any
    /// failure is terminal and keeps the config/BAR owner, including
    /// uncertain held locks.
    pub fn reset_core(&mut self) -> Result<(), Error> {
        block_on(self.reset_core_steps())
    }
    pub(super) async fn reset_core_steps(&mut self) -> Result<(), Error> {
        if self.failure.is_some() {
            return Err(Error::Poisoned);
        }
        self.timer_ready()?;
        let identity = self.identity.ok_or(Error::NotIdentified)?;
        self.core_reset_complete = false;
        let result = async {
            self.observe_management()?;
            let pcie = self.pcie_capability()?;
            let command = Self::checked(self.regs().config_read32(regs::COMMAND)?)? as u16;
            if command & regs::COMMAND_MEMORY == 0 {
                return Err(Error::ConfigDidNotLatch);
            }
            if !self.stopped {
                self.stop_engines_steps().await?;
            }
            // No new requester DMA can start while reset/bootcode state is
            // being rebuilt. The source saves/restores command using WORD
            // writes, never acknowledging PCI status with a dword RMW.
            let command = command & !(regs::COMMAND_MASTER | regs::COMMAND_INVALIDATE);
            self.regs().config_write16(regs::COMMAND, command)?;
            if self.regs().config_read32(regs::COMMAND)? as u16 != command {
                return Err(Error::ConfigDidNotLatch);
            }
            // tg3_reset_hw: tg3_stop_fw, then tg3_write_sig_pre_reset.
            self.stop_firmware().await?;
            self.sram(FIRMWARE_MBOX, Some(FIRMWARE_MAGIC))?;
            self.asf_driver_state(management::DRV_STATE_START)?;
            self.nvram_lock().await?;
            if let Err(error) = self.lock(1).await {
                let cleanup = self.flush(NVRAM_SWARB, SWARB_RELEASE);
                self.cleanup(cleanup);
                return Err(error);
            }
            // Before a reset write is issued we may release acquired grants.
            // Once issued, every error keeps ownership; a successful reset
            // itself undoes the NVRAM lock (Linux has no matching unlock).
            let preparation = (|| {
                self.write(GRC_FASTBOOT_PC, 0)?;
                if identity.asic.legacy() && self.read(PHY_TEST_CONTROL)? == PCIE10_PSCRAM {
                    self.write(PHY_TEST_CONTROL, PSCRAM)?;
                }
                self.write(GRC_MISC_CFG, RESET_PCIE_CLOCK)?;
                // tg3_override_clk.
                if identity.asic == Asic::Bcm5717 {
                    let value = self.read(CPMU_CLOCK_OVERRIDE_ENABLE)?;
                    self.write(CPMU_CLOCK_OVERRIDE_ENABLE, value | MAC_OVERRIDE_ENABLE)?;
                } else if identity.asic.plus_5717() {
                    self.write(CPMU_CLOCK_OVERRIDE, CLOCK_OVERRIDE)?;
                }
                Ok(())
            })();
            if preparation.is_err() {
                let release = self.unlock(1);
                self.cleanup(release);
                let release = self.flush(NVRAM_SWARB, SWARB_RELEASE);
                return self.combine(preparation, release);
            }
            // Do not MMIO-read here: decode may disappear until PCI config is
            // restored. The source requires both 120-us waits/config flush.
            self.write(GRC_MISC_CFG, CORE_RESET | RESET_PCIE_CLOCK)?;
            self.wait(120).await?;
            Self::checked(self.regs().config_read32(regs::COMMAND)?)?;
            self.wait(120).await?;
            let control = Self::checked(self.regs().config_read32(pcie + 8)?)? as u16;
            self.regs().config_write16(pcie + 8, control & !0x0810)?;
            if Self::checked(self.regs().config_read32(pcie + 8)?)? & 0x0810 != 0 {
                return Err(Error::ConfigDidNotLatch);
            }
            self.regs().config_write16(pcie + 10, 0x000f)?;
            let host = Self::checked(self.regs().config_read32(MISC_HOST_CTRL)?)?;
            self.regs()
                .config_write32(MISC_HOST_CTRL, (host & 0xffff_0000) | HOST_ACCESS)?;
            // tg3_restore_pci_state: the APE space only for a chip with one.
            let allow = if identity.ape { ALLOW_APE } else { 0 };
            self.regs().config_write32(PCISTATE, 0x60 | allow)?;
            if Self::checked(self.regs().config_read32(MISC_HOST_CTRL)?)? & 0xffff != HOST_ACCESS
                || Self::checked(self.regs().config_read32(PCISTATE)?)? & ALLOW_APE != allow
            {
                return Err(Error::ConfigDidNotLatch);
            }
            self.regs().config_write16(regs::COMMAND, command)?;
            if self.regs().config_read32(regs::COMMAND)? as u16 != command {
                return Err(Error::ConfigDidNotLatch);
            }
            let arbiter = self.read(MEMARB_MODE)?;
            self.flush(MEMARB_MODE, arbiter | ENABLE)?;
            if self.read(MEMARB_MODE)? & ENABLE == 0 {
                return Err(Error::ConfigDidNotLatch);
            }
            self.firmware_after_reset().await?;
            self.write(GRC_MODE, MAC_DATA_SWAP)?;
            self.flush(MAC_MODE, 0)?;
            self.wait(40).await?;
            self.unlock(1)?;
            self.flush(MAC_MI_MODE, 0x8000)?; // CPMU's 500-kHz MDIO clock.
            self.wait(80).await?;
            if identity.asic.legacy() {
                let value = self.read(POST_RESET_PCIE)?;
                self.write(POST_RESET_PCIE, value | PCIE_POST_RESET_FIX)?;
            }
            // tg3_restore_clk.
            if identity.asic == Asic::Bcm5717 {
                let value = self.read(CPMU_CLOCK_OVERRIDE_ENABLE)?;
                self.write(CPMU_CLOCK_OVERRIDE_ENABLE, value & !MAC_OVERRIDE_ENABLE)?;
            } else if identity.asic.plus_5717() {
                let value = self.read(CPMU_CLOCK_OVERRIDE)?;
                self.write(CPMU_CLOCK_OVERRIDE, value & !CLOCK_OVERRIDE)?;
            }
            if identity.asic == Asic::Bcm5762 {
                let value = self.read(CPMU_CLOCK_OVERRIDE_ENABLE)?;
                self.write(CPMU_CLOCK_OVERRIDE_ENABLE, value | MAC_OVERRIDE_ENABLE)?;
            }
            // tg3_chip_reset reprobes the ASF setting bootcode left.
            self.observe_management()?;
            Ok(())
        }
        .await;
        if result.is_ok() {
            self.core_reset_complete = true;
            self.stopped = false;
        }
        self.record(result)
    }
}

/// The function's configuration space over its register owner, for the
/// shared PCI power-up. A register failure that is not a configuration
/// error is kept and returned in place of the transport error.
struct Config<'a, R: Registers> {
    registers: RefCell<&'a mut R>,
    first: Cell<Option<Error>>,
}
impl<R: Registers> Config<'_, R> {
    fn kept(&self, error: Error, offset: u16, width: usize) -> ConfigError {
        match error {
            Error::Config(error) => error,
            error => {
                if self.first.get().is_none() {
                    self.first.set(Some(error));
                }
                ConfigError::before_effect(ConfigFailure::Access { offset, width })
            }
        }
    }
}
impl<R: Registers> ConfigSpace for Config<'_, R> {
    fn read8(&self, offset: u16) -> Result<u8, ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 3) * 8)) as u8)
    }
    fn read16(&self, offset: u16) -> Result<u16, ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 2) * 8)) as u16)
    }
    fn read32(&self, offset: u16) -> Result<u32, ConfigError> {
        let read = self.registers.borrow_mut().config_read32(offset);
        read.map_err(|error| self.kept(error, offset, 4))
    }
    fn write8(&mut self, offset: u16, _: u8) -> Result<(), ConfigError> {
        // The register owner has no byte store; the power-up uses none.
        Err(ConfigError::before_effect(ConfigFailure::Access {
            offset,
            width: 1,
        }))
    }
    fn write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        let written = self.registers.get_mut().config_write16(offset, value);
        written.map_err(|error| self.kept(error, offset, 2))
    }
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        let written = self.registers.get_mut().config_write32(offset, value);
        written.map_err(|error| self.kept(error, offset, 4))
    }
}
