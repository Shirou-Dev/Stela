// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2001-2004 David S. Miller
// Copyright (C) 2001-2003 Jeff Garzik
// Copyright (C) 2004 Sun Microsystems Inc.
// Copyright (C) 2005-2018 Broadcom
//! Exact BCM5762 A0 NIC board profile. No caller supplies a profile.
use super::{
    board::{Board, decode_mac, valid_mac},
    regs::*,
    *,
};

/// Pre-reset observations, compared again after bootcode. These words
/// identify a supported protocol/configuration; they are not authenticated data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::tg3) struct Profile {
    nvram: u32,
    autosense: u32,
    magic: u32,
    configuration: [u32; 3],
    subsystem: u32,
}
impl<R: Registers, D: Delay> Hardware<R, D> {
    pub(super) fn bcm5762_subsystem(&mut self) -> Result<u32, Error> {
        let subsystem = Self::checked(self.regs().config_read32(0x2c)?)?;
        // tg3_reset_hw has a distinct MRRS workaround for this Dell board.
        // No bridge restriction is inferred onto the ordinary profile.
        if subsystem == 0x07f0_1028 {
            return Err(Error::UnsupportedBoard);
        }
        Ok(subsystem)
    }
    /// Full readback matters for the new alternate registers: a posted write
    /// alone cannot check the hardware's required packet configuration.
    pub(super) fn bcm5762_write(&mut self, at: u32, value: u32) -> Result<(), Error> {
        self.write(at, value)?;
        if self.read(at)? != value {
            return Err(Error::ConfigDidNotLatch);
        }
        Ok(())
    }
    pub(super) fn bcm5762_board(&mut self) -> Result<Board, Error> {
        self.observe_management()?;
        let subsystem = self.bcm5762_subsystem()?;
        let config = self.sram(NIC_SRAM_DATA_CFG, None)?;
        if config & NIC_SRAM_DATA_CFG_PHY_TYPE_MASK != NIC_SRAM_DATA_CFG_PHY_TYPE_COPPER {
            return Err(Error::UnsupportedMedia);
        }
        // LOM GPIO state is bootcode-owned and needs a separate checked
        // reconstruction. This cut supports the positively described NIC.
        if config & NIC_SRAM_DATA_CFG_EEPROM_WP != 0 {
            return Err(Error::UnsupportedBoard);
        }
        let version_word = self.sram(NIC_SRAM_DATA_VER, None)?;
        let version = version_word >> NIC_SRAM_DATA_VER_SHIFT;
        if version == 0 || version >= 0x100 {
            return Err(Error::UnsupportedBoard);
        }
        let cfg2 = self.sram(NIC_SRAM_DATA_CFG_2, None)?;
        let led = super::board::decode_led(cfg2)?;
        // tg3_get_invariants preserves 5762's UART selector. Unlike
        // 5720, VMain selection does not acquire GPIO/modify CPMU_DRV_STATUS.
        let local = GRC_LCLCTRL_INT_ON_ATTN
            | GRC_LCLCTRL_AUTO_SEEPROM
            | (self.read(GRC_LOCAL_CTRL)? & GRC_LCLCTRL_GPIO_UART_SEL);
        self.bcm5762_write(GRC_LOCAL_CTRL, local)?;
        self.wait(100)?;
        self.flush(
            GRC_EEPROM_ADDR,
            EEPROM_ADDR_FSM_RESET | (EEPROM_DEFAULT_CLOCK_PERIOD << EEPROM_ADDR_CLKPERD_SHIFT),
        )?;
        self.wait(1000)?;
        let saved_local = self.read(GRC_LOCAL_CTRL)?;
        self.bcm5762_write(GRC_LOCAL_CTRL, saved_local | GRC_LCLCTRL_AUTO_SEEPROM)?;
        self.wait(100)?;
        let nvcfg = self.nvram_configuration()?;
        if nvcfg & NVRAM_CFG1_5762VENDOR_MASK == 0 {
            return Err(Error::UnsupportedBoard);
        }
        let vendor = nvcfg & NVRAM_CFG1_5752VENDOR_MASK;
        let eeprom = matches!(vendor, FLASH_5762_EEPROM_HD | FLASH_5762_EEPROM_LD);
        let macronix = matches!(
            vendor,
            FLASH_5762_MX25L_100
                | FLASH_5762_MX25L_200
                | FLASH_5762_MX25L_400
                | FLASH_5762_MX25L_800
                | FLASH_5762_MX25L_160_320
        );
        if !eeprom && !macronix {
            // In particular, never interpret an old 5720 ST/Atmel strap as a
            // working 5762 profile just because numeric fields overlap.
            return Err(Error::UnsupportedBoard);
        }
        let autosense = if macronix {
            let value = self.read(NVRAM_AUTOSENSE_STATUS)?;
            let shift = ((value >> AUTOSENSE_DEVID) & AUTOSENSE_DEVID_MASK) + AUTOSENSE_SIZE_IN_MB;
            let bytes = 1u32.checked_shl(shift).ok_or(Error::UnsupportedBoard)?;
            if !(0x84..=NVRAM_ADDR_MSK + 1).contains(&bytes) {
                return Err(Error::UnsupportedBoard);
            }
            value
        } else {
            0
        };
        // EEPROM remapping only changes the donor's decoder; accesses remain
        // NVRAM arbitration/read commands, without address translation.
        // Requiring a recognized magic on Macronix too is conservative: the
        // donor's Macronix branch returns earlier without this extra check.
        let magic = self.nvram_word(0, false, if macronix { 4096 } else { 0 })?;
        if magic != TG3_EEPROM_MAGIC && magic & TG3_EEPROM_MAGIC_FW_MSK != TG3_EEPROM_MAGIC_FW {
            return Err(Error::UnsupportedBoard);
        }
        let high = self.sram(NIC_SRAM_MAC_ADDR_HIGH_MBOX, None)?;
        let low = self.sram(NIC_SRAM_MAC_ADDR_LOW_MBOX, None)?;
        let mut mac = decode_mac(high, low);
        if high >> 16 != 0x484b || !valid_mac(mac) {
            // 5762 is not 5717_PLUS: all functions use offset 0x7c.
            mac = decode_mac(
                self.nvram_word(0x7c, false, 4096)?,
                self.nvram_word(0x80, false, 4096)?,
            );
        }
        if !super::board::usable_mac(mac) {
            mac = self.fallback_mac()?;
        }
        Ok(Board {
            mac,
            local,
            led,
            apd: cfg2 & NIC_SRAM_DATA_CFG_2_APD_EN != 0,
            capacitive: cfg2 & (1 << 17) != 0,
            profile_5762: Some(Profile {
                nvram: nvcfg & !NVRAM_CFG1_COMPAT_BYPASS,
                autosense,
                magic,
                configuration: [config, version_word, cfg2],
                subsystem,
            }),
            profile_5761: None,
        })
    }
}
