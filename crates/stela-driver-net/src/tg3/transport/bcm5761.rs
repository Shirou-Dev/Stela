// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2001-2004 David S. Miller
// Copyright (C) 2001-2003 Jeff Garzik
// Copyright (C) 2004 Sun Microsystems Inc.
// Copyright (C) 2005-2018 Broadcom
//! Exact BCM5761 A0 function-zero copper NIC NVM/board profile.
use super::{
    board::{Board, decode_mac, valid_mac},
    regs::*,
    *,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::tg3) struct Profile {
    configuration: [u32; 4],
    nvram: u32,
    magic: u32,
    subsystem: u32,
}

impl<R: Registers, D: Delay> Hardware<R, D> {
    pub(super) async fn bcm5761_board(&mut self) -> Result<Board, Error> {
        self.observe_management()?;
        let identity = self.identity.ok_or(Error::NotIdentified)?;
        if identity.chip_revision != 0x0576_1000 || identity.bdf_function != 0 {
            return Err(Error::UnsupportedRevision);
        }
        let config = self.sram(NIC_SRAM_DATA_CFG, None)?;
        if config & NIC_SRAM_DATA_CFG_PHY_TYPE_MASK != NIC_SRAM_DATA_CFG_PHY_TYPE_COPPER {
            return Err(Error::UnsupportedMedia);
        }
        if config & NIC_SRAM_DATA_CFG_EEPROM_WP != 0 {
            return Err(Error::UnsupportedBoard);
        }
        let version_word = self.sram(NIC_SRAM_DATA_VER, None)?;
        let version = version_word >> NIC_SRAM_DATA_VER_SHIFT;
        if version == 0 || version >= 0x100 {
            return Err(Error::UnsupportedBoard);
        }
        let cfg2 = self.sram(NIC_SRAM_DATA_CFG_2, None)?;
        let cfg3 = self.sram(NIC_SRAM_DATA_CFG_3, None)?;
        if cfg3 & NIC_SRAM_LNK_FLAP_AVOID != 0 {
            return Err(Error::UnsupportedBoard);
        }
        let pcie = self.pcie_capability()?;
        // tg3_get_invariants derives CLKREQ_BUG from the original observed
        // endpoint setting. Keep it across our own later 10/100 clears/reset.
        let control = Self::checked(self.regs().config_read32(pcie + 0x10)?)? as u16;
        if control == u16::MAX {
            return Err(Error::Removed);
        }
        self.clkreq_bug.get_or_insert(control & 0x100 != 0);
        let led = super::board::decode_led(cfg2)?;
        let local = GRC_LCLCTRL_INT_ON_ATTN | GRC_LCLCTRL_AUTO_SEEPROM;
        // 5761 is not 5717_PLUS. Source VMain setup writes the local
        // control directly, without the 5720 APE GPIO/CPMU-status handshake.
        self.flush(GRC_LOCAL_CTRL, local)?;
        self.wait(100).await?;
        self.flush(
            GRC_EEPROM_ADDR,
            EEPROM_ADDR_FSM_RESET | (EEPROM_DEFAULT_CLOCK_PERIOD << EEPROM_ADDR_CLKPERD_SHIFT),
        )?;
        self.wait(1000).await?;
        let observed = self.read(GRC_LOCAL_CTRL)?;
        self.flush(GRC_LOCAL_CTRL, observed | GRC_LCLCTRL_AUTO_SEEPROM)?;
        self.wait(100).await?;
        // Source TPM-protected NVM requires a separate lockout-bound read path.
        // Refuse before enabling NVRAM_ACCESS or issuing a read command.
        if self.read(NVRAM_CFG1)? & (1 << 27) != 0 {
            return Err(Error::UnsupportedBoard);
        }
        let nvram = self.nvram_configuration().await?;
        if nvram & (1 << 27) != 0 {
            return Err(Error::UnsupportedBoard);
        }
        // tg3_get_5761_nvram_info: eight Atmel and eight ST straps, all
        // buffered flash with direct 256-byte addressing. Not 5720 aliases.
        if !matches!(
            nvram & NVRAM_CFG1_5752VENDOR_MASK,
            0x0080_0003
                | 0x0080_0000
                | 0x0080_0002
                | 0x0080_0001
                | 0x0000_0003
                | 0x0000_0000
                | 0x0000_0002
                | 0x0000_0001
                | 0x0280_0001
                | 0x0280_0000
                | 0x0280_0002
                | 0x0280_0003
                | 0x0200_0001
                | 0x0200_0000
                | 0x0200_0002
                | 0x0200_0003
        ) {
            return Err(Error::UnsupportedBoard);
        }
        let magic = self.nvram_word(0, false, 256).await?;
        if magic != TG3_EEPROM_MAGIC && magic & TG3_EEPROM_MAGIC_FW_MSK != TG3_EEPROM_MAGIC_FW {
            return Err(Error::UnsupportedBoard);
        }
        let high = self.sram(NIC_SRAM_MAC_ADDR_HIGH_MBOX, None)?;
        let low = self.sram(NIC_SRAM_MAC_ADDR_LOW_MBOX, None)?;
        let mut mac = decode_mac(high, low);
        if high >> 16 != 0x484b || !valid_mac(mac) {
            mac = decode_mac(
                self.nvram_word(0x7c, false, 256).await?,
                self.nvram_word(0x80, false, 256).await?,
            );
        }
        if !super::board::usable_mac(mac) {
            mac = self.fallback_mac()?;
        }
        Ok(Board {
            mac,
            local,
            led,
            // Source only enables board APD on 57765_PLUS and later 5784.
            apd: false,
            capacitive: cfg2 & (1 << 17) != 0,
            profile_5762: None,
            profile_5761: Some(Profile {
                configuration: [config, version_word, cfg2, cfg3],
                nvram,
                magic,
                subsystem: Self::checked(self.regs().config_read32(0x2c)?)?,
            }),
            phy_otp: 0,
        })
    }
}
