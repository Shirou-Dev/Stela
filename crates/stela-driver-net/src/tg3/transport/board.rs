// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2001-2004 David S. Miller
// Copyright (C) 2001-2003 Jeff Garzik
// Copyright (C) 2004 Sun Microsystems Inc.
// Copyright (C) 2005-2018 Broadcom
//! Signed board settings, VMain selection and read-only per-ASIC NVRAM.
use super::{regs::*, *};
use crate::Mac;

#[derive(Clone, Copy)]
pub(in crate::tg3) struct Board {
    pub mac: Mac,
    pub local: u32,
    pub led: u32,
    pub apd: bool,
    pub capacitive: bool,
    pub profile_5762: Option<super::bcm5762::Profile>,
    pub profile_5761: Option<super::bcm5761::Profile>,
}
impl<R: Registers, D: Delay> Hardware<R, D> {
    /// Only matching copper BCM5720/5761/5762 A0 or BCM5719 after A0 is a
    /// packet candidate.
    pub(super) fn packet_identity(&mut self) -> Result<Identity, Error> {
        self.timer_ready()?;
        // Read static PCI/subsystem denials before identify changes host/MMIO
        // access controls. PCI table membership alone never authorizes packets.
        let pci = Self::checked(self.regs().config_read32(0)?)?;
        if matches!(pci, 0x1680_14e4 | 0x1681_14e4 | 0x1688_14e4 | 0x1689_14e4)
            && (Self::checked(self.regs().config_read32(PRODID)?)? != 0x0576_1000
                || self.regs().function_number() != 0)
        {
            return Err(Error::UnsupportedRevision);
        }
        if pci == 0x1687_14e4 {
            let revision = Self::checked(self.regs().config_read32(GEN2_PRODID)?)?;
            if revision != 0x0576_2000 {
                return Err(Error::UnsupportedRevision);
            }
            self.bcm5762_subsystem()?;
        }
        let id = self.identify()?;
        // Upper bits identify the ASIC, lower 12 keep revision/metal. This
        // packet backend implements exact A0 deltas; no extrapolated IDs.
        // BCM5719 is the exception: tg3 singles out only its A0, whose TSO,
        // jumbo ring, statistics and read DMA errata are not implemented
        // here, and treats every later 5719 revision alike.
        let admitted = if id.asic == Asic::Bcm5719 {
            id.chip_revision != CHIPREV_ID_5719_A0
        } else {
            id.chip_revision & 0xfff == 0
        };
        if !admitted {
            return Err(Error::UnsupportedRevision);
        }
        self.observe_management()?;
        self.read_phy_identity()?;
        Ok(id)
    }
    pub(super) fn board(&mut self) -> Result<Board, Error> {
        if self.identity.ok_or(Error::NotIdentified)?.asic == Asic::Bcm5761 {
            return self.bcm5761_board();
        }
        if self.identity.ok_or(Error::NotIdentified)?.asic == Asic::Bcm5762 {
            return self.bcm5762_board();
        }
        self.observe_management()?;
        let config = self.sram(NIC_SRAM_DATA_CFG, None)?;
        if config & NIC_SRAM_DATA_CFG_PHY_TYPE_MASK == NIC_SRAM_DATA_CFG_PHY_TYPE_FIBER {
            return Err(Error::UnsupportedMedia);
        }
        let version = self.sram(NIC_SRAM_DATA_VER, None)? >> NIC_SRAM_DATA_VER_SHIFT;
        let cfg2 = if version > 0 && version < 0x100 {
            self.sram(NIC_SRAM_DATA_CFG_2, None)?
        } else {
            0
        };
        let mut local = GRC_LCLCTRL_INT_ON_ATTN | GRC_LCLCTRL_AUTO_SEEPROM;
        if config & NIC_SRAM_DATA_CFG_EEPROM_WP != 0 {
            // LOM GPIO settings are bootcode-owned and must be preserved.
            local |= self.read(GRC_LOCAL_CTRL)?
                & (GRC_LCLCTRL_GPIO_OE0
                    | GRC_LCLCTRL_GPIO_OE1
                    | GRC_LCLCTRL_GPIO_OE2
                    | GRC_LCLCTRL_GPIO_OUTPUT0
                    | GRC_LCLCTRL_GPIO_OUTPUT1
                    | GRC_LCLCTRL_GPIO_OUTPUT2);
            local |= GRC_LCLCTRL_GPIO_OE1 | GRC_LCLCTRL_GPIO_OUTPUT1;
        } else {
            // tg3_pwrsrc_switch_to_vmain: internal port, not BDF.
            // tg3_set_function_status keeps 5717/5719's driver-present bits
            // in the APE and 5720's in the CPMU.
            self.lock(7)?;
            let result = (|| {
                let identity = self.identity.unwrap();
                let shift = TG3_APE_GPIO_MSG_SHIFT + 4 * u32::from(identity.function);
                if identity.asic == Asic::Bcm5719 {
                    let status = self.ape_read(TG3_APE_GPIO_MSG)?;
                    self.regs()
                        .ape_write32(TG3_APE_GPIO_MSG, (status & !(3 << shift)) | (1 << shift))?;
                } else {
                    let status = self.read(TG3_CPMU_DRV_STATUS)?;
                    self.flush(TG3_CPMU_DRV_STATUS, (status & !(3 << shift)) | (1 << shift))?;
                }
                self.flush(GRC_LOCAL_CTRL, local)?;
                self.wait(100)?;
                Ok(())
            })();
            let release = self.unlock(7);
            self.combine(result, release)?;
        }
        self.flush(
            GRC_EEPROM_ADDR,
            EEPROM_ADDR_FSM_RESET | (EEPROM_DEFAULT_CLOCK_PERIOD << EEPROM_ADDR_CLKPERD_SHIFT),
        )?;
        self.wait(1000)?;
        let saved_local = self.read(GRC_LOCAL_CTRL)?;
        self.flush(GRC_LOCAL_CTRL, saved_local | GRC_LCLCTRL_AUTO_SEEPROM)?;
        self.wait(100)?;
        // Decode the pinstrap, including Atmel non-power-of-two pages.
        // No unrecognized NVM is treated as a functional firmware source.
        let nvcfg = self.nvram_configuration()?;
        let asic = self.identity.unwrap().asic;
        let Some(kind) = nvram_kind(asic, nvcfg & NVRAM_CFG1_5752VENDOR_MASK) else {
            return Err(Error::UnsupportedBoard);
        };
        let eeprom = kind == Nvram::Eeprom;
        let atmel = kind == Nvram::Atmel;
        let page = if eeprom {
            0
        } else {
            match nvcfg & NVRAM_CFG1_5752PAGE_SIZE_MASK {
                FLASH_5752PAGE_SIZE_256 => 256,
                FLASH_5752PAGE_SIZE_512 => 512,
                FLASH_5752PAGE_SIZE_1K => 1024,
                FLASH_5752PAGE_SIZE_2K => 2048,
                FLASH_5752PAGE_SIZE_4K => 4096,
                FLASH_5752PAGE_SIZE_264 => 264,
                FLASH_5752PAGE_SIZE_528 => 528,
                _ => return Err(Error::UnsupportedBoard),
            }
        };
        let high = self.sram(NIC_SRAM_MAC_ADDR_HIGH_MBOX, None)?;
        let low = self.sram(NIC_SRAM_MAC_ADDR_LOW_MBOX, None)?;
        let mut mac = decode_mac(high, low);
        if high >> 16 != 0x484b || !valid_mac(mac) {
            let function = self.identity.unwrap().function;
            let offset = 0x7c
                + if function & 1 != 0 { 0x50 } else { 0 }
                + if function > 1 { 0x18c } else { 0 };
            let high = self.nvram_word(offset, atmel && matches!(page, 264 | 528), page)?;
            let low = self.nvram_word(offset + 4, atmel && matches!(page, 264 | 528), page)?;
            mac = decode_mac(high, low);
        }
        if !usable_mac(mac) {
            mac = self.fallback_mac()?;
        }
        let led = super::board::decode_led(cfg2)?;
        Ok(Board {
            mac,
            local,
            led,
            apd: cfg2 & NIC_SRAM_DATA_CFG_2_APD_EN != 0,
            capacitive: cfg2 & (1 << 17) != 0,
            profile_5762: None,
            profile_5761: None,
        })
    }
    pub(super) fn nvram_configuration(&mut self) -> Result<u32, Error> {
        self.nvram_lock()?;
        let result = (|| {
            let access = self.read(NVRAM_ACCESS)?;
            self.flush(NVRAM_ACCESS, access | ACCESS_ENABLE)?;
            let config = self.read(NVRAM_CFG1)?;
            let vendor = config & NVRAM_CFG1_5752VENDOR_MASK;
            let eeprom = match self.identity.ok_or(Error::NotIdentified)?.asic {
                Asic::Bcm5762 => matches!(vendor, FLASH_5762_EEPROM_HD | FLASH_5762_EEPROM_LD),
                asic @ (Asic::Bcm5719 | Asic::Bcm5720) => {
                    nvram_kind(asic, vendor) == Some(Nvram::Eeprom)
                }
                Asic::Bcm5761 => false, // Source pinstraps are buffered flash.
            };
            if eeprom {
                self.flush(NVRAM_CFG1, config & !NVRAM_CFG1_COMPAT_BYPASS)?;
                if self.identity.unwrap().asic == Asic::Bcm5762
                    && self.read(NVRAM_CFG1)? != config & !NVRAM_CFG1_COMPAT_BYPASS
                {
                    return Err(Error::ConfigDidNotLatch);
                }
            }
            Ok(config)
        })();
        let disable = (|| {
            let access = self.read(NVRAM_ACCESS)?;
            self.flush(NVRAM_ACCESS, access & !ACCESS_ENABLE)
        })();
        let result = self.combine(result, disable);
        let release = self.flush(NVRAM_SWARB, SWARB_REQ_CLR1);
        self.combine(result, release)
    }
    pub(super) fn nvram_word(
        &mut self,
        offset: u32,
        translate: bool,
        page: u32,
    ) -> Result<u32, Error> {
        let address = if translate {
            ((offset / page) << 9) + offset % page
        } else {
            offset
        };
        if address > NVRAM_ADDR_MSK || offset & 3 != 0 {
            return Err(Error::Bounds);
        }
        self.nvram_lock()?;
        let result = (|| {
            let access = self.read(NVRAM_ACCESS)?;
            self.flush(NVRAM_ACCESS, access | ACCESS_ENABLE)?;
            self.write(NVRAM_ADDR, address)?;
            self.write(
                NVRAM_CMD,
                NVRAM_CMD_RD | NVRAM_CMD_GO | NVRAM_CMD_FIRST | NVRAM_CMD_LAST | NVRAM_CMD_DONE,
            )?;
            for _ in 0..10_000 {
                self.wait(10)?;
                if self.read(NVRAM_CMD)? & NVRAM_CMD_DONE != 0 {
                    self.wait(10)?;
                    // All-ones is legal NVRAM data; access errors remain errors.
                    return self.regs().read32(NVRAM_RDDATA);
                }
            }
            Err(Error::NvramTimeout)
        })();
        let disable = (|| {
            let access = self.read(NVRAM_ACCESS)?;
            self.flush(NVRAM_ACCESS, access & !ACCESS_ENABLE)
        })();
        let result = self.combine(result, disable);
        let release = self.flush(NVRAM_SWARB, SWARB_REQ_CLR1);
        self.combine(result, release)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Nvram {
    Eeprom,
    Atmel,
    St,
}

/// tg3_get_5717_nvram_info and tg3_get_5720_nvram_info's vendor pinstrap
/// decode. The two tables reuse codes for different parts.
fn nvram_kind(asic: Asic, vendor: u32) -> Option<Nvram> {
    Some(match (asic, vendor) {
        (Asic::Bcm5719, FLASH_5717VENDOR_ATMEL_EEPROM | FLASH_5717VENDOR_MICRO_EEPROM)
        | (Asic::Bcm5720, FLASH_5720_EEPROM_HD | FLASH_5720_EEPROM_LD) => Nvram::Eeprom,
        (
            Asic::Bcm5719,
            FLASH_5717VENDOR_ATMEL_MDB011D
            | FLASH_5717VENDOR_ATMEL_ADB011B
            | FLASH_5717VENDOR_ATMEL_ADB011D
            | FLASH_5717VENDOR_ATMEL_MDB021D
            | FLASH_5717VENDOR_ATMEL_ADB021B
            | FLASH_5717VENDOR_ATMEL_ADB021D
            | FLASH_5717VENDOR_ATMEL_45USPT,
        )
        | (
            Asic::Bcm5720,
            FLASH_5720VENDOR_M_ATMEL_DB011D
            | FLASH_5720VENDOR_M_ATMEL_DB021D
            | FLASH_5720VENDOR_M_ATMEL_DB041D
            | FLASH_5720VENDOR_M_ATMEL_DB081D
            | FLASH_5720VENDOR_A_ATMEL_DB011B
            | FLASH_5720VENDOR_A_ATMEL_DB021B
            | FLASH_5720VENDOR_A_ATMEL_DB041B
            | FLASH_5720VENDOR_A_ATMEL_DB011D
            | FLASH_5720VENDOR_A_ATMEL_DB021D
            | FLASH_5720VENDOR_A_ATMEL_DB041D
            | FLASH_5720VENDOR_A_ATMEL_DB081D
            | FLASH_5720VENDOR_ATMEL_45USPT,
        ) => Nvram::Atmel,
        (
            Asic::Bcm5719,
            FLASH_5717VENDOR_ST_M_M25PE10
            | FLASH_5717VENDOR_ST_A_M25PE10
            | FLASH_5717VENDOR_ST_M_M45PE10
            | FLASH_5717VENDOR_ST_A_M45PE10
            | FLASH_5717VENDOR_ST_M_M25PE20
            | FLASH_5717VENDOR_ST_A_M25PE20
            | FLASH_5717VENDOR_ST_M_M45PE20
            | FLASH_5717VENDOR_ST_A_M45PE20
            | FLASH_5717VENDOR_ST_25USPT
            | FLASH_5717VENDOR_ST_45USPT,
        )
        | (
            Asic::Bcm5720,
            FLASH_5720VENDOR_M_ST_M25PE10
            | FLASH_5720VENDOR_M_ST_M25PE20
            | FLASH_5720VENDOR_M_ST_M25PE40
            | FLASH_5720VENDOR_M_ST_M25PE80
            | FLASH_5720VENDOR_M_ST_M45PE10
            | FLASH_5720VENDOR_M_ST_M45PE20
            | FLASH_5720VENDOR_M_ST_M45PE40
            | FLASH_5720VENDOR_M_ST_M45PE80
            | FLASH_5720VENDOR_A_ST_M25PE10
            | FLASH_5720VENDOR_A_ST_M25PE20
            | FLASH_5720VENDOR_A_ST_M25PE40
            | FLASH_5720VENDOR_A_ST_M25PE80
            | FLASH_5720VENDOR_A_ST_M45PE10
            | FLASH_5720VENDOR_A_ST_M45PE20
            | FLASH_5720VENDOR_A_ST_M45PE40
            | FLASH_5720VENDOR_A_ST_M45PE80
            | FLASH_5720VENDOR_ST_25USPT
            | FLASH_5720VENDOR_ST_45USPT,
        ) => Nvram::St,
        _ => return None,
    })
}

pub(super) fn decode_mac(high: u32, low: u32) -> Mac {
    Mac([
        (high >> 8) as u8,
        high as u8,
        (low >> 24) as u8,
        (low >> 16) as u8,
        (low >> 8) as u8,
        low as u8,
    ])
}
pub(super) fn valid_mac(mac: Mac) -> bool {
    mac.0 != [0; 6] && !mac.is_multicast()
}
/// A valid address other than the bare Broadcom OUI an unprogrammed part
/// reports.
pub(super) fn usable_mac(mac: Mac) -> bool {
    valid_mac(mac) && mac != Mac([0, 0x10, 0x18, 0, 0, 0])
}

impl<R: Registers, D: Delay> Hardware<R, D> {
    /// The end of `tg3_get_device_address` when neither the bootcode
    /// mailbox nor NVRAM holds an address: the MAC address registers, then
    /// a random address (`eth_hw_addr_random` in `tg3_init_one`).
    /// The choice is kept for this epoch's later board reads.
    pub(super) fn fallback_mac(&mut self) -> Result<Mac, Error> {
        if let Some(mac) = self.fallback_mac {
            return Ok(mac);
        }
        let mut mac = decode_mac(self.read(MAC_ADDR_0_HIGH)?, self.read(MAC_ADDR_0_LOW)?);
        if !usable_mac(mac) {
            let identity = self.identity.ok_or(Error::NotIdentified)?;
            let [low, high] = identity.device.to_le_bytes();
            mac = Mac::random(&[low, high, identity.bdf_function, identity.function]);
        }
        self.fallback_mac = Some(mac);
        Ok(mac)
    }
}

pub(super) fn decode_led(cfg2: u32) -> Result<u32, Error> {
    Ok(
        match cfg2 & (NIC_SRAM_DATA_CFG_LED_MODE_MASK | SHASTA_EXT_LED_MODE_MASK) {
            NIC_SRAM_DATA_CFG_LED_MODE_PHY_1 => LED_CTRL_MODE_PHY_1,
            NIC_SRAM_DATA_CFG_LED_MODE_PHY_2 => LED_CTRL_MODE_PHY_2,
            NIC_SRAM_DATA_CFG_LED_MODE_MAC => LED_CTRL_MODE_MAC,
            SHASTA_EXT_LED_SHARED => {
                LED_CTRL_MODE_SHARED
                    | LED_CTRL_MODE_PHY_1
                    | LED_CTRL_MODE_PHY_2
                    | LED_CTRL_BLINK_RATE_OVERRIDE
                    | LED_CTRL_BLINK_RATE_MASK
            }
            SHASTA_EXT_LED_MAC => LED_CTRL_MODE_SHASTA_MAC,
            SHASTA_EXT_LED_COMBO => LED_CTRL_MODE_COMBO | LED_CTRL_MODE_PHY_1 | LED_CTRL_MODE_PHY_2,
            _ => return Err(Error::UnsupportedBoard),
        },
    )
}
