// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2001-2004 David S. Miller
// Copyright (C) 2001-2003 Jeff Garzik
// Copyright (C) 2004 Sun Microsystems Inc.
// Copyright (C) 2005-2018 Broadcom
//! BCM5720/5761/5762 A0 copper setup. EEE and pause are explicitly not advertised.
use super::{board::Board, regs::*, *};
const BMCR: u32 = 0;
const BMSR: u32 = 1;
const ADVERTISE: u32 = 4;
const CTRL1000: u32 = 9;
const BMCR_RESET: u16 = 0x8000;
const BMCR_POWER_DOWN: u16 = 0x0800;
const AN_ENABLE_RESTART: u16 = 0x1200;
const BMSR_LINK_AN_COMPLETE: u16 = 0x24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Speed {
    Mb10Half,
    Mb10,
    Mb100Half,
    Mb100,
    Mb1000,
}
impl<R: Registers, D: Delay> Hardware<R, D> {
    /// tg3_power_down_phy's ordinary non-WoL copper branch. The caller has
    /// stopped and drained the packet epoch while keeping PCI D0.
    pub(in crate::tg3) fn power_down_packet_phy(&mut self) -> Result<(), Error> {
        self.timer_ready()?;
        if !self.stopped || self.failure.is_some() || self.cleanup_failure.is_some() {
            return Err(Error::Poisoned);
        }
        let bcm5761 = self.identity.ok_or(Error::NotIdentified)?.asic == Asic::Bcm5761;
        let management = self.observe_management();
        // tg3_power_down_prepare: ASF firmware keeps using the PHY, so it
        // stays powered.
        if self.record(management)?.asf {
            return Ok(());
        }
        // The source's KEEP_LINK_ON_PWRDN policy forbids this operation.
        // Observe the signed board word again before any PHY effect.
        // A policy refusal has made no PHY mutation and need not quarantine
        // the already stopped/drained packet mappings.
        let configuration = self.sram(NIC_SRAM_DATA_CFG_3, None);
        if self.record(configuration)? & NIC_SRAM_LNK_FLAP_AVOID != 0 {
            return Err(Error::UnsupportedBoard);
        }
        let result = (|| {
            self.pw(MII_TG3_EXT_CTRL, MII_TG3_EXT_CTRL_FORCE_LED_OFF)?;
            if u32::from(self.pr(MII_TG3_EXT_CTRL)?) & MII_TG3_EXT_CTRL_FORCE_LED_OFF == 0 {
                return Err(Error::ConfigDidNotLatch);
            }
            let power = MII_TG3_AUXCTL_PCTL_100TX_LPWR
                | MII_TG3_AUXCTL_PCTL_SPR_ISOLATE
                | MII_TG3_AUXCTL_PCTL_VREG_11V;
            self.aux_write(MII_TG3_AUXCTL_SHDWSEL_PWRCTL, power)?;
            if self.aux_read(MII_TG3_AUXCTL_SHDWSEL_PWRCTL)? & power != power {
                return Err(Error::ConfigDidNotLatch);
            }
            if bcm5761 {
                // tg3_power_down_phy: 5761_AX must use 12.5MHz before
                // BMCR.PDOWN. The stopped/drained D0 owner remains.
                let clock = self.read(TG3_CPMU_LSPD_1000MB_CLK)?;
                self.write(
                    TG3_CPMU_LSPD_1000MB_CLK,
                    (clock & !CPMU_LSPD_1000MB_MACCLK_MASK) | CPMU_LSPD_1000MB_MACCLK_12_5,
                )?;
                if self.read(TG3_CPMU_LSPD_1000MB_CLK)? & CPMU_LSPD_1000MB_MACCLK_MASK
                    != CPMU_LSPD_1000MB_MACCLK_12_5
                {
                    return Err(Error::ConfigDidNotLatch);
                }
            }
            self.pw(BMCR, u32::from(BMCR_POWER_DOWN))?;
            if self.pr(BMCR)? & BMCR_POWER_DOWN == 0 {
                return Err(Error::ConfigDidNotLatch);
            }
            Ok(())
        })();
        self.record(result)
    }
    fn pr(&mut self, at: u32) -> Result<u16, Error> {
        self.phy_command(at as u8, None)
    }
    fn pw(&mut self, at: u32, value: u32) -> Result<(), Error> {
        self.phy_command(at as u8, Some(value as u16)).map(|_| ())
    }
    fn aux_read(&mut self, shadow: u32) -> Result<u32, Error> {
        self.pw(
            MII_TG3_AUX_CTRL,
            (shadow << MII_TG3_AUXCTL_MISC_RDSEL_SHIFT) | MII_TG3_AUXCTL_SHDWSEL_MISC,
        )?;
        self.pr(MII_TG3_AUX_CTRL).map(u32::from)
    }
    fn aux_write(&mut self, shadow: u32, value: u32) -> Result<(), Error> {
        self.pw(
            MII_TG3_AUX_CTRL,
            value
                | shadow
                | if shadow == MII_TG3_AUXCTL_SHDWSEL_MISC {
                    MII_TG3_AUXCTL_MISC_WREN
                } else {
                    0
                },
        )
    }
    fn smdsp(&mut self, enable: bool) -> Result<(), Error> {
        let value = self.aux_read(MII_TG3_AUXCTL_SHDWSEL_AUXCTL)?;
        self.aux_write(
            MII_TG3_AUXCTL_SHDWSEL_AUXCTL,
            (if enable {
                value | MII_TG3_AUXCTL_ACTL_SMDSP_ENA
            } else {
                value & !MII_TG3_AUXCTL_ACTL_SMDSP_ENA
            }) | MII_TG3_AUXCTL_ACTL_TX_6DB,
        )
    }
    pub(super) fn initialize_phy(&mut self, board: Board) -> Result<(), Error> {
        let result = self.initialize_phy_inner(board);
        self.record(result)
    }
    fn initialize_phy_inner(&mut self, board: Board) -> Result<(), Error> {
        self.read_phy_identity()?;
        let bcm5761 = self.identity.ok_or(Error::NotIdentified)?.asic == Asic::Bcm5761;
        self.clear_packet_mac_status()?;
        self.pr(BMSR)?;
        self.pr(BMSR)?;
        self.pw(BMCR, u32::from(BMCR_RESET))?;
        let mut reset = false;
        for _ in 0..5000 {
            if self.pr(BMCR)? & BMCR_RESET == 0 {
                reset = true;
                break;
            }
            self.wait(10)?;
        }
        if !reset {
            return Err(Error::PhyResetTimeout);
        }
        self.wait(40)?;
        if bcm5761 {
            let clock = self.read(TG3_CPMU_LSPD_1000MB_CLK)?;
            if clock & CPMU_LSPD_1000MB_MACCLK_MASK == CPMU_LSPD_1000MB_MACCLK_12_5 {
                self.wait(40)?;
                self.write(
                    TG3_CPMU_LSPD_1000MB_CLK,
                    clock & !CPMU_LSPD_1000MB_MACCLK_MASK,
                )?;
                if self.read(TG3_CPMU_LSPD_1000MB_CLK)? & CPMU_LSPD_1000MB_MACCLK_MASK != 0 {
                    return Err(Error::ConfigDidNotLatch);
                }
            }
        }
        self.pw(
            MII_TG3_MISC_SHDW,
            MII_TG3_MISC_SHDW_WREN
                | MII_TG3_MISC_SHDW_SCR5_SEL
                | MII_TG3_MISC_SHDW_SCR5_LPED
                | MII_TG3_MISC_SHDW_SCR5_DLPTLM
                | MII_TG3_MISC_SHDW_SCR5_SDTL
                | MII_TG3_MISC_SHDW_SCR5_C125OE
                | MII_TG3_MISC_SHDW_SCR5_DLLAPD,
        )?;
        self.pw(
            MII_TG3_MISC_SHDW,
            MII_TG3_MISC_SHDW_WREN
                | MII_TG3_MISC_SHDW_APD_SEL
                | MII_TG3_MISC_SHDW_APD_WKTM_84MS
                | if board.apd {
                    MII_TG3_MISC_SHDW_APD_ENABLE
                } else {
                    0
                },
        )?;
        if bcm5761 {
            // Source 5761 has JITTER_BUG without ADJUST_TRIM and no jumbo PHY.
            self.smdsp(true)?;
            let result = (|| {
                self.pw(MII_TG3_DSP_ADDRESS, 0x000a)?;
                self.pw(MII_TG3_DSP_RW_PORT, 0x010b)
            })();
            let disable = self.smdsp(false);
            self.combine(result, disable)?;
        } else {
            let aux = self.aux_read(MII_TG3_AUXCTL_SHDWSEL_AUXCTL)?;
            self.aux_write(
                MII_TG3_AUXCTL_SHDWSEL_AUXCTL,
                aux | MII_TG3_AUXCTL_ACTL_EXTPKTLEN,
            )?;
            let ext = u32::from(self.pr(MII_TG3_EXT_CTRL)?);
            self.pw(MII_TG3_EXT_CTRL, ext | MII_TG3_EXT_CTRL_FIFO_ELASTIC)?;
        }
        if self.identity.ok_or(Error::NotIdentified)?.asic == Asic::Bcm5762 {
            // tg3_phy_reset: this DSP calibration is exact 5762 A0 only.
            self.pw(MII_TG3_DSP_ADDRESS, 0x0ffb)?;
            self.pw(MII_TG3_DSP_RW_PORT, 0x4000)?;
        }
        let misc = self.aux_read(MII_TG3_AUXCTL_SHDWSEL_MISC)?;
        self.aux_write(
            MII_TG3_AUXCTL_SHDWSEL_MISC,
            misc | MII_TG3_AUXCTL_MISC_FORCE_AMDIX | MII_TG3_AUXCTL_MISC_WIRESPD_EN,
        )?;
        self.aux_write(MII_TG3_AUXCTL_SHDWSEL_PWRCTL, 0)?;
        self.pr(MII_TG3_ISTAT)?;
        self.pr(MII_TG3_ISTAT)?;
        self.pw(MII_TG3_IMASK, 0xffff)?;
        if board.capacitive {
            let value = self.aux_read(MII_TG3_AUXCTL_SHDWSEL_MISCTEST)?;
            self.aux_write(MII_TG3_AUXCTL_SHDWSEL_MISCTEST, value | (1 << 10))?;
        }
        // 10/100 half/full and 1000 full duplex, no pause. Carrier uses the
        // negotiated PHY result to program MAC speed and duplex.
        self.pw(ADVERTISE, 0x01e1)?;
        self.pw(CTRL1000, 0x0200)?;
        if !bcm5761 {
            self.flush(
                TG3_CPMU_EEE_LNKIDL_CTRL,
                TG3_CPMU_EEE_LNKIDL_PCIE_NL0 | TG3_CPMU_EEE_LNKIDL_UART_IDL,
            )?;
            self.flush(TG3_CPMU_EEE_CTRL, TG3_CPMU_EEE_CTRL_EXIT_20_1_US)?;
            self.flush(TG3_CPMU_EEE_MODE, 0)?;
            self.smdsp(true)?;
            let result = (|| {
                self.write_mmd(7, 0x3c, 0)?; // MDIO_AN_EEE_ADV, disabled policy.
                self.pw(MII_TG3_DSP_ADDRESS, MII_TG3_DSP_CH34TP2)?;
                let value = u32::from(self.pr(MII_TG3_DSP_RW_PORT)?);
                self.pw(MII_TG3_DSP_ADDRESS, MII_TG3_DSP_CH34TP2)?;
                self.pw(MII_TG3_DSP_RW_PORT, value | MII_TG3_DSP_CH34TP2_HIBW01)
            })();
            let disable = self.smdsp(false);
            self.combine(result, disable)?;
        }
        self.pw(BMCR, u32::from(AN_ENABLE_RESTART))?;
        let test = u32::from(self.pr(MII_TG3_TEST1)?);
        self.pw(MII_TG3_TEST1, test | MII_TG3_TEST1_CRC_EN)?;
        self.pr(MII_TG3_RXR_COUNTERS)?;
        Ok(())
    }
    fn clear_packet_mac_status(&mut self) -> Result<(), Error> {
        self.write(MAC_EVENT, 0)?;
        let changed = MAC_STATUS_SYNC_CHANGED
            | MAC_STATUS_CFG_CHANGED
            | MAC_STATUS_MI_COMPLETION
            | MAC_STATUS_LNKSTATE_CHANGED;
        for _ in 0..100 {
            self.flush(MAC_STATUS, changed)?;
            self.wait(40)?;
            if self.read(MAC_STATUS)? & changed == 0 {
                return Ok(());
            }
        }
        Err(Error::ConfigDidNotLatch)
    }
    pub(super) fn copper_carrier(&mut self) -> Result<Option<Speed>, Error> {
        self.clear_packet_mac_status()?;
        self.pr(BMSR)?; // latch-low status must be sampled twice.
        if self.pr(BMSR)? & BMSR_LINK_AN_COMPLETE != BMSR_LINK_AN_COMPLETE {
            return Ok(None);
        }
        if self.pr(BMCR)? & 0x1000 == 0 {
            return Err(Error::UnsupportedMedia);
        }
        let aux = u32::from(self.pr(MII_TG3_AUX_STAT)?);
        let speed = match aux & MII_TG3_AUX_STAT_SPDMASK {
            MII_TG3_AUX_STAT_10HALF => Speed::Mb10Half,
            MII_TG3_AUX_STAT_10FULL => Speed::Mb10,
            MII_TG3_AUX_STAT_100FULL => Speed::Mb100,
            MII_TG3_AUX_STAT_100HALF => Speed::Mb100Half,
            MII_TG3_AUX_STAT_1000FULL => Speed::Mb1000,
            _ => return Ok(None),
        };
        let mut mode = self.read(MAC_MODE)? & !(MAC_MODE_PORT_MODE_MASK | MAC_MODE_HALF_DUPLEX);
        mode |= if speed == Speed::Mb1000 {
            MAC_MODE_PORT_MODE_GMII
        } else {
            MAC_MODE_PORT_MODE_MII
        };
        if matches!(speed, Speed::Mb10Half | Speed::Mb100Half) {
            mode |= MAC_MODE_HALF_DUPLEX;
        }
        self.write(MAC_MODE, mode)?;
        let mask = MAC_MODE_PORT_MODE_MASK | MAC_MODE_HALF_DUPLEX;
        if self.read(MAC_MODE)? & mask != mode & mask {
            return Err(Error::ConfigDidNotLatch);
        }
        self.wait(40)?;
        self.flush(MAC_EVENT, 0)?; // polled link; no IRQ callback exists.
        self.wait(40)?;
        self.packet_clkreq(speed)?;
        Ok(Some(speed))
    }
}
