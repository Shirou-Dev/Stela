// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2001-2004 David S. Miller
// Copyright (C) 2001-2003 Jeff Garzik
// Copyright (C) 2004 Sun Microsystems Inc.
// Copyright (C) 2005-2018 Broadcom
//! One BCM5717/5718/5719/5720/5761/5762/57765-class host-send/standard-receive/return queue, polled status DMA.
use super::{board::Board, phy::Speed, regs::*, *};

impl<R: Registers, D: Delay> Hardware<R, D> {
    pub(in crate::tg3) fn packet_prepare(&mut self) -> Result<Board, Error> {
        self.packet_identity()?;
        // Reject inherited requester DMA before allocating or publishing RAM.
        if self.regs().config_read32(4)? & 4 != 0 {
            return Err(Error::UnsupportedBoard);
        }
        self.board()
    }
    pub(in crate::tg3) fn packet_reset(&mut self, board: Board) -> Result<(), Error> {
        self.timer_ready()?;
        // PHY/config access is legal in the stopped packet epoch. No packet
        // engine is enabled by reopening this serialized register transport.
        self.stopped = false;
        // tg3_start: the APE hears of the driver before tg3_init_hw.
        self.ape_driver_start()?;
        self.initialize_phy(board)?;
        self.reset_core()?;
        // Re-observe post-bootcode signed board identity; never keep a
        // guessed MAC/management setting across reset.
        let observed = self.board()?;
        if observed.mac != board.mac
            || observed.apd != board.apd
            || observed.capacitive != board.capacitive
            || observed.local != board.local
            || observed.led != board.led
            || observed.profile_5762 != board.profile_5762
            || observed.profile_5761 != board.profile_5761
            || observed.phy_otp != board.phy_otp
        {
            return Err(Error::UnsupportedBoard);
        }
        Ok(())
    }
    fn ring_info(&mut self, at: u32, address: u64, count: u32) -> Result<(), Error> {
        self.sram(at, Some((address >> 32) as u32))?;
        self.sram(at + 4, Some(address as u32))?;
        self.sram(at + 8, Some(count << 16))?;
        Ok(())
    }
    pub(in crate::tg3) fn packet_start(
        &mut self,
        board: Board,
        addresses: [u64; 4],
        filter: &super::super::ReceiveFilter,
    ) -> Result<(), Error> {
        self.timer_ready()?;
        filter.validate()?;
        if !self.core_reset_completed() {
            return Err(Error::Poisoned);
        }
        let asic = self.identity.ok_or(Error::NotIdentified)?.asic;
        let bcm5762 = asic == Asic::Bcm5762;
        let legacy = asic.legacy();
        let bcm5717 = asic == Asic::Bcm5717;
        let class_57765 = asic.class_57765();
        let bcm5719 = asic == Asic::Bcm5719;
        // tg3's statistics workaround (5717, 5720 A0 and 5762, not 5719
        // after A0)
        // and its kept transmit length and mode fields (5720 and 5762).
        let attention = Self::statistics_attention(asic);
        let keeps_tx_fields = matches!(asic, Asic::Bcm5720 | Asic::Bcm5762);
        let geometry = super::super::geometry::Geometry::of(asic);
        if bcm5762 && self.read(TG3_CPMU_CLCK_ORIDE_ENABLE)? & TG3_CPMU_MAC_ORIDE_ENABLE == 0 {
            return Err(Error::ConfigDidNotLatch);
        }
        let [tx, rx, returns, status] = addresses;
        if !legacy {
            let dma = self.read(TG3PCI_DMA_RW_CTRL)? & !DMA_RWCTRL_DIS_CACHE_ALIGNMENT;
            self.flush(TG3PCI_DMA_RW_CTRL, dma | DMA_RWCTRL_DIS_CACHE_ALIGNMENT)?;
        }
        self.flush(
            GRC_MODE,
            GRC_MODE_WSWAP_DATA
                | GRC_MODE_BSWAP_DATA
                | GRC_MODE_WSWAP_NONFRM_DATA
                | GRC_MODE_HOST_SENDBDS
                | GRC_MODE_NO_TX_PHDR_CSUM
                | GRC_MODE_IRQ_ON_MAC_ATTN
                | GRC_MODE_HOST_STACKUP
                | if attention {
                    GRC_MODE_IRQ_ON_FLOW_ATTN
                } else {
                    0
                },
        )?;
        let misc = self.read(GRC_MISC_CFG)?;
        self.flush(
            GRC_MISC_CFG,
            (misc & !0xff) | (65 << GRC_MISC_CFG_PRESCALAR_SHIFT),
        )?;
        for (at, value) in [
            (BUFMGR_MB_RDMA_LOW_WATER, DEFAULT_MB_RDMA_LOW_WATER_5705),
            (
                BUFMGR_MB_MACRX_LOW_WATER,
                if legacy {
                    DEFAULT_MB_MACRX_LOW_WATER_5705
                } else {
                    DEFAULT_MB_MACRX_LOW_WATER_57765
                },
            ),
            (
                BUFMGR_MB_HIGH_WATER,
                if legacy {
                    DEFAULT_MB_HIGH_WATER_5705
                } else {
                    DEFAULT_MB_HIGH_WATER_57765
                },
            ),
            (BUFMGR_DMA_LOW_WATER, DEFAULT_DMA_LOW_WATER),
            (BUFMGR_DMA_HIGH_WATER, DEFAULT_DMA_HIGH_WATER),
        ] {
            self.write(at, value)?;
        }
        self.flush(
            BUFMGR_MODE,
            BUFMGR_MODE_ENABLE
                | BUFMGR_MODE_ATTN_ENABLE
                | if bcm5719 {
                    BUFMGR_MODE_NO_TX_UNDERRUN
                } else {
                    0
                }
                | if attention {
                    BUFMGR_MODE_MBLOW_ATTN_ENAB
                } else {
                    0
                },
        )?;
        let mut enabled = false;
        for _ in 0..2000 {
            if self.read(BUFMGR_MODE)? & BUFMGR_MODE_ENABLE != 0 {
                enabled = true;
                break;
            }
            self.wait(10)?;
        }
        if !enabled {
            return Err(Error::ConfigDidNotLatch);
        }
        self.write(RCVBDI_STD_THRESH, if legacy { 16 } else { 64 })?;
        if !legacy {
            self.write(STD_REPLENISH_LWM, TG3_SRAM_RX_STD_BDCACHE_SIZE_5700)?;
            self.write(RCVBDI_JUMBO_THRESH, 12)?; // disabled jumbo ring, donor default pending=100.
            self.write(JMB_REPLENISH_LWM, TG3_SRAM_RX_JMB_BDCACHE_SIZE_5700)?;
        }
        self.write(RCVDBDI_STD_BD, (rx >> 32) as u32)?;
        self.write(RCVDBDI_STD_BD + 4, rx as u32)?;
        self.write(
            RCVDBDI_STD_BD + 8,
            ((geometry.rx as u32) << 16) | if legacy { 0 } else { 1536 << 2 },
        )?;
        // tg3_reset_hw: the standard ring's NIC address outside 5717_PLUS.
        if bcm5762 || legacy {
            self.bcm5762_write(RCVDBDI_STD_BD + 12, NIC_SRAM_RX_BUFFER_DESC)?;
        } else if class_57765 {
            self.write(RCVDBDI_STD_BD + 12, NIC_SRAM_RX_BUFFER_DESC)?;
        }
        if !legacy {
            self.write(RCVDBDI_JUMBO_BD + 8, BDINFO_FLAGS_DISABLED)?;
        }
        self.rx_producer(geometry.rx - 1)?;
        self.flush(TG3_RX_JMB_PROD_IDX_REG, 0)?;
        for index in 1..if legacy {
            1
        } else if bcm5762 || class_57765 {
            2
        } else {
            4
        } {
            self.sram(
                NIC_SRAM_SEND_RCB + index * 16 + 8,
                Some(BDINFO_FLAGS_DISABLED),
            )?;
        }
        for index in 1..if legacy {
            1
        } else if bcm5762 || class_57765 {
            4
        } else {
            17
        } {
            self.sram(
                NIC_SRAM_RCV_RET_RCB + index * 16 + 8,
                Some(BDINFO_FLAGS_DISABLED),
            )?;
        }
        self.flush(MAILBOX_INTERRUPT, 1)?;
        self.tx_producer(0)?;
        self.rx_consumer(0)?;
        self.write(HOSTCC_STATUS_BLK_HOST_ADDR, (status >> 32) as u32)?;
        self.write(HOSTCC_STATUS_BLK_HOST_ADDR + 4, status as u32)?;
        self.ring_info(NIC_SRAM_SEND_RCB, tx, 512)?;
        self.ring_info(NIC_SRAM_RCV_RET_RCB, returns, geometry.returns as u32)?;
        if bcm5762 || legacy {
            self.sram(NIC_SRAM_SEND_RCB + 12, Some(NIC_SRAM_TX_BUFFER_DESC))?;
            self.sram(NIC_SRAM_RCV_RET_RCB + 12, Some(0))?;
        }
        let mac = board.mac.0;
        let high = u32::from(mac[0]) << 8 | u32::from(mac[1]);
        let low = u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]]);
        for index in 0..4 {
            self.write(MAC_ADDR_0_HIGH + index * 8, high)?;
            self.write(MAC_ADDR_0_LOW + index * 8, low)?;
        }
        self.write(
            MAC_TX_BACKOFF_SEED,
            mac.iter().map(|b| u32::from(*b)).sum::<u32>() & 0x3ff,
        )?;
        self.write(MAC_RX_MTU_SIZE, 1522)?;
        let lengths = if keeps_tx_fields {
            self.read(MAC_TX_LENGTHS)? & (TX_LENGTHS_JMB_FRM_LEN_MSK | TX_LENGTHS_CNT_DWN_VAL_MSK)
        } else {
            0
        };
        self.write(
            MAC_TX_LENGTHS,
            lengths
                | (2 << TX_LENGTHS_IPG_CRS_SHIFT)
                | (6 << TX_LENGTHS_IPG_SHIFT)
                | (32 << TX_LENGTHS_SLOT_TIME_SHIFT),
        )?;
        self.write(MAC_RCV_RULE_CFG, RCV_RULE_CFG_DEFAULT_CLASS)?;
        self.write(RCVLPC_CONFIG, 0x0181)?;
        let corruption_register = if bcm5762 {
            TG3_LSO_RD_DMA_CRPTEN_CTRL2
        } else {
            TG3_LSO_RD_DMA_CRPTEN_CTRL
        };
        // tg3_reset_hw: 5719, 5720 and 5762 only.
        if !(legacy || bcm5717 || class_57765) {
            let corruption = self.read(corruption_register)?
                | TG3_LSO_RD_DMA_CRPTEN_CTRL_BLEN_BD_4K
                | TG3_LSO_RD_DMA_CRPTEN_CTRL_BLEN_LSO_4K;
            if bcm5762 {
                self.bcm5762_write(corruption_register, corruption)?;
            } else {
                self.write(corruption_register, corruption)?;
            }
        }
        let statistics = self.read(RCVLPC_STATS_ENABLE)?;
        self.write(RCVLPC_STATS_ENABLE, statistics & !RCVLPC_STATSENAB_DACK_FIX)?;
        self.write(RCVLPC_STATSCTRL, RCVLPC_STATSCTRL_ENABLE)?;
        self.write(SNDDATAI_STATSENAB, 0xff_ffff)?;
        self.write(
            SNDDATAI_STATSCTRL,
            SNDDATAI_SCTRL_ENABLE | SNDDATAI_SCTRL_FASTUPD,
        )?;
        self.stop_block(HOSTCC_MODE)?;
        // Interrupts stay masked. Time and max-frame coalescing cause
        // status DMA even when the caller hasn't requested a NOW update yet.
        for (at, value) in [
            (HOSTCC_RXCOL_TICKS, 1),
            (HOSTCC_TXCOL_TICKS, 1),
            (HOSTCC_RXMAX_FRAMES, 1),
            (HOSTCC_TXMAX_FRAMES, 1),
            (HOSTCC_RXCOAL_MAXF_INT, 1),
            (HOSTCC_TXCOAL_MAXF_INT, 1),
        ] {
            self.write(at, value)?;
        }
        let command = Self::checked(self.regs().config_read32(4)?)? as u16;
        self.regs().config_write16(4, (command | 0x0406) & !0x10)?;
        if self.regs().config_read32(4)? as u16 != (command | 0x0406) & !0x10 {
            return Err(Error::ConfigDidNotLatch);
        }
        self.flush(
            HOSTCC_MODE,
            HOSTCC_MODE_ENABLE | HOSTCC_MODE_32BYTE | if attention { HOSTCC_MODE_ATTN } else { 0 },
        )?;
        self.write(RCVCC_MODE, RCVCC_MODE_ENABLE | RCVCC_MODE_ATTN_ENABLE)?;
        self.write(RCVLPC_MODE, RCVLPC_MODE_ENABLE)?;
        self.flush(
            MAC_MODE,
            MAC_MODE_PORT_MODE_GMII
                | MAC_MODE_TXSTAT_ENABLE
                | MAC_MODE_RXSTAT_ENABLE
                | MAC_MODE_TDE_ENABLE
                | MAC_MODE_RDE_ENABLE
                | MAC_MODE_FHDE_ENABLE
                // ENABLE_APE: the APE sends and receives through the MAC.
                | if self.identity.ok_or(Error::NotIdentified)?.ape {
                    MAC_MODE_APE_TX_EN | MAC_MODE_APE_RX_EN
                } else {
                    0
                }
                | MAC_MODE_RXSTAT_CLEAR
                | MAC_MODE_TXSTAT_CLEAR,
        )?;
        self.wait(40)?;
        self.flush(GRC_LOCAL_CTRL, board.local)?;
        self.wait(100)?;
        self.flush(
            WDMAC_MODE,
            WDMAC_MODE_ENABLE
                | WDMAC_MODE_TGTABORT_ENAB
                | WDMAC_MODE_MSTABORT_ENAB
                | WDMAC_MODE_PARITYERR_ENAB
                | WDMAC_MODE_ADDROFLOW_ENAB
                | WDMAC_MODE_FIFOOFLOW_ENAB
                | WDMAC_MODE_FIFOURUN_ENAB
                | WDMAC_MODE_FIFOOREAD_ENAB
                | WDMAC_MODE_LNGREAD_ENAB
                | WDMAC_MODE_STATUS_TAG_FIX,
        )?;
        self.wait(40)?;
        // BCM5762 uses a different register and rewrites the source
        // margin/watermark fields. BCM5717, BCM5719 after A0, BCM5720 and BCM5761
        // only add FIFO_OFLW_FIX.
        // Preserve every unrelated observed bit.
        let reserve_register = if bcm5762 {
            TG3_RDMA_RSRVCTRL_REG2
        } else {
            TG3_RDMA_RSRVCTRL_REG
        };
        let reserve = self.read(reserve_register)?;
        let reserve = if bcm5762 {
            (reserve
                & !(TG3_RDMA_RSRVCTRL_TXMRGN_MASK
                    | TG3_RDMA_RSRVCTRL_FIFO_LWM_MASK
                    | TG3_RDMA_RSRVCTRL_FIFO_HWM_MASK))
                | TG3_RDMA_RSRVCTRL_TXMRGN_320B
                | TG3_RDMA_RSRVCTRL_FIFO_LWM_1_5K
                | TG3_RDMA_RSRVCTRL_FIFO_HWM_1_5K
        } else {
            reserve
        } | TG3_RDMA_RSRVCTRL_FIFO_OFLW_FIX;
        self.write(reserve_register, reserve)?;
        if self.read(reserve_register)? != reserve {
            return Err(Error::ConfigDidNotLatch);
        }
        let rdma = if keeps_tx_fields {
            self.read(RDMAC_MODE)? & RDMAC_MODE_H2BNC_VLAN_DET
        } else {
            0
        };
        self.flush(
            RDMAC_MODE,
            rdma | if bcm5717 { RDMAC_MODE_MULT_DMA_RD_DIS } else { 0 }
                // tg3_reset_hw: a 57766 at the standard MTU reads send data
                // in 2K requests, and tg3 splits send BDs at 2K
                // (TG3_TX_BD_DMA_MAX_2K). Every frame here is a single BD
                // below 2K, so none needs splitting.
                | if asic == Asic::Bcm57766 { RDMAC_MODE_JMB_2K_MMRR } else { 0 }
                // tg3_reset_hw: a 5784 checks its BDs and mbufs for corruption.
                | if asic == Asic::Bcm5784 {
                    RDMAC_MODE_BD_SBD_CRPT_ENAB
                        | RDMAC_MODE_MBUF_RBD_CRPT_ENAB
                        | RDMAC_MODE_MBUF_SBD_CRPT_ENAB
                } else {
                    0
                }
                | RDMAC_MODE_IPV4_LSO_EN // source HW_TSO_2/3 mode; descriptors remain plain.
                | RDMAC_MODE_ENABLE
                | RDMAC_MODE_TGTABORT_ENAB
                | RDMAC_MODE_MSTABORT_ENAB
                | RDMAC_MODE_PARITYERR_ENAB
                | RDMAC_MODE_ADDROFLOW_ENAB
                | RDMAC_MODE_FIFOOFLOW_ENAB
                | RDMAC_MODE_FIFOURUN_ENAB
                | RDMAC_MODE_FIFOOREAD_ENAB
                | RDMAC_MODE_LNGREAD_ENAB
                | RDMAC_MODE_FIFO_LONG_BURST
                | if legacy { 0 } else { RDMAC_MODE_IPV6_LSO_EN },
        )?;
        self.wait(40)?;
        // Observe the residual channel lengths before applying 5719's or
        // 5720's documented workaround; no synthetic normal-channel assumption.
        for index in 0..if bcm5762 || legacy || bcm5717 || class_57765 {
            0
        } else {
            TG3_NUM_RDMA_CHANNELS
        } {
            if self.read(TG3_RDMA_LENGTH + index * 4)? > 9000 {
                let value = self.read(TG3_LSO_RD_DMA_CRPTEN_CTRL)?;
                self.write(
                    TG3_LSO_RD_DMA_CRPTEN_CTRL,
                    value
                        | if bcm5719 {
                            TG3_LSO_RD_DMA_TX_LENGTH_WA_5719
                        } else {
                            TG3_LSO_RD_DMA_TX_LENGTH_WA_5720
                        },
                )?;
                break;
            }
        }
        for (at, value) in [
            (RCVDCC_MODE, RCVDCC_MODE_ENABLE | RCVDCC_MODE_ATTN_ENABLE),
            (
                SNDDATAC_MODE,
                SNDDATAC_MODE_ENABLE
                    | if asic == Asic::Bcm5761 {
                        SNDDATAC_MODE_CDELAY
                    } else {
                        0
                    },
            ),
            (SNDBDC_MODE, SNDBDC_MODE_ENABLE | SNDBDC_MODE_ATTN_ENABLE),
            (RCVBDI_MODE, RCVBDI_MODE_ENABLE | RCVBDI_MODE_RCB_ATTN_ENAB),
            (
                RCVDBDI_MODE,
                RCVDBDI_MODE_ENABLE
                    | RCVDBDI_MODE_INV_RING_SZ
                    | if asic.large_rings() {
                        RCVDBDI_MODE_LRG_RING_SZ
                    } else {
                        0
                    },
            ),
            (SNDDATAI_MODE, SNDDATAI_MODE_ENABLE),
            (SNDDATAI_MODE, SNDDATAI_MODE_ENABLE | 0x8), // hardware TSO generation 2/3.
            (SNDBDI_MODE, SNDBDI_MODE_ENABLE | SNDBDI_MODE_ATTN_ENABLE),
            (SNDBDS_MODE, SNDBDS_MODE_ENABLE | SNDBDS_MODE_ATTN_ENABLE),
        ] {
            self.flush(at, value)?;
        }
        let tx_mode = if keeps_tx_fields {
            self.read(MAC_TX_MODE)? & (TX_MODE_JMB_FRM_LEN | TX_MODE_CNT_DN_MODE)
        } else {
            0
        };
        self.flush(
            MAC_TX_MODE,
            tx_mode | TX_MODE_ENABLE | TX_MODE_MBUF_LOCKUP_FIX,
        )?;
        self.wait(100)?;
        // Restore the requested table/mode before any new receive DMA can
        // start; the same policy survives full restart and held-D0 PHY resume.
        self.packet_filter_tables(filter)?;
        let rx_mode = self.receive_mode(
            RX_MODE_ENABLE
                | RX_MODE_IPV6_CSUM_ENABLE
                | if bcm5762 { RX_MODE_IPV4_FRAG_FIX } else { 0 },
            filter,
        );
        if bcm5762 {
            self.bcm5762_write(MAC_RX_MODE, rx_mode)?;
        } else {
            self.flush(MAC_RX_MODE, rx_mode)?;
        }
        self.wait(10)?;
        self.write(MAC_LED_CTRL, board.led)?;
        self.write(MAC_MI_STAT, MAC_MI_STAT_LNKSTAT_ATTN_ENAB)?;
        // 57765_CLASS keeps one frame, the others two.
        self.flush(MAC_LOW_WMARK_MAX_RX_FRAME, if class_57765 { 1 } else { 2 })?;
        // No multicast/VLAN/checksum offload is relied upon by the software.
        // Accept broadcast, own unicast and multicast as a raw Ethernet link.
        self.write(MAC_RCV_RULE_0, 0xc200_0000 & RCV_RULE_DISABLE_MASK)?;
        self.write(MAC_RCV_VALUE_0, RCV_RULE_DISABLE_MASK)?;
        self.write(MAC_RCV_RULE_1, 0x8600_0004 & RCV_RULE_DISABLE_MASK)?;
        self.write(MAC_RCV_VALUE_1, RCV_RULE_DISABLE_MASK)?;
        // tg3_reset_hw clears the rules up to its limit, eight on 5705_PLUS
        // parts, less the four ASF firmware keeps for itself.
        let limit = if self.management.asf { 4 } else { 8 };
        for index in 4..limit {
            self.write(MAC_RCV_RULE_0 + index * 8, 0)?;
            self.write(MAC_RCV_VALUE_0 + index * 8, 0)?;
        }
        self.initialize_phy(board)?;
        self.management_started()?;
        self.stopped = false;
        Ok(())
    }
    /// tg3_get_invariants' statistics workaround: 5717, 5720 A0 and 5762
    /// raise flow attention for the MBUF low-water discard indication.
    fn statistics_attention(asic: Asic) -> bool {
        matches!(asic, Asic::Bcm5717 | Asic::Bcm5720 | Asic::Bcm5762)
    }
    pub(in crate::tg3) fn packet_carrier(&mut self) -> Result<bool, Error> {
        self.copper_carrier()
            .map(|speed: Option<Speed>| speed.is_some())
    }
    pub(in crate::tg3) fn request_status(&mut self) -> Result<(), Error> {
        self.flush(
            HOSTCC_MODE,
            HOSTCC_MODE_ENABLE
                | HOSTCC_MODE_32BYTE
                | if Self::statistics_attention(self.identity.ok_or(Error::NotIdentified)?.asic) {
                    HOSTCC_MODE_ATTN
                } else {
                    0
                }
                | HOSTCC_MODE_NOW
                | HOSTCC_MODE_NOINT_ON_NOW,
        )
    }
    /// Classify the causes behind SD_STATUS_ERROR, following
    /// tg3_process_error. BCM5720_A0's MBUF low-water event is a discard
    /// indication, not a fatal DMA failure. tg3_periodic_fetch_stats clears
    /// that one W1C bit and counts one observation, not an exact packet total.
    pub(in crate::tg3) fn packet_attention(&mut self) -> Result<bool, Error> {
        let flow = self.read(HOSTCC_FLOW_ATTN)?;
        let message = self.read(MSGINT_STATUS)?;
        let read_dma = self.read(RDMAC_STATUS)?;
        let write_dma = self.read(WDMAC_STATUS)?;
        // tg3_process_error never treats the low-water bit as an error;
        // 5719 raises it without the statistics workaround's attention.
        let allowed = if self.identity.ok_or(Error::NotIdentified)?.asic == Asic::Bcm5761 {
            0
        } else {
            HOSTCC_FLOW_ATTN_MBUF_LWM
        };
        if flow & !allowed != 0
            || message & !MSGINT_STATUS_MSI_REQ != 0
            || read_dma != 0
            || write_dma != 0
        {
            return Err(Error::Attention {
                flow,
                message,
                read_dma,
                write_dma,
            });
        }
        let low_water = flow & HOSTCC_FLOW_ATTN_MBUF_LWM != 0;
        if low_water {
            // Do not echo the whole observed status into this W1C register.
            // Readback orders the acknowledgement; a new low-water event may
            // immediately reassert, so its being clear is not a completion
            // prerequisite. Never overwrite device-owned status DMA memory.
            self.write(HOSTCC_FLOW_ATTN, HOSTCC_FLOW_ATTN_MBUF_LWM)?;
            let after = self.read(HOSTCC_FLOW_ATTN)?;
            if after & !HOSTCC_FLOW_ATTN_MBUF_LWM != 0 {
                return Err(Error::Attention {
                    flow: after,
                    message,
                    read_dma,
                    write_dma,
                });
            }
        }
        Ok(low_water)
    }
    pub(in crate::tg3) fn tx_producer(&mut self, index: usize) -> Result<(), Error> {
        self.flush(MAILBOX_SNDHOST_PROD_IDX_0 + 4, index as u32)
    }
    pub(in crate::tg3) fn rx_producer(&mut self, index: usize) -> Result<(), Error> {
        self.flush(TG3_RX_STD_PROD_IDX_REG, index as u32)
    }
    pub(in crate::tg3) fn rx_consumer(&mut self, index: usize) -> Result<(), Error> {
        self.flush(MAILBOX_RCVRET_CON_IDX_0 + 4, index as u32)
    }
    /// tg3_halt's `tg3_stop_fw` and `tg3_write_sig_pre_reset(RESET_KIND_SHUTDOWN)`,
    /// before the engines stop.
    pub(in crate::tg3) fn packet_unload_begin(&mut self) -> Result<(), Error> {
        self.stop_firmware()?;
        self.asf_driver_state(super::management::DRV_STATE_UNLOAD)
    }
    /// tg3_halt's `tg3_write_sig_post_reset(RESET_KIND_SHUTDOWN)` and
    /// `tg3_power_down_prepare`'s APE UNLOAD, after the engines stopped: the
    /// management firmware has the port to itself again.
    pub(in crate::tg3) fn packet_unload_end(&mut self) -> Result<(), Error> {
        self.asf_driver_state(super::management::DRV_STATE_UNLOAD_DONE)?;
        self.ape_driver_unload()
    }
    pub(in crate::tg3) fn packet_stop(&mut self) -> Result<(), Error> {
        // A poisoned submission epoch cannot use normal helpers, but
        // stop accesses remain legal for containment. Failure never retires.
        // Re-observe every engine even after a partially failed core reset;
        // an old stopped bit cannot certify bootcode's subsequent effects.
        self.stop_engines_inner()?;
        self.stopped = true;
        let command = Self::checked(self.regs().config_read32(4)?)? as u16;
        self.regs().config_write16(4, command & !4)?;
        if self.regs().config_read32(4)? & 4 != 0 {
            return Err(Error::ConfigDidNotLatch);
        }
        if self.failure.is_some() || self.cleanup_failure.is_some() {
            // Stop/BME containment cannot retroactively acknowledge an
            // uncertain reset/firmware/APE ownership operation.
            return Err(Error::Poisoned);
        }
        Ok(())
    }
}
