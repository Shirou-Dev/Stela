// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2002 ShuChen <shuchen@realtek.com.tw>
// Copyright (c) 2003-2007 Francois Romieu <romieu@fr.zoreil.com>
// Copyright (c) a lot of people too. Please respect their work.
// Copyright (c) 2026 Stela contributors
//! Checked direct OCP protocols and modern shared FIFO ownership boundary.
use super::super::registers::*;
use super::{BlockError, Hardware, Registers, Timer};
impl<R: Registers, T: Timer> Hardware<'_, R, T> {
    pub(in super::super) fn mmio8(&self, reg: usize) -> Result<u8, BlockError> {
        let value = self.registers.read8(reg);
        if value == u8::MAX {
            return Err(BlockError::Device { status: 255 });
        }
        Ok(value)
    }
    pub(in super::super) fn mmio32(&self, reg: usize) -> Result<u32, BlockError> {
        let value = self.registers.read32(reg);
        if value == u32::MAX {
            return Err(BlockError::Device { status: value });
        }
        Ok(value)
    }
    pub(in super::super) fn mmio16(&self, reg: usize) -> Result<u16, BlockError> {
        let value = self.registers.read16(reg);
        if value == u16::MAX {
            return Err(BlockError::Device {
                status: u32::from(value),
            });
        }
        Ok(value)
    }
    pub(in super::super) fn wait8(
        &self,
        reg: usize,
        mask: u8,
        expected: u8,
        tries: usize,
    ) -> Result<(), BlockError> {
        for _ in 0..tries {
            self.timer.delay(100)?;
            if self.mmio8(reg)? & mask == expected {
                return Ok(());
            }
        }
        Err(BlockError::Timeout)
    }
    pub(in super::super) fn phy_ocp_read(&self, address: u16) -> Result<u16, BlockError> {
        if address & 1 != 0 {
            return Err(BlockError::Unsupported("unaligned Realtek PHY OCP address"));
        }
        self.registers.write32(PHY_OCP, u32::from(address) << 15);
        self.poll32(PHY_OCP, ACCESS, true, 25, 10)?;
        Ok(self.mmio32(PHY_OCP)? as u16)
    }
    pub(in super::super) fn phy_ocp_write(
        &self,
        address: u16,
        value: u16,
    ) -> Result<(), BlockError> {
        if address & 1 != 0 {
            return Err(BlockError::Unsupported("unaligned Realtek PHY OCP address"));
        }
        self.registers.write32(
            PHY_OCP,
            ACCESS | (u32::from(address) << 15) | u32::from(value),
        );
        self.poll32(PHY_OCP, ACCESS, false, 25, 10)
    }
    pub(in super::super) fn mac_ocp_read(&self, address: u16) -> Result<u16, BlockError> {
        if address & 1 != 0 {
            return Err(BlockError::Unsupported("unaligned Realtek MAC OCP address"));
        }
        self.registers.write32(MAC_OCP, u32::from(address) << 15);
        // This port is synchronous: unlike PHY OCP, no completion flag exists.
        Ok(self.mmio32(MAC_OCP)? as u16)
    }
    pub(in super::super) fn mac_ocp_write(
        &self,
        address: u16,
        value: u16,
    ) -> Result<(), BlockError> {
        if address & 1 != 0 {
            return Err(BlockError::Unsupported("unaligned Realtek MAC OCP address"));
        }
        self.registers.write32(
            MAC_OCP,
            ACCESS | (u32::from(address) << 15) | u32::from(value),
        );
        self.mmio8(COMMAND)?; // PCI commit also rejects a disconnected function.
        Ok(())
    }
    pub(in super::super) fn mac_ocp_modify(
        &self,
        address: u16,
        clear: u16,
        set: u16,
    ) -> Result<(), BlockError> {
        self.mac_ocp_write(address, (self.mac_ocp_read(address)? & !clear) | set)
    }
    /// Linux `rtl_wait_txrx_fifo_empty` for versions 40 and later.
    pub(in super::super) fn fifo_empty(&self) -> Result<(), BlockError> {
        if self.revision.version < 61 {
            self.poll32(TX_CONFIG, TX_FIFO_EMPTY, true, 100, 42)?;
        } else if self.revision.version >= 63 {
            self.registers
                .write8(COMMAND, self.mmio8(COMMAND)? | STOP_REQ);
        }
        self.wait8(
            MCU,
            MCU_TX_EMPTY | MCU_RX_EMPTY,
            MCU_TX_EMPTY | MCU_RX_EMPTY,
            42,
        )?; // Both TX and RX FIFOs empty.
        if self.revision.version >= 63 {
            let mut ready = false;
            for _ in 0..42 {
                self.timer.delay(100)?;
                if self.mmio16(INTERRUPT_MITIGATION)? & 0x0103 == 0x0103 {
                    ready = true;
                    break;
                }
            }
            if !ready {
                return Err(BlockError::Timeout);
            }
        }
        Ok(())
    }
    pub fn initialize_modern(&self) -> Result<(), BlockError> {
        if !matches!(
            self.revision.version,
            40 | 42 | 44 | 46 | 51 | 52 | 61 | 63..=66 | 70
        ) {
            return Ok(());
        }
        if matches!(self.revision.version, 51 | 52) {
            self.ep_stop_cmac()?;
        }
        let r = self.registers;
        r.write32(MISC, self.mmio32(MISC)? | RXDV_GATED); // RXDV gate.
        self.timer.delay(2_000)?;
        self.fifo_empty()?;
        r.write8(COMMAND, self.mmio8(COMMAND)? & !ENABLE);
        self.timer.delay(1_000)?;
        r.write8(MCU, self.mmio8(MCU)? & !MCU_OOB);
        self.mac_ocp_modify(0xe8de, 1 << 14, 0)?;
        self.wait8(MCU, LINK_LIST_READY, LINK_LIST_READY, 42)?; // Shared link-list ownership ready.
        if self.revision.nbase() {
            self.mac_ocp_write(0xc0aa, 0x07d0)?;
            self.mac_ocp_write(0xc0a6, 0x0150)?;
            self.mac_ocp_write(0xc01e, 0x5555)?;
        } else {
            self.mac_ocp_modify(0xe8de, 0, 1 << 15)?;
        }
        self.wait8(MCU, LINK_LIST_READY, LINK_LIST_READY, 42)
    }
}
