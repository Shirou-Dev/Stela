// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2007 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
//! Function reset, firmware synchronization and MAC setup from Linux igb.
use super::{
    Chip, InitializationWarnings, MAX_FRAME, Mac, QUEUE_ENABLE, RegisterIo, Timer, registers::*,
};
use crate::{
    block::BlockError,
    bus::pci::{ConfigSpace, Function},
};

#[derive(Clone, Copy, Default)]
pub(super) struct PciCapabilities {
    pub pcie: Option<u16>,
    pub power: Option<u16>,
}
impl PciCapabilities {
    pub(super) fn read<C: ConfigSpace>(function: &Function<C>) -> Result<Self, BlockError> {
        let mut found = Self::default();
        for (offset, id) in function.capabilities()? {
            match id {
                0x10 => found.pcie = Some(u16::from(offset)),
                1 => found.power = Some(u16::from(offset)),
                _ => {}
            }
        }
        Ok(found)
    }
}

pub(super) struct Hardware<'a, R, T> {
    pub io: &'a R,
    pub clock: &'a T,
    pub chip: Chip,
    pub port: u8,
    pub warnings: InitializationWarnings,
    clear_semaphore_once: bool,
}

impl<'a, R: RegisterIo, T: Timer> Hardware<'a, R, T> {
    pub(super) fn new(io: &'a R, clock: &'a T, chip: Chip) -> Self {
        Self {
            io,
            clock,
            chip,
            port: ((io.read(STATUS) >> 2) & 3) as u8,
            warnings: InitializationWarnings::default(),
            clear_semaphore_once: chip.modern(),
        }
    }

    pub(super) fn initialize(
        &mut self,
        config: &mut impl ConfigSpace,
        capabilities: PciCapabilities,
    ) -> Result<(Mac, InitializationWarnings), BlockError> {
        self.reset(config, capabilities)?;
        if self.io.read(CTRL_EXT) & CTRL_EXT_MODE != 0 {
            return Err(BlockError::Unsupported(
                "igb SGMII/SerDes media requires a separate PHY path",
            ));
        }
        self.io
            .write(CTRL_EXT, self.io.read(CTRL_EXT) & !CTRL_EXT_I2C);
        self.check_nvm()?;
        let mac = self.station_address()?;
        if self.chip.modern() && self.io.read(EECD) & EECD_FLASH == 0 {
            self.pll_workaround(config, capabilities)?;
        }
        self.configure_phy()?;
        self.configure_mac(mac);
        self.flush_82575_receive_fifo()?;
        Ok((mac, self.warnings))
    }

    fn reset(
        &mut self,
        config: &mut impl ConfigSpace,
        capabilities: PciCapabilities,
    ) -> Result<(), BlockError> {
        self.disable_master()?;
        if self.chip.old_reset() {
            self.completion_timeout(config, capabilities)?;
        }
        self.reset_mac()
    }

    /// Linux igb_down's register sequence: stop receive and transmit, give
    /// in-flight frames 10 ms, then igb_reset's bus master drain and MAC
    /// reset. Only a completed reset proves the controller writes no ring.
    /// The 82575/82576 completion timeout igb_reset_hw_82575 sets again is
    /// left as the start set it, as nothing runs on the stopped function.
    pub(super) fn stop(&mut self) -> Result<(), BlockError> {
        self.io.write(RCTL, self.io.read(RCTL) & !RCTL_EN);
        self.io.write(TCTL, self.io.read(TCTL) & !TCTL_EN);
        self.io.read(STATUS);
        self.clock.delay(10_000)?;
        self.disable_master()?;
        self.reset_mac()
    }

    /// igb_release_hw_control: hand the controller back to manageability
    /// firmware once the driver no longer owns it.
    pub(super) fn release_control(&self) {
        self.io
            .write(CTRL_EXT, self.io.read(CTRL_EXT) & !CTRL_EXT_DRIVER);
    }

    /// Mask interrupts, stop both engines and wait for the bus master to
    /// drain (igb_disable_pcie_master).
    fn disable_master(&self) -> Result<(), BlockError> {
        self.io.write(IMC, u32::MAX);
        self.io.write(EIMC, u32::MAX);
        self.io.write(GPIE, 0);
        self.io.write(RCTL, 0);
        self.io.write(TCTL, TCTL_PSP);
        self.io
            .write(CTRL, self.io.read(CTRL) | CTRL_MASTER_DISABLE);
        if !self
            .clock
            .wait(160_000, || self.io.read(STATUS) & STATUS_MASTER == 0)
        {
            return Err(BlockError::Timeout);
        }
        Ok(())
    }

    /// The function's MAC reset and what igb_reset clears after it.
    fn reset_mac(&mut self) -> Result<(), BlockError> {
        self.io.read(STATUS);
        self.clock.delay(10_000)?;
        // Reset this function, not DEV_RST: other copper ports are separate
        // PCI functions and may already have their own Stela driver.
        self.io.write(CTRL, self.io.read(CTRL) | CTRL_RST);
        if !self
            .clock
            .wait(20_000, || self.io.read(CTRL) & CTRL_RST == 0)
        {
            return Err(BlockError::Timeout);
        }
        self.warnings.nvm_autoload_timeout = !self
            .clock
            .wait(20_000, || self.io.read(EECD) & EECD_AUTO_RD != 0);
        if !self.chip.old_reset() {
            self.io.write(STATUS, 1 << 20);
        }
        self.io.write(IMC, u32::MAX);
        self.io.write(EIMC, u32::MAX);
        self.io.write(GPIE, 0);
        self.io.read(ICR);
        self.io.read(EICR);
        for queue in 0..self.chip.queues() {
            self.io.write(queue_register(RXDCTL, queue), 0);
            self.io.write(queue_register(TXDCTL, queue), 0);
        }
        if !self.clock.wait(20_000, || {
            (0..self.chip.queues()).all(|queue| {
                (self.io.read(queue_register(RXDCTL, queue))
                    | self.io.read(queue_register(TXDCTL, queue)))
                    & QUEUE_ENABLE
                    == 0
            })
        }) {
            return Err(BlockError::Timeout);
        }
        // igb_reset: wake-up control cleared after the MAC reset, so a wake
        // configuration a previous OS armed (APME, PME_EN) does not stay.
        self.io.write(WUC, 0);
        Ok(())
    }

    fn completion_timeout(
        &self,
        config: &mut impl ConfigSpace,
        capabilities: PciCapabilities,
    ) -> Result<(), BlockError> {
        let mut control = self.io.read(GCR);
        if control & GCR_COMPLETION_MASK == 0 {
            if control & GCR_V2 == 0 {
                control |= GCR_COMPLETION_10MS;
            } else {
                let capability = capabilities.pcie.ok_or(BlockError::Unsupported(
                    "igb completion timeout needs PCIe capability",
                ))?;
                if config.read16(capability + 2)? & 0xf < 2 {
                    return Err(BlockError::Unsupported(
                        "igb requires PCIe Device Control 2",
                    ));
                }
                let offset = capability + 0x28;
                let value = config.read16(offset)?;
                config.write16(offset, value | 5)?; // 16–55 ms
            }
        }
        self.io.write(GCR, control & !GCR_RESEND);
        Ok(())
    }

    fn put_hardware_semaphore(&self) {
        self.io.write(SWSM, self.io.read(SWSM) & !3);
    }

    fn hardware_semaphore(&mut self) -> Result<(), BlockError> {
        if !self.clock.wait(200_000, || self.io.read(SWSM) & 1 == 0) {
            if !self.clear_semaphore_once {
                return Err(BlockError::Timeout);
            }
            // Linux I210/i211 permits one recovery of a stale SMBI latch.
            self.clear_semaphore_once = false;
            self.put_hardware_semaphore();
            if !self.clock.wait(200_000, || self.io.read(SWSM) & 1 == 0) {
                return Err(BlockError::Timeout);
            }
        }
        if self.clock.wait(200_000, || {
            self.io.write(SWSM, self.io.read(SWSM) | 2);
            self.io.read(SWSM) & 2 != 0
        }) {
            Ok(())
        } else {
            self.put_hardware_semaphore();
            Err(BlockError::Timeout)
        }
    }

    fn acquire(&mut self, mask: u32) -> Result<(), BlockError> {
        for _ in 0..200 {
            self.hardware_semaphore()?;
            let value = self.io.read(SW_FW_SYNC);
            if value & (mask | mask << 16) == 0 {
                self.io.write(SW_FW_SYNC, value | mask);
                let acquired = self.io.read(SW_FW_SYNC) & mask == mask;
                self.put_hardware_semaphore();
                return if acquired {
                    Ok(())
                } else {
                    Err(BlockError::Device { status: value })
                };
            }
            self.put_hardware_semaphore();
            self.clock.delay(5_000)?;
        }
        Err(BlockError::Timeout)
    }

    fn release(&mut self, mask: u32) -> Result<(), BlockError> {
        self.hardware_semaphore()?;
        self.io.write(SW_FW_SYNC, self.io.read(SW_FW_SYNC) & !mask);
        let value = self.io.read(SW_FW_SYNC);
        self.put_hardware_semaphore();
        if value & mask == 0 {
            Ok(())
        } else {
            Err(BlockError::Device { status: value })
        }
    }

    pub(super) fn synchronized<V>(
        &mut self,
        mask: u32,
        operation: impl FnOnce(&mut Self) -> Result<V, BlockError>,
    ) -> Result<V, BlockError> {
        self.acquire(mask)?;
        let result = operation(self);
        let release = self.release(mask);
        match result {
            Ok(value) => release.map(|()| value),
            Err(error) => Err(error),
        }
    }

    pub(super) fn phy_mask(&self) -> u32 {
        match self.port {
            0 => 2,
            1 => 4,
            2 => 0x20,
            _ => 0x40,
        }
    }

    pub(super) fn phy_configuration(&mut self) {
        let register = if self.chip.modern() {
            EEMNGCTL_I210
        } else {
            EEMNGCTL
        };
        let mask = 1 << (18 + if self.chip.modern() { 0 } else { self.port });
        // Linux treats missing CFG_DONE as a diagnostic. It is not a
        // substitute for checking NVM contents and PHY transactions.
        self.warnings.phy_configuration_timeout |= !self
            .clock
            .wait(100_000, || self.io.read(register) & mask != 0);
    }

    fn configure_mac(&self, mac: Mac) {
        let control = self.io.read(CTRL);
        self.io.write(
            CTRL,
            (control | CTRL_SLU)
                & !(CTRL_MASTER_DISABLE
                    | CTRL_FRCSPD
                    | CTRL_FRCDPX
                    | CTRL_RFCE
                    | CTRL_TFCE
                    | CTRL_VME),
        );
        self.io
            .write(CTRL_EXT, self.io.read(CTRL_EXT) | CTRL_EXT_DRIVER);
        self.io.write(MRQC, 0);
        if self.chip != Chip::I82575 {
            self.io.write(VT_CTL, 0);
        }
        self.io.write(RXCSUM, 0);
        self.io.write(RFCTL, RFCTL_IPV6_EX_DIS);
        self.io.write(RLPML, (MAX_FRAME + 4) as u32);
        self.io.write(TIPG, 8 | (8 << 10) | (6 << 20));
        if self.chip.modern() {
            self.io.write(RXPBS, 0xa2);
            self.io.write(TXPBS, 0x0400_0014);
        }
        for index in 0..self.chip.receive_addresses() {
            let (low, high) = if index == 0 {
                let [a, b, c, d, e, f] = mac.0;
                (
                    u32::from_le_bytes([a, b, c, d]),
                    u32::from(u16::from_le_bytes([e, f])) | 1 << 31,
                )
            } else {
                (0, 0)
            };
            self.io.write(receive_address(index), low);
            self.io.read(STATUS);
            self.io.write(receive_address(index) + 4, high);
            self.io.read(STATUS);
        }
        for index in 0..128 {
            self.io.write(MTA + 4 * index, 0);
            if self.chip != Chip::I82575 {
                self.io.write(UTA + 4 * index, 0);
            }
            // VLAN filtering is disabled. I350's repeated-VFTA-write erratum
            // is irrelevant to this mode; no VLAN-filter support is claimed.
            self.io.write(VFTA + 4 * index, 0);
        }
        if self.chip != Chip::I82575 {
            self.io.write(
                VMOLR,
                (MAX_FRAME + 4) as u32 | (1 << 16) | (1 << 24) | (1 << 27) | (1 << 28) | (1 << 31),
            );
        }
        if matches!(self.chip, Chip::I350 | Chip::I210 | Chip::I211) {
            self.io.write(0x0e38, self.io.read(0x0e38) & !0x0c); // IPCNFG EEE advertisement off
            self.io.write(0x0e30, self.io.read(0x0e30) & !(7 << 16)); // EEER TX/RX LPI off
        }
    }

    fn flush_82575_receive_fifo(&self) -> Result<(), BlockError> {
        if self.chip != Chip::I82575 || self.io.read(MANC) & MANC_TCO == 0 {
            return Ok(());
        }
        // reset() already disabled and acknowledged every RX queue. Flush
        // the manageability FIFO with no DMA buffers exposed, rejecting all
        // packets for two milliseconds, then restore the global RX state.
        let filter = self.io.read(RFCTL);
        let maximum = self.io.read(RLPML);
        let control = self.io.read(RCTL);
        self.io.write(RFCTL, filter & !RFCTL_LEF);
        self.io.write(RLPML, 0);
        self.io.write(RCTL, RCTL_LPE);
        self.io.write(RCTL, RCTL_LPE | RCTL_EN);
        self.io.read(STATUS);
        self.clock.delay(2_000)?;
        self.io.write(RCTL, control);
        self.io.write(RLPML, maximum);
        self.io.write(RFCTL, filter);
        Ok(())
    }
}
