// SPDX-License-Identifier: BSD-3-Clause AND GPL-2.0-only
// Copyright (c) 2001-2020, Intel Corporation
// Linux e1000e adaptations: Copyright(c) 1999 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must keep the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 3. Neither the name of Intel Corporation nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

//! Intel 82574L (`8086:10d3`), one polled Ethernet queue with legacy
//! descriptors, no checksum/segmentation/VLAN offloads and no interrupts.
//!
//! The MAC/MDIO reset and hardware errata sequence is adapted from Intel's
//! BSD-licensed shared code, FreeBSD `sys/dev/e1000/e1000_82571.c`,
//! `e1000_phy.c`, `e1000_regs.h` and `e1000_defines.h`:
//! <https://github.com/freebsd/freebsd-src/tree/c6d7a2478c9eeb38ed1284e4ee1ff64c75ca8b09/sys/dev/e1000>.
//! Subsequent Linux `e1000e` adaptations follow commit
//! `a804c5742bff224d4cb4d25dd383554d598be32b`, `82571.c`, `phy.c`,
//! `netdev.c`, `defines.h` and `regs.h` under
//! <https://github.com/torvalds/linux/tree/a804c5742bff224d4cb4d25dd383554d598be32b/drivers/net/ethernet/intel/e1000e>.
//! These portions are GPL-2.0-only; see `LICENSES/GPL-2.0-only.txt`.
//! The descriptor datapath and Stela integration are independent Rust code.
//! This is not a match for the I217/I218/I219 integrated PHYs.
//!
//! Drop stops the controller and hands it back to manageability firmware;
//! DMA allocations live until reboot when the stop is not observed,
//! including after a transmit timeout;
//! a descriptor is never reused until the device writes its done bit.
pub mod pch;

use super::{
    HEADER, Link, LinkError, MAX_FRAME, MIN_FRAME, Mac, check_frame,
    ring::{DESCRIPTOR, DESCRIPTORS, Ring, write_transmit_frame},
};
use crate::{
    Handoff,
    block::BlockError,
    bus::{
        dma::{DmaAllocator, DmaBuffer},
        mmio::Mmio,
        pci::{self, ConfigSpace, Function},
    },
    registers,
};
use alloc::{format, rc::Rc, string::String, vec::Vec};
use core::{
    mem::ManuallyDrop,
    sync::atomic::{Ordering, fence},
    task::Poll,
};
use stela_driver_base::stepped::{Allowance, Stepped, block_on};

const VENDOR: u16 = 0x8086;
const DEVICE: u16 = 0x10d3;
const REGISTER_BYTES: u64 = 0x1_0000;
const CTRL: usize = 0x0000;
const STATUS: usize = 0x0008;
const EECD: usize = 0x0010;
const CTRL_EXT: usize = 0x0018;
/// Interrupt registers e1000_configure_msix and e1000_irq_enable program.
const ICS: usize = 0x00c8;
const IMS: usize = 0x00d0;
const EIAC: usize = 0x00dc;
const IVAR: usize = 0x00e4;
/// E1000_EITR_82574(0), vector 0's throttle.
const EITR0: usize = 0x00e8;
const IMS_LSC: u32 = 1 << 2;
const IMS_RXQ0: u32 = 1 << 20;
const IMS_OTHER: u32 = 1 << 24;
const IVAR_VALID: u32 = 0x8;
const CTRL_EXT_EIAME: u32 = 1 << 24;
const CTRL_EXT_IAME: u32 = 1 << 27;
const CTRL_EXT_PBA_CLR: u32 = 1 << 31;
const RFCTL_ACK_DIS: u32 = 1 << 12;
/// Linux's default 20000 interrupts a second, as 256 ns throttle units.
const THROTTLE: u32 = 1_000_000_000 / (20_000 * 256);
/// An MSI-X table entry's bytes.
const MSIX_ENTRY_BYTES: u64 = 16;
const MDIC: usize = 0x0020;
const ICR: usize = 0x00c0;
const IMC: usize = 0x00d8;
const RCTL: usize = 0x0100;
const TCTL: usize = 0x0400;
const TIPG: usize = 0x0410;
const EXTCNF_CTRL: usize = 0x0f00;
const POEMB: usize = 0x0f10;
const RDBAL: usize = 0x2800;
const RDBAH: usize = 0x2804;
const RDLEN: usize = 0x2808;
const RDH: usize = 0x2810;
const RDT: usize = 0x2818;
const RXDCTL: usize = 0x2828;
const TDBAL: usize = 0x3800;
const TDBAH: usize = 0x3804;
const TDLEN: usize = 0x3808;
const TDH: usize = 0x3810;
const TDT: usize = 0x3818;
const TXDCTL: usize = 0x3828;
const TARC: usize = 0x3840;
const RXCSUM: usize = 0x5000;
const RFCTL: usize = 0x5008;
const MTA: usize = 0x5200;
const RAL: usize = 0x5400;
const RAH: usize = 0x5404;
const GCR: usize = 0x5b00;
const GCR2: usize = 0x5b64;

const CTRL_MASTER_DISABLE: u32 = 1 << 2;
const CTRL_SLU: u32 = 1 << 6;
const CTRL_FRCSPD: u32 = 1 << 11;
const CTRL_FRCDPX: u32 = 1 << 12;
const CTRL_RST: u32 = 1 << 26;
const CTRL_RFCE: u32 = 1 << 27;
const CTRL_TFCE: u32 = 1 << 28;
const CTRL_RESERVED_29: u32 = 1 << 29;
const CTRL_VME: u32 = 1 << 30;
const STATUS_LU: u32 = 1 << 1;
const STATUS_MASTER: u32 = 1 << 19;
const EECD_AUTO_RD: u32 = 1 << 9;
const MDIO_OWN: u32 = 1 << 5;
const CTRL_EXT_DRIVER: u32 = 1 << 28;
const CTRL_EXT_LINK_MASK: u32 = 3 << 22;
const CTRL_EXT_LINK_82574: u32 = 1 << 22;
const POEMB_LPLU: u32 = (1 << 1) | (1 << 2);
const RCTL_EN: u32 = 1 << 1;
const RCTL_MPE: u32 = 1 << 4;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_SECRC: u32 = 1 << 26;
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;
const TCTL_COLLISIONS: u32 = (15 << 4) | (63 << 12);
const TCTL_RTLC: u32 = 1 << 24;
const TARC_ENABLE: u32 = 1 << 10;
const TARC_REQUIRED: u32 = 1 << 26;
const TARC_RESERVED: u32 = 0xf << 27;
const TXDCTL_POLICY: u32 = (1 << 24) | (1 << 22) | (1 << 16) | (1 << 8) | 31;
const RFCTL_EXTEN: u32 = 1 << 15;
const RAH_VALID: u32 = 1 << 31;
const GCR_REQUIRED: u32 = 1 << 22;
const GCR_L1_WITHOUT_L0S: u32 = 1 << 27;
const GCR2_ERRATA: u32 = 1;

const MDIC_WRITE: u32 = 1 << 26;
const MDIC_READ: u32 = 1 << 27;
const MDIC_READY: u32 = 1 << 28;
const MDIC_ERROR: u32 = 1 << 30;
const MDIC_PHY: u32 = 1 << 21;
const MDIC_REGISTER: u32 = 0x1f << 16;
const PHY_CONTROL: u16 = 0;
const PHY_ID1: u16 = 2;
const PHY_ID2: u16 = 3;
const PHY_ADVERTISE: u16 = 4;
const PHY_GIGABIT: u16 = 9;
const PHY_SPECIFIC: u16 = 16;
const PHY_PAGE: u16 = 22;
const PHY_BIAS1: u16 = 29;
const PHY_BIAS2: u16 = 30;
/// 1000BASE-T Status (IEEE 802.3 clause 40.5.1.1) and the BM PHY's receive
/// error counter (Linux `E1000_RECEIVE_ERROR_COUNTER`).
const PHY_GIGABIT_STATUS: u16 = 10;
const PHY_RECEIVE_ERRORS: u16 = 21;
const PHY_IDLE_ERRORS: u16 = 0xff;
/// Advertise 10/100 half and full duplex, IEEE 802.3 selector, no pause.
const PHY_ADVERTISE_10_100: u16 = 0x01e1;
/// 1000BASE-T Control: the half/full advertisement and master/slave bits,
/// of which only 1000 full duplex is advertised.
const PHY_GIGABIT_FIELDS: u16 = 0x1f00;
const PHY_GIGABIT_FULL: u16 = 1 << 9;
/// BM PHY bias settings Linux `e1000_copper_link_setup_m88` applies to
/// revision 2 parts.
const PHY_BIAS1_VALUE: u16 = 3;
const PHY_BIAS2_VALUE: u16 = 0;
const PHY_RESET: u16 = 1 << 15;
const PHY_LOOPBACK: u16 = 1 << 14;
const PHY_AUTONEG: u16 = 1 << 12;
const PHY_POWERDOWN: u16 = 1 << 11;
const PHY_ISOLATE: u16 = 1 << 10;
const PHY_RESTART: u16 = 1 << 9;
const PHY_DOWNSHIFT: u16 = 1 << 11;
const PHY_AUTO_MDIX: u16 = 3 << 5;
const PHY_POLARITY_DISABLE: u16 = 1 << 1;
const PHY_BM_REV2: u32 = 0x0141_0cb1;

const RX_DONE: u8 = 1;
const RX_EOP: u8 = 1 << 1;
// Checksum errors are irrelevant because checksum offload is disabled.
const RX_FRAME_ERRORS: u8 = 0x97;
const TX_DONE: u8 = 1;
const TX_EOP: u32 = 1 << 24;
const TX_IFCS: u32 = 1 << 25;
const TX_REPORT: u32 = 1 << 27;
const MASTER_WAIT_US: u64 = 160_000;
const RESET_WAIT_US: u64 = 20_000;
const OWNERSHIP_WAIT_US: u64 = 200_000;
/// The bounds a stop at drop waits within: it can run inside a processor's
/// exit, which must end well inside half a second. Linux's own: 800 master
/// polls 100 us apart, and MDIO ownership in ten 2 ms tries.
const STOP_WAITS: Waits = Waits {
    master_us: 80_000,
    ownership_us: 20_000,
    phy_configuration: false,
};
/// After receive and transmit are disabled, for frames in flight (Linux
/// `e1000e_down`).
const STOP_SETTLE_US: u64 = 10_000;
const MDIC_WAIT_US: u64 = 20_000;
/// A PHY reset's completion, polled every millisecond for at least this.
const PHY_WAIT_US: u64 = 500_000;
const PHY_POLL_US: u64 = 1_000;
/// Each link poll's share of waiting for a PHY check or reset under way:
/// up to this, plus the one piece that crosses it.
const STEP_US: u64 = 40_000;
/// The longest piece of one bounded wait in stepped work.
const PIECE_US: u64 = 10_000;
/// Linux runs the e1000e watchdog every two seconds.
const WATCHDOG_US: u64 = 2_000_000;
/// Copper inter-packet gaps: IPGT 8, IPGR1 8, IPGR2 6.
const TIPG_COPPER: u32 = 8 | 8 << 10 | 6 << 20;
/// RXDCTL prefetch, host and write-back thresholds with byte granularity.
const RXDCTL_POLICY: u32 = 1 << 16 | 4 << 8 | 8;
const RECEIVE_ADDRESSES: usize = 16;
const MULTICAST_HASH_WORDS: usize = 128;
/// After the MAC drains its bus master requests (Linux `e1000_reset_hw_82571`).
const MASTER_SETTLE_US: u64 = 10_000;
/// NVM auto-read starts the PHY's configuration; MDIO stays idle meanwhile.
const PHY_CONFIGURATION_US: u64 = 25_000;

pub fn matches<C: ConfigSpace>(function: &Function<C>) -> bool {
    matches_identity(&function.identity())
}

/// Candidate selection from copied identity DATA; owned attachment still
/// revalidates configuration and platform requirements.
pub fn matches_identity(function: &crate::bus::pci::Identity) -> bool {
    function.vendor == VENDOR && function.device == DEVICE && function.class == [2, 0, 0]
}

/// The reset and MDIO state machines use the same register interface in
/// production and in fault-injection tests.
trait Registers {
    fn read(&self, offset: usize) -> u32;
    fn write(&self, offset: usize, value: u32);
}

impl Registers for Mmio {
    fn read(&self, offset: usize) -> u32 {
        self.read32(offset)
    }

    fn write(&self, offset: usize, value: u32) {
        self.write32(offset, value);
    }
}

trait Timer {
    fn delay(&self, microseconds: u64) -> Result<(), BlockError>;
    fn wait(&self, microseconds: u64, ready: impl FnMut() -> bool) -> bool;
}

impl Timer for crate::timing::Timing {
    fn delay(&self, us: u64) -> Result<(), BlockError> {
        crate::timing::Timing::delay(self, us)
    }
    fn wait(&self, us: u64, ready: impl FnMut() -> bool) -> bool {
        crate::timing::Timing::wait(self, us, ready)
    }
}

/// How long a reset waits for the bus master and MDIO ownership, and
/// whether it waits for the PHY's configuration after the NVM load.
struct Waits {
    master_us: u64,
    ownership_us: u64,
    phy_configuration: bool,
}

/// What an attachment and a reinitialization wait.
const START_WAITS: Waits = Waits {
    master_us: MASTER_WAIT_US,
    ownership_us: OWNERSHIP_WAIT_US,
    phy_configuration: true,
};

/// The reset and PHY sequences over one register interface and clock. Given
/// a per-step wait share ([`Self::sliced`]), they run as stepped work: each
/// bounded wait goes in pieces of at most [`PIECE_US`], and a step ends once
/// its share is spent, keeping the same overall bounds.
struct Hardware<'a, R, T> {
    device: &'a R,
    clock: &'a T,
    slice: Option<&'a Allowance>,
}

impl<'a, R: Registers, T: Timer> Hardware<'a, R, T> {
    fn new(device: &'a R, clock: &'a T) -> Self {
        Self {
            device,
            clock,
            slice: None,
        }
    }

    fn sliced(self, slice: &'a Allowance) -> Self {
        Self {
            slice: Some(slice),
            ..self
        }
    }

    /// At least `us` microseconds, in pieces when stepped.
    async fn delay(&self, us: u64) -> Result<(), BlockError> {
        let Some(slice) = self.slice else {
            return self.clock.delay(us);
        };
        let mut left = us;
        while left != 0 {
            let piece = left.min(PIECE_US);
            self.clock.delay(piece)?;
            slice.spent(piece).await;
            left -= piece;
        }
        Ok(())
    }

    /// [`Timer::wait`], in pieces when stepped.
    async fn wait(&self, us: u64, mut ready: impl FnMut() -> bool) -> bool {
        let Some(slice) = self.slice else {
            return self.clock.wait(us, ready);
        };
        let mut left = us;
        loop {
            let piece = left.min(PIECE_US);
            if self.clock.wait(piece, &mut ready) {
                return true;
            }
            left -= piece;
            if left == 0 {
                return false;
            }
            slice.spent(piece).await;
        }
    }

    async fn ownership(&self, wait_us: u64) -> Result<(), BlockError> {
        let device = self.device;
        if self
            .wait(wait_us, || {
                device.write(EXTCNF_CTRL, device.read(EXTCNF_CTRL) | MDIO_OWN);
                device.read(EXTCNF_CTRL) & MDIO_OWN != 0
            })
            .await
        {
            Ok(())
        } else {
            release(device);
            Err(BlockError::Timeout)
        }
    }

    async fn reset(&self, waits: &Waits) -> Result<(), BlockError> {
        let device = self.device;
        device.write(IMC, u32::MAX);
        device.write(RCTL, 0);
        device.write(TCTL, device.read(TCTL) & !TCTL_EN);
        device.write(CTRL, device.read(CTRL) | CTRL_MASTER_DISABLE);
        if !self
            .wait(waits.master_us, || device.read(STATUS) & STATUS_MASTER == 0)
            .await
        {
            return Err(BlockError::Timeout);
        }
        device.read(STATUS); // flush posted PCIe writes before the settle time
        self.delay(MASTER_SETTLE_US).await?;
        self.ownership(waits.ownership_us).await?;
        device.write(CTRL, device.read(CTRL) | CTRL_RST);
        let reset_done = self
            .wait(RESET_WAIT_US, || device.read(CTRL) & CTRL_RST == 0)
            .await;
        release(device);
        if !reset_done
            || !self
                .wait(RESET_WAIT_US, || device.read(EECD) & EECD_AUTO_RD != 0)
                .await
        {
            return Err(BlockError::Timeout);
        }
        if waits.phy_configuration {
            self.delay(PHY_CONFIGURATION_US).await?;
        }
        device.write(IMC, u32::MAX);
        device.read(ICR);
        Ok(())
    }

    /// Linux `e1000e_down`'s register sequence: receive, then transmit, off,
    /// 10 ms for frames in flight, then `e1000_reset_hw_82571`'s bus master
    /// drain and MAC reset. Only a completed reset proves the controller
    /// writes no ring. Every wait fits a processor's exit ([`STOP_WAITS`]);
    /// the PHY is not waited for, as nothing configures it after a stop.
    async fn stop(&self) -> Result<(), BlockError> {
        let device = self.device;
        device.write(RCTL, device.read(RCTL) & !RCTL_EN);
        device.write(TCTL, device.read(TCTL) & !TCTL_EN);
        device.read(STATUS);
        self.delay(STOP_SETTLE_US).await?;
        self.reset(&STOP_WAITS).await
    }

    async fn mdic(&self, register: u16, data: Option<u16>) -> Result<u16, BlockError> {
        let device = self.device;
        let command = MDIC_PHY
            | (u32::from(register) << 16)
            | data.map_or(MDIC_READ, |data| MDIC_WRITE | u32::from(data));
        device.write(MDIC, command);
        if !self
            .wait(MDIC_WAIT_US, || device.read(MDIC) & MDIC_READY != 0)
            .await
        {
            return Err(BlockError::Timeout);
        }
        let result = device.read(MDIC);
        if result & MDIC_ERROR != 0 || result & MDIC_REGISTER != command & MDIC_REGISTER {
            return Err(BlockError::Device { status: result });
        }
        Ok(result as u16)
    }

    async fn reset_phy(&self) -> Result<(), BlockError> {
        let control = self.mdic(PHY_CONTROL, None).await?;
        self.mdic(PHY_CONTROL, Some(control | PHY_RESET)).await?;
        // Each poll is an MDIO read with its own bounded wait, so the polls
        // are counted delays rather than one wait.
        let mut waited = 0;
        loop {
            match self.mdic(PHY_CONTROL, None).await {
                Ok(value) if value & PHY_RESET != 0 => {}
                last => return last.map(|_| ()),
            }
            if waited >= PHY_WAIT_US {
                return Err(BlockError::Timeout);
            }
            self.delay(PHY_POLL_US).await?;
            waited += PHY_POLL_US;
        }
    }

    async fn configure_phy(&self) -> Result<(), BlockError> {
        self.ownership(OWNERSHIP_WAIT_US).await?;
        let result = self.configure_owned_phy().await;
        release(self.device);
        result
    }

    async fn configure_owned_phy(&self) -> Result<(), BlockError> {
        self.mdic(PHY_PAGE, Some(0)).await?;
        let id = u32::from(self.mdic(PHY_ID1, None).await?) << 16
            | u32::from(self.mdic(PHY_ID2, None).await?);
        if id != PHY_BM_REV2 {
            return Err(BlockError::Unsupported("82574L with an unknown PHY"));
        }
        let mut specific = self.mdic(PHY_SPECIFIC, None).await?;
        specific = (specific | PHY_AUTO_MDIX) & !PHY_POLARITY_DISABLE;
        self.mdic(PHY_SPECIFIC, Some(specific & !PHY_DOWNSHIFT))
            .await?;
        self.reset_phy().await?;
        self.mdic(PHY_SPECIFIC, Some(specific | PHY_DOWNSHIFT))
            .await?;
        self.mdic(PHY_BIAS1, Some(PHY_BIAS1_VALUE)).await?;
        self.mdic(PHY_BIAS2, Some(PHY_BIAS2_VALUE)).await?;
        self.reset_phy().await?;
        self.mdic(PHY_ADVERTISE, Some(PHY_ADVERTISE_10_100)).await?;
        let gigabit = self.mdic(PHY_GIGABIT, None).await?;
        self.mdic(
            PHY_GIGABIT,
            Some((gigabit & !PHY_GIGABIT_FIELDS) | PHY_GIGABIT_FULL),
        )
        .await?;
        let control = self.mdic(PHY_CONTROL, None).await?;
        self.mdic(
            PHY_CONTROL,
            Some(
                (control & !(PHY_RESET | PHY_LOOPBACK | PHY_POWERDOWN | PHY_ISOLATE))
                    | PHY_AUTONEG
                    | PHY_RESTART,
            ),
        )
        .await?;
        Ok(())
    }

    /// Whether the BM PHY has hung: its receive error counter and
    /// 1000BASE-T idle error count both saturated (Linux
    /// `e1000_check_phy_82574`). A failed MDIO read is not a hang.
    async fn phy_hung(&self) -> bool {
        if self.ownership(OWNERSHIP_WAIT_US).await.is_err() {
            return false;
        }
        let hung = self.mdic(PHY_RECEIVE_ERRORS, None).await == Ok(u16::MAX)
            && self
                .mdic(PHY_GIGABIT_STATUS, None)
                .await
                .is_ok_and(|status| status & PHY_IDLE_ERRORS == PHY_IDLE_ERRORS);
        release(self.device);
        hung
    }

    /// Linux's reset task's hardware part: the MAC reset, then the PHY.
    async fn reinitialize(&self) -> Result<(), BlockError> {
        self.reset(&START_WAITS).await?;
        self.configure_phy().await
    }
}

fn release(device: &impl Registers) {
    device.write(EXTCNF_CTRL, device.read(EXTCNF_CTRL) & !MDIO_OWN);
}

fn reset(device: &impl Registers, clock: &impl Timer) -> Result<(), BlockError> {
    block_on(Hardware::new(device, clock).reset(&START_WAITS))
}

/// [`Hardware::stop`], run to completion.
fn stop(device: &impl Registers, clock: &impl Timer) -> Result<(), BlockError> {
    block_on(Hardware::new(device, clock).stop())
}

/// `e1000e_release_hw_control`: hand the controller back to manageability
/// firmware once the driver no longer owns it.
fn release_control(device: &impl Registers) {
    device.write(CTRL_EXT, device.read(CTRL_EXT) & !CTRL_EXT_DRIVER);
}

fn configure_phy(device: &impl Registers, clock: &impl Timer) -> Result<(), BlockError> {
    block_on(Hardware::new(device, clock).configure_phy())
}

fn station(low: u32, high: u32) -> Option<Mac> {
    let [a, b, c, d] = low.to_le_bytes();
    let [e, f, _, _] = high.to_le_bytes();
    let mac = Mac([a, b, c, d, e, f]);
    (high & RAH_VALID != 0 && mac.0 != [0; 6] && !mac.is_multicast()).then_some(mac)
}

#[cfg(test)]
fn phy_hung(device: &impl Registers, clock: &impl Timer) -> bool {
    block_on(Hardware::new(device, clock).phy_hung())
}

/// The 82574L owns these buffers until reboot. Polling never waits for a
/// cable to be connected; [`Link::carrier`] reports autonegotiation's result.
pub struct E1000e {
    device: Mmio,
    receive: ManuallyDrop<Ring>,
    transmit: ManuallyDrop<Ring>,
    dropping_receive: bool,
    mac: Mac,
    clock: crate::timing::Timing,
    timing_failure: Option<BlockError>,
    /// When the next watchdog check is due, and how many checks in a row
    /// found the PHY hung.
    watchdog_at: u64,
    phy_hangs: u8,
    /// Register reads return all ones: the function is gone.
    faulted: bool,
    pub location: String,
    /// Whether MSI-X vector 0 sends the handoff's completion signal.
    signalled: bool,
    /// The watchdog's PHY check or reset under way.
    work: Option<Work>,
}

/// What a watchdog job found.
enum Outcome {
    Hung(bool),
    Reinitialized(Result<(), BlockError>),
}

/// Linux's watchdog PHY check or reset task, run a step per link poll so no
/// poll holds the processor for its waits (MDIO ownership, the PHY resets).
struct Work {
    task: Stepped<'static, Outcome>,
    slice: Rc<Allowance>,
    /// A reset: the rings are untouched and the carrier down until it ends.
    resetting: bool,
}

impl E1000e {
    /// Take an 82574L after ExitBootServices, including the required ASPM
    /// workaround on the endpoint and its immediate upstream PCIe bridge.
    ///
    /// # Safety
    ///
    /// The caller must own the controller and PCI configuration access in
    /// its segment exclusively. `handoff` must describe the machine's
    /// mapped ECAM/MMIO and DMA ranges. No firmware or other driver may
    /// access these resources during initialization.
    pub unsafe fn new(
        function: &mut Function,
        handoff: &Handoff,
        dma: &mut dyn DmaAllocator,
        minimum: alloc::rc::Rc<dyn crate::bus::pci::power::Timer>,
    ) -> Result<Self, BlockError> {
        let clock = crate::timing::Timing::checked(handoff.clock, minimum)?;
        if !matches(function) {
            return Err(BlockError::Unsupported("not an Intel 82574L"));
        }
        // SAFETY: the constructor's caller owns segment configuration and
        // the mapped ECAM handoff. Do this before enabling device decoding.
        unsafe { pci::disable_aspm_link(function, handoff)? };
        function.power_up(clock.minimum())?;
        let bars = function.bars()?;
        let device = registers(handoff, bars[0], 0, REGISTER_BYTES)?;
        function.enable_polled()?;
        let signalled = match (handoff.completion, function.interrupts()?.msix) {
            (Some(message), Some(msix)) => {
                let table = registers(
                    handoff,
                    bars[usize::from(msix.table_bar)],
                    u64::from(msix.table_offset),
                    MSIX_ENTRY_BYTES,
                )?;
                function.enable_msix(msix, || {
                    table.write32(0, message.address as u32);
                    table.write32(4, (message.address >> 32) as u32);
                    table.write32(8, message.data);
                    table.write32(12, 0);
                    Ok(())
                })?;
                true
            }
            _ => false,
        };
        reset(&device, &clock)?;
        let mac = station(device.read32(RAL), device.read32(RAH)).ok_or(
            BlockError::Unsupported("82574L without a valid NVM MAC address"),
        )?;
        configure_phy(&device, &clock)?;
        let mut net = Self {
            device,
            receive: ManuallyDrop::new(Ring::new(dma)?),
            transmit: ManuallyDrop::new(Ring::new(dma)?),
            dropping_receive: false,
            mac,
            clock,
            watchdog_at: 0,
            phy_hangs: 0,
            faulted: false,
            timing_failure: None,
            location: format!("{} Intel 82574L", function.address),
            signalled,
            work: None,
        };
        net.start();
        Ok(net)
    }

    /// Linux's watchdog, driven by link polls: discard transmit work the
    /// link took down with it, and reinitialize after two PHY hang reports
    /// in a row. Returns the carrier, down while a reset runs.
    fn watchdog(&mut self) -> Result<bool, LinkError> {
        if let Some(error) = &self.timing_failure {
            return Err(LinkError::Pci(error.clone()));
        }
        if let Some(outcome) = self.advance()
            && self.finish(outcome)?
        {
            return Ok(false);
        }
        if self.resetting() {
            return Ok(false);
        }
        let status = self.device.read32(STATUS);
        self.faulted |= status == u32::MAX;
        if self.faulted {
            return Err(LinkError::Adapter(format!(
                "{} lost register access; reinitialization required",
                self.location
            )));
        }
        let carrier = status & STATUS_LU != 0;
        if !carrier && self.transmit.pending() {
            self.flush_transmit();
        }
        let now = self.clock.now_us();
        if self.work.is_none() && now >= self.watchdog_at {
            self.watchdog_at = now.saturating_add(WATCHDOG_US);
            if let Some(outcome) = self.begin(false)
                && self.finish(outcome)?
            {
                return Ok(false);
            }
        }
        Ok(carrier)
    }

    /// Start a watchdog job and take its first step: its outcome if that
    /// completed it, otherwise `None` with the rest left for later polls.
    fn begin(&mut self, reinitialize: bool) -> Option<Outcome> {
        let (device, clock) = (self.device, self.clock.clone());
        let slice = Rc::new(Allowance::new(STEP_US));
        let shared = slice.clone();
        let mut task = Stepped::new(async move {
            let hardware = Hardware::new(&device, &clock).sliced(&shared);
            match reinitialize {
                true => Outcome::Reinitialized(hardware.reinitialize().await),
                false => Outcome::Hung(hardware.phy_hung().await),
            }
        });
        match task.step() {
            Poll::Ready(outcome) => Some(outcome),
            Poll::Pending => {
                self.work = Some(Work {
                    task,
                    slice,
                    resetting: reinitialize,
                });
                None
            }
        }
    }

    /// One step of the job under way, if any: its outcome once it ends.
    fn advance(&mut self) -> Option<Outcome> {
        let work = self.work.as_mut()?;
        work.slice.refill();
        let Poll::Ready(outcome) = work.task.step() else {
            return None;
        };
        self.work = None;
        Some(outcome)
    }

    fn resetting(&self) -> bool {
        self.work.as_ref().is_some_and(|work| work.resetting)
    }

    /// Act on a finished job: count PHY hang reports, starting a reset on
    /// the second in a row, or bring the rings back after a reset. Whether
    /// a reset started or ended.
    fn finish(&mut self, outcome: Outcome) -> Result<bool, LinkError> {
        match outcome {
            Outcome::Hung(hung) => {
                self.phy_hangs = if hung { self.phy_hangs + 1 } else { 0 };
                if self.phy_hangs > 1 {
                    self.phy_hangs = 0;
                    self.reinitialize()?;
                    return Ok(true);
                }
                Ok(false)
            }
            Outcome::Reinitialized(result) => self.reinitialized(result).map(|()| true),
        }
    }

    /// Stop transmit, discard every queued descriptor and start again
    /// empty, as Linux's reset does for work the link can no longer carry.
    fn flush_transmit(&mut self) {
        let control = self.device.read32(TCTL);
        self.device.write32(TCTL, control & !TCTL_EN);
        self.device.write32(TDH, 0);
        self.device.write32(TDT, 0);
        self.transmit.reset();
        self.device.write32(TCTL, control);
    }

    /// Linux's reset task: reset the MAC and PHY, then bring the rings
    /// back. It runs in steps ([`Work`]): this call takes the first.
    fn reinitialize(&mut self) -> Result<(), LinkError> {
        if let Some(error) = &self.timing_failure {
            return Err(LinkError::Pci(error.clone()));
        }
        match self.begin(true) {
            Some(outcome) => self.finish(outcome).map(|_| ()),
            None => Ok(()),
        }
    }

    /// The rings back after a completed reset, or its failure reported.
    fn reinitialized(&mut self, prepared: Result<(), BlockError>) -> Result<(), LinkError> {
        let failed = |error: BlockError| {
            if matches!(error, BlockError::PciPower(_)) {
                return LinkError::Pci(error);
            }
            LinkError::Adapter(format!(
                "{} reinitialization failed: {error}",
                self.location
            ))
        };
        if let Err(error) = prepared {
            if matches!(error, BlockError::PciPower(_)) {
                self.timing_failure = Some(error.clone());
                self.faulted = true;
                return Err(LinkError::Pci(error));
            }
            return Err(failed(error));
        }
        self.receive.reset();
        self.transmit.reset();
        self.dropping_receive = false;
        self.start();
        Ok(())
    }

    fn start(&mut self) {
        let device = &self.device;
        let control = device.read32(CTRL);
        device.write32(
            CTRL,
            (control | CTRL_SLU)
                & !(CTRL_MASTER_DISABLE
                    | CTRL_FRCSPD
                    | CTRL_FRCDPX
                    | CTRL_RFCE
                    | CTRL_TFCE
                    | CTRL_RESERVED_29
                    | CTRL_VME),
        );
        device.write32(
            CTRL_EXT,
            (device.read32(CTRL_EXT) & !CTRL_EXT_LINK_MASK) | CTRL_EXT_LINK_82574 | CTRL_EXT_DRIVER,
        );
        device.write32(POEMB, device.read32(POEMB) & !POEMB_LPLU);
        // Linux's 82574 setup enables L1 activation without L0s receive.
        device.write32(GCR, device.read32(GCR) | GCR_REQUIRED | GCR_L1_WITHOUT_L0S);
        device.write32(GCR2, device.read32(GCR2) | GCR2_ERRATA);
        // Other receive addresses and multicast hashes must not keep UNDI state.
        for entry in 1..RECEIVE_ADDRESSES {
            device.write32(RAL + entry * 8, 0);
            device.write32(RAH + entry * 8, 0);
        }
        for entry in 0..MULTICAST_HASH_WORDS {
            device.write32(MTA + entry * 4, 0);
        }
        device.write32(RFCTL, device.read32(RFCTL) & !RFCTL_EXTEN);
        device.write32(RXCSUM, 0);
        let write = |offset, value| device.write32(offset, value);
        self.receive.program(write, RDBAL, RDBAH, RDLEN);
        self.transmit.program(write, TDBAL, TDBAH, TDLEN);
        device.write32(RDH, 0);
        device.write32(RDT, 0);
        device.write32(TDH, 0);
        device.write32(TDT, 0);
        device.write32(RXDCTL, RXDCTL_POLICY);
        device.write32(TXDCTL, TXDCTL_POLICY);
        // 82574 erratum: both queues must use the same write-back policy.
        device.write32(TXDCTL + 0x100, TXDCTL_POLICY);
        device.write32(
            TARC,
            (device.read32(TARC) & !TARC_RESERVED) | TARC_REQUIRED | TARC_ENABLE,
        );
        device.write32(TIPG, TIPG_COPPER);
        for index in 0..DESCRIPTORS {
            self.offer_receive(index);
        }
        fence(Ordering::SeqCst);
        self.device.write32(RDT, (DESCRIPTORS - 1) as u32);
        self.device
            .write32(RCTL, RCTL_EN | RCTL_MPE | RCTL_BAM | RCTL_SECRC);
        self.device
            .write32(TCTL, TCTL_EN | TCTL_PSP | TCTL_COLLISIONS | TCTL_RTLC);
        if self.signalled {
            self.arm_interrupts();
        }
        self.device.read32(STATUS);
    }

    /// e1000_configure_msix and e1000_irq_enable for one vector: queue 0's
    /// receive and the other causes (link changes) send it, auto-cleared
    /// until the next empty receive re-arms it.
    fn arm_interrupts(&self) {
        let device = &self.device;
        // Linux's workaround for the 82574's spurious MSI-X interrupts.
        device.write32(RFCTL, device.read32(RFCTL) | RFCTL_ACK_DIS);
        device.write32(EITR0, THROTTLE);
        device.write32(IVAR, IVAR_VALID | (IVAR_VALID << 16));
        device.write32(
            CTRL_EXT,
            (device.read32(CTRL_EXT) & !CTRL_EXT_IAME) | CTRL_EXT_PBA_CLR | CTRL_EXT_EIAME,
        );
        device.write32(EIAC, IMS_RXQ0);
        device.write32(IMS, IMS_RXQ0 | IMS_OTHER | IMS_LSC);
    }

    fn offer_receive(&mut self, index: usize) {
        let base = index * DESCRIPTOR;
        let address = self.receive.address(index);
        self.receive.descriptors.write(base, address);
        self.receive.descriptors.write(base + 8, 0u64);
    }
}

/// Whether the controller wrote back the transmit descriptor at `base`.
fn transmitted(descriptors: &DmaBuffer, base: usize) -> bool {
    descriptors.read::<u8>(base + 12) & TX_DONE != 0
}

impl Drop for E1000e {
    /// Linux `e1000e_down` then `e1000e_release_hw_control`. The rings are
    /// freed only once the controller verifiably stopped; otherwise they
    /// stay allocated. A lost function, or one whose minimum delays
    /// failed, gets no register access.
    ///
    /// This drives the controller's registers, so the owner drops it where
    /// its MMIO window is mapped; anywhere else the first read faults.
    fn drop(&mut self) {
        // A PHY check or reset under way ends here; the stop resets the MAC.
        self.work = None;
        if self.faulted || self.timing_failure.is_some() || self.device.read32(STATUS) == u32::MAX {
            return;
        }
        if stop(&self.device, &self.clock).is_ok() {
            release_control(&self.device);
            // SAFETY: the completed MAC reset stopped every descriptor and
            // buffer access, and neither ring is used after this.
            unsafe {
                ManuallyDrop::drop(&mut self.receive);
                ManuallyDrop::drop(&mut self.transmit);
            }
        }
    }
}

impl Link for E1000e {
    fn mac(&self) -> Mac {
        self.mac
    }

    fn carrier(&mut self) -> bool {
        self.watchdog().unwrap_or(false)
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        check_frame(frame)?;
        if !self.watchdog()? {
            return Err(LinkError::NoCarrier);
        }
        if !self.transmit.free(transmitted) {
            return Err(LinkError::Busy);
        }
        let index = self.transmit.advance();
        let length = frame.len().max(MIN_FRAME);
        write_transmit_frame(self.transmit.buffer(index), frame, length);
        let base = index * DESCRIPTOR;
        let address = self.transmit.address(index);
        self.transmit.descriptors.write(base, address);
        self.transmit
            .descriptors
            .write(base + 8, length as u32 | TX_EOP | TX_IFCS | TX_REPORT);
        self.transmit.descriptors.write(base + 12, 0u32);
        fence(Ordering::SeqCst);
        self.device.write32(TDT, self.transmit.next as u32);
        Ok(())
    }

    fn signals(&self) -> bool {
        self.signalled
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        self.receive_frame(<[u8]>::to_vec)
    }

    /// The stack's receive path: the frame is copied into its reused
    /// buffer, so a received frame allocates nothing.
    fn receive_reusing(&mut self, frame: &mut Vec<u8>) -> Result<bool, LinkError> {
        self.receive_frame(|bytes| {
            frame.clear();
            frame.extend_from_slice(bytes);
        })
        .map(|received| received.is_some())
    }
}

impl E1000e {
    /// The next good whole frame the controller wrote back, passed to
    /// `take` while its buffer is still held.
    fn receive_frame<T>(
        &mut self,
        mut take: impl FnMut(&[u8]) -> T,
    ) -> Result<Option<T>, LinkError> {
        if let Some(error) = &self.timing_failure {
            return Err(LinkError::Pci(error.clone()));
        }
        if self.resetting() {
            if let Some(outcome) = self.advance() {
                self.finish(outcome)?;
            }
            if self.resetting() {
                return Ok(None);
            }
        }
        // Bound processing even if a device continually supplies bad frames.
        for _ in 0..DESCRIPTORS {
            let index = self.receive.next;
            let base = index * DESCRIPTOR;
            let status: u8 = self.receive.descriptors.read(base + 12);
            if status & RX_DONE == 0 {
                if let Some(tail) = self.receive.idle() {
                    fence(Ordering::SeqCst);
                    self.device.write32(RDT, tail);
                }
                if self.signalled {
                    // e1000_msix_other reads the link and other causes,
                    // clearing them so the next one sends the vector. A
                    // receive cause read with them is a frame to look for.
                    let causes = self.device.read32(ICR);
                    if causes & IMS_LSC != 0 {
                        self.watchdog()?;
                    }
                    if causes & IMS_RXQ0 != 0 {
                        continue;
                    }
                    // e1000e_poll: the receive cause auto-cleared when the
                    // vector fired; enable it again now the ring is empty.
                    self.device.write32(IMS, IMS_RXQ0);
                }
                return Ok(None);
            }
            fence(Ordering::Acquire);
            let length = usize::from(self.receive.descriptors.read::<u16>(base + 8));
            let errors: u8 = self.receive.descriptors.read(base + 13);
            let eop = status & RX_EOP != 0;
            let good = !self.dropping_receive
                && eop
                && errors & RX_FRAME_ERRORS == 0
                && (HEADER..=MAX_FRAME).contains(&length);
            let frame = good.then(|| take(&self.receive.buffer(index)[..length]));
            self.dropping_receive = !eop;
            self.offer_receive(index);
            self.receive.advance();
            if let Some(tail) = self.receive.offered(index) {
                fence(Ordering::SeqCst);
                self.device.write32(RDT, tail);
            }
            if frame.is_some() {
                return Ok(frame);
            }
        }
        if let Some(tail) = self.receive.idle() {
            fence(Ordering::SeqCst);
            self.device.write32(RDT, tail);
        }
        if self.signalled {
            // Frames stopped at the bound wait with the cause cleared; a
            // software cause sends it again, as e1000_watchdog_task does.
            self.device.write32(ICS, IMS_RXQ0);
            self.device.write32(IMS, IMS_RXQ0);
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
use crate::Clock;
