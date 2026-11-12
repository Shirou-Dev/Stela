// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2001-2004 David S. Miller
// Copyright (C) 2001-2003 Jeff Garzik
// Copyright (C) 2004 Sun Microsystems Inc.
// Copyright (C) 2005-2018 Broadcom
//! Linux tg3's APE, SRAM, MDIO, management handshake and engine-stop
//! protocols, with checked failures.
use super::{Asic, Delay, Error, Registers, candidate};

const MISC_HOST_CTRL: u16 = 0x68;
const PRODID: u16 = 0xbc;
const GEN2_PRODID: u16 = 0xf4;
const GEN15_PRODID: u16 = 0xfc;
const MEM_BASE: u32 = 0x7c;
const MEM_DATA: u32 = 0x84;
const MAC_MODE: u32 = 0x400;
const MAC_MI_COM: u32 = 0x44c;
const MAC_MI_MODE: u32 = 0x454;
const MAC_TX_MODE: u32 = 0x45c;
const MAC_RX_MODE: u32 = 0x468;
const SG_DIG_STATUS: u32 = 0x5b4;
const SG_DIG_IS_SERDES: u32 = 0x100;
const MI_AUTO_POLL: u32 = 0x10;
const MI_START: u32 = 0x2000_0000;
const MI_READ: u32 = 0x0800_0000;
const MI_WRITE: u32 = 0x0400_0000;
const MI_READ_FAILED: u32 = 0x1000_0000;
const FIRMWARE_MBOX: u32 = 0xb50;
const FIRMWARE_MAGIC: u32 = 0x4b65_7654;
const APE_LOCK_REQ: u32 = 0x2c;
const APE_LOCK_GRANT: u32 = 0x4c;
const APE_PER_LOCK_REQ: u32 = 0x8400;
const APE_PER_LOCK_GRANT: u32 = 0x8420;
const APE_DRIVER: u32 = 0x1000;
const PHY_LOCKS: [u8; 4] = [0, 2, 3, 5];
const ENABLE: u32 = 2;
const TRANSMIT_DATA_ENABLE: u32 = 0x0020_0000;
const FTQ_RESET: u32 = 0x5c00;
const HOSTCC_MODE: u32 = 0x3c00;
const STOP_RX: [u32; 5] = [0x2c00, 0x2000, 0x2400, 0x2800, 0x3000];
const STOP_TX: [u32; 6] = [0x1400, 0x1800, 0xc00, 0x4800, 0x1000, 0x1c00];
const WDMAC_MODE: u32 = 0x4c00;
const MAILBOX_INTERRUPT: u32 = 0x204;
const MASK_PCI_INT: u32 = 2;
const MEMARB_MODE: u32 = 0x4000;
const PCISTATE: u16 = 0x70;
const ALLOW_APE: u32 = 0x0007_0000;
const CPMU_STATUS: u32 = 0x362c;
const SRAM_CPMU_STATUS: u32 = 0xe00;
const HOST_ACCESS: u32 = 0x9a; // MASK_PCI_INT | WORD_SWAP | INDIR_ACCESS | PCISTATE_RW.
const SRAM_DATA_SIGNATURE: u32 = 0xb54;
const SRAM_DATA_PHY_ID: u32 = 0xb74;
const PHY_ID_MASK: u32 = 0xffff_fff0;

/// Broadcom's PHY ID layout from MII ID registers 2 and 3, which is not the
/// ordinary (ID1 << 16) | ID2.
const fn broadcom_phy_id(high: u32, low: u32) -> u32 {
    ((high & 0xffff) << 10) | ((low & 0xfc00) << 16) | (low & 0x3ff)
}

/// `TG3_KNOWN_PHY_ID`: the masked PHY IDs tg3 takes from the PHY itself.
const fn known_phy_id(masked: u32) -> bool {
    matches!(
        masked,
        0x6000_8040 // BCM5400
            | 0x6000_8050 // BCM5401
            | 0x6000_8070 // BCM5411
            | 0x6000_8110 // BCM5701
            | 0x6000_8160 // BCM5703
            | 0x6000_8190 // BCM5704
            | 0x6000_81a0 // BCM5705
            | 0x6000_8180 // BCM5750
            | 0x6000_8100 // BCM5752
            | 0x6000_8340 // BCM5714
            | 0x6000_8350 // BCM5780
            | 0xbc05_0ce0 // BCM5787
            | 0xbc05_0cc0 // BCM5755
            | 0xbc05_0ed0 // BCM5756
            | 0xdc00_ac40 // BCM5906
            | 0xbc05_0fd0 // BCM5761
            | 0x5c0d_8a00 // BCM5718C
            | 0xbc05_0ff0 // BCM5718S
            | 0x5c0d_8a40 // BCM57765
            | 0x5c0d_8a20 // BCM5719C
            | 0x5c0d_8b60 // BCM5720C
            | 0x8580_3780 // BCM5762
            | 0x6001_0140 // BCM8002
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub device: u16,
    /// Unaltered source chip identity, including revision and metal stepping.
    pub chip_revision: u32,
    pub asic: Asic,
    /// PCI BDF function observed from the config owner.
    pub bdf_function: u8,
    /// ASIC port: BCM5720 derives this from the signed CPMU SRAM word or
    /// live CPMU status, which need not equal the BDF function.
    pub function: u8,
    pub phy_address: u8,
    /// ENABLE_APE: the chip has an APE (see [`super::ape`]).
    pub ape: bool,
}

/// One serialized hardware epoch. Drop keeps its real registers/reservation;
/// this transport alone cannot prove platform DMA drain and release ownership.
pub struct Hardware<R: Registers, D: Delay> {
    registers: Option<R>,
    delay: D,
    identity: Option<Identity>,
    failure: Option<Error>,
    cleanup_failure: Option<Error>,
    stopped: bool,
    core_reset_complete: bool,
    // Source invariant captured once from this endpoint's initial
    // Link Control. A later 10/100 workaround clear must not erase that fact.
    clkreq_bug: Option<bool>,
    /// The address `tg3_get_device_address`'s fallback chose, kept so the
    /// board read again after the core reset finds the same one.
    fallback_mac: Option<crate::Mac>,
    /// What the signed board configuration last said the management
    /// firmware owns.
    management: management::Management,
    /// Linux's `ape_hb`: the next APE host heartbeat count.
    ape_heartbeat: u32,
    /// Whether the APE was last told the driver started.
    ape_started: bool,
    /// The interval until the next ASF heartbeat to firmware without an
    /// APE (`tg3_timer`'s `asf_counter`).
    asf_heartbeat: Option<alloc::boxed::Box<dyn crate::bus::pci::power::Interval>>,
}
impl<R: Registers, D: Delay> Drop for Hardware<R, D> {
    fn drop(&mut self) {
        if let Some(registers) = self.registers.take() {
            // Engine stop is not a posted-DMA drain, IOMMU unmap or IRQ drain.
            // Preserve the owner until a composed backend owns those.
            core::mem::forget(registers);
        }
    }
}
impl<R: Registers, D: Delay> Hardware<R, D> {
    /// Compose the original register and timing owners without device effects.
    ///
    /// # Safety
    /// `registers` satisfies its native ownership contract. `delay` is the
    /// calibrated timer supplied by that producer, usable in this
    /// device's power/CPU context for the whole epoch. A copied numeric
    /// rate or unchecked clock is not native timing permission. Isolated test
    /// models supply their explicit symbolic timer instead.
    pub unsafe fn new(registers: R, delay: D) -> Self {
        Self {
            registers: Some(registers),
            delay,
            identity: None,
            failure: None,
            cleanup_failure: None,
            stopped: false,
            core_reset_complete: false,
            clkreq_bug: None,
            fallback_mac: None,
            management: management::Management::default(),
            ape_heartbeat: 0,
            ape_started: false,
            asf_heartbeat: None,
        }
    }
    /// Stop inherited packet engines while the original configuration/root
    /// and DMA backing remain held. This publishes no DMA or reset operation.
    /// The returned registers still require an original-root drain receipt.
    #[expect(
        clippy::result_large_err,
        reason = "return the original owner and precise failure without allocating during refusal or retirement"
    )]
    pub fn quiesce_cold(mut self) -> Result<R, (Error, Self)> {
        let result = (|| {
            self.timer_ready()?;
            if self.identity.is_some() || self.failure.is_some() || self.stopped {
                return Err(Error::Poisoned);
            }
            let command = Self::checked(self.regs().config_read32(4)?)? as u16;
            if command & 4 != 0 {
                return Err(Error::UnsupportedBoard);
            }
            self.power_up()?;
            // Decode permits vendor containment; BME stays clear and inherited
            // interrupt delivery remains disabled by the original platform.
            self.regs().config_write16(4, command | 0x402)?;
            if self.regs().config_read32(4)? & 0x406 != 0x402 {
                return Err(Error::ConfigDidNotLatch);
            }
            self.packet_identity()?;
            self.packet_stop()
        })();
        match self.record(result) {
            Ok(()) => Ok(self.release_registers()),
            Err(error) => Err((error, self)),
        }
    }

    pub fn identity(&self) -> Option<Identity> {
        self.identity
    }
    pub fn failure(&self) -> Option<Error> {
        self.failure
    }
    pub fn cleanup_failure(&self) -> Option<Error> {
        self.cleanup_failure
    }
    pub fn engines_stopped(&self) -> bool {
        self.stopped
    }
    fn timer_ready(&self) -> Result<(), Error> {
        self.delay.check().map_err(Error::Timing)
    }
    fn wait(&mut self, microseconds: u64) -> Result<(), Error> {
        let result = self.delay.wait_us(microseconds).map_err(Error::Timing);
        // A failed settling wait cannot certify an in-flight device effect.
        // Poison even private packet helpers that return through Packet's error.
        self.record(result)
    }
    fn regs(&mut self) -> &mut R {
        self.registers
            .as_mut()
            .expect("retained hardware registers")
    }
    fn checked(value: u32) -> Result<u32, Error> {
        if value == u32::MAX {
            Err(Error::Removed)
        } else {
            Ok(value)
        }
    }
    fn read(&mut self, at: u32) -> Result<u32, Error> {
        Self::checked(self.regs().read32(at)?)
    }
    fn write(&mut self, at: u32, value: u32) -> Result<(), Error> {
        self.regs().write32(at, value)
    }
    fn flush(&mut self, at: u32, value: u32) -> Result<(), Error> {
        self.write(at, value)?;
        self.read(at)?;
        Ok(())
    }
    fn ape_read(&mut self, at: u32) -> Result<u32, Error> {
        Self::checked(self.regs().ape_read32(at)?)
    }
    fn check(&self) -> Result<Identity, Error> {
        if self.failure.is_some() {
            Err(Error::Poisoned)
        } else if self.stopped {
            Err(Error::Stopped)
        } else {
            self.timer_ready()?;
            self.identity.ok_or(Error::NotIdentified)
        }
    }
    fn record<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if let Err(error) = result {
            self.failure.get_or_insert(error);
        }
        result
    }
    fn cleanup(&mut self, result: Result<(), Error>) {
        if let Err(error) = result {
            self.cleanup_failure.get_or_insert(error);
        }
    }
    fn combine<T>(
        &mut self,
        primary: Result<T, Error>,
        cleanup: Result<(), Error>,
    ) -> Result<T, Error> {
        self.cleanup(cleanup);
        match primary {
            Err(error) => Err(error),
            Ok(value) => cleanup.map(|()| value),
        }
    }

    /// Observe config/ASIC and copper strap before taking PHY grants.
    /// This performs no reset, DMA publication or packet attachment.
    pub fn identify(&mut self) -> Result<Identity, Error> {
        if self.failure.is_some() {
            return Err(Error::Poisoned);
        }
        self.timer_ready()?;
        if let Some(identity) = self.identity {
            return Ok(identity);
        }
        let result = self.identify_inner();
        self.record(result)
    }
    fn identify_inner(&mut self) -> Result<Identity, Error> {
        let id = Self::checked(self.regs().config_read32(0)?)?;
        let class = Self::checked(self.regs().config_read32(8)?)?;
        let device = (id >> 16) as u16;
        if !candidate(
            id as u16,
            device,
            [(class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8],
        ) {
            return Err(Error::UnsupportedDevice);
        }
        let host = Self::checked(self.regs().config_read32(MISC_HOST_CTRL)?)?;
        // tg3_get_invariants establishes register word swapping/indirect
        // access through CONFIG space before the first MAC MMIO operation.
        let control = (host & 0xffff_0000) | HOST_ACCESS;
        self.regs().config_write32(MISC_HOST_CTRL, control)?;
        let observed = Self::checked(self.regs().config_read32(MISC_HOST_CTRL)?)?;
        if observed & 0xffff != HOST_ACCESS {
            return Err(Error::ConfigDidNotLatch);
        }
        let mut chip_revision = host >> 16;
        if chip_revision >> 12 == 0xf {
            let at = if matches!(device, 0x1655 | 0x1656 | 0x1665 | 0x1657 | 0x165f | 0x1687) {
                GEN2_PRODID
            } else if super::gen15_product(device) {
                GEN15_PRODID
            } else {
                PRODID
            };
            chip_revision = Self::checked(self.regs().config_read32(at)?)?;
        }
        let asic = match (device, chip_revision >> 12) {
            (0x1680 | 0x1681 | 0x1688 | 0x1689, 0x5761) => Asic::Bcm5761,
            // tg3_get_invariants: a 5717 C0 is a 5720 A0.
            (0x1655 | 0x1656 | 0x1665, 0x5717) if chip_revision == regs::CHIPREV_ID_5717_C0 => {
                chip_revision = regs::CHIPREV_ID_5720_A0;
                Asic::Bcm5720
            }
            (0x1655 | 0x1656 | 0x1665, 0x5717) => Asic::Bcm5717,
            (0x1657, 0x5719) => Asic::Bcm5719,
            // tg3_detect_asic_rev: the product ID, not the device ID, tells
            // a 57765 from a 57766.
            (device, 0x57785) if super::gen15_product(device) => Asic::Bcm57765,
            (device, 0x57766) if super::gen15_product(device) => Asic::Bcm57766,
            (0x165f, 0x5720) => Asic::Bcm5720,
            (0x1687, 0x5762) => Asic::Bcm5762,
            _ => return Err(Error::UnsupportedRevision),
        };
        let bdf_function = self.regs().function_number();
        if bdf_function > 7 {
            return Err(Error::UnsupportedDevice);
        }
        // tg3_get_invariants: netboot may have disabled the memory arbiter.
        // Establish and observe it before any SRAM data can be trusted.
        let arbiter = self.read(MEMARB_MODE)?;
        self.flush(MEMARB_MODE, arbiter | ENABLE)?;
        if self.read(MEMARB_MODE)? & ENABLE == 0 {
            return Err(Error::ConfigDidNotLatch);
        }
        let function = if asic.plus_5717() {
            let saved = self.sram(SRAM_CPMU_STATUS, None)?;
            let status = if saved & 0xffff == CPMU_STATUS {
                saved
            } else {
                self.read(CPMU_STATUS)?
            };
            if asic == Asic::Bcm5717 {
                u8::from(status & regs::CPMU_STATUS_FMSK_5717 != 0)
            } else {
                (status >> 30) as u8
            }
        } else {
            bdf_function & 3
        };
        let ape = super::ape(device);
        // tg3_get_invariants opens the APE register and memory space only
        // on a chip with an APE.
        if ape {
            let state = Self::checked(self.regs().config_read32(PCISTATE)?)?;
            self.regs().config_write32(PCISTATE, state | ALLOW_APE)?;
            if Self::checked(self.regs().config_read32(PCISTATE)?)? & ALLOW_APE != ALLOW_APE {
                return Err(Error::ConfigDidNotLatch);
            }
        }
        // tg3_mdio_init: only 5717_PLUS changes the PHY address.
        let phy_address = if asic.plus_5717() {
            if self.read(SG_DIG_STATUS)? & SG_DIG_IS_SERDES != 0 {
                return Err(Error::UnsupportedMedia);
            }
            function + 1
        } else {
            1
        };
        let identity = Identity {
            device,
            chip_revision,
            asic,
            bdf_function,
            function,
            phy_address,
            ape,
        };
        self.identity = Some(identity);
        if !ape {
            return Ok(identity);
        }
        // tg3_ape_lock_init clears only this port's stale grant bits;
        // it never invents an acquisition or clears a competitor's bit.
        let grant_base = if asic == Asic::Bcm5761 {
            APE_LOCK_GRANT
        } else {
            APE_PER_LOCK_GRANT
        };
        for lock in 0..=7u8 {
            let bit = if PHY_LOCKS.contains(&lock) || function == 0 {
                APE_DRIVER
            } else {
                1 << function
            };
            self.regs()
                .ape_write32(grant_base + u32::from(lock) * 4, bit)?;
        }
        Ok(identity)
    }

    fn lock_coordinates(&self, lock: u8) -> Result<(u32, u32, u32), Error> {
        let identity = self.identity.ok_or(Error::NotIdentified)?;
        let phy = PHY_LOCKS.contains(&lock);
        if !phy && !matches!(lock, 1 | 4 | 7) {
            return Err(Error::Bounds);
        }
        let bit = if phy || identity.function == 0 {
            APE_DRIVER
        } else {
            1 << identity.function
        };
        let (request, grant) = if identity.asic == Asic::Bcm5761 {
            (APE_LOCK_REQ, APE_LOCK_GRANT)
        } else {
            (APE_PER_LOCK_REQ, APE_PER_LOCK_GRANT)
        };
        Ok((
            request + u32::from(lock) * 4,
            grant + u32::from(lock) * 4,
            bit,
        ))
    }
    /// tg3_ape_lock: without an APE there is no one to share with, and the
    /// lock is taken at once.
    fn lock(&mut self, lock: u8) -> Result<(), Error> {
        if !self.identity.ok_or(Error::NotIdentified)?.ape {
            return Ok(());
        }
        let (request, grant, bit) = self.lock_coordinates(lock)?;
        self.regs().ape_write32(request, bit)?;
        let result = (|| {
            for _ in 0..100 {
                // Exact equality is required: our bit with a competing grant
                // is not exclusive ownership (tg3_ape_lock).
                if self.ape_read(grant)? == bit {
                    return Ok(());
                }
                self.wait(10)?;
            }
            Err(Error::ApeTimeout)
        })();
        if result.is_err() {
            let cleanup = self.regs().ape_write32(grant, bit);
            self.cleanup(cleanup);
        }
        result
    }
    fn unlock(&mut self, lock: u8) -> Result<(), Error> {
        if !self.identity.ok_or(Error::NotIdentified)?.ape {
            return Ok(());
        }
        let (_, grant, bit) = self.lock_coordinates(lock)?;
        self.regs().ape_write32(grant, bit)
    }

    fn restore_phy_mode(&mut self, mode: u32) -> Result<(), Error> {
        let restore = self.flush(MAC_MI_MODE, mode);
        let settle = self.wait(80);
        self.combine(restore, settle)
    }
    fn phy_command(&mut self, register: u8, data: Option<u16>) -> Result<u16, Error> {
        let identity = self.identity.ok_or(Error::NotIdentified)?;
        let mode = self.read(MAC_MI_MODE)?;
        let auto_poll = mode & MI_AUTO_POLL != 0;
        if auto_poll {
            self.flush(MAC_MI_MODE, mode & !MI_AUTO_POLL)?;
            if let Err(error) = self.wait(80) {
                let restore = self.restore_phy_mode(mode);
                return self.combine(Err(error), restore);
            }
        }
        let lock = PHY_LOCKS[usize::from(identity.function)];
        let acquired = self.lock(lock);
        let primary = if let Err(error) = acquired {
            Err(error)
        } else {
            let command = (u32::from(identity.phy_address) << 21)
                | (u32::from(register) << 16)
                | MI_START
                | data.map_or(MI_READ, |value| MI_WRITE | u32::from(value));
            let result = (|| {
                self.flush(MAC_MI_COM, command)?;
                for _ in 0..5000 {
                    self.wait(10)?;
                    if self.read(MAC_MI_COM)? & MI_START == 0 {
                        self.wait(5)?;
                        let value = self.read(MAC_MI_COM)?;
                        if value & MI_START != 0 {
                            return Err(Error::MdioTimeout);
                        }
                        if data.is_none() && value & MI_READ_FAILED != 0 {
                            return Err(Error::MdioReadFailed);
                        }
                        return Ok(value as u16);
                    }
                }
                Err(Error::MdioTimeout)
            })();
            // Restore autopoll before giving back the PHY grant, as the donor.
            let restore = if auto_poll {
                self.restore_phy_mode(mode)
            } else {
                Ok(())
            };
            let result = self.combine(result, restore);
            let release = self.unlock(lock);
            return self.combine(result, release);
        };
        let restore = if auto_poll {
            self.restore_phy_mode(mode)
        } else {
            Ok(())
        };
        self.combine(primary, restore)
    }
    pub fn read_phy(&mut self, register: u8) -> Result<u16, Error> {
        self.check()?;
        if register > 31 {
            return Err(Error::Bounds);
        }
        let result = self.phy_command(register, None);
        self.record(result)
    }
    pub fn write_phy(&mut self, register: u8, value: u16) -> Result<(), Error> {
        self.check()?;
        if register > 31 {
            return Err(Error::Bounds);
        }
        let result = self.phy_command(register, Some(value)).map(|_| ());
        self.record(result)
    }
    /// `tg3_phy_probe`'s PHY ID. The PHY's own ID registers are read only
    /// when no management firmware may be using the PHY (no ASF, no APE),
    /// and that ID is taken only when tg3 knows it (`TG3_KNOWN_PHY_ID`).
    /// Otherwise the ID the bootcode published in the signed NIC SRAM
    /// (`tg3_get_eeprom_hw_cfg`) stands, as in Linux; a published zero
    /// means no copper PHY. Linux's last fallback, its subsystem-ID table
    /// for unsigned boards, is not implemented: an unsigned board is
    /// refused. Like Linux, the driver sets up a published ID tg3 does not
    /// know as the family's copper PHY (tg3 keys its PHY setup to the ASIC
    /// for these families). A known ID must be the family's own PHY.
    pub fn read_phy_identity(&mut self) -> Result<u32, Error> {
        self.check()?;
        let result = (|| {
            let chip = self.identity.expect("identified");
            let hardware = if self.management.asf || chip.ape {
                None
            } else {
                let high = u32::from(self.phy_command(2, None)?);
                let low = u32::from(self.phy_command(3, None)?);
                Some(broadcom_phy_id(high, low))
            };
            let identity = match hardware {
                Some(identity) if known_phy_id(identity & PHY_ID_MASK) => identity,
                _ => {
                    if self.sram(SRAM_DATA_SIGNATURE, None)? != FIRMWARE_MAGIC {
                        return Err(Error::UnsignedBoard);
                    }
                    let published = self.sram(SRAM_DATA_PHY_ID, None)?;
                    if published == 0 {
                        0
                    } else {
                        broadcom_phy_id(published >> 16, published & 0xffff)
                    }
                }
            };
            let expected = match chip.asic {
                Asic::Bcm5761 => 0xbc05_0fd0,
                // tg3 names no 57766 PHY; its family's is the 57765's.
                Asic::Bcm57765 | Asic::Bcm57766 => 0x5c0d_8a40,
                Asic::Bcm5717 => 0x5c0d_8a00,
                Asic::Bcm5719 => 0x5c0d_8a20,
                Asic::Bcm5720 => 0x5c0d_8b60,
                Asic::Bcm5762 => 0x8580_3780,
            };
            let masked = identity & PHY_ID_MASK;
            // TG3_PHY_ID_INVALID published sends Linux to its subsystem
            // table, which is not implemented.
            if masked == 0 || identity == u32::MAX || (masked != expected && known_phy_id(masked)) {
                return Err(Error::UnsupportedMedia);
            }
            Ok(identity)
        })();
        self.record(result)
    }
    /// Clause 45 through Clause 22's MMD control/address pair (tg3_phy_cl45_read).
    pub fn read_mmd(&mut self, device: u8, register: u16) -> Result<u16, Error> {
        self.check()?;
        if device > 31 {
            return Err(Error::Bounds);
        }
        let result = (|| {
            self.phy_command(13, Some(u16::from(device)))?;
            self.phy_command(14, Some(register))?;
            self.phy_command(13, Some(0x4000 | u16::from(device)))?;
            self.phy_command(14, None)
        })();
        self.record(result)
    }
    pub fn write_mmd(&mut self, device: u8, register: u16, value: u16) -> Result<(), Error> {
        self.check()?;
        if device > 31 {
            return Err(Error::Bounds);
        }
        let result = (|| {
            self.phy_command(13, Some(u16::from(device)))?;
            self.phy_command(14, Some(register))?;
            self.phy_command(13, Some(0x4000 | u16::from(device)))?;
            self.phy_command(14, Some(value))?;
            Ok(())
        })();
        self.record(result)
    }

    fn sram(&mut self, at: u32, value: Option<u32>) -> Result<u32, Error> {
        // tg3_read/write_mem always restore the window to zero. This is the
        // serialized MAC MMIO path, never a CPU reference into NIC SRAM.
        let result = (|| {
            self.flush(MEM_BASE, at)?;
            if let Some(value) = value {
                self.write(MEM_DATA, value)?;
                self.regs().read32(MEM_DATA)?; // Legal data may be all ones.
                Ok(value)
            } else {
                // All-ones is legal SRAM data, unlike a control register.
                self.regs().read32(MEM_DATA)
            }
        })();
        let restore = self.flush(MEM_BASE, 0);
        self.combine(result, restore)
    }
    pub fn read_sram(&mut self, at: u32) -> Result<u32, Error> {
        self.check()?;
        if at & 3 != 0 || at >= 0x2_0000 {
            return Err(Error::Bounds);
        }
        let result = self.sram(at, None);
        self.record(result)
    }
    pub fn write_sram(&mut self, at: u32, value: u32) -> Result<(), Error> {
        self.check()?;
        if at & 3 != 0 || at >= 0x2_0000 {
            return Err(Error::Bounds);
        }
        let result = self.sram(at, Some(value)).map(|_| ());
        self.record(result)
    }
    /// Write the bootcode mailbox before core reset; no reset is implied.
    pub fn arm_firmware_handshake(&mut self) -> Result<(), Error> {
        self.write_sram(FIRMWARE_MBOX, FIRMWARE_MAGIC)
    }
    /// Observe bootcode's inverted signature after real reset. Firmware absence
    /// is explicit rather than Linux's log-and-continue fallback.
    pub fn wait_firmware(&mut self) -> Result<(), Error> {
        self.check()?;
        let result = (|| {
            for _ in 0..100_000 {
                if self.sram(FIRMWARE_MBOX, None)? == !FIRMWARE_MAGIC {
                    return Ok(());
                }
                self.wait(10)?;
            }
            Err(Error::FirmwareTimeout)
        })();
        self.record(result)
    }

    fn stop_block(&mut self, at: u32) -> Result<(), Error> {
        let value = self.read(at)?;
        self.flush(at, value & !ENABLE)?;
        for _ in 0..1000 {
            self.wait(100)?;
            if self.read(at)? & ENABLE == 0 {
                return Ok(());
            }
        }
        Err(Error::StopTimeout(at))
    }
    /// Stop ordinary packet engines in Linux tg3_abort_hw order. Does not
    /// certify PCI/remapper posted-write drain or release any DMA mapping.
    /// A failure is sticky, keeps the real owner, and never clears status RAM.
    pub fn stop_engines(&mut self) -> Result<(), Error> {
        self.check()?;
        let result = self.stop_engines_inner();
        if result.is_ok() {
            self.stopped = true;
        }
        self.record(result)
    }
    pub(super) fn stop_engines_inner(&mut self) -> Result<(), Error> {
        self.timer_ready()?;
        (|| {
            let host = Self::checked(self.regs().config_read32(MISC_HOST_CTRL)?)?;
            self.flush(u32::from(MISC_HOST_CTRL), host | MASK_PCI_INT)?;
            // The declared transport is single-vector/polled; cold attachment
            // must independently exclude/drain all inherited IRQ vectors.
            self.flush(MAILBOX_INTERRUPT, 1)?;
            let mode = self.read(MAC_RX_MODE)?;
            self.flush(MAC_RX_MODE, mode & !ENABLE)?;
            self.wait(10)?;
            // All declared parts are 5705_PLUS: RCVLSC/DMAC/MBFREE/BUFMGR/
            // MEMARB are not software-disableable and are absent.
            for at in STOP_RX.into_iter().chain(STOP_TX) {
                self.stop_block(at)?;
            }
            let mode = self.read(MAC_MODE)?;
            self.flush(MAC_MODE, mode & !TRANSMIT_DATA_ENABLE)?;
            self.wait(40)?;
            self.stop_block(MAC_TX_MODE)?;
            self.stop_block(HOSTCC_MODE)?;
            self.stop_block(WDMAC_MODE)?;
            self.write(FTQ_RESET, u32::MAX)?;
            self.write(FTQ_RESET, 0)?;
            self.read(FTQ_RESET)?;
            Ok(())
        })()
    }
    pub(super) fn release_registers(&mut self) -> R {
        self.registers.take().expect("retained hardware registers")
    }
}

#[cfg(test)]
mod tests;

mod bcm5761;
mod bcm5762;
pub(super) mod board;
mod packet_hw;
mod phy;
mod regs;
mod reset;

mod clkreq;

mod filter;
pub(super) mod management;
