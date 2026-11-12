// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2001-2004 David S. Miller
// Copyright (C) 2001-2003 Jeff Garzik
// Copyright (C) 2004 Sun Microsystems Inc.
// Copyright (C) 2005-2018 Broadcom
//! The driver's side of the management firmware handshake: Linux tg3's
//! ASF driver-state mailbox, APE host segment, driver state and events,
//! and, for ASF firmware on a chip without an APE, `tg3_stop_fw`'s pause
//! command and `tg3_timer`'s ASF heartbeat.
//!
//! ENABLE_APE is a property of the chip ([`super::super::ape`]); ASF
//! follows the signed board configuration.
use super::*;

const SRAM_DATA_SIGNATURE: u32 = 0xb54;
const SRAM_DATA_CONFIG: u32 = 0xb58;
const ASF_ENABLE: u32 = 0x80;
const APE_ENABLE: u32 = 0x0020_0000;
const FW_CMD_MBOX: u32 = 0xb78;
const FW_CMD_LEN_MBOX: u32 = 0xb7c;
const FW_CMD_DATA_MBOX: u32 = 0xb80;
const FWCMD_NICDRV_PAUSE_FW: u32 = 2;
const FWCMD_NICDRV_ALIVE3: u32 = 0xe;
const GRC_RX_CPU_EVENT: u32 = 0x6810;
const GRC_RX_CPU_DRIVER_EVENT: u32 = 0x4000;
/// `TG3_FW_EVENT_TIMEOUT_USEC`, polled in 8-us steps.
const FW_EVENT_POLLS: u32 = (2500 >> 3) + 1;
/// `TG3_FW_UPDATE_TIMEOUT_SEC`, and the heartbeat every half of it.
const FW_UPDATE_TIMEOUT_SEC: u32 = 5;
const FW_UPDATE_FREQ_US: u64 = 2_000_000;
const DRV_STATE_MBOX: u32 = 0xc04;
pub(super) const DRV_STATE_START: u32 = 0x0000_0001;
pub(super) const DRV_STATE_START_DONE: u32 = 0x8000_0001;
pub(super) const DRV_STATE_UNLOAD: u32 = 0x0000_0002;
pub(super) const DRV_STATE_UNLOAD_DONE: u32 = 0x8000_0002;

const APE_EVENT: u32 = 0x0c;
const APE_EVENT_1: u32 = 1;
const APE_SEG_SIG: u32 = 0x4000;
const APE_SEG_SIG_MAGIC: u32 = 0x4150_4521;
const APE_FW_STATUS: u32 = 0x400c;
const APE_FW_STATUS_READY: u32 = 0x100;
const APE_HOST_SEG_SIG: u32 = 0x4200;
const APE_HOST_SEG_SIG_MAGIC: u32 = 0x484f_5354;
const APE_HOST_SEG_LEN: u32 = 0x4204;
const APE_HOST_SEG_LEN_MAGIC: u32 = 0x20;
const APE_HOST_INIT_COUNT: u32 = 0x4208;
const APE_HOST_DRIVER_ID: u32 = 0x420c;
/// `APE_HOST_DRIVER_ID_MAGIC(TG3_MAJ_NUM, TG3_MIN_NUM)` for tg3 3.137, the
/// driver this one follows.
const APE_HOST_DRIVER_ID_MAGIC: u32 = 0xf000_0000 | (3 << 16) | (137 << 8);
const APE_HOST_BEHAVIOR: u32 = 0x4210;
const APE_HOST_BEHAV_NO_PHYLOCK: u32 = 1;
const APE_HOST_HEARTBEAT_INT_MS: u32 = 0x4214;
/// This link is polled, with no timer that would keep a heartbeat count
/// going while the stack is busy elsewhere, so it tells the APE not to
/// expect one, as drivers before the heartbeat did by leaving it zero.
const APE_HOST_HEARTBEAT_INT_DISABLE: u32 = 0;
const APE_HOST_HEARTBEAT_COUNT: u32 = 0x4218;
const APE_HOST_DRVR_STATE: u32 = 0x421c;
const APE_HOST_DRVR_STATE_START: u32 = 1;
const APE_HOST_DRVR_STATE_UNLOAD: u32 = 2;
const APE_EVENT_STATUS: u32 = 0x4300;
const APE_EVENT_STATUS_DRIVER_EVNT: u32 = 0x10;
const APE_EVENT_STATUS_STATE_CHNGE: u32 = 0x500;
const APE_EVENT_STATUS_STATE_START: u32 = 0x0001_0000;
const APE_EVENT_STATUS_STATE_UNLOAD: u32 = 0x0002_0000;
const APE_EVENT_STATUS_EVENT_PENDING: u32 = 0x8000_0000;
const APE_LOCK_MEM: u8 = 4;
/// `tg3_ape_send_event`'s wait for the APE to take the previous event.
const APE_EVENT_WAIT_US: u64 = 20_000;

/// What the signed board configuration says the management firmware owns.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::tg3) struct Management {
    /// ASF (NIC_SRAM_DATA_CFG_ASF_ENABLE): the firmware shares the PHY and
    /// receive path, so the driver keeps the PHY powered, leaves receive
    /// rules 4 to 7 and MAC address slot 1 to it, and has the MAC strip
    /// VLAN tags.
    pub asf: bool,
}

impl<R: Registers, D: Delay> Hardware<R, D> {
    /// `tg3_get_eeprom_hw_cfg` and `tg3_chip_reset`'s reprobe: the ASF
    /// setting from the signed board configuration. An unsigned board is
    /// refused, as no setting of it can be trusted.
    pub(super) fn observe_management(&mut self) -> Result<Management, Error> {
        if self.sram(SRAM_DATA_SIGNATURE, None)? != FIRMWARE_MAGIC {
            return Err(Error::UnsignedBoard);
        }
        let config = self.sram(SRAM_DATA_CONFIG, None)?;
        // tg3_get_eeprom_hw_cfg would set ENABLE_APE from this bit on a
        // chip Linux maps no APE window for; such a board is refused.
        if config & APE_ENABLE != 0 && !self.identity.ok_or(Error::NotIdentified)?.ape {
            return Err(Error::UnsupportedBoard);
        }
        let management = Management {
            asf: config & ASF_ENABLE != 0,
        };
        self.management = management;
        Ok(management)
    }
    pub(in crate::tg3) fn management(&self) -> Management {
        self.management
    }
    /// `tg3_write_sig_pre_reset` and `tg3_write_sig_post_reset`: the ASF
    /// new-handshake driver state, written only when ASF is enabled.
    pub(super) fn asf_driver_state(&mut self, state: u32) -> Result<(), Error> {
        if self.management.asf {
            self.sram(DRV_STATE_MBOX, Some(state))?;
        }
        Ok(())
    }
    fn ape_write(&mut self, at: u32, value: u32) -> Result<(), Error> {
        self.regs().ape_write32(at, value)
    }
    fn ape(&self) -> Result<bool, Error> {
        Ok(self.identity.ok_or(Error::NotIdentified)?.ape)
    }
    /// ASF firmware that talks to the driver through the RX CPU event
    /// mailbox: ENABLE_ASF without ENABLE_APE.
    fn legacy_asf(&self) -> Result<bool, Error> {
        Ok(self.management.asf && !self.ape()?)
    }
    /// `tg3_wait_for_event_ack`: give the RX CPU up to 2.5 ms to take the
    /// previous event. Like Linux, the driver goes on when it does not.
    fn wait_for_event_ack(&mut self) -> Result<(), Error> {
        for _ in 0..FW_EVENT_POLLS {
            if self.read(GRC_RX_CPU_EVENT)? & GRC_RX_CPU_DRIVER_EVENT == 0 {
                break;
            }
            self.wait(8)?;
        }
        Ok(())
    }
    /// `tg3_generate_fw_event`.
    fn generate_firmware_event(&mut self) -> Result<(), Error> {
        let event = self.read(GRC_RX_CPU_EVENT)?;
        self.flush(GRC_RX_CPU_EVENT, event | GRC_RX_CPU_DRIVER_EVENT)
    }
    /// `tg3_stop_fw`: ASF firmware without an APE pauses before the driver
    /// resets or halts the chip.
    pub(super) fn stop_firmware(&mut self) -> Result<(), Error> {
        if !self.legacy_asf()? {
            return Ok(());
        }
        self.wait_for_event_ack()?;
        self.sram(FW_CMD_MBOX, Some(FWCMD_NICDRV_PAUSE_FW))?;
        self.generate_firmware_event()?;
        self.wait_for_event_ack()
    }
    /// `tg3_timer`'s ASF heartbeat for firmware without an APE: every two
    /// seconds, FWCMD_NICDRV_ALIVE3 with a five-second timeout, so the
    /// firmware checks the rings before it would reset a silent driver.
    /// The packet poll calls this; a timer with no retained interval
    /// cannot keep the beat, and such a function is refused at start.
    pub(in crate::tg3) fn asf_heartbeat(&mut self) -> Result<(), Error> {
        if !self.legacy_asf()? {
            return Ok(());
        }
        let elapsed = match &self.asf_heartbeat {
            Some(interval) => interval.elapsed().map_err(Error::Timing),
            None => Err(Error::NotIdentified),
        };
        if !self.record(elapsed)? {
            return Ok(());
        }
        self.wait_for_event_ack()?;
        self.sram(FW_CMD_MBOX, Some(FWCMD_NICDRV_ALIVE3))?;
        self.sram(FW_CMD_LEN_MBOX, Some(4))?;
        self.sram(FW_CMD_DATA_MBOX, Some(FW_UPDATE_TIMEOUT_SEC))?;
        self.generate_firmware_event()?;
        self.begin_heartbeat_interval()
    }
    fn begin_heartbeat_interval(&mut self) -> Result<(), Error> {
        let interval = self.delay.begin_interval(FW_UPDATE_FREQ_US);
        match self.record(interval.map_err(Error::Timing))? {
            Some(interval) => {
                self.asf_heartbeat = Some(interval);
                Ok(())
            }
            None => self.record(Err(Error::UnsupportedBoard)),
        }
    }
    /// `tg3_ape_driver_state_change(RESET_KIND_INIT)`, once per driver
    /// start: the host segment, driver identity and START state, then the
    /// state-change event.
    pub(super) fn ape_driver_start(&mut self) -> Result<(), Error> {
        if self.ape_started || !self.ape()? {
            return Ok(());
        }
        let heartbeat = self.ape_heartbeat;
        self.ape_heartbeat = heartbeat.wrapping_add(1);
        self.ape_write(APE_HOST_HEARTBEAT_COUNT, heartbeat)?;
        self.ape_write(APE_HOST_SEG_SIG, APE_HOST_SEG_SIG_MAGIC)?;
        self.ape_write(APE_HOST_SEG_LEN, APE_HOST_SEG_LEN_MAGIC)?;
        let count = self.ape_read(APE_HOST_INIT_COUNT)?;
        self.ape_write(APE_HOST_INIT_COUNT, count.wrapping_add(1))?;
        self.ape_write(APE_HOST_DRIVER_ID, APE_HOST_DRIVER_ID_MAGIC)?;
        self.ape_write(APE_HOST_BEHAVIOR, APE_HOST_BEHAV_NO_PHYLOCK)?;
        self.ape_write(APE_HOST_DRVR_STATE, APE_HOST_DRVR_STATE_START)?;
        self.ape_started = true;
        self.ape_send_event(APE_EVENT_STATUS_STATE_START)
    }
    /// The end of `tg3_reset_hw`: the heartbeat interval and ASF's
    /// START_DONE.
    pub(super) fn management_started(&mut self) -> Result<(), Error> {
        if self.ape()? {
            self.ape_write(APE_HOST_HEARTBEAT_INT_MS, APE_HOST_HEARTBEAT_INT_DISABLE)?;
        }
        self.asf_driver_state(DRV_STATE_START_DONE)?;
        // tg3_timer_start: the first ASF heartbeat is due one interval on.
        self.asf_heartbeat = None;
        if self.legacy_asf()? {
            self.begin_heartbeat_interval()?;
        }
        Ok(())
    }
    /// `tg3_ape_driver_state_change(RESET_KIND_SHUTDOWN)` without wake-up:
    /// the UNLOAD state and its event, so the firmware takes the port back.
    pub(super) fn ape_driver_unload(&mut self) -> Result<(), Error> {
        if !self.ape_started {
            return Ok(());
        }
        self.ape_write(APE_HOST_DRVR_STATE, APE_HOST_DRVR_STATE_UNLOAD)?;
        self.ape_started = false;
        self.ape_send_event(APE_EVENT_STATUS_STATE_UNLOAD)
    }
    /// `tg3_ape_send_event`: only to running APE firmware, after it took the
    /// previous event. Like Linux, an event the APE does not take within
    /// 20 ms, or whose memory lock is not granted, is not sent; the state
    /// words written before it still say where the driver is.
    fn ape_send_event(&mut self, event: u32) -> Result<(), Error> {
        if self.ape_read(APE_SEG_SIG)? != APE_SEG_SIG_MAGIC
            || self.ape_read(APE_FW_STATUS)? & APE_FW_STATUS_READY == 0
        {
            return Ok(());
        }
        let mut remaining = APE_EVENT_WAIT_US;
        loop {
            match self.lock(APE_LOCK_MEM) {
                Ok(()) => {}
                Err(Error::ApeTimeout) => return Ok(()),
                Err(error) => return Err(error),
            }
            let status = match self.ape_read(APE_EVENT_STATUS) {
                Ok(status) => status,
                Err(error) => {
                    let release = self.unlock(APE_LOCK_MEM);
                    return self.combine(Err(error), release);
                }
            };
            if status & APE_EVENT_STATUS_EVENT_PENDING == 0 {
                break;
            }
            self.unlock(APE_LOCK_MEM)?;
            if remaining == 0 {
                return Ok(());
            }
            self.wait(10)?;
            remaining = remaining.saturating_sub(10);
        }
        let posted = self.ape_write(
            APE_EVENT_STATUS,
            event
                | APE_EVENT_STATUS_DRIVER_EVNT
                | APE_EVENT_STATUS_STATE_CHNGE
                | APE_EVENT_STATUS_EVENT_PENDING,
        );
        let release = self.unlock(APE_LOCK_MEM);
        self.combine(posted, release)?;
        self.ape_write(APE_EVENT, APE_EVENT_1)
    }
}
