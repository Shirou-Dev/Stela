// SPDX-License-Identifier: GPL-2.0-only
//! Original __tg3_set_rx_mode/tg3_set_multi and unicast-slot policy.
use super::super::ReceiveFilter;
use super::{regs::*, *};
const PROMISCUOUS: u32 = 0x100;

impl<R: Registers, D: Delay> Hardware<R, D> {
    // A full multicast bitmap and a unicast address's low four bytes may be
    // all ones. Keep removal detection on independent identity/MMIO
    // observations instead of treating those legal data words as status.
    fn filter_data(&mut self, at: u32) -> Result<u32, Error> {
        let value = self.regs().read32(at)?;
        if value == u32::MAX {
            let device = self.identity.ok_or(Error::NotIdentified)?.device;
            let actual = Self::checked(self.regs().config_read32(0)?)?;
            if actual != (u32::from(device) << 16) | 0x14e4 {
                return Err(Error::Removed);
            }
            self.read(MAC_MODE)?;
        }
        Ok(value)
    }
    /// All source table effects; also used before a new receive engine starts.
    pub(super) fn packet_filter_tables(&mut self, filter: &ReceiveFilter) -> Result<(), Error> {
        if !filter.promiscuous {
            for (at, value) in [
                MAC_HASH_REG_0,
                MAC_HASH_REG_1,
                MAC_HASH_REG_2,
                MAC_HASH_REG_3,
            ]
            .into_iter()
            .zip(filter.hashes())
            {
                self.write(at, value)?;
                if self.filter_data(at)? != value {
                    return Err(Error::ConfigDidNotLatch);
                }
            }
        }
        let (first, slots) = self.unicast_slots();
        if !filter.promiscuous && filter.unicast.len() <= slots {
            for (index, mac) in filter.unicast.iter().enumerate() {
                let at = MAC_ADDR_0_HIGH + (first + index as u32) * 8;
                let high = u32::from(u16::from_be_bytes([mac.0[0], mac.0[1]]));
                let low = u32::from_be_bytes([mac.0[2], mac.0[3], mac.0[4], mac.0[5]]);
                self.write(at, high)?;
                self.write(at + 4, low)?;
                if self.read(at)? != high || self.filter_data(at + 4)? != low {
                    return Err(Error::ConfigDidNotLatch);
                }
            }
        }
        Ok(())
    }
    pub(in crate::tg3) fn packet_receive_filter(
        &mut self,
        filter: &ReceiveFilter,
    ) -> Result<(), Error> {
        self.check()?;
        filter.validate()?;
        let result = (|| {
            let previous = self.read(MAC_RX_MODE)?;
            if previous & RX_MODE_ENABLE == 0 {
                return Err(Error::ConfigDidNotLatch);
            }
            let value = self.receive_mode(previous, filter);
            self.packet_filter_tables(filter)?;
            if value != previous {
                self.write(MAC_RX_MODE, value)?;
                if self.read(MAC_RX_MODE)? != value {
                    return Err(Error::ConfigDidNotLatch);
                }
                self.wait(10)?;
            }
            Ok(())
        })();
        // Partial hash/address/mode effects cannot become an acknowledged policy.
        self.record(result)
    }
    /// TG3_UCAST_ADDR_IDX and TG3_MAX_UCAST_ADDR: the first additional
    /// unicast slot and how many there are. ASF firmware keeps slot 1.
    fn unicast_slots(&self) -> (u32, usize) {
        if self.management.asf { (2, 2) } else { (1, 3) }
    }
    /// Raw VLAN tags are kept, as a build without VLAN offload does, except
    /// under ASF, which needs them stripped; the receive path then puts the
    /// stripped tag back.
    pub(super) fn receive_mode(&self, previous: u32, filter: &ReceiveFilter) -> u32 {
        let (_, slots) = self.unicast_slots();
        (previous & !(PROMISCUOUS | RX_MODE_KEEP_VLAN_TAG))
            | if self.management.asf {
                0
            } else {
                RX_MODE_KEEP_VLAN_TAG
            }
            | if filter.promiscuous(slots) {
                PROMISCUOUS
            } else {
                0
            }
    }
}
