// SPDX-License-Identifier: GPL-2.0-only
//! tg3's receive-mode policy.
use super::Error;
use crate::Mac;
use alloc::vec::Vec;

/// Requested hardware receive policy. The station address always remains.
/// Multicast uses the source 128-bit hash and can admit hash collisions. Up to
/// three additional unicast addresses (two when ASF firmware keeps a slot)
/// use exact slots; larger lists select promiscuous mode, as the pinned
/// driver does. Lists are additional to the
/// station address, not a replacement MAC or a device ownership grant.
///
/// As in the source helper, shortening `unicast` leaves old unused slots until
/// the next complete rebuild. This is a hardware filter, not packet isolation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveFilter {
    pub promiscuous: bool,
    pub all_multicast: bool,
    pub multicast: Vec<Mac>,
    pub unicast: Vec<Mac>,
}
impl Default for ReceiveFilter {
    fn default() -> Self {
        Self {
            promiscuous: false,
            all_multicast: true,
            multicast: Vec::new(),
            unicast: Vec::new(),
        }
    }
}
impl ReceiveFilter {
    pub(super) fn validate(&self) -> Result<(), Error> {
        if self.multicast.iter().any(|mac| !mac.is_multicast())
            || self
                .unicast
                .iter()
                .any(|mac| mac.is_multicast() || mac.0 == [0; 6])
        {
            Err(Error::InvalidMac)
        } else {
            Ok(())
        }
    }
    /// Whether the hardware must accept everything: asked for, or more
    /// additional unicast addresses than `slots` exact slots hold.
    pub(super) fn promiscuous(&self, slots: usize) -> bool {
        self.promiscuous || self.unicast.len() > slots
    }
    pub(super) fn hashes(&self) -> [u32; 4] {
        if self.all_multicast {
            return [u32::MAX; 4];
        }
        let mut hashes = [0; 4];
        for mac in &self.multicast {
            let bit = multicast_bit(*mac);
            hashes[bit / 32] |= 1 << (bit % 32);
        }
        hashes
    }
}

// calc_crc returns ~crc32(~0, mac, 6), the IEEE CRC-32; the source uses
// ~calc_crc & 0x7f. Its tests compare against the unchanged Linux table
// generator and crc32_le_base.
pub(super) fn multicast_bit(mac: Mac) -> usize {
    (!stela_driver_core::crc::crc32_ieee(&mac.0) & 0x7f) as usize
}
