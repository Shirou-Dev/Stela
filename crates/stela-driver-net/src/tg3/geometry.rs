// SPDX-License-Identifier: GPL-2.0-only
//! Source tg3 ring geometry follows ASIC capabilities, not PCI aliases.
use super::Asic;

#[derive(Clone, Copy)]
pub(super) struct Geometry {
    pub rx: usize,
    pub returns: usize,
}
impl Geometry {
    pub const fn of(asic: Asic) -> Self {
        match asic {
            // 5761 is 5705_PLUS without LRG_PROD_RING_CAP/JUMBO_CAPABLE.
            Asic::Bcm5761 | Asic::Bcm5784 => Self {
                rx: 512,
                returns: 512,
            },
            // JUMBO_CAPABLE without LRG_PROD_RING_CAP: tg3_rx_ret_ring_size's
            // 5700 return ring.
            Asic::Bcm57765 | Asic::Bcm57766 => Self {
                rx: 512,
                returns: 1024,
            },
            Asic::Bcm5717 | Asic::Bcm5719 | Asic::Bcm5720 | Asic::Bcm5762 => Self {
                rx: 2048,
                returns: 4096,
            },
        }
    }
    /// The last DMA address of the rings and status block: `tg3_init_one`'s
    /// coherent `persist_dma_mask`, 31 bits on a 57766. Packet buffers may
    /// lie anywhere.
    pub const fn ring_limit(asic: Asic) -> u64 {
        if matches!(asic, Asic::Bcm57766) {
            0x7fff_ffff
        } else {
            u64::MAX
        }
    }
}
