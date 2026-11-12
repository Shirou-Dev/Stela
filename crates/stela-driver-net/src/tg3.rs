// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2001-2004 David S. Miller
// Copyright (C) 2001-2003 Jeff Garzik
// Copyright (C) 2004 Sun Microsystems Inc.
// Copyright (C) 2005-2018 Broadcom
//! Broadcom Tigon3 hardware transport for the named BCM5720/5761/5762 cohort.
//!
//! `Packet::attach` composes one polled BCM5720/5761/5762 A0 copper queue
//! with requester-domain DMA and explicit retirement. BCM5761 requires
//! function-zero NIC wiring and recognized NVM; its original CLKREQ setting
//! selects the source per-speed send-BD workaround. These
//! bounded source-reviewed packet profiles have native model validation;
//! hardware remains unchecked. See NOTICE. SerDes and all other
//! ASIC/revision profiles explicitly refuse.
//!
//! All named chips have an APE window. MDIO takes the per-function APE
//! PHY grant, even when management firmware is not running. Management
//! firmware (ASF, APE) is told of the driver's start and stop as Linux
//! tells it, and keeps its PHY, receive rules and address slot. Linux's ignored
//! lock failures, firmware timeout fallback and silent stop timeout are
//! errors here. An uncertain operation poisons and keeps the
//! register owner, never permitting a new epoch by object reconstruction.
mod filter;
mod geometry;
pub use filter::ReceiveFilter;
pub mod io;
mod transport;

pub use packet::Packet;
pub use transport::Hardware;
mod packet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Config(crate::bus::pci::ConfigError),
    PciCapability(crate::bus::pci::CapabilityError),
    Access,
    Timing(crate::bus::pci::power::Error),
    Removed,
    Bounds,
    UnsupportedDevice,
    UnsupportedRevision,
    UnsupportedMedia,
    ApeTimeout,
    MdioTimeout,
    MdioReadFailed,
    FirmwareTimeout,
    StopTimeout(u32),
    /// The board configuration in NIC SRAM is not signed, so neither its
    /// media nor its management setting can be trusted.
    UnsignedBoard,
    UnsupportedPcie,
    ConfigDidNotLatch,
    NvramTimeout,
    Poisoned,
    NotIdentified,
    Stopped,
    PhyResetTimeout,
    UnsupportedBoard,
    InvalidMac,
    RingCorrupt,
    Attention {
        flow: u32,
        message: u32,
        read_dma: u32,
        write_dma: u32,
    },
    RingFull,
    Dma(crate::bus::dma::mapping::DmaError),
    Preparation(crate::bus::pci::requester::preparation::Error),
    Memory(crate::bus::dma::memory::MemoryError),
}

/// A plain account for the boot log and screen.
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Config(error) => error.fmt(f),
            Self::PciCapability(error) => error.fmt(f),
            Self::Access => f.write_str("a register access failed"),
            Self::Timing(error) => error.fmt(f),
            Self::Removed => f.write_str("the adapter stopped answering"),
            Self::Bounds => f.write_str("a register lies outside its window"),
            Self::UnsupportedDevice => f.write_str("this Broadcom device ID is unsupported"),
            Self::UnsupportedRevision => f.write_str("this chip revision is unsupported"),
            Self::UnsupportedMedia => {
                f.write_str("its media type (fiber or SerDes) is unsupported")
            }
            Self::ApeTimeout => f.write_str("its management processor (APE) did not answer"),
            Self::MdioTimeout => f.write_str("the PHY does not answer on its management bus"),
            Self::MdioReadFailed => f.write_str("a PHY register read failed"),
            Self::FirmwareTimeout => f.write_str("its firmware did not finish starting"),
            Self::StopTimeout(register) => {
                write!(f, "its engine at {register:#x} did not stop")
            }
            Self::UnsignedBoard => f.write_str("its board configuration in NIC SRAM is not signed"),
            Self::UnsupportedPcie => f.write_str("its PCIe setup is unsupported"),
            Self::ConfigDidNotLatch => f.write_str("a setting did not take"),
            Self::NvramTimeout => f.write_str("its NVRAM did not answer"),
            Self::Poisoned => f.write_str("an earlier failure left it unusable"),
            Self::NotIdentified => f.write_str("its chip could not be identified"),
            Self::Stopped => f.write_str("it is stopped"),
            Self::PhyResetTimeout => f.write_str("the PHY did not finish its reset"),
            Self::UnsupportedBoard => f.write_str("its board configuration is unsupported"),
            Self::InvalidMac => f.write_str("its MAC address in NVRAM is invalid"),
            Self::RingCorrupt => f.write_str("a descriptor ring is corrupt"),
            Self::Attention { .. } => f.write_str("the chip reported an internal error"),
            Self::RingFull => f.write_str("the transmit ring is full"),
            Self::Dma(error) => error.fmt(f),
            Self::Preparation(error) => error.fmt(f),
            Self::Memory(error) => error.fmt(f),
        }
    }
}

impl From<crate::bus::pci::CapabilityError> for Error {
    fn from(error: crate::bus::pci::CapabilityError) -> Self {
        Self::PciCapability(error)
    }
}
impl From<crate::bus::pci::ConfigError> for Error {
    fn from(error: crate::bus::pci::ConfigError) -> Self {
        Self::Config(error)
    }
}
impl Error {
    fn into_link(self) -> crate::LinkError {
        match self {
            Self::Timing(error) => crate::LinkError::Pci(crate::block::BlockError::PciPower(error)),
            Self::Config(error) => crate::LinkError::Pci(crate::block::BlockError::Config(error)),
            Self::PciCapability(error) => {
                crate::LinkError::Pci(crate::block::BlockError::PciCapability(error))
            }
            error => crate::LinkError::Adapter(alloc::format!("tg3: {error:?}")),
        }
    }
}

/// Serialized PCI/MAC/APE register ownership.
///
/// # Safety
/// Implementors keep one real exclusively reserved PCI function, its
/// configuration mapping, and its UC MAC BAR0 and APE BAR2 mappings. Reads and
/// writes are ordered native little-endian device accesses with complete bounds
/// checks and errors on removal. Config writes use required widths;
/// there are no other firmware/SMM/driver/IRQ users. MMIO must remain powered
/// and mapped until the owner is explicitly retired. A caller-supplied identity,
/// address cast, unrelated retention token or mock cannot grant native permission.
pub unsafe trait Registers {
    fn function_number(&self) -> u8;
    fn config_read32(&mut self, at: u16) -> Result<u32, Error>;
    fn config_write32(&mut self, at: u16, value: u32) -> Result<(), Error>;
    fn config_write16(&mut self, at: u16, value: u16) -> Result<(), Error>;
    fn read32(&mut self, at: u32) -> Result<u32, Error>;
    fn write32(&mut self, at: u32, value: u32) -> Result<(), Error>;
    fn ape_read32(&mut self, at: u32) -> Result<u32, Error>;
    fn ape_write32(&mut self, at: u32, value: u32) -> Result<(), Error>;
}

/// Original calibrated timing kept in the device's checked context.
/// The shared timer checks unavailable rates and uses modular elapsed ticks;
/// its successful waits preserve the complete requested minimum duration.
pub use crate::bus::pci::power::Timer as Delay;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asic {
    Bcm5761,
    Bcm5784,
    Bcm57765,
    Bcm57766,
    Bcm5717,
    Bcm5719,
    Bcm5720,
    Bcm5762,
}
impl Asic {
    /// tg3's 5717_PLUS class among the named ASICs: the internal port
    /// comes from the CPMU and addresses the PHY at port + 1.
    pub const fn plus_5717(self) -> bool {
        matches!(self, Self::Bcm5717 | Self::Bcm5719 | Self::Bcm5720)
    }
    /// The named 5755_PLUS ASICs before 57765_PLUS (5761 and 5784): no
    /// jumbo ring, 512-entry rings, PCIe 1.0a reset fixes and the PHY
    /// jitter workaround.
    pub const fn legacy(self) -> bool {
        matches!(self, Self::Bcm5761 | Self::Bcm5784)
    }
    /// tg3's 57765_CLASS: ASIC_REV_57765 and ASIC_REV_57766.
    pub const fn class_57765(self) -> bool {
        matches!(self, Self::Bcm57765 | Self::Bcm57766)
    }
    /// tg3's LRG_PROD_RING_CAP: 2048-entry standard and 4096-entry return
    /// rings.
    pub const fn large_rings(self) -> bool {
        matches!(
            self,
            Self::Bcm5717 | Self::Bcm5719 | Self::Bcm5720 | Self::Bcm5762
        )
    }
}

/// Devices Linux's PCI table marks TG3_DRV_DATA_FLAG_10_100_ONLY among the
/// named ones (BCM57791, BCM57795): their PHY has no gigabit to advertise.
pub const fn ten_hundred_only(device: u16) -> bool {
    matches!(device, 0x16b2 | 0x16b6)
}

/// Whether the device has an APE: Linux's `tg3_init_one` maps BAR 2 and
/// sets ENABLE_APE for exactly these device IDs. Every other Tigon3 has no
/// APE window, so its APE locks, events and register space do not exist.
pub const fn ape(device: u16) -> bool {
    matches!(
        device,
        0x1680
            | 0x1681
            | 0x1688
            | 0x1689
            | 0x1655
            | 0x1665
            | 0x1656
            | 0x1657
            | 0x165f
            | 0x1683
            | 0x1642
            | 0x1687
            | 0x1643
            | 0x16f3
            | 0x1641
    )
}

/// Source PCI table membership is only a probe candidate, never an attach grant.
pub fn candidate(vendor: u16, device: u16, class: [u8; 3]) -> bool {
    vendor == 0x14e4
        && class == [2, 0, 0]
        && (gen15_product(device)
            || matches!(
                device,
                0x1698
                    | 0x1684
                    | 0x1655
                    | 0x1656
                    | 0x1665
                    | 0x1657
                    | 0x165f
                    | 0x1680
                    | 0x1681
                    | 0x1688
                    | 0x1689
                    | 0x1687
            ))
}

/// The devices `tg3_detect_asic_rev` reads the product ID of from
/// TG3PCI_GEN15_PRODID_ASICREV: BCM57781, 57785, 57761, 57765, 57791,
/// 57795, 57762, 57766, 57782 and 57786, the 57765 class.
pub const fn gen15_product(device: u16) -> bool {
    matches!(
        device,
        0x16b0 | 0x16b1 | 0x16b2 | 0x16b4 | 0x16b5 | 0x16b6 | 0x1682 | 0x1686 | 0x16b7 | 0x16b3
    )
}

impl From<crate::bus::dma::mapping::DmaError> for Error {
    fn from(error: crate::bus::dma::mapping::DmaError) -> Self {
        Self::Dma(error)
    }
}
impl From<crate::bus::dma::memory::MemoryError> for Error {
    fn from(error: crate::bus::dma::memory::MemoryError) -> Self {
        Self::Memory(error)
    }
}
