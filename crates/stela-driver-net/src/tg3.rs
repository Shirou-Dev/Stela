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
    Bcm5720,
    Bcm5762,
}

/// Source PCI table membership is only a probe candidate, never an attach grant.
pub fn candidate(vendor: u16, device: u16, class: [u8; 3]) -> bool {
    vendor == 0x14e4
        && class == [2, 0, 0]
        && matches!(device, 0x165f | 0x1680 | 0x1681 | 0x1688 | 0x1689 | 0x1687)
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
