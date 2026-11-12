//! Operating systems setup has no disk backend for: every question about
//! this computer's volumes and disks is refused, by name.
use super::{Cpu, Disk, Host, PartitionInfo, Volume};
use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

pub(crate) const ADMIN: &str = "administrator rights";
/// What a disk identifier is preceded by where a user types it.
pub(crate) const DISK_PREFIX: &str = "";
pub(crate) const DISK_EXAMPLE: &str = "a whole disk";

/// The computer `stela` runs on.
pub(crate) struct System;

fn unsupported<T>(what: &str) -> Result<T> {
    bail!(
        "UNSUPPORTED {what}: setup reads disks through macOS, Linux or Windows, not {}",
        std::env::consts::OS
    )
}

impl Host for System {
    fn volume(&self, _: &Path) -> Result<Volume> {
        unsupported("volume inspection")
    }
    fn disks(&self) -> Result<Vec<Disk>> {
        unsupported("disk listing")
    }
    fn partition(&self, _: &str) -> Result<PartitionInfo> {
        unsupported("partition inspection")
    }
    fn serial(&self, _: &str) -> Result<Option<String>> {
        unsupported("disk serial numbers")
    }
    fn read(&self, _: &str, _: u64, _: usize) -> Result<Vec<u8>> {
        unsupported("raw partition reads")
    }
    fn write(&self, _: &str, _: u64, _: &[u8]) -> Result<()> {
        unsupported("raw partition writes")
    }
    fn unmount(&self, _: &PartitionInfo) -> Result<()> {
        unsupported("unmounting")
    }
    fn mount(&self, _: &str) -> Result<PathBuf> {
        unsupported("mounting")
    }
    fn cpu(&self) -> Result<Cpu> {
        super::cpu()
    }
}
