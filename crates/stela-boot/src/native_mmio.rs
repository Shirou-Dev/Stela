//! Native MMIO root publication. Firmware descriptions supply permissions;
//! exclusive device ownership is acquired separately by the native dispatcher.
//! [`Source`] serves the host drivers on every host processor through a
//! preallocated uncached aperture. WC and dynamic roots refuse.
mod aliases;
mod capture;
mod ecam;
mod shared;
pub(crate) mod shootdown;
mod window;
use ecam::RootWindow;

pub(crate) use capture::{CaptureHandoff, Prepared, Wire};
pub(crate) use shared::{
    ContainedPci, ContainmentError, InitialPciLines, IoapicRegisters, ModePin, NativeExclusiveHpet,
    NativeHpetMapping, PROCESSORS, PciScope, Source,
};
pub(crate) use window::Window;

use stela_drivers::bus::mmio::owned::Error;
const PAGE: u64 = 4096;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 2;
const HUGE: u64 = 1 << 7;
const NX: u64 = 1 << 63;
const APERTURE_OFFSET: u64 = 0x5_0000_0000;
const ENTRIES: usize = 512;

fn failed<T>(_: T) -> Error {
    Error::Unavailable
}

/// Borrow only the reserved capture produced by this handoff.
///
/// # Safety
/// The real post-EBS main owns this handoff and native physmap. Its loader
/// allocations remain pinned, and no source bytes have been reconstructed.
pub(crate) unsafe fn captured(
    handoff: &crate::handoff::Handoff,
) -> Result<&'static Wire, alloc::string::String> {
    use alloc::{format, string::String};
    let region = handoff
        .native_mmio_capture
        .region()
        .ok_or_else(|| String::from(handoff.native_mmio_capture.refusal()))?;
    let bytes = size_of::<Wire>().next_multiple_of(PAGE as usize) as u64;
    if region.physical != handoff.native_mmio.physical
        || region.bytes != handoff.native_mmio.bytes
        || region.physical == 0
        || !region.physical.is_multiple_of(PAGE)
        || region.bytes != bytes
        || region.physical.checked_add(region.bytes).is_none()
    {
        return Err(format!(
            "the native capture at {:#x} ({:#x} bytes) is not the handoff's {:#x} ({:#x} \
             bytes, {bytes:#x} expected)",
            region.physical, region.bytes, handoff.native_mmio.physical, handoff.native_mmio.bytes
        ));
    }
    // SAFETY: loader reserved this exact owned region; caller keeps
    // its physmap rather than treating the numeric PA as permission.
    let wire = unsafe { &*(crate::layout::physical(region.physical) as *const Wire) };
    if !wire.valid() {
        return Err(String::from("the native capture's records are not intact"));
    }
    if wire.root != handoff.root {
        return Err(format!(
            "the native capture names page root {:#x}, not the handoff's {:#x}",
            wire.root, handoff.root
        ));
    }
    if let Some(page) = (region.physical..region.physical + region.bytes)
        .step_by(PAGE as usize)
        .find(|&page| !wire.table_owned(page))
    {
        return Err(format!(
            "the native capture's page {page:#x} is not loader data in the final memory map"
        ));
    }
    Ok(wire)
}

/// # Safety
/// The original post-EBS handoff and physmap remain installed throughout the
/// aperture's lifetime. Shared activation consumes this claim.
unsafe fn claim_capture(
    handoff: &'static crate::handoff::Handoff,
) -> Result<(&'static Wire, capture::Origin), Error> {
    // SAFETY: the caller supplies the original handoff and physmap.
    let wire = unsafe { captured(handoff) }.map_err(|why| {
        crate::output::arguments(format_args!("NATIVE MMIO unavailable: {why}\n"));
        Error::Unavailable
    })?;
    Ok((wire, handoff.native_mmio_capture.claim()?))
}
