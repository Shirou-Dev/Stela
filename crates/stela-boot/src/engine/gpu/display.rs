//! The guest's display on a bound GPU's output.
//!
//! Binding a GPU ends the firmware's framebuffer on it, so Stela's console
//! moves to the output's front buffer at once, where the modeled DCP's frames
//! follow it. A GPU driving no display leaves the firmware's scanout alone.
//!
//! The DCP model presents under the board's device lock, on whichever PE
//! made the device access. A DRM request from a PE other than the boot CPU
//! waits for the boot CPU to run Linux, and the boot CPU may be waiting for
//! that lock, so a present only copies rows into a hidden buffer there and
//! queues its page flip. The flip is requested on the boot CPU: by its own
//! presents, or by the display's flush at the next vblank, which the home
//! machine's device deadline brings there.
use super::client;
use crate::console::{self, Framebuffer};
use crate::engine::host;
use crate::{Result, output};
use alloc::{boxed::Box, format};
use core::ops::Range;
use core::sync::atomic::Ordering;
use core::{cell::UnsafeCell, ffi::c_int, ffi::c_void, ptr::NonNull};
use stela_contracts::refuse;
use stela_drivers::gpu::metal::kms::{Display, Drm, Error as DisplayError};
use stela_soc::machine::{Scanout, ScanoutFormat, ScanoutMode};

/// A GPU's primary node, the DRM master.
struct Node(c_int);

// SAFETY: Linux's DRM ioctls honor their UAPI bounds. `client::map` retains
// each mapping for the boot, and different dumb objects have distinct backing.
unsafe impl Drm for Node {
    fn control(&mut self, request: u32, argument: *mut c_void) -> i64 {
        client::control(self.0, request, argument)
    }

    fn map(&mut self, offset: u64, bytes: usize) -> Option<NonNull<u8>> {
        client::map(self.0, offset, bytes)
    }

    fn immediate(&self) -> bool {
        host::processor() == super::BOOT_CPU.load(Ordering::Relaxed)
    }
}

/// The host scanout the modeled DCP presents to, once a GPU took the display.
struct KmsScanout(Display<Node>);

impl Scanout for KmsScanout {
    fn mode(&self) -> ScanoutMode {
        let (width, height) = self.0.size();
        ScanoutMode {
            width,
            height,
            format: ScanoutFormat::Bgra8888,
        }
    }

    fn refresh_millihertz(&self) -> u32 {
        self.0.refresh_millihertz()
    }

    fn physical_size_mm(&self) -> Option<(u32, u32)> {
        self.0.size_mm()
    }

    fn present(&mut self, rows: &[u8]) -> Result<()> {
        console::release();
        let presented = self.0.present(rows);
        self.finish_present(presented)
    }

    fn try_present_rows(
        &mut self,
        damage: Option<Range<usize>>,
        fill: &mut dyn FnMut(usize, &mut [u8]) -> Result<()>,
    ) -> Result<bool> {
        let prepared = self.0.prepare_rows(damage, fill)?;
        console::release();
        let presented = prepared.present();
        self.finish_present(presented)?;
        Ok(true)
    }

    fn queued(&self) -> bool {
        self.0.queued()
    }

    fn flush(&mut self) -> Result<()> {
        let flushed = self.0.flush();
        self.finish_present(flushed)
    }
}

impl KmsScanout {
    fn finish_present(&self, presented: Result<(), DisplayError>) -> Result<()> {
        // A stop's reason shows on the buffer that does.
        console::parked_on(screen(&self.0));
        presented.map_err(|error| {
            refuse!(
                "the GPU's display refused a frame: {error}",
                error = format!("{error:?}")
            )
        })
    }
}

/// `display`'s front buffer as a screen.
fn screen(display: &Display<Node>) -> Framebuffer {
    let (width, height) = display.size();
    let (pixels, pitch) = display.front();
    Framebuffer::linear(
        pixels.as_ptr() as usize,
        width as usize,
        height as usize,
        pitch / size_of::<u32>(),
    )
}

/// The display a GPU took, until the board's DCP takes it.
struct Taken(UnsafeCell<Option<Display<Node>>>);

// SAFETY: only the boot CPU's start reaches it, once each way.
unsafe impl Sync for Taken {}

static TAKEN: Taken = Taken(UnsafeCell::new(None));

/// Moves the display to the first bound GPU with an output, in the mode of
/// `wanted` pixels if it has it. What stops one GPU is reported.
pub(in crate::engine) fn take(wanted: (usize, usize)) {
    let Some(gpu) = super::installed() else {
        output::arguments(format_args!("GPU display: no installed GPU\n"));
        output::flush_log();
        return;
    };
    output::arguments(format_args!(
        "GPU display: evaluating {} bound device(s)\n",
        gpu.start.bound.len()
    ));
    output::flush_log();
    for (minor, bound) in gpu.start.bound.iter().enumerate() {
        let Some(fd) = client::open_node(minor as u32) else {
            output::arguments(format_args!(
                "GPU {}: failed to open DRM node {minor}\n",
                bound.name
            ));
            output::flush_log();
            continue;
        };
        match Display::take(Node(fd), (wanted.0 as u32, wanted.1 as u32)) {
            Ok(display) => {
                let (w, h) = display.size();
                output::arguments(format_args!(
                    "GPU {}: display taken successfully: {}x{} @ {}mHz\n",
                    bound.name,
                    w,
                    h,
                    display.refresh_millihertz()
                ));
                output::flush_log();
                crate::status::take_screen(Some(screen(&display)));
                // SAFETY: the one boot CPU, before any reader.
                unsafe { *TAKEN.0.get() = Some(display) };
                return;
            }
            Err(error) => {
                output::arguments(format_args!("GPU {}: no display: {error:?}\n", bound.name));
                output::flush_log();
                client::close_descriptor(fd);
            }
        }
    }
}

/// The scanout of the display [`take`] took, for the board's DCP.
pub(in crate::engine) fn scanout() -> Option<Box<dyn Scanout>> {
    // SAFETY: the one boot CPU, after `take`.
    let display = unsafe { (*TAKEN.0.get()).take() }?;
    Some(Box::new(KmsScanout(display)))
}
