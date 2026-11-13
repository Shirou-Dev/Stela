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
use stela_drivers::gpu::metal::kms::{self, Display, Drm, Error as DisplayError};
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

/// How long the GPU that showed the firmware's picture may take to detect
/// its display again. The GPU's reset ends the signal, and a monitor that
/// then searches its inputs drops hot-plug detect for some seconds; Linux
/// takes such a display when its hot-plug event arrives.
const RETURN_SECONDS: u64 = 8;
/// The pause between two detections in that time.
const RETURN_STEP_MILLIS: u64 = 100;

/// Moves the display to the first bound GPU with an output, in the mode of
/// `wanted` pixels if it has it. `firmware` names the function that showed
/// the firmware's picture: its display is known to exist, so it is awaited
/// within [`RETURN_SECONDS`]. What stops one GPU is reported with what its
/// connectors detected.
pub(in crate::engine) fn take(wanted: (usize, usize), firmware: Option<&str>) {
    let Some(gpu) = super::installed() else {
        return;
    };
    let wanted = (wanted.0 as u32, wanted.1 as u32);
    for (minor, bound) in gpu.start.bound.iter().enumerate() {
        let Some(fd) = client::open_node(minor as u32) else {
            continue;
        };
        let began = host::rdtsc();
        let patience = match firmware == Some(bound.name.as_str()) {
            true => RETURN_SECONDS.saturating_mul(gpu.tsc_hz),
            false => 0,
        };
        let taken = loop {
            match Display::take(Node(fd), wanted) {
                Err(DisplayError::NoOutput) if host::rdtsc().wrapping_sub(began) < patience => {
                    let step = host::rdtsc();
                    while host::rdtsc().wrapping_sub(step) < gpu.tsc_hz / 1000 * RETURN_STEP_MILLIS
                    {
                        core::hint::spin_loop();
                    }
                }
                taken => break taken,
            }
        };
        let waited_ms = host::rdtsc().wrapping_sub(began) / (gpu.tsc_hz / 1000).max(1);
        match taken {
            Ok(display) => {
                if waited_ms >= RETURN_STEP_MILLIS {
                    output::arguments(format_args!(
                        "GPU {}: display detected after {waited_ms} ms\n",
                        bound.name
                    ));
                }
                crate::status::take_screen(Some(screen(&display)));
                // SAFETY: the one boot CPU, before any reader.
                unsafe { *TAKEN.0.get() = Some(display) };
                return;
            }
            Err(error) => {
                output::arguments(format_args!(
                    "GPU {}: no display after {waited_ms} ms: {error:?}\n",
                    bound.name
                ));
                match kms::survey(&mut Node(fd)) {
                    Ok(seen) => {
                        for seen in seen {
                            output::arguments(format_args!("GPU {}: output {seen}\n", bound.name));
                        }
                    }
                    Err(error) => output::arguments(format_args!(
                        "GPU {}: outputs unreadable: {error:?}\n",
                        bound.name
                    )),
                }
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
