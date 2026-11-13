//! What a stopped boot still does. A stop halts with interrupts masked, and
//! in ACPI mode the firmware has handed the power button to the operating
//! system, so nothing would answer a press: the PC then turns off only
//! through the chipset's or the embedded controller's forced power-off, a
//! long hold, which some laptops do not perform for a halted system. The
//! stop therefore reads the button itself and turns the PC off at a press.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use stela_runtime::pc::power::{HostPower, Ports, ResetRegister};

const PCI_ADDRESS: u16 = 0xcf8;
const PCI_DATA: u16 = 0xcfc;
const KEYBOARD_STATUS: u16 = 0x64;
const KEYBOARD_INPUT_FULL: u8 = 1 << 1;
const KEYBOARD_PULSE_RESET: u8 = 0xfe;

/// How often a stopped boot reads the button. The status bit stays set
/// until written, so no press is lost between reads.
const BUTTON_MILLIS: u64 = 50;

/// The processor's I/O ports.
pub(crate) struct Io;

impl Ports for Io {
    fn in8(&mut self, port: u16) -> u8 {
        let value;
        // SAFETY: a port of the host's ACPI fixed hardware, at CPL0.
        unsafe {
            asm!("in al, dx", in("dx") port, out("al") value, options(nostack, preserves_flags))
        }
        value
    }

    fn out8(&mut self, port: u16, value: u8) {
        // SAFETY: as `in8`.
        unsafe {
            asm!("out dx, al", in("dx") port, in("al") value, options(nostack, preserves_flags))
        }
    }

    fn in16(&mut self, port: u16) -> u16 {
        let value;
        // SAFETY: as `in8`.
        unsafe {
            asm!("in ax, dx", in("dx") port, out("ax") value, options(nostack, preserves_flags))
        }
        value
    }

    fn out16(&mut self, port: u16, value: u16) {
        // SAFETY: as `in8`.
        unsafe {
            asm!("out dx, ax", in("dx") port, in("ax") value, options(nostack, preserves_flags))
        }
    }

    fn flush_caches(&mut self) {
        // SAFETY: WBINVD at CPL0 changes no program state.
        unsafe { asm!("wbinvd", options(nostack, preserves_flags)) }
    }
}

struct Hardware(UnsafeCell<Option<HostPower>>);

// SAFETY: written once by `arm` before `ARMED` is set, and only read after.
unsafe impl Sync for Hardware {}

static HARDWARE: Hardware = Hardware(UnsafeCell::new(None));
static ARMED: AtomicBool = AtomicBool::new(false);
static TSC_HZ: AtomicU64 = AtomicU64::new(0);

/// Give a later stop the host's power hardware. Called once, by the boot
/// processor, before any other processor runs Stela's code.
pub(crate) fn arm(power: &HostPower, tsc_hz: u64) {
    if tsc_hz == 0 || ARMED.load(Ordering::Acquire) {
        return;
    }
    // SAFETY: the one write, before `ARMED` lets any reader in.
    unsafe { *HARDWARE.0.get() = Some(power.clone()) };
    TSC_HZ.store(tsc_hz, Ordering::Relaxed);
    ARMED.store(true, Ordering::Release);
}

fn spin(milliseconds: u64) {
    let ticks = TSC_HZ.load(Ordering::Relaxed) / 1000 * milliseconds;
    // SAFETY: RDTSC is unprivileged on every x86-64 processor.
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    // SAFETY: as above.
    while unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < ticks {
        core::hint::spin_loop();
    }
}

/// Stay stopped for good with interrupts masked. Where the firmware runs
/// in ACPI mode, a press of the power button turns the PC off at S5 with
/// the sleep types the DSDT states; a PC that stays on, or states none, is
/// restarted, which hands it back to its firmware. In legacy mode the
/// firmware keeps the button and this only halts.
pub(crate) fn wait() -> ! {
    // SAFETY: no task resumes after a stop; interrupts stay masked.
    unsafe { asm!("cli", options(nomem, nostack)) };
    let power = ARMED
        .load(Ordering::Acquire)
        // SAFETY: `ARMED` follows the only write.
        .then(|| unsafe { (*HARDWARE.0.get()).as_ref() })
        .flatten()
        .filter(|power| power.acpi_mode(&mut Io));
    let Some(power) = power else {
        loop {
            // SAFETY: as above.
            unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
        }
    };
    // A press from before the stop is not a request to turn off.
    power.take_power_button(&mut Io);
    loop {
        spin(BUTTON_MILLIS);
        if power.take_power_button(&mut Io) {
            break;
        }
    }
    if let Some(sleep_types) = power.soft_off {
        power.enter_soft_off(&mut Io, sleep_types);
        spin(1000);
    }
    restart(power.reset)
}

/// Restart the PC: the FADT's reset register, then the 8042 keyboard
/// controller's reset pulse, then a triple fault, each given half a second.
pub(crate) fn restart(reset: Option<(ResetRegister, u8)>) -> ! {
    if let Some((register, value)) = reset {
        // SAFETY: the FADT's reset register; the machine resets.
        unsafe { write_reset(register, value) };
        spin(500);
    }
    if Io.in8(KEYBOARD_STATUS) != 0xff {
        for _ in 0..100 {
            if Io.in8(KEYBOARD_STATUS) & KEYBOARD_INPUT_FULL == 0 {
                break;
            }
            spin(1);
        }
        Io.out8(KEYBOARD_STATUS, KEYBOARD_PULSE_RESET);
        spin(500);
    }
    let empty = [0u16; 5];
    // SAFETY: an empty IDT makes the breakpoint a triple fault, which
    // resets the processor.
    unsafe {
        asm!("lidt [{}]", "int3", in(reg) &empty, options(noreturn));
    }
}

/// # Safety
///
/// `register` is the FADT's reset register.
pub(crate) unsafe fn write_reset(register: ResetRegister, value: u8) {
    match register {
        ResetRegister::Io(port) => Io.out8(port, value),
        ResetRegister::PciConfiguration {
            device,
            function,
            offset,
        } => {
            let address = 1 << 31
                | u32::from(device) << 11
                | u32::from(function) << 8
                | u32::from(offset & 0xfc);
            let shift = u32::from(offset & 3) * 8;
            // SAFETY: configuration mechanism 1 on bus 0, the caller's
            // register; the other bytes of its dword are written back.
            unsafe {
                asm!("out dx, eax", in("dx") PCI_ADDRESS, in("eax") address, options(nostack, preserves_flags));
                let dword: u32;
                asm!("in eax, dx", in("dx") PCI_DATA, out("eax") dword, options(nostack, preserves_flags));
                let dword = dword & !(0xff << shift) | u32::from(value) << shift;
                asm!("out dx, eax", in("dx") PCI_DATA, in("eax") dword, options(nostack, preserves_flags));
            }
        }
    }
}
