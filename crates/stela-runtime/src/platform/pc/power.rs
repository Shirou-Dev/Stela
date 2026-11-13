//! The host PC's ACPI fixed hardware for power: how the mount restarts and
//! powers off the machine when the guest does, and where it reads the
//! power button. Everything comes from the firmware's FADT and the DSDT's
//! `\_S5` object (ACPI 6.5 sections 4.8, 5.2.9 and 7.4.2); no chipset is
//! assumed.
//!
//! - Restart writes the FADT's RESET_VALUE to RESET_REG when the FADT sets
//!   RESET_REG_SUP (section 4.8.3.6). Only system I/O and PCI configuration
//!   space registers (segment 0, bus 0, as section 5.2.9 requires) are
//!   taken; a memory-space register is reported and left to the mount's
//!   architectural fallbacks.
//! - Power-off is the S5 soft-off sequence as Linux's
//!   `acpi_hw_legacy_sleep` runs it (section 7.4.2): every GPE disabled
//!   and every GPE and fixed event status cleared, so no pending wake event
//!   turns the machine straight back on; SLP_TYPx from `\_S5` written to
//!   PM1a_CNT and, when present, PM1b_CNT, then SLP_EN. A hardware-reduced
//!   platform writes them to its sleep control register instead, after
//!   clearing WAK_STS, as `acpi_hw_extended_sleep` does (section 4.8.3.7).
//!   The `\_PTS` and `\_GTS` control methods are AML the mount cannot run;
//!   firmware that needs them keeps the machine on and the mount says so.
//! - The fixed-feature power button sets PWRBTN_STS in PM1x_STS when
//!   PWRBTN_EN in PM1x_EN is set (section 4.8.4.1); a status bit is
//!   cleared by writing one. A FADT with PWR_BUTTON set has a
//!   control-method button instead, which needs AML and is not read. The
//!   mount reads the button only where the firmware already runs in ACPI
//!   mode: taking the fixed events from SMM firmware in legacy mode would
//!   leave its thermal, fan and battery events to an OS that services no
//!   SCI.
//!
//! The PM1 and GPE blocks and the sleep registers are system I/O ports.
//! The extended (X_) FADT blocks are preferred when present; one outside
//! I/O space is refused. A hardware-reduced platform has no PM1 blocks, so
//! it has no fixed button.
use super::acpi::{self, AcpiError};
use crate::Result;
use stela_contracts::Refusal;
use stela_contracts::bytes::{get_le32, get_le64};
use stela_contracts::refuse;

const HEADER: usize = 36;

/// FADT field offsets (ACPI 6.5 table 5.9).
const DSDT: usize = 40;
const PM1A_EVENT: usize = 56;
const PM1B_EVENT: usize = 60;
const PM1A_CONTROL: usize = 64;
const PM1B_CONTROL: usize = 68;
const GPE0_BLOCK: usize = 80;
const GPE1_BLOCK: usize = 84;
const PM1_EVENT_LENGTH: usize = 88;
const GPE0_BLOCK_LENGTH: usize = 92;
const GPE1_BLOCK_LENGTH: usize = 93;
const FLAGS: usize = 112;
const RESET_REGISTER: usize = 116;
const RESET_VALUE: usize = 128;
const X_DSDT: usize = 140;
const X_PM1A_EVENT: usize = 148;
const X_PM1B_EVENT: usize = 160;
const X_PM1A_CONTROL: usize = 172;
const X_PM1B_CONTROL: usize = 184;
const X_GPE0_BLOCK: usize = 220;
const X_GPE1_BLOCK: usize = 232;
const SLEEP_CONTROL: usize = 244;
const SLEEP_STATUS: usize = 256;
const GAS_BYTES: usize = 12;

/// FADT flags.
const CONTROL_METHOD_POWER_BUTTON: u32 = 1 << 4;
const RESET_SUPPORTED: u32 = 1 << 10;
const HARDWARE_REDUCED: u32 = 1 << 20;

/// Generic Address Structure address spaces.
const SYSTEM_MEMORY: u8 = 0;
const SYSTEM_IO: u8 = 1;
const PCI_CONFIGURATION: u8 = 2;

/// PM1 status and enable bits (ACPI 6.5 tables 4.16, 4.17).
pub const POWER_BUTTON: u16 = 1 << 8;
/// Every fixed event's status in PM1x_STS: TMR, BM, GBL, PWRBTN, SLPBTN,
/// RTC and WAK, Linux's `ACPI_BITMASK_ALL_FIXED_STATUS`.
pub const ALL_FIXED_STATUS: u16 = 0x8731;
/// The sleep status register's WAK_STS and the sleep control register's
/// fields (ACPI 6.5 sections 4.8.3.7, 4.8.3.8).
pub const SLEEP_WAKE_STATUS: u8 = 1 << 7;
const SLEEP_REGISTER_TYPE_SHIFT: u8 = 2;
const SLEEP_REGISTER_TYPE: u8 = 0x7 << SLEEP_REGISTER_TYPE_SHIFT;
const SLEEP_REGISTER_ENABLE: u8 = 1 << 5;
/// PM1 control bits (ACPI 6.5 table 4.18).
pub const SCI_ENABLE: u16 = 1 << 0;
const SLEEP_TYPE_SHIFT: u16 = 10;
const SLEEP_TYPE: u16 = 0x7 << SLEEP_TYPE_SHIFT;
const SLEEP_ENABLE: u16 = 1 << 13;

/// AML opcodes `\_S5` is declared with (ACPI 6.5 section 20.2).
const NAME_OP: u8 = 0x08;
const PACKAGE_OP: u8 = 0x12;
const ROOT_CHAR: u8 = b'\\';
const ZERO_OP: u8 = 0x00;
const ONE_OP: u8 = 0x01;
const BYTE_PREFIX: u8 = 0x0a;
const WORD_PREFIX: u8 = 0x0b;
const DWORD_PREFIX: u8 = 0x0c;

/// Where the reset value is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetRegister {
    Io(u16),
    /// Segment 0, bus 0.
    PciConfiguration {
        device: u8,
        function: u8,
        offset: u8,
    },
}

/// One PM1 register block pair: its event block (status, then enable) and
/// control block, as I/O ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pm1 {
    pub event: u16,
    pub control: u16,
}

/// A general-purpose event block (ACPI 6.5 section 4.8.4.1): its status
/// registers, then as many enable registers, one byte each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gpe {
    pub port: u16,
    pub bytes: u8,
}

impl Gpe {
    /// Each status register's port and its enable register's.
    pub fn registers(self) -> impl Iterator<Item = (u16, u16)> {
        let half = u16::from(self.bytes / 2);
        (0..half).map(move |index| (self.port + index, self.port + half + index))
    }
}

/// A hardware-reduced platform's sleep control and status registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SleepRegisters {
    pub control: u16,
    pub status: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostPower {
    /// PM1a and PM1b; PM1a is required for any PM1 use.
    pub pm1: [Option<Pm1>; 2],
    /// Bytes of each event block: status is the first half, enable the
    /// second.
    pub pm1_event_bytes: u8,
    /// SLP_TYPa and SLP_TYPb of S5, from `\_S5`.
    pub soft_off: Option<(u8, u8)>,
    pub reset: Option<(ResetRegister, u8)>,
    /// Whether the power button is the fixed-feature one.
    pub fixed_power_button: bool,
    /// GPE0 and GPE1.
    pub gpe: [Option<Gpe>; 2],
    /// A hardware-reduced platform's sleep registers.
    pub sleep_registers: Option<SleepRegisters>,
    /// What was found and refused, for the mount's report.
    pub refused: Option<Refusal>,
}

impl HostPower {
    /// PM1x_EN's port for an event block.
    pub fn enable_port(&self, pm1: Pm1) -> u16 {
        pm1.event + u16::from(self.pm1_event_bytes / 2)
    }

    /// The PM1 blocks present.
    pub fn blocks(&self) -> impl Iterator<Item = Pm1> + '_ {
        self.pm1.iter().flatten().copied()
    }
}

/// Port accesses to the host's ACPI fixed hardware.
pub trait Ports {
    fn in8(&mut self, port: u16) -> u8;
    fn out8(&mut self, port: u16, value: u8);
    fn in16(&mut self, port: u16) -> u16;
    fn out16(&mut self, port: u16, value: u16);
    /// Write the caches back to memory before the machine sleeps (WBINVD).
    fn flush_caches(&mut self);
}

impl HostPower {
    /// Whether the firmware runs in ACPI mode (SCI_EN), where the power
    /// button is the operating system's to answer. In legacy mode the
    /// firmware's own handler keeps it.
    pub fn acpi_mode(&self, ports: &mut impl Ports) -> bool {
        self.pm1[0].is_some_and(|pm1a| ports.in16(pm1a.control) & SCI_ENABLE != 0)
    }

    /// Whether PWRBTN_STS is set in a PM1 status register, clearing it
    /// where it is. The bit records a press of the button the chipset sees,
    /// whichever button the FADT declares, and stays set until written.
    pub fn take_power_button(&self, ports: &mut impl Ports) -> bool {
        let mut pressed = false;
        for block in self.blocks() {
            if ports.in16(block.event) & POWER_BUTTON != 0 {
                ports.out16(block.event, POWER_BUTTON);
                pressed = true;
            }
        }
        pressed
    }

    /// Enter S5 with the sleep types `(a, b)`, as Linux's
    /// `acpi_hw_legacy_sleep` and `acpi_hw_extended_sleep` do: every GPE
    /// disabled and every GPE and fixed event status cleared, so that no
    /// pending event turns the machine straight back on, then the sleep
    /// types and SLP_EN. Returns when the machine stayed on.
    pub fn enter_soft_off(&self, ports: &mut impl Ports, (a, b): (u8, u8)) {
        for (status, enable) in self.gpe.iter().flatten().flat_map(|gpe| gpe.registers()) {
            ports.out8(enable, 0);
            ports.out8(status, 0xff);
        }
        for block in self.blocks() {
            ports.out16(block.event, ALL_FIXED_STATUS);
        }
        if let Some(registers) = self.sleep_registers {
            ports.out8(registers.status, SLEEP_WAKE_STATUS);
            ports.flush_caches();
            ports.out8(registers.control, sleep_register_control(a));
            return;
        }
        for (block, sleep_type) in self.blocks().zip([a, b]) {
            let current = ports.in16(block.control);
            ports.out16(block.control, sleep_type_control(current, sleep_type));
        }
        ports.flush_caches();
        for (block, sleep_type) in self.blocks().zip([a, b]) {
            let current = ports.in16(block.control);
            ports.out16(block.control, sleep_control(current, sleep_type));
        }
    }
}

/// PM1x_CNT with S5's sleep type and SLP_EN clear, from its current
/// value: written first, as Linux writes SLP_TYP before SLP_EN.
pub fn sleep_type_control(current: u16, sleep_type: u8) -> u16 {
    current & !(SLEEP_TYPE | SLEEP_ENABLE)
        | (u16::from(sleep_type) << SLEEP_TYPE_SHIFT) & SLEEP_TYPE
}

/// PM1x_CNT with S5's sleep type and SLP_EN set, from its current value.
pub fn sleep_control(current: u16, sleep_type: u8) -> u16 {
    sleep_type_control(current, sleep_type) | SLEEP_ENABLE
}

/// The sleep control register's value entering `sleep_type`.
pub fn sleep_register_control(sleep_type: u8) -> u8 {
    (sleep_type << SLEEP_REGISTER_TYPE_SHIFT) & SLEEP_REGISTER_TYPE | SLEEP_REGISTER_ENABLE
}

/// A Generic Address Structure: its space and address.
fn gas(bytes: &[u8], offset: usize) -> Option<(u8, u64)> {
    let field = bytes.get(offset..offset + GAS_BYTES)?;
    Some((field[0], get_le64(field, 4)?))
}

/// An I/O port block: the X_ field when present, else the 32-bit one
/// (none for a register only the extended form gives).
fn port(fadt: &[u8], legacy: Option<usize>, extended: usize) -> Result<Option<u16>> {
    let address = match gas(fadt, extended) {
        Some((SYSTEM_IO, address)) if address != 0 => address,
        Some((_, address)) if address != 0 => {
            return Err(refuse!("an ACPI register block outside system I/O space"));
        }
        _ => legacy
            .and_then(|legacy| get_le32(fadt, legacy))
            .map_or(0, u64::from),
    };
    match address {
        0 => Ok(None),
        address => u16::try_from(address)
            .map(Some)
            .map_err(|_| refuse!("an ACPI register block above the I/O space")),
    }
}

fn reset_register(fadt: &[u8]) -> Result<Option<(ResetRegister, u8)>> {
    if get_le32(fadt, FLAGS).unwrap_or(0) & RESET_SUPPORTED == 0 {
        return Ok(None);
    }
    let (Some((space, address)), Some(&value)) = (gas(fadt, RESET_REGISTER), fadt.get(RESET_VALUE))
    else {
        return Ok(None);
    };
    let register = match space {
        SYSTEM_IO => ResetRegister::Io(
            u16::try_from(address).map_err(|_| refuse!("a reset register above the I/O space"))?,
        ),
        PCI_CONFIGURATION => ResetRegister::PciConfiguration {
            device: u8::try_from(address >> 32 & 0xffff)
                .ok()
                .filter(|device| *device < 32)
                .ok_or(refuse!("a PCI reset register device above 31"))?,
            function: u8::try_from(address >> 16 & 0xffff)
                .ok()
                .filter(|function| *function < 8)
                .ok_or(refuse!("a PCI reset register function above 7"))?,
            offset: u8::try_from(address & 0xffff)
                .map_err(|_| refuse!("a PCI reset register past configuration header space"))?,
        },
        SYSTEM_MEMORY => return Err(refuse!("a memory-space reset register")),
        _ => return Err(refuse!("a reset register in an unmodeled address space")),
    };
    Ok(Some((register, value)))
}

/// The FADT's power hardware, and the DSDT's physical address.
pub fn fadt(table: &[u8]) -> Result<(HostPower, u64), AcpiError> {
    const BAD: AcpiError = AcpiError::BadTable(*b"FACP");
    if table.len() < RESET_REGISTER || &table[..4] != b"FACP" {
        return Err(BAD);
    }
    let flags = get_le32(table, FLAGS).ok_or(BAD)?;
    let mut power = HostPower::default();
    let mut refuse = |reason: Refusal| {
        power.refused.get_or_insert(reason);
    };
    let dsdt = match get_le64(table, X_DSDT) {
        Some(address) if address != 0 => address,
        _ => u64::from(get_le32(table, DSDT).ok_or(BAD)?),
    };
    let mut reset = None;
    match reset_register(table) {
        Ok(found) => reset = found,
        Err(reason) => refuse(reason),
    }
    let mut pm1 = [None; 2];
    let mut event_bytes = 0;
    let mut sleep_registers = None;
    if flags & HARDWARE_REDUCED != 0 {
        match (
            port(table, None, SLEEP_CONTROL),
            port(table, None, SLEEP_STATUS),
        ) {
            (Ok(Some(control)), Ok(Some(status))) => {
                sleep_registers = Some(SleepRegisters { control, status });
            }
            (Ok(_), Ok(_)) => refuse(refuse!(
                "a hardware-reduced platform without sleep registers"
            )),
            (Err(reason), _) | (_, Err(reason)) => refuse(reason),
        }
    } else {
        event_bytes = table[PM1_EVENT_LENGTH];
        let blocks = [
            (PM1A_EVENT, X_PM1A_EVENT, PM1A_CONTROL, X_PM1A_CONTROL),
            (PM1B_EVENT, X_PM1B_EVENT, PM1B_CONTROL, X_PM1B_CONTROL),
        ];
        for (slot, (event, x_event, control, x_control)) in pm1.iter_mut().zip(blocks) {
            match (
                port(table, Some(event), x_event),
                port(table, Some(control), x_control),
            ) {
                (Ok(Some(event)), Ok(Some(control))) => *slot = Some(Pm1 { event, control }),
                (Ok(_), Ok(_)) => {}
                (Err(reason), _) | (_, Err(reason)) => refuse(reason),
            }
        }
        if pm1[0].is_none() {
            pm1 = [None; 2];
            refuse(refuse!("no PM1a event and control blocks"));
        } else if event_bytes < 4 || event_bytes % 2 != 0 {
            pm1 = [None; 2];
            refuse(refuse!(
                "a PM1 event block shorter than its status and enable registers"
            ));
        }
    }
    let mut gpe = [None; 2];
    let blocks = [
        (GPE0_BLOCK, X_GPE0_BLOCK, GPE0_BLOCK_LENGTH),
        (GPE1_BLOCK, X_GPE1_BLOCK, GPE1_BLOCK_LENGTH),
    ];
    for (slot, (legacy, extended, length)) in gpe.iter_mut().zip(blocks) {
        let bytes = table.get(length).copied().unwrap_or(0);
        match port(table, Some(legacy), extended) {
            Ok(Some(port)) if bytes != 0 && bytes % 2 == 0 => *slot = Some(Gpe { port, bytes }),
            Ok(Some(_)) => refuse(refuse!("a GPE block of no whole status and enable halves")),
            Ok(None) => {}
            Err(reason) => refuse(reason),
        }
    }
    let power = HostPower {
        pm1,
        pm1_event_bytes: event_bytes,
        reset,
        fixed_power_button: pm1[0].is_some() && flags & CONTROL_METHOD_POWER_BUTTON == 0,
        gpe,
        sleep_registers,
        ..power
    };
    Ok((power, dsdt))
}

/// One AML integer constant at the start of `bytes`, and its length.
fn integer(bytes: &[u8]) -> Option<(u64, usize)> {
    match *bytes.first()? {
        ZERO_OP => Some((0, 1)),
        ONE_OP => Some((1, 1)),
        BYTE_PREFIX => Some((u64::from(*bytes.get(1)?), 2)),
        WORD_PREFIX => Some((
            u64::from(u16::from_le_bytes(bytes.get(1..3)?.try_into().ok()?)),
            3,
        )),
        DWORD_PREFIX => Some((u64::from(get_le32(bytes, 1)?), 5)),
        _ => None,
    }
}

/// SLP_TYPa and SLP_TYPb of `\_S5` in a DSDT, when it is a static package
/// (`Name (_S5, Package () { a, b, ... })`); an `_S5` method or any other
/// form needs an AML interpreter and gives `None`.
pub fn soft_off(dsdt: &[u8]) -> Option<(u8, u8)> {
    let body = dsdt.get(HEADER..)?;
    let at = body.windows(4).enumerate().find_map(|(at, name)| {
        let named = match at.checked_sub(1).map(|before| body[before]) {
            Some(NAME_OP) => true,
            Some(ROOT_CHAR) => at.checked_sub(2).map(|before| body[before]) == Some(NAME_OP),
            _ => false,
        };
        (name == b"_S5_" && named && body.get(at + 4) == Some(&PACKAGE_OP)).then_some(at + 5)
    })?;
    // PkgLength: bits 7:6 of the lead byte count the bytes that follow.
    let lead = *body.get(at)?;
    let mut cursor = at + 1 + usize::from(lead >> 6);
    let elements = *body.get(cursor)?;
    cursor += 1;
    let mut values = [0u8; 2];
    for value in values.iter_mut().take(usize::from(elements.min(2))) {
        let (number, length) = integer(body.get(cursor..)?)?;
        *value = u8::try_from(number).ok().filter(|&kind| kind <= 7)?;
        cursor += length;
    }
    match elements {
        0 => None,
        1 => Some((values[0], values[0])),
        _ => Some((values[0], values[1])),
    }
}

/// The host's power hardware from its ACPI tables.
///
/// # Safety
///
/// `rsdp` must be the firmware's RSDP, with every table it reaches mapped.
pub unsafe fn discover(rsdp: u64) -> Result<HostPower, AcpiError> {
    // SAFETY: the caller's contract.
    let (mut power, dsdt) = fadt(unsafe { acpi::find(rsdp, b"FACP")? })?;
    if power.pm1[0].is_some() || power.sleep_registers.is_some() {
        // SAFETY: the FADT's DSDT, under the caller's contract.
        match unsafe { acpi::table(dsdt) }.ok().and_then(soft_off) {
            Some(types) => power.soft_off = Some(types),
            None => {
                power
                    .refused
                    .get_or_insert(refuse!("no static \\_S5 package in the DSDT"));
            }
        }
    }
    Ok(power)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// A 276-byte FADT with QEMU q35's power hardware.
    fn q35() -> Vec<u8> {
        let mut table = vec![0u8; 276];
        table[..4].copy_from_slice(b"FACP");
        table[DSDT..DSDT + 4].copy_from_slice(&0x7fe0_0000u32.to_le_bytes());
        table[GPE0_BLOCK..GPE0_BLOCK + 4].copy_from_slice(&0x620u32.to_le_bytes());
        table[GPE0_BLOCK_LENGTH] = 16;
        table[PM1A_EVENT..PM1A_EVENT + 4].copy_from_slice(&0x600u32.to_le_bytes());
        table[PM1A_CONTROL..PM1A_CONTROL + 4].copy_from_slice(&0x604u32.to_le_bytes());
        table[PM1_EVENT_LENGTH] = 4;
        table[FLAGS..FLAGS + 4].copy_from_slice(&(RESET_SUPPORTED | 1 << 5).to_le_bytes());
        table[RESET_REGISTER] = SYSTEM_IO;
        table[RESET_REGISTER + 4..RESET_REGISTER + 12].copy_from_slice(&0xcf9u64.to_le_bytes());
        table[RESET_VALUE] = 0x06;
        table
    }

    /// Ports as a map of words, recording every write in order; a write
    /// of ones to a PM1 status register clears those bits.
    #[derive(Default)]
    struct Board {
        words: alloc::collections::BTreeMap<u16, u16>,
        status: Vec<u16>,
        writes: Vec<(u16, u16)>,
        flushes: usize,
    }

    impl Ports for Board {
        fn in8(&mut self, port: u16) -> u8 {
            self.in16(port) as u8
        }
        fn out8(&mut self, port: u16, value: u8) {
            self.out16(port, u16::from(value));
        }
        fn in16(&mut self, port: u16) -> u16 {
            self.words.get(&port).copied().unwrap_or(0)
        }
        fn out16(&mut self, port: u16, value: u16) {
            self.writes.push((port, value));
            let word = self.words.entry(port).or_default();
            if self.status.contains(&port) {
                *word &= !value;
            } else {
                *word = value;
            }
        }
        fn flush_caches(&mut self) {
            self.flushes += 1;
            self.writes.push((0, 0));
        }
    }

    #[test]
    fn a_press_is_read_once_from_the_status_and_only_in_acpi_mode_is_it_ours() {
        let (power, _) = fadt(&q35()).unwrap();
        let mut board = Board {
            status: vec![0x600],
            ..Board::default()
        };
        assert!(!power.acpi_mode(&mut board));
        board.words.insert(0x604, SCI_ENABLE);
        assert!(power.acpi_mode(&mut board));
        assert!(!power.take_power_button(&mut board));
        assert!(board.writes.is_empty());
        // The button's bit beside the timer's, which stays.
        board.words.insert(0x600, POWER_BUTTON | 1);
        assert!(power.take_power_button(&mut board));
        assert_eq!(board.words[&0x600], 1);
        assert!(!power.take_power_button(&mut board));
        // No PM1 block, as a FADT without one leaves it: never ACPI mode.
        assert!(!HostPower::default().acpi_mode(&mut board));
    }

    #[test]
    fn soft_off_quiets_every_event_then_writes_the_type_before_the_enable() {
        let (mut power, _) = fadt(&q35()).unwrap();
        let mut board = Board::default();
        board.words.insert(0x604, SCI_ENABLE);
        power.enter_soft_off(&mut board, (5, 0));
        let gpe: Vec<(u16, u16)> = (0..8)
            .flat_map(|i| [(0x628 + i, 0), (0x620 + i, 0xff)])
            .collect();
        assert_eq!(board.writes[..16], gpe[..]);
        assert_eq!(
            board.writes[16..],
            [
                (0x600, ALL_FIXED_STATUS),
                (0x604, SCI_ENABLE | 5 << 10),
                (0, 0),
                (0x604, SCI_ENABLE | 5 << 10 | 1 << 13),
            ]
        );
        // A hardware-reduced platform's sleep registers take it instead.
        power.sleep_registers = Some(SleepRegisters {
            control: 0x700,
            status: 0x701,
        });
        power.gpe = [None; 2];
        let mut board = Board::default();
        power.enter_soft_off(&mut board, (5, 0));
        assert_eq!(
            board.writes,
            [
                (0x600, ALL_FIXED_STATUS),
                (0x701, u16::from(SLEEP_WAKE_STATUS)),
                (0, 0),
                (0x700, u16::from(sleep_register_control(5))),
            ]
        );
    }

    #[test]
    fn a_fadt_names_its_pm1_blocks_reset_register_and_button() {
        let (power, dsdt) = fadt(&q35()).unwrap();
        assert_eq!(dsdt, 0x7fe0_0000);
        let pm1a = Pm1 {
            event: 0x600,
            control: 0x604,
        };
        assert_eq!(power.pm1, [Some(pm1a), None]);
        assert_eq!(power.enable_port(pm1a), 0x602);
        assert_eq!(power.reset, Some((ResetRegister::Io(0xcf9), 6)));
        assert!(power.fixed_power_button);
        let gpe0 = Gpe {
            port: 0x620,
            bytes: 16,
        };
        assert_eq!(power.gpe, [Some(gpe0), None]);
        let registers: Vec<_> = gpe0.registers().collect();
        assert_eq!(registers.len(), 8);
        assert_eq!(
            (registers[0], registers[7]),
            ((0x620, 0x628), (0x627, 0x62f))
        );
        assert_eq!(power.sleep_registers, None);
        assert_eq!(power.refused, None);
    }

    #[test]
    fn extended_blocks_win_and_unsupported_forms_are_refused() {
        let mut table = q35();
        table[X_PM1A_EVENT] = SYSTEM_IO;
        table[X_PM1A_EVENT + 4..X_PM1A_EVENT + 12].copy_from_slice(&0x1800u64.to_le_bytes());
        table[X_PM1A_CONTROL] = SYSTEM_IO;
        table[X_PM1A_CONTROL + 4..X_PM1A_CONTROL + 12].copy_from_slice(&0x1804u64.to_le_bytes());
        table[RESET_REGISTER] = PCI_CONFIGURATION;
        table[RESET_REGISTER + 4..RESET_REGISTER + 12]
            .copy_from_slice(&(0x1f_u64 << 32 | 3 << 16 | 0xac).to_le_bytes());
        let (power, _) = fadt(&table).unwrap();
        assert_eq!(power.pm1[0].unwrap().event, 0x1800);
        assert_eq!(
            power.reset.unwrap().0,
            ResetRegister::PciConfiguration {
                device: 0x1f,
                function: 3,
                offset: 0xac
            }
        );
        table[RESET_REGISTER] = SYSTEM_MEMORY;
        table[X_PM1A_CONTROL] = SYSTEM_MEMORY;
        let (power, _) = fadt(&table).unwrap();
        assert_eq!(power.reset, None);
        assert_eq!(power.pm1, [None, None]);
        assert!(!power.fixed_power_button);
        assert_eq!(
            power.refused,
            Some(refuse!("a memory-space reset register"))
        );
        // A control-method button and a hardware-reduced platform.
        let mut table = q35();
        table[FLAGS] |= CONTROL_METHOD_POWER_BUTTON as u8;
        assert!(!fadt(&table).unwrap().0.fixed_power_button);
        table[FLAGS + 2] |= (HARDWARE_REDUCED >> 16) as u8;
        let (power, _) = fadt(&table).unwrap();
        assert_eq!(power.pm1, [None, None]);
        assert!(power.reset.is_some());
        assert_eq!(
            power.refused,
            Some(refuse!(
                "a hardware-reduced platform without sleep registers"
            ))
        );
        // Its sleep registers, in I/O space.
        for (offset, address) in [(SLEEP_CONTROL, 0x404u64), (SLEEP_STATUS, 0x400)] {
            table[offset] = SYSTEM_IO;
            table[offset + 4..offset + 12].copy_from_slice(&address.to_le_bytes());
        }
        let (power, _) = fadt(&table).unwrap();
        assert_eq!(
            power.sleep_registers,
            Some(SleepRegisters {
                control: 0x404,
                status: 0x400
            })
        );
        assert_eq!(power.refused, None);
        assert!(fadt(&table[..100]).is_err());
    }

    fn dsdt(body: &[u8]) -> Vec<u8> {
        let mut table = vec![0u8; HEADER];
        table[..4].copy_from_slice(b"DSDT");
        table.extend_from_slice(body);
        table
    }

    #[test]
    fn s5_sleep_types_come_from_a_static_package() {
        // QEMU: Name (_S5, Package (0x04) { Zero, Zero, Zero, Zero }).
        let qemu = dsdt(&[
            0x10, 0x08, b'_', b'S', b'5', b'_', 0x12, 0x06, 0x04, 0, 0, 0, 0,
        ]);
        assert_eq!(soft_off(&qemu), Some((0, 0)));
        // A rooted name with byte constants and a two-byte PkgLength.
        let board = dsdt(&[
            0x08, b'\\', b'_', b'S', b'5', b'_', 0x12, 0x40, 0x01, 0x02, 0x0a, 0x07, 0x0a, 0x05,
        ]);
        assert_eq!(soft_off(&board), Some((7, 5)));
        let single = dsdt(&[0x08, b'_', b'S', b'5', b'_', 0x12, 0x03, 0x01, 0x01]);
        assert_eq!(soft_off(&single), Some((1, 1)));
        // A method, an out-of-range type and a bare string are not taken.
        let method = dsdt(&[0x14, 0x08, b'_', b'S', b'5', b'_', 0x00, 0xa4, 0x00]);
        assert_eq!(soft_off(&method), None);
        let wide = dsdt(&[0x08, b'_', b'S', b'5', b'_', 0x12, 0x04, 0x01, 0x0a, 0x09]);
        assert_eq!(soft_off(&wide), None);
        assert_eq!(soft_off(&dsdt(b"_S5_")), None);
    }

    #[test]
    fn sleep_control_keeps_other_bits() {
        assert_eq!(
            sleep_control(SCI_ENABLE | 0x1c00, 5),
            SCI_ENABLE | 5 << 10 | 1 << 13
        );
        assert_eq!(sleep_control(0, 0), 1 << 13);
        // The type alone first, as Linux writes it.
        assert_eq!(
            sleep_type_control(SCI_ENABLE | 1 << 13, 5),
            SCI_ENABLE | 5 << 10
        );
        assert_eq!(sleep_register_control(5), 5 << 2 | 1 << 5);
    }
}
