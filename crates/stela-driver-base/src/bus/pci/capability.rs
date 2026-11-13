//! Capability-list walks of one function's configuration space: the standard
//! list from the Capabilities Pointer (0x34) and the PCI Express extended list
//! from 0x100. Each walk checks alignment, range, cycles and body overlap once;
//! a headers walk of the standard list reserves only each entry's header, for
//! a driver that reads no body the walk would size.
//!
//! Register layouts and sizes follow Linux include/uapi/linux/pci_regs.h
//! (`PCI_CAP_*_SIZEOF`, `PCI_EXT_CAP_*_SIZEOF`). A pointer with its reserved
//! low two bits set ends the walk.
//!
//! A census walk ([`Capabilities::census`], [`ExtendedCapabilities::census`])
//! is Linux's instead (`__pci_find_next_cap_ttl`,
//! `pci_find_next_ext_capability`), for the boot's census of every function,
//! where one odd list must not refuse the PC: it masks a pointer's low two
//! bits, and a pointer below the list's region, a revisit (Linux's TTL is the
//! region's dword count), a standard ID of 0xff or an extended header of zero
//! or all ones ends the list quietly. It sizes only the bodies the census
//! writes (MSI, MSI-X and PCI Express; ATS, PASID and PRI) and walks a
//! header inside another body. A sized body past the region or over another
//! entry reserves only its header, as [`Layout::Unsupported`], for the code
//! acting on it to refuse. Only a failed configuration read is an error.
use super::ConfigSpace;
use super::regs;

const STANDARD_START: u16 = 0x40;
const STANDARD_END: u16 = 0x100;
const EXTENDED_START: u16 = 0x100;
const EXTENDED_END: u16 = 0x1000;

/// Why a walk stopped. Each variant carries the offset of the entry at fault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityError {
    Config {
        offset: u16,
        error: super::ConfigError,
    },
    /// A header, or a register sizing it, read as all ones.
    FailedRead { offset: u16 },
    /// A pointer with its reserved low two bits set.
    Misaligned { offset: u16 },
    /// A pointer outside the list's region, or a body past its end.
    OutOfRange { offset: u16 },
    /// A pointer back to an entry already visited.
    Cycle { offset: u16 },
    /// A header inside an earlier entry's body, or a body over an earlier header.
    Overlap { offset: u16 },
    /// A reserved ID (0xff in the standard list, 0 after the first extended
    /// entry) or a length field below its header's size.
    Malformed { offset: u16 },
}

/// A plain account for the boot log.
impl core::fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Config { offset, error } => {
                write!(f, "its capability at {offset:#x} did not read ({error})")
            }
            Self::FailedRead { offset } => {
                write!(f, "its capability at {offset:#x} reads all ones")
            }
            Self::Misaligned { offset } => {
                write!(f, "its capability list points off alignment at {offset:#x}")
            }
            Self::OutOfRange { offset } => {
                write!(f, "its capability at {offset:#x} lies outside its list")
            }
            Self::Cycle { offset } => write!(f, "its capability list loops at {offset:#x}"),
            Self::Overlap { offset } => {
                write!(f, "its capability at {offset:#x} overlaps another")
            }
            Self::Malformed { offset } => write!(f, "its capability at {offset:#x} is malformed"),
        }
    }
}

impl CapabilityError {
    pub fn offset(&self) -> u16 {
        match *self {
            Self::Config { offset, .. } => offset,
            Self::FailedRead { offset }
            | Self::Misaligned { offset }
            | Self::OutOfRange { offset }
            | Self::Cycle { offset }
            | Self::Overlap { offset }
            | Self::Malformed { offset } => offset,
        }
    }
}

/// How much of an entry's body the walk sized and reserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Layout {
    /// The complete body from its ID's register layout.
    Sized,
    /// An ID without a layout here: only its header is reserved.
    Header,
    /// A known ID whose version or variant has no layout here: only its
    /// header is reserved.
    Unsupported,
}

/// One entry of the standard capability list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capability {
    pub offset: u16,
    pub id: u8,
    /// The ID and next-pointer word.
    pub header: u16,
    /// The bytes reserved from `offset`: the body for [`Layout::Sized`], the
    /// two header bytes otherwise.
    pub bytes: u16,
    pub layout: Layout,
}

/// One entry of the PCI Express extended capability list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtendedCapability {
    pub offset: u16,
    pub id: u16,
    pub version: u8,
    pub header: u32,
    /// The bytes reserved from `offset`: the body for [`Layout::Sized`], the
    /// four header bytes otherwise.
    pub bytes: u16,
    pub layout: Layout,
}

impl Capability {
    /// The bytes this entry reserves.
    pub fn span(&self) -> core::ops::Range<u16> {
        self.offset..self.offset + self.bytes
    }
}

impl ExtendedCapability {
    /// The bytes this entry reserves.
    pub fn span(&self) -> core::ops::Range<u16> {
        self.offset..self.offset + self.bytes
    }
}

/// The first of `spans` other than the one starting at `offset` that meets
/// `offset..offset + bytes`: sizes a body the walk reserved only the header of.
pub fn overlap(
    spans: impl IntoIterator<Item = core::ops::Range<u16>>,
    offset: u16,
    bytes: u16,
) -> Option<u16> {
    let end = offset.saturating_add(bytes);
    spans
        .into_iter()
        .find(|span| span.start != offset && span.start < end && offset < span.end)
        .map(|span| span.start)
}

/// Configuration reads for a walk: `bytes` is 1, 2 or 4.
pub trait CapabilityRead {
    type Error: From<CapabilityError>;
    fn read(&mut self, offset: u16, bytes: u8) -> Result<u32, Self::Error>;
}

/// Walks through a [`ConfigSpace`].
pub struct Config<'a, C: ?Sized>(pub &'a C);

impl<C: ConfigSpace + ?Sized> CapabilityRead for Config<'_, C> {
    type Error = CapabilityError;
    fn read(&mut self, offset: u16, bytes: u8) -> Result<u32, CapabilityError> {
        match bytes {
            1 => self.0.read8(offset).map(u32::from),
            2 => self.0.read16(offset).map(u32::from),
            _ => self.0.read32(offset),
        }
        .map_err(|error| CapabilityError::Config { offset, error })
    }
}

/// Walks through a fallible transport, such as a bridge's indirect window.
pub struct Transport<F>(pub F);

impl<F, E> CapabilityRead for Transport<F>
where
    F: FnMut(u16, u8) -> Result<u32, E>,
    E: From<CapabilityError>,
{
    type Error = E;
    fn read(&mut self, offset: u16, bytes: u8) -> Result<u32, E> {
        (self.0)(offset, bytes)
    }
}

/// The standard capability list of `config`.
pub fn capabilities<C: ConfigSpace + ?Sized>(config: &C) -> Capabilities<Config<'_, C>> {
    Capabilities::new(Config(config))
}

/// The standard capability list of `config`, reserving only each header: the
/// caller sizes and checks the bodies it reads with [`overlap`].
pub fn capability_headers<C: ConfigSpace + ?Sized>(config: &C) -> Capabilities<Config<'_, C>> {
    Capabilities {
        bodies: false,
        ..Capabilities::new(Config(config))
    }
}

/// The extended capability list of `config`.
pub fn extended_capabilities<C: ConfigSpace + ?Sized>(
    config: &C,
) -> ExtendedCapabilities<Config<'_, C>> {
    ExtendedCapabilities::new(Config(config))
}

/// Whether `config`'s standard list is well formed, with power management in
/// D0 and MSI and MSI-X disabled: a stopped function's interrupt and power state.
pub fn stopped_in_d0<C: ConfigSpace + ?Sized>(config: &C) -> Result<bool, CapabilityError> {
    for entry in capabilities(config) {
        let entry = entry?;
        let control = config
            .read16(entry.offset + 2)
            .map_err(|error| CapabilityError::Config {
                offset: entry.offset + 2,
                error,
            })?;
        if control == u16::MAX {
            return Ok(false);
        }
        let stopped = match entry.id {
            0x01 => {
                config
                    .read16(entry.offset + 4)
                    .map_err(|error| CapabilityError::Config {
                        offset: entry.offset + 4,
                        error,
                    })?
                    & 3
                    == 0
            }
            0x05 => control & 1 == 0,
            0x11 => control & (1 << 15) == 0,
            _ => true,
        };
        if !stopped {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Dword cells of one list's region: visited headers and reserved bytes.
#[derive(Clone, Copy)]
struct Cells<const N: usize> {
    headers: [u64; N],
    reserved: [u64; N],
}

impl<const N: usize> Cells<N> {
    const EMPTY: Self = Self {
        headers: [0; N],
        reserved: [0; N],
    };

    fn get(bits: &[u64; N], cell: usize) -> bool {
        bits[cell / 64] & (1 << (cell % 64)) != 0
    }

    /// Reserve `bytes` from `offset`, relative to the region's `base`.
    fn reserve(&mut self, base: u16, offset: u16, bytes: u16) -> Result<(), CapabilityError> {
        let first = usize::from((offset - base) / 4);
        let last = usize::from((offset - base + bytes).div_ceil(4));
        if (first..last).any(|cell| Self::get(&self.reserved, cell)) {
            return Err(CapabilityError::Overlap { offset });
        }
        for cell in first..last {
            self.reserved[cell / 64] |= 1 << (cell % 64);
        }
        Ok(())
    }

    /// Record a header at `offset`, refusing one already visited, or one
    /// inside reserved bytes unless `inside` allows it.
    fn visit(&mut self, base: u16, offset: u16, inside: bool) -> Result<(), CapabilityError> {
        let cell = usize::from((offset - base) / 4);
        if Self::get(&self.headers, cell) {
            return Err(CapabilityError::Cycle { offset });
        }
        if !inside && Self::get(&self.reserved, cell) {
            return Err(CapabilityError::Overlap { offset });
        }
        self.headers[cell / 64] |= 1 << (cell % 64);
        Ok(())
    }

    /// Reserve an entry of `extent` from `offset` in a census walk. A body
    /// past `end` or over reserved bytes reserves only the `header` bytes,
    /// when they are free, and a sized one becomes [`Layout::Unsupported`].
    fn place(
        &mut self,
        (base, end): (u16, u16),
        offset: u16,
        header: u16,
        (bytes, layout): (u16, Layout),
    ) -> (u16, Layout) {
        if offset + bytes <= end && self.reserve(base, offset, bytes).is_ok() {
            return (bytes, layout);
        }
        let _ = self.reserve(base, offset, header);
        match layout {
            Layout::Sized => (header, Layout::Unsupported),
            layout => (header, layout),
        }
    }
}

#[derive(Clone, Copy)]
enum State {
    Start,
    At(u16),
    Done,
}

/// The standard list, from the Capabilities Pointer; empty without the
/// Status register's Capabilities List bit. The walk ends after its first error.
pub struct Capabilities<R> {
    read: R,
    state: State,
    cells: Cells<1>,
    header_type: Option<u8>,
    /// Whether bodies are sized and reserved, or only headers.
    bodies: bool,
    /// Whether this is a census walk, which ends quietly where Linux's does.
    census: bool,
}

impl<R: CapabilityRead> Capabilities<R> {
    pub fn new(read: R) -> Self {
        Self {
            read,
            state: State::Start,
            cells: Cells::EMPTY,
            header_type: None,
            bodies: true,
            census: false,
        }
    }

    /// A census walk of the standard list (see the module documentation).
    pub fn census(read: R) -> Self {
        Self {
            census: true,
            ..Self::new(read)
        }
    }

    /// A list fault: an error, or in a census the list's quiet end.
    fn fault<T>(&self, error: CapabilityError) -> Result<Option<T>, R::Error> {
        if self.census {
            Ok(None)
        } else {
            Err(error.into())
        }
    }

    /// The flags word at `offset` that sizes a body. All ones is a failed
    /// read, or in a census a body with no layout.
    fn flags(&mut self, offset: u16) -> Result<Option<u16>, R::Error> {
        match self.read.read(offset, 2)? as u16 {
            u16::MAX => self.fault(CapabilityError::FailedRead { offset }),
            flags => Ok(Some(flags)),
        }
    }

    fn read16(&mut self, offset: u16) -> Result<u16, R::Error> {
        let value = self.read.read(offset, 2)? as u16;
        if value == u16::MAX {
            return Err(CapabilityError::FailedRead { offset }.into());
        }
        Ok(value)
    }

    fn first(&mut self) -> Result<Option<u16>, R::Error> {
        if self.read16(regs::STATUS)? & regs::STATUS_CAP_LIST == 0 {
            return Ok(None);
        }
        Ok(Some(
            self.read.read(regs::CAPABILITY_LIST, 1)? as u16 & 0xff,
        ))
    }

    /// The entry at `offset` and its next pointer, or none where a census
    /// ends the list.
    fn entry(&mut self, offset: u16) -> Result<Option<(Capability, u16)>, R::Error> {
        if !offset.is_multiple_of(4) {
            return self.fault(CapabilityError::Misaligned { offset });
        }
        if !(STANDARD_START..STANDARD_END).contains(&offset) {
            return self.fault(CapabilityError::OutOfRange { offset });
        }
        if let Err(error) = self.cells.visit(STANDARD_START, offset, self.census) {
            return self.fault(error);
        }
        let header = self.read.read(offset, 2)? as u16;
        if header == u16::MAX {
            return self.fault(CapabilityError::FailedRead { offset });
        }
        let id = header as u8;
        if id == 0xff {
            return self.fault(CapabilityError::Malformed { offset });
        }
        // A census sizes only the bodies it writes.
        let extent = if !self.bodies || self.census && !matches!(id, 0x05 | 0x10 | 0x11) {
            (2, Layout::Header)
        } else {
            self.extent(offset, id)?
        };
        let (bytes, layout) = if self.census {
            self.cells
                .place((STANDARD_START, STANDARD_END), offset, 2, extent)
        } else {
            if offset + extent.0 > STANDARD_END {
                return Err(CapabilityError::OutOfRange { offset }.into());
            }
            self.cells.reserve(STANDARD_START, offset, extent.0)?;
            extent
        };
        let capability = Capability {
            offset,
            id,
            header,
            bytes,
            layout,
        };
        Ok(Some((capability, header >> 8)))
    }

    /// The body size of capability `id` at `offset` (pci_regs.h).
    fn extent(&mut self, offset: u16, id: u8) -> Result<(u16, Layout), R::Error> {
        let sized = |bytes| Ok((bytes, Layout::Sized));
        let unsupported = Ok((2, Layout::Unsupported));
        match id {
            0x00 => sized(2),  // Null capability
            0x01 => sized(8),  // PCI_PM_SIZEOF
            0x02 => sized(12), // PCI_AGP_SIZEOF
            0x03 => sized(8),  // PCI_CAP_VPD_SIZEOF
            0x04 => sized(4),  // Slot identification
            0x05 => {
                let Some(flags) = self.flags(offset + 2)? else {
                    return unsupported;
                };
                sized(match (flags & 1 << 7 != 0, flags & 1 << 8 != 0) {
                    (false, false) => 10,
                    (true, false) => 14,
                    (false, true) => 20,
                    (true, true) => 24,
                })
            }
            0x07 => {
                if self.header_type()? != 0 {
                    return unsupported;
                }
                match (self.read16(offset + 2)? >> 12) & 3 {
                    0 => sized(8),      // PCI_CAP_PCIX_SIZEOF_V0
                    1 | 2 => sized(24), // PCI_CAP_PCIX_SIZEOF_V2
                    _ => unsupported,
                }
            }
            0x09 => {
                // A vendor-specific body states its own length. One that
                // states less than its three-byte header has no body to
                // size: Intel's PCH xHCI carries such an entry (lspci:
                // "Vendor Specific Information: Len=00"). Linux sizes no
                // vendor body and walks on, so only the header is reserved.
                match self.read.read(offset + 2, 1)? as u16 & 0xff {
                    0..3 => Ok((2, Layout::Header)),
                    bytes => sized(bytes),
                }
            }
            0x0d => sized(8), // Bridge subsystem vendor/device IDs
            0x10 => {
                let Some(flags) = self.flags(offset + 2)? else {
                    return unsupported;
                };
                let kind = (flags >> 4) & 15;
                let root = matches!(kind, 4 | 10);
                let slot = flags & 1 << 8 != 0;
                match flags & 15 {
                    1 if kind == 9 => sized(12), // PCI_CAP_EXP_RC_ENDPOINT_SIZEOF_V1
                    1 if root => sized(0x24),
                    1 if slot => sized(0x1c),
                    1 => sized(0x14),              // PCI_CAP_EXP_ENDPOINT_SIZEOF_V1
                    2 if kind == 9 => sized(0x2c), // PCI_CAP_EXP_RC_ENDPOINT_SIZEOF_V2
                    2 if root || slot => sized(0x3c), // PCI_CAP_EXP_SIZEOF
                    2 => sized(0x34),              // PCI_CAP_EXP_ENDPOINT_SIZEOF_V2
                    _ => unsupported,
                }
            }
            0x11 => sized(12), // PCI_CAP_MSIX_SIZEOF
            0x12 => {
                if offset + 8 > STANDARD_END {
                    return Err(CapabilityError::OutOfRange { offset }.into());
                }
                // PCI_SATA_SIZEOF_SHORT/LONG: a BAR or the inline register block.
                match self.read16(offset + 4)? & 15 {
                    0..=5 => sized(8),
                    15 => sized(16),
                    _ => unsupported,
                }
            }
            0x13 => sized(6), // PCI_CAP_AF_SIZEOF
            _ => Ok((2, Layout::Header)),
        }
    }

    fn header_type(&mut self) -> Result<u8, R::Error> {
        if let Some(kind) = self.header_type {
            return Ok(kind);
        }
        let kind = self.read.read(regs::HEADER_TYPE, 1)? as u8 & 0x7f;
        self.header_type = Some(kind);
        Ok(kind)
    }
}

impl<R: CapabilityRead> Iterator for Capabilities<R> {
    type Item = Result<Capability, R::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let offset = match self.state {
            State::Done => return None,
            State::At(offset) => offset,
            State::Start => match self.first() {
                Ok(Some(offset)) => offset,
                Ok(None) => {
                    self.state = State::Done;
                    return None;
                }
                Err(error) => {
                    self.state = State::Done;
                    return Some(Err(error));
                }
            },
        };
        let offset = if self.census { offset & !3 } else { offset };
        if offset == 0 {
            self.state = State::Done;
            return None;
        }
        match self.entry(offset) {
            Ok(Some((capability, next))) => {
                self.state = State::At(next);
                Some(Ok(capability))
            }
            Ok(None) => {
                self.state = State::Done;
                None
            }
            Err(error) => {
                self.state = State::Done;
                Some(Err(error))
            }
        }
    }
}

/// The extended list from 0x100. A first header of zero or all ones (no
/// extended configuration space) is an empty list.
pub struct ExtendedCapabilities<R> {
    read: R,
    state: State,
    cells: Cells<16>,
    /// Whether this is a census walk, which ends quietly where Linux's does.
    census: bool,
}

impl<R: CapabilityRead> ExtendedCapabilities<R> {
    pub fn new(read: R) -> Self {
        Self {
            read,
            state: State::Start,
            cells: Cells::EMPTY,
            census: false,
        }
    }

    /// A census walk of the extended list (see the module documentation).
    pub fn census(read: R) -> Self {
        Self {
            census: true,
            ..Self::new(read)
        }
    }

    /// A list fault: an error, or in a census the list's quiet end.
    fn fault<T>(&self, error: CapabilityError) -> Result<Option<T>, R::Error> {
        if self.census {
            Ok(None)
        } else {
            Err(error.into())
        }
    }

    /// The entry at `offset` and its next pointer, or none at the list's end.
    fn entry(&mut self, offset: u16) -> Result<Option<(ExtendedCapability, u16)>, R::Error> {
        if !offset.is_multiple_of(4) {
            return self.fault(CapabilityError::Misaligned { offset });
        }
        if !(EXTENDED_START..EXTENDED_END).contains(&offset) {
            return self.fault(CapabilityError::OutOfRange { offset });
        }
        if let Err(error) = self.cells.visit(EXTENDED_START, offset, self.census) {
            return self.fault(error);
        }
        // Linux `pci_cfg_space_size`: only a PCI Express or PCI-X function
        // has configuration space past 0xff. A conventional function read
        // there through ECAM may answer with its first 256 bytes again, as
        // an Intel PCH's SMBus does, which is no capability list.
        if offset == EXTENDED_START && !self.has_extended_space()? {
            return Ok(None);
        }
        let header = self.read.read(offset, 4)?;
        if offset == EXTENDED_START && matches!(header, 0 | u32::MAX) {
            return Ok(None);
        }
        if header == u32::MAX {
            return self.fault(CapabilityError::FailedRead { offset });
        }
        // ID 0 with a version or a next pointer is a null entry, which only
        // passes the walk on: how a hypervisor hides the list's first entry,
        // whose offset is fixed, and what Linux's walk skips.
        let id = header as u16;
        if header == 0 {
            return self.fault(CapabilityError::Malformed { offset });
        }
        // A census sizes only the bodies it writes: ATS, PRI and PASID.
        let (bytes, layout) = if self.census {
            let extent = match id {
                0x0f | 0x13 | 0x1b => self.extent(offset, id)?,
                _ => (4, Layout::Header),
            };
            self.cells
                .place((EXTENDED_START, EXTENDED_END), offset, 4, extent)
        } else {
            let (bytes, layout) = self.extent(offset, id)?;
            if offset + bytes > EXTENDED_END {
                return Err(CapabilityError::OutOfRange { offset }.into());
            }
            self.cells.reserve(EXTENDED_START, offset, bytes)?;
            (bytes, layout)
        };
        let capability = ExtendedCapability {
            offset,
            id,
            version: ((header >> 16) & 15) as u8,
            header,
            bytes,
            layout,
        };
        Ok(Some((capability, (header >> 20) as u16)))
    }

    /// Whether the standard list holds a PCI Express or a PCI-X capability.
    /// The list's own faults are the standard walk's to report: a pointer
    /// outside the list or a list longer than its space ends the search.
    fn has_extended_space(&mut self) -> Result<bool, R::Error> {
        const STATUS: u16 = 0x06;
        const STATUS_CAPABILITIES: u32 = 1 << 4;
        const POINTER: u16 = 0x34;
        if self.read.read(STATUS, 2)? & STATUS_CAPABILITIES == 0 {
            return Ok(false);
        }
        let mut offset = self.read.read(POINTER, 1)? as u16 & !3;
        for _ in 0..48 {
            if !(0x40..0x100).contains(&offset) {
                break;
            }
            let header = self.read.read(offset, 2)?;
            if matches!(header as u8, 0x07 | 0x10) {
                return Ok(true);
            }
            offset = (header >> 8) as u16 & !3;
        }
        Ok(false)
    }

    /// The body size of extended capability `id` at `offset` (pci_regs.h).
    fn extent(&mut self, offset: u16, id: u16) -> Result<(u16, Layout), R::Error> {
        let sized = |bytes| Ok((bytes, Layout::Sized));
        match id {
            0x03 => sized(12), // PCI_EXT_CAP_DSN_SIZEOF
            0x04 => sized(16), // PCI_EXT_CAP_PWR_SIZEOF
            0x0b | 0x23 => {
                // Vendor-specific and designated vendor-specific: the length
                // in bits 31:20 of the second dword.
                let minimum = if id == 0x0b { 8 } else { 10 };
                if offset + 8 > EXTENDED_END {
                    return Err(CapabilityError::OutOfRange { offset }.into());
                }
                let second = self.read.read(offset + 4, 4)?;
                if second == u32::MAX {
                    return Err(CapabilityError::FailedRead { offset: offset + 4 }.into());
                }
                let bytes = (second >> 20) as u16;
                if bytes < minimum {
                    return Err(CapabilityError::Malformed { offset }.into());
                }
                sized(bytes)
            }
            0x0e => sized(8),  // PCI_EXT_CAP_ARI_SIZEOF
            0x0f => sized(8),  // PCI_EXT_CAP_ATS_SIZEOF
            0x13 => sized(16), // PCI_EXT_CAP_PRI_SIZEOF
            0x18 => sized(8),  // PCI_EXT_CAP_LTR_SIZEOF
            0x1b => sized(8),  // PCI_EXT_CAP_PASID_SIZEOF
            0x1e => sized(16), // L1 PM Substates: capability, control 1 and 2
            0x1f => sized(12), // PCI_EXT_CAP_PTM_SIZEOF
            _ => Ok((4, Layout::Header)),
        }
    }
}

impl<R: CapabilityRead> Iterator for ExtendedCapabilities<R> {
    type Item = Result<ExtendedCapability, R::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let offset = match self.state {
            State::Done => return None,
            State::Start => EXTENDED_START,
            State::At(0) => {
                self.state = State::Done;
                return None;
            }
            State::At(offset) if self.census => offset & !3,
            State::At(offset) => offset,
        };
        match self.entry(offset) {
            Ok(Some((capability, next))) => {
                self.state = State::At(next);
                Some(Ok(capability))
            }
            Ok(None) => {
                self.state = State::Done;
                None
            }
            Err(error) => {
                self.state = State::Done;
                Some(Err(error))
            }
        }
    }
}

#[cfg(test)]
mod tests;
