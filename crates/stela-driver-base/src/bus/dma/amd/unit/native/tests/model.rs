use super::*;
use crate::bus::{
    dma::memory::{PageBacking, PageGeometry},
    mmio::owned::{
        AddressSpace, Authority, Error as MapError, InstalledMapping, MapFailure, MapRequest,
        MappingPlatform, PhysicalSpan, Protection, Resource, ResourceBacking, ResourceKind,
    },
    pci::{
        Address, ConfigSpace, Function,
        owned::{
            OwnedConfig,
            test_support::{Counters, fixture},
        },
    },
};
use alloc::{
    alloc::{Layout, alloc_zeroed, dealloc},
    boxed::Box,
    sync::Arc,
};
use std::{collections::BTreeMap, sync::Mutex};

pub(super) const ADDRESS: Address = Address {
    segment: 0x1234,
    bus: 0,
    device: 0,
    function: 2,
};
const BASE: u64 = 0xfed8_0000;
const SPACE: AddressSpace = AddressSpace {
    identity: 91,
    physical_bits: 48,
    virtual_bits: 48,
};
const PHYSICAL: u64 = 0x000f_ffff_ffff_f000;
pub(super) const FEATURES: u64 = (1 << 6) | (1 << 8);

struct Registers {
    cpu: NonNull<u8>,
    request: Mutex<Option<MapRequest>>,
}
// SAFETY: fixture raw CPU bytes only; synchronous peer access never overlaps
// another writer. The registry keeps the allocation through all views.
unsafe impl Send for Registers {}
// SAFETY: immutable metadata, locked registry bookkeeping, raw-only CPU access.
unsafe impl Sync for Registers {}
impl Registers {
    fn read(&self, offset: usize) -> u64 {
        assert!(offset < 16384 && offset.is_multiple_of(8));
        // SAFETY: bounded native-aligned fixture RAM, synchronous peer.
        u64::from_le(unsafe { self.cpu.as_ptr().add(offset).cast::<u64>().read_volatile() })
    }
    fn write(&self, offset: usize, value: u64) {
        assert!(offset < 16384 && offset.is_multiple_of(8));
        // SAFETY: same fixture register allocation; no safe byte aliases.
        unsafe {
            self.cpu
                .as_ptr()
                .add(offset)
                .cast::<u64>()
                .write_volatile(value.to_le())
        };
    }
}
impl Drop for Registers {
    fn drop(&mut self) {
        // SAFETY: exact unique register RAM, every mapping/view has released.
        unsafe {
            dealloc(
                self.cpu.as_ptr(),
                Layout::from_size_align(16384, 4096).unwrap(),
            )
        };
    }
}
// SAFETY: isolated fixture RAM models one UC mapping, never a
// native IOMMU. No claimed cache attributes escape this isolated permission.
unsafe impl MappingPlatform for Registers {
    fn check_context(&self, space: AddressSpace) -> Result<(), MapError> {
        assert_eq!(space, SPACE);
        Ok(())
    }
    unsafe fn map(
        &self,
        _: &Resource,
        request: MapRequest,
    ) -> Result<InstalledMapping, MapFailure> {
        assert!(self.request.lock().unwrap().replace(request).is_none());
        Ok(InstalledMapping {
            token: request.id,
            cpu_base: self.cpu,
            physical: request.physical,
            attribute: request.attribute,
            protection: request.protection,
        })
    }
    unsafe fn unmap(&self, request: MapRequest, _: InstalledMapping) -> Result<(), MapError> {
        assert_eq!(self.request.lock().unwrap().take(), Some(request));
        Ok(())
    }
}
struct RegisterResource(crate::bus::mmio::owned::model::MappingRetention<Arc<Registers>>);
// SAFETY: symbolic device span exclusively belongs to this isolated model.
unsafe impl ResourceBacking for RegisterResource {
    fn begin_mapping(&self) -> Result<crate::bus::pci::assignment::OpaqueUse, MapError> {
        self.0.begin_mapping()
    }

    fn physical_span(&self) -> PhysicalSpan {
        PhysicalSpan::new(BASE, 16384).unwrap()
    }
    fn kind(&self) -> ResourceKind {
        ResourceKind::Registers
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Mode {
    Normal,
    HeadOnly,
    OldStore,
    FutureStore,
    BadHead,
    Halt,
    Event,
    Overflow,
    HardwareError,
    AlterBase,
    StoreBeforeHead,
    /// The IVHD's optional control flag bits read as zero.
    HardwiredFlags,
    /// A control bit no one wrote reads as set.
    ForeignControl,
}
struct State {
    ram: BTreeMap<u64, (usize, usize)>,
    next_pa: u64,
    mode: Mode,
    commands: Vec<[u32; 4]>,
    pending_head: Option<u64>,
    guards: usize,
    enters: usize,
    syncs: usize,
    dte_cache: BTreeMap<u16, [u64; 2]>,
    translations: BTreeMap<(u16, u64), Translation>,
    fail_outer_guard: bool,
    posted: Vec<(u16, u16, u64, u32)>,
}
type Translation = Option<(u64, bool, bool)>;
type Image = (Vec<u64>, Vec<(u64, Vec<u8>)>);
/// Cloneable device/data peer only; no affine MMIO assignment controller.
#[derive(Clone)]
pub(super) struct DevicePeer {
    registers: Arc<Registers>,
    state: Arc<Mutex<State>>,
}
pub(super) struct Platform {
    peer: DevicePeer,
}
/// Actual external fixture scope. Native Unit::retire intentionally retires
/// walker RAM only, not its PCI mappings; default scope loss therefore keeps
/// the original register allocation/count instead of claiming complete cleanup.
pub(super) struct Peer {
    inner: DevicePeer,
    _mapping_owner: crate::bus::mmio::owned::model::MappingOwner<Arc<Registers>>,
}
impl core::ops::Deref for Peer {
    type Target = DevicePeer;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
struct Ram {
    cpu: NonNull<u8>,
    layout: Layout,
    physical: Vec<u64>,
    state: Arc<Mutex<State>>,
}
// SAFETY: uniquely owned aligned RAM; metadata immutable, bookkeeping
// locked. Raw accesses obey normal caller CPU/device ownership requirements.
unsafe impl Send for Ram {}
// SAFETY: exposes immutable metadata/raw pointers; no safe byte references.
unsafe impl Sync for Ram {}
// SAFETY: CPU allocation keeps the exact immutable symbolic native
// page list; labels differ from CPU pointers and never reach HW.
unsafe impl PageBacking for Ram {
    fn cpu_base(&self) -> NonNull<u8> {
        self.cpu
    }
    fn physical_pages(&self) -> &[u64] {
        &self.physical
    }
    fn page_shift(&self) -> u8 {
        12
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}
impl Drop for Ram {
    fn drop(&mut self) {
        assert!(
            self.state
                .lock()
                .unwrap()
                .ram
                .remove(&self.physical[0])
                .is_some()
        );
        // SAFETY: exact unique backing after every pin/view has released.
        unsafe { dealloc(self.cpu.as_ptr(), self.layout) };
    }
}
pub(super) struct Guard<'a>(&'a Platform);
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        let fail = {
            let mut state = self.0.peer.state.lock().unwrap();
            let fail = state.guards == 1 && state.fail_outer_guard;
            if fail {
                state.fail_outer_guard = false;
            }
            state.guards -= 1;
            fail
        };
        if fail {
            panic!("injected original process-guard teardown failure");
        }
    }
}
impl PageSource for Platform {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        PageGeometry::base_only(12)
    }
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        assert_eq!(attribute, CacheAttribute::WriteBack);
        let mut state = self.peer.state.lock().unwrap();
        assert!(
            state.guards > 0,
            "allocation requires original process guard"
        );
        let layout = Layout::from_size_align(bytes, alignment).unwrap();
        // SAFETY: fresh exclusive model CPU RAM, kept by Ram.
        let cpu = NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(MemoryError::OutOfMemory)?;
        let first = state.next_pa;
        state.next_pa += bytes as u64;
        state.ram.insert(first, (cpu.as_ptr() as usize, bytes));
        let physical = (0..bytes / 4096)
            .map(|index| first + (index * 4096) as u64)
            .collect();
        drop(state);
        PinnedPages::new(
            Box::new(Ram {
                cpu,
                layout,
                physical,
                state: self.peer.state.clone(),
            }),
            bytes,
            alignment,
        )
    }
    fn allocate_below(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
        physical_end_exclusive: u64,
    ) -> Result<PinnedPages, MemoryError> {
        assert_eq!(physical_end_exclusive, 1 << 32);
        if self
            .peer
            .state
            .lock()
            .unwrap()
            .next_pa
            .checked_add(bytes as u64)
            .is_none_or(|end| end > physical_end_exclusive)
        {
            return Err(MemoryError::OutOfMemory);
        }
        self.allocate(bytes, alignment, attribute)
    }
}
// SAFETY: synchronous peer shares coherent fixture RAM. These explicit
// fixtures model ordering/ownership but do not check native cache hardware.
unsafe impl TableVisibility for Platform {
    unsafe fn publish(&self, cpu: NonNull<u8>, bytes: usize) -> Result<(), MemoryError> {
        let state = self.peer.state.lock().unwrap();
        assert!(
            state.guards > 0,
            "publication requires original process guard"
        );
        let pointer = cpu.as_ptr() as usize;
        assert!(
            state
                .ram
                .values()
                .any(|&(base, count)| pointer >= base && pointer + bytes <= base + count)
        );
        Ok(())
    }
}
// SAFETY: all unit/requester/config/mapping/RAM resources are held
// synchronous isolated fixtures. No native hardware/root/clock is checked.
unsafe impl ColdPlatform for Platform {
    type Access<'a> = Guard<'a>;
    fn enter(&self) -> Result<Self::Access<'_>, DmaError> {
        let mut state = self.peer.state.lock().unwrap();
        state.guards += 1;
        state.enters += 1;
        Ok(Guard(self))
    }
    fn clock(&self) -> Clock {
        Clock {
            ticks_per_microsecond: 1000,
        }
    }
    fn physical_bits(&self) -> u8 {
        48
    }
    fn admit_payload(&self, pages: &DmaPages, _: Direction) -> Result<bool, DmaError> {
        assert!(self.peer.state.lock().unwrap().guards > 0);
        if pages.cache_attribute() != CacheAttribute::WriteBack {
            return Err(DmaError::CoherenceUnavailable);
        }
        Ok(true)
    }
    unsafe fn sync(
        &self,
        pages: &DmaPages,
        range: Range<usize>,
        _: Direction,
        _: bool,
    ) -> Result<(), DmaError> {
        let mut state = self.peer.state.lock().unwrap();
        assert!(state.guards > 0);
        assert!(range.start <= range.end && range.end <= pages.bytes());
        for &page in pages.physical_pages() {
            pointer(&state, page, 4096);
        }
        state.syncs += 1;
        Ok(())
    }
    fn relax(&self) {
        self.peer.tick();
    }
}
fn pointer(state: &State, physical: u64, bytes: usize) -> *mut u8 {
    let (&base, &(cpu, count)) = state
        .ram
        .range(..=physical)
        .next_back()
        .expect("retained peer PA");
    let offset = (physical - base) as usize;
    assert!(
        offset + bytes <= count,
        "hardware PA lies in original actual pin"
    );
    (cpu + offset) as *mut u8
}
fn word(state: &State, physical: u64) -> u64 {
    // SAFETY: independently decoded bounded peer PA, synchronous read.
    u64::from_le(unsafe { pointer(state, physical, 8).cast::<u64>().read_volatile() })
}
fn finish_posted(state: &mut State, mut matches: impl FnMut(u16, u16) -> bool) {
    for (rid, domain, physical, value) in core::mem::take(&mut state.posted) {
        if matches(rid, domain) {
            // SAFETY: this pending transaction keeps its original checked
            // payload PA; the synchronous peer is its only writer.
            unsafe {
                pointer(state, physical, 4)
                    .cast::<u32>()
                    .write_volatile(value.to_le())
            };
        } else {
            state.posted.push((rid, domain, physical, value));
        }
    }
}
impl DevicePeer {
    pub(super) fn post_write(&self, rid: u16, address: u64, value: u32) {
        let (physical, _, write) = self.walk(rid, address).expect("translated pending write");
        assert!(write && physical.is_multiple_of(4));
        let mut state = self.state.lock().unwrap();
        let domain = state.dte_cache[&rid][1] as u16;
        pointer(&state, physical, 4);
        state.posted.push((rid, domain, physical, value));
    }
    pub(super) fn payload_word(&self, physical: u64) -> u32 {
        let state = self.state.lock().unwrap();
        // SAFETY: bounded checked model payload, with no concurrent writer.
        u32::from_le(unsafe { pointer(&state, physical, 4).cast::<u32>().read_volatile() })
    }
    fn tick(&self) {
        let mut state = self.state.lock().unwrap();
        assert!(
            state.guards > 0,
            "MMIO/command progress requires original guard"
        );
        let mut control = self.registers.read(CONTROL);
        match state.mode {
            Mode::HardwiredFlags => control &= !(1 << 1 | 1 << 8 | 1 << 9 | 1 << 11),
            Mode::ForeignControl if control != 0 => control |= 1 << 5,
            _ => {}
        }
        self.registers.write(CONTROL, control);
        if control == 0 {
            self.registers.write(STATUS, 0);
            return;
        }
        self.registers.write(STATUS, RUNNING);
        if let Some(head) = state.pending_head.take() {
            self.registers.write(COMMAND_HEAD, head);
            return;
        }
        let mut head = self.registers.read(COMMAND_HEAD) as usize;
        let tail = self.registers.read(COMMAND_TAIL) as usize;
        if head == tail {
            return;
        }
        let ring = self.registers.read(COMMAND_BASE) & PHYSICAL;
        assert_eq!(self.registers.read(COMMAND_BASE) >> 56, 9);
        while head != tail {
            assert!(head < RING_BYTES && head.is_multiple_of(16));
            let cpu = pointer(&state, ring + head as u64, 16).cast::<u32>();
            let command = core::array::from_fn(|i| {
                // SAFETY: exact decoded kept ring entry.
                u32::from_le(unsafe { cpu.add(i).read_volatile() })
            });
            state.commands.push(command);
            match command[1] >> 28 {
                1 => {
                    assert_eq!(command[0] & 7, 1, "STORE only, no invented flush/drain bit");
                    let target =
                        u64::from(command[0] & !7) | u64::from(command[1] & 0x000f_ffff) << 32;
                    let sequence = u64::from(command[2]) | u64::from(command[3]) << 32;
                    let data = match state.mode {
                        Mode::OldStore => sequence - 1,
                        Mode::FutureStore => sequence + 1,
                        _ => sequence,
                    };
                    if state.mode != Mode::HeadOnly {
                        // SAFETY: checked completion PA named by wire
                        // command, not a predetermined callback return value.
                        unsafe {
                            pointer(&state, target, 8)
                                .cast::<u64>()
                                .write_volatile(data.to_le())
                        };
                    }
                }
                2 => {
                    assert_eq!(command[2..], [0, 0]);
                    assert_eq!(command[0] >> 16, 0);
                    finish_posted(&mut state, |rid, _| rid == command[0] as u16);
                    state.dte_cache.remove(&(command[0] as u16));
                }
                3 => {
                    assert_eq!(command[0], 0);
                    assert_ne!(command[1] & 0xffff, 0);
                    assert_eq!([command[2], command[3]], [0xffff_f003, 0x7fff_ffff]);
                    finish_posted(&mut state, |_, domain| domain == command[1] as u16);
                    state
                        .translations
                        .retain(|(domain, _), _| *domain != command[1] as u16);
                }
                8 => {
                    assert_eq!(command, [0, 8 << 28, 0, 0]);
                    finish_posted(&mut state, |_, _| true);
                    state.dte_cache.clear();
                    state.translations.clear();
                }
                other => panic!("unsupported actual wire command {other}"),
            }
            head = (head + COMMAND_BYTES) % RING_BYTES;
        }
        match state.mode {
            Mode::StoreBeforeHead => {
                state.pending_head = Some(head as u64);
                state.mode = Mode::Normal;
            }
            Mode::BadHead => self.registers.write(COMMAND_HEAD, 3),
            Mode::Halt => {
                self.registers.write(COMMAND_HEAD, head as u64);
                self.registers.write(STATUS, EVENT_RUNNING);
            }
            Mode::Event => {
                self.registers.write(COMMAND_HEAD, head as u64);
                self.registers.write(EVENT_TAIL, 16);
            }
            Mode::Overflow => {
                self.registers.write(COMMAND_HEAD, head as u64);
                self.registers.write(STATUS, RUNNING | 1);
            }
            Mode::HardwareError => {
                self.registers.write(COMMAND_HEAD, head as u64);
                self.registers.write(HARDWARE_EVENT_STATUS, 1);
            }
            Mode::AlterBase => {
                self.registers.write(COMMAND_HEAD, head as u64);
                self.registers.write(DEVICE_TABLE, 0);
            }
            _ => self.registers.write(COMMAND_HEAD, head as u64),
        }
    }
    pub(super) fn overwrite_dte_word(&self, rid: u16, index: usize, value: u64) {
        assert!(index < 4);
        let state = self.state.lock().unwrap();
        let table = self.registers.read(DEVICE_TABLE) & PHYSICAL;
        let &(cpu, bytes) = state.ram.get(&table).expect("original device table");
        let offset = usize::from(rid) * 32 + index * 8;
        assert!(offset + 8 <= bytes);
        // SAFETY: synchronous peer, original table allocation and one aligned
        // word in its retained RAM. This injects only the requested corruption.
        unsafe {
            (cpu as *mut u64)
                .add(offset / 8)
                .write_volatile(value.to_le())
        };
    }

    pub(super) fn walk(&self, rid: u16, address: u64) -> Option<(u64, bool, bool)> {
        let mut state = self.state.lock().unwrap();
        let table = self.registers.read(DEVICE_TABLE) & PHYSICAL;
        // Keep positive and negative DTE/page observations until the exact
        // matching wire invalidation. Re-reading RAM on every request would
        // conceal a missing RID/domain invalidation in the implementation.
        let words = if let Some(words) = state.dte_cache.get(&rid) {
            *words
        } else {
            let words = [
                word(&state, table + u64::from(rid) * 32),
                word(&state, table + u64::from(rid) * 32 + 8),
            ];
            state.dte_cache.insert(rid, words);
            words
        };
        let dte = words[0];
        if dte & 3 != 3 {
            return None;
        }
        let key = (words[1] as u16, address & !4095);
        if let Some(entry) = state.translations.get(&key) {
            return entry.map(|(pa, read, write)| (pa | (address & 4095), read, write));
        }
        let mut level = (dte >> 9) & 7;
        let mut page = dte & PHYSICAL;
        while level > 0 {
            let index = address >> (12 + 9 * (level - 1)) & 511;
            let entry = word(&state, page + index * 8);
            if entry & 1 == 0 {
                state.translations.insert(key, None);
                return None;
            }
            let next = (entry >> 9) & 7;
            if next == 0 {
                assert_eq!(level, 1);
                let result = (
                    entry & PHYSICAL,
                    (entry & dte) & (1 << 61) != 0,
                    (entry & dte) & (1 << 62) != 0,
                );
                state.translations.insert(key, Some(result));
                return Some((result.0 | (address & 4095), result.1, result.2));
            }
            assert_eq!(next, level - 1);
            page = entry & PHYSICAL;
            level = next;
        }
        None
    }
    pub(super) fn mode(&self, mode: Mode) {
        self.state.lock().unwrap().mode = mode;
    }
    pub(super) fn fail_outer_guard(&self) {
        self.state.lock().unwrap().fail_outer_guard = true;
    }
    pub(super) fn next_physical(&self, address: u64) {
        assert!(address.is_multiple_of(4096));
        self.state.lock().unwrap().next_pa = address;
    }
    pub(super) fn commands(&self) -> Vec<[u32; 4]> {
        self.state.lock().unwrap().commands.clone()
    }
    pub(super) fn live_ram(&self) -> usize {
        self.state.lock().unwrap().ram.len()
    }
    pub(super) fn retains(&self, physical: u64) -> bool {
        self.state
            .lock()
            .unwrap()
            .ram
            .range(..=physical)
            .next_back()
            .is_some_and(|(&base, &(_, bytes))| physical - base < bytes as u64)
    }
    pub(super) fn enters(&self) -> usize {
        self.state.lock().unwrap().enters
    }
    pub(super) fn syncs(&self) -> usize {
        self.state.lock().unwrap().syncs
    }
    pub(super) fn clear_syncs(&self) {
        self.state.lock().unwrap().syncs = 0;
    }
    pub(super) fn register(&self, offset: usize) -> u64 {
        self.registers.read(offset)
    }
    pub(super) fn set(&self, offset: usize, value: u64) {
        self.registers.write(offset, value);
    }
    pub(super) fn registers(&self) -> Vec<u64> {
        (0..16384)
            .step_by(8)
            .map(|offset| self.registers.read(offset))
            .collect()
    }
    pub(super) fn image(&self) -> Image {
        let state = self.state.lock().unwrap();
        let ram = state
            .ram
            .iter()
            .map(|(&pa, &(cpu, bytes))| {
                // SAFETY: model is stopped, exact RAM, no writer while locked.
                (
                    pa,
                    unsafe { core::slice::from_raw_parts(cpu as *const u8, bytes) }.to_vec(),
                )
            })
            .collect();
        (self.registers(), ram)
    }
    pub(super) fn pages(&self, bytes: usize) -> PinnedPages {
        let platform = Platform { peer: self.clone() };
        let _guard = platform.enter().unwrap();
        platform
            .allocate(bytes, 4096, CacheAttribute::WriteBack)
            .unwrap()
    }
}
pub(super) fn function(rid: u16) -> Function<OwnedConfig> {
    function_with_counters(rid).0
}
pub(super) fn function_with_counters(rid: u16) -> (Function<OwnedConfig>, Arc<Counters>) {
    let address = Address {
        segment: ADDRESS.segment,
        bus: (rid >> 8) as u8,
        device: ((rid >> 3) & 31) as u8,
        function: (rid & 7) as u8,
    };
    let (mut config, counters) = fixture(address);
    config.write32(0, 0x7925_14c3).unwrap();
    config.write32(4, 0).unwrap();
    config.write32(8, 0x0280_0001).unwrap();
    config.write32(0x0c, 0).unwrap();
    config.write32(0x100, 0).unwrap();
    (Function::new(address, config).unwrap(), counters)
}
pub(super) fn limits() -> Limits {
    Limits {
        table_pages: 8,
        table_backing_bytes: 32768,
        mappings: 16,
        wait_us: 10000,
    }
}
pub(super) fn checksum(bytes: &mut [u8]) {
    let len = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&len.to_le_bytes());
    bytes[9] = 0;
    bytes[9] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
}
pub(super) fn inputs() -> (FunctionInspection, Platform, Peer, Vec<u8>) {
    inputs_with_entries(&[1, 0, 0, 0])
}
pub(super) fn inputs_with_entries(entries: &[u8]) -> (FunctionInspection, Platform, Peer, Vec<u8>) {
    inputs_profile(entries, 1u32 | (48 << 8) | (48 << 15), FEATURES)
}
pub(super) fn inputs_profile(
    entries: &[u8],
    info: u32,
    features: u64,
) -> (FunctionInspection, Platform, Peer, Vec<u8>) {
    inputs_hardware(entries, info, features, (48 << 8) | (48 << 15))
}
pub(super) fn inputs_hardware(
    entries: &[u8],
    info: u32,
    features: u64,
    miscellaneous: u32,
) -> (FunctionInspection, Platform, Peer, Vec<u8>) {
    inputs_flagged(entries, info, features, miscellaneous, 0)
}
/// As [`inputs_hardware`], with the IVHD's `flags` byte.
pub(super) fn inputs_flagged(
    entries: &[u8],
    info: u32,
    features: u64,
    miscellaneous: u32,
    flags: u8,
) -> (FunctionInspection, Platform, Peer, Vec<u8>) {
    let layout = Layout::from_size_align(16384, 4096).unwrap();
    // SAFETY: isolated, page-aligned zeroed model register RAM.
    let cpu = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
    let registers = Arc::new(Registers {
        cpu,
        request: Mutex::new(None),
    });
    registers.write(0x30, features);
    let authority =
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        unsafe { Authority::isolated_model(registers.clone(), SPACE, Vec::new()) }.unwrap();
    // SAFETY: SAME original allocated register RAM with no model controller
    // or inventory backedge. Guard observes only its real retained CPU extent.
    let mapping_owner = unsafe {
        crate::bus::mmio::owned::model::MappingOwner::from_owned(registers.clone(), |ram| {
            if (ram.cpu.as_ptr() as usize).is_multiple_of(4096) {
                Ok(())
            } else {
                Err(crate::bus::pci::assignment::Error::Context)
            }
        })
    };
    let mapping = authority
        .map(
            Resource::new(Box::new(RegisterResource(
                mapping_owner.retention().unwrap(),
            ))),
            0,
            16384,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .unwrap();
    let (mut config, _) = fixture(ADDRESS);
    config.write32(0, 0x1234_1022).unwrap();
    config.write32(8, 0x0806_0001).unwrap();
    config.write32(0x0c, 0).unwrap();
    config.write16(6, 1 << 4).unwrap();
    config.write8(0x34, 0x40).unwrap();
    config
        .write32(0x40, 0x0f | (3 << 16) | (1 << 19) | (1 << 27))
        .unwrap();
    config.write32(0x44, BASE as u32 | 1).unwrap();
    config.write32(0x48, 0).unwrap();
    config.write32(0x4c, 0).unwrap();
    config.write32(0x50, miscellaneous).unwrap();
    let function = Function::new(ADDRESS, config).unwrap();
    let mut bytes = vec![0; 88];
    bytes[..4].copy_from_slice(b"IVRS");
    bytes[8] = 2;
    bytes[36..40].copy_from_slice(&info.to_le_bytes());
    bytes[48] = 0x11;
    bytes[49] = flags;
    bytes[50..52].copy_from_slice(&(40u16 + entries.len() as u16).to_le_bytes());
    bytes[52..54].copy_from_slice(&2u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&0x40u16.to_le_bytes());
    bytes[56..64].copy_from_slice(&BASE.to_le_bytes());
    bytes[64..66].copy_from_slice(&ADDRESS.segment.to_le_bytes());
    bytes[72..80].copy_from_slice(&features.to_le_bytes());
    bytes.extend_from_slice(entries);
    checksum(&mut bytes);
    let ivrs = Ivrs::parse(&bytes, 8).unwrap();
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let inspection = match unsafe {
        FunctionInspection::inspect(
            registers::Inputs {
                function,
                mappings: vec![mapping],
            },
            &ivrs,
        )
    } {
        Ok(inspection) => inspection,
        Err((error, _)) => panic!("{error:?}"),
    };
    let peer = DevicePeer {
        registers,
        state: Arc::new(Mutex::new(State {
            ram: BTreeMap::new(),
            next_pa: 0x100000,
            mode: Mode::Normal,
            commands: Vec::new(),
            pending_head: None,
            guards: 0,
            enters: 0,
            syncs: 0,
            dte_cache: BTreeMap::new(),
            translations: BTreeMap::new(),
            fail_outer_guard: false,
            posted: Vec::new(),
        })),
    };
    (
        inspection,
        Platform { peer: peer.clone() },
        Peer {
            inner: peer,
            _mapping_owner: mapping_owner,
        },
        bytes,
    )
}
pub(super) fn unit() -> (Unit<Platform>, Peer) {
    let (inspection, platform, peer, bytes) = inputs();
    let ivrs = Ivrs::parse(&bytes, 8).unwrap();
    // SAFETY: synchronous isolated model PCI/UC/RAM/firmware owners;
    // every requester, DMA/IRQ/work user is modeled as initially stopped.
    let unit = unsafe { Unit::cold(inspection, &ivrs, platform, limits()) }.unwrap();
    (unit, peer)
}
