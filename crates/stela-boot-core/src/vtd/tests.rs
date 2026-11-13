mod fallible_pci;
extern crate std;
use self::std::sync::Mutex;
use super::*;
use alloc::{
    alloc::{alloc_zeroed, dealloc},
    boxed::Box,
};
use core::alloc::Layout;
use stela_drivers::bus::dma::{
    mapping::DmaMapping,
    memory::{MemoryError, PageBacking},
};

struct Backing {
    pointer: NonNull<u8>,
    layout: Layout,
    pages: Vec<u64>,
    shift: u8,
    released: Arc<AtomicU64>,
}
// SAFETY: test-owned, immovable allocated RAM; immutable page metadata,
// no safe CPU aliases and no asynchronous physical hardware in the model.
unsafe impl Send for Backing {}
// SAFETY: shared access exposes metadata and raw pointers only.
unsafe impl Sync for Backing {}
// SAFETY: this is an explicit native physical-memory model. CPU RAM really
// exists and is held; the named PAs are modeled, not identity-inferred.
unsafe impl PageBacking for Backing {
    fn cpu_base(&self) -> NonNull<u8> {
        self.pointer
    }
    fn physical_pages(&self) -> &[u64] {
        &self.pages
    }
    fn page_shift(&self) -> u8 {
        self.shift
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}
impl Drop for Backing {
    fn drop(&mut self) {
        self.released.fetch_add(1, Ordering::Relaxed);
        // SAFETY: exact unique test allocation and original layout.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}
fn pages(bytes: usize, shift: u8, physical: u64, released: Arc<AtomicU64>) -> PinnedPages {
    let size = 1usize << shift;
    let layout = Layout::from_size_align(bytes, size).unwrap();
    // SAFETY: exclusive zeroed model RAM, released by Backing.
    let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
    let backing = Backing {
        pointer,
        layout,
        pages: (0..bytes / size)
            .map(|index| physical + (index * size) as u64)
            .collect(),
        shift,
        released,
    };
    PinnedPages::new(Box::new(backing), bytes, size).unwrap()
}
struct Source {
    next: AtomicU64,
    released: Arc<AtomicU64>,
    table_addresses: Mutex<BTreeMap<u64, usize>>,
}
impl PageSource for Source {
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        assert_eq!(
            (bytes, alignment, attribute),
            (PAGE, PAGE, CacheAttribute::WriteBack)
        );
        let physical = self.next.fetch_add(PAGE as u64, Ordering::Relaxed);
        let pages = pages(bytes, 12, physical, self.released.clone());
        let cpu = pages.cpu_mapping(CacheAttribute::WriteBack).unwrap();
        self.table_addresses
            .lock()
            .unwrap()
            .insert(physical, cpu.address(0, PAGE).unwrap().as_ptr() as usize);
        Ok(pages)
    }
}
fn source() -> &'static Source {
    Box::leak(Box::new(Source {
        next: AtomicU64::new(0x100000),
        released: Arc::new(AtomicU64::new(0)),
        table_addresses: Mutex::new(BTreeMap::new()),
    }))
}
struct Model {
    values: BTreeMap<usize, u64>,
    writes: Vec<(usize, u64)>,
    ticks: u64,
    block_iotlb: bool,
    block_context: bool,
    block_te_off: bool,
    cache_events: Vec<(bool, usize)>,
    fail_gsts_after: Option<u32>,
    source: Option<&'static Source>,
    visible_tables: BTreeMap<u64, Vec<u64>>,
    active_observations: usize,
    pending_payload: Vec<(usize, u32)>,
    iotlb_granularity: u64,
}
impl Model {
    fn visible_table(&self, physical: u64) -> &[u64] {
        self.visible_tables
            .get(&physical)
            .expect("walker reached an unflushed child table")
    }
    fn observe_level(&self, physical: u64, level: u8) {
        let entries = self.visible_table(physical);
        if level != 0 {
            for entry in entries.iter().filter(|entry| **entry & (READ | WRITE) != 0) {
                self.observe_level(entry & ADDRESS, level - 1);
            }
        }
    }
    fn observe_tables(&mut self) {
        if self.source.is_none()
            || self.values.get(&GSTS).copied().unwrap_or(0) & u64::from(TRANSLATION) == 0
        {
            return;
        }
        self.active_observations += 1;
        let root = self.values[&RTADDR] & ADDRESS;
        for root_pair in self.visible_table(root).as_chunks::<2>().0 {
            assert_eq!(
                root_pair[1], 0,
                "legacy root reserved high half became visible"
            );
            if root_pair[0] & 1 == 0 {
                continue;
            }
            for context_pair in self
                .visible_table(root_pair[0] & ADDRESS)
                .as_chunks::<2>()
                .0
            {
                if context_pair[0] & 1 != 0 {
                    let levels = (context_pair[1] & 7) as u8 + 2;
                    self.observe_level(context_pair[0] & ADDRESS, levels - 1);
                }
            }
        }
    }
    fn root_bytes(&self) -> Vec<u8> {
        self.visible_table(self.values[&RTADDR] & ADDRESS)
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect()
    }
    fn translation(&self, requester: u16, iova: u64) -> Option<u64> {
        let root = self.visible_table(self.values[&RTADDR] & ADDRESS);
        let root_entry = root[usize::from(requester >> 8) * 2];
        if root_entry & 1 == 0 {
            return None;
        }
        let context = self.visible_table(root_entry & ADDRESS);
        let index = usize::from(requester & 255) * 2;
        if context[index] & 1 == 0 {
            return None;
        }
        let levels = (context[index + 1] & 7) as u8 + 2;
        let mut physical = context[index] & ADDRESS;
        for level in (0..levels).rev() {
            let index = ((iova >> (12 + 9 * u32::from(level))) & 511) as usize;
            let entry = self.visible_table(physical)[index];
            if entry & (READ | WRITE) == 0 {
                return None;
            }
            physical = entry & ADDRESS;
        }
        Some(physical | iova & 4095)
    }
}
#[derive(Clone)]
struct ModelRegisters(Arc<Mutex<Model>>);
impl ModelRegisters {
    fn new() -> Self {
        let mut values = BTreeMap::new();
        values.insert(
            CAP,
            (47 << 16) | (4 << 8) | (1 << 4) | (1 << 54) | (1 << 55),
        );
        values.insert(ECAP, 1 | (0x10 << 8));
        Self(Arc::new(Mutex::new(Model {
            values,
            writes: Vec::new(),
            ticks: 0,
            block_iotlb: false,
            block_context: false,
            block_te_off: false,
            cache_events: Vec::new(),
            fail_gsts_after: None,
            source: None,
            visible_tables: BTreeMap::new(),
            active_observations: 0,
            pending_payload: Vec::new(),
            iotlb_granularity: 1,
        })))
    }
}
// SAFETY: synchronous model of the real registers and acknowledgements.
// Timeout injection leaves requests unacknowledged in the model.
unsafe impl Registers for ModelRegisters {
    fn bytes(&self) -> usize {
        4096
    }
    fn read32(&self, offset: usize) -> u32 {
        self.0
            .lock()
            .unwrap()
            .values
            .get(&offset)
            .copied()
            .unwrap_or(0) as u32
    }
    fn read64(&self, offset: usize) -> u64 {
        let mut model = self.0.lock().unwrap();
        let mut value = model.values.get(&offset).copied().unwrap_or(0);
        if offset == CCMD && value & CONTEXT_INVALIDATE != 0 && !model.block_context {
            value = value & !CONTEXT_INVALIDATE | 1 << 59;
            model.values.insert(offset, value);
        }
        if offset == 0x108 && value & IOTLB_INVALIDATE != 0 && !model.block_iotlb {
            if value & IOTLB_WRITE_DRAIN != 0 && model.iotlb_granularity == 1 {
                for (address, word) in model.pending_payload.drain(..) {
                    // SAFETY: each test keeps the owned allocation
                    // through this modeled device-write completion.
                    unsafe { (address as *mut u32).write_volatile(word.to_le()) };
                }
            }
            value = value & !(IOTLB_INVALIDATE | 3 << 57) | model.iotlb_granularity << 57;
            model.values.insert(offset, value);
        }
        value
    }
    fn write32(&self, offset: usize, value: u32) {
        let mut model = self.0.lock().unwrap();
        model.writes.push((offset, u64::from(value)));
        model.cache_events.push((false, offset));
        model.values.insert(offset, u64::from(value));
        if offset == GCMD {
            let mut status = model.values.get(&GSTS).copied().unwrap_or(0) as u32;
            if value & ROOT_POINTER != 0 {
                status |= ROOT_POINTER;
            }
            if value & TRANSLATION != 0 {
                status |= TRANSLATION;
            } else if !model.block_te_off {
                status &= !TRANSLATION;
            }
            status &= !WRITE_BUFFER;
            model.values.insert(GSTS, u64::from(status));
            model.observe_tables();
            if model.fail_gsts_after == Some(value) {
                model.values.insert(GSTS, u64::from(u32::MAX));
            }
        }
    }
    fn write64(&self, offset: usize, value: u64) {
        let mut model = self.0.lock().unwrap();
        model.writes.push((offset, value));
        model.cache_events.push((false, offset));
        model.values.insert(offset, value);
    }
    fn ticks(&self) -> u64 {
        let mut model = self.0.lock().unwrap();
        model.ticks += 1;
        model.ticks
    }
    fn timeout_ticks(&self) -> u64 {
        16
    }
    unsafe fn flush_table(&self, cpu: NonNull<u8>, bytes: usize, line: usize) {
        assert_eq!(bytes, PAGE);
        assert!((cpu.as_ptr() as usize).is_multiple_of(PAGE));
        let mut model = self.0.lock().unwrap();
        model.cache_events.push((true, cpu.as_ptr() as usize));
        if let Some(source) = model.source {
            let addresses = source.table_addresses.lock().unwrap();
            let physical = *addresses
                .iter()
                .rev()
                .find(|(_, pointer)| **pointer == cpu.as_ptr() as usize)
                .unwrap()
                .0;
            // SAFETY: model table mapping; snapshot represents
            // what a noncoherent walker can see after this real eviction.
            let visible =
                unsafe { core::slice::from_raw_parts(cpu.as_ptr().cast::<u64>(), PAGE / 8) }
                    .to_vec();
            model.visible_tables.insert(physical, visible);
            model.observe_tables();
        }
        // SAFETY: the model uses kept allocated table RAM and
        // the production CPUID validation; keep real cache effects too.
        unsafe { super::flush_table(cpu, bytes, line) };
    }
}

fn stopped_claim(rid: u16) -> RequesterClaim {
    RequesterClaim::model(rid, Arc::new(AtomicU64::new(0)))
}

#[test]
fn a_requester_that_arrives_later_joins_the_unit() {
    let registers = ModelRegisters::new();
    let unit =
        // SAFETY: the model registers stand in for the unit, and this test is the only
        // process-context owner.
        unsafe { Unit::take_over(registers.clone(), source(), &[8], 48, &[]) }.unwrap();
    assert!(!unit.allows(0x300));
    assert!(matches!(
        // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
        unsafe { unit.attach_requester(stopped_claim(0x300), &[]) },
        Err(AttachRequesterFailure {
            error: VtdError::Busy,
            ..
        })
    ));
    unit.admit_requester(0x300).unwrap();
    unit.admit_requester(0x300).unwrap();
    unit.admit_requester(9).unwrap();
    assert!(unit.allows(0x300));
    assert!(unit.allows(9));
    // SAFETY: as above.
    let later = unsafe { unit.attach_requester(stopped_claim(0x300), &[]) }.unwrap();
    // SAFETY: as above.
    let sibling = unsafe { unit.attach_requester(stopped_claim(9), &[]) }.unwrap();
    assert_ne!(later.domain_id(), sibling.domain_id());
}

#[test]
fn coherent_words_observe_only_the_live_domains_pins() {
    let registers = ModelRegisters::new();
    let unit =
            // SAFETY: the model registers stand in for the unit, and this test is the only
            // process-context owner.
            unsafe { Unit::take_over(registers.clone(), source(), &[8, 16], 48, &[]) }.unwrap();
    // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
    let first = unsafe { unit.attach_requester(stopped_claim(8), &[]) }.unwrap();
    // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
    let second = unsafe { unit.attach_requester(stopped_claim(16), &[]) }.unwrap();
    let released = Arc::new(AtomicU64::new(0));
    let pin = pages(PAGE, 12, 0x810000, released.clone());
    let cpu = pin.cpu_mapping(CacheAttribute::WriteBack).unwrap();
    let pointer = cpu.address(0, 4).unwrap().as_ptr().cast::<u32>();
    let mut mapping = DmaMapping::map(first.clone(), pin, Direction::FromDevice, u64::MAX).unwrap();
    let mut other = DmaMapping::map(
        second.clone(),
        pages(PAGE, 12, 0x910000, released.clone()),
        Direction::FromDevice,
        u64::MAX,
    )
    .unwrap();
    assert_eq!(mapping.address(), other.address());
    let token = {
        let mut guard = unit.lock();
        guard.state().domains[&8].mappings[&mapping.address().unwrap()].info
    };
    let before = registers.0.lock().unwrap().writes.len();
    for value in [0u32, 1, 0x8000_0000, 0x1234_5678, u32::MAX] {
        // SAFETY: synchronous modeled device producer writes its
        // allocation, without a CPU ownership transfer.
        unsafe { pointer.write_volatile(value.to_le()) };
        assert_eq!(mapping.read_coherent_u32(0), Ok(value));
        assert_eq!(other.read_coherent_u32(0), Ok(0));
    }
    // Observing coherent payloads does not invent a device stop, perform
    // cache invalidation, or trigger IOTLB/ownership-transfer commands.
    assert_eq!(registers.0.lock().unwrap().writes.len(), before);
    for offset in [1, PAGE - 3, PAGE, usize::MAX] {
        assert_eq!(
            mapping.read_coherent_u32(offset),
            Err(DmaError::InvalidRange)
        );
    }
    assert_eq!(
        // SAFETY: the model device is stopped and `token` names a mapping this test made.
        unsafe { second.read_coherent_u32(token, 0, Direction::FromDevice) },
        Err(DmaError::Unmapped)
    );
    assert_eq!(
        // SAFETY: the model device is stopped and `token` names a mapping this test made.
        unsafe { first.read_coherent_u32(token, 0, Direction::ToDevice) },
        Err(DmaError::InvalidRange)
    );
    // SAFETY: modeled producer and workers are stopped; no writes pending.
    unsafe { mapping.unmap() }.unwrap();
    assert_eq!(mapping.read_coherent_u32(0), Err(DmaError::Unmapped));
    assert_eq!(
        // SAFETY: the model device is stopped and `token` names a mapping this test made.
        unsafe { first.read_coherent_u32(token, 0, Direction::FromDevice) },
        Err(DmaError::Unmapped)
    );
    // SAFETY: the model device is stopped, so no transfer reaches this domain's mappings.
    drop(unsafe { first.detach() }.unwrap());
    assert_eq!(
        // SAFETY: the model device is stopped and `token` names a mapping this test made.
        unsafe { first.read_coherent_u32(token, 0, Direction::FromDevice) },
        Err(DmaError::Unmapped)
    );
    drop(first);
    // SAFETY: the model device is stopped, so no transfer reaches this domain's mappings.
    unsafe { other.unmap() }.unwrap();
    // SAFETY: the model device is stopped, so no transfer reaches this domain's mappings.
    drop(unsafe { second.detach() }.unwrap());
    drop(second);
    drop(cpu);
    assert_eq!(released.load(Ordering::Relaxed), 2);
    // SAFETY: no requester is attached, or the refusal leaves them all attached.
    unsafe { unit.shut_down() }.unwrap();
}

#[test]
fn payload_drain_requires_real_write_capability_and_acknowledged_visibility() {
    for supported in [false, true] {
        let registers = ModelRegisters::new();
        if !supported {
            *registers.0.lock().unwrap().values.get_mut(&CAP).unwrap() &= !CAP_WRITE_DRAIN;
        }
        let unit =
                // SAFETY: the model registers stand in for the unit, and this test is the only
                // process-context owner.
                unsafe { Unit::take_over(registers.clone(), source(), &[8], 48, &[]) }.unwrap();
        // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
        let domain = unsafe { unit.attach_requester(stopped_claim(8), &[]) }.unwrap();
        let pin = pages(PAGE, 12, 0xa10000, Arc::new(AtomicU64::new(0)));
        let cpu = pin.cpu_mapping(CacheAttribute::WriteBack).unwrap();
        let pointer = cpu.address(0, 4).unwrap().as_ptr().cast::<u32>();
        let mut mapping =
            DmaMapping::map(domain.clone(), pin, Direction::FromDevice, u64::MAX).unwrap();
        let before = registers.0.lock().unwrap().writes.len();
        if supported {
            registers
                .0
                .lock()
                .unwrap()
                .pending_payload
                .push((pointer as usize, 0x1234_abcd));
            assert_eq!(mapping.read_coherent_u32(0), Ok(0));
            // SAFETY: modeled engine cannot submit more requests; queued
            // translated payload remains held until real model ACK.
            unsafe { domain.drain_posted_writes() }.unwrap();
            assert_eq!(mapping.read_coherent_u32(0), Ok(0x1234_abcd));
            let model = registers.0.lock().unwrap();
            let writes = &model.writes[before..];
            assert!(model.pending_payload.is_empty());
            assert_eq!(
                writes[0],
                (
                    unit.iotlb,
                    IOTLB_INVALIDATE | IOTLB_GLOBAL | IOTLB_WRITE_DRAIN | IOTLB_READ_DRAIN
                )
            );
            assert_eq!(writes[1], (GCMD, u64::from(TRANSLATION | WRITE_BUFFER)));
        } else {
            assert_eq!(
                // SAFETY: the model engine submits nothing more; queued payload stays held
                // until its acknowledgement.
                unsafe { domain.drain_posted_writes() },
                Err(DmaError::DrainUnavailable)
            );
            assert_eq!(registers.0.lock().unwrap().writes.len(), before);
        }
        assert_eq!(unit.lock().state().domains[&8].mappings.len(), 1);
        // SAFETY: the model has no engine and no queued payload now.
        unsafe { mapping.unmap() }.unwrap();
        // SAFETY: the model device is stopped, so no transfer reaches this domain's mappings.
        drop(unsafe { domain.detach() }.unwrap());
        drop(domain);
        // SAFETY: no requester is attached, or the refusal leaves them all attached.
        unsafe { unit.shut_down() }.unwrap();
    }
}

#[test]
fn withheld_drain_bad_granularity_and_write_buffer_fault_keep_all_backing() {
    for failure in 0..3 {
        let registers = ModelRegisters::new();
        let unit =
                // SAFETY: the model registers stand in for the unit, and this test is the only
                // process-context owner.
                unsafe { Unit::take_over(registers.clone(), source(), &[8], 48, &[]) }.unwrap();
        let claim_drops = Arc::new(AtomicU64::new(0));
        let domain =
                // SAFETY: the model requester is stopped and owned by this test, with no DMA in
                // flight.
                unsafe { unit.attach_requester(RequesterClaim::model(8, claim_drops.clone()), &[]) }
                    .unwrap();
        let pin_drops = Arc::new(AtomicU64::new(0));
        let pin = pages(PAGE, 12, 0xb10000, pin_drops.clone());
        let cpu = pin.cpu_mapping(CacheAttribute::WriteBack).unwrap();
        let pointer = cpu.address(0, 4).unwrap().as_ptr().cast::<u32>();
        let mapping =
            DmaMapping::map(domain.clone(), pin, Direction::FromDevice, u64::MAX).unwrap();
        {
            let mut model = registers.0.lock().unwrap();
            model.pending_payload.push((pointer as usize, 0xfeed_beef));
            match failure {
                0 => model.block_iotlb = true,
                1 => model.iotlb_granularity = 0,
                _ => model.fail_gsts_after = Some(TRANSLATION | WRITE_BUFFER),
            }
        }
        assert_eq!(
            // SAFETY: the model engine submits nothing more; queued payload stays held
            // until its acknowledgement.
            unsafe { domain.drain_posted_writes() },
            Err(DmaError::InvalidationFailed)
        );
        {
            let mut guard = unit.lock();
            let state = guard.state();
            assert!(state.poisoned);
            assert_eq!(state.domains[&8].mappings.len(), 1);
        }
        assert_eq!(mapping.read_coherent_u32(0), Err(DmaError::MappingFailed));
        assert_eq!(
            // SAFETY: the model engine submits nothing more; queued payload stays held
            // until its acknowledgement.
            unsafe { domain.drain_posted_writes() },
            Err(DmaError::MappingFailed)
        );
        drop(cpu);
        drop(mapping);
        drop(domain);
        drop(unit);
        assert_eq!(pin_drops.load(Ordering::Relaxed), 0);
        assert_eq!(claim_drops.load(Ordering::Relaxed), 0);
        // Deliberate quarantine: only external platform recovery can
        // acknowledge the hardware lifetime after these faults.
    }
}
#[test]
fn scatter_maps_kept_native_subranges_and_releases_only_after_invalidation() {
    use stela_drivers::bus::dma::pages::PageRange;
    let source = source();
    let registers = ModelRegisters::new();
    {
        let mut model = registers.0.lock().unwrap();
        model.values.insert(ECAP, 0x10 << 8);
        model.source = Some(source);
    }
    // SAFETY: exclusive deterministic register/requester model; no device.
    let unit = unsafe { Unit::take_over(registers.clone(), source, &[8], 48, &[]) }.unwrap();
    // SAFETY: the model supplies the exact stopped requester claim.
    let domain = unsafe { unit.attach_requester(stopped_claim(8), &[]) }.unwrap();
    let released = Arc::new(AtomicU64::new(0));
    let granule = 2 * PAGE;
    let first = pages(2 * granule, 13, 0x900000, released.clone());
    let second = pages(granule, 13, 0x300000, released.clone());
    let scatter = DmaPages::from_ranges(vec![
        PageRange::new(first.clone(), granule..2 * granule).unwrap(),
        PageRange::new(second, 0..granule).unwrap(),
        PageRange::new(first, granule..2 * granule).unwrap(),
    ])
    .unwrap();
    assert!(scatter.as_single().is_none());
    assert_eq!(scatter.page_shift(), 13);
    let mut mapping =
        DmaMapping::map(domain.clone(), scatter, Direction::Bidirectional, u64::MAX).unwrap();
    let address = mapping.address().unwrap();
    assert_eq!(mapping.bytes(), 3 * granule);
    assert_eq!(
        mapping.read_coherent_u32(0),
        Err(DmaError::CoherenceUnavailable)
    );
    {
        let model = registers.0.lock().unwrap();
        for (index, physical) in [0x902000, 0x903000, 0x300000, 0x301000, 0x902000, 0x903000]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                model.translation(8, address + (index * PAGE) as u64),
                Some(physical)
            );
        }
        assert_eq!(model.translation(8, address + 3 * granule as u64), None);
        assert_eq!(model.translation(16, address), None);
    }
    assert_eq!(released.load(Ordering::Relaxed), 0);
    registers.0.lock().unwrap().block_iotlb = true;
    assert_eq!(
        // SAFETY: model is quiescent; an unacknowledged removal keeps pins.
        unsafe { mapping.unmap() },
        Err(DmaError::InvalidationFailed)
    );
    assert_eq!(released.load(Ordering::Relaxed), 0);
    registers.0.lock().unwrap().block_iotlb = false;
    // SAFETY: same stopped requester and unreused kept mapping token.
    unsafe { mapping.unmap() }.unwrap();
    assert_eq!(released.load(Ordering::Relaxed), 2);
    assert_eq!(registers.0.lock().unwrap().translation(8, address), None);
    // SAFETY: no mapping remains and the requester is still stopped.
    drop(unsafe { domain.detach() }.unwrap());
    drop(domain);
    // SAFETY: all contexts/mappings are retired; model has no DMA worker.
    unsafe { unit.shut_down() }.unwrap();
}

#[test]
fn covered_requesters_reach_only_the_window_until_attached_to_their_own_domain() {
    let source = source();
    let registers = ModelRegisters::new();
    {
        let mut m = registers.0.lock().unwrap();
        m.values.insert(ECAP, 0x10 << 8);
        m.source = Some(source);
    }
    let window = [0x80_0000..0x80_2000, 0x7d00_0000..0x7d00_1000];
    let unit =
            // SAFETY: the model registers stand in for the unit, and this test is the only
            // process-context owner.
            unsafe { Unit::take_over(registers.clone(), source, &[8, 16], 48, &window) }.unwrap();
    {
        let m = registers.0.lock().unwrap();
        for requester in [8, 16] {
            assert_eq!(m.translation(requester, 0x80_0010), Some(0x80_0010));
            assert_eq!(m.translation(requester, 0x80_1ff8), Some(0x80_1ff8));
            assert_eq!(m.translation(requester, 0x7d00_0000), Some(0x7d00_0000));
            assert_eq!(m.translation(requester, 0x80_2000), None);
            assert_eq!(m.translation(requester, 0x10_0000), None);
        }
        assert_eq!(m.translation(24, 0x80_0000), None);
    }
    // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
    let own = unsafe { unit.attach_requester(stopped_claim(8), &[]) }.unwrap();
    assert_eq!(own.domain_id(), WINDOW_DID + 1);
    let m = registers.0.lock().unwrap();
    assert_eq!(m.translation(8, 0x80_0000), None);
    assert_eq!(m.translation(16, 0x80_0000), Some(0x80_0000));
    // The swap invalidated the context cache before the new context.
    assert!(
        m.writes
            .iter()
            .any(|&(at, value)| at == CCMD && value & CONTEXT_GLOBAL != 0)
    );
    drop(m);
    // A window over the MSI range is refused.
    let msi = [window[0].clone(), 0xfee0_0000..0xfee0_1000];
    assert!(matches!(
        // SAFETY: the model registers stand in for the unit, and this test is the only
        // process-context owner.
        unsafe { Unit::take_over(ModelRegisters::new(), source, &[8], 48, &msi) },
        Err(TakeOverError {
            error: VtdError::Unsupported,
            started: false
        })
    ));
}

#[test]
fn contexts_separate_same_iova_and_reject_cross_domain_or_stale_tokens() {
    let source = source();
    let registers = ModelRegisters::new();
    {
        let mut m = registers.0.lock().unwrap();
        m.values.insert(ECAP, 0x10 << 8);
        m.source = Some(source);
    }
    let unit =
            // SAFETY: the model registers stand in for the unit, and this test is the only
            // process-context owner.
            unsafe { Unit::take_over(registers.clone(), source, &[8, 16, 24], 48, &[]) }.unwrap();
    // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
    let first = unsafe { unit.attach_requester(stopped_claim(8), &[]) }.unwrap();
    // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
    let second = unsafe { unit.attach_requester(stopped_claim(16), &[]) }.unwrap();
    assert_ne!(first.domain_id(), second.domain_id());
    let next_table = source.next.load(Ordering::Relaxed);
    for rejected in [8, 0x20] {
        assert!(matches!(
            // SAFETY: the model requester is stopped and owned by this test, with no DMA in
            // flight.
            unsafe { unit.attach_requester(stopped_claim(rejected), &[]) },
            Err(AttachRequesterFailure {
                error: VtdError::Busy,
                ..
            })
        ));
    }
    assert_eq!(
        source.next.load(Ordering::Relaxed),
        next_table,
        "duplicate/unlisted claims must not allocate or publish contexts"
    );
    let mut a = DmaMapping::map(
        first.clone(),
        pages(PAGE, 12, 0xd000000, Arc::new(AtomicU64::new(0))),
        Direction::Bidirectional,
        u64::MAX,
    )
    .unwrap();
    let mut b = DmaMapping::map(
        second.clone(),
        pages(PAGE, 12, 0xe000000, Arc::new(AtomicU64::new(0))),
        Direction::Bidirectional,
        u64::MAX,
    )
    .unwrap();
    assert_eq!(a.address(), b.address());
    let address = a.address().unwrap();
    {
        let m = registers.0.lock().unwrap();
        let root = m.visible_table(m.values[&RTADDR] & ADDRESS);
        let context = m.visible_table(root[0] & ADDRESS);
        assert_eq!(
            (context[8 * 2 + 1] >> 8) & 0xffff,
            u64::from(first.domain_id())
        );
        assert_eq!(
            (context[16 * 2 + 1] >> 8) & 0xffff,
            u64::from(second.domain_id())
        );
        assert_ne!(context[8 * 2] & ADDRESS, context[16 * 2] & ADDRESS);
        assert_eq!(m.translation(8, address), Some(0xd000000));
        assert_eq!(m.translation(16, address), Some(0xe000000));
        assert_eq!(m.translation(24, address), None);
    }
    let token = {
        let mut g = unit.lock();
        g.state().domains[&8].mappings[&address].info
    };
    assert_eq!(
        // SAFETY: the model device is stopped and `token` names a mapping this test made.
        unsafe { second.sync_for_device(token, 0..PAGE, Direction::Bidirectional) },
        Err(DmaError::Unmapped)
    );
    // SAFETY: the model device is stopped, so no transfer reaches this domain's mappings.
    assert!(matches!(unsafe { first.detach() }, Err(VtdError::Busy)));
    // SAFETY: no requester is attached, or the refusal leaves them all attached.
    assert_eq!(unsafe { unit.shut_down() }, Err(VtdError::Busy));
    // SAFETY: the model device is stopped, so no transfer reaches this domain's mappings.
    unsafe { a.unmap() }.unwrap();
    let old_did = first.domain_id();
    let old_epoch = first.generation();
    // SAFETY: the model device is stopped, so no transfer reaches this domain's mappings.
    drop(unsafe { first.detach() }.unwrap());
    assert_eq!(registers.0.lock().unwrap().translation(8, address), None);
    // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
    let replacement = unsafe { unit.attach_requester(stopped_claim(8), &[]) }.unwrap();
    assert_eq!(replacement.domain_id(), old_did);
    assert!(replacement.generation() > old_epoch);
    let mut c = DmaMapping::map(
        replacement.clone(),
        pages(PAGE, 12, 0xf000000, Arc::new(AtomicU64::new(0))),
        Direction::Bidirectional,
        u64::MAX,
    )
    .unwrap();
    assert_eq!(c.address(), Ok(address));
    assert!(matches!(
        DmaMapping::map(
            first.clone(),
            pages(PAGE, 12, 0x1110_0000, Arc::new(AtomicU64::new(0))),
            Direction::Bidirectional,
            u64::MAX
        ),
        Err(DmaError::Unmapped)
    ));
    assert_eq!(
        // SAFETY: the model device is stopped and `token` names a mapping this test made.
        unsafe { first.sync_for_device(token, 0..PAGE, Direction::Bidirectional) },
        Err(DmaError::Unmapped)
    );
    // SAFETY: the model device is stopped, so no transfer reaches this domain's mappings.
    assert!(matches!(unsafe { first.detach() }, Err(VtdError::Busy)));
    drop(first);
    {
        let m = registers.0.lock().unwrap();
        assert_eq!(m.translation(8, address), Some(0xf000000));
        assert_eq!(m.translation(16, address), Some(0xe000000));
    }
    // SAFETY: the model device is stopped, so no transfer reaches this domain's mappings.
    unsafe { c.unmap() }.unwrap();
    // SAFETY: the model device is stopped, so no transfer reaches this domain's mappings.
    drop(unsafe { replacement.detach() }.unwrap());
    drop(replacement);
    // SAFETY: the model device is stopped, so no transfer reaches this domain's mappings.
    unsafe { b.unmap() }.unwrap();
    // SAFETY: the model device is stopped, so no transfer reaches this domain's mappings.
    drop(unsafe { second.detach() }.unwrap());
    drop(second);
    // SAFETY: no requester is attached, or the refusal leaves them all attached.
    unsafe { unit.shut_down() }.unwrap();
}
#[test]
fn failed_context_detach_keeps_hardware_did_claim_and_tables_until_ack() {
    let source = source();
    let registers = ModelRegisters::new();
    let unit =
            // SAFETY: the model registers stand in for the unit, and this test is the only
            // process-context owner.
            unsafe { Unit::take_over(registers.clone(), source, &[8, 16], 48, &[]) }.unwrap();
    let released = Arc::new(AtomicU64::new(0));
    let first =
            // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
            unsafe { unit.attach_requester(RequesterClaim::model(8, released.clone()), &[]) }.unwrap();
    // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
    let second = unsafe { unit.attach_requester(stopped_claim(16), &[]) }.unwrap();
    let before = source.released.load(Ordering::Relaxed);
    registers.0.lock().unwrap().block_context = true;
    // SAFETY: the model device is stopped, so no transfer reaches this domain's mappings.
    assert!(matches!(unsafe { first.detach() }, Err(VtdError::Timeout)));
    assert_eq!(released.load(Ordering::Relaxed), 0);
    assert_eq!(source.released.load(Ordering::Relaxed), before);
    {
        let mut g = unit.lock();
        let state = g.state();
        assert!(state.poisoned);
        assert!(state.domains.contains_key(&8));
        assert_eq!(state.domains[&8].did, first.domain_id());
    }
    assert!(matches!(
        // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
        unsafe { unit.attach_requester(stopped_claim(8), &[]) },
        Err(AttachRequesterFailure {
            error: VtdError::Busy,
            ..
        })
    ));
    // SAFETY: no requester is attached, or the refusal leaves them all attached.
    assert_eq!(unsafe { unit.shut_down() }, Err(VtdError::Busy));
    registers.0.lock().unwrap().block_context = false;
    // SAFETY: the model device is stopped, so no transfer reaches this domain's mappings.
    drop(unsafe { first.detach() }.unwrap());
    assert_eq!(released.load(Ordering::Relaxed), 1);
    drop(first);
    // SAFETY: the model device is stopped, so no transfer reaches this domain's mappings.
    drop(unsafe { second.detach() }.unwrap());
    drop(second);
    // SAFETY: no requester is attached, or the refusal leaves them all attached.
    unsafe { unit.shut_down() }.unwrap();
}
#[test]
fn hardware_did_capacity_quarantine_and_software_epochs_never_wrap_or_reuse_early() {
    for nd in 0..=7 {
        let registers = ModelRegisters::new();
        registers
            .0
            .lock()
            .unwrap()
            .values
            .entry(CAP)
            .and_modify(|v| *v = (*v & !7) | nd);
        let source = source();
        // SAFETY: the model registers stand in for the unit, and this test is the only
        // process-context owner.
        let result = unsafe { Unit::take_over(registers, source, &[8], 48, &[]) };
        if nd == 7 {
            assert!(matches!(
                result,
                Err(TakeOverError {
                    error: VtdError::Unsupported,
                    started: false
                })
            ));
            assert_eq!(source.next.load(Ordering::Relaxed), 0x100000);
        } else {
            let unit = result.unwrap();
            assert_eq!(unit.max_domains, 1u32 << (4 + 2 * nd));
            // SAFETY: no requester is attached, or the refusal leaves them all attached.
            unsafe { unit.shut_down() }.unwrap();
        }
    }
    for invalid in [&[][..], &[8, 8][..]] {
        assert!(matches!(
            // SAFETY: the model registers stand in for the unit, and this test is the only
            // process-context owner.
            unsafe { Unit::take_over(ModelRegisters::new(), source(), invalid, 48, &[]) },
            Err(TakeOverError {
                error: VtdError::Unsupported,
                started: false
            })
        ));
    }
    // Requesters on two buses: a context table under each root entry.
    let unit =
            // SAFETY: the model registers stand in for the unit, and this test is the only
            // process-context owner.
            unsafe { Unit::take_over(ModelRegisters::new(), source(), &[8, 0x308], 48, &[]) }
                .unwrap();
    {
        let mut guard = unit.lock();
        let state = guard.state();
        assert_eq!(state.contexts.len(), 2);
        for bus in [0, 3] {
            assert_eq!(
                state.root.read(bus * 2),
                state.contexts[&(bus as u8)].physical() | 1
            );
            assert_eq!(state.root.read(bus * 2 + 1), 0);
        }
        assert_eq!(state.root.read(1), 0);
    }
    // SAFETY: no requester is attached, or the refusal leaves them all attached.
    unsafe { unit.shut_down() }.unwrap();
    let registers = ModelRegisters::new();
    let inventory: Vec<u16> = (0..16).collect();
    // SAFETY: the model registers stand in for the unit, and this test is the only
    // process-context owner.
    let unit = unsafe { Unit::take_over(registers, source(), &inventory, 48, &[]) }.unwrap();
    let mut domains = Vec::new();
    for rid in 0..15 {
        // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
        domains.push(unsafe { unit.attach_requester(stopped_claim(rid), &[]) }.unwrap());
    }
    assert!(matches!(
        // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
        unsafe { unit.attach_requester(stopped_claim(15), &[]) },
        Err(AttachRequesterFailure {
            error: VtdError::Busy,
            ..
        })
    ));
    let abandoned = domains.remove(3);
    let quarantined_did = abandoned.domain_id();
    drop(abandoned);
    {
        let mut g = unit.lock();
        assert!(!g.state().domains[&3].lifetime.is_live());
    }
    let retired = domains.remove(3);
    let reusable = retired.domain_id();
    // SAFETY: the model device is stopped, so no transfer reaches this domain's mappings.
    drop(unsafe { retired.detach() }.unwrap());
    drop(retired);
    // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
    let replacement = unsafe { unit.attach_requester(stopped_claim(15), &[]) }.unwrap();
    assert_eq!(replacement.domain_id(), reusable);
    assert_ne!(replacement.domain_id(), quarantined_did);
    // SAFETY: the model device is stopped, so no transfer reaches this domain's mappings.
    drop(unsafe { replacement.detach() }.unwrap());
    drop(replacement);
    {
        let mut g = unit.lock();
        g.state().next_generation = u64::MAX;
    }
    assert!(matches!(
        // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
        unsafe { unit.attach_requester(stopped_claim(15), &[]) },
        Err(AttachRequesterFailure {
            error: VtdError::Unsupported,
            ..
        })
    ));
    {
        let mut g = unit.lock();
        g.state().next_id = u64::MAX;
    }
    assert!(matches!(
        DmaMapping::map(
            domains[0].clone(),
            pages(PAGE, 12, 0x11000000, Arc::new(AtomicU64::new(0))),
            Direction::Bidirectional,
            u64::MAX
        ),
        Err(DmaError::MappingFailed)
    ));
    for domain in domains {
        // SAFETY: the model device is stopped, so no transfer reaches this domain's mappings.
        drop(unsafe { domain.detach() }.unwrap());
    }
    assert_eq!(
        // SAFETY: no requester is attached, or the refusal leaves them all attached.
        unsafe { unit.shut_down() },
        Err(VtdError::Busy),
        "abandoned claim must permanently reserve its actual context"
    );
}

#[test]
fn active_noncoherent_walker_never_reaches_unpublished_children() {
    let source = source();
    let registers = ModelRegisters::new();
    {
        let mut model = registers.0.lock().unwrap();
        model.values.insert(ECAP, 0x10 << 8);
        model.source = Some(source);
    }
    // SAFETY: stopped isolated model; enabling TE activates the observer.
    let unit = unsafe { Unit::take_over(registers.clone(), source, &[8], 48, &[]) }.unwrap();
    let domain =
            // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
            unsafe { unit.attach_requester(RequesterClaim::model(8, Arc::new(AtomicU64::new(0))), &[]) }
                .unwrap();
    let mut first = DmaMapping::map(
        domain.clone(),
        pages(PAGE, 12, 0xb000000, Arc::new(AtomicU64::new(0))),
        Direction::Bidirectional,
        u64::MAX,
    )
    .unwrap();
    let first_iova = first.address().unwrap();
    // Cross a 2 MiB boundary while an older mapping is reachable. Every
    // individual visible parent publication invokes the walker observer;
    // delaying all child evictions until final invalidation fails here.
    let mut second = DmaMapping::map(
        domain.clone(),
        pages(2 * 1024 * 1024, 12, 0xc000000, Arc::new(AtomicU64::new(0))),
        Direction::Bidirectional,
        u64::MAX,
    )
    .unwrap();
    let second_iova = second.address().unwrap();
    {
        let model = registers.0.lock().unwrap();
        assert!(model.active_observations > 10);
        assert_eq!(model.translation(8, first_iova), Some(0xb000000));
        assert_eq!(
            model.translation(8, second_iova + 511 * 4096),
            Some(0xc000000 + 511 * 4096)
        );
    }
    // SAFETY: stopped synchronous model; removal must evict the leaves.
    unsafe { second.unmap() }.unwrap();
    assert_eq!(
        registers.0.lock().unwrap().translation(8, second_iova),
        None
    );
    assert_eq!(
        registers.0.lock().unwrap().translation(8, first_iova),
        Some(0xb000000)
    );
    // SAFETY: no pending DMA or asynchronous work exists in the model.
    unsafe { first.unmap() }.unwrap();
    assert_eq!(registers.0.lock().unwrap().translation(8, first_iova), None);
    // SAFETY: all mappings retired and requester stays stopped.
    unsafe { domain.detach() }.unwrap();
    drop(domain);
    // SAFETY: no requester is attached, or the refusal leaves them all attached.
    unsafe { unit.shut_down() }.unwrap();
}

#[test]
fn only_a_refusal_before_any_write_from_a_unit_read_off_leaves_it_off() {
    let refused = |error, started| TakeOverError { error, started };
    for error in [
        VtdError::Unsupported,
        VtdError::RegisterRange,
        VtdError::Memory,
    ] {
        assert!(refused(error, false).leaves_unit_off(), "{error:?}");
        assert!(!refused(error, true).leaves_unit_off(), "{error:?}");
    }
    for error in [VtdError::Busy, VtdError::RegisterRead] {
        assert!(!refused(error, false).leaves_unit_off(), "{error:?}");
    }
    // An unsupported address width is refused before any register write.
    let registers = ModelRegisters::new();
    // SAFETY: the model registers stand in for the unit, and this test is the
    // only process-context owner.
    let result = unsafe { Unit::take_over(registers.clone(), source(), &[8], 31, &[]) };
    assert!(result.is_err_and(TakeOverError::leaves_unit_off));
    assert!(registers.0.lock().unwrap().writes.is_empty());
}

#[test]
fn all_ones_control_reads_never_establish_a_domain() {
    for offset in [CAP, ECAP, GSTS, PMEN] {
        let registers = ModelRegisters::new();
        let value = if matches!(offset, CAP | ECAP) {
            u64::MAX
        } else {
            u64::from(u32::MAX)
        };
        registers.0.lock().unwrap().values.insert(offset, value);
        let source = source();
        assert!(matches!(
            // SAFETY: explicit failed-register model; no takeover may occur.
            unsafe { Unit::take_over(registers.clone(), source, &[8], 48, &[]) },
            Err(TakeOverError {
                error: VtdError::RegisterRead,
                started: false
            })
        ));
        assert_eq!(source.next.load(Ordering::Relaxed), 0x100000);
        assert!(registers.0.lock().unwrap().writes.is_empty());
    }
    for command in [ROOT_POINTER, TRANSLATION] {
        let registers = ModelRegisters::new();
        registers.0.lock().unwrap().fail_gsts_after = Some(command);
        let source = source();
        let before = quarantined_units();
        assert!(matches!(
            // SAFETY: model injects failed GSTS only after this real stage's command; no
            // acknowledged usable Arc may escape.
            unsafe { Unit::take_over(registers.clone(), source, &[8], 48, &[]) },
            Err(TakeOverError {
                error: VtdError::RegisterRead,
                started: true
            })
        ));
        assert!(quarantined_units() > before);
        assert!(source.next.load(Ordering::Relaxed) > 0x100000);
        assert_eq!(source.released.load(Ordering::Relaxed), 0);
        if command == ROOT_POINTER {
            assert!(
                !registers
                    .0
                    .lock()
                    .unwrap()
                    .writes
                    .contains(&(GCMD, u64::from(TRANSLATION)))
            );
        }
    }
}

#[test]
fn missing_flush_capability_and_malformed_line_sizes_are_refused() {
    assert_eq!(qualified_flush_line(0, 8 << 8), Err(VtdError::Unsupported));
    for encoded in [0, 3, 255] {
        assert_eq!(
            qualified_flush_line(1 << 19, encoded << 8),
            Err(VtdError::Unsupported)
        );
    }
    assert_eq!(qualified_flush_line(1 << 19, 8 << 8), Ok(64));
}

#[test]
fn unmap_invalidates_the_aligned_page_block_when_the_unit_takes_psi() {
    for (largest, page_selective) in [(9u64, true), (1, false)] {
        let registers = ModelRegisters::new();
        *registers.0.lock().unwrap().values.get_mut(&CAP).unwrap() |=
            CAP_PAGE_SELECTIVE | largest << CAP_MAX_ADDRESS_MASK_SHIFT;
        // SAFETY: exclusive stopped model.
        let unit = unsafe { Unit::take_over(registers.clone(), source(), &[8], 48, &[]) }.unwrap();
        // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
        let domain = unsafe {
            unit.attach_requester(RequesterClaim::model(8, Arc::new(AtomicU64::new(0))), &[])
        }
        .unwrap();
        let pin = pages(3 * PAGE, 12, 0xa000000, Arc::new(AtomicU64::new(0)));
        let mut mapping =
            DmaMapping::map(domain.clone(), pin, Direction::Bidirectional, u64::MAX).unwrap();
        let (first, last) = {
            let address = mapping.address().unwrap();
            (address >> 12, (address + 3 * PAGE as u64 - 1) >> 12)
        };
        registers.0.lock().unwrap().writes.clear();
        // SAFETY: stopped synchronous model.
        unsafe { mapping.unmap() }.unwrap();
        let writes = registers.0.lock().unwrap().writes.clone();
        let request = writes
            .iter()
            .find(|(offset, _)| *offset == unit.iotlb)
            .unwrap()
            .1;
        let address = writes.iter().find(|(offset, _)| *offset == unit.iotlb - 8);
        if page_selective {
            assert_eq!(request & (3 << 60), IOTLB_PAGE);
            assert_eq!((request >> IOTLB_DOMAIN_SHIFT) & 0xffff, 1);
            // The smallest aligned block holding all three pages.
            let mask = u64::from(u64::BITS - (first ^ last).leading_zeros());
            assert!((2..=3).contains(&mask));
            assert_eq!(address.unwrap().1, (first >> mask << mask << 12) | mask);
        } else {
            // Past the unit's largest mask: the whole domain.
            assert_eq!(request & (3 << 60), IOTLB_DOMAIN);
            assert!(address.is_none());
        }
        // SAFETY: all mappings removed and no model DMA can restart.
        unsafe { domain.detach() }.unwrap();
        drop(domain);
        // SAFETY: every requester is detached.
        unsafe { unit.shut_down() }.unwrap();
    }
}

#[test]
fn noncoherent_table_flushes_precede_root_and_each_mapping_invalidation() {
    let registers = ModelRegisters::new();
    registers.0.lock().unwrap().values.insert(ECAP, 0x10 << 8);
    // SAFETY: exclusive stopped model with CPUID-checked native flushes.
    let unit = unsafe { Unit::take_over(registers.clone(), source(), &[8], 48, &[]) }.unwrap();
    let domain =
            // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
            unsafe { unit.attach_requester(RequesterClaim::model(8, Arc::new(AtomicU64::new(0))), &[]) }
                .unwrap();
    assert!(unit.table_cacheline.is_some());
    let root_position = registers
        .0
        .lock()
        .unwrap()
        .cache_events
        .iter()
        .position(|event| *event == (false, RTADDR))
        .unwrap();
    assert_eq!(
        registers.0.lock().unwrap().cache_events[..root_position]
            .iter()
            .filter(|event| event.0)
            .count(),
        2
    );
    registers.0.lock().unwrap().cache_events.clear();
    let pin = pages(PAGE, 12, 0xa000000, Arc::new(AtomicU64::new(0)));
    let mut mapping =
        DmaMapping::map(domain.clone(), pin, Direction::Bidirectional, u64::MAX).unwrap();
    // Every table the mapping touched, and no other, is flushed before
    // the publication: here the write-buffer flush, then the IOTLB's.
    let check = |publication: usize, count: usize| {
        let events = &registers.0.lock().unwrap().cache_events;
        let published = events
            .iter()
            .position(|event| *event == (false, publication))
            .unwrap();
        let flushed: alloc::collections::BTreeSet<_> = events[..published]
            .iter()
            .filter(|event| event.0)
            .map(|event| event.1)
            .collect();
        assert_eq!(flushed.len(), count);
        assert!(!events[published..].iter().any(|event| event.0));
    };
    // A fresh domain's mapping builds a path through every one of its
    // tables; the unit's root and context tables stay as they were.
    let tables = {
        let mut guard = unit.lock();
        guard.state().domains[&8].tables.len()
    };
    check(GCMD, tables);
    assert!(
        !registers
            .0
            .lock()
            .unwrap()
            .cache_events
            .contains(&(false, unit.iotlb))
    );
    registers.0.lock().unwrap().cache_events.clear();
    registers.0.lock().unwrap().block_iotlb = true;
    assert_eq!(
        // SAFETY: stopped synchronous model; unmap flush must precede IOTLB.
        unsafe { mapping.unmap() },
        Err(DmaError::InvalidationFailed)
    );
    // Only the leaf table changes.
    check(unit.iotlb, 1);
    registers.0.lock().unwrap().cache_events.clear();
    registers.0.lock().unwrap().block_iotlb = false;
    // SAFETY: same stopped requester; retry must flush again.
    unsafe { mapping.unmap() }.unwrap();
    check(unit.iotlb, 1);
    // SAFETY: all mappings removed and no model DMA can restart.
    unsafe { domain.detach() }.unwrap();
    drop(domain);
    // SAFETY: no requester is attached, or the refusal leaves them all attached.
    unsafe { unit.shut_down() }.unwrap();
}

#[test]
fn native_page_array_maps_through_real_tables_and_reclaims_after_acknowledged_unmap() {
    let registers = ModelRegisters::new();
    let source = source();
    // SAFETY: exclusively owned stopped requester in the explicit model.
    let unit = unsafe { Unit::take_over(registers.clone(), source, &[0x18], 48, &[]) }.unwrap();
    // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
    let domain = unsafe {
        unit.attach_requester(
            RequesterClaim::model(0x18, Arc::new(AtomicU64::new(0))),
            &[],
        )
    }
    .unwrap();
    let released = Arc::new(AtomicU64::new(0));
    // One 16 KiB native page; VT-d uses four 4 KiB leaves.
    let pin = pages(16384, 14, 0x8000000, released.clone());
    let mut mapping =
        DmaMapping::map(domain.clone(), pin, Direction::ToDevice, u32::MAX as u64).unwrap();
    let address = mapping.address().unwrap();
    assert_ne!(address, 0x8000000);
    {
        let mut guard = unit.lock();
        let state = guard.state();
        let live = &state.domains[&0x18].mappings[&address];
        assert_eq!(live.leaves.len(), 4);
        for (index, &(table, slot)) in live.leaves.iter().enumerate() {
            assert_eq!(
                state.domains[&0x18].tables[table].read(slot),
                (0x8000000 + (index * 4096) as u64) | READ
            );
        }
        assert_eq!(state.root.read(0), state.contexts[&0].physical() | 1);
        assert_eq!(state.contexts[&0].read(0x18 * 2 + 1), (1 << 8) | 2);
    }
    mapping.sync_for_device(0..16384).unwrap();
    let token = {
        let mut guard = unit.lock();
        guard.state().domains[&0x18].mappings[&address].info
    };
    assert_eq!(
        // SAFETY: defensive error-path probe; invalid metadata is rejected before any model DMA
        // cache/memory operation can occur.
        unsafe {
            domain.sync_for_device(
                DomainMapping {
                    id: token.id + 1,
                    ..token
                },
                0..4096,
                Direction::ToDevice,
            )
        },
        Err(DmaError::Unmapped)
    );
    assert_eq!(released.load(Ordering::Relaxed), 0);
    registers.0.lock().unwrap().block_iotlb = true;
    assert_eq!(
        // SAFETY: model requester has no outstanding DMA and is stopped.
        unsafe { mapping.unmap() },
        Err(DmaError::InvalidationFailed)
    );
    assert_eq!(released.load(Ordering::Relaxed), 0);
    registers.0.lock().unwrap().block_iotlb = false;
    // SAFETY: same stopped requester, retry of kept original mapping.
    unsafe { mapping.unmap() }.unwrap();
    assert_eq!(released.load(Ordering::Relaxed), 1);
    // SAFETY: all mappings are retired and model requester remains stopped.
    unsafe { domain.detach() }.unwrap();
    drop(domain);
    // SAFETY: no requester is attached, or the refusal leaves them all attached.
    unsafe { unit.shut_down() }.unwrap();
    let table_count = source.next.load(Ordering::Relaxed).saturating_sub(0x100000) / 4096;
    drop(unit);
    assert_eq!(source.released.load(Ordering::Relaxed), table_count);
    let model = registers.0.lock().unwrap();
    let root = model
        .writes
        .iter()
        .position(|(offset, _)| *offset == RTADDR)
        .unwrap();
    let context = model
        .writes
        .iter()
        .position(|(offset, _)| *offset == CCMD)
        .unwrap();
    let enable = model
        .writes
        .iter()
        .position(|(offset, value)| *offset == GCMD && *value == u64::from(TRANSLATION))
        .unwrap();
    assert!(root < context && context < enable);
}

#[test]
fn failed_translation_disable_keeps_tables_until_acknowledgement() {
    let registers = ModelRegisters::new();
    let source = source();
    // SAFETY: exclusively stopped model unit, with real allocated tables.
    let unit = unsafe { Unit::take_over(registers.clone(), source, &[8], 48, &[]) }.unwrap();
    let domain =
            // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
            unsafe { unit.attach_requester(RequesterClaim::model(8, Arc::new(AtomicU64::new(0))), &[]) }
                .unwrap();
    // SAFETY: the model device is stopped, so no transfer reaches this domain's mappings.
    unsafe { domain.detach() }.unwrap();
    drop(domain);
    let retained_before = source.released.load(Ordering::Relaxed);
    registers.0.lock().unwrap().block_te_off = true;
    // SAFETY: no model requesters or live mappings; inject TE-off timeout.
    assert_eq!(unsafe { unit.shut_down() }, Err(VtdError::Timeout));
    assert_eq!(source.released.load(Ordering::Relaxed), retained_before);
    assert_ne!(registers.read32(GSTS) & TRANSLATION, 0);
    let before = quarantined_units();
    drop(unit);
    assert!(quarantined_units() > before);
    assert_eq!(source.released.load(Ordering::Relaxed), retained_before);
}

#[test]
fn busy_firmware_unit_is_refused_without_writes() {
    let registers = ModelRegisters::new();
    registers
        .0
        .lock()
        .unwrap()
        .values
        .insert(GSTS, u64::from(TRANSLATION));
    let source = source();
    assert!(matches!(
        // SAFETY: model probe; active firmware translation must be refused.
        unsafe { Unit::take_over(registers.clone(), source, &[8], 48, &[]) },
        Err(TakeOverError {
            error: VtdError::Busy,
            started: false
        })
    ));
    assert_eq!(source.next.load(Ordering::Relaxed), 0x100000);
    assert!(registers.0.lock().unwrap().writes.is_empty());
}

#[test]
fn failed_map_quarantines_the_domain_and_keeps_pins() {
    let registers = ModelRegisters::new();
    let source = source();
    registers.0.lock().unwrap().values.insert(GSTS, 0);
    // SAFETY: exclusively owned model unit, all DMA stopped.
    let unit = unsafe { Unit::take_over(registers.clone(), source, &[8], 48, &[]) }.unwrap();
    let domain =
            // SAFETY: the model requester is stopped and owned by this test, with no DMA in flight.
            unsafe { unit.attach_requester(RequesterClaim::model(8, Arc::new(AtomicU64::new(0))), &[]) }
                .unwrap();
    let released = Arc::new(AtomicU64::new(0));
    let pin = pages(4096, 12, 0x9000000, released.clone());
    // Without Caching Mode a new mapping needs only the write-buffer
    // flush, which fails here.
    registers.0.lock().unwrap().fail_gsts_after = Some(TRANSLATION | WRITE_BUFFER);
    assert!(matches!(
        DmaMapping::map(domain.clone(), pin, Direction::Bidirectional, u64::MAX),
        Err(DmaError::InvalidationFailed)
    ));
    assert_eq!(released.load(Ordering::Relaxed), 0);
    let before = quarantined_domains();
    drop(domain);
    drop(unit);
    assert!(quarantined_domains() > before);
    assert_eq!(source.released.load(Ordering::Relaxed), 0);
    assert_eq!(released.load(Ordering::Relaxed), 0);
}

#[test]
fn invalid_window_geometry_never_publishes_a_hardware_root() {
    for range in [0..u64::MAX, u64::MAX - 4096..u64::MAX, 0x8000..0x8000] {
        let registers = ModelRegisters::new();
        let source = source();
        // SAFETY: the registers and page allocator are this test's exclusive
        // software models; the invalid range must cause no hardware writes.
        let result = unsafe { Unit::take_over(registers.clone(), source, &[8], 48, &[range]) };
        assert!(matches!(
            result,
            Err(TakeOverError {
                error: VtdError::Unsupported,
                started: false
            })
        ));
        assert!(registers.0.lock().unwrap().writes.is_empty());
    }
}

#[test]
fn initial_root_drain_precedes_private_attachment_and_requires_write_drain() {
    for supported in [false, true] {
        let registers = ModelRegisters::new();
        if !supported {
            *registers.0.lock().unwrap().values.get_mut(&CAP).unwrap() &= !CAP_WRITE_DRAIN;
        }
        // SAFETY: isolated, exclusive model unit and idle original requesters.
        let unit = unsafe {
            Unit::take_over(
                registers.clone(),
                source(),
                &[8],
                48,
                core::slice::from_ref(&(0x800000..0x801000)),
            )
        }
        .unwrap();
        let before = registers.0.lock().unwrap().writes.len();
        assert_eq!(
            unit.drain_initial_requester(9),
            Err(DmaError::IommuUnavailable)
        );
        assert_eq!(registers.0.lock().unwrap().writes.len(), before);
        if supported {
            let pin = pages(PAGE, 12, 0x800000, Arc::new(AtomicU64::new(0)));
            let cpu = pin.cpu_mapping(CacheAttribute::WriteBack).unwrap();
            let pointer = cpu.address(0, 4).unwrap().as_ptr().cast::<u32>();
            registers
                .0
                .lock()
                .unwrap()
                .pending_payload
                .push((pointer as usize, 0x76543210));
            unit.drain_initial_requester(8).unwrap();
            // SAFETY: owned aligned model word, pending writer completed above.
            assert_eq!(u32::from_le(unsafe { pointer.read_volatile() }), 0x76543210);
            assert!(registers.0.lock().unwrap().pending_payload.is_empty());
            // SAFETY: the model has no more DMA, IRQ or worker producers.
            let domain = unsafe { unit.attach_requester(stopped_claim(8), &[]) }.unwrap();
            let before = registers.0.lock().unwrap().writes.len();
            assert_eq!(
                unit.drain_initial_requester(8),
                Err(DmaError::IommuUnavailable)
            );
            assert_eq!(registers.0.lock().unwrap().writes.len(), before);
            // SAFETY: no model mappings or request producers remain.
            drop(unsafe { domain.detach() }.unwrap());
            drop(domain);
        } else {
            assert_eq!(
                unit.drain_initial_requester(8),
                Err(DmaError::DrainUnavailable)
            );
            assert_eq!(registers.0.lock().unwrap().writes.len(), before);
        }
        // SAFETY: every modeled requester and pending transfer has retired.
        unsafe { unit.shut_down() }.unwrap();
    }
}

#[test]
fn published_legacy_root_uses_full_entries_for_buses_zero_one_and_255() {
    let source = source();
    let registers = ModelRegisters::new();
    {
        let mut model = registers.0.lock().unwrap();
        model.values.insert(ECAP, 0x10 << 8); // Noncoherent walker: only real flushes publish.
        model.source = Some(source);
    }
    // SAFETY: exact stopped register/RAM peer, complete requester inventory.
    let unit = unsafe {
        Unit::take_over(
            registers.clone(),
            source,
            &[0x0008, 0x0108, 0xff08],
            48,
            core::slice::from_ref(&(0x2000..0x3000)),
        )
    }
    .unwrap();
    {
        let model = registers.0.lock().unwrap();
        let published = model.root_bytes();
        assert_eq!(published.len(), 4096);
        let mut contexts = Vec::new();
        // Spec9.1: inspect actual flushed bytes as 256 sixteen-byte entries,
        // independently from Table's u64 indexing or production write helpers.
        for (bus, entry) in published.as_chunks::<16>().0.iter().enumerate() {
            let low = u64::from_le_bytes(entry[..8].try_into().unwrap());
            let high = u64::from_le_bytes(entry[8..].try_into().unwrap());
            assert_eq!(high, 0, "bus {bus} reserved upper half");
            if matches!(bus, 0 | 1 | 255) {
                assert_eq!(low & 1, 1, "bus {bus} missing actual root entry");
                assert_eq!(low & 0xffe, 0, "bus {bus} reserved lower bits");
                contexts.push(low & ADDRESS);
            } else {
                assert_eq!(low, 0, "unowned/adjacent bus {bus} changed");
            }
        }
        contexts.sort_unstable();
        contexts.dedup();
        assert_eq!(
            contexts.len(),
            3,
            "each bus must lead to its own context page"
        );
        for rid in [0x0008, 0x0108, 0xff08] {
            assert_eq!(model.translation(rid, 0x2000), Some(0x2000));
            assert_eq!(model.translation(rid, 0x2fff), Some(0x2fff));
            assert_eq!(model.translation(rid, 0x3000), None);
        }
        for rid in [0x0208, 0x7f08, 0xfe08, 0xff10] {
            assert_eq!(model.translation(rid, 0x2000), None);
        }
    }
    // SAFETY: this synchronous peer has no attached or in-flight requester.
    unsafe { unit.shut_down() }.unwrap();
}

#[test]
fn dynamic_bus_root_publication_preserves_reserved_halves_and_other_buses() {
    let source = source();
    let registers = ModelRegisters::new();
    {
        let mut model = registers.0.lock().unwrap();
        model.values.insert(ECAP, 0x10 << 8);
        model.source = Some(source);
    }
    // SAFETY: exact owned peer; bus1 does not exist in the original inventory.
    let unit = unsafe {
        Unit::take_over(
            registers.clone(),
            source,
            &[0x0008, 0xff08],
            48,
            core::slice::from_ref(&(0x4000..0x5000)),
        )
    }
    .unwrap();
    let before = registers.0.lock().unwrap().root_bytes();
    unit.admit_requester(0x0108).unwrap();
    let after = {
        let model = registers.0.lock().unwrap();
        let after = model.root_bytes();
        assert_ne!(&after[16..24], &[0; 8], "bus1 low half was not published");
        for (offset, (&old, &new)) in before.iter().zip(&after).enumerate() {
            if !(16..24).contains(&offset) {
                assert_eq!(old, new, "dynamic publication changed byte {offset}");
            }
        }
        for (bus, entry) in after.as_chunks::<16>().0.iter().enumerate() {
            assert_eq!(&entry[8..], &[0; 8], "bus {bus} reserved high half");
        }
        assert_eq!(model.translation(0x0008, 0x4000), Some(0x4000));
        assert_eq!(model.translation(0xff08, 0x4000), Some(0x4000));
        assert_eq!(
            model.translation(0x0108, 0x4000),
            None,
            "new context must remain blocked"
        );
        assert_eq!(model.translation(0x0208, 0x4000), None);
        after
    };
    // SAFETY: this real model claim is stopped and paired to the new RID.
    let domain = unsafe { unit.attach_requester(stopped_claim(0x0108), &[]) }.unwrap();
    let mut mapping = DmaMapping::map(
        domain.clone(),
        pages(PAGE, 12, 0x990000, Arc::new(AtomicU64::new(0))),
        Direction::Bidirectional,
        u64::MAX,
    )
    .unwrap();
    let address = mapping.address().unwrap();
    {
        let model = registers.0.lock().unwrap();
        assert_eq!(
            model.root_bytes(),
            after,
            "attaching changed a root/adjacent bus entry"
        );
        assert_eq!(model.translation(0x0108, address), Some(0x990000));
        assert_eq!(model.translation(0x0008, 0x4000), Some(0x4000));
        assert_eq!(model.translation(0xff08, 0x4000), Some(0x4000));
        assert_eq!(model.translation(0x0208, address), None);
        assert_eq!(model.translation(0x7f08, address), None);
    }
    // SAFETY: actual synchronous peer stopped before unmap/detach.
    unsafe { mapping.unmap() }.unwrap();
    // SAFETY: all actual mappings are gone, no device/CPU callback remains.
    drop(unsafe { domain.detach() }.unwrap());
    // SAFETY: no requester is attached; initial window peers are also stopped.
    unsafe { unit.shut_down() }.unwrap();
}

mod requester_owner;

#[test]
fn mapped_registers_keep_and_retire_the_original_counted_mapping() {
    use stela_driver_base::bus::{
        mmio::owned::PhysicalSpan, pci::owned::test_support::bar_fixture,
    };

    let (owner, mapping) = bar_fixture(PhysicalSpan::new(0xfed9_0000, 4096).unwrap(), 4096);
    // SAFETY: the actual isolated register fixture owns this sole mapping;
    // no hardware or register accessor runs in this lifetime check.
    let registers = unsafe { MmioRegisters::from_mapping(mapping, || 0, 1) }.unwrap();
    assert_eq!(owner.unmaps.load(Ordering::Relaxed), 0);
    drop(registers);
    assert_eq!(owner.unmaps.load(Ordering::Relaxed), 1);
    // SAFETY: the same mapping has acknowledged unmap, and this test
    // published no raw access, alias or device callback.
    unsafe { owner.finish_unmapped() }.unwrap();
}

#[test]
fn blocked_initial_cohort_is_exact_and_each_requester_is_claimed_once() {
    let registers = ModelRegisters::new();
    let requesters = [0x0008, 0x0208];
    // SAFETY: this test exclusively owns the stopped model and its register bank.
    let unit =
        unsafe { Unit::take_over(registers.clone(), source(), &requesters, 48, &[]) }.unwrap();
    let before = registers.0.lock().unwrap().writes.len();
    assert!(matches!(
        unit.acknowledge_initial_block(&requesters[..1]),
        Err(DmaError::IommuUnavailable)
    ));
    assert_eq!(registers.0.lock().unwrap().writes.len(), before);
    let cohort = unit.acknowledge_initial_block(&requesters).unwrap();
    let writes = &registers.0.lock().unwrap().writes[before..].to_vec();
    assert!(writes.contains(&(CCMD, CONTEXT_INVALIDATE | CONTEXT_GLOBAL)));
    assert!(writes.contains(&(
        unit.iotlb,
        IOTLB_INVALIDATE | IOTLB_GLOBAL | IOTLB_READ_DRAIN | IOTLB_WRITE_DRAIN,
    )));
    assert!(matches!(
        unit.acknowledge_initial_block(&requesters),
        Err(DmaError::IommuUnavailable)
    ));
    let first = cohort.claim(requesters[0], &[]).unwrap();
    assert_eq!(first.requester(), requesters[0]);
    let before_check = registers.0.lock().unwrap().writes.len();
    first.check().unwrap();
    assert_eq!(registers.0.lock().unwrap().writes.len(), before_check);
    assert!(matches!(
        cohort.claim(requesters[0], &[]),
        Err(DmaError::IommuUnavailable)
    ));
    first.drain().unwrap();

    // SAFETY: model requester remains stopped with no DMA, IRQ or worker users.
    let domain = unsafe { unit.attach_requester(stopped_claim(requesters[0]), &[]) }.unwrap();
    assert_eq!(first.check(), Err(DmaError::IommuUnavailable));
    assert_eq!(first.drain(), Err(DmaError::IommuUnavailable));
    // SAFETY: the model has no live users or payload mappings.
    drop(unsafe { domain.detach() }.unwrap());
    drop(domain);
    assert_eq!(first.drain(), Err(DmaError::IommuUnavailable));
    cohort.claim(requesters[1], &[]).unwrap().drain().unwrap();
    // SAFETY: every modeled requester and transfer remains stopped.
    unsafe { unit.shut_down() }.unwrap();
}

/// A requester behind a PCI Express to PCI bridge attaches its own ID and
/// the bridge's secondary bus ID to one domain. The alias is claimed once,
/// so a sibling sharing it can neither claim nor attach it, and detach
/// blocks both entries again.
#[test]
fn blocked_requester_attaches_and_detaches_its_aliases_with_it() {
    let registers = ModelRegisters::new();
    let requesters = [0x0620, 0x0628];
    // SAFETY: this test exclusively owns the stopped model and its register bank.
    let unit =
        unsafe { Unit::take_over(registers.clone(), source(), &requesters, 48, &[]) }.unwrap();
    let cohort = unit.acknowledge_initial_block(&requesters).unwrap();
    // No function has the bridge's ID: it is allowed without joining the cohort.
    unit.admit_requester(0x0600).unwrap();
    assert!(matches!(
        cohort.claim(0x0620, &[0x0600, 0x0600]),
        Err(DmaError::IommuUnavailable)
    ));
    let first = cohort.claim(0x0620, &[0x0600]).unwrap();
    assert!(matches!(
        cohort.claim(0x0628, &[0x0600]),
        Err(DmaError::IommuUnavailable)
    ));
    first.drain().unwrap();
    let entry = |rid| {
        let mut guard = unit.lock();
        let (table, index) = guard.state().context(rid);
        (table.read(index), table.read(index + 1))
    };
    // SAFETY: model requester remains stopped with no DMA, IRQ or worker users.
    let domain = unsafe { unit.attach_requester(stopped_claim(0x0620), &[0x0600]) }.unwrap();
    assert_ne!(entry(0x0620).0, 0);
    assert_eq!(entry(0x0600), entry(0x0620));
    // SAFETY: the sibling's model claim stays stopped; refused before effects.
    assert!(unsafe { unit.attach_requester(stopped_claim(0x0628), &[0x0600]) }.is_err());
    // SAFETY: the model has no live users or payload mappings.
    drop(unsafe { domain.detach() }.unwrap());
    assert_eq!(entry(0x0620), (0, 0));
    assert_eq!(entry(0x0600), (0, 0));
    // SAFETY: every modeled requester and transfer remains stopped.
    unsafe { unit.shut_down() }.unwrap();
}

/// Without a blocked root no alias was claimed, so none attaches.
#[test]
fn a_requester_attaches_no_alias_before_the_initial_block() {
    let registers = ModelRegisters::new();
    // SAFETY: this test exclusively owns the stopped model and its register bank.
    let unit = unsafe { Unit::take_over(registers.clone(), source(), &[0x0600, 0x0620], 48, &[]) }
        .unwrap();
    // SAFETY: the model claim stays stopped; refused before effects.
    assert!(unsafe { unit.attach_requester(stopped_claim(0x0620), &[0x0600]) }.is_err());
    // SAFETY: model requester remains stopped with no DMA, IRQ or worker users.
    let domain = unsafe { unit.attach_requester(stopped_claim(0x0620), &[]) }.unwrap();
    // SAFETY: the model has no live users or payload mappings.
    drop(unsafe { domain.detach() }.unwrap());
    // SAFETY: every modeled requester and transfer remains stopped.
    unsafe { unit.shut_down() }.unwrap();
}

#[test]
fn blocked_initial_cohort_refuses_missing_read_drain_and_context_drift() {
    let registers = ModelRegisters::new();
    *registers.0.lock().unwrap().values.get_mut(&CAP).unwrap() &= !CAP_READ_DRAIN;
    // SAFETY: this test exclusively owns an idle isolated model unit.
    let unit = unsafe { Unit::take_over(registers.clone(), source(), &[8], 48, &[]) }.unwrap();
    let before = registers.0.lock().unwrap().writes.len();
    assert!(matches!(
        unit.acknowledge_initial_block(&[8]),
        Err(DmaError::DrainUnavailable)
    ));
    assert_eq!(registers.0.lock().unwrap().writes.len(), before);
    // SAFETY: the model has no transfer or attached requesters.
    unsafe { unit.shut_down() }.unwrap();

    let registers = ModelRegisters::new();
    // SAFETY: this test exclusively owns a second idle isolated model unit.
    let unit = unsafe { Unit::take_over(registers.clone(), source(), &[8], 48, &[]) }.unwrap();
    {
        let mut guard = unit.lock();
        let (table, index) = guard.state().context(8);
        table.write(index + 1, 1);
    }
    let before = registers.0.lock().unwrap().writes.len();
    assert!(matches!(
        unit.acknowledge_initial_block(&[8]),
        Err(DmaError::IommuUnavailable)
    ));
    assert_eq!(registers.0.lock().unwrap().writes.len(), before);
    {
        let mut guard = unit.lock();
        let (table, index) = guard.state().context(8);
        table.write(index + 1, 0);
    }
    registers.0.lock().unwrap().block_iotlb = true;
    assert!(matches!(
        unit.acknowledge_initial_block(&[8]),
        Err(DmaError::InvalidationFailed)
    ));
    assert!(unit.lock().state().poisoned);
    assert!(matches!(
        unit.acknowledge_initial_block(&[8]),
        Err(DmaError::IommuUnavailable)
    ));
}

#[test]
fn blocked_initial_acknowledgment_cannot_reclassify_hotplug_or_an_initial_window() {
    let registers = ModelRegisters::new();
    // SAFETY: exclusive idle model. The initial window is valid model RAM.
    let unit = unsafe {
        Unit::take_over(
            registers.clone(),
            source(),
            &[8],
            48,
            core::slice::from_ref(&(0x800000..0x801000)),
        )
    }
    .unwrap();
    let before = registers.0.lock().unwrap().writes.len();
    assert!(matches!(
        unit.acknowledge_initial_block(&[8]),
        Err(DmaError::IommuUnavailable)
    ));
    assert_eq!(registers.0.lock().unwrap().writes.len(), before);
    // SAFETY: no live model users.
    unsafe { unit.shut_down() }.unwrap();

    let registers = ModelRegisters::new();
    // SAFETY: exclusive idle model with no initial window.
    let unit = unsafe { Unit::take_over(registers.clone(), source(), &[8], 48, &[]) }.unwrap();
    unit.admit_requester(0x108).unwrap();
    let before = registers.0.lock().unwrap().writes.len();
    assert!(matches!(
        unit.acknowledge_initial_block(&[8, 0x108]),
        Err(DmaError::IommuUnavailable)
    ));
    assert_eq!(registers.0.lock().unwrap().writes.len(), before);
    // SAFETY: no live model users.
    unsafe { unit.shut_down() }.unwrap();
}
