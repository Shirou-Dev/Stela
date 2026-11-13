// SPDX-License-Identifier: GPL-2.0
/* Raw Linux pages backed by an explicitly retained platform reservation.
 * Descriptors follow PFNs, including across adjacent allocation boundaries.
 * Allocation records and live/run metadata are separate from struct page:
 * drivers retain the union fields Linux gives them. No native IRQ, userspace
 * mapping, page-cache, reclaim or DMA-domain ownership is inferred here. */
#include <linux/errno.h>
#include <linux/build_bug.h>
#include <linux/folio_batch.h>
#include <linux/gfp.h>
#include <linux/irqflags.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/poison.h>
#include <linux/printk.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <linux/swap.h>
#include <linux/thread_info.h>
#include <linux/sched/mm.h>
#include <linux/sched/task_stack.h>
#include <stela/catalogue.h>
#include <stela/linux.h>
#include <stela/page.h>
#include <stela/task.h>
#include <stela/task_bootstrap.h>

#include <internal.h>
#include "rcu/rcu.h"

#define NO_INDEX SIZE_MAX

/* HVO's masked tail encoding additionally requires a globally aligned
 * vmemmap. This catalog uses the pinned configuration's direct head encoding. */
static_assert(!IS_ENABLED(CONFIG_HUGETLB_PAGE_OPTIMIZE_VMEMMAP));
static_assert(!IS_ENABLED(CONFIG_SWAP) && !IS_ENABLED(CONFIG_NUMA));

struct page_state {
	size_t allocation;
	size_t run_first;
	unsigned int run_order;
	bool live;
	bool compound;
};

/* At most one pin per reservation page. Reserving a record before calling the
 * platform also permits allocation-free rollback of malformed provider output
 * that cannot be associated with any valid PFN. */
struct allocation_record {
	void *pin;
	size_t first;
	size_t count;
	size_t live;
	size_t next;
    size_t dma_refs;
    u64 external_nonce;
    /* Exact source factory identity only; never dereferenced/interpreted as
     * current/task ownership. Fresh descriptor nonce guards address reuse. */
    const void *external_task;
    enum { STACK_RESERVED, STACK_LENT, STACK_PUBLISHED } external_phase;
};

/* Inventory entries cover only actual writable mappings, never raw allocation
 * padding or guard holes. PFN-sorted descriptors are immutable for one owner. */
struct registered_extent {
    u64 physical_base;
    u8 *cpu_base;
    size_t page_count;
    size_t first;
    u32 kind;
};

static struct {
    u64 generation;
    size_t page_count;
    struct registered_extent *extents;
    size_t extent_count;
	struct stela_linux_page_ops ops;
	void *context;
	struct page *pages;
	struct page_state *state;
	struct allocation_record *allocations;
	size_t free_records;
	size_t retired;
	size_t live_pages;
    size_t stack_admissions;
    bool kernel_roots;
    bool hosted;
    u64 next_stack_nonce;
} catalog;
static u64 last_generation;
static bool in_callback;

/* The one memory node the catalog's pages form, for what Linux code reads of
 * it, and its page counters, which nothing moves. */
struct pglist_data contig_page_data;

atomic_long_t vm_node_stat[NR_VM_NODE_STAT_ITEMS];
atomic_long_t vm_zone_stat[NR_VM_ZONE_STAT_ITEMS];
atomic_long_t _totalram_pages __read_mostly;

void dump_page(const struct page *page, const char *reason)
{
	/* Report the native descriptor without traversing an untrusted mapping. */
	if (PagePoisoned(page))
		pr_warn("page:%p is uninitialized and poisoned\n", page);
	else
		pr_warn("page:%p flags:%lx refcount:%d mapcount:%ld\n", page,
			READ_ONCE(page->flags.f), page_ref_count(page),
			(long)atomic_read(&page->_mapcount) + 1);
	if (reason)
		pr_warn("page dumped because: %s\n", reason);
}

unsigned long zone_reclaimable_pages(struct zone *zone)
{
	/* Without swap or demotion, Linux counts only file-backed LRU pages. */
	return zone_page_state_snapshot(zone, NR_ZONE_INACTIVE_FILE) +
	       zone_page_state_snapshot(zone, NR_ZONE_ACTIVE_FILE);
}
DEFINE_STATIC_KEY_MAYBE(CONFIG_INIT_ON_FREE_DEFAULT_ON, init_on_free);

/* The catalog covers one node and one zone. Runtime stack reservations
 * remain physically present, but the ordinary allocator cannot manage them. */
static void publish_memory_inventory(unsigned long start_pfn, unsigned long end_pfn,
                                     unsigned long present, long managed)
{
	struct zone *zone = &contig_page_data.node_zones[ZONE_NORMAL];
	unsigned long spanned = end_pfn - start_pfn;

	contig_page_data.node_start_pfn = start_pfn;
	contig_page_data.node_spanned_pages = spanned;
	contig_page_data.node_present_pages = present;
	contig_page_data.nr_zones = present ? ZONE_NORMAL + 1 : 0;
	zone->zone_pgdat = present ? &contig_page_data : NULL;
	zone->zone_start_pfn = start_pfn;
	zone->spanned_pages = spanned;
	zone->present_pages = present;
	atomic_long_set(&zone->managed_pages, managed);
	atomic_long_set(&_totalram_pages, managed);
}

void si_meminfo(struct sysinfo *info)
{
	*info = (struct sysinfo){.totalram = totalram_pages(), .mem_unit = PAGE_SIZE};
}

#ifdef STELA_LINUX_PAGE_TEST
static size_t metadata_fail_after = NO_INDEX;
static size_t metadata_live;
#endif

static void *allocate_metadata(size_t size, size_t align)
{
#ifdef STELA_LINUX_PAGE_TEST
	if (metadata_fail_after != NO_INDEX) {
		if (!metadata_fail_after)
			return NULL;
		metadata_fail_after--;
	}
#endif
	void *object = stela_linux_heap_alloc(size, align);
#ifdef STELA_LINUX_PAGE_TEST
	if (object)
		metadata_live++;
#endif
	return object;
}

static void free_metadata(void *object, size_t size, size_t align)
{
#ifdef STELA_LINUX_PAGE_TEST
	if (!metadata_live) {
		pr_warn("page: free_metadata with !metadata_live\n");
		return;
	}
	metadata_live--;
#endif
	stela_linux_heap_free(object, size, align);
}

static void require_context(void)
{
	(void)stela_linux_owner();
	if (in_callback)
		pr_warn("page: require_context in_callback=true\n");
}

static void require_quiescence(void)
{
	require_context();
	if (!stela_linux_quiescent())
		pr_warn("page: require_quiescence called while not quiescent\n");
}

static void require_catalog(void)
{
	require_context();
	if (!catalog.pages)
		pr_warn("page: require_catalog called with NULL catalog.pages\n");
}

unsigned long stela_linux_page_boot_capacity(void)
{
	require_quiescence();
	require_catalog();
	unsigned long pages = 0;

	for (size_t i = 0; i < catalog.extent_count; i++) {
		const struct registered_extent *extent = catalog.extents + i;

		if (extent->kind == STELA_LINUX_PAGE_ORDINARY)
			pages += extent->page_count;
	}
	return pages;
}

int stela_linux_page_owner_context(const struct stela_linux_owner *expected)
{
    struct stela_linux_lease lease;
    stela_linux_lease_snapshot(&lease);
    return expected && lease.owner == expected && !in_callback &&
           stela_linux_quiescent() ? 0 : -EPERM;
}

bool stela_linux_page_request_basic(u32 gfp)
{
	/* x86-64 has no high memory, Stela no cpusets or NUMA nodes, and how hard
	 * to reclaim means nothing to an allocator that does not reclaim. RAM has
	 * one zone: __GFP_DMA32 only asks for what a device reaches, which its
	 * DMA mapping checks against its mask and refuses. TTM's and nouveau's
	 * allocations carry all of these. */
	gfp_t allowed = __GFP_ZERO | __GFP_COMP | __GFP_NOWARN | __GFP_NOMEMALLOC |
		__GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM | __GFP_IO | __GFP_FS |
		__GFP_HIGHMEM | __GFP_DMA32 | __GFP_HARDWALL | __GFP_THISNODE |
		__GFP_NORETRY | __GFP_RETRY_MAYFAIL;
	if (!IS_ENABLED(CONFIG_MEMCG))
		allowed |= __GFP_ACCOUNT;
	return !(gfp & ~(__force u32)allowed);
}

bool stela_linux_page_request_reclaimable(u32 gfp)
{
	/* Explicit mobility-class fallback, separate from the basic policy. A
	 * provider must opt in to actual permitted unmovable RAM backing; this
	 * classifier alone grants neither allocation nor migration authority. */
	u32 reclaimable = (__force u32)__GFP_RECLAIMABLE;
	return (gfp & reclaimable) && stela_linux_page_request_basic(gfp & ~reclaimable);
}

bool stela_linux_page_request_blocking(u32 gfp)
{
	return gfpflags_allow_blocking((__force gfp_t)gfp);
}

static void initialize_page(struct page *page)
{
	memset(page, 0, sizeof(*page));
	set_page_zone(page, ZONE_NORMAL);
	INIT_LIST_HEAD(&page->lru);
	atomic_set(&page->_mapcount, -1);
	set_page_count(page, 0);
}

static int register_inventory(
    const struct stela_linux_page_reservation *extents, const u32 *kinds,
    size_t extent_count, const struct stela_linux_page_ops *ops, void *context,
    bool hosted)
{
    if (hosted != stela_linux_kernel_hosted())
        return -EPERM;
    require_quiescence();
    if (catalog.pages)
        return -EBUSY;
    if (!extents || !extent_count ||
        (!hosted && (!ops || !ops->validate || !ops->allocate || !ops->release)) ||
        extent_count > (size_t)SSIZE_MAX / sizeof(struct registered_extent))
        return -EINVAL;
    u64 generation = extents[0].generation;
    if (!generation || generation <= last_generation)
        return -EINVAL;
    size_t count = 0;
    size_t managed = 0;
    for (size_t i = 0; i < extent_count; i++) {
        const struct stela_linux_page_reservation *item = extents + i;
        if (kinds && kinds[i] != STELA_LINUX_PAGE_ORDINARY &&
            kinds[i] != STELA_LINUX_PAGE_RUNTIME_STACK)
            return -EINVAL;
        if (item->generation != generation || !item->cpu_base || !item->page_count ||
            ((unsigned long)item->cpu_base & ~PAGE_MASK) ||
            (item->physical_base & (PAGE_SIZE - 1)) ||
            item->page_count > (size_t)SSIZE_MAX / PAGE_SIZE ||
            item->page_count > (ULONG_MAX - (unsigned long)item->cpu_base) / PAGE_SIZE ||
            item->page_count > (U64_MAX - item->physical_base) / PAGE_SIZE ||
            item->page_count > SIZE_MAX - count)
            return -EINVAL;
        if (i && item->physical_base < extents[i - 1].physical_base +
                (u64)extents[i - 1].page_count * PAGE_SIZE)
            return -EINVAL;
        for (size_t j = 0; j < i; j++) {
            unsigned long cpu = (unsigned long)item->cpu_base;
            unsigned long other = (unsigned long)extents[j].cpu_base;
            size_t bytes = item->page_count * PAGE_SIZE;
            size_t other_bytes = extents[j].page_count * PAGE_SIZE;
            if (cpu <= other ? other - cpu < bytes : cpu - other < other_bytes)
                return -EINVAL;
        }
        count += item->page_count;
        if (!kinds || kinds[i] == STELA_LINUX_PAGE_ORDINARY)
            managed += item->page_count;
    }
    if (count > (size_t)SSIZE_MAX / sizeof(struct page) ||
        count > (size_t)SSIZE_MAX / sizeof(struct page_state) ||
        count > (size_t)SSIZE_MAX / sizeof(struct allocation_record))
        return -EINVAL;
    struct page *pages = allocate_metadata(count * sizeof(*pages), __alignof__(*pages));
    if (!pages)
        return -ENOMEM;
    struct page_state *state = allocate_metadata(count * sizeof(*state), __alignof__(*state));
    if (!state) {
        free_metadata(pages, count * sizeof(*pages), __alignof__(*pages));
        return -ENOMEM;
    }
    struct allocation_record *allocations = allocate_metadata(count * sizeof(*allocations),
                                                              __alignof__(*allocations));
    if (!allocations) {
        free_metadata(state, count * sizeof(*state), __alignof__(*state));
        free_metadata(pages, count * sizeof(*pages), __alignof__(*pages));
        return -ENOMEM;
    }
    struct registered_extent *inventory = allocate_metadata(extent_count * sizeof(*inventory),
                                                             __alignof__(*inventory));
    if (!inventory) {
        free_metadata(allocations, count * sizeof(*allocations), __alignof__(*allocations));
        free_metadata(state, count * sizeof(*state), __alignof__(*state));
        free_metadata(pages, count * sizeof(*pages), __alignof__(*pages));
        return -ENOMEM;
    }
    size_t first = 0;
    for (size_t i = 0; i < extent_count; i++) {
        inventory[i] = (struct registered_extent){
            .physical_base = extents[i].physical_base, .cpu_base = extents[i].cpu_base,
            .page_count = extents[i].page_count, .first = first,
            .kind = kinds ? kinds[i] : STELA_LINUX_PAGE_ORDINARY,
        };
        first += extents[i].page_count;
    }
    for (size_t i = 0; i < count; i++) {
        initialize_page(pages + i);
        state[i].allocation = NO_INDEX;
        allocations[i] = (struct allocation_record){
            .next = i + 1 < count ? i + 1 : NO_INDEX,
        };
    }
    catalog.generation = generation;
    catalog.page_count = count;
    catalog.extents = inventory;
    catalog.extent_count = extent_count;
    if (ops)
        catalog.ops = *ops;
    catalog.context = context;
    catalog.pages = pages;
    catalog.state = state;
    catalog.allocations = allocations;
    catalog.free_records = 0;
    catalog.retired = NO_INDEX;
    catalog.next_stack_nonce = 1;
    catalog.hosted = hosted;
    lruvec_init(&contig_page_data.__lruvec);
    for (unsigned int i = 0; i < NR_VMSCAN_THROTTLE; i++)
        init_waitqueue_head(&contig_page_data.reclaim_wait[i]);
    const struct stela_linux_page_reservation *last = &extents[extent_count - 1];
    publish_memory_inventory(PHYS_PFN(extents[0].physical_base),
                             PHYS_PFN(last->physical_base) + last->page_count,
                             count, (long)managed);
    last_generation = generation;
    return 0;
}

int stela_linux_page_catalog_register_extents(
    const struct stela_linux_page_reservation *extents, size_t extent_count,
    const struct stela_linux_page_ops *ops, void *context)
{
    return register_inventory(extents, NULL, extent_count, ops, context, false);
}

#ifdef __linux__
int stela_linux_page_model_register(const struct stela_linux_owner *owner,
                                   void *cpu_base, size_t page_count,
                                   void *const *stacks, size_t stack_count)
{
    if (!stela_linux_kernel_hosted() || stela_linux_require_current(owner))
        return -EPERM;
    if (!is_power_of_2(page_count) || page_count > SIZE_MAX / PAGE_SIZE ||
        ((unsigned long)cpu_base & (page_count * PAGE_SIZE - 1)) ||
        (stack_count && !stacks) ||
        stack_count >= (size_t)SSIZE_MAX / sizeof(struct stela_linux_page_reservation))
        return -EINVAL;
    require_quiescence();
    if (catalog.pages)
        return -EBUSY;
    size_t count = stack_count + 1;
    struct stela_linux_page_reservation *extents =
        allocate_metadata(count * sizeof(*extents), __alignof__(*extents));
    if (!extents)
        return -ENOMEM;
    u32 *kinds = allocate_metadata(count * sizeof(*kinds), __alignof__(*kinds));
    if (!kinds) {
        free_metadata(extents, count * sizeof(*extents), __alignof__(*extents));
        return -ENOMEM;
    }
    /* Offsets form a private namespace for this mount's real kept mmaps.
     * Guard pages have no C descriptor and stacks never serve ordinary GFP. */
    extents[0] = (struct stela_linux_page_reservation){
        .generation = 1, .cpu_base = cpu_base, .page_count = page_count,
    };
    kinds[0] = STELA_LINUX_PAGE_ORDINARY;
    size_t stack_pages = THREAD_SIZE / PAGE_SIZE;
    size_t frame = ALIGN(page_count, stack_pages);
    int error = 0;
    if (frame > (U64_MAX >> PAGE_SHIFT) ||
        stack_count > ((U64_MAX >> PAGE_SHIFT) - frame) / stack_pages)
        error = -EOVERFLOW;
    for (size_t i = 0; !error && i < stack_count; i++) {
        if ((unsigned long)stacks[i] & (THREAD_SIZE - 1)) {
            error = -EINVAL;
            break;
        }
        extents[i + 1] = (struct stela_linux_page_reservation){
            .generation = 1, .physical_base = (u64)frame << PAGE_SHIFT,
            .cpu_base = stacks[i], .page_count = stack_pages,
        };
        kinds[i + 1] = STELA_LINUX_PAGE_RUNTIME_STACK;
        frame += stack_pages;
    }
    if (!error)
        error = register_inventory(extents, kinds, count, NULL, NULL, true);
    free_metadata(kinds, count * sizeof(*kinds), __alignof__(*kinds));
    free_metadata(extents, count * sizeof(*extents), __alignof__(*extents));
    return error;
}
#endif

int stela_linux_page_catalog_register(const struct stela_linux_page_reservation *reservation,
                                     const struct stela_linux_page_ops *ops, void *context)
{
    return stela_linux_page_catalog_register_extents(reservation, 1, ops, context);
}

int stela_linux_page_catalog_register_annotated(
    const struct stela_linux_page_extent *input, size_t count,
    const struct stela_linux_page_ops *ops, void *context)
{
    if (stela_linux_kernel_hosted())
        return -EPERM;
    require_quiescence();
    if (catalog.pages)
        return -EBUSY;
    if (!ops || !ops->release_ready || !input || !count ||
        count > (size_t)SSIZE_MAX / sizeof(struct stela_linux_page_extent) ||
        count > (size_t)SSIZE_MAX / sizeof(struct stela_linux_page_reservation) ||
        count > (size_t)SSIZE_MAX / sizeof(u32))
        return -EINVAL;
    for (size_t i = 0; i < count; i++) {
        if (input[i].reserved ||
            (input[i].kind != STELA_LINUX_PAGE_ORDINARY &&
             input[i].kind != STELA_LINUX_PAGE_RUNTIME_STACK))
            return -EINVAL;
        if (input[i].kind == STELA_LINUX_PAGE_RUNTIME_STACK &&
            (input[i].reservation.page_count != THREAD_SIZE / PAGE_SIZE ||
             (input[i].reservation.physical_base & (THREAD_SIZE - 1)) ||
             ((unsigned long)input[i].reservation.cpu_base & (THREAD_ALIGN - 1))))
            return -EINVAL;
    }
    struct stela_linux_page_reservation *extents =
        allocate_metadata(count * sizeof(*extents), __alignof__(*extents));
    if (!extents)
        return -ENOMEM;
    u32 *kinds = allocate_metadata(count * sizeof(*kinds), __alignof__(*kinds));
    if (!kinds) {
        free_metadata(extents, count * sizeof(*extents), __alignof__(*extents));
        return -ENOMEM;
    }
    for (size_t i = 0; i < count; i++) {
        extents[i] = input[i].reservation;
        kinds[i] = input[i].kind;
    }
    int error = register_inventory(extents, kinds, count, ops, context, false);
    free_metadata(kinds, count * sizeof(*kinds), __alignof__(*kinds));
    free_metadata(extents, count * sizeof(*extents), __alignof__(*extents));
    return error;
}

static_assert(sizeof(struct stela_linux_page_extent) == 40);
static_assert(offsetof(struct stela_linux_page_extent, kind) == 32);
static_assert(sizeof(struct stela_linux_stack_admission) == 40);
static_assert(offsetof(struct stela_linux_stack_admission, cpu_base) == 16);
static_assert(sizeof(struct stela_linux_stack_ticket) == 32);
static_assert(offsetof(struct stela_linux_stack_ticket, nonce) == 24);

static size_t page_index(const struct page *page)
{
	require_catalog();
	unsigned long address = (unsigned long)page;
	unsigned long base = (unsigned long)catalog.pages;
	size_t bytes = catalog.page_count * sizeof(*catalog.pages);
	if (address < base || address - base >= bytes ||
	    (address - base) % sizeof(*catalog.pages)) {
		pr_err("page: page_index invalid pointer %p\n", page);
		return 0;
	}
	size_t index = (address - base) / sizeof(*catalog.pages);
	if (!catalog.state[index].live) {
		pr_warn("page: page_index non-live index %zu\n", index);
	}
	return index;
}

/* Unlike FLATMEM, a descriptor index is not a PFN delta across a sparse gap.
 * Like Linux sparse sections, PFN lookup must first find actual coverage.
 * We do not admit dynamic section growth or move any escaped descriptor. */
static const struct registered_extent *index_extent(size_t index)
{
    for (size_t i = 0; i < catalog.extent_count; i++) {
        const struct registered_extent *extent = catalog.extents + i;
        if (index >= extent->first && index - extent->first < extent->page_count)
            return extent;
    }
    pr_err("page: index_extent out-of-bounds index %zu (extent_count=%zu)\n", index, catalog.extent_count);
    return catalog.extent_count ? &catalog.extents[0] : NULL;
}

static size_t physical_slot(phys_addr_t address)
{
    size_t low = 0, high = catalog.extent_count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        const struct registered_extent *extent = catalog.extents + middle;
        if (address < extent->physical_base) {
            high = middle;
        } else {
            u64 offset = address - extent->physical_base;
            if (offset < (u64)extent->page_count * PAGE_SIZE)
                return extent->first + (size_t)(offset >> PAGE_SHIFT);
            low = middle + 1;
        }
    }
    return NO_INDEX;
}

static size_t physical_index(phys_addr_t address)
{
    require_catalog();
    size_t index = physical_slot(address);
    if (index == NO_INDEX || !catalog.state[index].live) {
        pr_warn("page: physical_index address 0x%llx not live or NO_INDEX (slot=%zu)\n",
                (unsigned long long)address, index);
        return (index != NO_INDEX && index < catalog.page_count) ? index : 0;
    }
    return index;
}

void *stela_linux_page_dma_pin(u64 physical)
{
    if (stela_linux_kernel_hosted())
        return NULL;
    require_context();
    if (!catalog.pages || (physical & (PAGE_SIZE - 1)))
        return NULL;
    size_t index = physical_slot(physical);
    if (index == NO_INDEX || !catalog.state[index].live)
        return NULL;
    struct allocation_record *record = catalog.allocations + catalog.state[index].allocation;
    if (!record->pin || !record->live || record->dma_refs == SIZE_MAX)
        return NULL;
    /* Hold the provider's original allocation, including noncompound tails
     * which __free_pages may logically retire while the head has references. */
    record->dma_refs++;
    return record;
}

void stela_linux_page_dma_unpin(void *pin)
{
    if (stela_linux_kernel_hosted())
        stela_linux_fatal("native DMA unpin from a hosted page catalogue");
    require_catalog();
    unsigned long address = (unsigned long)pin;
    unsigned long base = (unsigned long)catalog.allocations;
    size_t bytes = catalog.page_count * sizeof(*catalog.allocations);
    if (address < base || address - base >= bytes ||
        (address - base) % sizeof(*catalog.allocations)) {
        pr_warn("page: stela_linux_page_dma_unpin invalid pin pointer %p\n", pin);
        return;
    }
    struct allocation_record *record = pin;
    if (!record->pin || !record->dma_refs) {
        pr_warn("page: stela_linux_page_dma_unpin pin=%p has no pin or dma_refs=0\n", pin);
        return;
    }
    record->dma_refs--;
    /* Final provider release still happens only at checked quiescence. */
}

/* This entry is for the actual registered Rust provider Context. Neither a
 * PFN nor a caller's generation/context labels manufacture an allocation. */
int stela_linux_page_mapping_pin(u64 generation, const void *context,
 const struct stela_linux_owner *owner, u64 physical,
 struct stela_linux_mapping_page *out)
{
 if (stela_linux_kernel_hosted()) return -EPERM;
 if (!out) return -EINVAL;
 *out=(struct stela_linux_mapping_page){};
 int error=stela_linux_page_owner_context(owner);
 if (error) return error;
 if (!catalog.pages || generation!=catalog.generation || context!=catalog.context ||
     (physical & (PAGE_SIZE-1))) return -EINVAL;
 size_t index=physical_slot(physical);
 if (index==NO_INDEX || !catalog.state[index].live) return -ENOENT;
 const struct registered_extent *extent=index_extent(index);
 if (extent->kind!=STELA_LINUX_PAGE_ORDINARY) return -EOPNOTSUPP;
 struct allocation_record *record=catalog.allocations+catalog.state[index].allocation;
 if (!record->pin || !record->live || record->external_nonce) return -EOPNOTSUPP;
 if (record->dma_refs==SIZE_MAX) return -EOVERFLOW;
 record->dma_refs++;
 *out=(struct stela_linux_mapping_page){.record=record,.provider_pin=record->pin,
  .cpu_page=extent->cpu_base+((index-extent->first)<<PAGE_SHIFT)};
 return 0;
}
int stela_linux_page_mapping_unpin(u64 generation, const void *context,
 const struct stela_linux_owner *owner, void *token)
{
 if (stela_linux_kernel_hosted()) return -EPERM;
 int error=stela_linux_page_owner_context(owner);
 if (error) return error;
 if (!catalog.pages || generation!=catalog.generation || context!=catalog.context)
  return -EINVAL;
 unsigned long address=(unsigned long)token, base=(unsigned long)catalog.allocations;
 size_t bytes=catalog.page_count*sizeof(*catalog.allocations);
 if (address<base || address-base>=bytes || (address-base)%sizeof(*catalog.allocations))
  return -EINVAL;
 struct allocation_record *record=token;
 if (!record->pin || !record->dma_refs || record->external_nonce) return -EINVAL;
 record->dma_refs--;
 /* No callback/allocation/recycle here: final provider release stays deferred
  * to pages_finish after the Rust clone has left its explicit release scope. */
 return 0;
}

struct page *pfn_to_page(unsigned long pfn)
{
    if (pfn > (U64_MAX >> PAGE_SHIFT)) {
        pr_warn("page: pfn_to_page pfn overflow: 0x%lx\n", pfn);
        return NULL;
    }
    if (!catalog.pages) {
        pr_warn("page: pfn_to_page NULL catalog.pages\n");
        return NULL;
    }
    return catalog.pages + physical_index((phys_addr_t)pfn << PAGE_SHIFT);
}

unsigned long page_to_pfn(const struct page *page)
{
    size_t index = page_index(page);
    const struct registered_extent *extent = index_extent(index);
    if (!extent) return 0;
    return (unsigned long)(extent->physical_base >> PAGE_SHIFT) + index - extent->first;
}

/* Original CPU-address lookup stays inside the current descriptor namespace. */
static size_t cpu_index(unsigned long address, size_t *offset)
{
    require_catalog();
    for (size_t i = 0; i < catalog.extent_count; i++) {
        const struct registered_extent *extent = catalog.extents + i;
        unsigned long base = (unsigned long)extent->cpu_base;
        if (address >= base && address - base < extent->page_count * PAGE_SIZE) {
            size_t delta = address - base;
            size_t index = extent->first + (delta >> PAGE_SHIFT);
            if (!catalog.state[index].live) {
                pr_warn("page: cpu_index address 0x%lx index %zu not live\n", address, index);
            }
            *offset = delta & (PAGE_SIZE - 1);
            return index;
        }
    }
    pr_warn("page: cpu_index address 0x%lx not found in any extent\n", address);
    *offset = 0;
    return 0;
}

struct page *stela_linux_virt_to_page(unsigned long address)
{
    size_t offset;
    size_t index = cpu_index(address, &offset);
    return catalog.pages + index;
}

void *stela_linux_page_to_virt(const struct page *page)
{
    size_t index = page_index(page);
    const struct registered_extent *extent = index_extent(index);
    if (!extent) return NULL;
    return extent->cpu_base + ((index - extent->first) << PAGE_SHIFT);
}

phys_addr_t stela_linux_page_to_phys(const struct page *page)
{
    if (stela_linux_kernel_hosted())
        stela_linux_fatal("physical page address requested from a hosted page catalogue");
    return PFN_PHYS(page_to_pfn(page));
}

struct page *stela_linux_phys_to_page(phys_addr_t address)
{
    if (stela_linux_kernel_hosted())
        stela_linux_fatal("physical page lookup requested from a hosted page catalogue");
    return pfn_to_page(PHYS_PFN(address));
}

unsigned long __phys_addr(unsigned long address)
{
    if (stela_linux_kernel_hosted())
        stela_linux_fatal("physical address requested from a hosted page catalogue");
    size_t offset;
    size_t index = cpu_index(address, &offset);
    const struct registered_extent *extent = index_extent(index);
    if (!extent) return 0;
    return (unsigned long)extent->physical_base +
           ((index - extent->first) << PAGE_SHIFT) + offset;
}

void *__phys_to_virt(phys_addr_t address)
{
    if (stela_linux_kernel_hosted())
        stela_linux_fatal("physical pointer requested from a hosted page catalogue");
    size_t index = physical_index(address);
    const struct registered_extent *extent = index_extent(index);
    size_t offset = ((index - extent->first) << PAGE_SHIFT) +
                    (size_t)(address & (PAGE_SIZE - 1));
    return extent->cpu_base + offset;
}

/* The callback may call ordinary native services, but cannot change Linux's
 * borrowed execution state. The single execution lock protects this catalog. */
static void check_callback(const struct stela_linux_owner *owner, int nesting,
			   unsigned long flags)
{
	if (stela_linux_owner() != owner || preempt_count() != nesting ||
	    arch_local_save_flags() != flags) {
		pr_warn("page: check_callback mismatch: owner=%p/%p nesting=%d/%d flags=0x%lx/0x%lx\n",
			stela_linux_owner(), owner, preempt_count(), nesting,
			arch_local_save_flags(), flags);
	}
}

int stela_linux_available_page_frames(unsigned long *available)
{
	if (!available)
		return -EINVAL;
	struct stela_linux_lease lease;
	stela_linux_lease_snapshot(&lease);
	const struct stela_linux_owner *owner = lease.owner;
	if (!owner || in_callback || !stela_linux_quiescent())
		return -EPERM;
	if (!catalog.pages)
		return -ENODEV;
    if (catalog.hosted) {
        unsigned long free = 0;
        for (size_t index = 0; index < catalog.extents[0].page_count; index++)
            free += catalog.state[index].allocation == NO_INDEX;
        *available = free;
        return 0;
    }
	if (!owner->services->available_page_frames)
		return -EOPNOTSUPP;

	int nesting = preempt_count();
	unsigned long flags = arch_local_save_flags();
	unsigned long total = 0;
	for (size_t i = 0; i < catalog.extent_count; i++) {
		const struct registered_extent *extent = catalog.extents + i;
		if (extent->kind != STELA_LINUX_PAGE_ORDINARY)
			continue;
		size_t count = 0;
		in_callback = true;
		int error = owner->services->available_page_frames(owner->context,
			(size_t)extent->cpu_base, extent->page_count, &count);
		in_callback = false;
		if (!stela_linux_lease_matches(&lease))
			pr_warn("page: available_page_frames lease mismatch\n");
		check_callback(owner, nesting, flags);
		if (error > 0 || count > extent->page_count)
			pr_warn("page: available_page_frames error=%d count=%zu\n", error, count);
		if (error)
			return error;
		total += count;
	}
	*available = total;
	return 0;
}

static void recycle_record(size_t index)
{
	catalog.allocations[index] = (struct allocation_record){.next = catalog.free_records};
	catalog.free_records = index;
}

static void queue_record(size_t index)
{
	struct allocation_record *record = catalog.allocations + index;
	if (!record->pin || record->live)
		pr_warn("page: queue_record index %zu invalid state (pin=%p live=%zu)\n",
			index, record->pin, record->live);
	record->next = catalog.retired;
	catalog.retired = index;
}

void stela_linux_pages_finish(void)
{
	require_quiescence();
	if (!catalog.pages)
		return;
	const struct stela_linux_owner *owner = stela_linux_owner();
    /* A bounded pass: an unready native owner cannot spin or prevent other
     * ready pins from retiring. Links/markers stay owned until actual ack. */
    size_t *link = &catalog.retired;
    while (*link != NO_INDEX) {
        size_t index = *link;
        struct allocation_record *record = catalog.allocations + index;
		if (!record->pin || record->live) {
			pr_warn("page: pages_finish record %zu invalid state (pin=%p live=%zu)\n",
				index, record->pin, record->live);
			link = &record->next;
			continue;
		}
        if (record->dma_refs) {
            link = &record->next;
            continue;
        }
        if (catalog.ops.release_ready) {
            in_callback = true;
            bool ready = catalog.ops.release_ready(catalog.context, record->pin);
            in_callback = false;
            check_callback(owner, 0, ARCH_IRQ_ENABLED);
            if (!ready) {
                link = &record->next;
                continue;
            }
        }
        *link = record->next;
		if (!catalog.hosted) {
			in_callback = true;
			catalog.ops.release(catalog.context, record->pin);
			in_callback = false;
			check_callback(owner, 0, ARCH_IRQ_ENABLED);
		}
		for (size_t i = 0; i < record->count; i++) {
			struct page_state *state = catalog.state + record->first + i;
			if (state->live || state->allocation != index)
				pr_warn("page: pages_finish state mismatch page %zu\n", record->first + i);
			state->allocation = NO_INDEX;
		}
		recycle_record(index);
	}
}

/* Initial root caches and their metadata live for this whole kernel. This is
 * separate from per-task refs: unregister must refuse even before the first
 * slab payload allocation and after every per-task resource has retired. */
int stela_linux_page_catalog_retain_kernel(u64 generation)
{
    require_quiescence();
    if (!catalog.pages || catalog.generation != generation)
        return -EINVAL;
    if (catalog.kernel_roots)
        return -EBUSY;
    catalog.kernel_roots = true;
    return 0;
}

int stela_linux_page_catalog_unregister(u64 generation)
{
	if (stela_linux_kernel_hosted())
		return -EPERM;
	require_quiescence();
	if (!catalog.pages || catalog.generation != generation)
		return -EINVAL;
	stela_linux_pages_finish();
	if (catalog.live_pages || catalog.retired != NO_INDEX || catalog.stack_admissions ||
        catalog.kernel_roots)
		return -EBUSY;
	size_t count = catalog.page_count;
    free_metadata(catalog.extents, catalog.extent_count * sizeof(*catalog.extents),
                  __alignof__(*catalog.extents));
	free_metadata(catalog.allocations, count * sizeof(*catalog.allocations),
		      __alignof__(*catalog.allocations));
	free_metadata(catalog.state, count * sizeof(*catalog.state), __alignof__(*catalog.state));
	free_metadata(catalog.pages, count * sizeof(*catalog.pages), __alignof__(*catalog.pages));
	memset(&catalog, 0, sizeof(catalog));
	publish_memory_inventory(0, 0, 0, 0);
	return 0;
}

static bool overlaps(unsigned long start, size_t bytes, const void *object, size_t size)
{
	unsigned long address = (unsigned long)object;
	return start <= address ? address - start < bytes : start - address < size;
}

static bool validate_range(void *cpu_base, const u64 *physical_pages,
                           size_t page_count, unsigned int order, u32 kind, size_t *first)
{
    size_t count = (size_t)1 << order;
    size_t bytes = count << PAGE_SHIFT;
    unsigned long cpu = (unsigned long)cpu_base;
    if (!cpu_base || !physical_pages ||
        page_count != count || (cpu & (bytes - 1)))
        return false;
    u64 physical = physical_pages[0];
    if (physical & (bytes - 1))
        return false;
    size_t index = physical_slot(physical);
    if (index == NO_INDEX || count > catalog.page_count - index)
        return false;
    size_t total = catalog.page_count;
    if (overlaps(cpu, bytes, catalog.pages, total * sizeof(*catalog.pages)) ||
        overlaps(cpu, bytes, catalog.state, total * sizeof(*catalog.state)) ||
        overlaps(cpu, bytes, catalog.allocations, total * sizeof(*catalog.allocations)) ||
        overlaps(cpu, bytes, catalog.extents, catalog.extent_count * sizeof(*catalog.extents)))
        return false;
    for (size_t i = 0; i < count; i++) {
        const struct registered_extent *extent = index_extent(index + i);
        size_t offset = (index + i - extent->first) << PAGE_SHIFT;
        if (physical > U64_MAX - (u64)i * PAGE_SIZE ||
            cpu > ULONG_MAX - i * PAGE_SIZE ||
            physical_pages[i] != physical + (u64)i * PAGE_SIZE ||
            extent->physical_base + offset != physical_pages[i] ||
            (unsigned long)extent->cpu_base + offset != cpu + i * PAGE_SIZE ||
            extent->kind != kind ||
            catalog.state[index + i].allocation != NO_INDEX)
            return false;
    }
    *first = index;
    return true;
}

static bool validate_allocation(const struct stela_linux_page_allocation *allocation,
                                unsigned int order, size_t *first)
{
    return allocation->pin &&
        validate_range(allocation->cpu_base, allocation->physical_pages,
                       allocation->page_count, order, STELA_LINUX_PAGE_ORDINARY, first);
}

static int reserve_stack_record(size_t first, size_t count,
                                struct stela_linux_stack_ticket *ticket)
{
    if (catalog.free_records == NO_INDEX)
        return -ENOMEM;
    if (catalog.next_stack_nonce == U64_MAX || catalog.stack_admissions == SIZE_MAX)
        return -EOVERFLOW;
    size_t index = catalog.free_records;
    struct allocation_record *record = catalog.allocations + index;
    catalog.free_records = record->next;
    u64 nonce = catalog.next_stack_nonce++;
    *record = (struct allocation_record){
        .first = first, .count = count, .external_nonce = nonce,
    };
    for (size_t i = 0; i < record->count; i++)
        catalog.state[first + i] = (struct page_state){.allocation = index};
    catalog.stack_admissions++;
    ticket->generation = catalog.generation;
    ticket->record = index;
    ticket->nonce = nonce;
    return 0;
}

/* This stage reserves descriptor markers only. Linux page refs remain zero
 * and the actual payload owner remains in Rust's affine cold preparation. */
int stela_linux_page_stack_admit(
    const struct stela_linux_stack_admission *request,
    struct stela_linux_stack_ticket *ticket)
{
    if (stela_linux_kernel_hosted())
        return -EPERM;
    require_quiescence();
    if (!request || request->version != STELA_LINUX_STACK_ADMISSION ||
        request->bytes != sizeof(*request) ||
        !ticket || ticket->version != STELA_LINUX_STACK_ADMISSION ||
        ticket->bytes != sizeof(*ticket))
        return -EINVAL;
    if (!catalog.pages || request->generation != catalog.generation ||
        request->page_count != THREAD_SIZE / PAGE_SIZE)
        return -EINVAL;
    unsigned int order = __ffs(request->page_count);
    if (order > MAX_PAGE_ORDER)
        return -EINVAL;
    size_t first;
    if (!validate_range(request->cpu_base, request->physical_pages, request->page_count,
                        order, STELA_LINUX_PAGE_RUNTIME_STACK, &first))
        return -EINVAL;
    return reserve_stack_record(first, request->page_count, ticket);
}

#ifdef __linux__
int stela_linux_page_model_stack_admit(const struct stela_linux_owner *owner,
                                       void *cpu_base,
                                       struct stela_linux_stack_ticket *ticket)
{
    if (!stela_linux_kernel_hosted() || stela_linux_page_owner_context(owner) ||
        stela_linux_require_current(owner))
        return -EPERM;
    if (!ticket || ticket->version != STELA_LINUX_MODEL_STACK ||
        ticket->bytes != sizeof(*ticket) || !catalog.hosted)
        return -EINVAL;
    for (size_t i = 0; i < catalog.extent_count; i++) {
        const struct registered_extent *extent = catalog.extents + i;
        if (extent->kind != STELA_LINUX_PAGE_RUNTIME_STACK || extent->cpu_base != cpu_base)
            continue;
        for (size_t page = 0; page < extent->page_count; page++) {
            if (catalog.state[extent->first + page].allocation != NO_INDEX)
                return -EBUSY;
        }
        return reserve_stack_record(extent->first, extent->page_count, ticket);
    }
    return -EINVAL;
}
#endif

/* An external NativeStack pin is held by its affine Rust owner, never by
 * ordinary allocation-record provider callbacks. Descriptor/page references
 * and original source/RCU/native return joins remain independent owners. */
static int stack_record(const struct stela_linux_stack_ticket *ticket,
                        struct allocation_record **out)
{
    u32 version = catalog.hosted ? STELA_LINUX_MODEL_STACK : STELA_LINUX_STACK_ADMISSION;
    if (!ticket || ticket->version != version ||
        ticket->bytes != sizeof(*ticket) || !catalog.pages ||
        ticket->generation != catalog.generation ||
        ticket->record >= catalog.page_count || !ticket->nonce)
        return -EINVAL;
    struct allocation_record *record = catalog.allocations + ticket->record;
    if (record->external_nonce != ticket->nonce || record->pin ||
        !record->count || record->count > catalog.page_count ||
        record->first > catalog.page_count - record->count || !catalog.stack_admissions)
        return -EINVAL;
    for (size_t i = 0; i < record->count; i++) {
        size_t index = record->first + i;
        if (catalog.state[index].allocation != ticket->record ||
            index_extent(index)->kind != STELA_LINUX_PAGE_RUNTIME_STACK)
            return -EINVAL;
    }
    *out = record;
    return 0;
}
int stela_linux_page_stack_source_context(const struct stela_linux_owner *expected)
{
    if (!expected || in_callback)
        return -EPERM;
    struct stela_linux_lease lease;
    stela_linux_lease_snapshot(&lease);
    if (lease.owner != expected)
        return -EPERM;
    return stela_linux_require_current(expected);
}

static int stack_current(bool sleepable)
{
    require_context();
    int error = stela_linux_require_current(stela_linux_owner());
    if (error)
        return error;
    return sleepable && !stela_linux_quiescent() ? -EBUSY : 0;
}
static int stack_remove(const struct stela_linux_stack_ticket *ticket,
                        struct allocation_record *record)
{
    if (record->live || record->dma_refs)
        return -EBUSY;
    for (size_t i = 0; i < record->count; i++) {
        size_t index = record->first + i;
        if (catalog.state[index].live || page_ref_count(catalog.pages + index))
            return -EBUSY;
    }
    for (size_t i = 0; i < record->count; i++)
        catalog.state[record->first + i].allocation = NO_INDEX;
    catalog.stack_admissions--;
    recycle_record(ticket->record);
    return 0;
}
int stela_linux_page_stack_cancel(const struct stela_linux_stack_ticket *ticket)
{
    require_quiescence();
    struct allocation_record *record;
    int error = stack_record(ticket, &record);
    if (error)
        return error;
    if (record->external_phase == STACK_PUBLISHED)
        return -EPERM;
    return stack_remove(ticket, record);
}
int stela_linux_page_stack_lend(const struct stela_linux_stack_ticket *ticket,
                              const void *actual_child, void **cpu_base)
{
    if (!actual_child || !cpu_base)
        return -EINVAL;
    *cpu_base = NULL;
    int error = stack_current(true);
    if (error)
        return error;
    struct allocation_record *record;
    error = stack_record(ticket, &record);
    if (error)
        return error;
    if (record->external_phase != STACK_RESERVED || record->external_task ||
        record->live || record->dma_refs || record->count != THREAD_SIZE / PAGE_SIZE)
        return -EBUSY;
    for (size_t i = 0; i < record->count; i++) {
        if (catalog.state[record->first + i].live ||
            page_ref_count(catalog.pages + record->first + i))
            return -EBUSY;
    }
    if (record->count > SIZE_MAX - catalog.live_pages)
        return -EOVERFLOW;
    unsigned int order = __ffs(record->count);
    for (size_t i = 0; i < record->count; i++) {
        initialize_page(catalog.pages + record->first + i);
        catalog.state[record->first + i] = (struct page_state){
            .allocation = ticket->record, .run_first = record->first,
            .run_order = order, .live = true,
        };
    }
    set_page_count(catalog.pages + record->first, 1);
    record->live = record->count;
    record->external_task = actual_child;
    record->external_phase = STACK_LENT;
    catalog.live_pages += record->count;
    *cpu_base = page_address(catalog.pages + record->first);
    return 0;
}
int stela_linux_page_stack_prepare_publish(
    const struct stela_linux_stack_ticket *ticket, const void *actual_child)
{
    int error = stack_current(false);
    if (error)
        return error;
    struct allocation_record *record;
    error = stack_record(ticket, &record);
    if (error)
        return error;
    if (!actual_child || record->external_task != actual_child ||
        record->external_phase != STACK_LENT || record->live != record->count || record->dma_refs)
        return -EINVAL;
    for (size_t i = 0; i < record->count; i++) {
        const struct page_state *state = catalog.state + record->first + i;
        if (!state->live || state->run_first != record->first ||
            state->run_order != __ffs(record->count) || state->compound ||
            page_ref_count(catalog.pages + record->first + i) != (i ? 0 : 1))
            return -EBUSY;
    }
    return 0;
}
void stela_linux_page_stack_publish(const struct stela_linux_stack_ticket *ticket,
                                 const void *actual_child)
{
    /* Private source nofail point, after native Dormant accepted and before
     * original tasklist/PID visibility. Never translate uncertainty to errno. */
    if (stela_linux_page_stack_prepare_publish(ticket, actual_child)) {
        pr_warn("page: page_stack_publish prepare failed\n");
        return;
    }
    catalog.allocations[ticket->record].external_phase = STACK_PUBLISHED;
}
int stela_linux_page_stack_retire(const struct stela_linux_stack_ticket *ticket,
                               const void *actual_child)
{
    int error = stack_current(true);
    if (error)
        return error;
    struct allocation_record *record;
    error = stack_record(ticket, &record);
    if (error)
        return error;
    if (!actual_child || record->external_task != actual_child ||
        record->external_phase != STACK_PUBLISHED)
        return -EINVAL;
    /* Private unsafe producer already joined the real original task/stack,
     * alias/RCU releases and actual native terminal successor. These checks
     * independently retain every real descriptor ref, never infer that join. */
    return stack_remove(ticket, record);
}

static bool reclaim_catalog_pages(gfp_t gfp)
{
	if (!catalog.kernel_roots || !gfpflags_allow_blocking(gfp) ||
	    !stela_linux_quiescent())
		return false;
	const struct stela_linux_owner *owner = stela_linux_owner();
	if (rcu_scheduler_active != RCU_SCHEDULER_RUNNING ||
	    !stela_linux_task_resource_roots_complete(owner) ||
	    stela_linux_require_current(owner))
		return false;
	struct task_struct *task = current;
	if (task->flags & PF_MEMALLOC)
		return false;

	struct stela_linux_lease lease;
	stela_linux_lease_snapshot(&lease);
	gfp = current_gfp_context(gfp);
	unsigned int flags = memalloc_noreclaim_save();
	/* Only slab reclaim is available here. Make one pressure pass using
	 * the original shrinker budgets, outside provider and record custody. */
	unsigned long reclaimed = shrink_slab(gfp, 0, NULL, 0);
	if (!stela_linux_quiescent() || !stela_linux_lease_matches(&lease) ||
	    current != task) {
		pr_warn("page: reclaim_catalog_pages state mismatch after shrink_slab\n");
	}
	memalloc_noreclaim_restore(flags);
	return reclaimed != 0;
}

/* The ordinary hosted extent is kept by the mount. Its page-state array already
 * records both live and retired runs. Never lend a retired run early. */
static size_t find_model_run(size_t count)
{
    size_t ordinary = catalog.extents[0].page_count;
    for (size_t first = 0; first + count <= ordinary; first += count) {
        size_t i = 0;
        while (i < count && catalog.state[first + i].allocation == NO_INDEX)
            i++;
        if (i == count)
            return first;
    }
    return NO_INDEX;
}

#ifdef STELA_LINUX_HOSTED_PAGE_TEST
/* The hosted model's pages share the test allocation routes, so a hosted
 * fixture refuses and counts them as it does heap allocations (route 2). */
bool stela_test_allocation_attempt(unsigned int route);
static bool hosted_page_attempt(void)
{
	return stela_test_allocation_attempt(2);
}
#else
static bool hosted_page_attempt(void)
{
	return true;
}
#endif

struct page *__alloc_pages_noprof(gfp_t gfp, unsigned int order, int preferred_nid,
				nodemask_t *nodemask)
{
	require_context();
	if (gfp & __GFP_NOFAIL) {
		stela_linux_unsupported("page allocation with __GFP_NOFAIL");
		return NULL;
	}
	if (!catalog.pages || order > MAX_PAGE_ORDER ||
	    (preferred_nid != NUMA_NO_NODE && preferred_nid != 0) ||
	    (nodemask && !node_isset(0, *nodemask)))
		return NULL;
	bool retried = false;
	bool atomic;
retry:
	atomic = !stela_linux_quiescent();
	const struct stela_linux_owner *owner = stela_linux_owner();
	int nesting = preempt_count();
	unsigned long flags = arch_local_save_flags();
	int error;
	if (catalog.hosted) {
		error = stela_linux_page_request_basic((__force u32)gfp) ||
			stela_linux_page_request_reclaimable((__force u32)gfp) ? 0 : -EOPNOTSUPP;
	} else {
		in_callback = true;
		error = catalog.ops.validate(catalog.context, (__force u32)gfp, order, atomic);
		in_callback = false;
		check_callback(owner, nesting, flags);
	}
	if (error) {
		pr_warn("page: validate order=%u failed: %d\n", order, error);
		if (error == -EOPNOTSUPP)
			stela_linux_unsupported("page allocation request");
		return NULL;
	}
	if (!atomic)
		stela_linux_pages_finish();
	if (catalog.free_records == NO_INDEX) {
		pr_warn("page: free_records exhausted\n");
		goto exhausted;
	}
	size_t record_index = catalog.free_records;
	struct allocation_record *record = catalog.allocations + record_index;
	catalog.free_records = record->next;
	*record = (struct allocation_record){0};
	struct stela_linux_page_allocation allocation = {0};
	size_t count = (size_t)1 << order;
	size_t first;
	if (catalog.hosted) {
		first = hosted_page_attempt() ? find_model_run(count) : NO_INDEX;
		if (first == NO_INDEX) {
			recycle_record(record_index);
			goto exhausted;
		}
		allocation.cpu_base = catalog.extents[0].cpu_base + (first << PAGE_SHIFT);
		record->pin = allocation.cpu_base;
	} else {
		in_callback = true;
		error = catalog.ops.allocate(catalog.context, (__force u32)gfp, order, atomic, &allocation);
		in_callback = false;
		check_callback(owner, nesting, flags);
		if (error) {
			pr_warn("page: allocate order=%u failed: %d\n", order, error);
			recycle_record(record_index);
			if (error == -ENOMEM)
				goto exhausted;
			if (error == -EOPNOTSUPP)
				stela_linux_unsupported("native page allocation request");
			return NULL;
		}
		if (!allocation.pin) {
			pr_warn("page: allocate order=%u returned NULL pin\n", order);
			recycle_record(record_index);
			return NULL;
		}
		record->pin = allocation.pin;
		if (!validate_allocation(&allocation, order, &first)) {
			pr_warn("page: validate_allocation order=%u failed pin=%p\n", order, allocation.pin);
			queue_record(record_index);
			if (!atomic)
				stela_linux_pages_finish();
			return NULL;
		}
	}
	record->first = first;
	record->count = count;
	record->live = count;
	for (size_t i = 0; i < count; i++) {
		initialize_page(catalog.pages + first + i);
		catalog.state[first + i] = (struct page_state){
			.allocation = record_index, .run_first = first,
			.run_order = order, .live = true,
		};
	}
	catalog.live_pages += count;
	struct page *page = catalog.pages + first;
	set_page_count(page, 1);
	if (gfp & __GFP_ZERO)
		memset(allocation.cpu_base, 0, count << PAGE_SHIFT);
	if (order && (gfp & __GFP_COMP))
		prep_compound_page(page, order);
	return page;

exhausted:
	if (!retried && reclaim_catalog_pages(gfp)) {
		retried = true;
		goto retry;
	}
	return NULL;
}

struct folio *__folio_alloc_noprof(gfp_t gfp, unsigned int order, int preferred_nid,
				  nodemask_t *nodemask)
{
	struct folio *folio = (struct folio *)__alloc_pages_noprof(gfp | __GFP_COMP, order,
								preferred_nid, nodemask);
	if (folio && order)
		folio_set_large_rmappable(folio);
	return folio;
}

unsigned long get_free_pages_noprof(gfp_t gfp, unsigned int order)
{
	struct page *page = alloc_pages_noprof(gfp & ~__GFP_HIGHMEM, order);
	return page ? (unsigned long)page_address(page) : 0;
}

unsigned long get_zeroed_page_noprof(gfp_t gfp)
{
	return get_free_pages_noprof(gfp | __GFP_ZERO, 0);
}

/* Validate one logical run before changing its count or descriptors. The
 * platform pin may cover additional runs after split_page or partial release. */
static size_t run_index(struct page *page, unsigned int order)
{
	size_t first = page_index(page);
	struct page_state *state = catalog.state + first;
	if (order > MAX_PAGE_ORDER || state->run_first != first || state->run_order != order ||
	    PageTail(page) || !!PageHead(page) != state->compound ||
	    (state->compound && compound_order(page) != order)) {
		pr_warn("page: run_index mismatch page=%p order=%u\n", page, order);
		return first;
	}
	size_t count = (size_t)1 << order;
	if (count > catalog.page_count - first) {
		pr_warn("page: run_index count exceeds page_count\n");
		return first;
	}
	for (size_t i = 0; i < count; i++) {
		struct page *part = page + i;
		struct page_state *item = state + i;
		if (!item->live || item->allocation != state->allocation || item->run_first != first ||
		    item->run_order != order || item->compound != state->compound ||
		    (i && (page_ref_count(part) || !!PageTail(part) != state->compound ||
			   (state->compound && compound_head(part) != page))) ||
		    atomic_read(&part->_mapcount) != -1) {
			pr_warn("page: run_index item mismatch index=%zu\n", first + i);
		}
	}
	return first;
}

void prep_compound_page(struct page *page, unsigned int order)
{
	size_t first = run_index(page, order);
	if (!order || PageHead(page) || page_ref_count(page) <= 0) {
		pr_warn("page: prep_compound_page unexpected state order=%u\n", order);
		return;
	}
	size_t count = (size_t)1 << order;
	__SetPageHead(page);
	for (size_t i = 1; i < count; i++) {
		struct page *tail = page + i;
		tail->mapping = TAIL_MAPPING;
		set_compound_head(tail, page, order);
		set_page_private(tail, 0);
	}
	/* Pinned Linux mm/internal.h's compound initialization. These are real
	 * struct-folio fields over the first tail descriptors, not a side map. */
	struct folio *folio = (struct folio *)page;
	folio->_flags_1 = (folio->_flags_1 & ~0xffUL) | order;
#ifdef NR_PAGES_IN_LARGE_FOLIO
	folio->_nr_pages = 1U << order;
#endif
	atomic_set(&folio->_large_mapcount, -1);
	atomic_set(&folio->_nr_pages_mapped, 0);
	if (IS_ENABLED(CONFIG_MM_ID)) {
		folio->_mm_ids = 0;
		folio->_mm_id_mapcount[0] = -1;
		folio->_mm_id_mapcount[1] = -1;
	}
	atomic_set(&folio->_entire_mapcount, -1);
	atomic_set(&folio->_pincount, 0);
	if (order > 1)
		INIT_LIST_HEAD(&folio->_deferred_list);
	for (size_t i = 0; i < count; i++)
		catalog.state[first + i].compound = true;
}

void split_page(struct page *page, unsigned int order)
{
	size_t first = run_index(page, order);
	if (PageHead(page) || page_ref_count(page) <= 0) {
		pr_warn("page: split_page unexpected state\n");
		return;
	}
	size_t count = (size_t)1 << order;
	for (size_t i = 0; i < count; i++) {
		if (i)
			set_page_count(page + i, 1);
		catalog.state[first + i].run_first = first + i;
		catalog.state[first + i].run_order = 0;
	}
}

static void retire_pages(size_t first, size_t count)
{
	size_t allocation = catalog.state[first].allocation;
	struct allocation_record *record = catalog.allocations + allocation;
	if (record->live < count || catalog.live_pages < count)
		pr_warn("page: retire_pages live count warning\n");
	for (size_t i = 0; i < count; i++) {
		if (!catalog.state[first + i].live || catalog.state[first + i].allocation != allocation) {
			pr_warn("page: retire_pages allocation mismatch\n");
			continue;
		}
		struct page *page = catalog.pages + first + i;
		bool compound = catalog.state[first + i].compound;
		bool head = !PageTail(page);
		unsigned long flags = page->flags.f;
		if (compound && first + i == catalog.state[first + i].run_first + 1)
			flags &= ~PAGE_FLAGS_SECOND;
		if ((flags & PAGE_FLAGS_CHECK_AT_FREE) || atomic_read(&page->_mapcount) != -1 ||
		    ((head || !compound) && page->mapping))
			pr_warn("page: retire_pages flags warning\n");
		if (compound && head) {
			struct folio *folio = (struct folio *)page;
			if (atomic_read(&folio->_large_mapcount) != -1 ||
			    atomic_read(&folio->_nr_pages_mapped) ||
			    atomic_read(&folio->_entire_mapcount) != -1 ||
			    atomic_read(&folio->_pincount) ||
			    (folio_order(folio) > 1 && !list_empty(&folio->_deferred_list)))
				pr_warn("page: retire_pages compound folio warning\n");
		}
	}
	for (size_t i = 0; i < count; i++) {
		catalog.state[first + i].live = false;
		initialize_page(catalog.pages + first + i);
	}
	record->live -= count;
	catalog.live_pages -= count;
	if (!record->live) {
        if (record->external_nonce) {
            /* Original free_thread_stack/__free_pages ended logical pages.
             * Do not queue a NULL ordinary provider pin or recycle native
             * stack descriptors before exact source/native/RCU retirement. */
            if (record->external_phase != STACK_LENT &&
                record->external_phase != STACK_PUBLISHED)
                pr_warn("page: retire_pages external_phase mismatch (%d)\n", record->external_phase);
        } else {
            queue_record(allocation);
        }
    }
}

void __free_pages(struct page *page, unsigned int order)
{
	if (!page) {
		pr_warn("page: __free_pages NULL page\n");
		return;
	}
	size_t first = run_index(page, order);
	if (page_ref_count(page) <= 0) {
		pr_warn("page: __free_pages refcount <= 0 page=%p\n", page);
		return;
	}
	bool compound = PageHead(page);
	if (put_page_testzero(page)) {
		retire_pages(first, (size_t)1 << order);
	} else if (!compound && order) {
		/* Linux drops noncompound tails even if a speculative reference
		 * retains the head; the eventual put_page frees only that head. */
		catalog.state[first].run_order = 0;
		retire_pages(first + 1, ((size_t)1 << order) - 1);
	}
}

void free_pages(unsigned long address, unsigned int order)
{
	require_context();
	if (!address)
		return;
	if (address & ~PAGE_MASK) {
		pr_warn("page: free_pages unaligned address 0x%lx\n", address);
		address &= PAGE_MASK;
	}
	__free_pages(virt_to_page(address), order);
}

static void check_frozen_folio(struct folio *folio, const struct page_state *state)
{
	struct page *page = &folio->page;
	unsigned int order = state->compound ? state->run_order : 0;
	if (page_ref_count(page) || PageTail(page) ||
	    !!PageHead(page) != state->compound || folio_order(folio) != order ||
	    folio_test_lru(folio) || folio_test_swapcache(folio) ||
	    folio_test_slab(folio) || folio_test_large_kmalloc(folio) || folio->mapping)
		pr_warn("page: check_frozen_folio mismatch\n");
}

static void retire_frozen_folio(struct folio *folio)
{
	struct page *page = &folio->page;
	size_t first = page_index(page);
	struct page_state *state = catalog.state + first;
	unsigned int order = state->compound ? state->run_order : 0;
	check_frozen_folio(folio, state);
	/* Raw alloc_pages ownership only: no page-cache, userspace, slab or
	 * zone-device cleanup is silently discarded. A noncompound high-order
	 * allocation intentionally loses only its first page here, as Linux does. */
	if (state->compound)
		(void)run_index(page, order);
	else if (atomic_read(&page->_mapcount) != -1) {
		pr_warn("page: retire_frozen_folio mapcount != -1 (mapcount=%d)\n",
			atomic_read(&page->_mapcount));
	}
	retire_pages(first, (size_t)1 << order);
}

void free_frozen_pages(struct page *page, unsigned int order)
{
	if (!order && !PageCompound(page)) {
		retire_frozen_folio(page_folio(page));
		return;
	}
	size_t first = run_index(page, order);
	check_frozen_folio(page_folio(page), catalog.state + first);
	retire_pages(first, (size_t)1 << order);
}

void drain_local_pages(struct zone *zone)
{
	/* The catalog returns pages directly to its native provider. Linux
	 * buddy per-CPU free lists have no producer on this allocator. */
	(void)zone;
}

void free_unref_folios(struct folio_batch *batch)
{
	/* The native catalog owns each allocation and its deferred pin release. */
	for (unsigned int i = 0; i < folio_batch_count(batch); i++)
		retire_frozen_folio(batch->folios[i]);
	folio_batch_reinit(batch);
}

static bool verify_extent(struct page *page, unsigned int order)
{
	size_t count = (size_t)1 << order;
	u8 *cpu = page_address(page);
	unsigned long pfn = page_to_pfn(page);
	bool correct = pfn_to_page(pfn) == page && virt_to_page(cpu) == page;
	for (size_t i = 0; i < count; i++) {
		correct &= page_to_pfn(page + i) == pfn + i;
		correct &= page_address(page + i) == cpu + i * PAGE_SIZE;
	}
	for (size_t i = 0; i < count * PAGE_SIZE; i++)
		correct &= READ_ONCE(cpu[i]) == 0;
	size_t last = count * PAGE_SIZE - 1;
	WRITE_ONCE(cpu[0], 0x95);
	WRITE_ONCE(cpu[last], 0x6a);
	correct &= READ_ONCE(cpu[0]) == 0x95 && READ_ONCE(cpu[last]) == 0x6a;
	phys_addr_t physical = page_to_phys(page);
	correct &= __pa(cpu + last) == physical + last;
	correct &= __va(physical + last) == cpu + last;
	return correct;
}

int stela_linux_page_catalog_verify(u64 generation)
{
	if (stela_linux_kernel_hosted())
		return -EPERM;
	require_quiescence();
	if (!catalog.pages || catalog.generation != generation)
		return -EINVAL;
	struct page *page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		return -ENOMEM;
	bool correct = verify_extent(page, 0) && page_ref_count(page) == 1;
	get_page(page);
	correct &= page_ref_count(page) == 2;
	__free_page(page);
	correct &= page_ref_count(page) == 1;
	put_page(page);
	stela_linux_pages_finish();
	if (!correct)
		return -EIO;
	struct folio *folio = folio_alloc(GFP_KERNEL | __GFP_ZERO, 2);
	if (!folio)
		return -ENOMEM;
	page = &folio->page;
	correct = verify_extent(page, 2) && folio_order(folio) == 2 &&
		folio_test_large_rmappable(folio) == IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE);
	for (size_t i = 1; i < 4; i++)
		correct &= PageTail(page + i) && compound_head(page + i) == page;
	get_page(page + 3);
	correct &= page_ref_count(page) == 2;
	__free_pages(page, 2);
	correct &= page_ref_count(page) == 1;
	put_page(page + 3);
	stela_linux_pages_finish();
	if (!correct)
		return -EIO;
	page = alloc_pages(GFP_KERNEL | __GFP_ZERO, 2);
	if (!page)
		return -ENOMEM;
	correct = verify_extent(page, 2) && !PageHead(page);
	split_page(page, 2);
	for (size_t i = 0; i < 4; i++) {
		correct &= page_ref_count(page + i) == 1 && !PageTail(page + i);
		__free_page(page + i);
	}
	stela_linux_pages_finish();
	if (!correct)
		return -EIO;
	page = alloc_pages(GFP_KERNEL | __GFP_ZERO, 2);
	if (!page)
		return -ENOMEM;
	correct = verify_extent(page, 2) && !PageHead(page);
	get_page(page);
	__free_pages(page, 2);
	correct &= page_ref_count(page) == 1;
	put_page(page);
	stela_linux_pages_finish();
	return correct ? 0 : -EIO;
}

#ifdef STELA_LINUX_PAGE_TEST
#include <linux/bottom_half.h>
#include <linux/rcupdate.h>
#include <linux/scatterlist.h>
#include <stela/test.h>

#define TEST_PAGES 16UL
#define TEST_PHYSICAL 0x23000000ULL

enum output_fault {
	OUTPUT_VALID,
	OUTPUT_WRONG_COUNT,
	OUTPUT_NONCONTIGUOUS,
	OUTPUT_CPU_OFFSET,
	OUTPUT_OUTSIDE,
	OUTPUT_OVERLAP,
};

struct test_pin {
	bool active;
	size_t first;
	size_t count;
	u64 physical[TEST_PAGES];
};

struct test_provider {
	u8 *cpu;
	bool used[TEST_PAGES];
	struct test_pin pins[TEST_PAGES];
	enum output_fault fault;
	unsigned int allocations;
	unsigned int releases;
	unsigned int validations;
	unsigned int unsupported;
	u32 seen_gfp;
	unsigned int seen_order;
	bool seen_atomic;
	bool refuse_atomic;
	bool exhausted;
	u64 overlap_physical;
    struct test_pin *held_pin;
    unsigned int readiness_checks;
    u64 physical_override[TEST_PAGES];
};

static struct test_provider fixture;

static int test_validate(void *context, u32 gfp, unsigned int order, bool atomic)
{
	struct test_provider *provider = context;
	assert(!stela_linux_try_enter(&stela_linux_bare));
	provider->validations++;
	provider->seen_gfp = gfp;
	provider->seen_order = order;
	provider->seen_atomic = atomic;
	if (!stela_linux_page_request_basic(gfp) || (provider->refuse_atomic && atomic))
		return -EOPNOTSUPP;
	return 0;
}

static int test_allocate(void *context, u32 gfp, unsigned int order, bool atomic,
			 struct stela_linux_page_allocation *allocation)
{
	struct test_provider *provider = context;
	assert(provider->seen_gfp == gfp && provider->seen_order == order &&
	       provider->seen_atomic == atomic);
	provider->allocations++;
	if (provider->exhausted || order > 4)
		return -ENOMEM;
	size_t count = (size_t)1 << order;
	size_t first = TEST_PAGES;
	for (size_t i = 0; i + count <= TEST_PAGES; i += count) {
		bool available = true;
		for (size_t j = 0; j < count; j++)
			available &= !provider->used[i + j];
		if (available) {
			first = i;
			break;
		}
	}
	if (first == TEST_PAGES)
		return -ENOMEM;
	struct test_pin *pin = NULL;
	for (size_t i = 0; i < TEST_PAGES; i++) {
		if (!provider->pins[i].active) {
			pin = provider->pins + i;
			break;
		}
	}
	assert(pin);
	*pin = (struct test_pin){.active = true, .first = first, .count = count};
	for (size_t i = 0; i < count; i++) {
		provider->used[first + i] = true;
		pin->physical[i] = provider->physical_override[first + i] ?
            provider->physical_override[first + i] :
            TEST_PHYSICAL + (u64)(first + i) * PAGE_SIZE;
	}
	/* The provider need not zero plain pages. ZERO must be enforced by the
	 * service before it publishes the payload. */
	memset(provider->cpu + first * PAGE_SIZE, 0xa7, count * PAGE_SIZE);
	*allocation = (struct stela_linux_page_allocation){
		.pin = pin, .cpu_base = provider->cpu + first * PAGE_SIZE,
		.physical_pages = pin->physical, .page_count = count,
	};
	switch (provider->fault) {
	case OUTPUT_VALID:
		break;
	case OUTPUT_WRONG_COUNT:
		allocation->page_count++;
		break;
	case OUTPUT_NONCONTIGUOUS:
		assert(count > 1);
		pin->physical[1] += PAGE_SIZE;
		break;
	case OUTPUT_CPU_OFFSET:
		allocation->cpu_base = (u8 *)allocation->cpu_base + PAGE_SIZE;
		break;
	case OUTPUT_OUTSIDE:
		pin->physical[0] = TEST_PHYSICAL - PAGE_SIZE;
		break;
	case OUTPUT_OVERLAP:
		assert(provider->overlap_physical);
		/* The deliberately wrong returned range must not alter the real
		 * pin's lifetime or the earlier pin's payload. */
		pin->physical[0] = provider->overlap_physical;
		allocation->cpu_base = provider->cpu +
			(size_t)(pin->physical[0] - TEST_PHYSICAL);
		break;
	}
	return 0;
}

static void test_release(void *context, void *token)
{
	struct test_provider *provider = context;
	struct test_pin *pin = token;
	assert(stela_linux_quiescent() && !stela_linux_try_enter(&stela_linux_bare));
	assert(pin->active);
	for (size_t i = 0; i < pin->count; i++) {
		assert(provider->used[pin->first + i]);
		provider->used[pin->first + i] = false;
	}
	pin->active = false;
	provider->releases++;
}

static void test_unsupported(void *context, const char *operation)
{
	struct test_provider *provider = context;
	assert(operation && *operation);
	provider->unsupported++;
}

static const struct stela_linux_page_ops test_ops = {
	.validate = test_validate, .allocate = test_allocate, .release = test_release,
};

static struct page *trap_page;

static void dead_descriptor(void)
{
	(void)page_to_pfn(trap_page);
}

static void unowned_physical(void)
{
	(void)pfn_to_page((TEST_PHYSICAL >> PAGE_SHIFT) + TEST_PAGES - 1);
}

static void unowned_virtual(void)
{
	(void)__pa(fixture.cpu + (TEST_PAGES - 1) * PAGE_SIZE);
}

static void interior_descriptor(void)
{
	(void)page_to_pfn((struct page *)((u8 *)trap_page + 1));
}

static void wrong_free_order(void)
{
	__free_pages(trap_page, 1);
}

static void null_free(void)
{
	__free_page(NULL);
}

static void free_compound_tail(void)
{
	__free_page(trap_page + 1);
}

static void split_compound(void)
{
	split_page(trap_page, 2);
}

static void finish_atomic(void)
{
	local_bh_disable();
	stela_linux_pages_finish();
}

static void register_atomic(void)
{
	local_bh_disable();
	const struct stela_linux_page_reservation reservation = {
        .generation = catalog.generation, .physical_base = TEST_PHYSICAL,
        .cpu_base = fixture.cpu, .page_count = TEST_PAGES,
    };
    (void)stela_linux_page_catalog_register(&reservation, &test_ops, &fixture);
}

static void mapped_free(void)
{
	trap_page->mapping = (struct address_space *)fixture.cpu;
	__free_page(trap_page);
}

static int unbalanced_validate(void *context, u32 gfp, unsigned int order, bool atomic)
{
	(void)context;
	(void)gfp;
	(void)order;
	(void)atomic;
	local_irq_disable();
	return 0;
}

static void unbalanced_callback(void)
{
	catalog.ops.validate = unbalanced_validate;
	(void)alloc_page(GFP_KERNEL);
}

static int reentrant_validate(void *context, u32 gfp, unsigned int order, bool atomic)
{
	(void)context;
	(void)gfp;
	(void)order;
	(void)atomic;
	(void)pfn_to_page(TEST_PHYSICAL >> PAGE_SHIFT);
	return 0;
}

static void reentrant_callback(void)
{
	catalog.ops.validate = reentrant_validate;
	(void)alloc_page(GFP_KERNEL);
}

static void noncompound_head_put(void)
{
	struct page *page = alloc_pages(GFP_KERNEL, 2);
	assert(page && !PageHead(page));
	unsigned long pfn = page_to_pfn(page);
	unsigned int releases = fixture.releases;
	put_page(page);
	/* Linux put_page on a noncompound high-order head does not retire its
	 * tail pages. Keep their backing and expose the leaked ownership. */
	for (size_t i = 1; i < 4; i++)
		assert(page_to_pfn(page + i) == pfn + i);
	assert(stela_linux_page_catalog_unregister(1) == -EBUSY);
	assert(fixture.releases == releases);
	(void)page_to_pfn(page);
}

static void refusal_and_rollback(void)
{
	unsigned int allocations = fixture.allocations;
	unsigned int reports = fixture.unsupported;
	assert(!alloc_page(GFP_KERNEL | __GFP_DMA));
	assert(fixture.unsupported == reports + 1 && fixture.allocations == allocations);
	assert(!alloc_page(GFP_KERNEL | __GFP_NOFAIL));
	assert(fixture.unsupported == reports + 2 && fixture.allocations == allocations);
	fixture.refuse_atomic = true;
	local_bh_disable();
	assert(!alloc_page(GFP_NOWAIT));
	assert(fixture.seen_atomic && fixture.seen_gfp == (__force u32)GFP_NOWAIT);
	local_bh_enable();
	assert(fixture.unsupported == reports + 3 && fixture.allocations == allocations);
	fixture.refuse_atomic = false;
	fixture.exhausted = true;
	assert(!alloc_page(GFP_KERNEL));
	assert(fixture.unsupported == reports + 3);
	fixture.exhausted = false;
	assert(!__alloc_pages_noprof(GFP_KERNEL, MAX_PAGE_ORDER + 1, 0, NULL));
	assert(!__alloc_pages_noprof(GFP_KERNEL, 0, 1, NULL));
	nodemask_t empty = NODE_MASK_NONE;
	assert(!__alloc_pages_noprof(GFP_KERNEL, 0, 0, &empty));
	for (enum output_fault fault = OUTPUT_WRONG_COUNT; fault <= OUTPUT_OUTSIDE; fault++) {
		fixture.fault = fault;
		unsigned int releases = fixture.releases;
		assert(!alloc_pages(GFP_KERNEL | __GFP_ZERO, 1));
		assert(fixture.releases == releases + 1 && !catalog.live_pages);
	}
	fixture.fault = OUTPUT_VALID;
	struct page *page = alloc_page(GFP_KERNEL);
	assert(page);
	fixture.overlap_physical = page_to_phys(page);
	fixture.fault = OUTPUT_OVERLAP;
	assert(!alloc_page(GFP_KERNEL));
	assert(page_ref_count(page) == 1);
	fixture.fault = OUTPUT_VALID;
	__free_page(page);
	stela_linux_pages_finish();
	fixture.overlap_physical = 0;
	fixture.fault = OUTPUT_WRONG_COUNT;
	unsigned int releases = fixture.releases;
	local_bh_disable();
	assert(!alloc_page(GFP_NOWAIT));
	assert(fixture.releases == releases);
	local_bh_enable();
	stela_linux_pages_finish();
	assert(fixture.releases == releases + 1);
	fixture.fault = OUTPUT_VALID;
	local_bh_disable();
	page = alloc_page(GFP_NOWAIT);
	assert(page && fixture.seen_atomic);
	__free_page(page);
	local_bh_enable();
	stela_linux_pages_finish();
}

static void adjacency_and_retirement(void)
{
	struct page *first = alloc_page(GFP_KERNEL | __GFP_ZERO);
	struct page *second = alloc_page(GFP_KERNEL | __GFP_ZERO);
	assert(first && second && second == first + 1);
	assert(page_to_pfn(second) == page_to_pfn(first) + 1);
	struct scatterlist sg = {0};
	sg_mark_end(&sg);
	sg_set_page(&sg, first, 2 * PAGE_SIZE, 0);
	struct sg_page_iter iterator = {.sg = &sg, .sg_pgoffset = 1};
	assert(sg_page_iter_page(&iterator) == second);
	u64 physical = page_to_phys(second);
	assert(__pa((u8 *)page_address(second) + 37) == physical + 37);
	assert(__va(physical + 37) == (u8 *)page_address(second) + 37);
	trap_page = first;
	assert(stela_test_traps(interior_descriptor));
	assert(stela_test_traps(wrong_free_order));
	assert(stela_test_traps(null_free));
	free_pages(0, 0);
	assert(stela_test_traps(mapped_free));
	assert(stela_test_traps(unowned_physical));
	assert(stela_test_traps(unowned_virtual));
	assert(stela_test_traps(finish_atomic));
	assert(stela_test_traps(register_atomic));
	assert(stela_test_traps(unbalanced_callback));
	assert(stela_test_traps(reentrant_callback));
	assert(stela_linux_page_catalog_unregister(1) == -EBUSY);
	unsigned int releases = fixture.releases;
	local_bh_disable();
	__free_page(first);
	assert(stela_test_traps(dead_descriptor));
	__free_page(second);
	assert(fixture.releases == releases);
	local_bh_enable();
	stela_linux_exit();
	assert(fixture.releases == releases + 2);
}

static void compound_and_split(void)
{
	assert(stela_test_traps(noncompound_head_put));
	trap_page = alloc_pages(GFP_KERNEL | __GFP_ZERO | __GFP_COMP, 2);
	assert(trap_page && PageHead(trap_page) && compound_order(trap_page) == 2);
	assert(stela_test_traps(free_compound_tail));
	assert(stela_test_traps(split_compound));
	get_page(trap_page + 3);
	assert(page_ref_count(trap_page) == 2);
	__free_pages(trap_page, 2);
	assert(page_ref_count(trap_page) == 1 && page_to_phys(trap_page + 3));
	put_page(trap_page + 3);
	assert(stela_test_traps(dead_descriptor));
	stela_linux_pages_finish();
	struct page *page = alloc_pages(GFP_KERNEL, 2);
	assert(page && !PageHead(page));
	split_page(page, 2);
	for (size_t i = 0; i < 4; i++) {
		assert(page_ref_count(page + i) == 1 && !PageTail(page + i));
		__free_page(page + i);
	}
	stela_linux_pages_finish();
	page = alloc_pages(GFP_KERNEL, 2);
	assert(page);
	get_page(page);
	__free_pages(page, 2);
	assert(page_ref_count(page) == 1);
	trap_page = page + 1;
	assert(stela_test_traps(dead_descriptor));
	put_page(page);
	stela_linux_pages_finish();
	struct folio *folio = folio_alloc(GFP_KERNEL, 1);
	assert(folio && folio_order(folio) == 1 &&
	       folio_test_large_rmappable(folio) == IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE));
	folio_get(folio);
	assert(folio_ref_count(folio) == 2);
	folio_put_refs(folio, 2);
	stela_linux_pages_finish();
	unsigned long address = get_zeroed_page(GFP_KERNEL);
	assert(address && *(u8 *)address == 0);
	free_page(address);
	address = __get_free_pages(GFP_KERNEL | __GFP_HIGHMEM, 1);
	assert(address && !(fixture.seen_gfp & (__force u32)__GFP_HIGHMEM));
	free_pages(address, 1);
	stela_linux_pages_finish();
	stela_linux_exit();
}

static void capacity(void)
{
	struct page *pages[TEST_PAGES];
	for (size_t i = 0; i < TEST_PAGES; i++) {
		pages[i] = alloc_page(GFP_KERNEL);
		assert(pages[i]);
	}
	unsigned int allocations = fixture.allocations;
	assert(!alloc_page(GFP_KERNEL) && fixture.allocations == allocations);
	unsigned int releases = fixture.releases;
	local_bh_disable();
	for (size_t i = 0; i < TEST_PAGES; i++)
		__free_page(pages[i]);
	assert(fixture.releases == releases);
	local_bh_enable();
	/* A subsequent sleeping request drains earlier retired pins before
	 * requesting more platform backing. */
	struct page *page = alloc_page(GFP_KERNEL);
	assert(page && fixture.releases == releases + TEST_PAGES);
	__free_page(page);
	stela_linux_pages_finish();
}

static void sg_markers_and_traversal(void)
{
	struct page *page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	assert(page);
	struct scatterlist first[3], second[2], single;
	memset(first, 0xa7, sizeof(first));
	sg_init_table(first, 3);
	sg_init_table(second, 2);
	for (size_t i = 0; i < 3; i++) {
		assert(!sg_page(first + i) && !first[i].offset && !first[i].length &&
		       !sg_dma_address(first + i) && !sg_dma_len(first + i) && !sg_is_chain(first + i));
#ifdef CONFIG_NEED_SG_DMA_FLAGS
		assert(!first[i].dma_flags);
#endif
		assert(!!sg_is_last(first + i) == (i == 2));
	}
	assert(sg_next(first) == first + 1 && sg_next(first + 2) == NULL);
	sg_init_one(&single, (u8 *)page_address(page) + 37, 77);
	assert(sg_page(&single) == page && single.offset == 37 && single.length == 77);
	assert(sg_is_last(&single) && sg_nents(&single) == 1 && !sg_next(&single));
	assert(sg_phys(&single) == page_to_phys(page) + 37);
	assert(sg_virt(&single) == (u8 *)page_address(page) + 37);
	sg_chain(first, 3, second);
	assert(sg_is_chain(first + 2) && !sg_is_last(first + 2));
	assert(sg_chain_ptr(first + 2) == second && !first[2].offset && !first[2].length);
	struct scatterlist *expected[] = {first, first + 1, second, second + 1};
	for (size_t i = 0; i < ARRAY_SIZE(expected); i++) {
		unsigned int length = (unsigned int)(i + 1) * 100;
		sg_set_page(expected[i], page, length, 0);
		sg_dma_len(expected[i]) = length;
	}
	struct scatterlist *sg = first;
	for (size_t i = 0; i < ARRAY_SIZE(expected); i++) {
		assert(sg == expected[i]);
		sg = sg_next(sg);
	}
	assert(!sg && sg_nents(first) == 4 && sg_last(first, 4) == second + 1);
	assert(!sg_nents(NULL) && sg_nents_for_len(NULL, 1) == -EINVAL);
	assert(!sg_nents_for_len(first, 0));
	assert(sg_nents_for_len(first, 100) == 1);
	assert(sg_nents_for_len(first, 101) == 2);
	assert(sg_nents_for_len(first, 300) == 2);
	assert(sg_nents_for_len(first, 301) == 3);
	assert(sg_nents_for_len(first, 1000) == 4);
	assert(sg_nents_for_len(first, 1001) == -EINVAL);
	assert(sg_nents_for_dma(first, 4, 128) == 10);
	__free_page(page);
	stela_linux_pages_finish();
}

static void sg_iterator_geometry(void)
{
	struct page *pages = alloc_pages(GFP_KERNEL, 3);
	assert(pages);
	struct scatterlist first[2], second[2];
	sg_init_table(first, 2);
	sg_init_table(second, 2);
	sg_chain(first, 2, second);
	sg_set_page(first, pages, PAGE_SIZE + 200, PAGE_SIZE - 100);
	sg_set_page(second, pages + 3, 100, 17);
	sg_set_page(second + 1, pages + 4, 2 * PAGE_SIZE, 0);
	struct sg_page_iter iterator;
	size_t count = 0;
	for_each_sg_page(first, &iterator, 3, 0) {
		assert(count < 6 && sg_page_iter_page(&iterator) == pages + count);
		count++;
	}
	assert(count == 6);
	count = 0;
	for_each_sg_page(first, &iterator, 3, 2) {
		assert(count < 4 && sg_page_iter_page(&iterator) == pages + 2 + count);
		count++;
	}
	assert(count == 4);
	count = 0;
	for_each_sg_page(first, &iterator, 3, 3) {
		assert(count < 3 && sg_page_iter_page(&iterator) == pages + 3 + count);
		count++;
	}
	assert(count == 3);
	count = 0;
	for_each_sg_page(first, &iterator, 1, 0)
		count++;
	assert(count == 3);
	__sg_page_iter_start(&iterator, first, 0, 0);
	assert(!__sg_page_iter_next(&iterator));
	__sg_page_iter_start(&iterator, first, 3, 6);
	assert(!__sg_page_iter_next(&iterator));
	/* Explicit CPU-only address labels exercise the original DMA iterator's
	 * arithmetic. They establish no requester mapping or DMA capability. */
	sg_dma_address(first) = 0x91000000;
	sg_dma_address(second) = 0xa2000000;
	sg_dma_address(second + 1) = 0xb3000000;
#ifdef CONFIG_NEED_SG_DMA_LENGTH
	sg_dma_len(first) = first->length;
	sg_dma_len(second) = second->length;
	sg_dma_len(second + 1) = second[1].length;
#endif
	const dma_addr_t addresses[] = {
		0x91000000, 0x91001000, 0x91002000, 0xa2000000, 0xb3000000, 0xb3001000,
	};
	struct sg_dma_page_iter dma_iterator;
	count = 0;
	for_each_sg_dma_page(first, &dma_iterator, 3, 0) {
		assert(count < ARRAY_SIZE(addresses));
		assert(sg_page_iter_dma_address(&dma_iterator) == addresses[count++]);
	}
	assert(count == ARRAY_SIZE(addresses));
	count = 0;
	for_each_sg_dma_page(first, &dma_iterator, 3, 3) {
		assert(count < 3 && sg_page_iter_dma_address(&dma_iterator) == addresses[3 + count]);
		count++;
	}
	assert(count == 3);
#ifdef CONFIG_NEED_SG_DMA_LENGTH
	/* Mapped lengths may differ from the logical page list. Neither iterator
	 * may accidentally consume the other's lengths. */
	sg_dma_len(first) = 200;
	sg_dma_len(second + 1) = PAGE_SIZE;
	const dma_addr_t shortened[] = {0x91000000, 0x91001000, 0xa2000000, 0xb3000000};
	count = 0;
	for_each_sg_dma_page(first, &dma_iterator, 3, 0) {
		assert(count < ARRAY_SIZE(shortened));
		assert(sg_page_iter_dma_address(&dma_iterator) == shortened[count++]);
	}
	assert(count == ARRAY_SIZE(shortened));
	count = 0;
	for_each_sg_page(first, &iterator, 3, 0)
		count++;
	assert(count == 6);
#endif
	__free_pages(pages, 3);
	stela_linux_pages_finish();
}

static void sg_chained_allocation(void)
{
	struct page *payload = alloc_page(GFP_KERNEL);
	assert(payload);
	unsigned int allocations = fixture.allocations;
	unsigned int releases = fixture.releases;
	unsigned int maximum = (unsigned int)SG_MAX_SINGLE_ALLOC;
	unsigned int nents = 2 * maximum + 3;
	struct sg_table table;
	assert(sg_alloc_table(&table, 0, GFP_KERNEL) == -EINVAL && !table.sgl);
	assert(!sg_alloc_table(&table, nents, GFP_KERNEL));
	assert(table.nents == nents && table.orig_nents == nents);
	assert(fixture.allocations == allocations + 2 && catalog.live_pages == 3);
	struct scatterlist *middle = sg_chain_ptr(table.sgl + maximum - 1);
	struct scatterlist *last_chunk = sg_chain_ptr(middle + maximum - 1);
	assert(sg_is_chain(table.sgl + maximum - 1) && sg_is_chain(middle + maximum - 1));
	assert(sg_next(table.sgl + maximum - 2) == middle);
	assert(sg_next(middle + maximum - 2) == last_chunk);
	struct page *first_chunk_page = virt_to_page(table.sgl);
	struct page *middle_chunk_page = virt_to_page(middle);
	assert(first_chunk_page != middle_chunk_page && first_chunk_page != payload);
	assert(page_ref_count(first_chunk_page) == 1 && page_ref_count(middle_chunk_page) == 1);
	struct scatterlist *sg;
	unsigned int index;
	for_each_sg(table.sgl, sg, table.orig_nents, index) {
		assert(!sg_is_chain(sg));
		sg_set_page(sg, payload, 64, 0);
	}
	assert(index == nents && sg_nents(table.sgl) == (int)nents);
	assert(sg_last(table.sgl, nents) == last_chunk + 4);
	assert(sg_nents_for_len(table.sgl, (u64)nents * 64) == (int)nents);
	assert(sg_nents_for_len(table.sgl, (u64)nents * 64 + 1) == -EINVAL);
	sg_free_table(&table);
	assert(!table.sgl && catalog.live_pages == 1 && fixture.releases == releases);
	assert(page_ref_count(payload) == 1 && page_to_phys(payload) == TEST_PHYSICAL);
	stela_linux_pages_finish();
	assert(fixture.releases == releases + 2);
	__free_page(payload);
	stela_linux_pages_finish();
	/* Exhaust the real fixture/catalog capacity after the first page-backed
	 * chunk. The unchanged allocation helper must unwind that partial chain. */
	struct page *held[TEST_PAGES - 1];
	for (size_t i = 0; i < ARRAY_SIZE(held); i++) {
		held[i] = alloc_page(GFP_KERNEL);
		assert(held[i]);
	}
	allocations = fixture.allocations;
	releases = fixture.releases;
	assert(sg_alloc_table(&table, nents, GFP_KERNEL) == -ENOMEM);
	assert(!table.sgl && table.orig_nents == maximum);
	assert(fixture.allocations == allocations + 1 && fixture.releases == releases);
	assert(catalog.live_pages == ARRAY_SIZE(held));
	stela_linux_pages_finish();
	assert(fixture.releases == releases + 1);
	for (size_t i = 0; i < ARRAY_SIZE(held); i++)
		__free_page(held[i]);
	stela_linux_pages_finish();
	assert(!catalog.live_pages);
}

static void sg_page_segments(void)
{
	struct page *pages[6];
	for (size_t i = 0; i < ARRAY_SIZE(pages); i++) {
		pages[i] = alloc_page(GFP_KERNEL);
		assert(pages[i]);
		if (i)
			assert(pages[i] == pages[0] + i && page_to_pfn(pages[i]) == page_to_pfn(pages[0]) + i);
	}
	struct sg_table table;
	unsigned long bytes = ARRAY_SIZE(pages) * PAGE_SIZE - 113 - 77;
	assert(!sg_alloc_table_from_pages(&table, pages, ARRAY_SIZE(pages), 113, bytes, GFP_KERNEL));
	assert(table.nents == 1 && table.orig_nents == 1 && sg_is_last(table.sgl));
	assert(sg_page(table.sgl) == pages[0] && table.sgl->offset == 113 && table.sgl->length == bytes);
	assert(sg_phys(table.sgl) == page_to_phys(pages[0]) + 113);
	assert(sg_virt(table.sgl) == (u8 *)page_address(pages[0]) + 113);
	sg_free_table(&table);
	assert(!sg_alloc_table_from_pages_segment(&table, pages, ARRAY_SIZE(pages), 113, bytes,
						2 * PAGE_SIZE + 127, GFP_KERNEL));
	assert(table.nents == 3 && table.orig_nents == 3);
	struct scatterlist *sg = table.sgl;
	const unsigned int lengths[] = {2 * PAGE_SIZE - 113, 2 * PAGE_SIZE, 2 * PAGE_SIZE - 77};
	for (size_t i = 0; i < ARRAY_SIZE(lengths); i++) {
		assert(sg && sg_page(sg) == pages[2 * i] && sg->length == lengths[i]);
		assert(sg->offset == (i ? 0U : 113U));
		sg = sg_next(sg);
	}
	assert(!sg);
	sg_free_table(&table);
	struct page *gapped[] = {pages[0], pages[1], pages[3], pages[4]};
	assert(!sg_alloc_table_from_pages(&table, gapped, ARRAY_SIZE(gapped), 17,
					4 * PAGE_SIZE - 17 - 9, GFP_KERNEL));
	assert(table.nents == 2 && table.orig_nents == 2);
	assert(sg_page(table.sgl) == pages[0] && table.sgl->offset == 17 &&
	       table.sgl->length == 2 * PAGE_SIZE - 17);
	sg = sg_next(table.sgl);
	assert(sg && sg_page(sg) == pages[3] && !sg->offset && sg->length == 2 * PAGE_SIZE - 9);
	assert(sg_is_last(sg));
	sg_free_table(&table);
	struct sg_append_table append = {0};
	assert(!sg_alloc_append_table_from_pages(&append, pages, 2, 0, 2 * PAGE_SIZE,
					       4 * PAGE_SIZE, 2, GFP_KERNEL));
	assert(!sg_alloc_append_table_from_pages(&append, pages + 2, 2, 0, 2 * PAGE_SIZE,
					       4 * PAGE_SIZE, 0, GFP_KERNEL));
	assert(append.sgt.nents == 1 && append.sgt.orig_nents == 1);
	assert(sg_page(append.sgt.sgl) == pages[0] && append.sgt.sgl->length == 4 * PAGE_SIZE);
	assert(sg_is_last(append.sgt.sgl));
	sg_free_append_table(&append);
	assert(!append.sgt.sgl && catalog.live_pages == ARRAY_SIZE(pages));
	for (size_t i = 0; i < ARRAY_SIZE(pages); i++) {
		assert(page_ref_count(pages[i]) == 1);
		__free_page(pages[i]);
	}
	stela_linux_pages_finish();
	assert(!catalog.live_pages);
}

static void reclaimable_policy(void)
{
	const gfp_t ordinary[] = {
		0, GFP_KERNEL, GFP_NOWAIT, GFP_KERNEL_ACCOUNT,
		GFP_KERNEL | __GFP_ZERO | __GFP_COMP | __GFP_NOWARN | __GFP_NOMEMALLOC,
	};
	for (size_t i = 0; i < ARRAY_SIZE(ordinary); i++) {
		u32 gfp = (__force u32)ordinary[i];
		u32 reclaimable = gfp | (__force u32)__GFP_RECLAIMABLE;
		assert(stela_linux_page_request_basic(gfp));
		assert(!stela_linux_page_request_reclaimable(gfp));
		assert(!stela_linux_page_request_basic(reclaimable));
		assert(stela_linux_page_request_reclaimable(reclaimable));
		assert(stela_linux_page_request_blocking(gfp) ==
		       stela_linux_page_request_blocking(reclaimable));
	}
	const gfp_t unsupported[] = {
		__GFP_MOVABLE, __GFP_DMA, __GFP_HIGH,
		__GFP_MEMALLOC, GFP_ATOMIC, __GFP_NOFAIL, __GFP_WRITE,
		(__force gfp_t)(1U << 31),
	};
	for (size_t i = 0; i < ARRAY_SIZE(unsupported); i++) {
		u32 gfp = (__force u32)(GFP_KERNEL | __GFP_RECLAIMABLE | unsupported[i]);
		assert(!stela_linux_page_request_basic(gfp));
		assert(!stela_linux_page_request_reclaimable(gfp));
	}
}


static u64 inventory_gap_physical;
static unsigned long inventory_gap_virtual;
static void absent_inventory_pfn(void)
{
    (void)pfn_to_page(inventory_gap_physical >> PAGE_SHIFT);
}
static void absent_inventory_virtual(void)
{
    (void)__pa(inventory_gap_virtual);
}

/* All extents below refer to this fixture's actual retained CPU allocation;
 * symbolic PA labels are CPU-test-only, not native physical qualification. */
static void immutable_multi_extent_inventory(void)
{
    static_assert(sizeof(struct stela_linux_page_reservation) == 32);
    static_assert(offsetof(struct stela_linux_page_reservation, generation) == 0);
    static_assert(offsetof(struct stela_linux_page_reservation, physical_base) == 8);
    static_assert(offsetof(struct stela_linux_page_reservation, cpu_base) == 16);
    static_assert(offsetof(struct stela_linux_page_reservation, page_count) == 24);
    static_assert(sizeof(struct stela_linux_page_ops) == 4 * sizeof(void *));
    static_assert(offsetof(struct stela_linux_page_ops, release_ready) == 3 * sizeof(void *));
    struct stela_linux_page_reservation extents[] = {
        {.generation = 3, .physical_base = TEST_PHYSICAL,
         .cpu_base = fixture.cpu, .page_count = TEST_PAGES / 2},
        {.generation = 3, .physical_base = TEST_PHYSICAL + TEST_PAGES / 2 * PAGE_SIZE,
         .cpu_base = fixture.cpu + TEST_PAGES / 2 * PAGE_SIZE, .page_count = TEST_PAGES / 2},
    };
    assert(stela_linux_page_catalog_register_extents(NULL, 1, &test_ops, &fixture) == -EINVAL);
    assert(stela_linux_page_catalog_register_extents(extents, 0, &test_ops, &fixture) == -EINVAL);
    struct stela_linux_page_reservation invalid[2];
    for (unsigned int fault = 0; fault < 6; fault++) {
        memcpy(invalid, extents, sizeof(invalid));
        switch (fault) {
        case 0: invalid[1].generation++; break;
        case 1: invalid[1].physical_base = invalid[0].physical_base; break;
        case 2: invalid[1].cpu_base = invalid[0].cpu_base; break;
        case 3: invalid[1].physical_base = U64_MAX & PAGE_MASK; break;
        case 4: invalid[1].cpu_base = (void *)(ULONG_MAX & PAGE_MASK); break;
        case 5: invalid[1].page_count = SIZE_MAX; break;
        }
        assert(stela_linux_page_catalog_register_extents(invalid, 2, &test_ops, &fixture) == -EINVAL);
        assert(!metadata_live && !catalog.pages);
    }
    for (size_t fail = 0; fail < 4; fail++) {
        metadata_fail_after = fail;
        assert(stela_linux_page_catalog_register_extents(extents, 2, &test_ops, &fixture) == -ENOMEM);
        assert(!metadata_live && !catalog.pages);
    }
    metadata_fail_after = NO_INDEX;
    assert(!stela_linux_page_catalog_register_extents(extents, 2, &test_ops, &fixture));
    struct page *all = alloc_pages(GFP_KERNEL | __GFP_COMP | __GFP_ZERO, 4);
    assert(all && verify_extent(all, 4));
    struct page *stable = all + TEST_PAGES / 2;
    assert(page_to_pfn(stable) == (TEST_PHYSICAL >> PAGE_SHIFT) + TEST_PAGES / 2);
    assert(stela_linux_page_catalog_register_extents(extents, 2, &test_ops, &fixture) == -EBUSY);
    assert(pfn_to_page(page_to_pfn(stable)) == stable);
    __free_pages(all, 4);
    assert(!stela_linux_page_catalog_unregister(3));
    assert(!metadata_live);

    /* Sparse PA coverage and an excluded CPU interval are independent. */
    for (unsigned int scenario = 0; scenario < 2; scenario++) {
        extents[0].generation = extents[1].generation = 4 + scenario;
        extents[0].page_count = extents[1].page_count = 4;
        extents[1].cpu_base = fixture.cpu + 8 * PAGE_SIZE;
        extents[1].physical_base = TEST_PHYSICAL + (scenario ? 4 : 64) * PAGE_SIZE;
        for (size_t i = 0; i < TEST_PAGES; i++)
            fixture.used[i] = (i >= 4 && i < 8) || i >= 12;
        for (size_t i = 0; i < 4; i++)
            fixture.physical_override[8 + i] = extents[1].physical_base + i * PAGE_SIZE;
        assert(!stela_linux_page_catalog_register_extents(extents, 2, &test_ops, &fixture));
        struct page *first = alloc_pages(GFP_KERNEL | __GFP_ZERO, 2);
        struct page *second = alloc_pages(GFP_KERNEL | __GFP_ZERO, 2);
        assert(first && second && second == first + 4);
        assert(page_to_pfn(first) == TEST_PHYSICAL >> PAGE_SHIFT);
        assert(page_to_pfn(second) == extents[1].physical_base >> PAGE_SHIFT);
        assert(page_address(first) == fixture.cpu && page_address(second) == fixture.cpu + 8 * PAGE_SIZE);
        assert(__va(page_to_phys(second) + 37) == fixture.cpu + 8 * PAGE_SIZE + 37);
        assert(__pa(fixture.cpu + 8 * PAGE_SIZE + 37) == page_to_phys(second) + 37);
        inventory_gap_virtual = (unsigned long)(fixture.cpu + 4 * PAGE_SIZE);
        assert(stela_test_traps(absent_inventory_virtual));
        if (!scenario) {
            inventory_gap_physical = TEST_PHYSICAL + 4 * PAGE_SIZE;
            assert(stela_test_traps(absent_inventory_pfn));
        }
        for (size_t i = 0; i < 4; i++) {
            assert(page_to_pfn(second + i) == (extents[1].physical_base >> PAGE_SHIFT) + i);
            assert(pfn_to_page(page_to_pfn(second + i)) == second + i);
        }
        assert(stela_linux_page_catalog_unregister(4 + scenario) == -EBUSY);
        __free_pages(first, 2);
        __free_pages(second, 2);
        assert(!stela_linux_page_catalog_unregister(4 + scenario));
        assert(!metadata_live);
        for (size_t i = 0; i < TEST_PAGES; i++) {
            fixture.used[i] = false;
            fixture.physical_override[i] = 0;
        }
    }
}



static bool test_release_ready(void *context, void *pin)
{
    struct test_provider *provider = context;
    assert(stela_linux_quiescent() && !stela_linux_try_enter(&stela_linux_bare));
    provider->readiness_checks++;
    return pin != provider->held_pin;
}

static void deferred_pin_retirement(void)
{
    const struct stela_linux_page_reservation extent = {
        .generation = 6, .physical_base = TEST_PHYSICAL, .cpu_base = fixture.cpu,
        .page_count = TEST_PAGES,
    };
    struct stela_linux_page_ops ops = test_ops;
    ops.release_ready = test_release_ready;
    assert(!metadata_live && !catalog.pages);
    assert(!stela_linux_page_catalog_register_extents(&extent, 1, &ops, &fixture));
    unsigned int released = fixture.releases;
    struct page *first = alloc_page(GFP_KERNEL);
    struct page *second = alloc_page(GFP_KERNEL);
    assert(first && second);
    size_t record = catalog.state[0].allocation;
    fixture.held_pin = catalog.allocations[record].pin;
    u8 *payload = page_address(first);
    *payload = 0x5a;
    get_page(first);
    unsigned int checks = fixture.readiness_checks;
    __free_page(first);
    stela_linux_pages_finish();
    assert(fixture.readiness_checks == checks && page_ref_count(first) == 1);
    __free_page(first);
    __free_page(second);
    assert(!catalog.live_pages && catalog.retired != NO_INDEX);
    stela_linux_pages_finish();
    assert(fixture.releases == released + 1 && fixture.held_pin->active);
    assert(*payload == 0x5a && catalog.state[0].allocation == record);
    assert(stela_linux_page_catalog_unregister(6) == -EBUSY);
    assert(catalog.pages && metadata_live && fixture.held_pin->active);
    /* A malformed overlapping output cannot bypass the pending marker. Its
     * own actual pin is released; the retained first pin remains untouched. */
    fixture.overlap_physical = TEST_PHYSICAL;
    fixture.fault = OUTPUT_OVERLAP;
    assert(!alloc_page(GFP_KERNEL));
    assert(fixture.held_pin->active && catalog.state[0].allocation == record);
    fixture.fault = OUTPUT_VALID;
    fixture.overlap_physical = 0;
    assert(fixture.releases == released + 2);
    fixture.held_pin = NULL; /* CPU model acknowledgment, not native fences. */
    stela_linux_pages_finish();
    assert(fixture.releases == released + 3 && catalog.retired == NO_INDEX);
    assert(catalog.state[0].allocation == NO_INDEX);
    stela_linux_pages_finish();
    assert(fixture.releases == released + 3);
    assert(!stela_linux_page_catalog_unregister(6) && !metadata_live);
}


static bool ordinary_release_ready(void *context, void *pin)
{
    assert(context == &fixture && pin);
    return true; /* These ordinary CPU pins have no additional lifetime fence. */
}

static bool refuse_availability;

static int test_available_page_frames(void *context, size_t start, size_t pages,
                                      size_t *available)
{
    assert(context == &fixture && start == (size_t)fixture.cpu && pages == TEST_PAGES);
    if (refuse_availability)
        return -EAGAIN;
    *available = pages - 1;
    return 0;
}

static void annotated_stack_admission(void)
{
    unsigned char *stack = aligned_alloc(THREAD_ALIGN, THREAD_SIZE);
    assert(stack);
    memset(stack, 0, THREAD_SIZE);
    u64 stack_physical = TEST_PHYSICAL + TEST_PAGES * PAGE_SIZE + THREAD_SIZE;
    u64 physical[THREAD_SIZE / PAGE_SIZE];
    for (size_t i = 0; i < ARRAY_SIZE(physical); i++)
        physical[i] = stack_physical + i * PAGE_SIZE;
    u64 generation = last_generation + 1;
    struct stela_linux_page_extent extents[2] = {
        {.reservation = {.generation = generation, .physical_base = TEST_PHYSICAL,
                         .cpu_base = fixture.cpu, .page_count = TEST_PAGES},
         .kind = STELA_LINUX_PAGE_ORDINARY},
        {.reservation = {.generation = generation, .physical_base = stack_physical,
                         .cpu_base = stack, .page_count = ARRAY_SIZE(physical)},
         .kind = STELA_LINUX_PAGE_RUNTIME_STACK},
    };
    struct stela_linux_page_ops ops = test_ops;
    assert(stela_linux_page_catalog_register_annotated(extents, ARRAY_SIZE(extents),
                                                       &ops, &fixture) == -EINVAL);
    ops.release_ready = ordinary_release_ready;
    assert(stela_linux_page_catalog_register_annotated(NULL, ARRAY_SIZE(extents),
                                                       &ops, &fixture) == -EINVAL);
    assert(stela_linux_page_catalog_register_annotated(extents, 0, &ops, &fixture) == -EINVAL);
    extents[1].kind = 2;
    assert(stela_linux_page_catalog_register_annotated(extents, ARRAY_SIZE(extents), &ops, &fixture) == -EINVAL);
    extents[1].kind = STELA_LINUX_PAGE_RUNTIME_STACK;
    extents[1].reserved = 1;
    assert(stela_linux_page_catalog_register_annotated(extents, ARRAY_SIZE(extents), &ops, &fixture) == -EINVAL);
    extents[1].reserved = 0;
    extents[1].reservation.page_count--;
    assert(stela_linux_page_catalog_register_annotated(extents, ARRAY_SIZE(extents), &ops, &fixture) == -EINVAL);
    extents[1].reservation.page_count++;
    extents[1].reservation.cpu_base = (u8 *)extents[1].reservation.cpu_base + 1;
    assert(stela_linux_page_catalog_register_annotated(extents, ARRAY_SIZE(extents), &ops, &fixture) == -EINVAL);
    extents[1].reservation.cpu_base = (u8 *)extents[1].reservation.cpu_base - 1;
    for (size_t i = 0; i < 6; i++) {
        metadata_fail_after = i;
        assert(stela_linux_page_catalog_register_annotated(extents, ARRAY_SIZE(extents), &ops, &fixture) == -ENOMEM);
        assert(!metadata_live && !catalog.pages);
    }
    metadata_fail_after = NO_INDEX;
    assert(!stela_linux_page_catalog_register_annotated(extents, ARRAY_SIZE(extents), &ops, &fixture));
    assert(catalog.extent_count == 2 && !catalog.stack_admissions);
    assert(stela_linux_page_boot_capacity() == TEST_PAGES);
    unsigned long available = ULONG_MAX;
    assert(!stela_linux_available_page_frames(&available));
    assert(available == TEST_PAGES - 1);
    refuse_availability = true;
    assert(stela_linux_available_page_frames(&available) == -EAGAIN);
    assert(available == TEST_PAGES - 1);
    refuse_availability = false;
    assert(totalram_pages() == TEST_PAGES);
    struct zone *zone = &contig_page_data.node_zones[ZONE_NORMAL];
    assert(zone_managed_pages(zone) == TEST_PAGES);
    assert(zone->present_pages == TEST_PAGES + ARRAY_SIZE(physical));
    assert(node_present_pages(0) == zone->present_pages);
    assert(zone->zone_start_pfn == PHYS_PFN(TEST_PHYSICAL));
    assert(zone_end_pfn(zone) == PHYS_PFN(stack_physical) + ARRAY_SIZE(physical));
    assert(zone->spanned_pages == zone->present_pages + THREAD_SIZE / PAGE_SIZE);
    assert(contig_page_data.node_start_pfn == zone->zone_start_pfn);
    assert(contig_page_data.node_spanned_pages == zone->spanned_pages);
    assert(contig_page_data.nr_zones == ZONE_NORMAL + 1);
    assert(zone->zone_pgdat == &contig_page_data);
    struct sysinfo info;
    si_meminfo(&info);
    assert(info.totalram == TEST_PAGES && info.mem_unit == PAGE_SIZE);
    /* Inspect private catalog identity: the public PFN/page conversions
     * deliberately reject these unpublished, zero-reference descriptors. */
    assert(catalog.pages + physical_slot(stack_physical) ==
           catalog.pages + physical_slot(TEST_PHYSICAL) + TEST_PAGES);
    struct stela_linux_stack_admission request = {
        .version = STELA_LINUX_STACK_ADMISSION, .bytes = sizeof(request),
        .generation = generation, .cpu_base = stack,
        .physical_pages = physical, .page_count = ARRAY_SIZE(physical),
    };
    struct stela_linux_stack_ticket empty = {
        .version = STELA_LINUX_STACK_ADMISSION, .bytes = sizeof(empty),
        .record = NO_INDEX,
    };
    struct stela_linux_stack_ticket ticket = empty;
    /* Only eight header bytes are owned in these controls. A bad bytes value
     * must refuse before reading any field from an absent tail. */
    u32 short_header[2] __aligned(__alignof__(struct stela_linux_stack_ticket)) = {
        STELA_LINUX_STACK_ADMISSION, sizeof(short_header),
    };
    assert(stela_linux_page_stack_admit((void *)short_header, &ticket) == -EINVAL);
    assert(!memcmp(&ticket, &empty, sizeof(ticket)));
    assert(stela_linux_page_stack_admit(&request, (void *)short_header) == -EINVAL);
    request.generation++;
    assert(stela_linux_page_stack_admit(&request, &ticket) == -EINVAL);
    request.generation--;
    request.page_count--;
    assert(stela_linux_page_stack_admit(&request, &ticket) == -EINVAL);
    request.page_count++;
    request.cpu_base = fixture.cpu;
    assert(stela_linux_page_stack_admit(&request, &ticket) == -EINVAL);
    request.cpu_base = stack;
    u64 saved = physical[1];
    physical[1] += PAGE_SIZE;
    assert(stela_linux_page_stack_admit(&request, &ticket) == -EINVAL);
    physical[1] = saved;
    u64 nonce = catalog.next_stack_nonce;
    catalog.next_stack_nonce = U64_MAX;
    assert(stela_linux_page_stack_admit(&request, &ticket) == -EOVERFLOW);
    assert(!memcmp(&ticket, &empty, sizeof(ticket)) && !catalog.stack_admissions);
    catalog.next_stack_nonce = nonce;
    assert(!stela_linux_page_stack_admit(&request, &ticket));
    assert(catalog.stack_admissions == 1 && !catalog.live_pages);
    assert(stela_linux_page_catalog_unregister(generation) == -EBUSY);
    /* Negative fence control, not a C payload loan: an unexpected logical
     * reference must prevent marker cancellation without changing its owner. */
    struct page *reserved = catalog.pages + physical_slot(stack_physical);
    set_page_count(reserved, 1);
    assert(stela_linux_page_stack_cancel(&ticket) == -EBUSY);
    assert(catalog.stack_admissions == 1 && page_ref_count(reserved) == 1);
    set_page_count(reserved, 0);
    struct stela_linux_stack_ticket second = empty;
    assert(stela_linux_page_stack_admit(&request, &second) == -EINVAL);
    assert(!memcmp(&second, &empty, sizeof(second)));
    struct stela_linux_stack_ticket wrong = ticket;
    wrong.nonce++;
    assert(stela_linux_page_stack_cancel(&wrong) == -EINVAL);
    wrong = ticket; wrong.generation++;
    assert(stela_linux_page_stack_cancel(&wrong) == -EINVAL);
    wrong = ticket; wrong.record = NO_INDEX;
    assert(stela_linux_page_stack_cancel(&wrong) == -EINVAL);
    assert(stela_linux_page_stack_cancel((void *)short_header) == -EINVAL);
    assert(catalog.stack_admissions == 1);
    /* Ordinary allocation validation may not consume a real RuntimeStack
     * view, before admission or after its unpublished marker is removed. */
    size_t first;
    struct stela_linux_page_allocation output = {
        .pin = &ticket, .cpu_base = stack, .physical_pages = physical,
        .page_count = ARRAY_SIZE(physical),
    };
    assert(!validate_allocation(&output, __ffs(ARRAY_SIZE(physical)), &first));
    assert(!stela_linux_page_stack_cancel(&ticket));
    assert(!catalog.stack_admissions);
    assert(stela_linux_page_stack_cancel(&ticket) == -EINVAL);
    assert(catalog.extents[1].kind == STELA_LINUX_PAGE_RUNTIME_STACK);
    assert(!validate_allocation(&output, __ffs(ARRAY_SIZE(physical)), &first));
    assert(!stela_linux_page_stack_admit(&request, &second));
    assert(second.nonce != ticket.nonce);
    assert(stela_linux_page_stack_cancel(&ticket) == -EINVAL);
    assert(!stela_linux_page_stack_cancel(&second));
    /* Original ordinary source/refcount/release behavior still works while
     * the separate stack descriptors remain reserved and unreferenced. */
    struct page *page = alloc_page(GFP_KERNEL | __GFP_ZERO);
    assert(page && page_ref_count(page) == 1);
    __free_page(page);
    stela_linux_pages_finish();
    assert(!catalog.live_pages && !catalog.stack_admissions);
    assert(!stela_linux_page_catalog_unregister(generation));
    assert(!metadata_live);
    assert(!totalram_pages() && !zone_managed_pages(zone));
    assert(!node_present_pages(0) && !zone->present_pages);
    assert(!zone->zone_start_pfn && !zone->spanned_pages && !zone->zone_pgdat);
    assert(!contig_page_data.node_start_pfn && !contig_page_data.node_spanned_pages);
    assert(!contig_page_data.nr_zones);
    assert(stela_linux_available_page_frames(&available) == -ENODEV);
    assert(available == TEST_PAGES - 1);
    free(stack);
}

static void dma_pins_retain_original_allocations(void)
{
    assert(!stela_linux_page_dma_pin(TEST_PHYSICAL));
    struct page *page = alloc_pages(GFP_KERNEL, 2);
    assert(page);
    u64 physical = page_to_phys(page);
    assert(!stela_linux_page_dma_pin(physical + 1));
    assert(!stela_linux_page_dma_pin(TEST_PHYSICAL + TEST_PAGES * PAGE_SIZE));
    /* A noncompound tail has no independent Linux page reference. The DMA
     * lease must hold the actual allocation when __free_pages drops it. */
    void *head = stela_linux_page_dma_pin(physical);
    void *tail = stela_linux_page_dma_pin(physical + 3 * PAGE_SIZE);
    assert(head && tail == head);
    struct allocation_record *record = head;
    record->dma_refs = SIZE_MAX;
    assert(!stela_linux_page_dma_pin(physical));
    record->dma_refs = 2;
    unsigned int releases = fixture.releases;
    __free_pages(page, 2);
    assert(!catalog.live_pages);
    assert(!stela_linux_page_dma_pin(physical));
    assert(stela_linux_page_catalog_unregister(catalog.generation) == -EBUSY);
    assert(fixture.releases == releases && record->pin && record->dma_refs == 2);
    stela_linux_page_dma_unpin(head);
    stela_linux_pages_finish();
    assert(fixture.releases == releases && record->pin && record->dma_refs == 1);
    stela_linux_page_dma_unpin(tail);
    assert(fixture.releases == releases);
    stela_linux_pages_finish();
    assert(fixture.releases == releases + 1 && catalog.retired == NO_INDEX);
    page = alloc_pages(GFP_KERNEL, 2);
    assert(page && page_to_phys(page) == physical);
    __free_pages(page, 2);
    stela_linux_pages_finish();
}

static void mapping_pins_retain_exact_original_allocations(
 const struct stela_linux_owner *owner)
{
 /* Match the actual entered owner so invalid generations/contexts reach
  * their own validation instead of an earlier foreign-owner refusal. */
 assert(stela_linux_owner()==owner);
 struct stela_linux_mapping_page a,b,refused;
 struct page *page=alloc_pages(GFP_KERNEL,2);
 assert(page);
 u64 physical=page_to_phys(page), generation=catalog.generation;
 static const struct stela_linux_services no_services={};
 static const struct stela_linux_owner foreign={.services=&no_services};
 assert(stela_linux_page_mapping_pin(generation+1,&fixture,owner,physical,&refused)==-EINVAL);
 assert(!refused.record && !refused.provider_pin && !refused.cpu_page);
 assert(stela_linux_page_mapping_pin(generation,&foreign,owner,physical,&refused)==-EINVAL);
 assert(stela_linux_page_mapping_pin(generation,&fixture,&foreign,physical,&refused)==-EPERM);
 assert(stela_linux_page_mapping_pin(generation,&fixture,owner,physical+1,&refused)==-EINVAL);
 preempt_disable();
 assert(stela_linux_page_mapping_pin(generation,&fixture,owner,physical,&refused)==-EPERM);
 preempt_enable();
 assert(!stela_linux_page_mapping_pin(generation,&fixture,owner,physical,&a));
 assert(!stela_linux_page_mapping_pin(generation,&fixture,owner,physical+3*PAGE_SIZE,&b));
 struct allocation_record *record=a.record;
 assert(b.record==a.record && a.provider_pin==record->pin && b.provider_pin==record->pin);
 assert(a.cpu_page==page_address(page) && b.cpu_page==(u8 *)page_address(page)+3*PAGE_SIZE);
 record->dma_refs=SIZE_MAX;
 assert(stela_linux_page_mapping_pin(generation,&fixture,owner,physical,&refused)==-EOVERFLOW);
 assert(!refused.record && !refused.provider_pin && !refused.cpu_page);
 record->dma_refs=2;
 unsigned int before=fixture.releases;
 __free_pages(page,2);
 assert(stela_linux_page_mapping_pin(generation,&fixture,owner,physical,&refused)==-ENOENT);
 assert(stela_linux_page_catalog_unregister(generation)==-EBUSY);
 assert(fixture.releases==before && record->dma_refs==2 && record->pin);
 assert(stela_linux_page_mapping_unpin(generation+1,&fixture,owner,a.record)==-EINVAL);
 assert(stela_linux_page_mapping_unpin(generation,&foreign,owner,a.record)==-EINVAL);
 assert(stela_linux_page_mapping_unpin(generation,&fixture,&foreign,a.record)==-EPERM);
 assert(record->dma_refs==2);
 assert(!stela_linux_page_mapping_unpin(generation,&fixture,owner,a.record));
 stela_linux_pages_finish();
 assert(record->dma_refs==1 && fixture.releases==before);
 assert(!stela_linux_page_mapping_unpin(generation,&fixture,owner,b.record));
 assert(stela_linux_page_mapping_unpin(generation,&fixture,owner,b.record)==-EINVAL);
 assert(fixture.releases==before); /* No inline provider release. */
 stela_linux_pages_finish();
 assert(fixture.releases==before+1);
}

int main(void)
{
	reclaimable_policy();
	assert(stela_linux_page_request_basic((__force u32)(GFP_KERNEL | __GFP_ZERO | __GFP_COMP)));
	assert(stela_linux_page_request_basic((__force u32)GFP_KERNEL_ACCOUNT));
	assert(!stela_linux_page_request_basic((__force u32)(GFP_KERNEL | __GFP_MOVABLE)));
	assert(!stela_linux_page_request_basic((__force u32)(GFP_KERNEL | __GFP_HIGH)));
	assert(!stela_linux_page_request_basic(0x80000000U));
	assert(stela_linux_page_request_blocking((__force u32)GFP_KERNEL));
	assert(!stela_linux_page_request_blocking((__force u32)GFP_NOWAIT));
	fixture.cpu = aligned_alloc(TEST_PAGES * PAGE_SIZE, TEST_PAGES * PAGE_SIZE);
	assert(fixture.cpu);
	const struct stela_linux_services services = {
		.unsupported = test_unsupported, .available_page_frames = test_available_page_frames,
	};
	const struct stela_linux_owner owner = {.services = &services, .context = &fixture};
	struct stela_linux_page_reservation reservation = {
		.generation = 1, .physical_base = TEST_PHYSICAL, .cpu_base = fixture.cpu,
		.page_count = TEST_PAGES,
	};
	assert(stela_linux_try_enter(&owner));
	assert(!stela_linux_try_enter(&stela_linux_bare));
	assert(!alloc_page(GFP_KERNEL));
	struct stela_linux_page_reservation invalid = reservation;
	invalid.page_count = SIZE_MAX;
	assert(stela_linux_page_catalog_register(&invalid, &test_ops, &fixture) == -EINVAL);
	invalid = reservation;
	invalid.generation = 0;
	assert(stela_linux_page_catalog_register(&invalid, &test_ops, &fixture) == -EINVAL);
	for (size_t i = 0; i < 4; i++) {
		metadata_fail_after = i;
		assert(stela_linux_page_catalog_register(&reservation, &test_ops, &fixture) == -ENOMEM);
		assert(!metadata_live && !catalog.pages);
	}
	metadata_fail_after = NO_INDEX;
	assert(!stela_linux_page_catalog_register(&reservation, &test_ops, &fixture));
	assert(stela_linux_page_catalog_register(&reservation, &test_ops, &fixture) == -EBUSY);
	assert(stela_linux_page_catalog_verify(2) == -EINVAL);
	assert(!stela_linux_page_catalog_verify(1));
	refusal_and_rollback();
	adjacency_and_retirement();
	stela_linux_enter(&owner);
	struct folio_batch batch;
	folio_batch_init(&batch);
	struct page *single = alloc_page(GFP_KERNEL);
	struct page *compound = alloc_pages(GFP_KERNEL | __GFP_COMP, 1);
	assert(single && compound);
	assert(page_ref_freeze(single, 1) && page_ref_freeze(compound, 1));
	folio_batch_add(&batch, page_folio(single));
	folio_batch_add(&batch, page_folio(compound));
	unsigned int releases = fixture.releases;
	free_unref_folios(&batch);
	assert(!folio_batch_count(&batch) && !catalog.live_pages);
	assert(fixture.releases == releases);
	stela_linux_pages_finish();
	assert(fixture.releases == releases + 2);
	struct page *run = alloc_pages(GFP_KERNEL, 2);
	assert(run && !PageHead(run) && page_ref_freeze(run, 1));
	free_frozen_pages(run, 2);
	assert(!catalog.live_pages && fixture.releases == releases + 2);
	stela_linux_pages_finish();
	assert(fixture.releases == releases + 3);
	struct page *queued_page = alloc_page(GFP_KERNEL);
	assert(queued_page);
	struct folio *queued = page_folio(queued_page);
	folio_add_lru(queued);
	assert(folio_ref_count(queued) == 2);
	folio_batch_add(&batch, queued);
	folio_batch_release(&batch);
	assert(!folio_batch_count(&batch) && batch.percpu_pvec_drained);
	assert(!catalog.live_pages && fixture.releases == releases + 3);
	stela_linux_pages_finish();
	assert(fixture.releases == releases + 4);
	queued_page = alloc_page(GFP_KERNEL);
	assert(queued_page);
	queued = page_folio(queued_page);
	mlock_new_folio(queued);
	assert(folio_test_mlocked(queued) && folio_ref_count(queued) == 2);
	lru_add_drain();
	assert(folio_test_lru(queued) && folio_test_unevictable(queued));
	assert(folio_ref_count(queued) == 1);
	munlock_folio(queued);
	lru_add_drain();
	assert(!folio_test_mlocked(queued) && !folio_test_unevictable(queued));
	folio_put(queued);
	stela_linux_pages_finish();
	assert(!catalog.live_pages && fixture.releases == releases + 5);
	compound_and_split();
	stela_linux_enter(&owner);
	capacity();
	sg_markers_and_traversal();
	sg_iterator_geometry();
	sg_chained_allocation();
	sg_page_segments();
    dma_pins_retain_original_allocations();
    mapping_pins_retain_exact_original_allocations(&owner);
	assert(!catalog.live_pages);
	assert(!stela_linux_page_catalog_unregister(1));
	assert(stela_linux_page_catalog_register(&reservation, &test_ops, &fixture) == -EINVAL);
	reservation.generation = 2;
	assert(!stela_linux_page_catalog_register(&reservation, &test_ops, &fixture));
	assert(stela_linux_page_catalog_unregister(1) == -EINVAL);
	assert(!stela_linux_page_catalog_unregister(2));
	assert(!metadata_live);
    immutable_multi_extent_inventory();
    deferred_pin_retirement();
    annotated_stack_admission();
	stela_linux_exit();
	assert(fixture.allocations == fixture.releases + 1); /* One deliberate ENOMEM. */
	for (size_t i = 0; i < TEST_PAGES; i++)
		assert(!fixture.used[i] && !fixture.pins[i].active);
	free(fixture.cpu);
	printf("Linux pages/SG: ownership, retirement, chains, iterators and coalescing passed\n");
	return 0;
}
#endif
