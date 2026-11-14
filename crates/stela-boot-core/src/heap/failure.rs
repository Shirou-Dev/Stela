//! First failed ordinary allocation: no allocation, waiting or caller formatter.
use super::{CLASSES, CPUS, Heap, Usage};
use core::{alloc::Layout, fmt, sync::atomic::Ordering};

struct Report {
    layout: Layout,
    usage: Option<Usage>,
    /// Live size-class bytes by class, and each tagged core's own bytes, as
    /// the relaxed per-core counters hold them.
    classes: [isize; CLASSES],
    cores: [isize; CPUS],
    tagged: usize,
}

fn capture(heap: &Heap, layout: Layout) -> Option<Report> {
    if heap
        .failure_reported
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return None;
    }
    heap.failed[0].store(layout.size(), Ordering::Relaxed);
    heap.failed[1].store(layout.align(), Ordering::Release);
    let usage = heap.try_lock().and_then(|guard| {
        // SAFETY: the successful one-shot guard owns heap metadata and masks
        // local IRQ reentry. No state borrow or guard reaches UART formatting.
        let state = unsafe { &*heap.state.get() };
        let usage = state.ready.then(|| heap.usage_locked(state));
        drop(guard);
        usage
    });
    let mut cores = [0; CPUS];
    let mut tagged = 0;
    for (slot, own) in cores.iter_mut().zip(heap.owned()) {
        *slot = own;
        tagged += 1;
    }
    Some(Report {
        layout,
        usage,
        classes: heap.class_live(),
        cores,
        tagged,
    })
}
impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HEAP ALLOCATION FAILURE bytes={} align={}",
            self.layout.size(),
            self.layout.align()
        )?;
        match self.usage {
            Some(usage) => {
                writeln!(
                    f,
                    " snapshot=locked-metadata live_estimate={} cpu_counters=relaxed total={} carved={} peak={} largest={}",
                    usage.live, usage.total, usage.carved, usage.peak, usage.largest
                )?;
                // The live free-list allocations by power of two from 4 KiB,
                // where a size holds a megabyte or more, as HEAP lines give them.
                f.write_str("HEAP AT FAILURE large")?;
                for (bucket, &(count, bytes)) in usage.large.iter().enumerate() {
                    if bytes >= 1 << 20 {
                        write!(f, " {}K:{count}/{}M", 4 << bucket, bytes >> 20)?;
                    }
                }
            }
            None => f.write_str(" snapshot=unavailable\nHEAP AT FAILURE")?,
        }
        f.write_str(" classes")?;
        for (class, &bytes) in self.classes.iter().enumerate() {
            write!(f, " {}:{}M", 16 << class, bytes >> 20)?;
        }
        f.write_str(" cores")?;
        for &own in &self.cores[..self.tagged] {
            write!(f, " {}M", own >> 20)?;
        }
        writeln!(f)
    }
}

pub(super) fn report(heap: &Heap, layout: Layout) {
    if let Some(report) = capture(heap, layout) {
        // This formatter emits only fixed strings and integer fields; the
        // sink is bounded, lock-free output that runs no queue or log.
        (heap.failure_sink)(format_args!("\n{report}\n"));
    }
}

#[cfg(test)]
#[path = "failure/tests.rs"]
mod tests;
