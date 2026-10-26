//! What the harness overwrites: every range of the final memory map the OS
//! may reclaim (`memory::is_reclaimable`, Aleph0's own classification),
//! except the harness's own image, which holds its code, stack, page tables
//! and everything else it still uses.

use uefi::boot::MemoryType;

use crate::memory::is_reclaimable;

const PAGE_SIZE: u64 = 4096;

/// Writes the `[start, end)` ranges of `regions` (start, pages, type) that
/// the OS may reclaim into `out`, with `keep` cut out of them, and returns
/// how many there are. Only the first `out.len()` are written.
pub fn reclaimable_except(
    regions: impl Iterator<Item = (u64, u64, MemoryType)>,
    keep: (u64, u64),
    out: &mut [(u64, u64)],
) -> usize {
    let mut count = 0;
    for (start, pages, _) in regions.filter(|&(_, _, memory_type)| is_reclaimable(memory_type)) {
        let end = start.saturating_add(pages.saturating_mul(PAGE_SIZE));
        // What lies below `keep`, and what lies above it.
        for (from, to) in [(start, end.min(keep.0)), (start.max(keep.1), end)] {
            if from < to {
                if let Some(slot) = out.get_mut(count) {
                    *slot = (from, to);
                }
                count += 1;
            }
        }
    }
    count
}

#[cfg(test)]
#[path = "../tests/unit/regions.rs"]
mod tests;
