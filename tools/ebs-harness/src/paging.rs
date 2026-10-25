//! The harness's own page tables, which replace the firmware's
//! (`BOOT_SERVICES_DATA`, overwritten later): an identity map of the first
//! GiBs in 2 MiB pages, which every x86-64 CPU has.
//!
//! ```text
//! PML4[0] ─▶ PDPT[0..gibs] ─▶ PD[gib][0..512] = 2 MiB pages, linear = physical
//! ```
//!
//! Every entry is present and writable, with XD clear, so the map works
//! whatever EFER.NXE the firmware left.

/// GiBs the tables can map: 64 PDs, 256 KiB of the harness's image.
pub const MAX_GIBS: usize = 64;
const SIZE_1G: u64 = 1 << 30;
const SIZE_2M: u64 = 1 << 21;
const ENTRIES: usize = 512;
/// The map covers at least this much, so the MMIO below 4 GiB (Local APIC,
/// flash) is mapped for `SetVirtualAddressMap` even when RAM ends lower.
const MIN_END: u64 = 4 * SIZE_1G;

/// Entry bit 0 (P): the entry is used.
const PRESENT: u64 = 1 << 0;
/// Entry bit 1 (R/W): writes allowed.
const WRITABLE: u64 = 1 << 1;
/// PD entry bit 7 (PS): maps a 2 MiB page.
const LARGE_PAGE: u64 = 1 << 7;

/// The tables, page-aligned, in the harness's `.bss`. Their linear address
/// is their physical one: the firmware's map and this one are identity.
#[repr(C, align(4096))]
pub struct PageTables {
    pml4: [u64; ENTRIES],
    pdpt: [u64; ENTRIES],
    pds: [[u64; ENTRIES]; MAX_GIBS],
}

impl PageTables {
    pub const EMPTY: Self = Self {
        pml4: [0; ENTRIES],
        pdpt: [0; ENTRIES],
        pds: [[0; ENTRIES]; MAX_GIBS],
    };

    /// Fills in the identity map of `[0, gibs GiB)`, and returns the value
    /// for CR3, or `None` if `gibs` is more than [`MAX_GIBS`].
    pub fn identity_map(&mut self, gibs: usize) -> Option<u64> {
        if gibs > MAX_GIBS {
            return None;
        }
        self.pml4[0] = self.pdpt.as_ptr() as u64 | PRESENT | WRITABLE;
        for gib in 0..gibs {
            self.pdpt[gib] = self.pds[gib].as_ptr() as u64 | PRESENT | WRITABLE;
            for (i, entry) in self.pds[gib].iter_mut().enumerate() {
                *entry = ((gib * ENTRIES + i) as u64 * SIZE_2M) | PRESENT | WRITABLE | LARGE_PAGE;
            }
        }
        Some(self.pml4.as_ptr() as u64)
    }
}

/// GiBs to map: up to the end of the memory map's last region (start,
/// pages), and at least 4 GiB.
pub fn gibs_to_map(regions: impl Iterator<Item = (u64, u64)>) -> usize {
    let end = regions
        .map(|(start, pages)| start.saturating_add(pages.saturating_mul(4096)))
        .fold(MIN_END, u64::max);
    end.div_ceil(SIZE_1G) as usize
}

#[cfg(test)]
#[path = "../tests/unit/paging.rs"]
mod tests;
