//! Aleph0's own page tables: the identity map VM exits load through
//! HOST_CR3.
//!
//! Until now HOST_CR3 was the firmware's CR3, so the exit handler ran on
//! page tables in `BOOT_SERVICES_DATA`, which the OS may reuse after
//! `ExitBootServices`. These tables belong to Aleph0 and map every address
//! the UEFI memory map reaches, identity (linear = physical), as the
//! firmware's do: the image, every allocation, and the firmware stack that
//! `vmx_return_to_launcher` returns to.
//!
//! The shape is the one `docs/PAGE_TABLE_WALK.md` describes: one PML4 entry
//! (the map ends below 512 GiB), one PDPT, and below it either 1 GiB pages
//! or one PD of 2 MiB pages per GiB:
//!
//! ```text
//! 1 GiB pages:  PML4[0] ─▶ PDPT[0..gibs] = 1 GiB pages               2 table pages
//! 2 MiB pages:  PML4[0] ─▶ PDPT[0..gibs] ─▶ PD[0..512] = 2 MiB pages  2 + gibs table pages
//! ```
//!
//! Every entry is present, writable and supervisor, with XD clear: the host
//! does not switch IA32_EFER on VM exit, so the tables must work whether or
//! not EFER.NXE is set. The memory-type bits (PWT, PCD, PAT) are 0, which
//! selects PAT entry 0, WB by default; the MTRRs then give device memory
//! its type, as they do for the firmware. Accessed and dirty are set from
//! the start, so the CPU never writes the tables.

use crate::vmx::cr::CR4_LA57;
use crate::vmx::ept::level::{Level, Pd, Pdpt, Pml4, TableLevel};
use crate::vmx::ept::{PDPT_SPAN, SIZE_1G};
use crate::vmx::page::{PAGE_SIZE, allocate_zeroed_pages};
use core::marker::PhantomData;

/// Entry bit 0 (P): the entry is used.
const PRESENT: u64 = 1 << 0;
/// Entry bit 1 (R/W): writes allowed.
const WRITABLE: u64 = 1 << 1;
/// Entry bit 5 (A): the CPU has used the entry. Set in advance.
const ACCESSED: u64 = 1 << 5;
/// Leaf bit 6 (D): the CPU has written the page. Set in advance.
const DIRTY: u64 = 1 << 6;
/// PDPT or PD entry bit 7 (PS): maps a 1 GiB or 2 MiB page directly.
const LARGE_PAGE: u64 = 1 << 7;
/// Bits 51:12: the physical address in an entry.
const ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Entries per table: 4096 bytes / 8 bytes per entry.
const ENTRIES: usize = 512;

/// The size of the pages the map is made of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageSize {
    /// PDPT entries map 1 GiB each: no PDs at all.
    Huge1G,
    /// PDPT entries point to PDs whose entries map 2 MiB each.
    Large2M,
}

impl PageSize {
    /// 1 GiB pages when the CPU has them ([`crate::vmx::cpuid::has_1g_pages`]),
    /// 2 MiB pages otherwise. Every 64-bit CPU has 2 MiB pages.
    pub fn for_cpu(has_1g_pages: bool) -> Self {
        if has_1g_pages { Self::Huge1G } else { Self::Large2M }
    }

    /// Name for the report.
    pub fn name(self) -> &'static str {
        match self {
            Self::Huge1G => "1 GiB pages",
            Self::Large2M => "2 MiB pages",
        }
    }
}

/// Why the host page tables could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPagingError {
    /// CR4.LA57 is set: the CPU walks 5 levels, and these tables have 4.
    /// HOST_CR4 is the running CR4, so the host would walk 5 levels too.
    FiveLevelPaging,
    /// The map would end at `end`: not a whole number of GiB above 0, or
    /// past what one PDPT reaches (512 GiB).
    InvalidEnd { end: u64 },
    /// UEFI could not provide the table pages.
    AllocationFailed,
}

/// Refuses 5-level paging: with CR4.LA57 set, CR3 would have to point to a
/// PML5.
pub fn check_paging_mode(cr4: u64) -> Result<(), HostPagingError> {
    if cr4 & CR4_LA57 != 0 {
        return Err(HostPagingError::FiveLevelPaging);
    }
    Ok(())
}

/// How many GiB a map ending at `end` covers. `end` comes from
/// `ept::memory_map_end`, so it is a whole number of GiB, and the map has
/// one PDPT, so it reaches 512 GiB at most; anything else is refused rather
/// than rounded.
fn gibs(end: u64) -> Result<usize, HostPagingError> {
    if end == 0 || !end.is_multiple_of(SIZE_1G) || end > PDPT_SPAN {
        return Err(HostPagingError::InvalidEnd { end });
    }
    Ok((end / SIZE_1G) as usize)
}

/// Pages the tables of a map of `gibs` GiB take: the PML4, the PDPT, and
/// with 2 MiB pages one PD per GiB.
pub fn table_pages(gibs: usize, page_size: PageSize) -> usize {
    match page_size {
        PageSize::Huge1G => 2,
        PageSize::Large2M => 2 + gibs,
    }
}

/// One entry of a level-`L` table. `repr(transparent)`, so a table page is
/// 512 of these back to back.
///
/// As with `ept::EptEntry`, the level decides the constructors: every level
/// above PT may point to a table ([`table`](Self::table)); a PDPT entry may
/// map 1 GiB ([`huge_page`](Self::huge_page)) and a PD entry 2 MiB
/// ([`large_page`](Self::large_page)). The map has no 4 KiB pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct HostEntry<L: Level> {
    raw: u64,
    level: PhantomData<L>,
}

impl<L: Level> HostEntry<L> {
    const fn from_raw(raw: u64) -> Self {
        Self {
            raw,
            level: PhantomData,
        }
    }
}

impl<L: TableLevel> HostEntry<L> {
    /// An entry pointing to the level-`L::Next` table at `address`.
    pub fn table(address: u64) -> Self {
        Self::from_raw((address & ADDRESS_MASK) | PRESENT | WRITABLE | ACCESSED)
    }
}

/// The bits of a leaf entry for the large page at `address`.
fn large_page_bits(address: u64) -> u64 {
    (address & ADDRESS_MASK) | PRESENT | WRITABLE | ACCESSED | DIRTY | LARGE_PAGE
}

impl HostEntry<Pdpt> {
    /// An entry mapping the 1 GiB page at `address`, which must be 1 GiB
    /// aligned.
    pub fn huge_page(address: u64) -> Self {
        Self::from_raw(large_page_bits(address))
    }
}

impl HostEntry<Pd> {
    /// An entry mapping the 2 MiB page at `address`, which must be 2 MiB
    /// aligned.
    pub fn large_page(address: u64) -> Self {
        Self::from_raw(large_page_bits(address))
    }
}

/// The tables of a map, as slices, with the physical address of the PDPT
/// and of the first PD. Under UEFI's identity mapping a table's physical
/// address is its virtual one; on the host tests these are made-up numbers.
struct Tables<'a> {
    pml4: &'a mut [HostEntry<Pml4>],
    pdpt: &'a mut [HostEntry<Pdpt>],
    /// With 2 MiB pages, one PD per GiB, back to back; empty otherwise.
    pds: &'a mut [HostEntry<Pd>],
    pdpt_address: u64,
    pds_address: u64,
}

/// Fills `tables` with an identity map of the first `gibs` GiB in
/// `page_size` pages. `tables.pds` holds `gibs` PDs for 2 MiB pages, and
/// none for 1 GiB pages.
fn fill_identity_map(tables: Tables<'_>, gibs: usize, page_size: PageSize) {
    tables.pml4[0] = HostEntry::table(tables.pdpt_address);
    for (gib, entry) in tables.pdpt[..gibs].iter_mut().enumerate() {
        let address = gib as u64 * SIZE_1G;
        *entry = match page_size {
            PageSize::Huge1G => HostEntry::huge_page(address),
            PageSize::Large2M => HostEntry::table(tables.pds_address + (gib * PAGE_SIZE) as u64),
        };
    }
    // The PDs are back to back, so PD entry number `i` across all of them
    // maps i * 2 MiB.
    for (i, entry) in tables.pds.iter_mut().enumerate() {
        *entry = HostEntry::large_page(i as u64 * (SIZE_1G / ENTRIES as u64));
    }
}

/// Aleph0's host page tables. Never freed: every VM exit loads them, and
/// the code that runs after the guest stops uses them until teardown loads
/// the firmware's CR3 again.
pub struct HostPageTables {
    pml4: u64,
    end: u64,
    page_size: PageSize,
    table_pages: usize,
}

impl HostPageTables {
    /// Builds an identity map of `[0, end)` in `page_size` pages.
    ///
    /// # Safety
    ///
    /// Boot services must still be active, and physical memory must be
    /// identity-mapped (as UEFI does), since the tables are filled through
    /// their physical addresses.
    pub unsafe fn build(end: u64, page_size: PageSize) -> Result<Self, HostPagingError> {
        let gibs = gibs(end)?;
        let pd_pages = table_pages(gibs, page_size) - 2;
        let pml4 = allocate_zeroed_pages(1, HostPagingError::AllocationFailed)?.as_ptr() as u64;
        let pdpt = allocate_zeroed_pages(1, HostPagingError::AllocationFailed)?.as_ptr() as u64;
        // No allocation at all when there are no PDs: UEFI refuses 0 pages.
        let pds = match pd_pages {
            0 => 0,
            pages => allocate_zeroed_pages(pages, HostPagingError::AllocationFailed)?.as_ptr() as u64,
        };

        /// The `pages` table pages at `address` as one slice of entries.
        ///
        /// # Safety
        ///
        /// `address` is a page-aligned allocation of `pages` zeroed pages
        /// (or `pages` is 0), and nothing else refers to it while the slice
        /// lives.
        unsafe fn table<'a, L: Level>(address: u64, pages: usize) -> &'a mut [HostEntry<L>] {
            if pages == 0 {
                return &mut [];
            }
            // SAFETY: the caller guarantees the memory is ours and as long as
            // the slice; an all-zero entry is a valid (not present) entry.
            unsafe { core::slice::from_raw_parts_mut(address as *mut HostEntry<L>, pages * ENTRIES) }
        }
        // SAFETY: each allocation above is page-aligned, zeroed and as long
        // as its slice, and nothing else refers to it yet.
        let tables = unsafe {
            Tables {
                pml4: table(pml4, 1),
                pdpt: table(pdpt, 1),
                pds: table(pds, pd_pages),
                pdpt_address: pdpt,
                pds_address: pds,
            }
        };
        fill_identity_map(tables, gibs, page_size);

        Ok(Self {
            pml4,
            end,
            page_size,
            table_pages: table_pages(gibs, page_size),
        })
    }

    /// The value for HOST_CR3: the PML4's address, with PWT, PCD and (when
    /// CR4.PCIDE is set) the PCID all 0.
    pub fn cr3(&self) -> u64 {
        self.pml4
    }

    /// End of the map: linear addresses `[0, end)` are mapped to themselves.
    pub fn end(&self) -> u64 {
        self.end
    }

    /// The size of the pages the map uses.
    pub fn page_size(&self) -> PageSize {
        self.page_size
    }

    /// Pages holding the tables.
    pub fn table_pages(&self) -> usize {
        self.table_pages
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/host/page_tables.rs"]
mod tests;
