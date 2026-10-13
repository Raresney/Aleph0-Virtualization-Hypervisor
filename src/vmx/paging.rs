//! A read-only walk of the current 4-level page tables.
//!
//! Answers one question: for a given address, what do the page tables say
//! about it? Is it mapped, can it be written, can code run from it?
//!
//! With guest CR3 = host CR3, the guest translates linear addresses through
//! exactly these tables, so what they say about a page is what the guest's
//! first translation stage gives. EPT (`vmx::ept`) then translates the
//! result a second time and may refuse the access on its own.
//!
//! In 64-bit mode the CPU translates every address through 4 levels of
//! tables, splitting the address into pieces:
//!
//! ```text
//!  47      39 38      30 29      21 20      12 11         0
//! [ PML4 idx | PDPT idx |  PD idx  |  PT idx  |   offset   ]
//!    9 bits     9 bits     9 bits     9 bits     12 bits
//! ```
//!
//! CR3 points to the first table (PML4). Each index picks one 8-byte entry
//! in the current table, and that entry points to the next table. The last
//! entry points to the page itself, and the offset is added to it.
//!
//! [`walk`] is pure logic over a "read the entry at this physical address"
//! function, so it can be tested on the host with fake tables.
//! [`walk_current`] runs it on the live CR3.
//!
//! A longer walkthrough with more examples is in `docs/PAGE_TABLE_WALK.md`.
//!
//! # Why the pieces are 12 and 9 bits
//!
//! A page is 4096 = 2^12 bytes, so 12 bits pick a byte inside it. A table
//! fills exactly one page with 8-byte entries: 4096 / 8 = 512 = 2^9
//! entries, so 9 bits pick an entry. 4 * 9 + 12 = 48 bits; bits 63:48 of
//! the address must be copies of bit 47 ("canonical").
//!
//! # The levels
//!
//! The names are historical: 32-bit x86 had only PD -> PT, and each wider
//! mode added a level on top. An entry is named after its table: PML4E,
//! PDPTE, PDE, PTE.
//!
//! ```text
//! CR3 ──► PML4  Page Map Level 4             one entry covers 512 GiB
//!          │
//!          ▼
//!         PDPT  Page Directory Pointer Table one entry covers   1 GiB ──(PS=1)──► 1 GiB page
//!          │
//!          ▼
//!         PD    Page Directory               one entry covers   2 MiB ──(PS=1)──► 2 MiB page
//!          │
//!          ▼
//!         PT    Page Table                   one entry covers   4 KiB = the page
//! ```
//!
//! Each level splits its region into 512 pieces. The tree only needs tables
//! for regions that are actually used: an unused 512 GiB region is just a
//! PML4 entry with P = 0. A flat table for 48 bits would itself be 512 GiB.
//!
//! At every level, two different things decide where to look:
//! - *which row* comes from the virtual address (that level's 9 bits);
//! - *where the table is* comes from the row read one level up (or CR3).
//!
//! # CR3
//!
//! One register per CPU core, holding the root of the tree in use right
//! now. It does not change per address: every lookup starts from the same
//! CR3 and only takes different rows. An OS gives each process its own tree
//! and loads that process's CR3 on a switch; VM entry/exit load GUEST_CR3 /
//! HOST_CR3 from the VMCS. Aleph0 never writes CR3: the UEFI firmware built
//! the (identity-mapped) tables and loaded CR3 before the `.efi` started.
//!
//! ```text
//!  63      52 51                     12 11     5  4   3  2  0
//! ┌──────────┬─────────────────────────┬────────┬───┬───┬────┐
//! │ reserved │  PML4 table address     │ ignored│PCD│PWT│ign │
//! └──────────┴─────────────────────────┴────────┴───┴───┴────┘
//! ```
//!
//! The low 12 address bits are always 0 (tables are 4 KiB-aligned), so they
//! are not stored. With CR4.PCIDE = 1, bits 11:0 hold a process-context ID.
//!
//! # Entry format
//!
//! Every entry is one 64-bit number: an address plus flag bits. `*` marks
//! the bits [`walk`] reads.
//!
//! An entry that points to the next table (any PML4E; PDPTE/PDE with PS=0):
//!
//! ```text
//!  63  62    52 51                    12 11  8  7   6  5   4   3   2   1   0
//! ┌───┬────────┬────────────────────────┬─────┬───┬───┬──┬───┬───┬───┬───┬───┐
//! │XD │ ignored│  next table address    │ ign │PS │ign│A │PCD│PWT│U/S│R/W│ P │
//! └───┴────────┴────────────────────────┴─────┴───┴───┴──┴───┴───┴───┴───┴───┘
//!   *                    *                      *                      *   *
//! ```
//!
//! A PTE (4 KiB page):
//!
//! ```text
//!  63  62 59 58 52 51                    12 11 9  8   7   6  5   4   3   2   1   0
//! ┌───┬─────┬─────┬────────────────────────┬────┬───┬───┬───┬──┬───┬───┬───┬───┬───┐
//! │XD │PKey │ ign │   4 KiB page address   │ign │ G │PAT│ D │A │PCD│PWT│U/S│R/W│ P │
//! └───┴─────┴─────┴────────────────────────┴────┴───┴───┴───┴──┴───┴───┴───┴───┴───┘
//! ```
//!
//! A PDE with PS = 1 (2 MiB page) looks like a PTE, except bit 7 is PS = 1,
//! PAT moves to bit 12, bits 20:13 are reserved (0), and the page address is
//! bits 51:21. A PDPTE with PS = 1 (1 GiB page) is the same with the page
//! address in bits 51:30 and bits 29:13 reserved.
//!
//! | Bit     | Name | Meaning                                                    |
//! |---------|------|------------------------------------------------------------|
//! | 0       | P    | Present. 0 = nothing mapped; all other bits are ignored.   |
//! | 1       | R/W  | Writes allowed in this region.                             |
//! | 2       | U/S  | User (ring 3) may access. 0 = kernel only.                 |
//! | 3, 4    | PWT, PCD | Caching: write-through, cache-disable.                 |
//! | 5       | A    | Accessed; set by the CPU when the entry is used.           |
//! | 6       | D    | Dirty (page entries only); set when the page is written.   |
//! | 7       | PS   | In PDPTE/PDE: 1 = this entry is a 1 GiB/2 MiB page.        |
//! | 7 or 12 | PAT  | Memory type (bit 7 in a PTE, bit 12 in a large page).      |
//! | 8       | G    | Global: keep in the TLB across CR3 changes (pages only).   |
//! | 51:12   | addr | Next table or page. Bits above MAXPHYADDR must be 0.       |
//! | 62:59   | PKey | Protection key (pages only); unused here.                  |
//! | 63      | XD   | No instruction fetch in this region (if EFER.NXE = 1).     |
//!
//! # Combining permissions
//!
//! The CPU checks every level and the strictest one wins, like doors in a
//! row: a page is writable only if R/W = 1 at *every* level (AND), and one
//! XD = 1 at *any* level blocks execution (OR). A PTE saying "writable"
//! under a read-only PDE is read-only.
//!
//! U/S works like R/W: a page is a *user* page only if U/S = 1 at every
//! level (AND); one U/S = 0 makes it a *supervisor* page. That matters even
//! for ring-0 code, through two CR4 bits:
//! - SMEP (bit 20): ring 0 may not *execute* from user pages.
//! - SMAP (bit 21): ring 0 may not *read or write* user pages unless
//!   RFLAGS.AC = 1.
//!
//! So for a ring-0 guest, "XD clear" alone does not prove a page is
//! executable, and "R/W set" alone does not prove it is writable.
//!
//! The CPU caches finished lookups in the TLB, so it does not walk on every
//! access; writing CR3 flushes most of that cache.
//!
//! # Worked example: the guest code page on Hyper-V
//!
//! Table locations and entry values are illustrative; the result matches
//! the Hyper-V log (`phys=0x7eb19000 size=Size4K writable=true xd=false`).
//!
//! ```text
//! virtual_address = 0x7eb19000
//!   47:39 = 000000000  PML4 index 0
//!   38:30 = 000000001  PDPT index 1
//!   29:21 = 111110101  PD   index 0x1F5
//!   20:12 = 100011001  PT   index 0x119
//!   11:0  = 0          offset 0
//!
//! CR3 = 0x7f801000                      -> table 0x7f801000
//! L4: row 0     at 0x7f801000 = 0x7f802023  P R/W A, PS=0 -> table 0x7f802000
//! L3: row 1     at 0x7f802008 = 0x7f803023  P R/W A, PS=0 -> table 0x7f803000
//! L2: row 0x1F5 at 0x7f803fa8 = 0x7f9a0023  P R/W A, PS=0 -> table 0x7f9a0000
//! L1: row 0x119 at 0x7f9a08c8 = 0x7eb19063  P R/W A D     -> page  0x7eb19000
//!
//! physical = 0x7eb19000 | (0x7eb19000 & 0xFFF) = 0x7eb19000
//! ```
//!
//! Each row address is `table + index * 8`; each next table is
//! `entry & ADDRESS_MASK`. The low bits `0x023` = `0b0010_0011` are P, R/W
//! and A; `0x063` adds D.
//!
//! Had the PD row been `0x7ea000E3` (`0xE3` sets PS), the walk would stop
//! at level 2 with a 2 MiB page and a 21-bit offset: physical =
//! `0x7ea00000 | (0x7eb19000 & 0x1FFFFF)` = the same `0x7eb19000`. The PT
//! index bits simply become part of the offset.

use super::cr::{read_cr3, read_cr4, CR4_LA57};

// Entry bits used by the walk; the full layout is in the module docs.

/// Bit 0 (P): the entry is valid. If 0, nothing is mapped below it.
const PRESENT: u64 = 1 << 0;
/// Bit 1 (R/W): writes allowed in this entry's region.
const WRITABLE: u64 = 1 << 1;
/// Bit 2 (U/S): user mode (ring 3) may access this entry's region.
const USER: u64 = 1 << 2;
/// Bit 7 (PS), in a PDPTE or PDE: this entry maps a 1 GiB or 2 MiB page
/// directly instead of pointing to a table.
const PAGE_SIZE_BIT: u64 = 1 << 7;
/// Bit 63 (XD): no instruction fetch in this entry's region.
const EXECUTE_DISABLE: u64 = 1 << 63;
/// Bits 51:12: physical address of the next table or of the page. Strips
/// the flag bits that share the same 8 bytes.
const ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageSize {
    Size4K,
    Size2M,
    Size1G,
}

/// How one virtual address translates, with permissions combined over
/// every level of the walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    pub physical: u64,
    pub size: PageSize,
    /// R/W is set at every level. (Supervisor code may also write a
    /// read-only page while CR0.WP = 0; this does not count that.)
    pub writable: bool,
    /// U/S is set at every level: a user page. Ring 0 cannot execute it
    /// under CR4.SMEP, nor read or write it under CR4.SMAP (with AC = 0).
    pub user: bool,
    /// XD is set at some level. Blocks instruction fetch when EFER.NXE = 1;
    /// when NXE = 0 the bit is reserved and any access faults.
    pub execute_disable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkError {
    /// CR4.LA57 is set; 5-level paging is not supported here.
    FiveLevelPaging,
    /// The entry at `level` (4 = PML4, 3 = PDPT, 2 = PD, 1 = PT) has P clear.
    NotPresent { level: u8 },
}

/// Translates `virtual_address` through the 4-level tables rooted at `cr3`.
///
/// `read_entry` returns the 8-byte entry at a physical address. The walker
/// never touches memory itself; the caller decides how entries are read,
/// which is what lets the tests use fake tables. Bits 11:0 of `cr3` (PCID
/// or cache flags) are ignored.
pub fn walk(cr3: u64, virtual_address: u64, read_entry: impl Fn(u64) -> u64) -> Result<Mapping, WalkError> {
    let mut table = cr3 & ADDRESS_MASK;
    // Permissions are combined over the whole walk, starting permissive.
    let mut writable = true;
    let mut user = true;
    let mut execute_disable = false;

    // Level 4 (PML4) down to level 1 (PT).
    for level in (1..=4u8).rev() {
        // This level's 9-bit index: bits 47:39 at level 4, 38:30 at level 3,
        // 29:21 at level 2, 20:12 at level 1.
        let shift = 12 + 9 * (level as u32 - 1);
        let index = (virtual_address >> shift) & 0x1FF;
        let entry = read_entry(table + index * 8);

        if entry & PRESENT == 0 {
            return Err(WalkError::NotPresent { level });
        }
        // Writable or user only if R/W or U/S is set at every level; one XD
        // bit at any level is enough to block execution.
        writable &= entry & WRITABLE != 0;
        user &= entry & USER != 0;
        execute_disable |= entry & EXECUTE_DISABLE != 0;

        // Does this entry map a page (end of the walk) or point to the next
        // table? At levels 3 and 2, the PS bit means "this entry is the
        // page": 1 GiB or 2 MiB, with a 30- or 21-bit offset instead of 12.
        // A level-1 entry is always a 4 KiB page.
        let size = match level {
            3 if entry & PAGE_SIZE_BIT != 0 => Some(PageSize::Size1G),
            2 if entry & PAGE_SIZE_BIT != 0 => Some(PageSize::Size2M),
            1 => Some(PageSize::Size4K),
            _ => None,
        };
        if let Some(size) = size {
            // Large-page entries keep the PAT bit at bit 12, inside the
            // offset range, so clear the offset bits from the frame.
            let offset_mask = (1u64 << shift) - 1;
            let frame = entry & ADDRESS_MASK & !offset_mask;
            return Ok(Mapping {
                physical: frame | (virtual_address & offset_mask),
                size,
                writable,
                user,
                execute_disable,
            });
        }

        // Not a page yet: the entry holds the next table's address.
        table = entry & ADDRESS_MASK;
    }

    unreachable!("a level-1 entry always ends the walk")
}

/// Translates `virtual_address` through the page tables the CPU is using now.
///
/// Reads the real CR3 and gives [`walk`] a function that reads each entry
/// straight from memory at its physical address. Refuses 5-level paging,
/// which [`walk`] does not handle.
///
/// # Safety
///
/// Reads the tables through their physical addresses, so the tables
/// themselves must be identity-mapped. UEFI guarantees that while boot
/// services are active; after `ExitBootServices` it no longer holds.
pub unsafe fn walk_current(virtual_address: u64) -> Result<Mapping, WalkError> {
    if unsafe { read_cr4() } & CR4_LA57 != 0 {
        return Err(WalkError::FiveLevelPaging);
    }
    let cr3 = unsafe { read_cr3() };
    walk(cr3, virtual_address, |physical| unsafe { (physical as *const u64).read_volatile() })
}

/// The tests build small fake page tables in a `HashMap` (physical address
/// to entry) and check translation, permission combining, large pages, and
/// missing entries.
#[cfg(test)]
#[path = "../../tests/unit/vmx/paging.rs"]
mod tests;
