//! Extended Page Tables (EPT): the second stage of address translation.
//!
//! With EPT on, every guest memory access is translated twice:
//!
//! ```text
//! guest linear ──(guest page tables, guest CR3)──▶ guest-physical (GPA)
//! GPA          ──(EPT tables, built here)───────▶ host-physical  (HPA)
//! ```
//!
//! The guest controls the first stage; only Aleph0 controls the second. An
//! access the EPT entry does not allow causes a VM exit (reason 48, EPT
//! violation) instead of reaching memory, which is how Aleph0 protects
//! memory from the guest.
//!
//! The EPT tables have the same shape as ordinary 4-level page tables (PML4,
//! PDPT, PD, PT; 512 entries of 8 bytes per 4 KiB table; the same 9-bit
//! index per level), but the entry bits differ:
//!
//! ```text
//!  63    52 51               12 11   8  7   6  5   3  2  1  0
//! ┌────────┬───────────────────┬──────┬───┬────┬─────┬──┬──┬──┐
//! │ ignored│ address of next   │ ign. │ PS│IPAT│ type│ X│ W│ R│
//! │        │ table or the page │      │   │    │(leaf)  │  │  │
//! └────────┴───────────────────┴──────┴───┴────┴─────┴──┴──┴──┘
//! ```
//!
//! - R, W, X (bits 0-2): read, write, execute. There is no separate
//!   "present" bit: an entry with R = W = X = 0 is not present.
//! - type (bits 5:3, leaf entries only): memory type. With EPT on it
//!   replaces the MTRRs' type for guest accesses, so Aleph0 copies the
//!   MTRRs' type into it (see `mtrr.rs`).
//! - IPAT (bit 6): ignore the guest's PAT. Left clear, so the guest's PAT
//!   still combines with the EPT type, as it would with the MTRRs' type
//!   without EPT.
//! - PS (bit 7, in a PD entry): this entry maps a 2 MiB page directly.
//!
//! Aleph0 builds an identity map (GPA = HPA) of all memory, each page with
//! the memory type the MTRRs give it, so the guest runs exactly as without
//! EPT. A few named 4 KiB pages are mapped read-only ([`MAX_PROTECTED`] at
//! most): the guest's data page, so its write is the intentional EPT
//! violation, and the guest's stack page, so the reinjected NMI's delivery
//! faults when the CPU pushes the interrupt frame. Each
//! [`ProtectedPage::grant_write`] makes its page writable when that page's
//! violation arrives. The longer walkthrough is in `docs/EPT.md`.

use core::fmt;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicU64, AtomicUsize, Ordering};

use uefi::boot;
use uefi::mem::memory_map::MemoryMap;

use super::instruction::{VmxFail, vmx_asm};
use super::msr::ControlCapability;
use super::mtrr::{MemoryType, Mtrrs};
use super::page::{PAGE_SIZE, allocate_zeroed_pages};
use super::vmcs::fields::SECONDARY_ENABLE_EPT;

use self::level::{Level, Pd, Pdpt, Pml4, Pt, TableLevel};

/// Entry bit 0: reads allowed.
pub const EPT_READ: u64 = 1 << 0;
/// Entry bit 1: writes allowed.
pub const EPT_WRITE: u64 = 1 << 1;
/// Entry bit 2: instruction fetches allowed.
pub const EPT_EXECUTE: u64 = 1 << 2;
/// Every access allowed.
pub const EPT_RWX: u64 = EPT_READ | EPT_WRITE | EPT_EXECUTE;

/// Leaf entries keep the memory type in bits 5:3.
const MEMORY_TYPE_SHIFT: u32 = 3;
/// The memory type field, once shifted down by [`MEMORY_TYPE_SHIFT`].
const MEMORY_TYPE_BITS: u64 = 0b111;
/// PD entry bit 7: maps a 2 MiB page instead of pointing to a PT.
const LARGE_PAGE: u64 = 1 << 7;
/// Bits 51:12: the physical address in an entry.
const ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000;
/// EPTP bits 5:3: page-walk length minus one; 3 means 4 levels.
const EPTP_WALK_LENGTH_4: u64 = 3 << 3;

/// Entries per table: 4096 bytes / 8 bytes per entry.
const ENTRIES: usize = 512;
/// How many pages [`Ept::build`] can map read-only and publish for the exit
/// handler at once: the guest's data page and its NMI-delivery stack page.
pub const MAX_PROTECTED: usize = 2;
/// What a PD entry maps: a 2 MiB page, or a PT of 512 4 KiB pages.
pub const SIZE_2M: u64 = 1 << 21;
/// What a PDPT entry maps: a PD of 512 2 MiB regions.
pub const SIZE_1G: u64 = 1 << 30;
/// How far one PDPT reaches (512 entries of 1 GiB). Aleph0 builds one PDPT,
/// so the identity map ends here at most.
pub const MAX_IDENTITY_MAP: u64 = ENTRIES as u64 * SIZE_1G;

// IA32_VMX_EPT_VPID_CAP bits this module needs.
/// Bit 6: 4-level EPT page walks.
const CAP_WALK_LENGTH_4: u64 = 1 << 6;
/// Bit 14: the EPT tables themselves may be write-back.
const CAP_WRITE_BACK: u64 = 1 << 14;
/// Bit 16: PD entries may map 2 MiB pages.
const CAP_2M_PAGES: u64 = 1 << 16;
/// Bit 20: the INVEPT instruction.
const CAP_INVEPT: u64 = 1 << 20;
/// Bit 25: single-context INVEPT (only this EPTP's translations).
const CAP_INVEPT_SINGLE_CONTEXT: u64 = 1 << 25;
/// Bit 26: all-context INVEPT (every EPTP's translations).
const CAP_INVEPT_ALL_CONTEXT: u64 = 1 << 26;

/// Which cached EPT translations INVEPT drops. The value is the INVEPT type
/// operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InveptType {
    /// Translations derived from one EPTP: the one in the descriptor.
    SingleContext = 1,
    /// Translations derived from any EPTP.
    AllContext = 2,
}

impl InveptType {
    pub fn name(self) -> &'static str {
        match self {
            Self::SingleContext => "single-context",
            Self::AllContext => "all-context",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EptError {
    /// The CPU does not allow the "enable EPT" secondary control (or has no
    /// secondary controls at all).
    EptUnsupported,
    /// No 4-level EPT page walks.
    PageWalkLength4Unsupported,
    /// The EPT tables cannot be write-back.
    WriteBackUnsupported,
    /// No 2 MiB EPT pages.
    LargePagesUnsupported,
    /// No INVEPT, or neither the single- nor the all-context type.
    InveptUnsupported,
    /// UEFI could not return its memory map.
    MemoryMapUnavailable,
    /// The memory map has no memory in it.
    EmptyMemoryMap,
    /// The memory map reaches `end`, past what one PDPT maps.
    RangeTooLarge { end: u64 },
    /// The page to protect lies outside the identity map.
    ProtectedPageOutsideMap,
    /// UEFI could not provide the table pages.
    AllocationFailed,
    /// An EPT was already built and its protected pages published; the exit
    /// handler keeps one published set.
    AlreadyBuilt,
}

/// Checks that this CPU supports the EPT Aleph0 builds, and picks the INVEPT
/// type: single-context when available, otherwise all-context.
///
/// `secondary` is IA32_VMX_PROCBASED_CTLS2 and `ept_vpid_cap`
/// IA32_VMX_EPT_VPID_CAP, both 0 when the CPU lacks them.
pub fn check_support(secondary: ControlCapability, ept_vpid_cap: u64) -> Result<InveptType, EptError> {
    if !secondary.allows(SECONDARY_ENABLE_EPT) {
        return Err(EptError::EptUnsupported);
    }
    if ept_vpid_cap & CAP_WALK_LENGTH_4 == 0 {
        return Err(EptError::PageWalkLength4Unsupported);
    }
    if ept_vpid_cap & CAP_WRITE_BACK == 0 {
        return Err(EptError::WriteBackUnsupported);
    }
    if ept_vpid_cap & CAP_2M_PAGES == 0 {
        return Err(EptError::LargePagesUnsupported);
    }
    if ept_vpid_cap & CAP_INVEPT == 0 {
        return Err(EptError::InveptUnsupported);
    }
    if ept_vpid_cap & CAP_INVEPT_SINGLE_CONTEXT != 0 {
        Ok(InveptType::SingleContext)
    } else if ept_vpid_cap & CAP_INVEPT_ALL_CONTEXT != 0 {
        Ok(InveptType::AllContext)
    } else {
        Err(EptError::InveptUnsupported)
    }
}

/// The four table levels, as types: EPT's, and those of Aleph0's host page
/// tables (`vmx::host`), which have the same shape. [`EptEntry`] takes one
/// as its parameter, so each constructor exists only for the level it is
/// valid at: a PML4 entry cannot map a page, and a PT entry cannot point to
/// a table.
pub mod level {
    mod sealed {
        pub trait Sealed {}
    }

    /// One EPT table level. Sealed: the four below are all there are.
    pub trait Level: sealed::Sealed {
        /// The level's name, for debug output.
        const NAME: &'static str;
        /// Position of the 9 address bits that index this level's table.
        const SHIFT: u32;

        /// Index into this level's table for `address`.
        fn index(address: u64) -> usize {
            ((address >> Self::SHIFT) & 0x1FF) as usize
        }
    }

    /// A level whose entries may point to a table of the level below.
    pub trait TableLevel: Level {
        /// The level of the table such an entry points to.
        type Next: Level;
    }

    /// Page Map Level 4: the root, one entry per 512 GiB. Index bits 47:39.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Pml4 {}
    /// Page Directory Pointer Table: one entry per GiB. Index bits 38:30.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Pdpt {}
    /// Page Directory: one entry per 2 MiB, a PD table or a 2 MiB page.
    /// Index bits 29:21.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Pd {}
    /// Page Table: one entry per 4 KiB page. Index bits 20:12.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Pt {}

    impl sealed::Sealed for Pml4 {}
    impl sealed::Sealed for Pdpt {}
    impl sealed::Sealed for Pd {}
    impl sealed::Sealed for Pt {}

    impl Level for Pml4 {
        const NAME: &'static str = "PML4";
        const SHIFT: u32 = 39;
    }
    impl Level for Pdpt {
        const NAME: &'static str = "PDPT";
        const SHIFT: u32 = 30;
    }
    impl Level for Pd {
        const NAME: &'static str = "PD";
        const SHIFT: u32 = 21;
    }
    impl Level for Pt {
        const NAME: &'static str = "PT";
        const SHIFT: u32 = 12;
    }

    impl TableLevel for Pml4 {
        type Next = Pdpt;
    }
    impl TableLevel for Pdpt {
        type Next = Pd;
    }
    impl TableLevel for Pd {
        type Next = Pt;
    }
}

/// One entry of a level-`L` table, laid out as in the module docs.
/// `repr(transparent)`, so a table page is 512 of these back to back.
///
/// What an entry can be depends on its level:
///
/// | Level | Constructors |
/// |---|---|
/// | [`Pml4`], [`Pdpt`] | [`table`](Self::table) |
/// | [`Pd`] | [`table`](Self::table), [`large_page`](Self::large_page) |
/// | [`Pt`] | [`page`](Self::page), [`with_access`](Self::with_access) |
#[repr(transparent)]
pub struct EptEntry<L: Level> {
    raw: u64,
    level: PhantomData<L>,
}

impl<L: Level> EptEntry<L> {
    /// Not present: R = W = X = 0.
    pub const EMPTY: Self = Self::from_raw(0);

    const fn from_raw(raw: u64) -> Self {
        Self {
            raw,
            level: PhantomData,
        }
    }
}

impl<L: TableLevel> EptEntry<L> {
    /// An entry pointing to the level-`L::Next` table at `address`, allowing
    /// every access. A non-leaf entry only limits what lies below it, so the
    /// leaf entries decide the permissions.
    pub fn table(address: u64) -> Self {
        Self::from_raw((address & ADDRESS_MASK) | EPT_RWX)
    }
}

impl EptEntry<Pd> {
    /// An entry mapping the 2 MiB page at `address`: RWX, of `memory_type`.
    pub fn large_page(address: u64, memory_type: MemoryType) -> Self {
        Self::from_raw((address & ADDRESS_MASK) | EPT_RWX | (memory_type.raw() << MEMORY_TYPE_SHIFT) | LARGE_PAGE)
    }

    /// How the entry maps its 2 MiB region, read back from its bits.
    pub fn mapping(self) -> RegionMapping {
        if self.raw & EPT_RWX == 0 {
            return RegionMapping::Invalid;
        }
        if self.raw & LARGE_PAGE == 0 {
            return RegionMapping::Pt;
        }
        let memory_type = (self.raw >> MEMORY_TYPE_SHIFT) & MEMORY_TYPE_BITS;
        MemoryType::from_raw(memory_type as u8).map_or(RegionMapping::Invalid, RegionMapping::LargePage)
    }
}

/// How a PD entry maps its 2 MiB region: see [`EptEntry::mapping`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionMapping {
    /// One 2 MiB page of this memory type.
    LargePage(MemoryType),
    /// A PT of 4 KiB pages, each with its own type and access.
    Pt,
    /// Neither: not present, or a 2 MiB page whose type bits hold a
    /// reserved value. `Ept::build` makes no such entry.
    Invalid,
}

impl fmt::Display for RegionMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LargePage(memory_type) => write!(f, "2 MiB pages, {}", memory_type.name()),
            Self::Pt => f.write_str("4 KiB pages (a PT each)"),
            Self::Invalid => f.write_str("invalid (not present or reserved type)"),
        }
    }
}

/// Consecutive 2 MiB regions the PDs map the same way: see
/// [`Ept::region_runs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionRun {
    pub start: u64,
    pub end: u64,
    pub mapping: RegionMapping,
}

/// The regions `pds` map, consecutive ones with the same
/// [`mapping`](EptEntry::mapping) merged into one run. `pds` are back to
/// back from GPA 0, as [`fill_identity_map`] fills them.
fn region_runs(pds: &[EptEntry<Pd>]) -> impl Iterator<Item = RegionRun> + '_ {
    let mut regions = pds.iter().map(|entry| entry.mapping()).enumerate().peekable();
    core::iter::from_fn(move || {
        let (first, mapping) = regions.next()?;
        let mut last = first;
        while let Some((next, _)) = regions.next_if(|&(_, next_mapping)| next_mapping == mapping) {
            last = next;
        }
        Some(RegionRun {
            start: first as u64 * SIZE_2M,
            end: (last as u64 + 1) * SIZE_2M,
            mapping,
        })
    })
}

impl EptEntry<Pt> {
    /// An entry mapping the 4 KiB page at `address` with `access` (a mix of
    /// [`EPT_READ`], [`EPT_WRITE`], [`EPT_EXECUTE`]), of `memory_type`.
    pub fn page(address: u64, access: u64, memory_type: MemoryType) -> Self {
        Self::from_raw((address & ADDRESS_MASK) | (memory_type.raw() << MEMORY_TYPE_SHIFT)).with_access(access)
    }

    /// The same entry with its R, W and X bits replaced by `access`.
    pub fn with_access(self, access: u64) -> Self {
        Self::from_raw((self.raw & !EPT_RWX) | (access & EPT_RWX))
    }
}

// Written by hand rather than derived: a derive would require `L` itself to
// implement each trait, and the level types are never instantiated.
impl<L: Level> Clone for EptEntry<L> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<L: Level> Copy for EptEntry<L> {}

impl<L: Level> PartialEq for EptEntry<L> {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl<L: Level> Eq for EptEntry<L> {}

impl<L: Level> Default for EptEntry<L> {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl<L: Level> fmt::Debug for EptEntry<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EptEntry<{}>({:#x})", L::NAME, self.raw)
    }
}

/// An EPT pointer: the value of the VMCS EPT_POINTER field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Eptp(u64);

impl Eptp {
    /// The EPT pointer for the PML4 table at `pml4`: write-back (bits 2:0 =
    /// 6), 4-level walk (bits 5:3 = 3), no accessed/dirty flags (bit 6 = 0).
    /// So the low bits are always 0x1E.
    pub fn new(pml4: u64) -> Self {
        Self((pml4 & ADDRESS_MASK) | MemoryType::WriteBack.raw() | EPTP_WALK_LENGTH_4)
    }

    /// The pointer as the CPU reads it.
    pub fn raw(self) -> u64 {
        self.0
    }
}

/// End of the identity map for memory-map regions `(start, pages)`: the
/// highest address any region reaches, rounded up to 1 GiB, so every PD is
/// full.
///
/// Every region counts, whatever its type, so memory-mapped I/O the
/// firmware reports is mapped too, with the memory type the MTRRs give it.
pub fn identity_map_end(regions: impl Iterator<Item = (u64, u64)>) -> Result<u64, EptError> {
    let mut highest = 0u64;
    for (start, pages) in regions {
        let end = pages
            .checked_mul(PAGE_SIZE as u64)
            .and_then(|size| start.checked_add(size))
            .ok_or(EptError::RangeTooLarge { end: u64::MAX })?;
        highest = highest.max(end);
    }
    if highest == 0 {
        return Err(EptError::EmptyMemoryMap);
    }
    let rounded = highest
        .checked_add(SIZE_1G - 1)
        .map(|end| end & !(SIZE_1G - 1))
        .ok_or(EptError::RangeTooLarge { end: highest })?;
    if rounded > MAX_IDENTITY_MAP {
        return Err(EptError::RangeTooLarge { end: highest });
    }
    Ok(rounded)
}

/// The tables of an identity map, as slices, with the physical address each
/// one has. Under UEFI's identity mapping a table's physical address is its
/// virtual one; on the host tests these are made-up numbers.
struct Tables<'a> {
    pml4: &'a mut [EptEntry<Pml4>],
    pdpt: &'a mut [EptEntry<Pdpt>],
    /// One PD per GiB of the map, back to back.
    pds: &'a mut [EptEntry<Pd>],
    /// One PT per split region ([`split_regions`]), back to back.
    pts: &'a mut [EptEntry<Pt>],
    pdpt_address: u64,
    pds_address: u64,
    pts_address: u64,
}

/// The memory type of the 2 MiB region at `region` when one 2 MiB page can
/// map it, or `None` when it needs a PT of 4 KiB pages: its pages differ in
/// memory type, or it holds one of `protected_pages`. An EPT entry has one
/// memory type, so a 2 MiB page over pages of mixed types would give some of
/// them the wrong one.
fn large_page_type(mtrrs: &Mtrrs, region: u64, protected_pages: &[u64]) -> Option<MemoryType> {
    if protected_pages.iter().any(|&page| region == region_of(page)) {
        return None;
    }
    mtrrs.block_type(region, SIZE_2M)
}

/// The start of the 2 MiB region holding `address`.
fn region_of(address: u64) -> u64 {
    address & !(SIZE_2M - 1)
}

/// How many 2 MiB regions of the first `gibs` GiB need a PT
/// ([`large_page_type`] is `None`): how many PTs [`fill_identity_map`]
/// takes. At least one, for the region holding a protected page (two
/// protected pages in the same region still share one PT).
fn split_regions(mtrrs: &Mtrrs, gibs: usize, protected_pages: &[u64]) -> usize {
    (0..gibs * ENTRIES)
        .filter(|&i| large_page_type(mtrrs, i as u64 * SIZE_2M, protected_pages).is_none())
        .count()
}

/// Fills `tables` with an identity map of the first `gibs` GiB, each page
/// with the memory type `mtrrs` gives it, and RWX except `protected_pages`,
/// which are read-only. A 2 MiB region is one 2 MiB page when it can be
/// ([`large_page_type`]); otherwise it takes the next PT in `tables.pts`
/// and is mapped in 4 KiB pages. Returns the index in `tables.pts` of each
/// protected page's entry, in the order given.
///
/// `pds` holds `gibs` tables and `pts` [`split_regions`] tables, and each of
/// `protected_pages` is 4 KiB-aligned and inside the map; [`Ept::build`]
/// checks all three.
fn fill_identity_map(
    tables: Tables<'_>,
    gibs: usize,
    mtrrs: &Mtrrs,
    protected_pages: &[u64],
) -> [usize; MAX_PROTECTED] {
    debug_assert!(tables.pds.len() == gibs * ENTRIES);
    debug_assert!(protected_pages.len() <= MAX_PROTECTED);
    tables.pml4[0] = EptEntry::table(tables.pdpt_address);
    for gib in 0..gibs {
        tables.pdpt[gib] = EptEntry::table(tables.pds_address + gib as u64 * PAGE_SIZE as u64);
    }

    // The PDs are back to back, one per PDPT entry, so PD entry number `i`
    // across all of them maps GPA i * 2 MiB. No PML4 index: the map ends at
    // 512 GiB at most, so every address in it uses PML4 entry 0.
    let (pts, rest) = tables.pts.as_chunks_mut::<ENTRIES>();
    debug_assert!(rest.is_empty(), "the PTs are whole tables");
    let mut pts = pts.iter_mut().enumerate();
    let mut protected = [None; MAX_PROTECTED];
    for (i, entry) in tables.pds.iter_mut().enumerate() {
        let region = i as u64 * SIZE_2M;
        if let Some(memory_type) = large_page_type(mtrrs, region, protected_pages) {
            *entry = EptEntry::large_page(region, memory_type);
            continue;
        }
        let (number, pt) = pts.next().expect("split_regions counted a PT for this region");
        *entry = EptEntry::table(tables.pts_address + (number * PAGE_SIZE) as u64);
        for (j, page) in pt.iter_mut().enumerate() {
            let address = region + (j * PAGE_SIZE) as u64;
            *page = EptEntry::page(address, EPT_RWX, mtrrs.memory_type(address));
        }
        // Mark every protected page that falls in this region read-only; two
        // in the same region share this one PT.
        for (slot, &protected_page) in protected_pages.iter().enumerate() {
            if region == region_of(protected_page) {
                let index = Pt::index(protected_page);
                pt[index] = pt[index].with_access(EPT_READ);
                protected[slot] = Some(number * ENTRIES + index);
            }
        }
    }
    debug_assert!(pts.next().is_none(), "every PT is used");
    let mut indices = [0; MAX_PROTECTED];
    for slot in 0..protected_pages.len() {
        indices[slot] = protected[slot].expect("the protected page is inside the map");
    }
    indices
}

/// One EPT identity map. Its table pages are never freed: the CPU walks them
/// on every guest access for as long as the VMCS points at them.
pub struct Ept {
    eptp: Eptp,
    end: u64,
    /// The PDs, kept to report how they map memory. Nothing writes them
    /// after the build: the EPTP enables no accessed/dirty flags, and
    /// [`ProtectedPage`] changes a PT entry only.
    pds: &'static [EptEntry<Pd>],
    split_regions: usize,
    table_pages: usize,
}

impl Ept {
    /// Builds the identity map from the UEFI memory map, with the memory
    /// types of `mtrrs` and each of `protected_pages` read-only, and
    /// publishes the [`ProtectedPage`]s the exit handler needs later. Refuses
    /// a second build with [`EptError::AlreadyBuilt`]: the handler keeps a
    /// fixed, small set ([`MAX_PROTECTED`]).
    ///
    /// # Safety
    ///
    /// Boot services must still be active, and physical memory must be
    /// identity-mapped (as UEFI does), since the tables are filled through
    /// their physical addresses.
    pub unsafe fn build(protected_pages: &[u64], invept: InveptType, mtrrs: &Mtrrs) -> Result<Self, EptError> {
        debug_assert!(protected_pages.len() <= MAX_PROTECTED);
        let map = boot::memory_map(boot::MemoryType::LOADER_DATA).map_err(|_| EptError::MemoryMapUnavailable)?;
        let end = identity_map_end(map.entries().map(|region| (region.phys_start, region.page_count)))?;
        for &protected_page in protected_pages {
            if protected_page >= end || !protected_page.is_multiple_of(PAGE_SIZE as u64) {
                return Err(EptError::ProtectedPageOutsideMap);
            }
        }

        let gibs = (end / SIZE_1G) as usize;
        let split_regions = split_regions(mtrrs, gibs, protected_pages);
        let pml4 = allocate_zeroed_pages(1, EptError::AllocationFailed)?.as_ptr() as u64;
        let pdpt = allocate_zeroed_pages(1, EptError::AllocationFailed)?.as_ptr() as u64;
        let pds = allocate_zeroed_pages(gibs, EptError::AllocationFailed)?.as_ptr() as u64;
        let pts = allocate_zeroed_pages(split_regions, EptError::AllocationFailed)?.as_ptr() as u64;

        /// The `pages` table pages at `address` as one slice of entries.
        ///
        /// # Safety
        ///
        /// `address` is a page-aligned allocation of `pages` zeroed pages,
        /// and nothing else refers to it for the returned lifetime.
        unsafe fn table<'a, L: Level>(address: u64, pages: usize) -> &'a mut [EptEntry<L>] {
            // SAFETY: the caller guarantees the memory is ours and as long as
            // the slice; an all-zero `EptEntry` is a valid (empty) entry.
            unsafe { core::slice::from_raw_parts_mut(address as *mut EptEntry<L>, pages * ENTRIES) }
        }
        // SAFETY: the PD allocation is page-aligned, zeroed and `gibs` pages
        // long, and nothing else refers to it yet. It is never freed, so the
        // slice can live as long as the map.
        let pd_entries: &'static mut [EptEntry<Pd>] = unsafe { table(pds, gibs) };
        // SAFETY: each other allocation above is page-aligned, zeroed and as
        // long as its slice, and nothing else refers to it yet.
        let tables = unsafe {
            Tables {
                pml4: table(pml4, 1),
                pdpt: table(pdpt, 1),
                pds: &mut *pd_entries,
                pts: table(pts, split_regions),
                pdpt_address: pdpt,
                pds_address: pds,
                pts_address: pts,
            }
        };
        let protected = fill_identity_map(tables, gibs, mtrrs, protected_pages);

        let ept = Self {
            eptp: Eptp::new(pml4),
            end,
            pds: pd_entries,
            split_regions,
            table_pages: 2 + gibs + split_regions,
        };
        let mut pages = [ProtectedPage::ABSENT; MAX_PROTECTED];
        for (slot, &gpa) in protected_pages.iter().enumerate() {
            pages[slot] = ProtectedPage {
                gpa,
                entry: (pts as *mut EptEntry<Pt>).wrapping_add(protected[slot]),
                eptp: ept.eptp,
                invept,
            };
        }
        publish(&pages[..protected_pages.len()])?;
        Ok(ept)
    }

    /// The value for the VMCS EPT_POINTER field.
    pub fn eptp(&self) -> Eptp {
        self.eptp
    }

    /// End of the identity map: GPAs `[0, end)` are mapped.
    pub fn end(&self) -> u64 {
        self.end
    }

    /// How many 2 MiB regions are mapped in 4 KiB pages, through a PT each:
    /// those whose pages differ in memory type, and the protected page's.
    pub fn split_regions(&self) -> usize {
        self.split_regions
    }

    /// Pages holding the tables: PML4, PDPT, the PDs and the PTs.
    pub fn table_pages(&self) -> usize {
        self.table_pages
    }

    /// The map as its PD entries hold it: runs of 2 MiB regions mapped the
    /// same way, from GPA 0 to [`end`](Self::end).
    pub fn region_runs(&self) -> impl Iterator<Item = RegionRun> + '_ {
        region_runs(self.pds)
    }
}

/// The page [`Ept::build`] maps read-only, with what making it writable
/// needs: its PT entry, the EPTP, and the INVEPT type to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedPage {
    /// Guest-physical address of the page.
    pub gpa: u64,
    /// Its entry in the PT [`Ept::build`] filled for its region.
    entry: *mut EptEntry<Pt>,
    eptp: Eptp,
    invept: InveptType,
}

impl ProtectedPage {
    /// A placeholder for the unused slots of a fixed-size array, before
    /// [`Ept::build`] fills the ones it uses. Never published.
    const ABSENT: Self = Self {
        gpa: 0,
        entry: core::ptr::null_mut(),
        eptp: Eptp(0),
        invept: InveptType::SingleContext,
    };

    /// Makes the page writable and drops cached translations with INVEPT.
    /// Returns the INVEPT type used, for the report.
    ///
    /// The CPU already drops the translation that caused an EPT violation,
    /// so the retried write would see the new entry even without INVEPT.
    /// INVEPT is still the architectural way to publish an EPT change, and
    /// changes not caused by a violation need it.
    ///
    /// # Safety
    ///
    /// VMX root operation, and [`Ept::build`]'s tables still in place. Called
    /// from the exit handler, while the guest is not running.
    pub unsafe fn grant_write(&self) -> Result<InveptType, VmxFail> {
        // SAFETY: `entry` points into the PT `Ept::build` filled, which is
        // never freed, and the guest is not running to race with the write.
        // The caller guarantees VMX root operation for INVEPT.
        unsafe {
            self.entry
                .write_volatile(self.entry.read_volatile().with_access(EPT_READ | EPT_WRITE));
            invalidate(self.invept, self.eptp)?;
        }
        Ok(self.invept)
    }
}

// What `Ept::build` publishes for the exit handler, which cannot take
// arguments from bring-up: up to [`MAX_PROTECTED`] read-only pages, all with
// the one EPTP and INVEPT type. Written once before VMLAUNCH; read only in
// exit context, on the one CPU that runs the guest. Atomics rather than a
// `static mut` or a lock: this `no_std` build has neither an allocator for
// `Once`-style cells nor a `Mutex`.
static PROTECTED_GPAS: [AtomicU64; MAX_PROTECTED] = [const { AtomicU64::new(0) }; MAX_PROTECTED];
static PROTECTED_ENTRIES: [AtomicPtr<EptEntry<Pt>>; MAX_PROTECTED] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_PROTECTED];
/// How many of the slots above [`publish`] filled. Read after [`INVEPT_TYPE`]
/// (Acquire), so a reader that sees a type sees this and the slots too.
static PROTECTED_COUNT: AtomicUsize = AtomicUsize::new(0);
static PUBLISHED_EPTP: AtomicU64 = AtomicU64::new(0);
/// The [`InveptType`] as its operand value, and the "published" flag: 0
/// until [`publish`] has stored everything else. Written last (Release),
/// read first (Acquire), so a reader that sees a type sees the rest.
static INVEPT_TYPE: AtomicU8 = AtomicU8::new(0);

/// The INVEPT type stored as `value`, or `None` for anything [`publish`]
/// never stores: 0 (nothing published) or an unknown type.
fn decode_invept(value: u8) -> Option<InveptType> {
    match value {
        1 => Some(InveptType::SingleContext),
        2 => Some(InveptType::AllContext),
        _ => None,
    }
}

/// Publishes `pages` for [`protected_page_for`]. Refuses a second
/// publication. `pages` holds at most [`MAX_PROTECTED`] entries, all sharing
/// one EPTP and INVEPT type.
fn publish(pages: &[ProtectedPage]) -> Result<(), EptError> {
    if decode_invept(INVEPT_TYPE.load(Ordering::Acquire)).is_some() {
        return Err(EptError::AlreadyBuilt);
    }
    debug_assert!(pages.len() <= MAX_PROTECTED);
    for (slot, page) in pages.iter().enumerate() {
        PROTECTED_GPAS[slot].store(page.gpa, Ordering::Relaxed);
        PROTECTED_ENTRIES[slot].store(page.entry, Ordering::Relaxed);
    }
    PROTECTED_COUNT.store(pages.len(), Ordering::Relaxed);
    // Every published page shares the one EPTP and INVEPT type; take them
    // from the first (there is always at least the data page).
    if let Some(first) = pages.first() {
        PUBLISHED_EPTP.store(first.eptp.raw(), Ordering::Relaxed);
        INVEPT_TYPE.store(first.invept as u8, Ordering::Release);
    }
    Ok(())
}

/// The published read-only page whose 4 KiB frame holds `gpa`, or `None`
/// when no page was published yet or `gpa` is in none of them. The exit
/// handler calls it with an EPT violation's GUEST_PHYSICAL_ADDRESS to find
/// the page to make writable.
pub fn protected_page_for(gpa: u64) -> Option<ProtectedPage> {
    let invept = decode_invept(INVEPT_TYPE.load(Ordering::Acquire))?;
    let eptp = Eptp(PUBLISHED_EPTP.load(Ordering::Relaxed));
    let count = PROTECTED_COUNT.load(Ordering::Relaxed);
    let frame = gpa & !(PAGE_SIZE as u64 - 1);
    let slot = PROTECTED_GPAS[..count]
        .iter()
        .position(|slot| slot.load(Ordering::Relaxed) == frame)?;
    Some(ProtectedPage {
        gpa: PROTECTED_GPAS[slot].load(Ordering::Relaxed),
        entry: PROTECTED_ENTRIES[slot].load(Ordering::Relaxed),
        eptp,
        invept,
    })
}

/// The 128-bit INVEPT descriptor: the EPTP, then 64 reserved bits that must
/// be 0.
#[repr(C, align(16))]
struct InveptDescriptor {
    eptp: u64,
    reserved: u64,
}

/// Runs INVEPT. Like the other VMX instructions it reports failure through
/// RFLAGS.
///
/// # Safety
///
/// The CPU must be in VMX root operation.
unsafe fn invalidate(kind: InveptType, eptp: Eptp) -> Result<(), VmxFail> {
    let descriptor = InveptDescriptor {
        eptp: eptp.raw(),
        reserved: 0,
    };
    // SAFETY: INVEPT reads only the 16-byte descriptor, which lives on this
    // stack frame; the caller guarantees VMX root operation.
    unsafe {
        vmx_asm!(
            "invept {kind}, [{descriptor}]",
            kind = in(reg) kind as u64,
            descriptor = in(reg) &descriptor
        )
    }
}

#[cfg(test)]
#[path = "../../tests/unit/vmx/ept.rs"]
mod tests;
