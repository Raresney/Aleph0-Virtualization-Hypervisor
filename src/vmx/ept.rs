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
//!   MTRRs' type into it (see `mtrr/`).
//! - IPAT (bit 6): ignore the guest's PAT. Left clear, so the guest's PAT
//!   still combines with the EPT type, as it would with the MTRRs' type
//!   without EPT.
//! - PS (bit 7, in a PDPT or PD entry): this entry maps a 1 GiB or 2 MiB
//!   page directly.
//!
//! Aleph0 builds an identity map (GPA = HPA) of the whole guest-physical
//! address space, as far as MAXPHYADDR and the 4-level walk reach
//! ([`MapLayout`]), so the guest runs as without EPT: each page of RAM with
//! the memory type the MTRRs give it, and everything else (MMIO, reserved
//! memory, holes in the UEFI memory map) UC whatever the MTRRs say
//! ([`EptTypes`]). The GiBs the UEFI memory map reaches are mapped through
//! PDs, in 2 MiB and 4 KiB pages; above them, where there is no RAM, each
//! GiB is one UC 1 GiB page. One 4 KiB page, the guest's data page, is
//! mapped read-only: a guest write to it is the intentional EPT violation,
//! and [`ProtectedPage::grant_write`] makes it writable when that exit
//! arrives.
//!
//! The guest's writes to its MTRRs change the types its memory should have.
//! [`TypeTables::apply`] rewrites the entries whose type changed and runs
//! INVEPT. A 2 MiB region whose pages come to differ in type needs a PT,
//! and the exit handler cannot allocate one, so [`Ept::build`] sets some
//! aside ([`spare_pts`]). The longer walkthrough is in `docs/EPT.md` and
//! `docs/MTRR.md`.

use core::fmt;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicU64, Ordering};

use uefi::boot;
use uefi::mem::memory_map::MemoryMap;

use super::instruction::{VmxFail, vmx_asm};
use super::msr::ControlCapability;
use super::mtrr::{MemoryType, MtrrCapabilities, Mtrrs};
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
/// What a PD entry maps: a 2 MiB page, or a PT of 512 4 KiB pages.
pub const SIZE_2M: u64 = 1 << 21;
/// What a PDPT entry maps: a PD of 512 2 MiB regions, or a 1 GiB page.
pub const SIZE_1G: u64 = 1 << 30;
/// What one PDPT maps: 512 entries of 1 GiB.
pub const PDPT_SPAN: u64 = ENTRIES as u64 * SIZE_1G;
/// Address bits a 4-level EPT walk translates: 9 per level and 12 of page
/// offset. A GPA needs no more, whatever MAXPHYADDR says.
const WALK_ADDRESS_BITS: u8 = 48;
/// End of the 32-bit address space, below which the Local APIC, the IOAPIC
/// and 32-bit PCI BARs live. Without 1 GiB pages the map reaches at least
/// this far ([`MapLayout::new`]).
const LOW_DEVICE_END: u64 = 4 * SIZE_1G;

// IA32_VMX_EPT_VPID_CAP bits this module needs.
/// Bit 6: 4-level EPT page walks.
const CAP_WALK_LENGTH_4: u64 = 1 << 6;
/// Bit 14: the EPT tables themselves may be write-back.
const CAP_WRITE_BACK: u64 = 1 << 14;
/// Bit 16: PD entries may map 2 MiB pages.
const CAP_2M_PAGES: u64 = 1 << 16;
/// Bit 17: PDPT entries may map 1 GiB pages.
const CAP_1G_PAGES: u64 = 1 << 17;
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
    /// The memory map reaches `end`, past `limit`, the end of the
    /// guest-physical address space ([`address_space_end`]).
    RangeTooLarge { end: u64, limit: u64 },
    /// The page to protect lies outside the identity map.
    ProtectedPageOutsideMap,
    /// UEFI could not provide the table pages.
    AllocationFailed,
    /// An EPT was already built and its protected page published; the exit
    /// handler knows one protected page only.
    AlreadyBuilt,
}

/// What the CPU allows in an EPT entry beyond what every EPT allows: what
/// the map may use ([`MapLayout`]), and what the CPU refuses in an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryRules {
    /// MAXPHYADDR: an entry's address bits from here up to 51 are reserved.
    pub physical_address_bits: u8,
    /// Whether a PDPT entry may map a 1 GiB page (IA32_VMX_EPT_VPID_CAP
    /// bit 17).
    pub huge_pages: bool,
}

/// What this CPU's EPT offers Aleph0: see [`check_support`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EptSupport {
    /// The INVEPT type to use: single-context when available.
    pub invept: InveptType,
    pub rules: EntryRules,
}

/// Checks that this CPU supports the EPT Aleph0 builds, picks the INVEPT
/// type (single-context when available, otherwise all-context), and reads
/// what else its entries may use.
///
/// `secondary` is IA32_VMX_PROCBASED_CTLS2 and `ept_vpid_cap`
/// IA32_VMX_EPT_VPID_CAP, both 0 when the CPU lacks them;
/// `physical_address_bits` is MAXPHYADDR (`cpuid::physical_address_bits`).
pub fn check_support(
    secondary: ControlCapability,
    ept_vpid_cap: u64,
    physical_address_bits: u8,
) -> Result<EptSupport, EptError> {
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
    let invept = if ept_vpid_cap & CAP_INVEPT_SINGLE_CONTEXT != 0 {
        InveptType::SingleContext
    } else if ept_vpid_cap & CAP_INVEPT_ALL_CONTEXT != 0 {
        InveptType::AllContext
    } else {
        return Err(EptError::InveptUnsupported);
    };
    Ok(EptSupport {
        invept,
        rules: EntryRules {
            physical_address_bits,
            huge_pages: ept_vpid_cap & CAP_1G_PAGES != 0,
        },
    })
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
/// | [`Pml4`] | [`table`](Self::table) |
/// | [`Pdpt`] | [`table`](Self::table), [`huge_page`](Self::huge_page) |
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

/// The bits of an RWX entry mapping the page at `address` itself, of
/// `memory_type`: a 1 GiB page in a PDPT entry, a 2 MiB one in a PD entry.
fn page_entry_bits(address: u64, memory_type: MemoryType) -> u64 {
    (address & ADDRESS_MASK) | EPT_RWX | (memory_type.raw() << MEMORY_TYPE_SHIFT) | LARGE_PAGE
}

/// The memory type a leaf entry `raw` holds in bits 5:3, or `None` for a
/// reserved value (2, 3 or 7).
fn leaf_memory_type(raw: u64) -> Option<MemoryType> {
    MemoryType::from_raw(((raw >> MEMORY_TYPE_SHIFT) & MEMORY_TYPE_BITS) as u8)
}

impl EptEntry<Pdpt> {
    /// An entry mapping the 1 GiB page at `address`: RWX, of `memory_type`.
    /// Only on a CPU with 1 GiB EPT pages ([`EntryRules::huge_pages`]).
    pub fn huge_page(address: u64, memory_type: MemoryType) -> Self {
        Self::from_raw(page_entry_bits(address, memory_type))
    }

    /// How the entry maps its GiB as one 1 GiB page, read back from its
    /// bits: [`RegionMapping::HugePage`], or [`RegionMapping::Invalid`] for
    /// anything else. An entry pointing to a PD is `Invalid` here too: the
    /// report reads that GiB's PD entries instead ([`TypeTables::region_runs`]).
    pub fn mapping(self) -> RegionMapping {
        if self.raw & EPT_RWX == 0 || self.raw & LARGE_PAGE == 0 {
            return RegionMapping::Invalid;
        }
        leaf_memory_type(self.raw).map_or(RegionMapping::Invalid, RegionMapping::HugePage)
    }
}

impl EptEntry<Pd> {
    /// An entry mapping the 2 MiB page at `address`: RWX, of `memory_type`.
    pub fn large_page(address: u64, memory_type: MemoryType) -> Self {
        Self::from_raw(page_entry_bits(address, memory_type))
    }

    /// How the entry maps its 2 MiB region, read back from its bits.
    pub fn mapping(self) -> RegionMapping {
        if self.raw & EPT_RWX == 0 {
            return RegionMapping::Invalid;
        }
        if self.raw & LARGE_PAGE == 0 {
            return RegionMapping::Pt;
        }
        leaf_memory_type(self.raw).map_or(RegionMapping::Invalid, RegionMapping::LargePage)
    }
}

/// How a PD entry maps its 2 MiB region, or a PDPT entry its GiB: see the
/// two `mapping` methods of [`EptEntry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionMapping {
    /// One 2 MiB page of this memory type: a PD entry.
    LargePage(MemoryType),
    /// One 1 GiB page of this memory type: a PDPT entry.
    HugePage(MemoryType),
    /// A PT of 4 KiB pages, each with its own type and access: a PD entry.
    Pt,
    /// Neither: not present, a page whose type bits hold a reserved value,
    /// or, read as a 1 GiB page, a PDPT entry pointing to a PD. `Ept::build`
    /// makes no such entry where it is read this way.
    Invalid,
}

impl fmt::Display for RegionMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LargePage(memory_type) => write!(f, "2 MiB pages, {}", memory_type.name()),
            Self::HugePage(memory_type) => write!(f, "1 GiB pages, {}", memory_type.name()),
            Self::Pt => f.write_str("4 KiB pages (a PT each)"),
            Self::Invalid => f.write_str("invalid (not present or reserved type)"),
        }
    }
}

/// Consecutive parts of the map mapped the same way: see
/// [`TypeTables::region_runs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionRun {
    pub start: u64,
    pub end: u64,
    pub mapping: RegionMapping,
}

/// The `mappings` of consecutive blocks of `size` bytes, from block number
/// `first`, with neighbours mapped alike merged into one run.
fn runs(mappings: impl Iterator<Item = RegionMapping>, first: usize, size: u64) -> impl Iterator<Item = RegionRun> {
    let mut blocks = mappings
        .enumerate()
        .map(move |(i, mapping)| (first + i, mapping))
        .peekable();
    core::iter::from_fn(move || {
        let (first, mapping) = blocks.next()?;
        let mut last = first;
        while let Some((next, _)) = blocks.next_if(|&(_, next_mapping)| next_mapping == mapping) {
            last = next;
        }
        Some(RegionRun {
            start: first as u64 * size,
            end: (last as u64 + 1) * size,
            mapping,
        })
    })
}

/// The regions `pds` map, as [`runs`]. `pds` are back to back, as
/// [`fill_identity_map`] fills them, from the one of region number `first`
/// (GPA `first` * 2 MiB).
fn region_runs(pds: &[EptEntry<Pd>], first: usize) -> impl Iterator<Item = RegionRun> + '_ {
    runs(pds.iter().map(|entry| entry.mapping()), first, SIZE_2M)
}

/// The GiBs `pdpts` map as 1 GiB pages, as [`runs`], from the entry of GiB
/// number `first`.
fn gib_runs(pdpts: &[EptEntry<Pdpt>], first: usize) -> impl Iterator<Item = RegionRun> + '_ {
    runs(pdpts.iter().map(|entry| entry.mapping()), first, SIZE_1G)
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

    /// The same entry with its memory type replaced by `memory_type`; its
    /// address and access stay.
    pub fn with_memory_type(self, memory_type: MemoryType) -> Self {
        let type_bits = MEMORY_TYPE_BITS << MEMORY_TYPE_SHIFT;
        Self::from_raw((self.raw & !type_bits) | (memory_type.raw() << MEMORY_TYPE_SHIFT))
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

/// End of memory-map regions `(start, pages)`: the highest address any
/// region reaches, rounded up to 1 GiB, so every PD of [`MapLayout`] is
/// full. Every region counts, whatever its type, so memory-mapped I/O the
/// firmware reports is in it too, UC ([`EptTypes`]).
///
/// A region reaching past the top of the 64-bit address space gives
/// `u64::MAX`, past any address space, which [`MapLayout::new`] refuses.
pub fn memory_map_end(regions: impl Iterator<Item = (u64, u64)>) -> Result<u64, EptError> {
    let highest = regions
        .map(|(start, pages)| start.saturating_add(pages.saturating_mul(PAGE_SIZE as u64)))
        .max()
        .filter(|&end| end > 0)
        .ok_or(EptError::EmptyMemoryMap)?;
    Ok(highest.checked_next_multiple_of(SIZE_1G).unwrap_or(u64::MAX))
}

/// End of the guest-physical address space EPT maps, for a CPU whose
/// physical addresses have `physical_address_bits` bits (MAXPHYADDR): every
/// address the guest can reach, as far as a 4-level walk translates.
pub fn address_space_end(physical_address_bits: u8) -> u64 {
    1 << physical_address_bits.min(WALK_ADDRESS_BITS)
}

/// How [`Ept::build`] lays out the identity map, GiB by GiB, from GPA 0:
///
/// ```text
/// 0 ── PDs (2 MiB and 4 KiB pages) ── pd_end ── 1 GiB pages, UC ── end
///      the GiBs the UEFI memory map        no RAM above the memory map
///      reaches: RAM, retyped when the
///      guest writes its MTRRs
/// ```
///
/// Every GiB the memory map reaches keeps a PD, even one of a single type,
/// so the guest's MTRR writes can retype its RAM 2 MiB or 4 KiB at a time
/// ([`retype`]) without splitting a 1 GiB page. Above the memory map there
/// is no RAM, so whatever the MTRRs say a GiB there is UC ([`EptTypes`]),
/// and never retyped: one 1 GiB page each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapLayout {
    /// GiBs `[0, pd_gibs)` are mapped through one PD each.
    pd_gibs: usize,
    /// GiBs `[pd_gibs, gibs)` are 1 GiB pages; the map ends at GiB `gibs`.
    gibs: usize,
}

impl MapLayout {
    /// The layout for a memory map ending at `memory_map_end`
    /// ([`memory_map_end`]) on a CPU with `rules`: up to the end of the
    /// address space ([`address_space_end`]). Without 1 GiB pages, a PD per
    /// GiB of a 46-bit address space would take 256 MiB of tables, so the
    /// PDs then stop at `max(memory_map_end, 4 GiB)`: the 32-bit device
    /// window, with the Local APIC and the IOAPIC, is mapped, and an access
    /// above it is an EPT violation.
    pub fn new(memory_map_end: u64, rules: EntryRules) -> Result<Self, EptError> {
        let limit = address_space_end(rules.physical_address_bits);
        if memory_map_end > limit {
            return Err(EptError::RangeTooLarge {
                end: memory_map_end,
                limit,
            });
        }
        let gibs_to = |end: u64| (end / SIZE_1G) as usize;
        Ok(if rules.huge_pages {
            Self {
                pd_gibs: gibs_to(memory_map_end),
                gibs: gibs_to(limit),
            }
        } else {
            let pd_gibs = gibs_to(memory_map_end.max(LOW_DEVICE_END).min(limit));
            Self { pd_gibs, gibs: pd_gibs }
        })
    }

    /// End of the map: GPAs `[0, end)` are mapped.
    pub fn end(self) -> u64 {
        self.gibs as u64 * SIZE_1G
    }

    /// End of the part mapped through PDs.
    pub fn pd_end(self) -> u64 {
        self.pd_gibs as u64 * SIZE_1G
    }

    /// How many GiBs are mapped through a PD each.
    pub fn pd_gibs(self) -> usize {
        self.pd_gibs
    }

    /// How many GiBs are 1 GiB pages.
    pub fn huge_gibs(self) -> usize {
        self.gibs - self.pd_gibs
    }

    /// How many PDPTs the map takes: one per 512 GiB, each in a PML4 entry.
    pub fn pdpts(self) -> usize {
        self.gibs.div_ceil(ENTRIES)
    }
}

/// Whether memory of UEFI type `memory_type` is RAM: memory the firmware or
/// an OS uses as memory, which EPT gives the type the MTRRs give it. Any
/// other type (memory-mapped I/O, reserved or unusable memory, a type this
/// list does not know) may hold a device's registers, and EPT maps it UC
/// ([`EptTypes`]).
pub fn is_ram(memory_type: boot::MemoryType) -> bool {
    use boot::MemoryType as Type;
    [
        Type::LOADER_CODE,
        Type::LOADER_DATA,
        Type::BOOT_SERVICES_CODE,
        Type::BOOT_SERVICES_DATA,
        Type::RUNTIME_SERVICES_CODE,
        Type::RUNTIME_SERVICES_DATA,
        Type::CONVENTIONAL,
        Type::ACPI_RECLAIM,
        Type::ACPI_NON_VOLATILE,
        Type::PERSISTENT_MEMORY,
    ]
    .contains(&memory_type)
}

/// The RAM of the UEFI memory map ([`is_ram`]): `[start, end)` ranges in
/// address order, apart from each other, so that memory RAM covers without
/// a gap lies in one range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamMap<'a> {
    ranges: &'a [(u64, u64)],
}

/// How much of a block of memory is RAM: see [`RamMap::coverage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RamCoverage {
    All,
    Part,
    None,
}

impl<'a> RamMap<'a> {
    /// The RAM of the memory-map regions `(start, pages, type)`, gathered in
    /// `ranges`, which has room for one range per region: sorted, and with
    /// ranges that overlap or touch merged into one.
    fn collect(regions: impl Iterator<Item = (u64, u64, boot::MemoryType)>, ranges: &'a mut [(u64, u64)]) -> Self {
        let mut count = 0;
        for (start, pages, _) in regions.filter(|&(_, pages, memory_type)| pages > 0 && is_ram(memory_type)) {
            let Some(slot) = ranges.get_mut(count) else {
                break;
            };
            *slot = (start, start.saturating_add(pages.saturating_mul(PAGE_SIZE as u64)));
            count += 1;
        }
        let ranges = &mut ranges[..count];
        ranges.sort_unstable_by_key(|&(start, _)| start);
        // Merged in place: range `i` goes on the last merged one if it
        // overlaps or touches it, else after it. `merged` <= `i` throughout.
        let mut merged = 0;
        for i in 0..ranges.len() {
            let (start, end) = ranges[i];
            if merged > 0 && start <= ranges[merged - 1].1 {
                ranges[merged - 1].1 = ranges[merged - 1].1.max(end);
            } else {
                ranges[merged] = (start, end);
                merged += 1;
            }
        }
        let ranges: &'a [(u64, u64)] = ranges;
        Self {
            ranges: &ranges[..merged],
        }
    }

    /// The ranges, in address order.
    pub fn ranges(&self) -> &'a [(u64, u64)] {
        self.ranges
    }

    /// Whether `address` is RAM.
    fn contains(&self, address: u64) -> bool {
        // The first range ending past `address` is the only one that can
        // hold it.
        let i = self.ranges.partition_point(|&(_, end)| end <= address);
        self.ranges.get(i).is_some_and(|&(start, _)| start <= address)
    }

    /// How much of the `size` bytes at `base` is RAM.
    fn coverage(&self, base: u64, size: u64) -> RamCoverage {
        let end = base + size;
        // The first range ending past `base`: all of the block lies in it,
        // or some of it, or none of the block is RAM, since every later
        // range starts later still.
        let i = self.ranges.partition_point(|&(_, range_end)| range_end <= base);
        match self.ranges.get(i) {
            Some(&(start, range_end)) if start <= base && end <= range_end => RamCoverage::All,
            Some(&(start, _)) if start < end => RamCoverage::Part,
            _ => RamCoverage::None,
        }
    }
}

/// The memory type EPT gives each guest page: the one the MTRRs give it
/// when it is RAM, UC when it is not.
///
/// Without EPT the MTRRs alone type every access, and firmware programs
/// them so that device memory is UC. EPT replaces them for guest accesses,
/// and they are now the guest's, which can make any range WB. Some VMMs
/// also leave device memory to their own EPT: Hyper-V's MTRRs make all of
/// the first 4 GiB WB, the device window below 4 GiB included (`docs/MTRR.md`
/// section 6). WB on a device's registers lets the CPU read them
/// speculatively and keep them in its caches, which the device does not
/// expect, and can end in a machine check, for the whole machine. So
/// whatever the MTRRs say, what the UEFI memory map does not call RAM is
/// UC. The guest's PAT can still make it WC, for a framebuffer: UC from
/// EPT with WC from the PAT gives WC (Intel SDM Vol. 3A, "Selecting Memory
/// Types for Pentium III and More Recent Processor Families"). KVM does the
/// same (`vmx_get_mt_mask` gives MMIO UC).
#[derive(Debug, Clone, Copy)]
pub struct EptTypes<'a> {
    pub mtrrs: &'a Mtrrs,
    pub ram: RamMap<'a>,
}

impl EptTypes<'_> {
    /// The EPT memory type of the 4 KiB page at `address`.
    fn page_type(&self, address: u64) -> MemoryType {
        if self.ram.contains(address) {
            self.mtrrs.memory_type(address)
        } else {
            MemoryType::Uncacheable
        }
    }

    /// The EPT memory type of the 2 MiB region at `region` when one 2 MiB
    /// page can carry it, or `None` when it needs a PT: its pages differ in
    /// type, or only some of them are RAM.
    ///
    /// A region only partly RAM always gets a PT, whatever the types now.
    /// The guest's MTRRs can make its RAM WB at any time while the rest
    /// stays UC, and that PT must not have to come from the spare ones
    /// ([`spare_pts`]), which only cover what MTRR writes can split.
    fn region_type(&self, region: u64) -> Option<MemoryType> {
        match self.ram.coverage(region, SIZE_2M) {
            RamCoverage::All => self.mtrrs.block_type(region, SIZE_2M),
            RamCoverage::Part => None,
            RamCoverage::None => Some(MemoryType::Uncacheable),
        }
    }
}

/// The tables of an identity map, as slices, with the physical address each
/// one has. Under UEFI's identity mapping a table's physical address is its
/// virtual one; on the host tests these are made-up numbers.
struct Tables<'a> {
    pml4: &'a mut [EptEntry<Pml4>],
    /// One PDPT per 512 GiB of the map, back to back, so entry `g` maps
    /// GiB `g`.
    pdpts: &'a mut [EptEntry<Pdpt>],
    /// One PD per GiB mapped through a PD ([`MapLayout`]), back to back.
    pds: &'a mut [EptEntry<Pd>],
    /// One PT per split region ([`split_regions`]), back to back.
    pts: &'a mut [EptEntry<Pt>],
    pdpts_address: u64,
    pds_address: u64,
    pts_address: u64,
}

/// The memory type of the 2 MiB region at `region` when one 2 MiB page can
/// map it, or `None` when it needs a PT of 4 KiB pages: its pages differ in
/// memory type, only some of them are RAM, or it holds `protected_page`. An
/// EPT entry has one memory type, so a 2 MiB page over pages of mixed types
/// would give some of them the wrong one.
fn large_page_type(types: &EptTypes<'_>, region: u64, protected_page: u64) -> Option<MemoryType> {
    if region == region_of(protected_page) {
        return None;
    }
    types.region_type(region)
}

/// The start of the 2 MiB region holding `address`.
fn region_of(address: u64) -> u64 {
    address & !(SIZE_2M - 1)
}

/// How many PTs [`Ept::build`] sets aside, beyond those the map needs, for
/// the 2 MiB regions the guest's MTRR writes split later: one per variable
/// range, and one for the first 2 MiB, which the fixed ranges can split.
///
/// With contiguous masks, as the SDM describes them, that is always enough.
/// A variable range of 2 MiB or more is aligned to its size, so it covers
/// whole regions. A smaller one lies inside one region. So at most one
/// region per variable range, plus the first, has pages of different
/// types, and a region that is one type again gives its PT back. Only a
/// non-contiguous mask, one that tests an address bit below 21 and leaves a
/// higher one free, can split more: [`retype`] then maps the regions left
/// without a PT UC.
pub fn spare_pts(mtrr: MtrrCapabilities) -> usize {
    mtrr.variable_count() + usize::from(mtrr.fixed())
}

/// How many 2 MiB regions of the first `pd_gibs` GiB need a PT
/// ([`large_page_type`] is `None`): how many PTs [`fill_identity_map`]
/// takes. At least 1, for the region holding `protected_page`.
fn split_regions(types: &EptTypes<'_>, pd_gibs: usize, protected_page: u64) -> usize {
    (0..pd_gibs * ENTRIES)
        .filter(|&i| large_page_type(types, i as u64 * SIZE_2M, protected_page).is_none())
        .count()
}

/// Fills `tables` with an identity map laid out as `layout` says, each page
/// with the memory type `types` gives it, and RWX except `protected_page`,
/// which is read-only. In the GiBs with a PD, a 2 MiB region is one 2 MiB
/// page when it can be ([`large_page_type`]); otherwise it takes the next
/// PT in `tables.pts` and is mapped in 4 KiB pages. Returns the index of
/// `protected_page`'s entry in `tables.pts`.
///
/// `pdpts` holds [`MapLayout::pdpts`] tables, `pds` [`MapLayout::pd_gibs`]
/// and `pts` [`split_regions`], and `protected_page` is 4 KiB-aligned and
/// in a GiB with a PD; [`Ept::build`] checks all four.
fn fill_identity_map(tables: Tables<'_>, layout: MapLayout, types: &EptTypes<'_>, protected_page: u64) -> usize {
    debug_assert!(tables.pdpts.len() == layout.pdpts() * ENTRIES);
    debug_assert!(tables.pds.len() == layout.pd_gibs * ENTRIES);
    // The PDPTs are back to back, one per PML4 entry, so PDPT entry number
    // `gib` across all of them maps GiB `gib`; likewise for the PDs and
    // their 2 MiB regions.
    for (number, entry) in tables.pml4.iter_mut().take(layout.pdpts()).enumerate() {
        *entry = EptEntry::table(tables.pdpts_address + (number * PAGE_SIZE) as u64);
    }
    for (gib, entry) in tables.pdpts.iter_mut().take(layout.gibs).enumerate() {
        let base = gib as u64 * SIZE_1G;
        *entry = if gib < layout.pd_gibs {
            EptEntry::table(tables.pds_address + (gib * PAGE_SIZE) as u64)
        } else {
            // Above the memory map, so no RAM: UC whatever the MTRRs say.
            debug_assert!(types.ram.coverage(base, SIZE_1G) == RamCoverage::None);
            EptEntry::huge_page(base, MemoryType::Uncacheable)
        };
    }

    let (pts, rest) = tables.pts.as_chunks_mut::<ENTRIES>();
    debug_assert!(rest.is_empty(), "the PTs are whole tables");
    let mut pts = pts.iter_mut().enumerate();
    let mut protected = None;
    for (i, entry) in tables.pds.iter_mut().enumerate() {
        let region = i as u64 * SIZE_2M;
        if let Some(memory_type) = large_page_type(types, region, protected_page) {
            *entry = EptEntry::large_page(region, memory_type);
            continue;
        }
        let (number, pt) = pts.next().expect("split_regions counted a PT for this region");
        *entry = EptEntry::table(tables.pts_address + (number * PAGE_SIZE) as u64);
        fill_pt(pt, region, types);
        if region == region_of(protected_page) {
            let index = Pt::index(protected_page);
            pt[index] = pt[index].with_access(EPT_READ);
            protected = Some(number * ENTRIES + index);
        }
    }
    debug_assert!(pts.next().is_none(), "every PT is used");
    protected.expect("the protected page is inside the map")
}

/// Fills `pt` with the 512 pages of the 2 MiB region at `region`: RWX,
/// each of the memory type `types` gives it.
fn fill_pt(pt: &mut [EptEntry<Pt>; ENTRIES], region: u64, types: &EptTypes<'_>) {
    for (j, page) in pt.iter_mut().enumerate() {
        let address = region + (j * PAGE_SIZE) as u64;
        *page = EptEntry::page(address, EPT_RWX, types.page_type(address));
    }
}

/// One EPT identity map. Its table pages are never freed: the CPU walks them
/// on every guest access for as long as the VMCS points at them.
pub struct Ept {
    eptp: Eptp,
    layout: MapLayout,
    memory_map_end: u64,
    split_regions: usize,
    spare_pts: usize,
    table_pages: usize,
}

impl Ept {
    /// Builds the identity map from the UEFI memory map, laid out for the
    /// CPU's `support` ([`MapLayout`]), with the memory types of `mtrrs` for
    /// its RAM and UC for everything else ([`EptTypes`]), `protected_page`
    /// read-only, and `spare_pts` more PTs set aside ([`spare_pts`]).
    /// Publishes the [`ProtectedPage`] the exit handler needs later, and
    /// returns, with the map, the [`TypeTables`] it needs to change memory
    /// types. Refuses a second build with [`EptError::AlreadyBuilt`]: the
    /// handler knows one map only.
    ///
    /// # Safety
    ///
    /// Boot services must still be active, and physical memory must be
    /// identity-mapped (as UEFI does), since the tables are filled through
    /// their physical addresses.
    pub unsafe fn build(
        protected_page: u64,
        support: EptSupport,
        mtrrs: &Mtrrs,
        spare_pts: usize,
    ) -> Result<(Self, TypeTables), EptError> {
        let map = boot::memory_map(boot::MemoryType::LOADER_DATA).map_err(|_| EptError::MemoryMapUnavailable)?;
        let memory_map_end = memory_map_end(map.entries().map(|region| (region.phys_start, region.page_count)))?;
        let layout = MapLayout::new(memory_map_end, support.rules)?;
        if protected_page >= layout.pd_end() || !protected_page.is_multiple_of(PAGE_SIZE as u64) {
            return Err(EptError::ProtectedPageOutsideMap);
        }

        // The RAM, kept with the tables: `retype` needs it in exit context,
        // which cannot ask UEFI. One range per memory-map region at most.
        let regions = map.entries().count();
        let ram_pages = (regions * size_of::<(u64, u64)>()).div_ceil(PAGE_SIZE);
        let ram_ranges = allocate_zeroed_pages(ram_pages, EptError::AllocationFailed)?.as_ptr() as *mut (u64, u64);
        // SAFETY: a zeroed, page-aligned allocation of at least `regions`
        // ranges, which nothing else refers to; never freed.
        let ram_ranges = unsafe { core::slice::from_raw_parts_mut(ram_ranges, regions) };
        let ram = RamMap::collect(
            map.entries()
                .map(|region| (region.phys_start, region.page_count, region.ty)),
            ram_ranges,
        );
        let types = EptTypes { mtrrs, ram };

        let split_regions = split_regions(&types, layout.pd_gibs, protected_page);
        let pt_count = split_regions + spare_pts;
        let pml4 = allocate_zeroed_pages(1, EptError::AllocationFailed)?.as_ptr() as u64;
        let pdpts = allocate_zeroed_pages(layout.pdpts(), EptError::AllocationFailed)?.as_ptr() as u64;
        let pds = allocate_zeroed_pages(layout.pd_gibs, EptError::AllocationFailed)?.as_ptr() as u64;
        let pts = allocate_zeroed_pages(pt_count, EptError::AllocationFailed)?.as_ptr() as u64;
        let free_pages = (pt_count * size_of::<u32>()).div_ceil(PAGE_SIZE);
        let free = allocate_zeroed_pages(free_pages, EptError::AllocationFailed)?.as_ptr() as *mut u32;

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
        // SAFETY: each allocation above is page-aligned, zeroed and at least
        // as long as its slice, and nothing else refers to it yet. The PTs
        // past the first `split_regions` are the spare ones, which the map
        // does not use yet.
        let tables = unsafe {
            Tables {
                pml4: table(pml4, 1),
                pdpts: table(pdpts, layout.pdpts()),
                pds: table(pds, layout.pd_gibs),
                pts: table(pts, split_regions),
                pdpts_address: pdpts,
                pds_address: pds,
                pts_address: pts,
            }
        };
        let protected = fill_identity_map(tables, layout, &types, protected_page);
        // SAFETY: `free` is a zeroed allocation of at least `pt_count` u32s,
        // which nothing else refers to yet.
        let free_len = fill_free_stack(
            unsafe { core::slice::from_raw_parts_mut(free, pt_count) },
            split_regions,
        );

        let ept = Self {
            eptp: Eptp::new(pml4),
            layout,
            memory_map_end,
            split_regions,
            spare_pts,
            table_pages: 1 + layout.pdpts() + layout.pd_gibs + pt_count,
        };
        let tables = TypeTables {
            pdpts: pdpts as *mut EptEntry<Pdpt>,
            layout,
            pds: pds as *mut EptEntry<Pd>,
            regions: layout.pd_gibs * ENTRIES,
            pts: pts as *mut EptEntry<Pt>,
            pt_count,
            pts_address: pts,
            free,
            free_len,
            protected_region: (protected_page / SIZE_2M) as usize,
            ram: ram.ranges().as_ptr(),
            ram_len: ram.ranges().len(),
            eptp: ept.eptp,
            invept: support.invept,
        };
        publish(ProtectedPage {
            gpa: protected_page,
            entry: (pts as *mut EptEntry<Pt>).wrapping_add(protected),
            eptp: ept.eptp,
            invept: support.invept,
        })?;
        Ok((ept, tables))
    }

    /// The value for the VMCS EPT_POINTER field.
    pub fn eptp(&self) -> Eptp {
        self.eptp
    }

    /// How the map is laid out: where it ends, and which GiBs have a PD.
    pub fn layout(&self) -> MapLayout {
        self.layout
    }

    /// End of the identity map: GPAs `[0, end)` are mapped.
    pub fn end(&self) -> u64 {
        self.layout.end()
    }

    /// End of the UEFI memory map, rounded up to 1 GiB ([`memory_map_end`]):
    /// every page of RAM lies below it, and all the memory Aleph0 itself
    /// uses, the EPT tables included.
    pub fn memory_map_end(&self) -> u64 {
        self.memory_map_end
    }

    /// How many 2 MiB regions are mapped in 4 KiB pages, through a PT each:
    /// those whose pages differ in memory type or are only partly RAM, and
    /// the protected page's.
    pub fn split_regions(&self) -> usize {
        self.split_regions
    }

    /// How many more PTs are set aside for regions the guest's MTRR writes
    /// split ([`spare_pts`]).
    pub fn spare_pts(&self) -> usize {
        self.spare_pts
    }

    /// Pages holding the tables: the PML4, the PDPTs, the PDs and the PTs,
    /// spare ones included.
    pub fn table_pages(&self) -> usize {
        self.table_pages
    }
}

/// The tables [`Ept::build`] filled, as the exit handler needs them once
/// the guest runs: to change memory types (the PDs and PTs, the spare PTs
/// it set aside ([`spare_pts`]), and how to run INVEPT), and to read the
/// map back. Made once, by `build`; the exit handler keeps it
/// (`vmexit::guest_mtrrs`), and applies the guest's MTRRs with it.
pub struct TypeTables {
    /// The PDPTs, back to back: entry g maps GiB g, `layout.gibs` of them.
    pdpts: *mut EptEntry<Pdpt>,
    layout: MapLayout,
    /// The PDs, back to back: entry i maps the 2 MiB region at i * 2 MiB.
    pds: *mut EptEntry<Pd>,
    regions: usize,
    /// Every PT, in use or spare, back to back; `pts_address` is the
    /// physical address of the first.
    pts: *mut EptEntry<Pt>,
    pt_count: usize,
    pts_address: u64,
    /// The free PTs' indices, a stack: its first `free_len` entries. It has
    /// room for all `pt_count`, so a PT given back always fits.
    free: *mut u32,
    free_len: usize,
    /// The region holding the protected page, which keeps its PT.
    protected_region: usize,
    /// The ranges of the [`RamMap`] `build` gathered: `ram_len` of them.
    ram: *const (u64, u64),
    ram_len: usize,
    eptp: Eptp,
    invept: InveptType,
}

impl TypeTables {
    /// The RAM of the UEFI memory map, which takes the MTRRs' memory types;
    /// everything else is UC ([`EptTypes`]).
    pub fn ram(&self) -> RamMap<'_> {
        // SAFETY: the ranges `build` gathered, `ram_len` of them, in an
        // allocation never freed and never written after `build`.
        let ranges = unsafe { core::slice::from_raw_parts(self.ram, self.ram_len) };
        RamMap { ranges }
    }

    /// Gives every page the memory type `mtrrs` gives it, or UC if it is not
    /// RAM ([`retype`], [`EptTypes`]), and runs INVEPT if an entry changed,
    /// so the CPU drops translations that still carry the old types. Returns
    /// what changed.
    ///
    /// # Safety
    ///
    /// VMX root operation, with [`Ept::build`]'s tables still in place and
    /// the guest not running: exit context.
    pub unsafe fn apply(&mut self, mtrrs: &Mtrrs) -> Result<Retyped, VmxFail> {
        // SAFETY: the PDs, PTs, free stack and RAM ranges `build`
        // allocated, as long as these slices and never freed. Nothing else
        // refers to them while `retype` runs: the guest is not running, and
        // `ProtectedPage` and `region_runs` are not in use during the exit
        // handler's call. The RAM ranges are only read.
        let retyped = unsafe {
            let ram = RamMap {
                ranges: core::slice::from_raw_parts(self.ram, self.ram_len),
            };
            let mut tables = Retype {
                pds: core::slice::from_raw_parts_mut(self.pds, self.regions),
                pts: core::slice::from_raw_parts_mut(self.pts.cast::<[EptEntry<Pt>; ENTRIES]>(), self.pt_count),
                pts_address: self.pts_address,
                free: FreePts {
                    stack: core::slice::from_raw_parts_mut(self.free, self.pt_count),
                    len: &mut self.free_len,
                },
                protected_region: self.protected_region,
            };
            retype(&mut tables, &EptTypes { mtrrs, ram })
        };
        if retyped.changed() {
            // SAFETY: the caller guarantees VMX root operation.
            unsafe { invalidate(self.invept, self.eptp) }?;
        }
        Ok(retyped)
    }

    /// The INVEPT type [`apply`](Self::apply) uses.
    pub fn invept(&self) -> InveptType {
        self.invept
    }

    /// How many PTs are free, set aside or given back.
    pub fn free_pts(&self) -> usize {
        self.free_len
    }

    /// The map from `start` to `end` as its entries hold it, read back from
    /// the entries the CPU walks: runs of 2 MiB regions mapped the same way
    /// by the PDs, then runs of 1 GiB pages above them ([`MapLayout`]). The
    /// whole map from 0 to [`Ept::end`] at bring-up, the regions an MTRR
    /// write changed in the exit handler's report.
    pub fn region_runs(&self, start: u64, end: u64) -> impl Iterator<Item = RegionRun> + '_ {
        let first = ((start / SIZE_2M) as usize).min(self.regions);
        let last = (end.div_ceil(SIZE_2M) as usize).clamp(first, self.regions);
        let first_gib = ((start / SIZE_1G) as usize).clamp(self.layout.pd_gibs, self.layout.gibs);
        let last_gib = (end.div_ceil(SIZE_1G) as usize).clamp(first_gib, self.layout.gibs);
        // SAFETY: the PDs and PDPTs `build` filled, `regions` and
        // `layout.gibs` entries, never freed. Only `apply` writes them (the
        // PDs), through `&mut self`, so never while this iterator borrows
        // `self`.
        let (pds, pdpts) = unsafe {
            (
                core::slice::from_raw_parts(self.pds, self.regions),
                core::slice::from_raw_parts(self.pdpts, self.layout.gibs),
            )
        };
        region_runs(&pds[first..last], first).chain(gib_runs(&pdpts[first_gib..last_gib], first_gib))
    }
}

/// Puts the PTs from `first_spare` to the end of `stack`'s length on the
/// free stack `stack`, so the first one comes off first, and returns how
/// many there are.
fn fill_free_stack(stack: &mut [u32], first_spare: usize) -> usize {
    let spare = first_spare..stack.len();
    let count = spare.len();
    for (slot, index) in stack.iter_mut().zip(spare.rev()) {
        *slot = index as u32;
    }
    count
}

/// The parts of an identity map [`retype`] changes: the real tables in exit
/// context ([`TypeTables::apply`]), vectors in the host tests.
struct Retype<'a> {
    /// One entry per 2 MiB region, from GPA 0.
    pds: &'a mut [EptEntry<Pd>],
    /// Every PT, in use or free; `pts_address` is the first one's physical
    /// address.
    pts: &'a mut [[EptEntry<Pt>; ENTRIES]],
    pts_address: u64,
    free: FreePts<'a>,
    /// The region holding the protected page, which keeps its PT.
    protected_region: usize,
}

/// The free PTs: a stack of their indices, the first `len` of `stack`.
struct FreePts<'a> {
    stack: &'a mut [u32],
    len: &'a mut usize,
}

impl FreePts<'_> {
    /// The index of a free PT, now in use, or `None` when none is left.
    fn take(&mut self) -> Option<usize> {
        *self.len = self.len.checked_sub(1)?;
        self.stack.get(*self.len).map(|&index| index as usize)
    }

    /// Puts the PT at `index` back: no PD entry points at it any more.
    fn give_back(&mut self, index: usize) {
        // The stack has room for every PT, and each is either in use or on
        // it once, so the slot is always there. A full stack means a PT was
        // given back twice: a bug in `retype`, not something a guest can do.
        let slot = self.stack.get_mut(*self.len);
        debug_assert!(slot.is_some(), "PT {index} given back to a full free stack");
        if let Some(slot) = slot {
            *slot = index as u32;
            *self.len += 1;
        }
    }
}

/// What [`retype`] changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Retyped {
    /// 2 MiB regions whose entries changed.
    pub regions: usize,
    /// From the start of the first of them to the end of the last; `None`
    /// when none changed.
    pub span: Option<(u64, u64)>,
    /// Regions now mapped through a spare PT: their pages came to differ in
    /// type.
    pub split: usize,
    /// Regions now one 2 MiB page, whose PT went back to the spare ones:
    /// their pages came to share one type.
    pub merged: usize,
    /// Regions whose pages differ in type, mapped UC as one 2 MiB page for
    /// lack of a spare PT. Counted whether or not this call made them so.
    pub uncached: usize,
}

impl Retyped {
    /// Whether any entry changed.
    pub fn changed(&self) -> bool {
        self.regions > 0
    }

    /// Counts the 2 MiB region number `region` as changed. [`retype`]'s
    /// second pass can count a region below one the first pass counted.
    fn count(&mut self, region: usize) {
        let start = region as u64 * SIZE_2M;
        let end = start + SIZE_2M;
        self.regions += 1;
        self.span = Some(match self.span {
            Some((first, last)) => (first.min(start), last.max(end)),
            None => (start, end),
        });
    }
}

/// Gives every region of `tables` the memory types `types` give its pages,
/// changing only the entries that differ, and returns what changed. As in
/// [`fill_identity_map`], a region whose pages share one type is one 2 MiB
/// page, and any other region, or the protected page's, a PT of 4 KiB pages
/// each of its own type. A region only partly RAM is always the second
/// ([`EptTypes::region_type`]), so it never takes or gives back a PT:
///
/// - One type, a 2 MiB page already: only its type bits change.
/// - One type, mapped through a PT: it becomes a 2 MiB page, and the PT goes
///   back on the free stack.
/// - Mixed types, or the protected page's region, mapped through a PT: the
///   type bits of its PT entries change. Their access bits stay, so the
///   protected page stays read-only, or writable once granted.
/// - Mixed types, a 2 MiB page: it takes a free PT, filled before the PD
///   entry points at it. With none left it stays one 2 MiB page, UC: the
///   one type that cannot hand a device stale data, as for an undefined
///   overlap of ranges. Only its RAM gets slower. It gets a PT at a later
///   call that gives one back.
///
/// The regions that need a PT come last, in a second pass over just the
/// ones the first pass found, so that every PT this call gives back is free
/// by then. In one pass, a region would find no PT when the one it needs is
/// only given back by a region after it, as when the guest moves a small
/// range down. A later call would only come with the guest's next type
/// change, so the region could stay UC for good.
///
/// The CPU may still hold translations made through the old entries:
/// [`TypeTables::apply`] runs INVEPT after. A PT taken back here may be
/// reused within the same call. That is sound with one vCPU, the guest
/// stopped and INVEPT run before it resumes. With several, the other vCPUs
/// would have to drop their translations through it first.
fn retype(tables: &mut Retype<'_>, types: &EptTypes<'_>) -> Retyped {
    let protected_region = tables.protected_region;
    // The type a region's 2 MiB page would have, `None` when it needs a PT.
    let wanted = |i: usize| {
        if i == protected_region {
            None
        } else {
            types.region_type(i as u64 * SIZE_2M)
        }
    };
    let mut retyped = Retyped::default();
    // The first and last region the second pass looks at.
    let mut needing_pts: Option<(usize, usize)> = None;
    for (i, entry) in tables.pds.iter_mut().enumerate() {
        let region = i as u64 * SIZE_2M;
        let pt = pt_index(*entry, tables.pts_address, tables.pts.len());
        let changed = match (entry.mapping(), wanted(i)) {
            (RegionMapping::LargePage(current), Some(memory_type)) => {
                let change = current != memory_type;
                if change {
                    *entry = EptEntry::large_page(region, memory_type);
                }
                change
            }
            (RegionMapping::Pt, Some(memory_type)) => {
                *entry = EptEntry::large_page(region, memory_type);
                if let Some(index) = pt {
                    tables.free.give_back(index);
                }
                retyped.merged += 1;
                true
            }
            (RegionMapping::Pt, None) => pt
                .and_then(|index| tables.pts.get_mut(index))
                .is_some_and(|pt| retype_pt(pt, region, types)),
            // Needs a PT: left to the second pass.
            (RegionMapping::LargePage(_), None) => {
                needing_pts = Some(needing_pts.map_or((i, i), |(first, _)| (first, i)));
                false
            }
            // Never made by `build` in a PD entry: left as it is.
            (RegionMapping::Invalid | RegionMapping::HugePage(_), _) => false,
        };
        if changed {
            retyped.count(i);
        }
    }

    let Some((first, last)) = needing_pts else {
        return retyped;
    };
    for (i, entry) in tables.pds.iter_mut().enumerate().take(last + 1).skip(first) {
        // The first pass left these regions alone, and made every other one
        // a PT or a 2 MiB page of the type it wants.
        let RegionMapping::LargePage(current) = entry.mapping() else {
            continue;
        };
        if wanted(i).is_some() {
            continue;
        }
        let region = i as u64 * SIZE_2M;
        let changed = match tables.free.take().filter(|&index| index < tables.pts.len()) {
            Some(index) => {
                fill_pt(&mut tables.pts[index], region, types);
                *entry = EptEntry::table(tables.pts_address + (index * PAGE_SIZE) as u64);
                retyped.split += 1;
                true
            }
            None => {
                retyped.uncached += 1;
                let change = current != MemoryType::Uncacheable;
                if change {
                    *entry = EptEntry::large_page(region, MemoryType::Uncacheable);
                }
                change
            }
        };
        if changed {
            retyped.count(i);
        }
    }
    retyped
}

/// The index, among `count` PTs from `pts_address`, of the PT the PD entry
/// `entry` points to, or `None` when it points to none of them.
fn pt_index(entry: EptEntry<Pd>, pts_address: u64, count: usize) -> Option<usize> {
    let offset = (entry.raw & ADDRESS_MASK).checked_sub(pts_address)?;
    let index = (offset / PAGE_SIZE as u64) as usize;
    (index < count).then_some(index)
}

/// Gives each page of `pt`, which maps the 2 MiB region at `region`, the
/// memory type `types` gives it, keeping its access bits. Returns whether
/// any entry changed.
fn retype_pt(pt: &mut [EptEntry<Pt>; ENTRIES], region: u64, types: &EptTypes<'_>) -> bool {
    let mut changed = false;
    for (j, page) in pt.iter_mut().enumerate() {
        let retyped = page.with_memory_type(types.page_type(region + (j * PAGE_SIZE) as u64));
        changed |= retyped != *page;
        *page = retyped;
    }
    changed
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
// arguments from bring-up. Written once before VMLAUNCH; read only in exit
// context, on the one CPU that runs the guest. Atomics rather than a
// `static mut` or a lock: this `no_std` build has neither an allocator for
// `Once`-style cells nor a `Mutex`.
static PROTECTED_GPA: AtomicU64 = AtomicU64::new(0);
static PROTECTED_ENTRY: AtomicPtr<EptEntry<Pt>> = AtomicPtr::new(core::ptr::null_mut());
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

/// Publishes `page` for [`protected_page`]. Refuses a second publication.
fn publish(page: ProtectedPage) -> Result<(), EptError> {
    if decode_invept(INVEPT_TYPE.load(Ordering::Acquire)).is_some() {
        return Err(EptError::AlreadyBuilt);
    }
    PROTECTED_GPA.store(page.gpa, Ordering::Relaxed);
    PROTECTED_ENTRY.store(page.entry, Ordering::Relaxed);
    PUBLISHED_EPTP.store(page.eptp.raw(), Ordering::Relaxed);
    INVEPT_TYPE.store(page.invept as u8, Ordering::Release);
    Ok(())
}

/// The page [`Ept::build`] made read-only, or `None` before it ran.
pub fn protected_page() -> Option<ProtectedPage> {
    let invept = decode_invept(INVEPT_TYPE.load(Ordering::Acquire))?;
    Some(ProtectedPage {
        gpa: PROTECTED_GPA.load(Ordering::Relaxed),
        entry: PROTECTED_ENTRY.load(Ordering::Relaxed),
        eptp: Eptp(PUBLISHED_EPTP.load(Ordering::Relaxed)),
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
