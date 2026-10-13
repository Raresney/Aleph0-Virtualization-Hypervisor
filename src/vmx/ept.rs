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
//! - type (bits 5:3, leaf entries only): memory type, 6 = write-back (WB).
//! - IPAT (bit 6): ignore the guest's PAT. Left clear, so the guest's PAT
//!   still combines with the EPT type, as the MTRRs would without EPT.
//! - PS (bit 7, in a PD entry): this entry maps a 2 MiB page directly.
//!
//! Aleph0 builds an identity map (GPA = HPA) of all memory, so the guest
//! runs exactly as without EPT. One 4 KiB page, the guest's data page, is
//! mapped read-only: a guest write to it is the intentional EPT violation,
//! and [`grant_write`] makes it writable when that exit arrives. The
//! longer walkthrough is in `docs/EPT.md`.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

use uefi::boot::{self, MemoryType};
use uefi::mem::memory_map::MemoryMap;

use super::instruction::{VmxFail, check_rflags};
use super::page::{PAGE_SIZE, allocate_zeroed_pages};

/// Entry bit 0: reads allowed.
pub const EPT_READ: u64 = 1 << 0;
/// Entry bit 1: writes allowed.
pub const EPT_WRITE: u64 = 1 << 1;
/// Entry bit 2: instruction fetches allowed.
pub const EPT_EXECUTE: u64 = 1 << 2;
/// Every access allowed.
pub const EPT_RWX: u64 = EPT_READ | EPT_WRITE | EPT_EXECUTE;

/// Memory type 6, write-back: the type of ordinary RAM.
const MEMORY_TYPE_WB: u64 = 6;
/// Leaf entries keep the memory type in bits 5:3.
const MEMORY_TYPE_SHIFT: u32 = 3;
/// PD entry bit 7: maps a 2 MiB page instead of pointing to a PT.
const LARGE_PAGE: u64 = 1 << 7;
/// Bits 51:12: the physical address in an entry.
const ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000;
/// EPTP bits 5:3: page-walk length minus one; 3 means 4 levels.
const EPTP_WALK_LENGTH_4: u64 = 3 << 3;

/// Entries per table: 4096 bytes / 8 bytes per entry.
const ENTRIES: usize = 512;
const SIZE_4K: u64 = 1 << 12;
const SIZE_2M: u64 = 1 << 21;
const SIZE_1G: u64 = 1 << 30;
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
/// Secondary control bit 1 (enable EPT), in the allowed (high) half of
/// IA32_VMX_PROCBASED_CTLS2.
const SECONDARY_ALLOWS_EPT: u64 = 1 << (32 + 1);

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
}

/// Checks that this CPU supports the EPT Aleph0 builds, and picks the INVEPT
/// type: single-context when available, otherwise all-context.
///
/// `secondary` is IA32_VMX_PROCBASED_CTLS2 and `ept_vpid_cap`
/// IA32_VMX_EPT_VPID_CAP, both 0 when the CPU lacks them.
pub fn check_support(secondary: u64, ept_vpid_cap: u64) -> Result<InveptType, EptError> {
    if secondary & SECONDARY_ALLOWS_EPT == 0 {
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

/// A non-leaf entry pointing to the next table at `address`, allowing every
/// access. A non-leaf entry only limits what lies below it, so the leaf
/// entries decide the permissions.
pub fn table_entry(address: u64) -> u64 {
    (address & ADDRESS_MASK) | EPT_RWX
}

/// A PD entry mapping the 2 MiB page at `address`: RWX, write-back.
pub fn large_page_entry(address: u64) -> u64 {
    (address & ADDRESS_MASK) | EPT_RWX | (MEMORY_TYPE_WB << MEMORY_TYPE_SHIFT) | LARGE_PAGE
}

/// A PT entry mapping the 4 KiB page at `address` with `access` (a mix of
/// [`EPT_READ`], [`EPT_WRITE`], [`EPT_EXECUTE`]), write-back.
pub fn page_entry(address: u64, access: u64) -> u64 {
    (address & ADDRESS_MASK) | (access & EPT_RWX) | (MEMORY_TYPE_WB << MEMORY_TYPE_SHIFT)
}

/// The EPT pointer for the PML4 table at `pml4`: write-back (bits 2:0 = 6),
/// 4-level walk (bits 5:3 = 3), no accessed/dirty flags (bit 6 = 0). So the
/// low bits are always 0x1E.
pub fn eptp(pml4: u64) -> u64 {
    (pml4 & ADDRESS_MASK) | MEMORY_TYPE_WB | EPTP_WALK_LENGTH_4
}

// No PML4 index helper: the map ends at 512 GiB at most, so every address
// in it uses PML4 entry 0.

/// Index into the PDPT: bits 38:30.
pub fn pdpt_index(address: u64) -> usize {
    ((address >> 30) & 0x1FF) as usize
}

/// Index into the PD: bits 29:21.
pub fn pd_index(address: u64) -> usize {
    ((address >> 21) & 0x1FF) as usize
}

/// Index into the PT: bits 20:12.
pub fn pt_index(address: u64) -> usize {
    ((address >> 12) & 0x1FF) as usize
}

/// End of the identity map for memory-map regions `(start, pages)`: the
/// highest address any region reaches, rounded up to 1 GiB, so every PD is
/// full.
///
/// Every region counts, whatever its type, so memory-mapped I/O the
/// firmware reports is mapped too (as write-back; see `docs/EPT.md`).
pub fn identity_map_end(regions: impl Iterator<Item = (u64, u64)>) -> Result<u64, EptError> {
    let mut highest = 0u64;
    for (start, pages) in regions {
        let end = pages
            .checked_mul(SIZE_4K)
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
    pml4: &'a mut [u64],
    pdpt: &'a mut [u64],
    /// One PD per GiB of the map, back to back.
    pds: &'a mut [u64],
    pt: &'a mut [u64],
    pdpt_address: u64,
    pds_address: u64,
    pt_address: u64,
}

/// Fills `tables` with an identity map of `[0, end)`: 2 MiB pages, RWX,
/// write-back, except the 2 MiB region holding `protected_page`. That
/// region goes through the PT in 4 KiB pages, and `protected_page` itself
/// is read-only. Returns the PT index of `protected_page`.
///
/// `end` is a multiple of 1 GiB, `pds` holds `end / 1 GiB` tables, and
/// `protected_page` is 4 KiB-aligned and below `end`; [`Ept::build`]
/// checks all three.
fn fill_identity_map(tables: Tables<'_>, end: u64, protected_page: u64) -> usize {
    let gibs = (end / SIZE_1G) as usize;
    tables.pml4[0] = table_entry(tables.pdpt_address);
    for gib in 0..gibs {
        tables.pdpt[gib] = table_entry(tables.pds_address + gib as u64 * PAGE_SIZE as u64);
    }

    // PD entry number `i` across all PDs maps GPA i * 2 MiB.
    for (i, entry) in tables.pds.iter_mut().enumerate().take(gibs * ENTRIES) {
        *entry = large_page_entry(i as u64 * SIZE_2M);
    }
    // The PDs are back to back, one per PDPT entry, so the PD entry for an
    // address is its PDPT index times 512 plus its PD index.
    let split = pdpt_index(protected_page) * ENTRIES + pd_index(protected_page);
    tables.pds[split] = table_entry(tables.pt_address);

    let region = protected_page & !(SIZE_2M - 1);
    for (i, entry) in tables.pt.iter_mut().enumerate() {
        *entry = page_entry(region + i as u64 * SIZE_4K, EPT_RWX);
    }
    let protected = pt_index(protected_page);
    tables.pt[protected] = page_entry(protected_page, EPT_READ);
    protected
}

/// One EPT identity map. Its table pages are never freed: the CPU walks them
/// on every guest access for as long as the VMCS points at them.
pub struct Ept {
    eptp: u64,
    end: u64,
    table_pages: usize,
}

impl Ept {
    /// Builds the identity map from the UEFI memory map, with
    /// `protected_page` read-only, and publishes what [`grant_write`] needs
    /// later in the exit handler.
    ///
    /// # Safety
    ///
    /// Boot services must still be active, and physical memory must be
    /// identity-mapped (as UEFI does), since the tables are filled through
    /// their physical addresses.
    pub unsafe fn build(protected_page: u64, invept: InveptType) -> Result<Self, EptError> {
        let map = boot::memory_map(MemoryType::LOADER_DATA).map_err(|_| EptError::MemoryMapUnavailable)?;
        let end = identity_map_end(map.entries().map(|region| (region.phys_start, region.page_count)))?;
        if protected_page >= end || !protected_page.is_multiple_of(SIZE_4K) {
            return Err(EptError::ProtectedPageOutsideMap);
        }

        let gibs = (end / SIZE_1G) as usize;
        let pml4 = allocate_zeroed_pages(1, EptError::AllocationFailed)?.as_ptr() as u64;
        let pdpt = allocate_zeroed_pages(1, EptError::AllocationFailed)?.as_ptr() as u64;
        let pds = allocate_zeroed_pages(gibs, EptError::AllocationFailed)?.as_ptr() as u64;
        let pt = allocate_zeroed_pages(1, EptError::AllocationFailed)?.as_ptr() as u64;

        // SAFETY: each allocation above is page-aligned, zeroed and as long
        // as its slice, and nothing else refers to it yet.
        let table = |address: u64, pages: usize| unsafe {
            core::slice::from_raw_parts_mut(address as *mut u64, pages * ENTRIES)
        };
        let protected = fill_identity_map(
            Tables {
                pml4: table(pml4, 1),
                pdpt: table(pdpt, 1),
                pds: table(pds, gibs),
                pt: table(pt, 1),
                pdpt_address: pdpt,
                pds_address: pds,
                pt_address: pt,
            },
            end,
            protected_page,
        );

        let ept = Self {
            eptp: eptp(pml4),
            end,
            table_pages: gibs + 3,
        };
        PROTECTED_PAGE.store(protected_page, Ordering::Relaxed);
        PROTECTED_ENTRY.store(pt + protected as u64 * 8, Ordering::Relaxed);
        PUBLISHED_EPTP.store(ept.eptp, Ordering::Relaxed);
        INVEPT_TYPE.store(invept as u64, Ordering::Relaxed);
        Ok(ept)
    }

    /// The value for the VMCS EPT_POINTER field.
    pub fn eptp(&self) -> u64 {
        self.eptp
    }

    /// End of the identity map: GPAs `[0, end)` are mapped.
    pub fn end(&self) -> u64 {
        self.end
    }

    /// Pages holding the tables: PML4, PDPT, the PDs and the PT.
    pub fn table_pages(&self) -> usize {
        self.table_pages
    }
}

// What `Ept::build` publishes for the exit handler, which cannot take
// arguments from bring-up. Written once before VMLAUNCH; read only in exit
// context, on the one CPU that runs the guest.
/// GPA of the read-only page, 0 before `build`.
static PROTECTED_PAGE: AtomicU64 = AtomicU64::new(0);
/// Address of its PT entry, 0 before `build`.
static PROTECTED_ENTRY: AtomicU64 = AtomicU64::new(0);
static PUBLISHED_EPTP: AtomicU64 = AtomicU64::new(0);
/// An [`InveptType`] as its operand value.
static INVEPT_TYPE: AtomicU64 = AtomicU64::new(0);

/// GPA of the page [`Ept::build`] made read-only, or 0 before it ran.
pub fn protected_page() -> u64 {
    PROTECTED_PAGE.load(Ordering::Relaxed)
}

/// Why [`grant_write`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantError {
    /// [`Ept::build`] never ran, so there is no page to unprotect.
    NothingProtected,
    /// INVEPT failed: CF (invalid) or ZF (valid, see the VM-instruction
    /// error).
    Invept(VmxFail),
}

/// Makes the protected page writable and drops cached translations with
/// INVEPT. Returns the INVEPT type used, for the report.
///
/// The CPU already drops the translation that caused an EPT violation, so
/// the retried write would see the new entry even without INVEPT. INVEPT is
/// still the architectural way to publish an EPT change, and changes not
/// caused by a violation need it.
///
/// # Safety
///
/// VMX root operation, and [`Ept::build`]'s tables still in place. Called
/// from the exit handler, while the guest is not running.
pub unsafe fn grant_write() -> Result<InveptType, GrantError> {
    let entry = PROTECTED_ENTRY.load(Ordering::Relaxed);
    if entry == 0 {
        return Err(GrantError::NothingProtected);
    }
    let invept = match INVEPT_TYPE.load(Ordering::Relaxed) {
        1 => InveptType::SingleContext,
        _ => InveptType::AllContext,
    };
    unsafe {
        let entry = entry as *mut u64;
        entry.write_volatile(entry.read_volatile() | EPT_WRITE);
        invalidate(invept, PUBLISHED_EPTP.load(Ordering::Relaxed)).map_err(GrantError::Invept)?;
    }
    Ok(invept)
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
unsafe fn invalidate(kind: InveptType, eptp: u64) -> Result<(), VmxFail> {
    let descriptor = InveptDescriptor { eptp, reserved: 0 };
    let rflags: u64;
    unsafe {
        asm!(
            "invept {kind}, [{descriptor}]",
            "pushfq",
            "pop {rflags}",
            kind = in(reg) kind as u64,
            descriptor = in(reg) &descriptor,
            rflags = lateout(reg) rflags,
        );
    }
    check_rflags(rflags)
}

#[cfg(test)]
#[path = "../../tests/unit/vmx/ept.rs"]
mod tests;
