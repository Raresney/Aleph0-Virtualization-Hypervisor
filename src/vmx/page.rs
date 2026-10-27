//! Page allocation, and the memory types that keep Aleph0's pages after
//! `ExitBootServices`.
//!
//! After `ExitBootServices` the OS may reuse every page of a type
//! `resident::memory::is_reclaimable` names (`LOADER_*`, `BOOT_SERVICES_*`,
//! conventional memory, ...). Aleph0 runs at every VM exit for as long as
//! the guest does, so everything it keeps comes from here as a resident
//! type: [`allocate_zeroed_pages`] gives [`RESIDENT_DATA`], and the image
//! copy (`resident::ResidentImage`) and the test guest's code ask for
//! [`RESIDENT_CODE`]. Each resident allocation is listed
//! ([`resident_allocations`]), so bring-up can check every one of them in
//! the memory map before the launch.

use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use uefi::boot::{self, AllocateType, MemoryType};

pub const PAGE_SIZE: usize = 4096;

/// The type of every page Aleph0 keeps after `ExitBootServices`. The UEFI
/// spec has the OS preserve runtime-services memory, and an OS leaves it out
/// of its free memory. docs/RESIDENT.md says why this and not `RESERVED`.
pub const RESIDENT_DATA: MemoryType = MemoryType::RUNTIME_SERVICES_DATA;

/// The type of Aleph0's image copy: its code runs from these pages, also in
/// the guest on the firmware's page tables (the `ExitBootServices` event),
/// and firmware with DXE memory protection commonly maps the data types,
/// `RESERVED` and [`RESIDENT_DATA`] included, no-execute.
pub const RESIDENT_CODE: MemoryType = MemoryType::RUNTIME_SERVICES_CODE;

/// One resident allocation: `pages` pages from `address`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allocation {
    pub address: u64,
    pub pages: usize,
    /// Whether it is [`RESIDENT_CODE`] (the image copy, the guest's code and
    /// data) rather than [`RESIDENT_DATA`]. Hiding keeps code pages
    /// executable by the guest (read-only, so they cannot be rewritten),
    /// since the `ExitBootServices` event callback runs in the guest from
    /// the image copy; it redirects data pages to the shadow (`vmx::ept`).
    pub code: bool,
}

impl Allocation {
    /// Whether `address` lies in this allocation's pages.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.address && address - self.address < (self.pages * PAGE_SIZE) as u64
    }
}

/// How many resident allocations [`resident_allocations`] can list.
/// Bring-up makes 27 on the Hyper-V test VM.
const LISTED_ALLOCATIONS: usize = 64;

/// Address, page count and code flag of each resident allocation, oldest
/// first. Only bring-up allocates, on one CPU; the atomics just avoid
/// `static mut`.
static ALLOCATIONS: [[AtomicU64; 3]; LISTED_ALLOCATIONS] =
    [const { [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)] }; LISTED_ALLOCATIONS];
/// Resident allocations so far, listed or not.
static ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Lists `allocation` if it has a resident type, or counts it as unlisted
/// once the list is full.
fn record(allocation: Allocation, memory_type: MemoryType) {
    if memory_type != RESIDENT_DATA && memory_type != RESIDENT_CODE {
        return;
    }
    let index = ALLOCATION_COUNT.fetch_add(1, Ordering::Relaxed);
    if let Some([address, pages, code]) = ALLOCATIONS.get(index) {
        address.store(allocation.address, Ordering::Relaxed);
        pages.store(allocation.pages as u64, Ordering::Relaxed);
        code.store(allocation.code.into(), Ordering::Relaxed);
    }
}

/// Every resident allocation so far, oldest first, up to the first
/// [`LISTED_ALLOCATIONS`].
pub fn resident_allocations() -> impl Iterator<Item = Allocation> {
    let listed = ALLOCATION_COUNT.load(Ordering::Relaxed).min(LISTED_ALLOCATIONS);
    ALLOCATIONS[..listed].iter().map(|[address, pages, code]| Allocation {
        address: address.load(Ordering::Relaxed),
        pages: pages.load(Ordering::Relaxed) as usize,
        code: code.load(Ordering::Relaxed) != 0,
    })
}

/// Whether `gpa` lies in one of Aleph0's own resident pages. Used to guard
/// the GPAs a forwarded Hyper-V access would have Hyper-V read or overlay
/// (`vmx::hyperv`): those act on Aleph0's address space past EPT, so one
/// naming an Aleph0 page must be refused, not forwarded.
///
/// Sound only once the allocation list is complete: bring-up refuses to
/// launch while [`unlisted_resident_allocations`] is non-zero, so by the
/// time the guest runs [`resident_allocations`] is every page Aleph0 keeps.
pub fn is_resident(gpa: u64) -> bool {
    resident_allocations().any(|a| a.contains(gpa))
}

/// Resident allocations made after the list was full, which
/// [`resident_allocations`] leaves out.
pub fn unlisted_resident_allocations() -> usize {
    ALLOCATION_COUNT
        .load(Ordering::Relaxed)
        .saturating_sub(LISTED_ALLOCATIONS)
}

/// Allocate and zero one resident page, preserving the caller's allocation
/// error type.
pub fn allocate_zeroed_page<E>(allocation_error: E) -> Result<NonNull<u8>, E> {
    allocate_zeroed_pages(1, allocation_error)
}

/// Allocate and zero `count` contiguous resident pages ([`RESIDENT_DATA`]),
/// preserving the caller's allocation error type.
pub fn allocate_zeroed_pages<E>(count: usize, allocation_error: E) -> Result<NonNull<u8>, E> {
    allocate_zeroed_pages_of_type(count, RESIDENT_DATA, allocation_error)
}

/// Like [`allocate_zeroed_pages`], with an explicit UEFI memory type. The
/// allocation is listed if the type is [`RESIDENT_DATA`] or
/// [`RESIDENT_CODE`].
///
/// The type can decide the page's permissions: firmware with DXE memory
/// protection commonly maps the data types no-execute and leaves the code
/// types executable.
pub fn allocate_zeroed_pages_of_type<E>(
    count: usize,
    memory_type: MemoryType,
    allocation_error: E,
) -> Result<NonNull<u8>, E> {
    let pages = boot::allocate_pages(AllocateType::AnyPages, memory_type, count).map_err(|_| allocation_error)?;

    assert_eq!(
        pages.as_ptr() as usize % PAGE_SIZE,
        0,
        "UEFI returned an unaligned page"
    );
    // SAFETY: `allocate_pages` returned `count` pages at `pages`, which
    // nothing else uses yet.
    unsafe { pages.write_bytes(0, count * PAGE_SIZE) };
    record(
        Allocation {
            address: pages.as_ptr() as u64,
            pages: count,
            code: memory_type == RESIDENT_CODE,
        },
        memory_type,
    );
    Ok(pages)
}

#[cfg(test)]
#[path = "../../tests/unit/vmx/page.rs"]
mod tests;
