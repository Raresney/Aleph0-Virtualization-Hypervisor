//! Unit tests for `src/vmx/host/page_tables.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.
//!
//! The tables are built in vectors at made-up physical addresses, then
//! walked with `paging::walk`, the same walker bring-up runs on the
//! firmware's tables, so the tests check what the CPU would resolve.

use super::*;
use crate::vmx::ept::SIZE_2M;
use crate::vmx::paging::{self, Mapping};

/// Made-up physical addresses of the tables: the PML4, the PDPT, then the
/// PDs back to back.
const PML4: u64 = 0x10_0000;
const PDPT: u64 = 0x10_1000;
const PDS: u64 = 0x10_2000;

/// A map of `gibs` GiB in `page_size` pages, filled by `fill_identity_map`.
struct Built {
    pml4: Vec<HostEntry<Pml4>>,
    pdpt: Vec<HostEntry<Pdpt>>,
    pds: Vec<HostEntry<Pd>>,
}

impl Built {
    fn new(gibs: usize, page_size: PageSize) -> Self {
        let pd_pages = table_pages(gibs, page_size) - 2;
        let mut built = Self {
            pml4: vec![HostEntry::from_raw(0); ENTRIES],
            pdpt: vec![HostEntry::from_raw(0); ENTRIES],
            pds: vec![HostEntry::from_raw(0); pd_pages * ENTRIES],
        };
        let tables = Tables {
            pml4: &mut built.pml4,
            pdpt: &mut built.pdpt,
            pds: &mut built.pds,
            pdpt_address: PDPT,
            pds_address: PDS,
        };
        fill_identity_map(tables, gibs, page_size);
        built
    }

    /// The entry at physical address `address`, as the walker reads it.
    fn read(&self, address: u64) -> u64 {
        let index = |base: u64| ((address - base) / 8) as usize;
        match address {
            PML4..PDPT => self.pml4[index(PML4)].raw,
            PDPT..PDS => self.pdpt[index(PDPT)].raw,
            _ => self.pds[index(PDS)].raw,
        }
    }

    fn walk(&self, address: u64) -> Result<Mapping, paging::WalkError> {
        paging::walk(PML4, address, |entry| self.read(entry))
    }
}

/// Addresses across a 4 GiB map: both ends of the first page and of each
/// GiB, and one inside a 2 MiB page.
const SAMPLES: [u64; 7] = [
    0,
    0xFFF,
    0x7eb1_9123,
    SIZE_1G - 1,
    SIZE_1G,
    3 * SIZE_1G + 5 * SIZE_2M + 0x42,
    4 * SIZE_1G - 1,
];

/// Checks that `mapping`, the walk of `address`, maps it to itself and lets
/// the ring-0 host read, write and execute it.
fn assert_identity(address: u64, mapping: Mapping, size: paging::PageSize) {
    assert_eq!(mapping.physical, address, "{address:#x} maps to itself");
    assert_eq!(mapping.size, size);
    assert!(mapping.writable, "{address:#x} writable");
    assert!(!mapping.user, "{address:#x} supervisor only");
    assert!(
        !mapping.execute_disable,
        "{address:#x} executable whatever EFER.NXE says"
    );
}

#[test]
fn one_gib_pages_map_every_address_to_itself() {
    let built = Built::new(4, PageSize::Huge1G);
    for address in SAMPLES {
        assert_identity(address, built.walk(address).unwrap(), paging::PageSize::Size1G);
    }
}

#[test]
fn two_mib_pages_map_every_address_to_itself() {
    let built = Built::new(4, PageSize::Large2M);
    for address in SAMPLES {
        assert_identity(address, built.walk(address).unwrap(), paging::PageSize::Size2M);
    }
}

#[test]
fn the_map_ends_at_its_last_gib() {
    for page_size in [PageSize::Huge1G, PageSize::Large2M] {
        let built = Built::new(4, page_size);
        assert_eq!(
            built.walk(4 * SIZE_1G),
            Err(paging::WalkError::NotPresent { level: 3 }),
            "{page_size:?}: no PDPT entry past the end"
        );
    }
}

#[test]
fn only_the_first_pml4_entry_is_used() {
    let built = Built::new(512, PageSize::Huge1G);
    assert_eq!(built.pml4[0], HostEntry::table(PDPT));
    assert!(built.pml4[1..].iter().all(|entry| entry.raw == 0));
}

#[test]
fn one_gib_pages_need_no_pds() {
    assert_eq!(table_pages(2, PageSize::Huge1G), 2);
    assert_eq!(table_pages(512, PageSize::Huge1G), 2);
    assert!(Built::new(2, PageSize::Huge1G).pds.is_empty());
}

#[test]
fn two_mib_pages_need_a_pd_per_gib() {
    assert_eq!(table_pages(2, PageSize::Large2M), 4);
    let built = Built::new(2, PageSize::Large2M);
    // The second GiB's PD is the second page after PDS.
    assert_eq!(built.pdpt[1], HostEntry::table(PDS + 0x1000));
    // PD entry 513 across both PDs: the second GiB's second 2 MiB page.
    assert_eq!(built.pds[513], HostEntry::large_page(SIZE_1G + SIZE_2M));
}

#[test]
fn table_entries_are_present_writable_and_accessed() {
    // P (bit 0), R/W (bit 1), A (bit 5); U/S (bit 2) and XD (bit 63) clear.
    assert_eq!(HostEntry::<Pml4>::table(0x7000).raw, 0x7000 | 0x23);
}

#[test]
fn large_pages_are_dirty_and_have_ps_set() {
    // As tables, plus D (bit 6) and PS (bit 7); PAT, PCD and PWT 0 (WB).
    assert_eq!(HostEntry::<Pdpt>::huge_page(SIZE_1G).raw, SIZE_1G | 0xE3);
    assert_eq!(HostEntry::<Pd>::large_page(SIZE_2M).raw, SIZE_2M | 0xE3);
}

#[test]
fn the_end_must_be_whole_gibs_up_to_one_pdpt() {
    assert_eq!(gibs(SIZE_1G), Ok(1));
    assert_eq!(gibs(MAX_IDENTITY_MAP), Ok(512));
    for end in [0, SIZE_1G + SIZE_2M, MAX_IDENTITY_MAP + SIZE_1G] {
        assert_eq!(gibs(end), Err(HostPagingError::InvalidEnd { end }));
    }
}

#[test]
fn five_level_paging_is_refused() {
    assert_eq!(check_paging_mode(CR4_LA57), Err(HostPagingError::FiveLevelPaging));
    // The CR4 the Hyper-V firmware runs with (no LA57).
    assert_eq!(check_paging_mode(0x2668), Ok(()));
}

#[test]
fn page_size_follows_the_cpu() {
    assert_eq!(PageSize::for_cpu(true), PageSize::Huge1G);
    assert_eq!(PageSize::for_cpu(false), PageSize::Large2M);
}
