//! Unit tests for `src/vmx/paging.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;
use std::collections::HashMap;

const P_RW: u64 = PRESENT | WRITABLE;
const PML4: u64 = 0x1000;
const PDPT: u64 = 0x2000;
const PD: u64 = 0x3000;
const PT: u64 = 0x4000;

/// Builds a virtual address from its table indices and page offset.
fn va(pml4: u64, pdpt: u64, pd: u64, pt: u64, offset: u64) -> u64 {
    (pml4 << 39) | (pdpt << 30) | (pd << 21) | (pt << 12) | offset
}

/// Fake physical memory holding page-table entries; unset entries read 0.
struct Tables(HashMap<u64, u64>);

impl Tables {
    fn new() -> Self {
        Self(HashMap::new())
    }
    fn set(&mut self, table: u64, index: u64, entry: u64) -> &mut Self {
        self.0.insert(table + index * 8, entry);
        self
    }
    fn walk(&self, cr3: u64, virtual_address: u64) -> Result<Mapping, WalkError> {
        walk(cr3, virtual_address, |address| {
            self.0.get(&address).copied().unwrap_or(0)
        })
    }
}

/// PML4[1] -> PDPT[2] -> PD[3] -> PT[4] -> page 0x0012_3000, all P|RW.
fn four_level_tables() -> Tables {
    let mut tables = Tables::new();
    tables
        .set(PML4, 1, PDPT | P_RW)
        .set(PDPT, 2, PD | P_RW)
        .set(PD, 3, PT | P_RW)
        .set(PT, 4, 0x0012_3000 | P_RW);
    tables
}

#[test]
fn four_kib_page_translates_with_offset() {
    let mapping = four_level_tables().walk(PML4, va(1, 2, 3, 4, 0xABC)).unwrap();
    assert_eq!(
        mapping,
        Mapping {
            physical: 0x0012_3ABC,
            size: PageSize::Size4K,
            writable: true,
            user: false,
            execute_disable: false,
        },
    );
}

#[test]
fn user_only_when_set_at_every_level() {
    let mut tables = Tables::new();
    tables
        .set(PML4, 1, PDPT | P_RW | USER)
        .set(PDPT, 2, PD | P_RW | USER)
        .set(PD, 3, PT | P_RW | USER)
        .set(PT, 4, 0x0012_3000 | P_RW | USER);
    assert!(tables.walk(PML4, va(1, 2, 3, 4, 0)).unwrap().user);

    // One supervisor entry anywhere makes it a supervisor page.
    tables.set(PDPT, 2, PD | P_RW);
    assert!(!tables.walk(PML4, va(1, 2, 3, 4, 0)).unwrap().user);
}

#[test]
fn cr3_low_bits_are_ignored() {
    let mapping = four_level_tables().walk(PML4 | 0x18, va(1, 2, 3, 4, 0)).unwrap();
    assert_eq!(mapping.physical, 0x0012_3000);
}

#[test]
fn read_only_at_any_level_makes_page_read_only() {
    let mut tables = four_level_tables();
    tables.set(PDPT, 2, PD | PRESENT);
    assert!(!tables.walk(PML4, va(1, 2, 3, 4, 0)).unwrap().writable);
}

#[test]
fn execute_disable_at_any_level_is_reported() {
    let mut tables = four_level_tables();
    tables.set(PML4, 1, PDPT | P_RW | EXECUTE_DISABLE);
    let mapping = tables.walk(PML4, va(1, 2, 3, 4, 0)).unwrap();
    assert!(mapping.execute_disable);
    // XD is a flag, not part of the address.
    assert_eq!(mapping.physical, 0x0012_3000);
}

#[test]
fn two_mib_page_keeps_offset_and_drops_pat_bit() {
    let mut tables = Tables::new();
    tables
        .set(PML4, 0, PDPT | P_RW)
        .set(PDPT, 0, PD | P_RW)
        // Bit 12 is PAT in a large-page entry, not an address bit.
        .set(PD, 5, 0x4020_0000 | (1 << 12) | PAGE_SIZE_BIT | P_RW);
    let mapping = tables.walk(PML4, va(0, 0, 5, 0x1F, 0x123)).unwrap();
    assert_eq!(mapping.size, PageSize::Size2M);
    assert_eq!(mapping.physical, 0x4020_0000 | (0x1F << 12) | 0x123);
}

#[test]
fn one_gib_page_keeps_offset() {
    let mut tables = Tables::new();
    tables
        .set(PML4, 0, PDPT | P_RW)
        .set(PDPT, 1, 0x8000_0000 | PAGE_SIZE_BIT | P_RW);
    let mapping = tables.walk(PML4, va(0, 1, 7, 9, 0x42)).unwrap();
    assert_eq!(mapping.size, PageSize::Size1G);
    assert_eq!(mapping.physical, 0x8000_0000 | (7 << 21) | (9 << 12) | 0x42);
}

#[test]
fn missing_entry_reports_its_level() {
    let mut tables = four_level_tables();
    tables.set(PD, 3, 0);
    assert_eq!(
        tables.walk(PML4, va(1, 2, 3, 4, 0)),
        Err(WalkError::NotPresent { level: 2 })
    );
}
