//! Unit tests for `src/paging.rs`.

use super::*;

#[test]
fn every_gib_maps_to_itself_in_2_mib_pages() {
    let mut tables = Box::new(PageTables::EMPTY);
    let cr3 = tables.identity_map(2).unwrap();
    assert_eq!(cr3, tables.pml4.as_ptr() as u64);
    assert_eq!(tables.pml4[0], tables.pdpt.as_ptr() as u64 | 0b11);
    assert_eq!(tables.pdpt[1], tables.pds[1].as_ptr() as u64 | 0b11);
    // PS, R/W, P: the first page, and the last page of GiB 1.
    assert_eq!(tables.pds[0][0], 0x83);
    assert_eq!(tables.pds[1][511], 0x7fe0_0000 | 0x83);
    // Nothing past the map.
    assert_eq!(tables.pdpt[2], 0);
    assert_eq!(tables.pml4[1], 0);
}

#[test]
fn more_gibs_than_the_tables_hold_are_refused() {
    let mut tables = Box::new(PageTables::EMPTY);
    assert_eq!(tables.identity_map(MAX_GIBS + 1), None);
    assert!(tables.identity_map(MAX_GIBS).is_some());
}

#[test]
fn the_map_reaches_the_last_region_and_at_least_4_gib() {
    // The test VM: RAM up to 2 GiB.
    assert_eq!(gibs_to_map([(0x0, 0x9f), (0x10_0000, 0x7ff00)].into_iter()), 4);
    // A region ending just past 4 GiB needs a fifth.
    assert_eq!(gibs_to_map([(0xffff_f000, 2)].into_iter()), 5);
}
