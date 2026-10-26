//! Unit tests for `src/resident/mod.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;

/// Part of the test VM's memory map: the firmware's data, Aleph0's
/// resident pages, free memory up to 2 GiB.
const MAP: [(u64, u64, MemoryType); 3] = [
    (0x7e00_0000, 0x100, MemoryType::BOOT_SERVICES_DATA),
    (0x7e10_0000, 0x20, MemoryType::RUNTIME_SERVICES_DATA),
    (0x7e12_0000, 0x1ee0, MemoryType::CONVENTIONAL),
];

#[test]
fn an_address_has_the_type_of_its_region() {
    let at = |address| memory_type_at(MAP.into_iter(), address);
    assert_eq!(at(0x7e10_0000), Some(MemoryType::RUNTIME_SERVICES_DATA));
    assert_eq!(at(0x7e11_f000), Some(MemoryType::RUNTIME_SERVICES_DATA));
    // The first byte past a region is the next one's.
    assert_eq!(at(0x7e12_0000), Some(MemoryType::CONVENTIONAL));
    assert_eq!(at(0x7e0f_ffff), Some(MemoryType::BOOT_SERVICES_DATA));
}

#[test]
fn an_address_outside_every_region_has_no_type() {
    let at = |address| memory_type_at(MAP.into_iter(), address);
    assert_eq!(at(0x7dff_f000), None);
    assert_eq!(at(0x8000_0000), None);
    // A region whose end would overflow still has its start.
    assert_eq!(
        memory_type_at([(u64::MAX - 0xFFF, u64::MAX, MemoryType::MMIO)].into_iter(), u64::MAX),
        Some(MemoryType::MMIO)
    );
}
