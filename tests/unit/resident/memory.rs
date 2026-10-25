//! Unit tests for `src/resident/memory.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;

#[test]
fn boot_time_memory_is_the_oss_after_exit_boot_services() {
    for memory_type in [
        MemoryType::LOADER_CODE,
        MemoryType::LOADER_DATA,
        MemoryType::BOOT_SERVICES_CODE,
        MemoryType::BOOT_SERVICES_DATA,
        MemoryType::CONVENTIONAL,
    ] {
        assert!(is_reclaimable(memory_type), "{memory_type:?}");
    }
}

#[test]
fn memory_the_os_takes_later_is_reclaimable_too() {
    for memory_type in [
        MemoryType::ACPI_RECLAIM,
        MemoryType::PERSISTENT_MEMORY,
        MemoryType::UNACCEPTED,
    ] {
        assert!(is_reclaimable(memory_type), "{memory_type:?}");
    }
}

#[test]
fn runtime_and_firmware_memory_is_kept() {
    for memory_type in [
        MemoryType::RESERVED,
        MemoryType::RUNTIME_SERVICES_CODE,
        MemoryType::RUNTIME_SERVICES_DATA,
        MemoryType::ACPI_NON_VOLATILE,
        MemoryType::PAL_CODE,
    ] {
        assert!(!is_reclaimable(memory_type), "{memory_type:?}");
    }
}

#[test]
fn what_is_not_memory_or_not_known_is_kept() {
    for memory_type in [
        MemoryType::UNUSABLE,
        MemoryType::MMIO,
        MemoryType::MMIO_PORT_SPACE,
        MemoryType::MAX,
        MemoryType(0x7000_0000),
        MemoryType(0x8000_0001),
    ] {
        assert!(!is_reclaimable(memory_type), "{memory_type:?}");
    }
}
