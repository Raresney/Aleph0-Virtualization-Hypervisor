//! Unit tests for `src/vmx/apic.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;
use crate::vmx::ept::{EPT_READ, EPT_RWX};
use crate::vmx::paging::PageSize;

/// The usual value on the bootstrap processor: base 0xFEE00000, xAPIC mode
/// (EN), BSP.
const XAPIC_BSP: ApicBase = ApicBase(0xFEE0_0900);

#[test]
fn the_mode_follows_en_and_extd() {
    assert_eq!(ApicBase(0xFEE0_0000).mode(), LapicMode::Disabled);
    assert_eq!(ApicBase(0xFEE0_0800).mode(), LapicMode::Xapic);
    assert_eq!(ApicBase(0xFEE0_0C00).mode(), LapicMode::X2apic);
    assert_eq!(ApicBase(0xFEE0_0400).mode(), LapicMode::Invalid);
}

#[test]
fn the_base_address_is_bits_maxphyaddr_to_12() {
    assert_eq!(XAPIC_BSP.address(46), 0xFEE0_0000);
    // A base firmware moved high, then cut at MAXPHYADDR 36.
    let high = ApicBase((1 << 40) | 0x1_2345_6000 | 0x900);
    assert_eq!(high.address(46), (1 << 40) | 0x1_2345_6000);
    assert_eq!(high.address(36), 0x1_2345_6000 & ((1 << 36) - 1));
    assert_eq!(high.address(0), 0);
    assert_eq!(high.address(64), (1 << 40) | 0x1_2345_6000);
}

#[test]
fn the_value_prints_with_its_mode_and_bsp() {
    assert!(XAPIC_BSP.bsp());
    assert_eq!(XAPIC_BSP.to_string(), "0xfee00900 (xAPIC, BSP)");
    assert_eq!(ApicBase(0xFEE0_0C00).to_string(), "0xfee00c00 (x2APIC)");
}

#[test]
fn the_version_range_is_an_integrated_apics() {
    assert!(INTEGRATED_APIC_VERSIONS.contains(&0x14));
    // An 82489DX, and the all-ones of a read that reached nothing.
    assert!(!INTEGRATED_APIC_VERSIONS.contains(&0x01));
    assert!(!INTEGRATED_APIC_VERSIONS.contains(&0xFF));
}

/// The firmware's page tables mapping `physical` there, as `walk_current`
/// gives it.
fn mapped_at(physical: u64) -> Result<Mapping, WalkError> {
    Ok(Mapping {
        physical,
        size: PageSize::Size1G,
        writable: true,
        user: false,
        execute_disable: false,
    })
}

/// EPT mapping the page at `hpa` as `memory_type` with `access`.
fn ept(hpa: u64, access: u64, memory_type: MemoryType) -> WalkEnd {
    WalkEnd::Mapped {
        hpa,
        size: 1 << 30,
        access,
        memory_type,
    }
}

#[test]
fn the_registers_are_readable_through_identity_maps_and_uc() {
    let base = 0xFEE0_0000;
    assert_eq!(
        check_registers(base, mapped_at(base), ept(base, EPT_RWX, MemoryType::Uncacheable)),
        Ok(())
    );
    assert_eq!(
        check_registers(base, mapped_at(base), ept(base, EPT_READ, MemoryType::Uncacheable)),
        Ok(())
    );
}

#[test]
fn the_guests_page_tables_must_map_the_registers_to_themselves() {
    let base = 0xFEE0_0000;
    let uc = ept(base, EPT_RWX, MemoryType::Uncacheable);
    let unmapped = Err(WalkError::NotPresent { level: 3 });
    assert_eq!(
        check_registers(base, unmapped, uc),
        Err(LocalApicError::GuestMapping {
            address: base,
            translation: unmapped
        })
    );
    assert!(matches!(
        check_registers(base, mapped_at(0x8000_0000), uc),
        Err(LocalApicError::GuestMapping { .. })
    ));
}

#[test]
fn ept_must_map_the_registers_to_themselves_uc_and_readable() {
    let base = 0xFEE0_0000;
    for end in [
        WalkEnd::NotPresent,
        WalkEnd::Misconfigured,
        ept(base, EPT_RWX, MemoryType::WriteBack),
        ept(0x8000_0000, EPT_RWX, MemoryType::Uncacheable),
        ept(base, 0, MemoryType::Uncacheable),
    ] {
        assert_eq!(
            check_registers(base, mapped_at(base), end),
            Err(LocalApicError::EptMapping { address: base, end }),
            "{end:?}"
        );
    }
}
