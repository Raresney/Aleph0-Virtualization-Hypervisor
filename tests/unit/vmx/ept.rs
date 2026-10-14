//! Unit tests for `src/vmx/ept.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::level::{Pd, Pdpt, Pml4, Pt};
use super::*;

/// A secondary capability MSR that allows EPT and nothing else.
const EPT_ALLOWED: ControlCapability = ControlCapability((SECONDARY_ENABLE_EPT as u64) << 32);

/// The EPT/VPID capabilities Aleph0 needs: 4-level walk, WB, 2 MiB pages,
/// INVEPT with both types.
const FULL_CAP: u64 =
    CAP_WALK_LENGTH_4 | CAP_WRITE_BACK | CAP_2M_PAGES | CAP_INVEPT | CAP_INVEPT_SINGLE_CONTEXT | CAP_INVEPT_ALL_CONTEXT;

#[test]
fn full_support_picks_single_context() {
    assert_eq!(check_support(EPT_ALLOWED, FULL_CAP), Ok(InveptType::SingleContext));
}

#[test]
fn all_context_is_the_fallback() {
    let cap = FULL_CAP & !CAP_INVEPT_SINGLE_CONTEXT;
    assert_eq!(check_support(EPT_ALLOWED, cap), Ok(InveptType::AllContext));
}

#[test]
fn each_missing_capability_has_its_error() {
    assert_eq!(
        check_support(ControlCapability(0), FULL_CAP),
        Err(EptError::EptUnsupported)
    );
    for (missing, error) in [
        (CAP_WALK_LENGTH_4, EptError::PageWalkLength4Unsupported),
        (CAP_WRITE_BACK, EptError::WriteBackUnsupported),
        (CAP_2M_PAGES, EptError::LargePagesUnsupported),
        (CAP_INVEPT, EptError::InveptUnsupported),
        (
            CAP_INVEPT_SINGLE_CONTEXT | CAP_INVEPT_ALL_CONTEXT,
            EptError::InveptUnsupported,
        ),
    ] {
        assert_eq!(check_support(EPT_ALLOWED, FULL_CAP & !missing), Err(error));
    }
}

#[test]
fn table_entry_allows_everything() {
    assert_eq!(EptEntry::<Pdpt>::table(0x7e00_1000), EptEntry::from_raw(0x7e00_1007));
}

#[test]
fn large_page_entry_is_rwx_write_back_2m() {
    // 0x7 RWX | 6 << 3 = 0x30 WB | 0x80 large page.
    assert_eq!(EptEntry::large_page(0x4020_0000), EptEntry::from_raw(0x4020_00B7));
}

#[test]
fn read_only_page_entry_has_only_r() {
    assert_eq!(EptEntry::page(0x7eb1_d000, EPT_READ), EptEntry::from_raw(0x7eb1_d031));
    assert_eq!(EptEntry::page(0x7eb1_d000, EPT_RWX), EptEntry::from_raw(0x7eb1_d037));
}

#[test]
fn with_access_replaces_only_the_permission_bits() {
    let read_only = EptEntry::page(0x7eb1_d000, EPT_READ);
    assert_eq!(
        read_only.with_access(EPT_READ | EPT_WRITE),
        EptEntry::from_raw(0x7eb1_d033)
    );
    assert_eq!(read_only.with_access(0), EptEntry::from_raw(0x7eb1_d030));
}

#[test]
fn eptp_low_bits_are_write_back_and_4_levels() {
    assert_eq!(Eptp::new(0x7e00_0000).raw(), 0x7e00_001e);
}

#[test]
fn each_level_indexes_its_own_address_bits() {
    let address = (3 << 39) | (5 << 30) | (7 << 21) | (9 << 12) | 0x123;
    assert_eq!(
        (
            Pml4::index(address),
            Pdpt::index(address),
            Pd::index(address),
            Pt::index(address)
        ),
        (3, 5, 7, 9)
    );
}

#[test]
fn every_level_can_point_to_the_next_table() {
    assert_eq!(EptEntry::<Pml4>::table(0x1000).raw, 0x1007);
    assert_eq!(EptEntry::<Pdpt>::table(0x1000).raw, 0x1007);
    assert_eq!(EptEntry::<Pd>::table(0x1000).raw, 0x1007);
}

#[test]
fn empty_entry_is_not_present_and_the_default() {
    assert_eq!(EptEntry::<Pt>::EMPTY.raw, 0);
    assert_eq!(EptEntry::<Pml4>::default(), EptEntry::EMPTY);
}

#[test]
fn debug_names_the_level() {
    assert_eq!(format!("{:?}", EptEntry::<Pd>::table(0x4000)), "EptEntry<PD>(0x4007)");
}

#[test]
fn map_end_is_the_highest_region_rounded_up_to_a_gib() {
    // 2 GiB of RAM in two regions, plus firmware MMIO just below 4 GiB.
    let regions = [(0, 0x1000), (0x0100_0000, 0x7_F000), (0xFFC0_0000, 0x400)];
    assert_eq!(identity_map_end(regions.into_iter()), Ok(4 * SIZE_1G));
}

#[test]
fn map_end_on_a_gib_boundary_is_not_rounded_further() {
    assert_eq!(identity_map_end([(0, 0x8_0000)].into_iter()), Ok(2 * SIZE_1G));
}

#[test]
fn map_end_past_one_pdpt_is_refused() {
    let past = MAX_IDENTITY_MAP + PAGE_SIZE as u64;
    assert_eq!(
        identity_map_end([(MAX_IDENTITY_MAP, 1)].into_iter()),
        Err(EptError::RangeTooLarge { end: past }),
    );
}

#[test]
fn empty_memory_map_is_refused() {
    assert_eq!(identity_map_end(core::iter::empty()), Err(EptError::EmptyMemoryMap));
}

/// The PML4, PDPT, PDs and PT of an identity map.
type Tables4 = (
    Vec<EptEntry<Pml4>>,
    Vec<EptEntry<Pdpt>>,
    Vec<EptEntry<Pd>>,
    Vec<EptEntry<Pt>>,
);

/// Fills a 2 GiB identity map with made-up table addresses and returns the
/// tables and the protected PT index.
fn filled(protected_page: u64) -> (Tables4, usize) {
    let (mut pml4, mut pdpt, mut pds, mut pt) = (
        vec![EptEntry::EMPTY; ENTRIES],
        vec![EptEntry::EMPTY; ENTRIES],
        vec![EptEntry::EMPTY; 2 * ENTRIES],
        vec![EptEntry::EMPTY; ENTRIES],
    );
    let protected = fill_identity_map(
        Tables {
            pml4: &mut pml4,
            pdpt: &mut pdpt,
            pds: &mut pds,
            pt: &mut pt,
            pdpt_address: 0x1000,
            pds_address: 0x2000,
            pt_address: 0x4000,
        },
        2,
        protected_page,
    );
    ((pml4, pdpt, pds, pt), protected)
}

#[test]
fn identity_map_links_the_levels() {
    let ((pml4, pdpt, _, _), _) = filled(0x7eb1_d000);
    assert_eq!(pml4[0], EptEntry::table(0x1000));
    assert_eq!(pml4[1], EptEntry::EMPTY);
    assert_eq!(pdpt[0], EptEntry::table(0x2000));
    assert_eq!(pdpt[1], EptEntry::table(0x3000));
    assert_eq!(pdpt[2], EptEntry::EMPTY);
}

#[test]
fn identity_map_uses_2m_pages_outside_the_split_region() {
    let ((_, _, pds, _), _) = filled(0x7eb1_d000);
    assert_eq!(pds[0], EptEntry::large_page(0));
    assert_eq!(pds[1023], EptEntry::large_page(1023 * SIZE_2M));
    // 0x7eb1_d000 is in the 2 MiB region 0x7ea0_0000, entry 0x3F5.
    assert_eq!(pds[0x3F5], EptEntry::table(0x4000));
    assert_eq!(pds[0x3F4], EptEntry::large_page(0x7e80_0000));
}

#[test]
fn identity_map_makes_only_the_protected_page_read_only() {
    let ((_, _, _, pt), protected) = filled(0x7eb1_d000);
    assert_eq!(protected, 0x11D);
    assert_eq!(pt[0x11D], EptEntry::page(0x7eb1_d000, EPT_READ));
    assert_eq!(pt[0x11C], EptEntry::page(0x7eb1_c000, EPT_RWX));
    assert_eq!(pt[0], EptEntry::page(0x7ea0_0000, EPT_RWX));
    assert_eq!(pt[511], EptEntry::page(0x7ebf_f000, EPT_RWX));
}

#[test]
fn only_published_invept_types_decode() {
    assert_eq!(decode_invept(0), None, "nothing published");
    assert_eq!(decode_invept(1), Some(InveptType::SingleContext));
    assert_eq!(decode_invept(2), Some(InveptType::AllContext));
    assert_eq!(decode_invept(3), None);
    assert_eq!(decode_invept(0xFF), None);
}
