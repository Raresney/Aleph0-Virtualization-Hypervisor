//! Unit tests for `src/vmx/ept.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;

/// The EPT/VPID capabilities Aleph0 needs: 4-level walk, WB, 2 MiB pages,
/// INVEPT with both types.
const FULL_CAP: u64 = CAP_WALK_LENGTH_4
    | CAP_WRITE_BACK
    | CAP_2M_PAGES
    | CAP_INVEPT
    | CAP_INVEPT_SINGLE_CONTEXT
    | CAP_INVEPT_ALL_CONTEXT;

#[test]
fn full_support_picks_single_context() {
    assert_eq!(check_support(SECONDARY_ALLOWS_EPT, FULL_CAP), Ok(InveptType::SingleContext));
}

#[test]
fn all_context_is_the_fallback() {
    let cap = FULL_CAP & !CAP_INVEPT_SINGLE_CONTEXT;
    assert_eq!(check_support(SECONDARY_ALLOWS_EPT, cap), Ok(InveptType::AllContext));
}

#[test]
fn each_missing_capability_has_its_error() {
    assert_eq!(check_support(0, FULL_CAP), Err(EptError::EptUnsupported));
    for (missing, error) in [
        (CAP_WALK_LENGTH_4, EptError::PageWalkLength4Unsupported),
        (CAP_WRITE_BACK, EptError::WriteBackUnsupported),
        (CAP_2M_PAGES, EptError::LargePagesUnsupported),
        (CAP_INVEPT, EptError::InveptUnsupported),
        (CAP_INVEPT_SINGLE_CONTEXT | CAP_INVEPT_ALL_CONTEXT, EptError::InveptUnsupported),
    ] {
        assert_eq!(check_support(SECONDARY_ALLOWS_EPT, FULL_CAP & !missing), Err(error));
    }
}

#[test]
fn table_entry_allows_everything() {
    assert_eq!(table_entry(0x7e00_1000), 0x7e00_1007);
}

#[test]
fn large_page_entry_is_rwx_write_back_2m() {
    // 0x7 RWX | 6 << 3 = 0x30 WB | 0x80 large page.
    assert_eq!(large_page_entry(0x4020_0000), 0x4020_00B7);
}

#[test]
fn read_only_page_entry_has_only_r() {
    assert_eq!(page_entry(0x7eb1_d000, EPT_READ), 0x7eb1_d031);
    assert_eq!(page_entry(0x7eb1_d000, EPT_RWX), 0x7eb1_d037);
}

#[test]
fn eptp_low_bits_are_write_back_and_4_levels() {
    assert_eq!(eptp(0x7e00_0000), 0x7e00_001E);
}

#[test]
fn indices_split_the_address() {
    let address = (3 << 39) | (5 << 30) | (7 << 21) | (9 << 12) | 0x123;
    assert_eq!(
        (pml4_index(address), pdpt_index(address), pd_index(address), pt_index(address)),
        (3, 5, 7, 9),
    );
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
    let past = MAX_IDENTITY_MAP + SIZE_4K;
    assert_eq!(
        identity_map_end([(MAX_IDENTITY_MAP, 1)].into_iter()),
        Err(EptError::RangeTooLarge { end: past }),
    );
}

#[test]
fn empty_memory_map_is_refused() {
    assert_eq!(identity_map_end(core::iter::empty()), Err(EptError::EmptyMemoryMap));
}

/// Fills a 2 GiB identity map with made-up table addresses and returns the
/// tables and the protected PT index.
fn filled(protected_page: u64) -> (Vec<u64>, Vec<u64>, Vec<u64>, Vec<u64>, usize) {
    let (mut pml4, mut pdpt, mut pds, mut pt) =
        (vec![0; ENTRIES], vec![0; ENTRIES], vec![0; 2 * ENTRIES], vec![0; ENTRIES]);
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
        2 * SIZE_1G,
        protected_page,
    );
    (pml4, pdpt, pds, pt, protected)
}

#[test]
fn identity_map_links_the_levels() {
    let (pml4, pdpt, _, _, _) = filled(0x7eb1_d000);
    assert_eq!(pml4[0], table_entry(0x1000));
    assert_eq!(pml4[1], 0);
    assert_eq!(pdpt[0], table_entry(0x2000));
    assert_eq!(pdpt[1], table_entry(0x3000));
    assert_eq!(pdpt[2], 0);
}

#[test]
fn identity_map_uses_2m_pages_outside_the_split_region() {
    let (_, _, pds, _, _) = filled(0x7eb1_d000);
    assert_eq!(pds[0], large_page_entry(0));
    assert_eq!(pds[1023], large_page_entry(1023 * SIZE_2M));
    // 0x7eb1_d000 is in the 2 MiB region 0x7ea0_0000, entry 0x3F5.
    assert_eq!(pds[0x3F5], table_entry(0x4000));
    assert_eq!(pds[0x3F4], large_page_entry(0x7e80_0000));
}

#[test]
fn identity_map_makes_only_the_protected_page_read_only() {
    let (_, _, _, pt, protected) = filled(0x7eb1_d000);
    assert_eq!(protected, 0x11D);
    assert_eq!(pt[0x11D], page_entry(0x7eb1_d000, EPT_READ));
    assert_eq!(pt[0x11C], page_entry(0x7eb1_c000, EPT_RWX));
    assert_eq!(pt[0], page_entry(0x7ea0_0000, EPT_RWX));
    assert_eq!(pt[511], page_entry(0x7ebf_f000, EPT_RWX));
}
