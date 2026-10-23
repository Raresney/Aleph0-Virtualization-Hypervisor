//! Unit tests for `src/vmx/ept.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::level::{Pd, Pdpt, Pml4, Pt};
use super::*;
use crate::vmx::mtrr::MemoryType::{Uncacheable as UC, WriteBack as WB, WriteProtected as WP};
use crate::vmx::mtrr::tests::{enabled, enabled_with_fixed, pc_fixed, range};

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
fn large_page_entry_is_rwx_2m_of_its_memory_type() {
    // 0x7 RWX | 6 << 3 = 0x30 WB | 0x80 large page.
    assert_eq!(EptEntry::large_page(0x4020_0000, WB), EptEntry::from_raw(0x4020_00B7));
    // UC is type 0: no type bits.
    assert_eq!(EptEntry::large_page(0xC000_0000, UC), EptEntry::from_raw(0xC000_0087));
}

#[test]
fn read_only_page_entry_has_only_r() {
    assert_eq!(
        EptEntry::page(0x7eb1_d000, EPT_READ, WB),
        EptEntry::from_raw(0x7eb1_d031)
    );
    assert_eq!(
        EptEntry::page(0x7eb1_d000, EPT_RWX, WB),
        EptEntry::from_raw(0x7eb1_d037)
    );
}

#[test]
fn page_entry_carries_its_memory_type_in_bits_5_to_3() {
    let write_combining = crate::vmx::mtrr::MemoryType::WriteCombining;
    assert_eq!(EptEntry::page(0xA_0000, EPT_RWX, UC), EptEntry::from_raw(0xA_0007));
    assert_eq!(
        EptEntry::page(0xA_0000, EPT_RWX, write_combining),
        EptEntry::from_raw(0xA_000F)
    );
}

#[test]
fn with_access_replaces_only_the_permission_bits() {
    let read_only = EptEntry::page(0x7eb1_d000, EPT_READ, WB);
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

/// MTRRs of a 2 GiB machine: WB up to 2 GiB, UC above (the default), a
/// 1 MiB UC hole at 0x7FF0_0000 (half of the 2 MiB region 0x7FE0_0000), and
/// a UC 2 MiB region at 0x4000_0000. No fixed ranges.
fn test_mtrrs() -> Mtrrs {
    Mtrrs::decode(
        enabled(UC),
        None,
        &[
            range(0, 2 * SIZE_1G, WB),
            range(0x7FF0_0000, 0x10_0000, UC),
            range(0x4000_0000, SIZE_2M, UC),
        ],
    )
    .unwrap()
}

/// The PML4, PDPT, PDs and PTs of an identity map.
type Tables4 = (
    Vec<EptEntry<Pml4>>,
    Vec<EptEntry<Pdpt>>,
    Vec<EptEntry<Pd>>,
    Vec<EptEntry<Pt>>,
);

/// Fills a 2 GiB identity map with [`test_mtrrs`] and one protected page:
/// see [`filled_pages`].
fn filled(protected_page: u64) -> (Tables4, usize) {
    filled_with(&test_mtrrs(), protected_page)
}

/// [`filled`] with a chosen `mtrrs`.
fn filled_with(mtrrs: &Mtrrs, protected_page: u64) -> (Tables4, usize) {
    let (tables, indices) = filled_pages(mtrrs, &[protected_page]);
    (tables, indices[0])
}

/// Fills a 2 GiB identity map with `mtrrs` and made-up table addresses (PDs
/// at 0x2000, PTs from 0x10_0000), and returns the tables and each protected
/// page's index in the PTs (only the first `protected_pages.len()` are
/// meaningful).
fn filled_pages(mtrrs: &Mtrrs, protected_pages: &[u64]) -> (Tables4, [usize; MAX_PROTECTED]) {
    let split = split_regions(mtrrs, 2, protected_pages);
    let (mut pml4, mut pdpt, mut pds, mut pts) = (
        vec![EptEntry::EMPTY; ENTRIES],
        vec![EptEntry::EMPTY; ENTRIES],
        vec![EptEntry::EMPTY; 2 * ENTRIES],
        vec![EptEntry::EMPTY; split * ENTRIES],
    );
    let protected = fill_identity_map(
        Tables {
            pml4: &mut pml4,
            pdpt: &mut pdpt,
            pds: &mut pds,
            pts: &mut pts,
            pdpt_address: 0x1000,
            pds_address: 0x2000,
            pts_address: 0x10_0000,
        },
        2,
        mtrrs,
        protected_pages,
    );
    ((pml4, pdpt, pds, pts), protected)
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
fn regions_of_one_memory_type_are_2m_pages_of_that_type() {
    let ((_, _, pds, _), _) = filled(0x7eb1_d000);
    assert_eq!(pds[0], EptEntry::large_page(0, WB));
    assert_eq!(pds[0x3F4], EptEntry::large_page(0x7e80_0000, WB));
    assert_eq!(pds[0x3FE], EptEntry::large_page(0x7FC0_0000, WB));
    // 0x4000_0000 is entry 0x200, the UC region.
    assert_eq!(pds[0x200], EptEntry::large_page(0x4000_0000, UC));
    assert_eq!(pds[0x201], EptEntry::large_page(0x4020_0000, WB));
}

#[test]
fn the_protected_region_and_mixed_regions_get_a_pt_each_in_address_order() {
    let mtrrs = test_mtrrs();
    assert_eq!(split_regions(&mtrrs, 2, &[0x7eb1_d000]), 2);
    let ((_, _, pds, _), _) = filled(0x7eb1_d000);
    // 0x7eb1_d000 is in the 2 MiB region 0x7ea0_0000, entry 0x3F5; the
    // mixed region 0x7FE0_0000 is entry 0x3FF.
    assert_eq!(pds[0x3F5], EptEntry::table(0x10_0000));
    assert_eq!(pds[0x3FF], EptEntry::table(0x10_1000));
}

#[test]
fn a_protected_page_in_a_mixed_region_needs_no_second_pt() {
    let mtrrs = test_mtrrs();
    assert_eq!(split_regions(&mtrrs, 2, &[0x7FE0_0000]), 1);
    let ((_, _, pds, pts), protected) = filled(0x7FE0_0000);
    assert_eq!(pds[0x3FF], EptEntry::table(0x10_0000));
    assert_eq!(protected, 0);
    assert_eq!(pts[0], EptEntry::page(0x7FE0_0000, EPT_READ, WB));
}

#[test]
fn identity_map_makes_only_the_protected_page_read_only() {
    let ((_, _, _, pts), protected) = filled(0x7eb1_d000);
    // The protected region's PT is the first one.
    assert_eq!(protected, 0x11D);
    assert_eq!(pts[0x11D], EptEntry::page(0x7eb1_d000, EPT_READ, WB));
    assert_eq!(pts[0x11C], EptEntry::page(0x7eb1_c000, EPT_RWX, WB));
    assert_eq!(pts[0], EptEntry::page(0x7ea0_0000, EPT_RWX, WB));
    assert_eq!(pts[511], EptEntry::page(0x7ebf_f000, EPT_RWX, WB));
}

#[test]
fn two_protected_pages_in_one_region_share_a_pt() {
    // The data page and a stack page one page after it, both in the 2 MiB
    // region 0x7ea0_0000: one PT, both entries read-only.
    let (data, stack) = (0x7eb1_d000, 0x7eb1_e000);
    assert_eq!(split_regions(&test_mtrrs(), 2, &[data, stack]), 2);
    let ((_, _, pds, pts), indices) = filled_pages(&test_mtrrs(), &[data, stack]);
    assert_eq!(pds[0x3F5], EptEntry::table(0x10_0000));
    assert_eq!(indices, [0x11D, 0x11E]);
    assert_eq!(pts[0x11D], EptEntry::page(data, EPT_READ, WB));
    assert_eq!(pts[0x11E], EptEntry::page(stack, EPT_READ, WB));
    assert_eq!(pts[0x11C], EptEntry::page(0x7eb1_c000, EPT_RWX, WB));
    assert_eq!(pts[0x11F], EptEntry::page(0x7eb1_f000, EPT_RWX, WB));
}

#[test]
fn two_protected_pages_in_different_regions_get_a_pt_each() {
    // The data page at 0x7eb1_d000 and a stack page in another large-page
    // region (0x1000_0000): three PTs (both regions, plus the mixed one),
    // assigned in address order.
    let (data, stack) = (0x7eb1_d000, 0x1000_0000);
    assert_eq!(split_regions(&test_mtrrs(), 2, &[data, stack]), 3);
    let ((_, _, pds, pts), indices) = filled_pages(&test_mtrrs(), &[data, stack]);
    // 0x1000_0000 (entry 0x80) comes first, then 0x7ea0_0000 (0x3F5), then
    // the mixed region 0x7FE0_0000 (0x3FF).
    assert_eq!(pds[0x80], EptEntry::table(0x10_0000));
    assert_eq!(pds[0x3F5], EptEntry::table(0x10_1000));
    assert_eq!(pds[0x3FF], EptEntry::table(0x10_2000));
    assert_eq!(indices, [ENTRIES + 0x11D, 0]);
    assert_eq!(pts[0], EptEntry::page(stack, EPT_READ, WB));
    assert_eq!(pts[ENTRIES + 0x11D], EptEntry::page(data, EPT_READ, WB));
    // Each region's other pages stay RWX.
    assert_eq!(pts[1], EptEntry::page(0x1000_1000, EPT_RWX, WB));
    assert_eq!(pts[ENTRIES + 0x11C], EptEntry::page(0x7eb1_c000, EPT_RWX, WB));
}

#[test]
fn a_mixed_region_maps_each_4k_page_with_its_own_type() {
    let ((_, _, _, pts), _) = filled(0x7eb1_d000);
    // The second PT maps 0x7FE0_0000: WB below the UC hole at 0x7FF0_0000.
    let pt = &pts[ENTRIES..];
    assert_eq!(pt[0], EptEntry::page(0x7FE0_0000, EPT_RWX, WB));
    assert_eq!(pt[255], EptEntry::page(0x7FEF_F000, EPT_RWX, WB));
    assert_eq!(pt[256], EptEntry::page(0x7FF0_0000, EPT_RWX, UC));
    assert_eq!(pt[511], EptEntry::page(0x7FFF_F000, EPT_RWX, UC));
}

#[test]
fn the_fixed_ranges_give_the_first_region_a_pt_of_their_types() {
    // The usual PC layout: WB RAM, the UC VGA window, WP ROMs below 1 MiB.
    let mtrrs = Mtrrs::decode(enabled_with_fixed(UC), Some(pc_fixed()), &[range(0, 2 * SIZE_1G, WB)]).unwrap();
    assert_eq!(split_regions(&mtrrs, 2, &[0x7eb1_d000]), 2);
    let ((_, _, pds, pts), protected) = filled_with(&mtrrs, 0x7eb1_d000);
    // Region 0 comes first in address order, so it takes the first PT.
    assert_eq!(pds[0], EptEntry::table(0x10_0000));
    assert_eq!(pds[1], EptEntry::large_page(SIZE_2M, WB));
    assert_eq!(pts[0x9F], EptEntry::page(0x9_F000, EPT_RWX, WB));
    assert_eq!(pts[0xA0], EptEntry::page(0xA_0000, EPT_RWX, UC));
    assert_eq!(pts[0xBF], EptEntry::page(0xB_F000, EPT_RWX, UC));
    assert_eq!(pts[0xC0], EptEntry::page(0xC_0000, EPT_RWX, WP));
    assert_eq!(pts[0xFF], EptEntry::page(0xF_F000, EPT_RWX, WP));
    // From 1 MiB on, the variable range again.
    assert_eq!(pts[0x100], EptEntry::page(0x10_0000, EPT_RWX, WB));
    // The protected page's region takes the second PT.
    assert_eq!(pds[0x3F5], EptEntry::table(0x10_1000));
    assert_eq!(protected, ENTRIES + 0x11D);
}

#[test]
fn without_mtrrs_the_map_is_all_write_back_with_one_pt() {
    // As before the MTRRs were read: only the protected region has a PT.
    assert_eq!(split_regions(&Mtrrs::Unsupported, 2, &[0x7eb1_d000]), 1);
    let ((_, _, pds, pts), protected) = filled_with(&Mtrrs::Unsupported, 0x7eb1_d000);
    for (i, entry) in pds.iter().enumerate() {
        let expected = if i == 0x3F5 {
            EptEntry::table(0x10_0000)
        } else {
            EptEntry::large_page(i as u64 * SIZE_2M, WB)
        };
        assert_eq!(*entry, expected, "PD entry {i:#x}");
    }
    assert_eq!(protected, 0x11D);
    for (j, page) in pts.iter().enumerate() {
        let access = if j == 0x11D { EPT_READ } else { EPT_RWX };
        let address = 0x7ea0_0000 + (j * PAGE_SIZE) as u64;
        assert_eq!(*page, EptEntry::page(address, access, WB), "PT entry {j:#x}");
    }
}

#[test]
fn pd_entries_read_back_how_they_map() {
    assert_eq!(
        EptEntry::<Pd>::large_page(0xC000_0000, UC).mapping(),
        RegionMapping::LargePage(UC)
    );
    assert_eq!(
        EptEntry::<Pd>::large_page(0, WB).mapping(),
        RegionMapping::LargePage(WB)
    );
    assert_eq!(EptEntry::<Pd>::table(0x10_0000).mapping(), RegionMapping::Pt);
    assert_eq!(EptEntry::<Pd>::EMPTY.mapping(), RegionMapping::Invalid);
    // RWX, large page, type 2: reserved, an EPT misconfiguration.
    assert_eq!(EptEntry::<Pd>::from_raw(0x97).mapping(), RegionMapping::Invalid);
    assert_eq!(RegionMapping::LargePage(WB).to_string(), "2 MiB pages, WB");
}

#[test]
fn region_runs_merge_pd_entries_that_map_alike() {
    let ((_, _, pds, _), _) = filled(0x7eb1_d000);
    let runs: Vec<_> = region_runs(&pds).map(|run| (run.start, run.end, run.mapping)).collect();
    assert_eq!(
        runs,
        [
            (0, 0x4000_0000, RegionMapping::LargePage(WB)),
            (0x4000_0000, 0x4020_0000, RegionMapping::LargePage(UC)),
            (0x4020_0000, 0x7EA0_0000, RegionMapping::LargePage(WB)),
            // The protected page's region.
            (0x7EA0_0000, 0x7EC0_0000, RegionMapping::Pt),
            (0x7EC0_0000, 0x7FE0_0000, RegionMapping::LargePage(WB)),
            // The region the 1 MiB UC hole splits.
            (0x7FE0_0000, 2 * SIZE_1G, RegionMapping::Pt),
        ]
    );
}

#[test]
fn only_published_invept_types_decode() {
    assert_eq!(decode_invept(0), None, "nothing published");
    assert_eq!(decode_invept(1), Some(InveptType::SingleContext));
    assert_eq!(decode_invept(2), Some(InveptType::AllContext));
    assert_eq!(decode_invept(3), None);
    assert_eq!(decode_invept(0xFF), None);
}
