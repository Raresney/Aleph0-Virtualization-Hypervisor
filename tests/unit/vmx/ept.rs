//! Unit tests for `src/vmx/ept.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::level::{Pd, Pdpt, Pml4, Pt};
use super::walk::WalkEnd;
use super::*;
use crate::vmx::guest::GUEST_MTRR_BASE;
use crate::vmx::mtrr::MemoryType::{Uncacheable as UC, WriteBack as WB, WriteProtected as WP};
use crate::vmx::mtrr::tests::{enabled, enabled_with_fixed, pc_fixed, range};
use crate::vmx::mtrr::{MtrrCapabilities, MtrrRegisters, MtrrState};

/// A secondary capability MSR that allows EPT and nothing else.
const EPT_ALLOWED: ControlCapability = ControlCapability((SECONDARY_ENABLE_EPT as u64) << 32);

/// The EPT/VPID capabilities Aleph0 needs: 4-level walk, WB, 2 MiB pages,
/// INVEPT with both types.
const FULL_CAP: u64 =
    CAP_WALK_LENGTH_4 | CAP_WRITE_BACK | CAP_2M_PAGES | CAP_INVEPT | CAP_INVEPT_SINGLE_CONTEXT | CAP_INVEPT_ALL_CONTEXT;

/// MAXPHYADDR on the Hyper-V test VM: CPUID 0x80000008 EAX 0x302e.
const HYPER_V_BITS: u8 = 46;

/// The INVEPT type [`check_support`] picks for `cap`.
fn invept_for(cap: u64) -> Result<InveptType, EptError> {
    check_support(EPT_ALLOWED, cap, HYPER_V_BITS).map(|support| support.invept)
}

#[test]
fn full_support_picks_single_context() {
    assert_eq!(invept_for(FULL_CAP), Ok(InveptType::SingleContext));
}

#[test]
fn all_context_is_the_fallback() {
    assert_eq!(
        invept_for(FULL_CAP & !CAP_INVEPT_SINGLE_CONTEXT),
        Ok(InveptType::AllContext)
    );
}

#[test]
fn the_rules_carry_maxphyaddr_and_whether_pdpt_entries_may_map_1_gib() {
    let rules = |cap| check_support(EPT_ALLOWED, cap, HYPER_V_BITS).map(|support| support.rules);
    assert_eq!(
        rules(FULL_CAP),
        Ok(EntryRules {
            physical_address_bits: HYPER_V_BITS,
            huge_pages: false,
            execute_only: false,
        })
    );
    assert_eq!(rules(FULL_CAP | CAP_1G_PAGES).map(|rules| rules.huge_pages), Ok(true));
    assert_eq!(
        rules(FULL_CAP | CAP_EXECUTE_ONLY).map(|rules| rules.execute_only),
        Ok(true)
    );
    // Hyper-V's IA32_VMX_EPT_VPID_CAP: bits 17 and 0 set.
    assert_eq!(
        rules(0x0000_0f01_06f3_4041).map(|rules| (rules.huge_pages, rules.execute_only)),
        Ok((true, true))
    );
}

#[test]
fn each_missing_capability_has_its_error() {
    assert_eq!(
        check_support(ControlCapability(0), FULL_CAP, HYPER_V_BITS),
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
        assert_eq!(invept_for(FULL_CAP & !missing), Err(error));
    }
}

#[test]
fn table_entry_allows_everything() {
    assert_eq!(EptEntry::<Pdpt>::table(0x7e00_1000), EptEntry::from_raw(0x7e00_1007));
}

#[test]
fn huge_page_entry_is_rwx_1g_of_its_memory_type() {
    // 0x7 RWX | 0x80 page size; UC is type 0: no type bits.
    assert_eq!(
        EptEntry::<Pdpt>::huge_page(0xC000_0000, UC),
        EptEntry::from_raw(0xC000_0087)
    );
    assert_eq!(
        EptEntry::<Pdpt>::huge_page(1 << 45, WB),
        EptEntry::from_raw((1 << 45) | 0xB7)
    );
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
    assert_eq!(memory_map_end(regions.into_iter()), Ok(4 * SIZE_1G));
}

#[test]
fn map_end_on_a_gib_boundary_is_not_rounded_further() {
    assert_eq!(memory_map_end([(0, 0x8_0000)].into_iter()), Ok(2 * SIZE_1G));
}

#[test]
fn a_region_past_the_top_of_the_address_space_ends_at_u64_max() {
    assert_eq!(memory_map_end([(u64::MAX - 0xFFF, 2)].into_iter()), Ok(u64::MAX));
    assert_eq!(memory_map_end([(0, u64::MAX)].into_iter()), Ok(u64::MAX));
}

#[test]
fn empty_memory_map_is_refused() {
    assert_eq!(memory_map_end(core::iter::empty()), Err(EptError::EmptyMemoryMap));
    assert_eq!(memory_map_end([(0, 0)].into_iter()), Err(EptError::EmptyMemoryMap));
}

/// The rules of a CPU with `bits` of physical address, with 1 GiB EPT
/// pages or without.
fn rules(bits: u8, huge_pages: bool) -> EntryRules {
    EntryRules {
        physical_address_bits: bits,
        huge_pages,
        execute_only: false,
    }
}

#[test]
fn the_address_space_ends_at_maxphyaddr_or_where_a_4_level_walk_stops() {
    assert_eq!(address_space_end(36), 1 << 36);
    assert_eq!(address_space_end(HYPER_V_BITS), 1 << 46);
    assert_eq!(address_space_end(48), 1 << 48);
    assert_eq!(address_space_end(52), 1 << 48);
}

#[test]
fn with_1_gib_pages_the_map_reaches_maxphyaddr_with_pds_for_the_memory_map() {
    // The Hyper-V test VM: 2 GiB of memory map, 46 bits.
    let layout = MapLayout::new(2 * SIZE_1G, rules(HYPER_V_BITS, true)).unwrap();
    assert_eq!(layout.pd_gibs(), 2);
    assert_eq!(layout.pd_end(), 2 * SIZE_1G);
    assert_eq!(layout.end(), 1 << 46);
    assert_eq!(layout.huge_gibs(), (1 << 16) - 2);
    assert_eq!(layout.pdpts(), 128);
    // 52 bits: the 4-level walk stops at 48, 512 PDPTs.
    let layout = MapLayout::new(2 * SIZE_1G, rules(52, true)).unwrap();
    assert_eq!((layout.end(), layout.pdpts()), (1 << 48, 512));
    // 36 bits, the smallest: one PDPT, partly filled.
    let layout = MapLayout::new(2 * SIZE_1G, rules(36, true)).unwrap();
    assert_eq!((layout.end(), layout.pdpts(), layout.huge_gibs()), (1 << 36, 1, 62));
}

#[test]
fn without_1_gib_pages_the_pds_reach_the_memory_map_or_4_gib_and_no_further() {
    let layout = MapLayout::new(2 * SIZE_1G, rules(HYPER_V_BITS, false)).unwrap();
    assert_eq!(
        (layout.pd_gibs(), layout.end(), layout.huge_gibs()),
        (4, 4 * SIZE_1G, 0)
    );
    let layout = MapLayout::new(8 * SIZE_1G, rules(HYPER_V_BITS, false)).unwrap();
    assert_eq!((layout.pd_gibs(), layout.end()), (8, 8 * SIZE_1G));
    assert_eq!(layout.pdpts(), 1);
}

#[test]
fn a_memory_map_past_the_address_space_is_refused() {
    for huge_pages in [false, true] {
        assert_eq!(
            MapLayout::new(1 << 37, rules(36, huge_pages)),
            Err(EptError::RangeTooLarge {
                end: 1 << 37,
                limit: 1 << 36
            })
        );
        assert_eq!(
            MapLayout::new(u64::MAX, rules(HYPER_V_BITS, huge_pages)),
            Err(EptError::RangeTooLarge {
                end: u64::MAX,
                limit: 1 << 46
            })
        );
    }
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

/// A map of `gibs` GiB, all of them through a PD: the layout of the 2 GiB
/// tests, which look at the part of the map the memory map reaches.
fn pds_only(gibs: usize) -> MapLayout {
    MapLayout { pd_gibs: gibs, gibs }
}

/// The PML4, PDPTs, PDs and PTs of an identity map.
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

/// All of memory RAM: the memory types are the MTRRs' alone.
const ALL_RAM: RamMap<'static> = RamMap {
    ranges: &[(0, u64::MAX)],
};

/// The EPT types of `mtrrs` with all memory RAM.
fn all_ram(mtrrs: &Mtrrs) -> EptTypes<'_> {
    EptTypes { mtrrs, ram: ALL_RAM }
}

/// Fills a 2 GiB identity map with `mtrrs`, all of it RAM: see
/// [`filled_with_ram`].
fn filled_with(mtrrs: &Mtrrs, protected_page: u64) -> (Tables4, usize) {
    filled_with_ram(&all_ram(mtrrs), protected_page)
}

/// Fills a 2 GiB identity map with `types` and made-up table addresses (PDs
/// at 0x2000, PTs from 0x10_0000), and returns the tables and the protected
/// page's index in the PTs.
fn filled_with_ram(types: &EptTypes<'_>, protected_page: u64) -> (Tables4, usize) {
    filled_as(pds_only(2), types, protected_page)
}

/// Fills a 2 GiB identity map with `mtrrs`, all of it RAM, and one or two
/// protected pages, and returns the tables and each protected page's index
/// in the PTs (only the first `protected_pages.len()` are meaningful).
fn filled_pages(mtrrs: &Mtrrs, protected_pages: &[u64]) -> (Tables4, [usize; MAX_PROTECTED]) {
    filled_as_pages(pds_only(2), &all_ram(mtrrs), protected_pages)
}

/// Fills an identity map laid out as `layout` with `types` and made-up
/// table addresses (PDPTs from 0x1000, the PDs right after them, PTs from
/// 0x10_0000), and returns the tables and the protected page's index in
/// the PTs.
fn filled_as(layout: MapLayout, types: &EptTypes<'_>, protected_page: u64) -> (Tables4, usize) {
    let (tables, indices) = filled_as_pages(layout, types, &[protected_page]);
    (tables, indices[0])
}

/// [`filled_as`] with one or two protected pages, returning each one's index
/// in the PTs (only the first `protected_pages.len()` are meaningful).
fn filled_as_pages(
    layout: MapLayout,
    types: &EptTypes<'_>,
    protected_pages: &[u64],
) -> (Tables4, [usize; MAX_PROTECTED]) {
    let split = split_regions(types, layout.pd_gibs(), protected_pages);
    let (mut pml4, mut pdpts, mut pds, mut pts) = (
        vec![EptEntry::EMPTY; ENTRIES],
        vec![EptEntry::EMPTY; layout.pdpts() * ENTRIES],
        vec![EptEntry::EMPTY; layout.pd_gibs() * ENTRIES],
        vec![EptEntry::EMPTY; split * ENTRIES],
    );
    let protected = fill_identity_map(
        Tables {
            pml4: &mut pml4,
            pdpts: &mut pdpts,
            pds: &mut pds,
            pts: &mut pts,
            pdpts_address: 0x1000,
            pds_address: 0x1000 + (layout.pdpts() * PAGE_SIZE) as u64,
            pts_address: 0x10_0000,
        },
        layout,
        types,
        protected_pages,
    );
    ((pml4, pdpts, pds, pts), protected)
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
    assert_eq!(split_regions(&all_ram(&mtrrs), 2, &[0x7eb1_d000]), 2);
    let ((_, _, pds, _), _) = filled(0x7eb1_d000);
    // 0x7eb1_d000 is in the 2 MiB region 0x7ea0_0000, entry 0x3F5; the
    // mixed region 0x7FE0_0000 is entry 0x3FF.
    assert_eq!(pds[0x3F5], EptEntry::table(0x10_0000));
    assert_eq!(pds[0x3FF], EptEntry::table(0x10_1000));
}

#[test]
fn a_protected_page_in_a_mixed_region_needs_no_second_pt() {
    let mtrrs = test_mtrrs();
    assert_eq!(split_regions(&all_ram(&mtrrs), 2, &[0x7FE0_0000]), 1);
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
    let mtrrs = test_mtrrs();
    assert_eq!(split_regions(&all_ram(&mtrrs), 2, &[data, stack]), 2);
    let ((_, _, pds, pts), indices) = filled_pages(&mtrrs, &[data, stack]);
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
    let mtrrs = test_mtrrs();
    assert_eq!(split_regions(&all_ram(&mtrrs), 2, &[data, stack]), 3);
    let ((_, _, pds, pts), indices) = filled_pages(&mtrrs, &[data, stack]);
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
    assert_eq!(split_regions(&all_ram(&mtrrs), 2, &[0x7eb1_d000]), 2);
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
    assert_eq!(split_regions(&all_ram(&Mtrrs::Unsupported), 2, &[0x7eb1_d000]), 1);
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
    let runs: Vec<_> = region_runs(&pds, 0)
        .map(|run| (run.start, run.end, run.mapping))
        .collect();
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

#[test]
fn with_memory_type_keeps_the_address_and_the_access() {
    let read_only = EptEntry::page(0x7eb1_d000, EPT_READ, WB);
    assert_eq!(
        read_only.with_memory_type(UC),
        EptEntry::page(0x7eb1_d000, EPT_READ, UC)
    );
    let writable = EptEntry::page(0x7eb1_d000, EPT_READ | EPT_WRITE, UC);
    assert_eq!(
        writable.with_memory_type(WP),
        EptEntry::page(0x7eb1_d000, EPT_READ | EPT_WRITE, WP)
    );
}

#[test]
fn region_runs_count_regions_from_the_first_entry_given() {
    let ((_, _, pds, _), _) = filled(0x7eb1_d000);
    // Entries 0x1FF..=0x201: WB, then the UC region at 0x4000_0000, then WB.
    let runs: Vec<_> = region_runs(&pds[0x1FF..0x202], 0x1FF)
        .map(|run| (run.start, run.end, run.mapping))
        .collect();
    assert_eq!(
        runs,
        [
            (0x3FE0_0000, 0x4000_0000, RegionMapping::LargePage(WB)),
            (0x4000_0000, 0x4020_0000, RegionMapping::LargePage(UC)),
            (0x4020_0000, 0x4040_0000, RegionMapping::LargePage(WB)),
        ]
    );
}

#[test]
fn spare_pts_cover_each_variable_range_and_the_fixed_ranges() {
    assert_eq!(spare_pts(MtrrCapabilities::NONE), 0);
    // Hyper-V: eight variable ranges and the fixed ones.
    assert_eq!(spare_pts(MtrrCapabilities::new((1 << 8) | 8, 46).unwrap()), 9);
    assert_eq!(spare_pts(MtrrCapabilities::new(10, 46).unwrap()), 10);
}

#[test]
fn the_free_stack_hands_out_the_spare_pts_in_address_order() {
    let mut stack = [0; 5];
    let mut len = fill_free_stack(&mut stack, 2);
    assert_eq!(len, 3);
    let mut free = FreePts {
        stack: &mut stack,
        len: &mut len,
    };
    assert_eq!(
        [free.take(), free.take(), free.take(), free.take()],
        [Some(2), Some(3), Some(4), None]
    );
    free.give_back(3);
    assert_eq!(free.take(), Some(3));
}

#[test]
fn a_pd_entry_names_its_pt_by_index() {
    let pts = 0x10_0000;
    assert_eq!(pt_index(EptEntry::table(pts), pts, 3), Some(0));
    assert_eq!(pt_index(EptEntry::table(pts + 0x2000), pts, 3), Some(2));
    assert_eq!(pt_index(EptEntry::table(pts + 0x3000), pts, 3), None);
    assert_eq!(pt_index(EptEntry::table(pts - 0x1000), pts, 3), None);
}

/// Where [`TypeMap`] puts its PTs.
const PTS_ADDRESS: u64 = 0x10_0000;
/// The protected page of the [`TypeMap`] tests: in region 0x3F5
/// (0x7EA0_0000), at index 0x11D of its PT.
const PROTECTED: u64 = 0x7eb1_d000;

/// A 2 GiB identity map as [`Ept::build`] leaves it, with the free stack
/// that [`TypeTables`] keeps, on vectors.
struct TypeMap {
    pds: Vec<EptEntry<Pd>>,
    /// Every PT, the spare ones last.
    pts: Vec<EptEntry<Pt>>,
    free: Vec<u32>,
    free_len: usize,
    ram: RamMap<'static>,
}

impl TypeMap {
    /// The map `mtrrs` give, all of it RAM, with [`PROTECTED`] read-only and
    /// `spare` PTs set aside.
    fn new(mtrrs: &Mtrrs, spare: usize) -> Self {
        Self::with_ram(mtrrs, spare, ALL_RAM)
    }

    /// [`new`](Self::new), with `ram` the only RAM.
    fn with_ram(mtrrs: &Mtrrs, spare: usize, ram: RamMap<'static>) -> Self {
        let types = EptTypes { mtrrs, ram };
        let split = split_regions(&types, 2, &[PROTECTED]);
        let mut pml4 = vec![EptEntry::EMPTY; ENTRIES];
        let mut pdpts = vec![EptEntry::EMPTY; ENTRIES];
        let mut pds = vec![EptEntry::EMPTY; 2 * ENTRIES];
        let mut pts = vec![EptEntry::EMPTY; (split + spare) * ENTRIES];
        fill_identity_map(
            Tables {
                pml4: &mut pml4,
                pdpts: &mut pdpts,
                pds: &mut pds,
                pts: &mut pts[..split * ENTRIES],
                pdpts_address: 0x1000,
                pds_address: 0x2000,
                pts_address: PTS_ADDRESS,
            },
            pds_only(2),
            &types,
            &[PROTECTED],
        );
        let mut free = vec![0; split + spare];
        let free_len = fill_free_stack(&mut free, split);
        Self {
            pds,
            pts,
            free,
            free_len,
            ram,
        }
    }

    /// Gives the map the types of `mtrrs` for its RAM, as
    /// [`TypeTables::apply`] does before its INVEPT.
    fn retype(&mut self, mtrrs: &Mtrrs) -> Retyped {
        let (pts, _) = self.pts.as_chunks_mut::<ENTRIES>();
        let mut tables = Retype {
            pds: &mut self.pds,
            pts,
            pts_address: PTS_ADDRESS,
            free: FreePts {
                stack: &mut self.free,
                len: &mut self.free_len,
            },
            protected_regions: [(PROTECTED / SIZE_2M) as usize, usize::MAX],
        };
        retype(&mut tables, &EptTypes { mtrrs, ram: self.ram })
    }

    /// PT number `index`.
    fn pt(&self, index: usize) -> &[EptEntry<Pt>] {
        &self.pts[index * ENTRIES..][..ENTRIES]
    }

    /// Hides one page, redirecting it to `shadow`, as [`TypeTables::hide`]
    /// does for each of Aleph0's pages.
    fn hide(&mut self, page: u64, shadow: u64, code: bool) -> Hidden {
        let (pts, _) = self.pts.as_chunks_mut::<ENTRIES>();
        let mtrrs = all_write_back();
        let mut tables = Hiding {
            pds: &mut self.pds,
            pts,
            free: FreePts {
                stack: &mut self.free,
                len: &mut self.free_len,
            },
            pts_address: PTS_ADDRESS,
            shadow,
            types: EptTypes {
                mtrrs: &mtrrs,
                ram: self.ram,
            },
        };
        let mut hidden = Hidden::default();
        hide_page(&mut tables, page, code, &mut hidden).unwrap();
        hidden
    }
}

/// A 2 GiB machine: all of it WB, the default UC above.
fn all_write_back() -> Mtrrs {
    Mtrrs::decode(enabled(UC), None, &[range(0, 2 * SIZE_1G, WB)]).unwrap()
}

/// [`all_write_back`] with variable ranges `more` added after the first.
fn write_back_with(more: &[(u64, u64)]) -> Mtrrs {
    let mut variable = vec![range(0, 2 * SIZE_1G, WB)];
    variable.extend_from_slice(more);
    Mtrrs::decode(enabled(UC), None, &variable).unwrap()
}

#[test]
fn the_same_types_change_nothing() {
    let mut map = TypeMap::new(&test_mtrrs(), 1);
    let (pds, pts) = (map.pds.clone(), map.pts.clone());
    assert_eq!(map.retype(&test_mtrrs()), Retyped::default());
    assert_eq!((map.pds, map.pts, map.free_len), (pds, pts, 1));
}

#[test]
fn a_region_of_one_type_changes_only_its_type_bits() {
    let mut map = TypeMap::new(&all_write_back(), 1);
    let before = map.pds.clone();
    let retyped = map.retype(&write_back_with(&[range(SIZE_2M, SIZE_2M, UC)]));
    assert_eq!(
        retyped,
        Retyped {
            regions: 1,
            span: Some((SIZE_2M, 2 * SIZE_2M)),
            ..Retyped::default()
        }
    );
    assert_eq!(map.pds[1], EptEntry::large_page(SIZE_2M, UC));
    // WB is 6 in bits 5:3, UC 0: nothing else in the entry differs.
    assert_eq!(map.pds[1].raw ^ before[1].raw, 6 << 3);
    for (i, (after, before)) in map.pds.iter().zip(&before).enumerate().filter(|&(i, _)| i != 1) {
        assert_eq!(after, before, "PD entry {i:#x}");
    }
}

#[test]
fn a_region_that_comes_to_mix_types_takes_a_spare_pt() {
    let mut map = TypeMap::new(&all_write_back(), 2);
    // One PT at build, the protected page's; the spare ones are 1 and 2.
    let retyped = map.retype(&write_back_with(&[range(SIZE_2M, 0x1000, UC)]));
    assert_eq!((retyped.regions, retyped.split, retyped.merged), (1, 1, 0));
    assert_eq!(map.pds[1], EptEntry::table(PTS_ADDRESS + 0x1000));
    assert_eq!(map.free_len, 1);
    let pt = map.pt(1);
    assert_eq!(pt[0], EptEntry::page(SIZE_2M, EPT_RWX, UC));
    assert_eq!(pt[1], EptEntry::page(SIZE_2M + 0x1000, EPT_RWX, WB));
    assert_eq!(pt[511], EptEntry::page(2 * SIZE_2M - 0x1000, EPT_RWX, WB));
}

#[test]
fn a_region_of_one_type_again_gives_its_pt_back() {
    let mut map = TypeMap::new(&all_write_back(), 2);
    map.retype(&write_back_with(&[range(SIZE_2M, 0x1000, UC)]));
    let retyped = map.retype(&all_write_back());
    assert_eq!((retyped.regions, retyped.split, retyped.merged), (1, 0, 1));
    assert_eq!(map.pds[1], EptEntry::large_page(SIZE_2M, WB));
    assert_eq!(map.free_len, 2);
    // The PT given back is the next one taken.
    map.retype(&write_back_with(&[range(3 * SIZE_2M, 0x1000, UC)]));
    assert_eq!(map.pds[3], EptEntry::table(PTS_ADDRESS + 0x1000));
}

/// A shadow HPA for the hiding tests: page-aligned, outside the 2 GiB map.
const SHADOW: u64 = 0xDEAD_0000;

#[test]
fn hiding_a_page_splits_its_region_and_redirects_it_to_the_shadow() {
    // One spare PT, which `hide` takes to split the region (index 1: index 0
    // is the protected page's PT).
    let mut map = TypeMap::new(&all_write_back(), 1);
    let region = 2 * SIZE_2M;
    let page = region + 5 * 0x1000;
    assert_eq!(map.pds[2], EptEntry::large_page(region, WB));

    let hidden = map.hide(page, SHADOW, false);
    assert_eq!((hidden.data_pages, hidden.regions_split), (1, 1));
    // The region is now a PT; the hidden page points at the shadow,
    // read-write; its neighbours keep their real identity mappings.
    assert_eq!(map.pds[2], EptEntry::table(PTS_ADDRESS + PAGE_SIZE as u64));
    assert_eq!(map.pt(1)[5], EptEntry::page(SHADOW, EPT_READ | EPT_WRITE, WB));
    assert_eq!(map.pt(1)[0], EptEntry::page(region, EPT_RWX, WB));
    assert_eq!(map.free_len, 0);
}

#[test]
fn a_hidden_code_page_is_kept_read_only_and_executable() {
    let mut map = TypeMap::new(&all_write_back(), 1);
    let page = 2 * SIZE_2M + 5 * 0x1000;
    let hidden = map.hide(page, SHADOW, true);
    assert_eq!((hidden.code_pages, hidden.regions_split), (1, 1));
    // Kept at its own address so the guest can still execute it (the
    // ExitBootServices callback), read-only so it cannot be rewritten.
    assert_eq!(map.pt(1)[5], EptEntry::page(page, EPT_READ | EPT_EXECUTE, WB));
}

#[test]
fn a_hidden_region_is_never_collapsed_by_retype() {
    let mut map = TypeMap::new(&all_write_back(), 1);
    let region = 2 * SIZE_2M;
    map.hide(region + 5 * 0x1000, SHADOW, false);

    // Region 2 is uniform WB, so retype would normally fold its PT back into
    // one 2 MiB page; the redirect's non-RWX access pins it as a PT, so the
    // hidden page is never re-exposed.
    let retyped = map.retype(&all_write_back());
    assert_eq!(retyped.merged, 0);
    assert_eq!(map.pds[2], EptEntry::table(PTS_ADDRESS + PAGE_SIZE as u64));
    assert_eq!(map.pt(1)[5], EptEntry::page(SHADOW, EPT_READ | EPT_WRITE, WB));
}

#[test]
fn the_protected_region_keeps_its_pt_and_its_access() {
    let mut map = TypeMap::new(&all_write_back(), 0);
    let region = PROTECTED & !(SIZE_2M - 1);
    let retyped = map.retype(&write_back_with(&[range(region, SIZE_2M, UC)]));
    assert_eq!((retyped.regions, retyped.split, retyped.merged), (1, 0, 0));
    assert_eq!(map.pds[0x3F5], EptEntry::table(PTS_ADDRESS));
    assert_eq!(map.pt(0)[0x11D], EptEntry::page(PROTECTED, EPT_READ, UC));
    assert_eq!(map.pt(0)[0], EptEntry::page(region, EPT_RWX, UC));
    // Once its write is granted, the page stays writable through a retype.
    map.pts[0x11D] = map.pts[0x11D].with_access(EPT_READ | EPT_WRITE);
    map.retype(&all_write_back());
    assert_eq!(map.pt(0)[0x11D], EptEntry::page(PROTECTED, EPT_READ | EPT_WRITE, WB));
}

#[test]
fn without_a_spare_pt_a_mixed_region_is_one_uc_page() {
    let mut map = TypeMap::new(&all_write_back(), 0);
    let retyped = map.retype(&write_back_with(&[range(SIZE_2M, 0x1000, UC)]));
    assert_eq!((retyped.regions, retyped.split, retyped.uncached), (1, 0, 1));
    assert_eq!(map.pds[1], EptEntry::large_page(SIZE_2M, UC));
    // Back to one type: WB again, nothing left UC.
    let retyped = map.retype(&all_write_back());
    assert_eq!((retyped.regions, retyped.uncached), (1, 0));
    assert_eq!(map.pds[1], EptEntry::large_page(SIZE_2M, WB));
}

#[test]
fn a_pt_given_back_is_taken_by_a_region_below_it_in_the_same_retype() {
    // Built with region 3 mixed, so it has a PT, and no spare one.
    let mut map = TypeMap::new(&write_back_with(&[range(3 * SIZE_2M, 0x1000, UC)]), 0);
    // The small range moves down to region 1, which comes first in address
    // order but takes region 3's PT: the first one, as region 3 comes before
    // the protected page's.
    let retyped = map.retype(&write_back_with(&[range(SIZE_2M, 0x1000, UC)]));
    assert_eq!((retyped.split, retyped.merged, retyped.uncached), (1, 1, 0));
    assert_eq!((retyped.regions, retyped.span), (2, Some((SIZE_2M, 4 * SIZE_2M))));
    assert_eq!(map.pds[1], EptEntry::table(PTS_ADDRESS));
    assert_eq!(map.pds[3], EptEntry::large_page(3 * SIZE_2M, WB));
    assert_eq!(map.pt(0)[0], EptEntry::page(SIZE_2M, EPT_RWX, UC));
    assert_eq!(map.pt(0)[1], EptEntry::page(SIZE_2M + 0x1000, EPT_RWX, WB));
    assert_eq!(map.free_len, 0);
}

#[test]
fn a_region_left_uc_gets_a_pt_from_the_next_retype_that_gives_one_back() {
    // Built with region 3 mixed, so it has a PT, and no spare one.
    let mut map = TypeMap::new(&write_back_with(&[range(3 * SIZE_2M, 0x1000, UC)]), 0);
    // Region 1 mixes too while region 3 keeps its PT: UC for now.
    let retyped = map.retype(&write_back_with(&[
        range(SIZE_2M, 0x1000, UC),
        range(3 * SIZE_2M, 0x1000, UC),
    ]));
    assert_eq!((retyped.split, retyped.merged, retyped.uncached), (0, 0, 1));
    assert_eq!(map.pds[1], EptEntry::large_page(SIZE_2M, UC));
    // Region 3 is one type again: its PT goes to region 1.
    let retyped = map.retype(&write_back_with(&[range(SIZE_2M, 0x1000, UC)]));
    assert_eq!((retyped.split, retyped.merged, retyped.uncached), (1, 1, 0));
    assert_eq!(map.pds[1], EptEntry::table(PTS_ADDRESS));
    assert_eq!(map.pt(0)[0], EptEntry::page(SIZE_2M, EPT_RWX, UC));
}

#[test]
fn disabling_the_mtrrs_makes_everything_uc_and_enabling_them_restores_the_map() {
    let mut map = TypeMap::new(&test_mtrrs(), 1);
    let retyped = map.retype(&Mtrrs::Disabled);
    // Every region but the protected one is a UC 2 MiB page; the mixed one
    // at 0x7FE0_0000 gave its PT back.
    assert_eq!(retyped.merged, 1);
    assert_eq!(map.free_len, 2);
    for (i, entry) in map.pds.iter().enumerate().filter(|&(i, _)| i != 0x3F5) {
        assert_eq!(*entry, EptEntry::large_page(i as u64 * SIZE_2M, UC), "PD entry {i:#x}");
    }
    assert!(map.pt(0).iter().all(|page| page.with_memory_type(UC) == *page));
    // Setting E again gives back exactly the map bring-up built.
    map.retype(&test_mtrrs());
    let built = TypeMap::new(&test_mtrrs(), 1);
    assert_eq!((map.pds, map.pts, map.free_len), (built.pds, built.pts, 1));
}

#[test]
fn the_spare_pts_cover_a_small_range_in_every_variable_range() {
    // Fixed ranges mixing the first 2 MiB, and eight 4 KiB UC ranges in
    // eight other regions: the most regions contiguous masks can split.
    let mut small: Vec<_> = (0..7).map(|n| range((2 + 2 * n) * SIZE_2M, 0x1000, UC)).collect();
    small.insert(0, range(0, 2 * SIZE_1G, WB));
    let mtrrs = Mtrrs::decode(enabled_with_fixed(UC), Some(pc_fixed()), &small).unwrap();
    let mut map = TypeMap::new(
        &all_write_back(),
        spare_pts(MtrrCapabilities::new((1 << 8) | 8, 39).unwrap()),
    );
    let retyped = map.retype(&mtrrs);
    assert_eq!((retyped.split, retyped.uncached), (8, 0));
    assert_eq!(retyped.span, Some((0, 15 * SIZE_2M)));
}

#[test]
fn the_fixed_ranges_retype_the_first_region_page_by_page() {
    let pc = Mtrrs::decode(enabled_with_fixed(UC), Some(pc_fixed()), &[range(0, 2 * SIZE_1G, WB)]).unwrap();
    let mut map = TypeMap::new(&pc, 0);
    // The VGA window becomes WB too: the first region stays mixed (WP ROMs).
    let mut fixed = pc_fixed();
    fixed[2] = u64::from_le_bytes([WB.raw() as u8; 8]);
    let vga_wb = Mtrrs::decode(enabled_with_fixed(UC), Some(fixed), &[range(0, 2 * SIZE_1G, WB)]).unwrap();
    let retyped = map.retype(&vga_wb);
    assert_eq!(retyped.span, Some((0, SIZE_2M)));
    assert_eq!(map.pds[0], EptEntry::table(PTS_ADDRESS));
    assert_eq!(map.pt(0)[0xA0], EptEntry::page(0xA_0000, EPT_RWX, WB));
    assert_eq!(map.pt(0)[0xC0], EptEntry::page(0xC_0000, EPT_RWX, WP));
}

#[test]
fn the_span_runs_from_the_first_changed_region_to_the_last() {
    let mut map = TypeMap::new(&all_write_back(), 0);
    let retyped = map.retype(&write_back_with(&[
        range(SIZE_2M, SIZE_2M, UC),
        range(0x4000_0000, SIZE_2M, UC),
    ]));
    assert_eq!(retyped.regions, 2);
    assert_eq!(retyped.span, Some((SIZE_2M, 0x4020_0000)));
}

#[test]
fn the_test_guests_mtrr_writes_retype_the_region_at_2_mib_and_put_it_back() {
    // Hyper-V's MTRRs (docs/MTRR.md section 6): default UC, the fixed
    // ranges WB below 0xA0000 and UC above, range 0 the first 4 GiB WB.
    let capabilities = MtrrCapabilities::new((1 << 8) | 8, 46).unwrap();
    let registers = MtrrRegisters::read_with(capabilities, |msr| match msr.address() {
        0x2FF => 0xC00,
        0x250 | 0x258 => 0x0606_0606_0606_0606,
        0x200 => 6,
        0x201 => 0x3FFF_0000_0800,
        _ => 0,
    })
    .unwrap();
    let mut state = MtrrState::new(registers).unwrap();
    let mut map = TypeMap::new(state.mtrrs(), spare_pts(capabilities));
    let built = TypeMap::new(state.mtrrs(), spare_pts(capabilities));
    // The guest's WRMSRs to its last variable range (7), in order: whether
    // they change any type, and how the region at 2 MiB is mapped after.
    for (address, value, changed, mapping) in [
        (0x20F, 0, false, RegionMapping::LargePage(WB)),
        (0x20E, GUEST_MTRR_BASE, false, RegionMapping::LargePage(WB)),
        (0x20F, 0x3FFF_FFE0_0800, true, RegionMapping::LargePage(UC)),
        (0x20F, 0x3FFF_FFFF_F800, true, RegionMapping::Pt),
        (0x20F, 0, true, RegionMapping::LargePage(WB)),
        (0x20E, 0, false, RegionMapping::LargePage(WB)),
        (0x20F, 0, false, RegionMapping::LargePage(WB)),
    ] {
        let msr = capabilities.msr(address).unwrap();
        assert_eq!(state.write(msr, value), Ok(changed), "{msr} <- {value:#x}");
        if changed {
            let retyped = map.retype(state.mtrrs());
            assert_eq!(retyped.span, Some((SIZE_2M, 2 * SIZE_2M)), "{msr} <- {value:#x}");
        }
        assert_eq!(map.pds[1].mapping(), mapping, "{msr} <- {value:#x}");
    }
    // As bring-up built it: the PT the 4 KiB range took is spare again.
    assert_eq!((map.pds, map.free_len), (built.pds, built.free_len));
}

#[test]
fn only_memory_the_firmware_or_an_os_uses_as_memory_is_ram() {
    use boot::MemoryType as Type;
    for ram in [
        Type::LOADER_CODE,
        Type::LOADER_DATA,
        Type::BOOT_SERVICES_CODE,
        Type::BOOT_SERVICES_DATA,
        Type::RUNTIME_SERVICES_CODE,
        Type::RUNTIME_SERVICES_DATA,
        Type::CONVENTIONAL,
        Type::ACPI_RECLAIM,
        Type::ACPI_NON_VOLATILE,
        Type::PERSISTENT_MEMORY,
    ] {
        assert!(is_ram(ram), "{ram:?}");
    }
    for other in [
        Type::RESERVED,
        Type::UNUSABLE,
        Type::MMIO,
        Type::MMIO_PORT_SPACE,
        Type::PAL_CODE,
        Type::UNACCEPTED,
        Type::custom(0x8000_0000),
    ] {
        assert!(!is_ram(other), "{other:?}");
    }
}

#[test]
fn the_ram_map_sorts_and_merges_the_ram_regions_and_drops_the_rest() {
    use boot::MemoryType as Type;
    let regions = [
        (0x10_0000, 0x100, Type::BOOT_SERVICES_DATA),
        (0, 0xA0, Type::CONVENTIONAL),
        // Touches the first region: one range with it.
        (0x20_0000, 0x200, Type::LOADER_DATA),
        (0xFEC0_0000, 1, Type::MMIO),
        (0x5000_0000, 0x10, Type::RESERVED),
        // Empty: ignored.
        (0x30_0000, 0, Type::CONVENTIONAL),
        // Overlaps the range the first and third make: merged into it.
        (0x38_0000, 0x100, Type::ACPI_NON_VOLATILE),
    ];
    let mut ranges = [(0, 0); 7];
    let ram = RamMap::collect(regions.into_iter(), &mut ranges);
    assert_eq!(ram.ranges(), [(0, 0xA_0000), (0x10_0000, 0x48_0000)]);
}

#[test]
fn the_ram_map_says_how_much_of_a_block_is_ram() {
    let ram = RamMap {
        ranges: &[(0, 0xA_0000), (0x10_0000, 0x7FF0_0000)],
    };
    assert!(ram.contains(0x9_F000));
    assert!(!ram.contains(0xA_0000));
    assert!(ram.contains(0x10_0000));
    assert!(!ram.contains(0x7FF0_0000));
    assert_eq!(ram.coverage(0, SIZE_2M), RamCoverage::Part);
    assert_eq!(ram.coverage(SIZE_2M, SIZE_2M), RamCoverage::All);
    assert_eq!(ram.coverage(0x7FC0_0000, SIZE_2M), RamCoverage::All);
    assert_eq!(ram.coverage(0x7FE0_0000, SIZE_2M), RamCoverage::Part);
    assert_eq!(ram.coverage(0x8000_0000, SIZE_2M), RamCoverage::None);
    // A block inside the gap between two ranges.
    assert_eq!(ram.coverage(0xA_0000, 0x1000), RamCoverage::None);
}

/// RAM below 1.5 GiB but for the legacy hole at 0xA0000..0x100000, as a
/// memory map with holes gives it; nothing above it in the 2 GiB of the
/// [`TypeMap`] tests, the protected page included.
const RAM_BELOW_1536_MIB: RamMap<'static> = RamMap {
    ranges: &[(0, 0xA_0000), (0x10_0000, 0x6000_0000)],
};

#[test]
fn memory_that_is_not_ram_is_uc_whatever_the_mtrrs_say() {
    // The MTRRs make all of the 2 GiB WB, as Hyper-V's make the first 4 GiB.
    let mtrrs = all_write_back();
    let types = EptTypes {
        mtrrs: &mtrrs,
        ram: RAM_BELOW_1536_MIB,
    };
    let ((_, _, pds, pts), _) = filled_with_ram(&types, PROTECTED);
    // Region 0 is only partly RAM: a PT, the hole UC.
    assert_eq!(pds[0], EptEntry::table(0x10_0000));
    assert_eq!(pts[0x9F], EptEntry::page(0x9_F000, EPT_RWX, WB));
    assert_eq!(pts[0xA0], EptEntry::page(0xA_0000, EPT_RWX, UC));
    assert_eq!(pts[0xFF], EptEntry::page(0xF_F000, EPT_RWX, UC));
    assert_eq!(pts[0x100], EptEntry::page(0x10_0000, EPT_RWX, WB));
    // RAM up to 1.5 GiB, WB; then UC 2 MiB pages.
    assert_eq!(pds[0x2FF], EptEntry::large_page(0x5FE0_0000, WB));
    assert_eq!(pds[0x300], EptEntry::large_page(0x6000_0000, UC));
    assert_eq!(pds[0x3FF], EptEntry::large_page(0x7FE0_0000, UC));
}

#[test]
fn a_region_only_partly_ram_has_a_pt_even_when_its_pages_share_a_type() {
    // With the MTRRs off, every page is UC, but the guest can turn them on
    // and make region 0's RAM WB: its PT is there from the start.
    let types = EptTypes {
        mtrrs: &Mtrrs::Disabled,
        ram: RAM_BELOW_1536_MIB,
    };
    assert_eq!(split_regions(&types, 2, &[PROTECTED]), 2);
    let ((_, _, pds, _), _) = filled_with_ram(&types, PROTECTED);
    assert_eq!(pds[0], EptEntry::table(0x10_0000));
    assert_eq!(pds[1], EptEntry::large_page(SIZE_2M, UC));
}

#[test]
fn the_guests_mtrrs_never_make_memory_that_is_not_ram_cacheable() {
    let mut map = TypeMap::with_ram(&all_write_back(), 1, RAM_BELOW_1536_MIB);
    let built = (map.pds.clone(), map.pts.clone(), map.free_len);
    assert_eq!(map.pds[0x300], EptEntry::large_page(0x6000_0000, UC));
    // A range over memory that is not RAM changes nothing, UC or WB.
    assert_eq!(
        map.retype(&write_back_with(&[range(0x6000_0000, SIZE_2M, UC)])),
        Retyped::default()
    );
    // With the MTRRs off the RAM is UC too: the 0x2FF regions of RAM from
    // 2 MiB, and region 0's RAM pages, which keep their PT.
    let retyped = map.retype(&Mtrrs::Disabled);
    assert_eq!((retyped.regions, retyped.merged, retyped.split), (0x300, 0, 0));
    assert_eq!(retyped.span, Some((0, 0x6000_0000)));
    assert_eq!(map.pds[0], EptEntry::table(PTS_ADDRESS));
    assert_eq!(map.pt(0)[0x100], EptEntry::page(0x10_0000, EPT_RWX, UC));
    // On again: the map bring-up built.
    map.retype(&all_write_back());
    assert_eq!((map.pds, map.pts, map.free_len), built);
}

// The whole guest-physical address space: the 1 GiB pages above the memory
// map, and the PDPTs that hold them.

#[test]
fn pdpt_entries_read_back_as_1g_pages() {
    assert_eq!(
        EptEntry::<Pdpt>::huge_page(0xC000_0000, UC).mapping(),
        RegionMapping::HugePage(UC)
    );
    // A PD pointer is read through its PD instead, so not as a 1 GiB page.
    assert_eq!(EptEntry::<Pdpt>::table(0x2000).mapping(), RegionMapping::Invalid);
    assert_eq!(EptEntry::<Pdpt>::EMPTY.mapping(), RegionMapping::Invalid);
    // RWX, page size, type 2: reserved.
    assert_eq!(EptEntry::<Pdpt>::from_raw(0x97).mapping(), RegionMapping::Invalid);
    assert_eq!(RegionMapping::HugePage(UC).to_string(), "1 GiB pages, UC");
}

/// The Hyper-V test VM's MTRRs (#16): default UC, the fixed ranges WB below
/// 0xA0000 and UC up to 1 MiB, and variable range 0 making the first 4 GiB
/// WB, with its 46-bit mask.
fn hyper_v_mtrrs() -> Mtrrs {
    let all = |memory_type: MemoryType| u64::from_le_bytes([memory_type.raw() as u8; 8]);
    let mut fixed = [all(UC); crate::vmx::mtrr::FIXED_MSRS];
    fixed[0] = all(WB);
    fixed[1] = all(WB);
    let first_4_gib = (WB.raw(), 0x3FFF_0000_0000 | crate::vmx::mtrr::PHYSMASK_VALID);
    Mtrrs::decode(enabled_with_fixed(UC), Some(fixed), &[first_4_gib]).unwrap()
}

/// The RAM Aleph0 found in the Hyper-V test VM's UEFI memory map (#16,
/// #17): `EPT RAM 0x0..0xa0000` and `0x100000..0x80000000`.
const HYPER_V_RAM: RamMap<'static> = RamMap {
    ranges: &[(0, 0xA_0000), (0x10_0000, 0x8000_0000)],
};

/// A protected data page where bring-up put one on Hyper-V.
const HYPER_V_DATA_PAGE: u64 = 0x7eab_0000;

/// Every leaf of `tables`, laid out as `layout`, in address order: its
/// base, size, memory type and access, read back from the entries. Panics
/// at an entry that maps nothing or holds a reserved type.
fn leaves(tables: &Tables4, layout: MapLayout) -> Vec<(u64, u64, MemoryType, u64)> {
    let (_, pdpts, pds, pts) = tables;
    let mut leaves = Vec::new();
    for (gib, pdpt_entry) in pdpts.iter().enumerate().take(layout.gibs) {
        let base = gib as u64 * SIZE_1G;
        if gib >= layout.pd_gibs() {
            let RegionMapping::HugePage(memory_type) = pdpt_entry.mapping() else {
                panic!("GiB {gib} is not a 1 GiB page: {pdpt_entry:?}");
            };
            leaves.push((base, SIZE_1G, memory_type, pdpt_entry.raw & EPT_RWX));
            continue;
        }
        for (i, pd_entry) in pds.iter().enumerate().skip(gib * ENTRIES).take(ENTRIES) {
            let region = i as u64 * SIZE_2M;
            match pd_entry.mapping() {
                RegionMapping::LargePage(memory_type) => {
                    leaves.push((region, SIZE_2M, memory_type, pd_entry.raw & EPT_RWX));
                }
                RegionMapping::Pt => {
                    let pt = pt_index(*pd_entry, 0x10_0000, pts.len() / ENTRIES).expect("one of the PTs");
                    for (j, page) in pts[pt * ENTRIES..][..ENTRIES].iter().enumerate() {
                        let memory_type = leaf_memory_type(page.raw).expect("a defined type");
                        leaves.push((
                            region + (j * PAGE_SIZE) as u64,
                            PAGE_SIZE as u64,
                            memory_type,
                            page.raw & EPT_RWX,
                        ));
                    }
                }
                other => panic!("region {i:#x} maps nothing: {other:?}"),
            }
        }
    }
    leaves
}

/// Checks that the map in `tables`, laid out as `layout`, covers
/// `[0, layout.end())` without a gap and gives every page the memory type
/// `types` gives it, RWX except `protected_page`, which is read-only.
fn assert_every_page_has_its_type(tables: &Tables4, layout: MapLayout, types: &EptTypes<'_>, protected_page: u64) {
    let mut next = 0;
    for (base, size, memory_type, access) in leaves(tables, layout) {
        assert_eq!(base, next, "a gap or an overlap before {base:#x}");
        next = base + size;
        let wanted = match size {
            SIZE_1G => {
                assert_eq!(
                    types.ram.coverage(base, SIZE_1G),
                    RamCoverage::None,
                    "RAM in the 1 GiB page {base:#x}"
                );
                UC
            }
            SIZE_2M => types.region_type(base).expect("a region of one type"),
            _ => types.page_type(base),
        };
        assert_eq!(memory_type, wanted, "the type of {base:#x} ({size:#x} bytes)");
        let wanted_access = if base == protected_page { EPT_READ } else { EPT_RWX };
        assert_eq!(access, wanted_access, "the access of {base:#x}");
    }
    assert_eq!(next, layout.end(), "the map ends early");
}

#[test]
fn the_hyper_v_map_gives_every_page_up_to_maxphyaddr_the_type_ept_types_gives_it() {
    let mtrrs = hyper_v_mtrrs();
    let types = EptTypes {
        mtrrs: &mtrrs,
        ram: HYPER_V_RAM,
    };
    let layout = MapLayout::new(2 * SIZE_1G, rules(HYPER_V_BITS, true)).unwrap();
    let (tables, _) = filled_as(layout, &types, HYPER_V_DATA_PAGE);
    assert_every_page_has_its_type(&tables, layout, &types, HYPER_V_DATA_PAGE);
    // As on Hyper-V: the first 2 MiB and the data page's region need a PT.
    assert_eq!(split_regions(&types, layout.pd_gibs(), &[HYPER_V_DATA_PAGE]), 2);
}

#[test]
fn the_local_apic_and_the_ioapic_are_in_a_uc_1_gib_page_above_the_memory_map() {
    let mtrrs = hyper_v_mtrrs();
    let types = EptTypes {
        mtrrs: &mtrrs,
        ram: HYPER_V_RAM,
    };
    let layout = MapLayout::new(2 * SIZE_1G, rules(HYPER_V_BITS, true)).unwrap();
    let ((_, pdpts, _, _), _) = filled_as(layout, &types, HYPER_V_DATA_PAGE);
    // Hyper-V's MTRRs make the first 4 GiB WB, devices included: EPT makes
    // the device window UC all the same, since it is not RAM.
    assert_eq!(mtrrs.memory_type(0xFEE0_0000), WB);
    assert_eq!(pdpts[Pdpt::index(0xFEE0_0000)], EptEntry::huge_page(3 * SIZE_1G, UC));
    assert_eq!(Pdpt::index(0xFEC0_0000), 3);
    assert_eq!(pdpts[2], EptEntry::huge_page(2 * SIZE_1G, UC));
    // The last GiB of the 46-bit space.
    assert_eq!(pdpts[(1 << 16) - 1], EptEntry::huge_page((1 << 46) - SIZE_1G, UC));
}

#[test]
fn a_map_past_512_gib_takes_one_pdpt_per_pml4_entry() {
    let mtrrs = test_mtrrs();
    let types = all_ram_below(&mtrrs, 2 * SIZE_1G);
    // 40 bits: 1 TiB, two PDPTs.
    let layout = MapLayout::new(2 * SIZE_1G, rules(40, true)).unwrap();
    let ((pml4, pdpts, _, _), _) = filled_as(layout, &types, 0x7eb1_d000);
    assert_eq!(pml4[0], EptEntry::table(0x1000));
    assert_eq!(pml4[1], EptEntry::table(0x2000));
    assert_eq!(pml4[2], EptEntry::EMPTY);
    // The PDs come right after the two PDPTs.
    assert_eq!(pdpts[0], EptEntry::table(0x3000));
    assert_eq!(pdpts[1], EptEntry::table(0x4000));
    assert_eq!(pdpts[2], EptEntry::huge_page(2 * SIZE_1G, UC));
    // GiB 512, entry 0 of the second PDPT, which PML4 entry 1 points to.
    assert_eq!((Pml4::index(512 * SIZE_1G), Pdpt::index(512 * SIZE_1G)), (1, 0));
    assert_eq!(pdpts[512], EptEntry::huge_page(512 * SIZE_1G, UC));
    assert_eq!(pdpts[1023], EptEntry::huge_page(1023 * SIZE_1G, UC));
}

/// The EPT types of `mtrrs` with RAM from 0 to `end`.
fn all_ram_below(mtrrs: &Mtrrs, end: u64) -> EptTypes<'_> {
    let ranges: &'static [(u64, u64)] = Box::leak(Box::new([(0, end)]));
    EptTypes {
        mtrrs,
        ram: RamMap { ranges },
    }
}

#[test]
fn a_map_with_uc_holes_and_gaps_in_its_ram_gives_every_page_its_type() {
    let mtrrs = test_mtrrs();
    // RAM with a gap of 3 MiB at 1 GiB (one region all hole, one half), and
    // ending 1 MiB short of 2 GiB.
    let ram = RamMap {
        ranges: &[(0, SIZE_1G), (SIZE_1G + 0x30_0000, 2 * SIZE_1G - 0x10_0000)],
    };
    let types = EptTypes { mtrrs: &mtrrs, ram };
    for layout in [
        MapLayout::new(2 * SIZE_1G, rules(40, true)).unwrap(),
        MapLayout::new(2 * SIZE_1G, rules(40, false)).unwrap(),
    ] {
        let (tables, _) = filled_as(layout, &types, 0x7eb1_d000);
        assert_every_page_has_its_type(&tables, layout, &types, 0x7eb1_d000);
    }
}

#[test]
fn without_1_gib_pages_the_device_window_below_4_gib_is_uc_2_mib_pages() {
    let mtrrs = hyper_v_mtrrs();
    let types = EptTypes {
        mtrrs: &mtrrs,
        ram: HYPER_V_RAM,
    };
    let layout = MapLayout::new(2 * SIZE_1G, rules(HYPER_V_BITS, false)).unwrap();
    let (tables, _) = filled_as(layout, &types, HYPER_V_DATA_PAGE);
    assert_every_page_has_its_type(&tables, layout, &types, HYPER_V_DATA_PAGE);
    let (_, pdpts, pds, _) = &tables;
    assert_eq!(pdpts.len(), ENTRIES);
    assert_eq!(pdpts[4], EptEntry::EMPTY, "nothing past 4 GiB");
    let lapic_region = (0xFEE0_0000 / SIZE_2M) as usize;
    assert_eq!(
        pds[lapic_region],
        EptEntry::large_page(0xFEE0_0000 & !(SIZE_2M - 1), UC)
    );
}

#[test]
fn region_runs_read_the_pds_then_the_1_gib_pages_above_them() {
    let mtrrs = hyper_v_mtrrs();
    let types = EptTypes {
        mtrrs: &mtrrs,
        ram: HYPER_V_RAM,
    };
    let layout = MapLayout::new(2 * SIZE_1G, rules(HYPER_V_BITS, true)).unwrap();
    let ((_, mut pdpts, mut pds, mut pts), _) = filled_as(layout, &types, HYPER_V_DATA_PAGE);
    let ram = HYPER_V_RAM.ranges();
    let tables = TypeTables {
        pml4: 0,
        pdpts: pdpts.as_mut_ptr(),
        layout,
        pds: pds.as_mut_ptr(),
        regions: pds.len(),
        pts: pts.as_mut_ptr(),
        pt_count: pts.len() / ENTRIES,
        pts_address: 0x10_0000,
        free: core::ptr::null_mut(),
        free_len: 0,
        protected_regions: [(HYPER_V_DATA_PAGE / SIZE_2M) as usize, usize::MAX],
        shadow: 0,
        ram: ram.as_ptr(),
        ram_len: ram.len(),
        eptp: Eptp::new(0),
        invept: InveptType::SingleContext,
        rules: rules(HYPER_V_BITS, true),
    };
    let runs = |start, end| -> Vec<_> {
        tables
            .region_runs(start, end)
            .map(|run| (run.start, run.end, run.mapping))
            .collect()
    };
    // As bring-up prints them on Hyper-V.
    assert_eq!(
        runs(0, layout.end()),
        [
            (0, SIZE_2M, RegionMapping::Pt),
            (SIZE_2M, 0x7EA0_0000, RegionMapping::LargePage(WB)),
            (0x7EA0_0000, 0x7EC0_0000, RegionMapping::Pt),
            (0x7EC0_0000, 2 * SIZE_1G, RegionMapping::LargePage(WB)),
            (2 * SIZE_1G, 1 << 46, RegionMapping::HugePage(UC)),
        ]
    );
    // A span inside the PDs reads none of the 1 GiB pages, and one above
    // them none of the PDs.
    assert_eq!(
        runs(SIZE_2M, 2 * SIZE_2M),
        [(SIZE_2M, 2 * SIZE_2M, RegionMapping::LargePage(WB))]
    );
    assert_eq!(
        runs(4 * SIZE_1G, 5 * SIZE_1G),
        [(4 * SIZE_1G, 5 * SIZE_1G, RegionMapping::HugePage(UC))]
    );
    assert!(runs(1 << 46, u64::MAX).is_empty());
}

// Walking the map `Ept::build` fills, as the exit handler does after an EPT
// violation or misconfiguration.

/// The Hyper-V test VM's rules, execute-only pages included.
const HYPER_V_RULES: EntryRules = EntryRules {
    physical_address_bits: HYPER_V_BITS,
    huge_pages: true,
    execute_only: true,
};

/// The entry at `address` in `tables`, which [`filled_as`] filled for
/// `layout`, at the addresses it gave them, with the PML4 at 0; `None`
/// outside them.
fn read_filled(tables: &Tables4, layout: MapLayout, address: u64) -> Option<u64> {
    let (pml4, pdpts, pds, pts) = tables;
    let index = |base: u64, len: usize| {
        (base..base + (len * size_of::<u64>()) as u64)
            .contains(&address)
            .then(|| ((address - base) / size_of::<u64>() as u64) as usize)
    };
    let pds_address = 0x1000 + (layout.pdpts() * PAGE_SIZE) as u64;
    index(0, pml4.len())
        .map(|i| pml4[i].raw)
        .or_else(|| index(0x1000, pdpts.len()).map(|i| pdpts[i].raw))
        .or_else(|| index(pds_address, pds.len()).map(|i| pds[i].raw))
        .or_else(|| index(0x10_0000, pts.len()).map(|i| pts[i].raw))
}

#[test]
fn the_walk_of_the_hyper_v_map_reaches_ram_devices_and_the_protected_page() {
    let mtrrs = hyper_v_mtrrs();
    let types = EptTypes {
        mtrrs: &mtrrs,
        ram: HYPER_V_RAM,
    };
    let layout = MapLayout::new(2 * SIZE_1G, HYPER_V_RULES).unwrap();
    let (tables, _) = filled_as(layout, &types, HYPER_V_DATA_PAGE);
    let walk_to = |gpa| {
        walk(Eptp::new(0), gpa, HYPER_V_RULES, |address| {
            read_filled(&tables, layout, address)
        })
    };
    let mapped = |hpa, size, access, memory_type| WalkEnd::Mapped {
        hpa,
        size,
        access,
        memory_type,
    };
    // RAM, a 2 MiB WB page.
    assert_eq!(walk_to(0x40_0123).end, mapped(0x40_0123, SIZE_2M, EPT_RWX, WB));
    // The Local APIC's version register: a UC 1 GiB page above the PDs.
    let lapic = walk_to(0xFEE0_0030);
    assert_eq!(lapic.end, mapped(0xFEE0_0030, SIZE_1G, EPT_RWX, UC));
    assert_eq!(lapic.entries().count(), 2);
    // The protected data page: read-only, through its region's PT.
    assert_eq!(
        walk_to(HYPER_V_DATA_PAGE + 4).end,
        mapped(HYPER_V_DATA_PAGE + 4, PAGE_SIZE as u64, EPT_READ, WB)
    );
    // The VGA window below 1 MiB is not RAM: UC.
    assert_eq!(walk_to(0xA_0000).end, mapped(0xA_0000, PAGE_SIZE as u64, EPT_RWX, UC));
    // The last byte of the 46-bit space, then the first past it.
    let last = (1 << 46) - 1;
    assert_eq!(walk_to(last).end, mapped(last, SIZE_1G, EPT_RWX, UC));
    assert_eq!(walk_to(1 << 46).end, WalkEnd::NotPresent);
    for gpa in [0x40_0123, 0xFEE0_0030, HYPER_V_DATA_PAGE, 0xA_0000, last] {
        assert!(walk_to(gpa).entries().all(|entry| entry.faults.is_empty()), "{gpa:#x}");
    }
}

/// Zeroed, page-aligned memory for real tables, freed on drop: what
/// `allocate_zeroed_pages` gives `Ept::build`, on the host.
struct Pages {
    start: core::ptr::NonNull<u8>,
    layout: std::alloc::Layout,
}

impl Pages {
    fn new(count: usize) -> Self {
        let layout = std::alloc::Layout::from_size_align(count.max(1) * PAGE_SIZE, PAGE_SIZE).unwrap();
        // SAFETY: `layout` has a nonzero size.
        let start = unsafe { std::alloc::alloc_zeroed(layout) };
        Self {
            start: core::ptr::NonNull::new(start).expect("host memory"),
            layout,
        }
    }

    fn address(&self) -> u64 {
        self.start.as_ptr() as u64
    }

    fn entries<L: Level>(&mut self) -> &mut [EptEntry<L>] {
        // SAFETY: the allocation is zeroed, page-aligned and this long, and
        // the slice borrows `self`; an all-zero entry is a valid one.
        unsafe {
            core::slice::from_raw_parts_mut(
                self.start.as_ptr().cast(),
                self.layout.size() / size_of::<EptEntry<L>>(),
            )
        }
    }
}

impl Drop for Pages {
    fn drop(&mut self) {
        // SAFETY: allocated in `new` with this layout, freed only here.
        unsafe { std::alloc::dealloc(self.start.as_ptr(), self.layout) }
    }
}

#[test]
fn the_type_tables_walk_reads_only_the_tables_build_allocated() {
    let mtrrs = test_mtrrs();
    let types = all_ram_below(&mtrrs, 2 * SIZE_1G);
    // 40 bits: two PDPTs, so the walk crosses PML4 entries too.
    let layout = MapLayout::new(2 * SIZE_1G, rules(40, true)).unwrap();
    let split = split_regions(&types, layout.pd_gibs(), &[PROTECTED]);
    let (mut pml4, mut pdpts, mut pds, mut pts) = (
        Pages::new(1),
        Pages::new(layout.pdpts()),
        Pages::new(layout.pd_gibs()),
        Pages::new(split),
    );
    let (pml4_address, pdpts_address, pds_address, pts_address) =
        (pml4.address(), pdpts.address(), pds.address(), pts.address());
    fill_identity_map(
        Tables {
            pml4: pml4.entries(),
            pdpts: pdpts.entries(),
            pds: pds.entries(),
            pts: pts.entries(),
            pdpts_address,
            pds_address,
            pts_address,
        },
        layout,
        &types,
        &[PROTECTED],
    );
    let ram = types.ram.ranges();
    let tables = TypeTables {
        pml4: pml4_address,
        pdpts: pdpts.entries().as_mut_ptr(),
        layout,
        pds: pds.entries().as_mut_ptr(),
        regions: layout.pd_gibs() * ENTRIES,
        pts: pts.entries().as_mut_ptr(),
        pt_count: split,
        pts_address,
        free: core::ptr::null_mut(),
        free_len: 0,
        protected_regions: [(PROTECTED / SIZE_2M) as usize, usize::MAX],
        shadow: 0,
        ram: ram.as_ptr(),
        ram_len: ram.len(),
        eptp: Eptp::new(pml4_address),
        invept: InveptType::SingleContext,
        // The host's heap addresses take up to 47 bits: with fewer, the
        // walk would rightly call the table pointers' high bits reserved.
        rules: rules(48, true),
    };
    let eptp = Eptp::new(pml4_address);
    let end_of = |gpa| tables.walk(eptp, gpa).end;
    // The UC 2 MiB region of `test_mtrrs`, the protected page, and a 1 GiB
    // page reached through PML4 entry 1.
    assert!(matches!(
        end_of(0x4000_0123),
        WalkEnd::Mapped {
            hpa: 0x4000_0123,
            memory_type: UC,
            ..
        }
    ));
    assert!(matches!(
        end_of(PROTECTED),
        WalkEnd::Mapped {
            access: EPT_READ,
            memory_type: WB,
            ..
        }
    ));
    let far = 600 * SIZE_1G + 0x123;
    assert_eq!(
        end_of(far),
        WalkEnd::Mapped {
            hpa: far,
            size: SIZE_1G,
            access: EPT_RWX,
            memory_type: UC,
        }
    );
    // An EPTP naming no table of ours: nothing is read.
    let foreign = tables.walk(Eptp::new(0x1234_5000), 0);
    assert_eq!(foreign.end, WalkEnd::OutsideTables { table: 0x1234_5000 });
    assert_eq!(foreign.entries().count(), 0);
    assert!(tables.contains_entry(pml4_address));
    assert!(tables.contains_entry(pts_address + (split * PAGE_SIZE) as u64 - 8));
    assert!(!tables.contains_entry(pml4_address + 4), "misaligned");
    assert!(!tables.contains_entry(0));
    // A PD entry pointing elsewhere is reported, not followed: reading
    // 0x1234_5000 on the host would fault.
    pds.entries::<Pd>()[0] = EptEntry::table(0x1234_5000);
    assert_eq!(end_of(0x1000), WalkEnd::OutsideTables { table: 0x1234_5000 });
}
