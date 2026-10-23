//! Unit tests for `src/vmx/ept.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::level::{Pd, Pdpt, Pml4, Pt};
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

/// Fills a 2 GiB identity map with [`test_mtrrs`]: see [`filled_with`].
fn filled(protected_page: u64) -> (Tables4, usize) {
    filled_with(&test_mtrrs(), protected_page)
}

/// Fills a 2 GiB identity map with `mtrrs` and made-up table addresses (PDs
/// at 0x2000, PTs from 0x10_0000), and returns the tables and the protected
/// page's index in the PTs.
fn filled_with(mtrrs: &Mtrrs, protected_page: u64) -> (Tables4, usize) {
    let split = split_regions(mtrrs, 2, protected_page);
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
        protected_page,
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
    assert_eq!(split_regions(&mtrrs, 2, 0x7eb1_d000), 2);
    let ((_, _, pds, _), _) = filled(0x7eb1_d000);
    // 0x7eb1_d000 is in the 2 MiB region 0x7ea0_0000, entry 0x3F5; the
    // mixed region 0x7FE0_0000 is entry 0x3FF.
    assert_eq!(pds[0x3F5], EptEntry::table(0x10_0000));
    assert_eq!(pds[0x3FF], EptEntry::table(0x10_1000));
}

#[test]
fn a_protected_page_in_a_mixed_region_needs_no_second_pt() {
    let mtrrs = test_mtrrs();
    assert_eq!(split_regions(&mtrrs, 2, 0x7FE0_0000), 1);
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
    assert_eq!(split_regions(&mtrrs, 2, 0x7eb1_d000), 2);
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
    assert_eq!(split_regions(&Mtrrs::Unsupported, 2, 0x7eb1_d000), 1);
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
}

impl TypeMap {
    /// The map `mtrrs` give, with [`PROTECTED`] read-only and `spare` PTs
    /// set aside.
    fn new(mtrrs: &Mtrrs, spare: usize) -> Self {
        let split = split_regions(mtrrs, 2, PROTECTED);
        let mut pml4 = vec![EptEntry::EMPTY; ENTRIES];
        let mut pdpt = vec![EptEntry::EMPTY; ENTRIES];
        let mut pds = vec![EptEntry::EMPTY; 2 * ENTRIES];
        let mut pts = vec![EptEntry::EMPTY; (split + spare) * ENTRIES];
        fill_identity_map(
            Tables {
                pml4: &mut pml4,
                pdpt: &mut pdpt,
                pds: &mut pds,
                pts: &mut pts[..split * ENTRIES],
                pdpt_address: 0x1000,
                pds_address: 0x2000,
                pts_address: PTS_ADDRESS,
            },
            2,
            mtrrs,
            PROTECTED,
        );
        let mut free = vec![0; split + spare];
        let free_len = fill_free_stack(&mut free, split);
        Self {
            pds,
            pts,
            free,
            free_len,
        }
    }

    /// Gives the map the types of `mtrrs`, as [`TypeTables::apply`] does
    /// before its INVEPT.
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
            protected_region: (PROTECTED / SIZE_2M) as usize,
        };
        retype(&mut tables, mtrrs)
    }

    /// PT number `index`.
    fn pt(&self, index: usize) -> &[EptEntry<Pt>] {
        &self.pts[index * ENTRIES..][..ENTRIES]
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
fn a_region_left_uc_gets_a_pt_once_one_is_free() {
    // Built with region 3 mixed, so it has a PT, and no spare one.
    let mut map = TypeMap::new(&write_back_with(&[range(3 * SIZE_2M, 0x1000, UC)]), 0);
    // Region 1 mixes before region 3 gives its PT back: UC for now.
    let moved = write_back_with(&[range(SIZE_2M, 0x1000, UC)]);
    let retyped = map.retype(&moved);
    assert_eq!((retyped.split, retyped.merged, retyped.uncached), (0, 1, 1));
    assert_eq!(map.pds[1], EptEntry::large_page(SIZE_2M, UC));
    // The next retype finds region 3's PT free: the first one, as region 3
    // comes before the protected page's in address order.
    let retyped = map.retype(&moved);
    assert_eq!((retyped.regions, retyped.split, retyped.uncached), (1, 1, 0));
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
