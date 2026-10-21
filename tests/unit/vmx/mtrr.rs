//! Unit tests for `src/vmx/mtrr.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items. The helpers that build MSR values are `pub(crate)`, for
//! the EPT tests.

use super::MemoryType::{Uncacheable as UC, WriteBack as WB, WriteCombining as WC, WriteThrough as WT};
use super::*;

const SIZE_2M: u64 = 1 << 21;
const SIZE_1G: u64 = 1 << 30;

/// IA32_MTRR_DEF_TYPE with the MTRRs enabled, fixed ranges off, and
/// `default` as the default type.
pub(crate) fn enabled(default: MemoryType) -> u64 {
    DEF_TYPE_ENABLE | default.raw()
}

/// IA32_MTRR_DEF_TYPE with the MTRRs and the fixed ranges enabled, and
/// `default` as the default type.
pub(crate) fn enabled_with_fixed(default: MemoryType) -> u64 {
    enabled(default) | DEF_TYPE_FIXED_ENABLE
}

/// The PHYSBASE/PHYSMASK pair of a valid range of `size` bytes (a power of
/// two) at `base`, on a CPU with 39 physical-address bits.
pub(crate) fn range(base: u64, size: u64, memory_type: MemoryType) -> (u64, u64) {
    let mask = ((1 << 39) - 1) & !(size - 1);
    (base | memory_type.raw(), mask | PHYSMASK_VALID)
}

/// MTRRs with `default` and the variable ranges `variable`, no fixed ones.
fn mtrrs(default: MemoryType, variable: &[(u64, u64)]) -> Mtrrs {
    Mtrrs::decode(enabled(default), None, variable).unwrap()
}

/// The ranges of MTRRs that are on; panics if they are not.
fn as_enabled(mtrrs: &Mtrrs) -> &EnabledMtrrs {
    let Mtrrs::Enabled(enabled) = mtrrs else {
        panic!("MTRRs not enabled: {mtrrs:?}");
    };
    enabled
}

/// Every byte of a fixed-range MSR set to `memory_type`.
fn fixed_all(memory_type: MemoryType) -> u64 {
    u64::from_le_bytes([memory_type.raw() as u8; 8])
}

/// The usual first MiB: RAM (WB) up to 0xA0000, the legacy VGA window
/// 0xA0000..0xC0000 UC, then the option ROMs and BIOS 0xC0000..0x100000 WP.
pub(crate) fn pc_fixed() -> [u64; FIXED_MSRS] {
    let mut fixed = [fixed_all(MemoryType::WriteProtected); FIXED_MSRS];
    fixed[0] = fixed_all(WB);
    fixed[1] = fixed_all(WB);
    fixed[2] = fixed_all(UC);
    fixed
}

#[test]
fn only_the_five_architectural_types_decode() {
    for (value, memory_type) in [
        (0, Some(UC)),
        (1, Some(WC)),
        (2, None),
        (3, None),
        (4, Some(WT)),
        (5, Some(MemoryType::WriteProtected)),
        (6, Some(WB)),
        (7, None),
        (0xFF, None),
    ] {
        assert_eq!(MemoryType::from_raw(value), memory_type, "type {value}");
    }
}

#[test]
fn types_encode_as_the_sdm_numbers_them() {
    assert_eq!(UC.raw(), 0);
    assert_eq!(WC.raw(), 1);
    assert_eq!(WT.raw(), 4);
    assert_eq!(MemoryType::WriteProtected.raw(), 5);
    assert_eq!(WB.raw(), 6);
    assert_eq!(WB.name(), "WB");
}

#[test]
fn disabled_mtrrs_make_everything_uncacheable() {
    // E clear: the default type, the fixed and the variable ranges are all
    // ignored, even a reserved type in them.
    let mtrrs = Mtrrs::decode(
        DEF_TYPE_FIXED_ENABLE | WB.raw(),
        Some([fixed_all(WB); FIXED_MSRS]),
        &[(7, PHYSMASK_VALID)],
    )
    .unwrap();
    assert_eq!(mtrrs, Mtrrs::Disabled);
    assert_eq!(mtrrs.memory_type(0), UC);
    assert_eq!(mtrrs.memory_type(0x7eb0_1000), UC);
    assert_eq!(mtrrs.block_type(0, SIZE_2M), Some(UC));
}

#[test]
fn without_mtrrs_everything_is_write_back() {
    let mtrrs = Mtrrs::Unsupported;
    assert_eq!(mtrrs.memory_type(0xA_0000), WB);
    assert_eq!(mtrrs.memory_type(0xFEE0_0000), WB);
}

#[test]
fn an_address_no_range_covers_gets_the_default_type() {
    let mtrrs = mtrrs(UC, &[range(0, 2 * SIZE_1G, WB)]);
    assert_eq!(mtrrs.memory_type(0x7FFF_F000), WB);
    assert_eq!(mtrrs.memory_type(2 * SIZE_1G), UC);
    assert_eq!(mtrrs.memory_type(0xFEE0_0000), UC);
}

#[test]
fn a_range_without_the_valid_bit_is_ignored() {
    let (base, mask) = range(0, 2 * SIZE_1G, WB);
    let mtrrs = mtrrs(UC, &[(base, mask & !PHYSMASK_VALID)]);
    assert_eq!(as_enabled(&mtrrs).variable_count(), 1);
    assert!(as_enabled(&mtrrs).variable_ranges().is_empty());
    assert_eq!(mtrrs.memory_type(0x1000_0000), UC);
}

#[test]
fn ranges_keep_their_number_base_mask_and_type() {
    let mtrrs = mtrrs(
        UC,
        &[(0, 0), range(0x8000_0000, 0x1000_0000, WC), range(0, SIZE_1G, WB)],
    );
    assert_eq!(
        as_enabled(&mtrrs).variable_ranges(),
        [
            VariableRange {
                number: 1,
                base: 0x8000_0000,
                mask: 0x7F_F000_0000,
                memory_type: WC,
            },
            VariableRange {
                number: 2,
                base: 0,
                mask: 0x7F_C000_0000,
                memory_type: WB,
            },
        ]
    );
}

#[test]
fn uncacheable_wins_an_overlap() {
    // A UC hole for MMIO inside a WB range, the common firmware layout.
    let mtrrs = mtrrs(WB, &[range(0, 4 * SIZE_1G, WB), range(0xC000_0000, SIZE_1G, UC)]);
    assert_eq!(mtrrs.memory_type(0xBFFF_F000), WB);
    assert_eq!(mtrrs.memory_type(0xC000_0000), UC);
    assert_eq!(mtrrs.memory_type(0xFEE0_0000), UC);
}

#[test]
fn write_through_wins_over_write_back() {
    let mtrrs = mtrrs(UC, &[range(0, SIZE_1G, WB), range(0, SIZE_2M, WT)]);
    assert_eq!(mtrrs.memory_type(0x1000), WT);
}

#[test]
fn an_undefined_overlap_is_uncacheable() {
    let mtrrs = mtrrs(WB, &[range(0, SIZE_1G, WC), range(0, SIZE_2M, WT)]);
    assert_eq!(mtrrs.memory_type(0x1000), UC);
    assert_eq!(mtrrs.memory_type(SIZE_2M), WC);
}

#[test]
fn three_overlapping_ranges_combine_the_same_in_any_order() {
    for ([a, b, c], expected) in [
        ([WT, WB, WB], WT),
        ([WB, WT, UC], UC),
        ([WC, WC, WB], UC),
        ([WB, WB, WB], WB),
    ] {
        for order in [[a, b, c], [a, c, b], [b, a, c], [b, c, a], [c, a, b], [c, b, a]] {
            let variable = order.map(|memory_type| range(0, SIZE_2M, memory_type));
            assert_eq!(mtrrs(WB, &variable).memory_type(0x1000), expected, "{order:?}");
        }
    }
}

#[test]
fn identical_overlapping_types_stay() {
    let mtrrs = mtrrs(UC, &[range(0, SIZE_1G, WC), range(0, SIZE_2M, WC)]);
    assert_eq!(mtrrs.memory_type(0x1000), WC);
}

#[test]
fn the_fixed_ranges_decide_the_first_mib() {
    let mtrrs = Mtrrs::decode(enabled_with_fixed(UC), Some(pc_fixed()), &[range(0, SIZE_1G, WB)]).unwrap();
    assert!(as_enabled(&mtrrs).fixed_enabled());
    // The variable range covers all of these too; the fixed ranges win.
    assert_eq!(mtrrs.memory_type(0x9_F000), WB);
    assert_eq!(mtrrs.memory_type(0xA_0000), UC);
    assert_eq!(mtrrs.memory_type(0xB_F000), UC);
    assert_eq!(mtrrs.memory_type(0xC_0000), MemoryType::WriteProtected);
    assert_eq!(mtrrs.memory_type(0xF_F000), MemoryType::WriteProtected);
    // From 1 MiB on, the variable ranges again.
    assert_eq!(mtrrs.memory_type(FIXED_END), WB);
}

#[test]
fn each_fixed_range_reads_its_own_byte() {
    // Byte n of each MSR holds type 6 for n even, 0 for n odd.
    let alternating = u64::from_le_bytes([6, 0, 6, 0, 6, 0, 6, 0]);
    let mtrrs = Mtrrs::decode(enabled_with_fixed(UC), Some([alternating; FIXED_MSRS]), &[]).unwrap();
    for (msr, start, size) in FIXED_RANGES {
        for n in 0..8 {
            let expected = if n % 2 == 0 { WB } else { UC };
            for address in [start + n * size, start + (n + 1) * size - PAGE_SIZE as u64] {
                assert_eq!(
                    mtrrs.memory_type(address),
                    expected,
                    "MSR {msr:#x} range {n} at {address:#x}"
                );
            }
        }
    }
}

#[test]
fn fixed_ranges_are_ignored_while_disabled_or_missing() {
    let disabled = Mtrrs::decode(enabled(WB), Some([fixed_all(UC); FIXED_MSRS]), &[]).unwrap();
    assert!(!as_enabled(&disabled).fixed_enabled());
    assert_eq!(disabled.memory_type(0xA_0000), WB);

    let missing = Mtrrs::decode(enabled_with_fixed(WB), None, &[]).unwrap();
    assert!(!as_enabled(&missing).fixed_enabled());
    assert_eq!(missing.memory_type(0xA_0000), WB);
}

#[test]
fn a_reserved_type_in_use_is_refused_with_its_msr() {
    assert_eq!(
        Mtrrs::decode(DEF_TYPE_ENABLE | 2, None, &[]),
        Err(MtrrError::ReservedType {
            msr: IA32_MTRR_DEF_TYPE,
            value: 2
        })
    );

    let mut fixed = [fixed_all(WB); FIXED_MSRS];
    fixed[4] = u64::from_le_bytes([6, 6, 6, 7, 6, 6, 6, 6]);
    assert_eq!(
        Mtrrs::decode(enabled_with_fixed(WB), Some(fixed), &[]),
        Err(MtrrError::ReservedType { msr: 0x269, value: 7 })
    );

    assert_eq!(
        Mtrrs::decode(enabled(WB), None, &[(0, 0), (3, PHYSMASK_VALID)]),
        Err(MtrrError::ReservedType { msr: 0x202, value: 3 })
    );
}

#[test]
fn a_reserved_type_out_of_use_is_accepted() {
    // A disabled fixed range and an invalid variable range: the CPU never
    // reads their types.
    let mtrrs = Mtrrs::decode(enabled(WB), Some([fixed_all(UC) | 2; FIXED_MSRS]), &[(3, 0)]);
    assert!(mtrrs.is_ok());
}

#[test]
fn more_variable_ranges_than_kept_are_refused() {
    let variable = [(0, 0); MAX_VARIABLE_RANGES + 1];
    assert_eq!(
        Mtrrs::decode(enabled(WB), None, &variable),
        Err(MtrrError::TooManyVariableRanges {
            count: MAX_VARIABLE_RANGES + 1
        })
    );
    assert!(Mtrrs::decode(enabled(WB), None, &variable[..MAX_VARIABLE_RANGES]).is_ok());
}

#[test]
fn a_block_inside_one_range_has_its_type() {
    let mtrrs = mtrrs(UC, &[range(0, 2 * SIZE_1G, WB)]);
    assert_eq!(mtrrs.block_type(0x4000_0000, SIZE_2M), Some(WB));
    assert_eq!(mtrrs.block_type(2 * SIZE_1G, SIZE_2M), Some(UC));
    assert_eq!(mtrrs.block_type(0, SIZE_1G), Some(WB));
}

#[test]
fn a_block_a_range_covers_in_part_is_mixed() {
    // A 1 MiB UC range in the upper half of the 2 MiB block at 0x7FE0_0000.
    let mtrrs = mtrrs(UC, &[range(0, 2 * SIZE_1G, WB), range(0x7FF0_0000, 0x10_0000, UC)]);
    assert_eq!(mtrrs.block_type(0x7FE0_0000, SIZE_2M), None);
    assert_eq!(mtrrs.block_type(0x7FC0_0000, SIZE_2M), Some(WB));
    // The same range, looked at in 4 KiB blocks, has one type per block.
    assert_eq!(mtrrs.block_type(0x7FEF_F000, PAGE_SIZE as u64), Some(WB));
    assert_eq!(mtrrs.block_type(0x7FF0_0000, PAGE_SIZE as u64), Some(UC));
}

#[test]
fn a_small_range_elsewhere_leaves_a_block_uniform() {
    // The UC range's mask tests bits inside a 2 MiB block, but its upper
    // bits do not match this block, so it covers none of it.
    let mtrrs = mtrrs(UC, &[range(0, 2 * SIZE_1G, WB), range(0x7FF0_0000, 0x10_0000, UC)]);
    let small = as_enabled(&mtrrs).variable_ranges()[1];
    assert!(small.may_split(0x7FE0_0000, SIZE_2M));
    assert!(!small.may_split(0x4000_0000, SIZE_2M));
    assert_eq!(mtrrs.block_type(0x4000_0000, SIZE_2M), Some(WB));
}

#[test]
fn a_partial_range_of_the_same_type_leaves_a_block_uniform() {
    let mtrrs = mtrrs(WB, &[range(0x10_0000, 0x10_0000, WB)]);
    assert_eq!(mtrrs.block_type(0, SIZE_2M), Some(WB));
}

#[test]
fn the_first_block_is_mixed_when_the_fixed_ranges_differ() {
    let mtrrs = Mtrrs::decode(enabled_with_fixed(WB), Some(pc_fixed()), &[]).unwrap();
    assert_eq!(mtrrs.block_type(0, SIZE_2M), None);
    assert_eq!(mtrrs.block_type(SIZE_2M, SIZE_2M), Some(WB));
}

#[test]
fn the_first_block_is_uniform_when_the_fixed_ranges_agree() {
    let mtrrs = Mtrrs::decode(enabled_with_fixed(WB), Some([fixed_all(WB); FIXED_MSRS]), &[]).unwrap();
    assert_eq!(mtrrs.block_type(0, SIZE_2M), Some(WB));
}

#[test]
fn runs_merge_blocks_of_the_same_type() {
    let mtrrs = Mtrrs::decode(
        enabled_with_fixed(UC),
        Some(pc_fixed()),
        &[range(0, 2 * SIZE_1G, WB), range(0x7FF0_0000, 0x10_0000, UC)],
    )
    .unwrap();
    let runs: Vec<_> = mtrrs.runs(4 * SIZE_1G, SIZE_2M).collect();
    assert_eq!(
        runs,
        [
            TypeRun {
                start: 0,
                end: SIZE_2M,
                memory_type: None,
            },
            TypeRun {
                start: SIZE_2M,
                end: 0x7FE0_0000,
                memory_type: Some(WB),
            },
            TypeRun {
                start: 0x7FE0_0000,
                end: 2 * SIZE_1G,
                memory_type: None,
            },
            TypeRun {
                start: 2 * SIZE_1G,
                end: 4 * SIZE_1G,
                memory_type: Some(UC),
            },
        ]
    );
}

#[test]
fn runs_in_4k_blocks_show_the_fixed_ranges() {
    let mtrrs = Mtrrs::decode(enabled_with_fixed(UC), Some(pc_fixed()), &[]).unwrap();
    let runs: Vec<_> = mtrrs
        .runs(FIXED_END, PAGE_SIZE as u64)
        .map(|run| (run.start, run.end, run.memory_type))
        .collect();
    assert_eq!(
        runs,
        [
            (0, 0xA_0000, Some(WB)),
            (0xA_0000, 0xC_0000, Some(UC)),
            (0xC_0000, FIXED_END, Some(MemoryType::WriteProtected)),
        ]
    );
}

#[test]
fn no_runs_for_an_empty_span() {
    assert_eq!(mtrrs(WB, &[]).runs(0, SIZE_2M).count(), 0);
}
