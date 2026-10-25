//! Unit tests for `src/regions.rs`.

use super::*;

/// The harness's image: 0x7e00_0000 to 0x7e01_0000.
const KEEP: (u64, u64) = (0x7e00_0000, 0x7e01_0000);

fn ranges(regions: &[(u64, u64, MemoryType)]) -> Vec<(u64, u64)> {
    let mut out = [(0, 0); 8];
    let count = reclaimable_except(regions.iter().copied(), KEEP, &mut out);
    out[..count].to_vec()
}

#[test]
fn reclaimable_regions_are_overwritten_whole() {
    assert_eq!(
        ranges(&[
            (0x0, 0x9f, MemoryType::CONVENTIONAL),
            (0x10_0000, 0x10, MemoryType::BOOT_SERVICES_DATA),
        ]),
        [(0x0, 0x9_f000), (0x10_0000, 0x11_0000)]
    );
}

#[test]
fn kept_regions_are_left_alone() {
    assert_eq!(
        ranges(&[
            (0x7f00_0000, 0x10, MemoryType::RUNTIME_SERVICES_DATA),
            (0x7f01_0000, 0x10, MemoryType::RUNTIME_SERVICES_CODE),
            (0xfee0_0000, 1, MemoryType::MMIO),
        ]),
        []
    );
}

#[test]
fn the_harness_image_is_cut_out_of_its_region() {
    // LOADER_CODE around the image: the parts below and above it.
    assert_eq!(
        ranges(&[(0x7dff_0000, 0x30, MemoryType::LOADER_CODE)]),
        [(0x7dff_0000, 0x7e00_0000), (0x7e01_0000, 0x7e02_0000)]
    );
    // A region that is the image, or inside it: nothing.
    assert_eq!(ranges(&[(0x7e00_0000, 0x10, MemoryType::LOADER_CODE)]), []);
    assert_eq!(ranges(&[(0x7e00_4000, 0x2, MemoryType::LOADER_CODE)]), []);
}

#[test]
fn a_region_overlapping_one_end_of_the_image_keeps_the_rest() {
    assert_eq!(
        ranges(&[
            (0x7dff_f000, 0x2, MemoryType::LOADER_DATA),
            (0x7e00_f000, 0x2, MemoryType::LOADER_DATA),
        ]),
        [(0x7dff_f000, 0x7e00_0000), (0x7e01_0000, 0x7e01_1000)]
    );
}

#[test]
fn ranges_past_the_output_are_counted_but_not_written() {
    let regions = [
        (0x0, 1, MemoryType::CONVENTIONAL),
        (0x1000, 1, MemoryType::CONVENTIONAL),
        (0x2000, 1, MemoryType::CONVENTIONAL),
    ];
    let mut out = [(0, 0); 2];
    assert_eq!(reclaimable_except(regions.into_iter(), KEEP, &mut out), 3);
    assert_eq!(out, [(0x0, 0x1000), (0x1000, 0x2000)]);
}
