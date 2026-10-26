//! Unit tests for `src/resident/pe.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;

/// Size of the test image: headers, one page with fixups, the table.
const IMAGE_SIZE: usize = 0x3000;
/// Where the PE signature starts.
const SIGNATURE: usize = 0x80;
/// Where the optional header starts.
const OPTIONAL: usize = SIGNATURE + 4 + 20;
/// RVA of the base relocation table.
const TABLE: usize = 0x2000;
/// An address in the image as the linker wrote it, for base 0x1_4000_0000.
const LINKED: u64 = 0x1_4000_1234;

fn put(image: &mut [u8], offset: usize, bytes: &[u8]) {
    image[offset..offset + bytes.len()].copy_from_slice(bytes);
}

/// A loaded PE32+ image whose base relocation table holds one block: page
/// 0x1000, with the given entries. Absolute addresses ([`LINKED`]) sit at
/// 0x1010 and 0x1ff8.
fn image_with(entries: &[u16]) -> Vec<u8> {
    let mut image = vec![0; IMAGE_SIZE];
    put(&mut image, 0, b"MZ");
    put(&mut image, 0x3C, &(SIGNATURE as u32).to_le_bytes());
    put(&mut image, SIGNATURE, b"PE\0\0");
    put(&mut image, OPTIONAL, &0x20Bu16.to_le_bytes());
    put(&mut image, OPTIONAL + 56, &(IMAGE_SIZE as u32).to_le_bytes());
    put(&mut image, OPTIONAL + 108, &16u32.to_le_bytes());
    let block_size = 8 + 2 * entries.len();
    put(&mut image, OPTIONAL + 152, &(TABLE as u32).to_le_bytes());
    put(&mut image, OPTIONAL + 156, &(block_size as u32).to_le_bytes());
    put(&mut image, TABLE, &0x1000u32.to_le_bytes());
    put(&mut image, TABLE + 4, &(block_size as u32).to_le_bytes());
    for (i, entry) in entries.iter().enumerate() {
        put(&mut image, TABLE + 8 + 2 * i, &entry.to_le_bytes());
    }
    put(&mut image, 0x1010, &LINKED.to_le_bytes());
    put(&mut image, 0x1FF8, &LINKED.to_le_bytes());
    image
}

fn u64_at(image: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap())
}

/// DIR64 fixups at page offsets 0x010 and 0xff8, then an ABSOLUTE pad.
const ENTRIES: [u16; 3] = [0xA010, 0xAFF8, 0x0000];

#[test]
fn headers_give_the_image_size_and_the_table() {
    let image = image_with(&ENTRIES);
    assert_eq!(
        Headers::parse(&image),
        Ok(Headers {
            size_of_image: IMAGE_SIZE,
            relocations: TABLE..TABLE + 14,
        })
    );
}

#[test]
fn every_dir64_fixup_moves_by_the_delta() {
    let mut image = image_with(&ENTRIES);
    let table = Headers::parse(&image).unwrap().relocations;
    assert_eq!(relocate(&mut image, table, 0x2000), Ok(2));
    assert_eq!(u64_at(&image, 0x1010), LINKED + 0x2000);
    assert_eq!(u64_at(&image, 0x1FF8), LINKED + 0x2000);
}

#[test]
fn a_copy_below_the_loaded_image_moves_its_addresses_down() {
    // The copy at 0x7e00_0000, the loaded image at 0x7f00_0000: the delta
    // wraps, and adding it subtracts.
    let mut image = image_with(&ENTRIES);
    let table = Headers::parse(&image).unwrap().relocations;
    let delta = 0x7e00_0000u64.wrapping_sub(0x7f00_0000);
    relocate(&mut image, table, delta).unwrap();
    assert_eq!(u64_at(&image, 0x1010), LINKED - 0x100_0000);
}

#[test]
fn padding_and_the_rest_of_the_image_stay_as_they_were() {
    let mut image = image_with(&ENTRIES);
    let before = image.clone();
    let table = Headers::parse(&image).unwrap().relocations;
    relocate(&mut image, table, 0x1000).unwrap();
    let changed: Vec<usize> = (0..IMAGE_SIZE).filter(|&i| image[i] != before[i]).collect();
    // Only the low bytes of the two addresses: 0x1234 + 0x1000 = 0x2234.
    assert_eq!(changed, [0x1011, 0x1FF9]);
}

#[test]
fn an_image_that_is_not_pe32_plus_is_refused() {
    let mut no_mz = image_with(&ENTRIES);
    no_mz[0] = b'Z';
    let mut pe32 = image_with(&ENTRIES);
    put(&mut pe32, OPTIONAL, &0x10Bu16.to_le_bytes());
    let mut signature_outside = image_with(&ENTRIES);
    put(&mut signature_outside, 0x3C, &0xFFFF_FFF0u32.to_le_bytes());
    for image in [no_mz, pe32, signature_outside, b"MZ".to_vec()] {
        assert_eq!(Headers::parse(&image), Err(PeError::NotPe32Plus));
    }
}

#[test]
fn an_image_without_a_relocation_table_cannot_move() {
    let mut empty = image_with(&ENTRIES);
    put(&mut empty, OPTIONAL + 156, &0u32.to_le_bytes());
    let mut five_directories = image_with(&ENTRIES);
    put(&mut five_directories, OPTIONAL + 108, &5u32.to_le_bytes());
    for image in [empty, five_directories] {
        assert_eq!(Headers::parse(&image), Err(PeError::NoRelocations));
    }
}

#[test]
fn a_table_past_the_image_is_refused() {
    let mut image = image_with(&ENTRIES);
    put(&mut image, OPTIONAL + 156, &0x1001u32.to_le_bytes());
    assert_eq!(Headers::parse(&image), Err(PeError::TableOutsideImage));
}

#[test]
fn a_block_that_does_not_fit_its_table_is_refused() {
    // A zeroed table, as if the firmware had not loaded it: size 0.
    for size in [0u32, 7, 13, 16] {
        let mut image = image_with(&ENTRIES);
        put(&mut image, TABLE + 4, &size.to_le_bytes());
        assert_eq!(
            relocate(&mut image, TABLE..TABLE + 14, 1),
            Err(PeError::BadBlock { offset: 0 }),
            "block size {size}"
        );
    }
}

#[test]
fn a_fixup_past_the_image_is_refused() {
    let mut image = image_with(&ENTRIES);
    put(&mut image, TABLE, &0x2FF8u32.to_le_bytes());
    assert_eq!(
        relocate(&mut image, TABLE..TABLE + 14, 1),
        Err(PeError::FixupOutsideImage { rva: 0x3008 })
    );
}

#[test]
fn other_fixup_types_are_refused() {
    // HIGHLOW (3), a 32-bit fixup: never in an x86-64 image.
    let mut image = image_with(&[0x3010, 0x0000]);
    let table = Headers::parse(&image).unwrap().relocations;
    assert_eq!(
        relocate(&mut image, table, 1),
        Err(PeError::UnsupportedFixup { kind: 3, rva: 0x1010 })
    );
}
