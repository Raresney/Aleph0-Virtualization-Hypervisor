//! Base relocation of a loaded PE32+ image: what moving Aleph0's image to
//! another address needs (Microsoft PE format specification, "The .reloc
//! Section (Image Only)").
//!
//! The linker writes every absolute address in the image (a vtable entry,
//! a pointer in a static) for one base address, and lists where each one
//! is in the base relocation table. A loader that puts the image `delta`
//! bytes away from that base adds `delta` to each listed address. The
//! firmware did that when it loaded Aleph0, and `ResidentImage::copy` does
//! it again, from the loaded image to its copy.
//!
//! ```text
//! 0x00  "MZ"
//! 0x3C  offset of the PE signature ──▶ "PE\0\0"
//!                                      COFF file header, 20 bytes
//!                                      optional header, magic 0x20B (PE32+):
//!                                        +56   SizeOfImage
//!                                        +108  NumberOfRvaAndSizes
//!                                        +112  data directories, 8 bytes each;
//!                                              #5: base relocation table (RVA, size)
//!
//! base relocation table: one block per 4 KiB page that has fixups
//!   page RVA (4 bytes) │ block size (4 bytes) │ entries, 2 bytes each: type 15:12, offset 11:0
//!
//!   type 10 (DIR64):    add delta to the 8 bytes at page RVA + offset
//!   type 0 (ABSOLUTE):  nothing; pads the block
//! ```
//!
//! An RVA is an offset from the image's start: once loaded, every section
//! sits at its RVA. An x86-64 image has no fixup type but these two.

use core::ops::Range;

/// Why an image could not be relocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeError {
    /// The headers are not a PE32+ image's, or lie outside the image.
    NotPe32Plus,
    /// The image has no base relocation table, so it cannot move.
    NoRelocations,
    /// The base relocation table lies outside the image.
    TableOutsideImage,
    /// The block at `offset` in the table is shorter than its header, has
    /// an odd size, or runs past the table's end.
    BadBlock { offset: usize },
    /// The DIR64 fixup at `rva` would write outside the image.
    FixupOutsideImage { rva: usize },
    /// The entry for `rva` has a type other than DIR64 and ABSOLUTE.
    UnsupportedFixup { kind: u8, rva: usize },
}

/// "MZ": the DOS header every PE image starts with.
const DOS_MAGIC: &[u8] = b"MZ";
/// Offset of the field holding the PE signature's offset.
const PE_OFFSET_FIELD: usize = 0x3C;
const PE_SIGNATURE: &[u8] = b"PE\0\0";
const COFF_HEADER_SIZE: usize = 20;
/// The optional header's magic for a PE32+ (64-bit) image.
const PE32_PLUS_MAGIC: u16 = 0x20B;
// Offsets in the PE32+ optional header.
const SIZE_OF_IMAGE: usize = 56;
const NUMBER_OF_RVA_AND_SIZES: usize = 108;
const DATA_DIRECTORIES: usize = 112;
/// Data directory #5: the base relocation table.
const BASE_RELOCATION_DIRECTORY: usize = 5;
const DATA_DIRECTORY_SIZE: usize = 8;
/// A block's page RVA and size.
const BLOCK_HEADER_SIZE: usize = 8;
const FIXUP_ABSOLUTE: u8 = 0;
const FIXUP_DIR64: u8 = 10;

/// What relocating a loaded image needs from its headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Headers {
    /// SizeOfImage: how many bytes the loaded image takes.
    pub size_of_image: usize,
    /// Where the base relocation table lies in the loaded image.
    pub relocations: Range<usize>,
}

impl Headers {
    /// Reads the headers at the start of the loaded `image`.
    pub fn parse(image: &[u8]) -> Result<Self, PeError> {
        if image.get(..DOS_MAGIC.len()) != Some(DOS_MAGIC) {
            return Err(PeError::NotPe32Plus);
        }
        let signature = read_u32(image, PE_OFFSET_FIELD).ok_or(PeError::NotPe32Plus)? as usize;
        if image.get(signature..signature.saturating_add(PE_SIGNATURE.len())) != Some(PE_SIGNATURE) {
            return Err(PeError::NotPe32Plus);
        }
        let optional = signature + PE_SIGNATURE.len() + COFF_HEADER_SIZE;
        if read_u16(image, optional) != Some(PE32_PLUS_MAGIC) {
            return Err(PeError::NotPe32Plus);
        }
        let size_of_image = read_u32(image, optional + SIZE_OF_IMAGE).ok_or(PeError::NotPe32Plus)? as usize;
        let directories = read_u32(image, optional + NUMBER_OF_RVA_AND_SIZES).ok_or(PeError::NotPe32Plus)? as usize;
        if directories <= BASE_RELOCATION_DIRECTORY {
            return Err(PeError::NoRelocations);
        }
        let directory = optional + DATA_DIRECTORIES + BASE_RELOCATION_DIRECTORY * DATA_DIRECTORY_SIZE;
        let rva = read_u32(image, directory).ok_or(PeError::NotPe32Plus)? as usize;
        let size = read_u32(image, directory + 4).ok_or(PeError::NotPe32Plus)? as usize;
        if size == 0 {
            return Err(PeError::NoRelocations);
        }
        let relocations = rva..rva + size;
        if relocations.end > image.len() {
            return Err(PeError::TableOutsideImage);
        }
        Ok(Self {
            size_of_image,
            relocations,
        })
    }
}

/// Adds `delta` to every DIR64 fixup the base relocation table at `table`
/// lists in the loaded `image`, and returns how many there were.
///
/// On an error the image is left partly relocated, so it must not run.
pub fn relocate(image: &mut [u8], table: Range<usize>, delta: u64) -> Result<usize, PeError> {
    let mut fixups = 0;
    let mut block = table.start;
    while block < table.end {
        let bad_block = PeError::BadBlock {
            offset: block - table.start,
        };
        let page = read_u32(image, block).ok_or(bad_block)? as usize;
        let size = read_u32(image, block + 4).ok_or(bad_block)? as usize;
        if size < BLOCK_HEADER_SIZE || !size.is_multiple_of(2) || size > table.end - block {
            return Err(bad_block);
        }
        for entry in (block + BLOCK_HEADER_SIZE..block + size).step_by(2) {
            let entry = read_u16(image, entry).ok_or(bad_block)?;
            let rva = page + usize::from(entry & 0xFFF);
            match (entry >> 12) as u8 {
                FIXUP_ABSOLUTE => {}
                FIXUP_DIR64 => {
                    let address = read(image, rva)
                        .map(u64::from_le_bytes)
                        .ok_or(PeError::FixupOutsideImage { rva })?;
                    // In bounds: `read` just read these 8 bytes.
                    image[rva..rva + size_of::<u64>()].copy_from_slice(&address.wrapping_add(delta).to_le_bytes());
                    fixups += 1;
                }
                kind => return Err(PeError::UnsupportedFixup { kind, rva }),
            }
        }
        block += size;
    }
    Ok(fixups)
}

/// The `N` bytes at `offset` in `bytes`, if they are all there.
fn read<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    bytes.get(offset..offset.checked_add(N)?)?.try_into().ok()
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    read(bytes, offset).map(u16::from_le_bytes)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    read(bytes, offset).map(u32::from_le_bytes)
}

#[cfg(test)]
#[path = "../../tests/unit/resident/pe.rs"]
mod tests;
