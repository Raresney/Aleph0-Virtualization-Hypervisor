//! Unit tests for `src/vmx/host_tables.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;

/// Base with a distinct byte in every position, so a byte landing in the
/// wrong field is caught.
const BASE: u64 = 0x1122_3344_5566_7788;

#[test]
fn tss_descriptor_layout() {
    let descriptor = tss_descriptor(BASE, 0x67);
    assert_eq!(
        descriptor,
        [
            0x67, 0x00, 0x88, 0x77, 0x66, 0x89, 0x00, 0x55, 0x44, 0x33, 0x22, 0x11, 0, 0, 0, 0
        ],
    );
}

#[test]
fn tss_descriptor_limit_high_bits() {
    let descriptor = tss_descriptor(0, 0xA_BCDE);
    assert_eq!(&descriptor[0..2], &[0xDE, 0xBC]);
    assert_eq!(descriptor[6], 0x0A, "limit 19:16 in the low nibble, flags clear");
}

#[test]
fn tss_descriptor_round_trips_through_gdt_decoder() {
    // Null descriptor, one code descriptor, then the 16-byte TSS at 0x10.
    let mut gdt = [0u8; 32];
    gdt[8..16].copy_from_slice(&0x00AF_9B00_0000_FFFFu64.to_le_bytes());
    gdt[16..32].copy_from_slice(&tss_descriptor(BASE, 0x67));
    let table = DescriptorTable {
        base: gdt.as_ptr() as u64,
        limit: gdt.len() as u16 - 1,
    };

    // SAFETY: `table` describes `gdt`, a live local array.
    assert_eq!(unsafe { segment_base_from_gdt(&table, 0x10) }, BASE);
}

#[test]
fn tss_holds_its_interrupt_stacks_and_no_io_bitmap() {
    let tss = Tss::new([0x1000, 0x2000, 0x3000, 0, 0, 0, 0x7000]);
    // Fields of a packed struct are copied out before comparing.
    assert_eq!(({ tss.ist1 }, { tss.ist2 }, { tss.ist3 }), (0x1000, 0x2000, 0x3000));
    assert_eq!(({ tss.ist4 }, { tss.ist7 }), (0, 0x7000));
    assert_eq!(({ tss.rsp0 }, { tss.rsp1 }, { tss.rsp2 }), (0, 0, 0));
    // The I/O map starts past the limit: no I/O permission bitmap.
    assert_eq!({ tss.iomap_base }, 0x68);
}
