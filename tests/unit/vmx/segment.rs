//! Unit tests for `src/vmx/segment.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;

/// Describe `gdt` the way GDTR would.
fn table(gdt: &[u8]) -> DescriptorTable {
    DescriptorTable {
        base: gdt.as_ptr() as u64,
        limit: gdt.len() as u16 - 1,
    }
}

#[test]
fn null_and_ldt_selectors_return_zero() {
    let gdt = [0xFFu8; 32];
    let gdt = table(&gdt);
    for selector in [0x0, 0x1, 0x3] {
        assert_eq!(
            unsafe { segment_base_from_gdt(&gdt, selector) },
            0,
            "selector {selector:#x}"
        );
    }
    // TI=1 names the LDT, which this decoder does not read.
    assert_eq!(unsafe { segment_base_from_gdt(&gdt, 0x0C) }, 0);
}

#[test]
fn selector_past_limit_returns_zero() {
    // The 16-byte TSS descriptor at 0x10 needs 16 bytes; only 8 are inside
    // the limit.
    let gdt = [0xFFu8; 24];
    assert_eq!(unsafe { segment_base_from_gdt(&table(&gdt), 0x10) }, 0);
}

#[test]
fn rpl_bits_are_ignored() {
    let mut gdt = [0u8; 32];
    gdt[0x10 + 2] = 0x78;
    gdt[0x10 + 3] = 0x56;
    gdt[0x10 + 4] = 0x34;
    gdt[0x10 + 7] = 0x12;
    let gdt = table(&gdt);
    assert_eq!(unsafe { segment_base_from_gdt(&gdt, 0x10) }, 0x1234_5678);
    assert_eq!(unsafe { segment_base_from_gdt(&gdt, 0x13) }, 0x1234_5678);
}

/// The usual flat 64-bit code descriptor: base 0, limit 0xFFFFF with
/// G = 1, L = 1, present, DPL 0, execute/read, accessed.
const FLAT_CODE_64: u64 = 0x00AF_9B00_0000_FFFF;
/// The usual flat data descriptor: G = 1, D/B = 1, read/write, accessed.
const FLAT_DATA: u64 = 0x00CF_9300_0000_FFFF;

#[test]
fn flat_code_descriptor_decodes() {
    assert_eq!(SegmentDescriptor(FLAT_CODE_64).base(), 0);
    assert_eq!(SegmentDescriptor(FLAT_CODE_64).limit(), 0xFFFF_FFFF);
    // G=1 L=1 | P=1 DPL=0 S=1 type=0xB
    assert_eq!(SegmentDescriptor(FLAT_CODE_64).access_rights(), 0xA09B);
}

#[test]
fn flat_data_descriptor_decodes() {
    assert_eq!(SegmentDescriptor(FLAT_DATA).limit(), 0xFFFF_FFFF);
    // G=1 D/B=1 | P=1 DPL=0 S=1 type=0x3
    assert_eq!(SegmentDescriptor(FLAT_DATA).access_rights(), 0xC093);
}

#[test]
fn scattered_base_and_byte_limit_decode() {
    // base 0x1234_5678, limit 0x1_2345 with G=0, P S type=0x3.
    let descriptor = 0x1201_9334_5678_2345;
    assert_eq!(SegmentDescriptor(descriptor).base(), 0x1234_5678);
    assert_eq!(SegmentDescriptor(descriptor).limit(), 0x1_2345);
    // Limit bits 19:16 sit between the two access-rights halves; they
    // must not leak into access-rights bits 11:8.
    assert_eq!(SegmentDescriptor(descriptor).access_rights(), 0x0093);
}

#[test]
fn read_descriptor_rejects_null_ldt_and_out_of_range() {
    let gdt = [0xFFu8; 24];
    let gdt = table(&gdt);
    assert_eq!(unsafe { read_descriptor(&gdt, 0x00) }, None);
    assert_eq!(unsafe { read_descriptor(&gdt, 0x03) }, None, "null with RPL 3");
    assert_eq!(unsafe { read_descriptor(&gdt, 0x0C) }, None, "TI=1 names the LDT");
    assert_eq!(unsafe { read_descriptor(&gdt, 0x18) }, None, "past the limit");
}

#[test]
fn read_descriptor_ignores_rpl() {
    let mut gdt = [0u8; 24];
    gdt[0x10..0x18].copy_from_slice(&FLAT_DATA.to_le_bytes());
    let gdt = table(&gdt);
    assert_eq!(
        unsafe { read_descriptor(&gdt, 0x10) },
        Some(SegmentDescriptor(FLAT_DATA))
    );
    assert_eq!(
        unsafe { read_descriptor(&gdt, 0x13) },
        Some(SegmentDescriptor(FLAT_DATA))
    );
}

#[test]
fn descriptor_table_operand_is_limit_then_base() {
    let table = DescriptorTable {
        base: 0x1122_3344_5566_7788,
        limit: 0xABCD,
    };
    assert_eq!(
        table.to_operand(),
        [0xCD, 0xAB, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
    );
}

#[test]
fn descriptor_table_operand_round_trips() {
    let table = DescriptorTable {
        base: 0x1122_3344_5566_7788,
        limit: 0x004F,
    };
    let operand = table.to_operand();
    assert_eq!(operand, [0x4F, 0x00, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
    assert_eq!(DescriptorTable::from_operand(operand), table);
}

#[test]
fn descriptor_offset_rules() {
    let gdt = DescriptorTable {
        base: 0x1000,
        limit: 0x4F,
    }; // 80 bytes
    assert_eq!(descriptor_offset(&gdt, 0x00, 8), None, "null selector");
    assert_eq!(descriptor_offset(&gdt, 0x03, 8), None, "null selector with RPL 3");
    assert_eq!(descriptor_offset(&gdt, 0x2C, 8), None, "TI = 1 names the LDT");
    assert_eq!(descriptor_offset(&gdt, 0x28, 8), Some(0x28));
    assert_eq!(descriptor_offset(&gdt, 0x2B, 8), Some(0x28), "RPL bits are ignored");
    assert_eq!(
        descriptor_offset(&gdt, 0x40, 16),
        Some(0x40),
        "16 bytes end exactly at the limit"
    );
    assert_eq!(descriptor_offset(&gdt, 0x48, 16), None, "16 bytes past the limit");
}

#[test]
fn system_descriptor_base_joins_all_four_pieces() {
    let mut bytes = [0u8; 16];
    bytes[2] = 0x88;
    bytes[3] = 0x77;
    bytes[4] = 0x66;
    bytes[7] = 0x55;
    bytes[8..12].copy_from_slice(&0x1122_3344u32.to_le_bytes());
    assert_eq!(system_descriptor_base(&bytes), 0x1122_3344_5566_7788);
}
