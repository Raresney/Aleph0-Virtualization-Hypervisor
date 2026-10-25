//! Unit tests for `src/vmx/guest_state.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;

const FLAT_CODE_64: u64 = 0x00AF_9B00_0000_FFFF;
/// Flat data descriptor with the accessed bit clear (type 0x2).
const FLAT_DATA_NOT_ACCESSED: u64 = 0x00CF_9200_0000_FFFF;
/// Busy 64-bit TSS descriptor, low 8 bytes: limit 0x67, type 0xB, P = 1.
const BUSY_TSS: u64 = 0x0000_8B00_0000_0067;

/// The Hyper-V firmware's IDT.
const FIRMWARE_IDT: DescriptorTable = DescriptorTable {
    base: 0x7f0a_4018,
    limit: 0xfff,
};

#[test]
fn the_test_guest_starts_at_its_code_with_interrupts_off_and_its_own_idt() {
    let idt = DescriptorTable {
        base: 0x7eae_e000,
        limit: 0x2f,
    };
    let entry = GuestEntry::At {
        rip: 0x7eae_c000,
        rsp: 0x7eae_f000,
        idtr: idt,
    };
    assert_eq!(entry.registers(), (0x7eae_c000, 0x7eae_f000, 0x2));
    assert_eq!(entry.idtr(), idt);
}

#[test]
fn in_place_keeps_the_firmware_idt_and_leaves_rip_rsp_and_rflags_to_vmlaunch() {
    let entry = GuestEntry::InPlace { idtr: FIRMWARE_IDT };
    // Placeholders: `launch_in_place` writes the real ones at VMLAUNCH.
    assert_eq!(entry.registers(), (0, 0, 0x2));
    assert_eq!(entry.idtr(), FIRMWARE_IDT);
}

#[test]
fn data_segment_gets_accessed_bit() {
    let segment = GuestSegment::from_descriptor(0x30, SegmentDescriptor(FLAT_DATA_NOT_ACCESSED), 0);
    assert_eq!(segment.access_rights, 0xC093);
    assert_eq!(segment.limit, 0xFFFF_FFFF);
}

#[test]
fn system_segment_type_is_left_alone() {
    // Bit 0 of a system type is not "accessed": type 0xA would be a
    // different descriptor kind, so it must not be touched.
    let segment = GuestSegment::from_descriptor(0x40, SegmentDescriptor(0x0000_8A00_0000_0067), 0x1000);
    assert_eq!(segment.access_rights, 0x008A);
}

#[test]
fn null_selector_is_unusable_but_keeps_base() {
    let segment = GuestSegment::unusable(0, 0xFFFF_8000_0000_0000);
    assert!(!segment.is_usable());
    assert_eq!(segment.base, 0xFFFF_8000_0000_0000);
}

#[test]
fn long_mode_cs_and_busy_tss_pass() {
    let cs = GuestSegment::from_descriptor(0x38, SegmentDescriptor(FLAT_CODE_64), 0);
    let tr = GuestSegment::from_descriptor(0x50, SegmentDescriptor(BUSY_TSS), 0x1000);
    assert_eq!(check_segments(&cs, &tr), Ok(()));
}

#[test]
fn compatibility_mode_cs_is_refused() {
    // Same code descriptor with L = 0, D/B = 1: 32-bit code.
    let cs = GuestSegment::from_descriptor(0x38, SegmentDescriptor(0x00CF_9B00_0000_FFFF), 0);
    let tr = GuestSegment::from_descriptor(0x50, SegmentDescriptor(BUSY_TSS), 0x1000);
    assert_eq!(
        check_segments(&cs, &tr),
        Err(GuestStateError::CsNot64Bit { access_rights: 0xC09B })
    );
}

#[test]
fn available_tss_is_refused() {
    // Type 0x9: a TSS that LTR has not marked busy.
    let cs = GuestSegment::from_descriptor(0x38, SegmentDescriptor(FLAT_CODE_64), 0);
    let tr = GuestSegment::from_descriptor(0x50, SegmentDescriptor(0x0000_8900_0000_0067), 0x1000);
    assert_eq!(
        check_segments(&cs, &tr),
        Err(GuestStateError::TrNotBusyTss { access_rights: 0x0089 })
    );
}

#[test]
fn unusable_tr_is_refused() {
    let cs = GuestSegment::from_descriptor(0x38, SegmentDescriptor(FLAT_CODE_64), 0);
    let tr = GuestSegment::unusable(0, 0);
    assert!(matches!(
        check_segments(&cs, &tr),
        Err(GuestStateError::TrNotBusyTss { .. })
    ));
}

#[test]
fn the_segment_table_lists_the_registers_in_the_sdm_order() {
    // The SDM numbers each kind of segment field ES, CS, SS, DS, FS, GS, LDTR,
    // TR, two apart; `GuestState::segments` lists the registers the same way.
    for (index, fields) in SEGMENT_FIELDS.iter().enumerate() {
        let step = 2 * index as u32;
        assert_eq!(fields.selector, fields::GUEST_ES_SELECTOR + step, "register {index}");
        assert_eq!(fields.base, fields::GUEST_ES_BASE + step, "register {index}");
        assert_eq!(fields.limit, fields::GUEST_ES_LIMIT + step, "register {index}");
        assert_eq!(
            fields.access_rights,
            fields::GUEST_ES_ACCESS_RIGHTS + step,
            "register {index}"
        );
    }
    assert_eq!(SEGMENT_FIELDS[1].selector, fields::GUEST_CS_SELECTOR);
    assert_eq!(SEGMENT_FIELDS[7].access_rights, fields::GUEST_TR_ACCESS_RIGHTS);
}

#[test]
fn a_segment_prints_as_the_guest_state_line_shows_it() {
    // The Hyper-V firmware's CS.
    let cs = GuestSegment {
        selector: 0x28,
        base: 0,
        limit: 0xffff_ffff,
        access_rights: 0xa09b,
    };
    assert_eq!(
        cs.to_string(),
        "selector=0x0028 base=0x0000000000000000 limit=0xffffffff access=0x0a09b"
    );
}
