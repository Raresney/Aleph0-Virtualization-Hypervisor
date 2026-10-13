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
