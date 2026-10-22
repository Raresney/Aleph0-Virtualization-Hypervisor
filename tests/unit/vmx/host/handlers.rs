//! Unit tests for `src/vmx/host/handlers.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items. The fault stubs are assembled into the test binary too,
//! so their bytes are checked here.

use super::*;

/// The bytes a stub starts with: `push $0` when the CPU pushes no error
/// code, then `push $vector`, as a sign-extended byte below 128 and a
/// 32-bit immediate from 128 on.
fn expected_prefix(vector: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    if !has_error_code(vector) {
        bytes.extend([0x6A, 0x00]);
    }
    if vector < 128 {
        bytes.extend([0x6A, vector]);
    } else {
        bytes.extend([0x68, vector, 0, 0, 0]);
    }
    bytes
}

#[test]
fn every_stub_pushes_its_error_code_slot_and_vector() {
    let stubs = stubs();
    for vector in 0..=u8::MAX {
        let start = usize::from(vector) * STUB_SIZE as usize;
        let prefix = expected_prefix(vector);
        assert_eq!(
            &stubs[start..start + prefix.len()],
            prefix.as_slice(),
            "stub of vector {vector}"
        );
    }
}

#[test]
fn every_stub_then_jumps_to_the_common_part() {
    let stubs = stubs();
    for vector in 0..=u8::MAX {
        let start = usize::from(vector) * STUB_SIZE as usize;
        let jump = stubs[start + expected_prefix(vector).len()];
        // JMP rel8 or JMP rel32.
        assert!(matches!(jump, 0xEB | 0xE9), "stub of vector {vector}: {jump:#04x}");
    }
}

#[test]
fn gates_point_at_the_nmi_entry_and_the_fault_stubs() {
    assert_eq!(handler_address(NMI_VECTOR), host_nmi_entry as *const () as u64);
    let stubs = (&raw const host_vector_stubs) as u64;
    assert_eq!(handler_address(0), stubs);
    assert_eq!(handler_address(13), stubs + 13 * 16);
    assert_eq!(handler_address(255), stubs + 255 * 16);
}

#[test]
fn a_pending_nmi_is_taken_once() {
    NMI_PENDING.store(true, Ordering::Release);
    assert!(nmi_pending());
    assert!(take_pending_nmi());
    assert!(!nmi_pending());
    assert!(!take_pending_nmi());
}

#[test]
fn the_exception_frame_matches_what_the_stubs_and_the_cpu_push() {
    // The stub's two pushes, then the CPU's five, lowest address first.
    assert_eq!(core::mem::size_of::<ExceptionFrame>(), 7 * 8);
    assert_eq!(core::mem::offset_of!(ExceptionFrame, error_code), 8);
    assert_eq!(core::mem::offset_of!(ExceptionFrame, rip), 16);
    assert_eq!(core::mem::offset_of!(ExceptionFrame, ss), 48);
}
