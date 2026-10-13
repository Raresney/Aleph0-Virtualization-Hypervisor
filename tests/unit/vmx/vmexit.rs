//! Unit tests for `src/vmx/vmexit.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;

#[test]
fn exit_reason_splits_basic_and_entry_failure() {
    assert_eq!(
        ExitReason::from_raw(18),
        ExitReason {
            basic: 18,
            entry_failure: false
        }
    );
    assert_eq!(
        ExitReason::from_raw(0x8000_0021),
        ExitReason {
            basic: 33,
            entry_failure: true
        },
    );
}

#[test]
fn exit_reason_ignores_other_high_bits() {
    // Bits 30:16 carry unrelated flags (e.g. bit 27, enclave mode).
    assert_eq!(ExitReason::from_raw(0x0800_000A).basic, 10);
}

#[test]
fn exception_vector_is_bits_7_to_0_of_valid_info() {
    // Valid (bit 31), error code (bit 11), hardware exception (type 3),
    // vector 14: a page fault.
    assert_eq!(exception_vector(0x8000_0B0E), Some(14));
}

#[test]
fn exception_vector_needs_the_valid_bit() {
    assert_eq!(exception_vector(0x0000_0B0E), None);
}

const RESUME: ExitAction = ExitAction::Resume {
    advance_rip: true,
    inject_nmi: false,
    nmi_window: None,
    grant_write: false,
};

#[test]
fn resume_tells_the_stub_to_resume() {
    assert_eq!(stub_return(RESUME, 1, 18), RESUME_GUEST);
    assert_eq!(RESUME_GUEST, 0);
}

#[test]
fn finished_stops_with_the_exit_count() {
    // Four exits: two main VMCALLs, an NMI, the guest NMI handler's VMCALL.
    assert_eq!(stub_return(ExitAction::Finished, 4, 18), vmcs::encode_finished(4));
}

#[test]
fn unexpected_stops_with_the_exit_and_its_reason() {
    assert_eq!(
        stub_return(ExitAction::Unexpected, 1, 10),
        vmcs::encode_unexpected(1, 10)
    );
}

#[test]
fn unreadable_reason_has_its_own_name() {
    assert_eq!(exit_reason_name(UNREADABLE_REASON), "VM_EXIT_REASON unreadable");
}

#[test]
fn nmi_window_exit_has_a_name() {
    assert_eq!(exit_reason_name(8), "NMI window");
}

#[test]
fn ept_exits_have_names() {
    assert_eq!(exit_reason_name(EXIT_REASON_EPT_VIOLATION), "EPT violation");
    assert_eq!(exit_reason_name(EXIT_REASON_EPT_MISCONFIG), "EPT misconfiguration");
}

#[test]
fn ept_access_name_prefers_write() {
    assert_eq!(ept_access_name(0x18A), "write");
    // Hardware may report a read along with the write of a read-modify-write.
    assert_eq!(ept_access_name(EPT_ACCESS_READ | EPT_ACCESS_WRITE), "write");
    assert_eq!(ept_access_name(EPT_ACCESS_FETCH), "instruction fetch");
    assert_eq!(ept_access_name(EPT_ACCESS_READ), "read");
    assert_eq!(ept_access_name(0), "no access bit set");
}

#[test]
fn ept_page_permissions_come_from_bits_5_to_3() {
    // The guest's data page: readable only.
    assert_eq!(ept_page_permissions(0x18A), (1, 0, 0));
    assert_eq!(ept_page_permissions(0x38), (1, 1, 1));
}
