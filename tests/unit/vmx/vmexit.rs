//! Unit tests for `src/vmx/vmexit.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;
use crate::vmx::exit_decision::{EPT_ACCESS_FETCH, EPT_ACCESS_READ, EPT_ACCESS_WRITE};

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
    assert_eq!(InterruptionInfo(0x8000_0B0E).vector(), Some(14));
}

#[test]
fn exception_vector_needs_the_valid_bit() {
    assert_eq!(InterruptionInfo(0x0000_0B0E).vector(), None);
}

const RESUME: ExitAction = ExitAction::Resume(ResumePlan::PAST_INSTRUCTION);

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
    assert_eq!(EptQualification(0x18A).access_name(), "write");
    // Hardware may report a read along with the write of a read-modify-write.
    assert_eq!(
        EptQualification(EPT_ACCESS_READ | EPT_ACCESS_WRITE).access_name(),
        "write"
    );
    assert_eq!(EptQualification(EPT_ACCESS_FETCH).access_name(), "instruction fetch");
    assert_eq!(EptQualification(EPT_ACCESS_READ).access_name(), "read");
    assert_eq!(EptQualification(0).access_name(), "no access bit set");
}

#[test]
fn ept_page_permissions_come_from_bits_5_to_3() {
    // The guest's data page: readable only.
    assert_eq!(EptQualification(0x18A).permissions(), (1, 0, 0));
    assert_eq!(EptQualification(0x38).permissions(), (1, 1, 1));
}
