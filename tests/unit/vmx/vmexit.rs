//! Unit tests for `src/vmx/vmexit.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;

#[test]
fn exit_reason_splits_basic_and_entry_failure() {
    assert_eq!(ExitReason::from_raw(18), ExitReason { basic: 18, entry_failure: false });
    assert_eq!(
        ExitReason::from_raw(0x8000_0021),
        ExitReason { basic: 33, entry_failure: true },
    );
}

#[test]
fn exit_reason_ignores_other_high_bits() {
    // Bits 30:16 carry unrelated flags (e.g. bit 27, enclave mode).
    assert_eq!(ExitReason::from_raw(0x0800_000A).basic, 10);
}

const VMCALL_EXIT: ExitReason = ExitReason { basic: 18, entry_failure: false };
const MARKER: u64 = GUEST_MARKER as u64;

#[test]
fn first_vmcall_with_marker_is_expected() {
    assert!(is_expected_vmcall_exit(1, VMCALL_EXIT, MARKER));
}

#[test]
fn second_vmcall_with_marker_plus_one_is_expected() {
    // The resumed guest ran `inc eax` before its second VMCALL.
    assert!(is_expected_vmcall_exit(2, VMCALL_EXIT, MARKER + 1));
}

#[test]
fn second_vmcall_with_unchanged_marker_is_not_expected() {
    // RAX unchanged means the guest re-ran the same VMCALL: guest RIP
    // was not advanced past it.
    assert!(!is_expected_vmcall_exit(2, VMCALL_EXIT, MARKER));
}

#[test]
fn vmcall_without_marker_is_not_expected() {
    // Right reason, but RAX does not prove the guest's own code ran.
    assert!(!is_expected_vmcall_exit(1, VMCALL_EXIT, 0));
}

#[test]
fn entry_failure_is_never_expected() {
    let invalid_guest_state = ExitReason { basic: 33, entry_failure: true };
    assert!(!is_expected_vmcall_exit(1, invalid_guest_state, MARKER));
}

#[test]
fn entry_failure_alone_rules_out_an_expected_exit() {
    // Right basic reason and marker; only the entry-failure bit differs.
    let failed_vmcall = ExitReason { basic: 18, entry_failure: true };
    assert!(!is_expected_vmcall_exit(1, failed_vmcall, MARKER));
}

#[test]
fn other_reason_alone_rules_out_an_expected_exit() {
    // Marker present and no entry failure; only the basic reason (CPUID)
    // differs.
    let cpuid_exit = ExitReason { basic: 10, entry_failure: false };
    assert!(!is_expected_vmcall_exit(1, cpuid_exit, MARKER));
}

#[test]
fn first_expected_exit_resumes_the_guest() {
    assert_eq!(exit_action(1, VMCALL_EXIT, MARKER), ExitAction::Resume);
}

#[test]
fn last_planned_exit_finishes() {
    assert_eq!(
        exit_action(PLANNED_VMCALL_EXITS, VMCALL_EXIT, MARKER + PLANNED_VMCALL_EXITS - 1),
        ExitAction::Finished,
    );
}

#[test]
fn unexpected_exit_is_never_resumed() {
    let cpuid_exit = ExitReason { basic: 10, entry_failure: false };
    assert_eq!(exit_action(1, cpuid_exit, MARKER), ExitAction::Unexpected);
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

#[test]
fn resume_tells_the_stub_to_resume() {
    assert_eq!(stub_return(ExitAction::Resume, 1, 18), RESUME_GUEST);
    assert_eq!(RESUME_GUEST, 0);
}

#[test]
fn finished_stops_with_the_exit_count() {
    assert_eq!(stub_return(ExitAction::Finished, 2, 18), vmcs::encode_finished(2));
}

#[test]
fn unexpected_stops_with_the_exit_and_its_reason() {
    assert_eq!(stub_return(ExitAction::Unexpected, 1, 10), vmcs::encode_unexpected(1, 10));
}

#[test]
fn unreadable_reason_has_its_own_name() {
    assert_eq!(exit_reason_name(UNREADABLE_REASON), "VM_EXIT_REASON unreadable");
}
