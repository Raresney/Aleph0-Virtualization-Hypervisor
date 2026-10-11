//! Unit tests for `src/vmx/vmcs/launch.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;

const CF: u64 = 1 << 0;
const ZF: u64 = 1 << 6;
/// RFLAGS bit 1 always reads as 1.
const RESERVED: u64 = 1 << 1;
/// RFLAGS.IF: firmware calls the launch with interrupts on.
const IF: u64 = 1 << 9;

const VMCALL: ExitReason = ExitReason { basic: 18, entry_failure: false };

#[test]
fn rflags_from_a_failed_vmlaunch_decode_as_launch_failed() {
    // The launch stub returns RFLAGS unencoded (kind 0).
    assert_eq!(
        decode(RESERVED | IF | CF),
        GuestStop::LaunchFailed { error: VmcsError::VmFailInvalid, instruction_error: None },
    );
    assert_eq!(
        decode(RESERVED | IF | ZF),
        GuestStop::LaunchFailed { error: VmcsError::VmFailValid, instruction_error: None },
    );
    assert_eq!(
        decode(RESERVED | IF),
        GuestStop::LaunchFailed { error: VmcsError::LaunchReturned, instruction_error: None },
    );
}

#[test]
fn finished_keeps_the_exit_count() {
    assert_eq!(decode(encode_finished(2)), GuestStop::Finished { exits: 2 });
}

#[test]
fn unexpected_keeps_the_exit_number_and_reason() {
    assert_eq!(
        decode(encode_unexpected(3, 0x8000_0021)),
        GuestStop::Unexpected { number: 3, reason: ExitReason { basic: 33, entry_failure: true } },
    );
}

#[test]
fn unexpected_keeps_the_largest_exit_number_that_fits() {
    let largest = (1 << 30) - 1;
    assert_eq!(
        decode(encode_unexpected(largest, 18)),
        GuestStop::Unexpected { number: largest, reason: VMCALL },
    );
}

#[test]
fn oversized_exit_number_cannot_change_the_kind() {
    // Only the low 30 bits are kept, so bits 63:62 still say "unexpected".
    assert!(matches!(
        decode(encode_unexpected(u64::MAX, 18)),
        GuestStop::Unexpected { reason: VMCALL, .. },
    ));
}

#[test]
fn failed_vmresume_keeps_its_flags() {
    assert_eq!(
        decode(encode_resume_failed(RESERVED | ZF)),
        GuestStop::ResumeFailed { error: VmcsError::VmFailValid, instruction_error: None },
    );
    assert_eq!(
        decode(encode_resume_failed(RESERVED)),
        GuestStop::ResumeFailed { error: VmcsError::ResumeReturned, instruction_error: None },
    );
}

#[test]
fn no_stop_value_is_zero() {
    // The exit handler returns 0 to mean "resume the guest".
    assert_ne!(encode_finished(0), 0);
    assert_ne!(encode_unexpected(0, 0), 0);
    assert_ne!(encode_resume_failed(0), 0);
}
