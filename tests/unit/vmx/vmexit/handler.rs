//! Unit tests for `src/vmx/vmexit/handler.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;

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
