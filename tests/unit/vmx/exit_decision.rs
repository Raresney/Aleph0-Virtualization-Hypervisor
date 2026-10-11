//! Unit tests for `src/vmx/exit_decision.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;

const MARKER: u64 = GUEST_MARKER as u64;
const NMI_MARKER: u64 = GUEST_NMI_MARKER as u64;
/// VM_EXIT_INTERRUPTION_INFO of an NMI exit.
const NMI_INFO: u32 = 0x8000_0202;

/// Before the first exit.
const START: ExitState = ExitState { main_vmcalls: 0, nmi_pending: false, nmis_injected: 0, nmis_handled: 0 };
/// After main VMCALL #1: the guest is in its wait loop.
const WAITING: ExitState = ExitState { main_vmcalls: 1, ..START };

fn exit(basic: u16) -> ExitInfo {
    ExitInfo {
        reason: ExitReason { basic, entry_failure: false },
        interruption_info: 0,
        guest_rax: 0,
        interruptibility: 0,
        idt_vectoring_valid: false,
    }
}

fn vmcall(rax: u64) -> ExitInfo {
    ExitInfo { guest_rax: rax, ..exit(EXIT_REASON_VMCALL) }
}

fn nmi(interruptibility: u32) -> ExitInfo {
    ExitInfo { interruption_info: NMI_INFO, interruptibility, ..exit(EXIT_REASON_EXCEPTION_OR_NMI) }
}

#[test]
fn injected_nmi_is_valid_type_2_vector_2() {
    assert_eq!(INJECT_NMI, 0x8000_0202);
}

#[test]
fn nmi_info_is_recognised() {
    assert!(is_nmi(0x8000_0202));
    // Bit 12 (NMI unblocking due to IRET) does not change what it is.
    assert!(is_nmi(0x8000_1202));
}

#[test]
fn exceptions_and_invalid_info_are_not_nmis() {
    // Page fault: hardware exception (type 3), error code valid, vector 14.
    assert!(!is_nmi(0x8000_0B0E));
    // NMI bits without the valid bit.
    assert!(!is_nmi(0x0000_0202));
    // Right vector, wrong type: hardware exception (type 3), vector 2.
    assert!(!is_nmi(0x8000_0302));
    // Right type, wrong vector: NMI type, vector 3.
    assert!(!is_nmi(0x8000_0203));
}

#[test]
fn first_main_vmcall_resumes() {
    assert_eq!(decide(START, vmcall(MARKER)), (ExitEvent::MainVmcall, WAITING));
}

#[test]
fn second_main_vmcall_without_an_nmi_finishes() {
    assert_eq!(
        decide(WAITING, vmcall(MARKER + 1)),
        (ExitEvent::LastMainVmcall, ExitState { main_vmcalls: 2, ..START }),
    );
}

#[test]
fn repeated_main_vmcall_is_unexpected() {
    // RAX unchanged: the guest ran the same VMCALL again, so RIP was not
    // advanced past it.
    assert_eq!(decide(WAITING, vmcall(MARKER)), (ExitEvent::Unexpected, WAITING));
}

#[test]
fn nmi_while_unblocked_is_injected() {
    assert_eq!(
        decide(WAITING, nmi(0)),
        (ExitEvent::NmiInjected, ExitState { nmis_injected: 1, ..WAITING }),
    );
}

#[test]
fn nmi_while_blocked_by_sti_waits_for_the_window() {
    // The SDM requires bit 0 to be 0 for an NMI injection, so STI blocking
    // defers the NMI just like NMI blocking does.
    assert_eq!(decide(WAITING, nmi(BLOCKING_BY_STI)).0, ExitEvent::NmiDeferred);
}

#[test]
fn nmi_while_blocked_by_nmi_waits_for_the_window() {
    assert_eq!(
        decide(WAITING, nmi(BLOCKING_BY_NMI)),
        (ExitEvent::NmiDeferred, ExitState { nmi_pending: true, ..WAITING }),
    );
}

#[test]
fn nmi_while_blocked_by_mov_ss_waits_for_the_window() {
    assert_eq!(decide(WAITING, nmi(BLOCKING_BY_MOV_SS)).0, ExitEvent::NmiDeferred);
}

#[test]
fn window_exit_injects_the_pending_nmi() {
    let pending = ExitState { nmi_pending: true, ..WAITING };
    assert_eq!(
        decide(pending, exit(EXIT_REASON_NMI_WINDOW)),
        (ExitEvent::NmiWindowInjected, ExitState { nmis_injected: 1, ..WAITING }),
    );
}

#[test]
fn window_exit_while_still_blocked_keeps_waiting() {
    let pending = ExitState { nmi_pending: true, ..WAITING };
    let still_blocked = ExitInfo { interruptibility: BLOCKING_BY_STI, ..exit(EXIT_REASON_NMI_WINDOW) };
    assert_eq!(decide(pending, still_blocked), (ExitEvent::NmiDeferred, pending));
}

#[test]
fn window_exit_without_a_pending_nmi_is_unexpected() {
    assert_eq!(decide(WAITING, exit(EXIT_REASON_NMI_WINDOW)), (ExitEvent::Unexpected, WAITING));
}

#[test]
fn guest_nmi_handler_vmcall_resumes() {
    let injected = ExitState { nmis_injected: 1, ..WAITING };
    assert_eq!(
        decide(injected, vmcall(NMI_MARKER)),
        (ExitEvent::GuestNmiHandler, ExitState { nmis_handled: 1, ..injected }),
    );
}

#[test]
fn full_nmi_run_finishes_with_both_counts() {
    let mut state = START;
    let mut event = ExitEvent::Unexpected;
    for exit in [vmcall(MARKER), nmi(0), vmcall(NMI_MARKER), vmcall(MARKER + 1)] {
        (event, state) = decide(state, exit);
    }
    assert_eq!(event, ExitEvent::LastMainVmcall);
    assert_eq!(state, ExitState { main_vmcalls: 2, nmi_pending: false, nmis_injected: 1, nmis_handled: 1 });
}

#[test]
fn deferred_nmi_run_finishes_with_both_counts() {
    let exits = [vmcall(MARKER), nmi(BLOCKING_BY_NMI), exit(EXIT_REASON_NMI_WINDOW), vmcall(NMI_MARKER), vmcall(MARKER + 1)];
    let mut state = START;
    let mut event = ExitEvent::Unexpected;
    for exit in exits {
        (event, state) = decide(state, exit);
    }
    assert_eq!(event, ExitEvent::LastMainVmcall);
    assert_eq!(state, ExitState { main_vmcalls: 2, nmi_pending: false, nmis_injected: 1, nmis_handled: 1 });
}

#[test]
fn interrupted_delivery_is_never_handled() {
    let interrupted = ExitInfo { idt_vectoring_valid: true, ..vmcall(MARKER) };
    assert_eq!(decide(START, interrupted), (ExitEvent::InterruptedDelivery, START));
}

#[test]
fn entry_failure_is_unexpected() {
    let failed = ExitInfo { reason: ExitReason { basic: EXIT_REASON_VMCALL, entry_failure: true }, ..vmcall(MARKER) };
    assert_eq!(decide(START, failed), (ExitEvent::Unexpected, START));
}

#[test]
fn exception_exit_is_unexpected() {
    let page_fault = ExitInfo { interruption_info: 0x8000_0B0E, ..exit(EXIT_REASON_EXCEPTION_OR_NMI) };
    assert_eq!(decide(WAITING, page_fault), (ExitEvent::Unexpected, WAITING));
}

#[test]
fn each_event_maps_to_its_action() {
    let resume = |advance_rip, inject_nmi, nmi_window| ExitAction::Resume { advance_rip, inject_nmi, nmi_window };
    assert_eq!(ExitEvent::MainVmcall.action(), resume(true, false, None));
    assert_eq!(ExitEvent::GuestNmiHandler.action(), resume(true, false, None));
    assert_eq!(ExitEvent::NmiInjected.action(), resume(false, true, Some(false)));
    assert_eq!(ExitEvent::NmiWindowInjected.action(), resume(false, true, Some(false)));
    assert_eq!(ExitEvent::NmiDeferred.action(), resume(false, false, Some(true)));
    assert_eq!(ExitEvent::LastMainVmcall.action(), ExitAction::Finished);
    assert_eq!(ExitEvent::InterruptedDelivery.action(), ExitAction::Unexpected);
    assert_eq!(ExitEvent::Unexpected.action(), ExitAction::Unexpected);
}
