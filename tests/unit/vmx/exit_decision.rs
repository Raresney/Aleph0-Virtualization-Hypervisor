//! Unit tests for `src/vmx/exit_decision.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;

const MARKER: u64 = GUEST_MARKER as u64;
const NMI_MARKER: u64 = GUEST_NMI_MARKER as u64;
/// VM_EXIT_INTERRUPTION_INFO of an NMI exit.
const NMI_INFO: InterruptionInfo = InterruptionInfo(0x8000_0202);

/// Before the first exit.
const START: ExitState = ExitState {
    main_vmcalls: 0,
    nmi_pending: false,
    nmis_injected: 0,
    nmis_handled: 0,
    ept_writes_granted: 0,
};
/// After the EPT violation: the data page is writable, main VMCALL #1 next.
const WRITTEN: ExitState = ExitState {
    ept_writes_granted: 1,
    ..START
};
/// After main VMCALL #1: the guest is in its wait loop.
const WAITING: ExitState = ExitState {
    main_vmcalls: 1,
    ..WRITTEN
};

/// GPA of the guest's read-only data page.
const PROTECTED_PAGE: u64 = 0x7eb1_d000;
/// Exit qualification of the guest's write to it: a write (bit 1) to a page
/// that is readable (bit 3) but not writable or executable, through the
/// guest's linear address (bits 7 and 8). Hyper-V and bare metal may set
/// other bits; only these matter.
const PROTECTED_WRITE: u64 = 0x18A;
/// A page fault: hardware exception (type 3), error code valid, vector 14.
const PAGE_FAULT_INFO: u32 = 0x8000_0B0E;

fn exit(basic: u16) -> ExitInfo {
    ExitInfo {
        reason: ExitReason {
            basic,
            entry_failure: false,
        },
        interruption_info: InterruptionInfo(0),
        guest_rax: 0,
        interruptibility: 0,
        idt_vectoring_valid: false,
        exit_qualification: EptQualification(0),
        guest_physical: 0,
        protected_page: PROTECTED_PAGE,
    }
}

/// An EPT violation at `gpa` with exit qualification `qualification`.
fn ept_violation(gpa: u64, qualification: u64) -> ExitInfo {
    ExitInfo {
        guest_physical: gpa,
        exit_qualification: EptQualification(qualification),
        ..exit(EXIT_REASON_EPT_VIOLATION)
    }
}

/// The guest's write to its data page, 4 bytes in (any offset counts).
fn protected_write() -> ExitInfo {
    ept_violation(PROTECTED_PAGE + 4, PROTECTED_WRITE)
}

fn vmcall(rax: u64) -> ExitInfo {
    ExitInfo {
        guest_rax: rax,
        ..exit(EXIT_REASON_VMCALL)
    }
}

fn nmi(interruptibility: u32) -> ExitInfo {
    ExitInfo {
        interruption_info: NMI_INFO,
        interruptibility,
        ..exit(EXIT_REASON_EXCEPTION_OR_NMI)
    }
}

#[test]
fn injected_nmi_is_valid_type_2_vector_2() {
    assert_eq!(InterruptionInfo::NMI, InterruptionInfo(0x8000_0202));
}

#[test]
fn nmi_info_is_recognised() {
    assert!(InterruptionInfo(0x8000_0202).is_nmi());
    // Bit 12 (NMI unblocking due to IRET) does not change what it is.
    assert!(InterruptionInfo(0x8000_1202).is_nmi());
}

#[test]
fn exceptions_and_invalid_info_are_not_nmis() {
    assert!(!InterruptionInfo(PAGE_FAULT_INFO).is_nmi());
    // NMI bits without the valid bit.
    assert!(!InterruptionInfo(0x0000_0202).is_nmi());
    // Right vector, wrong type: hardware exception (type 3), vector 2.
    assert!(!InterruptionInfo(0x8000_0302).is_nmi());
    // Right type, wrong vector: NMI type, vector 3.
    assert!(!InterruptionInfo(0x8000_0203).is_nmi());
}

#[test]
fn interruption_info_validity_is_bit_31() {
    assert!(InterruptionInfo(PAGE_FAULT_INFO).is_valid());
    assert!(!InterruptionInfo(PAGE_FAULT_INFO & !InterruptionInfo::VALID).is_valid());
}

#[test]
fn ept_qualification_flags_decode() {
    let write = EptQualification(PROTECTED_WRITE);
    assert!(write.is_write());
    assert!(write.linear_valid());
    assert!(write.is_protected_write());
    let read = EptQualification(EPT_ACCESS_READ | EPT_PAGE_READABLE);
    assert!(!read.is_write());
    assert!(!read.linear_valid());
    assert!(!read.is_protected_write());
}

#[test]
fn protected_write_qualification_matches_its_bits() {
    assert_eq!(
        PROTECTED_WRITE,
        EPT_ACCESS_WRITE | EPT_PAGE_READABLE | EPT_LINEAR_VALID | EPT_TRANSLATED_ACCESS
    );
}

#[test]
fn write_to_the_protected_page_is_granted() {
    assert_eq!(decide(START, protected_write()), (ExitEvent::EptWriteGranted, WRITTEN));
}

#[test]
fn write_to_another_page_is_unexpected() {
    let elsewhere = ept_violation(PROTECTED_PAGE + 0x1000, PROTECTED_WRITE);
    assert_eq!(decide(START, elsewhere), (ExitEvent::Unexpected, START));
}

#[test]
fn violation_with_nothing_protected_is_unexpected() {
    // Before Ept::build the protected page is 0, and GPA 0 must not match.
    let unprotected = ExitInfo {
        protected_page: 0,
        ..ept_violation(0, PROTECTED_WRITE)
    };
    assert_eq!(decide(START, unprotected), (ExitEvent::Unexpected, START));
}

#[test]
fn read_or_fetch_violation_is_unexpected() {
    let read = EPT_ACCESS_READ | EPT_PAGE_READABLE | EPT_LINEAR_VALID | EPT_TRANSLATED_ACCESS;
    let fetch = EPT_ACCESS_FETCH | EPT_PAGE_READABLE | EPT_LINEAR_VALID | EPT_TRANSLATED_ACCESS;
    assert_eq!(
        decide(START, ept_violation(PROTECTED_PAGE, read)).0,
        ExitEvent::Unexpected
    );
    assert_eq!(
        decide(START, ept_violation(PROTECTED_PAGE, fetch)).0,
        ExitEvent::Unexpected
    );
}

#[test]
fn write_to_a_page_already_writable_is_unexpected() {
    let writable = ept_violation(PROTECTED_PAGE, PROTECTED_WRITE | EPT_PAGE_WRITABLE);
    assert_eq!(decide(START, writable).0, ExitEvent::Unexpected);
}

#[test]
fn write_to_an_unreadable_page_is_unexpected() {
    let unreadable = ept_violation(PROTECTED_PAGE, PROTECTED_WRITE & !EPT_PAGE_READABLE);
    assert_eq!(decide(START, unreadable).0, ExitEvent::Unexpected);
}

#[test]
fn second_violation_on_the_page_is_unexpected() {
    // Write was granted once; another violation means the grant did not
    // take effect.
    assert_eq!(decide(WRITTEN, protected_write()), (ExitEvent::Unexpected, WRITTEN));
}

#[test]
fn violation_during_nmi_unblocking_iret_is_unexpected() {
    let iret = ept_violation(PROTECTED_PAGE, PROTECTED_WRITE | EPT_NMI_UNBLOCKING_IRET);
    assert_eq!(decide(START, iret).0, ExitEvent::Unexpected);
}

#[test]
fn violation_on_a_guest_page_table_access_is_unexpected() {
    // Bit 7 without bit 8: the CPU was reading a guest page table.
    let walk = ept_violation(PROTECTED_PAGE, PROTECTED_WRITE & !EPT_TRANSLATED_ACCESS);
    assert_eq!(decide(START, walk).0, ExitEvent::Unexpected);
    let no_linear = ept_violation(
        PROTECTED_PAGE,
        PROTECTED_WRITE & !(EPT_LINEAR_VALID | EPT_TRANSLATED_ACCESS),
    );
    assert_eq!(decide(START, no_linear).0, ExitEvent::Unexpected);
}

#[test]
fn ept_misconfiguration_is_unexpected() {
    let misconfig = ExitInfo {
        guest_physical: PROTECTED_PAGE,
        ..exit(EXIT_REASON_EPT_MISCONFIG)
    };
    assert_eq!(decide(START, misconfig), (ExitEvent::Unexpected, START));
}

#[test]
fn main_vmcall_before_the_violation_means_ept_did_not_protect() {
    assert_eq!(decide(START, vmcall(MARKER)), (ExitEvent::EptWriteMissing, START));
}

#[test]
fn first_main_vmcall_resumes() {
    assert_eq!(decide(WRITTEN, vmcall(MARKER)), (ExitEvent::MainVmcall, WAITING));
}

#[test]
fn second_main_vmcall_without_an_nmi_finishes() {
    assert_eq!(
        decide(WAITING, vmcall(MARKER + 1)),
        (
            ExitEvent::LastMainVmcall,
            ExitState {
                main_vmcalls: 2,
                ..WRITTEN
            }
        ),
    );
}

#[test]
fn plain_run_finishes_after_the_violation_and_two_vmcalls() {
    let mut state = START;
    let mut event = ExitEvent::Unexpected;
    for exit in [protected_write(), vmcall(MARKER), vmcall(MARKER + 1)] {
        (event, state) = decide(state, exit);
    }
    assert_eq!(event, ExitEvent::LastMainVmcall);
    assert_eq!(
        state,
        ExitState {
            main_vmcalls: 2,
            ..WRITTEN
        }
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
        (
            ExitEvent::NmiInjected,
            ExitState {
                nmis_injected: 1,
                ..WAITING
            }
        ),
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
        (
            ExitEvent::NmiDeferred,
            ExitState {
                nmi_pending: true,
                ..WAITING
            }
        ),
    );
}

#[test]
fn nmi_while_blocked_by_mov_ss_waits_for_the_window() {
    assert_eq!(decide(WAITING, nmi(BLOCKING_BY_MOV_SS)).0, ExitEvent::NmiDeferred);
}

#[test]
fn window_exit_injects_the_pending_nmi() {
    let pending = ExitState {
        nmi_pending: true,
        ..WAITING
    };
    assert_eq!(
        decide(pending, exit(EXIT_REASON_NMI_WINDOW)),
        (
            ExitEvent::NmiWindowInjected,
            ExitState {
                nmis_injected: 1,
                ..WAITING
            }
        ),
    );
}

#[test]
fn window_exit_while_still_blocked_keeps_waiting() {
    let pending = ExitState {
        nmi_pending: true,
        ..WAITING
    };
    let still_blocked = ExitInfo {
        interruptibility: BLOCKING_BY_STI,
        ..exit(EXIT_REASON_NMI_WINDOW)
    };
    assert_eq!(decide(pending, still_blocked), (ExitEvent::NmiDeferred, pending));
}

#[test]
fn window_exit_without_a_pending_nmi_is_unexpected() {
    assert_eq!(
        decide(WAITING, exit(EXIT_REASON_NMI_WINDOW)),
        (ExitEvent::Unexpected, WAITING)
    );
}

#[test]
fn guest_nmi_handler_vmcall_resumes() {
    let injected = ExitState {
        nmis_injected: 1,
        ..WAITING
    };
    assert_eq!(
        decide(injected, vmcall(NMI_MARKER)),
        (
            ExitEvent::GuestNmiHandler,
            ExitState {
                nmis_handled: 1,
                ..injected
            }
        ),
    );
}

#[test]
fn full_nmi_run_finishes_with_both_counts() {
    let mut state = START;
    let mut event = ExitEvent::Unexpected;
    for exit in [
        protected_write(),
        vmcall(MARKER),
        nmi(0),
        vmcall(NMI_MARKER),
        vmcall(MARKER + 1),
    ] {
        (event, state) = decide(state, exit);
    }
    assert_eq!(event, ExitEvent::LastMainVmcall);
    assert_eq!(
        state,
        ExitState {
            main_vmcalls: 2,
            nmi_pending: false,
            nmis_injected: 1,
            nmis_handled: 1,
            ept_writes_granted: 1
        },
    );
}

#[test]
fn deferred_nmi_run_finishes_with_both_counts() {
    let exits = [
        protected_write(),
        vmcall(MARKER),
        nmi(BLOCKING_BY_NMI),
        exit(EXIT_REASON_NMI_WINDOW),
        vmcall(NMI_MARKER),
        vmcall(MARKER + 1),
    ];
    let mut state = START;
    let mut event = ExitEvent::Unexpected;
    for exit in exits {
        (event, state) = decide(state, exit);
    }
    assert_eq!(event, ExitEvent::LastMainVmcall);
    assert_eq!(
        state,
        ExitState {
            main_vmcalls: 2,
            nmi_pending: false,
            nmis_injected: 1,
            nmis_handled: 1,
            ept_writes_granted: 1
        },
    );
}

#[test]
fn interrupted_delivery_is_never_handled() {
    let interrupted = ExitInfo {
        idt_vectoring_valid: true,
        ..vmcall(MARKER)
    };
    assert_eq!(decide(START, interrupted), (ExitEvent::InterruptedDelivery, START));
}

#[test]
fn entry_failure_is_unexpected() {
    let failed = ExitInfo {
        reason: ExitReason {
            basic: EXIT_REASON_VMCALL,
            entry_failure: true,
        },
        ..vmcall(MARKER)
    };
    assert_eq!(decide(START, failed), (ExitEvent::Unexpected, START));
}

#[test]
fn exception_exit_is_unexpected() {
    let page_fault = ExitInfo {
        interruption_info: InterruptionInfo(PAGE_FAULT_INFO),
        ..exit(EXIT_REASON_EXCEPTION_OR_NMI)
    };
    assert_eq!(decide(WAITING, page_fault), (ExitEvent::Unexpected, WAITING));
}

#[test]
fn each_event_maps_to_its_action() {
    let resume = |advance_rip, inject_nmi, nmi_window, grant_write| ExitAction::Resume {
        advance_rip,
        inject_nmi,
        nmi_window,
        grant_write,
    };
    assert_eq!(ExitEvent::MainVmcall.action(), resume(true, false, None, false));
    assert_eq!(ExitEvent::GuestNmiHandler.action(), resume(true, false, None, false));
    assert_eq!(ExitEvent::NmiInjected.action(), resume(false, true, Some(false), false));
    assert_eq!(
        ExitEvent::NmiWindowInjected.action(),
        resume(false, true, Some(false), false)
    );
    assert_eq!(ExitEvent::NmiDeferred.action(), resume(false, false, Some(true), false));
    // RIP not advanced: the write runs again once the page is writable.
    assert_eq!(ExitEvent::EptWriteGranted.action(), resume(false, false, None, true));
    assert_eq!(ExitEvent::LastMainVmcall.action(), ExitAction::Finished);
    assert_eq!(ExitEvent::InterruptedDelivery.action(), ExitAction::Unexpected);
    assert_eq!(ExitEvent::EptWriteMissing.action(), ExitAction::Unexpected);
    assert_eq!(ExitEvent::Unexpected.action(), ExitAction::Unexpected);
}
