//! Unit tests for `src/vmx/exit_decision/mod.rs`: the shared types, the
//! dispatch, and through `decide` the handlers in `scenario.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::scenario::{BLOCKING_BY_MOV_SS, BLOCKING_BY_NMI, BLOCKING_BY_STI};
use super::*;
use crate::vmx::guest::{
    GUEST_DATA_SEED, GUEST_EPT_VALUE, GUEST_IO_VALUE, GUEST_MARKER, GUEST_MSR_VALUE, GUEST_MTRR_BASE, GUEST_NMI_MARKER,
    GUEST_SCRATCH_PORT, expected_stats,
};
use crate::vmx::mtrr::MtrrCapabilities;
use crate::vmx::vmexit::VcpuStats;

const MARKER: u64 = GUEST_MARKER as u64;
const NMI_MARKER: u64 = GUEST_NMI_MARKER as u64;
/// VM_EXIT_INTERRUPTION_INFO of an NMI exit.
const NMI_INFO: InterruptionInfo = InterruptionInfo(0x8000_0202);

/// After the guest's emulated exits, before the EPT violation: the state the
/// scenario's own exits start from.
const START: ExitState = ExitState {
    main_vmcalls: 0,
    nmi_pending: false,
    nmis_handled: 0,
    ept_writes_granted: 0,
    nmi_stack_grants: 0,
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
/// GPA of the guest's read-only stack page, where the reinjected NMI's
/// delivery faults. The Hyper-V `-InjectNmi` run faulted at 0x7ff7fff8, in
/// this frame.
const STACK_PAGE: u64 = 0x7ff7_f000;
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
        // What the guest holds at main VMCALL #1 when its data page behaved.
        guest_rcx: GUEST_DATA_SEED.into(),
        guest_rdx: GUEST_EPT_VALUE.into(),
        interruptibility: 0,
        idt_vectoring: InterruptionInfo(0),
        idt_vectoring_error_code: 0,
        qualification: 0,
        guest_physical: 0,
        protected_page: PROTECTED_PAGE,
        stack_page: STACK_PAGE,
        mtrr: MtrrCapabilities::NONE,
        hyperv: false,
        guest_cpl: 0,
    }
}

/// An EPT violation at `gpa` with exit qualification `qualification`.
fn ept_violation(gpa: u64, qualification: u64) -> ExitInfo {
    ExitInfo {
        guest_physical: gpa,
        qualification,
        ..exit(EXIT_REASON_EPT_VIOLATION)
    }
}

/// The guest's write to its data page, 4 bytes in (any offset counts).
fn protected_write() -> ExitInfo {
    ept_violation(PROTECTED_PAGE + 4, PROTECTED_WRITE)
}

/// The reinjected NMI's delivery faulting on the read-only stack page as the
/// CPU pushes the interrupt frame: an EPT write violation on the stack page,
/// its IDT-vectoring field holding the interrupted NMI (`vectoring`). The
/// offset mirrors the Hyper-V run's GPA 0x7ff7fff8.
fn nmi_stack_fault(vectoring: InterruptionInfo) -> ExitInfo {
    ExitInfo {
        guest_physical: STACK_PAGE + 0xFF8,
        protected_page: STACK_PAGE,
        idt_vectoring: vectoring,
        qualification: PROTECTED_WRITE,
        ..exit(EXIT_REASON_EPT_VIOLATION)
    }
}

fn vmcall(rax: u64) -> ExitInfo {
    ExitInfo {
        guest_rax: rax,
        ..exit(EXIT_REASON_VMCALL)
    }
}

/// A VMCALL of the firmware or the OS, with `rcx` in RCX, from CPL 0, under
/// Hyper-V.
fn hypercall(rcx: u64) -> ExitInfo {
    ExitInfo {
        guest_rcx: rcx,
        hyperv: true,
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
    assert_eq!(
        decide(GuestKind::BuiltInTest, START, protected_write()),
        (ExitEvent::EptWriteGranted, WRITTEN)
    );
}

#[test]
fn write_to_another_page_stops_with_the_violation() {
    let elsewhere = ept_violation(PROTECTED_PAGE + 0x1000, PROTECTED_WRITE);
    assert_eq!(
        decide(GuestKind::BuiltInTest, START, elsewhere),
        (ExitEvent::EptViolation, START)
    );
}

#[test]
fn a_violation_on_a_device_page_stops_with_the_violation() {
    // The Local APIC's version register: EPT maps it, so a violation there
    // means the map is wrong.
    let read = EPT_ACCESS_READ | EPT_LINEAR_VALID | EPT_TRANSLATED_ACCESS;
    assert_eq!(
        decide(GuestKind::BuiltInTest, START, ept_violation(0xFEE0_0030, read)),
        (ExitEvent::EptViolation, START)
    );
}

#[test]
fn violation_with_nothing_protected_stops_with_the_violation() {
    // Before Ept::build the protected page is 0, and GPA 0 must not match.
    let unprotected = ExitInfo {
        protected_page: 0,
        stack_page: 0,
        ..ept_violation(0, PROTECTED_WRITE)
    };
    assert_eq!(
        decide(GuestKind::BuiltInTest, START, unprotected),
        (ExitEvent::EptViolation, START)
    );
}

#[test]
fn read_or_fetch_violation_stops_with_the_violation() {
    let read = EPT_ACCESS_READ | EPT_PAGE_READABLE | EPT_LINEAR_VALID | EPT_TRANSLATED_ACCESS;
    let fetch = EPT_ACCESS_FETCH | EPT_PAGE_READABLE | EPT_LINEAR_VALID | EPT_TRANSLATED_ACCESS;
    assert_eq!(
        decide(GuestKind::BuiltInTest, START, ept_violation(PROTECTED_PAGE, read)).0,
        ExitEvent::EptViolation
    );
    assert_eq!(
        decide(GuestKind::BuiltInTest, START, ept_violation(PROTECTED_PAGE, fetch)).0,
        ExitEvent::EptViolation
    );
}

#[test]
fn write_to_a_page_already_writable_stops_with_the_violation() {
    let writable = ept_violation(PROTECTED_PAGE, PROTECTED_WRITE | EPT_PAGE_WRITABLE);
    assert_eq!(
        decide(GuestKind::BuiltInTest, START, writable).0,
        ExitEvent::EptViolation
    );
}

#[test]
fn write_to_an_unreadable_page_stops_with_the_violation() {
    let unreadable = ept_violation(PROTECTED_PAGE, PROTECTED_WRITE & !EPT_PAGE_READABLE);
    assert_eq!(
        decide(GuestKind::BuiltInTest, START, unreadable).0,
        ExitEvent::EptViolation
    );
}

#[test]
fn second_violation_on_the_page_stops_with_the_violation() {
    // Write was granted once; another violation means the grant did not
    // take effect.
    assert_eq!(
        decide(GuestKind::BuiltInTest, WRITTEN, protected_write()),
        (ExitEvent::EptViolation, WRITTEN)
    );
}

#[test]
fn violation_during_nmi_unblocking_iret_stops_with_the_violation() {
    let iret = ept_violation(PROTECTED_PAGE, PROTECTED_WRITE | EPT_NMI_UNBLOCKING_IRET);
    assert_eq!(decide(GuestKind::BuiltInTest, START, iret).0, ExitEvent::EptViolation);
}

#[test]
fn violation_on_a_guest_page_table_access_stops_with_the_violation() {
    // Bit 7 without bit 8: the CPU was reading a guest page table.
    let walk = ept_violation(PROTECTED_PAGE, PROTECTED_WRITE & !EPT_TRANSLATED_ACCESS);
    assert_eq!(decide(GuestKind::BuiltInTest, START, walk).0, ExitEvent::EptViolation);
    let no_linear = ept_violation(
        PROTECTED_PAGE,
        PROTECTED_WRITE & !(EPT_LINEAR_VALID | EPT_TRANSLATED_ACCESS),
    );
    assert_eq!(
        decide(GuestKind::BuiltInTest, START, no_linear).0,
        ExitEvent::EptViolation
    );
}

#[test]
fn ept_misconfiguration_stops_with_its_own_event() {
    let misconfig = ExitInfo {
        guest_physical: PROTECTED_PAGE,
        ..exit(EXIT_REASON_EPT_MISCONFIG)
    };
    assert_eq!(
        decide(GuestKind::BuiltInTest, START, misconfig),
        (ExitEvent::EptMisconfig, START)
    );
}

#[test]
fn the_ept_stops_stop_the_guest() {
    for event in [ExitEvent::EptViolation, ExitEvent::EptMisconfig] {
        assert_eq!(event.action(), ExitAction::Unexpected, "{event:?}");
    }
}

#[test]
fn main_vmcall_before_the_violation_means_ept_did_not_protect() {
    assert_eq!(
        decide(GuestKind::BuiltInTest, START, vmcall(MARKER)),
        (ExitEvent::EptWriteMissing, START)
    );
}

#[test]
fn first_main_vmcall_resumes() {
    assert_eq!(
        decide(GuestKind::BuiltInTest, WRITTEN, vmcall(MARKER)),
        (ExitEvent::MainVmcall, WAITING)
    );
}

#[test]
fn first_main_vmcall_with_a_wrong_seed_is_a_data_page_mismatch() {
    let wrong_seed = ExitInfo {
        guest_rcx: 0xDA7B,
        ..vmcall(MARKER)
    };
    assert_eq!(
        decide(GuestKind::BuiltInTest, WRITTEN, wrong_seed),
        (ExitEvent::DataPageMismatch, WRITTEN)
    );
}

#[test]
fn first_main_vmcall_with_a_wrong_value_is_a_data_page_mismatch() {
    // The write never landed: the guest read the seed back.
    let unwritten = ExitInfo {
        guest_rdx: GUEST_DATA_SEED.into(),
        ..vmcall(MARKER)
    };
    assert_eq!(
        decide(GuestKind::BuiltInTest, WRITTEN, unwritten),
        (ExitEvent::DataPageMismatch, WRITTEN)
    );
}

#[test]
fn data_page_values_compare_as_32_bits() {
    let high_bits = ExitInfo {
        guest_rcx: (1 << 32) | u64::from(GUEST_DATA_SEED),
        guest_rdx: (1 << 32) | u64::from(GUEST_EPT_VALUE),
        ..vmcall(MARKER)
    };
    assert_eq!(
        decide(GuestKind::BuiltInTest, WRITTEN, high_bits),
        (ExitEvent::MainVmcall, WAITING)
    );
}

#[test]
fn second_main_vmcall_does_not_check_the_data_page() {
    // RCX is the wait loop's counter by then.
    let counting = ExitInfo {
        guest_rcx: 0x1FFF_0000,
        ..vmcall(MARKER + 1)
    };
    assert_eq!(
        decide(GuestKind::BuiltInTest, WAITING, counting).0,
        ExitEvent::LastMainVmcall
    );
}

#[test]
fn second_main_vmcall_without_an_nmi_finishes() {
    assert_eq!(
        decide(GuestKind::BuiltInTest, WAITING, vmcall(MARKER + 1)),
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
        (event, state) = decide(GuestKind::BuiltInTest, state, exit);
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
    assert_eq!(
        decide(GuestKind::BuiltInTest, WAITING, vmcall(MARKER)),
        (ExitEvent::Unexpected, WAITING)
    );
}

#[test]
fn nmi_while_unblocked_is_injected() {
    assert_eq!(
        decide(GuestKind::BuiltInTest, WAITING, nmi(0)),
        (ExitEvent::NmiInjected, WAITING)
    );
}

#[test]
fn nmi_while_blocked_by_sti_waits_for_the_window() {
    // The SDM requires bit 0 to be 0 for an NMI injection, so STI blocking
    // defers the NMI just like NMI blocking does.
    assert_eq!(
        decide(GuestKind::BuiltInTest, WAITING, nmi(BLOCKING_BY_STI)).0,
        ExitEvent::NmiDeferred
    );
}

#[test]
fn nmi_while_blocked_by_nmi_waits_for_the_window() {
    assert_eq!(
        decide(GuestKind::BuiltInTest, WAITING, nmi(BLOCKING_BY_NMI)),
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
    assert_eq!(
        decide(GuestKind::BuiltInTest, WAITING, nmi(BLOCKING_BY_MOV_SS)).0,
        ExitEvent::NmiDeferred
    );
}

#[test]
fn window_exit_injects_the_pending_nmi() {
    let pending = ExitState {
        nmi_pending: true,
        ..WAITING
    };
    assert_eq!(
        decide(GuestKind::BuiltInTest, pending, exit(EXIT_REASON_NMI_WINDOW)),
        (ExitEvent::NmiWindowInjected, WAITING)
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
    assert_eq!(
        decide(GuestKind::BuiltInTest, pending, still_blocked),
        (ExitEvent::NmiDeferred, pending)
    );
}

#[test]
fn window_exit_without_a_pending_nmi_is_unexpected() {
    assert_eq!(
        decide(GuestKind::BuiltInTest, WAITING, exit(EXIT_REASON_NMI_WINDOW)),
        (ExitEvent::Unexpected, WAITING)
    );
}

#[test]
fn guest_nmi_handler_vmcall_resumes() {
    assert_eq!(
        decide(GuestKind::BuiltInTest, WAITING, vmcall(NMI_MARKER)),
        (
            ExitEvent::GuestNmiHandler,
            ExitState {
                nmis_handled: 1,
                ..WAITING
            }
        ),
    );
}

#[test]
fn nmi_handler_vmcalls_saturate_their_count() {
    // Any guest code can make this VMCALL, as often as it likes.
    let full = ExitState {
        nmis_handled: u32::MAX,
        ..WAITING
    };
    assert_eq!(
        decide(GuestKind::BuiltInTest, full, vmcall(NMI_MARKER)),
        (ExitEvent::GuestNmiHandler, full)
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
        // The injected NMI's delivery faults on the read-only stack page.
        nmi_stack_fault(VECTORING_NMI),
        vmcall(NMI_MARKER),
        vmcall(MARKER + 1),
    ] {
        (event, state) = decide(GuestKind::BuiltInTest, state, exit);
    }
    assert_eq!(event, ExitEvent::LastMainVmcall);
    assert_eq!(
        state,
        ExitState {
            main_vmcalls: 2,
            nmi_pending: false,
            nmis_handled: 1,
            ept_writes_granted: 1,
            nmi_stack_grants: 1,
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
        // The window-injected NMI's delivery faults on the read-only stack page.
        nmi_stack_fault(VECTORING_NMI),
        vmcall(NMI_MARKER),
        vmcall(MARKER + 1),
    ];
    let mut state = START;
    let mut event = ExitEvent::Unexpected;
    for exit in exits {
        (event, state) = decide(GuestKind::BuiltInTest, state, exit);
    }
    assert_eq!(event, ExitEvent::LastMainVmcall);
    assert_eq!(
        state,
        ExitState {
            main_vmcalls: 2,
            nmi_pending: false,
            nmis_handled: 1,
            ept_writes_granted: 1,
            nmi_stack_grants: 1,
        },
    );
}

/// IDT-vectoring info of an NMI (type 2, vector 2) that the exit interrupted.
const VECTORING_NMI: InterruptionInfo = InterruptionInfo(0x8000_0202);

#[test]
fn a_vectoring_exit_is_still_judged_by_its_reason() {
    // Before re-delivery, any valid vectoring field stopped the guest. Now
    // the exit goes to its reason's handler, and the delivery is re-delivered
    // on top of the plan.
    let interrupted = ExitInfo {
        idt_vectoring: VECTORING_NMI,
        ..vmcall(MARKER)
    };
    assert_eq!(
        decide(GuestKind::BuiltInTest, WRITTEN, interrupted).0,
        ExitEvent::MainVmcall
    );
}

#[test]
fn an_ept_violation_during_delivery_grants_write_and_re_delivers() {
    // The test guest's reinjected NMI faults on its read-only stack page as
    // the CPU pushes the interrupt frame: an EPT violation whose IDT-vectoring
    // field holds the NMI. Grant write, and re-deliver the NMI on the retried
    // entry.
    let interrupted = nmi_stack_fault(VECTORING_NMI);
    let (event, state) = decide(GuestKind::BuiltInTest, START, interrupted);
    assert_eq!(event, ExitEvent::EptWriteGranted);
    assert_eq!(state.nmi_stack_grants, 1);
    let plan = match event.action() {
        ExitAction::Resume(plan) => plan,
        other => panic!("expected a resume, got {other:?}"),
    };
    let redelivery = interrupted.redelivery(None).expect("the NMI is re-delivered");
    assert_eq!(redelivery.info, VECTORING_NMI);
    assert_eq!(
        plan.redelivering(redelivery),
        Some(ResumePlan {
            redeliver: Some(redelivery),
            // The faulted NMI delivery left blocking by NMI set; re-delivery
            // clears it so VM entry can inject the NMI.
            clear_nmi_blocking: true,
            ..ResumePlan::RETRY_AFTER_GRANT
        })
    );
}

#[test]
fn the_nmi_delivery_fault_is_a_separate_grant_from_the_data_write() {
    // The data-page write was already granted; the reinjected NMI's delivery
    // now faults on the stack page. It advances its own counter, so it is
    // still granted (and re-delivered on top).
    let after_data = ExitState {
        ept_writes_granted: 1,
        ..START
    };
    let fault = nmi_stack_fault(VECTORING_NMI);
    assert_eq!(
        decide(GuestKind::BuiltInTest, after_data, fault),
        (
            ExitEvent::EptWriteGranted,
            ExitState {
                nmi_stack_grants: 1,
                ..after_data
            }
        )
    );
}

#[test]
fn a_second_nmi_delivery_fault_is_a_plain_ept_violation() {
    // One NMI-delivery fault is expected; a repeat means the grant did not
    // take effect, so it is reported like any other EPT violation.
    let after_fault = ExitState {
        nmi_stack_grants: 1,
        ..START
    };
    let fault = nmi_stack_fault(VECTORING_NMI);
    assert_eq!(
        decide(GuestKind::BuiltInTest, after_fault, fault),
        (ExitEvent::EptViolation, after_fault)
    );
}

#[test]
fn no_vectoring_means_no_redelivery() {
    assert_eq!(vmcall(MARKER).redelivery(None), None);
}

#[test]
fn nmi_vectoring_accepts_type_2_and_type_3_vector_2() {
    // Vector 2 is the NMI vector; Hyper-V reports the interrupted NMI with
    // type 3 rather than type 2, and both count as the NMI.
    assert!(InterruptionInfo(0x8000_0202).is_nmi_vectoring());
    assert!(InterruptionInfo(0x8000_0302).is_nmi_vectoring());
    // Not valid, right type but wrong vector, or a real type-3 exception.
    assert!(!InterruptionInfo(0x0000_0202).is_nmi_vectoring());
    assert!(!InterruptionInfo(0x8000_0203).is_nmi_vectoring());
    assert!(!InterruptionInfo(PAGE_FAULT_INFO).is_nmi_vectoring());
}

#[test]
fn a_type_3_vector_2_vectoring_re_delivers_as_an_nmi() {
    // Hyper-V reports the interrupted NMI as a hardware exception (type 3);
    // re-delivery must re-arm it as an NMI (type 2), not a #2 exception.
    let hyperv_nmi = ExitInfo {
        idt_vectoring: InterruptionInfo(0x8000_0302),
        ..vmcall(MARKER)
    };
    let redelivery = hyperv_nmi.redelivery(None).expect("vector 2 is the NMI");
    assert_eq!(redelivery.info, InterruptionInfo::NMI);
    assert!(redelivery.info.is_nmi());
}

#[test]
fn re_delivering_a_non_nmi_does_not_clear_nmi_blocking() {
    // Only a re-delivered NMI needs blocking by NMI cleared; a page fault
    // leaves it alone.
    let page_fault = ExitInfo {
        idt_vectoring: InterruptionInfo(PAGE_FAULT_INFO),
        ..vmcall(MARKER)
    };
    let redelivery = page_fault.redelivery(None).unwrap();
    let plan = ResumePlan::RETRY_AFTER_GRANT.redelivering(redelivery).unwrap();
    assert!(!plan.clear_nmi_blocking);
}

#[test]
fn a_hyperv_nmi_stack_fault_is_granted_re_delivered_and_unblocks_nmi() {
    // The Hyper-V `-InjectNmi` run: the reinjected NMI's delivery faults on
    // the stack page, and Hyper-V reports the interrupted NMI with type 3
    // (idt_vectoring = 0x8000_0302), with blocking by NMI set. Told apart by
    // page, it is still the NMI stack grant; re-delivery re-arms a type-2 NMI
    // and clears NMI blocking so VM entry can inject it.
    let fault = ExitInfo {
        interruptibility: BLOCKING_BY_NMI,
        ..nmi_stack_fault(InterruptionInfo(0x8000_0302))
    };
    let (event, state) = decide(GuestKind::BuiltInTest, WRITTEN, fault);
    assert_eq!(event, ExitEvent::EptWriteGranted);
    assert_eq!(state.nmi_stack_grants, 1);

    let plan = match event.action() {
        ExitAction::Resume(plan) => plan,
        other => panic!("expected a resume, got {other:?}"),
    };
    let redelivery = fault.redelivery(None).expect("the NMI is re-delivered");
    assert_eq!(redelivery.info, InterruptionInfo::NMI);
    let plan = plan.redelivering(redelivery).expect("re-delivered on top of the grant");
    assert!(plan.clear_nmi_blocking, "NMI blocking must be cleared for re-delivery");
    // The handler's helper drops bit 3 of the interruptibility state.
    assert_eq!(after_nmi_redelivery(BLOCKING_BY_NMI), 0);
}

#[test]
fn redelivery_clears_bits_30_to_12_and_keeps_the_event() {
    // Bit 12 (NMI unblocking due to IRET) is exit-only; it must not reach the
    // VM-entry field.
    let interrupted = ExitInfo {
        idt_vectoring: InterruptionInfo(0x8000_1202),
        ..vmcall(MARKER)
    };
    assert_eq!(
        interrupted.redelivery(None).unwrap().info,
        InterruptionInfo(0x8000_0202)
    );
}

#[test]
fn redelivery_keeps_an_exception_error_code() {
    // A hardware exception (type 3) with the error-code bit (#PF, vector 14).
    let page_fault = ExitInfo {
        idt_vectoring: InterruptionInfo(0x8000_0B0E),
        idt_vectoring_error_code: 0x2,
        ..vmcall(MARKER)
    };
    let redelivery = page_fault.redelivery(None).unwrap();
    assert_eq!(redelivery.error_code, Some(0x2));
    assert_eq!(redelivery.instruction_len, None);
    // An exception without the bit (#UD, vector 6) carries no error code.
    let invalid_opcode = ExitInfo {
        idt_vectoring: InterruptionInfo(0x8000_0306),
        idt_vectoring_error_code: 0x2,
        ..vmcall(MARKER)
    };
    assert_eq!(invalid_opcode.redelivery(None).unwrap().error_code, None);
}

#[test]
fn a_software_interrupt_re_delivers_with_its_length() {
    // A software interrupt (type 4), e.g. INT 0x80.
    let software = ExitInfo {
        idt_vectoring: InterruptionInfo(0x8000_0480),
        ..vmcall(MARKER)
    };
    assert_eq!(software.redelivery(Some(2)).unwrap().instruction_len, Some(2));
    // With the length unreadable, it cannot be re-delivered: the plan stops.
    let redelivery = software.redelivery(None).unwrap();
    assert_eq!(redelivery.instruction_len, None);
    assert_eq!(ResumePlan::RETRY_AFTER_GRANT.redelivering(redelivery), None);
}

#[test]
fn redelivery_conflicts_with_an_advance_or_injection() {
    let redelivery = ExitInfo {
        idt_vectoring: VECTORING_NMI,
        ..vmcall(MARKER)
    }
    .redelivery(None)
    .unwrap();
    // A plan that advances RIP, injects an NMI, or injects an exception
    // already uses the single VM-entry injection, so it cannot re-deliver.
    assert_eq!(ResumePlan::PAST_INSTRUCTION.redelivering(redelivery), None);
    assert_eq!(ResumePlan::INJECT_NMI.redelivering(redelivery), None);
    assert_eq!(ResumePlan::INJECT_GP.redelivering(redelivery), None);
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
    assert_eq!(
        decide(GuestKind::BuiltInTest, START, failed),
        (ExitEvent::Unexpected, START)
    );
}

#[test]
fn exception_exit_is_unexpected() {
    let page_fault = ExitInfo {
        interruption_info: InterruptionInfo(PAGE_FAULT_INFO),
        ..exit(EXIT_REASON_EXCEPTION_OR_NMI)
    };
    assert_eq!(
        decide(GuestKind::BuiltInTest, WAITING, page_fault),
        (ExitEvent::Unexpected, WAITING)
    );
}

#[test]
fn each_event_maps_to_its_action() {
    let resume = |advance_rip, inject_nmi, nmi_window, grant_write| {
        ExitAction::Resume(ResumePlan {
            advance_rip,
            inject_nmi,
            nmi_window,
            grant_write,
            emulate: None,
            inject_exception: None,
            redeliver: None,
            clear_nmi_blocking: false,
        })
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
    assert_eq!(ExitEvent::EptWriteMissing.action(), ExitAction::Unexpected);
    assert_eq!(ExitEvent::DataPageMismatch.action(), ExitAction::Unexpected);
    assert_eq!(ExitEvent::Unexpected.action(), ExitAction::Unexpected);
    let cpuid = Emulation::Cpuid { leaf: 1, subleaf: 0 };
    assert_eq!(
        ExitEvent::Emulated(cpuid).action(),
        ExitAction::Resume(ResumePlan {
            emulate: Some(cpuid),
            ..ResumePlan::PAST_INSTRUCTION
        })
    );
    assert_eq!(
        ExitEvent::GuestGeneralProtection.action(),
        ExitAction::Resume(ResumePlan::INJECT_GP)
    );
    // A fault: RIP stays on the instruction. A constant, so checked at compile time.
    const { assert!(!ResumePlan::INJECT_GP.advance_rip) };
    assert_eq!(
        ExitEvent::Halted.action(),
        ExitAction::Resume(ResumePlan::PAST_INSTRUCTION)
    );
    assert_eq!(
        ExitEvent::GuestInvalidOpcode.action(),
        ExitAction::Resume(ResumePlan::INJECT_UD)
    );
    const { assert!(!ResumePlan::INJECT_UD.advance_rip) };
}

#[test]
fn hlt_resumes_past_the_instruction() {
    assert_eq!(
        decide(GuestKind::BuiltInTest, START, exit(EXIT_REASON_HLT)),
        (ExitEvent::Halted, START)
    );
}

#[test]
fn hlt_in_an_sti_shadow_is_decided_the_same() {
    // `sti; hlt`: the exit reports blocking by STI; the decision does not
    // depend on it, the RIP advance ends it.
    let in_shadow = ExitInfo {
        interruptibility: BLOCKING_BY_STI,
        ..exit(EXIT_REASON_HLT)
    };
    assert_eq!(decide(GuestKind::BuiltInTest, START, in_shadow).0, ExitEvent::Halted);
}

#[test]
fn skipping_an_instruction_ends_sti_and_mov_ss_blocking_only() {
    assert_eq!(after_skipped_instruction(BLOCKING_BY_STI), 0);
    assert_eq!(after_skipped_instruction(BLOCKING_BY_MOV_SS), 0);
    // Blocking by SMI (bit 2) and by NMI (bit 3) outlast the instruction.
    assert_eq!(after_skipped_instruction(0b1111), 0b1100);
    assert_eq!(after_skipped_instruction(BLOCKING_BY_NMI), BLOCKING_BY_NMI);
}

#[test]
fn mwait_and_monitor_inject_invalid_opcode() {
    for basic in [EXIT_REASON_MWAIT, EXIT_REASON_MONITOR] {
        assert_eq!(
            decide(GuestKind::BuiltInTest, START, exit(basic)),
            (ExitEvent::GuestInvalidOpcode, START)
        );
    }
}

#[test]
fn injected_invalid_opcode_is_a_hardware_exception_without_error_code() {
    // Valid (bit 31), hardware exception (type 3), vector 6, no bit 11.
    assert_eq!(InterruptionInfo::INVALID_OPCODE, InterruptionInfo(0x8000_0306));
    assert!(!InterruptionInfo::INVALID_OPCODE.delivers_error_code());
    assert!(InterruptionInfo::GENERAL_PROTECTION.delivers_error_code());
}

#[test]
fn idle_exits_have_names() {
    assert_eq!(exit_reason_name(EXIT_REASON_HLT), "HLT");
    assert_eq!(exit_reason_name(EXIT_REASON_MWAIT), "MWAIT");
    assert_eq!(exit_reason_name(EXIT_REASON_MONITOR), "MONITOR");
}

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

/// The exits the guest's emulation block causes, in order.
fn emulated_exits() -> Vec<ExitInfo> {
    let msr = |basic, rax: u64, rdx: u64| ExitInfo {
        guest_rax: rax,
        guest_rcx: 0xC000_0102,
        guest_rdx: rdx,
        ..exit(basic)
    };
    let io = |is_in: bool, rax: u64| ExitInfo {
        qualification: (u64::from(GUEST_SCRATCH_PORT) << 16) | (u64::from(is_in) << 3),
        guest_rax: rax,
        ..exit(EXIT_REASON_IO_INSTRUCTION)
    };
    // Hyper-V's MTRRs: fixed ranges, eight variable ranges, MAXPHYADDR 46.
    let mtrr = |basic, msr: u32, value: u64| ExitInfo {
        guest_rax: value & 0xFFFF_FFFF,
        guest_rcx: msr.into(),
        guest_rdx: value >> 32,
        mtrr: MtrrCapabilities::new((1 << 8) | 8, 46).unwrap(),
        ..exit(basic)
    };
    vec![
        ExitInfo {
            guest_rax: 1,
            guest_rcx: 0,
            ..exit(EXIT_REASON_CPUID)
        },
        msr(EXIT_REASON_RDMSR, 0, 0),
        msr(EXIT_REASON_WRMSR, GUEST_MSR_VALUE & 0xFFFF_FFFF, GUEST_MSR_VALUE >> 32),
        msr(EXIT_REASON_RDMSR, 0, 0),
        msr(EXIT_REASON_WRMSR, 0, 0),
        io(true, 0),
        io(false, GUEST_IO_VALUE.into()),
        io(true, 0),
        io(false, 0),
        ExitInfo {
            guest_rax: 0x8000_0008,
            ..exit(EXIT_REASON_CPUID)
        },
        // Its last variable MTRR, number 7 under Hyper-V: read the pair,
        // turn it off, move it, 2 MiB, read the mask back, 4 KiB, then off
        // and back as it was.
        mtrr(EXIT_REASON_RDMSR, 0x20E, 0),
        mtrr(EXIT_REASON_RDMSR, 0x20F, 0),
        mtrr(EXIT_REASON_WRMSR, 0x20F, 0),
        mtrr(EXIT_REASON_WRMSR, 0x20E, GUEST_MTRR_BASE),
        mtrr(EXIT_REASON_WRMSR, 0x20F, 0x3FFF_FFE0_0800),
        mtrr(EXIT_REASON_RDMSR, 0x20F, 0),
        mtrr(EXIT_REASON_WRMSR, 0x20F, 0x3FFF_FFFF_F800),
        mtrr(EXIT_REASON_WRMSR, 0x20F, 0),
        mtrr(EXIT_REASON_WRMSR, 0x20E, 0),
        mtrr(EXIT_REASON_WRMSR, 0x20F, 0),
        exit(EXIT_REASON_HLT),
    ]
}

#[test]
fn cpuid_exit_is_dispatched_to_emulation() {
    let cpuid = ExitInfo {
        guest_rax: 1,
        guest_rcx: 0,
        ..exit(EXIT_REASON_CPUID)
    };
    assert_eq!(
        decide(GuestKind::BuiltInTest, START, cpuid).0,
        ExitEvent::Emulated(Emulation::Cpuid { leaf: 1, subleaf: 0 })
    );
}

#[test]
fn whole_guest_run_finishes_with_the_expected_stats() {
    // As the exit handler counts: every exit, then what a resumed one did.
    let mut state = ExitState::default();
    let mut stats = VcpuStats::ZERO;
    let mut event = ExitEvent::Unexpected;
    for exit in emulated_exits()
        .into_iter()
        .chain([protected_write(), vmcall(MARKER), vmcall(MARKER + 1)])
    {
        stats.count_exit();
        (event, state) = decide(GuestKind::BuiltInTest, state, exit);
        if let ExitAction::Resume(plan) = event.action() {
            stats.count_resumed(event, plan);
        }
    }
    assert_eq!(event, ExitEvent::LastMainVmcall);
    assert_eq!(stats, expected_stats(&stats));
    assert_eq!((stats.exits, stats.nmi_injections), (24, 0));
}

#[test]
fn injected_general_protection_is_a_hardware_exception_with_error_code() {
    // Valid (bit 31), error code (bit 11), hardware exception (type 3),
    // vector 13.
    assert_eq!(InterruptionInfo::GENERAL_PROTECTION, InterruptionInfo(0x8000_0B0D));
}

#[test]
fn msr_exits_are_dispatched_to_emulation() {
    // RDX = 0: `exit` defaults it to GUEST_EPT_VALUE, which as the upper half
    // of a WRMSR value would be non-canonical.
    let msr = |basic| ExitInfo {
        guest_rcx: 0xC000_0102,
        guest_rdx: 0,
        ..exit(basic)
    };
    assert_eq!(
        decide(GuestKind::BuiltInTest, START, msr(EXIT_REASON_RDMSR)).0,
        ExitEvent::Emulated(Emulation::Rdmsr { msr: 0xC000_0102 })
    );
    assert!(matches!(
        decide(GuestKind::BuiltInTest, START, msr(EXIT_REASON_WRMSR)).0,
        ExitEvent::Emulated(Emulation::Wrmsr { msr: 0xC000_0102, .. })
    ));
}

#[test]
fn io_exit_is_dispatched_to_emulation() {
    let byte_in = ExitInfo {
        qualification: (0x3FF << 16) | (1 << 3),
        ..exit(EXIT_REASON_IO_INSTRUCTION)
    };
    assert_eq!(
        decide(GuestKind::BuiltInTest, START, byte_in).0,
        ExitEvent::Emulated(Emulation::In {
            port: 0x3FF,
            size: IoSize::Byte
        })
    );
}

#[test]
fn an_nmi_from_root_operation_becomes_pending() {
    assert_eq!(START.with_host_nmi(false), START);
    assert_eq!(
        START.with_host_nmi(true),
        ExitState {
            nmi_pending: true,
            ..START
        }
    );
    // NMIs do not queue: one already pending stays the only one.
    let pending = START.with_host_nmi(true);
    assert_eq!(pending.with_host_nmi(true), pending);
}

#[test]
fn a_pending_nmi_keeps_the_nmi_window_on() {
    let pending = ExitState {
        nmi_pending: true,
        ..WAITING
    };
    assert_eq!(
        ResumePlan::PAST_INSTRUCTION.keeping_pending_nmi(pending),
        ResumePlan {
            nmi_window: Some(true),
            ..ResumePlan::PAST_INSTRUCTION
        }
    );
    // An injected #GP leaves the NMI waiting for the window too.
    assert_eq!(
        ResumePlan::INJECT_GP.keeping_pending_nmi(pending).nmi_window,
        Some(true)
    );
}

#[test]
fn without_a_pending_nmi_the_plan_is_unchanged() {
    for plan in [
        ResumePlan::PAST_INSTRUCTION,
        ResumePlan::INJECT_NMI,
        ResumePlan::RETRY_AFTER_GRANT,
    ] {
        assert_eq!(plan.keeping_pending_nmi(WAITING), plan);
    }
}

#[test]
fn an_nmi_in_root_operation_at_vmcall_1_reaches_the_guest() {
    // Main VMCALL #1, with an NMI that arrived while Aleph0 handled the EPT
    // violation before it.
    let (event, state) = decide(GuestKind::BuiltInTest, WRITTEN.with_host_nmi(true), vmcall(MARKER));
    assert_eq!(event, ExitEvent::MainVmcall);
    assert!(state.nmi_pending);
    let plan = match event.action() {
        ExitAction::Resume(plan) => plan.keeping_pending_nmi(state),
        action => panic!("main VMCALL #1 resumes, not {action:?}"),
    };
    assert_eq!(plan.nmi_window, Some(true));

    // The guest can take it at once: the NMI-window exit injects it, and
    // the run ends as one with a reinjected NMI does.
    let mut state = state;
    let mut event = ExitEvent::Unexpected;
    for exit in [exit(EXIT_REASON_NMI_WINDOW), vmcall(NMI_MARKER), vmcall(MARKER + 1)] {
        (event, state) = decide(GuestKind::BuiltInTest, state, exit);
        if exit.reason.basic == EXIT_REASON_NMI_WINDOW {
            assert_eq!(event, ExitEvent::NmiWindowInjected);
        }
    }
    assert_eq!(event, ExitEvent::LastMainVmcall);
    assert_eq!((state.nmis_handled, state.nmi_pending), (1, false));
}

/// What `decide` makes of `exit` for the firmware, from `state`.
fn firmware(state: ExitState, exit: ExitInfo) -> ExitAction {
    decide(GuestKind::Firmware, state, exit).0.action()
}

#[test]
fn the_firmware_resumes_from_every_exit_aleph0_handles() {
    // Hyper-V's first synthetic MSR, outside the MSR bitmap: #GP without
    // Hyper-V's interface, forwarded with it, and on either way.
    let synthetic_msr = ExitInfo {
        guest_rcx: 0x4000_0000,
        ..exit(EXIT_REASON_RDMSR)
    };
    let forwarded_msr = ExitInfo {
        hyperv: true,
        ..synthetic_msr
    };
    let pending = ExitState {
        nmi_pending: true,
        ..START
    };
    let handled = emulated_exits().into_iter().map(|exit| (START, exit)).chain([
        (START, synthetic_msr),
        (START, forwarded_msr),
        (START, hypercall(0x5C)),
        (START, vmcall(0)),
        (START, exit(EXIT_REASON_MWAIT)),
        (START, exit(EXIT_REASON_MONITOR)),
        (START, nmi(0)),
        (START, nmi(BLOCKING_BY_STI)),
        (pending, exit(EXIT_REASON_NMI_WINDOW)),
    ]);
    for (state, exit) in handled {
        assert!(
            matches!(firmware(state, exit), ExitAction::Resume(_)),
            "reason {} from {state:?}",
            exit.reason.basic
        );
    }
}

#[test]
fn the_firmware_stops_at_its_ept_violations() {
    // No page is the firmware's to write, so every EPT violation means the
    // map is wrong.
    for exit in [protected_write(), ept_violation(0xFEE0_0030, EPT_ACCESS_READ)] {
        assert_eq!(
            firmware(START, exit),
            ExitAction::Unexpected,
            "reason {}",
            exit.reason.basic
        );
    }
    assert_eq!(
        decide(GuestKind::Firmware, START, protected_write()),
        (ExitEvent::EptViolation, START)
    );
}

#[test]
fn the_firmware_resumes_past_aleph0s_own_vmcalls() {
    for (rcx, event) in [
        (vmcall::BOOT_SERVICES_ENDED, ExitEvent::BootServicesEnded),
        (vmcall::TEST, ExitEvent::TestVmcall),
    ] {
        // Under Hyper-V or not: they are Aleph0's either way.
        for hyperv in [false, true] {
            let exit = ExitInfo {
                hyperv,
                ..hypercall(rcx)
            };
            assert_eq!(decide(GuestKind::Firmware, START, exit), (event, START));
        }
        assert_eq!(event.action(), ExitAction::Resume(ResumePlan::PAST_INSTRUCTION));
    }
}

#[test]
fn aleph0s_vmcalls_have_reserved_hypercall_bits_set() {
    // Bits 63:60 of a hypercall input value are reserved, so no hypercall
    // Hyper-V takes has either value in RCX.
    for rcx in [vmcall::BOOT_SERVICES_ENDED, vmcall::TEST] {
        assert_ne!(rcx >> 60, 0, "{rcx:#x}");
    }
    assert_ne!(vmcall::BOOT_SERVICES_ENDED, vmcall::TEST);
    assert_eq!(vmcall::BOOT_SERVICES_ENDED, 0x416c_6570_6830_4542);
}

#[test]
fn every_other_firmware_vmcall_is_forwarded_under_hyper_v() {
    // HvCallPostMessage and HvCallSignalEvent as the VMBus drivers make
    // them, a fast rep hypercall, and Aleph0's values one bit off or cut to
    // their low half, which are hypercalls too (invalid ones, which Hyper-V
    // answers).
    for rcx in [
        0x5C,
        0x1_005D,
        0x0000_0002_0001_0003,
        vmcall::BOOT_SERVICES_ENDED ^ 1,
        vmcall::BOOT_SERVICES_ENDED & 0xFFFF_FFFF,
        vmcall::TEST ^ (1 << 63),
    ] {
        assert_eq!(
            decide(GuestKind::Firmware, START, hypercall(rcx)),
            (ExitEvent::Emulated(Emulation::Hypercall { input: rcx }), START),
            "rcx={rcx:#x}"
        );
    }
    // Aleph0's values in RAX are no call to Aleph0 any more.
    let in_rax = ExitInfo {
        guest_rax: vmcall::BOOT_SERVICES_ENDED,
        ..hypercall(0x5C)
    };
    assert_eq!(
        decide(GuestKind::Firmware, START, in_rax).0,
        ExitEvent::Emulated(Emulation::Hypercall { input: 0x5C })
    );
}

#[test]
fn a_forwarded_hypercall_resumes_past_the_vmcall_with_its_result() {
    let event = decide(GuestKind::Firmware, START, hypercall(0x5C)).0;
    assert_eq!(
        event.action(),
        ExitAction::Resume(ResumePlan {
            emulate: Some(Emulation::Hypercall { input: 0x5C }),
            ..ResumePlan::PAST_INSTRUCTION
        })
    );
}

#[test]
fn a_refused_forward_injects_at_the_instruction_and_keeps_the_rest() {
    let ExitAction::Resume(plan) = ExitEvent::Emulated(Emulation::Hypercall { input: 0x5C }).action() else {
        panic!("a forwarded hypercall resumes");
    };
    let plan = plan.keeping_pending_nmi(ExitState {
        nmi_pending: true,
        ..START
    });
    let refused = plan.refused_with(InterruptionInfo::INVALID_OPCODE);
    assert!(!refused.advance_rip);
    assert_eq!(refused.inject_exception, Some(InterruptionInfo::INVALID_OPCODE));
    assert_eq!(
        (refused.nmi_window, refused.emulate),
        (Some(true), Some(Emulation::Hypercall { input: 0x5C }))
    );
}

#[test]
fn a_vmcall_without_hyper_v_gets_invalid_opcode() {
    // As on hardware without a hypervisor: VMCALL outside VMX non-root
    // operation is #UD.
    let exit = ExitInfo {
        hyperv: false,
        ..hypercall(0x5C)
    };
    assert_eq!(
        decide(GuestKind::Firmware, START, exit),
        (ExitEvent::GuestInvalidOpcode, START)
    );
    assert_eq!(firmware(START, exit), ExitAction::Resume(ResumePlan::INJECT_UD));
}

#[test]
fn a_vmcall_from_cpl_3_gets_invalid_opcode_whatever_rcx_holds() {
    // Hyper-V refuses a hypercall from CPL > 0 with #UD; forwarding it from
    // root operation would make it at CPL 0 instead. Aleph0's own need CPL 0
    // too.
    for cpl in 1..=3 {
        for rcx in [0x5C, vmcall::BOOT_SERVICES_ENDED, vmcall::TEST] {
            let exit = ExitInfo {
                guest_cpl: cpl,
                ..hypercall(rcx)
            };
            assert_eq!(
                decide(GuestKind::Firmware, START, exit).0,
                ExitEvent::GuestInvalidOpcode,
                "cpl={cpl} rcx={rcx:#x}"
            );
        }
    }
}

#[test]
fn the_cpl_is_the_dpl_of_ss() {
    // A 64-bit kernel data segment (0xC093) and a user one (0xC0F3).
    assert_eq!(cpl_from_ss(0xC093), 0);
    assert_eq!(cpl_from_ss(0xC0F3), 3);
    assert_eq!(cpl_from_ss(0x1_C0B3), 1);
}

#[test]
fn the_test_guest_keeps_its_script_under_hyper_v() {
    // Its VMCALLs are its script's: Aleph0's values and hypercalls stop the
    // run, and its markers in RAX do what they always did.
    for rcx in [vmcall::BOOT_SERVICES_ENDED, vmcall::TEST, 0x5C] {
        assert_eq!(
            decide(GuestKind::BuiltInTest, WRITTEN, hypercall(rcx)).0,
            ExitEvent::Unexpected,
            "rcx={rcx:#x}"
        );
    }
    let marked = |rax| ExitInfo {
        hyperv: true,
        ..vmcall(rax)
    };
    assert_eq!(
        decide(GuestKind::BuiltInTest, WRITTEN, marked(MARKER)).0,
        ExitEvent::MainVmcall
    );
    assert_eq!(
        decide(GuestKind::BuiltInTest, WAITING, marked(NMI_MARKER)).0,
        ExitEvent::GuestNmiHandler
    );
    assert_eq!(
        decide(GuestKind::BuiltInTest, WAITING, marked(MARKER + 1)).0,
        ExitEvent::LastMainVmcall
    );
}

#[test]
fn the_firmware_stops_at_an_unhandled_exit() {
    let page_fault = ExitInfo {
        interruption_info: InterruptionInfo(PAGE_FAULT_INFO),
        ..exit(EXIT_REASON_EXCEPTION_OR_NMI)
    };
    let entry_failure = ExitInfo {
        reason: ExitReason {
            basic: 33,
            entry_failure: true,
        },
        ..exit(33)
    };
    // A triple fault (2), a CR access (28), an EPT misconfiguration (49).
    for exit in [
        page_fault,
        entry_failure,
        exit(2),
        exit(28),
        exit(EXIT_REASON_EPT_MISCONFIG),
    ] {
        assert_eq!(
            firmware(START, exit),
            ExitAction::Unexpected,
            "reason {}",
            exit.reason.basic
        );
    }
}

#[test]
fn the_firmware_never_finishes() {
    // Every basic reason and the test guest's markers, from every state its
    // run passes through, the last main VMCALL's included.
    for state in [START, WRITTEN, WAITING] {
        for basic in 0..=u16::from(u8::MAX) {
            for rax in [0, MARKER, MARKER + 1, NMI_MARKER] {
                let exit = ExitInfo {
                    guest_rax: rax,
                    ..exit(basic)
                };
                assert_ne!(
                    firmware(state, exit),
                    ExitAction::Finished,
                    "reason {basic} rax={rax:#x}"
                );
            }
        }
    }
}
