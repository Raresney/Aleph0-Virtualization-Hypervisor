//! The test guest's own exits: its write to the EPT-protected data page,
//! its main VMCALLs, and NMI reinjection.
//!
//! The guest (`guest.rs`) writes its read-only data page, makes two main
//! VMCALLs, with `GUEST_MARKER` and then `GUEST_MARKER + 1` in RAX, and
//! waits between them for an NMI:
//!
//! ```text
//! EPT violation  ──▶ a write to the protected data page: make it writable,
//!                    resume at the same RIP so the write is retried
//! main VMCALL #1 ──▶ resume past it (only after the EPT violation, and only
//!                    if ECX/EDX hold the data page's seed and new value)
//! NMI exit       ──▶ guest can take the NMI:  inject it at the next entry
//!                    guest cannot yet (STI, MOV SS or NMI blocking):
//!                                             turn on NMI-window exiting,
//! NMI-window exit──▶                          inject when the window opens
//! VMCALL with GUEST_NMI_MARKER (the guest's NMI handler) ──▶ resume past it
//! main VMCALL #2 ──▶ finished
//! ```

use super::{ExitEvent, ExitInfo, ExitState};
use crate::vmx::guest::{GUEST_DATA_SEED, GUEST_EPT_VALUE, GUEST_MARKER, GUEST_NMI_MARKER};

/// How many main VMCALLs the guest makes; the last one ends the run.
pub const PLANNED_MAIN_VMCALLS: u32 = 2;

/// Guest interruptibility bit 0: blocking by STI. The Intel SDM (Vol. 3C,
/// checks on guest non-register state) says: "A processor may require bit 0
/// (blocking by STI) to be 0 if the valid bit is 1 and the interruption type
/// is NMI." So an NMI is injected only when this bit is clear too.
pub(super) const BLOCKING_BY_STI: u32 = 1 << 0;
/// Guest interruptibility bit 1: blocking by MOV SS. VM entry refuses to
/// inject an NMI while it is set.
pub(super) const BLOCKING_BY_MOV_SS: u32 = 1 << 1;
/// Guest interruptibility bit 3: blocking by NMI. With virtual NMIs this is
/// an injected NMI the guest has not ended with IRET yet; VM entry refuses
/// to inject another while it is set.
pub(super) const BLOCKING_BY_NMI: u32 = 1 << 3;
/// Any of the blocking bits that may stop an NMI injection. The handler
/// injects only when none is set, and otherwise waits for the NMI window
/// instead of injecting blindly.
const NMI_INJECTION_BLOCKED: u32 = BLOCKING_BY_STI | BLOCKING_BY_MOV_SS | BLOCKING_BY_NMI;

/// Whether, at main VMCALL #1, ECX holds the seed the guest read from its
/// data page and EDX the value it wrote and read back. Compared as 32-bit
/// values: the guest loads both with 32-bit moves.
fn data_page_read_back(exit: &ExitInfo) -> bool {
    exit.guest_rcx as u32 == GUEST_DATA_SEED && exit.guest_rdx as u32 == GUEST_EPT_VALUE
}

/// The guest's RAX at its next main VMCALL: the marker, plus one for each
/// main VMCALL already handled (the guest runs `inc eax` before #2).
pub fn expected_main_rax(state: ExitState) -> u64 {
    u64::from(GUEST_MARKER) + u64::from(state.main_vmcalls)
}

/// `state` after an NMI is injected: nothing pending, one more injected.
/// Several NMIs never queue: a new NMI while one is pending replaces it, as
/// on real hardware, where at most one NMI waits.
fn injected(state: ExitState) -> ExitState {
    ExitState {
        nmi_pending: false,
        nmis_injected: state.nmis_injected + 1,
        ..state
    }
}

/// Exception or NMI (exit reason 0). Only an NMI is handled: reinjected now,
/// or once the guest's NMI window opens. Any exception stops the guest.
pub(super) fn exception_or_nmi(state: ExitState, exit: &ExitInfo) -> (ExitEvent, ExitState) {
    if !exit.interruption_info.is_nmi() {
        return (ExitEvent::Unexpected, state);
    }
    if exit.interruptibility & NMI_INJECTION_BLOCKED == 0 {
        (ExitEvent::NmiInjected, injected(state))
    } else {
        (
            ExitEvent::NmiDeferred,
            ExitState {
                nmi_pending: true,
                ..state
            },
        )
    }
}

/// NMI window (exit reason 8): inject the pending NMI.
pub(super) fn nmi_window(state: ExitState, exit: &ExitInfo) -> (ExitEvent, ExitState) {
    if !state.nmi_pending {
        return (ExitEvent::Unexpected, state);
    }
    // Per the SDM, NMI-window exits never occur under MOV SS blocking, but
    // the processor may still report one under STI blocking. Injecting then
    // would fail the VM entry, so keep waiting. (MOV SS stays in the mask;
    // it is harmless.)
    if exit.interruptibility & NMI_INJECTION_BLOCKED != 0 {
        (ExitEvent::NmiDeferred, state)
    } else {
        (ExitEvent::NmiWindowInjected, injected(state))
    }
}

/// EPT violation (exit reason 48). Exactly one is handled: the guest's
/// write to its protected data page, which must come before the first main
/// VMCALL.
pub(super) fn ept_violation(state: ExitState, exit: &ExitInfo) -> (ExitEvent, ExitState) {
    let protected_write = exit.protected_page != 0
        && exit.guest_physical & !0xFFF == exit.protected_page
        && exit.exit_qualification.is_protected_write();
    if protected_write && state.ept_writes_granted == 0 {
        (
            ExitEvent::EptWriteGranted,
            ExitState {
                ept_writes_granted: 1,
                ..state
            },
        )
    } else {
        (ExitEvent::Unexpected, state)
    }
}

/// VMCALL (exit reason 18): the guest's NMI handler, or its next main
/// VMCALL. Main VMCALL #1 must come after the EPT violation and show the
/// data page read back as planned.
pub(super) fn vmcall(state: ExitState, exit: &ExitInfo) -> (ExitEvent, ExitState) {
    if exit.guest_rax == u64::from(GUEST_NMI_MARKER) {
        return (
            ExitEvent::GuestNmiHandler,
            ExitState {
                nmis_handled: state.nmis_handled + 1,
                ..state
            },
        );
    }
    if exit.guest_rax != expected_main_rax(state) {
        return (ExitEvent::Unexpected, state);
    }
    if state.ept_writes_granted == 0 {
        return (ExitEvent::EptWriteMissing, state);
    }
    if state.main_vmcalls == 0 && !data_page_read_back(exit) {
        return (ExitEvent::DataPageMismatch, state);
    }
    let next = ExitState {
        main_vmcalls: state.main_vmcalls + 1,
        ..state
    };
    if next.main_vmcalls < PLANNED_MAIN_VMCALLS {
        (ExitEvent::MainVmcall, next)
    } else {
        (ExitEvent::LastMainVmcall, next)
    }
}
