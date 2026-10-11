//! What the VM-exit handler does with each exit: a pure state machine.
//!
//! The handler reads the exit's VMCS fields into an [`ExitInfo`], calls
//! [`decide`] with the [`ExitState`] kept between exits, and applies the
//! [`ExitAction`] of the returned [`ExitEvent`]. Nothing here touches the
//! CPU, so every case is a host unit test.
//!
//! The guest (`guest.rs`) makes two main VMCALLs, with `GUEST_MARKER` and
//! then `GUEST_MARKER + 1` in RAX, and waits between them for an NMI:
//!
//! ```text
//! main VMCALL #1 ──▶ resume past it
//! NMI exit       ──▶ guest can take the NMI:  inject it at the next entry
//!                    guest cannot yet (STI, MOV SS or NMI blocking):
//!                                             turn on NMI-window exiting,
//! NMI-window exit──▶                          inject when the window opens
//! VMCALL with GUEST_NMI_MARKER (the guest's NMI handler) ──▶ resume past it
//! main VMCALL #2 ──▶ finished
//! ```

use super::guest::{GUEST_MARKER, GUEST_NMI_MARKER};
use super::vmexit::ExitReason;

/// Basic exit reason of an exception or NMI exit.
pub const EXIT_REASON_EXCEPTION_OR_NMI: u16 = 0;
/// Basic exit reason of an NMI-window exit.
pub const EXIT_REASON_NMI_WINDOW: u16 = 8;
/// Basic exit reason of a VMCALL exit.
pub const EXIT_REASON_VMCALL: u16 = 18;

/// How many main VMCALLs the guest makes; the last one ends the run.
pub const PLANNED_MAIN_VMCALLS: u32 = 2;

/// Interruption-information bit 31: the field is valid.
const INTERRUPTION_VALID: u32 = 1 << 31;
/// Interruption type 2 (bits 10:8): NMI.
const INTERRUPTION_TYPE_NMI: u32 = 2;
/// IDT vector of NMI.
const NMI_VECTOR: u32 = 2;

/// VM_ENTRY_INTERRUPTION_INFO value that injects an NMI at the next VM
/// entry: valid, type NMI, vector 2. The CPU clears the field after each
/// successful entry, so it injects once.
pub const INJECT_NMI: u32 = INTERRUPTION_VALID | (INTERRUPTION_TYPE_NMI << 8) | NMI_VECTOR;

/// Guest interruptibility bit 0: blocking by STI. The Intel SDM (Vol. 3C,
/// checks on guest non-register state) says: "A processor may require bit 0
/// (blocking by STI) to be 0 if the valid bit is 1 and the interruption type
/// is NMI." So an NMI is injected only when this bit is clear too.
const BLOCKING_BY_STI: u32 = 1 << 0;
/// Guest interruptibility bit 1: blocking by MOV SS. VM entry refuses to
/// inject an NMI while it is set.
const BLOCKING_BY_MOV_SS: u32 = 1 << 1;
/// Guest interruptibility bit 3: blocking by NMI. With virtual NMIs this is
/// an injected NMI the guest has not ended with IRET yet; VM entry refuses
/// to inject another while it is set.
const BLOCKING_BY_NMI: u32 = 1 << 3;
/// Any of the blocking bits that may stop an NMI injection. The handler
/// injects only when none is set, and otherwise waits for the NMI window
/// instead of injecting blindly.
const NMI_INJECTION_BLOCKED: u32 = BLOCKING_BY_STI | BLOCKING_BY_MOV_SS | BLOCKING_BY_NMI;

/// Whether `info`, a VM_EXIT_INTERRUPTION_INFO value, describes an NMI:
/// valid, type 2, vector 2. Bit 12 (NMI unblocking due to IRET) is ignored.
pub fn is_nmi(info: u32) -> bool {
    info & INTERRUPTION_VALID != 0
        && (info >> 8) & 0b111 == INTERRUPTION_TYPE_NMI
        && info & 0xFF == NMI_VECTOR
}

/// What the handler read about the current exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitInfo {
    pub reason: ExitReason,
    /// VM_EXIT_INTERRUPTION_INFO.
    pub interruption_info: u32,
    pub guest_rax: u64,
    /// GUEST_INTERRUPTIBILITY_STATE.
    pub interruptibility: u32,
    /// IDT_VECTORING_INFO bit 31: the exit interrupted an event's delivery
    /// through the guest IDT.
    pub idt_vectoring_valid: bool,
}

/// What the handler remembers between exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExitState {
    /// Main VMCALLs handled so far.
    pub main_vmcalls: u32,
    /// An NMI arrived while the guest blocked NMIs and is not injected yet.
    pub nmi_pending: bool,
    /// NMIs reinjected into the guest.
    pub nmis_injected: u32,
    /// VMCALLs from the guest's NMI handler: reinjected NMIs that arrived.
    pub nmis_handled: u32,
}

/// What an exit turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitEvent {
    /// A main VMCALL before the last one.
    MainVmcall,
    /// The last planned main VMCALL.
    LastMainVmcall,
    /// The guest's NMI handler reporting that a reinjected NMI arrived.
    GuestNmiHandler,
    /// An NMI the guest can take now: inject it.
    NmiInjected,
    /// An NMI while the guest cannot take an NMI yet (STI, MOV SS or NMI
    /// blocking): wait for the NMI window.
    NmiDeferred,
    /// The NMI window opened: inject the pending NMI.
    NmiWindowInjected,
    /// The exit interrupted an event's delivery; re-delivering it is not
    /// handled.
    InterruptedDelivery,
    /// Anything else.
    Unexpected,
}

/// What the handler does after an exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitAction {
    /// Return to the guest.
    ///
    /// `advance_rip`: move GUEST_RIP past the exiting instruction (a
    /// VMCALL). `inject_nmi`: write [`INJECT_NMI`] to
    /// VM_ENTRY_INTERRUPTION_INFO. `nmi_window`: turn NMI-window exiting on
    /// (`Some(true)`) or off (`Some(false)`), or leave it (`None`).
    Resume { advance_rip: bool, inject_nmi: bool, nmi_window: Option<bool> },
    /// The last planned exit arrived as expected; stop.
    Finished,
    /// Not an exit this hypervisor handles; stop without resuming.
    Unexpected,
}

impl ExitEvent {
    /// The action for this event.
    ///
    /// Injecting always turns NMI-window exiting off: it may have been on
    /// for an earlier NMI the new one replaces, and turning it off when it
    /// was already off is harmless.
    pub fn action(self) -> ExitAction {
        let resume = |advance_rip, inject_nmi, nmi_window| ExitAction::Resume { advance_rip, inject_nmi, nmi_window };
        match self {
            Self::MainVmcall | Self::GuestNmiHandler => resume(true, false, None),
            Self::NmiInjected | Self::NmiWindowInjected => resume(false, true, Some(false)),
            Self::NmiDeferred => resume(false, false, Some(true)),
            Self::LastMainVmcall => ExitAction::Finished,
            Self::InterruptedDelivery | Self::Unexpected => ExitAction::Unexpected,
        }
    }
}

/// The guest's RAX at its next main VMCALL: the marker, plus one for each
/// main VMCALL already handled (the guest runs `inc eax` before #2).
pub fn expected_main_rax(state: ExitState) -> u64 {
    u64::from(GUEST_MARKER) + u64::from(state.main_vmcalls)
}

/// Decides what `exit` is, given what happened before (`state`), and
/// returns the event with the state for the next exit.
///
/// A VM-entry failure or an interrupted delivery is never handled. Several
/// NMIs never queue: a new NMI while one is pending replaces it, as on real
/// hardware, where at most one NMI waits.
pub fn decide(state: ExitState, exit: ExitInfo) -> (ExitEvent, ExitState) {
    if exit.reason.entry_failure {
        return (ExitEvent::Unexpected, state);
    }
    if exit.idt_vectoring_valid {
        return (ExitEvent::InterruptedDelivery, state);
    }

    let injected = ExitState { nmi_pending: false, nmis_injected: state.nmis_injected + 1, ..state };
    match exit.reason.basic {
        EXIT_REASON_EXCEPTION_OR_NMI if is_nmi(exit.interruption_info) => {
            if exit.interruptibility & NMI_INJECTION_BLOCKED == 0 {
                (ExitEvent::NmiInjected, injected)
            } else {
                (ExitEvent::NmiDeferred, ExitState { nmi_pending: true, ..state })
            }
        }
        // Per the SDM, NMI-window exits never occur under MOV SS blocking, but
        // the processor may still report one under STI blocking. Injecting
        // then would fail the VM entry, so keep waiting. (MOV SS stays in the
        // mask; it is harmless.)
        EXIT_REASON_NMI_WINDOW if state.nmi_pending && exit.interruptibility & NMI_INJECTION_BLOCKED != 0 => {
            (ExitEvent::NmiDeferred, state)
        }
        EXIT_REASON_NMI_WINDOW if state.nmi_pending => (ExitEvent::NmiWindowInjected, injected),
        EXIT_REASON_VMCALL if exit.guest_rax == u64::from(GUEST_NMI_MARKER) => {
            (ExitEvent::GuestNmiHandler, ExitState { nmis_handled: state.nmis_handled + 1, ..state })
        }
        EXIT_REASON_VMCALL if exit.guest_rax == expected_main_rax(state) => {
            let state = ExitState { main_vmcalls: state.main_vmcalls + 1, ..state };
            if state.main_vmcalls < PLANNED_MAIN_VMCALLS {
                (ExitEvent::MainVmcall, state)
            } else {
                (ExitEvent::LastMainVmcall, state)
            }
        }
        _ => (ExitEvent::Unexpected, state),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/vmx/exit_decision.rs"]
mod tests;
