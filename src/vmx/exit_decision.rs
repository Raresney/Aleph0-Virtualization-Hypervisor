//! What the VM-exit handler does with each exit: a pure state machine.
//!
//! The handler reads the exit's VMCS fields into an [`ExitInfo`], calls
//! [`decide`] with the [`ExitState`] kept between exits, and applies the
//! [`ExitAction`] of the returned [`ExitEvent`]. Nothing here touches the
//! CPU, so every case is a host unit test.
//!
//! The guest (`guest.rs`) writes its read-only data page, makes two main
//! VMCALLs, with `GUEST_MARKER` and then `GUEST_MARKER + 1` in RAX, and
//! waits between them for an NMI:
//!
//! ```text
//! EPT violation  ──▶ a write to the protected data page: make it writable,
//!                    resume at the same RIP so the write is retried
//! main VMCALL #1 ──▶ resume past it (only after the EPT violation)
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
/// Basic exit reason of an EPT violation: an access the EPT entries do not
/// allow.
pub const EXIT_REASON_EPT_VIOLATION: u16 = 48;
/// Basic exit reason of an EPT misconfiguration: an EPT entry the CPU
/// cannot use at all (for example W = 1 with R = 0). Never handled.
pub const EXIT_REASON_EPT_MISCONFIG: u16 = 49;

// Exit qualification bits of an EPT violation (Intel SDM Vol. 3C, "Exit
// Qualification for EPT Violations").
/// Bit 0: the access was a read.
pub const EPT_ACCESS_READ: u64 = 1 << 0;
/// Bit 1: the access was a write.
pub const EPT_ACCESS_WRITE: u64 = 1 << 1;
/// Bit 2: the access was an instruction fetch.
pub const EPT_ACCESS_FETCH: u64 = 1 << 2;
/// Bit 3: the EPT entries allowed reads of the page.
pub const EPT_PAGE_READABLE: u64 = 1 << 3;
/// Bit 4: the EPT entries allowed writes.
pub const EPT_PAGE_WRITABLE: u64 = 1 << 4;
/// Bit 5: the EPT entries allowed execution.
pub const EPT_PAGE_EXECUTABLE: u64 = 1 << 5;
/// Bit 7: GUEST_LINEAR_ADDRESS is valid.
pub const EPT_LINEAR_VALID: u64 = 1 << 7;
/// Bit 8 (with bit 7): the access was to the linear address the guest
/// used, not to one of the guest's own page tables during the walk.
pub const EPT_TRANSLATED_ACCESS: u64 = 1 << 8;
/// Bit 12: the violation happened during an IRET that ended NMI blocking.
/// Resuming would then need NMI blocking set again by hand, which Aleph0
/// does not do, so such a violation is never handled.
pub const EPT_NMI_UNBLOCKING_IRET: u64 = 1 << 12;

/// An EPT violation's exit qualification (EXIT_QUALIFICATION), decoded with
/// the bits above. Other exits carry other layouts in the same field; only
/// EPT exits are read through this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EptQualification(pub u64);

impl EptQualification {
    /// Whether the access was a write.
    pub fn is_write(self) -> bool {
        self.0 & EPT_ACCESS_WRITE != 0
    }

    /// The kind of access, for the report. Only one is named; a write wins,
    /// since that is the access Aleph0 handles.
    pub fn access_name(self) -> &'static str {
        if self.is_write() {
            "write"
        } else if self.0 & EPT_ACCESS_FETCH != 0 {
            "instruction fetch"
        } else if self.0 & EPT_ACCESS_READ != 0 {
            "read"
        } else {
            "no access bit set"
        }
    }

    /// What the EPT entries allowed for the page, from bits 5:3, as
    /// `(R, W, X)` with 1 for allowed.
    pub fn permissions(self) -> (u8, u8, u8) {
        (
            u8::from(self.0 & EPT_PAGE_READABLE != 0),
            u8::from(self.0 & EPT_PAGE_WRITABLE != 0),
            u8::from(self.0 & EPT_PAGE_EXECUTABLE != 0),
        )
    }

    /// Whether GUEST_LINEAR_ADDRESS is valid (bit 7).
    pub fn linear_valid(self) -> bool {
        self.0 & EPT_LINEAR_VALID != 0
    }

    /// The EPT violation Aleph0 handles: a write to a page EPT maps readable
    /// but not writable, through the linear address the guest used.
    pub fn is_protected_write(self) -> bool {
        let required = EPT_ACCESS_WRITE | EPT_PAGE_READABLE | EPT_LINEAR_VALID | EPT_TRANSLATED_ACCESS;
        let refused = EPT_PAGE_WRITABLE | EPT_NMI_UNBLOCKING_IRET;
        self.0 & required == required && self.0 & refused == 0
    }
}

/// How many main VMCALLs the guest makes; the last one ends the run.
pub const PLANNED_MAIN_VMCALLS: u32 = 2;

/// IDT vector of NMI.
pub const NMI_VECTOR: u8 = 2;

/// An interruption-information value: VM_EXIT_INTERRUPTION_INFO,
/// IDT_VECTORING_INFO and VM_ENTRY_INTERRUPTION_INFO share the layout.
///
/// ```text
///  31    30  13  12           11          10   8  7      0
/// ┌─────┬──────┬────────────┬────────────┬───────┬────────┐
/// │valid│ res. │NMI unblock.│ error code │ type  │ vector │
/// │     │      │ (exit only)│   valid    │       │        │
/// └─────┴──────┴────────────┴────────────┴───────┴────────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptionInfo(pub u32);

impl InterruptionInfo {
    /// Bit 31: the field is valid.
    pub const VALID: u32 = 1 << 31;
    /// Interruption type 2 (bits 10:8): NMI.
    const TYPE_NMI: u32 = 2;

    /// The VM_ENTRY_INTERRUPTION_INFO value that injects an NMI at the next
    /// VM entry: valid, type NMI, vector 2. The CPU clears the field after
    /// each successful entry, so it injects once.
    pub const NMI: Self = Self(Self::VALID | (Self::TYPE_NMI << 8) | NMI_VECTOR as u32);

    /// Whether the field describes an event at all (bit 31).
    pub fn is_valid(self) -> bool {
        self.0 & Self::VALID != 0
    }

    /// Whether this describes an NMI: valid, type 2, vector 2. Bit 12 (NMI
    /// unblocking due to IRET) is ignored.
    pub fn is_nmi(self) -> bool {
        self.is_valid() && (self.0 >> 8) & 0b111 == Self::TYPE_NMI && self.vector() == Some(NMI_VECTOR)
    }

    /// The vector (bits 7:0), if the field is valid.
    pub fn vector(self) -> Option<u8> {
        self.is_valid().then_some(self.0 as u8)
    }
}

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

/// What the handler read about the current exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitInfo {
    pub reason: ExitReason,
    /// VM_EXIT_INTERRUPTION_INFO.
    pub interruption_info: InterruptionInfo,
    pub guest_rax: u64,
    /// GUEST_INTERRUPTIBILITY_STATE.
    pub interruptibility: u32,
    /// IDT_VECTORING_INFO bit 31: the exit interrupted an event's delivery
    /// through the guest IDT.
    pub idt_vectoring_valid: bool,
    /// EXIT_QUALIFICATION, which [`decide`] reads for EPT violations only.
    pub exit_qualification: EptQualification,
    /// GUEST_PHYSICAL_ADDRESS, read for EPT exits only; 0 otherwise.
    pub guest_physical: u64,
    /// GPA of the page EPT maps read-only (`ept::protected_page`), 0 if none.
    pub protected_page: u64,
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
    /// EPT violations on the protected page after which write was granted.
    pub ept_writes_granted: u32,
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
    /// The guest wrote its protected data page: grant write and retry the
    /// write.
    EptWriteGranted,
    /// A main VMCALL arrived before any EPT violation: the write to the data
    /// page went through, so EPT did not protect it.
    EptWriteMissing,
    /// Anything else.
    Unexpected,
}

/// What the handler does after an exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitAction {
    /// Return to the guest.
    ///
    /// `advance_rip`: move GUEST_RIP past the exiting instruction (a
    /// VMCALL). `inject_nmi`: write [`InterruptionInfo::NMI`] to
    /// VM_ENTRY_INTERRUPTION_INFO. `nmi_window`: turn NMI-window exiting on
    /// (`Some(true)`) or off (`Some(false)`), or leave it (`None`).
    /// `grant_write`: make the protected page writable in EPT
    /// (`ept::grant_write`).
    Resume {
        advance_rip: bool,
        inject_nmi: bool,
        nmi_window: Option<bool>,
        grant_write: bool,
    },
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
        let resume = |advance_rip, inject_nmi, nmi_window| ExitAction::Resume {
            advance_rip,
            inject_nmi,
            nmi_window,
            grant_write: false,
        };
        match self {
            Self::MainVmcall | Self::GuestNmiHandler => resume(true, false, None),
            Self::NmiInjected | Self::NmiWindowInjected => resume(false, true, Some(false)),
            Self::NmiDeferred => resume(false, false, Some(true)),
            // RIP stays on the faulting write, so it runs again.
            Self::EptWriteGranted => ExitAction::Resume {
                advance_rip: false,
                inject_nmi: false,
                nmi_window: None,
                grant_write: true,
            },
            Self::LastMainVmcall => ExitAction::Finished,
            Self::InterruptedDelivery | Self::EptWriteMissing | Self::Unexpected => ExitAction::Unexpected,
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
/// hardware, where at most one NMI waits. Exactly one EPT violation is
/// handled, a write to the protected page, and it must come before the
/// first main VMCALL.
pub fn decide(state: ExitState, exit: ExitInfo) -> (ExitEvent, ExitState) {
    if exit.reason.entry_failure {
        return (ExitEvent::Unexpected, state);
    }
    if exit.idt_vectoring_valid {
        return (ExitEvent::InterruptedDelivery, state);
    }

    let injected = ExitState {
        nmi_pending: false,
        nmis_injected: state.nmis_injected + 1,
        ..state
    };
    match exit.reason.basic {
        EXIT_REASON_EXCEPTION_OR_NMI if exit.interruption_info.is_nmi() => {
            if exit.interruptibility & NMI_INJECTION_BLOCKED == 0 {
                (ExitEvent::NmiInjected, injected)
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
        // Per the SDM, NMI-window exits never occur under MOV SS blocking, but
        // the processor may still report one under STI blocking. Injecting
        // then would fail the VM entry, so keep waiting. (MOV SS stays in the
        // mask; it is harmless.)
        EXIT_REASON_NMI_WINDOW if state.nmi_pending && exit.interruptibility & NMI_INJECTION_BLOCKED != 0 => {
            (ExitEvent::NmiDeferred, state)
        }
        EXIT_REASON_NMI_WINDOW if state.nmi_pending => (ExitEvent::NmiWindowInjected, injected),
        EXIT_REASON_EPT_VIOLATION
            if exit.protected_page != 0
                && exit.guest_physical & !0xFFF == exit.protected_page
                && exit.exit_qualification.is_protected_write()
                && state.ept_writes_granted == 0 =>
        {
            (
                ExitEvent::EptWriteGranted,
                ExitState {
                    ept_writes_granted: 1,
                    ..state
                },
            )
        }
        EXIT_REASON_VMCALL if exit.guest_rax == u64::from(GUEST_NMI_MARKER) => (
            ExitEvent::GuestNmiHandler,
            ExitState {
                nmis_handled: state.nmis_handled + 1,
                ..state
            },
        ),
        EXIT_REASON_VMCALL if exit.guest_rax == expected_main_rax(state) && state.ept_writes_granted == 0 => {
            (ExitEvent::EptWriteMissing, state)
        }
        EXIT_REASON_VMCALL if exit.guest_rax == expected_main_rax(state) => {
            let state = ExitState {
                main_vmcalls: state.main_vmcalls + 1,
                ..state
            };
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
