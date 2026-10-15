//! What the VM-exit handler does with each exit: pure decisions, one
//! handler per exit reason.
//!
//! The handler reads the exit's VMCS fields into an [`ExitInfo`], calls
//! [`decide`] with the [`ExitState`] kept between exits, and applies the
//! [`ExitAction`] of the returned [`ExitEvent`]. Nothing here touches the
//! CPU, so every case is a host unit test.
//!
//! [`decide`] first checks what holds for every exit (a failed VM entry, an
//! interrupted event delivery), then dispatches on the exit reason to a
//! handler with the signature `fn(ExitState, &ExitInfo) -> (ExitEvent,
//! ExitState)`, the way KVM's `kvm_vmx_exit_handlers[]` does, but as a
//! `match`, which the compiler checks and turns into the same jump table:
//!
//! - `emulation.rs`: instructions Aleph0 executes for any guest (CPUID).
//! - `scenario.rs`: the test guest's own exits (its EPT write, its VMCALLs,
//!   NMI reinjection).
//!
//! An exit reason without a handler stops the guest.

mod emulation;
mod scenario;

pub use emulation::{Emulation, EmulationCounts, cpuid_policy};
pub use scenario::{PLANNED_MAIN_VMCALLS, expected_main_rax};

/// VM-exit reason, split into the fields of the VM_EXIT_REASON VMCS field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitReason {
    /// Bits 15:0: which event caused the exit (Intel SDM Vol. 3D, Appendix C).
    pub basic: u16,
    /// Bit 31: VM entry itself failed. The guest never ran; `basic` says
    /// why (33 = invalid guest state, 34 = MSR loading, 41 = machine check).
    pub entry_failure: bool,
}

impl ExitReason {
    pub fn from_raw(raw: u32) -> Self {
        Self {
            basic: raw as u16,
            entry_failure: raw & (1 << 31) != 0,
        }
    }
}

/// Human-readable name for a basic exit reason. Only the reasons this
/// hypervisor is likely to meet early on are spelled out.
pub fn exit_reason_name(basic: u16) -> &'static str {
    match basic {
        0 => "exception or NMI",
        1 => "external interrupt",
        2 => "triple fault",
        3 => "INIT signal",
        7 => "interrupt window",
        8 => "NMI window",
        9 => "task switch",
        10 => "CPUID",
        12 => "HLT",
        18 => "VMCALL",
        28 => "control-register access",
        30 => "I/O instruction",
        31 => "RDMSR",
        32 => "WRMSR",
        33 => "VM-entry failure: invalid guest state",
        34 => "VM-entry failure: MSR loading",
        41 => "VM-entry failure: machine-check event",
        48 => "EPT violation",
        49 => "EPT misconfiguration",
        UNREADABLE_REASON => "VM_EXIT_REASON unreadable",
        _ => "unnamed exit reason",
    }
}

/// Reason the handler reports when VM_EXIT_REASON itself could not be read.
/// Basic exit reasons stop far below 0xFFFF, so it never names a real exit.
pub const UNREADABLE_REASON: u16 = 0xFFFF;

/// Basic exit reason of an exception or NMI exit.
pub const EXIT_REASON_EXCEPTION_OR_NMI: u16 = 0;
/// Basic exit reason of an NMI-window exit.
pub const EXIT_REASON_NMI_WINDOW: u16 = 8;
/// Basic exit reason of CPUID, which always exits.
pub const EXIT_REASON_CPUID: u16 = 10;
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

/// What the handler read about the current exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitInfo {
    pub reason: ExitReason,
    /// VM_EXIT_INTERRUPTION_INFO.
    pub interruption_info: InterruptionInfo,
    /// The guest's RAX, RCX and RDX. CPUID reads its leaf from EAX and its
    /// subleaf from ECX. At main VMCALL #1, ECX and EDX hold what the guest
    /// read from its data page before and after its write.
    pub guest_rax: u64,
    pub guest_rcx: u64,
    pub guest_rdx: u64,
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
    /// Exits emulated so far, per instruction.
    pub emulated: EmulationCounts,
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
    /// Main VMCALL #1 after the granted write, but ECX/EDX do not hold what
    /// the guest should have read from its data page: the seed before its
    /// write, its own value after it.
    DataPageMismatch,
    /// An instruction Aleph0 executes for the guest, then resumes past it.
    Emulated(Emulation),
    /// The last main VMCALL arrived, but the guest's emulated exits do not
    /// match `guest::EXPECTED_EMULATION`.
    EmulationMissing,
    /// Anything else.
    Unexpected,
}

/// How the handler prepares the VMCS (and EPT) before resuming the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumePlan {
    /// Move GUEST_RIP past the exiting instruction (a VMCALL).
    pub advance_rip: bool,
    /// Write [`InterruptionInfo::NMI`] to VM_ENTRY_INTERRUPTION_INFO.
    pub inject_nmi: bool,
    /// Turn NMI-window exiting on (`Some(true)`) or off (`Some(false)`), or
    /// leave it (`None`).
    pub nmi_window: Option<bool>,
    /// Make the protected page writable in EPT
    /// (`ept::ProtectedPage::grant_write`).
    pub grant_write: bool,
    /// Execute this instruction for the guest and put its result in the
    /// guest's registers, before RIP moves past it.
    pub emulate: Option<Emulation>,
}

impl ResumePlan {
    /// Go on after the exiting instruction (a VMCALL).
    pub const PAST_INSTRUCTION: Self = Self {
        advance_rip: true,
        inject_nmi: false,
        nmi_window: None,
        grant_write: false,
        emulate: None,
    };
    /// Inject an NMI, delivered before the instruction the guest was about
    /// to run. Injecting always turns NMI-window exiting off: it may have
    /// been on for an earlier NMI the new one replaces, and turning it off
    /// when it was already off is harmless.
    pub const INJECT_NMI: Self = Self {
        advance_rip: false,
        inject_nmi: true,
        nmi_window: Some(false),
        grant_write: false,
        emulate: None,
    };
    /// Go on where the guest was, with NMI-window exiting on, so the next
    /// exit comes as soon as the guest can take an NMI.
    pub const WAIT_FOR_NMI_WINDOW: Self = Self {
        advance_rip: false,
        inject_nmi: false,
        nmi_window: Some(true),
        grant_write: false,
        emulate: None,
    };
    /// Make the protected page writable; RIP stays on the faulting write, so
    /// it runs again.
    pub const RETRY_AFTER_GRANT: Self = Self {
        advance_rip: false,
        inject_nmi: false,
        nmi_window: None,
        grant_write: true,
        emulate: None,
    };
}

/// What the handler does after an exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitAction {
    /// Return to the guest, after preparing it as the plan says.
    Resume(ResumePlan),
    /// The last planned exit arrived as expected; stop.
    Finished,
    /// Not an exit this hypervisor handles; stop without resuming.
    Unexpected,
}

impl ExitEvent {
    /// The action for this event.
    pub fn action(self) -> ExitAction {
        match self {
            Self::MainVmcall | Self::GuestNmiHandler => ExitAction::Resume(ResumePlan::PAST_INSTRUCTION),
            Self::NmiInjected | Self::NmiWindowInjected => ExitAction::Resume(ResumePlan::INJECT_NMI),
            Self::NmiDeferred => ExitAction::Resume(ResumePlan::WAIT_FOR_NMI_WINDOW),
            Self::EptWriteGranted => ExitAction::Resume(ResumePlan::RETRY_AFTER_GRANT),
            Self::Emulated(emulation) => ExitAction::Resume(ResumePlan {
                emulate: Some(emulation),
                ..ResumePlan::PAST_INSTRUCTION
            }),
            Self::LastMainVmcall => ExitAction::Finished,
            Self::InterruptedDelivery
            | Self::EptWriteMissing
            | Self::DataPageMismatch
            | Self::EmulationMissing
            | Self::Unexpected => ExitAction::Unexpected,
        }
    }
}

/// Decides what `exit` is, given what happened before (`state`), and
/// returns the event with the state for the next exit.
///
/// A VM-entry failure or an interrupted delivery is never handled, whatever
/// the reason. Every other exit goes to the handler for its reason.
pub fn decide(state: ExitState, exit: ExitInfo) -> (ExitEvent, ExitState) {
    if exit.reason.entry_failure {
        return (ExitEvent::Unexpected, state);
    }
    if exit.idt_vectoring_valid {
        return (ExitEvent::InterruptedDelivery, state);
    }
    match exit.reason.basic {
        EXIT_REASON_CPUID => emulation::cpuid(state, &exit),
        EXIT_REASON_EXCEPTION_OR_NMI => scenario::exception_or_nmi(state, &exit),
        EXIT_REASON_NMI_WINDOW => scenario::nmi_window(state, &exit),
        EXIT_REASON_EPT_VIOLATION => scenario::ept_violation(state, &exit),
        EXIT_REASON_VMCALL => scenario::vmcall(state, &exit),
        _ => (ExitEvent::Unexpected, state),
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/exit_decision.rs"]
mod tests;
