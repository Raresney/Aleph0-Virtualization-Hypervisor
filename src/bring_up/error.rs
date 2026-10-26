//! Why bring-up stopped, and how that gets printed.

use uefi::Status;
use uefi::boot::MemoryType;

use crate::vmx;
use crate::vmx::apic::LocalApicError;
use crate::vmx::context_tables::{GdtError, TssError};
use crate::vmx::ept::EptError;
use crate::vmx::exit_bitmaps::ExitBitmapsError;
use crate::vmx::exit_decision::ExitReason;
use crate::vmx::guest::GuestMemoryError;
use crate::vmx::guest_state::GuestStateError;
use crate::vmx::host::HostError;
use crate::vmx::mtrr::MtrrError;
use crate::vmx::vmcs::VmcsError;
use crate::vmx::vmexit::{VcpuStats, VmExitStackError};
use crate::vmx::vmxon::VmxOnError;

use super::teardown::TeardownError;

/// Why bring-up stopped. Each step returns one of these, so the sequence
/// reads top to bottom with `?` and [`report_error`] prints the outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BringUpError {
    Tss(TssError),
    Gdt(GdtError),
    VmExitStack(VmExitStackError),
    GuestMemory(GuestMemoryError),
    ExitBitmaps(ExitBitmapsError),
    VmxNotSupportedByCpu,
    VmxDisabledByFirmware,
    /// An MTRR MSR holds a value the CPU would refuse, or the MTRRs hold
    /// something Aleph0 cannot copy into EPT. Before VMXON.
    Mtrr(MtrrError),
    /// The CPU lacks EPT support Aleph0 needs, or building the EPT tables
    /// failed. Both happen before VMXON.
    Ept(EptError),
    /// The test guest could not read the Local APIC's registers in xAPIC
    /// mode: its page tables or EPT do not map their page to itself, EPT
    /// with UC. Before VMXON.
    LocalApic(LocalApicError),
    /// Building the page tables, GDT, TSS or IDT that VMX root operation
    /// runs on failed. Before VMXON.
    Host(HostError),
    VmxOn(VmxOnError),
    /// A VMCS step failed; `operation` names the step for the report.
    /// `instruction_error` is the VM-instruction error number of a
    /// VmFailValid, read when the error was created: after teardown it can
    /// no longer be read.
    Vmcs {
        operation: &'static str,
        error: VmcsError,
        instruction_error: Option<u32>,
    },
    /// Building or writing the guest state failed. For a VMCS failure,
    /// `instruction_error` is captured as for [`BringUpError::Vmcs`].
    GuestState {
        error: GuestStateError,
        instruction_error: Option<u32>,
    },
    /// GDTR, TR, the TSS base or IDTR of the context tables changed between
    /// activation and the launch. The VMCS guest fields were copied from the
    /// activated tables, so the guest would start on stale ones.
    ContextTablesChanged,
    /// The UEFI memory map, which the resident allocations are checked
    /// against, could not be read. Before the launch.
    ResidentMemoryMapUnavailable,
    /// The resident allocation at `address` lies in memory the OS may reuse
    /// after `ExitBootServices`: its memory-map region has type
    /// `memory_type`, or no region holds it (`None`). Before the launch.
    NotResident {
        address: u64,
        memory_type: Option<MemoryType>,
    },
    /// `count` resident allocations came after `vmx::page`'s list was full,
    /// so they could not be checked. Before the launch.
    ResidentAllocationsUnlisted(usize),
    /// `vmx::page` listed no resident allocation, not even the image copy,
    /// so the check would have checked nothing. Before the launch.
    NoResidentAllocations,
    /// The `ExitBootServices` event could not be created. Before the launch.
    ExitBootServicesEvent(Status),
    /// The guest stopped at exit `number`, which the exit handler did not
    /// resume: it does not handle that exit, or it is an expected VMCALL the
    /// handler could not step past. Its lines on serial say which.
    UnexpectedExit {
        number: u64,
        reason: ExitReason,
    },
    /// The CPU's MTRRs read differently after the guest than before: a
    /// guest write reached them instead of the guest's copy.
    MtrrsChanged,
    /// The exit handler wrote the lowest word of the VM-exit stack: it used
    /// all of it and may have run on into the memory below, which nothing
    /// guards.
    VmExitStackFull,
    /// The guest finished, but its exit statistics differ from what the
    /// test guest does (`guest::expected_stats`): an emulated exit is
    /// missing or came twice.
    UnexpectedExitStats(VcpuStats),
    /// VMRESUME failed after an exit the handler resumed.
    ResumeFailed {
        error: VmcsError,
        instruction_error: Option<u32>,
    },
    /// Leaving VMX operation failed. Returned only when nothing failed
    /// before teardown; otherwise that earlier error is returned and this
    /// one was printed when it happened.
    Teardown(TeardownError),
}

impl From<LocalApicError> for BringUpError {
    fn from(error: LocalApicError) -> Self {
        Self::LocalApic(error)
    }
}

impl From<TssError> for BringUpError {
    fn from(error: TssError) -> Self {
        Self::Tss(error)
    }
}

impl From<GdtError> for BringUpError {
    fn from(error: GdtError) -> Self {
        Self::Gdt(error)
    }
}

impl From<VmExitStackError> for BringUpError {
    fn from(error: VmExitStackError) -> Self {
        Self::VmExitStack(error)
    }
}

impl From<GuestMemoryError> for BringUpError {
    fn from(error: GuestMemoryError) -> Self {
        Self::GuestMemory(error)
    }
}

impl From<ExitBitmapsError> for BringUpError {
    fn from(error: ExitBitmapsError) -> Self {
        Self::ExitBitmaps(error)
    }
}

impl From<MtrrError> for BringUpError {
    fn from(error: MtrrError) -> Self {
        Self::Mtrr(error)
    }
}

impl From<EptError> for BringUpError {
    fn from(error: EptError) -> Self {
        Self::Ept(error)
    }
}

impl From<HostError> for BringUpError {
    fn from(error: HostError) -> Self {
        Self::Host(error)
    }
}

impl From<VmxOnError> for BringUpError {
    fn from(error: VmxOnError) -> Self {
        Self::VmxOn(error)
    }
}

/// Converts a guest-state failure, for use with `map_err`. Reads the
/// VM-instruction error number now, while the VMCS is still current.
pub(super) fn guest_state_error(error: GuestStateError) -> BringUpError {
    let instruction_error = match error {
        // SAFETY: a VmFailValid came from a VMX instruction in VMX operation,
        // and the VMCS is not cleared until teardown, after this runs.
        GuestStateError::Vmcs { error, .. } => unsafe { vmx::vmcs::instruction_error_for(error) },
        _ => None,
    };
    BringUpError::GuestState {
        error,
        instruction_error,
    }
}

impl From<TeardownError> for BringUpError {
    fn from(error: TeardownError) -> Self {
        Self::Teardown(error)
    }
}

/// Tags a VMCS failure with the step it came from, for use with `map_err`.
/// Reads the VM-instruction error number now, while the VMCS is still
/// current.
pub(super) fn vmcs_step(operation: &'static str) -> impl FnOnce(VmcsError) -> BringUpError {
    move |error| BringUpError::Vmcs {
        operation,
        error,
        // SAFETY: a VmFailValid came from a VMX instruction in VMX
        // operation, and the VMCS is not cleared until teardown, after this
        // runs.
        instruction_error: unsafe { vmx::vmcs::instruction_error_for(error) },
    }
}

/// Prints why bring-up stopped.
pub fn report_error(error: BringUpError) {
    match error {
        BringUpError::Tss(error) => log!("Context TSS allocation failed: {error:?}"),
        // Only this variant comes after LGDT/LTR; every other GdtError is
        // returned before the CPU's tables are touched.
        BringUpError::Gdt(GdtError::ActivationVerificationFailed) => {
            log!("Context GDT/TSS activation failed verification; the CPU may already use the new tables.")
        }
        BringUpError::Gdt(error) => log!("Context GDT/TSS setup failed: {error:?}; GDTR/TR unchanged."),
        BringUpError::VmExitStack(error) => log!("VM-exit stack allocation failed: {error:?}"),
        BringUpError::GuestMemory(GuestMemoryError::NotIdentityMapped {
            virtual_address,
            physical,
        }) => log!(
            "Guest memory setup failed: page {virtual_address:#018x} is mapped at {physical:#018x}, not identity-mapped."
        ),
        BringUpError::GuestMemory(error) => log!("Guest memory setup failed: {error:?}"),
        BringUpError::ExitBitmaps(error) => log!("Exit bitmap allocation failed: {error:?}"),
        BringUpError::VmxNotSupportedByCpu => log!("VMX not supported by this CPU."),
        BringUpError::VmxDisabledByFirmware => log!("VMX supported by CPU but disabled by firmware."),
        BringUpError::Mtrr(error) => log!("MTRR setup failed: {error}."),
        BringUpError::Ept(EptError::RangeTooLarge { end, limit }) => log!(
            "EPT setup failed: the memory map reaches {end:#x}, past {limit:#x}, the end of the guest-physical address space (MAXPHYADDR, at most the 48 bits a 4-level EPT walk translates)."
        ),
        BringUpError::Ept(error) => log!("EPT setup failed: {error:?}"),
        BringUpError::LocalApic(LocalApicError::GuestMapping { address, translation }) => log!(
            "The page tables the guest shares do not map the Local APIC's registers at {address:#x} to themselves: {translation:?}."
        ),
        BringUpError::LocalApic(LocalApicError::EptMapping { address, end }) => {
            log!("EPT does not map the Local APIC's registers at {address:#x} to themselves, UC: {end}.")
        }
        BringUpError::Host(error) => log!("Host environment setup failed: {error:?}"),
        BringUpError::VmxOn(error) => log!("VMXON failed: {error:?}"),
        BringUpError::Vmcs {
            operation,
            error,
            instruction_error,
        } => report_vmcs_error(operation, error, instruction_error),
        BringUpError::GuestState {
            error:
                GuestStateError::Vmcs {
                    field,
                    error: VmcsError::ReadbackMismatch { written, read, .. },
                },
            ..
        } => log!("Guest-state field {field:#06x} read back {read:#x}, but {written:#x} was written."),
        BringUpError::GuestState {
            error: GuestStateError::Vmcs { field, error },
            instruction_error,
        } => {
            log!("Guest-state field {field:#06x} failed:");
            report_vmcs_error("guest-state write", error, instruction_error);
        }
        BringUpError::GuestState { error, .. } => log!("Guest state invalid: {error:x?}"),
        BringUpError::ContextTablesChanged => {
            log!("Context descriptor tables changed after VMX/UEFI calls; the guest was not launched.")
        }
        BringUpError::ResidentMemoryMapUnavailable => {
            log!(
                "The UEFI memory map is unavailable, so the resident allocations went unchecked; the guest was not launched."
            )
        }
        BringUpError::NotResident {
            address,
            memory_type: Some(memory_type),
        } => log!(
            "The resident allocation at {address:#018x} is {memory_type:?}, which the OS may reuse after ExitBootServices; the guest was not launched."
        ),
        BringUpError::NotResident {
            address,
            memory_type: None,
        } => log!("The resident allocation at {address:#018x} is in no memory-map region; the guest was not launched."),
        BringUpError::ResidentAllocationsUnlisted(count) => log!(
            "{count} resident allocation(s) came after the list was full and went unchecked; the guest was not launched."
        ),
        BringUpError::NoResidentAllocations => {
            log!("No resident allocation was listed, not even the image copy; the guest was not launched.")
        }
        BringUpError::ExitBootServicesEvent(status) => {
            log!("The ExitBootServices event could not be created: {status:?}; the firmware was not launched.")
        }
        BringUpError::UnexpectedExit { number, reason } => log!(
            "Guest stopped at VM exit #{number}: reason={} ({}){}; Aleph0 did not resume the guest.",
            reason.basic,
            vmx::exit_decision::exit_reason_name(reason.basic),
            if reason.entry_failure { " [VM entry failed]" } else { "" },
        ),
        BringUpError::MtrrsChanged => {
            log!("The CPU's MTRRs changed while the guest ran: a guest write reached them, not its copy.")
        }
        BringUpError::VmExitStackFull => log!(
            "The exit handler used all {} bytes of the VM-exit stack and may have overwritten the memory below it.",
            vmx::vmexit::VM_EXIT_STACK_SIZE,
        ),
        BringUpError::UnexpectedExitStats(stats) => log!(
            "Guest finished, but its exit statistics were {stats}; expected {}.",
            vmx::guest::expected_stats(&stats),
        ),
        BringUpError::ResumeFailed {
            error,
            instruction_error,
        } => report_vmcs_error("resume", error, instruction_error),
        BringUpError::Teardown(error) => log!("Leaving VMX operation failed: {error:?}."),
    }
}

/// Prints a VMCS failure with the VM-instruction error number captured when
/// it happened. Reads nothing from the VMCS: by now it may be cleared.
fn report_vmcs_error(operation: &str, error: VmcsError, instruction_error: Option<u32>) {
    match (error, instruction_error) {
        (VmcsError::VmFailValid, Some(code)) => {
            let name = vmx::vmcs::vm_instruction_error_name(code);
            log!("VMCS {operation} failed: {name} ({code})");
        }
        (VmcsError::VmFailValid, None) => {
            log!("VMCS {operation} failed: VmFailValid, error number unreadable");
        }
        (VmcsError::ReadbackMismatch { field, written, read }, _) => {
            log!("VMCS {operation} failed: field {field:#06x} read back {read:#x}, but {written:#x} was written.");
        }
        _ => log!("VMCS {operation} failed: {error:?}"),
    }
}
