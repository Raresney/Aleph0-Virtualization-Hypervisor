//! The VM-exit handler's report lines: what an exit was and what Aleph0 did
//! about it. Kept apart from `handler.rs`, so that file reads as the steps.
//!
//! Like the handler, everything here runs in exit context: only VMREAD and
//! the serial port, never firmware.

use super::handler::{EmulationOutcome, ExitRead, Outcome, Resumed};
use super::policy::{self, COUNTERS, Detail, Histogram, Level};
use super::{RegisterFrame, dump, history, read_field};
use crate::vmx::ept::InveptType;
use crate::vmx::exit_decision::{
    EXIT_REASON_EPT_MISCONFIG, EXIT_REASON_EXCEPTION_OR_NMI, EptQualification, ExitEvent, ExitInfo, ExitState,
    InterruptionInfo, PLANNED_MAIN_VMCALLS, exit_reason_name, expected_main_rax,
};
use crate::vmx::guest::{EXPECTED_EMULATION, GUEST_DATA_SEED, GUEST_EPT_VALUE};
use crate::vmx::vmcs::VmcsError;
use crate::vmx::vmcs::fields::GUEST_LINEAR_ADDRESS;

/// One exit, as its report needs it.
pub(super) struct ExitReport<'a> {
    /// The exit's number, from 1.
    pub(super) number: u64,
    /// How many exits of its reason there have been, this one included.
    pub(super) count: u64,
    /// How much of it the print policy prints.
    pub(super) detail: Detail,
    /// What was read about it.
    pub(super) read: &'a ExitRead,
    /// Whether an NMI arrived in root operation since the last exit.
    pub(super) host_nmi: bool,
    /// What it turned out to be.
    pub(super) event: ExitEvent,
    /// The state after it.
    pub(super) next: ExitState,
    /// What came of it.
    pub(super) outcome: Outcome,
}

/// Prints one exit in as much detail as the print policy gives it: what was
/// read about it, an NMI that arrived in root operation meanwhile, what it
/// turned out to be and what came of it. The NMI is printed whatever the
/// detail.
pub(super) fn report_exit(report: &ExitReport<'_>) {
    let ExitReport {
        number,
        count,
        detail,
        read,
        host_nmi,
        event,
        next,
        outcome,
    } = *report;
    let tag = crate::TAG;
    match detail {
        Detail::Full => {}
        Detail::Summary => {
            // Only exits that resume are rate-limited, and only readable
            // ones, so the reason is known here.
            let basic = read.reason().map_or(0, |reason| reason.basic);
            crate::serial_println!(
                "{tag} VM exit #{number}: reason={basic} ({}), {count} exits of this reason so far.",
                exit_reason_name(basic),
            );
            if host_nmi {
                report_host_nmi(number);
            }
            return;
        }
        Detail::Silent => {
            if host_nmi {
                report_host_nmi(number);
            }
            return;
        }
    }
    report_read(number, read);
    if host_nmi {
        report_host_nmi(number);
    }
    match outcome {
        Outcome::Resumed { resumed, .. } => report_event(number, event, read.exit, next, Some(resumed)),
        Outcome::ResumeFailed(failure) => {
            crate::serial_println!("{tag} VM exit #{number}: {failure}; not resuming.")
        }
        Outcome::Stopped(_) => report_event(number, event, read.exit, next, None),
    }
    if outcome.stops() {
        crate::serial_println!("{tag} VM exit #{number}: stopping the guest; returning to bring-up.");
    }
}

/// Prints what [`ExitRead`] holds: the reason, the qualification, an EPT
/// exit's addresses, RIP and instruction length, RAX to RDX, and every field
/// that could not be read.
fn report_read(number: u64, read: &ExitRead) {
    let tag = crate::TAG;
    match read.reason() {
        Some(reason) => {
            crate::serial_println!(
                "{tag} VM exit #{number}: reason={} ({}){}",
                reason.basic,
                exit_reason_name(reason.basic),
                if reason.entry_failure {
                    " [VM entry failed; guest did not run]"
                } else {
                    ""
                },
            );
            if reason.basic == EXIT_REASON_EXCEPTION_OR_NMI
                && !reason.entry_failure
                && let Ok(info) = read.interruption_info
            {
                report_exception(number, InterruptionInfo(info as u32));
            }
        }
        None => report_unreadable(number, "VM_EXIT_REASON", read.reason),
    }
    match read.qualification {
        Ok(qualification) => crate::serial_println!("{tag} VM exit #{number}: qualification={qualification:#018x}"),
        Err(_) => report_unreadable(number, "EXIT_QUALIFICATION", read.qualification),
    }
    if let (Some(reason), Some(guest_physical)) = (read.reason(), read.guest_physical) {
        match guest_physical {
            Ok(guest_physical) => report_ept_exit(
                number,
                reason.basic,
                EptQualification(read.qualification.unwrap_or(0)),
                guest_physical,
            ),
            Err(_) => report_unreadable(number, "GUEST_PHYSICAL_ADDRESS", guest_physical),
        }
    }
    match (read.rip, read.length) {
        (Ok(rip), Ok(length)) => {
            crate::serial_println!("{tag} VM exit #{number}: guest rip={rip:#018x} instruction length={length}")
        }
        (rip, length) => {
            report_unreadable(number, "GUEST_RIP", rip);
            report_unreadable(number, "VM_EXIT_INSTRUCTION_LEN", length);
        }
    }
    let [rax, rbx, rcx, rdx] = read.registers;
    crate::serial_println!(
        "{tag} VM exit #{number}: guest rax={rax:#018x} rbx={rbx:#018x} rcx={rcx:#018x} rdx={rdx:#018x}"
    );
    report_unreadable(number, "VM_EXIT_INTERRUPTION_INFO", read.interruption_info);
    report_unreadable(number, "GUEST_INTERRUPTIBILITY_STATE", read.interruptibility);
    report_unreadable(number, "IDT_VECTORING_INFO", read.idt_vectoring);
}

/// Prints that the VMCS field `name` could not be read at exit `number`, if
/// `value` says so; prints nothing for a value that was read.
fn report_unreadable(number: u64, name: &str, value: Result<u64, VmcsError>) {
    if let Err(error) = value {
        crate::serial_println!("{} VM exit #{number}: {name} unreadable ({error:?})", crate::TAG);
    }
}

/// Prints an EPT exit's addresses and what the EPT entries allowed.
fn report_ept_exit(number: u64, basic: u16, qualification: EptQualification, guest_physical: u64) {
    let tag = crate::TAG;
    if basic == EXIT_REASON_EPT_MISCONFIG {
        crate::serial_println!(
            "{tag} VM exit #{number}: EPT misconfiguration at GPA {guest_physical:#018x}: an EPT entry for it is invalid."
        );
        return;
    }

    let (r, w, x) = qualification.permissions();
    let access = qualification.access_name();
    // The linear address is only valid with qualification bit 7, and only
    // the report needs it, so it is read here.
    match qualification.linear_valid().then(|| read_field(GUEST_LINEAR_ADDRESS)) {
        Some(Ok(linear)) => crate::serial_println!(
            "{tag} VM exit #{number}: EPT violation at GPA {guest_physical:#018x} (linear {linear:#018x}): {access}; page R={r} W={w} X={x}."
        ),
        Some(Err(error)) => crate::serial_println!(
            "{tag} VM exit #{number}: EPT violation at GPA {guest_physical:#018x} (linear address unreadable: {error:?}): {access}; page R={r} W={w} X={x}."
        ),
        None => crate::serial_println!(
            "{tag} VM exit #{number}: EPT violation at GPA {guest_physical:#018x} (no linear address): {access}; page R={r} W={w} X={x}."
        ),
    }
}

/// Prints that an NMI arrived while Aleph0 ran in root operation, and is
/// now pending for the guest. Not "resuming the guest": that text arms
/// `run-hyperv.ps1 -InjectNmi`.
fn report_host_nmi(number: u64) {
    if !policy::enabled(Level::Warn) {
        return;
    }
    crate::serial_println!(
        "{} VM exit #{number}: an NMI arrived while Aleph0 ran in root operation ({} so far); pending for the guest.",
        crate::TAG,
        crate::vmx::host::nmis_taken(),
    );
}

/// Prints what every stop adds after the lines of exit `number`: the
/// guest's state and registers (`frame`), how many exits of each reason there
/// were (`exits_by_reason`), including those the print policy left out, and
/// the last exits, oldest first.
pub(super) fn report_stop(number: u64, frame: &RegisterFrame, exits_by_reason: &[u64; COUNTERS]) {
    dump::report_guest(number, frame);
    crate::serial_println!(
        "{} VM exit #{number}: exits by reason: {}.",
        crate::TAG,
        Histogram(exits_by_reason)
    );
    history::report(format_args!("VM exit #{number}"));
}

/// Prints what exit `number` turned out to be and what Aleph0 does about
/// it. `state` is the state after the exit; `resumed` is how the guest goes
/// on, for events that resume it.
fn report_event(number: u64, event: ExitEvent, exit: Option<ExitInfo>, state: ExitState, resumed: Option<Resumed>) {
    let tag = crate::TAG;
    let rax = exit.map_or(0, |exit| exit.guest_rax);
    let rip = resumed.map_or(0, |resumed| resumed.rip);
    match event {
        ExitEvent::EptWriteGranted => crate::serial_println!(
            "{tag} VM exit #{number}: write to the protected data page: write granted (W=1), INVEPT {}; retrying the write at rip={rip:#018x}.",
            resumed
                .and_then(|resumed| resumed.invept)
                .map_or("not run", InveptType::name),
        ),
        ExitEvent::DataPageMismatch => crate::serial_println!(
            "{tag} VM exit #{number}: the data page read back rcx={:#x} rdx={:#x}, expected {GUEST_DATA_SEED:#x} and {GUEST_EPT_VALUE:#x}.",
            exit.map_or(0, |exit| exit.guest_rcx),
            exit.map_or(0, |exit| exit.guest_rdx),
        ),
        ExitEvent::EptWriteMissing => crate::serial_println!(
            "{tag} VM exit #{number}: main VMCALL (rax={rax:#x}) before any EPT violation: the guest's write to its data page was not caught, so EPT did not protect it."
        ),
        ExitEvent::MainVmcall => crate::serial_println!(
            "{tag} VM exit #{number}: expected VMCALL (rax={rax:#x}); resuming the guest at rip={rip:#018x}."
        ),
        ExitEvent::GuestNmiHandler => crate::serial_println!(
            "{tag} VM exit #{number}: guest NMI handler ran (rax={rax:#x}); the reinjected NMI was delivered; resuming the guest at rip={rip:#018x}."
        ),
        ExitEvent::NmiInjected => crate::serial_println!(
            "{tag} VM exit #{number}: NMI (interruption info={:#010x}); reinjecting it into the guest at rip={rip:#018x}.",
            exit.map_or(0, |exit| exit.interruption_info.0),
        ),
        ExitEvent::NmiDeferred => crate::serial_println!(
            "{tag} VM exit #{number}: NMI cannot be injected yet (interruptibility={:#x}); waiting for the NMI window.",
            exit.map_or(0, |exit| exit.interruptibility),
        ),
        ExitEvent::NmiWindowInjected => crate::serial_println!(
            "{tag} VM exit #{number}: NMI window open; reinjecting the pending NMI at rip={rip:#018x}."
        ),
        ExitEvent::LastMainVmcall if state.nmis_injected == 0 && state.nmis_handled == 0 && !state.nmi_pending => {
            crate::serial_println!(
                "{tag} VM exit #{number}: expected VMCALL (rax={rax:#x}); all {PLANNED_MAIN_VMCALLS} planned VMCALLs handled; no NMI arrived."
            )
        }
        ExitEvent::LastMainVmcall => crate::serial_println!(
            "{tag} VM exit #{number}: expected VMCALL (rax={rax:#x}); all {PLANNED_MAIN_VMCALLS} planned VMCALLs handled; NMIs: {} reinjected, {} handled by the guest{}.",
            state.nmis_injected,
            state.nmis_handled,
            // An NMI deferred but never injected before the last VMCALL.
            if state.nmi_pending {
                ", 1 still pending (dropped)"
            } else {
                ""
            },
        ),
        ExitEvent::Emulated(_) => report_emulation(number, resumed.and_then(|resumed| resumed.emulated), rip),
        ExitEvent::GuestGeneralProtection => crate::serial_println!(
            "{tag} VM exit #{number}: MSR {:#x} is outside the MSR bitmap, or the WRMSR value is not canonical; injecting #GP(0) at rip={rip:#018x}.",
            exit.map_or(0, |exit| exit.guest_rcx as u32),
        ),
        // Not "resuming the guest": `run-hyperv.ps1 -InjectNmi` waits for
        // that text after main VMCALL #1, and this exit comes before it.
        ExitEvent::Halted => crate::serial_println!("{tag} VM exit #{number}: HLT; going on at rip={rip:#018x}."),
        ExitEvent::GuestInvalidOpcode => crate::serial_println!(
            "{tag} VM exit #{number}: MWAIT or MONITOR, which the guest's CPUID does not offer; injecting #UD at rip={rip:#018x}."
        ),
        ExitEvent::EmulationMissing => crate::serial_println!(
            "{tag} VM exit #{number}: last main VMCALL (rax={rax:#x}), but the emulated exits were {} instead of {EXPECTED_EMULATION}.",
            state.emulated,
        ),
        ExitEvent::InterruptedDelivery => crate::serial_println!(
            "{tag} VM exit #{number}: the exit interrupted an event's delivery through the guest IDT; Aleph0 does not re-deliver it."
        ),
        ExitEvent::Unexpected => crate::serial_println!(
            "{tag} VM exit #{number}: NOT an expected exit (the next main VMCALL should have rax={:#x}).",
            expected_main_rax(state),
        ),
    }
    if event == ExitEvent::LastMainVmcall {
        crate::serial_println!(
            "{tag} VM exit #{number}: EPT: {} write violation(s) on the protected data page, write granted.",
            state.ept_writes_granted,
        );
        crate::serial_println!("{tag} VM exit #{number}: emulated exits: {}.", state.emulated);
    }
}

/// Prints what an emulated instruction did and where the guest resumes.
fn report_emulation(number: u64, outcome: Option<EmulationOutcome>, rip: u64) {
    let tag = crate::TAG;
    match outcome {
        Some(EmulationOutcome::Cpuid {
            leaf,
            subleaf,
            raw,
            guest,
        }) => crate::serial_println!(
            "{tag} VM exit #{number}: CPUID leaf={leaf:#x} subleaf={subleaf:#x} -> eax={:#010x} ebx={:#010x} ecx={:#010x} edx={:#010x} (processor ecx={:#010x}); resuming at rip={rip:#018x}.",
            guest.eax,
            guest.ebx,
            guest.ecx,
            guest.edx,
            raw.ecx,
        ),
        Some(EmulationOutcome::Rdmsr { msr, value }) => crate::serial_println!(
            "{tag} VM exit #{number}: RDMSR {msr:#x} -> {value:#018x}; resuming at rip={rip:#018x}."
        ),
        Some(EmulationOutcome::Wrmsr { msr, value }) => crate::serial_println!(
            "{tag} VM exit #{number}: WRMSR {msr:#x} <- {value:#018x}; resuming at rip={rip:#018x}."
        ),
        Some(EmulationOutcome::In { port, size, value }) => crate::serial_println!(
            "{tag} VM exit #{number}: IN port {port:#x} size={} -> {value:#x}; resuming at rip={rip:#018x}.",
            size.bytes(),
        ),
        Some(EmulationOutcome::Out { port, size, value }) => crate::serial_println!(
            "{tag} VM exit #{number}: OUT port {port:#x} size={} value={value:#x}; resuming at rip={rip:#018x}.",
            size.bytes(),
        ),
        None => crate::serial_println!("{tag} VM exit #{number}: emulated instruction not executed."),
    }
}

/// Prints the vector of an exception exit, from its VM_EXIT_INTERRUPTION_INFO
/// `info`. Exit qualification, printed by the caller, holds the faulting
/// address for a page fault (#PF, vector 14). NMI exits share reason 0 but
/// are not exceptions; the event line printed later reports them.
fn report_exception(number: u64, info: InterruptionInfo) {
    let tag = crate::TAG;
    if info.is_nmi() {
        return;
    }
    let raw = info.0;
    match info.vector() {
        Some(vector) => crate::serial_println!(
            "{tag} VM exit #{number}: guest exception vector={vector} (interruption info={raw:#010x})"
        ),
        None => crate::serial_println!("{tag} VM exit #{number}: interruption info not valid ({raw:#010x})"),
    }
}
