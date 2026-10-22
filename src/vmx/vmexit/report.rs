//! The VM-exit handler's report lines: what an exit was and what Aleph0 did
//! about it. Kept apart from `handler.rs`, so that file reads as the steps.
//!
//! Like the handler, everything here runs in exit context: only VMREAD and
//! the serial port, never firmware.

use super::handler::{EmulationOutcome, Resumed};
use crate::vmx::ept::InveptType;
use crate::vmx::exit_decision::{
    EXIT_REASON_EPT_MISCONFIG, EptQualification, ExitEvent, ExitInfo, ExitState, InterruptionInfo,
    PLANNED_MAIN_VMCALLS, expected_main_rax,
};
use crate::vmx::guest::{EXPECTED_EMULATION, GUEST_DATA_SEED, GUEST_EPT_VALUE};
use crate::vmx::vmcs::fields::{GUEST_LINEAR_ADDRESS, GUEST_PHYSICAL_ADDRESS, VM_EXIT_INTERRUPTION_INFO};
use crate::vmx::vmcs::{self, VmcsError};

/// Reads one VMCS field for the diagnostic, printing instead of failing.
pub(super) fn read_or_report(name: &str, field: u32) -> Option<u64> {
    // SAFETY: exit context: VMX root operation, with the guest's VMCS
    // current.
    match unsafe { vmcs::vmread(field) } {
        Ok(value) => Some(value),
        Err(error) => {
            report_unreadable(name, error);
            None
        }
    }
}

fn report_unreadable(name: &str, error: VmcsError) {
    crate::serial_println!("{} VM exit: {name} unreadable ({error:?})", crate::TAG);
}

/// Prints an EPT exit's addresses and what the EPT entries allowed, and
/// returns GUEST_PHYSICAL_ADDRESS (`None` if unreadable, after printing why).
pub(super) fn report_ept_exit(number: u64, basic: u16, qualification: EptQualification) -> Option<u64> {
    let tag = crate::TAG;
    let guest_physical = read_or_report("GUEST_PHYSICAL_ADDRESS", GUEST_PHYSICAL_ADDRESS)?;
    if basic == EXIT_REASON_EPT_MISCONFIG {
        crate::serial_println!(
            "{tag} VM exit #{number}: EPT misconfiguration at GPA {guest_physical:#018x}: an EPT entry for it is invalid."
        );
        return Some(guest_physical);
    }

    let (r, w, x) = qualification.permissions();
    let access = qualification.access_name();
    // The linear address is only valid with qualification bit 7.
    match qualification
        .linear_valid()
        .then(|| read_or_report("GUEST_LINEAR_ADDRESS", GUEST_LINEAR_ADDRESS))
        .flatten()
    {
        Some(linear) => crate::serial_println!(
            "{tag} VM exit #{number}: EPT violation at GPA {guest_physical:#018x} (linear {linear:#018x}): {access}; page R={r} W={w} X={x}."
        ),
        None => crate::serial_println!(
            "{tag} VM exit #{number}: EPT violation at GPA {guest_physical:#018x} (no linear address): {access}; page R={r} W={w} X={x}."
        ),
    }
    Some(guest_physical)
}

/// Prints that an NMI arrived while Aleph0 ran in root operation, and is
/// now pending for the guest. Not "resuming the guest": that text arms
/// `run-hyperv.ps1 -InjectNmi`.
pub(super) fn report_host_nmi(number: u64) {
    crate::serial_println!(
        "{} VM exit #{number}: an NMI arrived while Aleph0 ran in root operation ({} so far); pending for the guest.",
        crate::TAG,
        crate::vmx::host::nmis_taken(),
    );
}

/// Prints what exit `number` turned out to be and what Aleph0 does about
/// it. `state` is the state after the exit; `resumed` is how the guest goes
/// on, for events that resume it.
pub(super) fn report_event(
    number: u64,
    event: ExitEvent,
    exit: Option<ExitInfo>,
    state: ExitState,
    resumed: Option<Resumed>,
) {
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

/// Prints the vector of an exception exit. Exit qualification, printed by
/// the caller, holds the faulting address for a page fault (#PF, vector 14).
/// NMI exits share reason 0 but are not exceptions; the event line printed
/// later reports them.
pub(super) fn report_exception(number: u64) {
    let tag = crate::TAG;
    if let Some(info) = read_or_report("VM_EXIT_INTERRUPTION_INFO", VM_EXIT_INTERRUPTION_INFO) {
        let interruption = InterruptionInfo(info as u32);
        if interruption.is_nmi() {
            return;
        }
        match interruption.vector() {
            Some(vector) => crate::serial_println!(
                "{tag} VM exit #{number}: guest exception vector={vector} (interruption info={info:#010x})"
            ),
            None => crate::serial_println!("{tag} VM exit #{number}: interruption info not valid ({info:#010x})"),
        }
    }
}
