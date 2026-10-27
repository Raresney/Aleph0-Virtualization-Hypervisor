//! The VM-exit handler's report lines: what an exit was and what Aleph0 did
//! about it. Kept apart from `handler.rs`, so that file reads as the steps.
//!
//! Like the handler, everything here runs in exit context: only VMREAD and
//! the serial port, never firmware.

use super::guest_mtrrs::{self, MtrrWrite};
use super::handler::{EmulationOutcome, ExitRead, Outcome, Resumed};
use super::policy::{COUNTERS, Detail, Histogram};
use super::stats::Tally;
use super::{RegisterFrame, dump, history, read_field, stats};
use crate::vmx::ept::{Eptp, InveptType, Retyped};
use crate::vmx::exit_decision::{
    EXIT_REASON_EPT_MISCONFIG, EXIT_REASON_EXCEPTION_OR_NMI, EXIT_REASON_RDMSR, EXIT_REASON_VMCALL, EXIT_REASON_WRMSR,
    EptQualification, ExitEvent, ExitInfo, ExitState, InterruptionInfo, PLANNED_MAIN_VMCALLS, exit_reason_name,
    expected_main_rax, wrmsr_value,
};
use crate::vmx::guest::{GUEST_DATA_SEED, GUEST_EPT_VALUE};
use crate::vmx::hyperv;
use crate::vmx::mtrr::{self, FIXED_END, MtrrMsr, Mtrrs};
use crate::vmx::page::PAGE_SIZE;
use crate::vmx::vmcs::fields::{EPT_POINTER, GUEST_LINEAR_ADDRESS};
use crate::vmx::vmcs::{GuestKind, VmcsError};

/// One exit, as its report needs it.
pub(super) struct ExitReport<'a> {
    /// The guest it came from.
    pub(super) guest: GuestKind,
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
        guest,
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
            report_forwarded(number, basic);
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
        Outcome::Resumed { resumed, .. } => report_event(guest, number, event, read.exit, next, Some(resumed)),
        Outcome::ResumeFailed(failure) => {
            crate::serial_println!("{tag} VM exit #{number}: {failure}; not resuming.")
        }
        Outcome::Stopped(_) => report_event(guest, number, event, read.exit, next, None),
    }
    if outcome.stops() {
        crate::serial_println!("{tag} VM exit #{number}: stopping the guest; {}.", after_stop(guest));
    }
}

/// Where a stop of `guest` goes, for its report line.
pub(super) fn after_stop(guest: GuestKind) -> &'static str {
    if guest.stop_returns_to_bring_up() {
        "returning to bring-up"
    } else {
        "halting: the firmware has nothing to return to"
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
    if let Some(rights) = read.ss_access_rights {
        report_unreadable(number, "GUEST_SS_ACCESS_RIGHTS", rights);
    }
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

/// Prints the walk of `gpa` through the EPT tables EPT_POINTER names: each
/// entry on its path, what the CPU refuses in it, and how the walk ended
/// (`ept::walk`), as KVM prints the hierarchy of an EPT entry with reserved
/// bits set. The walk reads only Aleph0's own table pages.
fn report_ept_walk(number: u64, gpa: u64) {
    let tag = crate::TAG;
    let eptp = match read_field(EPT_POINTER) {
        Ok(raw) => Eptp::from_raw(raw),
        Err(error) => {
            crate::serial_println!("{tag} VM exit #{number}: EPT_POINTER unreadable ({error:?}); no EPT walk.");
            return;
        }
    };
    let Some(walk) = guest_mtrrs::inspect(|_, tables| tables.walk(eptp, gpa)) else {
        crate::serial_println!("{tag} VM exit #{number}: the EPT tables are not available; no EPT walk.");
        return;
    };
    crate::serial_println!(
        "{tag} VM exit #{number}: EPT walk of GPA {gpa:#018x} from EPTP {:#x}:",
        eptp.raw()
    );
    for entry in walk.entries() {
        crate::serial_println!(
            "{tag} VM exit #{number}:   {} entry {:#x} at {:#x} = {:#018x}: {}",
            entry.level.name(),
            entry.index,
            entry.address,
            entry.raw,
            entry.faults,
        );
    }
    crate::serial_println!("{tag} VM exit #{number}:   {}.", walk.end);
}

/// Prints that an NMI arrived while Aleph0 ran in root operation, and is
/// now pending for the guest. Not "resuming the guest": that text arms
/// `run-hyperv.ps1 -InjectNmi`.
fn report_host_nmi(number: u64) {
    crate::serial_println!(
        "{} VM exit #{number}: an NMI arrived while Aleph0 ran in root operation ({} so far); pending for the guest.",
        crate::TAG,
        crate::vmx::host::nmis_taken(),
    );
}

/// Prints, after the summary line of exit `number`, what Aleph0 forwarded
/// to Hyper-V so far at exits of its reason `basic`: hypercalls by call code
/// for VMCALL, synthetic MSRs for RDMSR and WRMSR. Nothing when none was,
/// or for another reason.
fn report_forwarded(number: u64, basic: u16) {
    let forwarded = stats::forwarded();
    let (what, tally) = match basic {
        EXIT_REASON_VMCALL => ("hypercalls by call code", forwarded.hypercalls),
        EXIT_REASON_RDMSR => ("synthetic MSR reads", forwarded.synthetic_reads),
        EXIT_REASON_WRMSR => ("synthetic MSR writes", forwarded.synthetic_writes),
        _ => return,
    };
    if tally != Tally::EMPTY {
        crate::serial_println!(
            "{} VM exit #{number}: forwarded to Hyper-V so far: {what}: {tally}.",
            crate::TAG
        );
    }
}

/// Prints what every stop adds after the lines of exit `number`: the
/// guest's state and registers (`frame`), the vCPU's exit statistics with
/// what was forwarded to Hyper-V, how many exits of each reason there were
/// (`exits_by_reason`), including those the print policy left out, and the
/// last exits, oldest first.
pub(super) fn report_stop(number: u64, frame: &RegisterFrame, exits_by_reason: &[u64; COUNTERS]) {
    dump::report_guest(number, frame);
    let tag = crate::TAG;
    crate::serial_println!("{tag} VM exit #{number}: exit statistics: {}.", stats::snapshot());
    let forwarded = stats::forwarded();
    crate::serial_println!(
        "{tag} VM exit #{number}: forwarded to Hyper-V: hypercalls by call code: {}; synthetic MSR reads: {}; synthetic MSR writes: {}.",
        forwarded.hypercalls,
        forwarded.synthetic_reads,
        forwarded.synthetic_writes,
    );
    crate::serial_println!(
        "{} VM exit #{number}: exits by reason: {}.",
        crate::TAG,
        Histogram(exits_by_reason)
    );
    history::report(format_args!("VM exit #{number}"));
}

/// Prints what exit `number` of `guest` turned out to be and what Aleph0
/// does about it. `state` is the state after the exit; `resumed` is how the
/// guest goes on, for events that resume it.
fn report_event(
    guest: GuestKind,
    number: u64,
    event: ExitEvent,
    exit: Option<ExitInfo>,
    state: ExitState,
    resumed: Option<Resumed>,
) {
    let tag = crate::TAG;
    let rax = exit.map_or(0, |exit| exit.guest_rax);
    let rcx = exit.map_or(0, |exit| exit.guest_rcx);
    let rip = resumed.map_or(0, |resumed| resumed.rip);
    let nmis_injected = stats::snapshot().nmi_injections;
    match event {
        ExitEvent::EptWriteGranted => {
            // Name the page the grant was for: the guest's data page, or the
            // reinjected NMI's stack page, told apart by the faulting GPA.
            let (page, gpa) = exit.map_or(("protected data page", 0), |exit| {
                let gpa = exit.guest_physical;
                if exit.stack_page != 0 && gpa & !(PAGE_SIZE as u64 - 1) == exit.stack_page {
                    ("NMI stack page", gpa)
                } else {
                    ("protected data page", gpa)
                }
            });
            crate::serial_println!(
                "{tag} VM exit #{number}: write to the {page} at GPA {gpa:#018x}: write granted (W=1), INVEPT {}; retrying the write at rip={rip:#018x}.",
                resumed
                    .and_then(|resumed| resumed.invept)
                    .map_or("not run", InveptType::name),
            )
        }
        ExitEvent::DataPageMismatch => crate::serial_println!(
            "{tag} VM exit #{number}: the data page read back rcx={:#x} rdx={:#x}, expected {GUEST_DATA_SEED:#x} and {GUEST_EPT_VALUE:#x}.",
            exit.map_or(0, |exit| exit.guest_rcx),
            exit.map_or(0, |exit| exit.guest_rdx),
        ),
        ExitEvent::EptWriteMissing => crate::serial_println!(
            "{tag} VM exit #{number}: main VMCALL (rax={rax:#x}) before any EPT violation: the guest's write to its data page was not caught, so EPT did not protect it."
        ),
        ExitEvent::EptViolation => {
            crate::serial_println!(
                "{tag} VM exit #{number}: an EPT violation Aleph0 does not handle: only the guest's first write to its protected data page is one; the map is wrong for this GPA."
            );
            report_ept_walk(number, exit.map_or(0, |exit| exit.guest_physical));
        }
        // The read's line already says an entry is invalid; the walk says
        // which.
        ExitEvent::EptMisconfig => report_ept_walk(number, exit.map_or(0, |exit| exit.guest_physical)),
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
        ExitEvent::LastMainVmcall if nmis_injected == 0 && state.nmis_handled == 0 && !state.nmi_pending => {
            crate::serial_println!(
                "{tag} VM exit #{number}: expected VMCALL (rax={rax:#x}); all {PLANNED_MAIN_VMCALLS} planned VMCALLs handled; no NMI arrived."
            )
        }
        ExitEvent::LastMainVmcall => crate::serial_println!(
            "{tag} VM exit #{number}: expected VMCALL (rax={rax:#x}); all {PLANNED_MAIN_VMCALLS} planned VMCALLs handled; NMIs: {nmis_injected} reinjected, {} handled by the guest{}.",
            state.nmis_handled,
            // An NMI deferred but never injected before the last VMCALL.
            if state.nmi_pending {
                ", 1 still pending (dropped)"
            } else {
                ""
            },
        ),
        ExitEvent::Emulated(_) => report_emulation(number, resumed.and_then(|resumed| resumed.emulated), rip),
        ExitEvent::GuestGeneralProtection => report_general_protection(number, exit, rip),
        // Not "resuming the guest": `run-hyperv.ps1 -InjectNmi` waits for
        // that text after main VMCALL #1, and this exit comes before it.
        ExitEvent::Halted => crate::serial_println!("{tag} VM exit #{number}: HLT; going on at rip={rip:#018x}."),
        ExitEvent::GuestInvalidOpcode => report_invalid_opcode(number, exit, rip),
        ExitEvent::BootServicesEnded => crate::serial_println!(
            "{tag} VM exit #{number}: VMCALL from Aleph0's ExitBootServices event (rcx={rcx:#x}): boot services are over; output phase now runtime (serial only); going on at rip={rip:#018x}."
        ),
        ExitEvent::TestVmcall => {
            crate::serial_println!("{tag} VM exit #{number}: test VMCALL (rcx={rcx:#x}); going on at rip={rip:#018x}.")
        }
        ExitEvent::Unexpected if guest == GuestKind::BuiltInTest => crate::serial_println!(
            "{tag} VM exit #{number}: NOT an expected exit (the next main VMCALL should have rax={:#x}).",
            expected_main_rax(state),
        ),
        // The firmware has no script: the lines above name the exit.
        ExitEvent::Unexpected => {
            crate::serial_println!("{tag} VM exit #{number}: NOT an exit Aleph0 handles for the firmware.")
        }
    }
    if event == ExitEvent::LastMainVmcall {
        crate::serial_println!(
            "{tag} VM exit #{number}: EPT: {} write violation(s) on the protected data page and {} on the NMI stack page, write granted.",
            state.ept_writes_granted,
            state.nmi_stack_grants,
        );
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
        Some(EmulationOutcome::MtrrRead { msr, value }) => crate::serial_println!(
            "{tag} VM exit #{number}: RDMSR {:#x} ({msr}) -> {value:#018x}, from the guest's MTRRs; resuming at rip={rip:#018x}.",
            msr.address(),
        ),
        Some(EmulationOutcome::MtrrWrite {
            msr,
            value,
            cpu_value,
            write,
        }) => report_mtrr_write(number, msr, value, cpu_value, write, rip),
        Some(EmulationOutcome::In { port, size, value }) => crate::serial_println!(
            "{tag} VM exit #{number}: IN port {port:#x} size={} -> {value:#x}; resuming at rip={rip:#018x}.",
            size.bytes(),
        ),
        Some(EmulationOutcome::Out { port, size, value }) => crate::serial_println!(
            "{tag} VM exit #{number}: OUT port {port:#x} size={} value={value:#x}; resuming at rip={rip:#018x}.",
            size.bytes(),
        ),
        Some(EmulationOutcome::Hypercall { input, result }) => crate::serial_println!(
            "{tag} VM exit #{number}: hypercall {:#06x} (rcx={input:#x}) forwarded to Hyper-V -> status {:#x} (rax={result:#x}); resuming at rip={rip:#018x}.",
            hyperv::call_code(input),
            result as u16,
        ),
        Some(EmulationOutcome::SyntheticRead { msr, value }) => crate::serial_println!(
            "{tag} VM exit #{number}: RDMSR {msr:#x} (synthetic) forwarded to Hyper-V -> {value:#018x}; resuming at rip={rip:#018x}."
        ),
        Some(EmulationOutcome::SyntheticWrite { msr, value }) => crate::serial_println!(
            "{tag} VM exit #{number}: WRMSR {msr:#x} (synthetic) <- {value:#018x} forwarded to Hyper-V; resuming at rip={rip:#018x}."
        ),
        Some(EmulationOutcome::Refused { emulation, exception }) => crate::serial_println!(
            "{tag} VM exit #{number}: Hyper-V refused the forwarded {emulation:?} with {}; injecting it at rip={rip:#018x}.",
            exception_mnemonic(exception),
        ),
        None => crate::serial_println!("{tag} VM exit #{number}: emulated instruction not executed."),
    }
}

/// `#UD` or `#GP(0)`, the exceptions a forwarded access is refused with.
fn exception_mnemonic(exception: InterruptionInfo) -> &'static str {
    if exception == InterruptionInfo::INVALID_OPCODE {
        "#UD"
    } else {
        "#GP(0)"
    }
}

/// Prints why the guest gets #UD: for a VMCALL, that it came from CPL > 0
/// or that there is no Hyper-V to take it; otherwise, that it is MWAIT or
/// MONITOR.
fn report_invalid_opcode(number: u64, exit: Option<ExitInfo>, rip: u64) {
    let tag = crate::TAG;
    match exit.filter(|exit| exit.reason.basic == EXIT_REASON_VMCALL) {
        Some(exit) if exit.guest_cpl != 0 => crate::serial_println!(
            "{tag} VM exit #{number}: VMCALL (rcx={:#x}) from CPL {}, which Hyper-V refuses too; injecting #UD at rip={rip:#018x}.",
            exit.guest_rcx,
            exit.guest_cpl,
        ),
        Some(exit) => crate::serial_println!(
            "{tag} VM exit #{number}: VMCALL (rcx={:#x}) is not Aleph0's, and there is no Hyper-V interface to forward it to; injecting #UD at rip={rip:#018x}.",
            exit.guest_rcx,
        ),
        None => crate::serial_println!(
            "{tag} VM exit #{number}: MWAIT or MONITOR, which the guest's CPUID does not offer; injecting #UD at rip={rip:#018x}."
        ),
    }
}

/// Prints why the guest gets a #GP at its RDMSR or WRMSR: for a WRMSR of
/// one of its MTRRs, what the CPU refuses in the value; for an MTRR address
/// the CPU has no MSR at, that; otherwise, that the MSR is outside the MSR
/// bitmap or the value is not canonical.
fn report_general_protection(number: u64, exit: Option<ExitInfo>, rip: u64) {
    let tag = crate::TAG;
    let msr = exit.map_or(0, |exit| exit.guest_rcx as u32);
    let refused_mtrr = exit
        .filter(|exit| exit.reason.basic == EXIT_REASON_WRMSR)
        .and_then(|exit| {
            let mtrr = exit.mtrr.msr(msr)?;
            let value = wrmsr_value(&exit);
            exit.mtrr.check(mtrr, value).err().map(|error| (mtrr, value, error))
        });
    let absent_mtrr = exit.is_some_and(|exit| mtrr::is_msr_address(msr) && exit.mtrr.msr(msr).is_none());
    match refused_mtrr {
        Some((mtrr, value, error)) => crate::serial_println!(
            "{tag} VM exit #{number}: WRMSR {msr:#x} ({mtrr}) <- {value:#018x} refused: {error}; the guest's MTRRs unchanged; injecting #GP(0) at rip={rip:#018x}."
        ),
        None if absent_mtrr => crate::serial_println!(
            "{tag} VM exit #{number}: MSR {msr:#x} is an MTRR address this CPU has no MSR at (see IA32_MTRRCAP); injecting #GP(0) at rip={rip:#018x}."
        ),
        None => crate::serial_println!(
            "{tag} VM exit #{number}: MSR {msr:#x} is outside the MSR bitmap, or the WRMSR value is not canonical; injecting #GP(0) at rip={rip:#018x}."
        ),
    }
}

/// Prints a WRMSR of the guest's MTRRs: the write, beside the CPU's own
/// MSR, which keeps its value; then, if the types changed, the guest's
/// MTRRs as they now stand and the EPT regions that changed, read back from
/// the PD entries.
fn report_mtrr_write(number: u64, msr: MtrrMsr, value: u64, cpu_value: u64, write: MtrrWrite, rip: u64) {
    let tag = crate::TAG;
    crate::serial_println!(
        "{tag} VM exit #{number}: WRMSR {:#x} ({msr}) <- {value:#018x}, into the guest's MTRRs; the CPU's {msr} stays {cpu_value:#018x}.",
        msr.address(),
    );
    match write.retyped {
        None => crate::serial_println!(
            "{tag} VM exit #{number}: every address keeps its memory type; EPT unchanged; resuming at rip={rip:#018x}."
        ),
        Some(retyped) => {
            guest_mtrrs::inspect(|mtrrs, types| {
                report_guest_mtrrs(number, mtrrs, msr.is_fixed());
                report_retyped(number, &retyped, write.invept, types.free_pts());
                if let Some((start, end)) = retyped.span {
                    for run in types.region_runs(start, end) {
                        crate::serial_println!(
                            "{tag} VM exit #{number}: EPT {:#014x}..{:#014x}: {}",
                            run.start,
                            run.end,
                            run.mapping
                        );
                    }
                }
            });
            crate::serial_println!("{tag} VM exit #{number}: resuming at rip={rip:#018x}.");
        }
    }
}

/// Prints the guest's MTRRs as bring-up prints the CPU's: whether they are
/// on, the variable ranges in use, and, after a write to a fixed-range MSR
/// (`fixed_written`), the types of the first MiB.
fn report_guest_mtrrs(number: u64, mtrrs: &Mtrrs, fixed_written: bool) {
    let tag = crate::TAG;
    crate::serial_println!("{tag} VM exit #{number}: guest MTRRs: {mtrrs}.");
    let Mtrrs::Enabled(enabled) = mtrrs else {
        return;
    };
    for range in enabled.variable_ranges() {
        crate::serial_println!("{tag} VM exit #{number}: guest MTRR {range}");
    }
    if fixed_written && enabled.fixed_enabled() {
        for run in mtrrs.runs(FIXED_END, PAGE_SIZE as u64) {
            crate::serial_println!(
                "{tag} VM exit #{number}: guest MTRR fixed {:#07x}..{:#07x}: {}",
                run.start,
                run.end,
                run.type_name(),
            );
        }
    }
}

/// Prints what changed in EPT after the guest's MTRRs did, and the spare
/// PTs `free_pts` left.
fn report_retyped(number: u64, retyped: &Retyped, invept: Option<InveptType>, free_pts: usize) {
    let tag = crate::TAG;
    match invept {
        Some(invept) => crate::serial_println!(
            "{tag} VM exit #{number}: EPT: {} region(s) retyped ({} split into a spare PT, {} merged back into one 2 MiB page); {free_pts} spare PT(s) left; INVEPT {}.",
            retyped.regions,
            retyped.split,
            retyped.merged,
            invept.name(),
        ),
        None => crate::serial_println!(
            "{tag} VM exit #{number}: EPT unchanged: the types changed only where nothing is mapped."
        ),
    }
    if retyped.uncached > 0 {
        crate::serial_println!(
            "{tag} VM exit #{number}: EPT: {} region(s) of mixed types mapped UC as one page: no spare PT left.",
            retyped.uncached,
        );
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
