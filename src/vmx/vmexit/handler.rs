//! The VM-exit handler the entry stub calls: read the exit, judge it, carry
//! it out, report it.
//!
//! [`vmexit_handler`] runs four steps:
//!
//! 1. [`read_exit`] reads the exit's VMCS fields and the guest registers.
//!    It prints nothing.
//! 2. [`judge`] folds in an NMI that arrived while Aleph0 ran (`vmx::host`)
//!    and passes the exit to `exit_decision::decide` with the state kept
//!    between exits.
//! 3. [`carry_out`] executes an emulated instruction and prepares the VMCS as
//!    the event's `ResumePlan` says, or stops the guest. It prints nothing
//!    either: a step that fails says why in its [`ResumeFailure`].
//! 4. `report.rs` prints the exit and its [`Outcome`], once everything about
//!    the exit is known, in as much detail as the print policy gives it
//!    (`policy.rs`): whole for a stop and for the first exits of each reason,
//!    rate-limited after that.

use core::arch::x86_64::{__cpuid_count, CpuidResult};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use core::fmt;

use super::guest_mtrrs::{self, MtrrAccessFailure, MtrrWrite};
use super::history::{self, ExitRecord};
use super::policy::{self, COUNTERS, MAX_LEVEL, exit_detail};
use super::report::{ExitReport, after_stop, report_exit, report_stop};
use super::stats::{self, VcpuStats};
use super::{RegisterFrame, read_field};
use crate::output::Phase;
use crate::port;
use crate::vmx::ept::{self, InveptType, ProtectedPage};
use crate::vmx::exit_decision::{
    EXIT_REASON_EPT_MISCONFIG, EXIT_REASON_EPT_VIOLATION, EXIT_REASON_IO_INSTRUCTION, EXIT_REASON_VMCALL, Emulation,
    ExitAction, ExitEvent, ExitInfo, ExitReason, ExitState, InterruptionInfo, IoSize, Redelivery, ResumePlan,
    UNREADABLE_REASON, after_nmi_redelivery, after_skipped_instruction, cpl_from_ss, cpuid_policy, decide,
    is_canonical_48, merge_in,
};
use crate::vmx::host;
use crate::vmx::hyperv::{self, HypercallRegisters};
use crate::vmx::instruction::VmxFail;
use crate::vmx::msr;
use crate::vmx::mtrr::MtrrMsr;
use crate::vmx::page;
use crate::vmx::vmcs::fields::{
    EXIT_QUALIFICATION, GUEST_INTERRUPTIBILITY_STATE, GUEST_PHYSICAL_ADDRESS, GUEST_RIP, GUEST_SS_ACCESS_RIGHTS,
    IDT_VECTORING_ERROR_CODE, IDT_VECTORING_INFO, VM_ENTRY_EXCEPTION_ERROR_CODE, VM_ENTRY_INSTRUCTION_LEN,
    VM_ENTRY_INTERRUPTION_INFO, VM_EXIT_INSTRUCTION_LEN, VM_EXIT_INTERRUPTION_INFO, VM_EXIT_REASON,
};
use crate::vmx::vmcs::{self, GuestKind, VmcsError, encode_finished, encode_resume_failed, encode_unexpected};

/// Exits so far per basic reason ([`policy::counter`]), including the
/// current one: for the print policy and the histogram every stop prints.
/// Only the exit handler touches them, with interrupts off, on the one CPU
/// that runs the guest; the atomics just avoid `static mut`.
static EXITS_BY_REASON: [AtomicU64; COUNTERS] = [const { AtomicU64::new(0) }; COUNTERS];

/// Counts an exit of basic reason `basic`, and returns how many there have
/// been, this one included.
fn count_exit(basic: u16) -> u64 {
    EXITS_BY_REASON[policy::counter(basic)].fetch_add(1, Ordering::Relaxed) + 1
}

/// The counts of [`EXITS_BY_REASON`] as they stand.
fn exits_by_reason() -> [u64; COUNTERS] {
    core::array::from_fn(|slot| EXITS_BY_REASON[slot].load(Ordering::Relaxed))
}

// The `ExitState` that `decide` carries from one exit to the next, one
// atomic per field, for the same reason as `EXITS_BY_REASON`.
static MAIN_VMCALLS: AtomicU32 = AtomicU32::new(0);
static NMI_PENDING: AtomicBool = AtomicBool::new(false);
static NMIS_HANDLED: AtomicU32 = AtomicU32::new(0);
static EPT_WRITES_GRANTED: AtomicU32 = AtomicU32::new(0);
static NMI_STACK_GRANTS: AtomicU32 = AtomicU32::new(0);

fn load_state() -> ExitState {
    ExitState {
        main_vmcalls: MAIN_VMCALLS.load(Ordering::Relaxed),
        nmi_pending: NMI_PENDING.load(Ordering::Relaxed),
        nmis_handled: NMIS_HANDLED.load(Ordering::Relaxed),
        ept_writes_granted: EPT_WRITES_GRANTED.load(Ordering::Relaxed),
        nmi_stack_grants: NMI_STACK_GRANTS.load(Ordering::Relaxed),
    }
}

fn store_state(state: ExitState) {
    MAIN_VMCALLS.store(state.main_vmcalls, Ordering::Relaxed);
    NMI_PENDING.store(state.nmi_pending, Ordering::Relaxed);
    NMIS_HANDLED.store(state.nmis_handled, Ordering::Relaxed);
    EPT_WRITES_GRANTED.store(state.ept_writes_granted, Ordering::Relaxed);
    NMI_STACK_GRANTS.store(state.nmi_stack_grants, Ordering::Relaxed);
}

/// Handler return value that tells the entry stub to resume the guest.
/// Every other value is a stop value (see `vmx/vmcs/launch.rs`).
const RESUME_GUEST: u64 = 0;

/// What the handler returns to the entry stub for `action` at exit
/// `number`: [`RESUME_GUEST`], or the stop value `vmcs::launch` returns.
fn stub_return(action: ExitAction, number: u64, raw_reason: u32) -> u64 {
    match action {
        ExitAction::Resume(_) => RESUME_GUEST,
        ExitAction::Finished => encode_finished(number),
        ExitAction::Unexpected => encode_unexpected(number, raw_reason),
    }
}

/// The guest RIP after an instruction of `length` bytes, or `None` when that would wrap past the top of the
/// address space or land outside the canonical range.
///
/// `rip` is the guest's: a guest kernel can map code in the last bytes of the address space, where the sum
/// overflows (a panic in debug builds, a silent wrap in release). An instruction ending at the last canonical
/// byte of the lower half does not overflow, but gives `0x0000_8000_0000_0000`, and VM entry would then fail its
/// guest-state checks on RIP. The caller stops the guest instead, in both cases.
fn next_rip(rip: u64, length: u64) -> Option<u64> {
    rip.checked_add(length).filter(|&next| is_canonical_48(next))
}

/// VM-exit handler: decides what the exit is (`exit_decision::decide`),
/// carries that out, prints the exit over serial, then tells the entry stub
/// what to do. It returns [`RESUME_GUEST`] after preparing the VMCS for the
/// guest to go on (the stub then executes VMRESUME), or, for the test guest,
/// a stop value (the stub then returns it from `vmcs::launch` to bring-up).
/// A stop of the firmware halts here ([`halt_unless_returnable`]).
///
/// Runs on the VM-exit stack with interrupts off. It may only use things
/// that need no firmware: VMREAD/VMWRITE (the VMCS is still current) and the
/// serial port. `uefi::println!` must not be called here; `log!` and the
/// panic handler skip the console once the phase below is set. For an
/// emulated instruction it also writes the result into the guest's registers
/// in `frame`.
#[unsafe(no_mangle)]
extern "efiapi" fn vmexit_handler(frame: *mut RegisterFrame) -> u64 {
    // First, so every line below (and any panic) skips the firmware console.
    // Put back when the guest resumes ([`resume_phase`]). After a stop that
    // returns, bring-up switches it back once it has left VMX operation.
    let phase = crate::output::set_phase(Phase::VmExit);
    #[cfg(feature = "host-fault-test")]
    host::fault_on_purpose();
    #[cfg(feature = "forward-refusal-test")]
    hyperv::refuse_on_purpose();

    let guest = GuestKind::SELECTED;
    let number = stats::update(VcpuStats::count_exit);
    // SAFETY: the entry stub passes a pointer to the frame it just pushed on
    // the exit stack. It stays put until this returns and nothing else
    // touches it meanwhile; the stub pops it into the guest's registers
    // afterwards, so writes here reach the guest.
    let frame = unsafe { &mut *frame };
    let read = read_exit(frame);
    let host_nmi = host::take_pending_nmi();
    let (event, next) = judge(guest, read.exit, host_nmi);
    let outcome = carry_out(event, &read, next, frame);
    if let Outcome::Resumed { plan, .. } = outcome {
        stats::update(|stats| stats.count_resumed(event, plan));
        stats::update_forwarded(|forwarded| forwarded.count(plan.emulate));
    }
    // Before anything prints, so a panic while printing still shows this exit.
    history::record(read.record(number, event));
    let basic = read.reason().map_or(UNREADABLE_REASON, |reason| reason.basic);
    let count = count_exit(basic);
    report_exit(&ExitReport {
        guest,
        number,
        count,
        detail: exit_detail(count, outcome.stops(), read.unreadable(), MAX_LEVEL),
        read: &read,
        host_nmi,
        event,
        next,
        outcome,
    });
    if outcome.stops() {
        report_stop(number, frame, &exits_by_reason());
        halt_unless_returnable(guest);
    } else {
        #[cfg(feature = "host-nmi-test")]
        if event == ExitEvent::MainVmcall {
            wait_for_host_nmi(number);
        }
        // Last, after every VMCS write of this exit.
        keep_nmi_window_for_host_nmi(number);
        crate::output::set_phase(resume_phase(event, phase));
    }
    stub_return(outcome.action(), number, read.raw_reason())
}

/// The output phase the guest resumes in after `event`: the one the exit
/// found (`found`), except after the `ExitBootServices` VMCALL, from which
/// on it is [`Phase::Runtime`] for good: the firmware console is gone.
fn resume_phase(event: ExitEvent, found: Phase) -> Phase {
    if event == ExitEvent::BootServicesEnded {
        Phase::Runtime
    } else {
        found
    }
}

/// Halts after a stop of a `guest` whose stop cannot return to bring-up
/// (`GuestKind::stop_returns_to_bring_up`): the firmware, launched in place,
/// has reused the stack `vmcs::launch_in_place` ran on, and no frame was
/// saved to jump back to. The stop's report is already on serial.
fn halt_unless_returnable(guest: GuestKind) {
    if !guest.stop_returns_to_bring_up() {
        crate::output::halt_forever();
    }
}

/// What [`read_exit`] read about one exit. Each VMCS field keeps its VMREAD
/// result, so the report can show an unreadable one where it belongs.
pub(super) struct ExitRead {
    /// VM_EXIT_REASON.
    pub(super) reason: Result<u64, VmcsError>,
    /// VM_EXIT_INTERRUPTION_INFO.
    pub(super) interruption_info: Result<u64, VmcsError>,
    /// EXIT_QUALIFICATION.
    pub(super) qualification: Result<u64, VmcsError>,
    /// GUEST_PHYSICAL_ADDRESS, read for EPT exits only (`None` for others).
    pub(super) guest_physical: Option<Result<u64, VmcsError>>,
    /// GUEST_SS_ACCESS_RIGHTS, the CPL, read for VMCALL exits only.
    pub(super) ss_access_rights: Option<Result<u64, VmcsError>>,
    /// GUEST_RIP.
    pub(super) rip: Result<u64, VmcsError>,
    /// VM_EXIT_INSTRUCTION_LEN.
    pub(super) length: Result<u64, VmcsError>,
    /// GUEST_INTERRUPTIBILITY_STATE.
    pub(super) interruptibility: Result<u64, VmcsError>,
    /// IDT_VECTORING_INFO.
    pub(super) idt_vectoring: Result<u64, VmcsError>,
    /// The guest's RAX, RBX, RCX and RDX as the stub saved them, before an
    /// emulated instruction changes them.
    ///
    /// The stub pushed them just below HOST_RSP; after a normal exit they are
    /// the guest's values. After a VM-entry failure (exit reason bit 31) the
    /// guest never ran, so they are whatever was live when entry was
    /// attempted: the host's registers for VMLAUNCH, or the restored guest
    /// registers (the previous exit's) for VMRESUME. Either way, not this
    /// exit's guest.
    pub(super) registers: [u64; 4],
    /// The page EPT protects, for granting write.
    protected: Option<ProtectedPage>,
    /// Everything `decide` needs, `None` if a field it needs was unreadable.
    pub(super) exit: Option<ExitInfo>,
}

impl ExitRead {
    /// The exit reason, if VM_EXIT_REASON was readable.
    pub(super) fn reason(&self) -> Option<ExitReason> {
        self.reason.ok().map(|raw| ExitReason::from_raw(raw as u32))
    }

    /// VM_EXIT_REASON for the stop value, or [`UNREADABLE_REASON`].
    fn raw_reason(&self) -> u32 {
        self.reason.map_or(u32::from(UNREADABLE_REASON), |raw| raw as u32)
    }

    /// This exit, number `number`, as the history keeps it, with what
    /// `decide` made of it (`event`).
    fn record(&self, number: u64, event: ExitEvent) -> ExitRecord {
        ExitRecord {
            number,
            reason: self.reason.ok().map(|raw| raw as u32),
            qualification: self.qualification.ok(),
            rip: self.rip.ok(),
            length: self.length.ok(),
            interruption_info: self.interruption_info.ok().map(|info| info as u32),
            idt_vectoring_info: self.idt_vectoring.ok().map(|info| info as u32),
            registers: self.registers,
            event,
        }
    }

    /// Whether a VMCS field the handler read could not be read.
    fn unreadable(&self) -> bool {
        [
            self.reason,
            self.interruption_info,
            self.qualification,
            self.guest_physical.unwrap_or(Ok(0)),
            self.ss_access_rights.unwrap_or(Ok(0)),
            self.rip,
            self.length,
            self.interruptibility,
            self.idt_vectoring,
        ]
        .iter()
        .any(Result::is_err)
    }
}

/// Reads the exit's VMCS fields and the guest registers, and collects what
/// [`judge`] and [`carry_out`] need. Prints nothing.
fn read_exit(frame: &RegisterFrame) -> ExitRead {
    let reason = read_field(VM_EXIT_REASON);
    let decoded = reason.ok().map(|raw| ExitReason::from_raw(raw as u32));
    let interruption_info = read_field(VM_EXIT_INTERRUPTION_INFO);
    let qualification = read_field(EXIT_QUALIFICATION);
    let ept_exit = decoded.is_some_and(|reason| {
        !reason.entry_failure && matches!(reason.basic, EXIT_REASON_EPT_VIOLATION | EXIT_REASON_EPT_MISCONFIG)
    });
    let guest_physical = ept_exit.then(|| read_field(GUEST_PHYSICAL_ADDRESS));
    // Only a VMCALL is judged by the CPL; 0 otherwise, which `decide` never
    // looks at, and an unreadable one leaves the VMCALL unjudged.
    let vmcall_exit = decoded.is_some_and(|reason| !reason.entry_failure && reason.basic == EXIT_REASON_VMCALL);
    let ss_access_rights = vmcall_exit.then(|| read_field(GUEST_SS_ACCESS_RIGHTS));
    let guest_cpl = ss_access_rights.map_or(Some(0), |rights| rights.ok().map(cpl_from_ss));
    let rip = read_field(GUEST_RIP);
    let length = read_field(VM_EXIT_INSTRUCTION_LEN);
    let interruptibility = read_field(GUEST_INTERRUPTIBILITY_STATE);
    let idt_vectoring = read_field(IDT_VECTORING_INFO);
    // The read-only page this exit's access fell in, if any: an EPT exit
    // whose GUEST_PHYSICAL_ADDRESS is one of the published protected pages
    // (the data page, or the NMI-delivery stack page). The grant path makes
    // exactly this page writable.
    let protected = guest_physical
        .and_then(|gpa| gpa.ok())
        .and_then(ept::protected_page_for);
    let mtrr = guest_mtrrs::capabilities();

    // Only EPT and I/O exits are judged by EXIT_QUALIFICATION. For any other
    // exit an unreadable one (reported later) does not matter.
    let judged_by_qualification =
        ept_exit || decoded.is_some_and(|reason| !reason.entry_failure && reason.basic == EXIT_REASON_IO_INSTRUCTION);
    let qualification_for_decide = if judged_by_qualification {
        qualification.ok()
    } else {
        Some(qualification.unwrap_or(0))
    };
    // Meaningful only when idt_vectoring is valid and carries an error code;
    // 0 otherwise, so an unreadable field never stops an exit that ignores it.
    let idt_vectoring_error_code = read_field(IDT_VECTORING_ERROR_CODE).unwrap_or(0) as u32;
    // Meaningful only for EPT exits; decide never looks at it otherwise.
    let guest_physical_for_decide = guest_physical.map_or(Some(0), Result::ok);
    let exit = match (
        decoded,
        interruption_info.ok(),
        interruptibility.ok(),
        idt_vectoring.ok(),
        qualification_for_decide,
        guest_physical_for_decide,
        guest_cpl,
    ) {
        (
            Some(reason),
            Some(info),
            Some(blocking),
            Some(vectoring),
            Some(qualification),
            Some(guest_physical),
            Some(guest_cpl),
        ) => {
            Some(ExitInfo {
                reason,
                interruption_info: InterruptionInfo(info as u32),
                guest_rax: frame.rax,
                guest_rcx: frame.rcx,
                guest_rdx: frame.rdx,
                interruptibility: blocking as u32,
                // IDT_VECTORING_INFO has the interruption-information layout.
                idt_vectoring: InterruptionInfo(vectoring as u32),
                idt_vectoring_error_code,
                qualification,
                guest_physical,
                protected_page: protected.map_or(0, |page| page.gpa),
                stack_page: ept::nmi_stack_page(),
                mtrr,
                hyperv: hyperv::offered(),
                guest_cpl,
            })
        }
        // An unreadable field is reported later; without it the exit cannot
        // be judged.
        _ => None,
    };

    ExitRead {
        reason,
        interruption_info,
        qualification,
        guest_physical,
        ss_access_rights,
        rip,
        length,
        interruptibility,
        idt_vectoring,
        registers: [frame.rax, frame.rbx, frame.rcx, frame.rdx],
        protected,
        exit,
    }
}

/// Decides what `exit` of `guest` is with the state kept between exits, and
/// keeps the state for the next one. An NMI that arrived in root operation
/// since the last exit (`host_nmi`) is pending for the guest first. An exit
/// that could not be read is unexpected.
fn judge(guest: GuestKind, exit: Option<ExitInfo>, host_nmi: bool) -> (ExitEvent, ExitState) {
    let state = load_state().with_host_nmi(host_nmi);
    let (event, next) = match exit {
        Some(exit) => decide(guest, state, exit),
        None => (ExitEvent::Unexpected, state),
    };
    store_state(next);
    (event, next)
}

/// What carrying out an exit's event came to.
#[derive(Debug, Clone, Copy)]
pub(super) enum Outcome {
    /// The guest goes on: the VMCS is prepared as `plan` says.
    Resumed { plan: ResumePlan, resumed: Resumed },
    /// The plan could not be carried out, so the guest stops.
    ResumeFailed(ResumeFailure),
    /// The event itself stops the guest (`Finished` or `Unexpected`).
    Stopped(ExitAction),
}

impl Outcome {
    /// What the entry stub does next.
    pub(super) fn action(self) -> ExitAction {
        match self {
            Self::Resumed { plan, .. } => ExitAction::Resume(plan),
            Self::ResumeFailed(_) => ExitAction::Unexpected,
            Self::Stopped(action) => action,
        }
    }

    /// Whether the guest stops at this exit.
    pub(super) fn stops(self) -> bool {
        !matches!(self, Self::Resumed { .. })
    }
}

/// Carries out `event`: prepares the guest to resume as its plan says, or
/// stops it. `next` is the state after the exit. Prints nothing.
fn carry_out(event: ExitEvent, read: &ExitRead, next: ExitState, frame: &mut RegisterFrame) -> Outcome {
    match event.action() {
        ExitAction::Resume(plan) => {
            let plan = plan.keeping_pending_nmi(next);
            // Re-deliver an event this exit interrupted mid-delivery. The plan
            // refuses when it would also advance RIP or inject its own event,
            // since only one event is injected per VM entry.
            let plan = match read
                .exit
                .and_then(|exit| exit.redelivery(read.length.ok().map(|length| length as u32)))
            {
                Some(redelivery) => plan.redelivering(redelivery),
                None => Some(plan),
            };
            match plan {
                Some(plan) => match prepare_resume(read, plan, frame) {
                    Ok((plan, resumed)) => Outcome::Resumed { plan, resumed },
                    Err(failure) => Outcome::ResumeFailed(failure),
                },
                None => Outcome::ResumeFailed(ResumeFailure::RedeliveryConflict),
            }
        }
        stop => Outcome::Stopped(stop),
    }
}

/// Turns NMI-window exiting on if an NMI arrived in root operation after
/// [`judge`] looked. The host NMI handler turns it on itself, but a write
/// of the primary controls in [`prepare_resume`] may have replaced its
/// write; nothing writes them after this, so the guest exits to take the
/// NMI as soon as it can.
fn keep_nmi_window_for_host_nmi(number: u64) {
    if !host::nmi_pending() {
        return;
    }
    crate::serial_println!(
        "{} VM exit #{number}: an NMI arrived in root operation during this exit; NMI-window exiting on.",
        crate::TAG
    );
    // SAFETY: exit context: VMX root operation, with the guest's VMCS
    // current. `configure_controls` checked that the CPU allows NMI-window
    // exiting.
    if let Err(error) = unsafe { vmcs::set_nmi_window_exiting(true) } {
        crate::serial_println!(
            "{} VM exit #{number}: could not turn NMI-window exiting on ({error:?}); the NMI waits for the next exit.",
            crate::TAG
        );
    }
}

/// Waits in root operation, after main VMCALL #1, until an NMI arrives or
/// the guest's own wait would have given up. `run-hyperv.ps1 -InjectNmi`
/// sends its NMI once serial shows the resume line printed just before, so
/// the NMI reaches the host NMI handler instead of the guest.
#[cfg(feature = "host-nmi-test")]
fn wait_for_host_nmi(number: u64) {
    let tag = crate::TAG;
    crate::serial_println!("{tag} VM exit #{number}: host-nmi-test: waiting in VMX root operation for an NMI.");
    let mut rounds = crate::vmx::guest::GUEST_WAIT_ITERATIONS;
    while !host::nmi_pending() && rounds > 0 {
        core::hint::spin_loop();
        rounds -= 1;
    }
    if host::nmi_pending() {
        crate::serial_println!(
            "{tag} VM exit #{number}: host-nmi-test: the host NMI handler ran ({} NMI(s) in root operation so far).",
            host::nmis_taken()
        );
    } else {
        crate::serial_println!("{tag} VM exit #{number}: host-nmi-test: no NMI arrived; going on.");
    }
}

/// What an emulated instruction did, for the report.
#[derive(Debug, Clone, Copy)]
pub(super) enum EmulationOutcome {
    /// CPUID `leaf`/`subleaf`: what the processor returned (`raw`) and what
    /// the guest got after `cpuid_policy` (`guest`).
    Cpuid {
        leaf: u32,
        subleaf: u32,
        raw: CpuidResult,
        guest: CpuidResult,
    },
    /// RDMSR of `msr` returned `value`.
    Rdmsr { msr: u32, value: u64 },
    /// WRMSR wrote `value` to `msr`.
    Wrmsr { msr: u32, value: u64 },
    /// RDMSR of the guest's MTRR `msr` returned `value`, from its copy.
    MtrrRead { msr: MtrrMsr, value: u64 },
    /// WRMSR wrote `value` to the guest's MTRR `msr`, in its copy, with
    /// what EPT made of it (`write`). The CPU's own MSR holds `cpu_value`,
    /// read after the write, which it leaves alone.
    MtrrWrite {
        msr: MtrrMsr,
        value: u64,
        cpu_value: u64,
        write: MtrrWrite,
    },
    /// IN of `size` from `port` read `value`.
    In { port: u16, size: IoSize, value: u32 },
    /// OUT of `value` (`size` wide) to `port`.
    Out { port: u16, size: IoSize, value: u32 },
    /// The hypercall with input value `input` went to Hyper-V, which
    /// returned `result` in RAX: the status in bits 15:0, the reps done in
    /// bits 43:32.
    Hypercall { input: u64, result: u64 },
    /// RDMSR of the synthetic MSR `msr` returned `value`, from Hyper-V.
    SyntheticRead { msr: u32, value: u64 },
    /// WRMSR wrote `value` to the synthetic MSR `msr`, at Hyper-V.
    SyntheticWrite { msr: u32, value: u64 },
    /// Hyper-V refused the forwarded `emulation` with `exception`, which the
    /// guest gets at its own instruction instead.
    Refused {
        emulation: Emulation,
        exception: InterruptionInfo,
    },
}

impl EmulationOutcome {
    /// The exception the guest gets when Hyper-V refused the access.
    fn refused(self) -> Option<InterruptionInfo> {
        match self {
            Self::Refused { exception, .. } => Some(exception),
            _ => None,
        }
    }
}

/// Whether the hypercall with input value `input` names a page of Aleph0's
/// own memory as its input or output ([`hyperv::hypercall_gpas`]), which
/// Hyper-V would read or write past EPT, so the forwarder must refuse it.
fn hypercall_names_aleph0(input: u64, frame: &RegisterFrame) -> bool {
    hyperv::hypercall_gpas(input, frame.rdx, frame.r8)
        .into_iter()
        .flatten()
        .any(page::is_resident)
}

/// Executes `emulation` in root operation and writes its result into the
/// guest's registers in `frame`. Only an access to the guest's MTRRs can
/// fail; one Hyper-V refuses comes back as [`EmulationOutcome::Refused`],
/// with `frame` unchanged.
fn execute(emulation: Emulation, frame: &mut RegisterFrame) -> Result<EmulationOutcome, ResumeFailure> {
    Ok(match emulation {
        Emulation::Cpuid { leaf, subleaf } => {
            // In root operation CPUID returns the processor's values (under
            // Hyper-V: what Hyper-V shows Aleph0).
            let raw = __cpuid_count(leaf, subleaf);
            let guest = cpuid_policy(leaf, raw);
            // CPUID writes 32-bit registers, which zero-extends them.
            frame.rax = guest.eax.into();
            frame.rbx = guest.ebx.into();
            frame.rcx = guest.ecx.into();
            frame.rdx = guest.edx.into();
            EmulationOutcome::Cpuid {
                leaf,
                subleaf,
                raw,
                guest,
            }
        }
        Emulation::Rdmsr { msr } => {
            // SAFETY: `decide` emulates only INTERCEPTED_MSRS, which exist on
            // every CPU Aleph0 runs on (IA32_KERNEL_GS_BASE: every 64-bit
            // CPU) and have no read side effects.
            let value = unsafe { msr::rdmsr(msr) };
            // RDMSR writes EAX and EDX, which zero-extends them.
            frame.rax = value & 0xFFFF_FFFF;
            frame.rdx = value >> 32;
            EmulationOutcome::Rdmsr { msr, value }
        }
        Emulation::Wrmsr { msr, value } => {
            // SAFETY: an intercepted MSR (see Rdmsr), and `decide` checked
            // the value is canonical, so WRMSR cannot fault. VM entry and
            // exit do not switch IA32_KERNEL_GS_BASE and Aleph0 never runs
            // SWAPGS, so the guest's value is simply the CPU's.
            unsafe { msr::wrmsr(msr, value) };
            EmulationOutcome::Wrmsr { msr, value }
        }
        Emulation::MtrrRead { msr } => {
            let value = guest_mtrrs::read(msr).map_err(ResumeFailure::GuestMtrrs)?;
            // RDMSR writes EAX and EDX, which zero-extends them.
            frame.rax = value & 0xFFFF_FFFF;
            frame.rdx = value >> 32;
            EmulationOutcome::MtrrRead { msr, value }
        }
        Emulation::MtrrWrite { msr, value } => {
            // SAFETY: exit context: VMX root operation, the guest stopped at
            // this exit.
            let write = unsafe { guest_mtrrs::write(msr, value) }.map_err(ResumeFailure::GuestMtrrs)?;
            // SAFETY: `decide` routes only the MTRR MSRs the CPU has to the
            // copy, and reading one has no side effects. Read for the report,
            // which shows the CPU's untouched.
            let cpu_value = unsafe { msr::rdmsr(msr.address()) };
            EmulationOutcome::MtrrWrite {
                msr,
                value,
                cpu_value,
                write,
            }
        }
        Emulation::In { port, size } => {
            // SAFETY: the guest asked for exactly this access, which it could
            // have made without Aleph0, and IN/OUT at CPL 0 in root operation
            // cannot fault. A 2- or 4-byte access at 0x3FC-0x3FE also touches
            // 0x3FF, so it exits and passes through to COM1's registers at
            // 0x3FC-0x3FE, the guest's own UART (docs/EMULATED_EXITS.md
            // section 5).
            let value = unsafe {
                match size {
                    IoSize::Byte => u32::from(port::inb(port)),
                    IoSize::Word => u32::from(port::inw(port)),
                    IoSize::Dword => port::inl(port),
                }
            };
            frame.rax = merge_in(frame.rax, size, value);
            EmulationOutcome::In { port, size, value }
        }
        Emulation::Out { port, size, value } => {
            // SAFETY: as for In: the guest's own OUT.
            unsafe {
                match size {
                    IoSize::Byte => port::outb(port, value as u8),
                    IoSize::Word => port::outw(port, value as u16),
                    IoSize::Dword => port::outl(port, value),
                }
            }
            EmulationOutcome::Out { port, size, value }
        }
        Emulation::Hypercall { input } if hypercall_names_aleph0(input, frame) => {
            // The hypercall names an Aleph0 page as its input or output: Hyper-V
            // would read or write Aleph0's own memory past EPT (HYPERV_INTERFACE.md
            // section 8). Refuse it as Hyper-V refuses a bad hypercall, with #GP
            // at the guest's VMCALL, instead of forwarding.
            EmulationOutcome::Refused {
                emulation,
                exception: InterruptionInfo::GENERAL_PROTECTION,
            }
        }
        Emulation::Hypercall { input } => {
            let mut registers = HypercallRegisters {
                rcx: input,
                rdx: frame.rdx,
                r8: frame.r8,
                rax: 0,
            };
            // SAFETY: exit context: VMX root operation at CPL 0 with the host
            // IDT loaded, the guest stopped at its VMCALL. `decide` forwards
            // only with Hyper-V's interface present and from the guest's CPL
            // 0, so this is a hypercall the guest could have made itself.
            match unsafe { hyperv::forward_hypercall(&mut registers) } {
                Ok(()) => {
                    frame.rax = registers.rax;
                    frame.rcx = registers.rcx;
                    frame.rdx = registers.rdx;
                    frame.r8 = registers.r8;
                    EmulationOutcome::Hypercall {
                        input,
                        result: registers.rax,
                    }
                }
                Err(_) => EmulationOutcome::Refused {
                    emulation,
                    exception: InterruptionInfo::INVALID_OPCODE,
                },
            }
        }
        Emulation::SyntheticRead { msr } => {
            // SAFETY: as for Hypercall, at the guest's RDMSR, which needs CPL
            // 0 to exit at all.
            match unsafe { hyperv::forward_rdmsr(msr) } {
                Ok(value) => {
                    // RDMSR writes EAX and EDX, which zero-extends them.
                    frame.rax = value & 0xFFFF_FFFF;
                    frame.rdx = value >> 32;
                    EmulationOutcome::SyntheticRead { msr, value }
                }
                Err(_) => EmulationOutcome::Refused {
                    emulation,
                    exception: InterruptionInfo::GENERAL_PROTECTION,
                },
            }
        }
        Emulation::SyntheticWrite { msr, value } if hyperv::overlay_gpa(msr, value).is_some_and(page::is_resident) => {
            // The guest asks Hyper-V to overlay one of its pages at a GPA that
            // falls in Aleph0's own memory (HYPERV_INTERFACE.md section 8):
            // refuse with #GP at the guest's WRMSR instead of forwarding.
            EmulationOutcome::Refused {
                emulation,
                exception: InterruptionInfo::GENERAL_PROTECTION,
            }
        }
        Emulation::SyntheticWrite { msr, value } => {
            // SAFETY: as for SyntheticRead, at the guest's WRMSR.
            match unsafe { hyperv::forward_wrmsr(msr, value) } {
                Ok(()) => EmulationOutcome::SyntheticWrite { msr, value },
                Err(_) => EmulationOutcome::Refused {
                    emulation,
                    exception: InterruptionInfo::GENERAL_PROTECTION,
                },
            }
        }
    })
}

/// How the guest goes on after [`prepare_resume`].
#[derive(Debug, Clone, Copy)]
pub(super) struct Resumed {
    /// Where the guest resumes.
    pub(super) rip: u64,
    /// The INVEPT type used, if the protected page was made writable.
    pub(super) invept: Option<InveptType>,
    /// What the emulated instruction did, if the plan emulated one.
    pub(super) emulated: Option<EmulationOutcome>,
}

/// Why the guest cannot resume from an exit it was meant to resume from.
/// Its `Display` is the report's line, before "; not resuming.".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResumeFailure {
    /// GUEST_RIP could not be read.
    RipUnreadable,
    /// RIP must move past the instruction, but VM_EXIT_INSTRUCTION_LEN could
    /// not be read.
    LengthUnreadable,
    /// The next RIP would wrap past the top of the address space or be
    /// non-canonical ([`next_rip`]).
    NextRipInvalid,
    /// A VMWRITE the plan needs failed; `what` names the step.
    Write { what: &'static str, error: VmcsError },
    /// The plan makes the protected page writable, but there is none.
    NoProtectedPage,
    /// INVEPT failed after the protected page was made writable.
    GrantWrite(VmxFail),
    /// RDMSR or WRMSR of the guest's MTRRs failed.
    GuestMtrrs(MtrrAccessFailure),
    /// The exit interrupted an event's delivery, but this exit's plan already
    /// advances RIP or injects its own event, so the event cannot be
    /// re-delivered: only one event is injected per VM entry. (A software
    /// event whose instruction length is unreadable fails the same way.)
    RedeliveryConflict,
}

impl fmt::Display for ResumeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::RipUnreadable => f.write_str("guest RIP unreadable"),
            Self::LengthUnreadable => f.write_str("instruction length unreadable"),
            Self::NextRipInvalid => f.write_str("next guest RIP would wrap or be non-canonical"),
            Self::Write { what, error } => write!(f, "could not {what} ({error:?})"),
            Self::NoProtectedPage => f.write_str("no protected page to make writable"),
            Self::GrantWrite(error) => write!(f, "could not make the protected page writable (INVEPT {error:?})"),
            Self::GuestMtrrs(failure) => write!(f, "{failure}"),
            Self::RedeliveryConflict => f.write_str(
                "an interrupted event cannot be re-delivered while the exit advances RIP or injects its own event",
            ),
        }
    }
}

/// VMWRITEs `value` to `field` for a resume plan; `what` names the step if
/// it fails.
fn write_for_resume(field: u32, value: u64, what: &'static str) -> Result<(), ResumeFailure> {
    // SAFETY: exit context: VMX root operation, with the guest's VMCS current.
    unsafe { vmcs::vmwrite(field, value) }.map_err(|error| ResumeFailure::Write { what, error })
}

/// Prepares the VMCS (and EPT) as `plan` says: executes the emulated
/// instruction into `frame`, moves GUEST_RIP past the exiting instruction
/// and ends an STI or MOV SS shadow, queues an NMI or an exception for
/// injection at the next VM entry, turns NMI-window exiting on or off, and
/// makes the protected page writable. Returns the plan carried out, which
/// injects an exception instead of advancing RIP when Hyper-V refused a
/// forwarded access, and how the guest resumes; or why it cannot.
fn prepare_resume(
    read: &ExitRead,
    plan: ResumePlan,
    frame: &mut RegisterFrame,
) -> Result<(ResumePlan, Resumed), ResumeFailure> {
    let rip = read.rip.map_err(|_| ResumeFailure::RipUnreadable)?;
    // Checked before the emulation: with the length unreadable or the new RIP
    // wrapping or non-canonical, a WRMSR or OUT would already have happened
    // when the guest stops, and serial would never show it.
    let advance_to = if plan.advance_rip {
        let length = read.length.map_err(|_| ResumeFailure::LengthUnreadable)?;
        Some(next_rip(rip, length).ok_or(ResumeFailure::NextRipInvalid)?)
    } else {
        None
    };
    // Before RIP moves: the guest resumes past the instruction with its
    // result already in its registers.
    let emulated = plan.emulate.map(|emulation| execute(emulation, frame)).transpose()?;
    // Hyper-V refused a forwarded access: the guest gets the same exception,
    // at its own instruction, as it would without Aleph0.
    let (plan, advance_to) = match emulated.and_then(EmulationOutcome::refused) {
        Some(exception) => (plan.refused_with(exception), None),
        None => (plan, advance_to),
    };
    let ResumePlan {
        inject_nmi,
        nmi_window,
        grant_write,
        inject_exception,
        redeliver,
        clear_nmi_blocking,
        ..
    } = plan;

    let resume_rip = if let Some(next) = advance_to {
        write_for_resume(GUEST_RIP, next, "advance guest RIP")?;
        // `exit` is always read here: `decide` only plans a resume for an
        // exit it could judge. Written only when a shadow was set, so most
        // exits pay nothing.
        let interruptibility = read.exit.map_or(0, |exit| exit.interruptibility);
        let cleared = after_skipped_instruction(interruptibility);
        if cleared != interruptibility {
            write_for_resume(
                GUEST_INTERRUPTIBILITY_STATE,
                cleared.into(),
                "end the guest's STI/MOV SS blocking",
            )?;
        }
        next
    } else {
        // An NMI exit: the guest goes on at the instruction it was about to
        // run, and the injected NMI is delivered before it. An EPT
        // violation: the faulting write runs again. A #GP or #UD: delivered
        // at the RDMSR, WRMSR or VMCALL, which faults.
        rip
    };

    if clear_nmi_blocking {
        // Re-delivering an NMI whose delivery faulted: clear blocking by NMI
        // so VM entry can inject it. `exit` is always read for a resumed exit,
        // and this plan never also advances RIP (`ResumePlan::redelivering`),
        // so it does not race the STI/MOV SS clearing above.
        let interruptibility = read.exit.map_or(0, |exit| exit.interruptibility);
        let cleared = after_nmi_redelivery(interruptibility);
        if cleared != interruptibility {
            write_for_resume(
                GUEST_INTERRUPTIBILITY_STATE,
                cleared.into(),
                "end the guest's NMI blocking for re-delivery",
            )?;
        }
    }
    if inject_nmi {
        write_for_resume(
            VM_ENTRY_INTERRUPTION_INFO,
            InterruptionInfo::NMI.0.into(),
            "queue the NMI for injection",
        )?;
    }
    if let Some(exception) = inject_exception {
        // SAFETY: exit context: VMX root operation, with the guest's VMCS
        // current.
        unsafe { queue_exception(exception) }.map_err(|error| ResumeFailure::Write {
            what: "queue the exception for injection",
            error,
        })?;
    }
    if let Some(redelivery) = redeliver {
        // SAFETY: exit context: VMX root operation, with the guest's VMCS
        // current.
        unsafe { write_redelivery(redelivery) }.map_err(|error| ResumeFailure::Write {
            what: "queue the interrupted event for re-delivery",
            error,
        })?;
    }
    if let Some(on) = nmi_window {
        // SAFETY: exit context: VMX root operation, with the guest's VMCS
        // current. `configure_controls` checked that the CPU allows
        // NMI-window exiting.
        unsafe { vmcs::set_nmi_window_exiting(on) }.map_err(|error| ResumeFailure::Write {
            what: if on {
                "turn NMI-window exiting on"
            } else {
                "turn NMI-window exiting off"
            },
            error,
        })?;
    }
    let invept = if grant_write {
        let page = read.protected.ok_or(ResumeFailure::NoProtectedPage)?;
        // SAFETY: exit context: VMX root operation, guest stopped. `page`
        // came from `ept::protected_page_for`, so `Ept::build` made the
        // tables, which are never freed.
        Some(unsafe { page.grant_write() }.map_err(ResumeFailure::GrantWrite)?)
    } else {
        None
    };
    Ok((
        plan,
        Resumed {
            rip: resume_rip,
            invept,
            emulated,
        },
    ))
}

/// Queues `exception` for the next VM entry, with error code 0 if it
/// delivers one, through the guest's own IDT at the instruction RIP points
/// to.
///
/// # Safety
///
/// VMX root operation with the guest's VMCS current.
unsafe fn queue_exception(exception: InterruptionInfo) -> Result<(), VmcsError> {
    // SAFETY: the caller guarantees VMX root operation with a current VMCS.
    unsafe {
        if exception.delivers_error_code() {
            vmcs::vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, 0)?;
        }
        vmcs::vmwrite(VM_ENTRY_INTERRUPTION_INFO, exception.0.into())
    }
}

/// Queues the event `redelivery` describes for the next VM entry: its
/// interruption info, its error code when it carries one, and its
/// instruction length for a software interrupt or exception. The
/// interruption-information field is written last, as for an injection.
///
/// # Safety
///
/// VMX root operation with the guest's VMCS current.
unsafe fn write_redelivery(redelivery: Redelivery) -> Result<(), VmcsError> {
    // SAFETY: the caller guarantees VMX root operation with a current VMCS.
    unsafe {
        if let Some(error_code) = redelivery.error_code {
            vmcs::vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code.into())?;
        }
        if let Some(length) = redelivery.instruction_len {
            vmcs::vmwrite(VM_ENTRY_INSTRUCTION_LEN, length.into())?;
        }
        vmcs::vmwrite(VM_ENTRY_INTERRUPTION_INFO, redelivery.info.0.into())
    }
}

/// Called by the entry stub when VMRESUME falls through instead of entering
/// the guest; `rflags` is RFLAGS right after it, and `frame` the guest's
/// registers, which the stub pushed again. Prints why, then the same stop
/// report as an exit that stops the guest, and returns the stop value the
/// stub hands back to bring-up, or halts for the firmware.
#[unsafe(no_mangle)]
extern "efiapi" fn vmresume_failed(rflags: u64, frame: *const RegisterFrame) -> u64 {
    // The handler put the guest's phase back before VMRESUME; this is exit
    // context again.
    crate::output::set_phase(Phase::VmExit);
    let guest = GuestKind::SELECTED;
    let tag = crate::TAG;
    match vmcs::resume_failure(rflags) {
        // SAFETY: a VmFailValid implies VMX operation with a current VMCS,
        // so the error number is readable.
        VmcsError::VmFailValid => match unsafe { vmcs::vm_instruction_error() } {
            Ok(code) => crate::serial_println!(
                "{tag} VMRESUME failed: {} ({code})",
                vmcs::vm_instruction_error_name(code),
            ),
            Err(error) => crate::serial_println!("{tag} VMRESUME failed: VmFailValid, error unreadable ({error:?})"),
        },
        error => crate::serial_println!("{tag} VMRESUME failed: {error:?}"),
    }
    crate::serial_println!("{tag} VMRESUME failed; stopping the guest; {}.", after_stop(guest));
    // SAFETY: the stub passes the frame it just pushed on the exit stack,
    // which stays put until this returns.
    let frame = unsafe { &*frame };
    // The VMRESUME belongs to the last exit, so its number heads the report.
    report_stop(stats::snapshot().exits, frame, &exits_by_reason());
    halt_unless_returnable(guest);
    encode_resume_failed(rflags)
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/vmexit/handler.rs"]
mod tests;
