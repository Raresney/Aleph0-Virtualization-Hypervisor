//! The VM-exit handler the entry stub calls: read the exit, judge it, act
//! on it.
//!
//! [`vmexit_handler`] runs three steps. [`read_exit`] reads the exit's VMCS
//! fields and the guest registers and prints them; [`judge`] folds in an NMI
//! that arrived while Aleph0 ran (`vmx::host`) and passes them to
//! `exit_decision::decide` with the state kept between exits; [`apply`]
//! executes an emulated instruction, prepares the VMCS as the event's
//! `ResumePlan` says, or stops, and prints the outcome.

use core::arch::x86_64::{__cpuid_count, CpuidResult};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::RegisterFrame;
use super::report::{read_or_report, report_ept_exit, report_event, report_exception, report_host_nmi};
use crate::port;
use crate::vmx::ept::{self, InveptType, ProtectedPage};
use crate::vmx::exit_decision::{
    EXIT_REASON_EPT_MISCONFIG, EXIT_REASON_EPT_VIOLATION, EXIT_REASON_EXCEPTION_OR_NMI, EXIT_REASON_IO_INSTRUCTION,
    Emulation, EmulationCounts, EptQualification, ExitAction, ExitEvent, ExitInfo, ExitReason, ExitState,
    InterruptionInfo, IoSize, Redelivery, ResumePlan, UNREADABLE_REASON, after_skipped_instruction, cpuid_policy,
    decide, exit_reason_name, is_canonical_48, merge_in,
};
use crate::vmx::host;
use crate::vmx::msr;
use crate::vmx::vmcs::fields::{
    EXIT_QUALIFICATION, GUEST_INTERRUPTIBILITY_STATE, GUEST_RIP, IDT_VECTORING_ERROR_CODE, IDT_VECTORING_INFO,
    VM_ENTRY_EXCEPTION_ERROR_CODE, VM_ENTRY_INSTRUCTION_LEN, VM_ENTRY_INTERRUPTION_INFO, VM_EXIT_INSTRUCTION_LEN,
    VM_EXIT_INTERRUPTION_INFO, VM_EXIT_REASON,
};
use crate::vmx::vmcs::{self, VmcsError, encode_finished, encode_resume_failed, encode_unexpected};

/// Exits handled so far, including the current one, so the first exit is
/// number 1. Only the exit handler touches it, with interrupts off, on the
/// one CPU that runs the guest; the atomic just avoids `static mut`.
static EXIT_COUNT: AtomicU64 = AtomicU64::new(0);

// The `ExitState` that `decide` carries from one exit to the next, one
// atomic per field, for the same reason as `EXIT_COUNT`.
static MAIN_VMCALLS: AtomicU32 = AtomicU32::new(0);
static NMI_PENDING: AtomicBool = AtomicBool::new(false);
static NMIS_INJECTED: AtomicU32 = AtomicU32::new(0);
static NMIS_HANDLED: AtomicU32 = AtomicU32::new(0);
static EPT_WRITES_GRANTED: AtomicU32 = AtomicU32::new(0);
static EMULATED_CPUID: AtomicU32 = AtomicU32::new(0);
static EMULATED_RDMSR: AtomicU32 = AtomicU32::new(0);
static EMULATED_WRMSR: AtomicU32 = AtomicU32::new(0);
static EMULATED_IN: AtomicU32 = AtomicU32::new(0);
static EMULATED_OUT: AtomicU32 = AtomicU32::new(0);
static EMULATED_HLT: AtomicU32 = AtomicU32::new(0);

fn load_state() -> ExitState {
    ExitState {
        main_vmcalls: MAIN_VMCALLS.load(Ordering::Relaxed),
        nmi_pending: NMI_PENDING.load(Ordering::Relaxed),
        nmis_injected: NMIS_INJECTED.load(Ordering::Relaxed),
        nmis_handled: NMIS_HANDLED.load(Ordering::Relaxed),
        ept_writes_granted: EPT_WRITES_GRANTED.load(Ordering::Relaxed),
        emulated: EmulationCounts {
            cpuid: EMULATED_CPUID.load(Ordering::Relaxed),
            rdmsr: EMULATED_RDMSR.load(Ordering::Relaxed),
            wrmsr: EMULATED_WRMSR.load(Ordering::Relaxed),
            io_in: EMULATED_IN.load(Ordering::Relaxed),
            io_out: EMULATED_OUT.load(Ordering::Relaxed),
            hlt: EMULATED_HLT.load(Ordering::Relaxed),
        },
    }
}

fn store_state(state: ExitState) {
    MAIN_VMCALLS.store(state.main_vmcalls, Ordering::Relaxed);
    NMI_PENDING.store(state.nmi_pending, Ordering::Relaxed);
    NMIS_INJECTED.store(state.nmis_injected, Ordering::Relaxed);
    NMIS_HANDLED.store(state.nmis_handled, Ordering::Relaxed);
    EPT_WRITES_GRANTED.store(state.ept_writes_granted, Ordering::Relaxed);
    EMULATED_CPUID.store(state.emulated.cpuid, Ordering::Relaxed);
    EMULATED_RDMSR.store(state.emulated.rdmsr, Ordering::Relaxed);
    EMULATED_WRMSR.store(state.emulated.wrmsr, Ordering::Relaxed);
    EMULATED_IN.store(state.emulated.io_in, Ordering::Relaxed);
    EMULATED_OUT.store(state.emulated.io_out, Ordering::Relaxed);
    EMULATED_HLT.store(state.emulated.hlt, Ordering::Relaxed);
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

/// VM-exit handler: prints the exit over serial, decides what it is
/// (`exit_decision::decide`), then tells the entry stub what to do. It
/// returns [`RESUME_GUEST`] after preparing the VMCS for the guest to go on
/// (the stub then executes VMRESUME), or a stop value (the stub then returns
/// it from `vmcs::launch` to bring-up).
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
    // Bring-up switches it back once it has left VMX operation.
    crate::output::set_phase(crate::output::Phase::VmExit);
    #[cfg(feature = "host-fault-test")]
    host::fault_on_purpose();

    let number = EXIT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    // SAFETY: the entry stub passes a pointer to the frame it just pushed on
    // the exit stack. It stays put until this returns and nothing else
    // touches it meanwhile; the stub pops it into the guest's registers
    // afterwards, so writes here reach the guest.
    let frame = unsafe { &mut *frame };
    let read = read_exit(number, frame);
    let (event, next) = judge(number, read.exit);
    let action = apply(number, event, &read, next, frame);
    stub_return(action, number, read.raw_reason.unwrap_or(u32::from(UNREADABLE_REASON)))
}

/// What [`read_exit`] read about one exit.
struct ExitRead {
    /// VM_EXIT_REASON, `None` if unreadable.
    raw_reason: Option<u32>,
    /// Everything `decide` needs, `None` if a field it needs was unreadable.
    exit: Option<ExitInfo>,
    /// GUEST_RIP and VM_EXIT_INSTRUCTION_LEN, for resuming.
    rip: Option<u64>,
    length: Option<u64>,
    /// The page EPT protects, for granting write.
    protected: Option<ProtectedPage>,
}

/// Reads the exit's VMCS fields and the guest registers, printing them, and
/// collects what [`judge`] and [`apply`] need.
fn read_exit(number: u64, frame: &RegisterFrame) -> ExitRead {
    let tag = crate::TAG;
    let raw_reason = read_or_report("VM_EXIT_REASON", VM_EXIT_REASON).map(|raw| raw as u32);
    let reason = raw_reason.map(ExitReason::from_raw);
    if let Some(reason) = reason {
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
        if reason.basic == EXIT_REASON_EXCEPTION_OR_NMI && !reason.entry_failure {
            report_exception(number);
        }
    }
    let qualification = read_or_report("EXIT_QUALIFICATION", EXIT_QUALIFICATION);
    if let Some(qualification) = qualification {
        crate::serial_println!("{tag} VM exit #{number}: qualification={qualification:#018x}");
    }
    let ept_exit = reason.filter(|reason| {
        !reason.entry_failure && matches!(reason.basic, EXIT_REASON_EPT_VIOLATION | EXIT_REASON_EPT_MISCONFIG)
    });
    let guest_physical = match ept_exit {
        Some(reason) => report_ept_exit(number, reason.basic, EptQualification(qualification.unwrap_or(0))),
        // Meaningful only for EPT exits; decide never looks at it otherwise.
        None => Some(0),
    };
    // Only EPT and I/O exits are judged by EXIT_QUALIFICATION. For any other
    // exit an unreadable one (printed above) does not matter.
    let judged_by_qualification = ept_exit.is_some()
        || reason.is_some_and(|reason| !reason.entry_failure && reason.basic == EXIT_REASON_IO_INSTRUCTION);
    let qualification = if judged_by_qualification {
        qualification
    } else {
        Some(qualification.unwrap_or(0))
    };
    let rip = read_or_report("GUEST_RIP", GUEST_RIP);
    let length = read_or_report("VM_EXIT_INSTRUCTION_LEN", VM_EXIT_INSTRUCTION_LEN);
    if let (Some(rip), Some(length)) = (rip, length) {
        crate::serial_println!("{tag} VM exit #{number}: guest rip={rip:#018x} instruction length={length}");
    }

    // The stub pushed these just below HOST_RSP; after a normal exit they are
    // the guest's values. After a VM-entry failure (exit reason bit 31) the
    // guest never ran, so they are whatever was live when entry was attempted:
    // the host's registers for VMLAUNCH, or the restored guest registers
    // (the previous exit's) for VMRESUME. Either way, not this exit's guest.
    crate::serial_println!(
        "{tag} VM exit #{number}: guest rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}",
        frame.rax,
        frame.rbx,
        frame.rcx,
        frame.rdx,
    );

    let protected = ept::protected_page();
    let interruption_info = read_or_report("VM_EXIT_INTERRUPTION_INFO", VM_EXIT_INTERRUPTION_INFO);
    let interruptibility = read_or_report("GUEST_INTERRUPTIBILITY_STATE", GUEST_INTERRUPTIBILITY_STATE);
    let idt_vectoring = read_or_report("IDT_VECTORING_INFO", IDT_VECTORING_INFO);
    // Meaningful only when idt_vectoring is valid and carries an error code;
    // 0 otherwise, so an unreadable field never stops an exit that ignores it.
    let idt_vectoring_error_code =
        read_or_report("IDT_VECTORING_ERROR_CODE", IDT_VECTORING_ERROR_CODE).unwrap_or(0) as u32;
    let exit = match (
        reason,
        interruption_info,
        interruptibility,
        idt_vectoring,
        qualification,
        guest_physical,
    ) {
        (Some(reason), Some(info), Some(blocking), Some(vectoring), Some(qualification), Some(guest_physical)) => {
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
            })
        }
        // An unreadable field was printed; without it the exit cannot be
        // judged.
        _ => None,
    };

    ExitRead {
        raw_reason,
        exit,
        rip,
        length,
        protected,
    }
}

/// Decides what `exit` is with the state kept between exits, and keeps the
/// state for the next one. An NMI that arrived in root operation since the
/// last exit is pending for the guest first. An exit that could not be read
/// is unexpected.
fn judge(number: u64, exit: Option<ExitInfo>) -> (ExitEvent, ExitState) {
    let host_nmi = host::take_pending_nmi();
    if host_nmi {
        report_host_nmi(number);
    }
    let state = load_state().with_host_nmi(host_nmi);
    let (event, next) = match exit {
        Some(exit) => decide(state, exit),
        None => (ExitEvent::Unexpected, state),
    };
    store_state(next);
    (event, next)
}

/// Carries out `event` at exit `number`: prepares the guest to resume as
/// its plan says, or stops it, and prints what happened. `next` is the
/// state after the exit. Returns what the entry stub should do.
fn apply(number: u64, event: ExitEvent, read: &ExitRead, next: ExitState, frame: &mut RegisterFrame) -> ExitAction {
    let action = match event.action() {
        ExitAction::Resume(plan) => {
            let plan = plan.keeping_pending_nmi(next);
            // Re-deliver an event this exit interrupted mid-delivery. The
            // plan refuses when it would also advance RIP or inject its own
            // event, since only one event is injected per VM entry.
            let plan = match read
                .exit
                .and_then(|exit| exit.redelivery(read.length.map(|length| length as u32)))
            {
                Some(redelivery) => plan.redelivering(redelivery),
                None => Some(plan),
            };
            match plan {
                Some(plan) => match prepare_resume(number, read, plan, frame) {
                    Some(resumed) => {
                        report_event(number, event, read.exit, next, Some(resumed));
                        #[cfg(feature = "host-nmi-test")]
                        if event == ExitEvent::MainVmcall {
                            wait_for_host_nmi(number);
                        }
                        // Last, after every VMCS write of this exit.
                        keep_nmi_window_for_host_nmi(number);
                        ExitAction::Resume(plan)
                    }
                    // Why the guest cannot go on was printed.
                    None => ExitAction::Unexpected,
                },
                None => {
                    crate::serial_println!(
                        "{} VM exit #{number}: the exit interrupted an event's delivery, but this exit's handler advances RIP or injects its own event; not re-delivering, stopping.",
                        crate::TAG
                    );
                    report_event(number, event, read.exit, next, None);
                    ExitAction::Unexpected
                }
            }
        }
        stop => {
            report_event(number, event, read.exit, next, None);
            stop
        }
    };

    if !matches!(action, ExitAction::Resume(_)) {
        crate::serial_println!(
            "{} VM exit #{number}: stopping the guest; returning to bring-up.",
            crate::TAG
        );
    }
    action
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
    /// IN of `size` from `port` read `value`.
    In { port: u16, size: IoSize, value: u32 },
    /// OUT of `value` (`size` wide) to `port`.
    Out { port: u16, size: IoSize, value: u32 },
}

/// Executes `emulation` in root operation and writes its result into the
/// guest's registers in `frame`.
fn execute(emulation: Emulation, frame: &mut RegisterFrame) -> EmulationOutcome {
    match emulation {
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
        Emulation::In { port, size } => {
            // SAFETY: the guest asked for exactly this access, which it could
            // have made without Aleph0, and IN/OUT at CPL 0 in root operation
            // cannot fault. A 2- or 4-byte access at 0x3FC-0x3FE also touches
            // 0x3FF, so it exits and passes through to the UART registers at
            // 0x3FC-0x3FE, which serial.rs uses (docs/EMULATED_EXITS.md
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
    }
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

/// Prepares the VMCS (and EPT) as `plan` says: executes the emulated
/// instruction into `frame`, moves GUEST_RIP past the exiting instruction
/// and ends an STI or MOV SS shadow, queues an NMI or an exception for
/// injection at the next VM entry, turns NMI-window exiting on or off, and
/// makes the protected page writable. Returns how the guest resumes, or
/// `None` after printing why it cannot.
fn prepare_resume(number: u64, read: &ExitRead, plan: ResumePlan, frame: &mut RegisterFrame) -> Option<Resumed> {
    let ExitRead {
        rip,
        length,
        protected,
        exit,
        ..
    } = *read;
    let ResumePlan {
        advance_rip,
        inject_nmi,
        nmi_window,
        grant_write,
        emulate,
        inject_exception,
        redeliver,
    } = plan;
    let tag = crate::TAG;
    let Some(rip) = rip else {
        crate::serial_println!("{tag} VM exit #{number}: guest RIP unreadable; not resuming.");
        return None;
    };
    // Checked before the emulation: with the length unreadable or the new RIP
    // wrapping or non-canonical, a WRMSR or OUT would already have happened
    // when the guest stops, and serial would never show it.
    let advance_to = if advance_rip {
        let Some(length) = length else {
            crate::serial_println!("{tag} VM exit #{number}: instruction length unreadable; not resuming.");
            return None;
        };
        let Some(next) = next_rip(rip, length) else {
            crate::serial_println!(
                "{tag} VM exit #{number}: next guest RIP would wrap or be non-canonical; not resuming."
            );
            return None;
        };
        Some(next)
    } else {
        None
    };
    // Before RIP moves: the guest resumes past the instruction with its
    // result already in its registers.
    let emulated = emulate.map(|emulation| execute(emulation, frame));

    let resume_rip = if let Some(next) = advance_to {
        // SAFETY: exit context: VMX root operation, with the guest's VMCS
        // current.
        if let Err(error) = unsafe { vmcs::vmwrite(GUEST_RIP, next) } {
            crate::serial_println!("{tag} VM exit #{number}: could not advance guest RIP ({error:?}); not resuming.");
            return None;
        }
        // `exit` is always read here: `decide` only plans a resume for an
        // exit it could judge. Written only when a shadow was set, so most
        // exits pay nothing.
        let interruptibility = exit.map_or(0, |exit| exit.interruptibility);
        let cleared = after_skipped_instruction(interruptibility);
        if cleared != interruptibility
            // SAFETY: exit context: VMX root operation, with the guest's VMCS
            // current.
            && let Err(error) = unsafe { vmcs::vmwrite(GUEST_INTERRUPTIBILITY_STATE, cleared.into()) }
        {
            crate::serial_println!(
                "{tag} VM exit #{number}: could not end the guest's STI/MOV SS blocking ({error:?}); not resuming."
            );
            return None;
        }
        next
    } else {
        // An NMI exit: the guest goes on at the instruction it was about to
        // run, and the injected NMI is delivered before it. An EPT
        // violation: the faulting write runs again. A #GP: delivered at the
        // RDMSR/WRMSR, which faults.
        rip
    };

    if inject_nmi
        // SAFETY: exit context: VMX root operation, with the guest's VMCS
        // current.
        && let Err(error) = unsafe { vmcs::vmwrite(VM_ENTRY_INTERRUPTION_INFO, InterruptionInfo::NMI.0.into()) }
    {
        crate::serial_println!(
            "{tag} VM exit #{number}: could not queue the NMI for injection ({error:?}); not resuming."
        );
        return None;
    }
    if let Some(exception) = inject_exception
        // SAFETY: exit context: VMX root operation, with the guest's VMCS
        // current.
        && let Err(error) = unsafe { queue_exception(exception) }
    {
        crate::serial_println!(
            "{tag} VM exit #{number}: could not queue the exception for injection ({error:?}); not resuming."
        );
        return None;
    }
    if let Some(redelivery) = redeliver {
        crate::serial_println!(
            "{tag} VM exit #{number}: re-delivering the interrupted event (info={:#010x}); RIP stays at {resume_rip:#018x}.",
            redelivery.info.0,
        );
        // SAFETY: exit context: VMX root operation, with the guest's VMCS
        // current.
        if let Err(error) = unsafe { write_redelivery(redelivery) } {
            crate::serial_println!(
                "{tag} VM exit #{number}: could not queue the interrupted event for re-delivery ({error:?}); not resuming."
            );
            return None;
        }
    }
    if let Some(on) = nmi_window
        // SAFETY: exit context: VMX root operation, with the guest's VMCS
        // current. `configure_controls` checked that the CPU allows
        // NMI-window exiting.
        && let Err(error) = unsafe { vmcs::set_nmi_window_exiting(on) }
    {
        crate::serial_println!(
            "{tag} VM exit #{number}: could not turn NMI-window exiting {} ({error:?}); not resuming.",
            if on { "on" } else { "off" },
        );
        return None;
    }
    let invept = if grant_write {
        let Some(page) = protected else {
            crate::serial_println!("{tag} VM exit #{number}: no protected page to make writable; not resuming.");
            return None;
        };
        // SAFETY: exit context: VMX root operation, guest stopped. `page`
        // came from `ept::protected_page`, so `Ept::build` made the tables,
        // which are never freed.
        match unsafe { page.grant_write() } {
            Ok(invept) => Some(invept),
            Err(error) => {
                crate::serial_println!(
                    "{tag} VM exit #{number}: could not make the protected page writable (INVEPT {error:?}); not resuming."
                );
                return None;
            }
        }
    } else {
        None
    };
    Some(Resumed {
        rip: resume_rip,
        invept,
        emulated,
    })
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
/// the guest; `rflags` is RFLAGS right after it. Prints why, then returns
/// the stop value the stub hands back to bring-up.
#[unsafe(no_mangle)]
extern "efiapi" fn vmresume_failed(rflags: u64) -> u64 {
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
    crate::serial_println!("{tag} VMRESUME failed; stopping the guest; returning to bring-up.");
    encode_resume_failed(rflags)
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/vmexit/handler.rs"]
mod tests;
