//! The VM-exit handler the entry stub calls: read the exit, judge it, act
//! on it.
//!
//! [`vmexit_handler`] runs three steps. [`read_exit`] reads the exit's VMCS
//! fields and the guest registers and prints them; [`judge`] passes them to
//! `exit_decision::decide` with the state kept between exits; [`apply`]
//! prepares the VMCS as the event's `ResumePlan` says, or stops, and
//! prints the outcome.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::RegisterFrame;
use super::report::{read_or_report, report_ept_exit, report_event, report_exception};
use crate::vmx::ept::{self, InveptType, ProtectedPage};
use crate::vmx::exit_decision::{
    EXIT_REASON_EPT_MISCONFIG, EXIT_REASON_EPT_VIOLATION, EXIT_REASON_EXCEPTION_OR_NMI, EptQualification, ExitAction,
    ExitEvent, ExitInfo, ExitReason, ExitState, InterruptionInfo, ResumePlan, UNREADABLE_REASON, decide,
    exit_reason_name,
};
use crate::vmx::vmcs::fields::{
    EXIT_QUALIFICATION, GUEST_INTERRUPTIBILITY_STATE, GUEST_RIP, IDT_VECTORING_INFO, VM_ENTRY_INTERRUPTION_INFO,
    VM_EXIT_INSTRUCTION_LEN, VM_EXIT_INTERRUPTION_INFO, VM_EXIT_REASON,
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

fn load_state() -> ExitState {
    ExitState {
        main_vmcalls: MAIN_VMCALLS.load(Ordering::Relaxed),
        nmi_pending: NMI_PENDING.load(Ordering::Relaxed),
        nmis_injected: NMIS_INJECTED.load(Ordering::Relaxed),
        nmis_handled: NMIS_HANDLED.load(Ordering::Relaxed),
        ept_writes_granted: EPT_WRITES_GRANTED.load(Ordering::Relaxed),
    }
}

fn store_state(state: ExitState) {
    MAIN_VMCALLS.store(state.main_vmcalls, Ordering::Relaxed);
    NMI_PENDING.store(state.nmi_pending, Ordering::Relaxed);
    NMIS_INJECTED.store(state.nmis_injected, Ordering::Relaxed);
    NMIS_HANDLED.store(state.nmis_handled, Ordering::Relaxed);
    EPT_WRITES_GRANTED.store(state.ept_writes_granted, Ordering::Relaxed);
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

/// VM-exit handler: prints the exit over serial, decides what it is
/// (`exit_decision::decide`), then tells the entry stub what to do. It
/// returns [`RESUME_GUEST`] after preparing the VMCS for the guest to go on
/// (the stub then executes VMRESUME), or a stop value (the stub then returns
/// it from `vmcs::launch` to bring-up).
///
/// Runs on the VM-exit stack with interrupts off. It may only use things
/// that need no firmware: VMREAD/VMWRITE (the VMCS is still current) and the
/// serial port. `uefi::println!` must not be called here; `log!` and the
/// panic handler skip the console once the phase below is set.
#[unsafe(no_mangle)]
extern "efiapi" fn vmexit_handler(frame: *const RegisterFrame) -> u64 {
    // First, so every line below (and any panic) skips the firmware console.
    // Bring-up switches it back once it has left VMX operation.
    crate::output::set_phase(crate::output::Phase::VmExit);

    let number = EXIT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    // SAFETY: the entry stub passes a pointer to the frame it just pushed on
    // the exit stack, which stays put until this returns.
    let read = read_exit(number, unsafe { &*frame });
    let (event, next) = judge(read.exit);
    let action = apply(number, event, &read, next);
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
    // Likewise, only an EPT exit needs EXIT_QUALIFICATION to be judged; an
    // unreadable one was printed above.
    let qualification = match ept_exit {
        Some(_) => qualification,
        None => Some(qualification.unwrap_or(0)),
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
                idt_vectoring_valid: InterruptionInfo(vectoring as u32).is_valid(),
                exit_qualification: EptQualification(qualification),
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
/// state for the next one. An exit that could not be read is unexpected.
fn judge(exit: Option<ExitInfo>) -> (ExitEvent, ExitState) {
    let state = load_state();
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
fn apply(number: u64, event: ExitEvent, read: &ExitRead, next: ExitState) -> ExitAction {
    let action = match event.action() {
        ExitAction::Resume(plan) => match prepare_resume(number, read.rip, read.length, plan, read.protected) {
            Some(resumed) => {
                report_event(number, event, read.exit, next, Some(resumed));
                ExitAction::Resume(plan)
            }
            // Why the guest cannot go on was printed.
            None => ExitAction::Unexpected,
        },
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

/// How the guest goes on after [`prepare_resume`].
#[derive(Debug, Clone, Copy)]
pub(super) struct Resumed {
    /// Where the guest resumes.
    pub(super) rip: u64,
    /// The INVEPT type used, if the protected page was made writable.
    pub(super) invept: Option<InveptType>,
}

/// Prepares the VMCS (and EPT) as `plan` says: moves GUEST_RIP past the
/// exiting instruction, queues an NMI for injection at the next VM entry,
/// turns NMI-window exiting on or off, and makes `protected` writable.
/// Returns how the guest resumes, or `None` after printing why it cannot.
fn prepare_resume(
    number: u64,
    rip: Option<u64>,
    length: Option<u64>,
    plan: ResumePlan,
    protected: Option<ProtectedPage>,
) -> Option<Resumed> {
    let ResumePlan {
        advance_rip,
        inject_nmi,
        nmi_window,
        grant_write,
    } = plan;
    let tag = crate::TAG;
    let Some(rip) = rip else {
        crate::serial_println!("{tag} VM exit #{number}: guest RIP unreadable; not resuming.");
        return None;
    };

    let resume_rip = if advance_rip {
        let Some(length) = length else {
            crate::serial_println!("{tag} VM exit #{number}: instruction length unreadable; not resuming.");
            return None;
        };
        if let Err(error) = unsafe { vmcs::vmwrite(GUEST_RIP, rip + length) } {
            crate::serial_println!("{tag} VM exit #{number}: could not advance guest RIP ({error:?}); not resuming.");
            return None;
        }
        rip + length
    } else {
        // An NMI exit: the guest goes on at the instruction it was about to
        // run, and the injected NMI is delivered before it. An EPT
        // violation: the faulting write runs again.
        rip
    };

    if inject_nmi
        && let Err(error) = unsafe { vmcs::vmwrite(VM_ENTRY_INTERRUPTION_INFO, InterruptionInfo::NMI.0.into()) }
    {
        crate::serial_println!(
            "{tag} VM exit #{number}: could not queue the NMI for injection ({error:?}); not resuming."
        );
        return None;
    }
    if let Some(on) = nmi_window
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
    })
}

/// Called by the entry stub when VMRESUME falls through instead of entering
/// the guest; `rflags` is RFLAGS right after it. Prints why, then returns
/// the stop value the stub hands back to bring-up.
#[unsafe(no_mangle)]
extern "efiapi" fn vmresume_failed(rflags: u64) -> u64 {
    let tag = crate::TAG;
    match vmcs::resume_failure(rflags) {
        // VmFailValid implies a current VMCS, so the error number is readable.
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
