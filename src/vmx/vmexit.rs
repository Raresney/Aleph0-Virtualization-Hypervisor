//! VM-exit host resources: the exit stack, the assembly entry stub, and the
//! exit handler.
//!
//! On every VM exit the CPU loads host state from the VMCS and jumps to
//! HOST_RIP ([`entry_address`]) with RSP = HOST_RSP ([`VmExitStack::top`]).
//! Nothing else is set up for us: interrupts are off (host RFLAGS is forced
//! to 0x2), and the guest's general-purpose registers are still live in the
//! CPU, so the stub saves them before any Rust code can clobber them.
//!
//! `bring_up::run` enters the guest through `vmcs::launch`, so the guest's
//! first VM exit lands here. The handler prints each exit over serial, and
//! `exit_decision::decide` says what it is: a write to the EPT-protected
//! data page to allow and retry, a VMCALL to resume past, an NMI to
//! reinject, an NMI window to inject in, the last planned VMCALL, or
//! something unexpected. To resume, the handler updates the VMCS and returns
//! 0, and the stub executes VMRESUME. To stop, it returns a stop value, and
//! the stub jumps back into `vmcs::launch`, which returns to bring-up (see
//! `vmx/vmcs/launch.rs`).

use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::ept::{self, InveptType, ProtectedPage};
use super::exit_decision::{
    EXIT_REASON_EPT_MISCONFIG, EXIT_REASON_EPT_VIOLATION, EXIT_REASON_EXCEPTION_OR_NMI, EptQualification, ExitAction,
    ExitEvent, ExitInfo, ExitState, InterruptionInfo, PLANNED_MAIN_VMCALLS, ResumePlan, decide, expected_main_rax,
};
use super::guest::{GUEST_DATA_SEED, GUEST_EPT_VALUE};
use super::page::{PAGE_SIZE, allocate_zeroed_pages};
use super::vmcs::fields::{
    EXIT_QUALIFICATION, GUEST_INTERRUPTIBILITY_STATE, GUEST_LINEAR_ADDRESS, GUEST_PHYSICAL_ADDRESS, GUEST_RIP,
    IDT_VECTORING_INFO, VM_ENTRY_INTERRUPTION_INFO, VM_EXIT_INSTRUCTION_LEN, VM_EXIT_INTERRUPTION_INFO, VM_EXIT_REASON,
};
use super::vmcs::{self, VmcsError, encode_finished, encode_resume_failed, encode_unexpected};

pub const VM_EXIT_STACK_PAGES: usize = 4;
pub const VM_EXIT_STACK_SIZE: usize = VM_EXIT_STACK_PAGES * PAGE_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmExitStackError {
    /// Failed to allocate memory for the VM-exit stack.
    AllocationFailed,
}

/// Owns a contiguous stack allocation that must outlive every use of HOST_RSP.
pub struct VmExitStack {
    base: NonNull<u8>,
}

impl VmExitStack {
    /// Allocate a zeroed, page-aligned stack for the host VM-exit path.
    pub fn allocate() -> Result<Self, VmExitStackError> {
        let base = allocate_zeroed_pages(VM_EXIT_STACK_PAGES, VmExitStackError::AllocationFailed)?;
        Ok(Self { base })
    }

    /// Top of the downward-growing stack, for HOST_RSP.
    pub fn top(&self) -> u64 {
        // Compute base + VM_EXIT_STACK_SIZE, check 16-byte alignment, and
        // return the address as u64. The stack grows toward lower addresses.
        let top = unsafe { self.base.as_ptr().add(VM_EXIT_STACK_SIZE) } as usize;
        assert_eq!(top % 16, 0);
        top as u64
    }
}

#[repr(C)]
struct RegisterFrame {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

// The entry stub pushes r15 first and rax last, so rax ends up at the lowest
// address. Tie the struct layout to that order, so reordering a field or a
// push breaks the build instead of silently mixing up guest registers.
const _: () = {
    assert!(core::mem::size_of::<RegisterFrame>() == 15 * 8);
    assert!(core::mem::offset_of!(RegisterFrame, rax) == 0);
    assert!(core::mem::offset_of!(RegisterFrame, r15) == 14 * 8);
};

// Every exit enters here with RSP = HOST_RSP, the top of the exit stack, so
// the stack starts empty on each exit and does not grow across exits.
//
// Stack alignment (Microsoft x64 ABI: RSP is a multiple of 16 at each
// `call`): HOST_RSP is 16-aligned; 15 pushes take 120 bytes, and 40 more
// (32 bytes of shadow space plus 8 of padding) make 160, a multiple of 16.
// After the 15 pops RSP is HOST_RSP again, so the failure path needs only
// the 32 bytes of shadow space.
//
// Only the 15 general-purpose registers are saved, because nothing here
// touches vector state: the x86_64-unknown-uefi target is soft-float with
// MMX/SSE disabled (only `fxsr` is among its vector features), so the handler
// and `core::fmt` never use x87, XMM or MXCSR. If SSE target features are ever
// enabled, the handler would clobber the guest's vector registers, and this
// stub would have to save them (for example with FXSAVE/FXRSTOR) before an OS
// guest can run.
core::arch::global_asm!(
    r#"
    .globl vmexit_entry
vmexit_entry:
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rbp
    push rdi
    push rsi
    push rdx
    push rcx
    push rbx
    push rax

    mov rcx, rsp
    sub rsp, 40
    cld
    call vmexit_handler

    // RAX = 0: resume the guest. Anything else is a stop value: return it
    // from vmx_launch (vmx/vmcs/launch.rs), abandoning this stack.
    test rax, rax
    jnz vmx_return_to_launcher

    // Resume: restore the guest's registers in the reverse order of the
    // pushes above; RIP, RSP and RFLAGS come from the VMCS, not from this
    // frame.
    add rsp, 40
    pop rax
    pop rbx
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rbp
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
    vmresume

    // Reached only if VMRESUME failed; RFLAGS say how. vmresume_failed
    // returns the stop value in RAX.
    pushfq
    pop rcx
    sub rsp, 32
    call vmresume_failed
    jmp vmx_return_to_launcher
"#
);

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
const UNREADABLE_REASON: u16 = 0xFFFF;

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

/// Reads one VMCS field for the diagnostic, printing instead of failing.
fn read_or_report(name: &str, field: u32) -> Option<u64> {
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

    let tag = crate::TAG;
    let number = EXIT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;

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
    let frame = unsafe { &*frame };
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

    let state = load_state();
    let (event, next) = match exit {
        Some(exit) => decide(state, exit),
        None => (ExitEvent::Unexpected, state),
    };
    store_state(next);

    let action = match event.action() {
        ExitAction::Resume(plan) => match prepare_resume(number, rip, length, plan, protected) {
            Some(resumed) => {
                report_event(number, event, exit, next, Some(resumed));
                ExitAction::Resume(plan)
            }
            // Why the guest cannot go on was printed.
            None => ExitAction::Unexpected,
        },
        stop => {
            report_event(number, event, exit, next, None);
            stop
        }
    };

    if !matches!(action, ExitAction::Resume(_)) {
        crate::serial_println!("{tag} VM exit #{number}: stopping the guest; returning to bring-up.");
    }
    stub_return(action, number, raw_reason.unwrap_or(u32::from(UNREADABLE_REASON)))
}

/// How the guest goes on after [`prepare_resume`].
#[derive(Debug, Clone, Copy)]
struct Resumed {
    /// Where the guest resumes.
    rip: u64,
    /// The INVEPT type used, if the protected page was made writable.
    invept: Option<InveptType>,
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

/// Prints an EPT exit's addresses and what the EPT entries allowed, and
/// returns GUEST_PHYSICAL_ADDRESS (`None` if unreadable, after printing why).
fn report_ept_exit(number: u64, basic: u16, qualification: EptQualification) -> Option<u64> {
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
    }
}

/// Prints the vector of an exception exit. Exit qualification, printed by
/// the caller, holds the faulting address for a page fault (#PF, vector 14).
/// NMI exits share reason 0 but are not exceptions; the event line printed
/// later reports them.
fn report_exception(number: u64) {
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

unsafe extern "C" {
    fn vmexit_entry() -> !;
}

pub fn entry_address() -> u64 {
    vmexit_entry as *const () as usize as u64
}

#[cfg(test)]
#[path = "../../tests/unit/vmx/vmexit.rs"]
mod tests;
