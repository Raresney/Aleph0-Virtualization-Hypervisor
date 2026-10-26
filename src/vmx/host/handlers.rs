//! What the host IDT's gates run: an NMI handler that hands the NMI to the
//! guest, and a fault handler that prints and halts, except for the #UD or
//! #GP Hyper-V raises at an instruction Aleph0 forwards for the guest
//! (`hyperv::recovery`), which it resumes at the forwarder's recovery point.
//!
//! Both run in VMX root operation with the guest's VMCS current: the CPU
//! loads this IDT only on a VM exit, and teardown loads the firmware's IDT
//! again before it leaves VMX operation. Like the exit handler, they use no
//! firmware and no allocation, and print with `serial_println!`, whose
//! driver keeps no lock that an interrupted print could hold.
//!
//! # NMIs
//!
//! An NMI that arrives in root operation belongs to the guest: it would
//! have caused an NMI exit had the guest been running. The handler cannot
//! inject it, since injecting depends on the exit being handled. Instead:
//!
//! 1. It sets [`NMI_PENDING`], which the exit handler folds into its exit
//!    state at the next exit (`ExitState::with_host_nmi`).
//! 2. It turns NMI-window exiting on, so the guest exits as soon as it can
//!    take an NMI, even if no other exit comes first. That exit injects the
//!    NMI the way an NMI deferred by the guest is injected.
//!
//! Step 2 covers an NMI arriving after the exit handler's last look at
//! `NMI_PENDING` and before VMRESUME: nothing writes the primary controls
//! after that look, so the NMI-window bit stays on.
//!
//! NMIs that arrive while the guest stops or teardown starts are counted but
//! never reach a guest.
//!
//! After an NMI-caused VM exit, the CPU blocks NMIs until the next IRET or
//! VM entry (Intel SDM Vol. 3C, "Architectural State Before a VM Exit").
//! The exit handler never runs IRET, so the next VMRESUME unblocks them; an
//! NMI that arrives in between is held by the CPU and causes an NMI exit
//! right after the entry. A guest that stops at such an exit leaves NMIs
//! blocked until firmware's next interrupt handler runs IRET, as before.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::idt::{exception_name, has_error_code};
use crate::vmx::cr::read_cr2;
use crate::vmx::exit_decision::NMI_VECTOR;
use crate::vmx::hyperv;
use crate::vmx::vmcs;

/// Bytes per fault stub: each starts on a 16-byte boundary and fits in it.
const STUB_SIZE: u64 = 16;

/// Set by the host NMI handler, cleared by [`take_pending_nmi`].
static NMI_PENDING: AtomicBool = AtomicBool::new(false);
/// NMIs taken in VMX root operation since bring-up, for the report.
static NMIS_TAKEN: AtomicU32 = AtomicU32::new(0);

// AT&T syntax, so `$` marks immediates: the vector is an assembler symbol,
// which Intel syntax would read as a memory operand.
//
// `host_vector_stubs`: 256 stubs, one per vector, each at
// `host_vector_stubs + 16 * vector`. A stub makes every frame alike (a 0
// where the CPU pushes no error code, then the vector) and jumps to the
// common part. The error-code list matches `idt::has_error_code`; a host
// test checks every stub's bytes against it. The largest stub is 12 bytes:
// `push $0` (2), `push $vector` (5 from vector 128 on), `jmp` (5).
//
// `host_exception_common`: passes a pointer to the frame to
// `host_exception_handler` (Microsoft x64 ABI: first argument in RCX,
// RSP 16-byte aligned at the call, 32 bytes of shadow space), keeping the
// frame's address in RBP, which the handler preserves. The handler returns
// only for a fault it recovers from, with the frame's RIP moved to the
// recovery point: then it drops the vector and error code and returns with
// IRETQ. Nothing else is restored: the forwarders resume with the registers
// the ABI lets a call change, possibly changed, which they allow for.
//
// `host_nmi_entry`: saves the registers the ABI lets a callee change (RAX,
// RCX, RDX, R8-R11; no vector registers, the target is soft-float, see
// `vmx::vmexit`), calls `host_nmi_handler` on an aligned stack, restores
// them, and returns with IRETQ, which also restores RFLAGS (DF included).
core::arch::global_asm!(
    r#"
    .text
    .balign 16
    .globl host_vector_stubs
host_vector_stubs:
    .set host_vector, 0
    .rept 256
    .balign 16
    .if !((host_vector == 8) || ((host_vector >= 10) && (host_vector <= 14)) || (host_vector == 17) || (host_vector == 21) || (host_vector == 29) || (host_vector == 30))
    pushq $0
    .endif
    pushq $host_vector
    jmp host_exception_common
    .set host_vector, host_vector + 1
    .endr

host_exception_common:
    pushq %rbp
    movq %rsp, %rbp
    leaq 8(%rbp), %rcx
    andq $-16, %rsp
    subq $32, %rsp
    cld
    call host_exception_handler
    movq %rbp, %rsp
    popq %rbp
    addq $16, %rsp
    iretq

    .balign 16
    .globl host_nmi_entry
host_nmi_entry:
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %rbp
    movq %rsp, %rbp
    andq $-16, %rsp
    subq $32, %rsp
    cld
    call host_nmi_handler
    movq %rbp, %rsp
    popq %rbp
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdx
    popq %rcx
    popq %rax
    iretq
"#,
    options(att_syntax)
);

unsafe extern "C" {
    static host_vector_stubs: u8;
    fn host_nmi_entry();
}

/// The handler the host IDT's gate for `vector` points to: the NMI entry
/// for vector 2, the vector's fault stub for every other.
pub fn handler_address(vector: u8) -> u64 {
    if vector == NMI_VECTOR {
        host_nmi_entry as *const () as u64
    } else {
        (&raw const host_vector_stubs) as u64 + u64::from(vector) * STUB_SIZE
    }
}

/// The frame `host_exception_common` passes: what the stub pushed, then
/// what the CPU pushed, lowest address first.
#[repr(C)]
struct ExceptionFrame {
    vector: u64,
    /// The CPU's error code, or the stub's 0 for a vector without one.
    error_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

/// Called by the fault stubs: prints where Aleph0 faulted and halts this
/// CPU for good. A fault in root operation is a bug in Aleph0, and the
/// state it broke is unknown, so nothing is retried. The one exception is
/// Hyper-V refusing an instruction Aleph0 forwards for the guest: that
/// fault moves the frame's RIP to the forwarder's recovery point and
/// returns, and `host_exception_common` resumes there.
#[unsafe(no_mangle)]
extern "efiapi" fn host_exception_handler(frame: *mut ExceptionFrame) {
    // SAFETY: `host_exception_common` passes the address of the frame on
    // its stack, which stays put until it returns with IRETQ, and nothing
    // else touches it meanwhile.
    let frame = unsafe { &mut *frame };
    let vector = frame.vector as u8;
    if let Some(resume) = hyperv::recovery(frame.rip, vector) {
        frame.rip = resume;
        return;
    }
    let tag = crate::TAG;
    crate::serial_println!(
        "{tag} HOST EXCEPTION in VMX root operation: vector {vector} ({}).",
        exception_name(vector)
    );
    if has_error_code(vector) {
        crate::serial_println!("{tag} HOST EXCEPTION: error code {:#x}.", frame.error_code);
    }
    crate::serial_println!(
        "{tag} HOST EXCEPTION: rip={:#018x} cs={:#06x} rflags={:#x} rsp={:#018x} ss={:#06x} cr2={:#018x}.",
        frame.rip,
        frame.cs,
        frame.rflags,
        frame.rsp,
        frame.ss,
        read_cr2(),
    );
    crate::serial_println!("{tag} HOST EXCEPTION: halting this CPU.");
    crate::output::halt_forever()
}

/// Called by `host_nmi_entry`: marks the NMI pending for the guest and asks
/// for an exit as soon as the guest can take it (see the module docs).
#[unsafe(no_mangle)]
extern "efiapi" fn host_nmi_handler() {
    NMIS_TAKEN.fetch_add(1, Ordering::Relaxed);
    NMI_PENDING.store(true, Ordering::Release);
    // SAFETY: this IDT is live only between a VM exit and teardown, so the
    // CPU is in VMX root operation with the guest's VMCS current. Bring-up
    // checked that the CPU allows NMI-window exiting. A failure leaves the
    // NMI pending; the exit handler turns the window on again before it
    // resumes the guest.
    let _ = unsafe { vmcs::set_nmi_window_exiting(true) };
}

/// Whether an NMI arrived in root operation since the last
/// [`take_pending_nmi`], and clears that.
pub fn take_pending_nmi() -> bool {
    NMI_PENDING.swap(false, Ordering::Acquire)
}

/// Whether an NMI arrived in root operation that the exit handler has not
/// taken yet.
pub fn nmi_pending() -> bool {
    NMI_PENDING.load(Ordering::Acquire)
}

/// How many NMIs arrived in root operation so far.
pub fn nmis_taken() -> u32 {
    NMIS_TAKEN.load(Ordering::Relaxed)
}

/// The assembled fault stubs, for the host test that checks them.
#[cfg(test)]
fn stubs() -> &'static [u8] {
    // SAFETY: the 256 stubs are 16 bytes each, back to back from the label,
    // in the image's text for as long as it runs, and never written.
    unsafe { core::slice::from_raw_parts(&raw const host_vector_stubs, super::idt::VECTORS * STUB_SIZE as usize) }
}

/// Faults on purpose in root operation, to show the host fault handler at
/// work: a read of a non-canonical address raises #GP(0).
#[cfg(feature = "host-fault-test")]
pub fn fault_on_purpose() {
    crate::serial_println!(
        "{} host-fault-test: reading a non-canonical address in VMX root operation.",
        crate::TAG
    );
    // SAFETY: none: this faults by design. The #GP goes to the host fault
    // handler, which prints it and halts, so nothing runs after it.
    unsafe {
        core::arch::asm!(
            "mov {value}, qword ptr [{address}]",
            address = in(reg) 0x8000_0000_0000_0000u64,
            value = out(reg) _,
            options(nostack, readonly),
        );
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/host/handlers.rs"]
mod tests;
