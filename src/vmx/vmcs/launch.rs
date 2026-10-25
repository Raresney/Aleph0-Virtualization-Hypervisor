//! Entering the guest with VMLAUNCH, and coming back when it stops.
//!
//! A successful VMLAUNCH never falls through: the CPU runs the guest, and
//! every VM exit starts the VM-exit stub in `vmx::vmexit` on its own stack.
//! To let bring-up go on after the guest stops, [`launch`] first saves the
//! caller's registers and stack pointer, like C's `setjmp`. When the guest
//! should stop, the exit stub jumps to `vmx_return_to_launcher`, which
//! restores them and returns, like `longjmp`. To the Rust caller, `launch`
//! is an ordinary function that returns a [`GuestStop`].
//!
//! Every way back from the guest carries a *stop value*. Bits 63:62 say
//! which kind it is, and the rest is the payload:
//!
//! | bits 63:62 | payload | meaning |
//! |---|---|---|
//! | 0 | RFLAGS right after VMLAUNCH | VMLAUNCH failed |
//! | 1 | number of exits | all planned exits arrived |
//! | 2 | exit number (61:32), raw exit reason (31:0) | an exit the handler does not resume |
//! | 3 | RFLAGS right after VMRESUME | VMRESUME failed |
//!
//! Kind 0 is RFLAGS itself, so the launch stub returns it without encoding:
//! RFLAGS bits 63:22 are reserved and read as 0. No stop value is 0, because
//! RFLAGS bit 1 always reads as 1, so the exit handler can return 0 to mean
//! "resume the guest".
//!
//! [`launch_in_place`] is the other way in, for the firmware: there is no
//! guest code to jump to and no stop to come back from. It writes the RIP,
//! RSP and RFLAGS it runs with into the guest state just before VMLAUNCH,
//! so the guest starts at the instruction after VMLAUNCH, on the same stack.
//! The code that called it then goes on as the guest, in VMX non-root
//! operation, and returns to its own caller. Nothing jumps back into its
//! frame, so it saves none.

use core::arch::asm;
use core::sync::atomic::AtomicU64;

use super::fields::{GUEST_RFLAGS, GUEST_RIP, GUEST_RSP};
use super::{VmcsError, instruction_error_for, launch_failure, resume_failure};
use crate::vmx::exit_decision::ExitReason;

/// RSP inside `vmx_launch`, saved after it pushed the caller's registers;
/// `vmx_return_to_launcher` reloads it to get back into that frame.
///
/// Only the stub below reads and writes it, once per launch, on the one CPU
/// that runs the guest. The atomic just gives it a fixed, writable home
/// without `static mut`, and `no_mangle` keeps the name the asm uses.
#[unsafe(no_mangle)]
static VMX_LAUNCH_RSP: AtomicU64 = AtomicU64::new(0);

// `vmx_launch` is called with the Microsoft x64 ABI (`efiapi`). A callee
// must preserve RBX, RBP, RDI, RSI, R12-R15 and RSP, so the stub pushes the
// eight registers and saves RSP. The ABI also makes XMM6-XMM15
// callee-saved, but the x86_64-unknown-uefi target is soft-float with SSE
// disabled, so neither the caller nor the exit handler uses them (see the
// VM-exit stub in `vmx::vmexit`).
//
// While the guest runs, this frame on the firmware stack stays untouched:
// the exit handler runs on the VM-exit stack, and the guest on its own page.
//
// No call happens here, so stack alignment does not matter. On the way
// back, RFLAGS are what VMLAUNCH left (failure), or host RFLAGS as loaded
// by the VM exit, 0x2 (stop), so IF stays 0 until teardown.
core::arch::global_asm!(
    r#"
    .globl vmx_launch
vmx_launch:
    push rbx
    push rbp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    mov [rip + VMX_LAUNCH_RSP], rsp
    vmlaunch

    // Reached only if VMLAUNCH failed. Its RFLAGS are the stop value
    // (kind 0); fall through to return them.
    pushfq
    pop rax

    // RAX holds the stop value. The VM-exit stub also jumps here when the
    // guest stops: back into vmx_launch's frame, then return to its caller.
    .globl vmx_return_to_launcher
vmx_return_to_launcher:
    mov rsp, [rip + VMX_LAUNCH_RSP]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    pop rbx
    ret
"#
);

unsafe extern "efiapi" {
    /// The stub above. Returns a stop value.
    fn vmx_launch() -> u64;
}

/// Why the guest stopped, or why it never ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestStop {
    /// All planned VMCALL exits arrived as expected.
    Finished { exits: u64 },
    /// Exit `number` was not one the handler resumes.
    Unexpected { number: u64, reason: ExitReason },
    /// VMLAUNCH fell through; the guest never ran.
    LaunchFailed {
        error: VmcsError,
        instruction_error: Option<u32>,
    },
    /// VMRESUME fell through after an exit the handler resumed.
    ResumeFailed {
        error: VmcsError,
        instruction_error: Option<u32>,
    },
}

const KIND_SHIFT: u32 = 62;
const PAYLOAD_MASK: u64 = (1 << KIND_SHIFT) - 1;
const KIND_LAUNCH_FAILED: u64 = 0;
const KIND_FINISHED: u64 = 1;
const KIND_UNEXPECTED: u64 = 2;
const KIND_RESUME_FAILED: u64 = 3;

/// Width of the exit-number field (bits 61:32) of an unexpected-exit stop
/// value. A larger number keeps only its low 30 bits, so it can never spill
/// into the kind.
const EXIT_NUMBER_BITS: u32 = 30;
const EXIT_NUMBER_MASK: u64 = (1 << EXIT_NUMBER_BITS) - 1;

/// Stop value for "all planned exits arrived", after `exits` exits.
pub fn encode_finished(exits: u64) -> u64 {
    (KIND_FINISHED << KIND_SHIFT) | (exits & PAYLOAD_MASK)
}

/// Stop value for exit `number`, whose raw VM_EXIT_REASON is `raw_reason`.
pub fn encode_unexpected(number: u64, raw_reason: u32) -> u64 {
    (KIND_UNEXPECTED << KIND_SHIFT) | ((number & EXIT_NUMBER_MASK) << 32) | u64::from(raw_reason)
}

/// Stop value for a VMRESUME that fell through and left `rflags`.
pub fn encode_resume_failed(rflags: u64) -> u64 {
    (KIND_RESUME_FAILED << KIND_SHIFT) | (rflags & PAYLOAD_MASK)
}

/// Decodes a stop value. `instruction_error` is always `None` here: reading
/// it needs the current VMCS, which only `launch` can do.
fn decode(value: u64) -> GuestStop {
    let payload = value & PAYLOAD_MASK;
    match value >> KIND_SHIFT {
        KIND_LAUNCH_FAILED => GuestStop::LaunchFailed {
            error: launch_failure(payload),
            instruction_error: None,
        },
        KIND_FINISHED => GuestStop::Finished { exits: payload },
        KIND_UNEXPECTED => GuestStop::Unexpected {
            number: payload >> 32,
            reason: ExitReason::from_raw(payload as u32),
        },
        // KIND_RESUME_FAILED: `value >> 62` is at most 3.
        _ => GuestStop::ResumeFailed {
            error: resume_failure(payload),
            instruction_error: None,
        },
    }
}

/// Enters the guest described by the current VMCS, and returns once the
/// guest has stopped or VMLAUNCH has failed.
///
/// The guest runs between VMLAUNCH and the stop: the exit handler resumes
/// it after each planned VMCALL, and stops it after the last one or at any
/// exit or VMRESUME failure it does not handle. The module docs explain how
/// execution gets back here.
///
/// For a VmFailValid of VMLAUNCH or VMRESUME, the VM-instruction error is
/// read here, while the VMCS is still current; teardown clears it.
///
/// Invalid *guest* state is not a launch failure: the CPU reports it as a
/// VM exit with bit 31 of the exit reason set (basic reason 33), which
/// arrives as [`GuestStop::Unexpected`].
///
/// # Safety
///
/// VMX root operation, with a current VMCS whose controls, host state and
/// guest state are fully written. HOST_RSP and HOST_RIP must point at a live
/// exit stack and handler, and the guest's pages must stay allocated.
pub unsafe fn launch() -> GuestStop {
    // SAFETY: the caller guarantees VMX root operation with a fully written
    // current VMCS, HOST_RSP/HOST_RIP at a live exit stack and handler, and
    // guest pages that stay allocated.
    let value = unsafe { vmx_launch() };
    match decode(value) {
        GuestStop::LaunchFailed { error, .. } => GuestStop::LaunchFailed {
            error,
            // SAFETY: still in VMX operation with the VMCS current; teardown
            // has not run yet.
            instruction_error: unsafe { instruction_error_for(error) },
        },
        GuestStop::ResumeFailed { error, .. } => GuestStop::ResumeFailed {
            error,
            // SAFETY: as above.
            instruction_error: unsafe { instruction_error_for(error) },
        },
        stop => stop,
    }
}

/// Decodes what the in-place launch's asm leaves: 0 when it runs on as the
/// guest, or the RFLAGS of the VMWRITE or VMLAUNCH that failed, which are
/// never 0 (bit 1 always reads as 1).
fn decode_in_place(value: u64) -> Result<(), VmcsError> {
    match value {
        0 => Ok(()),
        rflags => Err(launch_failure(rflags)),
    }
}

/// Enters the guest described by the current VMCS in place: the guest is
/// this code, from the instruction after VMLAUNCH on, with the RSP and
/// RFLAGS it had there, IF included. So this returns `Ok` in VMX non-root
/// operation, to its caller, as if VMLAUNCH had been an instruction that did
/// nothing. The registers VM entry does not load (the general-purpose ones)
/// keep their values across it.
///
/// Returns [`GuestStop::LaunchFailed`] in root operation if VMLAUNCH, or a
/// VMWRITE of GUEST_RIP, GUEST_RSP or GUEST_RFLAGS just before it, failed:
/// the guest never ran. A failed VMWRITE reads as VmFailValid with error 12
/// (unsupported VMCS component).
///
/// An interrupt that arrives after RFLAGS is copied runs the firmware's
/// handler in root operation, on the stack below the copied RSP, and is
/// gone by VMLAUNCH; the guest starts with that same RSP.
///
/// # Safety
///
/// As for [`launch`], except for RIP, RSP and RFLAGS, which this writes:
/// VMX root operation, with a current VMCS whose controls, host state and
/// other guest state are fully written, and HOST_RSP and HOST_RIP at a live
/// exit stack and handler. The guest state must describe the running
/// context (`guest_state::GuestEntry::InPlace`), so that the code after
/// VMLAUNCH runs the same as before it. No VM exit may jump back here: the
/// exit handler must halt on a stop (`GuestKind::Firmware`).
pub unsafe fn launch_in_place() -> Result<(), GuestStop> {
    let value: u64;
    // SAFETY: the caller guarantees VMX root operation with a fully written
    // current VMCS and a guest state that is this context's. VMWRITE changes
    // only the VMCS. Each `jbe` leaves at the first VMfail (CF = 1 or
    // ZF = 1). PUSHFQ and POP balance, so RSP at VMLAUNCH, and at `2:` where
    // the guest starts, is the one written to GUEST_RSP. VM entry keeps the
    // general-purpose registers, so every operand still holds its value
    // there; flags are clobbered either way (no `preserves_flags`).
    unsafe {
        asm!(
            "lea {value}, [rip + 2f]",
            "vmwrite {rip_field}, {value}",
            "jbe 3f",
            "vmwrite {rsp_field}, rsp",
            "jbe 3f",
            "pushfq",
            "pop {value}",
            "vmwrite {rflags_field}, {value}",
            "jbe 3f",
            "vmlaunch",
            // VMLAUNCH or a VMWRITE failed: its RFLAGS say how.
            "3:",
            "pushfq",
            "pop {value}",
            "jmp 4f",
            // The guest starts here, in VMX non-root operation.
            "2:",
            "xor {value:e}, {value:e}",
            "4:",
            // `out`, not `lateout`: written before the inputs are last read.
            value = out(reg) value,
            rip_field = in(reg) u64::from(GUEST_RIP),
            rsp_field = in(reg) u64::from(GUEST_RSP),
            rflags_field = in(reg) u64::from(GUEST_RFLAGS),
        );
    }
    decode_in_place(value).map_err(|error| GuestStop::LaunchFailed {
        error,
        // SAFETY: the launch failed, so this is still root operation with the
        // VMCS current; teardown has not run yet.
        instruction_error: unsafe { instruction_error_for(error) },
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/vmcs/launch.rs"]
mod tests;
