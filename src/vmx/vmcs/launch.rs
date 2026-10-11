//! How the guest stopped, packed into the one 64-bit value the assembly
//! stubs can pass back to Rust.
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

use super::{launch_failure, resume_failure, VmcsError};
use crate::vmx::vmexit::ExitReason;

/// Why the guest stopped, or why it never ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestStop {
    /// All planned VMCALL exits arrived as expected.
    Finished { exits: u64 },
    /// Exit `number` was not one the handler resumes.
    Unexpected { number: u64, reason: ExitReason },
    /// VMLAUNCH fell through; the guest never ran.
    LaunchFailed { error: VmcsError, instruction_error: Option<u32> },
    /// VMRESUME fell through after an exit the handler resumed.
    ResumeFailed { error: VmcsError, instruction_error: Option<u32> },
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

#[cfg(test)]
#[path = "../../../tests/unit/vmx/vmcs/launch.rs"]
mod tests;
