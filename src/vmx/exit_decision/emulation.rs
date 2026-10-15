//! Instructions Aleph0 executes for the guest: passthrough emulation.
//!
//! Some guest instructions always exit (CPUID). Others exit because the
//! exit bitmaps ask for it (`vmx::exit_bitmaps`). A handler here decides
//! what to execute and counts it. `vmexit::handler` then runs the real
//! instruction in root operation, writes the result into the guest's
//! registers and moves RIP past the instruction, so the guest sees what the
//! hardware says, except where a policy here changes it
//! ([`cpuid_policy`]).

use core::arch::x86_64::CpuidResult;
use core::fmt;

use super::{ExitEvent, ExitInfo, ExitState};

/// An instruction the exit handler executes for the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emulation {
    /// CPUID with EAX = `leaf`, ECX = `subleaf`.
    Cpuid { leaf: u32, subleaf: u32 },
}

/// Emulated exits handled so far, per instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EmulationCounts {
    pub cpuid: u32,
}

impl fmt::Display for EmulationCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cpuid={}", self.cpuid)
    }
}

/// CPUID.1:ECX bit 5: VMX.
const CPUID_1_ECX_VMX: u32 = 1 << 5;

/// What the guest sees for CPUID `leaf`, given what the processor returned
/// in root operation.
///
/// Everything passes through except CPUID.1:ECX.VMX. A guest that saw it
/// would try VMXON, which always exits (reason 27), and Aleph0 does not
/// emulate VMX. Left as the processor says, for the OS-guest step:
/// - ECX bit 31 (hypervisor present) and the leaves from 0x40000000, which
///   under Hyper-V describe Hyper-V;
/// - values that depend on CR4 and XCR0 (CPUID.1:ECX.OSXSAVE, leaf 0xD),
///   which are right for the guest only while it shares the host's.
pub fn cpuid_policy(leaf: u32, raw: CpuidResult) -> CpuidResult {
    match leaf {
        1 => CpuidResult {
            ecx: raw.ecx & !CPUID_1_ECX_VMX,
            ..raw
        },
        _ => raw,
    }
}

/// `state` with one more emulated exit, as `count` adds it.
fn counted(state: ExitState, count: impl FnOnce(&mut EmulationCounts)) -> ExitState {
    let mut next = state;
    count(&mut next.emulated);
    next
}

/// CPUID (exit reason 10), which always exits: execute it with the guest's
/// EAX (leaf) and ECX (subleaf).
pub(super) fn cpuid(state: ExitState, exit: &ExitInfo) -> (ExitEvent, ExitState) {
    let emulation = Emulation::Cpuid {
        leaf: exit.guest_rax as u32,
        subleaf: exit.guest_rcx as u32,
    };
    (
        ExitEvent::Emulated(emulation),
        counted(state, |counts| counts.cpuid += 1),
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/exit_decision/emulation.rs"]
mod tests;
