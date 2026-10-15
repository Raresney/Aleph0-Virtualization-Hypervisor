//! Instructions Aleph0 executes for the guest: passthrough emulation.
//!
//! Some guest instructions always exit (CPUID). Others exit because the
//! exit bitmaps ask for it (RDMSR/WRMSR, through the MSR bitmap in
//! `vmx::exit_bitmaps`). A handler here decides
//! what to execute and counts it. `vmexit::handler` then runs the real
//! instruction in root operation, writes the result into the guest's
//! registers and moves RIP past the instruction, so the guest sees what the
//! hardware says, except where a policy here changes it
//! ([`cpuid_policy`]).

use core::arch::x86_64::CpuidResult;
use core::fmt;

use super::{ExitEvent, ExitInfo, ExitState};
use crate::vmx::exit_bitmaps::{INTERCEPTED_MSRS, MsrAccess, msr_bit};

/// An instruction the exit handler executes for the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emulation {
    /// CPUID with EAX = `leaf`, ECX = `subleaf`.
    Cpuid { leaf: u32, subleaf: u32 },
    /// RDMSR of `msr`, an intercepted MSR.
    Rdmsr { msr: u32 },
    /// WRMSR of `value` (EDX:EAX) to `msr`, an intercepted MSR. `value` is
    /// canonical, so the real WRMSR cannot fault.
    Wrmsr { msr: u32, value: u64 },
}

/// Emulated exits handled so far, per instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EmulationCounts {
    pub cpuid: u32,
    pub rdmsr: u32,
    pub wrmsr: u32,
}

impl fmt::Display for EmulationCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cpuid={} rdmsr={} wrmsr={}", self.cpuid, self.rdmsr, self.wrmsr)
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

/// Whether `value` is a canonical 48-bit address: bits 63:47 all equal.
/// With 5-level paging (CR4.LA57) it would be bits 63:56; Aleph0's guest
/// shares the host's CR4, which UEFI leaves without LA57.
pub(super) fn is_canonical_48(value: u64) -> bool {
    ((value as i64) << 16 >> 16) as u64 == value
}

/// What an RDMSR or WRMSR of an MSR gets.
enum MsrRoute {
    /// In [`INTERCEPTED_MSRS`]: emulate it.
    Intercepted,
    /// Outside both MSR-bitmap ranges, so it exits whatever the bitmap
    /// says. Aleph0 does not know it exists, and a real RDMSR/WRMSR of a
    /// missing MSR would #GP in the host, so the guest gets the #GP.
    OutOfRange,
    /// In range but its bit is clear, so it should never have exited: the
    /// bitmap is broken. Stop.
    NotIntercepted,
}

/// Which [`MsrRoute`] `msr` takes.
fn route(msr: u32) -> MsrRoute {
    if msr_bit(msr, MsrAccess::Read).is_none() {
        MsrRoute::OutOfRange
    } else if INTERCEPTED_MSRS.contains(&msr) {
        MsrRoute::Intercepted
    } else {
        MsrRoute::NotIntercepted
    }
}

/// RDMSR (exit reason 31) of the MSR in ECX.
pub(super) fn rdmsr(state: ExitState, exit: &ExitInfo) -> (ExitEvent, ExitState) {
    let msr = exit.guest_rcx as u32;
    match route(msr) {
        MsrRoute::Intercepted => (
            ExitEvent::Emulated(Emulation::Rdmsr { msr }),
            counted(state, |counts| counts.rdmsr += 1),
        ),
        MsrRoute::OutOfRange => (ExitEvent::GuestGeneralProtection, state),
        MsrRoute::NotIntercepted => (ExitEvent::Unexpected, state),
    }
}

/// WRMSR (exit reason 32) of EDX:EAX to the MSR in ECX. Like WRMSR itself,
/// it ignores the upper halves of RDX and RAX.
pub(super) fn wrmsr(state: ExitState, exit: &ExitInfo) -> (ExitEvent, ExitState) {
    let msr = exit.guest_rcx as u32;
    let value = (exit.guest_rdx << 32) | (exit.guest_rax & 0xFFFF_FFFF);
    match route(msr) {
        // Every intercepted MSR holds an address (only IA32_KERNEL_GS_BASE
        // today). A real WRMSR of a non-canonical one would #GP in the host,
        // in exit context, so the guest gets that #GP instead.
        MsrRoute::Intercepted if !is_canonical_48(value) => (ExitEvent::GuestGeneralProtection, state),
        MsrRoute::Intercepted => (
            ExitEvent::Emulated(Emulation::Wrmsr { msr, value }),
            counted(state, |counts| counts.wrmsr += 1),
        ),
        MsrRoute::OutOfRange => (ExitEvent::GuestGeneralProtection, state),
        MsrRoute::NotIntercepted => (ExitEvent::Unexpected, state),
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/exit_decision/emulation.rs"]
mod tests;
