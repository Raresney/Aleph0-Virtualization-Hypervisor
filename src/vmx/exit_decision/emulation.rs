//! Instructions Aleph0 executes for the guest: passthrough emulation.
//!
//! Some guest instructions always exit (CPUID). Others exit because the
//! exit bitmaps ask for it (RDMSR/WRMSR through the MSR bitmap, IN/OUT through
//! the I/O bitmaps, both in `vmx::exit_bitmaps`). A handler here decides
//! what to execute and counts it. `vmexit::handler` then runs the real
//! instruction in root operation, writes the result into the guest's
//! registers and moves RIP past the instruction, so the guest sees what the
//! hardware says, except where a policy here changes it
//! ([`cpuid_policy`]).
//!
//! HLT is counted with them but never executed: Aleph0 resumes past it (see
//! [`hlt`]).

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
    /// IN of `size` from `port`.
    In { port: u16, size: IoSize },
    /// OUT of `value` (`size` wide) to `port`.
    Out { port: u16, size: IoSize, value: u32 },
}

/// Emulated exits handled so far, per instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EmulationCounts {
    pub cpuid: u32,
    pub rdmsr: u32,
    pub wrmsr: u32,
    pub io_in: u32,
    pub io_out: u32,
    /// HLT exits, resumed past without halting.
    pub hlt: u32,
}

impl fmt::Display for EmulationCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cpuid={} rdmsr={} wrmsr={} in={} out={} hlt={}",
            self.cpuid, self.rdmsr, self.wrmsr, self.io_in, self.io_out, self.hlt
        )
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

/// HLT (exit reason 12): resume past it without halting. A halted vCPU
/// waits for an interrupt, and the guest's interrupts are delivered when it
/// next runs anyway, so going on at once is a correct, if busy, wait. The
/// HLT activity state would avoid one exit per idle loop round, but needs
/// IA32_VMX_MISC bit 6 and a rule for NMI exits taken in that state.
pub(super) fn hlt(state: ExitState) -> (ExitEvent, ExitState) {
    (ExitEvent::Halted, counted(state, |counts| counts.hlt += 1))
}

/// Whether `value` is a canonical 48-bit address: bits 63:47 all equal.
/// With 5-level paging (CR4.LA57) it would be bits 63:56; Aleph0's guest
/// shares the host's CR4, which UEFI leaves without LA57.
pub fn is_canonical_48(value: u64) -> bool {
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

/// How many bytes an IN or OUT moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoSize {
    Byte,
    Word,
    Dword,
}

impl IoSize {
    /// Bytes moved: 1, 2 or 4.
    pub fn bytes(self) -> u8 {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
            Self::Dword => 4,
        }
    }

    /// The bits of RAX the access uses: AL, AX or EAX.
    fn mask(self) -> u64 {
        match self {
            Self::Byte => 0xFF,
            Self::Word => 0xFFFF,
            Self::Dword => 0xFFFF_FFFF,
        }
    }
}

/// An I/O instruction's exit qualification (Intel SDM Vol. 3C, "Exit
/// Qualification for I/O Instructions"):
///
/// ```text
/// bits 2:0   size − 1: 0 = 1 byte, 1 = 2 bytes, 3 = 4 bytes
/// bit  3     direction: 1 = IN, 0 = OUT
/// bit  4     string instruction (INS/OUTS)
/// bit  5     REP prefix
/// bit  6     operand: 1 = immediate port, 0 = DX
/// bits 31:16 port
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoQualification(pub u64);

impl IoQualification {
    /// The access size, or `None` for the encodings the SDM leaves unused.
    pub fn size(self) -> Option<IoSize> {
        match self.0 & 0b111 {
            0 => Some(IoSize::Byte),
            1 => Some(IoSize::Word),
            3 => Some(IoSize::Dword),
            _ => None,
        }
    }

    /// Whether it is IN (bit 3); OUT otherwise.
    pub fn is_in(self) -> bool {
        self.0 & (1 << 3) != 0
    }

    /// Whether it is INS or OUTS (bit 4).
    pub fn is_string(self) -> bool {
        self.0 & (1 << 4) != 0
    }

    /// Whether it has a REP prefix (bit 5).
    pub fn is_rep(self) -> bool {
        self.0 & (1 << 5) != 0
    }

    /// The port (bits 31:16).
    pub fn port(self) -> u16 {
        (self.0 >> 16) as u16
    }
}

/// RAX after an IN of `size` that read `value`. A 1- or 2-byte IN writes
/// only AL or AX and keeps the rest of RAX. A 4-byte IN writes EAX, which
/// zero-extends into RAX like every 32-bit register write in 64-bit mode.
pub fn merge_in(rax: u64, size: IoSize, value: u32) -> u64 {
    match size {
        IoSize::Dword => u64::from(value),
        _ => (rax & !size.mask()) | (u64::from(value) & size.mask()),
    }
}

/// The value an OUT of `size` sends: AL, AX or EAX.
pub fn out_value(rax: u64, size: IoSize) -> u32 {
    (rax & size.mask()) as u32
}

/// IN or OUT (exit reason 30), for a port the I/O bitmaps intercept: passed
/// through with the port and size from the exit qualification. Not checked
/// against INTERCEPTED_PORTS: an access to several ports exits if any of
/// them is intercepted (`in ax, dx` at 0x3FE covers 0x3FF), and passing
/// that access through is what the guest would have done anyway. String
/// and REP forms, which read or write guest memory, stop the guest.
pub(super) fn io(state: ExitState, exit: &ExitInfo) -> (ExitEvent, ExitState) {
    let io = IoQualification(exit.qualification);
    let Some(size) = io.size() else {
        return (ExitEvent::Unexpected, state);
    };
    if io.is_string() || io.is_rep() {
        return (ExitEvent::Unexpected, state);
    }
    let port = io.port();
    if io.is_in() {
        (
            ExitEvent::Emulated(Emulation::In { port, size }),
            counted(state, |counts| counts.io_in += 1),
        )
    } else {
        let value = out_value(exit.guest_rax, size);
        (
            ExitEvent::Emulated(Emulation::Out { port, size, value }),
            counted(state, |counts| counts.io_out += 1),
        )
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/exit_decision/emulation.rs"]
mod tests;
