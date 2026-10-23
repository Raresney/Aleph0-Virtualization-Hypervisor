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
//! first VM exit lands here. The handler (`handler.rs`) prints each exit over
//! serial, and `exit_decision::decide` says what it is: an instruction to
//! execute for the guest (CPUID, RDMSR, WRMSR, IN, OUT), or a #GP to inject
//! for an MSR it cannot have or a non-canonical value written to one it can,
//! a write to the EPT-protected data page to allow and retry, a VMCALL to
//! resume past, an NMI to reinject, an NMI window to inject in, the last
//! planned VMCALL, or something unexpected. To resume, the
//! handler updates the VMCS and returns 0, and the stub executes VMRESUME. To
//! stop, it returns a stop value, and the stub jumps back into
//! `vmcs::launch`, which returns to bring-up (see `vmx/vmcs/launch.rs`). The
//! lines that only print live in `report.rs`; how much of each exit they
//! print is `policy.rs`'s decision. Every exit is counted in the vCPU's
//! statistics (`stats.rs`). Every stop adds the guest's state and registers
//! (`dump.rs`), the statistics, and the last exits (`history.rs`).

use core::ptr::NonNull;

use super::page::{PAGE_SIZE, allocate_zeroed_pages};
use super::vmcs::{self, VmcsError};

mod dump;
mod handler;
mod history;
mod policy;
mod report;
mod stats;

pub use stats::{VcpuStats, snapshot as vcpu_stats};

/// Prints the last VM exits, oldest first, each line after `context`: for
/// the panic handler, so a panic in exit context shows what led to it. Like
/// the panic handler, left out of host tests.
#[cfg(not(test))]
pub use history::report as report_exit_history;

/// VMREADs `field` of the current VMCS. For the exit handler and its
/// reports, which run in exit context only.
fn read_field(field: u32) -> Result<u64, VmcsError> {
    // SAFETY: exit context: VMX root operation, with the guest's VMCS
    // current.
    unsafe { vmcs::vmread(field) }
}

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

    /// Top of the downward-growing stack, for HOST_RSP. The x64 calling
    /// convention the entry stub follows needs it 16-byte aligned.
    pub fn top(&self) -> u64 {
        // SAFETY: the allocation is VM_EXIT_STACK_SIZE bytes long, so this is
        // one past its end, which `add` allows.
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
// After the 15 pops RSP is HOST_RSP again, and the failure path pushes the
// same 15 registers, so the same 40 bytes align its call too.
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

    // Reached only if VMRESUME failed; RFLAGS say how. The guest's
    // registers are still live: push them again as a RegisterFrame for the
    // stop's dump. PUSH leaves RFLAGS alone, so PUSHFQ still reads what
    // VMRESUME left. vmresume_failed(rflags = RCX, frame = RDX) returns the
    // stop value in RAX.
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
    pushfq
    pop rcx
    mov rdx, rsp
    sub rsp, 40
    call vmresume_failed
    jmp vmx_return_to_launcher
"#
);

unsafe extern "C" {
    fn vmexit_entry() -> !;
}

/// The address of the entry stub, for HOST_RIP.
pub fn entry_address() -> u64 {
    vmexit_entry as *const () as usize as u64
}
