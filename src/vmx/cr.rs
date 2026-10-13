//! Access to the x86 control registers (CRx) needed for VMX host state.
//!
//! CR0 controls basic execution modes, including protected mode and paging.
//! CR3 selects the current page-table root (and can carry PCID information).
//! CR4 enables additional CPU features, including VMX through CR4.VMXE.
//! On VM exit, the CPU loads host CR0, CR3, and CR4 from the VMCS, so those
//! fields must describe the environment the host handler will run in.
use core::arch::asm;

/// CR4 bit 12 (LA57): 5-level paging. [`super::paging::walk`] only handles
/// 4 levels.
pub const CR4_LA57: u64 = 1 << 12;

/// CR4 bit 13: VMX-enable. VMXON raises #UD while this is clear.
pub const CR4_VMXE: u64 = 1 << 13;

/// CR4 bit 20 (SMEP): ring 0 may not execute from user pages.
pub const CR4_SMEP: u64 = 1 << 20;

/// CR4 bit 21 (SMAP): ring 0 may not read or write user pages while
/// RFLAGS.AC = 0.
pub const CR4_SMAP: u64 = 1 << 21;

/// Reads CR0.
pub unsafe fn read_cr0() -> u64 {
    let value: u64;

    unsafe {
        asm!(
            "mov {}, cr0",
            out(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }

    value
}

/// Writes CR0.
pub unsafe fn write_cr0(value: u64) {
    unsafe {
        asm!(
            "mov cr0, {}",
            in(reg) value,
            options(nostack, preserves_flags),
        );
    }
}

/// Reads CR3.
pub unsafe fn read_cr3() -> u64 {
    let value: u64;

    unsafe {
        asm!(
            "mov {}, cr3",
            out(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }

    value
}

/// Writes CR3.
pub unsafe fn write_cr3(value: u64) {
    unsafe {
        asm!(
            "mov cr3, {}",
            in(reg) value,
            options(nostack, preserves_flags),
        );
    }
}

/// Reads CR4.
pub unsafe fn read_cr4() -> u64 {
    let value: u64;

    unsafe {
        asm!(
            "mov {}, cr4",
            out(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }

    value
}

/// Writes CR4.
pub unsafe fn write_cr4(value: u64) {
    unsafe {
        asm!(
            "mov cr4, {}",
            in(reg) value,
            options(nostack, preserves_flags),
        );
    }
}

/// Sets CR4.VMXE, leaving every other bit untouched.
pub unsafe fn enable_vmxe() {
    let mut cr4: u64;
    unsafe {
        cr4 = read_cr4();
        cr4 |= CR4_VMXE;
        write_cr4(cr4);
    }
}
