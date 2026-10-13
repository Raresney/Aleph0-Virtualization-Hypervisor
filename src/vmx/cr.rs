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

/// Defines a safe reader, and optionally an unsafe writer, for one control
/// register. Reading a control register in ring 0 has no side effects;
/// writing one changes how the CPU runs, so writers stay `unsafe`.
macro_rules! control_register {
    ($read:ident, $write:ident, $register:literal) => {
        control_register!($read, $register);

        #[doc = concat!("Writes ", $register, ".")]
        ///
        /// # Safety
        ///
        /// The new value must keep the CPU in a state the running code can
        /// continue in (paging, protection and VMX fixed bits included).
        pub unsafe fn $write(value: u64) {
            // SAFETY: the caller guarantees the value is valid to load.
            unsafe { asm!(concat!("mov ", $register, ", {}"), in(reg) value, options(nostack, preserves_flags)) };
        }
    };
    ($read:ident, $register:literal) => {
        #[doc = concat!("Reads ", $register, ".")]
        pub fn $read() -> u64 {
            let value: u64;
            // SAFETY: a read of a control register in ring 0: no memory
            // access, no side effects.
            unsafe { asm!(concat!("mov {}, ", $register), out(reg) value, options(nomem, nostack, preserves_flags)) };
            value
        }
    };
}

control_register!(read_cr0, write_cr0, "cr0");
control_register!(read_cr3, "cr3");
control_register!(read_cr4, write_cr4, "cr4");

/// Sets CR4.VMXE, leaving every other bit untouched.
///
/// # Safety
///
/// The CPU must support VMX (CPUID.1:ECX.VMX); otherwise the write faults.
pub unsafe fn enable_vmxe() {
    // SAFETY: only VMXE changes, which the caller has checked is supported.
    unsafe { write_cr4(read_cr4() | CR4_VMXE) };
}
