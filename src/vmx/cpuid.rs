//! CPUID-based feature detection.

use core::arch::x86_64::__cpuid;

/// Checks CPUID.1:ECX.VMX\[bit 5\] to determine whether the CPU implements
/// VMX (Intel VT-x).
pub fn is_vmx_supported() -> bool {
    __cpuid(1).ecx >> 5 & 1 == 1
}

/// Checks CPUID.1:EDX.MTRR\[bit 12\]: whether the CPU has memory type range
/// registers. IA32_MTRRCAP and the other MTRR MSRs exist only if it does.
pub fn has_mtrr() -> bool {
    __cpuid(1).edx >> 12 & 1 == 1
}
