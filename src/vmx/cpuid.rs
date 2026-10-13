//! CPUID-based VMX feature detection.

/// Checks CPUID.1:ECX.VMX\[bit 5\] to determine whether the CPU implements
/// VMX (Intel VT-x).
pub fn is_vmx_supported() -> bool {
    use core::arch::x86_64::__cpuid;
    __cpuid(1).ecx >> 5 & 1 == 1
}
