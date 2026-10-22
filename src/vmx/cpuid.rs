//! CPUID-based feature detection.

use core::arch::x86_64::__cpuid;

/// CPUID leaf of the extended feature flags.
const EXTENDED_FEATURES: u32 = 0x8000_0001;

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

/// Checks CPUID.80000001H:EDX\[bit 26\] (Page1GB): whether a PDPT entry may
/// map a 1 GiB page. Leaf 0x80000001 exists on every 64-bit CPU, since its
/// EDX bit 29 is what reports long mode.
pub fn has_1g_pages() -> bool {
    __cpuid(EXTENDED_FEATURES).edx >> 26 & 1 == 1
}
