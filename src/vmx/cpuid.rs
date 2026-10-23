//! CPUID-based feature detection.

use core::arch::x86_64::__cpuid;

/// CPUID leaf whose EAX is the highest extended leaf.
const EXTENDED_MAX: u32 = 0x8000_0000;
/// CPUID leaf of the extended feature flags.
const EXTENDED_FEATURES: u32 = 0x8000_0001;
/// CPUID leaf of the address sizes: EAX bits 7:0 are MAXPHYADDR.
pub const ADDRESS_SIZES: u32 = 0x8000_0008;
/// MAXPHYADDR when CPUID lacks [`ADDRESS_SIZES`]: 36 on a CPU with PAE,
/// which every 64-bit one has (Intel SDM Vol. 3A, "Physical Address
/// Size").
const DEFAULT_PHYSICAL_ADDRESS_BITS: u8 = 36;

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

/// MAXPHYADDR, how many bits a physical address has: CPUID.80000008H:EAX
/// bits 7:0. Physical-address bits from there up are reserved, in page
/// tables as in the MTRRs.
pub fn physical_address_bits() -> u8 {
    if __cpuid(EXTENDED_MAX).eax < ADDRESS_SIZES {
        return DEFAULT_PHYSICAL_ADDRESS_BITS;
    }
    __cpuid(ADDRESS_SIZES).eax as u8
}
