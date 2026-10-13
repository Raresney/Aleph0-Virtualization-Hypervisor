//! VMX (Intel VT-x) support detection.
//!
//! Checking whether the CPU can enter VMX operation requires three
//! independent checks, each gated behind its own stub below:
//!
//! 1. [`cpuid::is_vmx_supported`] — CPUID.1:ECX.VMX\[bit 5\] is set.
//! 2. [`msr::feature_control_vmx_enabled`] — IA32_FEATURE_CONTROL MSR
//!    (0x3A) has the lock bit set and the "VMX outside SMX" bit set.
//! 3. [`detect`] — combines the two checks above into the single entry
//!    point the rest of the hypervisor should call.
//!
//! The CPUID check must run before the MSR check: IA32_FEATURE_CONTROL is
//! only guaranteed to exist on CPUs that support VMX or SMX, so reading it
//! on a CPU that doesn't (per CPUID) risks a #GP with no exception handler
//! installed yet.

pub mod cpuid;
pub mod cr;
pub mod ept;
pub mod exit_decision;
pub mod guest;
pub mod guest_state;
pub mod host_tables;
pub mod instruction;
pub mod msr;
pub mod page;
pub mod paging;
pub mod region;
pub mod segment;
pub mod vmcs;
pub mod vmexit;
pub mod vmxon;

/// Overall VMX support/readiness state for the current CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmxCapabilities {
    /// CPUID reports VMX and IA32_FEATURE_CONTROL allows entering VMX operation.
    Supported,
    /// CPUID does not report the VMX feature bit.
    NotSupportedByCpu,
    /// CPUID reports VMX, but IA32_FEATURE_CONTROL disables it (e.g. locked
    /// by BIOS/firmware with the VMX-outside-SMX bit clear).
    DisabledByFirmware,
}

/// Runs the full VMX support/enablement check.
///
/// Checks CPUID first; the MSR check only runs if CPUID confirms VMX
/// support, since IA32_FEATURE_CONTROL isn't guaranteed to exist otherwise.
pub unsafe fn detect() -> VmxCapabilities {
    if !cpuid::is_vmx_supported() {
        return VmxCapabilities::NotSupportedByCpu;
    }

    let result: VmxCapabilities;
    unsafe {
        if msr::feature_control_vmx_enabled() {
            result = VmxCapabilities::Supported;
        } else {
            result = VmxCapabilities::DisabledByFirmware;
        }
    }

    result
}
