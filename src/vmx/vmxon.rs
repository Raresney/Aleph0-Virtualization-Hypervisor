//! Entering and leaving VMX root operation.
//!
//! [`enter_vmx_root_operation`] checks the region size IA32_VMX_BASIC
//! asks for, allocates the VMXON region (`region::VmxRegion`), sets
//! CR4.VMXE and the CR0/CR4 bits VMX operation fixes, and executes VMXON.
//! [`VmxOperation::leave`] undoes it: VMXOFF, then CR0/CR4 as they were.
//!
//! VMXON takes a memory operand holding the region's physical address,
//! and reports failure through RFLAGS: CF = 1 is VmFailInvalid (bad region,
//! alignment or revision identifier), ZF = 1 is VmFailValid (already in VMX
//! operation, error number 15).
//!
//! The region is resident (`page::RESIDENT_DATA`): the CPU uses it for as
//! long as VMX operation lasts, after `ExitBootServices` too, so the OS must
//! never reclaim it.

use super::cr;
use super::instruction::{VmxFail, vmx_asm};
use super::msr;
use super::page::PAGE_SIZE;
use super::region::VmxRegion;

/// Why entering VMX operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmxOnError {
    /// UEFI could not provide a page.
    AllocationFailed,
    /// IA32_VMX_BASIC reports a VMX region size outside the allocated page.
    UnsupportedRegionSize,
    /// VMXON reported VmFailInvalid (CF=1).
    VmFailInvalid,
    /// VMXON reported VmFailValid (ZF=1): typically already in VMX operation.
    VmFailValid,
}

impl From<VmxFail> for VmxOnError {
    fn from(fail: VmxFail) -> Self {
        match fail {
            VmxFail::Invalid => Self::VmFailInvalid,
            VmxFail::Valid => Self::VmFailValid,
        }
    }
}

/// VMX root operation, entered by [`enter_vmx_root_operation`]: the VMXON
/// region the CPU uses meanwhile, and CR0/CR4 from before VMXON, which
/// [`VmxOperation::leave`] restores.
///
/// No `Drop`: the region must stay allocated while the CPU is in VMX
/// operation, and leaving should follow a VMCLEAR, which only the owner of
/// the VMCS can do.
pub struct VmxOperation {
    _region: VmxRegion,
    original_cr0: u64,
    original_cr4: u64,
}

impl VmxOperation {
    /// Executes VMXOFF, then restores CR0 and CR4 to their values before
    /// VMXON, which clears CR4.VMXE.
    ///
    /// If VMXOFF fails, the CPU is still in VMX operation, so CR0 and CR4
    /// stay as they are: clearing CR4.VMXE in VMX operation raises #GP, and
    /// CR0 must keep the bits VMX operation fixes.
    ///
    /// # Safety
    ///
    /// Every VMCS used on this CPU should be cleared with VMCLEAR first, so
    /// the CPU writes its data back to memory. If one was not (its VMCLEAR
    /// failed), only that VMCS's memory is stale, which is harmless while its
    /// region is never reused. No VMX instruction may run after this
    /// succeeds.
    pub unsafe fn leave(self) -> Result<(), VmxFail> {
        // SAFETY: this value exists only after VMXON succeeded, so the CPU
        // is in VMX root operation; the caller guarantees no VMX instruction
        // follows. CR0/CR4 get back the values the code ran with before
        // VMXON, legal again once VMX operation has ended.
        unsafe {
            vmxoff()?;
            cr::write_cr0(self.original_cr0);
            cr::write_cr4(self.original_cr4);
        }
        Ok(())
    }
}

/// Forces CR0 and CR4 into the ranges the CPU requires for VMX operation.
///
/// # Safety
///
/// The CPU must support VMX (the FIXED MSRs exist only then), and the
/// running code must keep working with the bits VMX operation forces (in
/// practice CR0.PE, CR0.PG, CR0.NE and CR4.VMXE, which UEFI already has, or
/// does not mind).
pub unsafe fn apply_fixed_bits() {
    // SAFETY: the caller guarantees VMX support, so the FIXED MSRs exist,
    // and that the running code can go on with the bits they force.
    unsafe {
        let cr0 = (cr::read_cr0() | msr::rdmsr(msr::IA32_VMX_CR0_FIXED0)) & msr::rdmsr(msr::IA32_VMX_CR0_FIXED1);
        let cr4 = (cr::read_cr4() | msr::rdmsr(msr::IA32_VMX_CR4_FIXED0)) & msr::rdmsr(msr::IA32_VMX_CR4_FIXED1);

        cr::write_cr0(cr0);
        cr::write_cr4(cr4);
    }
}

/// Executes VMXON on `region`.
///
/// # Safety
///
/// CR4.VMXE and the fixed CR0/CR4 bits must be set, and `region` must stay
/// allocated for as long as VMX operation lasts.
pub unsafe fn vmxon(region: &VmxRegion) -> Result<(), VmxOnError> {
    // SAFETY: VMXON reads only the 8-byte operand; the caller guarantees the
    // CR0/CR4 state VMXON needs and the region's lifetime.
    Ok(unsafe { vmx_asm!("vmxon [{0}]", in(reg) region.phys_addr_ref()) }?)
}

/// Executes VMXOFF, leaving VMX operation.
///
/// # Safety
///
/// The CPU must be in VMX root operation, and no VMX instruction may run
/// after this succeeds.
unsafe fn vmxoff() -> Result<(), VmxFail> {
    // SAFETY: the caller guarantees VMX root operation, so VMXOFF cannot #UD.
    unsafe { vmx_asm!("vmxoff") }
}

/// The returned [`VmxOperation`] keeps the region allocated for as long as
/// the CPU is in VMX operation, and remembers CR0/CR4 for leaving it.
///
/// If VMXON fails, CR0 and CR4 are restored, so CR4.VMXE is not left set
/// outside VMX operation.
///
/// # Safety
///
/// The CPU must support VMX with IA32_FEATURE_CONTROL allowing it outside
/// SMX ([`super::detect`]), and must not be in VMX operation already.
pub unsafe fn enter_vmx_root_operation() -> Result<VmxOperation, VmxOnError> {
    // SAFETY: the caller guarantees VMX support and that this CPU is not
    // in VMX operation yet. CR0/CR4 change only to what VMXON needs, and
    // go back if it fails; the region outlives VMX operation, since
    // `VmxOperation` owns it.
    unsafe {
        let region_size = (msr::rdmsr(msr::IA32_VMX_BASIC) >> 32) & 0x1fff;
        if region_size == 0 || region_size > PAGE_SIZE as u64 {
            return Err(VmxOnError::UnsupportedRegionSize);
        }

        // Allocate before touching CR0/CR4 so VMXON is the only step that
        // can fail with the control registers modified.
        let vmxon_region = VmxRegion::allocate(VmxOnError::AllocationFailed)?;

        let (original_cr0, original_cr4) = (cr::read_cr0(), cr::read_cr4());
        cr::enable_vmxe();
        apply_fixed_bits();
        if let Err(error) = vmxon(&vmxon_region) {
            cr::write_cr0(original_cr0);
            cr::write_cr4(original_cr4);
            return Err(error);
        }
        Ok(VmxOperation {
            _region: vmxon_region,
            original_cr0,
            original_cr4,
        })
    }
}
