//! Entering VMX root operation (VMXON).
//!
//! Order matters; every step is a stub below:
//!
//! 1. [`cr::enable_vmxe`] — set CR4.VMXE. VMXON is #UD without it.
//! 2. [`apply_fixed_bits`] — make CR0/CR4 satisfy `IA32_VMX_CR{0,4}_FIXED{0,1}`.
//!    For each register: `value = (value | fixed0) & fixed1`. VMXON fails
//!    with VmFailInvalid if this is skipped.
//! 3. [`VmxOnRegion::allocate`] — one 4 KiB page, 4 KiB-aligned, zeroed.
//!    `boot::allocate_pages` already guarantees page alignment, and UEFI
//!    identity-maps memory, so the pointer is also the physical address.
//! 4. [`vmcs_revision_id`] — bits 0..=30 of `IA32_VMX_BASIC`, written to
//!    the first 4 bytes of the region via [`VmxOnRegion::write_revision_id`].
//! 5. [`vmxon`] — execute VMXON. The instruction takes a *memory* operand
//!    holding the 64-bit physical address, so pass a pointer to a local
//!    `u64`, not the address itself. Then read RFLAGS:
//!    CF=1 → VmFailInvalid (bad region, alignment or revision id),
//!    ZF=1 → VmFailValid (already in VMX operation, error number 15).
//!
//! [`enter_vmx_root_operation`] runs the sequence end to end, and
//! [`VmxOperation::leave`] undoes it: VMXOFF, then CR0/CR4 as they were.
//!
//! Memory type: `LOADER_DATA` is fine while Boot Services are alive. If the
//! hypervisor is meant to survive `ExitBootServices`, this must become
//! `RUNTIME_SERVICES_DATA` (or a reserved type) so the OS never reclaims it.

use super::cr;
use super::instruction::{VmxFail, check_rflags};
use super::msr;
use super::page::{PAGE_SIZE, allocate_zeroed_page};
use core::arch::asm;

/// VMXON region size. Architecturally at most 4 KiB; one page is the norm.
pub const VMXON_REGION_SIZE: usize = 4096;
const _: () = assert!(VMXON_REGION_SIZE == PAGE_SIZE);

/// A 4 KiB, 4 KiB-aligned region handed to VMXON.
pub struct VmxOnRegion {
    /// Physical address of the region. Equal to the virtual address under UEFI.
    phys_addr: u64,
}

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
    _region: VmxOnRegion,
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
        unsafe {
            vmxoff()?;
            cr::write_cr0(self.original_cr0);
            cr::write_cr4(self.original_cr4);
        }
        Ok(())
    }
}

impl VmxOnRegion {
    /// Allocates and zeroes one page through UEFI Boot Services.
    pub fn allocate() -> Result<Self, VmxOnError> {
        let ptr = allocate_zeroed_page(VmxOnError::AllocationFailed)?;

        Ok(Self {
            phys_addr: ptr.as_ptr() as u64,
        })
    }

    /// Physical address to hand to VMXON.
    pub fn phys_addr_ref(&self) -> &u64 {
        &self.phys_addr
    }

    /// Writes the VMCS revision identifier into the first 4 bytes.
    ///
    /// # Safety
    ///
    /// The region must not be in use by VMXON when it is modified.
    pub unsafe fn write_revision_id(&mut self, revision_id: u32) {
        unsafe {
            (self.phys_addr as *mut u32).write_volatile(revision_id);
        }
    }
}

/// VMCS revision identifier from `IA32_VMX_BASIC` bits 0..=30.
pub unsafe fn vmcs_revision_id() -> u32 {
    unsafe { (msr::rdmsr(msr::IA32_VMX_BASIC) & 0x7FFF_FFFF) as u32 }
}

/// Forces CR0 and CR4 into the ranges the CPU requires for VMX operation.
pub unsafe fn apply_fixed_bits() {
    unsafe {
        let cr0 = (cr::read_cr0() | msr::rdmsr(msr::IA32_VMX_CR0_FIXED0)) & msr::rdmsr(msr::IA32_VMX_CR0_FIXED1);
        let cr4 = (cr::read_cr4() | msr::rdmsr(msr::IA32_VMX_CR4_FIXED0)) & msr::rdmsr(msr::IA32_VMX_CR4_FIXED1);

        cr::write_cr0(cr0);
        cr::write_cr4(cr4);
    }
}

/// Executes VMXON on `region`.
pub unsafe fn vmxon(region: &VmxOnRegion) -> Result<(), VmxOnError> {
    let rflags: u64;
    unsafe {
        asm!(
            "vmxon [{0}]",
            "pushfq",
            "pop {1}",
            in(reg) region.phys_addr_ref(),
            lateout(reg) rflags
        );
    }

    Ok(check_rflags(rflags)?)
}

/// Executes VMXOFF, leaving VMX operation.
unsafe fn vmxoff() -> Result<(), VmxFail> {
    let rflags: u64;
    unsafe {
        asm!(
            "vmxoff",
            "pushfq",
            "pop {0}",
            lateout(reg) rflags
        );
    }

    check_rflags(rflags)
}

/// The returned [`VmxOperation`] keeps the region allocated for as long as
/// the CPU is in VMX operation, and remembers CR0/CR4 for leaving it.
///
/// If VMXON fails, CR0 and CR4 are restored, so CR4.VMXE is not left set
/// outside VMX operation.
pub unsafe fn enter_vmx_root_operation() -> Result<VmxOperation, VmxOnError> {
    unsafe {
        let region_size = (msr::rdmsr(msr::IA32_VMX_BASIC) >> 32) & 0x1fff;
        if region_size == 0 || region_size > PAGE_SIZE as u64 {
            return Err(VmxOnError::UnsupportedRegionSize);
        }

        // Allocate before touching CR0/CR4 so VMXON is the only step that
        // can fail with the control registers modified.
        let mut vmxon_region = VmxOnRegion::allocate()?;
        vmxon_region.write_revision_id(vmcs_revision_id());

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
