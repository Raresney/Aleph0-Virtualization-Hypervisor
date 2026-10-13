//! The 4 KiB regions VMX instructions take by physical address: the VMXON
//! region and each VMCS. Both start with the VMCS revision identifier from
//! IA32_VMX_BASIC and are otherwise left to the CPU.

use super::msr;
use super::page::allocate_zeroed_page;

/// IA32_VMX_BASIC bits 30:0: the revision identifier both regions start with.
const REVISION_ID_MASK: u64 = 0x7FFF_FFFF;

/// The VMCS revision identifier, from IA32_VMX_BASIC bits 30:0.
///
/// # Safety
///
/// The CPU must support VMX, or reading IA32_VMX_BASIC raises #GP.
pub unsafe fn vmcs_revision_id() -> u32 {
    // SAFETY: the caller guarantees VMX support, so the MSR exists.
    (unsafe { msr::rdmsr(msr::IA32_VMX_BASIC) } & REVISION_ID_MASK) as u32
}

/// One zeroed, page-aligned 4 KiB page with the revision identifier in its
/// first four bytes. Never freed: no `Drop`, because the CPU may use the
/// page for as long as VMX operation lasts.
pub struct VmxRegion {
    /// Physical address. Equal to the virtual address under UEFI's identity
    /// mapping.
    phys_addr: u64,
}

impl VmxRegion {
    /// Allocates the page and writes the revision identifier.
    /// `allocation_error` is returned if UEFI has no page.
    ///
    /// # Safety
    ///
    /// The CPU must support VMX (see [`vmcs_revision_id`]).
    pub unsafe fn allocate<E>(allocation_error: E) -> Result<Self, E> {
        let page = allocate_zeroed_page(allocation_error)?;
        // SAFETY: the page is freshly allocated, page-aligned and zeroed, so a
        // u32 write at its start is in bounds and aligned; the CPU does not
        // use it yet. VMX support is the caller's obligation.
        unsafe { page.cast::<u32>().as_ptr().write_volatile(vmcs_revision_id()) };
        Ok(Self {
            phys_addr: page.as_ptr() as u64,
        })
    }

    /// The memory operand VMXON, VMCLEAR and VMPTRLD take: a pointer to the
    /// 64-bit physical address, not the address itself.
    pub fn phys_addr_ref(&self) -> &u64 {
        &self.phys_addr
    }
}
