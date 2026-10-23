//! The MSR bitmap and the two I/O bitmaps: which guest RDMSR/WRMSR and
//! IN/OUT exit to Aleph0.
//!
//! With "use MSR bitmaps" (primary control bit 28) RDMSR/WRMSR exit only for
//! MSRs whose bit is set, and with "use I/O bitmaps" (bit 25) IN/OUT exit
//! only for ports whose bit is set. Everything else reaches the hardware
//! directly. That is a correct passthrough even for MSRs whose guest value
//! is a VMCS field: while the guest runs, the CPU holds the guest's value.
//!
//! ```text
//! MSR bitmap, one 4 KiB page (Intel SDM Vol. 3C, "MSR-Bitmap Address"):
//! offset 0x000  read,  MSR 0x00000000..=0x00001FFF
//! offset 0x400  read,  MSR 0xC0000000..=0xC0001FFF
//! offset 0x800  write, MSR 0x00000000..=0x00001FFF
//! offset 0xC00  write, MSR 0xC0000000..=0xC0001FFF
//! RDMSR/WRMSR of any other MSR always exits.
//!
//! I/O bitmaps, one bit per port:
//! A (one page): ports 0x0000..=0x7FFF    B (one page): ports 0x8000..=0xFFFF
//! An access to several ports exits if any of their bits is set.
//! ```

use core::ptr::NonNull;

use super::guest::GUEST_SCRATCH_PORT;
use super::msr::{
    IA32_BNDCFGS, IA32_DEBUGCTL, IA32_EFER, IA32_FS_BASE, IA32_GS_BASE, IA32_KERNEL_GS_BASE, IA32_PAT,
    IA32_PERF_GLOBAL_CTRL, IA32_SYSENTER_CS, IA32_SYSENTER_EIP, IA32_SYSENTER_ESP,
};
use super::mtrr;
use super::page::{PAGE_SIZE, allocate_zeroed_page};
use super::vmcs::fields::{IO_BITMAP_A, IO_BITMAP_B, MSR_BITMAP};
use super::vmcs::{self, VmcsError};

/// MSRs whose RDMSR and WRMSR exit to Aleph0, which passes them through: it
/// runs a real RDMSR/WRMSR in root operation, which reaches the CPU's own
/// MSR, so none may be in [`VMCS_HELD_MSRS`] (checked at compile time
/// below).
///
/// The MTRR MSRs exit too ([`ExitBitmaps::allocate`]), but are never
/// passed through: the guest reads and writes a copy of them
/// (`vmexit::guest_mtrrs`), since the CPU's still set the memory types of
/// Aleph0's own accesses. Every address an MTRR can have exits
/// ([`mtrr::every_msr_address`]), not only those the CPU has, so the guest
/// gets #GP for the others from Aleph0 rather than from whatever the CPU
/// holds there.
pub const INTERCEPTED_MSRS: [u32; 1] = [IA32_KERNEL_GS_BASE];

/// Ports whose IN and OUT exit to Aleph0.
pub const INTERCEPTED_PORTS: [u16; 1] = [GUEST_SCRATCH_PORT];

/// MSRs whose guest value is a VMCS guest-state field. In root operation a
/// real RDMSR/WRMSR reaches the host's value, not the guest's, so an
/// emulated access to one would read or overwrite the wrong value.
const VMCS_HELD_MSRS: [u32; 10] = [
    IA32_DEBUGCTL,
    IA32_SYSENTER_CS,
    IA32_SYSENTER_ESP,
    IA32_SYSENTER_EIP,
    IA32_PAT,
    IA32_PERF_GLOBAL_CTRL,
    IA32_BNDCFGS,
    IA32_EFER,
    IA32_FS_BASE,
    IA32_GS_BASE,
];

// Every intercepted MSR has a bitmap bit, and none is held in the VMCS.
const _: () = {
    let mut i = 0;
    while i < INTERCEPTED_MSRS.len() {
        assert!(msr_bit(INTERCEPTED_MSRS[i], MsrAccess::Read).is_some());
        let mut j = 0;
        while j < VMCS_HELD_MSRS.len() {
            assert!(
                INTERCEPTED_MSRS[i] != VMCS_HELD_MSRS[j],
                "an intercepted MSR is held in the VMCS"
            );
            j += 1;
        }
        i += 1;
    }
};

/// Which half of the MSR bitmap: RDMSR or WRMSR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsrAccess {
    Read,
    Write,
}

/// Where `msr`'s bit for `access` is in the MSR bitmap: (byte offset in the
/// page, bit in that byte). `None` for MSRs outside the two ranges the
/// bitmap covers, whose RDMSR and WRMSR always exit.
pub const fn msr_bit(msr: u32, access: MsrAccess) -> Option<(usize, u8)> {
    let (read_offset, index) = match msr {
        0..=0x1FFF => (0x000, msr),
        0xC000_0000..=0xC000_1FFF => (0x400, msr - 0xC000_0000),
        _ => return None,
    };
    let offset = match access {
        MsrAccess::Read => read_offset,
        MsrAccess::Write => read_offset + 0x800,
    };
    Some((offset + index as usize / 8, (index % 8) as u8))
}

/// Which I/O bitmap page a port is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoBitmap {
    /// Ports 0x0000–0x7FFF.
    A,
    /// Ports 0x8000–0xFFFF.
    B,
}

/// Where `port`'s bit is: (page, byte offset in it, bit in that byte).
pub const fn io_bit(port: u16) -> (IoBitmap, usize, u8) {
    let page = if port < 0x8000 { IoBitmap::A } else { IoBitmap::B };
    let index = (port & 0x7FFF) as usize;
    (page, index / 8, (port % 8) as u8)
}

/// Sets the bits of [`INTERCEPTED_MSRS`] and of every address an MTRR MSR
/// can have (read and write), and of [`INTERCEPTED_PORTS`], in zeroed
/// bitmap pages.
fn fill(msr: &mut [u8], io_a: &mut [u8], io_b: &mut [u8]) {
    for intercepted in INTERCEPTED_MSRS.into_iter().chain(mtrr::every_msr_address()) {
        for access in [MsrAccess::Read, MsrAccess::Write] {
            // Always `Some`: checked at compile time above, and every MTRR
            // MSR is below 0x300.
            if let Some((offset, bit)) = msr_bit(intercepted, access) {
                msr[offset] |= 1 << bit;
            }
        }
    }
    for port in INTERCEPTED_PORTS {
        let (page, offset, bit) = io_bit(port);
        let page = match page {
            IoBitmap::A => &mut *io_a,
            IoBitmap::B => &mut *io_b,
        };
        page[offset] |= 1 << bit;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitBitmapsError {
    /// UEFI could not provide a bitmap page.
    AllocationFailed,
}

/// The three bitmap pages. Never freed: the CPU reads them on every guest
/// RDMSR, WRMSR, IN and OUT for as long as the VMCS points at them.
pub struct ExitBitmaps {
    msr: NonNull<u8>,
    io_a: NonNull<u8>,
    io_b: NonNull<u8>,
}

impl ExitBitmaps {
    /// Allocates three zeroed pages and sets the intercepted bits: those of
    /// [`INTERCEPTED_MSRS`], of every address an MTRR MSR can have, and of
    /// [`INTERCEPTED_PORTS`].
    pub fn allocate() -> Result<Self, ExitBitmapsError> {
        let page = || allocate_zeroed_page(ExitBitmapsError::AllocationFailed);
        let bitmaps = Self {
            msr: page()?,
            io_a: page()?,
            io_b: page()?,
        };
        // SAFETY: three separate fresh allocations of one zeroed page each,
        // which nothing else refers to while these slices live.
        let (msr, io_a, io_b) = unsafe {
            (
                core::slice::from_raw_parts_mut(bitmaps.msr.as_ptr(), PAGE_SIZE),
                core::slice::from_raw_parts_mut(bitmaps.io_a.as_ptr(), PAGE_SIZE),
                core::slice::from_raw_parts_mut(bitmaps.io_b.as_ptr(), PAGE_SIZE),
            )
        };
        fill(msr, io_a, io_b);
        Ok(bitmaps)
    }

    /// Physical address of the MSR bitmap. UEFI identity-maps memory, so it
    /// is the page's address.
    pub fn msr_address(&self) -> u64 {
        self.msr.as_ptr() as u64
    }

    /// Physical address of I/O bitmap A.
    pub fn io_a_address(&self) -> u64 {
        self.io_a.as_ptr() as u64
    }

    /// Physical address of I/O bitmap B.
    pub fn io_b_address(&self) -> u64 {
        self.io_b.as_ptr() as u64
    }

    /// Writes the three addresses to the current VMCS and reads them back.
    ///
    /// # Safety
    ///
    /// VMX root operation with a current VMCS. The pages must stay allocated
    /// for as long as that VMCS can be entered (they are never freed).
    pub unsafe fn write_to_vmcs(&self) -> Result<(), VmcsError> {
        // SAFETY: the caller guarantees VMX root operation with a current
        // VMCS; the pages are never freed.
        unsafe {
            vmcs::write_verified(MSR_BITMAP, self.msr_address())?;
            vmcs::write_verified(IO_BITMAP_A, self.io_a_address())?;
            vmcs::write_verified(IO_BITMAP_B, self.io_b_address())?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/unit/vmx/exit_bitmaps.rs"]
mod tests;
