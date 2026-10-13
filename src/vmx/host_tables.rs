//! Host descriptor tables for a future VMX guest launch.
//!
//! TODO:
//! - Provide RSP0/IST stacks if the host IDT or privilege transitions will
//!   use them; the TSS currently has zeroed stack fields.

use crate::vmx::segment::{DescriptorTable, read_cs, read_gdtr, read_idtr, read_ss, read_tr, segment_base_from_gdt};
use core::{
    arch::asm,
    ptr::{self, NonNull, copy_nonoverlapping},
};
use uefi::boot;

use super::page::{PAGE_SIZE, allocate_zeroed_page};
#[repr(C, packed)]
struct Tss {
    reserved1: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    reserved2: u64,
    ist1: u64,
    ist2: u64,
    ist3: u64,
    ist4: u64,
    ist5: u64,
    ist6: u64,
    ist7: u64,
    reserved3: u64,
    reserved4: u16,
    iomap_base: u16,
}

const _: () = {
    assert!(core::mem::size_of::<Tss>() == 0x68);
    assert!(core::mem::offset_of!(Tss, rsp0) == 0x04);
    assert!(core::mem::offset_of!(Tss, ist1) == 0x24);
    assert!(core::mem::offset_of!(Tss, iomap_base) == 0x66);
};

/// Why setting up the host TSS failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TssError {
    /// UEFI could not allocate the TSS page.
    AllocationFailed,
}

pub struct TssRegion {
    page: NonNull<u8>,
}

impl TssRegion {
    /// Allocate a page that stays live while the CPU may use this TSS.
    /// Initialize the TSS to zero and set its I/O-map base past the TSS limit.
    /// Return `TssError::AllocationFailed` if UEFI cannot provide a page.
    pub fn allocate() -> Result<Self, TssError> {
        let page = allocate_zeroed_page(TssError::AllocationFailed)?;
        let tss = page.cast::<Tss>().as_ptr();
        unsafe {
            ptr::addr_of_mut!((*tss).iomap_base).write_unaligned(core::mem::size_of::<Tss>() as u16);
        }
        Ok(Self { page })
    }

    /// Return the TSS linear address for its GDT descriptor and VMCS host state.
    pub fn base(&self) -> u64 {
        self.page.as_ptr() as u64
    }
}

/// Why setting up the host GDT failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GdtError {
    /// UEFI could not allocate the GDT page.
    AllocationFailed,
    /// The current GDT plus alignment and a 16-byte TSS descriptor cannot fit in one page.
    TooLarge,
    /// The active GDTR has a null base address.
    InvalidSource,
    /// A TSS descriptor has already been appended to this GDT.
    AlreadyInstalled,
    /// The TSS descriptor could not be verified after being appended.
    TssVerificationFailed,
    /// The prepared GDTR could not be verified after appending the TSS descriptor.
    GdtrPreparationFailed,
    /// The active IDT is missing or does not contain complete 16-byte gates.
    InvalidIdt,
    /// A present IDT gate needs an IST stack, but the host TSS has none.
    IdtRequiresIst,
    /// The CPU state did not match the prepared GDT and TSS after loading them.
    ActivationVerificationFailed,
}

/// Encode a present, available 64-bit TSS descriptor (type 0x9, DPL 0)
/// with byte granularity. Only the low 20 bits of `limit` are encodable.
fn tss_descriptor(base: u64, limit: u32) -> [u8; 16] {
    let mut descriptor = [0u8; 16];
    descriptor[0..2].copy_from_slice(&(limit as u16).to_le_bytes());
    descriptor[2..4].copy_from_slice(&(base as u16).to_le_bytes());
    descriptor[4] = (base >> 16) as u8;
    descriptor[5] = 0x89;
    descriptor[6] = ((limit >> 16) & 0x0f) as u8;
    descriptor[7] = (base >> 24) as u8;
    descriptor[8..12].copy_from_slice(&((base >> 32) as u32).to_le_bytes());
    descriptor
}

pub struct GdtRegion {
    page: NonNull<u8>,
    original_length: usize,
    tss_selector: Option<u16>,
}

impl GdtRegion {
    /// # Safety
    ///
    /// The active GDTR must describe readable memory for `limit + 1` bytes,
    /// and that table must remain stable while it is copied.
    pub unsafe fn copy_active() -> Result<Self, GdtError> {
        let page = allocate_zeroed_page(GdtError::AllocationFailed)?;
        unsafe {
            let descriptor_table = read_gdtr();
            let original_length = descriptor_table.limit as usize + 1;
            let offset = (original_length + 7) & !7;
            if offset + 16 > PAGE_SIZE {
                boot::free_pages(page, 1).expect("failed to free oversized GDT page");
                return Err(GdtError::TooLarge);
            }
            if descriptor_table.base == 0 {
                boot::free_pages(page, 1).expect("failed to free unused GDT page");
                return Err(GdtError::InvalidSource);
            }

            copy_nonoverlapping(descriptor_table.base as *const u8, page.as_ptr(), original_length);

            Ok(Self {
                page,
                original_length,
                tss_selector: None,
            })
        }
    }

    /// Return the linear address of the copied GDT.
    pub fn base(&self) -> u64 {
        self.page.as_ptr() as u64
    }

    /// Return the copied GDT's base and limit once its TSS descriptor exists.
    pub fn prepared_gdtr(&self) -> Option<DescriptorTable> {
        let selector = self.tss_selector?;
        Some(DescriptorTable {
            base: self.base(),
            limit: selector + 15,
        })
    }

    /// Append an available 64-bit TSS descriptor and return its selector.
    /// This does not load the GDT or change TR; the TSS must remain live when it is loaded.
    pub fn append_tss_descriptor(&mut self, tss_region: &TssRegion) -> Result<u16, GdtError> {
        if self.tss_selector.is_some() {
            return Err(GdtError::AlreadyInstalled);
        }

        let offset = self.original_length.next_multiple_of(8);
        if offset + 16 > PAGE_SIZE {
            return Err(GdtError::TooLarge);
        }

        let descriptor = tss_descriptor(tss_region.base(), (core::mem::size_of::<Tss>() - 1) as u32);

        unsafe {
            copy_nonoverlapping(descriptor.as_ptr(), self.page.as_ptr().add(offset), descriptor.len());
        }

        let selector = offset as u16;
        self.tss_selector = Some(selector);
        Ok(selector)
    }

    /// Check the TSS descriptor in the copied GDT before it is loaded.
    pub fn verify_tss_descriptor(&self, tss_region: &TssRegion) -> bool {
        let Some(selector) = self.tss_selector else {
            return false;
        };
        let offset = selector as usize;
        if selector == 0 || selector & 7 != 0 || offset + 16 > PAGE_SIZE {
            return false;
        }

        let descriptor = unsafe { core::slice::from_raw_parts(self.page.as_ptr().add(offset), 16) };
        let limit = u16::from_le_bytes([descriptor[0], descriptor[1]]) as u32 | (((descriptor[6] & 0x0f) as u32) << 16);
        let base = u16::from_le_bytes([descriptor[2], descriptor[3]]) as u64
            | ((descriptor[4] as u64) << 16)
            | ((descriptor[7] as u64) << 24)
            | ((u32::from_le_bytes([descriptor[8], descriptor[9], descriptor[10], descriptor[11]]) as u64) << 32);

        limit == (core::mem::size_of::<Tss>() - 1) as u32
            && base == tss_region.base()
            && descriptor[5] == 0x89
            && descriptor[6] & 0xf0 == 0
            && descriptor[12..16] == [0; 4]
    }

    /// Check the active tables, load this GDT and TSS, and verify the CPU state.
    ///
    /// # Safety
    ///
    /// The GDT and TSS must remain live while the CPU uses them. The caller
    /// must ensure the active selectors and IDT remain usable after the switch.
    /// The active IDT must be readable and stable through its reported limit
    /// while its gates are inspected. Call only once: LTR marks the TSS
    /// descriptor busy, so the pre-load verifier will reject a second call.
    /// If post-load verification fails, the CPU still uses the new tables.
    pub unsafe fn activate(&self, tss_region: &TssRegion) -> Result<(), GdtError> {
        if !self.verify_tss_descriptor(tss_region) {
            return Err(GdtError::TssVerificationFailed);
        }
        let gdtr = self.prepared_gdtr().ok_or(GdtError::GdtrPreparationFailed)?;

        let (cs, ss) = unsafe { (read_cs(), read_ss()) };

        let cs_offset = (cs & !7) as usize;
        let ss_offset = (ss & !7) as usize;
        if cs & 0x4 != 0
            || ss & 0x4 != 0
            || cs_offset == 0
            || cs_offset + 8 > self.original_length
            || (ss_offset != 0 && ss_offset + 8 > self.original_length)
        {
            return Err(GdtError::GdtrPreparationFailed);
        }

        let idtr = unsafe { read_idtr() };
        let idt_length = idtr.limit as usize + 1;
        if idtr.base == 0 || !idt_length.is_multiple_of(16) {
            return Err(GdtError::InvalidIdt);
        }
        let idt = idtr.base as *const u8;
        for offset in (0..idt_length).step_by(16) {
            let (ist, attributes) =
                unsafe { (idt.add(offset + 4).read_volatile(), idt.add(offset + 5).read_volatile()) };
            if attributes & 0x80 != 0 && ist & 0x07 != 0 {
                return Err(GdtError::IdtRequiresIst);
            }
        }

        let mut gdtr_operand = [0u8; 10];
        gdtr_operand[..2].copy_from_slice(&gdtr.limit.to_le_bytes());
        gdtr_operand[2..].copy_from_slice(&gdtr.base.to_le_bytes());

        let selector = self.tss_selector.ok_or(GdtError::GdtrPreparationFailed)?;
        unsafe {
            asm!(
                "lgdt [{operand}]",
                "ltr {selector:x}",
                operand = in(reg) gdtr_operand.as_ptr(),
                selector = in(reg) selector,
                options(nostack, preserves_flags),
            );
        }

        let loaded_gdtr = unsafe { read_gdtr() };
        let loaded_tr = unsafe { read_tr() };
        if loaded_gdtr.base != gdtr.base
            || loaded_gdtr.limit != gdtr.limit
            || loaded_tr != selector
            || unsafe { segment_base_from_gdt(&loaded_gdtr, loaded_tr) } != tss_region.base()
        {
            return Err(GdtError::ActivationVerificationFailed);
        }

        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/unit/vmx/host_tables.rs"]
mod tests;
