//! The GDT and TSS the firmware context runs on, and the TSS layout both
//! TSSs share.
//!
//! Firmware may leave TR unset (Hyper-V's does), but the guest state copies
//! TR, and VM entry refuses a guest TR that is not usable. So Aleph0 copies
//! the firmware's GDT into a page of its own, appends a 64-bit TSS
//! descriptor, and loads both ([`GdtRegion::activate`]). Bring-up and the
//! test guest run on them.
//!
//! VMX root operation does not: every VM exit loads Aleph0's own GDT, TSS
//! and IDT (`vmx::host`), whose TSS comes from
//! [`TssRegion::allocate_with_interrupt_stacks`].
//!
//! This TSS's stack fields (RSP0-2, IST1-7) stay 0: the firmware context
//! never changes privilege level, and `activate` refuses an IDT with a gate
//! that would switch to an IST stack.

use crate::vmx::segment::{
    self, DescriptorTable, SegmentDescriptor, descriptor_offset, read_cs, read_gdtr, read_idtr, read_ss, read_tr,
    segment_base_from_gdt, system_descriptor_base,
};
use core::{
    arch::asm,
    ptr::{NonNull, copy_nonoverlapping},
};
use uefi::boot;

use super::page::{PAGE_SIZE, allocate_zeroed_page};
/// The 64-bit TSS. In long mode it holds only stack pointers: RSP0-2 for a
/// change of privilege level, and IST1-7, the stacks an IDT gate can name.
#[repr(C, packed)]
pub(crate) struct Tss {
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

/// Bytes of a [`Tss`]; its descriptor's limit is one less (0x67).
pub(crate) const TSS_SIZE: usize = core::mem::size_of::<Tss>();

const _: () = {
    assert!(TSS_SIZE == 0x68);
    assert!(core::mem::offset_of!(Tss, rsp0) == 0x04);
    assert!(core::mem::offset_of!(Tss, ist1) == 0x24);
    assert!(core::mem::offset_of!(Tss, iomap_base) == 0x66);
};

impl Tss {
    /// A TSS whose IST1-IST7 fields hold `interrupt_stacks` (0 for an unused
    /// one), with RSP0-2 at 0, and the I/O-map base past the limit, so it has
    /// no I/O permission bitmap.
    pub(crate) fn new(interrupt_stacks: [u64; 7]) -> Self {
        let [ist1, ist2, ist3, ist4, ist5, ist6, ist7] = interrupt_stacks;
        Self {
            reserved1: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            reserved2: 0,
            ist1,
            ist2,
            ist3,
            ist4,
            ist5,
            ist6,
            ist7,
            reserved3: 0,
            reserved4: 0,
            iomap_base: TSS_SIZE as u16,
        }
    }
}

/// Why setting up a TSS failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TssError {
    /// UEFI could not allocate the TSS page.
    AllocationFailed,
}

pub struct TssRegion {
    page: NonNull<u8>,
}

impl TssRegion {
    /// Allocate a page that stays live while the CPU may use this TSS, and
    /// write a TSS with no stacks in it ([`Tss::new`]).
    /// Return `TssError::AllocationFailed` if UEFI cannot provide a page.
    pub fn allocate() -> Result<Self, TssError> {
        Self::allocate_with_interrupt_stacks([0; 7])
    }

    /// Like [`allocate`](Self::allocate), with IST1-IST7 set to
    /// `interrupt_stacks`.
    pub fn allocate_with_interrupt_stacks(interrupt_stacks: [u64; 7]) -> Result<Self, TssError> {
        let page = allocate_zeroed_page(TssError::AllocationFailed)?;
        // SAFETY: `page` is a fresh page, larger than a `Tss`, which nothing
        // else refers to yet. The write is unaligned because `Tss` is packed.
        unsafe { page.cast::<Tss>().as_ptr().write_unaligned(Tss::new(interrupt_stacks)) };
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

/// Descriptor byte 5 of an available 64-bit TSS: present (bit 7), DPL 0,
/// S = 0, type 0x9.
const TSS_AVAILABLE_PRESENT: u8 = 0x89;
/// Size of a 64-bit system descriptor (TSS) and of an IDT gate.
const SYSTEM_DESCRIPTOR_SIZE: usize = 16;
/// IDT gate byte 5, bit 7: the gate is present.
const GATE_PRESENT: u8 = 0x80;
/// IDT gate byte 4, bits 2:0: the IST index (0 = no IST).
const GATE_IST_MASK: u8 = 0x07;

/// Encode a present, available 64-bit TSS descriptor (type 0x9, DPL 0)
/// with byte granularity. Only the low 20 bits of `limit` are encodable.
pub(crate) fn tss_descriptor(base: u64, limit: u32) -> [u8; SYSTEM_DESCRIPTOR_SIZE] {
    let mut descriptor = [0u8; SYSTEM_DESCRIPTOR_SIZE];
    descriptor[0..2].copy_from_slice(&(limit as u16).to_le_bytes());
    descriptor[2..4].copy_from_slice(&(base as u16).to_le_bytes());
    descriptor[4] = (base >> 16) as u8;
    descriptor[5] = TSS_AVAILABLE_PRESENT;
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
        // SAFETY: `page` was just allocated and nothing refers to it, so it
        // may be freed; the copy reads the active GDT, which the caller
        // guarantees is readable through its limit, into the page, which it
        // fits (checked first).
        unsafe {
            let descriptor_table = read_gdtr();
            let original_length = descriptor_table.limit as usize + 1;
            let offset = (original_length + 7) & !7;
            if offset + SYSTEM_DESCRIPTOR_SIZE > PAGE_SIZE {
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
            limit: selector + SYSTEM_DESCRIPTOR_SIZE as u16 - 1,
        })
    }

    /// Append an available 64-bit TSS descriptor and return its selector.
    /// This does not load the GDT or change TR; the TSS must remain live when it is loaded.
    pub fn append_tss_descriptor(&mut self, tss_region: &TssRegion) -> Result<u16, GdtError> {
        if self.tss_selector.is_some() {
            return Err(GdtError::AlreadyInstalled);
        }

        let offset = self.original_length.next_multiple_of(8);
        if offset + SYSTEM_DESCRIPTOR_SIZE > PAGE_SIZE {
            return Err(GdtError::TooLarge);
        }

        let descriptor = tss_descriptor(tss_region.base(), (TSS_SIZE - 1) as u32);

        // SAFETY: the 16 bytes at `offset` lie within the GDT page (checked
        // above), which this region owns; the CPU does not use the copy yet.
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
        if selector == 0 || selector & segment::SELECTOR_RPL_TI != 0 || offset + SYSTEM_DESCRIPTOR_SIZE > PAGE_SIZE {
            return false;
        }

        // SAFETY: the descriptor lies within the GDT page (checked above),
        // which this region owns and nothing else writes.
        let descriptor = unsafe { &*self.page.as_ptr().add(offset).cast::<[u8; SYSTEM_DESCRIPTOR_SIZE]>() };
        // G is 0 in a TSS descriptor Aleph0 writes, so this is the raw limit.
        let low = SegmentDescriptor(u64::from_le_bytes(descriptor[..8].try_into().expect("8 bytes")));

        low.limit() == (TSS_SIZE - 1) as u32
            && system_descriptor_base(descriptor) == tss_region.base()
            && descriptor[5] == TSS_AVAILABLE_PRESENT
            && descriptor[6] & 0xF0 == 0
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

        // The selectors in use must name descriptors inside the copied part of
        // the GDT. SS may be null in 64-bit mode.
        let (cs, ss) = (read_cs(), read_ss());
        let copied = DescriptorTable {
            base: self.base(),
            limit: (self.original_length - 1) as u16,
        };
        let ss_is_null = ss & !segment::SELECTOR_RPL == 0;
        if descriptor_offset(&copied, cs, 8).is_none() || !(ss_is_null || descriptor_offset(&copied, ss, 8).is_some()) {
            return Err(GdtError::GdtrPreparationFailed);
        }

        let idtr = read_idtr();
        let idt_length = idtr.limit as usize + 1;
        if idtr.base == 0 || !idt_length.is_multiple_of(SYSTEM_DESCRIPTOR_SIZE) {
            return Err(GdtError::InvalidIdt);
        }
        let idt = idtr.base as *const u8;
        for offset in (0..idt_length).step_by(SYSTEM_DESCRIPTOR_SIZE) {
            // SAFETY: the gate lies within the IDT limit, and the caller
            // guarantees the IDT is readable through it.
            let (ist, attributes) =
                unsafe { (idt.add(offset + 4).read_volatile(), idt.add(offset + 5).read_volatile()) };
            if attributes & GATE_PRESENT != 0 && ist & GATE_IST_MASK != 0 {
                return Err(GdtError::IdtRequiresIst);
            }
        }

        let selector = self.tss_selector.ok_or(GdtError::GdtrPreparationFailed)?;
        // SAFETY: the copied GDT keeps the active CS/SS descriptors (checked
        // above) and holds the verified TSS descriptor at `selector`; the
        // caller keeps both pages live.
        unsafe {
            segment::load_gdtr(&gdtr);
            asm!("ltr {selector:x}", selector = in(reg) selector, options(nostack, preserves_flags));
        }

        let loaded_gdtr = read_gdtr();
        let loaded_tr = read_tr();
        if loaded_gdtr != gdtr || loaded_tr != selector {
            return Err(GdtError::ActivationVerificationFailed);
        }
        // SAFETY: `loaded_gdtr` is the copied GDT (checked above), which this
        // region owns.
        if unsafe { segment_base_from_gdt(&loaded_gdtr, loaded_tr) } != tss_region.base() {
            return Err(GdtError::ActivationVerificationFailed);
        }

        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/unit/vmx/context_tables.rs"]
mod tests;
