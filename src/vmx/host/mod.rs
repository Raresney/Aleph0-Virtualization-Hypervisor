//! What Aleph0 runs on in VMX root operation: its own page tables, GDT,
//! TSS and IDT, with interrupt stacks and handlers.
//!
//! A VM exit loads HOST_CR3, HOST_GDTR_BASE, HOST_IDTR_BASE, HOST_TR_BASE
//! and the host selectors from the VMCS. Until now they were the firmware's
//! (a copy of its GDT, in the TSS's case), so the exit handler depended on
//! firmware memory the OS may reuse after `ExitBootServices`, and an NMI or
//! fault in root operation ran a firmware handler. [`HostEnvironment`]
//! replaces all of them:
//!
//! | VMCS field | Built by | Contents |
//! |---|---|---|
//! | HOST_CR3 | `page_tables.rs` | identity map of everything the UEFI memory map reaches |
//! | HOST_GDTR_BASE, selectors | `gdt.rs` | code, data and TSS, at the firmware's selector indices |
//! | HOST_TR_BASE | `host_tables::Tss` | IST1-3: the NMI, #DF and #MC stacks |
//! | HOST_IDTR_BASE | `idt.rs`, `handlers.rs` | 256 gates: NMI to the guest, faults printed |
//!
//! The firmware context does not use any of them: bring-up and the test
//! guest keep the firmware's page tables and IDT and the GDT copy from
//! `host_tables.rs`. Only VM exits switch to these, and teardown switches
//! back (`bring_up::teardown`).
//!
//! The pages come from `page.rs` like every other allocation; moving them to
//! memory the OS keeps is a later step.

mod gdt;
mod handlers;
mod idt;
mod page_tables;

pub use gdt::{FirmwareSelectors, GdtLayoutError};
pub use handlers::{nmi_pending, nmis_taken, take_pending_nmi};
pub use idt::InterruptStack;
pub use page_tables::{HostPageTables, HostPagingError, PageSize};

#[cfg(feature = "host-fault-test")]
pub use handlers::fault_on_purpose;

use core::ptr::NonNull;

use super::cpuid;
use super::cr::read_cr4;
use super::host_tables::{TssError, TssRegion};
use super::page::{PAGE_SIZE, allocate_zeroed_page, allocate_zeroed_pages};
use super::segment::GATE_SIZE;
use super::vmcs::{HostSelectors, HostTables};

/// Pages per interrupt stack. The fault handler formats with `core::fmt`,
/// which needs more than the few hundred bytes the NMI handler does.
pub const INTERRUPT_STACK_PAGES: usize = 2;

/// Why the host environment could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostError {
    Paging(HostPagingError),
    Gdt(GdtLayoutError),
    Tss(TssError),
    /// UEFI could not provide the GDT, IDT or interrupt-stack pages.
    AllocationFailed,
}

impl From<HostPagingError> for HostError {
    fn from(error: HostPagingError) -> Self {
        Self::Paging(error)
    }
}

impl From<TssError> for HostError {
    fn from(error: TssError) -> Self {
        Self::Tss(error)
    }
}

/// Aleph0's root-operation environment. Its pages are never freed: every VM
/// exit loads them.
pub struct HostEnvironment {
    page_tables: HostPageTables,
    gdt: NonNull<u8>,
    gdt_limit: u16,
    selectors: HostSelectors,
    tss: TssRegion,
    idt: NonNull<u8>,
    /// Top of each interrupt stack, in [`InterruptStack::ALL`] order.
    interrupt_stacks: [u64; InterruptStack::ALL.len()],
}

impl HostEnvironment {
    /// Builds the page tables (an identity map of `[0, map_end)`), the
    /// interrupt stacks, the TSS, the GDT that keeps `firmware`'s selectors,
    /// and the IDT.
    ///
    /// # Safety
    ///
    /// Boot services must still be active, and physical memory must be
    /// identity-mapped (as UEFI does), since the tables are written through
    /// their physical addresses.
    pub unsafe fn build(map_end: u64, firmware: FirmwareSelectors) -> Result<Self, HostError> {
        page_tables::check_paging_mode(read_cr4())?;
        let layout = gdt::layout(firmware)?;
        let page_size = PageSize::for_cpu(cpuid::has_1g_pages());
        // SAFETY: the caller guarantees boot services and identity mapping.
        let page_tables = unsafe { HostPageTables::build(map_end, page_size) }?;

        let mut interrupt_stacks = [0; InterruptStack::ALL.len()];
        let mut ist = [0; 7];
        for (stack, top) in InterruptStack::ALL.into_iter().zip(&mut interrupt_stacks) {
            let base = allocate_zeroed_pages(INTERRUPT_STACK_PAGES, HostError::AllocationFailed)?;
            // The CPU aligns RSP down to 16 bytes before it pushes on an IST
            // stack; a page-aligned top already is.
            *top = base.as_ptr() as u64 + (INTERRUPT_STACK_PAGES * PAGE_SIZE) as u64;
            ist[usize::from(stack.ist()) - 1] = *top;
        }
        let tss = TssRegion::allocate_with_interrupt_stacks(ist)?;

        let gdt = allocate_zeroed_page(HostError::AllocationFailed)?;
        // SAFETY: `gdt` is a fresh page, 8-byte aligned, holding exactly
        // `SLOTS` u64s, which nothing else refers to yet.
        gdt::encode(&layout, tss.base(), unsafe {
            &mut *gdt.cast::<[u64; gdt::SLOTS]>().as_ptr()
        });

        let idt = allocate_zeroed_page(HostError::AllocationFailed)?;
        const _: () = assert!(idt::VECTORS * GATE_SIZE == PAGE_SIZE);
        // SAFETY: `idt` is a fresh page, exactly `VECTORS` gates long, which
        // nothing else refers to yet.
        let gates = unsafe { &mut *idt.cast::<[[u8; GATE_SIZE]; idt::VECTORS]>().as_ptr() };
        idt::fill(gates, layout.selectors.cs, handlers::handler_address);

        Ok(Self {
            page_tables,
            gdt,
            gdt_limit: layout.limit,
            selectors: layout.selectors,
            tss,
            idt,
            interrupt_stacks,
        })
    }

    /// The VMCS host fields that come from this environment.
    pub fn vmcs_tables(&self) -> HostTables {
        HostTables {
            cr3: self.page_tables.cr3(),
            gdtr_base: self.gdt_base(),
            idtr_base: self.idt_base(),
            tr_base: self.tss.base(),
            selectors: self.selectors,
        }
    }

    pub fn page_tables(&self) -> &HostPageTables {
        &self.page_tables
    }

    pub fn gdt_base(&self) -> u64 {
        self.gdt.as_ptr() as u64
    }

    /// The GDT limit: through the TSS descriptor.
    pub fn gdt_limit(&self) -> u16 {
        self.gdt_limit
    }

    pub fn selectors(&self) -> HostSelectors {
        self.selectors
    }

    pub fn tss_base(&self) -> u64 {
        self.tss.base()
    }

    pub fn idt_base(&self) -> u64 {
        self.idt.as_ptr() as u64
    }

    /// The top of `stack`, as the TSS holds it.
    pub fn interrupt_stack_top(&self, stack: InterruptStack) -> u64 {
        self.interrupt_stacks[usize::from(stack.ist()) - 1]
    }
}
