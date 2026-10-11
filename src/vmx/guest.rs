//! Guest memory: one code page, one stack page and one IDT page.
//!
//! The guest's instructions are assembled into the `.efi` image between
//! `guest_code_start` and `guest_code_end`, then copied into a page of their
//! own, so the guest never executes from host code pages. The copy only
//! works because the code is position-independent: no absolute addresses,
//! only relative jumps.
//!
//! Guest RIP is [`GuestMemory::code_base`], guest RSP
//! [`GuestMemory::stack_top`], and guest IDTR [`GuestMemory::idt`];
//! `GuestState::write` (in `guest_state`) writes them to the VMCS.
//! [`GuestMemory::check_mappings`] confirms that the current page tables,
//! which the guest shares, map the code page executable, the stack page
//! writable, and the IDT page readable for the ring-0 guest.
//!
//! The guest has its own IDT because Aleph0 reinjects NMIs into it: the
//! firmware's IDT would run the firmware's default NMI handler, which
//! dead-loops. Only vector 2 (NMI) is present. Every exception exits to
//! Aleph0 before it reaches the IDT (exception bitmap all ones), and the
//! guest runs with IF = 0, so no other vector is ever delivered through it.

use core::ptr::NonNull;

use uefi::boot::MemoryType;

use super::cr::{self, read_cr4};
use super::page::{allocate_zeroed_pages_of_type, PAGE_SIZE};
use super::paging::{self, Mapping, WalkError};
use super::segment::{self, DescriptorTable};

/// Value the guest loads into EAX before its first main VMCALL.
///
/// The VM-exit handler prints the guest's RAX, so seeing this value on
/// serial shows the guest's own instructions ran, not just that an exit
/// happened. `mov eax` zero-extends, so RAX reads back as this value. The
/// guest adds one before its second main VMCALL, so that exit shows
/// `GUEST_MARKER + 1`.
pub const GUEST_MARKER: u32 = 0xA1E0;

/// Value the guest's NMI handler loads into EAX before its VMCALL: "NMI" in
/// ASCII. The main code's RAX is only ever `GUEST_MARKER` or
/// `GUEST_MARKER + 1`, so the exit handler can tell the VMCALLs apart.
pub const GUEST_NMI_MARKER: u32 = 0x004E_4D49;

/// Rounds of the guest's wait loop (test, pause, decrement) before it gives
/// up waiting for an NMI. Aimed at several seconds; PAUSE takes a different
/// number of cycles on each CPU generation, so the Hyper-V run measures the
/// real time.
pub const GUEST_WAIT_ITERATIONS: u32 = 0x2000_0000;

core::arch::global_asm!(
    r#"
    .globl guest_code_start
    .globl guest_nmi_handler
    .globl guest_code_end
guest_code_start:
    // No NMI handled yet. General-purpose registers are not VMCS fields, so
    // without this EBX would hold whatever the host had at VMLAUNCH.
    xor ebx, ebx
    mov eax, {marker}
    vmcall
    // Main VMCALL #1 is done and Aleph0 advanced RIP past it. Wait for an
    // NMI: the handler below sets EBX. Give up after a fixed number of
    // rounds, so a run without an NMI still ends.
    mov ecx, {iterations}
guest_wait:
    test ebx, ebx
    jnz guest_wait_done
    pause
    dec ecx
    jnz guest_wait
guest_wait_done:
    // Main VMCALL #2: RAX one higher shows the code after VMCALL #1 ran,
    // and EBX says whether an NMI was handled.
    inc eax
    vmcall
    // Aleph0 stops the guest at main VMCALL #2. If it ever resumed it, UD2
    // turns that into an exception exit instead of running into the handler.
    ud2
guest_nmi_handler:
    // Vector 2 of the guest IDT. Tell Aleph0 the reinjected NMI arrived,
    // keeping the main code's RAX intact.
    push rax
    mov eax, {nmi_marker}
    vmcall
    pop rax
    mov ebx, 1
    // IRETQ restores RIP, CS, RFLAGS, RSP and SS only, so EBX stays set for
    // the wait loop. With virtual NMIs on, it also ends the guest's NMI
    // blocking.
    iretq
guest_code_end:
"#,
    marker = const GUEST_MARKER,
    iterations = const GUEST_WAIT_ITERATIONS,
    nmi_marker = const GUEST_NMI_MARKER,
);

unsafe extern "C" {
    static guest_code_start: u8;
    static guest_nmi_handler: u8;
    static guest_code_end: u8;
}

/// The guest's instruction bytes, as assembled into the image.
fn guest_code() -> &'static [u8] {
    let start = &raw const guest_code_start;
    let end = &raw const guest_code_end;
    // Both labels come from the one asm block above, start before end.
    unsafe { core::slice::from_raw_parts(start, end.offset_from(start) as usize) }
}

/// Offset of `guest_nmi_handler` from the start of the guest code, which is
/// also its offset in the code page after the copy.
fn nmi_handler_offset() -> usize {
    let start = &raw const guest_code_start;
    let handler = &raw const guest_nmi_handler;
    // Both labels come from the one asm block above, start before handler.
    unsafe { handler.offset_from(start) as usize }
}

/// IDT vector of NMI.
const NMI_VECTOR: usize = 2;
/// Size of one 64-bit IDT gate.
const GATE_SIZE: usize = 16;
/// GUEST_IDTR limit: three gates, vectors 0 to 2. Only vector 2 is present.
const GUEST_IDT_LIMIT: u16 = (3 * GATE_SIZE - 1) as u16;

/// A 64-bit interrupt gate to `handler` through code segment `selector`:
/// present, DPL 0, no IST.
///
/// ```text
/// bytes 0-1    handler bits 15:0
/// bytes 2-3    code segment selector
/// byte  4      IST index: 0, use the current stack
/// byte  5      0x8E: present, DPL 0, type 0xE (64-bit interrupt gate)
/// bytes 6-7    handler bits 31:16
/// bytes 8-11   handler bits 63:32
/// bytes 12-15  reserved, 0
/// ```
fn interrupt_gate(handler: u64, selector: u16) -> [u8; GATE_SIZE] {
    let mut gate = [0u8; GATE_SIZE];
    gate[0..2].copy_from_slice(&(handler as u16).to_le_bytes());
    gate[2..4].copy_from_slice(&selector.to_le_bytes());
    gate[5] = 0x8E;
    gate[6..8].copy_from_slice(&((handler >> 16) as u16).to_le_bytes());
    gate[8..12].copy_from_slice(&((handler >> 32) as u32).to_le_bytes());
    gate
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestMemoryError {
    /// The assembled guest code does not fit in one page.
    CodeTooLarge,
    /// Failed to allocate the guest code page.
    CodeAllocationFailed,
    /// Failed to allocate the guest stack page.
    StackAllocationFailed,
    /// Failed to allocate the guest IDT page.
    IdtAllocationFailed,
    /// The page-table walk for the code page failed.
    CodeNotMapped(WalkError),
    /// The page-table walk for the stack page failed.
    StackNotMapped(WalkError),
    /// The page-table walk for the IDT page failed.
    IdtNotMapped(WalkError),
    /// The code page is mapped with XD set at some level.
    CodeNotExecutable,
    /// The code page is a user page and CR4.SMEP is set, so the ring-0
    /// guest could not execute it.
    CodeBlockedBySmep,
    /// The stack page is read-only at some level.
    StackNotWritable,
    /// The stack page is a user page and CR4.SMAP is set, so the ring-0
    /// guest (RFLAGS.AC = 0) could not push to it.
    StackBlockedBySmap,
    /// The IDT page is a user page and CR4.SMAP is set, so the CPU could
    /// not read the NMI gate while delivering an NMI to the guest.
    IdtBlockedBySmap,
}

/// Checks that a ring-0 guest running with `cr4` can execute from `code`
/// and write to `stack`.
///
/// Assumes the guest gets this same CR4 and RFLAGS.AC = 0, as planned for
/// the guest state.
fn check_permissions(code: &Mapping, stack: &Mapping, cr4: u64) -> Result<(), GuestMemoryError> {
    if code.execute_disable {
        return Err(GuestMemoryError::CodeNotExecutable);
    }
    if code.user && cr4 & cr::CR4_SMEP != 0 {
        return Err(GuestMemoryError::CodeBlockedBySmep);
    }
    if !stack.writable {
        return Err(GuestMemoryError::StackNotWritable);
    }
    if stack.user && cr4 & cr::CR4_SMAP != 0 {
        return Err(GuestMemoryError::StackBlockedBySmap);
    }
    Ok(())
}

/// Checks that the CPU can read the guest IDT while delivering an NMI to the
/// ring-0 guest. Delivery reads the IDT as an implicit supervisor access,
/// which CR4.SMAP blocks on a user page whatever RFLAGS.AC says. The CPU
/// never writes the IDT, so a read-only page is fine.
fn check_idt_permissions(idt: &Mapping, cr4: u64) -> Result<(), GuestMemoryError> {
    if idt.user && cr4 & cr::CR4_SMAP != 0 {
        return Err(GuestMemoryError::IdtBlockedBySmap);
    }
    Ok(())
}

/// How the current page tables map the three guest pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestMappings {
    pub code: Mapping,
    pub stack: Mapping,
    pub idt: Mapping,
}

/// Owns the guest code, stack and IDT pages. Never freed: the guest may run
/// from them for as long as the CPU stays in VMX operation.
pub struct GuestMemory {
    code: NonNull<u8>,
    stack: NonNull<u8>,
    idt: NonNull<u8>,
}

impl GuestMemory {
    /// Allocate the three pages, copy the guest code into the code page, and
    /// write the NMI gate into the IDT page.
    ///
    /// The code page is `LOADER_CODE` because firmware may map
    /// `LOADER_DATA` no-execute; the stack and IDT pages are `LOADER_DATA`.
    /// The gate uses the current CS selector, which the guest state copies.
    pub fn allocate() -> Result<Self, GuestMemoryError> {
        let code_bytes = guest_code();
        if code_bytes.len() > PAGE_SIZE {
            return Err(GuestMemoryError::CodeTooLarge);
        }

        let code = allocate_zeroed_pages_of_type(
            1,
            MemoryType::LOADER_CODE,
            GuestMemoryError::CodeAllocationFailed,
        )?;
        let stack = allocate_zeroed_pages_of_type(
            1,
            MemoryType::LOADER_DATA,
            GuestMemoryError::StackAllocationFailed,
        )?;
        let idt = allocate_zeroed_pages_of_type(
            1,
            MemoryType::LOADER_DATA,
            GuestMemoryError::IdtAllocationFailed,
        )?;

        unsafe { core::ptr::copy_nonoverlapping(code_bytes.as_ptr(), code.as_ptr(), code_bytes.len()) };
        let memory = Self { code, stack, idt };

        let gate = interrupt_gate(memory.nmi_handler(), unsafe { segment::read_cs() });
        unsafe {
            core::ptr::copy_nonoverlapping(gate.as_ptr(), idt.as_ptr().add(NMI_VECTOR * GATE_SIZE), GATE_SIZE)
        };
        Ok(memory)
    }

    /// Address of the first guest instruction, for GUEST_RIP.
    pub fn code_base(&self) -> u64 {
        self.code.as_ptr() as u64
    }

    /// Number of guest code bytes copied into the code page.
    pub fn code_len(&self) -> usize {
        guest_code().len()
    }

    /// Address of the guest's NMI handler in the code page: the target of
    /// the vector 2 gate.
    pub fn nmi_handler(&self) -> u64 {
        self.code_base() + nmi_handler_offset() as u64
    }

    /// Top of the downward-growing guest stack, for GUEST_RSP.
    pub fn stack_top(&self) -> u64 {
        let top = unsafe { self.stack.as_ptr().add(PAGE_SIZE) } as usize;
        assert_eq!(top % 16, 0);
        top as u64
    }

    /// The guest's own IDT, for GUEST_IDTR: vectors 0 to 2, only vector 2
    /// (NMI) present.
    pub fn idt(&self) -> DescriptorTable {
        DescriptorTable { base: self.idt.as_ptr() as u64, limit: GUEST_IDT_LIMIT }
    }

    /// Walks the current page tables for the three pages and checks that
    /// the code page is executable, the stack page writable, and the IDT
    /// page readable by the CPU on the ring-0 guest's behalf.
    ///
    /// The guest will use these same tables (guest CR3 = host CR3, no EPT).
    /// Each page is 4 KiB-aligned, so one walk covers the whole page: a page
    /// can never straddle two mappings.
    ///
    /// Requiring XD clear is stricter than needed when EFER.NXE = 0, but then
    /// a set XD bit is reserved and would fault anyway. The guest runs in
    /// ring 0, so a user page is also refused where CR4.SMEP (code) or
    /// CR4.SMAP (stack, IDT) would block it; see [`check_permissions`] and
    /// [`check_idt_permissions`].
    ///
    /// # Safety
    ///
    /// Boot services must still be active; see [`paging::walk_current`].
    pub unsafe fn check_mappings(&self) -> Result<GuestMappings, GuestMemoryError> {
        let code = unsafe { paging::walk_current(self.code_base()) }
            .map_err(GuestMemoryError::CodeNotMapped)?;
        let stack = unsafe { paging::walk_current(self.stack.as_ptr() as u64) }
            .map_err(GuestMemoryError::StackNotMapped)?;
        let idt = unsafe { paging::walk_current(self.idt().base) }
            .map_err(GuestMemoryError::IdtNotMapped)?;

        let cr4 = unsafe { read_cr4() };
        check_permissions(&code, &stack, cr4)?;
        check_idt_permissions(&idt, cr4)?;
        Ok(GuestMappings { code, stack, idt })
    }
}

#[cfg(test)]
#[path = "../../tests/unit/vmx/guest.rs"]
mod tests;
