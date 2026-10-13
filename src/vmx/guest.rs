//! Guest memory: a code page with a data page right after it, one stack
//! page and one IDT page.
//!
//! The guest's instructions are assembled into the `.efi` image between
//! `guest_code_start` and `guest_code_end`, then copied into a page of their
//! own, so the guest never executes from host code pages. The copy only
//! works because the code is position-independent: no absolute addresses,
//! only relative jumps and RIP-relative addressing.
//!
//! The data page is the one EPT maps read-only (`vmx::ept`). It is allocated
//! together with the code page, so the guest finds it at a fixed distance
//! from its own code (`lea rdi, [rip + guest_code_start]`, plus one page)
//! without being told an address. The guest reads it (allowed), writes it
//! (an EPT violation, after which Aleph0 makes it writable and the write is
//! retried), and reads it back.
//!
//! Guest RIP is [`GuestMemory::code_base`], guest RSP
//! [`GuestMemory::stack_top`], and guest IDTR [`GuestMemory::idt`];
//! `GuestState::write` (in `guest_state`) writes them to the VMCS.
//! [`GuestMemory::check_mappings`] confirms that the current page tables,
//! which the guest shares, map the code page executable, the stack and data
//! pages writable, and the IDT page readable for the ring-0 guest.
//!
//! The guest has its own IDT because Aleph0 reinjects NMIs into it: the
//! firmware's IDT would run the firmware's default NMI handler, which
//! dead-loops. Only vector 2 (NMI) is present. Every exception exits to
//! Aleph0 before it reaches the IDT (exception bitmap all ones), and the
//! guest runs with IF = 0, so no other vector is ever delivered through it.

use core::ptr::NonNull;

use uefi::boot::MemoryType;

use super::cr::{self, read_cr4};
use super::exit_decision::NMI_VECTOR;
use super::page::{PAGE_SIZE, allocate_zeroed_pages_of_type};
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

/// Value Aleph0 writes at the start of the guest data page before launch.
/// The guest reads it into ECX, so seeing it at main VMCALL #1 shows the
/// read went through EPT.
pub const GUEST_DATA_SEED: u32 = 0xDA7A;

/// Value the guest writes to its data page: "EPT" in ASCII. The write is the
/// intentional EPT violation; the guest reads the page back into EDX, so
/// seeing it at main VMCALL #1 shows the retried write landed.
pub const GUEST_EPT_VALUE: u32 = 0x0045_5054;

core::arch::global_asm!(
    r#"
    .globl guest_code_start
    .globl guest_nmi_handler
    .globl guest_code_end
guest_code_start:
    // No NMI handled yet. General-purpose registers are not VMCS fields, so
    // without this EBX would hold whatever the host had at VMLAUNCH.
    xor ebx, ebx
    // The data page follows the code page. RIP-relative, so this still
    // finds it after the code is copied.
    lea rdi, [rip + guest_code_start]
    add rdi, 0x1000
    // Read: EPT allows it, ECX = GUEST_DATA_SEED.
    mov ecx, dword ptr [rdi]
    // Write: EPT maps the page read-only, so this exits (EPT violation).
    // Aleph0 makes the page writable and resumes at this same instruction,
    // which then succeeds.
    mov dword ptr [rdi], {ept_value}
    // Read back: EDX = GUEST_EPT_VALUE.
    mov edx, dword ptr [rdi]
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
    ept_value = const GUEST_EPT_VALUE,
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
    // SAFETY: both labels come from the one asm block above, start before
    // end, so the range is the assembled code: initialised, in the image for
    // as long as it runs, and never written.
    unsafe { core::slice::from_raw_parts(start, end.offset_from(start) as usize) }
}

/// Offset of `guest_nmi_handler` from the start of the guest code, which is
/// also its offset in the code page after the copy.
fn nmi_handler_offset() -> usize {
    let start = &raw const guest_code_start;
    let handler = &raw const guest_nmi_handler;
    // SAFETY: both labels come from the one asm block above, so they point
    // into the same object, start before handler.
    unsafe { handler.offset_from(start) as usize }
}

/// Size of one 64-bit IDT gate.
const GATE_SIZE: usize = 16;
/// Byte offset of the NMI gate (vector 2) in the guest IDT.
const NMI_GATE_OFFSET: usize = NMI_VECTOR as usize * GATE_SIZE;
/// GUEST_IDTR limit: three gates, vectors 0 to 2. Only vector 2 is present.
const GUEST_IDT_LIMIT: u16 = (3 * GATE_SIZE - 1) as u16;
// The NMI gate must lie inside the IDT limit, or the guest would #GP on an NMI.
const _: () = assert!(NMI_GATE_OFFSET + GATE_SIZE - 1 <= GUEST_IDT_LIMIT as usize);

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
    /// Failed to allocate the guest code and data pages.
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
    /// The page-table walk for the data page failed.
    DataNotMapped(WalkError),
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
    /// The data page is read-only at some level of the guest's page
    /// tables. The guest's write would then be a page fault, not the EPT
    /// violation the test needs.
    DataNotWritable,
    /// The data page is a user page and CR4.SMAP is set, so the ring-0
    /// guest's accesses to it would fault before reaching EPT.
    DataBlockedBySmap,
    /// The page tables map a guest page somewhere other than itself. Guest
    /// RIP, RSP and IDTR are these virtual addresses, and the EPT identity
    /// map and its protected GPA assume virtual = guest-physical = physical.
    NotIdentityMapped { virtual_address: u64, physical: u64 },
}

/// Checks that `mapping`, the page-table walk of `virtual_address`, maps it
/// to the same physical address.
fn check_identity(virtual_address: u64, mapping: &Mapping) -> Result<(), GuestMemoryError> {
    if mapping.physical != virtual_address {
        return Err(GuestMemoryError::NotIdentityMapped {
            virtual_address,
            physical: mapping.physical,
        });
    }
    Ok(())
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

/// Checks that the ring-0 guest can read and write the data page through
/// the page tables it shares with the host, so its write reaches EPT
/// instead of causing a page fault first.
fn check_data_permissions(data: &Mapping, cr4: u64) -> Result<(), GuestMemoryError> {
    if !data.writable {
        return Err(GuestMemoryError::DataNotWritable);
    }
    if data.user && cr4 & cr::CR4_SMAP != 0 {
        return Err(GuestMemoryError::DataBlockedBySmap);
    }
    Ok(())
}

/// How the current page tables map the four guest pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestMappings {
    pub code: Mapping,
    pub stack: Mapping,
    pub idt: Mapping,
    pub data: Mapping,
}

/// Owns the guest code and data, stack and IDT pages. Never freed: the
/// guest may run from them for as long as the CPU stays in VMX operation.
pub struct GuestMemory {
    /// Two pages: the code, then the data page.
    code: NonNull<u8>,
    stack: NonNull<u8>,
    idt: NonNull<u8>,
}

impl GuestMemory {
    /// Allocate the pages, copy the guest code into the code page, write the
    /// seed into the data page, and write the NMI gate into the IDT page.
    ///
    /// The code and data pages are one two-page `LOADER_CODE` allocation:
    /// `LOADER_CODE` because firmware may map `LOADER_DATA` no-execute, and
    /// one allocation because the guest finds the data page right after its
    /// code. The stack and IDT pages are `LOADER_DATA`. The gate uses the
    /// current CS selector, which the guest state copies.
    pub fn allocate() -> Result<Self, GuestMemoryError> {
        let code_bytes = guest_code();
        if code_bytes.len() > PAGE_SIZE {
            return Err(GuestMemoryError::CodeTooLarge);
        }

        let code = allocate_zeroed_pages_of_type(2, MemoryType::LOADER_CODE, GuestMemoryError::CodeAllocationFailed)?;
        let stack = allocate_zeroed_pages_of_type(1, MemoryType::LOADER_DATA, GuestMemoryError::StackAllocationFailed)?;
        let idt = allocate_zeroed_pages_of_type(1, MemoryType::LOADER_DATA, GuestMemoryError::IdtAllocationFailed)?;

        // SAFETY: `code` is a fresh two-page allocation, and the code is at
        // most one page (checked above).
        unsafe { core::ptr::copy_nonoverlapping(code_bytes.as_ptr(), code.as_ptr(), code_bytes.len()) };
        let memory = Self { code, stack, idt };
        // SAFETY: the data page is the second page of the fresh `code`
        // allocation, 4 KiB-aligned, so a u32 at its start is in bounds and
        // aligned.
        unsafe { (memory.data_page() as *mut u32).write_volatile(GUEST_DATA_SEED) };

        let gate = interrupt_gate(memory.nmi_handler(), segment::read_cs());
        // SAFETY: `idt` is a fresh page, and the gate ends within the IDT
        // limit (asserted at compile time), far inside it.
        unsafe { core::ptr::copy_nonoverlapping(gate.as_ptr(), idt.as_ptr().add(NMI_GATE_OFFSET), GATE_SIZE) };
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

    /// Address of the data page, right after the code page. Under the
    /// identity mappings it is also the page's guest-physical address, the
    /// one EPT maps read-only.
    pub fn data_page(&self) -> u64 {
        self.code_base() + PAGE_SIZE as u64
    }

    /// Top of the downward-growing guest stack, for GUEST_RSP.
    pub fn stack_top(&self) -> u64 {
        // SAFETY: the stack is one page, so this is one past its end, which
        // `add` allows.
        let top = unsafe { self.stack.as_ptr().add(PAGE_SIZE) } as usize;
        assert_eq!(top % 16, 0);
        top as u64
    }

    /// The guest's own IDT, for GUEST_IDTR: vectors 0 to 2, only vector 2
    /// (NMI) present.
    pub fn idt(&self) -> DescriptorTable {
        DescriptorTable {
            base: self.idt.as_ptr() as u64,
            limit: GUEST_IDT_LIMIT,
        }
    }

    /// Walks the current page tables for the four pages and checks that
    /// each is identity-mapped ([`check_identity`]), the code page
    /// executable, the stack and data pages writable, and the IDT page
    /// readable by the CPU on the ring-0 guest's behalf.
    ///
    /// The guest will use these same tables (guest CR3 = host CR3); EPT
    /// translates their result a second time.
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
        let stack_base = self.stack.as_ptr() as u64;
        // SAFETY: the caller guarantees boot services are active, which is
        // what `walk_current` needs.
        let walk = |address| unsafe { paging::walk_current(address) };
        let code = walk(self.code_base()).map_err(GuestMemoryError::CodeNotMapped)?;
        let stack = walk(stack_base).map_err(GuestMemoryError::StackNotMapped)?;
        let idt = walk(self.idt().base).map_err(GuestMemoryError::IdtNotMapped)?;
        let data = walk(self.data_page()).map_err(GuestMemoryError::DataNotMapped)?;
        for (virtual_address, mapping) in [
            (self.code_base(), &code),
            (stack_base, &stack),
            (self.idt().base, &idt),
            (self.data_page(), &data),
        ] {
            check_identity(virtual_address, mapping)?;
        }

        let cr4 = read_cr4();
        check_permissions(&code, &stack, cr4)?;
        check_idt_permissions(&idt, cr4)?;
        check_data_permissions(&data, cr4)?;
        Ok(GuestMappings { code, stack, idt, data })
    }
}

#[cfg(test)]
#[path = "../../tests/unit/vmx/guest.rs"]
mod tests;
