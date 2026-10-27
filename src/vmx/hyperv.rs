//! Hyper-V's interface to its guests, which Aleph0's guest keeps
//! (docs/HYPERV_INTERFACE.md): Aleph0 repeats each hypercall and each
//! synthetic-MSR access in root operation, so L0 Hyper-V serves it as an
//! access of Aleph0's own virtual processor, the one the guest ran on before
//! Aleph0 started.
//!
//! ```text
//! guest (L2)                    Aleph0 (L1, root)                 Hyper-V (L0)
//! VMCALL, RCX/RDX/R8 ─exit 18─▶ forward_hypercall: same RCX/RDX/R8,
//!                               VMCALL ──────────────────────────▶ serves it
//!        RAX, RCX, RDX, R8 ◀──── into the guest's frame, RIP past ◀ RAX = status
//! RDMSR 0x40000020 ─exit 31───▶ forward_rdmsr: RDMSR ────────────▶ answers
//!        EDX:EAX ◀────────────── into the guest's frame ◀──────────
//! ```
//!
//! EPT is an identity map, so every GPA a hypercall names (its input and
//! output pages in RDX and R8) means the same page to Hyper-V. The pages
//! Hyper-V overlays at GPAs the guest picked (the hypercall page, the
//! reference TSC page, the SynIC's message and event pages) sit in Aleph0's
//! address space, which the guest sees through the same map.
//!
//! Hyper-V refuses some of what it is asked: a hypercall before the guest
//! enabled the hypercall page gets #UD, a value an MSR does not take #GP.
//! (An MSR Hyper-V does not define at all, in its block or not, reads 0 and
//! ignores writes: `forward-refusal-test` showed it.) Aleph0 cannot know all
//! of that up front, so the forwarders let the CPU tell: the host fault
//! handler resumes each forwarding instruction's #UD or #GP at its recovery
//! point ([`recovery`]), and the guest gets the same exception at its own
//! instruction, as it would without Aleph0.
//!
//! Fast hypercalls also pass data in XMM0-XMM5. Aleph0 never touches vector
//! state (soft-float target, see `vmx::vmexit`), so those stay the guest's
//! across the forward.

use core::arch::x86_64::{__cpuid, CpuidResult};
use core::ops::RangeInclusive;
use core::sync::atomic::{AtomicBool, Ordering};

/// CPUID.1:ECX bit 31: a hypervisor is present, and leaves 0x40000000 and up
/// describe it.
const HYPERVISOR_PRESENT: u32 = 1 << 31;
/// CPUID leaf whose EAX is the highest hypervisor leaf and EBX:ECX:EDX the
/// vendor ("Microsoft Hv").
pub const VENDOR_LEAF: u32 = 0x4000_0000;
/// CPUID leaf whose EAX names the interface the hypervisor implements.
pub const INTERFACE_LEAF: u32 = 0x4000_0001;
/// CPUID.40000001H:EAX of the Microsoft hypervisor interface, "Hv#1". The
/// TLFS says to check this, not the vendor: other hypervisors (KVM, QEMU)
/// offer the same interface under their own vendor.
pub const INTERFACE_SIGNATURE: u32 = u32::from_le_bytes(*b"Hv#1");

/// Hyper-V's synthetic MSRs, all at `0x4000_0000 + n` (TLFS appendix): the
/// partition's (guest OS ID, hypercall page, reference counter and TSC
/// page, frequencies), the virtual processor's (VP index, APIC assist,
/// SynIC, synthetic timers), and past `0x400000FF` the crash MSRs
/// (`0x40000100`-`0x40000105`), TSC invariant control (`0x40000118`, which
/// Linux writes) and the nested SynIC's (`0x40001080` and up). None is in
/// the MSR bitmap's ranges, so each RDMSR and WRMSR of them exits. One
/// Hyper-V does not define reads 0 and ignores writes, as it does for the
/// guest without Aleph0, so a wide range forwards nothing the guest could
/// not already reach.
pub const SYNTHETIC_MSRS: RangeInclusive<u32> = 0x4000_0000..=0x4000_FFFF;

/// Whether CPUID says the Microsoft hypervisor interface is offered: the
/// hypervisor-present bit in `leaf1_ecx`, a highest hypervisor leaf
/// (`max_leaf`, CPUID.40000000H:EAX) that includes the interface leaf, and
/// "Hv#1" there (`interface`, CPUID.40000001H:EAX).
///
/// Without the present bit, leaves 0x40000000 and up are not a hypervisor's:
/// Intel answers an out-of-range leaf with the highest basic leaf's data.
pub fn offers_interface(leaf1_ecx: u32, max_leaf: u32, interface: u32) -> bool {
    leaf1_ecx & HYPERVISOR_PRESENT != 0 && max_leaf >= INTERFACE_LEAF && interface == INTERFACE_SIGNATURE
}

/// What CPUID says about Hyper-V's interface, for bring-up's report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Detection {
    /// CPUID.1:ECX.
    pub leaf1_ecx: u32,
    /// CPUID.40000000H: the highest hypervisor leaf and the vendor.
    pub vendor: CpuidResult,
    /// CPUID.40000001H:EAX.
    pub interface: u32,
}

impl Detection {
    /// Reads the three leaves. Under Hyper-V, root operation sees what the
    /// guest sees, since `cpuid_policy` passes these leaves through.
    pub fn read() -> Self {
        Self {
            leaf1_ecx: __cpuid(1).ecx,
            vendor: __cpuid(VENDOR_LEAF),
            interface: __cpuid(INTERFACE_LEAF).eax,
        }
    }

    /// Whether the interface is offered ([`offers_interface`]).
    pub fn offers_interface(&self) -> bool {
        offers_interface(self.leaf1_ecx, self.vendor.eax, self.interface)
    }

    /// The vendor's 12 bytes, EBX then ECX then EDX, as CPUID returns them.
    pub fn vendor_bytes(&self) -> [u8; 12] {
        let mut bytes = [0; 12];
        bytes[0..4].copy_from_slice(&self.vendor.ebx.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.vendor.ecx.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.vendor.edx.to_le_bytes());
        bytes
    }
}

/// Whether bring-up found Hyper-V's interface; the exit handler reads it at
/// every exit. False until [`publish`] runs.
static OFFERED: AtomicBool = AtomicBool::new(false);

/// Records, before VMLAUNCH, whether Hyper-V's interface is offered.
pub fn publish(offered: bool) {
    OFFERED.store(offered, Ordering::Relaxed);
}

/// What [`publish`] recorded.
pub fn offered() -> bool {
    OFFERED.load(Ordering::Relaxed)
}

/// Synthetic MSRs whose value overlays a page at a guest-chosen GPA: when
/// the guest writes one with the enable bit set, Hyper-V lays a page over
/// that GPA in the virtual processor's address space, which is Aleph0's
/// (TLFS: the hypercall page, the reference TSC page, the VP assist page,
/// and the SynIC's message and event pages, SIMP and SIEFP). The guest
/// pointing one at an Aleph0 page would have Hyper-V overlay Aleph0's own
/// memory, past EPT, so [`overlay_gpa`] lets the forwarder refuse it.
const OVERLAY_MSRS: [u32; 5] = [
    0x4000_0001, // HV_X64_MSR_HYPERCALL
    0x4000_0021, // HV_X64_MSR_REFERENCE_TSC
    0x4000_0073, // HV_X64_MSR_VP_ASSIST_PAGE (APIC assist)
    0x4000_0083, // HV_X64_MSR_SIMP (SynIC message page)
    0x4000_0084, // HV_X64_MSR_SIEFP (SynIC event flags page)
];

/// Bit 0 of an overlay MSR: enable. Clear disables the overlay, naming no
/// GPA to guard.
const OVERLAY_ENABLE: u64 = 1 << 0;

/// Bits 51:12 of an overlay-MSR value or a hypercall GPA register: the
/// guest-physical page frame, the rest a page offset or reserved.
const GPA_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Bit 16 of a hypercall input value (RCX): a fast hypercall, whose input
/// and output are in registers (RDX, R8, XMM) rather than at GPAs.
const FAST: u64 = 1 << 16;

/// The GPA a WRMSR of `value` to synthetic MSR `msr` would have Hyper-V
/// overlay in Aleph0's address space, or `None` when `msr` overlays no page
/// or the write disables the overlay ([`OVERLAY_MSRS`]).
pub fn overlay_gpa(msr: u32, value: u64) -> Option<u64> {
    (OVERLAY_MSRS.contains(&msr) && value & OVERLAY_ENABLE != 0).then_some(value & GPA_MASK)
}

/// The GPAs a hypercall with input value `input` names: the input page in
/// `rdx` and the output page in `r8`, or none for a fast hypercall, whose
/// data is in registers Hyper-V cannot use to reach Aleph0's memory. The
/// forwarder refuses the call if either names an Aleph0 page.
pub fn hypercall_gpas(input: u64, rdx: u64, r8: u64) -> [Option<u64>; 2] {
    if input & FAST != 0 {
        [None, None]
    } else {
        [Some(rdx & GPA_MASK), Some(r8 & GPA_MASK)]
    }
}

/// The call code of a hypercall input value: bits 15:0 of RCX.
///
/// ```text
///  63:60  59:48        47:44  43:32      31      30:27  26:17        16    15:0
/// ┌─────┬────────────┬──────┬──────────┬───────┬──────┬────────────┬─────┬───────────┐
/// │ res │ rep start  │ res  │ rep count│ nested│ res  │ var. header│ fast│ call code │
/// └─────┴────────────┴──────┴──────────┴───────┴──────┴────────────┴─────┴───────────┘
/// ```
pub fn call_code(input: u64) -> u16 {
    input as u16
}

/// The registers a hypercall reads and writes (TLFS, "Hypercall Inputs" for
/// x64): RCX the input value, RDX and R8 the input and output GPAs (or, for
/// a fast hypercall, its input data, and RDX:R8 its output), RAX the result
/// value. Hyper-V may also update RCX, the rep start index, when it
/// continues a rep hypercall.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HypercallRegisters {
    pub rcx: u64,
    pub rdx: u64,
    pub r8: u64,
    pub rax: u64,
}

// `hyperv_forward_hypercall` reads and writes the fields at these offsets.
const _: () = {
    assert!(core::mem::offset_of!(HypercallRegisters, rcx) == 0);
    assert!(core::mem::offset_of!(HypercallRegisters, rdx) == 8);
    assert!(core::mem::offset_of!(HypercallRegisters, r8) == 16);
    assert!(core::mem::offset_of!(HypercallRegisters, rax) == 24);
};

/// Hyper-V refused a forwarded instruction with the exception its
/// forwarder recovers from: #UD for VMCALL, #GP for RDMSR and WRMSR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused;

/// IDT vectors the forwarders recover from.
const INVALID_OPCODE: u8 = 6;
const GENERAL_PROTECTION: u8 = 13;

// The forwarders, Microsoft x64 ABI (`efiapi`), each returning 0 when the
// instruction ran and 1 when Hyper-V raised the exception [`recovery`] names
// for it. The host fault handler resumes that exception at the `_refused`
// label, with RSP and RFLAGS as at the instruction and every register the
// ABI lets a callee change possibly changed.
//
// hyperv_forward_hypercall(registers = RCX): loads RCX, RDX and R8 from
// `registers`, keeping the pointer on the stack, since Hyper-V may write
// RCX (and RDX, R8 for a fast hypercall's output), and stores all four back.
//
// hyperv_forward_rdmsr(msr = ECX, value = RDX): stores EDX:EAX at `value`.
//
// hyperv_forward_wrmsr(msr = ECX, value = RDX): writes RDX as EDX:EAX.
core::arch::global_asm!(
    r#"
    .globl hyperv_forward_hypercall
    .globl hyperv_hypercall_instruction
    .globl hyperv_hypercall_refused
hyperv_forward_hypercall:
    push rcx
    mov rax, rcx
    mov rcx, [rax]
    mov rdx, [rax + 8]
    mov r8, [rax + 16]
hyperv_hypercall_instruction:
    vmcall
    pop r9
    mov [r9], rcx
    mov [r9 + 8], rdx
    mov [r9 + 16], r8
    mov [r9 + 24], rax
    xor eax, eax
    ret
hyperv_hypercall_refused:
    pop r9
    mov eax, 1
    ret

    .globl hyperv_forward_rdmsr
    .globl hyperv_rdmsr_instruction
    .globl hyperv_rdmsr_refused
hyperv_forward_rdmsr:
    mov r8, rdx
hyperv_rdmsr_instruction:
    rdmsr
    shl rdx, 32
    or rax, rdx
    mov [r8], rax
    xor eax, eax
    ret
hyperv_rdmsr_refused:
    mov eax, 1
    ret

    .globl hyperv_forward_wrmsr
    .globl hyperv_wrmsr_instruction
    .globl hyperv_wrmsr_refused
hyperv_forward_wrmsr:
    mov eax, edx
    shr rdx, 32
hyperv_wrmsr_instruction:
    wrmsr
    xor eax, eax
    ret
hyperv_wrmsr_refused:
    mov eax, 1
    ret
"#
);

unsafe extern "efiapi" {
    fn hyperv_forward_hypercall(registers: *mut HypercallRegisters) -> u64;
    fn hyperv_forward_rdmsr(msr: u32, value: *mut u64) -> u64;
    fn hyperv_forward_wrmsr(msr: u32, value: u64) -> u64;
}

unsafe extern "C" {
    static hyperv_hypercall_instruction: u8;
    static hyperv_hypercall_refused: u8;
    static hyperv_rdmsr_instruction: u8;
    static hyperv_rdmsr_refused: u8;
    static hyperv_wrmsr_instruction: u8;
    static hyperv_wrmsr_refused: u8;
}

/// Where the host fault handler resumes after exception `vector` at `rip`:
/// the forwarder's `_refused` label, when `rip` is a forwarding instruction
/// and `vector` the exception Hyper-V refuses it with. `None` for any other
/// fault, which stays a bug in Aleph0.
pub fn recovery(rip: u64, vector: u8) -> Option<u64> {
    let points = [
        (
            &raw const hyperv_hypercall_instruction,
            INVALID_OPCODE,
            &raw const hyperv_hypercall_refused,
        ),
        (
            &raw const hyperv_rdmsr_instruction,
            GENERAL_PROTECTION,
            &raw const hyperv_rdmsr_refused,
        ),
        (
            &raw const hyperv_wrmsr_instruction,
            GENERAL_PROTECTION,
            &raw const hyperv_wrmsr_refused,
        ),
    ];
    points
        .into_iter()
        .find(|&(at, refused_with, _)| at as u64 == rip && refused_with == vector)
        .map(|(_, _, resume)| resume as u64)
}

/// The guest's hypercall in `registers`, made again in root operation:
/// Hyper-V's results replace them.
///
/// # Safety
///
/// VMX root operation under Hyper-V, at CPL 0, with the guest stopped at its
/// VMCALL exit and the host IDT loaded, whose #UD gate recovers through
/// [`recovery`]. The hypercall acts on Aleph0's virtual processor and on the
/// guest pages the GPAs name, as the guest asked.
pub unsafe fn forward_hypercall(registers: &mut HypercallRegisters) -> Result<(), Refused> {
    // SAFETY: the caller's guarantees; the forwarder reads and writes only
    // `registers` and its own stack.
    match unsafe { hyperv_forward_hypercall(registers) } {
        0 => Ok(()),
        _ => Err(Refused),
    }
}

/// RDMSR of the synthetic MSR `msr`, in root operation.
///
/// # Safety
///
/// As for [`forward_hypercall`], for the guest's RDMSR exit and the #GP
/// gate.
pub unsafe fn forward_rdmsr(msr: u32) -> Result<u64, Refused> {
    let mut value = 0;
    // SAFETY: the caller's guarantees; the forwarder writes only `value`.
    match unsafe { hyperv_forward_rdmsr(msr, &mut value) } {
        0 => Ok(value),
        _ => Err(Refused),
    }
}

/// WRMSR of `value` to the synthetic MSR `msr`, in root operation. It acts
/// on Aleph0's virtual processor, as the guest's would have.
///
/// # Safety
///
/// As for [`forward_rdmsr`], for the guest's WRMSR exit.
pub unsafe fn forward_wrmsr(msr: u32, value: u64) -> Result<(), Refused> {
    // SAFETY: the caller's guarantees.
    match unsafe { hyperv_forward_wrmsr(msr, value) } {
        0 => Ok(()),
        _ => Err(Refused),
    }
}

/// Once, at the first exit under Hyper-V, forwards an access Hyper-V takes
/// and one that faults, and prints what came back:
/// - RDMSR and WRMSR of 0 to `0x4000FFFF`, which Hyper-V does not define:
///   it reads 0 and ignores the write (seen on Hyper-V), no #GP;
/// - WRMSR of a non-canonical value to IA32_KERNEL_GS_BASE, which raises
///   #GP whoever runs it: `Err(Refused)` means the host fault handler
///   resumed the forwarder at its recovery point.
#[cfg(feature = "forward-refusal-test")]
pub fn refuse_on_purpose() {
    static DONE: AtomicBool = AtomicBool::new(false);
    if !offered() || DONE.swap(true, Ordering::Relaxed) {
        return;
    }
    const UNDEFINED: u32 = 0x4000_FFFF;
    const KERNEL_GS_BASE: u32 = crate::vmx::msr::IA32_KERNEL_GS_BASE;
    const NON_CANONICAL: u64 = 0x8000_0000_0000_0000;
    // SAFETY: exit context: VMX root operation under Hyper-V at CPL 0, with
    // the host IDT loaded; the guest is stopped at this exit. Hyper-V does not
    // define 0x4000FFFF, and the non-canonical WRMSR faults before it writes.
    let (read, write, refused) = unsafe {
        (
            forward_rdmsr(UNDEFINED),
            forward_wrmsr(UNDEFINED, 0),
            forward_wrmsr(KERNEL_GS_BASE, NON_CANONICAL),
        )
    };
    crate::serial_println!(
        "{} forward-refusal-test: RDMSR {UNDEFINED:#x} -> {read:x?}, WRMSR {UNDEFINED:#x} <- 0 -> {write:?}; WRMSR {KERNEL_GS_BASE:#x} <- {NON_CANONICAL:#x} -> {refused:?}; Aleph0 still runs.",
        crate::TAG
    );
}

#[cfg(test)]
#[path = "../../tests/unit/vmx/hyperv.rs"]
mod tests;
