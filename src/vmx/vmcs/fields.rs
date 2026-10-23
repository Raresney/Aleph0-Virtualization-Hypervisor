//! VMCS field encodings, and the bits inside the control fields.
//!
//! [`super::vmread`] and [`super::vmwrite`] name a field by a 32-bit
//! *encoding*, not by an offset into the VMCS region (whose layout is
//! undocumented). The encoding packs what kind of field it is:
//!
//! ```text
//!  14  13  12  11  10  9            1   0
//! ┌───────┬───┬───────┬──────────────┬──────┐
//! │ width │ 0 │ type  │    index     │access│
//! └───────┴───┴───────┴──────────────┴──────┘
//! ```
//!
//! - width: 0 = 16-bit, 1 = 64-bit, 2 = 32-bit, 3 = natural (64-bit here)
//! - type: 0 = control, 1 = read-only data, 2 = guest state, 3 = host state
//! - access: 0 = the full field, 1 = the high 32 bits of a 64-bit field
//!
//! So the leading hex digits already say what a field is: `0x08xx` is a
//! 16-bit guest field, `0x6Cxx` a natural-width host field.

/// Pin-based VM-execution controls.
pub const PIN_BASED_VM_EXEC_CONTROL: u32 = 0x4000;
/// Primary processor-based VM-execution controls.
pub const PRIMARY_VM_EXEC_CONTROL: u32 = 0x4002;
/// Pin-based control bit 3: an NMI that arrives while the guest runs causes
/// a VM exit (reason 0, interruption type NMI) instead of being delivered
/// through the guest's IDT.
pub const PIN_BASED_NMI_EXITING: u32 = 1 << 3;
/// Pin-based control bit 5, "virtual NMIs": the CPU tracks the guest's NMI
/// blocking, so an injected NMI blocks further ones until the guest's IRET.
/// Requires NMI exiting.
pub const PIN_BASED_VIRTUAL_NMIS: u32 = 1 << 5;
/// Primary processor-based control bit 7: HLT causes a VM exit (reason 12).
pub const CPU_BASED_HLT_EXITING: u32 = 1 << 7;
/// Primary processor-based control bit 22: a VM exit (reason 8) as soon as
/// the guest can take an NMI. Requires virtual NMIs.
pub const CPU_BASED_NMI_WINDOW_EXITING: u32 = 1 << 22;
/// Primary processor-based control bit 25: IN/OUT exit only for ports whose
/// bit is set in the I/O bitmaps ([`IO_BITMAP_A`], [`IO_BITMAP_B`]). While
/// set, the CPU ignores bit 24 (unconditional I/O exiting).
pub const CPU_BASED_USE_IO_BITMAPS: u32 = 1 << 25;
/// Primary processor-based control bit 28: RDMSR/WRMSR exit only for MSRs
/// whose bit is set in the MSR bitmap ([`MSR_BITMAP`]). Without it, every
/// RDMSR and WRMSR exits.
pub const CPU_BASED_USE_MSR_BITMAPS: u32 = 1 << 28;
/// Primary processor-based control bit 31: the CPU also uses the secondary
/// controls ([`SECONDARY_VM_EXEC_CONTROL`]). Without it they all count as 0.
pub const CPU_BASED_ACTIVATE_SECONDARY_CONTROLS: u32 = 1 << 31;
/// Secondary control bit 1: guest-physical addresses are translated through
/// the EPT tables named by [`EPT_POINTER`].
pub const SECONDARY_ENABLE_EPT: u32 = 1 << 1;
/// Secondary control bit 5: the guest's TLB entries are tagged with a
/// virtual-processor identifier. Aleph0 does not enable it; the EPT/VPID
/// capability MSR exists if either this or EPT is allowed.
pub const SECONDARY_ENABLE_VPID: u32 = 1 << 5;
/// Exception bitmap: bit N set makes guest exception vector N cause a VM exit
/// (reason 0) instead of being delivered through the guest's IDT.
pub const EXCEPTION_BITMAP: u32 = 0x4004;
/// Page-fault error-code mask and match: with bit 14 of the exception bitmap
/// set, a guest #PF exits only if (error code & mask) == match, so 0 and 0
/// make every #PF exit.
pub const PAGE_FAULT_ERROR_CODE_MASK: u32 = 0x4006;
/// See [`PAGE_FAULT_ERROR_CODE_MASK`].
pub const PAGE_FAULT_ERROR_CODE_MATCH: u32 = 0x4008;
/// CR3-target count: how many CR3-target values are valid; VM entry requires
/// at most 4.
pub const CR3_TARGET_COUNT: u32 = 0x400A;
/// VM-exit controls.
pub const VM_EXIT_CONTROLS: u32 = 0x400C;
/// VM-exit MSR-store count: entries in the MSR-store list; nonzero needs a
/// valid list address.
pub const VM_EXIT_MSR_STORE_COUNT: u32 = 0x400E;
/// VM-exit MSR-load count: entries in the MSR-load list; nonzero needs a
/// valid list address.
pub const VM_EXIT_MSR_LOAD_COUNT: u32 = 0x4010;
/// VM-entry controls.
pub const VM_ENTRY_CONTROLS: u32 = 0x4012;
/// VM-entry MSR-load count: entries in the MSR-load list; nonzero needs a
/// valid list address.
pub const VM_ENTRY_MSR_LOAD_COUNT: u32 = 0x4014;
/// VM-entry interruption-information field: bit 31 set injects an event on
/// entry, so 0 means no injection.
pub const VM_ENTRY_INTERRUPTION_INFO: u32 = 0x4016;
/// VM-entry exception error code (32-bit): the error code delivered with an
/// injected exception whose interruption info has bit 11 set.
pub const VM_ENTRY_EXCEPTION_ERROR_CODE: u32 = 0x4018;
/// VM-entry instruction length (32-bit): the length the CPU charges when it
/// injects a software interrupt or software exception (interruption types 4,
/// 5 and 6), so RIP ends past the INT/INT3/INTO that was being delivered.
pub const VM_ENTRY_INSTRUCTION_LEN: u32 = 0x401A;
/// Secondary processor-based VM-execution controls. The CPU reads this field
/// only while primary bit 31 ([`CPU_BASED_ACTIVATE_SECONDARY_CONTROLS`]) is
/// set.
pub const SECONDARY_VM_EXEC_CONTROL: u32 = 0x401E;

/// Physical addresses of the I/O bitmaps: A covers ports 0x0000–0x7FFF,
/// B ports 0x8000–0xFFFF, one bit per port (64-bit).
pub const IO_BITMAP_A: u32 = 0x2000;
pub const IO_BITMAP_B: u32 = 0x2002;
/// Physical address of the 4 KiB MSR bitmap (64-bit).
pub const MSR_BITMAP: u32 = 0x2004;
/// EPT pointer (EPTP): the physical address of the EPT PML4 table, with the
/// memory type and page-walk length in its low bits (see `vmx::ept::Eptp`).
pub const EPT_POINTER: u32 = 0x201A;

/// VM-exit control bit 9: the host runs in 64-bit mode after a VM exit.
pub const VM_EXIT_HOST_ADDRESS_SPACE_SIZE: u32 = 1 << 9;
/// VM-exit control bit 2: save the guest's DR7 and IA32_DEBUGCTL into the
/// VMCS (GUEST_DR7, GUEST_IA32_DEBUGCTL). Every exit sets DR7 to 0x400, so
/// without it the guest's DR7 is gone after the exit.
pub const VM_EXIT_SAVE_DEBUG_CONTROLS: u64 = 1 << 2;
/// VM-exit control bits 18 and 20: save the guest's PAT and EFER into
/// GUEST_IA32_PAT and GUEST_IA32_EFER.
pub const VM_EXIT_SAVE_IA32_PAT: u64 = 1 << 18;
pub const VM_EXIT_SAVE_IA32_EFER: u64 = 1 << 20;
/// VM-exit control bits that load host PAT and EFER from the VMCS.
pub const VM_EXIT_LOAD_IA32_PAT: u64 = 1 << 19;
pub const VM_EXIT_LOAD_IA32_EFER: u64 = 1 << 21;
/// VM-entry control bit 9: the guest starts in IA-32e (64-bit) mode.
pub const VM_ENTRY_IA32E_MODE_GUEST: u32 = 1 << 9;
/// VM-entry control bits that load guest PAT and EFER from the VMCS. When a
/// bit is 0, the guest keeps the value the CPU already has, and the matching
/// guest field may not even exist.
pub const VM_ENTRY_LOAD_IA32_PAT: u64 = 1 << 14;
pub const VM_ENTRY_LOAD_IA32_EFER: u64 = 1 << 15;

/// Why the last VMX instruction failed (32-bit; valid after VMfailValid).
pub const VM_INSTRUCTION_ERROR: u32 = 0x4400;
/// Why the last VM exit happened (32-bit).
pub const VM_EXIT_REASON: u32 = 0x4402;
/// VM-exit interruption information (32-bit), for exception exits (reason 0):
/// bits 7:0 vector, bits 10:8 event type, bit 11 error code valid, bit 31 the
/// field is valid.
pub const VM_EXIT_INTERRUPTION_INFO: u32 = 0x4404;
/// VM-exit interruption error code (32-bit): the error code of the exception
/// that caused the exit, when VM_EXIT_INTERRUPTION_INFO bit 11 says it has one.
pub const VM_EXIT_INTERRUPTION_ERROR_CODE: u32 = 0x4406;
/// IDT-vectoring information (32-bit): bit 31 is set when the VM exit
/// interrupted the delivery of an event through the guest's IDT. Same layout
/// as the interruption-information fields.
pub const IDT_VECTORING_INFO: u32 = 0x4408;
/// IDT-vectoring error code (32-bit): the error code of the event whose
/// delivery the exit interrupted, when IDT_VECTORING_INFO bit 11 says it has
/// one.
pub const IDT_VECTORING_ERROR_CODE: u32 = 0x440A;
/// Length in bytes of the instruction that caused the exit (32-bit), for
/// exits caused by an instruction (VMCALL, CPUID, ...). Used to advance RIP.
pub const VM_EXIT_INSTRUCTION_LEN: u32 = 0x440C;
/// Extra exit detail whose meaning depends on the exit reason (natural
/// width), e.g. the kind of access for an EPT violation.
pub const EXIT_QUALIFICATION: u32 = 0x6400;
/// Guest-physical address of an EPT violation or misconfiguration (64-bit).
pub const GUEST_PHYSICAL_ADDRESS: u32 = 0x2400;
/// Guest-linear address of an EPT violation (natural width), valid when
/// exit qualification bit 7 is set.
pub const GUEST_LINEAR_ADDRESS: u32 = 0x640A;

/// Guest segment selectors (16-bit).
pub const GUEST_ES_SELECTOR: u32 = 0x0800;
pub const GUEST_CS_SELECTOR: u32 = 0x0802;
pub const GUEST_SS_SELECTOR: u32 = 0x0804;
pub const GUEST_DS_SELECTOR: u32 = 0x0806;
pub const GUEST_FS_SELECTOR: u32 = 0x0808;
pub const GUEST_GS_SELECTOR: u32 = 0x080A;
pub const GUEST_LDTR_SELECTOR: u32 = 0x080C;
pub const GUEST_TR_SELECTOR: u32 = 0x080E;

/// Must be set to `!0` unless shadow VMCS is in use (64-bit). A classic
/// omission: leaving it zero makes VM entry fail with an invalid-guest-state
/// exit.
pub const VMCS_LINK_POINTER: u32 = 0x2800;

/// Guest IA32_DEBUGCTL, PAT and EFER (64-bit). PAT and EFER exist only on
/// CPUs that support the matching VM-entry load controls.
pub const GUEST_IA32_DEBUGCTL: u32 = 0x2802;
pub const GUEST_IA32_PAT: u32 = 0x2804;
pub const GUEST_IA32_EFER: u32 = 0x2806;

/// Guest segment limits (32-bit).
pub const GUEST_ES_LIMIT: u32 = 0x4800;
pub const GUEST_CS_LIMIT: u32 = 0x4802;
pub const GUEST_SS_LIMIT: u32 = 0x4804;
pub const GUEST_DS_LIMIT: u32 = 0x4806;
pub const GUEST_FS_LIMIT: u32 = 0x4808;
pub const GUEST_GS_LIMIT: u32 = 0x480A;
pub const GUEST_LDTR_LIMIT: u32 = 0x480C;
pub const GUEST_TR_LIMIT: u32 = 0x480E;
pub const GUEST_GDTR_LIMIT: u32 = 0x4810;
pub const GUEST_IDTR_LIMIT: u32 = 0x4812;

/// Guest segment access rights (32-bit), in the format of
/// [`crate::vmx::segment::SegmentDescriptor::access_rights`].
pub const GUEST_ES_ACCESS_RIGHTS: u32 = 0x4814;
pub const GUEST_CS_ACCESS_RIGHTS: u32 = 0x4816;
pub const GUEST_SS_ACCESS_RIGHTS: u32 = 0x4818;
pub const GUEST_DS_ACCESS_RIGHTS: u32 = 0x481A;
pub const GUEST_FS_ACCESS_RIGHTS: u32 = 0x481C;
pub const GUEST_GS_ACCESS_RIGHTS: u32 = 0x481E;
pub const GUEST_LDTR_ACCESS_RIGHTS: u32 = 0x4820;
pub const GUEST_TR_ACCESS_RIGHTS: u32 = 0x4822;

/// Guest interruptibility state (32-bit): 0 = no blocking by STI, MOV SS,
/// SMI or NMI.
pub const GUEST_INTERRUPTIBILITY_STATE: u32 = 0x4824;
/// Guest activity state (32-bit): 0 = active, as opposed to HLT, shutdown
/// or wait-for-SIPI.
pub const GUEST_ACTIVITY_STATE: u32 = 0x4826;
/// Guest SYSENTER code selector (32-bit).
pub const GUEST_IA32_SYSENTER_CS: u32 = 0x482A;

/// Guest control registers (natural width).
pub const GUEST_CR0: u32 = 0x6800;
pub const GUEST_CR3: u32 = 0x6802;
pub const GUEST_CR4: u32 = 0x6804;

/// Guest segment and descriptor-table bases (natural width).
pub const GUEST_ES_BASE: u32 = 0x6806;
pub const GUEST_CS_BASE: u32 = 0x6808;
pub const GUEST_SS_BASE: u32 = 0x680A;
pub const GUEST_DS_BASE: u32 = 0x680C;
pub const GUEST_FS_BASE: u32 = 0x680E;
pub const GUEST_GS_BASE: u32 = 0x6810;
pub const GUEST_LDTR_BASE: u32 = 0x6812;
pub const GUEST_TR_BASE: u32 = 0x6814;
pub const GUEST_GDTR_BASE: u32 = 0x6816;
pub const GUEST_IDTR_BASE: u32 = 0x6818;

/// Guest DR7 (natural width), loaded when "load debug controls" is set.
pub const GUEST_DR7: u32 = 0x681A;
/// Guest RSP (natural width).
pub const GUEST_RSP: u32 = 0x681C;
/// Guest RIP (natural width).
pub const GUEST_RIP: u32 = 0x681E;
/// Guest RFLAGS (natural width).
pub const GUEST_RFLAGS: u32 = 0x6820;
/// Guest pending debug exceptions (natural width): 0 = none pending.
pub const GUEST_PENDING_DEBUG_EXCEPTIONS: u32 = 0x6822;
/// Guest SYSENTER stack and entry addresses (natural width).
pub const GUEST_IA32_SYSENTER_ESP: u32 = 0x6824;
pub const GUEST_IA32_SYSENTER_EIP: u32 = 0x6826;

/// Host segment selectors (16-bit).
pub const HOST_ES_SELECTOR: u32 = 0x0C00;
pub const HOST_CS_SELECTOR: u32 = 0x0C02;
pub const HOST_SS_SELECTOR: u32 = 0x0C04;
pub const HOST_DS_SELECTOR: u32 = 0x0C06;
pub const HOST_FS_SELECTOR: u32 = 0x0C08;
pub const HOST_GS_SELECTOR: u32 = 0x0C0A;
pub const HOST_TR_SELECTOR: u32 = 0x0C0C;

/// Host PAT and EFER (64-bit, loaded when selected on VM exit).
pub const HOST_IA32_PAT: u32 = 0x2C00;
pub const HOST_IA32_EFER: u32 = 0x2C02;

/// Host SYSENTER code selector (32-bit).
pub const HOST_IA32_SYSENTER_CS: u32 = 0x4C00;

/// Host control registers (natural width).
pub const HOST_CR0: u32 = 0x6C00;
pub const HOST_CR3: u32 = 0x6C02;
pub const HOST_CR4: u32 = 0x6C04;

/// Host segment and descriptor-table bases (natural width).
pub const HOST_FS_BASE: u32 = 0x6C06;
pub const HOST_GS_BASE: u32 = 0x6C08;
pub const HOST_TR_BASE: u32 = 0x6C0A;
pub const HOST_GDTR_BASE: u32 = 0x6C0C;
pub const HOST_IDTR_BASE: u32 = 0x6C0E;

/// Host SYSENTER stack and entry addresses (natural width).
pub const HOST_IA32_SYSENTER_ESP: u32 = 0x6C10;
pub const HOST_IA32_SYSENTER_EIP: u32 = 0x6C12;

/// Host RSP: the stack the CPU switches to on every VM exit.
pub const HOST_RSP: u32 = 0x6C14;
/// Host RIP: the exit handler the CPU jumps to on every VM exit.
pub const HOST_RIP: u32 = 0x6C16;
