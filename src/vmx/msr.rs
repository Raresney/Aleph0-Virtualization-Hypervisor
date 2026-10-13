//! Model-specific registers (MSRs): their addresses, the bits this
//! hypervisor reads in them, and RDMSR/WRMSR.
use core::arch::asm;

/// MSR address of IA32_FEATURE_CONTROL.
pub const IA32_FEATURE_CONTROL: u32 = 0x3A;

/// Bit 0: lock bit. Once set, the MSR is read-only until reset.
pub const LOCK_BIT: u64 = 1 << 0;

/// Bit 2: enable VMX outside SMX operation.
pub const VMX_OUTSIDE_SMX_BIT: u64 = 1 << 2;

/// SYSENTER's host code selector, stack pointer, and entry address.
pub const IA32_SYSENTER_CS: u32 = 0x174;
pub const IA32_SYSENTER_ESP: u32 = 0x175;
pub const IA32_SYSENTER_EIP: u32 = 0x176;

/// Page attribute table and extended feature enable register.
pub const IA32_PAT: u32 = 0x277;
pub const IA32_EFER: u32 = 0xC000_0080;

/// IA32_EFER bit 11 (NXE): no-execute enable. While clear, the XD bit in a
/// page-table entry is reserved, not a permission.
pub const EFER_NXE: u64 = 1 << 11;

/// MSRs holding the FS and GS segment bases. Unlike the selectors, these are
/// live in long mode: operating systems use FS/GS for per-thread and per-CPU
/// data.
pub const IA32_FS_BASE: u32 = 0xC000_0100;
pub const IA32_GS_BASE: u32 = 0xC000_0101;

pub unsafe fn read_feature_control() -> u64 {
    unsafe { rdmsr(IA32_FEATURE_CONTROL) }
}

/// Returns whether VMX is enabled for operation outside SMX.
///
/// The IA32_FEATURE_CONTROL MSR must be locked and the
/// VMX-outside-SMX bit (bit 2) must be set.
pub unsafe fn feature_control_vmx_enabled() -> bool {
    let value = unsafe { read_feature_control() };

    let locked = value & LOCK_BIT != 0;
    let vmx_enabled = value & VMX_OUTSIDE_SMX_BIT != 0;

    locked && vmx_enabled
}

/// IA32_VMX_BASIC. Bits 0..=30: VMCS revision identifier (bit 31 is always 0).
/// Bit 55: when set, the `IA32_VMX_TRUE_*_CTLS` MSRs exist and should be
/// preferred over the non-TRUE variants when configuring the VMCS later.
pub const IA32_VMX_BASIC: u32 = 0x480;

pub const IA32_VMX_PINBASED_CTLS: u32 = 0x481;
pub const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
pub const IA32_VMX_EXIT_CTLS: u32 = 0x483;
pub const IA32_VMX_ENTRY_CTLS: u32 = 0x484;
pub const IA32_VMX_TRUE_PINBASED_CTLS: u32 = 0x48D;
pub const IA32_VMX_TRUE_PROCBASED_CTLS: u32 = 0x48E;
pub const IA32_VMX_TRUE_EXIT_CTLS: u32 = 0x48F;
pub const IA32_VMX_TRUE_ENTRY_CTLS: u32 = 0x490;

/// Secondary processor-based controls: same layout as the other control
/// MSRs. It has no "true" variant. Exists only if the primary controls allow
/// bit 31 (activate secondary controls).
pub const IA32_VMX_PROCBASED_CTLS2: u32 = 0x48B;
/// What EPT and VPID support: page-walk lengths, memory types, page sizes,
/// INVEPT types. Exists only if the secondary controls allow EPT or VPID.
pub const IA32_VMX_EPT_VPID_CAP: u32 = 0x48C;

/// Primary control bit 31, "activate secondary controls", as it appears in
/// the allowed (high) half of the primary capability MSR.
const PRIMARY_ALLOWS_SECONDARY: u64 = 1 << (32 + 31);
/// Secondary control bit 1 (enable EPT) and bit 5 (enable VPID), in the
/// allowed half of the secondary capability MSR.
const SECONDARY_ALLOWS_EPT_OR_VPID: u64 = (1 << (32 + 1)) | (1 << (32 + 5));

/// Raw VMX control capability MSRs, not the values currently in the VMCS.
/// For each control MSR, the low 32 bits require control bits to be 1;
/// the high 32 bits allow control bits to be 1. At the same bit position:
/// (low, high) = (0, 0) means must be 0, (0, 1) means either value,
/// and (1, 1) means must be 1. (1, 0) is inconsistent.
/// `basic` and `ept_vpid_cap` have different layouts and are not
/// control-bit masks.
#[derive(Debug, Clone, Copy)]
pub struct VmcsControlMsrs {
    pub basic: u64,
    pub pinbased: u64,
    pub primary: u64,
    pub exit: u64,
    pub entry: u64,
    /// IA32_VMX_PROCBASED_CTLS2, or 0 when the CPU has no secondary
    /// controls. 0 allows no bit, so every secondary request is refused.
    pub secondary: u64,
    /// IA32_VMX_EPT_VPID_CAP, or 0 when the CPU supports neither EPT nor
    /// VPID.
    pub ept_vpid_cap: u64,
}

/// Read IA32_VMX_BASIC and the four control MSRs, selecting the true variants
/// when BASIC bit 55 reports them, plus the secondary controls and the
/// EPT/VPID capabilities where they exist. This does not write VMCS fields.
///
/// # Safety
///
/// The caller must first confirm CPU support for VMX before reading VMX MSRs.
pub unsafe fn read_vmcs_control_msrs() -> VmcsControlMsrs {
    unsafe {
        let basic = rdmsr(IA32_VMX_BASIC);
        let use_true_controls = basic & (1u64 << 55) != 0;
        let (pin_id, primary_id, exit_id, entry_id) = if use_true_controls {
            (
                IA32_VMX_TRUE_PINBASED_CTLS,
                IA32_VMX_TRUE_PROCBASED_CTLS,
                IA32_VMX_TRUE_EXIT_CTLS,
                IA32_VMX_TRUE_ENTRY_CTLS,
            )
        } else {
            (
                IA32_VMX_PINBASED_CTLS,
                IA32_VMX_PROCBASED_CTLS,
                IA32_VMX_EXIT_CTLS,
                IA32_VMX_ENTRY_CTLS,
            )
        };
        let pinbased = rdmsr(pin_id);
        let primary = rdmsr(primary_id);
        let exit = rdmsr(exit_id);
        let entry = rdmsr(entry_id);
        // Reading an MSR the CPU does not have raises #GP, so each one is
        // read only when the MSR before it says it exists.
        let secondary = if primary & PRIMARY_ALLOWS_SECONDARY != 0 {
            rdmsr(IA32_VMX_PROCBASED_CTLS2)
        } else {
            0
        };
        let ept_vpid_cap = if secondary & SECONDARY_ALLOWS_EPT_OR_VPID != 0 {
            rdmsr(IA32_VMX_EPT_VPID_CAP)
        } else {
            0
        };

        VmcsControlMsrs {
            basic,
            pinbased,
            primary,
            exit,
            entry,
            secondary,
            ept_vpid_cap,
        }
    }
}

/// Bits that must be 1 in CR0 while in VMX operation.
pub const IA32_VMX_CR0_FIXED0: u32 = 0x486;
/// Bits that may be 1 in CR0 while in VMX operation (a 0 here means "must be 0").
pub const IA32_VMX_CR0_FIXED1: u32 = 0x487;
/// Bits that must be 1 in CR4 while in VMX operation.
pub const IA32_VMX_CR4_FIXED0: u32 = 0x488;
/// Bits that may be 1 in CR4 while in VMX operation (a 0 here means "must be 0").
pub const IA32_VMX_CR4_FIXED1: u32 = 0x489;

/// Reads an arbitrary MSR.
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let (low, high): (u32, u32);

    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }

    ((high as u64) << 32) | low as u64
}
