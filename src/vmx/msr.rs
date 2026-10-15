//! Model-specific registers (MSRs): their addresses, the bits this
//! hypervisor reads in them, and RDMSR.
use core::arch::asm;

use super::vmcs::fields::{CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, SECONDARY_ENABLE_EPT, SECONDARY_ENABLE_VPID};

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
/// IA32_KERNEL_GS_BASE: the GS base SWAPGS exchanges with IA32_GS_BASE.
/// VM entry and exit do not switch it, so while the guest runs it holds the
/// guest's value, and Aleph0 (which never runs SWAPGS) does not use it.
pub const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;
/// MSRs whose guest value is a VMCS guest-state field (loaded at VM entry,
/// saved at VM exit when the controls say so). Listed for
/// `exit_bitmaps::VMCS_HELD_MSRS`; Aleph0 does not read or write them.
pub const IA32_DEBUGCTL: u32 = 0x1D9;
pub const IA32_PERF_GLOBAL_CTRL: u32 = 0x38F;
pub const IA32_BNDCFGS: u32 = 0xD90;

/// Reads IA32_FEATURE_CONTROL.
///
/// # Safety
///
/// The CPU must support VMX or SMX (CPUID), or the MSR may not exist and the
/// read raises #GP.
pub unsafe fn read_feature_control() -> u64 {
    // SAFETY: the caller guarantees VMX or SMX support, so the MSR exists;
    // reading it has no side effects.
    unsafe { rdmsr(IA32_FEATURE_CONTROL) }
}

/// Returns whether VMX is enabled for operation outside SMX.
///
/// The IA32_FEATURE_CONTROL MSR must be locked and the
/// VMX-outside-SMX bit (bit 2) must be set.
///
/// # Safety
///
/// As for [`read_feature_control`]: the CPU must support VMX or SMX.
pub unsafe fn feature_control_vmx_enabled() -> bool {
    // SAFETY: the caller's obligation, as for `read_feature_control`.
    let value = unsafe { read_feature_control() };

    let locked = value & LOCK_BIT != 0;
    let vmx_enabled = value & VMX_OUTSIDE_SMX_BIT != 0;

    locked && vmx_enabled
}

/// IA32_VMX_BASIC. Bits 0..=30: VMCS revision identifier (bit 31 is always 0).
/// Bit 55: see [`VMX_BASIC_TRUE_CONTROLS`].
pub const IA32_VMX_BASIC: u32 = 0x480;
/// IA32_VMX_BASIC bit 55: the `IA32_VMX_TRUE_*_CTLS` MSRs exist and should
/// be preferred over the non-TRUE variants when configuring the VMCS.
pub const VMX_BASIC_TRUE_CONTROLS: u64 = 1 << 55;

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

/// One raw VMX control capability MSR, for one 32-bit control field.
///
/// The low 32 bits require control bits to be 1; the high 32 bits allow
/// control bits to be 1. At the same bit position: (low, high) = (0, 0)
/// means must be 0, (0, 1) means either value, and (1, 1) means must be 1.
/// (1, 0) is inconsistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlCapability(pub u64);

/// A control value the CPU does not allow: a requested bit outside the
/// allowed half, or a capability whose required bits are not allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedControl;

impl ControlCapability {
    /// Bits that must be 1 (the low half).
    pub fn required(self) -> u32 {
        self.0 as u32
    }

    /// Bits that may be 1 (the high half).
    pub fn allowed(self) -> u32 {
        (self.0 >> 32) as u32
    }

    /// Whether every bit of `bits` may be 1.
    pub fn allows(self, bits: u32) -> bool {
        self.allowed() & bits == bits
    }

    /// The control value for `desired`: its bits plus the required ones.
    /// Rejects an inconsistent capability or a requested bit the CPU
    /// cannot enable.
    pub fn choose(self, desired: u32) -> Result<u32, UnsupportedControl> {
        if !self.allows(self.required()) || !self.allows(desired) {
            return Err(UnsupportedControl);
        }
        // Add mandatory bits without changing any other requested bits.
        Ok(desired | self.required())
    }
}

/// Raw VMX capability MSRs, not the values currently in the VMCS.
/// `basic` and `ept_vpid_cap` have their own layouts; the rest are
/// [`ControlCapability`] pairs.
#[derive(Debug, Clone, Copy)]
pub struct VmcsControlMsrs {
    pub basic: u64,
    pub pinbased: ControlCapability,
    pub primary: ControlCapability,
    pub exit: ControlCapability,
    pub entry: ControlCapability,
    /// IA32_VMX_PROCBASED_CTLS2, or 0 when the CPU has no secondary
    /// controls. 0 allows no bit, so every secondary request is refused.
    pub secondary: ControlCapability,
    /// IA32_VMX_EPT_VPID_CAP, or 0 when the CPU supports neither EPT nor
    /// VPID.
    pub ept_vpid_cap: u64,
}

/// Read IA32_VMX_BASIC and the four control MSRs, selecting the true variants
/// when [`VMX_BASIC_TRUE_CONTROLS`] reports them, plus the secondary controls
/// and the EPT/VPID capabilities where they exist. This does not write VMCS
/// fields.
///
/// # Safety
///
/// The caller must first confirm CPU support for VMX before reading VMX MSRs.
pub unsafe fn read_vmcs_control_msrs() -> VmcsControlMsrs {
    // SAFETY: the caller confirmed VMX support, so IA32_VMX_BASIC and the
    // control MSRs exist; the optional ones are read only when the MSR
    // before them says they exist.
    unsafe {
        let basic = rdmsr(IA32_VMX_BASIC);
        let use_true_controls = basic & VMX_BASIC_TRUE_CONTROLS != 0;
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
        let pinbased = ControlCapability(rdmsr(pin_id));
        let primary = ControlCapability(rdmsr(primary_id));
        let exit = ControlCapability(rdmsr(exit_id));
        let entry = ControlCapability(rdmsr(entry_id));
        // Reading an MSR the CPU does not have raises #GP, so each one is
        // read only when the MSR before it says it exists.
        let secondary = ControlCapability(if primary.allows(CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
            rdmsr(IA32_VMX_PROCBASED_CTLS2)
        } else {
            0
        });
        let ept_vpid_cap = if secondary.allows(SECONDARY_ENABLE_EPT) || secondary.allows(SECONDARY_ENABLE_VPID) {
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
///
/// # Safety
///
/// `msr` must exist on this CPU, or RDMSR raises #GP. A few MSRs change
/// state when read; reading one of those must be what the caller wants.
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let (low, high): (u32, u32);

    // SAFETY: RDMSR only reads the MSR; the caller guarantees it exists
    // and that reading it is harmless.
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

#[cfg(test)]
#[path = "../../tests/unit/vmx/msr.rs"]
mod tests;
