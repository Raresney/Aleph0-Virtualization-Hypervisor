//! Outcome reporting shared by every VMX instruction.
//!
//! VMX instructions do not raise exceptions on ordinary failure; they report
//! through RFLAGS instead. Each module's error type converts from
//! [`VmxFail`], so callers can use `?` straight after [`check_rflags`].

/// How a VMX instruction failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmxFail {
    /// CF=1: failed with no current VMCS to record why (VMfailInvalid).
    Invalid,
    /// ZF=1: failed and stored a reason in the current VMCS's
    /// VM-instruction error field (VMfailValid).
    Valid,
}

/// Decodes the RFLAGS value a VMX instruction leaves behind.
///
/// All flags clear on success, CF set for VMfailInvalid, ZF set for
/// VMfailValid. Call this right after the `asm!` block instead of repeating
/// the bit tests.
pub fn check_rflags(rflags: u64) -> Result<(), VmxFail> {
    /// RFLAGS.CF, bit 0.
    const CF: u64 = 1 << 0;
    /// RFLAGS.ZF, bit 6.
    const ZF: u64 = 1 << 6;

    if rflags & CF != 0 {
        Err(VmxFail::Invalid)
    } else if rflags & ZF != 0 {
        Err(VmxFail::Valid)
    } else {
        Ok(())
    }
}

/// Runs one VMX instruction and decodes its outcome from RFLAGS.
///
/// Expands to the instruction, then `pushfq; pop` into a fresh register,
/// then [`check_rflags`], and evaluates to `Result<(), VmxFail>`. Operands
/// follow the template as in `asm!`, without a trailing comma. Use it
/// inside an `unsafe` block whose `SAFETY` comment covers the instruction.
///
/// VMREAD and VMWRITE do not use it: they have an output, or operands whose
/// width needs spelling out, so they stay explicit `asm!` blocks.
macro_rules! vmx_asm {
    ($template:literal $(, $($operands:tt)+)?) => {{
        let rflags: u64;
        ::core::arch::asm!($template, "pushfq", "pop {rflags}", $($($operands)+,)? rflags = lateout(reg) rflags);
        $crate::vmx::instruction::check_rflags(rflags)
    }};
}
pub(crate) use vmx_asm;

#[cfg(test)]
#[path = "../../tests/unit/vmx/instruction.rs"]
mod tests;
