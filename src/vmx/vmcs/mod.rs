//! The Virtual Machine Control Structure (VMCS).
//!
//! A VMCS describes one virtual CPU: the guest's register state, the host
//! state to return to on a VM exit, and which events cause those exits.
//! One VMCS per vCPU; one "current" VMCS per logical processor.
//!
//! The region looks exactly like the VMXON region — 4 KiB, 4 KiB-aligned,
//! revision identifier in the first four bytes — but it is used differently.
//! Apart from that revision identifier, **never touch it with ordinary loads
//! and stores**: the internal layout is undocumented and the CPU caches
//! fields internally. [`vmread`] and [`vmwrite`] are the only legal access.
//!
//! Lifecycle:
//!
//! 1. [`VmxRegion::allocate`] — a page with the revision identifier, same
//!    as the VMXON region.
//! 2. [`VmcsRegion::vmclear`] — initialise it and flush any cached data the
//!    CPU holds for that physical address. Required once before first use,
//!    even on a freshly zeroed page.
//! 3. [`VmcsRegion::vmptrld`] — make it the *current* VMCS. From here on
//!    [`vmread`]/[`vmwrite`] act on it implicitly, with no address operand.
//! 4. [`vmwrite`] the fields, then [`launch`] (VMLAUNCH).
//!
//! [`VmcsRegion::create_current`] runs steps 1-3.
//!
//! Fields are addressed by a 32-bit **encoding**, not by an offset. The
//! encoding packs the field's width, type (control / read-only / guest /
//! host) and index; every encoding this hypervisor uses is in [`fields`].
//!
//! Like VMXON, these instructions report failure through RFLAGS rather than
//! exceptions: CF=1 is VMfailInvalid, ZF=1 is VMfailValid. The difference is
//! that once a current VMCS exists, VMfailValid also stores a numeric reason
//! readable via [`vm_instruction_error`].

use crate::vmx::ept::Eptp;
use crate::vmx::instruction::{VmxFail, check_rflags, vmx_asm};
use crate::vmx::msr::{self, UnsupportedControl, VmcsControlMsrs};
use crate::vmx::region::VmxRegion;
use crate::vmx::{cr, segment};
use core::arch::asm;

pub mod fields;
mod launch;

pub use launch::{GuestStop, encode_finished, encode_resume_failed, encode_unexpected, launch};

// Private glob: this file uses dozens of encodings. Callers elsewhere import
// from `vmcs::fields` themselves, so each constant has a single path.
use fields::*;

/// Requested control bits; CPU-required bits are added by `configure_controls`.
#[derive(Debug, Clone, Copy)]
pub struct DesiredControls {
    pub pin: u32,
    pub primary: u32,
    /// Secondary processor-based controls. Nonzero also turns on primary
    /// bit 31, without which the CPU ignores them.
    pub secondary: u32,
    pub exit: u32,
    pub entry: u32,
}

impl DesiredControls {
    /// Minimal requests for a 64-bit guest on this 64-bit host, plus NMI
    /// exiting with virtual NMIs, so Aleph0 sees the guest's NMIs and can
    /// reinject them, EPT, so guest memory goes through Aleph0's tables, and
    /// the MSR and I/O bitmaps, so only the MSRs and ports Aleph0 chooses
    /// exit (`vmx::exit_bitmaps`).
    pub const fn minimal_64_bit_guest() -> Self {
        Self {
            pin: PIN_BASED_NMI_EXITING | PIN_BASED_VIRTUAL_NMIS,
            primary: CPU_BASED_USE_IO_BITMAPS | CPU_BASED_USE_MSR_BITMAPS,
            secondary: SECONDARY_ENABLE_EPT,
            exit: VM_EXIT_HOST_ADDRESS_SPACE_SIZE,
            entry: VM_ENTRY_IA32E_MODE_GUEST,
        }
    }
}

/// The primary controls to request for `desired`: its own bits, plus
/// "activate secondary controls" when it asks for any secondary control.
fn primary_request(desired: DesiredControls) -> u32 {
    if desired.secondary != 0 {
        desired.primary | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS
    } else {
        desired.primary
    }
}

/// Exception bitmap value: every exception vector (0-31) causes a VM exit.
///
/// The guest has its own IDT with only vector 2 (NMI) present. Without an
/// exit, a guest fault would hit a missing gate (#GP, then #DF, then a triple
/// fault), so the host would see nothing useful. With all bits set, every
/// exception arrives as exit reason 0 and the handler prints the vector.
const EXCEPTION_BITMAP_ALL: u32 = u32::MAX;

/// Why a VMCS operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmcsError {
    /// UEFI could not provide a page.
    AllocationFailed,
    /// CF=1: the instruction failed with no current VMCS to record why.
    VmFailInvalid,
    /// ZF=1: the instruction failed and stored a reason in the current VMCS;
    /// read it with [`vm_instruction_error`].
    VmFailValid,
    /// [`write_verified`] read `read` back from `field` after writing
    /// `written`. Both instructions reported success, so this is not a VMX
    /// failure.
    ReadbackMismatch { field: u32, written: u64, read: u64 },
    /// The requested control value is not supported by the processor.
    UnsupportedControlValue,
    /// A host-state value failed its check before being written: a selector
    /// with RPL or TI set, a null CS or TR, or a null or misaligned
    /// HOST_RSP/HOST_RIP.
    HostStateValidation,
    /// VMLAUNCH fell through to the next instruction with CF and ZF both
    /// clear. A successful VMLAUNCH never falls through, so the guest was
    /// not entered, for a reason the flags do not say.
    LaunchReturned,
    /// VMRESUME fell through to the next instruction with CF and ZF both
    /// clear. Like [`VmcsError::LaunchReturned`], the guest was not entered.
    ResumeReturned,
    /// The CPU does not allow NMI-window exiting, which the exit handler
    /// needs to inject an NMI that arrived while the guest blocked NMIs.
    NmiWindowExitingUnsupported,
}

impl From<VmxFail> for VmcsError {
    fn from(fail: VmxFail) -> Self {
        match fail {
            VmxFail::Invalid => Self::VmFailInvalid,
            VmxFail::Valid => Self::VmFailValid,
        }
    }
}

impl From<UnsupportedControl> for VmcsError {
    fn from(_: UnsupportedControl) -> Self {
        Self::UnsupportedControlValue
    }
}

/// A VMCS: a [`VmxRegion`] used as a VMCS, through VMCLEAR and VMPTRLD.
pub struct VmcsRegion {
    region: VmxRegion,
}

impl VmcsRegion {
    /// Initialises the VMCS and flushes CPU-cached data for its address.
    ///
    /// Must run once before the region is first used, and again whenever a
    /// VMCS stops being current on this processor.
    ///
    /// # Safety
    ///
    /// The CPU must be in VMX root operation.
    pub unsafe fn vmclear(&self) -> Result<(), VmcsError> {
        // SAFETY: VMCLEAR reads only the 8-byte operand and works on a region
        // this value owns; the caller guarantees VMX root operation.
        Ok(unsafe { vmx_asm!("vmclear [{0}]", in(reg) self.region.phys_addr_ref()) }?)
    }

    /// Allocates a VMCS, initialises it, and makes it the current VMCS.
    ///
    /// Runs lifecycle steps 1-3. The region must stay allocated for as long
    /// as it is current or may become current again.
    ///
    /// # Safety
    ///
    /// The CPU must be in VMX root operation.
    pub unsafe fn create_current() -> Result<Self, VmcsError> {
        // SAFETY: VMX root operation (the caller's obligation) implies VMX
        // support. The revision identifier is written before VMPTRLD, not
        // just before use: VMPTRLD rejects a region whose identifier does
        // not match the CPU (error 11).
        unsafe {
            let vmcs = Self {
                region: VmxRegion::allocate(VmcsError::AllocationFailed)?,
            };
            vmcs.vmclear()?;
            vmcs.vmptrld()?;
            Ok(vmcs)
        }
    }

    /// Makes this VMCS the current one for this logical processor.
    ///
    /// # Safety
    ///
    /// The CPU must be in VMX root operation, and the region must have been
    /// cleared with [`VmcsRegion::vmclear`].
    pub unsafe fn vmptrld(&self) -> Result<(), VmcsError> {
        // SAFETY: VMPTRLD reads only the 8-byte operand; the caller
        // guarantees VMX root operation and a cleared region.
        Ok(unsafe { vmx_asm!("vmptrld [{0}]", in(reg) self.region.phys_addr_ref()) }?)
    }
}

/// Reads a field from the current VMCS.
///
/// Operand order is the opposite of [`vmwrite`]: `VMREAD dest, field`, so the
/// destination register comes first and the encoding second.
///
/// # Safety
///
/// VMX operation must be active and a VMCS current on this CPU; outside VMX
/// operation VMREAD raises #UD.
pub unsafe fn vmread(field_encoding: u32) -> Result<u64, VmcsError> {
    let value: u64;
    let rflags: u64;

    // SAFETY: the caller guarantees VMX operation with a current VMCS;
    // VMREAD writes only `value` and RFLAGS.
    unsafe {
        asm!(
            "vmread {value}, {field:r}",
            "pushfq",
            "pop {rflags}",
            value = out(reg) value,
            // Cast to u64 like vmwrite does: `{field:r}` names the full
            // 64-bit register, and a u32 input leaves its upper half
            // undefined, which the CPU would read as part of the encoding.
            field = in(reg) field_encoding as u64,
            rflags = lateout(reg) rflags,
        );
    }

    check_rflags(rflags)?;

    Ok(value)
}

/// Writes a field in the current VMCS.
///
/// Operand order is `VMWRITE field, value` — the encoding comes first, which
/// reads backwards compared to a normal `mov`.
///
/// # Safety
///
/// VMX operation must be active and a VMCS current on this CPU. The value
/// takes effect at the next VM entry or exit, so it must be one the rest of
/// Aleph0 expects in that field.
pub unsafe fn vmwrite(field_encoding: u32, value: u64) -> Result<(), VmcsError> {
    let rflags: u64;

    // SAFETY: the caller guarantees VMX operation with a current VMCS,
    // and that the value suits the field; VMWRITE changes only the VMCS.
    unsafe {
        asm!(
            "vmwrite {field:r}, {value}",
            "pushfq",
            "pop {rflags}",
            value = in(reg) value,
            field = in(reg) field_encoding as u64,
            rflags = lateout(reg) rflags,
        );
    }

    Ok(check_rflags(rflags)?)
}

/// Writes a field in the current VMCS and reads it back, so a value that did
/// not land as written is caught here rather than as a VM-entry failure.
///
/// # Safety
///
/// VMX operation must be active and a VMCS current on this CPU.
pub unsafe fn write_verified(field: u32, value: u64) -> Result<(), VmcsError> {
    // SAFETY: the caller guarantees VMX operation with a current VMCS.
    let read = unsafe {
        vmwrite(field, value)?;
        vmread(field)?
    };
    if read != value {
        return Err(VmcsError::ReadbackMismatch {
            field,
            written: value,
            read,
        });
    }
    Ok(())
}

/// Decodes the RFLAGS left behind when VMLAUNCH falls through. That only
/// happens on failure, so clear flags become [`VmcsError::LaunchReturned`]
/// instead of success.
fn launch_failure(rflags: u64) -> VmcsError {
    fall_through_failure(rflags, VmcsError::LaunchReturned)
}

/// Decodes the RFLAGS left behind when VMRESUME falls through. VMRESUME runs
/// in the VM-exit entry stub (`vmx::vmexit`), which passes RFLAGS here, so
/// this is public; clear flags become [`VmcsError::ResumeReturned`].
pub fn resume_failure(rflags: u64) -> VmcsError {
    fall_through_failure(rflags, VmcsError::ResumeReturned)
}

/// VMLAUNCH and VMRESUME reach the next instruction only when they fail:
/// CF=1 and ZF=1 say how, and clear flags mean `clear`.
fn fall_through_failure(rflags: u64, clear: VmcsError) -> VmcsError {
    match check_rflags(rflags) {
        Err(fail) => fail.into(),
        Ok(()) => clear,
    }
}

/// Derive legal pin, primary, exit, and entry controls from the CPU masks,
/// write them to the current VMCS, and verify each field by reading it back.
/// When `desired.secondary` is nonzero, the secondary controls are chosen,
/// written and verified the same way, and primary bit 31 activates them.
/// Always request 64-bit host mode on VM exit, regardless of `desired.exit`.
/// Also zeroes the counts and fields VM entry checks, and makes every guest
/// exception exit ([`EXCEPTION_BITMAP_ALL`]). It also checks that the CPU
/// allows NMI-window exiting (`VmcsError::NmiWindowExitingUnsupported`
/// otherwise), which the exit handler switches on at run time.
///
/// # Safety
///
/// VMX operation must be active and a VMCS must be current on this CPU.
pub unsafe fn configure_controls(capabilities: &VmcsControlMsrs, desired: DesiredControls) -> Result<(), VmcsError> {
    let pin = capabilities.pinbased.choose(desired.pin)?;
    let primary = capabilities.primary.choose(primary_request(desired))?;
    let secondary = if desired.secondary != 0 {
        Some(capabilities.secondary.choose(desired.secondary)?)
    } else {
        None
    };
    // NMI-window exiting is only switched on while an NMI waits for
    // injection (`set_nmi_window_exiting`), but the CPU must allow it.
    if !capabilities.primary.allows(CPU_BASED_NMI_WINDOW_EXITING) {
        return Err(VmcsError::NmiWindowExitingUnsupported);
    }
    let exit = capabilities
        .exit
        .choose(desired.exit | VM_EXIT_HOST_ADDRESS_SPACE_SIZE)?;
    let entry = capabilities.entry.choose(desired.entry)?;

    // SAFETY: the caller guarantees VMX operation with a current VMCS.
    unsafe {
        write_verified(PIN_BASED_VM_EXEC_CONTROL, pin.into())?;
        write_verified(PRIMARY_VM_EXEC_CONTROL, primary.into())?;
        write_verified(VM_EXIT_CONTROLS, exit.into())?;
        write_verified(VM_ENTRY_CONTROLS, entry.into())?;
        if let Some(secondary) = secondary {
            write_verified(SECONDARY_VM_EXEC_CONTROL, secondary.into())?;
        }

        // VM entry checks these fields, and VMCLEAR does not guarantee that
        // a fresh VMCS holds zeros in them, so write the zeros explicitly:
        // no CR3 targets, no MSR load/store lists, no event injection. The
        // #PF mask and match are not entry checks, but they decide which
        // page faults the exception bitmap below catches: 0 and 0 mean all.
        for field in [
            CR3_TARGET_COUNT,
            VM_EXIT_MSR_STORE_COUNT,
            VM_EXIT_MSR_LOAD_COUNT,
            VM_ENTRY_MSR_LOAD_COUNT,
            VM_ENTRY_INTERRUPTION_INFO,
            PAGE_FAULT_ERROR_CODE_MASK,
            PAGE_FAULT_ERROR_CODE_MATCH,
        ] {
            write_verified(field, 0)?;
        }

        write_verified(EXCEPTION_BITMAP, EXCEPTION_BITMAP_ALL.into())?;
    }

    Ok(())
}

/// Capture the active host state and write it to the current VMCS.
/// Do not use this as evidence that VM entry is ready until all host fields
/// required by the selected VM-exit controls have been populated.
///
/// # Safety
///
/// VMX operation must be active, a VMCS must be current on this CPU, and the
/// host GDT and TSS must already be active and remain valid on VM exit.
pub unsafe fn configure_host_state() -> Result<(), VmcsError> {
    // SAFETY: the caller guarantees the host GDT is active and live, and UEFI
    // runs in long mode.
    let segments = unsafe { segment::read_all() };
    let cr0 = cr::read_cr0();
    let cr3 = cr::read_cr3();
    let cr4 = cr::read_cr4();
    // SAFETY: the SYSENTER MSRs exist on every x86_64 CPU, and reading
    // them has no side effects.
    let (sysenter_cs, sysenter_esp, sysenter_eip) = unsafe {
        (
            u64::from(msr::rdmsr(msr::IA32_SYSENTER_CS) as u32),
            msr::rdmsr(msr::IA32_SYSENTER_ESP),
            msr::rdmsr(msr::IA32_SYSENTER_EIP),
        )
    };

    // VM entry requires every host selector to have RPL and TI clear, and
    // CS and TR to be non-null.
    {
        let selectors = [
            segments.es,
            segments.cs,
            segments.ss,
            segments.ds,
            segments.fs,
            segments.gs,
            segments.tr,
        ];

        if selectors
            .iter()
            .any(|selector| selector & segment::SELECTOR_RPL_TI != 0)
        {
            return Err(VmcsError::HostStateValidation);
        }
    }

    if segments.cs == 0 || segments.tr == 0 {
        return Err(VmcsError::HostStateValidation);
    }
    // SAFETY: the caller guarantees VMX operation with a current VMCS.
    let exit_controls = unsafe { vmread(VM_EXIT_CONTROLS)? };

    // SAFETY: the caller guarantees VMX operation with a current VMCS. PAT
    // and EFER are read only when the exit controls load them, which the CPU
    // allows only if it has them.
    // Host PAT and EFER are written only when the exit controls load them.
    // HOST_RSP and HOST_RIP come later, from `configure_host_entry`.
    unsafe {
        write_verified(HOST_ES_SELECTOR, segments.es as u64)?;
        write_verified(HOST_CS_SELECTOR, segments.cs as u64)?;
        write_verified(HOST_SS_SELECTOR, segments.ss as u64)?;
        write_verified(HOST_DS_SELECTOR, segments.ds as u64)?;
        write_verified(HOST_FS_SELECTOR, segments.fs as u64)?;
        write_verified(HOST_GS_SELECTOR, segments.gs as u64)?;
        write_verified(HOST_TR_SELECTOR, segments.tr as u64)?;

        write_verified(HOST_CR0, cr0)?;
        write_verified(HOST_CR3, cr3)?;
        write_verified(HOST_CR4, cr4)?;

        write_verified(HOST_FS_BASE, segments.fs_base)?;
        write_verified(HOST_GS_BASE, segments.gs_base)?;
        write_verified(HOST_TR_BASE, segments.tr_base)?;
        write_verified(HOST_GDTR_BASE, segments.gdtr.base)?;
        write_verified(HOST_IDTR_BASE, segments.idtr.base)?;

        write_verified(HOST_IA32_SYSENTER_CS, sysenter_cs)?;
        write_verified(HOST_IA32_SYSENTER_ESP, sysenter_esp)?;
        write_verified(HOST_IA32_SYSENTER_EIP, sysenter_eip)?;

        if exit_controls & VM_EXIT_LOAD_IA32_PAT != 0 {
            write_verified(HOST_IA32_PAT, msr::rdmsr(msr::IA32_PAT))?;
        }
        if exit_controls & VM_EXIT_LOAD_IA32_EFER != 0 {
            write_verified(HOST_IA32_EFER, msr::rdmsr(msr::IA32_EFER))?;
        }
    }

    Ok(())
}

/// Store the host stack top and VM-exit entry address without entering a guest.
///
/// # Safety
///
/// VMX operation must be active and a VMCS current on this CPU. The stack
/// and entry code must remain mapped and valid whenever a VM exit can occur.
pub unsafe fn configure_host_entry(stack_top: u64, entry_address: u64) -> Result<(), VmcsError> {
    if stack_top == 0 || stack_top & 15 != 0 || entry_address == 0 {
        return Err(VmcsError::HostStateValidation);
    }

    // SAFETY: the caller guarantees VMX operation with a current VMCS.
    unsafe {
        write_verified(HOST_RSP, stack_top)?;
        write_verified(HOST_RIP, entry_address)?;
    }
    Ok(())
}

/// `primary` with NMI-window exiting turned on or off, other bits unchanged.
fn with_nmi_window_exiting(primary: u64, on: bool) -> u64 {
    let bit = u64::from(CPU_BASED_NMI_WINDOW_EXITING);
    if on { primary | bit } else { primary & !bit }
}

/// Turns NMI-window exiting on or off in the current VMCS. The exit handler
/// turns it on while an NMI waits until the guest can take it, and off once
/// the NMI is injected.
///
/// # Safety
///
/// VMX operation with a current VMCS. `configure_controls` has checked that
/// the CPU allows the bit.
pub unsafe fn set_nmi_window_exiting(on: bool) -> Result<(), VmcsError> {
    // SAFETY: the caller guarantees VMX operation with a current VMCS.
    let primary = unsafe { vmread(PRIMARY_VM_EXEC_CONTROL)? };
    // SAFETY: the caller guarantees VMX operation with a current VMCS. Only
    // the NMI-window bit changes, which the caller checked the CPU allows.
    unsafe { vmwrite(PRIMARY_VM_EXEC_CONTROL, with_nmi_window_exiting(primary, on)) }
}

/// Writes the EPT pointer and reads it back. VM entry checks it only when
/// the "enable EPT" secondary control is set.
///
/// # Safety
///
/// VMX operation with a current VMCS. The tables `eptp` names must stay
/// allocated for as long as the VMCS may be used.
pub unsafe fn set_ept_pointer(eptp: Eptp) -> Result<(), VmcsError> {
    // SAFETY: the caller guarantees VMX operation with a current VMCS.
    unsafe { write_verified(EPT_POINTER, eptp.raw()) }
}

/// The numeric reason the last VMX instruction failed.
///
/// Only meaningful straight after a [`VmcsError::VmFailValid`], and only
/// while a current VMCS exists. The field keeps the last value the CPU wrote,
/// so reading it at any other time returns something stale with no way to
/// tell — that is the caller's responsibility, not something the hardware
/// flags.
///
/// Never call this to diagnose a failed [`vmread`]: this *is* a `vmread`, so
/// it would fail the same way and recurse.
///
/// # Safety
///
/// VMX operation must be active and a VMCS current on this CPU.
pub unsafe fn vm_instruction_error() -> Result<u32, VmcsError> {
    // VM_INSTRUCTION_ERROR is a 32-bit field; VMREAD zero-extends it.
    // SAFETY: the caller guarantees VMX operation with a current VMCS.
    Ok(unsafe { vmread(VM_INSTRUCTION_ERROR)? } as u32)
}

/// The VM-instruction error number behind `error`: `Some` only for a
/// VmFailValid whose number is readable.
///
/// Call it right after the failure. The number lives in the current VMCS,
/// so it is gone once the VMCS is cleared or VMX operation is left, which
/// teardown does before bring-up prints its errors.
///
/// # Safety
///
/// A VmFailValid can only come from a VMX instruction executed in VMX
/// operation with a current VMCS, so the VMREAD here cannot raise #UD. That
/// holds only until the VMCS is cleared or VMXOFF runs: call this before
/// either.
pub unsafe fn instruction_error_for(error: VmcsError) -> Option<u32> {
    if error == VmcsError::VmFailValid {
        // SAFETY: a VmFailValid comes from a VMX instruction run in VMX
        // operation with a current VMCS, which the caller guarantees is still
        // current.
        unsafe { vm_instruction_error() }.ok()
    } else {
        None
    }
}

/// Human-readable name for a [`vm_instruction_error`] code.
///
/// Numbers from Intel SDM Vol. 3, "VM-Instruction Error Numbers"; only the
/// ones reachable from this code are spelled out.
pub fn vm_instruction_error_name(error: u32) -> &'static str {
    match error {
        2 => "VMCLEAR with invalid physical address",
        3 => "VMCLEAR with VMXON pointer",
        4 => "VMLAUNCH with non-clear VMCS",
        5 => "VMRESUME with non-launched VMCS",
        7 => "VM entry with invalid control field(s)",
        8 => "VM entry with invalid host-state field(s)",
        9 => "VMPTRLD with invalid physical address",
        10 => "VMPTRLD with VMXON pointer",
        11 => "VMPTRLD with incorrect VMCS revision identifier",
        12 => "VMREAD/VMWRITE from/to unsupported VMCS component",
        13 => "VMWRITE to read-only VMCS component",
        15 => "VMXON executed in VMX root operation",
        _ => "unknown VM-instruction error",
    }
}

/// Proves the access path to the current VMCS works: write a field, read
/// it back.
///
/// Leaves the test pattern in GUEST_RIP; guest-state setup overwrites it.
///
/// # Safety
///
/// VMX operation must be active and a VMCS current on this CPU
/// ([`VmcsRegion::create_current`]).
pub unsafe fn self_test() -> Result<(), VmcsError> {
    // Bits set in both halves, so a write that only lands in the low 32 bits
    // is caught. Canonical (bits 63:47 clear), which GUEST_RIP will need once
    // VM entry starts checking it.
    const PATTERN: u64 = 0x0000_7FFF_DEAD_BEEF;

    // SAFETY: the caller guarantees VMX operation with a current VMCS.
    unsafe { write_verified(GUEST_RIP, PATTERN) }
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/vmcs.rs"]
mod tests;
