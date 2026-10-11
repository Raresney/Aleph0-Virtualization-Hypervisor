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
//! 1. [`VmcsRegion::allocate`] + [`VmcsRegion::write_revision_id`] — same as
//!    the VMXON region.
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

use core::arch::asm;
use crate::vmx::msr::{self, VmcsControlMsrs};
use crate::vmx::{cr, segment};
use crate::vmx::instruction::{check_rflags, VmxFail};

use super::page::{allocate_zeroed_page, PAGE_SIZE};
use super::vmxon::vmcs_revision_id;

pub mod fields;
mod launch;

pub use launch::{encode_finished, encode_resume_failed, encode_unexpected, launch, GuestStop};

// Private glob: this file uses dozens of encodings. Callers elsewhere import
// from `vmcs::fields` themselves, so each constant has a single path.
use fields::*;

/// VMCS region size. Architecturally at most 4 KiB; one page is the norm.
pub const VMCS_REGION_SIZE: usize = 4096;
const _: () = assert!(VMCS_REGION_SIZE == PAGE_SIZE);

/// Requested control bits; CPU-required bits are added by `configure_controls`.
#[derive(Debug, Clone, Copy)]
pub struct DesiredControls {
    pub pin: u32,
    pub primary: u32,
    pub exit: u32,
    pub entry: u32,
}

impl DesiredControls {
    /// Minimal requests for a 64-bit guest on this 64-bit host, plus NMI
    /// exiting with virtual NMIs, so Aleph0 sees the guest's NMIs and can
    /// reinject them.
    pub const fn minimal_64_bit_guest() -> Self {
        Self {
            pin: PIN_BASED_NMI_EXITING | PIN_BASED_VIRTUAL_NMIS,
            primary: 0,
            exit: VM_EXIT_HOST_ADDRESS_SPACE_SIZE,
            entry: VM_ENTRY_IA32E_MODE_GUEST,
        }
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
    /// [`self_test`] read back something other than what it wrote. Both
    /// instructions reported success, so this is not a VMX failure.
    SelfTestMismatch,
    /// The requested control value is not supported by the processor.
    UnsupportedControlValue,
    /// A control field read back differently from the value written to it.
    ControlReadbackMismatch,
    /// Host state validation failed.
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

/// A 4 KiB, 4 KiB-aligned VMCS region.
pub struct VmcsRegion {
    /// Physical address of the region. Equal to the virtual address under UEFI.
    phys_addr: u64,
}

impl VmcsRegion {
    /// Allocates and zeroes one page through UEFI Boot Services.
    pub fn allocate() -> Result<Self, VmcsError> {
        let ptr = allocate_zeroed_page(VmcsError::AllocationFailed)?;

        Ok(
            Self {
                phys_addr: ptr.as_ptr() as u64
            }
        )
    }

    /// Address of the field holding the physical address, for the memory
    /// operand that VMCLEAR and VMPTRLD take.
    pub fn phys_addr_ref(&self) -> &u64 {
        &self.phys_addr
    }

    /// Writes the VMCS revision identifier into the first four bytes.
    ///
    /// # Safety
    ///
    /// The region must not be in use as a VMCS when it is modified.
    pub unsafe fn write_revision_id(&mut self, revision_id: u32) {
        unsafe {
            (self.phys_addr as *mut u32).write_volatile(revision_id);
        }
    }

    /// Initialises the VMCS and flushes CPU-cached data for its address.
    ///
    /// Must run once before the region is first used, and again whenever a
    /// VMCS stops being current on this processor.
    pub unsafe fn vmclear(&self) -> Result<(), VmcsError> {
        let rflags: u64;
        unsafe {
            asm!(
                "vmclear [{0}]",
                "pushfq",
                "pop {1}",
                in(reg) self.phys_addr_ref(),
                lateout(reg) rflags
            );
        }

        Ok(check_rflags(rflags)?)

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
        unsafe {
            let mut region = Self::allocate()?;
            // Before VMPTRLD, not just before use: VMPTRLD rejects a region
            // whose revision identifier does not match the CPU (error 11).
            region.write_revision_id(vmcs_revision_id());
            region.vmclear()?;
            region.vmptrld()?;
            Ok(region)
        }
    }

    /// Makes this VMCS the current one for this logical processor.
    pub unsafe fn vmptrld(&self) -> Result<(), VmcsError> {
        let rflags: u64;
        unsafe {
            asm!(
                "vmptrld [{0}]",
                "pushfq",
                "pop {1}",
                in(reg) self.phys_addr_ref(),
                lateout(reg) rflags
            );
        }

        Ok(check_rflags(rflags)?)
    }
}

/// Reads a field from the current VMCS.
///
/// Operand order is the opposite of [`vmwrite`]: `VMREAD dest, field`, so the
/// destination register comes first and the encoding second.
pub unsafe fn vmread(field_encoding: u32) -> Result<u64, VmcsError> {
    let value: u64;
    let rflags: u64;

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
pub unsafe fn vmwrite(field_encoding: u32, value: u64) -> Result<(), VmcsError> {
    let rflags: u64;

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
    let pin = choose_control(capabilities.pinbased, desired.pin)?;
    let primary = choose_control(capabilities.primary, desired.primary)?;
    // NMI-window exiting is only switched on while an NMI waits for
    // injection (`set_nmi_window_exiting`), but the CPU must allow it.
    choose_control(capabilities.primary, CPU_BASED_NMI_WINDOW_EXITING)
        .map_err(|_| VmcsError::NmiWindowExitingUnsupported)?;
    let exit = choose_control(capabilities.exit, desired.exit | VM_EXIT_HOST_ADDRESS_SPACE_SIZE)?;
    let entry = choose_control(capabilities.entry, desired.entry)?;

    unsafe {
        vmwrite(PIN_BASED_VM_EXEC_CONTROL, pin.into())?;
        vmwrite(PRIMARY_VM_EXEC_CONTROL, primary.into())?;
        vmwrite(VM_EXIT_CONTROLS, exit.into())?;
        vmwrite(VM_ENTRY_CONTROLS, entry.into())?;

        // Verify by reading back
        if vmread(PIN_BASED_VM_EXEC_CONTROL)? != pin as u64 {
            return Err(VmcsError::ControlReadbackMismatch);
        }
        if vmread(PRIMARY_VM_EXEC_CONTROL)? != primary as u64 {
            return Err(VmcsError::ControlReadbackMismatch);
        }
        if vmread(VM_EXIT_CONTROLS)? != exit as u64 {
            return Err(VmcsError::ControlReadbackMismatch);
        }
        if vmread(VM_ENTRY_CONTROLS)? != entry as u64 {
            return Err(VmcsError::ControlReadbackMismatch);
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
            vmwrite(field, 0)?;
            if vmread(field)? != 0 {
                return Err(VmcsError::ControlReadbackMismatch);
            }
        }

        vmwrite(EXCEPTION_BITMAP, EXCEPTION_BITMAP_ALL.into())?;
        if vmread(EXCEPTION_BITMAP)? != u64::from(EXCEPTION_BITMAP_ALL) {
            return Err(VmcsError::ControlReadbackMismatch);
        }
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
    // a. Read segment::read_all() and cr::read_cr0/cr3/cr4 after GDT/TSS activation.
    // b. Check the host selectors' VM-entry constraints before writing them.
    // c. Pair each HOST_* selector, CR, and base encoding with its live value;
    //    use vmwrite and vmread to verify every pair, as configure_controls does.
    // d. Load host PAT/EFER only when selected VM-exit controls require them.
    // e. Configure HOST_RSP/HOST_RIP separately with configure_host_entry; do not launch.
    let segments = unsafe { segment::read_all() };
    let cr0 = unsafe { cr::read_cr0() };
    let cr3 = unsafe { cr::read_cr3() };
    let cr4 = unsafe { cr::read_cr4() };
    let sysenter_cs = u64::from(unsafe { msr::rdmsr(msr::IA32_SYSENTER_CS) } as u32);
    let sysenter_esp = unsafe { msr::rdmsr(msr::IA32_SYSENTER_ESP) };
    let sysenter_eip = unsafe { msr::rdmsr(msr::IA32_SYSENTER_EIP) };

    {

        let selectors = [
            segments.es, segments.cs, segments.ss, segments.ds,
            segments.fs, segments.gs, segments.tr,
        ];

        if selectors.iter().any(|selector| selector & 0b111 != 0) {
            return Err(VmcsError::HostStateValidation);
        }
    }

    if segments.cs == 0 || segments.tr == 0 {
        return Err(VmcsError::HostStateValidation);
    }
    let exit_controls = unsafe { vmread(VM_EXIT_CONTROLS)? };
    
    unsafe {
        write_host_state(HOST_ES_SELECTOR, segments.es as u64)?;
        write_host_state(HOST_CS_SELECTOR, segments.cs as u64)?;
        write_host_state(HOST_SS_SELECTOR, segments.ss as u64)?;
        write_host_state(HOST_DS_SELECTOR, segments.ds as u64)?;
        write_host_state(HOST_FS_SELECTOR, segments.fs as u64)?;
        write_host_state(HOST_GS_SELECTOR, segments.gs as u64)?;
        write_host_state(HOST_TR_SELECTOR, segments.tr as u64)?;

        write_host_state(HOST_CR0, cr0)?;
        write_host_state(HOST_CR3, cr3)?;
        write_host_state(HOST_CR4, cr4)?;

        write_host_state(HOST_FS_BASE, segments.fs_base)?;
        write_host_state(HOST_GS_BASE, segments.gs_base)?;
        write_host_state(HOST_TR_BASE, segments.tr_base)?;
        write_host_state(HOST_GDTR_BASE, segments.gdtr.base)?;
        write_host_state(HOST_IDTR_BASE, segments.idtr.base)?;

        write_host_state(HOST_IA32_SYSENTER_CS, sysenter_cs)?;
        write_host_state(HOST_IA32_SYSENTER_ESP, sysenter_esp)?;
        write_host_state(HOST_IA32_SYSENTER_EIP, sysenter_eip)?;

        if exit_controls & VM_EXIT_LOAD_IA32_PAT != 0 {
            write_host_state(HOST_IA32_PAT, msr::rdmsr(msr::IA32_PAT))?;
        }
        if exit_controls & VM_EXIT_LOAD_IA32_EFER != 0 {
            write_host_state(HOST_IA32_EFER, msr::rdmsr(msr::IA32_EFER))?;
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

    unsafe {
        write_host_state(HOST_RSP, stack_top)?;
        write_host_state(HOST_RIP, entry_address)?;
    }
    Ok(())
}

/// Write a host state field and verify it by reading it back.
unsafe fn write_host_state(field_encoding: u32, value: u64) -> Result<(), VmcsError> {
    unsafe {
        vmwrite(field_encoding, value)?;
        let read_back = vmread(field_encoding)?;
        if read_back != value {
            return Err(VmcsError::HostStateValidation);
        }
        Ok(())
    }
}

/// Choose a 32-bit VMCS control value using one raw capability MSR.
/// The low half forces bits to 1; the high half permits bits to be 1.
/// Reject an inconsistent mask or a requested bit the CPU cannot enable.
fn choose_control(capability: u64, desired: u32) -> Result<u32, VmcsError> {
    let required = capability as u32;
    let allowed = (capability >> 32) as u32;
    if required & !allowed != 0 || desired & !allowed != 0 {
        return Err(VmcsError::UnsupportedControlValue);
    }

    // Add mandatory bits without changing any other requested bits.
    Ok(desired | required)
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
    let primary = unsafe { vmread(PRIMARY_VM_EXEC_CONTROL)? };
    unsafe { vmwrite(PRIMARY_VM_EXEC_CONTROL, with_nmi_window_exiting(primary, on)) }
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
pub unsafe fn vm_instruction_error() -> Result<u32, VmcsError> {
    // VM_INSTRUCTION_ERROR is a 32-bit field; VMREAD zero-extends it.
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
/// Requires VMX operation and a current VMCS ([`VmcsRegion::create_current`]).
/// Leaves the test pattern in GUEST_RIP; guest-state setup overwrites it.
pub unsafe fn self_test() -> Result<(), VmcsError> {
    // Bits set in both halves, so a write that only lands in the low 32 bits
    // is caught. Canonical (bits 63:47 clear), which GUEST_RIP will need once
    // VM entry starts checking it.
    const PATTERN: u64 = 0x0000_7FFF_DEAD_BEEF;

    unsafe {
        vmwrite(GUEST_RIP, PATTERN)?;
        if vmread(GUEST_RIP)? != PATTERN {
            return Err(VmcsError::SelfTestMismatch);
        }
    }

    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/vmcs.rs"]
mod tests;
