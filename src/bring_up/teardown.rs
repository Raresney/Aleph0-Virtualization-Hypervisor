//! Leaving VMX operation and handing the CPU back to firmware.
//!
//! Runs after the guest stopped, and after any failure once VMXON has
//! succeeded, so firmware gets the CPU back outside VMX operation. The one
//! exception is a failing VMXOFF: the CPU is then still in VMX root
//! operation with CR4.VMXE set, and teardown prints that.
//!
//! The order matters:
//!
//! 1. Load the firmware's GDTR and IDTR again. A VM exit loads the host
//!    tables with limits of 0xFFFF, and firmware never knew about Aleph0's
//!    GDT.
//! 2. VMCLEAR the VMCS, so the CPU writes any VMCS data it caches back to
//!    memory.
//! 3. VMXOFF, then CR0/CR4 as they were before VMXON
//!    (`VmxOperation::leave`). CR4.VMXE can only be cleared after VMXOFF.
//! 4. Switch the output phase back to boot services.
//! 5. Turn interrupts back on, if firmware had them on.
//! 6. Check and print the result.
//!
//! When the guest ran, interrupts are off until step 5: a VM exit loads
//! host RFLAGS as 0x2. The phase changes late for the same reason. The
//! firmware console can call RestoreTPL, which executes STI, so a console
//! line during steps 1 to 3 could turn interrupts on early. Until step 4
//! the exit handler's phase keeps `log!` on serial. On paths that never
//! launched, the phase is still boot services and interrupts were never
//! turned off, so neither concern applies.
//!
//! TR keeps Aleph0's TSS selector. LTR cannot load a null selector, and the
//! TSS and GDT pages are never freed, so the CPU's cached TSS descriptor
//! stays valid. The selector may lie past the firmware GDT's limit; only an
//! LTR or a task switch would look it up again.
//!
//! Three more things a VM exit changes are intentionally not restored: DR7 is
//! set to 0x400, IA32_DEBUGCTL is cleared, and LDTR is made null. Firmware
//! then runs with those values, which only matters while a hardware debugger
//! is attached; UEFI uses no LDT.

use core::arch::asm;

use crate::output::{self, Phase};
use crate::vmx::cr::{self, CR4_VMXE};
use crate::vmx::instruction::VmxFail;
use crate::vmx::segment::{self, DescriptorTable};
use crate::vmx::vmcs::{VmcsError, VmcsRegion};
use crate::vmx::vmxon::VmxOperation;

/// RFLAGS.IF, bit 9: maskable interrupts are delivered.
const RFLAGS_IF: u64 = 1 << 9;

/// Firmware state from before bring-up changed it, for [`teardown`] to put
/// back.
#[derive(Debug, Clone, Copy)]
pub(super) struct FirmwareState {
    pub(super) gdtr: DescriptorTable,
    pub(super) idtr: DescriptorTable,
    pub(super) interrupts_enabled: bool,
}

/// Which teardown step failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownError {
    /// VMCLEAR failed, so the VMCS data may not have been written back.
    Vmclear(VmcsError),
    /// VMXOFF failed: the CPU is still in VMX operation, with CR4.VMXE set.
    Vmxoff(VmxFail),
}

/// Whether maskable interrupts are on right now.
pub(super) fn interrupts_enabled() -> bool {
    read_rflags() & RFLAGS_IF != 0
}

fn read_rflags() -> u64 {
    let rflags: u64;
    // SAFETY: PUSHFQ and POP only use the stack below RSP, which `asm!`
    // allows once `nostack` is left out, and change nothing else.
    unsafe { asm!("pushfq", "pop {0}", out(reg) rflags, options(preserves_flags)) };
    rflags
}

/// Leaves VMX operation and restores the firmware's CPU state, in the order
/// the module docs give.
///
/// Every step runs even if an earlier one failed, except restoring CR0/CR4
/// after a failed VMXOFF. Each failure is printed when it happens; the
/// first one is returned.
///
/// # Safety
///
/// `vmx_operation` must be this CPU's VMX operation and `vmcs` its only
/// VMCS, if one was created. The guest must not be running, and `firmware`
/// must describe the firmware's live descriptor tables.
pub(super) unsafe fn teardown(
    vmx_operation: VmxOperation,
    vmcs: Option<&VmcsRegion>,
    firmware: &FirmwareState,
) -> Result<(), TeardownError> {
    let mut result = Ok(());

    // SAFETY: `firmware` holds the firmware's own tables, which boot
    // services keep live (the caller's obligation).
    unsafe {
        segment::load_gdtr(&firmware.gdtr);
        segment::load_idtr(&firmware.idtr);
    }

    if let Some(vmcs) = vmcs
        // SAFETY: still in VMX operation, with `vmcs` this CPU's VMCS;
        // VMXOFF comes next.
        && let Err(error) = unsafe { vmcs.vmclear() }
    {
        log!("Teardown: VMCLEAR failed: {error:?}.");
        result = Err(TeardownError::Vmclear(error));
    }

    // SAFETY: the VMCS was cleared above (or its failure printed, which only
    // leaves that VMCS's memory stale), and no VMX instruction runs after
    // this.
    if let Err(fail) = unsafe { vmx_operation.leave() } {
        log!("Teardown: VMXOFF failed: {fail:?}; still in VMX operation, CR4.VMXE left set.");
        result = result.and(Err(TeardownError::Vmxoff(fail)));
    }

    output::set_phase(Phase::BootServices);
    if firmware.interrupts_enabled {
        // SAFETY: firmware had interrupts on, and its IDT is loaded again, so
        // every interrupt reaches a firmware handler.
        unsafe { asm!("sti", options(nostack)) };
    }

    report(firmware);
    result
}

/// Prints whether teardown left the CPU as firmware expects. Reaches the
/// console too: the phase is boot services again.
fn report(firmware: &FirmwareState) {
    let vmxe = cr::read_cr4() & CR4_VMXE != 0;
    let tables_restored = segment::read_gdtr() == firmware.gdtr && segment::read_idtr() == firmware.idtr;
    log!(
        "Teardown: CR4.VMXE={} firmware GDTR/IDTR restored={tables_restored} IF={}.",
        u8::from(vmxe),
        u8::from(interrupts_enabled()),
    );
}
