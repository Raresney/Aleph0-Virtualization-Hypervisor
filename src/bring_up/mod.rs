//! The bring-up sequence: everything `main` does between setting up output
//! and idling.
//!
//! The steps, in order:
//!
//! 1. Load a host GDT with a TSS ([`activate_host_tables`]); VM entry needs
//!    a nonzero host TR.
//! 2. Allocate the VM-exit stack and the guest's code and stack pages, and
//!    check how the page tables map the guest pages.
//! 3. Detect VMX, enter VMX root operation, and fill in the VMCS: controls,
//!    host state, guest state ([`bring_up_vmx`]).
//! 4. Check that none of this disturbed the host's descriptor tables, and
//!    stop if it did.
//! 5. Launch the guest with VMLAUNCH. `vmx::vmcs::launch` returns once the
//!    guest has stopped: after its last planned exit, or at an exit or
//!    failure the exit handler in `vmx::vmexit` does not handle.
//!
//! Each step returns either what the CPU will keep using or a
//! [`BringUpError`]; `?` stops at the first failure and [`report_error`]
//! prints it. Lines that only print state live in [`report`], so this file
//! reads as the sequence itself.

mod error;
mod report;

pub use error::{report_error, BringUpError};

use crate::vmx;
use crate::vmx::VmxCapabilities;
use crate::vmx::guest::GuestMemory;
use crate::vmx::guest_state::GuestState;
use crate::vmx::host_tables::{GdtError, GdtRegion, TssRegion};
use crate::vmx::segment::DescriptorTable;
use crate::vmx::vmcs::{DesiredControls, GuestStop, VmcsRegion};
use crate::vmx::vmexit::{VmExitStack, VM_EXIT_STACK_SIZE};
use crate::vmx::vmxon::VmxOnRegion;

use error::{guest_state_error, vmcs_step};

/// How the guest run ended when everything went to plan.
#[derive(Debug, Clone, Copy)]
pub struct GuestRun {
    /// VM exits handled, all of them the planned VMCALLs.
    pub exits: u64,
}

/// The host GDT and TSS, plus the descriptor-table state recorded right
/// after they were activated.
struct HostTables {
    _tss: TssRegion,
    _gdt: GdtRegion,
    gdtr: DescriptorTable,
    tr: u16,
    tss_base: u64,
    idtr: DescriptorTable,
}

// The CPU keeps using these pages for as long as it is in VMX operation,
// including after `run` returns an error. Freeing them on drop would hand
// memory the CPU still uses back to UEFI, so none of them may implement
// `Drop`; this turns adding a `Drop` impl (or a field that needs dropping)
// into a compile error.
const _: () = assert!(
    !core::mem::needs_drop::<TssRegion>()
        && !core::mem::needs_drop::<GdtRegion>()
        && !core::mem::needs_drop::<VmExitStack>()
        && !core::mem::needs_drop::<GuestMemory>()
        && !core::mem::needs_drop::<VmxOnRegion>()
        && !core::mem::needs_drop::<VmcsRegion>()
);

/// Activates the host tables, enters VMX operation, prepares the VMCS, and
/// launches the guest.
///
/// Returns once the guest has stopped, or at the first failure. The CPU is
/// still in VMX operation afterwards.
///
/// Every region allocated here (TSS, GDT, VM-exit stack, guest pages, VMXON
/// region, VMCS) must stay allocated while the CPU may use it. None of these
/// types implement `Drop`, so their pages are never returned to UEFI, not
/// even when this function returns early with an error.
pub fn run() -> Result<GuestRun, BringUpError> {
    let host_tables = activate_host_tables()?;

    // Independent of VMX, so this runs and prints even under QEMU/TCG.
    report::segment_state();

    let vmexit_stack = VmExitStack::allocate()?;
    log!("VM-exit stack allocated: top={:#018x} size={VM_EXIT_STACK_SIZE}.", vmexit_stack.top());

    let guest = GuestMemory::allocate()?;
    log!(
        "Guest memory allocated: code={:#018x} ({} bytes copied) stack top={:#018x}.",
        guest.code_base(), guest.code_len(), guest.stack_top(),
    );
    let mappings = unsafe { guest.check_mappings() }?;
    report::guest_mappings(&guest, &mappings);

    // Named, not `_`, so the values are not dropped early. Dropping frees
    // nothing anyway: the assertion above guarantees that none of the region
    // types implement `Drop`, and the CPU uses the VMXON region and the VMCS
    // for as long as it is in VMX operation.
    let (_vmxon, _vmcs) = bring_up_vmx(&vmexit_stack, &guest)?;

    check_host_tables_preserved(&host_tables)?;

    log!("Launching the guest with VMLAUNCH; its VM exits are reported on serial only.");
    guest_result(unsafe { vmx::vmcs::launch() })
}

/// Turns the way the guest stopped into bring-up's result.
fn guest_result(stop: GuestStop) -> Result<GuestRun, BringUpError> {
    match stop {
        GuestStop::Finished { exits } => Ok(GuestRun { exits }),
        GuestStop::Unexpected { number, reason } => {
            Err(BringUpError::UnexpectedExit { number, reason })
        }
        GuestStop::LaunchFailed { error, instruction_error } => {
            Err(BringUpError::Vmcs { operation: "launch", error, instruction_error })
        }
        GuestStop::ResumeFailed { error, instruction_error } => {
            Err(BringUpError::ResumeFailed { error, instruction_error })
        }
    }
}

/// Builds a GDT that adds a TSS descriptor to a copy of the firmware's GDT,
/// loads it with LTR, and records the resulting state for later checks.
fn activate_host_tables() -> Result<HostTables, BringUpError> {
    let tss = TssRegion::allocate()?;
    log!("Host TSS allocated at {:#018x}; TR not loaded yet.", tss.base());

    let mut gdt = unsafe { GdtRegion::copy_active() }?;
    log!("Host GDT copied at {:#018x}.", gdt.base());

    let selector = gdt.append_tss_descriptor(&tss)?;
    if !gdt.verify_tss_descriptor(&tss) {
        return Err(GdtError::TssVerificationFailed.into());
    }
    let prepared = gdt
        .prepared_gdtr()
        .filter(|prepared| prepared.base == gdt.base() && prepared.limit == selector + 15)
        .ok_or(GdtError::GdtrPreparationFailed)?;
    log!(
        "Host GDT prepared: base={:#018x} limit={:#06x} tr_selector={selector:#06x}.",
        prepared.base, prepared.limit,
    );

    unsafe { gdt.activate(&tss) }?;
    log!("Host GDT and TSS activated and verified.");

    Ok(HostTables {
        gdtr: prepared,
        tr: selector,
        tss_base: tss.base(),
        idtr: unsafe { vmx::segment::read_idtr() },
        _tss: tss,
        _gdt: gdt,
    })
}

/// Detects VMX, enters root operation, then prepares the VMCS controls,
/// host state, and guest state. VM entry is not attempted.
fn bring_up_vmx(
    vmexit_stack: &VmExitStack,
    guest: &GuestMemory,
) -> Result<(VmxOnRegion, VmcsRegion), BringUpError> {
    match unsafe { vmx::detect() } {
        VmxCapabilities::Supported => {
            log!("VMX supported and enabled by firmware.");
        }
        VmxCapabilities::NotSupportedByCpu => return Err(BringUpError::VmxNotSupportedByCpu),
        VmxCapabilities::DisabledByFirmware => return Err(BringUpError::VmxDisabledByFirmware),
    }

    let controls = unsafe { vmx::msr::read_vmcs_control_msrs() };
    report::vmx_capabilities(&controls);

    let vmxon = unsafe { vmx::vmxon::enter_vmx_root_operation() }?;
    log!("Entered VMX root operation.");

    // Only legal now: the VMCS instructions raise #UD outside VMX operation.
    let vmcs = unsafe { VmcsRegion::create_current() }.map_err(vmcs_step("creation"))?;
    unsafe { vmx::vmcs::self_test() }.map_err(vmcs_step("self-test"))?;
    log!("VMCS self-test passed: VMREAD returned what VMWRITE stored.");

    unsafe { vmx::vmcs::configure_controls(&controls, DesiredControls::minimal_64_bit_guest()) }
        .map_err(vmcs_step("control setup"))?;
    log!("VMCS controls written and read back successfully.");

    unsafe { vmx::vmcs::configure_host_state() }.map_err(vmcs_step("host-state setup"))?;
    let exit_controls = unsafe { vmx::vmcs::vmread(vmx::vmcs::fields::VM_EXIT_CONTROLS) }
        .map_err(vmcs_step("exit-control readback"))?;
    log!(
        "VMCS host fields written and read back; host PAT load={} EFER load={}; VM entry not attempted.",
        exit_controls & vmx::vmcs::fields::VM_EXIT_LOAD_IA32_PAT != 0,
        exit_controls & vmx::vmcs::fields::VM_EXIT_LOAD_IA32_EFER != 0,
    );

    unsafe { vmx::vmcs::configure_host_entry(vmexit_stack.top(), vmx::vmexit::entry_address()) }
        .map_err(vmcs_step("host entry address setup"))?;
    log!("VMCS HOST_RSP/HOST_RIP written and read back; VM entry not attempted.");

    // After the controls: they decide whether guest PAT/EFER fields exist.
    let guest_state = unsafe { GuestState::from_current(guest.code_base(), guest.stack_top()) }
        .map_err(guest_state_error)?;
    unsafe { guest_state.write() }.map_err(guest_state_error)?;
    report::guest_state(&guest_state);

    Ok((vmxon, vmcs))
}

/// Confirms that VMXON, the VMCS work, and UEFI calls left the host GDTR,
/// TR, TSS base, and IDTR as they were after activation. If anything
/// changed, stops before the launch: the host fields in the VMCS describe
/// the activated tables, and every VM exit would load them.
fn check_host_tables_preserved(expected: &HostTables) -> Result<(), BringUpError> {
    let gdtr = unsafe { vmx::segment::read_gdtr() };
    let tr = unsafe { vmx::segment::read_tr() };
    let idtr = unsafe { vmx::segment::read_idtr() };
    let same_gdtr = gdtr.base == expected.gdtr.base && gdtr.limit == expected.gdtr.limit;
    let same_idtr = idtr.base == expected.idtr.base && idtr.limit == expected.idtr.limit;
    let same_tss_base = same_gdtr && tr == expected.tr
        && unsafe { vmx::segment::segment_base_from_gdt(&gdtr, tr) } == expected.tss_base;

    if same_gdtr && same_idtr && same_tss_base {
        log!("Host GDTR, TR, TSS base and IDTR preserved after VMX/UEFI calls.");
        Ok(())
    } else {
        log!("WARNING: Host descriptor state changed after VMX/UEFI calls.");
        log!(
            "Expected GDTR={:?} TR={:#06x} TSS={:#018x} IDTR={:?}",
            expected.gdtr, expected.tr, expected.tss_base, expected.idtr,
        );
        log!("Actual GDTR={gdtr:?} TR={tr:#06x} IDTR={idtr:?} TSS base matches={same_tss_base}");
        Err(BringUpError::HostTablesChanged)
    }
}
