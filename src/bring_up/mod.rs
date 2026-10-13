//! The bring-up sequence: everything `main` does between setting up output
//! and returning to firmware.
//!
//! The steps, in order:
//!
//! 1. Load a host GDT with a TSS ([`activate_host_tables`]); VM entry needs
//!    a nonzero host TR. The firmware's GDTR is recorded first, and put back
//!    on every return path once this step has succeeded: by `run` if a
//!    failure comes before VMXON, by step 7 after it.
//! 2. Allocate the VM-exit stack and the guest's pages, and check how the
//!    page tables map the guest pages.
//! 3. Detect VMX, read its capability MSRs and check EPT support
//!    ([`check_vmx_support`]), then build the EPT identity map with the
//!    guest's data page read-only.
//! 4. Enter VMX root operation and create the VMCS.
//! 5. Fill in the VMCS: controls, EPT pointer, host state, guest state
//!    ([`prepare_vmcs`]). Then check that none of this disturbed the host's
//!    descriptor tables, and stop if it did.
//! 6. Launch the guest with VMLAUNCH. `vmx::vmcs::launch` returns once the
//!    guest has stopped: after its last planned exit, or at an exit or
//!    failure the exit handler in `vmx::vmexit` does not handle.
//! 7. Leave VMX operation and restore the firmware's state
//!    ([`teardown::teardown`]). Runs whatever happened after VMXON
//!    succeeded (creating the VMCS, steps 5 and 6), so firmware gets the CPU
//!    back outside VMX operation unless VMXOFF itself fails. If VMXON or an
//!    earlier step failed there is nothing to leave, and only the firmware's
//!    GDTR needs loading again.
//!
//! Each step returns either what the CPU will keep using or a
//! [`BringUpError`]; `?` stops at the first failure and [`report_error`]
//! prints it. Before VMXON that failure goes straight back to `main` (with
//! the firmware's GDTR loaded again); after VMXON it still goes through
//! teardown first. Lines that only print state live in [`report`], so this
//! file reads as the sequence itself.

mod error;
mod report;
mod teardown;

pub use error::{BringUpError, report_error};

use crate::vmx;
use crate::vmx::VmxCapabilities;
use crate::vmx::ept::{self, Ept, InveptType};
use crate::vmx::guest::GuestMemory;
use crate::vmx::guest_state::GuestState;
use crate::vmx::host_tables::{GdtError, GdtRegion, TssRegion};
use crate::vmx::msr::VmcsControlMsrs;
use crate::vmx::segment::DescriptorTable;
use crate::vmx::vmcs::{DesiredControls, GuestStop, VmcsRegion};
use crate::vmx::vmexit::{VM_EXIT_STACK_SIZE, VmExitStack};
use crate::vmx::vmxon::VmxOperation;

use error::{guest_state_error, vmcs_step};
use teardown::FirmwareState;

/// How the guest run ended when everything went to plan.
#[derive(Debug, Clone, Copy)]
pub struct GuestRun {
    /// VM exits handled, all of them the planned VMCALLs.
    pub exits: u64,
}

/// The host GDT and TSS, plus the descriptor-table state recorded right
/// after they were activated, and the firmware's GDTR from before.
struct HostTables {
    _tss: TssRegion,
    _gdt: GdtRegion,
    gdtr: DescriptorTable,
    tr: u16,
    tss_base: u64,
    /// IDTR after activation. Activation does not touch the IDT, so this is
    /// also the firmware's IDTR.
    idtr: DescriptorTable,
    /// GDTR before activation. Teardown loads it again.
    firmware_gdtr: DescriptorTable,
}

// The CPU uses these pages while `run` is in progress, and some of them after
// it returns: the TSS through TR, and the VMXON region and VMCS if VMXOFF
// failed. Freeing them on drop would hand memory the CPU still uses back to
// UEFI, so none of them may implement `Drop`; this turns adding a `Drop` impl
// (or a field that needs dropping) into a compile error.
const _: () = assert!(
    !core::mem::needs_drop::<TssRegion>()
        && !core::mem::needs_drop::<GdtRegion>()
        && !core::mem::needs_drop::<VmExitStack>()
        && !core::mem::needs_drop::<GuestMemory>()
        && !core::mem::needs_drop::<Ept>()
        && !core::mem::needs_drop::<VmxOperation>()
        && !core::mem::needs_drop::<VmcsRegion>()
);

/// Activates the host tables, enters VMX operation, prepares the VMCS,
/// launches the guest, and leaves VMX operation again.
///
/// Returns once the guest has stopped, or at the first failure. Once the host
/// tables are active, every return path puts the firmware's GDTR back. If
/// VMXON succeeded, it also puts back the IDTR and interrupt flag and leaves
/// VMX operation. The one exception is a failing VMXOFF: the CPU then stays
/// in VMX root operation with CR4.VMXE set, and teardown prints that.
///
/// Every region allocated here (TSS, GDT, VM-exit stack, guest pages, EPT
/// tables, VMXON region, VMCS) stays allocated, even after this returns. None of these
/// types implement `Drop`, so their pages are never returned to UEFI. TR
/// keeps pointing at the TSS (see `teardown`).
pub fn run() -> Result<GuestRun, BringUpError> {
    let host_tables = activate_host_tables()?;

    // Independent of VMX, so this runs and prints even under QEMU/TCG.
    report::segment_state();

    let entry = match enter_vmx(&host_tables) {
        Ok(entry) => entry,
        Err(error) => {
            // Nothing to leave yet, but the CPU still runs on Aleph0's GDT,
            // which firmware never knew about. IF is still 1 and the phase
            // is still boot services, so this needs no ordering care.
            // SAFETY: the firmware's own GDT, read before activation. Boot
            // services are still running, so it is still live.
            unsafe { vmx::segment::load_gdtr(&host_tables.firmware_gdtr) };
            return Err(error);
        }
    };
    let VmxEntry {
        vmexit_stack,
        guest,
        ept,
        controls,
        firmware,
        vmx_operation,
    } = entry;

    // From here on every path goes through teardown before returning.
    // Only legal now: the VMCS instructions raise #UD outside VMX operation.
    let vmcs = unsafe { VmcsRegion::create_current() }.map_err(vmcs_step("creation"));
    let result = match &vmcs {
        Ok(_) => launch_guest(&controls, &vmexit_stack, &guest, &ept, &host_tables),
        Err(error) => Err(*error),
    };
    let left = unsafe { teardown::teardown(vmx_operation, vmcs.as_ref().ok(), &firmware) };

    // A failure before teardown explains more than one during it; a
    // teardown failure was printed when it happened.
    match (result, left) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
        (Ok(run), Ok(())) => Ok(run),
    }
}

/// What exists once VMXON has succeeded, for the rest of [`run`].
struct VmxEntry {
    vmexit_stack: VmExitStack,
    guest: GuestMemory,
    ept: Ept,
    controls: VmcsControlMsrs,
    firmware: FirmwareState,
    vmx_operation: VmxOperation,
}

/// Steps 2 to 4 up to the VMCS: allocates the VM-exit stack and the guest's
/// pages, checks VMX and EPT support, builds the EPT tables, and enters VMX
/// root operation. A failure here leaves the CPU outside VMX operation, so
/// `run` only has to put the firmware's GDTR back.
fn enter_vmx(host_tables: &HostTables) -> Result<VmxEntry, BringUpError> {
    let vmexit_stack = VmExitStack::allocate()?;
    log!(
        "VM-exit stack allocated: top={:#018x} size={VM_EXIT_STACK_SIZE}.",
        vmexit_stack.top()
    );

    let guest = GuestMemory::allocate()?;
    log!(
        "Guest memory allocated: code={:#018x} ({} bytes copied) stack top={:#018x}.",
        guest.code_base(),
        guest.code_len(),
        guest.stack_top(),
    );
    log!(
        "Guest IDT at {:#018x} (limit {:#06x}): vector 2 -> NMI handler at {:#018x}.",
        guest.idt().base,
        guest.idt().limit,
        guest.nmi_handler(),
    );
    let mappings = unsafe { guest.check_mappings() }?;
    report::guest_mappings(&guest, &mappings);

    let (controls, invept) = check_vmx_support()?;

    // The identity mapping makes the data page's address its GPA.
    let ept = unsafe { Ept::build(guest.data_page(), invept) }?;
    report::ept(&ept, guest.data_page());

    // Recorded before VMXON: once the guest runs, its VM exits clear IF, and
    // teardown turns interrupts back on only if firmware had them on.
    let firmware = FirmwareState {
        gdtr: host_tables.firmware_gdtr,
        idtr: host_tables.idtr,
        interrupts_enabled: teardown::interrupts_enabled(),
    };
    let vmx_operation = unsafe { vmx::vmxon::enter_vmx_root_operation() }?;
    log!("Entered VMX root operation.");

    Ok(VmxEntry {
        vmexit_stack,
        guest,
        ept,
        controls,
        firmware,
        vmx_operation,
    })
}

/// Builds a GDT that adds a TSS descriptor to a copy of the firmware's GDT,
/// loads it with LTR, and records the resulting state for later checks.
fn activate_host_tables() -> Result<HostTables, BringUpError> {
    // Before anything is loaded, so teardown can give firmware its own GDT
    // back.
    let firmware_gdtr = unsafe { vmx::segment::read_gdtr() };

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
        prepared.base,
        prepared.limit,
    );

    unsafe { gdt.activate(&tss) }?;
    log!("Host GDT and TSS activated and verified.");

    Ok(HostTables {
        gdtr: prepared,
        tr: selector,
        tss_base: tss.base(),
        idtr: unsafe { vmx::segment::read_idtr() },
        firmware_gdtr,
        _tss: tss,
        _gdt: gdt,
    })
}

/// Detects VMX, reads the capability MSRs the VMCS controls are chosen from,
/// and checks that the CPU supports the EPT Aleph0 builds. Returns the MSRs
/// and the INVEPT type to use.
fn check_vmx_support() -> Result<(VmcsControlMsrs, InveptType), BringUpError> {
    match unsafe { vmx::detect() } {
        VmxCapabilities::Supported => {
            log!("VMX supported and enabled by firmware.");
        }
        VmxCapabilities::NotSupportedByCpu => return Err(BringUpError::VmxNotSupportedByCpu),
        VmxCapabilities::DisabledByFirmware => return Err(BringUpError::VmxDisabledByFirmware),
    }

    let controls = unsafe { vmx::msr::read_vmcs_control_msrs() };
    report::vmx_capabilities(&controls);

    let invept = ept::check_support(controls.secondary, controls.ept_vpid_cap)?;
    log!(
        "EPT supported: 4-level walk, WB, 2 MiB pages, INVEPT {}.",
        invept.name()
    );
    Ok((controls, invept))
}

/// Prepares the current VMCS, checks the host tables, and launches the
/// guest. Returns once the guest has stopped.
fn launch_guest(
    controls: &VmcsControlMsrs,
    vmexit_stack: &VmExitStack,
    guest: &GuestMemory,
    ept: &Ept,
    host_tables: &HostTables,
) -> Result<GuestRun, BringUpError> {
    prepare_vmcs(controls, vmexit_stack, guest, ept)?;
    check_host_tables_preserved(host_tables)?;

    log!("Launching the guest with VMLAUNCH; its VM exits are reported on serial only.");
    guest_result(unsafe { vmx::vmcs::launch() })
}

/// Fills in the current VMCS: controls, EPT pointer, host state, and guest
/// state. VM entry is not attempted.
fn prepare_vmcs(
    controls: &VmcsControlMsrs,
    vmexit_stack: &VmExitStack,
    guest: &GuestMemory,
    ept: &Ept,
) -> Result<(), BringUpError> {
    unsafe { vmx::vmcs::self_test() }.map_err(vmcs_step("self-test"))?;
    log!("VMCS self-test passed: VMREAD returned what VMWRITE stored.");

    unsafe { vmx::vmcs::configure_controls(controls, DesiredControls::minimal_64_bit_guest()) }
        .map_err(vmcs_step("control setup"))?;
    log!("VMCS controls written and read back successfully.");

    unsafe { vmx::vmcs::set_ept_pointer(ept.eptp()) }.map_err(vmcs_step("EPT pointer setup"))?;
    log!(
        "VMCS EPT pointer {:#018x} (WB, 4-level) written and read back.",
        ept.eptp()
    );

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
    let guest_state = unsafe { GuestState::from_current(guest.code_base(), guest.stack_top(), guest.idt()) }
        .map_err(guest_state_error)?;
    unsafe { guest_state.write() }.map_err(guest_state_error)?;
    report::guest_state(&guest_state);

    Ok(())
}

/// Turns the way the guest stopped into bring-up's result.
fn guest_result(stop: GuestStop) -> Result<GuestRun, BringUpError> {
    match stop {
        GuestStop::Finished { exits } => Ok(GuestRun { exits }),
        GuestStop::Unexpected { number, reason } => Err(BringUpError::UnexpectedExit { number, reason }),
        GuestStop::LaunchFailed {
            error,
            instruction_error,
        } => Err(BringUpError::Vmcs {
            operation: "launch",
            error,
            instruction_error,
        }),
        GuestStop::ResumeFailed {
            error,
            instruction_error,
        } => Err(BringUpError::ResumeFailed {
            error,
            instruction_error,
        }),
    }
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
    let same_tss_base = same_gdtr
        && tr == expected.tr
        && unsafe { vmx::segment::segment_base_from_gdt(&gdtr, tr) } == expected.tss_base;

    if same_gdtr && same_idtr && same_tss_base {
        log!("Host GDTR, TR, TSS base and IDTR preserved after VMX/UEFI calls.");
        Ok(())
    } else {
        log!("WARNING: Host descriptor state changed after VMX/UEFI calls.");
        log!(
            "Expected GDTR={:?} TR={:#06x} TSS={:#018x} IDTR={:?}",
            expected.gdtr,
            expected.tr,
            expected.tss_base,
            expected.idtr,
        );
        log!("Actual GDTR={gdtr:?} TR={tr:#06x} IDTR={idtr:?} TSS base matches={same_tss_base}");
        Err(BringUpError::HostTablesChanged)
    }
}
