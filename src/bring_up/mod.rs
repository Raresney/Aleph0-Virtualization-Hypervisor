//! The bring-up sequence: everything `main` does between setting up output
//! and returning to firmware.
//!
//! The steps, in order:
//!
//! 1. Load a copy of the firmware's GDT with a TSS appended
//!    ([`activate_context_tables`]); the guest state copies TR, and VM entry
//!    refuses an unusable guest TR. The firmware's GDTR is recorded first,
//!    and put back on every return path once this step has succeeded: by
//!    `run` if a failure comes before VMXON, by step 7 after it.
//! 2. Allocate the VM-exit stack, the guest's pages and the MSR and I/O
//!    bitmaps, and check how the page tables map the guest pages.
//! 3. Detect VMX, read its capability MSRs and check EPT support
//!    ([`check_vmx_support`]), read the MTRRs, then build the EPT identity
//!    map with their memory types and the guest's data page read-only. Build
//!    what Aleph0 runs on after a VM exit ([`HostEnvironment`]): page tables
//!    mapping the same range, a GDT, a TSS with interrupt stacks, an IDT.
//! 4. Enter VMX root operation and create the VMCS.
//! 5. Fill in the VMCS: controls, EPT pointer, exit bitmaps, host state,
//!    guest state ([`prepare_vmcs`]). Then check that none of this disturbed
//!    the host's descriptor tables, and stop if it did.
//! 6. Launch the guest with VMLAUNCH. `vmx::vmcs::launch` returns once the
//!    guest has stopped: after its last planned exit, or at an exit or
//!    failure the exit handler in `vmx::vmexit` does not handle. The host
//!    state the guest reaches through passthrough emulation
//!    ([`PassthroughState`]) is read before and after, and printed.
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
use crate::vmx::context_tables::{GdtError, GdtRegion, TssRegion};
use crate::vmx::ept::{self, Ept, InveptType};
use crate::vmx::exit_bitmaps::ExitBitmaps;
use crate::vmx::guest::{GUEST_SCRATCH_PORT, GuestMemory};
use crate::vmx::guest_state::GuestState;
use crate::vmx::host::{FirmwareSelectors, HostEnvironment};
use crate::vmx::msr::{IA32_KERNEL_GS_BASE, VmcsControlMsrs};
use crate::vmx::segment::DescriptorTable;
use crate::vmx::vmcs::{DesiredControls, GuestKind, GuestStop, VmcsRegion};
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

/// Host state the guest reaches through passthrough emulation: real
/// hardware, not a copy. The guest saves and restores it, so it reads the
/// same before and after the guest's run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PassthroughState {
    kernel_gs_base: u64,
    com1_scratch: u8,
}

impl PassthroughState {
    /// Reads the current values.
    fn read() -> Self {
        Self {
            // SAFETY: IA32_KERNEL_GS_BASE exists on every 64-bit CPU, and
            // reading it has no side effect.
            kernel_gs_base: unsafe { vmx::msr::rdmsr(IA32_KERNEL_GS_BASE) },
            // SAFETY: the COM1 scratch register, a byte with no effect on
            // the UART; reading it has no side effect. Aleph0 prints on
            // COM2, so this does not disturb its output.
            com1_scratch: unsafe { crate::port::inb(GUEST_SCRATCH_PORT) },
        }
    }
}

/// The GDT copy and TSS that bring-up and the test guest run on, plus the
/// descriptor-table state recorded right after they were activated, and the
/// firmware's GDTR from before. VMX root operation runs on
/// [`HostEnvironment`] instead.
struct ContextTables {
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
    !core::mem::needs_drop::<HostEnvironment>()
        && !core::mem::needs_drop::<TssRegion>()
        && !core::mem::needs_drop::<GdtRegion>()
        && !core::mem::needs_drop::<VmExitStack>()
        && !core::mem::needs_drop::<GuestMemory>()
        && !core::mem::needs_drop::<Ept>()
        && !core::mem::needs_drop::<ExitBitmaps>()
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
/// tables, host environment, exit bitmaps, VMXON region, VMCS) stays allocated, even after this
/// returns. None of these types implement `Drop`, so their pages are never
/// returned to UEFI. TR keeps pointing at the TSS (see `teardown`).
pub fn run() -> Result<GuestRun, BringUpError> {
    let context_tables = activate_context_tables()?;

    // Independent of VMX, so this runs and prints even under QEMU/TCG.
    report::segment_state();

    let entry = match enter_vmx(&context_tables) {
        Ok(entry) => entry,
        Err(error) => {
            // Nothing to leave yet, but the CPU still runs on Aleph0's GDT,
            // which firmware never knew about. IF is still 1 and the phase
            // is still boot services, so this needs no ordering care.
            // SAFETY: the firmware's own GDT, read before activation. Boot
            // services are still running, so it is still live.
            unsafe { vmx::segment::load_gdtr(&context_tables.firmware_gdtr) };
            return Err(error);
        }
    };
    let VmxEntry {
        vmexit_stack,
        guest,
        ept,
        host,
        bitmaps,
        controls,
        firmware,
        vmx_operation,
    } = entry;

    // From here on every path goes through teardown before returning.
    // SAFETY: VMXON succeeded in `enter_vmx`, so this CPU is in VMX root
    // operation; outside it the VMCS instructions would raise #UD.
    let vmcs = unsafe { VmcsRegion::create_current() }.map_err(vmcs_step("creation"));
    let result = match &vmcs {
        Ok(_) => launch_guest(&controls, &vmexit_stack, &guest, &ept, &host, &bitmaps, &context_tables),
        Err(error) => Err(*error),
    };
    // SAFETY: `vmx_operation` is this CPU's and `vmcs` its only VMCS; the
    // guest is not running (launch returned, or never happened); `firmware`
    // was read from the live tables before activation.
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
    host: HostEnvironment,
    bitmaps: ExitBitmaps,
    controls: VmcsControlMsrs,
    firmware: FirmwareState,
    vmx_operation: VmxOperation,
}

/// Steps 2 to 4 up to the VMCS: allocates the VM-exit stack, the guest's
/// pages and the exit bitmaps, checks VMX and EPT support, reads the MTRRs,
/// builds the EPT tables and the host environment, and enters VMX root
/// operation. A failure here leaves the CPU
/// outside VMX operation, so `run` only has to put the firmware's GDTR back.
fn enter_vmx(context_tables: &ContextTables) -> Result<VmxEntry, BringUpError> {
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
    // SAFETY: boot services are still active.
    let mappings = unsafe { guest.check_mappings() }?;
    report::guest_mappings(&guest, &mappings);

    let bitmaps = ExitBitmaps::allocate()?;
    report::exit_bitmaps(&bitmaps);

    let (controls, invept) = check_vmx_support()?;

    let mtrrs = vmx::mtrr::read()?;
    report::mtrrs(&mtrrs);
    let protected_pages = [guest.data_page(), guest.stack_page()];
    // SAFETY: boot services are still active, and UEFI identity-maps
    // memory, which also makes the guest pages' addresses their GPAs.
    let ept = unsafe { Ept::build(&protected_pages, invept, &mtrrs) }?;
    report::ept(&ept, &protected_pages);

    // The same range as EPT: every address the UEFI memory map reaches,
    // which holds the image, every allocation and the firmware stack.
    // SAFETY: boot services are still active, and UEFI identity-maps memory.
    let host = unsafe { HostEnvironment::build(ept.end(), FirmwareSelectors::read()) }?;
    report::host_environment(&host, vmx::cr::read_cr3());

    // Recorded before VMXON: once the guest runs, its VM exits clear IF, and
    // teardown turns interrupts back on only if firmware had them on.
    let firmware = FirmwareState {
        cr3: vmx::cr::read_cr3(),
        gdtr: context_tables.firmware_gdtr,
        idtr: context_tables.idtr,
        interrupts_enabled: teardown::interrupts_enabled(),
    };
    // SAFETY: `check_vmx_support` confirmed VMX support and enablement, and
    // nothing has entered VMX operation yet.
    let vmx_operation = unsafe { vmx::vmxon::enter_vmx_root_operation() }?;
    log!("Entered VMX root operation.");

    Ok(VmxEntry {
        vmexit_stack,
        guest,
        ept,
        host,
        bitmaps,
        controls,
        firmware,
        vmx_operation,
    })
}

/// Builds a GDT that adds a TSS descriptor to a copy of the firmware's GDT,
/// loads it with LTR, and records the resulting state for later checks.
fn activate_context_tables() -> Result<ContextTables, BringUpError> {
    // Before anything is loaded, so teardown can give firmware its own GDT
    // back.
    let firmware_gdtr = vmx::segment::read_gdtr();

    let tss = TssRegion::allocate()?;
    log!("Context TSS allocated at {:#018x}; TR not loaded yet.", tss.base());

    // SAFETY: the active GDTR is the firmware's, live and readable through
    // its limit, and nothing changes it while it is copied.
    let mut gdt = unsafe { GdtRegion::copy_active() }?;
    log!("Context GDT copied at {:#018x}.", gdt.base());

    let selector = gdt.append_tss_descriptor(&tss)?;

    // `activate` checks the TSS descriptor and the GDTR before loading them.
    // SAFETY: `ContextTables` keeps the GDT and TSS pages, which are never
    // freed; the copy keeps the firmware's descriptors, so the active
    // selectors stay usable; the firmware IDT is live; and this is the only
    // activation.
    unsafe { gdt.activate(&tss) }?;
    let prepared = gdt.prepared_gdtr().ok_or(GdtError::GdtrPreparationFailed)?;
    log!(
        "Context GDT and TSS activated and verified: base={:#018x} limit={:#06x} tr_selector={selector:#06x}.",
        prepared.base,
        prepared.limit,
    );

    Ok(ContextTables {
        gdtr: prepared,
        tr: selector,
        tss_base: tss.base(),
        idtr: vmx::segment::read_idtr(),
        firmware_gdtr,
        _tss: tss,
        _gdt: gdt,
    })
}

/// Detects VMX, reads the capability MSRs the VMCS controls are chosen from,
/// and checks that the CPU supports the EPT Aleph0 builds. Returns the MSRs
/// and the INVEPT type to use.
fn check_vmx_support() -> Result<(VmcsControlMsrs, InveptType), BringUpError> {
    match vmx::detect() {
        VmxCapabilities::Supported => {
            log!("VMX supported and enabled by firmware.");
        }
        VmxCapabilities::NotSupportedByCpu => return Err(BringUpError::VmxNotSupportedByCpu),
        VmxCapabilities::DisabledByFirmware => return Err(BringUpError::VmxDisabledByFirmware),
    }

    // SAFETY: `detect` just confirmed VMX support.
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
    host: &HostEnvironment,
    bitmaps: &ExitBitmaps,
    context_tables: &ContextTables,
) -> Result<GuestRun, BringUpError> {
    prepare_vmcs(controls, vmexit_stack, guest, ept, host, bitmaps)?;
    check_context_tables_preserved(context_tables)?;

    log!("Launching the guest with VMLAUNCH; its VM exits are reported on serial only.");
    let before = PassthroughState::read();
    // SAFETY: `prepare_vmcs` wrote the controls, the host state
    // (HOST_RSP/HOST_RIP at the live exit stack and handler) and the guest
    // state; the exit stack, guest pages, EPT tables, host environment and
    // exit bitmaps are never freed.
    let stop = unsafe { vmx::vmcs::launch() };
    report::passthrough_state(before, PassthroughState::read());
    let run = guest_result(stop)?;
    // The guest has stopped, so no exit handler is counting any more.
    let stats = vmx::vmexit::vcpu_stats();
    if stats != vmx::guest::expected_stats(&stats) {
        return Err(BringUpError::UnexpectedExitStats(stats));
    }
    Ok(run)
}

/// Fills in the current VMCS: controls, EPT pointer, exit bitmaps, host state,
/// and guest state. VM entry is not attempted.
fn prepare_vmcs(
    controls: &VmcsControlMsrs,
    vmexit_stack: &VmExitStack,
    guest: &GuestMemory,
    ept: &Ept,
    host: &HostEnvironment,
    bitmaps: &ExitBitmaps,
) -> Result<(), BringUpError> {
    // SAFETY: VMX root operation with the VMCS `run` created and made
    // current.
    unsafe { vmx::vmcs::self_test() }.map_err(vmcs_step("self-test"))?;
    log!("VMCS self-test passed: VMREAD returned what VMWRITE stored.");

    // SAFETY: VMX root operation with the VMCS `run` created and made
    // current.
    unsafe { vmx::vmcs::configure_controls(controls, DesiredControls::minimal_64_bit_guest(GuestKind::BuiltInTest)) }
        .map_err(vmcs_step("control setup"))?;
    log!("VMCS controls written and read back successfully.");

    // SAFETY: VMX root operation with the VMCS `run` created and made
    // current. The EPT tables are never freed.
    unsafe { vmx::vmcs::set_ept_pointer(ept.eptp()) }.map_err(vmcs_step("EPT pointer setup"))?;
    log!(
        "VMCS EPT pointer {:#018x} (WB, 4-level) written and read back.",
        ept.eptp().raw()
    );

    // SAFETY: VMX root operation with the VMCS `run` created and made
    // current. The bitmap pages are never freed.
    unsafe { bitmaps.write_to_vmcs() }.map_err(vmcs_step("exit bitmap setup"))?;
    log!("VMCS MSR and I/O bitmap addresses written and read back.");

    // SAFETY: VMX root operation with the VMCS `run` created and made
    // current. The host environment's pages are never freed.
    unsafe { vmx::vmcs::configure_host_state(&host.vmcs_tables()) }.map_err(vmcs_step("host-state setup"))?;
    // SAFETY: VMX root operation with the VMCS `run` created and made
    // current.
    let exit_controls = unsafe { vmx::vmcs::vmread(vmx::vmcs::fields::VM_EXIT_CONTROLS) }
        .map_err(vmcs_step("exit-control readback"))?;
    log!(
        "VMCS host fields written and read back; host PAT load={} EFER load={}; VM entry not attempted.",
        exit_controls & vmx::vmcs::fields::VM_EXIT_LOAD_IA32_PAT != 0,
        exit_controls & vmx::vmcs::fields::VM_EXIT_LOAD_IA32_EFER != 0,
    );

    // SAFETY: VMX root operation with the VMCS `run` created and made
    // current. The exit stack and the handler stay in place for as long as
    // the guest can exit.
    unsafe { vmx::vmcs::configure_host_entry(vmexit_stack.top(), vmx::vmexit::entry_address()) }
        .map_err(vmcs_step("host entry address setup"))?;
    log!("VMCS HOST_RSP/HOST_RIP written and read back; VM entry not attempted.");

    // After the controls: they decide whether guest PAT/EFER fields exist.
    // SAFETY: VMX root operation with the VMCS `run` created and made
    // current. The controls are written, and the host GDT is live and stable.
    let guest_state = unsafe { GuestState::from_current(guest.code_base(), guest.stack_top(), guest.idt()) }
        .map_err(guest_state_error)?;
    // SAFETY: VMX root operation with the VMCS `run` created and made
    // current.
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

/// Confirms that VMXON, the VMCS work, and UEFI calls left the context
/// GDTR, TR, TSS base, and IDTR as they were after activation. If anything
/// changed, stops before the launch: the guest-state fields in the VMCS
/// were copied from the activated tables.
fn check_context_tables_preserved(expected: &ContextTables) -> Result<(), BringUpError> {
    let gdtr = vmx::segment::read_gdtr();
    let tr = vmx::segment::read_tr();
    let idtr = vmx::segment::read_idtr();
    let same_gdtr = gdtr == expected.gdtr;
    let same_idtr = idtr == expected.idtr;
    let same_tss_base = same_gdtr && tr == expected.tr && {
        // SAFETY: `gdtr` is Aleph0's own GDT (`same_gdtr`), live and never
        // freed.
        unsafe { vmx::segment::segment_base_from_gdt(&gdtr, tr) == expected.tss_base }
    };

    if same_gdtr && same_idtr && same_tss_base {
        log!("Context GDTR, TR, TSS base and IDTR preserved after VMX/UEFI calls.");
        Ok(())
    } else {
        log!("WARNING: Context descriptor state changed after VMX/UEFI calls.");
        log!(
            "Expected GDTR={:?} TR={:#06x} TSS={:#018x} IDTR={:?}",
            expected.gdtr,
            expected.tr,
            expected.tss_base,
            expected.idtr,
        );
        log!("Actual GDTR={gdtr:?} TR={tr:#06x} IDTR={idtr:?} TSS base matches={same_tss_base}");
        Err(BringUpError::ContextTablesChanged)
    }
}
