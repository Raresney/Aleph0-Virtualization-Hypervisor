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
//! 2. Allocate the VM-exit stack and the guest's pages, and check how the
//!    page tables map the guest pages.
//! 3. Detect VMX, read its capability MSRs and check EPT support
//!    ([`check_vmx_support`]), read the MTRRs, then build the EPT identity
//!    map with their memory types and the guest's data page read-only, with
//!    spare PTs for the guest's MTRR writes. Allocate the MSR and I/O
//!    bitmaps, which intercept every MTRR MSR, and give the exit handler the
//!    guest's copy of the MTRRs. Build what Aleph0 runs on after a VM exit
//!    ([`HostEnvironment`]): page tables mapping the same range, a GDT, a
//!    TSS with interrupt stacks, an IDT.
//! 4. Enter VMX root operation and create the VMCS.
//! 5. Check in the UEFI memory map that every resident allocation, the
//!    image copy included, lies in memory the OS keeps after
//!    `ExitBootServices` ([`check_resident_memory`]). Fill in the VMCS:
//!    controls, EPT pointer, exit bitmaps, host state, guest state
//!    ([`prepare_vmcs`]). Then check that none of this disturbed the host's
//!    descriptor tables, and stop if it did.
//! 6. Launch the guest with VMLAUNCH: the one `GuestKind::SELECTED` names.
//!    - The test guest ([`run_test_guest`]): `vmx::vmcs::launch` returns
//!      once the guest has stopped: after its last planned exit, or at an
//!      exit or failure the exit handler in `vmx::vmexit` does not handle.
//!      The host state the guest reaches through passthrough emulation
//!      ([`PassthroughState`]) is read before and after, and printed, and
//!      so are the CPU's MTRRs, which the guest must never reach.
//!    - The firmware ([`virtualize_firmware`]): the `ExitBootServices`
//!      event is created first (`resident::watch_exit_boot_services`), then
//!      `vmx::vmcs::launch_in_place` returns in VMX non-root operation, as
//!      the guest. `run` then returns to `main`, and `main` to the firmware,
//!      which keeps running virtualized. Step 7 does not run; a stop of the
//!      firmware halts in the exit handler.
//! 7. Leave VMX operation and restore the firmware's state
//!    ([`teardown::teardown`]). Runs whatever happened after VMXON
//!    succeeded (creating the VMCS, steps 5 and 6), except a firmware that
//!    now runs as the guest, so firmware gets the CPU back outside VMX
//!    operation unless VMXOFF itself fails. If VMXON or an earlier step
//!    failed there is nothing to leave, and only the firmware's GDTR needs
//!    loading again.
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

use uefi::boot::{self, MemoryType};
use uefi::mem::memory_map::MemoryMap;

use crate::resident::{self, memory};
use crate::vmx;
use crate::vmx::VmxCapabilities;
use crate::vmx::apic::{self, ApicBase, IA32_APIC_BASE, LapicMode};
use crate::vmx::context_tables::{GdtError, GdtRegion, TssRegion};
use crate::vmx::ept::{self, Ept, EptSupport, TypeTables};
use crate::vmx::exit_bitmaps::ExitBitmaps;
use crate::vmx::guest::{GUEST_SCRATCH_PORT, GuestMemory};
use crate::vmx::guest_state::{GuestEntry, GuestState};
use crate::vmx::host::{FirmwareSelectors, HostEnvironment};
use crate::vmx::msr::{IA32_KERNEL_GS_BASE, VmcsControlMsrs};
use crate::vmx::mtrr::{MtrrError, MtrrRegisters, MtrrState};
use crate::vmx::page;
use crate::vmx::segment::DescriptorTable;
use crate::vmx::vmcs::{DesiredControls, GuestKind, GuestStop, VmcsRegion};
use crate::vmx::vmexit::{VM_EXIT_STACK_SIZE, VmExitStack};
use crate::vmx::vmxon::VmxOperation;

use error::{guest_state_error, vmcs_step};
use teardown::FirmwareState;

/// How bring-up ended when everything went to plan.
#[derive(Debug, Clone, Copy)]
pub enum GuestRun {
    /// The test guest finished after `exits` VM exits, all of them handled,
    /// and VMX operation is left.
    Finished { exits: u64 },
    /// The firmware runs as the guest: the code that receives this runs in
    /// VMX non-root operation, and returns to the firmware virtualized.
    Virtualized,
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

impl ContextTables {
    /// The GDT and TSS pages, which the in-place firmware guest runs on and
    /// the CPU reads through EPT, so hiding must keep them visible
    /// ([`TypeTables::hide`]). The TSS is a single 64-bit TSS (one page); the
    /// GDT spans its base through its limit.
    fn guest_visible_tables(&self) -> [page::Allocation; 2] {
        let pages = |base: u64, bytes: u64| {
            let start = base & !(page::PAGE_SIZE as u64 - 1);
            page::Allocation {
                address: start,
                pages: (base + bytes - start).div_ceil(page::PAGE_SIZE as u64) as usize,
                code: false,
            }
        };
        [
            pages(self.gdtr.base, u64::from(self.gdtr.limit) + 1),
            // The TSS is one page, allocated page-aligned (`TssRegion`).
            pages(self.tss_base, page::PAGE_SIZE as u64),
        ]
    }
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
        && !core::mem::needs_drop::<TypeTables>()
        && !core::mem::needs_drop::<ExitBitmaps>()
        && !core::mem::needs_drop::<VmxOperation>()
        && !core::mem::needs_drop::<VmcsRegion>()
);

/// Activates the host tables, enters VMX operation, prepares the VMCS,
/// launches the guest, and, for the test guest, leaves VMX operation again.
///
/// Returns once the test guest has stopped, once the firmware runs as the
/// guest ([`GuestRun::Virtualized`], in VMX non-root operation), or at the
/// first failure. Once the host tables are active, every other return path
/// puts the firmware's GDTR back. If VMXON succeeded, it also puts back the
/// IDTR and interrupt flag and leaves VMX operation. The one exception is a
/// failing VMXOFF: the CPU then stays in VMX root operation with CR4.VMXE
/// set, and teardown prints that. The firmware guest keeps Aleph0's GDT
/// copy, TSS and CR4.VMXE.
///
/// Every region allocated here (TSS, GDT, VM-exit stack, guest pages, EPT
/// tables, host environment, exit bitmaps, VMXON region, VMCS) stays allocated, even after this
/// returns. None of these types implement `Drop`, so their pages are never
/// returned to UEFI. TR keeps pointing at the TSS (see `teardown`). All of
/// them are resident (`vmx::page`), so after a return to the firmware the
/// OS loses them too.
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
        mtrrs,
        types,
    } = entry;

    // From here on every path goes through teardown before returning.
    // SAFETY: VMXON succeeded in `enter_vmx`, so this CPU is in VMX root
    // operation; outside it the VMCS instructions would raise #UD.
    let vmcs = unsafe { VmcsRegion::create_current() }.map_err(vmcs_step("creation"));
    let result = match &vmcs {
        // Every page Aleph0 keeps is now allocated: finalize the memory
        // (check it is resident, hide it from the guest, publish the type
        // tables), then launch.
        Ok(_) => finalize_memory(mtrrs, types, &context_tables)
            .and_then(|()| launch_guest(&controls, &vmexit_stack, &guest, &ept, &host, &bitmaps, &context_tables)),
        Err(error) => Err(*error),
    };
    // This already runs as the guest: the firmware gets the CPU back
    // virtualized, with no teardown and no VMXOFF.
    if let Ok(GuestRun::Virtualized) = result {
        return result;
    }
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
    /// The guest's MTRRs and the EPT type tables, published to the exit
    /// handler in `launch_guest` after `hide` runs.
    mtrrs: MtrrState,
    types: TypeTables,
}

/// Steps 2 to 4 up to the VMCS: allocates the VM-exit stack and the guest's
/// pages, checks VMX and EPT support, reads the MTRRs, builds the EPT
/// tables, the exit bitmaps and the host environment, and enters VMX root
/// operation. A failure here leaves the CPU outside VMX operation, so `run`
/// only has to put the firmware's GDTR back.
fn enter_vmx(context_tables: &ContextTables) -> Result<VmxEntry, BringUpError> {
    let vmexit_stack = VmExitStack::allocate()?;
    log!(
        "VM-exit stack allocated: top={:#018x} size={VM_EXIT_STACK_SIZE}.",
        vmexit_stack.top()
    );

    // shortcut: the firmware guest gets the test guest's pages too, to give
    // `Ept::build` a page to protect; they are resident, and `finalize_memory`
    // now hides them from the guest (code read-only, data to the shadow) like
    // the rest of Aleph0, so no OS reaches them. Drop them once `Ept::build`
    // no longer needs a protected page of its own.
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

    let (controls, ept_support) = check_vmx_support()?;

    // The guest's MTRRs start as the CPU's.
    let mtrrs = MtrrState::new(vmx::mtrr::read()?)?;
    let capabilities = mtrrs.registers().capabilities();
    report::mtrrs(mtrrs.mtrrs());
    let protected_pages = [guest.data_page(), guest.stack_page()];
    // SAFETY: boot services are still active, and UEFI identity-maps
    // memory, which also makes the guest pages' addresses their GPAs.
    let (ept, types) = unsafe {
        Ept::build(
            &protected_pages,
            ept_support,
            mtrrs.mtrrs(),
            ept::spare_pts(capabilities),
        )
    }?;
    report::ept(&ept, &types, &protected_pages);
    let _local_apic = check_local_apic(&ept, &types, ept_support)?;
    // Test only: the guest's read of the Local APIC then meets a PDPT entry
    // the CPU refuses, so the run shows the EPT misconfiguration stop and
    // its walk on real VMX.
    #[cfg(feature = "ept-misconfig-test")]
    if let Some(registers) = _local_apic {
        // SAFETY: before VMLAUNCH: the CPU has never walked the tables.
        unsafe { types.misconfigure(registers) };
        log!(
            "ept-misconfig-test: the PDPT entry of GiB {:#x} is now W without R.",
            registers >> 30
        );
    }

    let bitmaps = ExitBitmaps::allocate()?;
    report::exit_bitmaps(&bitmaps, capabilities);
    // `mtrrs` and `types` are published to the exit handler only in
    // `launch_guest`, once every page Aleph0 keeps is allocated and `hide`
    // has redirected them to the shadow: no exit, which is the only reader,
    // happens before VMLAUNCH.
    let hyperv = vmx::hyperv::Detection::read();
    report::hyperv(&hyperv);
    vmx::hyperv::publish(hyperv.offers_interface());

    // Every address the UEFI memory map reaches, which holds the image,
    // every allocation (the EPT tables included) and the firmware stack:
    // not the device space above it, which EPT maps for the guest only.
    // SAFETY: boot services are still active, and UEFI identity-maps memory.
    let host = unsafe { HostEnvironment::build(ept.memory_map_end(), FirmwareSelectors::read()) }?;
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
        mtrrs,
        types,
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

/// Checks that the test guest can read the Local APIC's version register,
/// and returns where it reads it. In xAPIC mode both the page tables the
/// guest shares and EPT must map the register page, device memory above the
/// UEFI memory map, to itself, EPT with UC. In any other mode there is no
/// register page: the guest skips its read, and this returns `None`.
fn check_local_apic(ept: &Ept, types: &TypeTables, support: EptSupport) -> Result<Option<u64>, BringUpError> {
    // SAFETY: IA32_APIC_BASE exists on every CPU with a Local APIC, which
    // every x86-64 CPU has, and reading it has no side effects.
    let apic_base = ApicBase(unsafe { vmx::msr::rdmsr(IA32_APIC_BASE) });
    if apic_base.mode() != LapicMode::Xapic {
        report::local_apic_skipped(apic_base);
        return Ok(None);
    }
    let registers = apic_base.address(support.rules.physical_address_bits);
    // SAFETY: boot services are still active, so the firmware's tables are
    // identity-mapped.
    let translation = unsafe { vmx::paging::walk_current(registers) };
    let walk = types.walk(ept.eptp(), registers);
    report::local_apic(apic_base, registers, walk.end);
    apic::check_registers(registers, translation, walk.end)?;
    Ok(Some(registers))
}

/// Detects VMX, reads the capability MSRs the VMCS controls are chosen from,
/// and checks that the CPU supports the EPT Aleph0 builds. Returns the MSRs
/// and what the CPU's EPT offers.
fn check_vmx_support() -> Result<(VmcsControlMsrs, EptSupport), BringUpError> {
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

    let support = ept::check_support(
        controls.secondary,
        controls.ept_vpid_cap,
        vmx::cpuid::physical_address_bits(),
    )?;
    report::ept_support(support);
    Ok((controls, support))
}

/// Checks the resident memory, prepares the current VMCS for the guest
/// `GuestKind::SELECTED` names, checks the host tables, and launches the
/// guest. Returns once the test guest has stopped, or in VMX non-root
/// operation once the firmware runs as the guest.
fn launch_guest(
    controls: &VmcsControlMsrs,
    vmexit_stack: &VmExitStack,
    guest: &GuestMemory,
    ept: &Ept,
    host: &HostEnvironment,
    bitmaps: &ExitBitmaps,
    context_tables: &ContextTables,
) -> Result<GuestRun, BringUpError> {
    let kind = GuestKind::SELECTED;
    let entry = match kind {
        GuestKind::BuiltInTest => GuestEntry::At {
            rip: guest.code_base(),
            rsp: guest.stack_top(),
            idtr: guest.idt(),
        },
        GuestKind::Firmware => GuestEntry::InPlace {
            idtr: context_tables.idtr,
        },
    };
    prepare_vmcs(controls, vmexit_stack, ept, host, bitmaps, kind, entry)?;
    check_context_tables_preserved(context_tables)?;

    match kind {
        GuestKind::BuiltInTest => run_test_guest(vmexit_stack),
        GuestKind::Firmware => virtualize_firmware(),
    }
}

/// With every page Aleph0 keeps now allocated: checks they all lie in
/// memory the OS preserves ([`check_resident_memory`]), hides them from the
/// guest in EPT ([`hide_resident_memory`]), and hands the guest's MTRRs and
/// the type tables to the exit handler (`publish_guest_mtrrs`). The last
/// step before the launch; no exit, the only reader, has happened yet.
fn finalize_memory(
    mtrrs: MtrrState,
    mut types: TypeTables,
    context_tables: &ContextTables,
) -> Result<(), BringUpError> {
    check_resident_memory()?;
    // The built-in test guest runs from Aleph0's own resident pages (its
    // code, stack, IDT and data are `GuestMemory`), so hiding them would
    // hide the guest from itself; it tests the exit machinery, not hiding.
    // The firmware, and an OS, run from their own memory, which is not
    // resident, so hiding Aleph0's pages never touches the guest.
    if !matches!(GuestKind::SELECTED, GuestKind::BuiltInTest) {
        hide_resident_memory(&mut types, mtrrs.mtrrs(), context_tables)?;
    }
    vmx::vmexit::publish_guest_mtrrs(mtrrs, types);
    Ok(())
}

/// Checks, in the UEFI memory map, that every resident allocation
/// (`vmx::page`) lies in memory the OS keeps after `ExitBootServices`, and
/// prints each one's type. A `LOADER_*` or `BOOT_SERVICES_*` page here would
/// be reused by the OS while Aleph0 still needs it.
fn check_resident_memory() -> Result<(), BringUpError> {
    let map = boot::memory_map(MemoryType::LOADER_DATA).map_err(|_| BringUpError::ResidentMemoryMapUnavailable)?;
    let mut pages = 0;
    for allocation in page::resident_allocations() {
        let regions = map
            .entries()
            .map(|region| (region.phys_start, region.page_count, region.ty));
        let memory_type = resident::memory_type_at(regions, allocation.address);
        report::resident_allocation(allocation, memory_type);
        if memory_type.is_none_or(memory::is_reclaimable) {
            return Err(BringUpError::NotResident {
                address: allocation.address,
                memory_type,
            });
        }
        pages += allocation.pages;
    }
    // The image copy is always listed: an empty list means listing broke,
    // and the loop above checked nothing.
    if pages == 0 {
        return Err(BringUpError::NoResidentAllocations);
    }
    match page::unlisted_resident_allocations() {
        0 => {
            log!("Resident memory checked: {pages} pages, all kept by the OS after ExitBootServices.");
            Ok(())
        }
        unlisted => Err(BringUpError::ResidentAllocationsUnlisted(unlisted)),
    }
}

/// Redirects every page Aleph0 keeps to the EPT shadow page, so the guest
/// can neither read Aleph0's memory nor rewrite its EPT or exit handler
/// ([`TypeTables::hide`]). Runs after [`check_resident_memory`], which has
/// already confirmed the allocation list is complete (no unlisted
/// allocation, which would leave a page exposed), and before VMLAUNCH.
///
/// The in-place firmware guest runs on Aleph0's context GDT and TSS, which
/// the CPU reads through EPT on every interrupt and segment load, so those
/// pages are kept visible: hiding them would feed the CPU a zeroed
/// descriptor table and triple-fault the guest.
fn hide_resident_memory(
    types: &mut TypeTables,
    mtrrs: &vmx::mtrr::Mtrrs,
    context_tables: &ContextTables,
) -> Result<(), BringUpError> {
    let visible = context_tables.guest_visible_tables();
    // SAFETY: still single-threaded with the guest not launched, so the CPU
    // has not walked the EPT and `build`'s tables are not aliased.
    let hidden = unsafe { types.hide(page::resident_allocations(), mtrrs, &visible) }?;
    report::hidden(hidden);
    Ok(())
}

/// Creates the `ExitBootServices` event, then launches the firmware in
/// place: from VMLAUNCH on, this code is the guest. Returns
/// [`GuestRun::Virtualized`] in VMX non-root operation, or the launch's
/// failure in root operation, with the event closed again.
fn virtualize_firmware() -> Result<GuestRun, BringUpError> {
    // Before VMLAUNCH: once the firmware is the guest, every firmware call
    // can exit, and one Aleph0 does not handle stops it.
    let event =
        resident::watch_exit_boot_services().map_err(|error| BringUpError::ExitBootServicesEvent(error.status()))?;
    log!("ExitBootServices event created: its VMCALL will tell Aleph0 when boot services end.");
    log!("Launching the firmware in place with VMLAUNCH; its VM exits are reported on serial only.");
    // SAFETY: `prepare_vmcs` wrote the controls, the host state
    // (HOST_RSP/HOST_RIP at the live exit stack and handler) and the guest
    // state of this context (`GuestEntry::InPlace`); the exit stack, EPT
    // tables, host environment and exit bitmaps are never freed, and the
    // handler halts at a stop of the firmware (`GuestKind::Firmware`).
    match unsafe { vmx::vmcs::launch_in_place() } {
        Ok(()) => Ok(GuestRun::Virtualized),
        Err(stop) => {
            // Outside VMX operation its VMCALL would raise #UD inside
            // ExitBootServices.
            if let Err(error) = boot::close_event(event) {
                log!("ExitBootServices event not closed: {:?}.", error.status());
            }
            guest_result(stop)
        }
    }
}

/// Launches the test guest and checks its run once it has stopped: the
/// exit stack, the host state it reaches through passthrough emulation,
/// the CPU's MTRRs, and its exit statistics.
fn run_test_guest(vmexit_stack: &VmExitStack) -> Result<GuestRun, BringUpError> {
    log!("Launching the guest with VMLAUNCH; its VM exits are reported on serial only.");
    let before = PassthroughState::read();
    let mtrrs_before = vmx::mtrr::read();
    // SAFETY: `prepare_vmcs` wrote the controls, the host state
    // (HOST_RSP/HOST_RIP at the live exit stack and handler) and the guest
    // state; the exit stack, guest pages, EPT tables, host environment and
    // exit bitmaps are never freed.
    let stop = unsafe { vmx::vmcs::launch() };
    // SAFETY: the guest has stopped, so no exit handler runs on the stack.
    let stack_used = unsafe { vmexit_stack.used() };
    log!("VM-exit stack: {stack_used} of {VM_EXIT_STACK_SIZE} bytes used.");
    report::passthrough_state(before, PassthroughState::read());
    let mtrrs_after = vmx::mtrr::read();
    // The guest has stopped, so no exit handler writes its MTRRs any more.
    let guest_mtrrs = vmx::vmexit::guest_mtrr_registers();
    report::mtrrs_after_guest(&mtrrs_before, &mtrrs_after, guest_mtrrs.as_ref());
    // Before the guest's own result: an overflow corrupts whatever lies below
    // the stack, and the guest's stop may only be its consequence.
    if stack_used == VM_EXIT_STACK_SIZE {
        return Err(BringUpError::VmExitStackFull);
    }
    let run = guest_result(stop)?;
    // The guest has stopped, so no exit handler is counting any more.
    let stats = vmx::vmexit::vcpu_stats();
    if stats != vmx::guest::expected_stats(&stats) {
        return Err(BringUpError::UnexpectedExitStats(stats));
    }
    check_mtrrs_untouched(&mtrrs_before, &mtrrs_after)?;
    Ok(run)
}

/// Checks that the CPU's MTRRs read the same after the guest as before
/// (`before`, `after`): its MTRR writes went to its copy, never to the MSRs
/// that set the memory types of Aleph0's own accesses.
fn check_mtrrs_untouched(
    before: &Result<MtrrRegisters, MtrrError>,
    after: &Result<MtrrRegisters, MtrrError>,
) -> Result<(), BringUpError> {
    match (before, after) {
        (Ok(before), Ok(after)) if before == after => Ok(()),
        (Err(error), _) | (_, Err(error)) => Err(BringUpError::Mtrr(*error)),
        (Ok(_), Ok(_)) => Err(BringUpError::MtrrsChanged),
    }
}

/// Fills in the current VMCS: controls for a `kind` guest, EPT pointer, exit
/// bitmaps, host state, and guest state starting at `entry`. VM entry is not
/// attempted.
fn prepare_vmcs(
    controls: &VmcsControlMsrs,
    vmexit_stack: &VmExitStack,
    ept: &Ept,
    host: &HostEnvironment,
    bitmaps: &ExitBitmaps,
    kind: GuestKind,
    entry: GuestEntry,
) -> Result<(), BringUpError> {
    // SAFETY: VMX root operation with the VMCS `run` created and made
    // current.
    unsafe { vmx::vmcs::self_test() }.map_err(vmcs_step("self-test"))?;
    log!("VMCS self-test passed: VMREAD returned what VMWRITE stored.");

    // SAFETY: VMX root operation with the VMCS `run` created and made
    // current.
    unsafe { vmx::vmcs::configure_controls(controls, DesiredControls::minimal_64_bit_guest(kind)) }
        .map_err(vmcs_step("control setup"))?;
    log!("VMCS controls for the {kind:?} guest written and read back successfully.");

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
    let guest_state = unsafe { GuestState::from_current(entry) }.map_err(guest_state_error)?;
    // SAFETY: VMX root operation with the VMCS `run` created and made
    // current.
    unsafe { guest_state.write() }.map_err(guest_state_error)?;
    report::guest_state(&guest_state, entry);

    Ok(())
}

/// Turns the way the guest stopped into bring-up's result.
fn guest_result(stop: GuestStop) -> Result<GuestRun, BringUpError> {
    match stop {
        GuestStop::Finished { exits } => Ok(GuestRun::Finished { exits }),
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
