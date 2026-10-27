//! Bring-up lines that only print state. Kept apart from the sequence in
//! `mod.rs`, so that file reads as the steps themselves.
//!
//! Nothing here changes CPU state or can fail.

use uefi::boot::MemoryType;

use super::PassthroughState;
use crate::vmx;
use crate::vmx::apic::{ApicBase, LAPIC_VERSION};
use crate::vmx::ept::{Ept, EptSupport, Hidden, TypeTables, WalkEnd};
use crate::vmx::exit_bitmaps::{ExitBitmaps, INTERCEPTED_MSRS, INTERCEPTED_PORTS};
use crate::vmx::guest::{GuestMappings, GuestMemory};
use crate::vmx::guest_state::{GuestEntry, GuestState};
use crate::vmx::host::{HostEnvironment, InterruptStack};
use crate::vmx::hyperv::{Detection, INTERFACE_LEAF, SYNTHETIC_MSRS, VENDOR_LEAF};
use crate::vmx::msr::VmcsControlMsrs;
use crate::vmx::mtrr::{MtrrCapabilities, MtrrError, MtrrRegisters, Mtrrs};
use crate::vmx::page::Allocation;

/// Prints the segmentation state of the context tables, which the guest
/// state copies and the host GDT keeps the selectors of.
///
/// TR is the one to watch: VM entry rejects an unusable guest TR.
pub(super) fn segment_state() {
    // SAFETY: the context GDT is live (activated by bring-up, never freed), and
    // UEFI runs in long mode.
    let state = unsafe { vmx::segment::read_all() };

    log!(
        "segments: cs={:#06x} ss={:#06x} ds={:#06x} es={:#06x} fs={:#06x} gs={:#06x} tr={:#06x}",
        state.cs,
        state.ss,
        state.ds,
        state.es,
        state.fs,
        state.gs,
        state.tr,
    );
    log!(
        "bases:    fs={:#018x} gs={:#018x} tr={:#018x}",
        state.fs_base,
        state.gs_base,
        state.tr_base,
    );
    log!(
        "gdtr:     base={:#018x} limit={:#06x}",
        state.gdtr.base,
        state.gdtr.limit,
    );
    log!(
        "idtr:     base={:#018x} limit={:#06x}",
        state.idtr.base,
        state.idtr.limit,
    );

    if state.tr == 0 {
        log!("WARNING: TR is 0; VM entry would reject this host state.");
    }
}

/// Prints the VMX capability MSRs: IA32_VMX_BASIC; for each of the four
/// control fields and the secondary controls, which bits must be 1 (low
/// half) and may be 1 (high half); and IA32_VMX_EPT_VPID_CAP.
pub(super) fn vmx_capabilities(controls: &VmcsControlMsrs) {
    log!(
        "VMX BASIC={:#018x}; true controls={}",
        controls.basic,
        controls.basic & vmx::msr::VMX_BASIC_TRUE_CONTROLS != 0,
    );
    for (name, capability) in [
        ("pin", controls.pinbased),
        ("primary", controls.primary),
        ("exit", controls.exit),
        ("entry", controls.entry),
    ] {
        log!(
            "VMX {name}: required={:#010x} allowed={:#010x}",
            capability.required(),
            capability.allowed(),
        );
    }
    log!(
        "VMX secondary: required={:#010x} allowed={:#010x}; EPT/VPID capabilities={:#018x}",
        controls.secondary.required(),
        controls.secondary.allowed(),
        controls.ept_vpid_cap,
    );
}

/// Prints the MTRRs [`vmx::mtrr::read`] decoded: whether they are on, the
/// default type, each variable range in use, and the types the fixed ranges
/// give the first MiB.
pub(super) fn mtrrs(mtrrs: &Mtrrs) {
    log!("MTRRs: {mtrrs}.");
    let Mtrrs::Enabled(enabled) = mtrrs else {
        return;
    };
    for range in enabled.variable_ranges() {
        log!("MTRR {range}");
    }
    if enabled.fixed_enabled() {
        for run in mtrrs.runs(vmx::mtrr::FIXED_END, vmx::page::PAGE_SIZE as u64) {
            log!("MTRR fixed {:#07x}..{:#07x}: {}", run.start, run.end, run.type_name());
        }
    }
}

/// Prints what the CPU's EPT offers: what Aleph0 requires of it, and what
/// the map may use.
pub(super) fn ept_support(support: EptSupport) {
    log!(
        "EPT supported: 4-level walk, WB, 2 MiB pages, INVEPT {}; 1 GiB pages={}; MAXPHYADDR {} bits.",
        support.invept.name(),
        support.rules.huge_pages,
        support.rules.physical_address_bits,
    );
}

/// Prints the EPT identity map [`Ept::build`] made, and how its entries
/// (`types`) map each run of it: read back from the entries, so the lines
/// show what the CPU walks.
pub(super) fn ept(ept: &Ept, types: &TypeTables, protected_pages: &[u64]) {
    let layout = ept.layout();
    log!(
        "EPT built: identity 0x0..{:#x} ({} GiB), {} table pages: {} PDPT(s); {} PD(s), for 0x0..{:#x}, with {} PTs for 2 MiB regions mapped in 4 KiB pages and {} spare PTs for the guest's MTRR writes; {} GiB above as 1 GiB pages; {} pages read-only (R=1 W=0 X=0).",
        ept.end(),
        ept.end() >> 30,
        ept.table_pages(),
        layout.pdpts(),
        layout.pd_gibs(),
        layout.pd_end(),
        ept.split_regions(),
        ept.spare_pts(),
        layout.huge_gibs(),
        protected_pages.len(),
    );
    for page in protected_pages {
        log!("EPT read-only page: {page:#018x}.");
    }
    let ram = types.ram().ranges();
    log!(
        "EPT memory types: the MTRRs' for the {} RAM range(s) of the UEFI memory map, UC for everything else (MMIO, reserved memory, holes).",
        ram.len()
    );
    for &(start, end) in ram {
        log!("EPT RAM {start:#014x}..{end:#014x}");
    }
    for run in types.region_runs(0, ept.end()) {
        log!("EPT {:#014x}..{:#014x}: {}", run.start, run.end, run.mapping);
    }
}

/// Prints IA32_APIC_BASE and how EPT maps the Local APIC's register page at
/// `registers`, as the walk of it ended (`walk_end`), for the test guest's
/// read of its version register.
pub(super) fn local_apic(apic_base: ApicBase, registers: u64, walk_end: WalkEnd) {
    log!(
        "Local APIC: IA32_APIC_BASE={apic_base}; its registers at {registers:#x} are {walk_end}; the test guest reads the version register at {:#x}.",
        registers + LAPIC_VERSION,
    );
}

/// Prints that the Local APIC IA32_APIC_BASE describes is not in xAPIC mode,
/// so the test guest has no register page to read, and skips its read.
pub(super) fn local_apic_skipped(apic_base: ApicBase) {
    log!("Local APIC: IA32_APIC_BASE={apic_base}: no register page to read; the test guest skips its read.");
}

/// Prints what VMX root operation will run on: the host page tables next to
/// the firmware's CR3 they replace, the GDT, TSS and IDT, and the interrupt
/// stacks.
pub(super) fn host_environment(host: &HostEnvironment, firmware_cr3: u64) {
    let tables = host.page_tables();
    log!(
        "Host page tables: identity 0x0..{:#x} ({} GiB), {}, {} table pages; HOST_CR3={:#x} (firmware CR3={firmware_cr3:#x}).",
        tables.end(),
        tables.end() >> 30,
        tables.page_size().name(),
        tables.table_pages(),
        tables.cr3(),
    );
    let selectors = host.selectors();
    log!(
        "Host GDT at {:#018x} (limit {:#06x}): code {:#06x}, data {:#06x}, TSS {:#06x} at {:#018x}; IDT at {:#018x} (256 gates).",
        host.gdt_base(),
        host.gdt_limit(),
        selectors.cs,
        selectors.ss,
        selectors.tr,
        host.tss_base(),
        host.idt_base(),
    );
    for stack in InterruptStack::ALL {
        let (name, ist, top) = (stack.name(), stack.ist(), host.interrupt_stack_top(stack));
        log!("Host interrupt stack: {name} IST{ist} top={top:#018x}.");
    }
}

/// Prints one resident allocation with the type the memory map gives it
/// (`None`: no region holds it).
pub(super) fn resident_allocation(allocation: Allocation, memory_type: Option<MemoryType>) {
    let Allocation { address, pages, .. } = allocation;
    match memory_type {
        Some(memory_type) => log!("Resident allocation at {address:#018x}: {pages} page(s), {memory_type:?}."),
        None => log!("Resident allocation at {address:#018x}: {pages} page(s), in no memory-map region."),
    }
}

/// Prints how many of Aleph0's own pages EPT now hides from the guest.
pub(super) fn hidden(hidden: Hidden) {
    log!(
        "Aleph0 pages hidden from the guest: {} data page(s) redirected to the EPT shadow, \
         {} code page(s) read-only, {} region(s) split into a PT.",
        hidden.data_pages,
        hidden.code_pages,
        hidden.regions_split,
    );
}

/// Prints how the current page tables, which the guest will share, map the
/// guest pages. Only called once all permission checks have passed.
pub(super) fn guest_mappings(guest: &GuestMemory, mappings: &GuestMappings) {
    let stack_base = guest.stack_top() - vmx::page::PAGE_SIZE as u64;
    for (name, virtual_address, mapping) in [
        ("code", guest.code_base(), mappings.code),
        ("stack", stack_base, mappings.stack),
        ("IDT", guest.idt().base, mappings.idt),
        ("data", guest.data_page(), mappings.data),
    ] {
        log!(
            "Guest {name} page: virt={virtual_address:#018x} phys={:#018x} identity={} size={:?} writable={} user={} xd={}",
            mapping.physical,
            mapping.physical == virtual_address,
            mapping.size,
            mapping.writable,
            mapping.user,
            mapping.execute_disable,
        );
    }

    // The guest shares these tables, so a guest EFER.NXE that differs from
    // the host's would turn any XD bit in them into a reserved-bit fault.
    // SAFETY: IA32_EFER exists on every x86_64 CPU, and reading it has no
    // side effects.
    let nxe = unsafe { vmx::msr::rdmsr(vmx::msr::IA32_EFER) } & vmx::msr::EFER_NXE != 0;
    let cr4 = vmx::cr::read_cr4();
    log!(
        "Guest code page executable, stack and data pages writable; host EFER.NXE={nxe} CR4.SMEP={} CR4.SMAP={}.",
        cr4 & vmx::cr::CR4_SMEP != 0,
        cr4 & vmx::cr::CR4_SMAP != 0,
    );
}

/// Prints where the exit bitmaps are and what they intercept: the MSRs
/// passed through, every MTRR address, of which the guest's copy holds
/// those `mtrr` lists, and the ports.
pub(super) fn exit_bitmaps(bitmaps: &ExitBitmaps, mtrr: MtrrCapabilities) {
    log!(
        "Exit bitmaps allocated: MSR={:#018x} I/O A={:#018x} I/O B={:#018x}.",
        bitmaps.msr_address(),
        bitmaps.io_a_address(),
        bitmaps.io_b_address(),
    );
    log!("Intercepted MSRs (read and write): {INTERCEPTED_MSRS:x?}; intercepted ports: {INTERCEPTED_PORTS:x?}.");
    let addresses = vmx::mtrr::every_msr_address().count();
    match mtrr.msrs().count() {
        0 => log!("Intercepted MTRR addresses (read and write): all {addresses}, which get #GP: the CPU has no MTRRs."),
        count => log!(
            "Intercepted MTRR addresses (read and write): all {addresses}. The guest reads and writes a copy of the {count} MSRs the CPU has (IA32_MTRR_DEF_TYPE, {} fixed-range MSRs and {} variable ranges); the other {} get #GP.",
            if mtrr.fixed() { vmx::mtrr::FIXED_MSRS } else { 0 },
            mtrr.variable_count(),
            addresses - count,
        ),
    }
}

/// Prints what CPUID says of Hyper-V's interface (`detection`), and so what
/// the guest's hypercalls and synthetic MSRs get.
pub(super) fn hyperv(detection: &Detection) {
    let vendor = detection.vendor_bytes();
    let vendor = core::str::from_utf8(&vendor).unwrap_or("not ASCII");
    let line = format_args!(
        "CPUID.1:ECX={:#010x}, leaf {VENDOR_LEAF:#x}: max leaf {:#x} vendor \"{vendor}\", leaf {INTERFACE_LEAF:#x}: interface {:#010x}",
        detection.leaf1_ecx, detection.vendor.eax, detection.interface,
    );
    if detection.offers_interface() {
        log!(
            "Hyper-V interface offered ({line}): the guest keeps it; Aleph0 forwards its hypercalls and its synthetic MSRs {:#x}..={:#x} to Hyper-V.",
            SYNTHETIC_MSRS.start(),
            SYNTHETIC_MSRS.end(),
        );
    } else {
        log!("No Hyper-V interface ({line}): the guest's VMCALLs other than Aleph0's get #UD, its synthetic MSRs #GP.");
    }
}

/// Prints whether the CPU's MTRRs read the same after the guest
/// (`before`, `after`), and whether the guest left its copy (`guest`) as
/// it found it. Still in the exit phase, so serial only.
pub(super) fn mtrrs_after_guest(
    before: &Result<MtrrRegisters, MtrrError>,
    after: &Result<MtrrRegisters, MtrrError>,
    guest: Option<&MtrrRegisters>,
) {
    match (before, after) {
        (Ok(before), Ok(after)) => log!(
            "MTRRs after the guest: the CPU's unchanged={}; the guest's copy restored={}.",
            before == after,
            guest == Some(before),
        ),
        (Err(error), _) | (_, Err(error)) => log!("MTRRs after the guest: the CPU's could not be read: {error}."),
    }
}

/// Prints the host state the guest reached through passthrough emulation,
/// before and after its run. Still in the exit phase, so serial only.
pub(super) fn passthrough_state(before: PassthroughState, after: PassthroughState) {
    log!(
        "Passthrough state before the guest {before:x?}, after it {after:x?}: restored={}.",
        before == after
    );
}

/// Prints the guest state that was written to the VMCS. If VM entry later
/// fails with "invalid guest state" (exit reason 33), these are the values
/// the CPU rejected.
pub(super) fn guest_state(state: &GuestState, entry: GuestEntry) {
    state.report(format_args!("Guest"));
    if let GuestEntry::InPlace { .. } = entry {
        log!(
            "Guest rip, rsp and rflags are placeholders: VMLAUNCH writes its own, and the code after it goes on as the guest."
        );
    }
    log!("VMCS guest fields written and read back; VM entry not attempted.");
}
