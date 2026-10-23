//! Bring-up lines that only print state. Kept apart from the sequence in
//! `mod.rs`, so that file reads as the steps themselves.
//!
//! Nothing here changes CPU state or can fail.

use super::PassthroughState;
use crate::vmx;
use crate::vmx::exit_bitmaps::{ExitBitmaps, INTERCEPTED_MSRS, INTERCEPTED_PORTS};
use crate::vmx::guest::{GuestMappings, GuestMemory};
use crate::vmx::guest_state::GuestState;
use crate::vmx::host::{HostEnvironment, InterruptStack};
use crate::vmx::msr::VmcsControlMsrs;
use crate::vmx::mtrr::{MemoryType, Mtrrs};

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
    let enabled = match mtrrs {
        Mtrrs::Unsupported => {
            log!("MTRRs: not supported (CPUID); all memory is treated as WB.");
            return;
        }
        Mtrrs::Disabled => {
            log!("MTRRs: disabled (IA32_MTRR_DEF_TYPE.E=0); all memory is UC.");
            return;
        }
        Mtrrs::Enabled(enabled) => enabled,
    };
    log!(
        "MTRRs: enabled, default type {}; fixed ranges {}; {} variable ranges, {} in use.",
        enabled.default_type().name(),
        if enabled.fixed_enabled() { "enabled" } else { "disabled" },
        enabled.variable_count(),
        enabled.variable_ranges().len(),
    );
    for range in enabled.variable_ranges() {
        log!(
            "MTRR variable range {}: base={:#014x} mask={:#014x} {}",
            range.number,
            range.base,
            range.mask,
            range.memory_type.name(),
        );
    }
    if enabled.fixed_enabled() {
        for run in mtrrs.runs(vmx::mtrr::FIXED_END, vmx::page::PAGE_SIZE as u64) {
            log!(
                "MTRR fixed {:#07x}..{:#07x}: {}",
                run.start,
                run.end,
                type_name(run.memory_type)
            );
        }
    }
}

/// Prints the EPT identity map [`Ept::build`](vmx::ept::Ept::build) made,
/// and how its PD entries map each run of 2 MiB regions: read back from the
/// entries, so the lines show what the CPU walks.
pub(super) fn ept(ept: &vmx::ept::Ept, protected_pages: &[u64]) {
    log!(
        "EPT built: identity 0x0..{:#x} ({} GiB), {} table pages, {} of them PTs for 2 MiB regions mapped in 4 KiB pages; {} pages read-only (R=1 W=0 X=0).",
        ept.end(),
        ept.end() >> 30,
        ept.table_pages(),
        ept.split_regions(),
        protected_pages.len(),
    );
    for page in protected_pages {
        log!("EPT read-only page: {page:#018x}.");
    }
    for run in ept.region_runs() {
        log!("EPT {:#014x}..{:#014x}: {}", run.start, run.end, run.mapping);
    }
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

/// A run's type for the report: its name, or "mixed" for blocks whose pages
/// differ.
fn type_name(memory_type: Option<MemoryType>) -> &'static str {
    match memory_type {
        Some(memory_type) => memory_type.name(),
        None => "mixed (4 KiB pages)",
    }
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

/// Prints where the exit bitmaps are and what they intercept.
pub(super) fn exit_bitmaps(bitmaps: &ExitBitmaps) {
    log!(
        "Exit bitmaps allocated: MSR={:#018x} I/O A={:#018x} I/O B={:#018x}.",
        bitmaps.msr_address(),
        bitmaps.io_a_address(),
        bitmaps.io_b_address(),
    );
    log!("Intercepted MSRs (read and write): {INTERCEPTED_MSRS:x?}; intercepted ports: {INTERCEPTED_PORTS:x?}.");
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
pub(super) fn guest_state(state: &GuestState) {
    state.report(format_args!("Guest"));
    log!("VMCS guest fields written and read back; VM entry not attempted.");
}
