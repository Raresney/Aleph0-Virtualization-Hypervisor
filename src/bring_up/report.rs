//! Bring-up lines that only print state. Kept apart from the sequence in
//! `mod.rs`, so that file reads as the steps themselves.
//!
//! Nothing here changes CPU state or can fail.

use crate::vmx;
use crate::vmx::guest::{GuestMappings, GuestMemory};
use crate::vmx::guest_state::GuestState;
use crate::vmx::msr::VmcsControlMsrs;

/// Prints the segmentation state that will go into the VMCS host fields.
///
/// TR is the one to watch: VM entry rejects a host TR selector of 0.
pub(super) fn segment_state() {
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

/// Prints the EPT identity map [`Ept::build`](vmx::ept::Ept::build) made.
pub(super) fn ept(ept: &vmx::ept::Ept, data_page: u64) {
    log!(
        "EPT built: identity 0x0..{:#x} ({} GiB) with 2 MiB pages, {} table pages; data page {data_page:#018x} read-only (R=1 W=0 X=0).",
        ept.end(),
        ept.end() >> 30,
        ept.table_pages(),
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
    let nxe = unsafe { vmx::msr::rdmsr(vmx::msr::IA32_EFER) } & vmx::msr::EFER_NXE != 0;
    let cr4 = vmx::cr::read_cr4();
    log!(
        "Guest code page executable, stack and data pages writable; host EFER.NXE={nxe} CR4.SMEP={} CR4.SMAP={}.",
        cr4 & vmx::cr::CR4_SMEP != 0,
        cr4 & vmx::cr::CR4_SMAP != 0,
    );
}

/// Prints the guest state that was written to the VMCS. If VM entry later
/// fails with "invalid guest state" (exit reason 33), these are the values
/// the CPU rejected.
pub(super) fn guest_state(state: &GuestState) {
    log!(
        "Guest rip={:#018x} rsp={:#018x} rflags={:#x} cr0={:#x} cr3={:#x} cr4={:#x}",
        state.rip,
        state.rsp,
        state.rflags,
        state.cr0,
        state.cr3,
        state.cr4,
    );
    for (name, segment) in [
        ("cs", state.cs),
        ("ss", state.ss),
        ("ds", state.ds),
        ("es", state.es),
        ("fs", state.fs),
        ("gs", state.gs),
        ("tr", state.tr),
        ("ldtr", state.ldtr),
    ] {
        log!(
            "Guest {name:<4} selector={:#06x} base={:#018x} limit={:#010x} access={:#07x}",
            segment.selector,
            segment.base,
            segment.limit,
            segment.access_rights,
        );
    }
    log!(
        "Guest gdtr={:#018x}/{:#06x} idtr={:#018x}/{:#06x}; PAT load={} EFER load={}",
        state.gdtr.base,
        state.gdtr.limit,
        state.idtr.base,
        state.idtr.limit,
        state.pat.is_some(),
        state.efer.is_some(),
    );
    log!("VMCS guest fields written and read back; VM entry not attempted.");
}
