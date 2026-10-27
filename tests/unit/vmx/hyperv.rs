//! Unit tests for `src/vmx/hyperv.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items. The forwarders are assembled into the test binary too, so
//! the recovery points are checked against their bytes.

use super::*;

/// CPUID.1:ECX as Hyper-V showed it to Aleph0 (ROADMAP.md), bit 31 set.
const HYPERV_LEAF1_ECX: u32 = 0xf7fa_3223;
/// CPUID.40000000H:EAX, the highest hypervisor leaf, as Hyper-V showed it
/// to Aleph0 (docs/HYPERV_INTERFACE.md).
const HYPERV_MAX_LEAF: u32 = 0x4000_000B;

#[test]
fn hyper_v_offers_its_interface() {
    assert!(offers_interface(HYPERV_LEAF1_ECX, HYPERV_MAX_LEAF, INTERFACE_SIGNATURE));
    assert_eq!(INTERFACE_SIGNATURE, 0x3123_7648);
}

#[test]
fn no_interface_without_the_hypervisor_present_bit() {
    // Bare metal: leaves from 0x40000000 answer with the highest basic leaf's
    // data, which could hold anything.
    assert!(!offers_interface(
        HYPERV_LEAF1_ECX & !(1 << 31),
        HYPERV_MAX_LEAF,
        INTERFACE_SIGNATURE
    ));
}

#[test]
fn no_interface_when_the_interface_leaf_is_past_the_highest() {
    assert!(!offers_interface(HYPERV_LEAF1_ECX, VENDOR_LEAF, INTERFACE_SIGNATURE));
}

#[test]
fn no_interface_for_another_signature() {
    // Another hypervisor's interface leaf, or none: "Hv#0", 0.
    for interface in [u32::from_le_bytes(*b"Hv#0"), 0] {
        assert!(!offers_interface(HYPERV_LEAF1_ECX, HYPERV_MAX_LEAF, interface));
    }
}

#[test]
fn the_vendor_reads_ebx_ecx_edx() {
    let detection = Detection {
        leaf1_ecx: HYPERV_LEAF1_ECX,
        vendor: CpuidResult {
            eax: HYPERV_MAX_LEAF,
            ebx: 0x7263_694D,
            ecx: 0x666F_736F,
            edx: 0x7648_2074,
        },
        interface: INTERFACE_SIGNATURE,
    };
    assert_eq!(&detection.vendor_bytes(), b"Microsoft Hv");
    assert!(detection.offers_interface());
}

#[test]
fn the_call_code_is_bits_15_to_0() {
    // HvCallPostMessage (0x5c), fast, with a rep count of 2.
    assert_eq!(call_code(0x0000_0002_0001_005C), 0x5C);
}

#[test]
fn the_synthetic_range_covers_hyper_v_and_nothing_in_the_bitmap() {
    use crate::vmx::exit_bitmaps::{MsrAccess, msr_bit};
    // Guest OS ID, the reference counter, TSC invariant control, the
    // nested SynIC control.
    for msr in [0x4000_0000, 0x4000_0020, 0x4000_0118, 0x4000_1080] {
        assert!(SYNTHETIC_MSRS.contains(&msr), "{msr:#x}");
    }
    for msr in [0x3FFF_FFFF, 0x4001_0000] {
        assert!(!SYNTHETIC_MSRS.contains(&msr), "{msr:#x}");
    }
    // Every one of them exits, whatever the bitmap says.
    for msr in [*SYNTHETIC_MSRS.start(), *SYNTHETIC_MSRS.end()] {
        assert_eq!(msr_bit(msr, MsrAccess::Read), None);
    }
}

/// The address of a forwarder's label.
fn address(label: *const u8) -> u64 {
    label as u64
}

#[test]
fn each_forwarding_instruction_recovers_from_its_own_exception() {
    for (instruction, vector, refused) in [
        (
            &raw const hyperv_hypercall_instruction,
            INVALID_OPCODE,
            &raw const hyperv_hypercall_refused,
        ),
        (
            &raw const hyperv_rdmsr_instruction,
            GENERAL_PROTECTION,
            &raw const hyperv_rdmsr_refused,
        ),
        (
            &raw const hyperv_wrmsr_instruction,
            GENERAL_PROTECTION,
            &raw const hyperv_wrmsr_refused,
        ),
    ] {
        assert_eq!(recovery(address(instruction), vector), Some(address(refused)));
        // Any other exception there is still a bug, and so is the right
        // exception one byte off.
        let other = if vector == INVALID_OPCODE {
            GENERAL_PROTECTION
        } else {
            INVALID_OPCODE
        };
        assert_eq!(recovery(address(instruction), other), None);
        assert_eq!(recovery(address(instruction) + 1, vector), None);
        assert_eq!(recovery(address(refused), vector), None);
    }
}

#[test]
fn no_recovery_elsewhere() {
    assert_eq!(recovery(0, GENERAL_PROTECTION), None);
    assert_eq!(recovery(recovery as *const () as u64, INVALID_OPCODE), None);
}

#[test]
fn the_recovery_points_sit_on_the_instructions() {
    // VMCALL is 0F 01 C1, RDMSR 0F 32, WRMSR 0F 30: the RIP the CPU reports
    // for the fault is the label's.
    // SAFETY: each label is in the forwarders' assembled code, which is in
    // the test binary's text for as long as it runs and never written; each
    // instruction is at least as long as the bytes read.
    let (vmcall, rdmsr, wrmsr) = unsafe {
        (
            *(&raw const hyperv_hypercall_instruction).cast::<[u8; 3]>(),
            *(&raw const hyperv_rdmsr_instruction).cast::<[u8; 2]>(),
            *(&raw const hyperv_wrmsr_instruction).cast::<[u8; 2]>(),
        )
    };
    assert_eq!(vmcall, [0x0F, 0x01, 0xC1]);
    assert_eq!(rdmsr, [0x0F, 0x32]);
    assert_eq!(wrmsr, [0x0F, 0x30]);
}

#[test]
fn an_overlay_msr_write_names_the_page_it_overlays() {
    // Enable bit set: the GPA is bits 63:12 of the value, page-aligned.
    assert_eq!(overlay_gpa(0x4000_0001, 0x7f60_b001), Some(0x7f60_b000));
    assert_eq!(overlay_gpa(0x4000_0083, 0x1_2345_6001), Some(0x1_2345_6000));
    // Enable bit clear: the write disables the overlay, so no GPA to guard.
    assert_eq!(overlay_gpa(0x4000_0001, 0x7f60_b000), None);
    // An MSR that overlays nothing (a synthetic timer): never a GPA.
    assert_eq!(overlay_gpa(0x4000_00b0, 0x7f60_b001), None);
}

#[test]
fn a_non_fast_hypercall_names_its_input_and_output_pages() {
    // Call code 0x5c, not fast (bit 16 clear): RDX and R8 are GPAs.
    assert_eq!(
        hypercall_gpas(0x005c, 0x1000_0040, 0x2000_0080),
        [Some(0x1000_0000), Some(0x2000_0000)]
    );
    // Fast (bit 16 set): the data is in registers, not at GPAs.
    assert_eq!(hypercall_gpas(0x1_005c, 0x1000_0040, 0x2000_0080), [None, None]);
}
