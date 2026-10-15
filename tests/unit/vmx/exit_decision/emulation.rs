//! Unit tests for `src/vmx/exit_decision/emulation.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;
use crate::vmx::exit_decision::{EXIT_REASON_CPUID, EptQualification, ExitReason, InterruptionInfo};

/// CPUID leaf 1 as a Hyper-V guest with nested virtualization sees it: VMX
/// (ECX bit 5) set.
const LEAF_1: CpuidResult = CpuidResult {
    eax: 0x0009_06EA,
    ebx: 0x0010_0800,
    ecx: 0xFEDA_32A3,
    edx: 0x1F8B_FBFF,
};

/// An exit with reason `basic` and every other field zero.
fn exit(basic: u16) -> ExitInfo {
    ExitInfo {
        reason: ExitReason {
            basic,
            entry_failure: false,
        },
        interruption_info: InterruptionInfo(0),
        guest_rax: 0,
        guest_rcx: 0,
        guest_rdx: 0,
        interruptibility: 0,
        idt_vectoring_valid: false,
        exit_qualification: EptQualification(0),
        guest_physical: 0,
        protected_page: 0,
    }
}

#[test]
fn leaf_1_hides_vmx_and_nothing_else() {
    assert_ne!(LEAF_1.ecx & (1 << 5), 0);
    let guest = cpuid_policy(1, LEAF_1);
    assert_eq!(guest.ecx, LEAF_1.ecx & !(1 << 5));
    assert_eq!((guest.eax, guest.ebx, guest.edx), (LEAF_1.eax, LEAF_1.ebx, LEAF_1.edx));
}

#[test]
fn leaf_1_without_vmx_is_unchanged() {
    let no_vmx = CpuidResult {
        ecx: LEAF_1.ecx & !(1 << 5),
        ..LEAF_1
    };
    assert_eq!(cpuid_policy(1, no_vmx), no_vmx);
}

#[test]
fn other_leaves_pass_through() {
    for leaf in [0, 7, 0xD, 0x4000_0000, 0x8000_0001] {
        assert_eq!(cpuid_policy(leaf, LEAF_1), LEAF_1, "leaf {leaf:#x}");
    }
}

#[test]
fn cpuid_takes_leaf_and_subleaf_from_the_low_halves_of_rax_and_rcx() {
    let cpuid_exit = ExitInfo {
        guest_rax: 0xFFFF_FFFF_0000_0007,
        guest_rcx: 0x0000_0001_0000_0001,
        ..exit(EXIT_REASON_CPUID)
    };
    let (event, state) = cpuid(ExitState::default(), &cpuid_exit);
    assert_eq!(event, ExitEvent::Emulated(Emulation::Cpuid { leaf: 7, subleaf: 1 }));
    assert_eq!(state.emulated.cpuid, 1);
}

#[test]
fn counts_display_names_each_instruction() {
    let counts = EmulationCounts { cpuid: 1 };
    assert_eq!(counts.to_string(), "cpuid=1");
}
