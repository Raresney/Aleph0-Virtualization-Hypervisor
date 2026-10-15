//! Unit tests for `src/vmx/exit_decision/emulation.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;
use crate::vmx::exit_decision::{
    EXIT_REASON_CPUID, EXIT_REASON_RDMSR, EXIT_REASON_WRMSR, EptQualification, ExitReason, InterruptionInfo,
};

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
    let counts = EmulationCounts {
        cpuid: 1,
        rdmsr: 2,
        wrmsr: 3,
    };
    assert_eq!(counts.to_string(), "cpuid=1 rdmsr=2 wrmsr=3");
}

const KERNEL_GS_BASE: u32 = 0xC000_0102;

fn msr_exit(basic: u16, msr: u64, rax: u64, rdx: u64) -> ExitInfo {
    ExitInfo {
        guest_rcx: msr,
        guest_rax: rax,
        guest_rdx: rdx,
        ..exit(basic)
    }
}

#[test]
fn rdmsr_of_an_intercepted_msr_is_emulated_and_counted() {
    let (event, state) = rdmsr(
        ExitState::default(),
        &msr_exit(EXIT_REASON_RDMSR, KERNEL_GS_BASE.into(), 0, 0),
    );
    assert_eq!(event, ExitEvent::Emulated(Emulation::Rdmsr { msr: KERNEL_GS_BASE }));
    assert_eq!(state.emulated.rdmsr, 1);
}

#[test]
fn rdmsr_ignores_the_upper_half_of_rcx() {
    let exit = msr_exit(
        EXIT_REASON_RDMSR,
        0xFFFF_FFFF_0000_0000 | u64::from(KERNEL_GS_BASE),
        0,
        0,
    );
    assert_eq!(
        rdmsr(ExitState::default(), &exit).0,
        ExitEvent::Emulated(Emulation::Rdmsr { msr: KERNEL_GS_BASE })
    );
}

#[test]
fn msrs_outside_the_bitmap_get_a_general_protection_fault() {
    // Hyper-V's synthetic MSRs start at 0x40000000; neither range covers them.
    for msr in [0x4000_0000, 0xC000_2000] {
        let state = ExitState::default();
        assert_eq!(
            rdmsr(state, &msr_exit(EXIT_REASON_RDMSR, msr, 0, 0)),
            (ExitEvent::GuestGeneralProtection, state)
        );
        assert_eq!(
            wrmsr(state, &msr_exit(EXIT_REASON_WRMSR, msr, 0, 0)),
            (ExitEvent::GuestGeneralProtection, state)
        );
    }
}

#[test]
fn an_msr_in_range_but_not_intercepted_means_a_broken_bitmap() {
    // IA32_TIME_STAMP_COUNTER and IA32_EFER: in range, bits clear.
    for msr in [0x10, 0xC000_0080] {
        assert_eq!(
            rdmsr(ExitState::default(), &msr_exit(EXIT_REASON_RDMSR, msr, 0, 0)).0,
            ExitEvent::Unexpected
        );
        assert_eq!(
            wrmsr(ExitState::default(), &msr_exit(EXIT_REASON_WRMSR, msr, 0, 0)).0,
            ExitEvent::Unexpected
        );
    }
}

#[test]
fn wrmsr_value_is_edx_eax_without_their_upper_halves() {
    let exit = msr_exit(
        EXIT_REASON_WRMSR,
        KERNEL_GS_BASE.into(),
        0xDEAD_BEEF_0000_1234,
        0xFFFF_FFFF_0000_7A1E,
    );
    let (event, state) = wrmsr(ExitState::default(), &exit);
    assert_eq!(
        event,
        ExitEvent::Emulated(Emulation::Wrmsr {
            msr: KERNEL_GS_BASE,
            value: 0x0000_7A1E_0000_1234
        })
    );
    assert_eq!(state.emulated.wrmsr, 1);
}

#[test]
fn a_non_canonical_wrmsr_value_gets_a_general_protection_fault() {
    let exit = msr_exit(EXIT_REASON_WRMSR, KERNEL_GS_BASE.into(), 0, 0x0000_8000);
    let state = ExitState::default();
    assert_eq!(wrmsr(state, &exit), (ExitEvent::GuestGeneralProtection, state));
}

#[test]
fn a_canonical_upper_half_wrmsr_value_is_emulated() {
    let exit = msr_exit(EXIT_REASON_WRMSR, KERNEL_GS_BASE.into(), 0, 0xFFFF_8000);
    assert_eq!(
        wrmsr(ExitState::default(), &exit).0,
        ExitEvent::Emulated(Emulation::Wrmsr {
            msr: KERNEL_GS_BASE,
            value: 0xFFFF_8000_0000_0000
        })
    );
}

#[test]
fn canonical_means_bits_63_to_47_all_equal() {
    assert!(is_canonical_48(0));
    assert!(is_canonical_48(0x0000_7FFF_FFFF_FFFF));
    assert!(is_canonical_48(0xFFFF_8000_0000_0000));
    assert!(is_canonical_48(u64::MAX));
    assert!(!is_canonical_48(0x0000_8000_0000_0000));
    assert!(!is_canonical_48(0xFFFF_7FFF_FFFF_FFFF));
    assert!(!is_canonical_48(0x8000_0000_0000_0000));
}
