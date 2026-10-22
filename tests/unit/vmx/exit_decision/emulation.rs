//! Unit tests for `src/vmx/exit_decision/emulation.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;
use crate::vmx::exit_decision::{
    EXIT_REASON_CPUID, EXIT_REASON_IO_INSTRUCTION, EXIT_REASON_RDMSR, EXIT_REASON_WRMSR, ExitReason, InterruptionInfo,
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
        qualification: 0,
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
    assert_eq!(
        cpuid(&cpuid_exit),
        ExitEvent::Emulated(Emulation::Cpuid { leaf: 7, subleaf: 1 })
    );
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
fn rdmsr_of_an_intercepted_msr_is_emulated() {
    assert_eq!(
        rdmsr(&msr_exit(EXIT_REASON_RDMSR, KERNEL_GS_BASE.into(), 0, 0)),
        ExitEvent::Emulated(Emulation::Rdmsr { msr: KERNEL_GS_BASE })
    );
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
        rdmsr(&exit),
        ExitEvent::Emulated(Emulation::Rdmsr { msr: KERNEL_GS_BASE })
    );
}

#[test]
fn msrs_outside_the_bitmap_get_a_general_protection_fault() {
    // Hyper-V's synthetic MSRs start at 0x40000000; neither range covers them.
    for msr in [0x4000_0000, 0xC000_2000] {
        assert_eq!(
            rdmsr(&msr_exit(EXIT_REASON_RDMSR, msr, 0, 0)),
            ExitEvent::GuestGeneralProtection
        );
        assert_eq!(
            wrmsr(&msr_exit(EXIT_REASON_WRMSR, msr, 0, 0)),
            ExitEvent::GuestGeneralProtection
        );
    }
}

#[test]
fn an_msr_in_range_but_not_intercepted_means_a_broken_bitmap() {
    // IA32_TIME_STAMP_COUNTER and IA32_EFER: in range, bits clear.
    for msr in [0x10, 0xC000_0080] {
        assert_eq!(rdmsr(&msr_exit(EXIT_REASON_RDMSR, msr, 0, 0)), ExitEvent::Unexpected);
        assert_eq!(wrmsr(&msr_exit(EXIT_REASON_WRMSR, msr, 0, 0)), ExitEvent::Unexpected);
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
    assert_eq!(
        wrmsr(&exit),
        ExitEvent::Emulated(Emulation::Wrmsr {
            msr: KERNEL_GS_BASE,
            value: 0x0000_7A1E_0000_1234
        })
    );
}

#[test]
fn a_non_canonical_wrmsr_value_gets_a_general_protection_fault() {
    let exit = msr_exit(EXIT_REASON_WRMSR, KERNEL_GS_BASE.into(), 0, 0x0000_8000);
    assert_eq!(wrmsr(&exit), ExitEvent::GuestGeneralProtection);
}

#[test]
fn a_canonical_upper_half_wrmsr_value_is_emulated() {
    let exit = msr_exit(EXIT_REASON_WRMSR, KERNEL_GS_BASE.into(), 0, 0xFFFF_8000);
    assert_eq!(
        wrmsr(&exit),
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

/// Exit qualification of an I/O instruction: size − 1 in bits 2:0, IN in
/// bit 3, string in bit 4, REP in bit 5, port in bits 31:16.
fn io_qualification(port: u16, size_minus_1: u64, is_in: bool) -> u64 {
    (u64::from(port) << 16) | (u64::from(is_in) << 3) | size_minus_1
}

fn io_exit(qualification: u64, rax: u64) -> ExitInfo {
    ExitInfo {
        qualification,
        guest_rax: rax,
        ..exit(EXIT_REASON_IO_INSTRUCTION)
    }
}

#[test]
fn io_qualification_decodes_size_direction_and_port() {
    let byte_in = IoQualification(io_qualification(0x3FF, 0, true));
    assert_eq!(byte_in.size(), Some(IoSize::Byte));
    assert!(byte_in.is_in());
    assert!(!byte_in.is_string());
    assert!(!byte_in.is_rep());
    assert_eq!(byte_in.port(), 0x3FF);
    let dword_out = IoQualification(io_qualification(0xCF8, 3, false));
    assert_eq!(dword_out.size(), Some(IoSize::Dword));
    assert!(!dword_out.is_in());
    assert_eq!(dword_out.port(), 0xCF8);
    assert_eq!(
        IoQualification(io_qualification(0x60, 1, true)).size(),
        Some(IoSize::Word)
    );
}

#[test]
fn unused_size_encodings_have_no_size() {
    for size_minus_1 in [2, 4, 5, 6, 7] {
        assert_eq!(IoQualification(size_minus_1).size(), None, "{size_minus_1}");
    }
}

#[test]
fn string_and_rep_bits_decode() {
    assert!(IoQualification(1 << 4).is_string());
    assert!(IoQualification(1 << 5).is_rep());
}

#[test]
fn byte_and_word_in_keep_the_rest_of_rax() {
    let rax = 0x1122_3344_5566_7788;
    assert_eq!(merge_in(rax, IoSize::Byte, 0xA5), 0x1122_3344_5566_77A5);
    assert_eq!(merge_in(rax, IoSize::Word, 0xBEEF), 0x1122_3344_5566_BEEF);
}

#[test]
fn dword_in_zero_extends_into_rax() {
    assert_eq!(merge_in(0x1122_3344_5566_7788, IoSize::Dword, 0xDEAD_BEEF), 0xDEAD_BEEF);
}

#[test]
fn out_value_takes_al_ax_or_eax() {
    let rax = 0x1122_3344_5566_7788;
    assert_eq!(out_value(rax, IoSize::Byte), 0x88);
    assert_eq!(out_value(rax, IoSize::Word), 0x7788);
    assert_eq!(out_value(rax, IoSize::Dword), 0x5566_7788);
}

#[test]
fn in_is_emulated() {
    assert_eq!(
        io(&io_exit(io_qualification(0x3FF, 0, true), 0)),
        ExitEvent::Emulated(Emulation::In {
            port: 0x3FF,
            size: IoSize::Byte
        })
    );
}

#[test]
fn out_is_emulated_with_the_value_from_rax() {
    assert_eq!(
        io(&io_exit(io_qualification(0x3FF, 0, false), 0xFFFF_FF00 | 0xA5)),
        ExitEvent::Emulated(Emulation::Out {
            port: 0x3FF,
            size: IoSize::Byte,
            value: 0xA5
        })
    );
}

#[test]
fn string_or_rep_io_stops_the_guest() {
    let string = io_qualification(0x3FF, 0, true) | (1 << 4);
    let rep = string | (1 << 5);
    for qualification in [string, rep] {
        assert_eq!(io(&io_exit(qualification, 0)), ExitEvent::Unexpected);
    }
}

#[test]
fn io_with_an_unused_size_stops_the_guest() {
    assert_eq!(io(&io_exit(io_qualification(0x3FF, 2, true), 0)), ExitEvent::Unexpected);
}

/// Every MSR index the bitmap covers: the two ranges whose bits the CPU consults.
fn bitmap_msr_indexes() -> impl Iterator<Item = u32> {
    (0u32..=0x1FFF).chain(0xC000_0000..=0xC000_1FFF)
}

#[test]
fn rdmsr_is_emulated_only_for_the_intercepted_msrs() {
    for msr in bitmap_msr_indexes() {
        let event = rdmsr(&msr_exit(EXIT_REASON_RDMSR, msr.into(), 0, 0));
        if INTERCEPTED_MSRS.contains(&msr) {
            assert_eq!(event, ExitEvent::Emulated(Emulation::Rdmsr { msr }), "MSR {msr:#x}");
        } else {
            // In range with its bit clear: it should never have exited, so the bitmap is broken.
            assert_eq!(event, ExitEvent::Unexpected, "MSR {msr:#x}");
        }
    }
}

#[test]
fn wrmsr_is_emulated_only_for_the_intercepted_msrs() {
    for msr in bitmap_msr_indexes() {
        // RAX and RDX are zero, so the value is 0, which is canonical.
        let event = wrmsr(&msr_exit(EXIT_REASON_WRMSR, msr.into(), 0, 0));
        if INTERCEPTED_MSRS.contains(&msr) {
            assert_eq!(
                event,
                ExitEvent::Emulated(Emulation::Wrmsr { msr, value: 0 }),
                "MSR {msr:#x}"
            );
        } else {
            assert_eq!(event, ExitEvent::Unexpected, "MSR {msr:#x}");
        }
    }
}
