//! Unit tests for `src/vmx/exit_bitmaps.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;
use crate::vmx::mtrr::MtrrCapabilities;

#[test]
fn low_msrs_are_read_from_offset_0() {
    assert_eq!(msr_bit(0, MsrAccess::Read), Some((0, 0)));
    assert_eq!(msr_bit(0x1FFF, MsrAccess::Read), Some((0x3FF, 7)));
}

#[test]
fn high_msrs_are_read_from_offset_0x400() {
    assert_eq!(msr_bit(0xC000_0000, MsrAccess::Read), Some((0x400, 0)));
    assert_eq!(msr_bit(0xC000_1FFF, MsrAccess::Read), Some((0x7FF, 7)));
}

#[test]
fn writes_use_the_upper_half_of_the_page() {
    assert_eq!(msr_bit(0, MsrAccess::Write), Some((0x800, 0)));
    assert_eq!(msr_bit(0xC000_1FFF, MsrAccess::Write), Some((0xFFF, 7)));
}

#[test]
fn msrs_outside_both_ranges_have_no_bit() {
    for msr in [0x2000, 0xBFFF_FFFF, 0xC000_2000, 0x4000_0000, u32::MAX] {
        assert_eq!(msr_bit(msr, MsrAccess::Read), None, "{msr:#x}");
        assert_eq!(msr_bit(msr, MsrAccess::Write), None, "{msr:#x}");
    }
}

#[test]
fn kernel_gs_base_is_bit_2_of_byte_0x20_in_each_high_half() {
    // 0xC0000102 - 0xC0000000 = 0x102 = 258 = 32 * 8 + 2.
    assert_eq!(msr_bit(0xC000_0102, MsrAccess::Read), Some((0x420, 2)));
    assert_eq!(msr_bit(0xC000_0102, MsrAccess::Write), Some((0xC20, 2)));
}

#[test]
fn ports_split_between_bitmaps_a_and_b() {
    assert_eq!(io_bit(0), (IoBitmap::A, 0, 0));
    assert_eq!(io_bit(0x7FFF), (IoBitmap::A, 0xFFF, 7));
    assert_eq!(io_bit(0x8000), (IoBitmap::B, 0, 0));
    assert_eq!(io_bit(0xFFFF), (IoBitmap::B, 0xFFF, 7));
}

#[test]
fn com1_scratch_is_bit_7_of_byte_0x7f() {
    // 0x3FF = 1023 = 127 * 8 + 7, as in docs/PORT_IO.md section 7.
    assert_eq!(io_bit(0x3FF), (IoBitmap::A, 0x7F, 7));
}

#[test]
fn fill_sets_exactly_the_intercepted_bits() {
    let (mut msr, mut io_a, mut io_b) = ([0u8; PAGE_SIZE], [0u8; PAGE_SIZE], [0u8; PAGE_SIZE]);
    fill(&mut msr, &mut io_a, &mut io_b);
    let ones = |page: &[u8]| page.iter().map(|byte| byte.count_ones()).sum::<u32>();
    assert_eq!(msr[0x420], 1 << 2);
    assert_eq!(msr[0xC20], 1 << 2);
    // IA32_KERNEL_GS_BASE and the 76 MTRR addresses, each read and write.
    assert_eq!(ones(&msr), 2 + 2 * 76);
    assert_eq!(io_a[0x7F], 1 << 7);
    assert_eq!(ones(&io_a), 1);
    assert_eq!(ones(&io_b), 0);
}

#[test]
fn fill_intercepts_both_ways_every_mtrr_address_whatever_the_cpu_has() {
    let (mut msr, mut io_a, mut io_b) = ([0u8; PAGE_SIZE], [0u8; PAGE_SIZE], [0u8; PAGE_SIZE]);
    fill(&mut msr, &mut io_a, &mut io_b);
    let intercepted = |address: u32, access| {
        let (offset, bit) = msr_bit(address, access).unwrap();
        msr[offset] & (1 << bit) != 0
    };
    // Hyper-V's 28 MTRR MSRs, and the variable ranges past its eight.
    let hyper_v = MtrrCapabilities::new((1 << 8) | 8, 46).unwrap();
    for address in hyper_v.msrs().map(|mtrr| mtrr.address()).chain(0x210..0x240) {
        for access in [MsrAccess::Read, MsrAccess::Write] {
            assert!(intercepted(address, access), "{address:#x} {access:?}");
        }
    }
    // IA32_MTRRCAP stays the guest's, IA32_PAT is held in the VMCS, and
    // 0x240 is past the variable ranges Aleph0 keeps.
    for address in [0xFE, 0x277, 0x240] {
        assert!(!intercepted(address, MsrAccess::Read), "{address:#x}");
        assert!(!intercepted(address, MsrAccess::Write), "{address:#x}");
    }
}

#[test]
fn no_mtrr_address_is_passed_through_or_held_in_the_vmcs() {
    for address in mtrr::every_msr_address() {
        assert!(msr_bit(address, MsrAccess::Read).is_some(), "{address:#x}");
        assert!(!INTERCEPTED_MSRS.contains(&address), "{address:#x}");
        // IA32_PAT (0x277) is the one in their neighbourhood.
        assert!(!VMCS_HELD_MSRS.contains(&address), "{address:#x}");
    }
}
