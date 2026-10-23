//! Unit tests for `src/vmx/vmcs/mod.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;
use crate::vmx::msr::ControlCapability;

#[test]
fn an_unsupported_control_is_a_vmcs_error() {
    assert_eq!(VmcsError::from(UnsupportedControl), VmcsError::UnsupportedControlValue);
}

const CF: u64 = 1 << 0;
const ZF: u64 = 1 << 6;
/// RFLAGS bit 1 always reads as 1.
const RESERVED: u64 = 1 << 1;

#[test]
fn launch_with_cf_is_fail_invalid() {
    assert_eq!(launch_failure(RESERVED | CF), VmcsError::VmFailInvalid);
}

#[test]
fn launch_with_zf_is_fail_valid() {
    assert_eq!(launch_failure(RESERVED | ZF), VmcsError::VmFailValid);
}

#[test]
fn launch_falling_through_with_clear_flags_is_still_a_failure() {
    // A successful VMLAUNCH never reaches the next instruction, so
    // clear flags here must not be read as success.
    assert_eq!(launch_failure(RESERVED), VmcsError::LaunchReturned);
}

#[test]
fn resume_with_cf_is_fail_invalid() {
    assert_eq!(resume_failure(RESERVED | CF), VmcsError::VmFailInvalid);
}

#[test]
fn resume_with_zf_is_fail_valid() {
    assert_eq!(resume_failure(RESERVED | ZF), VmcsError::VmFailValid);
}

#[test]
fn resume_falling_through_with_clear_flags_is_still_a_failure() {
    // A successful VMRESUME never reaches the next instruction either.
    assert_eq!(resume_failure(RESERVED), VmcsError::ResumeReturned);
}

#[test]
fn only_vm_fail_valid_has_an_instruction_error_to_read() {
    // Every other error returns before the VMREAD, which would fault outside
    // VMX operation (as it would here, on the host).
    for error in [
        VmcsError::VmFailInvalid,
        VmcsError::LaunchReturned,
        VmcsError::ResumeReturned,
        VmcsError::AllocationFailed,
    ] {
        // SAFETY: none of these is VmFailValid, so no VMREAD runs.
        assert_eq!(unsafe { instruction_error_for(error) }, None);
    }
}

#[test]
fn secondary_controls_activate_primary_bit_31() {
    let desired = DesiredControls::minimal_64_bit_guest(GuestKind::BuiltInTest);
    assert_eq!(desired.secondary, SECONDARY_ENABLE_EPT);
    assert_eq!(primary_request(desired), desired.primary | (1 << 31));
}

#[test]
fn no_secondary_controls_leave_the_primary_request_alone() {
    let desired = DesiredControls {
        primary: 0x10,
        secondary: 0,
        ..DesiredControls::minimal_64_bit_guest(GuestKind::BuiltInTest)
    };
    assert_eq!(primary_request(desired), 0x10);
}

#[test]
fn nmi_window_on_sets_only_bit_22() {
    assert_eq!(with_nmi_window_exiting(0x8401_E172, true), 0x8441_E172);
}

#[test]
fn nmi_window_off_clears_only_bit_22() {
    assert_eq!(with_nmi_window_exiting(0x8441_E172, false), 0x8401_E172);
}

#[test]
fn the_guest_requests_hlt_exiting_and_the_msr_and_io_bitmaps() {
    let desired = DesiredControls::minimal_64_bit_guest(GuestKind::BuiltInTest);
    assert_eq!(desired.primary, (1 << 7) | (1 << 25) | (1 << 28));
}

#[test]
fn every_exception_of_the_built_in_test_guest_exits() {
    assert_eq!(exception_bitmap(GuestKind::BuiltInTest), u32::MAX);
    assert_eq!(
        DesiredControls::minimal_64_bit_guest(GuestKind::BuiltInTest).exception_bitmap,
        u32::MAX
    );
}

#[test]
fn a_guest_with_its_own_idt_takes_its_own_exceptions() {
    assert_eq!(exception_bitmap(GuestKind::OwnIdt), 0);
    assert_eq!(
        DesiredControls::minimal_64_bit_guest(GuestKind::OwnIdt).exception_bitmap,
        0
    );
}

/// Capability MSRs that allow exactly the VM-exit controls `exit` and the
/// VM-entry controls `entry`, and require none.
fn allowing(exit: u32, entry: u32) -> VmcsControlMsrs {
    VmcsControlMsrs {
        basic: 0,
        pinbased: ControlCapability(0),
        primary: ControlCapability(0),
        exit: ControlCapability(u64::from(exit) << 32),
        entry: ControlCapability(u64::from(entry) << 32),
        secondary: ControlCapability(0),
        ept_vpid_cap: 0,
    }
}

#[test]
fn the_pat_is_switched_when_the_cpu_allows_all_three_controls() {
    // Exit bits 18 (save IA32_PAT) and 19 (load IA32_PAT), entry bit 14
    // (load IA32_PAT).
    let save_and_load = (1 << 18) | (1 << 19);
    assert_eq!(pat_switch(&allowing(save_and_load, 1 << 14)), (save_and_load, 1 << 14));
    // With any one missing, none: the guest's writes would be lost at VM
    // entry, or one PAT would still serve both.
    for (exit, entry) in [(1 << 19, 1 << 14), (1 << 18, 1 << 14), (save_and_load, 0)] {
        assert_eq!(
            pat_switch(&allowing(exit, entry)),
            (0, 0),
            "exit={exit:#x} entry={entry:#x}"
        );
    }
}
