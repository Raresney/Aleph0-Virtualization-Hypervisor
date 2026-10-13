//! Unit tests for `src/vmx/msr.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;

/// Build a capability MSR from its required (low) and allowed (high) halves.
fn capability(required: u32, allowed: u32) -> ControlCapability {
    ControlCapability((u64::from(allowed) << 32) | u64::from(required))
}

#[test]
fn halves_split_required_and_allowed() {
    let capability = capability(0x16, 0x8000_00FF);
    assert_eq!(capability.required(), 0x16);
    assert_eq!(capability.allowed(), 0x8000_00FF);
}

#[test]
fn allows_needs_every_bit() {
    let capability = capability(0, 0b0110);
    assert!(capability.allows(0b0010));
    assert!(capability.allows(0b0110));
    assert!(!capability.allows(0b0001));
    assert!(!capability.allows(0b0011), "one allowed bit is not enough");
}

#[test]
fn required_bits_are_added() {
    assert_eq!(capability(0x16, 0xFF).choose(0), Ok(0x16));
}

#[test]
fn allowed_desired_bits_are_kept() {
    assert_eq!(capability(0x16, 0xFFFF).choose(0x200), Ok(0x216));
}

#[test]
fn desired_bit_not_allowed_is_rejected() {
    assert_eq!(capability(0x16, 0xFF).choose(0x200), Err(UnsupportedControl));
}

#[test]
fn required_bit_not_allowed_is_rejected() {
    // (low, high) = (1, 0) is inconsistent: required but not allowed.
    assert_eq!(capability(0x1, 0x0).choose(0), Err(UnsupportedControl));
}
