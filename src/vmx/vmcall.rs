//! Aleph0's own VMCALLs: a VMCALL whose RCX holds one of these values is a
//! call to Aleph0, which `exit_decision::decide` handles for the firmware
//! and the OS after it. Every other VMCALL is a Hyper-V hypercall, whose
//! input value is in RCX too (`vmx::hyperv`), and Aleph0 forwards it.
//!
//! Each value is eight ASCII bytes read big-endian, so a register dump
//! shows it as text: `0x416c657068304542` is "Aleph0EB". Its top byte, 'A'
//! (0x41), sets bit 62, which is reserved in a hypercall input value (bits
//! 63:60, TLFS "Hypercall Inputs"), so no valid hypercall is ever taken for
//! one of these.
//!
//! This file depends on nothing, because the `ExitBootServices` test
//! harness (`tools/ebs-harness`) includes it too.

/// Boot services have ended: Aleph0's `ExitBootServices` event makes this
/// VMCALL in the guest (`resident::watch_exit_boot_services`), and Aleph0
/// switches its output to the runtime phase. "Aleph0EB".
pub const BOOT_SERVICES_ENDED: u64 = u64::from_be_bytes(*b"Aleph0EB");

/// Does nothing but exit: Aleph0 resumes past it. The `ExitBootServices`
/// harness makes it to see a VMCALL handled. "Aleph0TS".
pub const TEST: u64 = u64::from_be_bytes(*b"Aleph0TS");

/// Bits 63:60 of a hypercall input value, reserved: Hyper-V refuses a
/// hypercall with any of them set.
const HYPERCALL_RESERVED_TOP: u64 = 0xF << 60;

const _: () = assert!(BOOT_SERVICES_ENDED & HYPERCALL_RESERVED_TOP != 0 && TEST & HYPERCALL_RESERVED_TOP != 0);
