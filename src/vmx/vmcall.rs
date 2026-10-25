//! Aleph0's own VMCALLs: a VMCALL whose RAX holds one of these values is a
//! call to Aleph0, which `exit_decision::decide` handles for the firmware
//! and the OS after it. Hyper-V's hypercalls (#27) take their input in RCX
//! and ignore RAX, so a guest makes one of these only on purpose.
//!
//! Each value is eight ASCII bytes read big-endian, so a register dump
//! shows it as text: `0x416c657068304542` is "Aleph0EB".
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
