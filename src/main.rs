// Host unit tests (`cargo test --target <host triple>`) build with std and
// the test harness; the UEFI build is no_std with a firmware entry point.
#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), no_std)]

use uefi::prelude::*;

/// Prints a tagged line to COM1, and to the firmware console while still in
/// boot services.
///
/// Safe in every context: outside the boot-services phase (see
/// `output::Phase`) the console half is skipped and only serial is written.
///
/// Defined above the `mod` lines on purpose: a `macro_rules!` macro is only
/// visible to code that comes after it, and `bring_up` uses it.
macro_rules! log {
    ($($arg:tt)*) => {
        crate::output::log_line(format_args!($($arg)*))
    };
}

mod bring_up;
mod output;
mod serial;
mod vmx;

/// Prefix for every line this hypervisor prints, on screen and on COM1.
pub const TAG: &str = "[Aleph0 Virtualization Hypervisor]";

#[cfg_attr(not(test), entry)]
fn main() -> Status {
    // First, so every later line also reaches COM1. Needs no firmware.
    let serial = serial::init();

    log!("Initializing UEFI helpers...");

    uefi::helpers::init().unwrap();

    log!("UEFI helpers initialized successfully.");
    match serial {
        Ok(()) => log!("Serial output enabled on COM1 ({:#x}).", serial::COM1),
        Err(error) => log!("Serial output disabled: {error:?}; console only."),
    }

    // Bring-up returns once the guest has stopped, or at the first failure.
    // If the guest ran, the exit handler switched the output phase, so the
    // line below goes to serial only. The CPU is still in VMX operation.
    match bring_up::run() {
        Ok(run) => log!("Guest finished after {} VM exits.", run.exits),
        Err(error) => bring_up::report_error(error),
    }

    loop { }
}
