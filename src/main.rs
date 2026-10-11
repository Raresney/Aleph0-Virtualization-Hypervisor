// Host unit tests (`cargo test --target <host triple>`) build with std and
// the test harness; the UEFI build is no_std with a firmware entry point.
#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), no_std)]

use core::time::Duration;

use uefi::boot::{self, EventType, TimerTrigger, Tpl};
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
    // Either way it has left VMX operation if it entered it, so firmware
    // can take over again.
    let status = match bring_up::run() {
        Ok(run) => {
            log!("Guest finished after {} VM exits; VMX operation left.", run.exits);
            Status::SUCCESS
        }
        Err(error) => {
            bring_up::report_error(error);
            Status::ABORTED
        }
    };

    check_firmware_timer();
    log!("Returning to firmware with {status:?}.");
    status
}

/// How long [`check_firmware_timer`] waits.
const TIMER_CHECK: Duration = Duration::from_secs(1);

/// Waits on a one-shot UEFI timer event. Only the firmware's timer
/// interrupt signals it, so getting past the wait shows that interrupts
/// reach the firmware's handlers through the restored IDT. If they do not,
/// the wait never ends, and the "Waiting" line is the last one on serial.
///
/// WaitForEvent may turn interrupts on by itself (through RestoreTPL), so
/// this does not show that teardown restored IF; teardown prints IF itself.
fn check_firmware_timer() {
    log!("Waiting {} s on a firmware timer event...", TIMER_CHECK.as_secs());

    // SAFETY: no notification function, so no callback can run with a bad
    // context pointer.
    let event = match unsafe { boot::create_event(EventType::TIMER, Tpl::APPLICATION, None, None) } {
        Ok(event) => event,
        Err(error) => {
            log!("Firmware timer event not created: {:?}.", error.status());
            return;
        }
    };

    let mut events = [event];
    if let Err(error) = boot::set_timer(&events[0], TimerTrigger::Relative(TIMER_CHECK)) {
        log!("Firmware timer not armed: {:?}.", error.status());
    } else if let Err(error) = boot::wait_for_event(&mut events) {
        log!("Waiting on the firmware timer failed: {:?}.", error.status());
    } else {
        log!("Firmware timer fired: interrupts reach the firmware again.");
    }

    let [event] = events;
    if let Err(error) = boot::close_event(event) {
        log!("Firmware timer event not closed: {:?}.", error.status());
    }
}
