// Host unit tests (`cargo test --target <host triple>`) build with std and
// the test harness; the UEFI build is no_std with a firmware entry point.
#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), no_std)]
// Every `unsafe` block says why it is sound here (`// SAFETY:`), and every
// `unsafe fn` lists its callers' obligations (`# Safety`).
#![warn(clippy::undocumented_unsafe_blocks)]

use core::time::Duration;

use uefi::boot::{self, EventType, TimerTrigger, Tpl};
use uefi::prelude::*;

/// Prints a tagged line to the serial port (COM2), and to the firmware
/// console while still in boot services.
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
mod port;
mod resident;
mod serial;
mod vmx;

/// Prefix for every line this hypervisor prints, on screen and on serial.
pub const TAG: &str = "[Aleph0 Virtualization Hypervisor]";

/// Where Aleph0 prints: COM2, leaving COM1 to the guest.
const OUTPUT_PORT: serial::SerialPort = serial::SerialPort::COM2;

#[cfg_attr(not(test), entry)]
fn main() -> Status {
    // First, so every later line also reaches serial. Needs no firmware.
    let serial = serial::init(OUTPUT_PORT);

    log!("Initializing UEFI helpers...");

    uefi::helpers::init().unwrap();

    log!("UEFI helpers initialized successfully.");
    match serial {
        Ok(()) => log!("Serial output enabled on {OUTPUT_PORT}."),
        Err(error) => log!("Serial output disabled on {OUTPUT_PORT}: {error:?}; console only."),
    }

    // The firmware unloads this image when `main` returns, and the OS may
    // reuse its pages after ExitBootServices; the copy stays.
    // SAFETY: boot services are active, and the only statics written so far
    // are the serial port, its readiness, the output phase and the `uefi`
    // crate's image handle and system table: none an address in the image.
    match unsafe { resident::ResidentImage::copy() } {
        Ok(image) => {
            log!(
                "Image copied to resident memory: {:#018x} -> {:#018x}, {} bytes, {} fixups applied; running on from the copy.",
                image.loaded(),
                image.base(),
                image.size(),
                image.fixups(),
            );
            // SAFETY: `image` is this image's copy, and nothing below uses
            // this image's statics again.
            unsafe { image.call(run) }
        }
        Err(error) => {
            log!("Image not copied to resident memory: {error:?}; Aleph0 cannot outlive boot services.");
            Status::ABORTED
        }
    }
}

/// Everything after the copy, in the resident image: bring-up, and the
/// return to the firmware.
fn run() -> Status {
    // Bring-up returns once the test guest has stopped, once the firmware
    // runs as the guest, or at the first failure. In the first and last case
    // it has left VMX operation if it entered it, unless VMXOFF failed: then
    // the CPU is still in VMX root operation with CR4.VMXE set, teardown
    // printed that, and firmware takes over in that state. Once the firmware
    // runs as the guest, everything below runs in VMX non-root operation.
    let status = match bring_up::run() {
        Ok(bring_up::GuestRun::Finished { exits }) => {
            log!("Guest finished after {exits} VM exits; VMX operation left.");
            Status::SUCCESS
        }
        Ok(bring_up::GuestRun::Virtualized) => {
            log!("The firmware runs as the guest: Aleph0 returns to it in VMX non-root operation.");
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
/// reach the firmware's handlers: through the restored IDT, or, once the
/// firmware runs as the guest, through its own IDT in VMX non-root
/// operation, with no VM exit. If they do not, the wait never ends, and the
/// "Waiting" line is the last one on serial.
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
