//! Where output may go, and what happens when the hypervisor panics.
//!
//! # Why Aleph0 has its own panic handler
//!
//! The `uefi` crate's handler (its `panic_handler` feature) prints with
//! `uefi::println!`, then calls `boot::stall` and `runtime::reset`: three
//! firmware calls. A panic inside the VM-exit handler would then enter
//! firmware from exit context, where interrupts are off and the firmware's
//! state is whatever the guest left behind. After `ExitBootServices` the
//! message would be lost entirely.
//!
//! This handler prints over serial first (no firmware needed), then on the
//! console, then halts the CPU. It never stalls, resets, or otherwise calls
//! into firmware.
//!
//! Host unit tests link `std`, which brings its own panic handler; two would
//! not link, so the handler and its state are compiled out under `cfg(test)`.

#[cfg(not(test))]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicU8, Ordering};

/// Set by the first panic. A second panic, raised while the first is still
/// printing (for example from a `Display` impl or the console driver), sees
/// `true` and halts at once instead of recursing forever.
#[cfg(not(test))]
static PANICKING: AtomicBool = AtomicBool::new(false);

/// Reports a panic and stops this CPU for good.
///
/// Runs in any context: ordinary UEFI code, the VM-exit handler, and later
/// after `ExitBootServices`. It must therefore not depend on firmware for
/// anything it needs to get the message out.
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // `swap` reads the old value and stores `true` in one indivisible step,
    // so exactly one panic gets `false` back and goes on to print. That
    // guarantee comes from atomicity alone; the flag guards no other data,
    // so `Relaxed` would be enough and `SeqCst` is just the strictest choice.
    if PANICKING.swap(true, Ordering::SeqCst) {
        halt_forever();
    }

    // Serial first: it needs no firmware, so the message is already on serial
    // if the console call below hangs or faults. `PanicInfo`'s `Display`
    // prints "panicked at FILE:LINE:COL:" followed by the message.
    crate::serial_println!("{} PANIC: {info}", crate::TAG);
    // What led here, if the guest ran: its last VM exits. After the message,
    // so the message is out even if this goes wrong.
    crate::vmx::vmexit::report_exit_history(format_args!("PANIC"));

    // Firmware console: only in the boot-services phase. In the VM-exit
    // handler or after `ExitBootServices` the message goes to serial alone.
    if console_allowed() {
        uefi::println!("{} PANIC: {info}", crate::TAG);
    }

    halt_forever();
}

/// Stops this CPU permanently, with interrupts disabled.
///
/// Used wherever execution must end without firmware help: after a panic,
/// after an exception in VMX root operation (`vmx::host`), and after a stop
/// of the firmware guest, which has nothing to return to. The test guest's
/// stop does not halt; the VM-exit handler hands it back to bring-up.
///
/// * `CLI` clears RFLAGS.IF, so maskable interrupts (timer, devices) are no
///   longer delivered. During boot services UEFI runs with interrupts on and
///   its timer fires regularly; without CLI, firmware interrupt handlers
///   would keep running. After a VM exit IF is already 0 (host RFLAGS is
///   loaded as 0x2), so there CLI only makes sure.
/// * `HLT` stops executing until an interrupt arrives. With IF = 0 only
///   non-maskable events wake it: NMI, SMI, machine check, INIT/reset.
/// * After an NMI handler returns, execution continues after `HLT`; the loop
///   sends it straight back to `CLI; HLT`.
///
/// `HLT` instead of an empty `loop {}`: a busy loop keeps the core at 100%,
/// while under Hyper-V a `HLT` is itself a VM exit that lets Hyper-V
/// deschedule the vCPU, so a halted Aleph0 costs the host no CPU time.
///
/// `-> !` ("never") tells the compiler this function does not return, which
/// is what lets the panic handler end with a call to it.
pub fn halt_forever() -> ! {
    loop {
        // SAFETY: CLI and HLT only stop this CPU, which is what this
        // function is for; they touch no memory (`nomem`) and no stack
        // (`nostack`). `preserves_flags` is deliberately absent, because CLI
        // changes RFLAGS.
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

/// Which context the hypervisor is running in, as far as output is concerned.
///
/// `#[repr(u8)]` with explicit values makes `phase as u8` a fixed number, so
/// the phase can live in an [`AtomicU8`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    /// Ordinary UEFI code before `ExitBootServices`: `main` and bring-up,
    /// and again once teardown has left VMX operation. The only phase in
    /// which the firmware console may be used.
    BootServices = 0,
    /// After `ExitBootServices`: the firmware console is gone and the OS
    /// owns the machine. The exit handler sets it for good at the VMCALL of
    /// Aleph0's `ExitBootServices` event (`resident`).
    Runtime = 1,
    /// The VM-exit handler, which puts the phase it found back when it
    /// resumes the guest (in place, the guest is Aleph0's own code too, which
    /// may use the console again); after a stop that returns to bring-up,
    /// bring-up until teardown has left VMX operation. Interrupts off,
    /// firmware state unknown.
    VmExit = 2,
}

impl Phase {
    /// The phase stored as `value`.
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::BootServices,
            1 => Self::Runtime,
            _ => Self::VmExit,
        }
    }
}

/// The current [`Phase`], stored as its `u8` value. Starts in boot services,
/// because that is where `main` begins.
///
/// `SeqCst` below is stronger than needed: the phase guards no other data and
/// only one CPU runs this code, so `Relaxed` would do.
static PHASE: AtomicU8 = AtomicU8::new(Phase::BootServices as u8);

/// Switches the output phase, and returns the one it replaces; later `log!`
/// lines and panics follow it.
pub fn set_phase(phase: Phase) -> Phase {
    Phase::from_u8(PHASE.swap(phase as u8, Ordering::SeqCst))
}

/// Whether the firmware console may be used right now.
fn console_allowed() -> bool {
    PHASE.load(Ordering::SeqCst) == Phase::BootServices as u8
}

/// Implementation of the `log!` macro in `main.rs`. Taking `Arguments` means
/// the caller's expressions are evaluated once, then formatted once per
/// destination.
///
/// Serial is written in every phase. The firmware console only in
/// [`Phase::BootServices`]; elsewhere calling it is unsafe (VM-exit handler)
/// or pointless (after `ExitBootServices` it silently prints nothing).
pub fn log_line(args: core::fmt::Arguments) {
    let tag = crate::TAG;
    if console_allowed() {
        uefi::println!("{tag} {args}");
    }
    crate::serial_println!("{tag} {args}");
}
