//! Firmware-independent debug output over the COM1 serial port.
//!
//! Further reading, kept in the repository so it is not forgotten:
//!
//! * `docs/SERIAL_LOGGING.md`: a beginner walkthrough of this file. Its
//!   step numbers match the `Step N` comments below.
//! * `docs/PORT_IO.md`: how `in`/`out` and the 16-bit I/O port space work,
//!   and how a hypervisor intercepts them.
//!
//! # Why not `uefi::println!`?
//!
//! `uefi::println!` calls the firmware's console driver. That is fine in
//! `main`, but this hypervisor will soon print from places where calling
//! firmware is unsafe or impossible:
//!
//! * the VM-exit handler, which runs with interrupts off, on its own stack,
//!   in the middle of whatever the firmware was doing when the guest started;
//! * anything after `ExitBootServices`, when the firmware console is gone.
//!
//! This module drives the serial hardware directly with `in`/`out`
//! instructions. It needs no allocator, no firmware, no interrupts and no
//! locks, so it works in every one of those contexts. Every VMM (QEMU,
//! Hyper-V, VMware, Bochs) emulates this device, which is why it is the
//! standard debug channel for OS and hypervisor work.
//!
//! # The device: a 16550 UART
//!
//! A UART turns bytes into a bit stream on a wire. The PC-compatible one sits
//! at I/O port base `0x3F8` (COM1) and exposes eight byte-wide registers at
//! `base + 0` through `base + 7`.
//!
//! # Port I/O in short
//!
//! x86 has two address spaces. Memory is reached with ordinary instructions
//! (`mov`). The **I/O space** is separate and **16 bits wide**: port numbers
//! run from `0x0000` to `0xFFFF` (65,536 ports, one byte each), and only the
//! `in`/`out` instructions reach it. Port `0x3F8` and memory address `0x3F8`
//! are unrelated.
//!
//! * `out dx, al` sends the byte in AL to the port numbered by DX;
//!   `in al, dx` reads a byte from port DX into AL.
//! * The port must be in DX here: the other form, with the port written
//!   into the instruction, only reaches ports `0x00`–`0xFF`, and COM1 is
//!   above that.
//! * Data can be 8, 16 or 32 bits (AL, AX, EAX). The UART's registers are
//!   all 8-bit, so this file only uses byte access ([`outb`], [`inb`]).
//! * The CPU sends the access to the chipset as an I/O transaction, and the
//!   device that claims that port answers. No device means a read of `0xFF`.
//! * Ports are not memory: a read can change device state, and writing and
//!   reading the same port can reach two different registers.
//! * Ring 0 may use any port; this code always runs at ring 0.
//!
//! Under Hyper-V, every `in`/`out` here causes a VM exit (reason 30) and
//! Hyper-V's emulated UART answers. Details: `docs/PORT_IO.md`.
//!
//! The registers used here, by offset from the base:
//!
//! | Offset | DLAB=0 (normal)         | DLAB=1 (setup)          |
//! |--------|-------------------------|-------------------------|
//! | 0      | transmit/receive byte   | divisor latch, low byte |
//! | 1      | interrupt enable        | divisor latch, high byte|
//! | 2      | FIFO control (write)    |                         |
//! | 3      | line control; bit 7 is DLAB                       |
//! | 4      | modem control; bit 4 is loopback                  |
//! | 5      | line status; bit 5 = ready for another byte       |
//!
//! DLAB ("divisor latch access bit") reuses offsets 0 and 1 for the baud
//! divisor while it is set. The UART clock runs at 115200 × 16 Hz, so the
//! divisor is `115200 / baud`; 1 selects the maximum, 115200 baud. Virtual
//! UARTs ignore the speed entirely, but real ones and terminal software
//! expect the usual "115200 8N1": 8 data bits, no parity, 1 stop bit.
//!
//! # Sending a byte
//!
//! Poll line status bit 5 ("transmit holding register empty") until it is
//! set, then write the byte to offset 0. That is all [`write_byte`] does. The
//! poll is bounded, so a missing or wedged UART slows output down instead
//! of hanging the hypervisor.
//!
//! # Seeing the output
//!
//! * QEMU: `scripts/run.ps1` passes `-serial stdio`, so output appears in the
//!   terminal. OVMF also mirrors its own console to COM1, so lines printed
//!   with `log!` in `main` show up twice there: once from OVMF, once from
//!   this module.
//! * Hyper-V: `scripts/run-hyperv.ps1` attaches COM1 to a named pipe and reads it;
//!   see that script and the README.
//!
//! # Concurrency
//!
//! There is no lock. That is sound while exactly one CPU runs this code and
//! nothing interrupts a print with another print: true today, because the
//! exit handler runs with interrupts off and only between guest instructions.
//! Once several vCPUs exist, output needs a spinlock (not one that can
//! deadlock if an exit handler interrupts its own holder).

use core::arch::asm;
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

// Step 1: where the chip lives. COM1 claims the 8 ports 0x3F8..=0x3FF and
// uses the low 3 bits of the port number to pick one of its registers.

/// I/O port base of COM1. A `u16` because port numbers are 16-bit.
pub const COM1: u16 = 0x3F8;

/// Register offsets from the port base. See the module table.
/// Offset 0 is two registers: writing it sends a byte, reading it receives.
const DATA: u16 = 0;
const INTERRUPT_ENABLE: u16 = 1;
const FIFO_CONTROL: u16 = 2;
const LINE_CONTROL: u16 = 3;
const MODEM_CONTROL: u16 = 4;
const LINE_STATUS: u16 = 5;

/// Line control: 8 data bits, no parity, 1 stop bit.
const LINE_8N1: u8 = 0b0000_0011;
/// Line control bit 7: offsets 0 and 1 address the baud divisor.
const LINE_DLAB: u8 = 1 << 7;
/// FIFO control: enable FIFOs, clear both, 14-byte receive threshold.
const FIFO_ENABLE_AND_CLEAR: u8 = 0b1100_0111;
/// Modem control: DTR + RTS + OUT2, the normal "ready" state.
const MODEM_READY: u8 = 0b0000_1011;
/// Modem control bit 4: internal loopback, transmitted bytes are received.
const MODEM_LOOPBACK: u8 = 1 << 4;
/// Line status bit 0: a received byte is waiting.
const STATUS_DATA_READY: u8 = 1 << 0;
/// Line status bit 5: the transmit register can take another byte.
const STATUS_TRANSMIT_EMPTY: u8 = 1 << 5;

/// Polls before giving up on a byte. Virtual UARTs are ready immediately;
/// this only bounds the wait when the device is missing or stuck.
const SPIN_LIMIT: u32 = 100_000;

/// Set once [`init`] has found a working UART. Writes before that, or
/// after a failed init, are dropped instead of touching an unknown device.
static READY: AtomicBool = AtomicBool::new(false);

/// Baud-rate divisor for the 115200 Hz UART reference rate.
pub const fn divisor(baud: u32) -> u16 {
    (115_200 / baud) as u16
}

// Step 0: the only two ways this driver touches hardware. Everything else in
// the file is calls to these.
//
// The `asm!` options are promises to the compiler:
// - `nostack`: the instruction does not push or pop;
// - `preserves_flags`: `in`/`out` do not change RFLAGS;
// - `nomem`: the instruction does not read or write memory, so the compiler
//   may move ordinary memory accesses across it. True for the UART, which
//   never touches RAM. Do NOT copy `nomem` into port I/O for a DMA device
//   (one that reads a buffer in RAM after an `out` command): the compiler
//   could then move the buffer writes after the command.

/// Writes one byte to an I/O port: `out dx, al`.
///
/// `in("dx") port` loads the 16-bit port number into DX and `in("al") value`
/// loads the byte into AL before the instruction runs; the CPU then sends an
/// I/O write for that port to the chipset.
///
/// # Safety
///
/// Port writes reach hardware directly; the port must belong to a device
/// this code owns.
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: OUT touches only the I/O port, which the caller guarantees
    // belongs to a device this code owns.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }
}

/// Reads one byte from an I/O port: `in al, dx`.
///
/// `in("dx") port` loads the port number into DX; afterwards `out("al")`
/// copies the byte the device returned from AL into `value`. A port no
/// device claims reads as `0xFF`.
///
/// # Safety
///
/// Some device registers change state when read (reading the UART's data
/// register removes the received byte); the port must belong to a device
/// this code owns.
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: IN touches only the I/O port, which the caller guarantees
    // belongs to a device this code owns.
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags));
    }
    value
}

/// Why [`init`] did not enable serial output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialError {
    /// The loopback test did not return the byte it sent: no UART at this
    /// port, or one that does not behave like a 16550.
    LoopbackFailed,
}

/// Programs COM1 for 115200 8N1 with polling (no interrupts), then proves a
/// UART is really there with a loopback test before enabling output.
///
/// Safe to call more than once; firmware may already have configured the
/// same port, and reprogramming it with the same settings is harmless.
pub fn init() -> Result<(), SerialError> {
    let [divisor_low, divisor_high] = divisor(115_200).to_le_bytes();

    // SAFETY: every port below is a COM1 register, the UART this driver
    // owns.
    unsafe {
        // Step 2a: no UART interrupts. This driver polls the status
        // register instead, and no interrupt handler exists.
        outb(COM1 + INTERRUPT_ENABLE, 0);

        // Step 2b: set the speed. Baud = bits per second on the wire, and
        // the chip produces it as 115200 / divisor. The divisor is 16 bits,
        // split across offsets 0 (low) and 1 (high), which only hold it
        // while DLAB (line control bit 7) is set, like holding Shift.
        outb(COM1 + LINE_CONTROL, LINE_DLAB); // 0b1000_0000: DLAB on
        outb(COM1 + DATA, divisor_low); // offset 0 = divisor low
        outb(COM1 + INTERRUPT_ENABLE, divisor_high); // offset 1 = divisor high

        // Step 2c: frame format 8N1 (8 data bits, no parity, 1 stop bit).
        // Writing 0b0000_0011 also clears bit 7, turning DLAB off, so
        // offsets 0/1 are data and interrupt enable again. Forgetting this
        // is the classic bug: every "send" would change the speed instead.
        outb(COM1 + LINE_CONTROL, LINE_8N1);

        // Step 2d: enable and empty the 16-byte transmit/receive queues.
        outb(COM1 + FIFO_CONTROL, FIFO_ENABLE_AND_CLEAR);

        // Step 3: prove a UART is here. Loopback makes the chip feed its
        // transmitter into its own receiver, so a byte written must come
        // straight back. A port no device claims reads as 0xFF and fails
        // this check. Nothing leaves the chip while loopback is on.
        const PROBE: u8 = 0xAE;
        outb(COM1 + MODEM_CONTROL, MODEM_READY | MODEM_LOOPBACK);
        outb(COM1 + DATA, PROBE);
        let mut received = None;
        for _ in 0..SPIN_LIMIT {
            if inb(COM1 + LINE_STATUS) & STATUS_DATA_READY != 0 {
                received = Some(inb(COM1 + DATA));
                break;
            }
        }

        // End of step 3, and step 2e: leave loopback whatever the result
        // and signal "ready" (DTR + RTS + OUT2). Step 2e lives here because
        // the loopback test also writes modem control. From here on, bytes
        // leave the chip normally, and the firmware's own console driver
        // can use the port again.
        outb(COM1 + MODEM_CONTROL, MODEM_READY);

        if received != Some(PROBE) {
            return Err(SerialError::LoopbackFailed);
        }
    }

    READY.store(true, Ordering::Release);
    Ok(())
}

/// Sends one byte, waiting (boundedly) for the transmitter.
/// Does nothing until [`init`] has succeeded.
///
/// Step 4. Line status bit 5 is a light the chip controls: writing a byte
/// turns it off (busy), and the chip turns it back on by itself once it has
/// taken the byte. Reading the status only looks at the light; it does not
/// make the chip ready. Under Hyper-V the light is back on instantly.
pub fn write_byte(byte: u8) {
    if !READY.load(Ordering::Acquire) {
        return;
    }

    // SAFETY: COM1's status and data registers, the UART this driver
    // owns; `init` found it there.
    unsafe {
        // Wait for "can take a byte", but never forever: a missing or
        // stuck UART must not hang the hypervisor.
        for _ in 0..SPIN_LIMIT {
            if inb(COM1 + LINE_STATUS) & STATUS_TRANSMIT_EMPTY != 0 {
                break;
            }
        }
        outb(COM1 + DATA, byte);
    }
}

/// Sends a string, expanding `\n` to `\r\n`: terminals need the carriage
/// return to move back to column 0.
///
/// Step 5: a string is only bytes, so this is [`write_byte`] in a loop.
pub fn write_str(text: &str) {
    for byte in text.bytes() {
        if byte == b'\n' {
            write_byte(b'\r');
        }
        write_byte(byte);
    }
}

/// Zero-sized handle that lets `core::fmt` format straight to the port,
/// with no buffer or allocation.
///
/// Step 6: `core::fmt` can write to anything implementing `fmt::Write`.
/// It hands over the formatted output in pieces as it produces them, and
/// each piece goes straight to [`write_str`]. No heap is needed, which is
/// why `serial_println!` is safe in the VM-exit handler.
pub struct Serial;

impl fmt::Write for Serial {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        write_str(text);
        Ok(())
    }
}

/// Implementation detail of [`serial_print!`] and [`serial_println!`].
#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    // Serial never reports an error, so the result carries no information.
    let _ = fmt::Write::write_fmt(&mut Serial, args);
}

/// Like `print!`, but to COM1 only. Safe in the VM-exit handler.
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::serial::_print(format_args!($($arg)*))
    };
}

/// Like `println!`, but to COM1 only. Safe in the VM-exit handler.
#[macro_export]
macro_rules! serial_println {
    () => {
        $crate::serial::write_str("\n")
    };
    ($($arg:tt)*) => {{
        $crate::serial::_print(format_args!($($arg)*));
        $crate::serial::write_str("\n");
    }};
}

#[cfg(test)]
#[path = "../tests/unit/serial.rs"]
mod tests;
