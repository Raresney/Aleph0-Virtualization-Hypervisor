//! Port I/O: the `in` and `out` instructions, 1, 2 and 4 bytes wide.
//!
//! Used by the serial driver (`serial.rs`) and by the VM-exit handler, which
//! runs a guest's intercepted IN/OUT for it. Background: `docs/PORT_IO.md`.
//!
//! The `asm!` options are promises to the compiler:
//! - `nostack`: the instruction does not push or pop;
//! - `preserves_flags`: `in`/`out` do not change RFLAGS;
//! - `nomem`: the instruction does not read or write memory, so the compiler
//!   may move ordinary memory accesses across it. True for the UART, which
//!   never touches RAM. Do NOT copy `nomem` into port I/O for a DMA device
//!   (one that reads a buffer in RAM after an `out` command): the compiler
//!   could then move the buffer writes after the command. The guest's IN/OUT
//!   are emulated with these functions too; they reach no RAM through Aleph0
//!   (string I/O stops the guest instead).

use core::arch::asm;

/// Writes one byte to an I/O port: `out dx, al`.
///
/// `in("dx") port` loads the 16-bit port number into DX and `in("al") value`
/// loads the byte into AL before the instruction runs; the CPU then sends an
/// I/O write for that port to the chipset.
///
/// # Safety
///
/// Port writes reach hardware directly; the port must belong to a device
/// the caller owns, or be one a guest asked to write.
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: OUT touches only the I/O port, which the caller guarantees it
    // may write.
    unsafe { asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags)) }
}

/// Writes two bytes to an I/O port: `out dx, ax`.
///
/// # Safety
///
/// As for [`outb`].
pub unsafe fn outw(port: u16, value: u16) {
    // SAFETY: as for `outb`.
    unsafe { asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags)) }
}

/// Writes four bytes to an I/O port: `out dx, eax`.
///
/// # Safety
///
/// As for [`outb`].
pub unsafe fn outl(port: u16, value: u32) {
    // SAFETY: as for `outb`.
    unsafe { asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags)) }
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
/// the caller owns, or be one a guest asked to read.
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: IN touches only the I/O port, which the caller guarantees it
    // may read.
    unsafe { asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags)) }
    value
}

/// Reads two bytes from an I/O port: `in ax, dx`.
///
/// # Safety
///
/// As for [`inb`].
pub unsafe fn inw(port: u16) -> u16 {
    let value: u16;
    // SAFETY: as for `inb`.
    unsafe { asm!("in ax, dx", out("ax") value, in("dx") port, options(nomem, nostack, preserves_flags)) }
    value
}

/// Reads four bytes from an I/O port: `in eax, dx`.
///
/// # Safety
///
/// As for [`inb`].
pub unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    // SAFETY: as for `inb`.
    unsafe { asm!("in eax, dx", out("eax") value, in("dx") port, options(nomem, nostack, preserves_flags)) }
    value
}
