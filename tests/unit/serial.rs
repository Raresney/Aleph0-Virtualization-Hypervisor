//! Unit tests for `src/serial.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;

#[test]
fn divisor_for_common_rates() {
    assert_eq!(divisor(115_200), 1);
    assert_eq!(divisor(57_600), 2);
    assert_eq!(divisor(9_600), 12);
}

#[test]
fn registers_are_offsets_from_the_port_base() {
    // COM2's line status register, which `write_byte` polls.
    assert_eq!(SerialPort::COM2.register(LINE_STATUS), 0x2FD);
    assert_eq!(SerialPort::COM2.register(DATA), 0x2F8);
    assert_eq!(SerialPort::COM1.register(LINE_STATUS), 0x3FD);
}

#[test]
fn ports_print_their_name_and_base() {
    assert_eq!(SerialPort::COM2.to_string(), "COM2 (0x2f8)");
    assert_eq!(SerialPort::COM1.to_string(), "COM1 (0x3f8)");
    assert_eq!(SerialPort(0x3E8).to_string(), "the UART at 0x3e8");
}
