//! Unit tests for `src/vmx/host/idt.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;

/// Made-up handler addresses: 16 bytes apart, like the fault stubs.
fn handler(vector: u8) -> u64 {
    0x7e00_0000 + u64::from(vector) * 16
}

fn filled() -> Box<[[u8; GATE_SIZE]; VECTORS]> {
    let mut idt = Box::new([[0xAA; GATE_SIZE]; VECTORS]);
    fill(&mut idt, 0x28, handler);
    idt
}

#[test]
fn nmi_double_fault_and_machine_check_have_stacks_of_their_own() {
    assert_eq!(interrupt_stack(2), Some(InterruptStack::Nmi));
    assert_eq!(interrupt_stack(8), Some(InterruptStack::DoubleFault));
    assert_eq!(interrupt_stack(18), Some(InterruptStack::MachineCheck));
    for vector in (0..=u8::MAX).filter(|vector| ![2, 8, 18].contains(vector)) {
        assert_eq!(interrupt_stack(vector), None, "vector {vector}");
    }
}

#[test]
fn each_interrupt_stack_has_its_own_ist_number() {
    let ists = InterruptStack::ALL.map(InterruptStack::ist);
    assert_eq!(ists, [1, 2, 3]);
}

#[test]
fn every_gate_points_to_its_handler_through_the_code_selector() {
    let idt = filled();
    for vector in 0..=u8::MAX {
        let ist = interrupt_stack(vector).map_or(0, InterruptStack::ist);
        assert_eq!(
            idt[usize::from(vector)],
            interrupt_gate(handler(vector), 0x28, ist),
            "vector {vector}"
        );
    }
}

#[test]
fn the_gates_name_their_ist_in_byte_4() {
    let idt = filled();
    assert_eq!(idt[2][4], 1, "NMI on IST1");
    assert_eq!(idt[8][4], 2, "#DF on IST2");
    assert_eq!(idt[18][4], 3, "#MC on IST3");
    assert_eq!(idt[14][4], 0, "#PF on the current stack");
}

#[test]
fn exactly_the_architectural_vectors_have_an_error_code() {
    let with_code: Vec<u8> = (0..=u8::MAX).filter(|&vector| has_error_code(vector)).collect();
    assert_eq!(with_code, [8, 10, 11, 12, 13, 14, 17, 21, 29, 30]);
}

#[test]
fn exceptions_are_named_by_mnemonic() {
    assert_eq!(exception_name(13), "#GP general protection");
    assert_eq!(exception_name(14), "#PF page fault");
    assert_eq!(exception_name(2), "NMI");
    assert_eq!(exception_name(15), "reserved exception");
    assert_eq!(exception_name(31), "reserved exception");
    assert_eq!(exception_name(32), "interrupt");
}
