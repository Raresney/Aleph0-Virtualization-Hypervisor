//! Unit tests for `src/vmx/vmexit/history.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;
use crate::vmx::exit_decision::Emulation;

fn kept<const N: usize>(ring: &Ring<u32, N>) -> Vec<u32> {
    ring.oldest_first().copied().collect()
}

#[test]
fn an_empty_ring_keeps_nothing() {
    let ring: Ring<u32, 4> = Ring::new(0);
    assert_eq!(ring.kept(), 0);
    assert_eq!(ring.overwritten(), 0);
    assert!(kept(&ring).is_empty());
}

#[test]
fn a_ring_keeps_everything_until_full() {
    let mut ring: Ring<u32, 4> = Ring::new(0);
    for item in 1..=4 {
        ring.push(item);
    }
    assert_eq!(kept(&ring), [1, 2, 3, 4]);
    assert_eq!(ring.overwritten(), 0);
}

#[test]
fn a_full_ring_overwrites_the_oldest_and_keeps_the_order() {
    let mut ring: Ring<u32, 4> = Ring::new(0);
    for item in 1..=6 {
        ring.push(item);
    }
    assert_eq!(kept(&ring), [3, 4, 5, 6]);
    assert_eq!(ring.overwritten(), 2);
}

#[test]
fn a_ring_wraps_any_number_of_times() {
    let mut ring: Ring<u32, 64> = Ring::new(0);
    for item in 1..=1000 {
        ring.push(item);
    }
    assert_eq!(kept(&ring), (937..=1000).collect::<Vec<u32>>());
    assert_eq!(ring.overwritten(), 1000 - 64);
}

#[test]
fn a_record_prints_as_one_line() {
    // Exit #3 of the Hyper-V runs: WRMSR of IA32_KERNEL_GS_BASE.
    let record = ExitRecord {
        number: 3,
        reason: Some(32),
        qualification: Some(0),
        rip: Some(0x7eae_1028),
        length: Some(2),
        interruption_info: Some(0),
        idt_vectoring_info: Some(0),
        registers: [0, 0x2_0800, 0xc000_0102, 0x7a1e],
        event: ExitEvent::Emulated(Emulation::Wrmsr {
            msr: 0xc000_0102,
            value: 0x7a1e_0000_0000,
        }),
    };
    assert_eq!(
        record.to_string(),
        "#3 reason=32 (WRMSR) rip=0x7eae1028 len=2 qual=0x0 info=0x0 vectoring=0x0 \
         rax=0x0 rbx=0x20800 rcx=0xc0000102 rdx=0x7a1e -> Emulated(Wrmsr { msr: c0000102, value: 7a1e00000000 })"
    );
}

#[test]
fn a_record_marks_unreadable_fields_and_failed_entries() {
    let record = ExitRecord {
        number: 1,
        reason: Some(33 | 1 << 31),
        rip: None,
        ..ExitRecord::EMPTY
    };
    assert_eq!(
        record.to_string(),
        "#1 reason=33 (VM-entry failure: invalid guest state) [entry failed] rip=? len=? qual=? info=? \
         vectoring=? rax=0x0 rbx=0x0 rcx=0x0 rdx=0x0 -> Unexpected"
    );
    let unread = ExitRecord {
        number: 2,
        ..ExitRecord::EMPTY
    };
    assert!(unread.to_string().starts_with("#2 reason=? rip=?"));
}
