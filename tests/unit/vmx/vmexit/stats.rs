//! Unit tests for `src/vmx/vmexit/stats.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;
use crate::vmx::exit_decision::{ExitAction, IoSize};
use crate::vmx::mtrr::MtrrCapabilities;

/// The statistics after one resumed exit of `event`, with its own plan.
fn after(event: ExitEvent) -> VcpuStats {
    let ExitAction::Resume(plan) = event.action() else {
        panic!("{event:?} does not resume");
    };
    let mut stats = VcpuStats::ZERO;
    stats.count_resumed(event, plan);
    stats
}

#[test]
fn exits_are_numbered_from_one() {
    let mut stats = VcpuStats::ZERO;
    assert_eq!([stats.count_exit(), stats.count_exit()], [1, 2]);
    assert_eq!(stats.exits, 2);
}

#[test]
fn each_emulated_instruction_has_its_own_counter() {
    let emulated = |emulation| after(ExitEvent::Emulated(emulation));
    let port = 0x3FF;
    let size = IoSize::Byte;
    let def_type = MtrrCapabilities::new(8, 46).unwrap().msr(0x2FF).unwrap();
    for (stats, counter) in [
        (emulated(Emulation::Cpuid { leaf: 1, subleaf: 0 }), "cpuid_exits"),
        (emulated(Emulation::Rdmsr { msr: 0xC000_0102 }), "msr_read_exits"),
        (
            emulated(Emulation::Wrmsr {
                msr: 0xC000_0102,
                value: 0,
            }),
            "msr_write_exits",
        ),
        (emulated(Emulation::MtrrRead { msr: def_type }), "mtrr_read_exits"),
        (
            emulated(Emulation::MtrrWrite {
                msr: def_type,
                value: 0xC06,
            }),
            "mtrr_write_exits",
        ),
        (emulated(Emulation::In { port, size }), "io_in_exits"),
        (emulated(Emulation::Out { port, size, value: 0 }), "io_out_exits"),
        (after(ExitEvent::Halted), "halt_exits"),
        (after(ExitEvent::NmiInjected), "nmi_injections"),
        (after(ExitEvent::NmiWindowInjected), "nmi_injections"),
        (after(ExitEvent::GuestGeneralProtection), "exception_injections"),
        (after(ExitEvent::GuestInvalidOpcode), "exception_injections"),
    ] {
        // Exactly that counter is 1, and no other.
        let line = stats.to_string();
        let ones: Vec<&str> = line.split(' ').filter(|field| field.ends_with("=1")).collect();
        assert_eq!(ones, [format!("{counter}=1")], "{line}");
    }
}

#[test]
fn exits_that_do_nothing_for_the_guest_count_nothing_more() {
    for event in [
        ExitEvent::MainVmcall,
        ExitEvent::GuestNmiHandler,
        ExitEvent::NmiDeferred,
        ExitEvent::EptWriteGranted,
    ] {
        assert_eq!(after(event), VcpuStats::ZERO, "{event:?}");
    }
}

#[test]
fn stats_print_as_one_line_of_named_counters() {
    let stats = VcpuStats {
        exits: 13,
        cpuid_exits: 1,
        msr_read_exits: 2,
        msr_write_exits: 2,
        io_in_exits: 2,
        io_out_exits: 2,
        halt_exits: 1,
        ..VcpuStats::ZERO
    };
    assert_eq!(
        stats.to_string(),
        "exits=13 cpuid_exits=1 msr_read_exits=2 msr_write_exits=2 mtrr_read_exits=0 mtrr_write_exits=0 \
         io_in_exits=2 io_out_exits=2 halt_exits=1 nmi_injections=0 exception_injections=0"
    );
}
