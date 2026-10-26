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
         io_in_exits=2 io_out_exits=2 halt_exits=1 nmi_injections=0 exception_injections=0 \
         hypercall_exits=0 synthetic_read_exits=0 synthetic_write_exits=0"
    );
}

#[test]
fn forwarded_accesses_count_by_call_code_and_msr() {
    let mut stats = VcpuStats::ZERO;
    let mut forwarded = Forwarded::NONE;
    for emulation in [
        // HvCallPostMessage twice, once fast with a rep count; HvCallSignalEvent.
        Emulation::Hypercall { input: 0x5C },
        Emulation::Hypercall {
            input: 0x0000_0002_0001_005C,
        },
        Emulation::Hypercall { input: 0x5D },
        Emulation::SyntheticRead { msr: 0x4000_0020 },
        Emulation::SyntheticRead { msr: 0x4000_0020 },
        Emulation::SyntheticWrite {
            msr: 0x4000_0001,
            value: 0x7FF2_0001,
        },
    ] {
        let event = ExitEvent::Emulated(emulation);
        let ExitAction::Resume(plan) = event.action() else {
            panic!("{event:?} does not resume");
        };
        stats.count_resumed(event, plan);
        forwarded.count(plan.emulate);
    }
    assert_eq!(
        (
            stats.hypercall_exits,
            stats.synthetic_read_exits,
            stats.synthetic_write_exits
        ),
        (3, 2, 1)
    );
    assert_eq!(forwarded.hypercalls.counts(), [(0x5C, 2), (0x5D, 1)]);
    assert_eq!(forwarded.synthetic_reads.to_string(), "0x40000020=2");
    assert_eq!(forwarded.synthetic_writes.to_string(), "0x40000001=1");
}

#[test]
fn nothing_else_is_forwarded() {
    let mut forwarded = Forwarded::NONE;
    for emulate in [
        None,
        Some(Emulation::Cpuid {
            leaf: 0x4000_0000,
            subleaf: 0,
        }),
        Some(Emulation::Rdmsr { msr: 0xC000_0102 }),
    ] {
        forwarded.count(emulate);
    }
    assert_eq!(forwarded, Forwarded::NONE);
}

#[test]
fn a_refused_forward_counts_the_access_and_the_exception() {
    // The plan `prepare_resume` carries out when Hyper-V refuses a hypercall.
    let emulation = Emulation::Hypercall { input: 0x5C };
    let plan = ResumePlan {
        advance_rip: false,
        emulate: Some(emulation),
        ..ResumePlan::INJECT_UD
    };
    let mut stats = VcpuStats::ZERO;
    stats.count_resumed(ExitEvent::Emulated(emulation), plan);
    assert_eq!((stats.hypercall_exits, stats.exception_injections), (1, 1));
}

#[test]
fn a_tally_shares_one_counter_past_its_keys() {
    let mut tally = Tally::EMPTY;
    assert_eq!(tally.to_string(), "none");
    for key in 0..TALLY_KEYS as u32 + 2 {
        tally.count(key);
    }
    tally.count(0);
    assert_eq!(tally.counts().len(), TALLY_KEYS);
    assert_eq!(tally.counts()[0], (0, 2));
    assert_eq!(tally.other, 2);
    assert!(tally.to_string().ends_with(" 0x1f=1 other=2"), "{tally}");
}
