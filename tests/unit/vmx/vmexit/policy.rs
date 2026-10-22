//! Unit tests for `src/vmx/vmexit/policy.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;
use crate::vmx::exit_decision::UNREADABLE_REASON;

/// The details of exits 1 to `last` of one reason, none of which stops the
/// guest, in a build printing up to `max_level`.
fn details(last: u64, max_level: Level) -> Vec<Detail> {
    (1..=last)
        .map(|count| exit_detail(count, false, false, max_level))
        .collect()
}

#[test]
fn the_first_exits_of_a_reason_print_in_full() {
    assert!(
        details(FULL_EXITS_PER_REASON, Level::Info)
            .iter()
            .all(|&detail| detail == Detail::Full)
    );
}

#[test]
fn after_the_first_exits_only_powers_of_two_print_a_summary() {
    let printed: Vec<(u64, Detail)> = (FULL_EXITS_PER_REASON + 1..=4096)
        .map(|count| (count, exit_detail(count, false, false, Level::Info)))
        .filter(|&(_, detail)| detail != Detail::Silent)
        .collect();
    let summaries: Vec<u64> = printed.iter().map(|&(count, _)| count).collect();
    assert_eq!(summaries, [32, 64, 128, 256, 512, 1024, 2048, 4096]);
    assert!(printed.iter().all(|&(_, detail)| detail == Detail::Summary));
}

#[test]
fn a_stop_always_prints_in_full() {
    for count in [1, 17, 33, 1_000_000] {
        assert_eq!(
            exit_detail(count, true, false, Level::Info),
            Detail::Full,
            "count {count}"
        );
    }
}

#[test]
fn an_unreadable_field_always_prints_in_full() {
    assert_eq!(exit_detail(33, false, true, Level::Info), Detail::Full);
}

#[test]
fn trace_prints_every_exit_in_full() {
    assert!(details(5000, Level::Trace).iter().all(|&detail| detail == Detail::Full));
}

#[test]
fn the_test_guest_runs_print_every_exit_in_full() {
    // The basic reasons of the recorded runs, in order: nine emulated exits,
    // HLT, the EPT violation, then the VMCALLs; with -InjectNmi an NMI exit
    // and the guest NMI handler's VMCALL come before the last one.
    let plain = [10, 31, 32, 31, 32, 30, 30, 30, 30, 12, 48, 18, 18];
    let inject_nmi = [10, 31, 32, 31, 32, 30, 30, 30, 30, 12, 48, 18, 0, 18, 18];
    for run in [&plain[..], &inject_nmi[..]] {
        let mut counts = [0u64; COUNTERS];
        for (number, &basic) in run.iter().enumerate() {
            counts[counter(basic)] += 1;
            let stops = number == run.len() - 1;
            let detail = exit_detail(counts[counter(basic)], stops, false, MAX_LEVEL);
            assert_eq!(detail, Detail::Full, "exit #{}", number + 1);
        }
    }
}

#[test]
fn every_reason_has_a_counter_and_none_is_out_of_bounds() {
    assert_eq!(counter(10), 10);
    assert_eq!(counter(127), 127);
    assert_eq!(counter(128), OTHER_REASONS);
    assert_eq!(counter(UNREADABLE_REASON), OTHER_REASONS);
    assert!(counter(u16::MAX) < COUNTERS);
}

#[test]
fn the_histogram_lists_each_counted_reason_with_its_name() {
    // The plain run's counts.
    let mut counts = [0u64; COUNTERS];
    for (basic, count) in [(10, 1), (12, 1), (18, 2), (30, 4), (31, 2), (32, 2), (48, 1)] {
        counts[counter(basic)] = count;
    }
    assert_eq!(
        Histogram(&counts).to_string(),
        "10 (CPUID)=1, 12 (HLT)=1, 18 (VMCALL)=2, 30 (I/O instruction)=4, 31 (RDMSR)=2, 32 (WRMSR)=2, 48 (EPT violation)=1"
    );
}

#[test]
fn the_histogram_names_the_shared_counter_other() {
    let mut counts = [0u64; COUNTERS];
    counts[counter(0)] = 1;
    counts[counter(UNREADABLE_REASON)] = 2;
    assert_eq!(Histogram(&counts).to_string(), "0 (exception or NMI)=1, other=2");
    assert_eq!(Histogram(&[0; COUNTERS]).to_string(), "none");
}

#[test]
fn the_default_build_prints_up_to_info() {
    assert_eq!(MAX_LEVEL == Level::Trace, cfg!(feature = "trace-exits"));
}
