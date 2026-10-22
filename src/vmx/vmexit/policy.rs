//! How much of each VM exit the handler prints.
//!
//! Under Hyper-V every serial byte is itself an exit to Hyper-V, and an exit
//! printed in full is about five lines. The test guest's 13 exits do not
//! notice. Firmware idling in HLT, or a kernel booting through thousands of
//! CPUID, MSR and HLT exits, would spend most of its time printing. So each
//! exit gets a [`Detail`] from its [`Level`]:
//!
//! | Exit | Level | Detail in the default build |
//! |---|---|---|
//! | stops the guest, or a VMCS field could not be read | error | in full |
//! | one of the first [`FULL_EXITS_PER_REASON`] of its reason | info | in full |
//! | the 32nd, 64th, 128th, ... of its reason | info | one summary line |
//! | any other | trace | nothing |
//!
//! A build prints the levels up to [`MAX_LEVEL`]: info by default, trace
//! with the `trace-exits` Cargo feature, which prints every exit in full.
//! An NMI that arrived while Aleph0 ran is a warning, printed whatever the
//! exit's detail. Every stop also prints how many exits of each reason there
//! were ([`Histogram`]), so the exits left out still show in the totals.

use core::fmt;

use crate::vmx::exit_decision::exit_reason_name;

/// How much a report line matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// The guest stops, or Aleph0 could not read what it needed.
    Error,
    /// Unusual, but handled: an NMI that arrived while Aleph0 ran.
    Warn,
    /// What exits did, within the rate limit.
    Info,
    /// Every exit, in full.
    Trace,
}

/// The most detailed level this build prints: trace with the `trace-exits`
/// Cargo feature, info otherwise. Nothing can set a level at run time yet.
pub const MAX_LEVEL: Level = if cfg!(feature = "trace-exits") {
    Level::Trace
} else {
    Level::Info
};

/// Whether this build prints lines of `level`.
pub fn enabled(level: Level) -> bool {
    level <= MAX_LEVEL
}

/// Exits of one reason printed in full before the rate limit starts. Each
/// reason in the test guest's run stays well under it (four I/O exits at
/// most), so its exits print exactly as before.
pub const FULL_EXITS_PER_REASON: u64 = 16;

/// How much of one exit is printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detail {
    /// Every line: what was read, what it turned out to be, what was done.
    Full,
    /// One line: the exit's number and reason, and how many there were.
    Summary,
    /// Nothing.
    Silent,
}

/// How much of an exit to print: exit `count` of its reason (1 for the
/// first), which `stops` the guest or not, with an `unreadable` VMCS field or
/// not, in a build that prints up to `max_level` ([`MAX_LEVEL`]).
pub fn exit_detail(count: u64, stops: bool, unreadable: bool, max_level: Level) -> Detail {
    let level = if stops || unreadable {
        Level::Error
    } else if count <= FULL_EXITS_PER_REASON {
        Level::Info
    } else {
        Level::Trace
    };
    if level <= max_level {
        Detail::Full
    } else if count.is_power_of_two() && Level::Info <= max_level {
        Detail::Summary
    } else {
        Detail::Silent
    }
}

/// Basic exit reasons with a counter of their own: 0 to 127, well past the
/// highest the SDM defines.
pub const REASON_COUNTERS: usize = 128;
/// The counter every other reason shares: one past the SDM's, or
/// `UNREADABLE_REASON` (`0xFFFF`) when VM_EXIT_REASON could not be read.
pub const OTHER_REASONS: usize = REASON_COUNTERS;
/// Counters in all.
pub const COUNTERS: usize = REASON_COUNTERS + 1;

/// The counter of basic exit reason `basic`. Never past the last one,
/// whatever `basic` is.
pub fn counter(basic: u16) -> usize {
    usize::from(basic).min(OTHER_REASONS)
}

/// The exit counts by reason, as the line every stop prints:
/// `10 (CPUID)=1, 12 (HLT)=1, 18 (VMCALL)=2`, with `other=N` for the shared
/// counter. Reasons without an exit are left out.
pub struct Histogram<'a>(pub &'a [u64; COUNTERS]);

impl fmt::Display for Histogram<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut counted = self.0.iter().enumerate().filter(|&(_, &count)| count > 0).peekable();
        if counted.peek().is_none() {
            return f.write_str("none");
        }
        let mut separator = "";
        for (slot, count) in counted {
            if slot == OTHER_REASONS {
                write!(f, "{separator}other={count}")?;
            } else {
                write!(f, "{separator}{slot} ({})={count}", exit_reason_name(slot as u16))?;
            }
            separator = ", ";
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/vmexit/policy.rs"]
mod tests;
