//! Per-vCPU exit statistics, kept the way KVM keeps `struct kvm_vcpu_stat`:
//! plain counters that the exit handler bumps in one place, for any guest,
//! and that no decision ever reads. `exit_decision::decide` says what an exit
//! is; these count what Aleph0 then did about it.
//!
//! Every stop prints them, before the exits by reason (`policy::Histogram`).
//! Once the test guest has finished, bring-up compares them with what that
//! guest does (`guest::expected_stats`), as a KVM selftest checks a vCPU's
//! statistics after its run.

use core::cell::UnsafeCell;
use core::fmt;

use crate::vmx::exit_decision::{Emulation, ExitEvent, ResumePlan};

/// One vCPU's exit statistics. Each counter is a `u64`: at a billion exits a
/// second, one would take over 500 years to overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VcpuStats {
    /// Every VM exit, handled or not.
    pub exits: u64,
    /// CPUIDs executed for the guest.
    pub cpuid_exits: u64,
    /// RDMSRs executed for the guest.
    pub msr_read_exits: u64,
    /// WRMSRs executed for the guest.
    pub msr_write_exits: u64,
    /// INs executed for the guest.
    pub io_in_exits: u64,
    /// OUTs executed for the guest.
    pub io_out_exits: u64,
    /// HLTs the guest was resumed past.
    pub halt_exits: u64,
    /// NMIs injected into the guest.
    pub nmi_injections: u64,
    /// Exceptions injected into the guest (#GP, #UD).
    pub exception_injections: u64,
}

impl VcpuStats {
    /// No exit yet.
    pub const ZERO: Self = Self {
        exits: 0,
        cpuid_exits: 0,
        msr_read_exits: 0,
        msr_write_exits: 0,
        io_in_exits: 0,
        io_out_exits: 0,
        halt_exits: 0,
        nmi_injections: 0,
        exception_injections: 0,
    };

    /// Counts one more exit and returns its number, from 1.
    pub fn count_exit(&mut self) -> u64 {
        self.exits += 1;
        self.exits
    }

    /// Counts what Aleph0 did at an exit it resumed from: `event`, carried
    /// out as `plan`. An exit that stops the guest counts in `exits` only,
    /// since what its plan would have done never happened.
    pub fn count_resumed(&mut self, event: ExitEvent, plan: ResumePlan) {
        match plan.emulate {
            Some(Emulation::Cpuid { .. }) => self.cpuid_exits += 1,
            Some(Emulation::Rdmsr { .. }) => self.msr_read_exits += 1,
            Some(Emulation::Wrmsr { .. }) => self.msr_write_exits += 1,
            Some(Emulation::In { .. }) => self.io_in_exits += 1,
            Some(Emulation::Out { .. }) => self.io_out_exits += 1,
            None => {}
        }
        // HLT resumes past the instruction like a VMCALL does, so only the
        // event tells it apart.
        if event == ExitEvent::Halted {
            self.halt_exits += 1;
        }
        if plan.inject_nmi {
            self.nmi_injections += 1;
        }
        if plan.inject_exception.is_some() {
            self.exception_injections += 1;
        }
    }
}

impl fmt::Display for VcpuStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            exits,
            cpuid_exits,
            msr_read_exits,
            msr_write_exits,
            io_in_exits,
            io_out_exits,
            halt_exits,
            nmi_injections,
            exception_injections,
        } = self;
        write!(
            f,
            "exits={exits} cpuid_exits={cpuid_exits} msr_read_exits={msr_read_exits} \
             msr_write_exits={msr_write_exits} io_in_exits={io_in_exits} io_out_exits={io_out_exits} \
             halt_exits={halt_exits} nmi_injections={nmi_injections} exception_injections={exception_injections}"
        )
    }
}

struct Stats(UnsafeCell<VcpuStats>);

// SAFETY: Aleph0 runs one vCPU on one CPU. Only the exit handler writes the
// statistics ([`update`]), with interrupts off, and the host NMI handler
// never touches them. They are read by that handler outside `update`, and by
// bring-up once the guest has stopped, when no exit handler runs.
unsafe impl Sync for Stats {}

static STATS: Stats = Stats(UnsafeCell::new(VcpuStats::ZERO));

/// Applies `update` to the statistics. For the exit handler only.
pub(super) fn update<R>(update: impl FnOnce(&mut VcpuStats) -> R) -> R {
    // SAFETY: the exit handler is the only writer, and no reader runs while
    // it writes (see `Stats`).
    update(unsafe { &mut *STATS.0.get() })
}

/// The statistics as they stand.
pub fn snapshot() -> VcpuStats {
    // SAFETY: a reader runs only when the exit handler is not writing (see
    // `Stats`).
    unsafe { *STATS.0.get() }
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/vmexit/stats.rs"]
mod tests;
