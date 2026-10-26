//! Per-vCPU exit statistics, kept the way KVM keeps `struct kvm_vcpu_stat`:
//! plain counters that the exit handler bumps in one place, for any guest,
//! and that no decision ever reads. `exit_decision::decide` says what an exit
//! is; these count what Aleph0 then did about it.
//!
//! Every stop prints them, before the exits by reason (`policy::Histogram`).
//! Once the test guest has finished, bring-up compares them with what that
//! guest does (`guest::expected_stats`), as a KVM selftest checks a vCPU's
//! statistics after its run.
//!
//! What was forwarded to Hyper-V, by call code and by MSR, is counted beside
//! them ([`Forwarded`]), so the counters bring-up compares and carries in an
//! error stay a few words.

use core::cell::UnsafeCell;
use core::fmt;

use crate::vmx::exit_decision::{Emulation, ExitEvent, ResumePlan};
use crate::vmx::hyperv;

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
    /// RDMSRs of the guest's MTRRs, answered from its copy.
    pub mtrr_read_exits: u64,
    /// WRMSRs of the guest's MTRRs, written to its copy.
    pub mtrr_write_exits: u64,
    /// INs executed for the guest.
    pub io_in_exits: u64,
    /// OUTs executed for the guest.
    pub io_out_exits: u64,
    /// HLTs the guest was resumed past.
    pub halt_exits: u64,
    /// NMIs injected into the guest.
    pub nmi_injections: u64,
    /// Exceptions injected into the guest (#GP, #UD), those Hyper-V raised
    /// for a forwarded access included.
    pub exception_injections: u64,
    /// Hypercalls forwarded to Hyper-V, refused ones included.
    pub hypercall_exits: u64,
    /// RDMSRs of synthetic MSRs forwarded to Hyper-V, refused ones included.
    pub synthetic_read_exits: u64,
    /// WRMSRs of synthetic MSRs forwarded to Hyper-V, refused ones included.
    pub synthetic_write_exits: u64,
}

impl VcpuStats {
    /// No exit yet.
    pub const ZERO: Self = Self {
        exits: 0,
        cpuid_exits: 0,
        msr_read_exits: 0,
        msr_write_exits: 0,
        mtrr_read_exits: 0,
        mtrr_write_exits: 0,
        io_in_exits: 0,
        io_out_exits: 0,
        halt_exits: 0,
        nmi_injections: 0,
        exception_injections: 0,
        hypercall_exits: 0,
        synthetic_read_exits: 0,
        synthetic_write_exits: 0,
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
            Some(Emulation::MtrrRead { .. }) => self.mtrr_read_exits += 1,
            Some(Emulation::MtrrWrite { .. }) => self.mtrr_write_exits += 1,
            Some(Emulation::In { .. }) => self.io_in_exits += 1,
            Some(Emulation::Out { .. }) => self.io_out_exits += 1,
            Some(Emulation::Hypercall { .. }) => self.hypercall_exits += 1,
            Some(Emulation::SyntheticRead { .. }) => self.synthetic_read_exits += 1,
            Some(Emulation::SyntheticWrite { .. }) => self.synthetic_write_exits += 1,
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
            mtrr_read_exits,
            mtrr_write_exits,
            io_in_exits,
            io_out_exits,
            halt_exits,
            nmi_injections,
            exception_injections,
            hypercall_exits,
            synthetic_read_exits,
            synthetic_write_exits,
        } = self;
        write!(
            f,
            "exits={exits} cpuid_exits={cpuid_exits} msr_read_exits={msr_read_exits} \
             msr_write_exits={msr_write_exits} mtrr_read_exits={mtrr_read_exits} \
             mtrr_write_exits={mtrr_write_exits} io_in_exits={io_in_exits} io_out_exits={io_out_exits} \
             halt_exits={halt_exits} nmi_injections={nmi_injections} exception_injections={exception_injections} \
             hypercall_exits={hypercall_exits} synthetic_read_exits={synthetic_read_exits} \
             synthetic_write_exits={synthetic_write_exits}"
        )
    }
}

/// What Aleph0 forwarded to Hyper-V at the exits it resumed from, refused
/// accesses included, as KVM's Hyper-V code counts hypercalls by code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Forwarded {
    /// Hypercalls by call code (RCX bits 15:0).
    pub hypercalls: Tally,
    /// RDMSRs of synthetic MSRs by MSR.
    pub synthetic_reads: Tally,
    /// WRMSRs of synthetic MSRs by MSR.
    pub synthetic_writes: Tally,
}

impl Forwarded {
    /// Nothing forwarded yet.
    pub const NONE: Self = Self {
        hypercalls: Tally::EMPTY,
        synthetic_reads: Tally::EMPTY,
        synthetic_writes: Tally::EMPTY,
    };

    /// Counts what a resumed exit's plan emulated (`emulate`), if it was
    /// forwarded to Hyper-V.
    pub fn count(&mut self, emulate: Option<Emulation>) {
        match emulate {
            Some(Emulation::Hypercall { input }) => self.hypercalls.count(hyperv::call_code(input).into()),
            Some(Emulation::SyntheticRead { msr }) => self.synthetic_reads.count(msr),
            Some(Emulation::SyntheticWrite { msr, .. }) => self.synthetic_writes.count(msr),
            _ => {}
        }
    }
}

/// Keys a [`Tally`] counts on their own.
pub const TALLY_KEYS: usize = 32;

/// Counts by key, a hypercall's call code or an MSR, for the first
/// [`TALLY_KEYS`] keys seen; later keys share [`Tally::other`]. The
/// firmware's VMBus drivers use a handful of call codes, and a guest with
/// the SynIC writes its 16 SINTx MSRs and a dozen more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tally {
    /// `(key, count)`, in the order first seen; the first `len` are used.
    keys: [(u32, u64); TALLY_KEYS],
    len: usize,
    /// Counts of the keys that found no slot.
    pub other: u64,
}

impl Tally {
    /// Nothing counted.
    pub const EMPTY: Self = Self {
        keys: [(0, 0); TALLY_KEYS],
        len: 0,
        other: 0,
    };

    /// Counts one more of `key`.
    pub fn count(&mut self, key: u32) {
        if let Some((_, count)) = self.keys[..self.len].iter_mut().find(|(seen, _)| *seen == key) {
            *count += 1;
        } else if self.len < TALLY_KEYS {
            self.keys[self.len] = (key, 1);
            self.len += 1;
        } else {
            self.other += 1;
        }
    }

    /// The keys counted, with their counts, in the order first seen.
    pub fn counts(&self) -> &[(u32, u64)] {
        &self.keys[..self.len]
    }
}

/// `0x5c=3 0x5d=1`, then `other=N` for the keys without a slot; `none` when
/// nothing was counted.
impl fmt::Display for Tally {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self == Self::EMPTY {
            return f.write_str("none");
        }
        let mut separator = "";
        for (key, count) in self.counts() {
            write!(f, "{separator}{key:#x}={count}")?;
            separator = " ";
        }
        if self.other > 0 {
            write!(f, "{separator}other={}", self.other)?;
        }
        Ok(())
    }
}

struct Stats<T>(UnsafeCell<T>);

// SAFETY: Aleph0 runs one vCPU on one CPU. Only the exit handler writes the
// statistics ([`update`], [`update_forwarded`]), with interrupts off, and
// the host NMI handler never touches them. They are read by that handler
// outside those calls, and by bring-up once the guest has stopped, when no
// exit handler runs.
unsafe impl<T> Sync for Stats<T> {}

static STATS: Stats<VcpuStats> = Stats(UnsafeCell::new(VcpuStats::ZERO));
static FORWARDED: Stats<Forwarded> = Stats(UnsafeCell::new(Forwarded::NONE));

/// Applies `update` to the statistics. For the exit handler only.
pub(super) fn update<R>(update: impl FnOnce(&mut VcpuStats) -> R) -> R {
    // SAFETY: the exit handler is the only writer, and no reader runs while
    // it writes (see `Stats`).
    update(unsafe { &mut *STATS.0.get() })
}

/// Applies `update` to what was forwarded. For the exit handler only.
pub(super) fn update_forwarded(update: impl FnOnce(&mut Forwarded)) {
    // SAFETY: as for `update`.
    update(unsafe { &mut *FORWARDED.0.get() })
}

/// The statistics as they stand.
pub fn snapshot() -> VcpuStats {
    // SAFETY: a reader runs only when the exit handler is not writing (see
    // `Stats`).
    unsafe { *STATS.0.get() }
}

/// What was forwarded so far.
pub fn forwarded() -> Forwarded {
    // SAFETY: as for `snapshot`.
    unsafe { *FORWARDED.0.get() }
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/vmexit/stats.rs"]
mod tests;
