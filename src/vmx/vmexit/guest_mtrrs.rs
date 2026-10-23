//! The guest's MTRRs: the copy its RDMSR and WRMSR of an MTRR MSR reach
//! instead of the CPU's, and the EPT memory types that follow it.
//!
//! With EPT on, the MTRRs no longer set the memory types of guest accesses:
//! the EPT entries do (`docs/MTRR.md`). They still set those of Aleph0's own
//! accesses in root operation, so a guest that wrote them could make
//! Aleph0's code, data or stacks UC or WP. So the guest never writes them.
//! The MSR bitmap intercepts every MTRR MSR (`exit_bitmaps`), RDMSR reads
//! this copy, and WRMSR writes it, after which EPT takes the types the copy
//! gives (`ept::TypeTables`). KVM keeps the same per vCPU
//! (`vcpu->arch.mtrr_state`).
//!
//! Like the statistics (`stats.rs`), this is exit-handler state. Bring-up
//! publishes it before VMLAUNCH, starting as the CPU's own MTRRs; from then
//! on only the exit handler touches it, until the guest has stopped.

use core::cell::UnsafeCell;
use core::fmt;

use crate::vmx::ept::{InveptType, Retyped, TypeTables};
use crate::vmx::instruction::VmxFail;
use crate::vmx::mtrr::{MtrrCapabilities, MtrrError, MtrrMsr, MtrrRegisters, MtrrState, Mtrrs};

/// The guest's MTRRs, and the EPT tables whose memory types follow them.
struct GuestMtrrs {
    state: MtrrState,
    types: TypeTables,
}

struct Cell(UnsafeCell<Option<GuestMtrrs>>);

// SAFETY: Aleph0 runs one vCPU on one CPU. Bring-up writes the cell
// ([`publish`]) before the guest runs; then only the exit handler uses it,
// with interrupts off, and the host NMI handler never touches it; bring-up
// reads it again once the guest has stopped. Nobody keeps a reference past
// the call that made it ([`with`]).
unsafe impl Sync for Cell {}

static GUEST_MTRRS: Cell = Cell(UnsafeCell::new(None));

/// Gives the exit handler the guest's MTRRs, starting as `state` (the
/// CPU's), and `types`, the EPT tables whose memory types follow them. For
/// bring-up, before VMLAUNCH. `types` comes from the one `Ept::build`, so
/// there is only ever one guest to publish.
pub fn publish(state: MtrrState, types: TypeTables) {
    // SAFETY: no exit handler runs before VMLAUNCH (see `Cell`).
    unsafe { *GUEST_MTRRS.0.get() = Some(GuestMtrrs { state, types }) };
}

/// Calls `f` with the guest's MTRRs, or returns `None` before [`publish`].
fn with<R>(f: impl FnOnce(&mut GuestMtrrs) -> R) -> Option<R> {
    // SAFETY: bring-up and the exit handler never run at the same time,
    // and the reference does not outlive `f` (see `Cell`).
    unsafe { (*GUEST_MTRRS.0.get()).as_mut().map(f) }
}

/// The guest's MTRR MSRs, for `decide`: [`MtrrCapabilities::NONE`] before
/// [`publish`], so none of them is routed to the copy.
pub(super) fn capabilities() -> MtrrCapabilities {
    with(|guest| guest.state.registers().capabilities()).unwrap_or(MtrrCapabilities::NONE)
}

/// The guest's MTRR MSRs as they stand, or `None` before [`publish`]. For
/// bring-up, once the guest has stopped.
pub fn registers() -> Option<MtrrRegisters> {
    with(|guest| guest.state.registers().clone())
}

/// What RDMSR of `msr` returns the guest: its copy's value.
pub(super) fn read(msr: MtrrMsr) -> Result<u64, MtrrAccessFailure> {
    with(|guest| guest.state.registers().get(msr)).ok_or(MtrrAccessFailure::NotPublished)
}

/// What a guest WRMSR of an MTRR came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MtrrWrite {
    /// What changed in EPT, or `None` when every address keeps the type it
    /// had, so EPT was left alone.
    pub(super) retyped: Option<Retyped>,
    /// The INVEPT run once EPT changed.
    pub(super) invept: Option<InveptType>,
}

/// Why an access to the guest's MTRRs failed. None of these should happen:
/// `decide` routes an MSR to the copy only once it is published, and checks
/// a written value first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MtrrAccessFailure {
    /// Bring-up never published the guest's MTRRs.
    NotPublished,
    /// The copy refused the value.
    Refused(MtrrError),
    /// INVEPT failed after EPT took the new types.
    Invept(VmxFail),
}

impl fmt::Display for MtrrAccessFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPublished => f.write_str("the guest's MTRRs were never set up"),
            Self::Refused(error) => write!(f, "the guest's MTRRs refused the write ({error})"),
            Self::Invept(error) => write!(f, "EPT took the guest's MTRR types, but INVEPT failed ({error:?})"),
        }
    }
}

/// WRMSR of `value` to the guest's `msr`: into its copy, never the CPU's.
/// If that changes the type of any address, EPT takes the new types, and
/// INVEPT drops the translations made with the old ones.
///
/// # Safety
///
/// Exit context: VMX root operation, with the guest stopped at an exit.
pub(super) unsafe fn write(msr: MtrrMsr, value: u64) -> Result<MtrrWrite, MtrrAccessFailure> {
    with(|guest| {
        let changed = guest.state.write(msr, value).map_err(MtrrAccessFailure::Refused)?;
        if !changed {
            return Ok(MtrrWrite {
                retyped: None,
                invept: None,
            });
        }
        // SAFETY: the caller guarantees exit context, and `types` came from
        // `Ept::build`, whose tables are never freed.
        let retyped = unsafe { guest.types.apply(guest.state.mtrrs()) }.map_err(MtrrAccessFailure::Invept)?;
        Ok(MtrrWrite {
            retyped: Some(retyped),
            invept: retyped.changed().then(|| guest.types.invept()),
        })
    })
    .unwrap_or(Err(MtrrAccessFailure::NotPublished))
}

/// Calls `f` with the memory types the guest's MTRRs give and the EPT
/// tables that carry them, for the exit handler's report. `None` before
/// [`publish`].
pub(super) fn inspect<R>(f: impl FnOnce(&Mtrrs, &TypeTables) -> R) -> Option<R> {
    with(|guest| f(guest.state.mtrrs(), &guest.types))
}
