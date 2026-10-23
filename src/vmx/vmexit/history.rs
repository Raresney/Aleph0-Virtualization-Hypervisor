//! The last VM exits, kept to show what led to a stop or a panic.
//!
//! An exit printed in full shows only itself, and past the print policy's
//! limit most exits are not printed at all (`policy.rs`). So the exit handler
//! records every exit in a ring of the last [`HISTORY_LEN`]: what it read
//! (no VMREAD is added for this) and what `decide` made of it. Every stop
//! prints the ring oldest first, after the dump, and so does the panic
//! handler, after its message.

use core::cell::UnsafeCell;
use core::fmt;

use crate::vmx::exit_decision::{ExitEvent, ExitReason, exit_reason_name};

/// Exits the history keeps.
pub const HISTORY_LEN: usize = 64;

/// The last `N` items pushed; once it is full, each push overwrites the
/// oldest.
pub struct Ring<T, const N: usize> {
    items: [T; N],
    /// Items pushed so far, kept or not.
    pushed: u64,
}

impl<T: Copy, const N: usize> Ring<T, N> {
    /// An empty ring. `filler` only fills the slots nothing was pushed to,
    /// which are never read.
    pub const fn new(filler: T) -> Self {
        const { assert!(N > 0) };
        Self {
            items: [filler; N],
            pushed: 0,
        }
    }

    /// Adds `item`, overwriting the oldest once the ring is full.
    pub fn push(&mut self, item: T) {
        self.items[(self.pushed % N as u64) as usize] = item;
        self.pushed += 1;
    }

    /// How many items the ring holds: the pushed ones, up to `N`.
    pub fn kept(&self) -> usize {
        self.pushed.min(N as u64) as usize
    }

    /// How many pushed items are no longer kept.
    pub fn overwritten(&self) -> u64 {
        self.pushed.saturating_sub(N as u64)
    }

    /// The kept items, oldest first.
    pub fn oldest_first(&self) -> impl Iterator<Item = &T> {
        // Once items were overwritten, the oldest kept one is where the next
        // push will go.
        let start = if self.overwritten() > 0 {
            (self.pushed % N as u64) as usize
        } else {
            0
        };
        (0..self.kept()).map(move |index| &self.items[(start + index) % N])
    }
}

/// One exit, as the history keeps it. `None` marks a VMCS field that could
/// not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitRecord {
    pub number: u64,
    /// VM_EXIT_REASON.
    pub reason: Option<u32>,
    pub qualification: Option<u64>,
    pub rip: Option<u64>,
    pub length: Option<u64>,
    /// VM_EXIT_INTERRUPTION_INFO.
    pub interruption_info: Option<u32>,
    /// IDT_VECTORING_INFO.
    pub idt_vectoring_info: Option<u32>,
    /// RAX, RBX, RCX and RDX at the exit.
    pub registers: [u64; 4],
    /// What `decide` made of the exit.
    pub event: ExitEvent,
}

impl ExitRecord {
    /// Fills the slots of an empty history.
    const EMPTY: Self = Self {
        number: 0,
        reason: None,
        qualification: None,
        rip: None,
        length: None,
        interruption_info: None,
        idt_vectoring_info: None,
        registers: [0; 4],
        event: ExitEvent::Unexpected,
    };
}

/// A field of a record, or `?` when it could not be read.
struct Field {
    value: Option<u64>,
    /// Hexadecimal; decimal otherwise, for a count.
    hex: bool,
}

/// `value` in hexadecimal.
fn hex(value: Option<u64>) -> Field {
    Field { value, hex: true }
}

/// `value`, a count, in decimal.
fn decimal(value: Option<u64>) -> Field {
    Field { value, hex: false }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.value {
            Some(value) if self.hex => write!(f, "{value:#x}"),
            Some(value) => write!(f, "{value}"),
            None => f.write_str("?"),
        }
    }
}

impl fmt::Display for ExitRecord {
    /// One line: `#3 reason=32 (WRMSR) rip=0x7eae1028 len=2 qual=0x0
    /// info=0x0 vectoring=0x0 rax=0x0 rbx=0x20800 rcx=0xc0000102
    /// rdx=0x7a1e -> Emulated(Wrmsr { .. })`, the event in hexadecimal.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{} ", self.number)?;
        match self.reason.map(ExitReason::from_raw) {
            Some(reason) => write!(
                f,
                "reason={} ({}){}",
                reason.basic,
                exit_reason_name(reason.basic),
                if reason.entry_failure { " [entry failed]" } else { "" },
            )?,
            None => f.write_str("reason=?")?,
        }
        let [rax, rbx, rcx, rdx] = self.registers;
        write!(
            f,
            " rip={} len={} qual={} info={} vectoring={} rax={rax:#x} rbx={rbx:#x} rcx={rcx:#x} rdx={rdx:#x} -> {:x?}",
            hex(self.rip),
            decimal(self.length),
            hex(self.qualification),
            hex(self.interruption_info.map(u64::from)),
            hex(self.idt_vectoring_info.map(u64::from)),
            self.event,
        )
    }
}

/// The history, in a cell the exit handler writes through a shared static.
struct History(UnsafeCell<Ring<ExitRecord, HISTORY_LEN>>);

// SAFETY: Aleph0 runs on one CPU. Only the exit handler writes the history
// ([`record`]), with interrupts off, and the host NMI handler never touches
// it. It is read by the same exit handler at a stop, after its last write,
// and by the panic handler, which runs on that CPU after the code that
// panicked: `record` itself cannot panic, so no reader sees half a record.
unsafe impl Sync for History {}

static HISTORY: History = History(UnsafeCell::new(Ring::new(ExitRecord::EMPTY)));

/// Adds `record` to the history. For the exit handler only.
pub(super) fn record(record: ExitRecord) {
    // SAFETY: the exit handler is the only writer, and no reader runs while
    // it writes (see `History`).
    unsafe { (*HISTORY.0.get()).push(record) };
}

/// Prints the history oldest first, each line after `context` (`VM exit
/// #13`, or `PANIC`). Prints nothing before the first exit.
pub fn report(context: fmt::Arguments<'_>) {
    // SAFETY: a reader runs only when the exit handler is not writing (see
    // `History`).
    let history = unsafe { &*HISTORY.0.get() };
    if history.kept() == 0 {
        return;
    }
    let tag = crate::TAG;
    crate::serial_println!(
        "{tag} {context}: the last {} exits, oldest first ({} older not kept):",
        history.kept(),
        history.overwritten(),
    );
    for record in history.oldest_first() {
        crate::serial_println!("{tag} {context}:   {record}");
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/vmexit/history.rs"]
mod tests;
