//! What every stop prints about the guest after its exit's lines, so a stop
//! nobody planned for can be read without another run:
//!
//! 1. its state as the CPU saved it at the exit ([`GuestState::read`]), in
//!    the format bring-up printed before VMLAUNCH;
//! 2. its 15 general-purpose registers, from the frame the entry stub saved;
//! 3. its DR7, PAT and EFER, from wherever the controls leave them
//!    ([`saved_registers`]);
//! 4. the VMCS fields that explain an exit ([`DUMP_LINES`]): pending events,
//!    an injection Aleph0 queued, the exit's event, the guest addresses, and
//!    the controls.
//!
//! Every value comes from a VMREAD or an MSR read in exit context. A field
//! that cannot be read is printed as unreadable, and the dump goes on.

use core::fmt;

use super::{RegisterFrame, read_field};
use crate::vmx::guest_state::GuestState;
use crate::vmx::msr::{self, IA32_EFER, IA32_PAT};
use crate::vmx::vmcs::VmcsError;
use crate::vmx::vmcs::fields::{
    EXCEPTION_BITMAP, GUEST_ACTIVITY_STATE, GUEST_DR7, GUEST_IA32_EFER, GUEST_IA32_PAT, GUEST_INTERRUPTIBILITY_STATE,
    GUEST_LINEAR_ADDRESS, GUEST_PENDING_DEBUG_EXCEPTIONS, GUEST_PHYSICAL_ADDRESS, IDT_VECTORING_ERROR_CODE,
    IDT_VECTORING_INFO, PIN_BASED_VM_EXEC_CONTROL, PRIMARY_VM_EXEC_CONTROL, SECONDARY_VM_EXEC_CONTROL,
    VM_ENTRY_CONTROLS, VM_ENTRY_EXCEPTION_ERROR_CODE, VM_ENTRY_INTERRUPTION_INFO, VM_ENTRY_LOAD_IA32_EFER,
    VM_ENTRY_LOAD_IA32_PAT, VM_EXIT_CONTROLS, VM_EXIT_INTERRUPTION_ERROR_CODE, VM_EXIT_INTERRUPTION_INFO,
    VM_EXIT_LOAD_IA32_EFER, VM_EXIT_LOAD_IA32_PAT, VM_EXIT_SAVE_DEBUG_CONTROLS, VM_EXIT_SAVE_IA32_EFER,
    VM_EXIT_SAVE_IA32_PAT,
};

/// One line of the dump: a label and the VMCS fields it shows, by name.
#[derive(Debug, Clone, Copy)]
pub struct DumpLine {
    pub label: &'static str,
    pub fields: &'static [(&'static str, u32)],
}

/// The VMCS fields the dump prints besides the guest state, one line each.
pub const DUMP_LINES: [DumpLine; 5] = [
    DumpLine {
        label: "guest events",
        fields: &[
            ("interruptibility", GUEST_INTERRUPTIBILITY_STATE),
            ("activity", GUEST_ACTIVITY_STATE),
            ("pending_debug", GUEST_PENDING_DEBUG_EXCEPTIONS),
        ],
    },
    DumpLine {
        label: "queued injection",
        fields: &[
            ("info", VM_ENTRY_INTERRUPTION_INFO),
            ("error_code", VM_ENTRY_EXCEPTION_ERROR_CODE),
        ],
    },
    DumpLine {
        label: "exit event",
        fields: &[
            ("info", VM_EXIT_INTERRUPTION_INFO),
            ("error_code", VM_EXIT_INTERRUPTION_ERROR_CODE),
            ("idt_vectoring", IDT_VECTORING_INFO),
            ("idt_vectoring_error_code", IDT_VECTORING_ERROR_CODE),
        ],
    },
    DumpLine {
        label: "addresses",
        fields: &[
            ("guest_linear", GUEST_LINEAR_ADDRESS),
            ("guest_physical", GUEST_PHYSICAL_ADDRESS),
        ],
    },
    DumpLine {
        label: "controls",
        fields: &[
            ("pin", PIN_BASED_VM_EXEC_CONTROL),
            ("primary", PRIMARY_VM_EXEC_CONTROL),
            ("secondary", SECONDARY_VM_EXEC_CONTROL),
            ("exit", VM_EXIT_CONTROLS),
            ("entry", VM_ENTRY_CONTROLS),
            ("exception_bitmap", EXCEPTION_BITMAP),
        ],
    },
];

/// Fields on the longest [`DumpLine`].
const MAX_FIELDS: usize = 6;

/// A VMCS value for the dump: hexadecimal, or why it could not be read.
pub struct Value(pub Result<u64, VmcsError>);

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Ok(value) => write!(f, "{value:#x}"),
            Err(error) => write!(f, "unreadable ({error:?})"),
        }
    }
}

/// A [`DumpLine`] with the values read for its fields, as printed:
/// `label: name=0x.. name=0x..`. A value missing from `values` prints as
/// unreadable.
pub struct DumpValues<'a> {
    pub line: &'a DumpLine,
    pub values: &'a [Result<u64, VmcsError>],
}

impl fmt::Display for DumpValues<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.line.label)?;
        f.write_str(":")?;
        for (index, &(name, _)) in self.line.fields.iter().enumerate() {
            let value = self.values.get(index).copied().unwrap_or(Err(VmcsError::VmFailInvalid));
            write!(f, " {name}={}", Value(value))?;
        }
        Ok(())
    }
}

/// Where the guest's value of a register that VM exits may save can be
/// found after the exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// In this VMCS guest field: the exit controls saved it there.
    Vmcs(u32),
    /// In this MSR: neither entry nor exit switches it, so the CPU still
    /// holds the guest's value.
    Msr(u32),
    /// Nowhere: the exit loaded a value of its own without saving the
    /// guest's.
    NotSaved,
}

/// Where the guest's DR7, PAT and EFER are after an exit, from the VM-entry
/// controls (`entry`) and VM-exit controls (`exit`). Every exit sets DR7 to
/// 0x400, so the guest's DR7 is only in the VMCS, under "save debug
/// controls". PAT and EFER are in the VMCS under their save controls, still
/// in the MSR when no control loads them on entry or exit, and lost
/// otherwise.
pub fn saved_registers(entry: u64, exit: u64) -> [(&'static str, Source); 3] {
    let msr_source = |save: u64, field: u32, entry_load: u64, exit_load: u64, msr: u32| {
        if exit & save != 0 {
            Source::Vmcs(field)
        } else if entry & entry_load == 0 && exit & exit_load == 0 {
            Source::Msr(msr)
        } else {
            Source::NotSaved
        }
    };
    [
        (
            "dr7",
            if exit & VM_EXIT_SAVE_DEBUG_CONTROLS != 0 {
                Source::Vmcs(GUEST_DR7)
            } else {
                Source::NotSaved
            },
        ),
        (
            "pat",
            msr_source(
                VM_EXIT_SAVE_IA32_PAT,
                GUEST_IA32_PAT,
                VM_ENTRY_LOAD_IA32_PAT,
                VM_EXIT_LOAD_IA32_PAT,
                IA32_PAT,
            ),
        ),
        (
            "efer",
            msr_source(
                VM_EXIT_SAVE_IA32_EFER,
                GUEST_IA32_EFER,
                VM_ENTRY_LOAD_IA32_EFER,
                VM_EXIT_LOAD_IA32_EFER,
                IA32_EFER,
            ),
        ),
    ]
}

/// Prints the dump for the stop at exit `number`, with the guest's
/// general-purpose registers from `frame`.
pub(super) fn report_guest(number: u64, frame: &RegisterFrame) {
    let tag = crate::TAG;
    // SAFETY: exit context: VMX root operation, with the guest's VMCS
    // current.
    match unsafe { GuestState::read() } {
        Ok(state) => state.report(format_args!("VM exit #{number}: guest")),
        Err(error) => crate::serial_println!("{tag} VM exit #{number}: guest state unreadable ({error:?})"),
    }
    report_registers(number, frame);
    report_saved_registers(number);
    for line in &DUMP_LINES {
        let mut values = [Err(VmcsError::VmFailInvalid); MAX_FIELDS];
        for (value, &(_, field)) in values.iter_mut().zip(line.fields) {
            *value = read_field(field);
        }
        let values = &values[..line.fields.len()];
        crate::serial_println!("{tag} VM exit #{number}: {}", DumpValues { line, values });
    }
}

/// Prints the 15 general-purpose registers in `frame`, four to a line.
fn report_registers(number: u64, frame: &RegisterFrame) {
    let tag = crate::TAG;
    let RegisterFrame {
        rax,
        rbx,
        rcx,
        rdx,
        rsi,
        rdi,
        rbp,
        r8,
        r9,
        r10,
        r11,
        r12,
        r13,
        r14,
        r15,
    } = *frame;
    crate::serial_println!(
        "{tag} VM exit #{number}: guest rax={rax:#018x} rbx={rbx:#018x} rcx={rcx:#018x} rdx={rdx:#018x}"
    );
    crate::serial_println!(
        "{tag} VM exit #{number}: guest rsi={rsi:#018x} rdi={rdi:#018x} rbp={rbp:#018x} r8={r8:#018x}"
    );
    crate::serial_println!(
        "{tag} VM exit #{number}: guest r9={r9:#018x} r10={r10:#018x} r11={r11:#018x} r12={r12:#018x}"
    );
    crate::serial_println!("{tag} VM exit #{number}: guest r13={r13:#018x} r14={r14:#018x} r15={r15:#018x}");
}

/// Prints the guest's DR7, PAT and EFER from wherever [`saved_registers`]
/// finds them.
fn report_saved_registers(number: u64) {
    let tag = crate::TAG;
    let (Ok(entry), Ok(exit)) = (read_field(VM_ENTRY_CONTROLS), read_field(VM_EXIT_CONTROLS)) else {
        crate::serial_println!("{tag} VM exit #{number}: guest dr7/pat/efer: controls unreadable");
        return;
    };
    crate::serial_print!("{tag} VM exit #{number}: guest");
    for (name, source) in saved_registers(entry, exit) {
        match source {
            Source::Vmcs(field) => crate::serial_print!(" {name}={} (VMCS)", Value(read_field(field))),
            Source::Msr(msr) => {
                // SAFETY: IA32_PAT and IA32_EFER exist on every 64-bit CPU,
                // and reading them has no side effects.
                let value = unsafe { msr::rdmsr(msr) };
                crate::serial_print!(" {name}={value:#x} (MSR, not switched)");
            }
            Source::NotSaved => crate::serial_print!(" {name}=not saved"),
        }
    }
    crate::serial_println!();
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/vmexit/dump.rs"]
mod tests;
