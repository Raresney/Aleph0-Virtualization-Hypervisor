//! Unit tests for `src/vmx/vmexit/dump.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;
use std::collections::HashSet;

/// The VM-exit controls of the Hyper-V runs: the required bits
/// (`0x00036ffb`, which include "host address-space size"). No save or load
/// control for DR7, PAT or EFER is among them.
const HYPER_V_EXIT: u64 = 0x0003_6ffb;
/// The VM-entry controls of the Hyper-V runs: the required bits
/// (`0x000011fb`) and "IA-32e mode guest" (bit 9).
const HYPER_V_ENTRY: u64 = 0x0000_11fb | (1 << 9);

#[test]
fn every_dumped_field_appears_once() {
    let encodings: Vec<u32> = DUMP_LINES
        .iter()
        .flat_map(|line| line.fields)
        .map(|&(_, field)| field)
        .collect();
    let unique: HashSet<u32> = encodings.iter().copied().collect();
    assert_eq!(unique.len(), encodings.len(), "a VMCS field is dumped twice");
}

#[test]
fn every_dump_line_names_its_fields_apart() {
    for line in &DUMP_LINES {
        let names: HashSet<&str> = line.fields.iter().map(|&(name, _)| name).collect();
        assert_eq!(names.len(), line.fields.len(), "line {}", line.label);
        assert!(line.fields.len() <= MAX_FIELDS, "line {}", line.label);
    }
}

#[test]
fn the_dump_includes_the_new_error_code_fields() {
    let encodings: HashSet<u32> = DUMP_LINES
        .iter()
        .flat_map(|line| line.fields)
        .map(|&(_, field)| field)
        .collect();
    assert!(encodings.contains(&0x4406), "VM-exit interruption error code");
    assert!(encodings.contains(&0x440A), "IDT-vectoring error code");
}

#[test]
fn under_hyper_v_dr7_is_lost_and_pat_and_efer_are_still_in_their_msrs() {
    assert_eq!(
        saved_registers(HYPER_V_ENTRY, HYPER_V_EXIT),
        [
            ("dr7", Source::NotSaved),
            ("pat", Source::Msr(IA32_PAT)),
            ("efer", Source::Msr(IA32_EFER)),
        ]
    );
}

#[test]
fn the_save_controls_put_the_registers_in_the_vmcs() {
    let saving = HYPER_V_EXIT | VM_EXIT_SAVE_DEBUG_CONTROLS | VM_EXIT_SAVE_IA32_PAT | VM_EXIT_SAVE_IA32_EFER;
    assert_eq!(
        saved_registers(HYPER_V_ENTRY, saving),
        [
            ("dr7", Source::Vmcs(GUEST_DR7)),
            ("pat", Source::Vmcs(GUEST_IA32_PAT)),
            ("efer", Source::Vmcs(GUEST_IA32_EFER)),
        ]
    );
}

#[test]
fn a_register_loaded_on_entry_or_exit_but_not_saved_is_lost() {
    let entry_loads_pat = HYPER_V_ENTRY | VM_ENTRY_LOAD_IA32_PAT;
    assert_eq!(
        saved_registers(entry_loads_pat, HYPER_V_EXIT)[1],
        ("pat", Source::NotSaved)
    );
    let exit_loads_efer = HYPER_V_EXIT | VM_EXIT_LOAD_IA32_EFER;
    assert_eq!(
        saved_registers(HYPER_V_ENTRY, exit_loads_efer)[2],
        ("efer", Source::NotSaved)
    );
}

#[test]
fn a_dump_line_prints_each_field_by_name() {
    let line = &DUMP_LINES[1];
    let values = [Ok(0x8000_0b0e), Err(VmcsError::VmFailValid)];
    assert_eq!(
        DumpValues { line, values: &values }.to_string(),
        "queued injection: info=0x80000b0e error_code=unreadable (VmFailValid)"
    );
}

#[test]
fn a_dump_line_with_too_few_values_prints_the_rest_as_unreadable() {
    let line = &DUMP_LINES[3];
    let values = [Ok(0x7eae_2000)];
    assert_eq!(
        DumpValues { line, values: &values }.to_string(),
        "addresses: guest_linear=0x7eae2000 guest_physical=unreadable (VmFailInvalid)"
    );
}
