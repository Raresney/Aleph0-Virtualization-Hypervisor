//! Unit tests for `src/vmx/ept/walk.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use std::collections::HashMap;

use super::super::level::{Pd, Pdpt, Pml4, Pt};
use super::super::{EPT_RWX, EptEntry};
use super::*;
use crate::vmx::mtrr::MemoryType::{Uncacheable as UC, WriteBack as WB};

/// The Hyper-V test VM's rules: MAXPHYADDR 46, 1 GiB pages, and
/// execute-only pages (IA32_VMX_EPT_VPID_CAP `0x00000f0106f34041`, bit 0).
const HYPER_V: EntryRules = EntryRules {
    physical_address_bits: 46,
    huge_pages: true,
    execute_only: true,
};

/// [`HYPER_V`] on a CPU without 1 GiB or execute-only pages.
const BASIC: EntryRules = EntryRules {
    huge_pages: false,
    execute_only: false,
    ..HYPER_V
};

const ALL_LEVELS: [WalkLevel; 4] = [WalkLevel::Pml4, WalkLevel::Pdpt, WalkLevel::Pd, WalkLevel::Pt];

#[test]
fn every_entry_ept_build_makes_is_valid() {
    let table = EptEntry::<Pml4>::table(0x7eaa_9000).raw;
    for level in [WalkLevel::Pml4, WalkLevel::Pdpt, WalkLevel::Pd] {
        assert!(check_entry(table, level, HYPER_V).is_empty(), "{level:?}");
    }
    for memory_type in [UC, WB] {
        let huge = EptEntry::<Pdpt>::huge_page(3 << 30, memory_type).raw;
        assert!(check_entry(huge, WalkLevel::Pdpt, HYPER_V).is_empty());
        let large = EptEntry::<Pd>::large_page(0x7ec0_0000, memory_type).raw;
        assert!(check_entry(large, WalkLevel::Pd, HYPER_V).is_empty());
        for access in [EPT_RWX, EPT_READ, EPT_READ | EPT_WRITE] {
            let page = EptEntry::<Pt>::page(0x7eab_0000, access, memory_type).raw;
            assert!(check_entry(page, WalkLevel::Pt, HYPER_V).is_empty());
        }
    }
}

#[test]
fn an_entry_that_is_not_present_is_never_misconfigured() {
    // R = W = X = 0 is an EPT violation if a walk reaches it, whatever else
    // the entry holds.
    for raw in [0, 0xFFFF_FFFF_FFFF_FFF8, 1 << 51 | 0x7 << 3] {
        for level in ALL_LEVELS {
            assert!(check_entry(raw, level, BASIC).is_empty(), "{raw:#x} at {level:?}");
        }
    }
}

#[test]
fn address_bits_from_maxphyaddr_up_to_51_are_reserved_at_every_level() {
    let page = EptEntry::<Pt>::page(0x1000, EPT_RWX, WB).raw;
    for level in ALL_LEVELS {
        let raw = if level == WalkLevel::Pt {
            page
        } else {
            EptEntry::<Pml4>::table(0x1000).raw
        };
        assert_eq!(check_entry(raw | 1 << 46, level, HYPER_V).reserved_bits, 1 << 46);
        assert_eq!(check_entry(raw | 1 << 51, level, HYPER_V).reserved_bits, 1 << 51);
        assert_eq!(check_entry(raw | 1 << 45, level, HYPER_V).reserved_bits, 0);
    }
    // MAXPHYADDR 52: no address bit is reserved; 62:52 are ignored anyway.
    let rules = EntryRules {
        physical_address_bits: 52,
        ..HYPER_V
    };
    assert!(check_entry(page | 1 << 51 | 1 << 60, WalkLevel::Pt, rules).is_empty());
}

#[test]
fn a_pml4_entry_has_no_memory_type_ipat_or_page_size() {
    let table = EptEntry::<Pml4>::table(0x1000).raw;
    assert_eq!(
        check_entry(table | 6 << 3, WalkLevel::Pml4, HYPER_V).reserved_bits,
        0x30
    );
    assert_eq!(
        check_entry(table | 1 << 6, WalkLevel::Pml4, HYPER_V).reserved_bits,
        0x40
    );
    // Bit 7 makes no 512 GiB page: it is reserved.
    assert_eq!(
        check_entry(table | 1 << 7, WalkLevel::Pml4, HYPER_V).reserved_bits,
        0x80
    );
}

#[test]
fn a_pointer_to_a_table_has_no_memory_type_or_ipat() {
    let table = EptEntry::<Pdpt>::table(0x2000).raw;
    for level in [WalkLevel::Pdpt, WalkLevel::Pd] {
        let faults = check_entry(table | 6 << 3 | 1 << 6, level, HYPER_V);
        assert_eq!(faults.reserved_bits, 0x70, "{level:?}");
        // The type bits are reserved bits here, not a memory type.
        assert_eq!(faults.reserved_memory_type, None);
    }
}

#[test]
fn a_large_page_keeps_its_address_bits_below_its_alignment_clear() {
    let huge = EptEntry::<Pdpt>::huge_page(1 << 30, UC).raw;
    assert_eq!(
        check_entry(huge | 0x1000, WalkLevel::Pdpt, HYPER_V).reserved_bits,
        0x1000
    );
    assert_eq!(
        check_entry(huge | 1 << 29, WalkLevel::Pdpt, HYPER_V).reserved_bits,
        1 << 29
    );
    let large = EptEntry::<Pd>::large_page(1 << 21, WB).raw;
    assert_eq!(
        check_entry(large | 1 << 20, WalkLevel::Pd, HYPER_V).reserved_bits,
        1 << 20
    );
    // Bit 21 is the 2 MiB page's own address.
    assert!(check_entry(large | 1 << 22, WalkLevel::Pd, HYPER_V).is_empty());
}

#[test]
fn a_1_gib_page_is_reserved_on_a_cpu_without_them() {
    let huge = EptEntry::<Pdpt>::huge_page(1 << 30, UC).raw;
    assert_eq!(check_entry(huge, WalkLevel::Pdpt, BASIC).reserved_bits, 1 << 7);
}

#[test]
fn a_pt_entry_may_set_ipat_and_ignores_bit_7() {
    let page = EptEntry::<Pt>::page(0x5000, EPT_RWX, WB).raw;
    assert!(check_entry(page | 1 << 6 | 1 << 7, WalkLevel::Pt, BASIC).is_empty());
}

#[test]
fn write_without_read_is_refused_at_every_level() {
    for access in [EPT_WRITE, EPT_WRITE | EPT_EXECUTE] {
        for level in ALL_LEVELS {
            let raw = 0x1000 | access;
            assert_eq!(
                check_entry(raw, level, HYPER_V).bad_access,
                Some(BadAccess::WriteWithoutRead),
                "{raw:#x} at {level:?}"
            );
        }
    }
}

#[test]
fn execute_only_is_refused_only_on_a_cpu_without_it() {
    let raw = 0x5000 | EPT_EXECUTE | (WB.raw() << 3);
    assert_eq!(
        check_entry(raw, WalkLevel::Pt, BASIC).bad_access,
        Some(BadAccess::ExecuteOnly)
    );
    assert!(check_entry(raw, WalkLevel::Pt, HYPER_V).is_empty());
}

#[test]
fn a_page_of_a_reserved_memory_type_is_refused() {
    for memory_type in [2, 3, 7] {
        let page = 0x5000 | EPT_RWX | memory_type << 3;
        let faults = check_entry(page, WalkLevel::Pt, HYPER_V);
        assert_eq!(faults.reserved_memory_type, Some(memory_type as u8));
        assert_eq!(faults.reserved_bits, 0);
        let large = (1 << 21) | EPT_RWX | memory_type << 3 | 1 << 7;
        assert_eq!(
            check_entry(large, WalkLevel::Pd, HYPER_V).reserved_memory_type,
            Some(memory_type as u8)
        );
    }
}

#[test]
fn faults_print_what_the_cpu_refuses() {
    assert_eq!(EntryFaults::default().to_string(), "ok");
    let table = EptEntry::<Pml4>::table(0x1000).raw;
    assert_eq!(
        check_entry((table & !EPT_READ) | 1 << 7, WalkLevel::Pml4, BASIC).to_string(),
        "reserved bits 0x80 set; write without read"
    );
    assert_eq!(
        check_entry(0x5000 | EPT_EXECUTE | 2 << 3, WalkLevel::Pt, BASIC).to_string(),
        "execute-only, which this CPU does not allow; reserved memory type 2"
    );
}

/// Physical memory for the walk: the table pages at `tables`, holding the
/// entries in `entries` and 0 everywhere else. An address outside every
/// table page reads as `None`, as `TypeTables::walk` reads it.
struct Memory {
    tables: Vec<u64>,
    entries: HashMap<u64, u64>,
}

impl Memory {
    fn read(&self, address: u64) -> Option<u64> {
        self.tables
            .iter()
            .any(|&table| (table..table + 0x1000).contains(&address))
            .then(|| self.entries.get(&address).copied().unwrap_or(0))
    }
}

/// The PML4, PDPT, PD and PT of [`memory`].
const PML4: u64 = 0x1000;
const PDPT: u64 = 0x2000;
const PD: u64 = 0x3000;
const PT: u64 = 0x4000;

/// A small map in four table pages:
///
/// - GiB 0 through a PD: its first 2 MiB through a PT, whose entry 5 maps
///   the page at 0x5000 read-only and WB; then a 2 MiB WB page;
/// - GiB 3 a 1 GiB UC page, as the Local APIC's is.
fn memory() -> Memory {
    let entries = HashMap::from([
        (PML4, EptEntry::<Pml4>::table(PDPT).raw),
        (PDPT, EptEntry::<Pdpt>::table(PD).raw),
        (PDPT + 3 * 8, EptEntry::<Pdpt>::huge_page(3 << 30, UC).raw),
        (PD, EptEntry::<Pd>::table(PT).raw),
        (PD + 8, EptEntry::<Pd>::large_page(1 << 21, WB).raw),
        (PT + 5 * 8, EptEntry::<Pt>::page(0x5000, EPT_READ, WB).raw),
    ]);
    Memory {
        tables: vec![PML4, PDPT, PD, PT],
        entries,
    }
}

fn walk_in(memory: &Memory, gpa: u64, rules: EntryRules) -> EptWalk {
    walk(Eptp::new(PML4), gpa, rules, |address| memory.read(address))
}

/// What a walk read: each entry's level, index and address.
fn path(walk: &EptWalk) -> Vec<(WalkLevel, usize, u64)> {
    walk.entries()
        .map(|entry| (entry.level, entry.index, entry.address))
        .collect()
}

#[test]
fn a_4_kib_page_is_reached_through_all_four_levels() {
    let walk = walk_in(&memory(), 0x5123, HYPER_V);
    assert_eq!(
        path(&walk),
        [
            (WalkLevel::Pml4, 0, PML4),
            (WalkLevel::Pdpt, 0, PDPT),
            (WalkLevel::Pd, 0, PD),
            (WalkLevel::Pt, 5, PT + 5 * 8),
        ]
    );
    assert_eq!(
        walk.end,
        WalkEnd::Mapped {
            hpa: 0x5123,
            size: 0x1000,
            access: EPT_READ,
            memory_type: WB,
        }
    );
    assert!(walk.entries().all(|entry| entry.faults.is_empty()));
}

#[test]
fn a_2_mib_and_a_1_gib_page_end_the_walk_early() {
    let memory = memory();
    let large = walk_in(&memory, 0x2F_ABCD, HYPER_V);
    assert_eq!(path(&large).len(), 3);
    assert_eq!(
        large.end,
        WalkEnd::Mapped {
            hpa: 0x2F_ABCD,
            size: 1 << 21,
            access: EPT_RWX,
            memory_type: WB,
        }
    );
    let lapic = walk_in(&memory, 0xFEE0_0030, HYPER_V);
    assert_eq!(
        path(&lapic),
        [(WalkLevel::Pml4, 0, PML4), (WalkLevel::Pdpt, 3, PDPT + 3 * 8)]
    );
    assert_eq!(
        lapic.end,
        WalkEnd::Mapped {
            hpa: 0xFEE0_0030,
            size: 1 << 30,
            access: EPT_RWX,
            memory_type: UC,
        }
    );
    assert_eq!(
        lapic.end.to_string(),
        "mapped to HPA 0xfee00030 by a 1 GiB page, UC, R=1 W=1 X=1"
    );
}

#[test]
fn an_entry_not_present_ends_the_walk() {
    let memory = memory();
    // GiB 1: PDPT entry 1 is 0.
    let walk = walk_in(&memory, 1 << 30, HYPER_V);
    assert_eq!(
        path(&walk),
        [(WalkLevel::Pml4, 0, PML4), (WalkLevel::Pdpt, 1, PDPT + 8)]
    );
    assert_eq!(walk.end, WalkEnd::NotPresent);
    // Past the map: PML4 entry 1 is 0.
    assert_eq!(walk_in(&memory, 1 << 39, HYPER_V).end, WalkEnd::NotPresent);
}

#[test]
fn the_walk_stops_at_the_entry_the_cpu_refuses_and_names_what() {
    let mut memory = memory();
    // PD entry 2: W without R, the classic misconfiguration.
    memory
        .entries
        .insert(PD + 2 * 8, EptEntry::<Pd>::large_page(2 << 21, WB).raw & !EPT_READ);
    let walk = walk_in(&memory, (2 << 21) + 0x10, HYPER_V);
    assert_eq!(walk.end, WalkEnd::Misconfigured);
    let last = walk.entries().last().unwrap();
    assert_eq!((last.level, last.index), (WalkLevel::Pd, 2));
    assert_eq!(last.faults.bad_access, Some(BadAccess::WriteWithoutRead));
    // A 1 GiB page on a CPU without them.
    let walk = walk_in(&memory, 0xFEE0_0000, BASIC);
    assert_eq!(walk.end, WalkEnd::Misconfigured);
    assert_eq!(walk.entries().last().unwrap().faults.reserved_bits, 1 << 7);
}

#[test]
fn a_pointer_outside_the_tables_is_reported_and_not_followed() {
    let mut memory = memory();
    // PD entry 3 points to 0x9000, which is no table.
    memory.entries.insert(PD + 3 * 8, EptEntry::<Pd>::table(0x9000).raw);
    let followed = walk_in(&memory, 3 << 21, HYPER_V);
    assert_eq!(followed.end, WalkEnd::OutsideTables { table: 0x9000 });
    assert_eq!(path(&followed).len(), 3);
    // An EPTP that names no table: nothing is read.
    let rootless = walk(Eptp::new(0x8000), 0x5000, HYPER_V, |address| memory.read(address));
    assert_eq!(rootless.end, WalkEnd::OutsideTables { table: 0x8000 });
    assert_eq!(rootless.entries().count(), 0);
    assert_eq!(
        rootless.end.to_string(),
        "points to 0x8000, none of Aleph0's EPT tables: not followed"
    );
}

#[test]
fn levels_name_and_index_like_the_typed_levels() {
    let gpa = (3 << 39) | (5 << 30) | (7 << 21) | (9 << 12);
    assert_eq!(ALL_LEVELS.map(|level| level.index(gpa)), [3, 5, 7, 9]);
    assert_eq!(ALL_LEVELS.map(WalkLevel::name), ["PML4", "PDPT", "PD", "PT"]);
    assert_eq!(
        ALL_LEVELS.map(WalkLevel::page_size),
        [1 << 39, 1 << 30, 1 << 21, 1 << 12]
    );
}
