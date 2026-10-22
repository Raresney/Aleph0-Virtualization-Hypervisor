//! Unit tests for `src/vmx/host/gdt.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;
use crate::vmx::segment::{SegmentDescriptor, system_descriptor_base};

/// The selectors the Hyper-V firmware runs with.
const HYPER_V: FirmwareSelectors = FirmwareSelectors {
    cs: 0x28,
    ss: 0x08,
    ds: 0x08,
    es: 0x08,
    fs: 0x08,
    gs: 0x08,
};

/// A TSS base with a distinct byte in every position.
const TSS_BASE: u64 = 0x1122_3344_5566_7788;

fn encoded(layout: &GdtLayout) -> [u64; SLOTS] {
    let mut gdt = [u64::MAX; SLOTS];
    encode(layout, TSS_BASE, &mut gdt);
    gdt
}

#[test]
fn hyper_v_selectors_put_the_tss_after_the_code_descriptor() {
    let layout = layout(HYPER_V).unwrap();
    assert_eq!(
        layout.selectors,
        HostSelectors {
            cs: 0x28,
            ss: 0x08,
            ds: 0x08,
            es: 0x08,
            fs: 0x08,
            gs: 0x08,
            tr: 0x30,
        }
    );
    // Slots 0-7: the TSS takes 6 and 7.
    assert_eq!(layout.limit, 0x3F);
}

#[test]
fn every_slot_holds_what_its_selector_names() {
    let gdt = encoded(&layout(HYPER_V).unwrap());
    assert_eq!(gdt[0], 0, "null");
    assert_eq!(gdt[1], DATA);
    assert_eq!(gdt[2..5], [0; 3], "unused slots are null");
    assert_eq!(gdt[5], CODE_64);
    let tss: [u8; 16] = [gdt[6].to_le_bytes(), gdt[7].to_le_bytes()]
        .concat()
        .try_into()
        .unwrap();
    assert_eq!(system_descriptor_base(&tss), TSS_BASE);
    assert_eq!(SegmentDescriptor(gdt[6]).limit(), 0x67);
    assert!(gdt[8..].iter().all(|&slot| slot == 0), "nothing past the TSS");
}

#[test]
fn code_descriptor_is_flat_64_bit_ring_0() {
    let code = SegmentDescriptor(CODE_64);
    // VMCS access-rights format: G = 1, L = 1, P = 1, DPL 0, S = 1, type
    // 0xB. What the Hyper-V firmware's CS shows, accessed bit included.
    assert_eq!(code.access_rights(), 0xA09B);
    assert_eq!(code.base(), 0);
    assert_eq!(code.limit(), 0xFFFF_FFFF);
}

#[test]
fn data_descriptor_is_flat_read_write_ring_0() {
    let data = SegmentDescriptor(DATA);
    // G = 1, D/B = 1, P = 1, DPL 0, S = 1, type 0x3: the Hyper-V
    // firmware's data segments.
    assert_eq!(data.access_rights(), 0xC093);
    assert_eq!(data.base(), 0);
    assert_eq!(data.limit(), 0xFFFF_FFFF);
}

#[test]
fn null_data_selectors_stay_null() {
    let firmware = FirmwareSelectors {
        fs: 0,
        gs: 0,
        ..HYPER_V
    };
    let layout = layout(firmware).unwrap();
    assert_eq!((layout.selectors.fs, layout.selectors.gs), (0, 0));
    let gdt = encoded(&layout);
    assert_eq!(gdt[0], 0, "a null selector writes no descriptor");
}

#[test]
fn each_distinct_data_selector_gets_a_data_descriptor() {
    let firmware = FirmwareSelectors {
        ss: 0x30,
        ds: 0x10,
        ..HYPER_V
    };
    let layout = layout(firmware).unwrap();
    // The TSS goes above the highest slot used, here SS's.
    assert_eq!(layout.selectors.tr, 0x38);
    let gdt = encoded(&layout);
    assert_eq!((gdt[1], gdt[2], gdt[6]), (DATA, DATA, DATA));
    assert_eq!(gdt[5], CODE_64);
}

#[test]
fn a_null_code_selector_is_refused() {
    let firmware = FirmwareSelectors { cs: 0, ..HYPER_V };
    assert_eq!(layout(firmware), Err(GdtLayoutError::NullCode));
}

#[test]
fn a_selector_with_rpl_or_ti_set_is_refused() {
    for selector in [0x0B, 0x0C] {
        let firmware = FirmwareSelectors {
            ds: selector,
            ..HYPER_V
        };
        assert_eq!(layout(firmware), Err(GdtLayoutError::NotRing0Gdt { selector }));
    }
}

#[test]
fn data_in_the_code_slot_is_refused() {
    let firmware = FirmwareSelectors { ss: 0x28, ..HYPER_V };
    assert_eq!(layout(firmware), Err(GdtLayoutError::DataInCodeSlot { selector: 0x28 }));
}

#[test]
fn a_gdt_past_one_page_is_refused() {
    // Slot 510 leaves one slot, but the TSS needs two.
    let firmware = FirmwareSelectors { cs: 510 * 8, ..HYPER_V };
    assert_eq!(layout(firmware), Err(GdtLayoutError::TooLarge));
    let firmware = FirmwareSelectors { cs: 509 * 8, ..HYPER_V };
    assert_eq!(layout(firmware).map(|layout| layout.limit), Ok(4095));
}
