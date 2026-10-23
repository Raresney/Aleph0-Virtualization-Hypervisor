//! Unit tests for `src/vmx/mtrr/registers.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;
use crate::vmx::mtrr::MemoryType::{self, Uncacheable as UC, WriteBack as WB};

/// IA32_MTRRCAP of the Hyper-V VM: eight variable ranges, the fixed ranges,
/// and WC (bit 10), which nothing here reads.
const HYPER_V_MTRRCAP: u64 = (1 << 10) | CAP_FIXED | 8;
/// MAXPHYADDR of the Hyper-V VM: its PHYSMASK0 stops at bit 45.
const HYPER_V_ADDRESS_BITS: u8 = 46;

/// IA32_MTRR_DEF_TYPE as Hyper-V's firmware leaves it: MTRRs and fixed
/// ranges on, default type UC.
const HYPER_V_DEF_TYPE: u64 = DEF_TYPE_ENABLE | DEF_TYPE_FIXED_ENABLE;
/// Hyper-V's variable range 0: the first 4 GiB, WB.
const HYPER_V_PHYSBASE0: u64 = 0x6;
const HYPER_V_PHYSMASK0: u64 = 0x3FFF_0000_0800;

fn hyper_v() -> MtrrCapabilities {
    MtrrCapabilities::new(HYPER_V_MTRRCAP, HYPER_V_ADDRESS_BITS).unwrap()
}

/// The MSR at `address` among those `capabilities` lists.
fn msr(capabilities: MtrrCapabilities, address: u32) -> MtrrMsr {
    capabilities
        .msrs()
        .find(|msr| msr.address() == address)
        .unwrap_or_else(|| panic!("no MTRR MSR {address:#x}"))
}

/// Every byte of a fixed-range MSR set to `memory_type`.
fn fixed_all(memory_type: MemoryType) -> u64 {
    u64::from_le_bytes([memory_type.raw() as u8; 8])
}

/// The value Hyper-V's firmware leaves in the MTRR MSR at `address`: WB
/// below 0xA0000 and UC up to 1 MiB in the fixed ranges, variable range 0
/// for the first 4 GiB, the other ranges unused.
fn hyper_v_value(address: u32) -> u64 {
    match address {
        IA32_MTRR_DEF_TYPE => HYPER_V_DEF_TYPE,
        0x250 | 0x258 => fixed_all(WB),
        0x259..=0x26F => fixed_all(UC),
        0x200 => HYPER_V_PHYSBASE0,
        0x201 => HYPER_V_PHYSMASK0,
        _ => 0,
    }
}

#[test]
fn mtrrcap_gives_the_variable_count_and_the_fixed_ranges() {
    let capabilities = hyper_v();
    assert_eq!(capabilities.variable_count(), 8);
    assert!(capabilities.fixed);
    assert!(!MtrrCapabilities::new(10, 46).unwrap().fixed);
}

#[test]
fn more_variable_ranges_than_kept_are_refused() {
    assert_eq!(
        MtrrCapabilities::new(MAX_VARIABLE_RANGES as u64 + 1, 46),
        Err(MtrrError::TooManyVariableRanges {
            count: MAX_VARIABLE_RANGES + 1
        })
    );
    assert!(MtrrCapabilities::new(MAX_VARIABLE_RANGES as u64, 46).is_ok());
}

#[test]
fn the_msrs_are_def_type_the_fixed_ones_then_each_pair() {
    let addresses: Vec<u32> = hyper_v().msrs().map(MtrrMsr::address).collect();
    let mut expected = vec![0x2FF, 0x250, 0x258, 0x259];
    expected.extend(0x268..=0x26F);
    expected.extend(0x200..=0x20F);
    assert_eq!(addresses, expected);
}

#[test]
fn without_fixed_ranges_only_def_type_and_the_pairs_exist() {
    let addresses: Vec<u32> = MtrrCapabilities::new(2, 46)
        .unwrap()
        .msrs()
        .map(MtrrMsr::address)
        .collect();
    assert_eq!(addresses, [0x2FF, 0x200, 0x201, 0x202, 0x203]);
}

#[test]
fn a_cpu_without_mtrrs_has_no_mtrr_msr() {
    assert_eq!(MtrrCapabilities::NONE.msrs().count(), 0);
}

#[test]
fn mtrrcap_itself_is_not_among_the_msrs() {
    // Read-only: WRMSR to it always faults, and the guest reads the CPU's.
    assert!(hyper_v().msrs().all(|msr| msr.address() != IA32_MTRRCAP));
}

#[test]
fn def_type_takes_a_type_and_the_two_enable_bits() {
    let def_type = msr(hyper_v(), IA32_MTRR_DEF_TYPE);
    for value in [
        0,
        HYPER_V_DEF_TYPE,
        DEF_TYPE_ENABLE | WB.raw(),
        DEF_TYPE_FIXED_ENABLE | 1,
    ] {
        assert_eq!(hyper_v().check(def_type, value), Ok(()), "{value:#x}");
    }
}

#[test]
fn def_type_refuses_reserved_bits_and_types() {
    let def_type = msr(hyper_v(), IA32_MTRR_DEF_TYPE);
    // Bits 9:8 lie between the type and FE; bit 12 is past E.
    for bits in [0x300, 1 << 12, 1 << 63] {
        assert_eq!(
            hyper_v().check(def_type, HYPER_V_DEF_TYPE | bits),
            Err(MtrrError::ReservedBits { msr: 0x2FF, bits })
        );
    }
    assert_eq!(
        hyper_v().check(def_type, DEF_TYPE_ENABLE | 2),
        Err(MtrrError::ReservedType { msr: 0x2FF, value: 2 })
    );
}

#[test]
fn a_fixed_range_msr_refuses_a_reserved_type_in_any_byte() {
    let capabilities = hyper_v();
    let fix4k = msr(capabilities, 0x26A);
    assert_eq!(capabilities.check(fix4k, fixed_all(WB)), Ok(()));
    for byte in 0..8 {
        let mut bytes = [WB.raw() as u8; 8];
        bytes[byte] = 7;
        assert_eq!(
            capabilities.check(fix4k, u64::from_le_bytes(bytes)),
            Err(MtrrError::ReservedType { msr: 0x26A, value: 7 }),
            "byte {byte}"
        );
    }
}

#[test]
fn physbase_takes_a_type_and_an_address_below_maxphyaddr() {
    let physbase = msr(hyper_v(), 0x20E);
    assert_eq!(hyper_v().check(physbase, 0x3FFF_FFFF_F000 | WB.raw()), Ok(()));
    // Bits 11:8, then bit 46, the first one past MAXPHYADDR.
    for bits in [0xF00, 1 << 46, 1 << 63] {
        assert_eq!(
            hyper_v().check(physbase, 0x20_0000 | bits),
            Err(MtrrError::ReservedBits { msr: 0x20E, bits })
        );
    }
}

#[test]
fn physbase_refuses_a_reserved_type_while_its_range_is_off() {
    // `Mtrrs::decode` never reads the type of a range without the valid
    // bit, but WRMSR checks it all the same.
    let physbase = msr(hyper_v(), 0x20E);
    assert_eq!(
        hyper_v().check(physbase, 0x20_0000 | 3),
        Err(MtrrError::ReservedType { msr: 0x20E, value: 3 })
    );
}

#[test]
fn physmask_takes_the_valid_bit_and_a_mask_below_maxphyaddr() {
    let physmask = msr(hyper_v(), 0x20F);
    for value in [0, HYPER_V_PHYSMASK0, 0x3FFF_FFFF_F800, 0x3FFF_FFE0_0000] {
        assert_eq!(hyper_v().check(physmask, value), Ok(()), "{value:#x}");
    }
    // Bits 10:0, where a PHYSBASE has its type, then bit 46.
    for bits in [WB.raw(), 0x400, 1 << 46] {
        assert_eq!(
            hyper_v().check(physmask, HYPER_V_PHYSMASK0 | bits),
            Err(MtrrError::ReservedBits { msr: 0x20F, bits })
        );
    }
}

#[test]
fn maxphyaddr_past_52_bits_leaves_bits_63_to_52_reserved() {
    let capabilities = MtrrCapabilities::new(HYPER_V_MTRRCAP, 64).unwrap();
    let physmask = msr(capabilities, 0x201);
    assert_eq!(capabilities.check(physmask, 0x000F_FFFF_FFFF_F800), Ok(()));
    assert_eq!(
        capabilities.check(physmask, 1 << 52),
        Err(MtrrError::ReservedBits {
            msr: 0x201,
            bits: 1 << 52
        })
    );
}

#[test]
fn reading_asks_for_exactly_the_msrs_the_cpu_has() {
    let mut asked = Vec::new();
    MtrrRegisters::read_with(hyper_v(), |msr| {
        asked.push(msr.address());
        hyper_v_value(msr.address())
    })
    .unwrap();
    assert_eq!(asked, hyper_v().msrs().map(MtrrMsr::address).collect::<Vec<_>>());
}

#[test]
fn hyper_v_registers_decode_as_its_bring_up_printed() {
    let registers = MtrrRegisters::read_with(hyper_v(), |msr| hyper_v_value(msr.address())).unwrap();
    let mtrrs = registers.decode().unwrap();
    assert_eq!(
        mtrrs.to_string(),
        "enabled, default type UC; fixed ranges enabled; 8 variable ranges, 1 in use"
    );
    let Mtrrs::Enabled(enabled) = &mtrrs else {
        panic!("{mtrrs:?}");
    };
    assert_eq!(
        enabled.variable_ranges()[0].to_string(),
        "variable range 0: base=0x000000000000 mask=0x3fff00000000 WB"
    );
    assert_eq!(mtrrs.memory_type(0x9_F000), WB);
    assert_eq!(mtrrs.memory_type(0xA_0000), UC);
    assert_eq!(mtrrs.memory_type(0xFFFF_F000), WB);
    assert_eq!(mtrrs.memory_type(0x1_0000_0000), UC);
}

#[test]
fn reading_refuses_what_wrmsr_would_have_refused() {
    // Variable range 7 is off, so decoding alone would accept its reserved
    // type; no CPU can hold it, so it comes from a broken VMM below Aleph0.
    let reserved_type = MtrrRegisters::read_with(hyper_v(), |msr| match msr.address() {
        0x20E => 2,
        address => hyper_v_value(address),
    });
    assert_eq!(reserved_type, Err(MtrrError::ReservedType { msr: 0x20E, value: 2 }));
    let reserved_bits = MtrrRegisters::read_with(hyper_v(), |msr| match msr.address() {
        0x2FF => HYPER_V_DEF_TYPE | 0x100,
        address => hyper_v_value(address),
    });
    assert_eq!(
        reserved_bits,
        Err(MtrrError::ReservedBits {
            msr: 0x2FF,
            bits: 0x100
        })
    );
}

#[test]
fn without_mtrrs_nothing_is_read_and_everything_is_write_back() {
    let registers = MtrrRegisters::read_with(MtrrCapabilities::NONE, |msr| panic!("read {msr:?}")).unwrap();
    assert_eq!(registers.decode(), Ok(Mtrrs::Unsupported));
}

#[test]
fn errors_say_what_the_cpu_refuses() {
    assert_eq!(
        MtrrError::ReservedType { msr: 0x202, value: 3 }.to_string(),
        "the reserved memory type 3 in MSR 0x202"
    );
    assert_eq!(
        MtrrError::ReservedBits {
            msr: 0x2FF,
            bits: 0x300
        }
        .to_string(),
        "reserved bits 0x300 set in MSR 0x2ff"
    );
    assert_eq!(
        MtrrError::TooManyVariableRanges { count: 40 }.to_string(),
        "IA32_MTRRCAP reports 40 variable ranges, more than the 32 Aleph0 keeps"
    );
}
