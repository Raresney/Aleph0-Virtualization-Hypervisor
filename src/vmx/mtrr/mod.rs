//! Memory type range registers (MTRRs): the memory type firmware gives each
//! range of physical memory.
//!
//! The memory type decides how the CPU caches an access: write-back for RAM,
//! uncacheable for device registers, write-combining for a framebuffer.
//! Without EPT the CPU takes it from the MTRRs, combined with the PAT type
//! the page tables select. With EPT on, the MTRRs no longer apply to guest
//! accesses: the EPT leaf entry's type takes their place. So `ept.rs` puts
//! the type read here into each entry, and the guest gets the types it would
//! get without Aleph0. The longer walkthrough is in `docs/MTRR.md`.
//!
//! The registers (Intel SDM Vol. 3A, "Memory Type Range Registers"):
//!
//! - IA32_MTRRCAP: how many variable ranges exist, and whether the fixed
//!   ones do.
//! - IA32_MTRR_DEF_TYPE: the type of memory no range covers, and the enable
//!   bits.
//! - 11 fixed-range MSRs: the first MiB, eight ranges per MSR (of 64, 16 or
//!   4 KiB), one type byte per range.
//! - Variable ranges: IA32_MTRR_PHYSBASEn / IA32_MTRR_PHYSMASKn pairs. An
//!   address is in range n when `address & mask == base & mask`.
//!
//! This file decodes their values into memory types; `registers.rs` reads
//! the MSRs and knows which values WRMSR refuses.

use core::fmt;

use super::page::PAGE_SIZE;

mod registers;

pub use registers::{MtrrCapabilities, MtrrMsr, MtrrRegisters, MtrrState, read};

/// IA32_MTRRCAP: bits 7:0 count the variable ranges, bit 8 says the fixed
/// ranges exist.
pub const IA32_MTRRCAP: u32 = 0xFE;
const CAP_VARIABLE_COUNT: u64 = 0xFF;
const CAP_FIXED: u64 = 1 << 8;

/// IA32_MTRR_DEF_TYPE: bits 7:0 the default type, bit 10 (FE) enables the
/// fixed ranges, bit 11 (E) enables the MTRRs.
pub const IA32_MTRR_DEF_TYPE: u32 = 0x2FF;
const DEF_TYPE_FIXED_ENABLE: u64 = 1 << 10;
const DEF_TYPE_ENABLE: u64 = 1 << 11;

/// IA32_MTRR_PHYSBASE0. Variable range n has its PHYSBASE at
/// `0x200 + 2n` and its PHYSMASK right after.
pub const IA32_MTRR_PHYSBASE0: u32 = 0x200;
/// PHYSMASK bit 11: the range is in use.
const PHYSMASK_VALID: u64 = 1 << 11;
/// Bits 7:0 of IA32_MTRR_DEF_TYPE and of a PHYSBASE: a memory type.
const TYPE_BITS: u64 = 0xFF;
/// Bits 51:12 of a PHYSBASE or PHYSMASK: the address part. Bits above the
/// CPU's physical-address width are reserved, so they read as 0 and need no
/// masking of their own.
const ADDRESS_BITS: u64 = 0x000F_FFFF_FFFF_F000;

/// How many variable ranges Aleph0 keeps. CPUs have 8 or 10; IA32_MTRRCAP
/// could report up to 255, which [`Mtrrs::decode`] refuses rather than
/// dropping ranges.
pub const MAX_VARIABLE_RANGES: usize = 32;

/// Number of fixed-range MSRs.
pub const FIXED_MSRS: usize = 11;

// The fixed-range MSRs, each named after the first address it covers.
/// 0x00000..0x80000 in eight 64 KiB ranges.
pub const IA32_MTRR_FIX64K_00000: u32 = 0x250;
/// 0x80000..0xA0000 in eight 16 KiB ranges.
pub const IA32_MTRR_FIX16K_80000: u32 = 0x258;
/// 0xA0000..0xC0000 in eight 16 KiB ranges.
pub const IA32_MTRR_FIX16K_A0000: u32 = 0x259;
/// 0xC0000..0xC8000 in eight 4 KiB ranges.
pub const IA32_MTRR_FIX4K_C0000: u32 = 0x268;
/// 0xC8000..0xD0000 in eight 4 KiB ranges.
pub const IA32_MTRR_FIX4K_C8000: u32 = 0x269;
/// 0xD0000..0xD8000 in eight 4 KiB ranges.
pub const IA32_MTRR_FIX4K_D0000: u32 = 0x26A;
/// 0xD8000..0xE0000 in eight 4 KiB ranges.
pub const IA32_MTRR_FIX4K_D8000: u32 = 0x26B;
/// 0xE0000..0xE8000 in eight 4 KiB ranges.
pub const IA32_MTRR_FIX4K_E0000: u32 = 0x26C;
/// 0xE8000..0xF0000 in eight 4 KiB ranges.
pub const IA32_MTRR_FIX4K_E8000: u32 = 0x26D;
/// 0xF0000..0xF8000 in eight 4 KiB ranges.
pub const IA32_MTRR_FIX4K_F0000: u32 = 0x26E;
/// 0xF8000..0x100000 in eight 4 KiB ranges.
pub const IA32_MTRR_FIX4K_F8000: u32 = 0x26F;

/// The fixed-range MSRs in address order: each one's address, the start of
/// its first range and the size of each of its eight ranges. Byte n of the
/// MSR is the type of range n.
pub const FIXED_RANGES: [(u32, u64, u64); FIXED_MSRS] = [
    (IA32_MTRR_FIX64K_00000, 0x0_0000, 0x1_0000),
    (IA32_MTRR_FIX16K_80000, 0x8_0000, 0x4000),
    (IA32_MTRR_FIX16K_A0000, 0xA_0000, 0x4000),
    (IA32_MTRR_FIX4K_C0000, 0xC_0000, 0x1000),
    (IA32_MTRR_FIX4K_C8000, 0xC_8000, 0x1000),
    (IA32_MTRR_FIX4K_D0000, 0xD_0000, 0x1000),
    (IA32_MTRR_FIX4K_D8000, 0xD_8000, 0x1000),
    (IA32_MTRR_FIX4K_E0000, 0xE_0000, 0x1000),
    (IA32_MTRR_FIX4K_E8000, 0xE_8000, 0x1000),
    (IA32_MTRR_FIX4K_F0000, 0xF_0000, 0x1000),
    (IA32_MTRR_FIX4K_F8000, 0xF_8000, 0x1000),
];

/// Where the fixed ranges end: they cover the first MiB.
pub const FIXED_END: u64 = 0x10_0000;

/// A memory type, as the MTRRs, the PAT and EPT entries encode it. The
/// values not listed (2, 3, 7 and up) are reserved: in an MTRR they are a
/// firmware bug, in an EPT entry an EPT misconfiguration. `repr(u8)`: the
/// discriminants are the hardware encodings, which [`raw`](Self::raw) returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MemoryType {
    /// UC: every access goes to memory or the device, in program order.
    /// Device registers (MMIO) need it.
    Uncacheable = 0,
    /// WC: not cached, but writes are combined into bursts. Framebuffers.
    WriteCombining = 1,
    /// WT: reads cached, writes go straight through to memory.
    WriteThrough = 4,
    /// WP: reads cached, writes go to memory without updating the cache.
    WriteProtected = 5,
    /// WB: fully cached. Ordinary RAM.
    WriteBack = 6,
}

impl MemoryType {
    /// The type encoded as `value`, or `None` for a reserved value.
    pub fn from_raw(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Uncacheable),
            1 => Some(Self::WriteCombining),
            4 => Some(Self::WriteThrough),
            5 => Some(Self::WriteProtected),
            6 => Some(Self::WriteBack),
            _ => None,
        }
    }

    /// The encoding: the value the MTRRs and EPT entries hold.
    pub fn raw(self) -> u64 {
        self as u64
    }

    /// The SDM's abbreviation.
    pub fn name(self) -> &'static str {
        match self {
            Self::Uncacheable => "UC",
            Self::WriteCombining => "WC",
            Self::WriteThrough => "WT",
            Self::WriteProtected => "WP",
            Self::WriteBack => "WB",
        }
    }

    /// The type of an address that two variable ranges of types `self` and
    /// `other` both cover (SDM, "MTRR Precedences"): the same type stays,
    /// UC wins over anything, and WT wins over WB. Any other overlap is
    /// undefined; UC is the one choice that cannot hand a device stale data.
    fn overlap(self, other: Self) -> Self {
        match (self, other) {
            _ if self == other => self,
            (Self::WriteThrough, Self::WriteBack) | (Self::WriteBack, Self::WriteThrough) => Self::WriteThrough,
            _ => Self::Uncacheable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtrrError {
    /// A type field of MSR `msr` holds the reserved memory type `value`.
    ReservedType { msr: u32, value: u8 },
    /// MSR `msr` has the reserved bits `bits` set.
    ReservedBits { msr: u32, bits: u64 },
    /// IA32_MTRRCAP reports `count` variable ranges, more than
    /// [`MAX_VARIABLE_RANGES`].
    TooManyVariableRanges { count: usize },
}

impl fmt::Display for MtrrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::ReservedType { msr, value } => write!(f, "the reserved memory type {value} in MSR {msr:#x}"),
            Self::ReservedBits { msr, bits } => write!(f, "reserved bits {bits:#x} set in MSR {msr:#x}"),
            Self::TooManyVariableRanges { count } => write!(
                f,
                "IA32_MTRRCAP reports {count} variable ranges, more than the {MAX_VARIABLE_RANGES} Aleph0 keeps"
            ),
        }
    }
}

/// A variable range in use (its PHYSMASK valid bit set), decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VariableRange {
    /// Its number n: the MSRs are IA32_MTRR_PHYSBASEn and PHYSMASKn.
    pub number: usize,
    /// PHYSBASE bits 51:12.
    pub base: u64,
    /// PHYSMASK bits 51:12: which address bits must equal the base's.
    pub mask: u64,
    pub memory_type: MemoryType,
}

impl VariableRange {
    /// Fills the unused slots of [`EnabledMtrrs::variable`].
    const UNUSED: Self = Self {
        number: 0,
        base: 0,
        mask: 0,
        memory_type: MemoryType::Uncacheable,
    };

    /// Whether `address` is in the range.
    fn covers(&self, address: u64) -> bool {
        address & self.mask == self.base & self.mask
    }

    /// Whether the range may cover some pages of the `size`-byte block at
    /// `base` and not others. The block's pages differ only in the address
    /// bits below `size`. If the mask tests none of those, the range covers
    /// the whole block or none of it; if it tests some, it covers part of
    /// the block, as long as the bits above match.
    fn may_split(&self, base: u64, size: u64) -> bool {
        let inside = (size - 1) & ADDRESS_BITS;
        let above = self.mask & !inside;
        self.mask & inside != 0 && base & above == self.base & above
    }
}

impl fmt::Display for VariableRange {
    /// `variable range 0: base=0x000000000000 mask=0x3fff00000000 WB`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "variable range {}: base={:#014x} mask={:#014x} {}",
            self.number,
            self.base,
            self.mask,
            self.memory_type.name()
        )
    }
}

/// The MTRRs of this CPU, decoded and checked: every type in use is a valid
/// memory type, so looking one up cannot fail.
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "built once at bring-up and passed by reference; the crate has no allocator to box it"
)]
pub enum Mtrrs {
    /// The CPU has no MTRRs at all (CPUID). Every address is WB, so caching
    /// is up to the PAT alone, as it was for Aleph0's EPT before MTRRs were
    /// read.
    Unsupported,
    /// IA32_MTRR_DEF_TYPE.E is clear: all memory is UC, whatever the other
    /// MTRRs hold.
    Disabled,
    /// IA32_MTRR_DEF_TYPE.E is set: the default type and the ranges apply.
    Enabled(EnabledMtrrs),
}

/// MTRRs that are on: the default type and the ranges that override it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnabledMtrrs {
    default_type: MemoryType,
    /// The type of each fixed range, per MSR in [`FIXED_RANGES`] order, or
    /// `None` when the fixed ranges are missing or disabled.
    fixed: Option<[[MemoryType; 8]; FIXED_MSRS]>,
    /// How many variable ranges the CPU has, used or not.
    variable_count: usize,
    /// The ranges in use, first `in_use` entries.
    variable: [VariableRange; MAX_VARIABLE_RANGES],
    in_use: usize,
}

impl Mtrrs {
    /// Decodes the MSR values: `def_type` is IA32_MTRR_DEF_TYPE, `fixed` the
    /// fixed-range MSRs in [`FIXED_RANGES`] order (`None` when IA32_MTRRCAP
    /// says they do not exist), and `variable` the (PHYSBASE, PHYSMASK) pair
    /// of every variable range, in order.
    ///
    /// Only what the CPU uses is checked: nothing while the MTRRs are
    /// disabled, the fixed ranges only when enabled, and only the variable
    /// ranges in use.
    pub fn decode(def_type: u64, fixed: Option<[u64; FIXED_MSRS]>, variable: &[(u64, u64)]) -> Result<Self, MtrrError> {
        if variable.len() > MAX_VARIABLE_RANGES {
            return Err(MtrrError::TooManyVariableRanges { count: variable.len() });
        }
        if def_type & DEF_TYPE_ENABLE == 0 {
            return Ok(Self::Disabled);
        }
        let mut mtrrs = EnabledMtrrs {
            default_type: decode_type(IA32_MTRR_DEF_TYPE, def_type)?,
            fixed: None,
            variable_count: variable.len(),
            variable: [VariableRange::UNUSED; MAX_VARIABLE_RANGES],
            in_use: 0,
        };

        if def_type & DEF_TYPE_FIXED_ENABLE != 0
            && let Some(fixed) = fixed
        {
            let mut types = [[MemoryType::Uncacheable; 8]; FIXED_MSRS];
            for ((value, &(msr, ..)), types) in fixed.iter().zip(&FIXED_RANGES).zip(&mut types) {
                for (byte, memory_type) in value.to_le_bytes().into_iter().zip(types) {
                    *memory_type = decode_type(msr, byte.into())?;
                }
            }
            mtrrs.fixed = Some(types);
        }

        for (number, &(base, mask)) in variable.iter().enumerate() {
            if mask & PHYSMASK_VALID == 0 {
                continue;
            }
            mtrrs.variable[mtrrs.in_use] = VariableRange {
                number,
                base: base & ADDRESS_BITS,
                mask: mask & ADDRESS_BITS,
                memory_type: decode_type(IA32_MTRR_PHYSBASE0 + 2 * number as u32, base)?,
            };
            mtrrs.in_use += 1;
        }
        Ok(Self::Enabled(mtrrs))
    }

    /// The memory type of the 4 KiB page at `address` (SDM, "MTRR
    /// Precedences"): WB without MTRRs, UC while they are disabled, and
    /// otherwise what [`EnabledMtrrs`] gives it.
    pub fn memory_type(&self, address: u64) -> MemoryType {
        match self {
            Self::Unsupported => MemoryType::WriteBack,
            Self::Disabled => MemoryType::Uncacheable,
            Self::Enabled(mtrrs) => mtrrs.memory_type(address),
        }
    }

    /// The memory type of the whole `size`-byte block at `base`, or `None`
    /// when its 4 KiB pages do not all have the same type. `size` is a power
    /// of two of at least 4 KiB, and `base` a multiple of it.
    pub fn block_type(&self, base: u64, size: u64) -> Option<MemoryType> {
        debug_assert!(size.is_power_of_two() && size >= PAGE_SIZE as u64 && base.is_multiple_of(size));
        match self {
            Self::Unsupported | Self::Disabled => Some(self.memory_type(base)),
            Self::Enabled(mtrrs) => mtrrs.block_type(base, size),
        }
    }

    /// `[0, end)` cut into blocks of `size` bytes, with consecutive blocks of
    /// the same [`block_type`](Self::block_type) merged into one run. `end`
    /// is a multiple of `size`. Each block's type is looked up once.
    pub fn runs(&self, end: u64, size: u64) -> impl Iterator<Item = TypeRun> + '_ {
        debug_assert!(end.is_multiple_of(size));
        let mut blocks = (0..end)
            .step_by(size as usize)
            .map(move |start| (start, self.block_type(start, size)))
            .peekable();
        core::iter::from_fn(move || {
            let (start, memory_type) = blocks.next()?;
            let mut run_end = start + size;
            while let Some((next, _)) = blocks.next_if(|&(_, next_type)| next_type == memory_type) {
                run_end = next + size;
            }
            Some(TypeRun {
                start,
                end: run_end,
                memory_type,
            })
        })
    }
}

impl fmt::Display for Mtrrs {
    /// Whether the MTRRs are on and, when they are, the default type and
    /// how many ranges apply: `enabled, default type UC; fixed ranges
    /// enabled; 8 variable ranges, 1 in use`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("not supported (CPUID); all memory is treated as WB"),
            Self::Disabled => f.write_str("disabled (IA32_MTRR_DEF_TYPE.E=0); all memory is UC"),
            Self::Enabled(enabled) => write!(
                f,
                "enabled, default type {}; fixed ranges {}; {} variable ranges, {} in use",
                enabled.default_type().name(),
                if enabled.fixed_enabled() { "enabled" } else { "disabled" },
                enabled.variable_count(),
                enabled.variable_ranges().len(),
            ),
        }
    }
}

impl EnabledMtrrs {
    /// The type of memory no range covers.
    pub fn default_type(&self) -> MemoryType {
        self.default_type
    }

    /// Whether the fixed ranges exist and are enabled.
    pub fn fixed_enabled(&self) -> bool {
        self.fixed.is_some()
    }

    /// How many variable ranges the CPU has, used or not.
    pub fn variable_count(&self) -> usize {
        self.variable_count
    }

    /// The variable ranges in use.
    pub fn variable_ranges(&self) -> &[VariableRange] {
        &self.variable[..self.in_use]
    }

    /// The memory type of the 4 KiB page at `address`: below 1 MiB the fixed
    /// range's type, when they are enabled; otherwise the type of the
    /// variable ranges covering it, or the default type if none does.
    fn memory_type(&self, address: u64) -> MemoryType {
        if let Some(memory_type) = self.fixed_type(address) {
            return memory_type;
        }
        self.variable_ranges()
            .iter()
            .filter(|range| range.covers(address))
            .map(|range| range.memory_type)
            .reduce(MemoryType::overlap)
            .unwrap_or(self.default_type)
    }

    /// See [`Mtrrs::block_type`].
    ///
    /// The type is the same for every page unless the fixed ranges reach
    /// into the block or a variable range covers only part of it. Only then
    /// are the pages looked at one by one, so a map of all memory stays
    /// cheap to build.
    fn block_type(&self, base: u64, size: u64) -> Option<MemoryType> {
        let fixed_inside = self.fixed.is_some() && base < FIXED_END;
        let split = self.variable_ranges().iter().any(|range| range.may_split(base, size));
        let first = self.memory_type(base);
        if !fixed_inside && !split {
            return Some(first);
        }
        (base..base + size)
            .step_by(PAGE_SIZE)
            .all(|page| self.memory_type(page) == first)
            .then_some(first)
    }

    /// The type of the fixed range holding `address`, or `None` when the
    /// fixed ranges are off or `address` is past the first MiB.
    fn fixed_type(&self, address: u64) -> Option<MemoryType> {
        let fixed = self.fixed.as_ref()?;
        FIXED_RANGES.iter().zip(fixed).find_map(|(&(_, start, size), types)| {
            let offset = address.checked_sub(start)?;
            types.get((offset / size) as usize).copied()
        })
    }
}

/// Consecutive blocks of one memory type: see [`Mtrrs::runs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeRun {
    pub start: u64,
    pub end: u64,
    /// `None` when the pages of each block differ in type.
    pub memory_type: Option<MemoryType>,
}

impl TypeRun {
    /// The run's type for a report: its name, or "mixed" for blocks whose
    /// pages differ.
    pub fn type_name(&self) -> &'static str {
        self.memory_type.map_or("mixed (4 KiB pages)", MemoryType::name)
    }
}

/// The memory type in bits 7:0 of `value`, read from MSR `msr`.
fn decode_type(msr: u32, value: u64) -> Result<MemoryType, MtrrError> {
    let raw = (value & TYPE_BITS) as u8;
    MemoryType::from_raw(raw).ok_or(MtrrError::ReservedType { msr, value: raw })
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/mtrr.rs"]
pub(crate) mod tests;
