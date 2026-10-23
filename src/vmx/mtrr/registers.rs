//! The MTRR MSRs as RDMSR and WRMSR see them: which ones a CPU has, which
//! values WRMSR refuses, and reading them.
//!
//! `mod.rs` decodes MTRR values into memory types. This file is about the
//! MSRs themselves (Intel SDM Vol. 3A, "Memory Type Range Registers"):
//!
//! - Which exist ([`MtrrCapabilities`]): IA32_MTRR_DEF_TYPE, the 11
//!   fixed-range MSRs when IA32_MTRRCAP bit 8 is set, and a PHYSBASE/PHYSMASK
//!   pair for each variable range IA32_MTRRCAP counts. IA32_MTRRCAP itself
//!   is read-only, and not counted among them.
//! - Which values WRMSR refuses with #GP ([`MtrrCapabilities::check`]): a
//!   reserved memory type in a type field, or a reserved bit set. The CPU
//!   checks the value on its own, whether or not that MTRR is in use, which
//!   makes this stricter than [`Mtrrs::decode`]. KVM's `kvm_mtrr_valid`
//!   applies the same rules.
//!
//! ```text
//! MSR                  bits that may be set (any other bit is reserved)
//! IA32_MTRR_DEF_TYPE   7:0 default type, 10 FE, 11 E
//! fixed-range MSRs     all 64: eight type bytes
//! IA32_MTRR_PHYSBASEn  7:0 type, MAXPHYADDR-1:12 base
//! IA32_MTRR_PHYSMASKn  11 valid, MAXPHYADDR-1:12 mask
//! ```
//!
//! - Their values ([`MtrrRegisters`]), each one a value the CPU would
//!   accept, and the same values decoded ([`MtrrState`]), which is what the
//!   guest's copy of its MTRRs is (`vmexit::guest_mtrrs`).

use core::fmt;

use super::{
    ADDRESS_BITS, CAP_FIXED, CAP_VARIABLE_COUNT, DEF_TYPE_ENABLE, DEF_TYPE_FIXED_ENABLE, FIXED_MSRS, FIXED_RANGES,
    IA32_MTRR_DEF_TYPE, IA32_MTRR_PHYSBASE0, IA32_MTRRCAP, MAX_VARIABLE_RANGES, MtrrError, Mtrrs, PHYSMASK_VALID,
    TYPE_BITS, decode_type,
};
use crate::vmx::cpuid;
use crate::vmx::msr::rdmsr;

/// The widest physical address a PHYSBASE or PHYSMASK holds: its address
/// part is bits 51:12.
const MAX_PHYSICAL_ADDRESS_BITS: u8 = 52;

/// Just past the PHYSMASK of variable range [`MAX_VARIABLE_RANGES`] - 1:
/// 0x240.
const VARIABLE_END: u32 = IA32_MTRR_PHYSBASE0 + 2 * MAX_VARIABLE_RANGES as u32;

/// Every address an MTRR MSR has on some CPU, whether or not this one has
/// it: IA32_MTRR_DEF_TYPE, the fixed-range MSRs, and PHYSBASEn and
/// PHYSMASKn of the first [`MAX_VARIABLE_RANGES`] variable ranges
/// (0x200..0x240).
///
/// The MSR bitmap intercepts all of them (`exit_bitmaps`), and the guest
/// gets #GP for those the CPU lacks ([`MtrrCapabilities::msr`] is `None`),
/// as it would on bare metal. So whether the guest reaches a real MTRR
/// never depends on IA32_MTRRCAP counting every one the CPU has.
pub fn every_msr_address() -> impl Iterator<Item = u32> {
    core::iter::once(IA32_MTRR_DEF_TYPE)
        .chain(FIXED_RANGES.iter().map(|&(msr, ..)| msr))
        .chain(IA32_MTRR_PHYSBASE0..VARIABLE_END)
}

/// Whether `address` is one of [`every_msr_address`].
pub fn is_msr_address(address: u32) -> bool {
    address == IA32_MTRR_DEF_TYPE
        || FIXED_RANGES.iter().any(|&(msr, ..)| msr == address)
        || (IA32_MTRR_PHYSBASE0..VARIABLE_END).contains(&address)
}

/// What IA32_MTRRCAP and CPUID say about the MTRR MSRs: which of them
/// exist, and which bits of a PHYSBASE or PHYSMASK are reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MtrrCapabilities {
    /// CPUID.1:EDX bit 12: the CPU has MTRRs at all.
    supported: bool,
    /// IA32_MTRRCAP bit 8: the fixed-range MSRs exist.
    fixed: bool,
    /// IA32_MTRRCAP bits 7:0: how many variable ranges, at most
    /// [`MAX_VARIABLE_RANGES`].
    variable_count: u8,
    /// MAXPHYADDR. Bits of a PHYSBASE or PHYSMASK from this one up are
    /// reserved.
    physical_address_bits: u8,
}

impl MtrrCapabilities {
    /// A CPU without MTRRs (CPUID.1:EDX bit 12 clear): no MTRR MSR exists.
    pub const NONE: Self = Self {
        supported: false,
        fixed: false,
        variable_count: 0,
        physical_address_bits: 0,
    };

    /// The MTRR MSRs of a CPU whose IA32_MTRRCAP is `mtrrcap` and whose
    /// physical addresses have `physical_address_bits` bits (MAXPHYADDR).
    /// Refuses more variable ranges than [`MAX_VARIABLE_RANGES`] rather than
    /// dropping some.
    pub fn new(mtrrcap: u64, physical_address_bits: u8) -> Result<Self, MtrrError> {
        let count = (mtrrcap & CAP_VARIABLE_COUNT) as usize;
        if count > MAX_VARIABLE_RANGES {
            return Err(MtrrError::TooManyVariableRanges { count });
        }
        Ok(Self {
            supported: true,
            fixed: mtrrcap & CAP_FIXED != 0,
            variable_count: count as u8,
            physical_address_bits: physical_address_bits.min(MAX_PHYSICAL_ADDRESS_BITS),
        })
    }

    /// How many variable ranges the CPU has.
    pub fn variable_count(self) -> usize {
        self.variable_count.into()
    }

    /// Whether the fixed-range MSRs exist.
    pub fn fixed(self) -> bool {
        self.supported && self.fixed
    }

    /// The MTRR MSR at `address`, or `None` when the CPU has no MTRR there.
    pub fn msr(self, address: u32) -> Option<MtrrMsr> {
        if !self.supported {
            return None;
        }
        if address == IA32_MTRR_DEF_TYPE {
            return Some(MtrrMsr(Kind::DefType));
        }
        if let Some(index) = FIXED_RANGES.iter().position(|&(msr, ..)| msr == address) {
            return self.fixed.then_some(MtrrMsr(Kind::Fixed(index as u8)));
        }
        let offset = address.checked_sub(IA32_MTRR_PHYSBASE0)?;
        let number = u8::try_from(offset / 2)
            .ok()
            .filter(|&number| number < self.variable_count)?;
        Some(MtrrMsr(if offset % 2 == 0 {
            Kind::PhysBase(number)
        } else {
            Kind::PhysMask(number)
        }))
    }

    /// Every MTRR MSR the CPU has: IA32_MTRR_DEF_TYPE, the fixed-range MSRs
    /// in [`FIXED_RANGES`] order, then IA32_MTRR_PHYSBASEn and PHYSMASKn of
    /// each variable range. None without MTRRs.
    pub fn msrs(self) -> impl Iterator<Item = MtrrMsr> {
        let def_type = self.supported.then_some(MtrrMsr(Kind::DefType));
        let fixed = (0..FIXED_MSRS as u8)
            .filter(move |_| self.supported && self.fixed)
            .map(|index| MtrrMsr(Kind::Fixed(index)));
        let variable = (0..self.variable_count)
            .flat_map(|number| [MtrrMsr(Kind::PhysBase(number)), MtrrMsr(Kind::PhysMask(number))]);
        def_type.into_iter().chain(fixed).chain(variable)
    }

    /// Checks `value` as WRMSR to `msr` does: `Ok` if the CPU would take it,
    /// otherwise what it would refuse with #GP. A reserved bit set (see the
    /// module docs), or a reserved memory type in a type field. The CPU
    /// checks every type field, used or not: a variable range's type even
    /// while its valid bit is clear, the fixed ranges' while they are off.
    pub fn check(self, msr: MtrrMsr, value: u64) -> Result<(), MtrrError> {
        let address = msr.address();
        // What may be set, and how many type bytes there are, from bit 0.
        let (allowed, type_bytes) = match msr.0 {
            Kind::DefType => (TYPE_BITS | DEF_TYPE_FIXED_ENABLE | DEF_TYPE_ENABLE, 1),
            Kind::Fixed(_) => (u64::MAX, 8),
            Kind::PhysBase(_) => (TYPE_BITS | self.address_bits(), 1),
            Kind::PhysMask(_) => (PHYSMASK_VALID | self.address_bits(), 0),
        };
        let reserved = value & !allowed;
        if reserved != 0 {
            return Err(MtrrError::ReservedBits {
                msr: address,
                bits: reserved,
            });
        }
        for byte in value.to_le_bytes().into_iter().take(type_bytes) {
            decode_type(address, byte.into())?;
        }
        Ok(())
    }

    /// The address bits of a PHYSBASE or PHYSMASK the CPU implements: bits
    /// MAXPHYADDR-1:12.
    fn address_bits(self) -> u64 {
        ADDRESS_BITS & ((1 << self.physical_address_bits) - 1)
    }
}

/// One MTRR MSR. Only [`MtrrCapabilities`] makes them, so its fixed-range
/// index or variable range number is always one the CPU has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MtrrMsr(Kind);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// IA32_MTRR_DEF_TYPE.
    DefType,
    /// The fixed-range MSR at this index of [`FIXED_RANGES`].
    Fixed(u8),
    /// IA32_MTRR_PHYSBASEn of variable range n.
    PhysBase(u8),
    /// IA32_MTRR_PHYSMASKn of variable range n.
    PhysMask(u8),
}

impl MtrrMsr {
    /// The MSR's address, as RDMSR and WRMSR take it in ECX.
    pub fn address(self) -> u32 {
        match self.0 {
            Kind::DefType => IA32_MTRR_DEF_TYPE,
            Kind::Fixed(index) => FIXED_RANGES[usize::from(index)].0,
            Kind::PhysBase(number) => IA32_MTRR_PHYSBASE0 + 2 * u32::from(number),
            Kind::PhysMask(number) => IA32_MTRR_PHYSBASE0 + 2 * u32::from(number) + 1,
        }
    }

    /// Whether it is one of the fixed-range MSRs.
    pub fn is_fixed(self) -> bool {
        matches!(self.0, Kind::Fixed(_))
    }
}

impl fmt::Display for MtrrMsr {
    /// The SDM's name: `IA32_MTRR_DEF_TYPE`, `IA32_MTRR_FIX16K_A0000`,
    /// `IA32_MTRR_PHYSMASK7`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Kind::DefType => f.write_str("IA32_MTRR_DEF_TYPE"),
            Kind::Fixed(index) => {
                let (_, start, size) = FIXED_RANGES[usize::from(index)];
                write!(f, "IA32_MTRR_FIX{}K_{start:05X}", size / 1024)
            }
            Kind::PhysBase(number) => write!(f, "IA32_MTRR_PHYSBASE{number}"),
            Kind::PhysMask(number) => write!(f, "IA32_MTRR_PHYSMASK{number}"),
        }
    }
}

/// The values of every MTRR MSR a CPU has ([`MtrrCapabilities::msrs`]),
/// each one a value the CPU would accept ([`MtrrCapabilities::check`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtrrRegisters {
    capabilities: MtrrCapabilities,
    def_type: u64,
    /// In [`FIXED_RANGES`] order; 0 when the fixed ranges do not exist.
    fixed: [u64; FIXED_MSRS],
    /// (PHYSBASEn, PHYSMASKn) of variable range n; 0 past the CPU's count.
    variable: [(u64, u64); MAX_VARIABLE_RANGES],
}

impl MtrrRegisters {
    /// The value of each MSR `capabilities` lists, as `read` returns it.
    /// Refuses a value the CPU would not accept: no CPU holds one, since
    /// WRMSR refuses them, so it can only come from a broken VMM below
    /// Aleph0.
    pub fn read_with(capabilities: MtrrCapabilities, mut read: impl FnMut(MtrrMsr) -> u64) -> Result<Self, MtrrError> {
        let mut registers = Self {
            capabilities,
            def_type: 0,
            fixed: [0; FIXED_MSRS],
            variable: [(0, 0); MAX_VARIABLE_RANGES],
        };
        for msr in capabilities.msrs() {
            let value = read(msr);
            capabilities.check(msr, value)?;
            *registers.value_mut(msr) = value;
        }
        Ok(registers)
    }

    /// Which MSRs there are.
    pub fn capabilities(&self) -> MtrrCapabilities {
        self.capabilities
    }

    /// The value of `msr`, as RDMSR returns it.
    pub fn get(&self, msr: MtrrMsr) -> u64 {
        match msr.0 {
            Kind::DefType => self.def_type,
            Kind::Fixed(index) => self.fixed[usize::from(index)],
            Kind::PhysBase(number) => self.variable[usize::from(number)].0,
            Kind::PhysMask(number) => self.variable[usize::from(number)].1,
        }
    }

    /// Writes `value` to `msr` as WRMSR does: a value the CPU would refuse
    /// ([`MtrrCapabilities::check`]) is refused, and every value stays as
    /// it was.
    pub fn write(&mut self, msr: MtrrMsr, value: u64) -> Result<(), MtrrError> {
        self.capabilities.check(msr, value)?;
        *self.value_mut(msr) = value;
        Ok(())
    }

    /// The memory types the values give ([`Mtrrs::decode`]).
    /// [`Mtrrs::Unsupported`] without MTRRs.
    pub fn decode(&self) -> Result<Mtrrs, MtrrError> {
        if !self.capabilities.supported {
            return Ok(Mtrrs::Unsupported);
        }
        Mtrrs::decode(
            self.def_type,
            self.capabilities.fixed.then_some(self.fixed),
            &self.variable[..self.capabilities.variable_count()],
        )
    }

    /// Where `msr`'s value is kept.
    fn value_mut(&mut self, msr: MtrrMsr) -> &mut u64 {
        match msr.0 {
            Kind::DefType => &mut self.def_type,
            Kind::Fixed(index) => &mut self.fixed[usize::from(index)],
            Kind::PhysBase(number) => &mut self.variable[usize::from(number)].0,
            Kind::PhysMask(number) => &mut self.variable[usize::from(number)].1,
        }
    }
}

/// MTRRs both as their MSRs hold them and decoded, kept in step: what the
/// guest's copy of its MTRRs is. KVM keeps the same per vCPU
/// (`kvm_mtrr`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtrrState {
    registers: MtrrRegisters,
    /// `registers`, decoded.
    mtrrs: Mtrrs,
}

impl MtrrState {
    /// `registers` with their decoding.
    pub fn new(registers: MtrrRegisters) -> Result<Self, MtrrError> {
        let mtrrs = registers.decode()?;
        Ok(Self { registers, mtrrs })
    }

    /// The MSRs' values.
    pub fn registers(&self) -> &MtrrRegisters {
        &self.registers
    }

    /// The memory types they give.
    pub fn mtrrs(&self) -> &Mtrrs {
        &self.mtrrs
    }

    /// Writes `value` to `msr` as WRMSR does, and returns whether the
    /// memory type of any address changed.
    ///
    /// A value the CPU would refuse is refused, and everything stays as it
    /// was: the #GP the guest gets for it is all that happens, as on bare
    /// metal. That holds while the MTRRs are disabled too, when nothing
    /// decodes them: an OS clears IA32_MTRR_DEF_TYPE.E, writes the ranges,
    /// then sets E again, and a bad range must fault at its own WRMSR, not
    /// at the one that sets E. Writes while E is clear change no type, so
    /// only the write that sets E again returns `true`.
    ///
    /// A value WRMSR takes always decodes, every type field being valid;
    /// should one not, it is refused all the same.
    pub fn write(&mut self, msr: MtrrMsr, value: u64) -> Result<bool, MtrrError> {
        let old = self.registers.get(msr);
        self.registers.write(msr, value)?;
        match self.registers.decode() {
            Ok(mtrrs) => {
                let changed = mtrrs != self.mtrrs;
                self.mtrrs = mtrrs;
                Ok(changed)
            }
            Err(error) => {
                *self.registers.value_mut(msr) = old;
                Err(error)
            }
        }
    }
}

/// Reads this CPU's MTRR MSRs: none when CPUID says it has no MTRRs, since
/// reading one would then raise #GP.
pub fn read() -> Result<MtrrRegisters, MtrrError> {
    let capabilities = if cpuid::has_mtrr() {
        // SAFETY: CPUID reports MTRRs, so IA32_MTRRCAP exists. Reading it
        // has no side effects.
        MtrrCapabilities::new(unsafe { rdmsr(IA32_MTRRCAP) }, cpuid::physical_address_bits())?
    } else {
        MtrrCapabilities::NONE
    };
    // SAFETY: `capabilities` lists only the MTRR MSRs CPUID and
    // IA32_MTRRCAP say exist. Reading them has no side effects.
    MtrrRegisters::read_with(capabilities, |msr| unsafe { rdmsr(msr.address()) })
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/mtrr/registers.rs"]
mod tests;
