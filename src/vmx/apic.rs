//! The Local APIC, as far as Aleph0 needs it: where IA32_APIC_BASE puts its
//! registers, which mode it is in, and the register the test guest reads.
//!
//! In xAPIC mode the registers are a 4 KiB page of MMIO at the base
//! address, `0xFEE00000` unless firmware moved it: device memory outside
//! RAM, which EPT maps UC to itself (`ept::MapLayout`). In x2APIC mode they
//! are MSRs instead, and the page decodes nothing (Intel SDM Vol. 3A, "Local
//! APIC Status and Location" and "x2APIC Mode").

use core::fmt;
use core::ops::RangeInclusive;

use super::ept::WalkEnd;
use super::mtrr::MemoryType;
use super::paging::{Mapping, WalkError};

/// IA32_APIC_BASE: the Local APIC's base address and mode.
pub const IA32_APIC_BASE: u32 = 0x1B;
/// IA32_APIC_BASE bit 8: this CPU is the bootstrap processor.
const APIC_BASE_BSP: u64 = 1 << 8;
/// IA32_APIC_BASE bits 11:10, EN and EXTD: the mode ([`LapicMode`]).
pub const APIC_BASE_MODE: u64 = 0b11 << 10;
/// [`APIC_BASE_MODE`] in xAPIC mode: EN = 1, EXTD = 0.
pub const APIC_BASE_XAPIC: u64 = 0b10 << 10;
/// [`APIC_BASE_MODE`] in x2APIC mode: EN = 1, EXTD = 1.
const APIC_BASE_X2APIC: u64 = 0b11 << 10;
/// [`APIC_BASE_MODE`] with the Local APIC off: EN = 0, EXTD = 0.
const APIC_BASE_DISABLED: u64 = 0;

/// Offset of the version register in the xAPIC's register page.
pub const LAPIC_VERSION: u64 = 0x30;
/// Bits 7:0 of the version register on an integrated APIC, which every
/// CPU since the Pentium has (Intel SDM Vol. 3A, "Local APIC Version
/// Register"). A read of nothing gives `0xFF`, outside the range.
pub const INTEGRATED_APIC_VERSIONS: RangeInclusive<u8> = 0x10..=0x15;

/// The mode bits 11:10 of IA32_APIC_BASE set, named as KVM's `enum
/// lapic_mode` names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LapicMode {
    Disabled,
    /// The registers are the MMIO page at the base address.
    Xapic,
    /// The registers are MSRs; the MMIO page decodes nothing.
    X2apic,
    /// EXTD without EN, which the CPU never takes.
    Invalid,
}

impl LapicMode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Xapic => "xAPIC",
            Self::X2apic => "x2APIC",
            Self::Invalid => "invalid mode",
        }
    }
}

/// An IA32_APIC_BASE value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApicBase(pub u64);

impl ApicBase {
    /// The physical address of the register page, bits MAXPHYADDR-1:12 on a
    /// CPU with `physical_address_bits` (MAXPHYADDR).
    pub fn address(self, physical_address_bits: u8) -> u64 {
        let below_maxphyaddr = u64::MAX
            .checked_shr(64u32.saturating_sub(physical_address_bits.into()))
            .unwrap_or(0);
        self.0 & below_maxphyaddr & !0xFFF
    }

    pub fn mode(self) -> LapicMode {
        match self.0 & APIC_BASE_MODE {
            APIC_BASE_DISABLED => LapicMode::Disabled,
            APIC_BASE_XAPIC => LapicMode::Xapic,
            APIC_BASE_X2APIC => LapicMode::X2apic,
            _ => LapicMode::Invalid,
        }
    }

    /// Whether this CPU is the bootstrap processor (bit 8).
    pub fn bsp(self) -> bool {
        self.0 & APIC_BASE_BSP != 0
    }
}

impl fmt::Display for ApicBase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x} ({}", self.0, self.mode().name())?;
        if self.bsp() {
            f.write_str(", BSP")?;
        }
        f.write_str(")")
    }
}

/// Why the test guest could not read the Local APIC's registers, in xAPIC
/// mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalApicError {
    /// The page tables the guest shares with bring-up do not map the
    /// register page at `address` to itself: how they translate it instead.
    GuestMapping {
        address: u64,
        translation: Result<Mapping, WalkError>,
    },
    /// EPT does not map the register page at `address` to itself, UC: how
    /// the walk of it ended instead.
    EptMapping { address: u64, end: WalkEnd },
}

/// Checks that the test guest can read the registers of a Local APIC in
/// xAPIC mode, at `address`: the guest's page tables translating the page
/// to itself (`translation`, as `paging::walk_current` gives it), since the
/// guest reads it through that linear address, and EPT mapping it to
/// itself, UC, readable, as the walk of it ended (`walk_end`). In any other
/// mode there is no register page, and the guest skips its read.
pub fn check_registers(
    address: u64,
    translation: Result<Mapping, WalkError>,
    walk_end: WalkEnd,
) -> Result<(), LocalApicError> {
    if translation.map(|mapping| mapping.physical) != Ok(address) {
        return Err(LocalApicError::GuestMapping { address, translation });
    }
    match walk_end {
        WalkEnd::Mapped {
            hpa,
            memory_type: MemoryType::Uncacheable,
            access,
            ..
        } if hpa == address && access & super::ept::EPT_READ != 0 => Ok(()),
        end => Err(LocalApicError::EptMapping { address, end }),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/vmx/apic.rs"]
mod tests;
