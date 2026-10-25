//! Reading the EPT tables back the way the CPU walks them: what it refuses
//! in an entry ([`check_entry`]), and the path of one GPA from the EPTP down
//! ([`walk`]).
//!
//! An EPT misconfiguration (exit reason 49) is an entry the CPU refuses to
//! use at all; an EPT violation (reason 48) an access the entries do not
//! allow, or a GPA nothing maps. Aleph0's map allows every access but one
//! (`Ept::build`), so either exit means the map is wrong, and the exit
//! handler prints the walk: every entry on the GPA's path, what the CPU
//! refuses in it, and how the walk ended. KVM prints the same hierarchy for
//! a reserved-bit fault on its own EPT entries (`get_mmio_spte`: "reserved
//! bits set on MMU-present spte ... hierarchy"), from the same rules
//! (`__reset_rsvds_bits_mask_ep` and `is_rsvd_spte`).
//!
//! Both are pure. [`walk`] reads entries through a function the caller
//! gives it, which returns `None` for an address outside the tables, so a
//! corrupt table pointer is reported, never followed.

use core::fmt;

use super::level::{Level, Pd, Pdpt, Pml4, Pt};
use super::{
    ADDRESS_MASK, EPT_EXECUTE, EPT_READ, EPT_RWX, EPT_WRITE, EntryRules, Eptp, LARGE_PAGE, MEMORY_TYPE_BITS,
    MEMORY_TYPE_SHIFT, WALK_ADDRESS_BITS, leaf_memory_type,
};
use crate::vmx::mtrr::MemoryType;

/// A table level of the walk, from the root down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkLevel {
    Pml4,
    Pdpt,
    Pd,
    Pt,
}

impl WalkLevel {
    /// The level's name: "PML4", "PDPT", "PD" or "PT".
    pub fn name(self) -> &'static str {
        match self {
            Self::Pml4 => Pml4::NAME,
            Self::Pdpt => Pdpt::NAME,
            Self::Pd => Pd::NAME,
            Self::Pt => Pt::NAME,
        }
    }

    /// Index of `gpa`'s entry in a table of this level.
    pub fn index(self, gpa: u64) -> usize {
        match self {
            Self::Pml4 => Pml4::index(gpa),
            Self::Pdpt => Pdpt::index(gpa),
            Self::Pd => Pd::index(gpa),
            Self::Pt => Pt::index(gpa),
        }
    }

    /// The level of the table an entry here points to; `None` for a PT,
    /// whose entries always map a page.
    fn below(self) -> Option<Self> {
        match self {
            Self::Pml4 => Some(Self::Pdpt),
            Self::Pdpt => Some(Self::Pd),
            Self::Pd => Some(Self::Pt),
            Self::Pt => None,
        }
    }

    /// Whether the entry `raw` at this level maps a page itself: every PT
    /// entry, and a PDPT or PD entry with bit 7 set. A PML4 entry never
    /// does: bit 7 is reserved there.
    fn is_leaf(self, raw: u64) -> bool {
        match self {
            Self::Pml4 => false,
            Self::Pdpt | Self::Pd => raw & LARGE_PAGE != 0,
            Self::Pt => true,
        }
    }

    /// Bytes a page this level's entry maps: 4 KiB at a PT, 2 MiB at a PD,
    /// 1 GiB at a PDPT.
    fn page_size(self) -> u64 {
        let shift = match self {
            Self::Pml4 => Pml4::SHIFT,
            Self::Pdpt => Pdpt::SHIFT,
            Self::Pd => Pd::SHIFT,
            Self::Pt => Pt::SHIFT,
        };
        1 << shift
    }
}

/// Bits `low..=high` set, as KVM's `rsvd_bits`.
const fn bits(low: u32, high: u32) -> u64 {
    (u64::MAX >> (63 - high)) & (u64::MAX << low)
}

/// The bits an entry at `level` must keep 0: one that points to a table,
/// or with `leaf` one that maps a page. These are KVM's EPT
/// `rsvd_bits_mask` (`__reset_rsvds_bits_mask_ep`), from the formats in the
/// Intel SDM (Vol. 3C, "EPT Translation Mechanism").
fn reserved_bits(level: WalkLevel, leaf: bool, rules: EntryRules) -> u64 {
    // Address bits from MAXPHYADDR up to 51, at every level.
    let address = match rules.physical_address_bits {
        bits_used @ 0..=51 => bits(u32::from(bits_used), 51),
        _ => 0,
    };
    address
        | match (level, leaf) {
            // No memory type, no IPAT and no page size in a PML4 entry.
            (WalkLevel::Pml4, _) => bits(3, 7),
            // No memory type and no IPAT in an entry pointing to a table.
            (WalkLevel::Pdpt | WalkLevel::Pd, false) => bits(3, 6),
            // A 1 GiB page's address bits below its alignment, and the page
            // size bit itself on a CPU without 1 GiB pages.
            (WalkLevel::Pdpt, true) => bits(12, 29) | if rules.huge_pages { 0 } else { LARGE_PAGE },
            // A 2 MiB page's address bits below its alignment. 2 MiB pages
            // themselves are allowed: `check_support` requires them.
            (WalkLevel::Pd, true) => bits(12, 20),
            (WalkLevel::Pt, _) => 0,
        }
}

/// An access an entry's bits 2:0 may not allow (KVM's `bad_mt_xwr` for its
/// XWR part).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadAccess {
    /// W = 1 with R = 0: 010b or 110b.
    WriteWithoutRead,
    /// X = 1 with R = W = 0, 100b, on a CPU without execute-only pages
    /// ([`EntryRules::execute_only`]).
    ExecuteOnly,
}

/// What the CPU refuses in one EPT entry ([`check_entry`]): any of it is an
/// EPT misconfiguration once a walk reaches the entry (Intel SDM Vol. 3C,
/// "EPT Misconfigurations").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EntryFaults {
    /// The bits set that the entry's level reserves.
    pub reserved_bits: u64,
    /// An access bits 2:0 may not allow.
    pub bad_access: Option<BadAccess>,
    /// A page's memory type (bits 5:3) when it is a reserved value: 2, 3 or
    /// 7.
    pub reserved_memory_type: Option<u8>,
}

impl EntryFaults {
    /// Whether the CPU uses the entry as it is.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

impl fmt::Display for EntryFaults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("ok");
        }
        let mut separator = "";
        if self.reserved_bits != 0 {
            write!(f, "reserved bits {:#x} set", self.reserved_bits)?;
            separator = "; ";
        }
        if let Some(access) = self.bad_access {
            let what = match access {
                BadAccess::WriteWithoutRead => "write without read",
                BadAccess::ExecuteOnly => "execute-only, which this CPU does not allow",
            };
            write!(f, "{separator}{what}")?;
            separator = "; ";
        }
        if let Some(memory_type) = self.reserved_memory_type {
            write!(f, "{separator}reserved memory type {memory_type}")?;
        }
        Ok(())
    }
}

/// What the CPU refuses in `raw`, an entry at `level`, on a CPU with
/// `rules`: KVM's `is_rsvd_spte`. Nothing for an entry with R = W = X = 0:
/// that one is not present, and a walk reaching it is an EPT violation, not
/// a misconfiguration. (Mode-based execute control, which would make bit 10
/// an execute bit too, is off.)
pub fn check_entry(raw: u64, level: WalkLevel, rules: EntryRules) -> EntryFaults {
    let access = raw & EPT_RWX;
    if access == 0 {
        return EntryFaults::default();
    }
    let leaf = level.is_leaf(raw);
    let bad_access = if access & EPT_WRITE != 0 && access & EPT_READ == 0 {
        Some(BadAccess::WriteWithoutRead)
    } else if access == EPT_EXECUTE && !rules.execute_only {
        Some(BadAccess::ExecuteOnly)
    } else {
        None
    };
    // Only a page has a memory type; in an entry pointing to a table the
    // same bits are reserved ones.
    let memory_type = ((raw >> MEMORY_TYPE_SHIFT) & MEMORY_TYPE_BITS) as u8;
    EntryFaults {
        reserved_bits: raw & reserved_bits(level, leaf, rules),
        bad_access,
        reserved_memory_type: (leaf && MemoryType::from_raw(memory_type).is_none()).then_some(memory_type),
    }
}

/// One entry a [`walk`] read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkedEntry {
    pub level: WalkLevel,
    /// Its index in its table.
    pub index: usize,
    /// Its physical address.
    pub address: u64,
    pub raw: u64,
    /// What the CPU refuses in it.
    pub faults: EntryFaults,
}

/// How a [`walk`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkEnd {
    /// A page of `size` bytes maps the GPA to `hpa`, allowing `access`
    /// (R, W, X in bits 2:0), of `memory_type`.
    Mapped {
        hpa: u64,
        size: u64,
        access: u64,
        memory_type: MemoryType,
    },
    /// The last entry has R = W = X = 0: nothing maps the GPA.
    NotPresent,
    /// The last entry is one the CPU refuses: an EPT misconfiguration.
    Misconfigured,
    /// The last entry points to `table` (or the EPTP does, with no entry
    /// read), which is not one of the tables: not followed.
    OutsideTables { table: u64 },
    /// The GPA has a bit set above the 48 a 4-level walk translates, which
    /// a CPU whose MAXPHYADDR is larger lets the guest use: nothing maps
    /// it, and no entry is read.
    BeyondWalk,
}

impl fmt::Display for WalkEnd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Mapped {
                hpa,
                size,
                access,
                memory_type,
            } => {
                let size = match size {
                    0x1000 => "4 KiB",
                    0x20_0000 => "2 MiB",
                    _ => "1 GiB",
                };
                write!(
                    f,
                    "mapped to HPA {hpa:#x} by a {size} page, {}, R={} W={} X={}",
                    memory_type.name(),
                    access & EPT_READ,
                    (access & EPT_WRITE) >> 1,
                    (access & EPT_EXECUTE) >> 2,
                )
            }
            Self::NotPresent => f.write_str("not present: nothing maps the GPA"),
            Self::Misconfigured => f.write_str("the CPU refuses the last entry: an EPT misconfiguration"),
            Self::OutsideTables { table } => {
                write!(f, "points to {table:#x}, none of Aleph0's EPT tables: not followed")
            }
            Self::BeyondWalk => f.write_str("beyond the 48 bits a 4-level walk translates: nothing maps the GPA"),
        }
    }
}

/// The path of one GPA through the tables ([`walk`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EptWalk {
    pub gpa: u64,
    entries: [Option<WalkedEntry>; 4],
    pub end: WalkEnd,
}

impl EptWalk {
    /// The entries the walk read, from the PML4 down.
    pub fn entries(&self) -> impl Iterator<Item = &WalkedEntry> {
        self.entries.iter().flatten()
    }
}

/// Walks `gpa` through the tables `eptp` names, as the CPU does: one entry
/// per level from the PML4 down, until one maps a page, is not present, or
/// is one the CPU refuses by `rules` ([`check_entry`]). `read` returns the
/// 8-byte entry at a physical address, or `None` for an address outside
/// the tables, where the walk stops instead of reading on.
pub fn walk(eptp: Eptp, gpa: u64, rules: EntryRules, read: impl Fn(u64) -> Option<u64>) -> EptWalk {
    let mut entries = [None; 4];
    // The levels index bits 47:12 only: walked, such a GPA would alias one
    // 2^48 lower.
    if gpa >> WALK_ADDRESS_BITS != 0 {
        return EptWalk {
            gpa,
            entries,
            end: WalkEnd::BeyondWalk,
        };
    }
    let mut table = eptp.pml4();
    let mut level = WalkLevel::Pml4;
    for slot in &mut entries {
        let index = level.index(gpa);
        let address = table + (index * size_of::<u64>()) as u64;
        let Some(raw) = read(address) else {
            return EptWalk {
                gpa,
                entries,
                end: WalkEnd::OutsideTables { table },
            };
        };
        let faults = check_entry(raw, level, rules);
        *slot = Some(WalkedEntry {
            level,
            index,
            address,
            raw,
            faults,
        });
        let end = if raw & EPT_RWX == 0 {
            Some(WalkEnd::NotPresent)
        } else if !faults.is_empty() {
            Some(WalkEnd::Misconfigured)
        } else if level.is_leaf(raw) {
            let size = level.page_size();
            // `check_entry` found no reserved type, so there is one; a page
            // without one would be a misconfiguration all the same.
            Some(
                leaf_memory_type(raw).map_or(WalkEnd::Misconfigured, |memory_type| WalkEnd::Mapped {
                    hpa: (raw & ADDRESS_MASK & !(size - 1)) | (gpa & (size - 1)),
                    size,
                    access: raw & EPT_RWX,
                    memory_type,
                }),
            )
        } else {
            None
        };
        if let Some(end) = end {
            return EptWalk { gpa, entries, end };
        }
        table = raw & ADDRESS_MASK;
        level = level.below().expect("a PT entry always maps a page");
    }
    unreachable!("a PT entry always ends the walk")
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/ept/walk.rs"]
mod tests;
