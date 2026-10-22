//! Aleph0's own GDT for VMX root operation.
//!
//! A VM exit loads GDTR from HOST_GDTR_BASE and the selectors from the host
//! selector fields. The CPU then reads this GDT whenever it reloads a
//! segment register from it: IRETQ out of the host NMI handler reloads CS
//! and SS, and so does any interrupt return.
//!
//! The descriptors sit at the *firmware's* selector indices. On Hyper-V the
//! firmware runs with CS = 0x28 and SS = DS = ES = FS = GS = 0x08, so:
//!
//! ```text
//! index  selector  descriptor
//!   0     0x00     null
//!   1     0x08     data: flat, read/write
//!   2-4            null (unused)
//!   5     0x28     code: 64-bit, execute/read
//!   6-7   0x30     TSS (16 bytes: two slots)
//! ```
//!
//! Teardown loads the firmware's GDTR again but cannot reload CS without a
//! far return. With the same selectors in both tables, the selectors the CPU
//! keeps after a VM exit name the firmware's own code and data descriptors
//! once the firmware's GDT is back, so a later interrupt return in firmware
//! finds what it expects. The TSS takes the first free slot above them.

use super::HostError;
use crate::vmx::host_tables::{TSS_SIZE, tss_descriptor};
use crate::vmx::page::PAGE_SIZE;
use crate::vmx::segment::{self, SELECTOR_RPL_TI};
use crate::vmx::vmcs::HostSelectors;

/// A flat 64-bit code descriptor: base 0, limit 0xFFFFF in 4 KiB units
/// (G = 1), L = 1 and D = 0 (64-bit), present, DPL 0, type 0xB
/// (execute/read, accessed).
pub const CODE_64: u64 = 0x00AF_9B00_0000_FFFF;
/// A flat data descriptor: base 0, limit 0xFFFFF in 4 KiB units (G = 1),
/// D/B = 1, present, DPL 0, type 0x3 (read/write, accessed).
///
/// Both descriptors have the accessed bit set already, so the CPU never
/// writes the GDT to set it.
pub const DATA: u64 = 0x00CF_9300_0000_FFFF;

/// Bytes per GDT slot.
const SLOT_SIZE: usize = 8;
/// Slots in the one page the GDT lives in.
pub const SLOTS: usize = PAGE_SIZE / SLOT_SIZE;

/// The selectors the firmware runs with, which the host GDT keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareSelectors {
    pub cs: u16,
    pub ss: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
}

impl FirmwareSelectors {
    /// The selectors in the segment registers right now.
    pub fn read() -> Self {
        Self {
            cs: segment::read_cs(),
            ss: segment::read_ss(),
            ds: segment::read_ds(),
            es: segment::read_es(),
            fs: segment::read_fs(),
            gs: segment::read_gs(),
        }
    }

    /// The data selectors, in the order the VMCS host fields list them.
    fn data(self) -> [u16; 5] {
        [self.ss, self.ds, self.es, self.fs, self.gs]
    }
}

/// Why the host GDT cannot keep the firmware's selectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GdtLayoutError {
    /// CS is null. VM entry refuses a null host CS.
    NullCode,
    /// `selector` has RPL or TI set. VM entry requires both clear in every
    /// host selector.
    NotRing0Gdt { selector: u16 },
    /// A data selector names CS's slot, which cannot hold both descriptors.
    DataInCodeSlot { selector: u16 },
    /// The descriptors and the TSS do not fit in one page.
    TooLarge,
}

/// Where the descriptors go: the selectors the VMCS host fields take, and
/// the GDT limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GdtLayout {
    pub selectors: HostSelectors,
    /// GDTR limit: the last byte of the TSS descriptor. A VM exit sets the
    /// limit to 0xFFFF regardless; this is for the report and the tests.
    pub limit: u16,
}

/// The slot `selector` names: its index, bits 15:3.
fn slot(selector: u16) -> usize {
    usize::from(selector >> 3)
}

/// Lays out a GDT that keeps `firmware`'s selectors: the code descriptor at
/// CS's slot, a data descriptor at the slot of every non-null data selector,
/// and the TSS in the two slots after the highest of them.
pub fn layout(firmware: FirmwareSelectors) -> Result<GdtLayout, GdtLayoutError> {
    let all = [firmware.cs].into_iter().chain(firmware.data());
    if let Some(selector) = all.clone().find(|selector| selector & SELECTOR_RPL_TI != 0) {
        return Err(GdtLayoutError::NotRing0Gdt { selector });
    }
    if slot(firmware.cs) == 0 {
        return Err(GdtLayoutError::NullCode);
    }
    if let Some(selector) = firmware
        .data()
        .into_iter()
        .find(|&data| slot(data) == slot(firmware.cs))
    {
        return Err(GdtLayoutError::DataInCodeSlot { selector });
    }

    let tss_slot = all.map(slot).max().unwrap_or(0) + 1;
    if tss_slot + 2 > SLOTS {
        return Err(GdtLayoutError::TooLarge);
    }
    let tr = (tss_slot * SLOT_SIZE) as u16;
    Ok(GdtLayout {
        selectors: HostSelectors {
            cs: firmware.cs,
            ss: firmware.ss,
            ds: firmware.ds,
            es: firmware.es,
            fs: firmware.fs,
            gs: firmware.gs,
            tr,
        },
        limit: tr + 2 * SLOT_SIZE as u16 - 1,
    })
}

/// Writes the GDT `layout` describes into `gdt` (one page of [`SLOTS`]
/// slots), with a TSS descriptor for the TSS at `tss_base`. Every slot the
/// layout does not use is null.
pub fn encode(layout: &GdtLayout, tss_base: u64, gdt: &mut [u64; SLOTS]) {
    let selectors = layout.selectors;
    gdt.fill(0);
    for data in [selectors.ss, selectors.ds, selectors.es, selectors.fs, selectors.gs] {
        if slot(data) != 0 {
            gdt[slot(data)] = DATA;
        }
    }
    gdt[slot(selectors.cs)] = CODE_64;

    let tss = tss_descriptor(tss_base, (TSS_SIZE - 1) as u32);
    let (low, high) = tss.split_at(SLOT_SIZE);
    gdt[slot(selectors.tr)] = u64::from_le_bytes(low.try_into().expect("8 bytes"));
    gdt[slot(selectors.tr) + 1] = u64::from_le_bytes(high.try_into().expect("8 bytes"));
}

impl From<GdtLayoutError> for HostError {
    fn from(error: GdtLayoutError) -> Self {
        Self::Gdt(error)
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/host/gdt.rs"]
mod tests;
