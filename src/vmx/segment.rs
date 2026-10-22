//! Reading the CPU's segmentation state.
//!
//! Long mode barely uses segmentation — most bases are 0 and limits are
//! ignored — but the registers still exist, and VM entry checks the values
//! written into the VMCS for both host and guest. So the state has to be read
//! out of the running CPU and copied in.
//!
//! Three kinds of value are needed per segment:
//!
//! * the **selector** — an index into the GDT, held in CS/SS/DS/ES/FS/GS/TR;
//! * the **base** — the real 64-bit start address. Only FS, GS and TR matter
//!   in long mode; the rest are architecturally 0.
//! * the **limit** and **access rights** — needed for guest state, not for
//!   host state. They are decoded from the segment's GDT descriptor by
//!   [`SegmentDescriptor::limit`] and [`SegmentDescriptor::access_rights`].
//!
//! Host state has two extra rules the CPU enforces at VM entry, both common
//! causes of "invalid host state" (error 8):
//!
//! * every host selector must have its RPL and TI bits (the low 3) clear;
//! * the host TR selector must not be 0 — it has to point at a real TSS.
//!
//! Nothing here needs VMX, so [`read_all`] can be called and printed under
//! plain QEMU/TCG to sanity-check the values before any VMCS work.

use super::msr;
use core::arch::asm;

/// Contents of GDTR or IDTR: where a descriptor table starts and how big it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescriptorTable {
    /// Address of the first descriptor.
    pub base: u64,
    /// Size of the table in bytes, minus one.
    pub limit: u16,
}

impl DescriptorTable {
    /// The 10-byte memory operand of LGDT/LIDT and SGDT/SIDT: the limit,
    /// then the base, both little-endian.
    pub fn to_operand(self) -> [u8; 10] {
        let mut operand = [0u8; 10];
        operand[..2].copy_from_slice(&self.limit.to_le_bytes());
        operand[2..].copy_from_slice(&self.base.to_le_bytes());
        operand
    }

    /// The inverse of [`DescriptorTable::to_operand`].
    pub fn from_operand(operand: [u8; 10]) -> Self {
        let [limit_low, limit_high, base @ ..] = operand;
        Self {
            base: u64::from_le_bytes(base),
            limit: u16::from_le_bytes([limit_low, limit_high]),
        }
    }
}

/// Reads GDTR, the pointer to the Global Descriptor Table.
pub fn read_gdtr() -> DescriptorTable {
    let mut operand = [0u8; 10];
    // SAFETY: SGDT writes exactly 10 bytes to `operand`, which is ours and
    // 10 bytes long; it has no other effect. No `nomem`: claiming it lets the
    // compiler drop the buffer and fold the decoding to zero, which it does
    // in release.
    unsafe { asm!("sgdt [{0}]", in(reg) operand.as_mut_ptr(), options(nostack, preserves_flags)) };
    DescriptorTable::from_operand(operand)
}

/// Reads IDTR, the pointer to the Interrupt Descriptor Table.
pub fn read_idtr() -> DescriptorTable {
    let mut operand = [0u8; 10];
    // SAFETY: as in `read_gdtr`, with SIDT.
    unsafe { asm!("sidt [{0}]", in(reg) operand.as_mut_ptr(), options(nostack, preserves_flags)) };
    DescriptorTable::from_operand(operand)
}

/// Loads GDTR. Segment registers keep their cached descriptors until they
/// are reloaded, so nothing visible changes until then.
///
/// # Safety
///
/// `table` must describe a live GDT with valid descriptors for the
/// selectors in CS, SS, DS, ES, FS and GS, in case they are reloaded.
pub unsafe fn load_gdtr(table: &DescriptorTable) {
    let operand = table.to_operand();
    // SAFETY: LGDT only reads the 10-byte operand; the caller guarantees the
    // table it names is live and valid.
    unsafe { asm!("lgdt [{0}]", in(reg) operand.as_ptr(), options(readonly, nostack, preserves_flags)) };
}

/// Loads IDTR.
///
/// # Safety
///
/// `table` must describe a live IDT whose gates handle every interrupt and
/// exception that may arrive.
pub unsafe fn load_idtr(table: &DescriptorTable) {
    let operand = table.to_operand();
    // SAFETY: LIDT only reads the 10-byte operand; the caller guarantees the
    // table it names is live and handles every vector that may arrive.
    unsafe { asm!("lidt [{0}]", in(reg) operand.as_ptr(), options(readonly, nostack, preserves_flags)) };
}

/// Defines a safe reader for one selector register. Reading a selector (or
/// TR with STR) has no side effects, and Aleph0 always runs in ring 0, where
/// neither instruction can fault.
macro_rules! selector_reader {
    ($(#[$doc:meta])* $name:ident, $instruction:literal) => {
        $(#[$doc])*
        pub fn $name() -> u16 {
            let selector: u16;
            // SAFETY: a read of a selector register: no memory access, no
            // side effects, no fault in ring 0.
            unsafe { asm!($instruction, out(reg) selector, options(nomem, nostack, preserves_flags)) };
            selector
        }
    };
}

selector_reader!(
    /// Reads the CS selector, which also carries the current privilege level.
    read_cs,
    "mov {:x}, cs"
);
selector_reader!(
    /// Reads the SS selector.
    read_ss,
    "mov {:x}, ss"
);
selector_reader!(
    /// Reads the DS selector.
    read_ds,
    "mov {:x}, ds"
);
selector_reader!(
    /// Reads the ES selector.
    read_es,
    "mov {:x}, es"
);
selector_reader!(
    /// Reads the FS selector.
    read_fs,
    "mov {:x}, fs"
);
selector_reader!(
    /// Reads the GS selector.
    read_gs,
    "mov {:x}, gs"
);
selector_reader!(
    /// Reads the Task Register selector, which points at the TSS descriptor.
    ///
    /// A zero value here is a problem: VM entry rejects a host TR selector of
    /// 0. Firmware may leave TR unset, so check it before preparing VMCS host
    /// state.
    read_tr,
    "str {:x}"
);

/// Reads the FS base from [`msr::IA32_FS_BASE`].
///
/// # Safety
///
/// The CPU must support long mode, so that the MSR exists.
pub unsafe fn read_fs_base() -> u64 {
    // SAFETY: the caller guarantees long mode, which has IA32_FS_BASE.
    unsafe { msr::rdmsr(msr::IA32_FS_BASE) }
}

/// Reads the GS base from [`msr::IA32_GS_BASE`].
///
/// # Safety
///
/// The CPU must support long mode, so that the MSR exists.
pub unsafe fn read_gs_base() -> u64 {
    // SAFETY: the caller guarantees long mode, which has IA32_GS_BASE.
    unsafe { msr::rdmsr(msr::IA32_GS_BASE) }
}

/// Selector bits 1:0 (RPL): the requested privilege level. Selectors 0-3
/// all name the null descriptor.
pub const SELECTOR_RPL: u16 = 0b11;
/// Selector bit 2 (TI): the selector names the LDT, not the GDT.
pub const SELECTOR_TI: u16 = 1 << 2;
/// Selector bits 2:0, TI and RPL. Clearing them leaves the byte offset of
/// the descriptor in the table.
pub const SELECTOR_RPL_TI: u16 = 0b111;

/// Byte offset in `gdt` of the `size`-byte descriptor `selector` names.
///
/// The selector's index is bits 15:3 and each GDT slot is 8 bytes, so the
/// selector with its low 3 bits cleared is already the byte offset. `None`
/// for a null selector (any RPL), an LDT selector (TI = 1), or a descriptor
/// that does not end within the GDT limit.
pub fn descriptor_offset(gdt: &DescriptorTable, selector: u16, size: usize) -> Option<usize> {
    let offset = usize::from(selector & !SELECTOR_RPL_TI);
    let fits = offset + size <= usize::from(gdt.limit) + 1;
    (selector & SELECTOR_TI == 0 && offset != 0 && fits).then_some(offset)
}

/// Size of one 64-bit IDT gate.
pub const GATE_SIZE: usize = 16;
/// Gate byte 5: present (bit 7), DPL 0, type 0xE (64-bit interrupt gate,
/// which clears RFLAGS.IF on delivery).
const INTERRUPT_GATE_PRESENT: u8 = 0x8E;
/// Gate byte 4, bits 2:0: the IST index.
const GATE_IST_MASK: u8 = 0b111;

/// A 64-bit interrupt gate to `handler` through code segment `selector`:
/// present, DPL 0, on interrupt stack `ist` (1-7 name the TSS's IST1-IST7;
/// 0 keeps the stack the CPU is on). Only bits 2:0 of `ist` are encodable.
///
/// ```text
/// bytes 0-1    handler bits 15:0
/// bytes 2-3    code segment selector
/// byte  4      bits 2:0: IST index
/// byte  5      0x8E: present, DPL 0, type 0xE (64-bit interrupt gate)
/// bytes 6-7    handler bits 31:16
/// bytes 8-11   handler bits 63:32
/// bytes 12-15  reserved, 0
/// ```
pub fn interrupt_gate(handler: u64, selector: u16, ist: u8) -> [u8; GATE_SIZE] {
    let mut gate = [0u8; GATE_SIZE];
    gate[0..2].copy_from_slice(&(handler as u16).to_le_bytes());
    gate[2..4].copy_from_slice(&selector.to_le_bytes());
    gate[4] = ist & GATE_IST_MASK;
    gate[5] = INTERRUPT_GATE_PRESENT;
    gate[6..8].copy_from_slice(&((handler >> 16) as u16).to_le_bytes());
    gate[8..12].copy_from_slice(&((handler >> 32) as u32).to_le_bytes());
    gate
}

/// Base address in a 16-byte system descriptor (a 64-bit TSS). Bits 31:0
/// are scattered as in a code/data descriptor; bits 63:32 follow in bytes
/// 8-11:
///
/// ```text
/// bytes 2..4    base 15:0
/// byte  4       base 23:16
/// byte  7       base 31:24
/// bytes 8..12   base 63:32
/// ```
pub fn system_descriptor_base(bytes: &[u8; 16]) -> u64 {
    let (low, high) = bytes.split_at(8);
    let low = SegmentDescriptor(u64::from_le_bytes(low.try_into().expect("8 bytes")));
    let high = u32::from_le_bytes(high[..4].try_into().expect("4 bytes"));
    low.base() | (u64::from(high) << 32)
}

/// Extracts a segment's base address from its 16-byte GDT descriptor, or 0
/// if [`descriptor_offset`] refuses the selector.
///
/// Needed for TR, whose base is not available from any register or MSR — it
/// has to be read out of the descriptor the selector points at.
///
/// # Safety
///
/// `gdt` must describe a live, readable GDT through its reported limit.
pub unsafe fn segment_base_from_gdt(gdt: &DescriptorTable, selector: u16) -> u64 {
    let Some(offset) = descriptor_offset(gdt, selector, 16) else {
        return 0;
    };
    // SAFETY: `descriptor_offset` checked that the 16 bytes lie within the
    // limit, and the caller guarantees the table is readable.
    let bytes = unsafe { ((gdt.base + offset as u64) as *const [u8; 16]).read_unaligned() };
    system_descriptor_base(&bytes)
}

// An 8-byte code/data descriptor, as a little-endian u64. The base and limit
// are scattered for backwards compatibility with the 286:
//
//  63    56 55 54 53 52 51  48 47 46 45 44 43  40 39             16 15       0
// ┌────────┬──┬──┬──┬───┬─────┬──┬─────┬──┬──────┬─────────────────┬──────────┐
// │base    │G │D │L │AVL│limit│P │ DPL │S │ type │ base 23:0       │limit 15:0│
// │31:24   │  │/B│  │   │19:16│  │     │  │      │                 │          │
// └────────┴──┴──┴──┴───┴─────┴──┴─────┴──┴──────┴─────────────────┴──────────┘
//
// The VMCS stores access rights as bits 55:52 and 47:40 of this, packed
// together with the limit bits removed:
//
//  31     17  16     15 14 13 12  11  8  7  6 5  4  3   0
// ┌─────────┬────────┬──┬──┬──┬───┬─────┬──┬───┬──┬──────┐
// │reserved │unusable│G │D │L │AVL│ res │P │DPL│S │ type │
// └─────────┴────────┴──┴──┴──┴───┴─────┴──┴───┴──┴──────┘

/// VMCS access-rights bit 16: the segment register is unusable, as after
/// loading a null selector. VM entry then ignores the other bits.
pub const ACCESS_RIGHTS_UNUSABLE: u32 = 1 << 16;

/// Descriptor bit 55 (G): the limit counts 4 KiB units, not bytes.
const DESCRIPTOR_GRANULARITY: u64 = 1 << 55;

/// An 8-byte code or data descriptor from the GDT, as a little-endian u64
/// (see the layout above).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentDescriptor(pub u64);

impl SegmentDescriptor {
    /// Base bits 31:0.
    ///
    /// Enough for CS, SS, DS and ES, whose bases are 32-bit (and ignored in
    /// 64-bit mode). FS and GS take their 64-bit base from MSRs instead; TR
    /// needs [`segment_base_from_gdt`], since a TSS descriptor is 16 bytes.
    pub fn base(self) -> u64 {
        ((self.0 >> 16) & 0xFF_FFFF) | ((self.0 >> 32) & 0xFF00_0000)
    }

    /// The segment limit in bytes, as the VMCS wants it.
    ///
    /// The descriptor stores 20 bits. With G = 1 they count 4 KiB pages, so
    /// the byte limit is `raw * 4096 + 4095`: 0xFFFFF becomes 0xFFFF_FFFF.
    pub fn limit(self) -> u32 {
        let raw = (self.0 & 0xFFFF) as u32 | ((self.0 >> 32) as u32 & 0xF_0000);
        if self.0 & DESCRIPTOR_GRANULARITY != 0 {
            (raw << 12) | 0xFFF
        } else {
            raw
        }
    }

    /// The access rights in VMCS format: descriptor bits 47:40 become bits
    /// 7:0, descriptor bits 55:52 become bits 15:12, and the limit bits in
    /// between (11:8 here) are cleared, since VM entry requires them to be 0.
    pub fn access_rights(self) -> u32 {
        (self.0 >> 40) as u32 & 0xF0FF
    }
}

/// Reads the 8-byte descriptor `selector` names, or `None` if
/// [`descriptor_offset`] refuses it.
///
/// # Safety
///
/// `gdt` must describe a live, readable GDT through its reported limit.
pub unsafe fn read_descriptor(gdt: &DescriptorTable, selector: u16) -> Option<SegmentDescriptor> {
    let offset = descriptor_offset(gdt, selector, 8)?;
    // SAFETY: `descriptor_offset` checked that the 8 bytes lie within the
    // limit, and the caller guarantees the table is readable.
    let raw = unsafe { ((gdt.base + offset as u64) as *const u64).read_unaligned() };
    Some(SegmentDescriptor(raw))
}

/// Everything about the current segmentation state, for printing or for
/// filling in the VMCS.
#[derive(Debug, Clone, Copy)]
pub struct SegmentState {
    pub cs: u16,
    pub ss: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub tr: u16,
    pub fs_base: u64,
    pub gs_base: u64,
    pub tr_base: u64,
    pub gdtr: DescriptorTable,
    pub idtr: DescriptorTable,
}

/// Snapshots the current segmentation state.
///
/// # Safety
///
/// The current GDT must be live and readable through its limit (TR's base is
/// read from it), and the CPU must be in long mode (FS/GS bases are MSRs).
pub unsafe fn read_all() -> SegmentState {
    // Both are needed before the struct can be built: TR's base is only
    // reachable by indexing the GDT with the TR selector.
    let gdtr = read_gdtr();
    let tr = read_tr();

    // SAFETY: the caller guarantees long mode and a readable GDT.
    unsafe {
        SegmentState {
            cs: read_cs(),
            ss: read_ss(),
            ds: read_ds(),
            es: read_es(),
            fs: read_fs(),
            gs: read_gs(),
            tr,
            fs_base: read_fs_base(),
            gs_base: read_gs_base(),
            tr_base: segment_base_from_gdt(&gdtr, tr),
            gdtr,
            idtr: read_idtr(),
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/vmx/segment.rs"]
mod tests;
