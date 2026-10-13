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
//!   [`descriptor_limit`] and [`descriptor_access_rights`].
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
use core::{arch::asm, ptr::read_volatile};

/// Contents of GDTR or IDTR: where a descriptor table starts and how big it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescriptorTable {
    /// Address of the first descriptor.
    pub base: u64,
    /// Size of the table in bytes, minus one.
    pub limit: u16,
}

/// Reads GDTR, the pointer to the Global Descriptor Table.
pub unsafe fn read_gdtr() -> DescriptorTable {
    let mut buffer = [0u8; 10];
    unsafe {
        asm!(
            "sgdt [{0}]",
            in(reg) buffer.as_mut_ptr(),
            // No `nomem`: the instruction writes 10 bytes through that
            // pointer. Claiming otherwise lets the compiler drop the buffer
            // and fold the reads below to zero — which it does in release.
            options(nostack, preserves_flags)
        );
    }

    DescriptorTable {
        base: u64::from_le_bytes([
            buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9],
        ]),
        limit: u16::from_le_bytes([buffer[0], buffer[1]]),
    }
}

/// Reads IDTR, the pointer to the Interrupt Descriptor Table.
pub unsafe fn read_idtr() -> DescriptorTable {
    let mut buffer = [0u8; 10];
    unsafe {
        asm!(
            "sidt [{0}]",
            in(reg) buffer.as_mut_ptr(),
            // No `nomem`: the instruction writes 10 bytes through that
            // pointer. Claiming otherwise lets the compiler drop the buffer
            // and fold the reads below to zero — which it does in release.
            options(nostack, preserves_flags)
        );
    }

    DescriptorTable {
        base: u64::from_le_bytes([
            buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9],
        ]),
        limit: u16::from_le_bytes([buffer[0], buffer[1]]),
    }
}

/// The 10-byte memory operand LGDT and LIDT read: the limit, then the base,
/// both little-endian. SGDT and SIDT write the same layout.
fn descriptor_table_operand(table: &DescriptorTable) -> [u8; 10] {
    let mut operand = [0u8; 10];
    operand[..2].copy_from_slice(&table.limit.to_le_bytes());
    operand[2..].copy_from_slice(&table.base.to_le_bytes());
    operand
}

/// Loads GDTR. Segment registers keep their cached descriptors until they
/// are reloaded, so nothing visible changes until then.
///
/// # Safety
///
/// `table` must describe a live GDT with valid descriptors for the
/// selectors in CS, SS, DS, ES, FS and GS, in case they are reloaded.
pub unsafe fn load_gdtr(table: &DescriptorTable) {
    let operand = descriptor_table_operand(table);
    unsafe {
        asm!(
            "lgdt [{0}]",
            in(reg) operand.as_ptr(),
            options(readonly, nostack, preserves_flags)
        );
    }
}

/// Loads IDTR.
///
/// # Safety
///
/// `table` must describe a live IDT whose gates handle every interrupt and
/// exception that may arrive.
pub unsafe fn load_idtr(table: &DescriptorTable) {
    let operand = descriptor_table_operand(table);
    unsafe {
        asm!(
            "lidt [{0}]",
            in(reg) operand.as_ptr(),
            options(readonly, nostack, preserves_flags)
        );
    }
}

/// Reads the CS selector, which also carries the current privilege level.
pub unsafe fn read_cs() -> u16 {
    let selector: u16;
    unsafe {
        asm!(
            "mov {:x}, cs",
            out(reg) selector,
            options(nomem, nostack, preserves_flags),
        );
    }

    selector
}

/// Reads the SS selector.
pub unsafe fn read_ss() -> u16 {
    let selector: u16;
    unsafe {
        asm!(
            "mov {:x}, ss",
            out(reg) selector,
            options(nomem, nostack, preserves_flags),
        );
    }

    selector
}

/// Reads the DS selector.
pub unsafe fn read_ds() -> u16 {
    let selector: u16;
    unsafe {
        asm!(
            "mov {:x}, ds",
            out(reg) selector,
            options(nomem, nostack, preserves_flags),
        );
    }

    selector
}

/// Reads the ES selector.
pub unsafe fn read_es() -> u16 {
    let selector: u16;
    unsafe {
        asm!(
            "mov {:x}, es",
            out(reg) selector,
            options(nomem, nostack, preserves_flags),
        );
    }

    selector
}

/// Reads the FS selector.
pub unsafe fn read_fs() -> u16 {
    let selector: u16;
    unsafe {
        asm!(
            "mov {:x}, fs",
            out(reg) selector,
            options(nomem, nostack, preserves_flags),
        );
    }

    selector
}

/// Reads the GS selector.
pub unsafe fn read_gs() -> u16 {
    let selector: u16;
    unsafe {
        asm!(
            "mov {:x}, gs",
            out(reg) selector,
            options(nomem, nostack, preserves_flags),
        );
    }

    selector
}

/// Reads the Task Register selector, which points at the TSS descriptor.
///
/// A zero value here is a problem: VM entry rejects a host TR selector of 0.
/// Firmware may leave TR unset, so check it before preparing VMCS host state.
pub unsafe fn read_tr() -> u16 {
    let selector: u16;
    unsafe {
        asm!(
            "str {:x}",
            out(reg) selector,
            options(nomem, nostack, preserves_flags),
        );
    }

    selector
}

/// Reads the FS base from [`msr::IA32_FS_BASE`].
pub unsafe fn read_fs_base() -> u64 {
    unsafe { msr::rdmsr(msr::IA32_FS_BASE) }
}

/// Reads the GS base from [`msr::IA32_GS_BASE`].
pub unsafe fn read_gs_base() -> u64 {
    unsafe { msr::rdmsr(msr::IA32_GS_BASE) }
}

/// Extracts a segment's base address from its GDT descriptor.
///
/// Needed for TR, whose base is not available from any register or MSR — it
/// has to be read out of the descriptor the selector points at.
///
/// The selector's index is bits 15:3, and each descriptor is 8 bytes, so the
/// selector value is already the byte offset into the table. A TSS descriptor
/// in long mode is 16 bytes and scatters the base across four fields:
///
/// ```text
/// bytes 2..4    base 15:0
/// byte  4       base 23:16
/// byte  7       base 31:24
/// bytes 8..12   base 63:32
/// ```
///
/// # Safety
///
/// `gdt` must describe a live, readable GDT through its reported limit.
/// A selector outside that limit, or one referring to the LDT, returns zero.
pub unsafe fn segment_base_from_gdt(gdt: &DescriptorTable, selector: u16) -> u64 {
    // The low 3 bits are RPL and TI, so 0x01..0x03 also name the null
    // descriptor. Shift them off before testing.
    let index = (selector >> 3) as u64;
    if index == 0 {
        return 0;
    }

    let offset = (index * 8) as usize;
    if selector & 0x4 != 0 || offset + 12 > gdt.limit as usize + 1 {
        return 0;
    }

    // Each descriptor is 8 bytes, so this is where the descriptor lives —
    // not the base itself, which is stored inside it.
    let descriptor = (gdt.base + offset as u64) as *const u8;

    unsafe {
        let low = u16::from_le_bytes([read_volatile(descriptor.add(2)), read_volatile(descriptor.add(3))]) as u64;
        let mid = read_volatile(descriptor.add(4)) as u64;
        let high = read_volatile(descriptor.add(7)) as u64;
        let upper = u32::from_le_bytes([
            read_volatile(descriptor.add(8)),
            read_volatile(descriptor.add(9)),
            read_volatile(descriptor.add(10)),
            read_volatile(descriptor.add(11)),
        ]) as u64;

        low | (mid << 16) | (high << 24) | (upper << 32)
    }
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

/// Base bits 31:0 of an 8-byte descriptor.
///
/// Enough for CS, SS, DS and ES, whose bases are 32-bit (and ignored in
/// 64-bit mode). FS and GS take their 64-bit base from MSRs instead; TR
/// needs [`segment_base_from_gdt`], since a TSS descriptor is 16 bytes.
pub fn descriptor_base(descriptor: u64) -> u64 {
    ((descriptor >> 16) & 0xFF_FFFF) | ((descriptor >> 32) & 0xFF00_0000)
}

/// The segment limit in bytes, as the VMCS wants it.
///
/// The descriptor stores 20 bits. With G = 1 they count 4 KiB pages, so
/// the byte limit is `raw * 4096 + 4095`: 0xFFFFF becomes 0xFFFF_FFFF.
pub fn descriptor_limit(descriptor: u64) -> u32 {
    let raw = (descriptor & 0xFFFF) as u32 | ((descriptor >> 32) as u32 & 0xF_0000);
    if descriptor & DESCRIPTOR_GRANULARITY != 0 {
        (raw << 12) | 0xFFF
    } else {
        raw
    }
}

/// The access rights in VMCS format: descriptor bits 47:40 become bits 7:0,
/// descriptor bits 55:52 become bits 15:12, and the limit bits in between
/// (11:8 here) are cleared, since VM entry requires them to be 0.
pub fn descriptor_access_rights(descriptor: u64) -> u32 {
    (descriptor >> 40) as u32 & 0xF0FF
}

/// Reads the 8-byte descriptor `selector` points at.
///
/// Returns `None` for a null selector, an LDT selector (TI = 1), or one
/// whose descriptor would extend past the GDT limit.
///
/// # Safety
///
/// `gdt` must describe a live, readable GDT through its reported limit.
pub unsafe fn read_descriptor(gdt: &DescriptorTable, selector: u16) -> Option<u64> {
    // The low 3 bits are RPL and TI; the rest is the byte offset.
    let offset = (selector & !0b111) as usize;
    if selector & 0x4 != 0 || offset == 0 || offset + 8 > gdt.limit as usize + 1 {
        return None;
    }
    Some(unsafe { ((gdt.base + offset as u64) as *const u64).read_unaligned() })
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
pub unsafe fn read_all() -> SegmentState {
    unsafe {
        // Both are needed before the struct can be built: TR's base is only
        // reachable by indexing the GDT with the TR selector.
        let gdtr = read_gdtr();
        let tr = read_tr();

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
