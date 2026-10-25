//! Guest state for the first VM entry.
//!
//! On VMLAUNCH the CPU loads the guest's registers from the VMCS guest-state
//! fields, checks them, and starts executing at GUEST_RIP. Every register the
//! guest will have must therefore be written here first.
//!
//! The simplest valid 64-bit state is a copy of what the host CPU is running
//! with right now, since that state demonstrably works. Only RIP, RSP,
//! RFLAGS and IDTR depend on the guest ([`GuestEntry`]):
//!
//! | Guest field                  | Value                                     |
//! |------------------------------|-------------------------------------------|
//! | RIP, RSP                     | test guest: its code page and stack top; firmware: the instruction after VMLAUNCH and the stack it runs on |
//! | RFLAGS                       | test guest: `0x2`, only the always-1 bit (IF = 0, AC = 0); firmware: the running RFLAGS, IF included |
//! | CR0, CR3, CR4                | the host's (same page tables, same modes) |
//! | CS, SS, DS, ES, FS, GS, TR   | the host's selectors, decoded from the GDT |
//! | LDTR                         | unusable (UEFI does not use an LDT)       |
//! | GDTR                         | the host's table                          |
//! | IDTR                         | test guest: its own IDT (`GuestMemory::idt`); firmware: the firmware's |
//! | SYSENTER MSRs                | the host's                                |
//! | DR7, IA32_DEBUGCTL           | `0x400` (reset value), `0`                |
//! | PAT, EFER                    | the host's, only if the entry controls load them |
//! | VMCS link pointer            | all ones: no shadow VMCS                  |
//! | activity, interruptibility, pending debug exceptions | `0`: running, nothing blocked |
//!
//! Without the "load IA32_EFER" entry control, the guest keeps the CPU's
//! current EFER, with LMA/LME set from the "IA-32e mode guest" control. So
//! the guest gets the host's EFER.NXE either way, which the shared page
//! tables need (see [`super::paging`]).
//!
//! The guest shares the host's GDT, TSS and page tables. The test guest has
//! an IDT of its own for NMIs; the firmware keeps its own IDT, and stays on
//! Aleph0's GDT copy with its TSS, since VM entry needs a busy TSS in TR and
//! Hyper-V's firmware never loads one. That is a bring-up stage, not
//! isolation.
//!
//! [`GuestState::write`] reads every field back after writing it. As with
//! the host fields, that proves storage only: the CPU checks the state when
//! VMLAUNCH runs, and reports a bad guest state as exit reason 33.
//! [`check_segments`] catches the two mistakes most likely to cause that.
//!
//! After a VM exit the same fields hold the guest's state as the CPU saved
//! it. [`GuestState::read`] reads them back, and every stop prints them with
//! [`GuestState::report`], in the format bring-up prints before VMLAUNCH.

use core::fmt;

use super::cr;
use super::msr;
use super::segment::{self, ACCESS_RIGHTS_UNUSABLE, DescriptorTable, SegmentDescriptor};
use super::vmcs::{self, VmcsError, fields};

/// RFLAGS bit 1 is reserved and must be 1; every other bit is 0.
const INITIAL_RFLAGS: u64 = 0x2;
/// DR7 after reset: only the reserved bit 10 set, no breakpoints.
const INITIAL_DR7: u64 = 0x400;
/// No shadow VMCS. Zero would be read as a pointer and fail VM entry.
const VMCS_LINK_POINTER_NONE: u64 = !0;

/// Access-rights type bit 0: "accessed". VM entry requires it in every
/// usable code/data segment. The CPU normally sets it in the descriptor when
/// the segment is loaded, but that is not guaranteed in a copied GDT.
const TYPE_ACCESSED: u32 = 1 << 0;
/// Access-rights bit 4 (S): 1 = code or data segment, 0 = system segment
/// (TSS, LDT, gates).
const CODE_OR_DATA: u32 = 1 << 4;
/// Access-rights bit 13 (L): 64-bit code segment.
const LONG_MODE: u32 = 1 << 13;
/// Access-rights bits 4:0: S and the 4-bit type, which together say what
/// kind of descriptor it is.
const KIND_MASK: u32 = 0x1F;
/// Access-rights bits 4:0 of a busy 64-bit TSS: S = 0, type 0xB. LTR marks
/// the TSS busy, and VM entry into a 64-bit guest requires that type.
const BUSY_TSS_64: u32 = 0xB;

/// One segment register as the VMCS stores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestSegment {
    pub selector: u16,
    pub base: u64,
    /// In bytes, already scaled by the granularity bit.
    pub limit: u32,
    /// VMCS format; see [`SegmentDescriptor::access_rights`].
    pub access_rights: u32,
}

impl GuestSegment {
    /// A register holding a null selector: unusable, so VM entry ignores
    /// its limit and access rights. FS and GS still pass their MSR base.
    fn unusable(selector: u16, base: u64) -> Self {
        Self {
            selector,
            base,
            limit: 0,
            access_rights: ACCESS_RIGHTS_UNUSABLE,
        }
    }

    /// A usable register loaded from its 8-byte descriptor, with `base`
    /// supplied by the caller (it lives in different places per register).
    fn from_descriptor(selector: u16, descriptor: SegmentDescriptor, base: u64) -> Self {
        let mut access_rights = descriptor.access_rights();
        if access_rights & CODE_OR_DATA != 0 {
            access_rights |= TYPE_ACCESSED;
        }
        Self {
            selector,
            base,
            limit: descriptor.limit(),
            access_rights,
        }
    }

    fn is_usable(&self) -> bool {
        self.access_rights & ACCESS_RIGHTS_UNUSABLE == 0
    }
}

impl fmt::Display for GuestSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "selector={:#06x} base={:#018x} limit={:#010x} access={:#07x}",
            self.selector, self.base, self.limit, self.access_rights,
        )
    }
}

/// The four VMCS fields of one segment register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SegmentFields {
    selector: u32,
    base: u32,
    limit: u32,
    access_rights: u32,
}

/// The fields of ES, CS, SS, DS, FS, GS, LDTR and TR, in the order
/// [`GuestState::segments`] lists the registers. [`GuestState::write`] and
/// [`GuestState::read`] both walk this table, so they cannot disagree.
const SEGMENT_FIELDS: [SegmentFields; 8] = {
    use fields::*;
    [
        SegmentFields {
            selector: GUEST_ES_SELECTOR,
            base: GUEST_ES_BASE,
            limit: GUEST_ES_LIMIT,
            access_rights: GUEST_ES_ACCESS_RIGHTS,
        },
        SegmentFields {
            selector: GUEST_CS_SELECTOR,
            base: GUEST_CS_BASE,
            limit: GUEST_CS_LIMIT,
            access_rights: GUEST_CS_ACCESS_RIGHTS,
        },
        SegmentFields {
            selector: GUEST_SS_SELECTOR,
            base: GUEST_SS_BASE,
            limit: GUEST_SS_LIMIT,
            access_rights: GUEST_SS_ACCESS_RIGHTS,
        },
        SegmentFields {
            selector: GUEST_DS_SELECTOR,
            base: GUEST_DS_BASE,
            limit: GUEST_DS_LIMIT,
            access_rights: GUEST_DS_ACCESS_RIGHTS,
        },
        SegmentFields {
            selector: GUEST_FS_SELECTOR,
            base: GUEST_FS_BASE,
            limit: GUEST_FS_LIMIT,
            access_rights: GUEST_FS_ACCESS_RIGHTS,
        },
        SegmentFields {
            selector: GUEST_GS_SELECTOR,
            base: GUEST_GS_BASE,
            limit: GUEST_GS_LIMIT,
            access_rights: GUEST_GS_ACCESS_RIGHTS,
        },
        SegmentFields {
            selector: GUEST_LDTR_SELECTOR,
            base: GUEST_LDTR_BASE,
            limit: GUEST_LDTR_LIMIT,
            access_rights: GUEST_LDTR_ACCESS_RIGHTS,
        },
        SegmentFields {
            selector: GUEST_TR_SELECTOR,
            base: GUEST_TR_BASE,
            limit: GUEST_TR_LIMIT,
            access_rights: GUEST_TR_ACCESS_RIGHTS,
        },
    ]
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestStateError {
    /// The selector names the LDT or lies past the GDT limit.
    BadSelector { selector: u16 },
    /// CS is unusable or not a 64-bit code segment (L = 0), so the guest
    /// could not run 64-bit code at GUEST_RIP.
    CsNot64Bit { access_rights: u32 },
    /// TR is unusable or not a busy 64-bit TSS.
    TrNotBusyTss { access_rights: u32 },
    /// Writing `field` failed: VMWRITE or VMREAD failed, or it read back a
    /// different value than was written ([`VmcsError::ReadbackMismatch`]).
    Vmcs { field: u32, error: VmcsError },
}

/// Where the guest starts: the part of its state that is not a copy of the
/// running CPU's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestEntry {
    /// At `rip` on the stack `rsp`, with interrupts off (RFLAGS `0x2`) and the
    /// IDT `idtr`: the built-in test guest.
    At { rip: u64, rsp: u64, idtr: DescriptorTable },
    /// In place: the code after VMLAUNCH goes on as the guest, on the stack
    /// it runs on, with the RFLAGS it has there, and the IDT `idtr`, the
    /// firmware's. Only VMLAUNCH knows that RIP, RSP and RFLAGS, so
    /// `vmcs::launch_in_place` writes them; until then the fields hold
    /// placeholders: 0, 0 and `0x2`.
    InPlace { idtr: DescriptorTable },
}

impl GuestEntry {
    /// GUEST_RIP, GUEST_RSP and GUEST_RFLAGS to write before VMLAUNCH.
    fn registers(self) -> (u64, u64, u64) {
        match self {
            Self::At { rip, rsp, .. } => (rip, rsp, INITIAL_RFLAGS),
            Self::InPlace { .. } => (0, 0, INITIAL_RFLAGS),
        }
    }

    /// GUEST_IDTR.
    fn idtr(self) -> DescriptorTable {
        match self {
            Self::At { idtr, .. } | Self::InPlace { idtr } => idtr,
        }
    }
}

/// The complete guest state, captured from the host and ready to write.
#[derive(Debug, Clone, Copy)]
pub struct GuestState {
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub es: GuestSegment,
    pub cs: GuestSegment,
    pub ss: GuestSegment,
    pub ds: GuestSegment,
    pub fs: GuestSegment,
    pub gs: GuestSegment,
    pub ldtr: GuestSegment,
    pub tr: GuestSegment,
    pub gdtr: DescriptorTable,
    pub idtr: DescriptorTable,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    /// `Some` only when the VM-entry controls load guest PAT.
    pub pat: Option<u64>,
    /// `Some` only when the VM-entry controls load guest EFER.
    pub efer: Option<u64>,
}

impl GuestState {
    /// Captures the host's current state, with the guest's own RIP, RSP,
    /// RFLAGS and IDTR from `entry`, and checks CS and TR.
    ///
    /// # Safety
    ///
    /// VMX operation must be active with the controls already written to the
    /// current VMCS (they decide whether PAT and EFER are needed). The host
    /// GDT must be live and stable.
    pub unsafe fn from_current(entry: GuestEntry) -> Result<Self, GuestStateError> {
        let (rip, rsp, rflags) = entry.registers();
        // SAFETY: the caller guarantees a live, stable host GDT, and UEFI
        // runs in long mode.
        let host = unsafe { segment::read_all() };
        let gdt = &host.gdtr;
        // SAFETY: the caller guarantees VMX operation with a current VMCS.
        let entry_controls =
            unsafe { vmcs::vmread(fields::VM_ENTRY_CONTROLS) }.map_err(|error| GuestStateError::Vmcs {
                field: fields::VM_ENTRY_CONTROLS,
                error,
            })?;

        // SAFETY: `gdt` is the live host GDT (the caller's obligation). The
        // SYSENTER MSRs exist on every x86_64 CPU; PAT and EFER are read only
        // when the entry controls load them, which the CPU allows only if it
        // has them.
        let state = unsafe {
            Self {
                rip,
                rsp,
                rflags,
                cr0: cr::read_cr0(),
                cr3: cr::read_cr3(),
                cr4: cr::read_cr4(),
                es: segment_from_gdt(gdt, host.es, None)?,
                cs: segment_from_gdt(gdt, host.cs, None)?,
                ss: segment_from_gdt(gdt, host.ss, None)?,
                ds: segment_from_gdt(gdt, host.ds, None)?,
                fs: segment_from_gdt(gdt, host.fs, Some(host.fs_base))?,
                gs: segment_from_gdt(gdt, host.gs, Some(host.gs_base))?,
                ldtr: GuestSegment::unusable(0, 0),
                tr: segment_from_gdt(gdt, host.tr, Some(host.tr_base))?,
                gdtr: host.gdtr,
                idtr: entry.idtr(),
                sysenter_cs: u64::from(msr::rdmsr(msr::IA32_SYSENTER_CS) as u32),
                sysenter_esp: msr::rdmsr(msr::IA32_SYSENTER_ESP),
                sysenter_eip: msr::rdmsr(msr::IA32_SYSENTER_EIP),
                pat: (entry_controls & fields::VM_ENTRY_LOAD_IA32_PAT != 0).then(|| msr::rdmsr(msr::IA32_PAT)),
                efer: (entry_controls & fields::VM_ENTRY_LOAD_IA32_EFER != 0).then(|| msr::rdmsr(msr::IA32_EFER)),
            }
        };

        check_segments(&state.cs, &state.tr)?;
        Ok(state)
    }

    /// The segment registers, in [`SEGMENT_FIELDS`] order.
    fn segments(&self) -> [GuestSegment; 8] {
        [self.es, self.cs, self.ss, self.ds, self.fs, self.gs, self.ldtr, self.tr]
    }

    /// Writes every guest-state field to the current VMCS and reads each one
    /// back. Does not launch.
    ///
    /// # Safety
    ///
    /// VMX operation must be active and a VMCS current on this CPU.
    pub unsafe fn write(&self) -> Result<(), GuestStateError> {
        use fields::*;

        let other_fields = [
            (GUEST_RIP, self.rip),
            (GUEST_RSP, self.rsp),
            (GUEST_RFLAGS, self.rflags),
            (GUEST_CR0, self.cr0),
            (GUEST_CR3, self.cr3),
            (GUEST_CR4, self.cr4),
            (GUEST_GDTR_BASE, self.gdtr.base),
            (GUEST_GDTR_LIMIT, self.gdtr.limit.into()),
            (GUEST_IDTR_BASE, self.idtr.base),
            (GUEST_IDTR_LIMIT, self.idtr.limit.into()),
            (GUEST_IA32_SYSENTER_CS, self.sysenter_cs),
            (GUEST_IA32_SYSENTER_ESP, self.sysenter_esp),
            (GUEST_IA32_SYSENTER_EIP, self.sysenter_eip),
            (GUEST_DR7, INITIAL_DR7),
            (GUEST_IA32_DEBUGCTL, 0),
            (VMCS_LINK_POINTER, VMCS_LINK_POINTER_NONE),
            (GUEST_ACTIVITY_STATE, 0),
            (GUEST_INTERRUPTIBILITY_STATE, 0),
            (GUEST_PENDING_DEBUG_EXCEPTIONS, 0),
        ];

        // SAFETY: the caller guarantees VMX operation with a current VMCS.
        unsafe {
            for (segment, fields) in self.segments().into_iter().zip(SEGMENT_FIELDS) {
                write_field(fields.selector, segment.selector.into())?;
                write_field(fields.base, segment.base)?;
                write_field(fields.limit, segment.limit.into())?;
                write_field(fields.access_rights, segment.access_rights.into())?;
            }
            for (field, value) in other_fields {
                write_field(field, value)?;
            }
            if let Some(pat) = self.pat {
                write_field(GUEST_IA32_PAT, pat)?;
            }
            if let Some(efer) = self.efer {
                write_field(GUEST_IA32_EFER, efer)?;
            }
        }
        Ok(())
    }

    /// Reads the state back from the current VMCS: the fields
    /// [`write`](Self::write) writes that this type holds. After a VM exit
    /// they are the guest's state as the CPU saved it. PAT and EFER are read
    /// when the entry controls load them, as [`from_current`](Self::from_current)
    /// decides.
    ///
    /// # Safety
    ///
    /// VMX operation must be active and a VMCS current on this CPU.
    pub unsafe fn read() -> Result<Self, GuestStateError> {
        use fields::*;

        // SAFETY: the caller guarantees VMX operation with a current VMCS.
        unsafe {
            let mut segments = [GuestSegment::unusable(0, 0); 8];
            for (segment, fields) in segments.iter_mut().zip(SEGMENT_FIELDS) {
                *segment = GuestSegment {
                    selector: read_field(fields.selector)? as u16,
                    base: read_field(fields.base)?,
                    limit: read_field(fields.limit)? as u32,
                    access_rights: read_field(fields.access_rights)? as u32,
                };
            }
            let [es, cs, ss, ds, fs, gs, ldtr, tr] = segments;
            let entry_controls = read_field(VM_ENTRY_CONTROLS)?;
            Ok(Self {
                rip: read_field(GUEST_RIP)?,
                rsp: read_field(GUEST_RSP)?,
                rflags: read_field(GUEST_RFLAGS)?,
                cr0: read_field(GUEST_CR0)?,
                cr3: read_field(GUEST_CR3)?,
                cr4: read_field(GUEST_CR4)?,
                es,
                cs,
                ss,
                ds,
                fs,
                gs,
                ldtr,
                tr,
                gdtr: DescriptorTable {
                    base: read_field(GUEST_GDTR_BASE)?,
                    limit: read_field(GUEST_GDTR_LIMIT)? as u16,
                },
                idtr: DescriptorTable {
                    base: read_field(GUEST_IDTR_BASE)?,
                    limit: read_field(GUEST_IDTR_LIMIT)? as u16,
                },
                sysenter_cs: read_field(GUEST_IA32_SYSENTER_CS)?,
                sysenter_esp: read_field(GUEST_IA32_SYSENTER_ESP)?,
                sysenter_eip: read_field(GUEST_IA32_SYSENTER_EIP)?,
                pat: match entry_controls & VM_ENTRY_LOAD_IA32_PAT {
                    0 => None,
                    _ => Some(read_field(GUEST_IA32_PAT)?),
                },
                efer: match entry_controls & VM_ENTRY_LOAD_IA32_EFER {
                    0 => None,
                    _ => Some(read_field(GUEST_IA32_EFER)?),
                },
            })
        }
    }

    /// Prints the state, a few lines each starting with `prefix`: before
    /// VMLAUNCH what bring-up wrote, at a stop what the CPU saved. The same
    /// format both times, so the two can be compared line by line.
    pub fn report(&self, prefix: fmt::Arguments<'_>) {
        log!(
            "{prefix} rip={:#018x} rsp={:#018x} rflags={:#x} cr0={:#x} cr3={:#x} cr4={:#x}",
            self.rip,
            self.rsp,
            self.rflags,
            self.cr0,
            self.cr3,
            self.cr4,
        );
        for (name, segment) in [
            ("cs", self.cs),
            ("ss", self.ss),
            ("ds", self.ds),
            ("es", self.es),
            ("fs", self.fs),
            ("gs", self.gs),
            ("tr", self.tr),
            ("ldtr", self.ldtr),
        ] {
            log!("{prefix} {name:<4} {segment}");
        }
        log!(
            "{prefix} gdtr={:#018x}/{:#06x} idtr={:#018x}/{:#06x}; PAT load={} EFER load={}",
            self.gdtr.base,
            self.gdtr.limit,
            self.idtr.base,
            self.idtr.limit,
            self.pat.is_some(),
            self.efer.is_some(),
        );
        log!(
            "{prefix} sysenter cs={:#x} esp={:#018x} eip={:#018x}",
            self.sysenter_cs,
            self.sysenter_esp,
            self.sysenter_eip,
        );
    }
}

/// Builds the guest copy of one host segment register.
///
/// `base` overrides the descriptor's base: FS and GS keep theirs in MSRs,
/// and TR's is 64 bits wide in a 16-byte descriptor.
///
/// # Safety
///
/// `gdt` must describe a live, readable GDT through its limit.
unsafe fn segment_from_gdt(
    gdt: &DescriptorTable,
    selector: u16,
    base: Option<u64>,
) -> Result<GuestSegment, GuestStateError> {
    // Selectors 0-3 all name the null descriptor (the low 2 bits are RPL).
    if selector & !segment::SELECTOR_RPL == 0 {
        return Ok(GuestSegment::unusable(selector, base.unwrap_or(0)));
    }
    // SAFETY: the caller guarantees `gdt` is live and readable.
    let descriptor =
        unsafe { segment::read_descriptor(gdt, selector) }.ok_or(GuestStateError::BadSelector { selector })?;
    let base = base.unwrap_or_else(|| descriptor.base());
    Ok(GuestSegment::from_descriptor(selector, descriptor, base))
}

/// Checks the two segments whose mistakes would otherwise only show up as an
/// unexplained "invalid guest state" exit: CS must be 64-bit code, and TR a
/// busy 64-bit TSS.
fn check_segments(cs: &GuestSegment, tr: &GuestSegment) -> Result<(), GuestStateError> {
    if !cs.is_usable() || cs.access_rights & LONG_MODE == 0 {
        return Err(GuestStateError::CsNot64Bit {
            access_rights: cs.access_rights,
        });
    }
    if !tr.is_usable() || tr.access_rights & KIND_MASK != BUSY_TSS_64 {
        return Err(GuestStateError::TrNotBusyTss {
            access_rights: tr.access_rights,
        });
    }
    Ok(())
}

/// Reads one field.
///
/// # Safety
///
/// VMX operation must be active and a VMCS current on this CPU.
unsafe fn read_field(field: u32) -> Result<u64, GuestStateError> {
    // SAFETY: the caller guarantees VMX operation with a current VMCS.
    unsafe { vmcs::vmread(field) }.map_err(|error| GuestStateError::Vmcs { field, error })
}

/// Writes one field and verifies it by reading it back.
///
/// # Safety
///
/// VMX operation must be active and a VMCS current on this CPU.
unsafe fn write_field(field: u32, value: u64) -> Result<(), GuestStateError> {
    // SAFETY: the caller guarantees VMX operation with a current VMCS.
    unsafe { vmcs::write_verified(field, value) }.map_err(|error| GuestStateError::Vmcs { field, error })
}

#[cfg(test)]
#[path = "../../tests/unit/vmx/guest_state.rs"]
mod tests;
