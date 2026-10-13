//! Guest state for the first VM entry.
//!
//! On VMLAUNCH the CPU loads the guest's registers from the VMCS guest-state
//! fields, checks them, and starts executing at GUEST_RIP. Every register the
//! guest will have must therefore be written here first.
//!
//! The simplest valid 64-bit state is a copy of what the host CPU is running
//! with right now, since that state demonstrably works:
//!
//! | Guest field                  | Value                                     |
//! |------------------------------|-------------------------------------------|
//! | RIP, RSP                     | the guest code page and guest stack top   |
//! | RFLAGS                       | `0x2`: only the always-1 bit; IF = 0, AC = 0 |
//! | CR0, CR3, CR4                | the host's (same page tables, same modes) |
//! | CS, SS, DS, ES, FS, GS, TR   | the host's selectors, decoded from the GDT |
//! | LDTR                         | unusable (UEFI does not use an LDT)       |
//! | GDTR                         | the host's table                          |
//! | IDTR                         | the guest's own IDT (`GuestMemory::idt`)  |
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
//! The guest shares the host's GDT, TSS and page tables, and has an IDT of
//! its own for NMIs. That is fine for a test guest, but it is not isolation.
//!
//! [`GuestState::write`] reads every field back after writing it. As with
//! the host fields, that proves storage only: the CPU checks the state when
//! VMLAUNCH runs, and reports a bad guest state as exit reason 33.
//! [`check_segments`] catches the two mistakes most likely to cause that.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestStateError {
    /// The selector names the LDT or lies past the GDT limit.
    BadSelector { selector: u16 },
    /// CS is unusable or not a 64-bit code segment (L = 0), so the guest
    /// could not run 64-bit code at GUEST_RIP.
    CsNot64Bit { access_rights: u32 },
    /// TR is unusable or not a busy 64-bit TSS.
    TrNotBusyTss { access_rights: u32 },
    /// VMWRITE or VMREAD of `field` failed.
    Vmcs { field: u32, error: VmcsError },
    /// `field` read back a different value than was written.
    ReadbackMismatch { field: u32, written: u64, read: u64 },
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
    /// Captures the host's current state, with the guest's own `rip`, `rsp`
    /// and `idtr`, and checks CS and TR.
    ///
    /// # Safety
    ///
    /// VMX operation must be active with the controls already written to the
    /// current VMCS (they decide whether PAT and EFER are needed). The host
    /// GDT must be live and stable.
    pub unsafe fn from_current(rip: u64, rsp: u64, idtr: DescriptorTable) -> Result<Self, GuestStateError> {
        let host = unsafe { segment::read_all() };
        let gdt = &host.gdtr;
        let entry_controls =
            unsafe { vmcs::vmread(fields::VM_ENTRY_CONTROLS) }.map_err(|error| GuestStateError::Vmcs {
                field: fields::VM_ENTRY_CONTROLS,
                error,
            })?;

        let state = unsafe {
            Self {
                rip,
                rsp,
                rflags: INITIAL_RFLAGS,
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
                idtr,
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

    /// Writes every guest-state field to the current VMCS and reads each one
    /// back. Does not launch.
    ///
    /// # Safety
    ///
    /// VMX operation must be active and a VMCS current on this CPU.
    pub unsafe fn write(&self) -> Result<(), GuestStateError> {
        use fields::*;

        let segments = [
            (
                self.es,
                GUEST_ES_SELECTOR,
                GUEST_ES_BASE,
                GUEST_ES_LIMIT,
                GUEST_ES_ACCESS_RIGHTS,
            ),
            (
                self.cs,
                GUEST_CS_SELECTOR,
                GUEST_CS_BASE,
                GUEST_CS_LIMIT,
                GUEST_CS_ACCESS_RIGHTS,
            ),
            (
                self.ss,
                GUEST_SS_SELECTOR,
                GUEST_SS_BASE,
                GUEST_SS_LIMIT,
                GUEST_SS_ACCESS_RIGHTS,
            ),
            (
                self.ds,
                GUEST_DS_SELECTOR,
                GUEST_DS_BASE,
                GUEST_DS_LIMIT,
                GUEST_DS_ACCESS_RIGHTS,
            ),
            (
                self.fs,
                GUEST_FS_SELECTOR,
                GUEST_FS_BASE,
                GUEST_FS_LIMIT,
                GUEST_FS_ACCESS_RIGHTS,
            ),
            (
                self.gs,
                GUEST_GS_SELECTOR,
                GUEST_GS_BASE,
                GUEST_GS_LIMIT,
                GUEST_GS_ACCESS_RIGHTS,
            ),
            (
                self.ldtr,
                GUEST_LDTR_SELECTOR,
                GUEST_LDTR_BASE,
                GUEST_LDTR_LIMIT,
                GUEST_LDTR_ACCESS_RIGHTS,
            ),
            (
                self.tr,
                GUEST_TR_SELECTOR,
                GUEST_TR_BASE,
                GUEST_TR_LIMIT,
                GUEST_TR_ACCESS_RIGHTS,
            ),
        ];

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

        unsafe {
            for (segment, selector, base, limit, access_rights) in segments {
                write_field(selector, segment.selector.into())?;
                write_field(base, segment.base)?;
                write_field(limit, segment.limit.into())?;
                write_field(access_rights, segment.access_rights.into())?;
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
}

/// Builds the guest copy of one host segment register.
///
/// `base` overrides the descriptor's base: FS and GS keep theirs in MSRs,
/// and TR's is 64 bits wide in a 16-byte descriptor.
unsafe fn segment_from_gdt(
    gdt: &DescriptorTable,
    selector: u16,
    base: Option<u64>,
) -> Result<GuestSegment, GuestStateError> {
    // Selectors 0-3 all name the null descriptor (the low 2 bits are RPL).
    if selector & !segment::SELECTOR_RPL == 0 {
        return Ok(GuestSegment::unusable(selector, base.unwrap_or(0)));
    }
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
    if !tr.is_usable() || tr.access_rights & 0x1F != BUSY_TSS_64 {
        return Err(GuestStateError::TrNotBusyTss {
            access_rights: tr.access_rights,
        });
    }
    Ok(())
}

/// Writes one field and verifies it by reading it back.
unsafe fn write_field(field: u32, value: u64) -> Result<(), GuestStateError> {
    let vmcs_error = |error| GuestStateError::Vmcs { field, error };
    unsafe { vmcs::vmwrite(field, value) }.map_err(vmcs_error)?;
    let read = unsafe { vmcs::vmread(field) }.map_err(vmcs_error)?;
    if read != value {
        return Err(GuestStateError::ReadbackMismatch {
            field,
            written: value,
            read,
        });
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/vmx/guest_state.rs"]
mod tests;
