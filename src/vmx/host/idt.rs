//! Aleph0's own IDT for VMX root operation: what the CPU runs when an
//! exception or NMI arrives while Aleph0 itself runs.
//!
//! Until now HOST_IDTR_BASE was the firmware's IDT, so a fault in the exit
//! handler ran a firmware handler from exit context, and an NMI ran the
//! firmware's NMI handler, which dead-loops. This IDT has all 256 gates
//! (one page: 256 × 16 bytes), each to an Aleph0 handler (`handlers.rs`):
//!
//! | Vectors | Handler | Stack |
//! |---|---|---|
//! | 2 (NMI) | marks the NMI pending for the guest, returns | IST1 |
//! | 8 (#DF) | prints and halts | IST2 |
//! | 18 (#MC) | prints and halts | IST3 |
//! | every other | prints and halts | the current one |
//!
//! NMI, #DF and #MC get stacks of their own because they can arrive when the
//! current stack is unusable: an NMI at any instruction, #DF after a fault
//! while delivering a fault (a stack overflow, for example), #MC at any time.
//! Maskable interrupts never arrive: a VM exit loads RFLAGS as 0x2 (IF = 0),
//! and Aleph0 never sets IF in root operation. Their gates exist so a stray
//! `int n` is printed instead of hitting a missing gate.

use crate::vmx::exit_decision::NMI_VECTOR;
use crate::vmx::segment::{GATE_SIZE, interrupt_gate};

/// Gates in the IDT: one per vector.
pub const VECTORS: usize = 256;
/// IDT vector of #DF (double fault).
pub const DOUBLE_FAULT_VECTOR: u8 = 8;
/// IDT vector of #MC (machine check).
pub const MACHINE_CHECK_VECTOR: u8 = 18;

/// The interrupt stacks the host TSS provides, by IST number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptStack {
    Nmi = 1,
    DoubleFault = 2,
    MachineCheck = 3,
}

impl InterruptStack {
    /// Every interrupt stack, in IST order.
    pub const ALL: [Self; 3] = [Self::Nmi, Self::DoubleFault, Self::MachineCheck];

    /// The IST number a gate names: 1-7.
    pub fn ist(self) -> u8 {
        self as u8
    }

    /// Name for the report.
    pub fn name(self) -> &'static str {
        match self {
            Self::Nmi => "NMI",
            Self::DoubleFault => "#DF",
            Self::MachineCheck => "#MC",
        }
    }
}

/// The stack `vector` is delivered on: its own for NMI, #DF and #MC, the
/// current one (`None`) for every other vector.
pub fn interrupt_stack(vector: u8) -> Option<InterruptStack> {
    match vector {
        NMI_VECTOR => Some(InterruptStack::Nmi),
        DOUBLE_FAULT_VECTOR => Some(InterruptStack::DoubleFault),
        MACHINE_CHECK_VECTOR => Some(InterruptStack::MachineCheck),
        _ => None,
    }
}

/// Whether the CPU pushes an error code when it delivers exception
/// `vector`: #DF, #TS, #NP, #SS, #GP, #PF, #AC, #CP, #VC and #SX (Intel SDM
/// Vol. 3A, "Exception and Interrupt Reference"). The handler stubs push a 0
/// for every other vector, so all frames look alike; their assembly lists
/// the same vectors.
pub fn has_error_code(vector: u8) -> bool {
    matches!(vector, 8 | 10..=14 | 17 | 21 | 29 | 30)
}

/// The mnemonic of exception `vector`, for the report.
pub fn exception_name(vector: u8) -> &'static str {
    match vector {
        0 => "#DE divide error",
        1 => "#DB debug",
        NMI_VECTOR => "NMI",
        3 => "#BP breakpoint",
        4 => "#OF overflow",
        5 => "#BR bound range",
        6 => "#UD invalid opcode",
        7 => "#NM device not available",
        DOUBLE_FAULT_VECTOR => "#DF double fault",
        10 => "#TS invalid TSS",
        11 => "#NP segment not present",
        12 => "#SS stack fault",
        13 => "#GP general protection",
        14 => "#PF page fault",
        16 => "#MF x87 floating point",
        17 => "#AC alignment check",
        MACHINE_CHECK_VECTOR => "#MC machine check",
        19 => "#XM SIMD floating point",
        20 => "#VE virtualization exception",
        21 => "#CP control protection",
        28 => "#HV hypervisor injection",
        29 => "#VC VMM communication",
        30 => "#SX security",
        // 9 was the 386's coprocessor segment overrun; the rest never had a use.
        9 | 15 | 22..=27 | 31 => "reserved exception",
        _ => "interrupt",
    }
}

/// Fills `idt` with a gate for every vector: to `handler(vector)`, through
/// code segment `selector`, on the stack [`interrupt_stack`] picks.
pub fn fill(idt: &mut [[u8; GATE_SIZE]; VECTORS], selector: u16, handler: impl Fn(u8) -> u64) {
    for (vector, gate) in (0..=u8::MAX).zip(idt.iter_mut()) {
        let ist = interrupt_stack(vector).map_or(0, InterruptStack::ist);
        *gate = interrupt_gate(handler(vector), selector, ist);
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/host/idt.rs"]
mod tests;
