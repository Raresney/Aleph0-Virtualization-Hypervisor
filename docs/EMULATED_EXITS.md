# Emulated exits: CPUID, RDMSR/WRMSR and port I/O

An operating system runs CPUID among its first instructions, and CPUID
always causes a VM exit. Until Aleph0 handles such exits, no real guest code
can run under it. This page explains how Aleph0 handles the exits every guest
needs: it executes the instruction itself and hands the result back
(**passthrough emulation**):

- one handler per exit reason;
- the flow of one emulated exit;
- CPUID, and the one value Aleph0 changes;
- the MSR bitmap, and which RDMSR/WRMSR exit;
- the I/O bitmaps, and which IN/OUT exit;
- the test the guest runs, and how it is checked;
- what the Hyper-V run printed;
- what is not covered yet.

Code:

- `src/vmx/exit_decision/mod.rs`: `decide`, the dispatch on the exit reason, and the shared exit types;
- `src/vmx/exit_decision/emulation.rs`: the handlers for CPUID, RDMSR, WRMSR and IN/OUT, and `cpuid_policy`;
- `src/vmx/exit_decision/scenario.rs`: the test guest's own exits (EPT write, VMCALLs, NMI);
- `src/vmx/exit_bitmaps.rs`: the MSR bitmap and the two I/O bitmaps;
- `src/vmx/vmexit/handler.rs`: `execute`, `prepare_resume`, `queue_general_protection`;
- `src/vmx/vmexit/report.rs`: the report lines;
- `src/port.rs`: `in`/`out` of 1, 2 and 4 bytes;
- `src/vmx/guest.rs`: the guest code that causes the exits, and its checks;
- `src/bring_up/mod.rs`: `PassthroughState`.

## 1. One handler per exit reason

The exit handler (`vmexit/handler.rs`) reads an exit into an `ExitInfo`, calls
`exit_decision::decide`, and applies what comes back (`docs/NMI.md`
section 6). `decide` first handles what holds for every exit, whatever its
reason: a failed VM entry and an exit that interrupted an event's delivery
both stop the guest. Then it dispatches on the basic exit reason:

```rust
pub fn decide(state: ExitState, exit: ExitInfo) -> (ExitEvent, ExitState) {
    if exit.reason.entry_failure {
        return (ExitEvent::Unexpected, state);
    }
    if exit.idt_vectoring_valid {
        return (ExitEvent::InterruptedDelivery, state);
    }
    match exit.reason.basic {
        EXIT_REASON_CPUID => emulation::cpuid(state, &exit),
        EXIT_REASON_RDMSR => emulation::rdmsr(state, &exit),
        EXIT_REASON_WRMSR => emulation::wrmsr(state, &exit),
        EXIT_REASON_IO_INSTRUCTION => emulation::io(state, &exit),
        EXIT_REASON_EXCEPTION_OR_NMI => scenario::exception_or_nmi(state, &exit),
        EXIT_REASON_NMI_WINDOW => scenario::nmi_window(state, &exit),
        EXIT_REASON_EPT_VIOLATION => scenario::ept_violation(state, &exit),
        EXIT_REASON_VMCALL => scenario::vmcall(state, &exit),
        _ => (ExitEvent::Unexpected, state),
    }
}
```

Every handler has the same signature, `fn(ExitState, &ExitInfo) ->
(ExitEvent, ExitState)`: given the state kept between exits and what was
read about this exit, it returns what the exit is and the state for the next
one. None of them touches the CPU, so each can be tested on the host.

KVM keeps the same structure as a table of function pointers indexed by exit
reason (`kvm_vmx_exit_handlers[]`). Aleph0 uses a `match` instead, without
function pointers: each handler stays a separate pure function, and the list
of handled reasons is readable in one place. A reason without a handler lands
in the `_` arm, which is `Unexpected` and stops the guest.

The handlers live in two files:

- `emulation.rs`: instructions Aleph0 executes for **any** guest (CPUID,
  RDMSR, WRMSR, IN, OUT). It stays when an OS guest comes.
- `scenario.rs`: the test guest's own exits (its write to the protected data
  page, its VMCALLs, NMI reinjection). It goes when an OS guest comes.

## 2. Passthrough: the flow of one emulated exit

For these instructions Aleph0 does not model the device or the register file.
It runs the same instruction itself, in VMX root operation, and puts the
result where the guest expects it:

```text
guest: cpuid / rdmsr / wrmsr / in / out
  │  VM exit
  ▼
vmexit_entry (stub)    push the 15 general-purpose registers = RegisterFrame
  ▼
vmexit_handler(frame)
  ├─ read_exit   VMCS fields + frame                 ─▶ ExitInfo
  ├─ judge       decide(state, exit)                 ─▶ ExitEvent::Emulated(Emulation), next state
  └─ apply       event.action()
                   = Resume(ResumePlan { emulate: Some(emulation), advance_rip: true, .. })
       └─ prepare_resume
            1. execute(emulation, frame)   the real instruction, in root operation;
                                           result into frame.rax .. frame.rdx
            2. GUEST_RIP = RIP + VM_EXIT_INSTRUCTION_LEN
     returns RESUME_GUEST (0)
  ▼
vmexit_entry (stub)    pop the frame into the guest's registers, VMRESUME
  ▼
guest: the instruction after the emulated one, with the result in its registers
```

The plan comes from one arm of `ExitEvent::action`:

```rust
Self::Emulated(emulation) => ExitAction::Resume(ResumePlan {
    emulate: Some(emulation),
    ..ResumePlan::PAST_INSTRUCTION
}),
```

`PAST_INSTRUCTION` is the plan that advances RIP. The instruction is
executed **before** RIP moves, so the guest never runs past it without its
result. `VM_EXIT_INSTRUCTION_LEN` gives the length; Aleph0 does not decode
the instruction.

Where RIP will go is worked out before the instruction runs, with
`next_rip`. RIP is the guest's: for an instruction at the very top of the
address space `RIP + length` would wrap, and the guest is stopped instead,
before the instruction takes effect (the same as when the length cannot be
read).

The stub pushed the guest's registers into a `RegisterFrame` on the exit
stack, and `execute` takes it as `&mut RegisterFrame`. After the handler
returns 0 the stub pops that frame into the CPU, so what `execute` wrote
reaches the guest. The register rules are the instructions' own:

| Instruction      | Result             | What `execute` writes                                               |
| ---------------- | ------------------ | ------------------------------------------------------------------- |
| CPUID            | EAX, EBX, ECX, EDX | each as a 32-bit write, which zero-extends into the 64-bit register |
| RDMSR            | EDX:EAX            | `rax = value & 0xFFFF_FFFF`, `rdx = value >> 32`                    |
| WRMSR            | —                  | no register                                                         |
| IN, 8 or 16 bits | AL or AX           | only those bits; the rest of RAX stays                              |
| IN, 32 bits      | EAX                | zero-extends into RAX                                               |
| OUT              | —                  | no register                                                         |

The IN rule is `merge_in`:

```rust
pub fn merge_in(rax: u64, size: IoSize, value: u32) -> u64 {
    match size {
        IoSize::Dword => u64::from(value),
        _ => (rax & !size.mask()) | (u64::from(value) & size.mask()),
    }
}
```

For `rax = 0x1122_3344_5566_7788`:

- `in al, dx` reading `0xA5` gives `0x1122_3344_5566_77A5`;
- `in ax, dx` reading `0xBEEF` gives `0x1122_3344_5566_BEEF`;
- `in eax, dx` reading `0x1234_5678` gives `0x0000_0000_1234_5678`.

A worked exit: the guest runs `rdmsr` (`0F 32`, 2 bytes) with
`ecx = 0xC0000102`. The exit has reason 31; `emulation::rdmsr` returns
`Emulation::Rdmsr { msr: 0xC0000102 }`; `execute` runs the real RDMSR, gets
(say) `0x0000_7A1E_0000_0000` and writes `rax = 0`, `rdx = 0x7A1E`; GUEST_RIP
moves by 2; the guest continues after its `rdmsr`.

Each emulation handler also counts its exit in `ExitState::emulated`
(`EmulationCounts`), which section 6 uses.

## 3. CPUID and its policy

CPUID always exits in VMX non-root operation; no control turns that off.
`emulation::cpuid` takes the leaf from the guest's EAX and the subleaf from
ECX, and `execute` runs `__cpuid_count(leaf, subleaf)` in root operation.
Under Hyper-V that returns what Hyper-V shows Aleph0.

Everything passes through except one bit:

```rust
const CPUID_1_ECX_VMX: u32 = 1 << 5;

pub fn cpuid_policy(leaf: u32, raw: CpuidResult) -> CpuidResult {
    match leaf {
        1 => CpuidResult {
            ecx: raw.ecx & !CPUID_1_ECX_VMX,
            ..raw
        },
        _ => raw,
    }
}
```

**CPUID.1:ECX bit 5 (VMX) is hidden.** A guest that saw it would try VMXON,
which always exits (reason 27) in non-root operation, and Aleph0 does not
emulate VMX. The report line prints both values, so the effect is visible:
`ecx=` is what the guest got, `processor ecx=` what the CPU returned.

What passes through, and must be decided before an OS guest:

- **ECX bit 31 (hypervisor present) and the leaves from 0x40000000.** Under
  nested Hyper-V they describe Hyper-V. A Windows guest that sees them would
  use Hyper-V's interface, and its hypercalls are VMCALLs, which exit to
  Aleph0, not to Hyper-V, and Aleph0 treats them as unexpected.
- **Values that follow CR4 and XCR0**: CPUID.1:ECX.OSXSAVE and leaf 0xD
  (the XSAVE area size). They are right for the guest only while its CR4 and
  XCR0 equal the host's, as they do today.

## 4. The MSR bitmap

RDMSR and WRMSR cause a VM exit depending on one primary control:

- without "use MSR bitmaps" (bit 28), **every** RDMSR and WRMSR exits;
- with it, they exit only for MSRs whose bit is set in the MSR bitmap, and
  always for MSRs outside the two ranges the bitmap covers.

Aleph0 turns the control on (`DesiredControls::minimal_64_bit_guest`).
`ExitBitmaps::allocate` makes three zeroed pages (this one and the two I/O
bitmaps of section 5) and sets the bits of `INTERCEPTED_MSRS` and
`INTERCEPTED_PORTS`; `write_to_vmcs` writes the MSR bitmap's address to
`MSR_BITMAP` (`0x2004`). The page has four quarters:

```text
MSR bitmap, one 4 KiB page (Intel SDM Vol. 3C, "MSR-Bitmap Address"):
offset 0x000  read,  MSR 0x00000000..=0x00001FFF
offset 0x400  read,  MSR 0xC0000000..=0xC0001FFF
offset 0x800  write, MSR 0x00000000..=0x00001FFF
offset 0xC00  write, MSR 0xC0000000..=0xC0001FFF
RDMSR/WRMSR of any other MSR always exits.
```

`msr_bit` finds an MSR's bit:

```rust
pub const fn msr_bit(msr: u32, access: MsrAccess) -> Option<(usize, u8)> {
    let (read_offset, index) = match msr {
        0..=0x1FFF => (0x000, msr),
        0xC000_0000..=0xC000_1FFF => (0x400, msr - 0xC000_0000),
        _ => return None,
    };
    let offset = match access {
        MsrAccess::Read => read_offset,
        MsrAccess::Write => read_offset + 0x800,
    };
    Some((offset + index as usize / 8, (index % 8) as u8))
}
```

For IA32_KERNEL_GS_BASE (`0xC0000102`): index `0x102`, so byte
`0x400 + 0x102 / 8 = 0x420` and bit `0x102 % 8 = 2` for reads, byte `0xC20`
bit 2 for writes. `None` means the MSR is outside both ranges.

### Why not exiting is a correct passthrough

For an MSR whose bit is clear, the guest's own RDMSR/WRMSR runs in non-root
operation, and the CPU uses the guest's value. That holds even for MSRs
whose guest value is a VMCS field (IA32*GS_BASE, IA32_EFER, IA32_PAT,
IA32_SYSENTER*\*): while the guest runs, the CPU holds the guest's value, so
the guest reads and writes its own.

### The trap: emulating an MSR the VMCS holds

An _intercepted_ MSR is different. Aleph0 emulates it with a real
RDMSR/WRMSR in root operation, which reaches the **host's** value, not the
guest's. For IA32_GS_BASE, say, a VM exit loads `HOST_GS_BASE`, so an
emulated RDMSR would give the guest the host's GS base, and an emulated
WRMSR would overwrite the host's. Hence `VMCS_HELD_MSRS`, the MSRs whose
guest value is a VMCS field, and a compile-time check that no intercepted
MSR is on it, or lacks a bitmap bit:

```rust
pub const INTERCEPTED_MSRS: [u32; 1] = [IA32_KERNEL_GS_BASE];

// Every intercepted MSR has a bitmap bit, and none is held in the VMCS.
const _: () = {
    let mut i = 0;
    while i < INTERCEPTED_MSRS.len() {
        assert!(msr_bit(INTERCEPTED_MSRS[i], MsrAccess::Read).is_some());
        let mut j = 0;
        while j < VMCS_HELD_MSRS.len() {
            assert!(
                INTERCEPTED_MSRS[i] != VMCS_HELD_MSRS[j],
                "an intercepted MSR is held in the VMCS"
            );
            j += 1;
        }
        i += 1;
    }
};
```

IA32_KERNEL_GS_BASE is safe because VM entry and exit do not switch it (it
has no VMCS field) and Aleph0 never runs SWAPGS: the CPU's value is the
guest's.

### The three routes

An RDMSR or WRMSR exit takes one of three routes, chosen by `route`:

| MSR                                       | Route                                                   | Event                    |
| ----------------------------------------- | ------------------------------------------------------- | ------------------------ |
| in `INTERCEPTED_MSRS`                     | emulate with the real RDMSR/WRMSR                       | `Emulated`               |
| outside both ranges (`msr_bit` is `None`) | inject #GP(0) into the guest                            | `GuestGeneralProtection` |
| in range, bit clear                       | it should never have exited: the bitmap is broken; stop | `Unexpected`             |

The middle row is what hardware does for an MSR that does not exist.
Aleph0 does not know whether such an MSR exists, and a real RDMSR/WRMSR of a
missing one would #GP in the host, so the guest gets the #GP instead.

**WRMSR checks the value first.** Every intercepted MSR holds an address
(only IA32_KERNEL_GS_BASE today), and a WRMSR of a non-canonical address
faults. In the guest that is correct; in exit context it would be a #GP in
the host, where nothing can handle it (the host IDT is the firmware's). So
`wrmsr` calls `is_canonical_48` and, for a non-canonical value, injects the
guest's #GP instead of executing:

```rust
pub(super) fn is_canonical_48(value: u64) -> bool {
    ((value as i64) << 16 >> 16) as u64 == value
}
```

`0xFFFF_8000_0000_0000` and `0x0000_7A1E_0000_0000` are canonical (bits
63:47 all equal); `0x0000_8000_0000_0000` is not (bit 47 set, bits 63:48
clear).

### Injecting #GP

The plan `INJECT_GP` leaves RIP where it is, as for any fault, and
`queue_general_protection` writes the event for the next VM entry:

```rust
unsafe fn queue_general_protection() -> Result<(), VmcsError> {
    // SAFETY: the caller guarantees VMX root operation with a current VMCS.
    unsafe {
        vmcs::vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, 0)?;
        vmcs::vmwrite(
            VM_ENTRY_INTERRUPTION_INFO,
            InterruptionInfo::GENERAL_PROTECTION.0.into(),
        )
    }
}
```

```text
0x80000B0D = 1000 0000 0000 0000 0000 1011 0000 1101
bit 31    = 1   valid
bit 11    = 1   deliver an error code (0, from VM_ENTRY_EXCEPTION_ERROR_CODE)
bits 10:8 = 3   type: hardware exception
bits 7:0  = 13  vector: #GP
```

The CPU delivers it through the guest's own IDT, at the `rdmsr`/`wrmsr`
that faulted.

## 5. The I/O bitmaps

IN and OUT work the same way, with "use I/O bitmaps" (primary bit 25) and
two bitmap pages, one bit per port:

```text
I/O bitmaps, one bit per port:
A (one page): ports 0x0000..=0x7FFF    B (one page): ports 0x8000..=0xFFFF
An access to several ports exits if any of their bits is set.
```

While bit 25 is set, the CPU ignores bit 24 (unconditional I/O exiting).
`io_bit` finds a port's bit:

```rust
pub const fn io_bit(port: u16) -> (IoBitmap, usize, u8) {
    let page = if port < 0x8000 { IoBitmap::A } else { IoBitmap::B };
    let index = (port & 0x7FFF) as usize;
    (page, index / 8, (port % 8) as u8)
}
```

The bit of port _p_ is bit `p % 8` of byte `(p & 0x7FFF) / 8` in its page.
Aleph0 intercepts one port, `0x3FF`, the COM1 scratch register (base `0x3F8`

- 7): a byte with no effect on the UART that `serial.rs` never uses. It is
  bit 7 of byte `0x7F` in page A. `write_to_vmcs` writes the pages' addresses
  to `IO_BITMAP_A` (`0x2000`) and `IO_BITMAP_B` (`0x2002`).

### The multi-port rule

A 2- or 4-byte access touches 2 or 4 consecutive ports, and it exits if
**any** of their bits is set. So `in ax, dx` with `dx = 0x3FE` exits, because
it covers `0x3FE` and `0x3FF`. The exit handler does not check the port
against `INTERCEPTED_PORTS`: it passes through the port and size from the
exit qualification, as the guest would have done itself. This is a known
property, not a bug in the test: a 4-byte access at `0x3FC` exits, and
Aleph0 then reaches the real COM1 registers `0x3FC` to `0x3FF` (modem
control, line status, modem status and scratch), including the ones the
serial driver uses. The test guest never does that. It is a decision for
the OS-guest step (section 8).

### The exit qualification

Aleph0 learns what the guest did from the exit qualification, not from
decoding the instruction (`IoQualification`):

```text
bits 2:0   size − 1: 0 = 1 byte, 1 = 2 bytes, 3 = 4 bytes
bit  3     direction: 1 = IN, 0 = OUT
bit  4     string instruction (INS/OUTS)
bit  5     REP prefix
bit  6     operand: 1 = immediate port, 0 = DX
bits 31:16 port
```

For `in al, dx` with `dx = 0x3FF` the qualification is `0x03FF0008`: port
`0x3FF` in bits 31:16, direction bit set, size 1. For `out dx, al` it is
`0x03FF0000`. An OUT sends the value in AL, AX or EAX of the guest's RAX
(`out_value`); an IN merges into RAX as in section 2. `execute` runs the
matching function of `src/port.rs` (`inb`, `inw`, `inl`, `outb`, `outw`,
`outl`).

The encoding 2 of the size field is unused, and a **string or REP form
(INS, OUTS, REP) stops the guest**. Those read or write guest memory through
the guest's page tables and EPT, and handling them would need a translation
of the guest's addresses, segment and direction-flag handling and page
crossings; Aleph0 has none. This is also why the `nomem` option in
`port.rs` is sound here: no emulated port access reaches RAM through
Aleph0.

## 6. The test

The guest begins with a block that causes the nine emulated exits, before
the EPT write and the VMCALLs (`src/vmx/guest.rs`):

```asm
guest_code_start:
    // CPUID always exits; Aleph0 executes it and hides VMX (CPUID.1:ECX
    // bit 5), so a guest never tries VMXON.
    mov eax, 1
    xor ecx, ecx
    cpuid
    bt ecx, 5
    jc guest_emulation_failed
    // IA32_KERNEL_GS_BASE exits through the MSR bitmap; Aleph0 runs the
    // real RDMSR/WRMSR. Save it, write GUEST_MSR_VALUE, read it back,
    // restore it.
    mov ecx, {kernel_gs_base}
    rdmsr
    mov esi, eax
    mov edi, edx
    mov eax, {msr_low}
    mov edx, {msr_high}
    wrmsr
    xor eax, eax
    xor edx, edx
    rdmsr
    cmp eax, {msr_low}
    jne guest_emulation_failed
    cmp edx, {msr_high}
    jne guest_emulation_failed
    mov eax, esi
    mov edx, edi
    wrmsr
    // The COM1 scratch register exits through the I/O bitmap; Aleph0 runs
    // the real IN/OUT. Save it, write GUEST_IO_VALUE, read it back, restore
    // it.
    mov dx, {scratch_port}
    in al, dx
    mov sil, al
    mov al, {io_value}
    out dx, al
    xor eax, eax
    in al, dx
    cmp al, {io_value}
    jne guest_emulation_failed
    mov al, sil
    out dx, al
```

```asm
guest_emulation_failed:
    // An emulated instruction returned the wrong value: stop with a marker
    // in RAX, which the #UD exit prints.
    mov eax, {fail_marker}
    ud2
```

The placeholders are the constants of `guest.rs`:

| Placeholder           | Value                                                                      |
| --------------------- | -------------------------------------------------------------------------- |
| `kernel_gs_base`      | `IA32_KERNEL_GS_BASE`, `0xC0000102`                                        |
| `msr_low`, `msr_high` | the halves of `GUEST_MSR_VALUE`, `0x0000_7A1E_0000_0000`: `0` and `0x7A1E` |
| `scratch_port`        | `GUEST_SCRATCH_PORT`, `0x3FF`                                              |
| `io_value`            | `GUEST_IO_VALUE`, `0xA5`                                                   |
| `fail_marker`         | `GUEST_EMULATION_FAIL_MARKER`, `0xFA11`                                    |

The nine exits, in the order they happen:

| #   | Instruction    | What it checks                            |
| --- | -------------- | ----------------------------------------- |
| 1   | `cpuid` leaf 1 | bit 5 of ECX is clear: VMX is hidden      |
| 2   | `rdmsr`        | saves the original IA32_KERNEL_GS_BASE    |
| 3   | `wrmsr`        | writes `GUEST_MSR_VALUE`                  |
| 4   | `rdmsr`        | reads back `GUEST_MSR_VALUE`, both halves |
| 5   | `wrmsr`        | writes the original back                  |
| 6   | `in al, dx`    | saves the original scratch byte           |
| 7   | `out dx, al`   | writes `GUEST_IO_VALUE`                   |
| 8   | `in al, dx`    | reads back `GUEST_IO_VALUE`               |
| 9   | `out dx, al`   | writes the original back                  |

The guest's CPUID check only tests the VMX bit. The full CPUID result is
visible on serial, but the guest does not check it. The MSR and port are real
hardware, not a copy, so on success the guest saves what it writes and puts
it back. If a check fails after its first WRMSR or OUT, it jumps to
`guest_emulation_failed` and `ud2` **without** restoring; bring-up does not
restore either, and prints `restored=false` below.

### Two checks, because one is not enough

- **The guest checks the values.** A wrong result ends in `ud2` with
  `0xFA11` in EAX. The #UD is an exception exit (reason 0, vector 6), which
  `exit_decision` does not handle, so the guest stops and serial shows the
  marker in RAX.
- **Aleph0 checks the counts.** A guest that got the right value does not
  prove the exit happened: with a broken bitmap, `rdmsr` would run directly
  and return the same value. `ExitState::emulated` counts each emulated exit,
  and at the last main VMCALL `scenario::vmcall` compares it with
  `guest::EXPECTED_EMULATION`:

```rust
pub const EXPECTED_EMULATION: EmulationCounts = EmulationCounts {
    cpuid: 1,
    rdmsr: 2,
    wrmsr: 2,
    io_in: 2,
    io_out: 2,
};
```

Any other count gives `EmulationMissing` and stops the guest instead of
ending the run.

### What serial shows

Each emulated exit prints one line (`report_emulation`), after the usual
`reason=`, `qualification=` and register lines of `docs/EPT.md`:

```text
VM exit #N: CPUID leaf=0x1 subleaf=0x0 -> eax=... ebx=... ecx=... edx=... (processor ecx=...); resuming at rip=...
VM exit #N: RDMSR 0xc0000102 -> 0x...; resuming at rip=...
VM exit #N: WRMSR 0xc0000102 <- 0x00007a1e00000000; resuming at rip=...
VM exit #N: IN port 0x3ff size=1 -> 0x...; resuming at rip=...
VM exit #N: OUT port 0x3ff size=1 value=0xa5; resuming at rip=...
VM exit #N: emulated exits: cpuid=1 rdmsr=2 wrmsr=2 in=2 out=2.
```

The last line comes with the final VMCALL. The EPT violation, which was
exit #1 before this step, is now exit #10.

### What bring-up checks

The MSR and the port are real, so `bring_up` reads them before and after the
guest (`PassthroughState`, both the IA32_KERNEL_GS_BASE value and the COM1
scratch byte) and prints whether they match:

```text
Passthrough state before the guest PassthroughState { kernel_gs_base: <hex>, com1_scratch: <hex> }, after it PassthroughState { ... }: restored=true.
```

`restored=true` shows the guest put both back; `restored=false` means its
check failed after a write.

## 7. On Hyper-V

The first Hyper-V run of this work had the bitmaps on and the guest
unchanged. It printed `VMX primary: required=0x240065f2 allowed=0xf7f9fffe`
(bits 25 and 28 are allowed, and neither is required, so Aleph0 has to set
them), wrote and read back the three bitmap addresses, and showed the old
three exits and `SUCCESS`: turning the bitmaps on changed nothing for that
guest, which runs no MSR or port instruction.

Plain run (`.\scripts\run-hyperv.ps1`), twelve exits. This is an excerpt of
`run\serial.log`. The `[Aleph0 Virtualization Hypervisor]` prefix is
removed, and of the five lines each exit prints only the reason line and the
result line are kept.

Bring-up, before the guest:

```text
Exit bitmaps allocated: MSR=0x000000007eaf2000 I/O A=0x000000007eaf1000 I/O B=0x000000007eaf0000.
Intercepted MSRs (read and write): [c0000102]; intercepted ports: [3ff].
VMCS MSR and I/O bitmap addresses written and read back.
```

The nine emulated exits:

```text
VM exit #1: reason=10 (CPUID)
VM exit #1: CPUID leaf=0x1 subleaf=0x0 -> eax=0x00090672 ebx=0x00020800 ecx=0xf7fa3203 edx=0x1f8bfbff (processor ecx=0xf7fa3223); resuming at rip=0x000000007eaf5009.
VM exit #2: reason=31 (RDMSR)
VM exit #2: RDMSR 0xc0000102 -> 0x0000000000000000; resuming at rip=0x000000007eaf501a.
VM exit #3: reason=32 (WRMSR)
VM exit #3: WRMSR 0xc0000102 <- 0x00007a1e00000000; resuming at rip=0x000000007eaf502a.
VM exit #4: reason=31 (RDMSR)
VM exit #4: RDMSR 0xc0000102 -> 0x00007a1e00000000; resuming at rip=0x000000007eaf5030.
VM exit #5: reason=32 (WRMSR)
VM exit #5: WRMSR 0xc0000102 <- 0x0000000000000000; resuming at rip=0x000000007eaf5043.
VM exit #6: reason=30 (I/O instruction)
VM exit #6: IN port 0x3ff size=1 -> 0x0; resuming at rip=0x000000007eaf5048.
VM exit #7: reason=30 (I/O instruction)
VM exit #7: OUT port 0x3ff size=1 value=0xa5; resuming at rip=0x000000007eaf504e.
VM exit #8: reason=30 (I/O instruction)
VM exit #8: IN port 0x3ff size=1 -> 0xa5; resuming at rip=0x000000007eaf5051.
VM exit #9: reason=30 (I/O instruction)
VM exit #9: OUT port 0x3ff size=1 value=0x0; resuming at rip=0x000000007eaf5059.
```

- Exit #1: the processor returned `ecx=0xf7fa3223` and the guest got
  `0xf7fa3203`. They differ by `0x20`, bit 5, the VMX bit, which the
  nested Hyper-V shows to Aleph0 and the policy hides from the guest. The
  policy changes nothing else. The guest value still has bit 31 set
  (hypervisor present), one of the open decisions of section 3.
- Exits #2 to #5: IA32_KERNEL_GS_BASE was `0x0`. The guest wrote
  `0x00007a1e00000000` (exit #3 shows it split as RDX = `0x7a1e`,
  RAX = `0x0`), read the same value back, and wrote `0x0` again.
- Exits #6 to #9: the exit qualification is `0x03ff0008` for the two INs and
  `0x03ff0000` for the two OUTs: port `0x3ff`, size 1, direction in bit 3.
  The scratch byte was `0x0`; `0xa5` written by exit #7 was read back by
  exit #8. So the scratch register of Hyper-V's UART works, and its absence
  (a read-back other than `0xa5`, which would stop the guest at `ud2` with
  `0xFA11` in EAX, section 6) did not happen. Exit #9 put `0x0` back.
- Each RIP in `resuming at` is the exit's RIP plus its instruction length
  (2 for `cpuid`, `rdmsr` and `wrmsr`, 1 for `in` and `out`), as in
  section 2.

The EPT write, the VMCALLs and the end of the run:

```text
VM exit #10: reason=48 (EPT violation)
VM exit #10: EPT violation at GPA 0x000000007eaf6000 (linear 0x000000007eaf6000): write; page R=1 W=0 X=0.
VM exit #10: write to the protected data page: write granted (W=1), INVEPT single-context; retrying the write at rip=0x000000007eaf506b.
VM exit #11: reason=18 (VMCALL)
VM exit #11: expected VMCALL (rax=0xa1e0); resuming the guest at rip=0x000000007eaf507b.
VM exit #12: reason=18 (VMCALL)
VM exit #12: expected VMCALL (rax=0xa1e1); all 2 planned VMCALLs handled; no NMI arrived.
VM exit #12: EPT: 1 write violation(s) on the protected data page, write granted.
VM exit #12: emulated exits: cpuid=1 rdmsr=2 wrmsr=2 in=2 out=2.
VM exit #12: stopping the guest; returning to bring-up.
Passthrough state before the guest PassthroughState { kernel_gs_base: 0, com1_scratch: 0 }, after it PassthroughState { kernel_gs_base: 0, com1_scratch: 0 }: restored=true.
Teardown: CR4.VMXE=0 firmware GDTR/IDTR restored=true IF=1.
Guest finished after 12 VM exits; VMX operation left.
Firmware timer fired: interrupts reach the firmware again.
Returning to firmware with SUCCESS.
```

- Exit #10 is the EPT violation that was exit #1 in `docs/EPT.md`, with the
  same qualification, `0x58a`. Its addresses differ (the data page is at
  `0x7eaf6000`) because the guest code grew to 169 bytes and the
  allocations moved.
- Exits #11 and #12 are the main VMCALL #1 and #2.
- `emulated exits: cpuid=1 rdmsr=2 wrmsr=2 in=2 out=2.` is
  `EXPECTED_EMULATION`. Aleph0's own count agrees with the guest's checks,
  so each of the nine instructions did cause an exit (section 6).
- `restored=true`: before and after the guest, IA32_KERNEL_GS_BASE and the
  COM1 scratch byte are both `0`. The guest wrote other values in between
  (exits #3 and #7), so it put both back (exits #5 and #9).

With `-InjectNmi`, fourteen exits: exits #1 to #11 as above, then the NMI
flow of `docs/NMI.md`, with the emulated exits before it unchanged:

```text
VM exit #12: reason=0 (exception or NMI)
VM exit #12: NMI (interruption info=0x80000202); reinjecting it into the guest at rip=0x000000007eaf5086.
VM exit #13: reason=18 (VMCALL)
VM exit #13: guest NMI handler ran (rax=0x4e4d49); the reinjected NMI was delivered; resuming the guest at rip=0x000000007eaf509a.
VM exit #14: expected VMCALL (rax=0xa1e1); all 2 planned VMCALLs handled; NMIs: 1 reinjected, 1 handled by the guest.
VM exit #14: emulated exits: cpuid=1 rdmsr=2 wrmsr=2 in=2 out=2.
Passthrough state before the guest PassthroughState { kernel_gs_base: 0, com1_scratch: 0 }, after it PassthroughState { kernel_gs_base: 0, com1_scratch: 0 }: restored=true.
Guest finished after 14 VM exits; VMX operation left.
```

The NMI is not an emulated exit, so the counts stay at 1, 2, 2, 2, 2.

## 8. Limits before an OS guest

- **The CPUID decisions of section 3**: the hypervisor-present bit, the
  leaves from 0x40000000, and OSXSAVE with leaf 0xD.
- **Unconditional exits.** XSETBV (reason 55), INVD (13), GETSEC (11), the
  VMX instructions and task switches always exit. Aleph0 handles none of
  them (except the test guest's VMCALLs, in `scenario.rs`); they reach the
  `_` arm and stop the guest. An OS runs XSETBV early.
- **String and REP I/O** stop the guest (section 5).
- **Only one MSR and one port are intercepted.** Every other MSR inside the
  bitmap's ranges and every other port reaches the hardware without Aleph0
  seeing it (MSRs outside the ranges get a #GP, section 4). The
  multi-port rule (section 5) also lets a wide access that touches `0x3FF`
  reach its neighbours, the serial driver's registers.
- **The #GP path is tested on the host only.** It is delivered through the
  guest's own IDT, which in the test guest has only vector 2, so a #GP would
  find no gate. The test guest never triggers it. The decisions
  (`GuestGeneralProtection`) and the encoding (`0x80000B0D`) are host tests;
  delivery needs an OS guest with an IDT of its own.
- **MSRs held in the VMCS cannot be intercepted.** They would need an
  emulation path that reads and writes the VMCS guest-state field
  (VMREAD/VMWRITE) instead of using RDMSR/WRMSR. `VMCS_HELD_MSRS` lists ten;
  newer CPUs have more fields (IA32_RTIT_CTL, IA32_S_CET and IA32_PKRS, for
  example), which belong on the list before Aleph0 intercepts them.

## Cheat sheet

| Item                                 | Value                                                                      |
| ------------------------------------ | -------------------------------------------------------------------------- |
| Primary control bit 28               | use MSR bitmaps                                                            |
| Primary control bit 25               | use I/O bitmaps (bit 24 is then ignored)                                   |
| `MSR_BITMAP`                         | `0x2004`                                                                   |
| `IO_BITMAP_A` / `IO_BITMAP_B`        | `0x2000` / `0x2002`                                                        |
| Exit reason 10 / 31 / 32 / 30        | CPUID / RDMSR / WRMSR / I/O instruction                                    |
| MSR bitmap quarters                  | `0x000` read low, `0x400` read high, `0x800` write low, `0xC00` write high |
| I/O bit of port _p_                  | bit `p % 8` of byte `(p & 0x7FFF) / 8`, page A below `0x8000`              |
| Intercepted                          | `IA32_KERNEL_GS_BASE` (`0xC0000102`), port `0x3FF`                         |
| I/O qualification                    | 2:0 size − 1, 3 IN, 4 string, 5 REP, 6 immediate, 31:16 port               |
| CPUID policy                         | CPUID.1:ECX bit 5 (VMX) cleared                                            |
| Injected #GP                         | `0x80000B0D`, error code 0, RIP unchanged                                  |
| `GUEST_MSR_VALUE` / `GUEST_IO_VALUE` | `0x0000_7A1E_0000_0000` / `0xA5`                                           |
| `GUEST_EMULATION_FAIL_MARKER`        | `0xFA11` in EAX at the `ud2`                                               |
| `EXPECTED_EMULATION`                 | cpuid 1, rdmsr 2, wrmsr 2, in 2, out 2                                     |
