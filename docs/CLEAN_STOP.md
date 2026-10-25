# The clean stop: leaving VMX and returning to firmware

How Aleph0 stops its guest, leaves VMX operation, puts the firmware's CPU
state back, and returns from the EFI application with a `Status`, instead of
halting after the last VM exit (ROADMAP section 4). It covers how execution
gets from the VM-exit stub back into `bring_up::run`, the 64-bit stop value
that says why the guest stopped, the teardown order and the reasons for it,
and what the Hyper-V run printed.

Code: `src/vmx/vmcs/launch.rs` (launch stub and stop value),
`src/vmx/vmexit/` (exit stub and handler), `src/bring_up/teardown.rs`,
`src/bring_up/mod.rs` (`run`), `src/vmx/vmxon.rs` (`VmxOperation::leave`),
`src/main.rs` (timer check and return).

## 1. The problem

Before this change, `bring_up::run` ended with VMLAUNCH and never came back:

```
main ─▶ run ─▶ ... ─▶ VMLAUNCH ─▶ guest ─▶ VM exit ─▶ exit stub ─▶ handler ─▶ cli; hlt
                                                       (exit stack)
```

After VMLAUNCH, host code runs only when a VM exit starts the exit stub at
`HOST_RIP`, with `RSP = HOST_RSP` on the separate VM-exit stack. The frames
of `main` and `run` are still on the firmware stack, but nothing jumps back
to them, so the only option was to halt.

Returning to firmware needs two things:

1. **A way back into `run`'s frame** from the exit stub (section 2).
2. **Undoing what VMX and the VM exits changed** before firmware runs
   again (section 5). A VM exit loads host state with a few fixed values:

   | State | After every VM exit | Firmware expects |
   |---|---|---|
   | GDTR limit, IDTR limit | `0xFFFF` | the real table size |
   | TR limit | `0x67` | (unchanged for Aleph0's own TSS) |
   | RFLAGS | `0x2`, so IF = 0 | IF = 1 (timer interrupts) |
   | DR7, IA32_DEBUGCTL | `0x400`, `0` | the same values, unless a debugger is attached |
   | LDTR | null | null (UEFI uses no LDT) |

   On top of that the CPU is still in VMX root operation, with CR4.VMXE set
   and a current VMCS.

## 2. Getting back into `run`: a setjmp/longjmp

`vmx_launch` (in `launch.rs`) is a small assembly routine that saves its
caller's state *before* VMLAUNCH, like C's `setjmp`. When the guest should
stop, the exit stub jumps to `vmx_return_to_launcher`, which restores that
state and returns, like `longjmp`. To Rust, `vmcs::launch()` is an ordinary
call that returns a `GuestStop`.

### What gets saved

`vmx_launch` is called with the Microsoft x64 ABI (`efiapi`). A function
must give its caller back RBX, RBP, RDI, RSI, R12-R15 and RSP unchanged. So
the stub pushes those eight registers and writes RSP to a static,
`VMX_LAUNCH_RSP`:

```
firmware stack (grows down)

  │ ...                     │  launch()'s frame (Rust)
  │ return address          │  ◀ pushed by `call vmx_launch`
  │ rbx                     │
  │ rbp                     │
  │ rdi                     │
  │ rsi                     │
  │ r12                     │
  │ r13                     │
  │ r14                     │
  │ r15                     │  ◀ RSP here is saved in VMX_LAUNCH_RSP
  └─────────────────────────┘
```

`vmx_return_to_launcher` loads RSP from `VMX_LAUNCH_RSP`, pops the eight
registers in reverse order, and executes `ret`. The return address on the
stack takes it back into `launch()`, with the stop value in RAX, the
ordinary return register.

The ABI also makes XMM6-XMM15 callee-saved. The `x86_64-unknown-uefi`
target is soft-float with SSE disabled, so neither Aleph0 nor the guest
touches them.

### Why the saved frame survives the guest run

Three stacks are in play, and only the first one holds the saved frame:

| Stack | Who uses it | While the guest runs |
|---|---|---|
| firmware stack | `main`, `run`, `launch`, `vmx_launch` | frozen; nothing writes it |
| VM-exit stack (16 pages, `HOST_RSP`) | the exit stub and handler | every exit starts at its top again |
| guest stack page | the guest | the guest's RSP |

The guest runs with IF = 0, and every guest exception exits (exception
bitmap all ones), so no firmware handler runs on the firmware stack in the
meantime.

### The full path of one run

```
run ─▶ launch() ─▶ vmx_launch: push 8 regs, save RSP, VMLAUNCH
                                   │
          guest: mov eax,0xa1e0; vmcall ──▶ exit #1 ──▶ handler returns 0
                                   ◀── stub pops guest regs, VMRESUME
     guest: (wait loop) inc eax; vmcall ──▶ exit #2 ──▶ handler returns 0x4000_0000_0000_0002
                                                        │ stub: test rax,rax; jnz
                                                        ▼
                                   vmx_return_to_launcher: RSP = VMX_LAUNCH_RSP,
                                   pop 8 regs, ret
run ◀─ launch() returns GuestStop::Finished { exits: 2 }
 └─▶ teardown ─▶ main: timer check ─▶ return SUCCESS to firmware
```

## 3. The stop value

The stubs can pass one register back, so every way back carries one 64-bit
**stop value**. Bits 63:62 say which kind it is, and the rest is the payload:

| Bits 63:62 | Payload | Meaning | `GuestStop` |
|---|---|---|---|
| 0 | RFLAGS right after VMLAUNCH | VMLAUNCH failed | `LaunchFailed` |
| 1 | number of exits | all planned exits arrived | `Finished` |
| 2 | exit number (bits 61:32), raw exit reason (bits 31:0) | an exit the handler does not resume | `Unexpected` |
| 3 | RFLAGS right after VMRESUME | VMRESUME failed | `ResumeFailed` |

Kind 0 is RFLAGS itself, unencoded: RFLAGS bits 63:22 are reserved and read
as 0, so the launch stub can return it as it is. RFLAGS bit 1 always reads
as 1, so **no stop value is 0**. That frees 0 to mean "resume the guest" as
the exit handler's return value.

Worked examples:

| Situation | Stop value | Decoded |
|---|---|---|
| the Hyper-V run: exit #2 was the last planned one | `0x4000_0000_0000_0002` | `Finished { exits: 2 }` |
| if exit #1 were a CPUID exit (reason 10) | `0x8000_0001_0000_000A` | `Unexpected { number: 1, reason: 10 }` |
| VMLAUNCH fails with ZF set (called with IF = 1) | `0x0000_0000_0000_0242` | `LaunchFailed { VmFailValid }` |
| VMRESUME fails with ZF set (IF = 0 after the exit) | `0xC000_0000_0000_0042` | `ResumeFailed { VmFailValid }` |

The exit number keeps only 30 bits, so an absurdly large number can never
spill into the kind bits. `encode_*` and `decode` are pure functions with
host tests in `tests/unit/vmx/vmcs/launch.rs`.

## 4. What the exit handler returns

`vmexit_handler` prints the exit, as before, then returns a `u64` to the
stub instead of halting:

| Exit | Handler action | Returns | Stub does |
|---|---|---|---|
| expected VMCALL, not the last one | writes GUEST_RIP = RIP + instruction length | `0` | pops guest registers, VMRESUME |
| expected VMCALL, the last planned one | prints `all 2 planned VMCALLs handled` | `encode_finished(number)` | jumps to `vmx_return_to_launcher` |
| anything else | prints `NOT an expected exit` | `encode_unexpected(number, reason)` | jumps to `vmx_return_to_launcher` |
| expected VMCALL, but GUEST_RIP cannot be advanced | prints why | `encode_unexpected(number, 18)` | jumps to `vmx_return_to_launcher` |

If VMRESUME itself falls through, the stub calls `vmresume_failed`, which
prints the reason and returns `encode_resume_failed(rflags)`; the stub then
jumps to `vmx_return_to_launcher` too. If VM_EXIT_REASON cannot be read, the
reason sent back is `0xFFFF`, which no real exit uses
(`exit_reason_name` prints it as `VM_EXIT_REASON unreadable`).

The stop path never restores the guest's registers: the exit stack is
simply abandoned, and the next launch would start it from the top again.

Since the NMI step, `exit_decision::decide` makes this decision, and the handler also resumes after NMI and NMI-window exits; see [NMI.md](NMI.md).

## 5. Teardown

`bring_up::teardown::teardown` runs in plain Rust on the firmware stack,
right after `launch()` returns. The order matters:

| # | Step | Why here |
|---|---|---|
| 1 | CR3, `lgdt` / `lidt` with the firmware's CR3, GDTR and IDTR | VM exits load Aleph0's own page tables, GDT and IDT ([HOST_ENVIRONMENT.md](HOST_ENVIRONMENT.md)); CR3 first, before anything can call firmware |
| 2 | VMCLEAR the VMCS (if one was created) | writes the CPU's cached VMCS data back to memory and makes it not current |
| 3 | VMXOFF, then CR0/CR4 as they were before VMXON | CR4.VMXE can only be cleared after VMXOFF; clearing it earlier is #GP |
| 4 | output phase back to `BootServices` | `log!` may use the firmware console again |
| 5 | STI, only if IF was 1 before VMXON | firmware's timer interrupts come back |
| 6 | read CR4, CR3, GDTR, IDTR, RFLAGS and print them | the `Teardown:` line on serial and console |

Worked example from the Hyper-V run: the guest-state line printed
`idtr=0x000000007ff2fcd0/0x0fff`, the firmware's IDT. After each VM exit the
CPU's IDTR was `0x7ff2fcd0/0xffff`; step 1 loads `/0x0fff` again. The same
line printed `cr4=0x2668`: CR4 in VMX operation, with bit 13 (`0x2000`,
VMXE) set. Step 3 writes back the CR4 value saved before VMXON, which has
VMXE clear, and the `Teardown:` line confirms `CR4.VMXE=0`.

### Why interrupts and the console come back last

When the guest ran, interrupts stay off from the first VM exit until step 5.
The firmware console can call `RestoreTPL`, which executes STI, so a console
`log!` during steps 1 to 3 would turn interrupts on too early. Until step 4
the phase is still `VmExit` (the exit handler set it), so `log!` writes to
serial only. On paths that never launched the guest, the phase is still
`BootServices` and IF was never cleared, so the problem does not arise.

IF is recorded in `run` right before VMXON (`FirmwareState`), not in the
launch stub. Nothing between VMXON and VMLAUNCH turns interrupts off, so the
value is the same, and the stub stays smaller.

### What teardown leaves as it is

- **TR** keeps Aleph0's TSS selector. LTR cannot load a null selector, and
  the TSS and GDT pages are never freed, so the CPU's cached TSS descriptor
  stays valid. The selector may lie past the firmware GDT's limit; only an
  LTR or a task switch would look it up again.
- **DR7, IA32_DEBUGCTL, LDTR** stay as the VM exit set them. Firmware
  normally runs with those values anyway; they matter only with a hardware
  debugger attached.
- **Memory**: no page is returned to UEFI. The TSS, GDT, VM-exit stack,
  guest pages, VMXON region and VMCS stay allocated.

### When a teardown step fails

Every step runs even if an earlier one failed. The exception: after a
failed VMXOFF, CR0/CR4 are not touched, because the CPU is still in VMX
operation. Each failure is printed when it happens. `run` returns the error
from before teardown if there was one, otherwise `BringUpError::Teardown`.

## 6. Error numbers are read early

For a VmFailValid, the reason number lives in the current VMCS
(`VM_INSTRUCTION_ERROR`). Errors used to read it while printing. Now they are
printed after teardown, and a VMREAD after VMXOFF raises #UD. So the number
is read when the error is created, while the VMCS is still current:
`vmcs_step` and `guest_state_error` (in `bring_up/error.rs`) and `launch()`
store it in the error value (`instruction_error: Option<u32>`), and
`report_vmcs_error` only prints what was stored.

## 7. Which failures reach teardown

| Where `run` fails | What is undone before returning |
|---|---|
| before the host tables are active (TSS/GDT allocation) | nothing was changed |
| after activation, before VMXON (allocation, page-table check, VMX unsupported, VMXON failed) | the firmware's GDTR is loaded again |
| after VMXON (VMCS setup, changed host tables, VMLAUNCH, unexpected exit, VMRESUME) | full teardown |

So once VMXON succeeds, firmware never gets the CPU back in VMX operation,
unless VMXOFF itself fails, which teardown prints.

## 8. Back in `main`

`main` maps the result to a `Status` (`SUCCESS` for the planned run,
`ABORTED` for any error), then runs `check_firmware_timer`: it creates a
one-shot UEFI timer event, arms it for 1 s, waits for it, and closes it. Only
the firmware's timer interrupt signals that event, so getting past the wait
shows that interrupts reach the firmware's handlers through the restored
IDT. If they did not, the wait would never end and `Waiting 1 s on a firmware
timer event...` would be the last line on serial.

The wait does not prove that teardown restored IF: WaitForEvent can turn
interrupts on by itself through `RestoreTPL`. That is why the `Teardown:`
line prints IF separately.

Then `main` returns the status, and the firmware's boot manager takes over.

## 9. The Hyper-V run

The tail of `run\serial.log` from the clean-stop step, before NMI exiting was added, with what each part shows. Its addresses and the exit #2 RIP match that older guest, not the current one:

> This log predates EPT and the emulated exits. Since then the guest first
> causes nine emulated exits (CPUID, four MSR, four I/O; see
> [EMULATED_EXITS.md](EMULATED_EXITS.md)), one HLT and one EPT violation, so
> in a current run its VMCALLs are exits #12 and #13: the numbers are eleven
> higher. The guest RIPs and addresses differ too. Since #22 the `Teardown:`
> line also reports `firmware CR3 restored=true`.

```text
VM exit #1: guest rip=0x000000007eb0f005 instruction length=3
VM exit #1: guest rax=0x000000000000a1e0 ...                      ◀ guest code ran up to VMCALL
VM exit #1: expected VMCALL (rax=0xa1e0); resuming the guest at rip=0x000000007eb0f008.
VM exit #2: guest rip=0x000000007eb0f005 instruction length=3
VM exit #2: guest rax=0x000000000000a1e1 ...                      ◀ resumed past VMCALL, ran inc eax
VM exit #2: expected VMCALL (rax=0xa1e1); all 2 planned exits handled.
VM exit #2: stopping the guest; returning to bring-up.            ◀ handler returned 0x4000_0000_0000_0002
Teardown: CR4.VMXE=0 firmware GDTR/IDTR restored=true IF=1.       ◀ back in run(), VMX off
Guest finished after 2 VM exits; VMX operation left.             ◀ GuestStop::Finished { exits: 2 }
Waiting 1 s on a firmware timer event...
Firmware timer fired: interrupts reach the firmware again.        ◀ IDT and timer work
Returning to firmware with SUCCESS.                               ◀ main returns
```

Under QEMU without VMX, bring-up stops in step 1 at an older check
(`IdtRequiresIst`: OVMF's IDT uses IST stacks), before any table is loaded.
The timer check still runs, and the last line is `Returning to firmware
with ABORTED.`

## 10. What is not covered yet

- Only the planned path ran on real VMX. The other stops (unexpected exit,
  failed VMLAUNCH or VMRESUME) go through the same teardown but have only
  been compiled. The `unexpected-exit-test` Cargo feature changes the
  expected guest RAX on purpose, which exercises `Unexpected` at main
  VMCALL #1 (exit #12), the stop report, teardown from exit context, and
  `ABORTED` (`run-hyperv.ps1 -Features unexpected-exit-test`).
- NMIs: since the NMI step, NMI exiting is on and NMIs are reinjected into
  the guest's own IDT; see NMI.md.
- After `ExitBootServices` Aleph0 must stay resident instead of returning
  (ROADMAP section 5). The stop path is then the way to shut the hypervisor
  down, not the normal end of a run.
- All of this is the test guest's path, the regression mode (Cargo feature
  `test-guest`). A default build virtualizes the firmware in place, which
  has no stop to return from: a stop of the firmware halts after its report,
  and no teardown runs. See [FIRMWARE_GUEST.md](FIRMWARE_GUEST.md).

## Cheat sheet

| Name | Where | What |
|---|---|---|
| `vmx_launch` | `vmcs/launch.rs` | push 8 callee-saved regs, save RSP, VMLAUNCH |
| `vmx_return_to_launcher` | `vmcs/launch.rs` | reload RSP, pop 8 regs, `ret` with the stop value in RAX |
| `VMX_LAUNCH_RSP` | `vmcs/launch.rs` | the saved RSP |
| `GuestStop` | `vmcs/launch.rs` | `Finished`, `Unexpected`, `LaunchFailed`, `ResumeFailed` |
| `RESUME_GUEST` (0) | `vmexit/handler.rs` | handler return value: resume |
| `stub_return` | `vmexit/handler.rs` | `ExitAction` to `0` or a stop value |
| `VmxOperation::leave` | `vmxon.rs` | VMXOFF, then CR0/CR4 from before VMXON |
| `load_gdtr`, `load_idtr` | `segment.rs` | LGDT/LIDT from a `DescriptorTable` |
| `teardown` | `bring_up/teardown.rs` | tables, VMCLEAR, VMXOFF + CRs, phase, STI, report |
| `check_firmware_timer` | `main.rs` | 1 s UEFI timer event before returning |
