# The firmware as the guest: virtualizing in place

Until issue #21 Aleph0 ran a separate test guest, stopped it after its
scripted VMCALLs, left VMX and returned to the firmware, which then ran as
before, outside any VM. Now a default build makes the firmware itself the
guest: the code after Aleph0's own VMLAUNCH goes on in VMX non-root
operation, returns through `bring_up::run` and `main`, and the boot manager
or the UEFI shell that started Aleph0 keeps running virtualized. The test
guest stays, as a regression mode.

Code: `src/vmx/vmcs/launch.rs` (`launch_in_place`), `src/vmx/guest_state.rs`
(`GuestEntry`), `src/vmx/vmcs/mod.rs` (`GuestKind`, the exception bitmap),
`src/vmx/exit_decision/mod.rs` (`decide`), `src/vmx/vmexit/handler.rs` (the
stop), `src/bring_up/mod.rs` (`launch_guest`), `src/main.rs`.

## 1. The two paths

```text
test guest (`test-guest` feature):
  run ─▶ vmx_launch ─▶ VMLAUNCH ─▶ guest code page ─▶ ... ─▶ exit ─▶ handler ─▶ stop value
                ▲                                                                  │
                └──────────────── vmx_return_to_launcher ◀─────────────────────────┘
  run ─▶ teardown (VMXOFF) ─▶ main ─▶ firmware, outside VMX

firmware (default):
  run ─▶ launch_in_place ─▶ VMLAUNCH ─┐   root operation
  ════════════════════════════════════╪══════════════════════════════════════
                                      └▶ the next instruction ─▶ ret ─▶ run ─▶ main ─▶ firmware ─▶ ...
                                         non-root operation, until the next exit
  every exit ─▶ handler ─▶ VMRESUME, back to wherever the firmware was
  a stop     ─▶ handler ─▶ report ─▶ halt
```

`GuestKind::SELECTED` picks one at build time: `Firmware`, or `BuiltInTest`
with the `test-guest` Cargo feature. Everything that differs between the two
hangs off that one value:

| | `BuiltInTest` | `Firmware` |
|---|---|---|
| guest state (`GuestEntry`) | `At`: its code page, stack top, RFLAGS `0x2`, its IDT | `InPlace`: written at VMLAUNCH, the firmware's IDT |
| launch | `vmcs::launch`, returns at the stop | `vmcs::launch_in_place`, returns as the guest |
| exception bitmap | all ones | 0 |
| VMCALL | the script (`scenario::vmcall`) | Aleph0's own (`vmx::vmcall`, [RESIDENT.md](RESIDENT.md)) resume; any other is a Hyper-V hypercall, forwarded ([HYPERV_INTERFACE.md](HYPERV_INTERFACE.md)) |
| EPT violation | the protected-page write, once | stops, with the walk of the GPA |
| a stop | returns to bring-up, teardown, `SUCCESS` or `ABORTED` | halts after the report |

Everything else is the same for both: CPUID, RDMSR/WRMSR (MTRRs to the
guest's copy, Hyper-V's synthetic MSRs forwarded, #GP for any other MSR
outside the MSR bitmap), IN/OUT, HLT, #UD for MWAIT and MONITOR, NMI
reinjection, the EPT misconfiguration stop.

## 2. The guest state: the running context

The guest state is already a copy of the running CPU (`GuestState::from_current`):
CR0, CR3, CR4, the selectors, GDTR (Aleph0's GDT copy with its TSS, since
VM entry needs a busy TSS in TR and Hyper-V's firmware never loads one),
SYSENTER, PAT. For the firmware only four fields differ from the test
guest's:

| Field | Value |
|---|---|
| GUEST_RIP | the instruction after VMLAUNCH in `launch_in_place` |
| GUEST_RSP | RSP at VMLAUNCH |
| GUEST_RFLAGS | RFLAGS at VMLAUNCH, so IF is the firmware's (1) |
| GUEST_IDTR | the firmware's IDT, recorded when the GDT copy was activated |

RIP, RSP and RFLAGS only exist at VMLAUNCH, so `GuestEntry::InPlace` writes
placeholders (0, 0, `0x2`), bring-up prints that, and `launch_in_place`
writes the real ones in the same asm block as the VMLAUNCH:

```text
lea     rax, [rip + 2f]        ; RIP the guest starts at: label 2 below
vmwrite GUEST_RIP, rax
jbe     3f                     ; CF = 1 or ZF = 1: VMfailInvalid or VMfailValid
vmwrite GUEST_RSP, rsp         ; RSP right now: nothing below moves it
jbe     3f
pushfq
pop     rax
vmwrite GUEST_RFLAGS, rax      ; RFLAGS right now, IF included
jbe     3f
vmlaunch                       ; success never falls through
3:  pushfq                     ; failure: return its RFLAGS
    pop rax
    jmp 4f
2:  xor eax, eax               ; the guest starts here: return 0
4:
```

VM entry loads RIP, RSP and RFLAGS from the VMCS but leaves RAX to R15
alone, so at label 2 every register holds what it held at VMLAUNCH. To the
compiler the block is one instruction that returned 0 in RAX, with RSP
unchanged: the `ret`s that follow walk back up the same firmware stack, now
in non-root operation. `decode_in_place` turns the value into `Ok` (0) or
the failure (never 0: RFLAGS bit 1 always reads as 1).

An interrupt that arrives between the PUSHFQ and VMLAUNCH runs the
firmware's handler in root operation, on the stack below RSP, and is over
before VMLAUNCH. With IF = 1 and external-interrupt exiting off, the
firmware's own interrupts then go through its own IDT, with no VM exit.

## 3. A stop

The test guest's stop jumps back into the frame `vmx_launch` saved
(`VMX_LAUNCH_RSP`, [CLEAN_STOP.md](CLEAN_STOP.md)). `launch_in_place` saves
none: by the time the firmware stops, it has returned from that frame long
ago and reused the stack. So for the firmware (`GuestKind::stop_returns_to_bring_up`
is false) the handler prints the whole stop (the exit, the guest's state and
registers, the statistics, the exits by reason, the last exits), then halts
this CPU with `cli; hlt`. The line before the dump says so:

```text
VM exit #N: NOT an exit Aleph0 handles for the firmware.
VM exit #N: stopping the guest; halting: the firmware has nothing to return to.
```

A failed VMRESUME halts the same way. Teardown never runs for the firmware
once it has launched: CR4.VMXE stays set, the GDT stays Aleph0's copy, and
the CPU stays in VMX operation for good.

## 4. Output

The exit handler sets the `VmExit` output phase first, so nothing in exit
context reaches the firmware console. In place, the guest is Aleph0's own
code too until `main` returns, and it may print with `log!`; so the handler
puts back the phase it found when it resumes the guest, and the console
works again in non-root operation. `vmresume_failed` sets `VmExit` again
itself. After the launch `main` prints
`The firmware runs as the guest: Aleph0 returns to it in VMX non-root operation.`,
then waits on a firmware timer event, which shows that the timer interrupt
reaches the firmware's handler through its own IDT.

## 5. Running it

```powershell
.\scripts\run-hyperv.ps1 -ProcessorCount 1   # the firmware
.\scripts\run-hyperv.ps1 -TestGuest          # the regression mode
.\scripts\run-hyperv.ps1 -InjectNmi          # the regression mode, with an NMI
```

`-TestGuest` adds the `test-guest` feature, and so does `-InjectNmi`, whose
job waits for a line only the test guest's VMCALLs print. The
`host-nmi-test`, `unexpected-exit-test` and `ept-misconfig-test` features
turn it on themselves; `host-fault-test` and `trace-exits` work in both
modes.

On Hyper-V Gen 2, the keyboard, disk and video are VMBus devices: the
firmware's hypercalls are VMCALLs, which stopped it, and its reads and
writes of the synthetic MSRs (`0x40000000` and up) lie outside the MSR
bitmap, so they got a #GP. The first Hyper-V run showed which comes first:

```text
Launching the firmware in place with VMLAUNCH; its VM exits are reported on serial only.
VM exit #1: CPUID leaf=0x1 subleaf=0x1 -> ... resuming at rip=0x000000007ff1b167.
   (#2 to #6: CPUID leaves 0 and 1 at the same RIP)
VM exit #7: reason=31 (RDMSR)
VM exit #7: MSR 0x40000020 is outside the MSR bitmap, or the WRMSR value is not canonical; injecting #GP(0) at rip=0x000000007ff1d9c8.
VM exit #8: reason=2 (triple fault)
VM exit #8: guest rip=0x00000000047466e4 instruction length=0
VM exit #8: NOT an exit Aleph0 handles for the firmware.
VM exit #8: stopping the guest; halting: the firmware has nothing to return to.
VM exit #8: guest gdtr=0x000000007eaba000/0x004f idtr=0x0000000000000000/0x0000; ...
VM exit #8: exits by reason: 2 (triple fault)=1, 10 (CPUID)=6, 31 (RDMSR)=1.
```

The launch itself worked: the console showed the tag of `main`'s line
after it, so Aleph0's own code ran on as the guest. Drawing that line, the
firmware read `0x40000020`, `HV_X64_MSR_TIME_REF_COUNT` (the partition
reference counter its timer code uses), got the #GP, and its fatal-error
path loaded a zero IDT (the stop's `idtr=0/0`) and triple-faulted on
purpose. The test guest's runs printed the same exits as before: 24 and
`SUCCESS`, and 26 with `-InjectNmi`.

Since #27 Aleph0 forwards the firmware's hypercalls and synthetic MSRs to
Hyper-V ([HYPERV_INTERFACE.md](HYPERV_INTERFACE.md)). The same RDMSR at
`0x7ff1d9c8` now reads the reference counter, and the firmware runs on:
its timer fires, its VMBus drivers signal the host with hypercall `0x5d`,
it draws its "Virtual Machine Boot Summary" screen, and Tab then Enter on
its keyboard press "Restart now", which resets the VM as it does without
Aleph0 (HYPERV_INTERFACE.md section 7). Left alone at that screen, it ran
5 min 21 s under Aleph0 with no stop: 67 million exits, nearly all HLT
(`reason=12 (HLT), 67108864 exits of this reason so far` at exit
#67319478).

## 6. Not covered yet

- Its idle loop: HLT exits and resumes at once, so the exit counts grow
  quickly: about 36 million exits in three minutes at the Boot Summary
  screen, nearly all HLT, with the print policy keeping the first 16 of
  each reason in full and then one summary line per power of two.
- CR0/CR4 masks, so the firmware sees CR4.VMXE today (#24); re-delivering
  interrupted events and the interrupt policy for an OS (#26).
- The firmware guest still gets the test guest's pages, because `Ept::build`
  protects their data page. Nothing in the firmware touches it, and since
  #23 they are resident, so no OS reuses them either.
- Staying resident after `ExitBootServices` (#23) is implemented
  ([RESIDENT.md](RESIDENT.md)); its harness run stopped where the firmware
  did, at `0x40000020`, and is to be run again now that #27 forwards it.

## Cheat sheet

| Name | Where | What |
|---|---|---|
| `GuestKind::SELECTED` | `vmcs/mod.rs` | `Firmware`, or `BuiltInTest` with `test-guest` |
| `GuestEntry::InPlace` | `guest_state.rs` | RIP/RSP/RFLAGS placeholders, the firmware's IDTR |
| `launch_in_place` | `vmcs/launch.rs` | writes RIP/RSP/RFLAGS, VMLAUNCH, returns `Ok` as the guest |
| `decode_in_place` | `vmcs/launch.rs` | 0 → `Ok`, RFLAGS → the failure |
| `decide(GuestKind, ..)` | `exit_decision/mod.rs` | only the test guest has VMCALLs and a protected page |
| `halt_unless_returnable` | `vmexit/handler.rs` | a stop of the firmware halts |
| `GuestRun::Virtualized` | `bring_up/mod.rs` | `run` returned in non-root operation; no teardown |
