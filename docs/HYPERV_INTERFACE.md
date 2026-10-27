# Hyper-V's interface: kept, and forwarded

Aleph0 runs nested under Hyper-V, and its guest ran on Hyper-V before
Aleph0 started: the firmware Aleph0 virtualizes in place had already set up
its hypercall page and its SynIC, because on a Gen 2 VM the keyboard, the
disk and the video are VMBus devices. Until issue #27 the guest still saw
Hyper-V in CPUID, but the parts of the interface that exit did not work:

- a hypercall is a VMCALL, which always exits, and Aleph0 stopped the
  firmware at any VMCALL that was not its own;
- Hyper-V's synthetic MSRs lie outside both MSR-bitmap ranges, so every
  RDMSR and WRMSR of them exited, and Aleph0 gave the guest a #GP.

The firmware's first synthetic MSR, `0x40000020`, got that #GP, and its
fatal-error path triple-faulted on purpose ([FIRMWARE_GUEST.md](FIRMWARE_GUEST.md)
section 5). Now Aleph0 repeats each hypercall and each synthetic-MSR access
in root operation, so L0 Hyper-V serves it as an access of Aleph0's own
virtual processor, the one the guest ran on before Aleph0 started.

Code: `src/vmx/hyperv.rs` (detection, the range, the forwarders and their
recovery points), `src/vmx/exit_decision/mod.rs` (`firmware_vmcall`),
`src/vmx/exit_decision/emulation.rs` (`route`, `MsrRoute::Synthetic`),
`src/vmx/vmexit/handler.rs` (`execute`, `prepare_resume`),
`src/vmx/host/handlers.rs` (the recovery in the host fault handler),
`src/vmx/vmexit/stats.rs` (`Forwarded`, `Tally`), `src/vmx/vmcall.rs`.

## 1. The decision: forward, everywhere

The issue weighed two options:

| | A: forward | B: hide Hyper-V from the OS |
|---|---|---|
| CPUID | passes through: ECX bit 31, the leaves from `0x40000000` | bit 31 cleared, the leaves answer zeros |
| the firmware | works: its VMBus drivers keep their hypercalls and SynIC | needs A anyway while boot services run |
| the OS | takes its Hyper-V paths (`ms_hyperv`, hypercall page, SynIC, the TSC and APIC frequencies from MSRs) | takes its bare-metal paths |

**Decision: A, for the firmware and the OS.** The firmware needs A whatever
the OS gets, and with A the first-boot kernel keeps the configuration #17
proved (`CONFIG_HYPERVISOR_GUEST=y`), so #28 boots the same kernel under
Aleph0 that already boots without it. B stays possible: the experiment
below shows the Linux target boots on the bare-metal paths too, so an OS
guest that must not see Hyper-V can get B later, in `cpuid_policy`, with A
left in place for the firmware.

What each experiment printed (section 7 has the lines):

- **A, firmware mode, 1 vCPU, Hyper-V.** The firmware ran on for minutes,
  36 million exits and no stop: synthetic MSR `0x40000020` read 16350 times,
  hypercall `0x5d` made at least 32 times, all forwarded. It drew its "Virtual
  Machine Boot Summary" screen, and Tab then Enter pressed "Restart now":
  Hyper-V logged event 18514, "reset by the guest operating system", as in
  the control run without Aleph0.
- **B, a kernel without Hyper-V guest support, without Aleph0.** Linux
  6.18.58 from `scripts/linux/build.sh` with `# CONFIG_HYPERVISOR_GUEST is
  not set` reached its shell. Without Hyper-V's frequency MSRs the fast
  TSC calibration and the PIT failed (the VM has no PIT), the TSC was
  calibrated against the ACPI PM timer (3168.264 MHz, where Hyper-V's MSR
  says 3187.199), the clocksource was `tsc-early` at the shell and `tsc`
  after the refinement at 1.19 s (3187.198 MHz); the TSC deadline timer is
  available for the LAPIC timer. Compared with #17's run, the CPU flags lack
  `constant_tsc`, `nonstop_tsc`, `tsc_reliable` and `tsc_known_freq`, which
  the kernel's Hyper-V code brings: it writes `0x40000118` to expose the
  invariant TSC and reads the frequency from `0x40000022`.

## 2. Whose VMCALL

A VMCALL means something different to each guest kind:

| Guest | CPL | RCX | Event | What Aleph0 does |
|---|---|---|---|---|
| test guest | any | any | `scenario::vmcall` | its script, by RAX markers, as before |
| firmware or OS | > 0 | any | `GuestInvalidOpcode` | #UD, as Hyper-V gives (KVM's emulation of Hyper-V too) |
| firmware or OS | 0 | `BOOT_SERVICES_ENDED`, `TEST` | `BootServicesEnded`, `TestVmcall` | resumes past it |
| firmware or OS | 0 | anything else, Hyper-V present | `Emulated(Hypercall)` | forwards it |
| firmware or OS | 0 | anything else, no Hyper-V | `GuestInvalidOpcode` | #UD, as on hardware without a hypervisor |

**Aleph0's own VMCALLs moved from RAX to RCX.** A hypercall's input value
is RCX:

```text
 63:60  59:48        47:44  43:32      31      30:27  26:17        16    15:0
┌─────┬────────────┬──────┬──────────┬───────┬──────┬────────────┬─────┬───────────┐
│ res │ rep start  │ res  │ rep count│ nested│ res  │ var. header│ fast│ call code │
└─────┴────────────┴──────┴──────────┴───────┴──────┴────────────┴─────┴───────────┘
```

`"Aleph0EB"` read big-endian is `0x416c657068304542`: its top nibble, 4,
sets bit 62, reserved, so Hyper-V would refuse it as a hypercall, and no
hypercall it takes is ever mistaken for Aleph0's. RAX, which a hypercall
ignores, could hold the signature by chance; RCX cannot hold it in a valid
hypercall. A compile-time assert in `vmcall.rs` checks both values.

**The CPL comes from SS.DPL** (`cpl_from_ss`, GUEST_SS_ACCESS_RIGHTS bits
6:5), read for VMCALL exits only. Without the check, a VMCALL from user
mode would reach Hyper-V from Aleph0's CPL 0.

**Hyper-V present** means CPUID.1:ECX bit 31, a highest hypervisor leaf of
at least `0x40000001`, and `"Hv#1"` in CPUID.40000001H:EAX, the interface
signature the TLFS says to check (`offers_interface`). Bring-up reads the
leaves once (`Detection::read`), prints them, and publishes the result
(`hyperv::publish`); every exit carries it as `ExitInfo::hyperv`.

## 3. Which MSRs

`SYNTHETIC_MSRS` is `0x40000000..=0x4000FFFF`, wider than the
`0x40000000`-`0x400000FF` the issue named: Hyper-V puts MSRs past `0xFF`
too, among them the crash MSRs (`0x40000100`-`0x40000105`),
`HV_X64_MSR_TSC_INVARIANT_CONTROL` (`0x40000118`, which the Linux target
writes at boot) and the nested SynIC's (`0x40001080` and up). An MSR
Hyper-V does not define reads 0 and ignores writes (section 5 shows
`0x4000FFFF`), as it does for the guest without Aleph0, so the wider range
forwards nothing the guest could not reach anyway.

`route` checks the range only outside the bitmap's ranges:

| MSR | Route | Event |
|---|---|---|
| in `INTERCEPTED_MSRS` | the real RDMSR/WRMSR | `Emulated(Rdmsr)`, `Emulated(Wrmsr)` |
| an MTRR MSR the guest has | its copy | `Emulated(MtrrRead)`, `Emulated(MtrrWrite)` |
| an MTRR address the CPU has no MSR at | #GP(0) | `GuestGeneralProtection` |
| outside both ranges, in `SYNTHETIC_MSRS`, Hyper-V present | forward | `Emulated(SyntheticRead)`, `Emulated(SyntheticWrite)` |
| outside both ranges otherwise | #GP(0) | `GuestGeneralProtection` |
| in range, bit clear | the bitmap is broken: stop | `Unexpected` |

A forwarded WRMSR is not checked for a canonical value: Hyper-V checks
what it takes.

## 4. Forwarding

`execute` (`vmexit/handler.rs`) runs the forwarders in `hyperv.rs`, small
`global_asm!` functions:

```text
hyperv_forward_hypercall(registers):        hyperv_forward_rdmsr(msr, value):
    push registers                              mov r8, value
    rcx, rdx, r8 <- registers               hyperv_rdmsr_instruction:
hyperv_hypercall_instruction:                   rdmsr
    vmcall               ; to L0 Hyper-V        [value] <- edx:eax
    pop r9                                      return 0
    registers <- rcx, rdx, r8, rax          hyperv_rdmsr_refused:
    return 0                                    return 1
hyperv_hypercall_refused:
    pop r9
    return 1
```

`hyperv_forward_wrmsr` is the RDMSR's twin. The registers in and out:

- **Hypercall:** in, the guest's RCX (the input value), RDX and R8 (the
  input and output GPAs, or a fast hypercall's data); out, RAX (the result:
  status in bits 15:0, reps done in 43:32), and RCX, RDX and R8 written
  back too, since Hyper-V updates RCX's rep start index when it continues a
  rep hypercall, and a fast hypercall can return data in RDX and R8. RIP
  then moves past the VMCALL. A fast hypercall's XMM0-XMM5 pass unchanged:
  Aleph0 never touches vector state (the target is soft-float, see
  `vmx::vmexit`).
- **RDMSR / WRMSR:** EDX:EAX, as for every emulated MSR.

**Why the GPAs stay valid:** EPT is an identity map, so a GPA the guest
passes names the same page for Hyper-V. The pages Hyper-V overlays at GPAs
the guest chose (the hypercall page, the reference TSC page, the SynIC's
message and event pages) appear in Aleph0's address space, and the guest
sees them through the same map. In the run below the guest's VMCALL is at
`0x7f60b000`, the start of its hypercall page, which the firmware placed
there before Aleph0 started.

A hypercall from L1 in VMX root operation reaches L0 as a hypercall of
L1's virtual processor; that is how a nested hypervisor talks to Hyper-V
(MiniVisor and hvpp forward their guests' hypercalls the same way).

## 5. When Hyper-V refuses

Hyper-V raises #UD for a hypercall it does not take (none enabled yet, for
example) and #GP for an MSR value that is refused. Raised in root
operation, either would land in the host IDT's fault handler, which prints
and halts: a guest could stop Aleph0 with one WRMSR. So each forwarding
instruction has a recovery point:

```text
fault at RIP ─▶ stub ─▶ host_exception_common ─▶ host_exception_handler
                                                   │
             hyperv::recovery(RIP, vector) ────────┤ Some(resume): frame.RIP = resume, return
                                                   │ None: print, halt (a bug, as before)
host_exception_common: RSP from RBP, drop vector and error code, IRETQ ─▶ _refused: return 1
```

`recovery` matches the RIP exactly and the vector too (#UD at the VMCALL,
#GP at the RDMSR and the WRMSR); any other fault stays a bug. A host test
reads the assembled bytes at each label (`0F 01 C1`, `0F 32`, `0F 30`), so
the label is the instruction the CPU reports.

The forwarder returns 1, `execute` returns `EmulationOutcome::Refused` with
the guest's registers unchanged, and `prepare_resume` turns the plan into
the exception's (`ResumePlan::refused_with`, host-tested): RIP stays on
the guest's instruction, and #UD or #GP(0) is injected there, as Hyper-V
would have done without Aleph0. The plan it returns is the one carried
out, so the statistics count the forwarded access and the injected
exception both.

The `forward-refusal-test` Cargo feature checks the path on Hyper-V: at the
first exit it forwards an RDMSR and a WRMSR of 0 to `0x4000FFFF`, which
Hyper-V does not define, and a WRMSR of a non-canonical value to
IA32_KERNEL_GS_BASE, which faults on any CPU:

```text
forward-refusal-test: RDMSR 0x4000ffff -> Ok(0), WRMSR 0x4000ffff <- 0 -> Ok(()); WRMSR 0xc0000102 <- 0x8000000000000000 -> Err(Refused); Aleph0 still runs.
```

The #GP reached the host fault handler, which resumed the forwarder at its
recovery point, and the firmware ran on for 6 million more exits. So an
undefined synthetic MSR is no refusal at all; only a value Hyper-V or the
CPU checks is. Hyper-V refused no hypercall in any run, so the VMCALL's #UD
recovery has the host test of its label only.

## 6. What it prints

Bring-up, after the exit bitmaps:

```text
Hyper-V interface offered (CPUID.1:ECX=0xf7fa3223, leaf 0x40000000: max leaf 0x4000000b vendor "Microsoft Hv", leaf 0x40000001: interface 0x31237648): the guest keeps it; Aleph0 forwards its hypercalls and its synthetic MSRs 0x40000000..=0x4000ffff to Hyper-V.
```

Each forwarded exit printed in full, within the print policy's first 16 of
its reason:

```text
VM exit #N: hypercall 0x005d (rcx=0x1005d) forwarded to Hyper-V -> status 0x0 (rax=0x0); resuming at rip=...
VM exit #N: RDMSR 0x40000020 (synthetic) forwarded to Hyper-V -> 0x00000000003b5321; resuming at rip=...
VM exit #N: WRMSR 0x40000001 (synthetic) <- 0x... forwarded to Hyper-V; resuming at rip=...
VM exit #N: Hyper-V refused the forwarded SyntheticWrite { msr: ..., value: ... } with #GP(0); injecting it at rip=...
VM exit #N: VMCALL (rcx=...) from CPL 3, which Hyper-V refuses too; injecting #UD at rip=...
```

The counts cost no line per exit. `VcpuStats` counts `hypercall_exits`,
`synthetic_read_exits` and `synthetic_write_exits`, and `Forwarded` keeps
them by call code (RCX bits 15:0) and by MSR, the first 32 keys each, the
rest in `other`. They are kept apart from `VcpuStats`, which bring-up
compares and returns in an error, so that stays a few words. A stop prints
both:

```text
VM exit #N: exit statistics: exits=... hypercall_exits=... synthetic_read_exits=... synthetic_write_exits=....
VM exit #N: forwarded to Hyper-V: hypercalls by call code: 0x5d=...; synthetic MSR reads: 0x40000020=...; synthetic MSR writes: none.
```

The firmware never stops when all goes well, so the summary line of a
VMCALL, RDMSR or WRMSR exit (the 32nd, 64th, ... of its reason) adds that
reason's tally:

```text
VM exit #101685: reason=18 (VMCALL), 32 exits of this reason so far.
VM exit #101685: forwarded to Hyper-V so far: hypercalls by call code: 0x5d=32.
```

## 7. The Hyper-V runs

**Firmware mode, `-ProcessorCount 1`.** From bring-up to the first
forwarded exits:

```text
Launching the firmware in place with VMLAUNCH; its VM exits are reported on serial only.
The firmware runs as the guest: Aleph0 returns to it in VMX non-root operation.
Waiting 1 s on a firmware timer event...
VM exit #1: HLT; going on at rip=0x000000007ff26114.
   (#2 to #7: CPUID)
VM exit #8: reason=31 (RDMSR)
VM exit #8: guest rip=0x000000007ff1d9c8 instruction length=2
VM exit #8: guest rax=0x0000000040000020 rbx=0x0000000040000020 rcx=0x0000000040000020 rdx=0x0000000000090004
VM exit #8: RDMSR 0x40000020 (synthetic) forwarded to Hyper-V -> 0x00000000003b5321; resuming at rip=0x000000007ff1d9ca.
   (the same RDMSR every few exits: HV_X64_MSR_TIME_REF_COUNT, 100 ns units, counting up)
VM exit #1675: reason=31 (RDMSR), 32 exits of this reason so far.
VM exit #1675: forwarded to Hyper-V so far: synthetic MSR reads: 0x40000020=32.
Firmware timer fired: interrupts reach the firmware again.
VM exit #101124: reason=18 (VMCALL)
VM exit #101124: guest rip=0x000000007f60b000 instruction length=3
VM exit #101124: guest rax=0x000000007f60b000 rbx=0x000000007ff21140 rcx=0x000000000001005d rdx=0x000000000000200d
VM exit #101124: hypercall 0x005d (rcx=0x1005d) forwarded to Hyper-V -> status 0x0 (rax=0x0); resuming at rip=0x000000007f60b003.
VM exit #101685: reason=18 (VMCALL), 32 exits of this reason so far.
VM exit #101685: forwarded to Hyper-V so far: hypercalls by call code: 0x5d=32.
...
VM exit #36639479: reason=31 (RDMSR), 16384 exits of this reason so far.
VM exit #36639479: forwarded to Hyper-V so far: synthetic MSR reads: 0x40000020=16350.
```

The exit at `0x7ff1d9c8` is the one that got #GP before (FIRMWARE_GUEST.md
section 5). `0x5d` with bit 16 is a fast `HvCallSignalEvent`, the VMBus
drivers' doorbell to the host, with the connection ID in RDX; it returned
`HV_STATUS_SUCCESS`. No WRMSR exit came: the firmware's SynIC was set up
before Aleph0 started. Between the timer reads the firmware idles in HLT,
which made most of the 36 million exits. Every hypercall seen was `0x5d`;
a stop would print the whole tally, and none came.

The console showed the firmware's "Virtual Machine Boot Summary" ("No
operating system was loaded", the "Restart now" button): Aleph0 had
returned to it, and it found no other boot option. The keyboard, through
Hyper-V's `Msvm_Keyboard.TypeKey`:

| Run | Keys | Result |
|---|---|---|
| control: `-TestGuest`, the firmware no longer virtualized after `SUCCESS` | Enter | nothing visible, as under Aleph0 in the first run |
| control | Tab, Enter | the VM reset, event 18514 "was reset by the guest operating system" at 19:10:40 |
| firmware under Aleph0 | Tab, Enter | the VM reset at the Enter (uptime 12 s before, 8 s after), event 18514 at 19:11:31 |

A triple fault in root operation would have reset the VM as well, but
Hyper-V logs that as event 18560; both resets were 18514. So the firmware,
as Aleph0's guest, read Tab and Enter from its VMBus keyboard and restarted
the VM through its own reset path.

Left alone at that screen in a third run, the firmware ran 5 min 21 s
with no stop: 67 million exits, the last summary lines

```text
VM exit #36592027: forwarded to Hyper-V so far: synthetic MSR reads: 0x40000020=16350.
VM exit #48865745: reason=10 (CPUID), 131072 exits of this reason so far.
VM exit #67319478: reason=12 (HLT), 67108864 exits of this reason so far.
```

**`-TestGuest` and `-InjectNmi`.** The same exits as before: 24 and
`SUCCESS`, 26 with the NMI reinjected at #24 and handled at #25, and
`SUCCESS`. The stop lines now end with the new counters, all zero:

```text
VM exit #26: exit statistics: exits=26 cpuid_exits=2 msr_read_exits=2 msr_write_exits=2 mtrr_read_exits=3 mtrr_write_exits=7 io_in_exits=2 io_out_exits=2 halt_exits=1 nmi_injections=1 exception_injections=0 hypercall_exits=0 synthetic_read_exits=0 synthetic_write_exits=0.
VM exit #26: forwarded to Hyper-V: hypercalls by call code: none; synthetic MSR reads: none; synthetic MSR writes: none.
```

`guest::expected_stats` requires those zeros: the test guest's VMCALLs are
its script's.

**Option B, without Aleph0.** `-Kernel <the build> -WithoutAleph0
-ProcessorCount 1`, from COM1:

```text
[    0.000000] tsc: Fast TSC calibration failed
[    0.000000] TSC deadline timer available
[    0.000000] Using NULL legacy PIC
[    0.000000] Failed to register legacy timer interrupt
[    0.000000] tsc: Unable to calibrate against PIT
[    0.000000] tsc: using PMTIMER reference calibration
[    0.000000] tsc: Detected 3168.264 MHz processor
[    0.082478] clocksource: Switched to clocksource tsc-early
[    0.230865] Run /init as init process
aleph0-linux: clocksource tsc-early
aleph0-linux: shell
[    1.186621] tsc: Refined TSC clocksource calibration: 3187.198 MHz
[    1.188874] clocksource: Switched to clocksource tsc
```

No `Hypervisor detected` line, as expected. The build took a copy of
`scripts/linux/` with that one line changed (and `# CONFIG_HYPERV is not
set` dropped, since it depends on `CONFIG_HYPERVISOR_GUEST`), in a work
directory of its own; it is not part of the repository.

## 8. Not covered yet

- **A 32-bit caller.** A hypercall from 32-bit mode passes its input in
  EDX:EAX, EBX:ECX and EDI:ESI; Aleph0 forwards the x64 registers only
  (a `shortcut:` comment in `firmware_vmcall`). Firmware and the Linux
  target run in 64-bit mode.
- **Isolation.** The forwarded MSRs and hypercalls act on Aleph0's own
  virtual processor: the guest can set its VP assist page, its SynIC or the
  partition's reset MSR, as it could without Aleph0. Keeping the guest from
  Hyper-V's state of Aleph0's processor comes after the first boot.
- **Guest addresses Hyper-V acts on, past EPT.** A hypercall's input and
  output pages (RDX, R8 for a non-fast call) and the overlay MSRs
  (`0x40000001` the hypercall page, `0x40000021` the reference TSC page,
  `0x40000073` the VP assist page, `0x40000083`/`0x40000084` the SynIC's
  message and event pages) name GPAs that Hyper-V reads, writes or overlays
  in Aleph0's own address space, where EPT does not apply. A guest that
  writes `0x40000001` with the address of Aleph0's exit handler and the
  enable bit would get Hyper-V's hypercall code laid over it. Issue #51 now
  checks each such GPA against Aleph0's resident allocations
  (`hyperv::hypercall_gpas`, `hyperv::overlay_gpa`, `page::is_resident`) and
  refuses it with #GP at the guest's instruction, instead of forwarding, so
  the guest cannot aim Hyper-V at Aleph0's pages even once they are hidden.
- **Whether Linux boots on the forwarded interface:** #28. The harness of
  #23 now gets through `ExitBootServices`, during which the firmware's
  VMBus drivers post a message (`0x5c`), zero the synthetic timers and mask
  the SINTs, all forwarded ([RESIDENT.md](RESIDENT.md) section 7).
- **Synthetic interrupts:** with external-interrupt exiting off, Hyper-V's
  interrupts reach the guest's IDT directly (the firmware timer above); the
  interrupt policy is #26.
- **The CPUID bits that follow the guest's CR4 and secondary controls:** #25.

## Cheat sheet

| Name | Where | What |
|---|---|---|
| `offers_interface`, `Detection` | `vmx/hyperv.rs` | bit 31, max leaf, `"Hv#1"`; the leaves bring-up prints |
| `publish`, `offered` | `vmx/hyperv.rs` | the result, for every exit (`ExitInfo::hyperv`) |
| `SYNTHETIC_MSRS` | `vmx/hyperv.rs` | `0x40000000..=0x4000FFFF` |
| `forward_hypercall`, `forward_rdmsr`, `forward_wrmsr` | `vmx/hyperv.rs` | the access again, in root operation; `Err(Refused)` on #UD/#GP |
| `recovery` | `vmx/hyperv.rs` | where the host fault handler resumes a refused forward |
| `firmware_vmcall` | `exit_decision/mod.rs` | CPL, Aleph0's own by RCX, forward, #UD |
| `cpl_from_ss` | `exit_decision/mod.rs` | SS.DPL, bits 6:5 of the access rights |
| `MsrRoute::Synthetic` | `exit_decision/emulation.rs` | the range, outside the bitmap, Hyper-V present |
| `Emulation::Hypercall`, `SyntheticRead`, `SyntheticWrite` | `exit_decision/emulation.rs` | what `execute` forwards |
| `EmulationOutcome::Refused` | `vmexit/handler.rs` | the exception Hyper-V raised, injected instead |
| `Forwarded`, `Tally` | `vmexit/stats.rs` | the counts by call code and by MSR |
| `BOOT_SERVICES_ENDED`, `TEST` | `vmx/vmcall.rs` | Aleph0's own VMCALLs, by RCX, reserved bit 62 set |
