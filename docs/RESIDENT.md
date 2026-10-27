# Staying resident after `ExitBootServices`

Once the OS loader calls `ExitBootServices`, the OS owns the machine: it may
reuse every page the UEFI memory map lists as `LOADER_*`, `BOOT_SERVICES_*`
or conventional memory. Until issue #23 everything Aleph0 needs at a VM exit
was in those types: its image (`LOADER_CODE`) and every page it allocated
(`LOADER_DATA`). An OS booted under Aleph0 would have overwritten the exit
handler, its stack or the EPT tables, and the next exit would have run into
whatever the OS put there.

Code: `src/resident/` (`mod.rs`: the image copy and the `ExitBootServices`
event; `memory.rs`: which types the OS reclaims; `pe.rs`: base relocation),
`src/vmx/page.rs` (the resident allocation path), `src/bring_up/mod.rs`
(`check_resident_memory`, `virtualize_firmware`), `src/vmx/vmcall.rs`,
`src/vmx/exit_decision/mod.rs` (`firmware_vmcall`), `src/vmx/vmexit/handler.rs`
(`resume_phase`), `tools/ebs-harness/`.

## 1. What the OS keeps

The UEFI spec's table "Memory Type Usage after ExitBootServices()" decides
it, and `resident::memory::is_reclaimable` encodes it:

| Type | After `ExitBootServices` | `is_reclaimable` |
|---|---|---|
| `LOADER_CODE`, `LOADER_DATA` | the loader and the OS use it as they see fit | yes |
| `BOOT_SERVICES_CODE`, `BOOT_SERVICES_DATA`, `CONVENTIONAL` | general use | yes |
| `ACPI_RECLAIM` | general use once ACPI is enabled | yes |
| `PERSISTENT_MEMORY` | works as conventional memory | yes |
| `UNACCEPTED` | general use once accepted | yes |
| `RUNTIME_SERVICES_CODE`, `RUNTIME_SERVICES_DATA` | preserved | no |
| `RESERVED`, `ACPI_NON_VOLATILE`, `PAL_CODE` | preserved | no |
| `UNUSABLE`, MMIO, MMIO port space | never used as memory | no |
| OEM and OS-loader types (`0x7000_0000` and up) | only their owner knows | no |

Linux 6.18 (`arch/x86/platform/efi/efi.c`, `do_add_efi_memmap`) turns the
runtime types, `RESERVED`, MMIO and `PAL_CODE` into E820 reserved ranges,
which it never allocates from.

## 2. Aleph0's pages: `RUNTIME_SERVICES_DATA`

`vmx::page` has one allocation path, and it gives resident types:

| Constant | Type | For |
|---|---|---|
| `RESIDENT_DATA` | `RUNTIME_SERVICES_DATA` | everything `allocate_zeroed_page(s)` returns: the VMXON region and VMCS, the exit stack, the MSR and I/O bitmaps, the EPT tables, the host page tables, GDT, TSS, IDT and interrupt stacks, the context GDT and TSS, the test guest's stack and IDT |
| `RESIDENT_CODE` | `RUNTIME_SERVICES_CODE` | the image copy (section 3) and the test guest's code and data pages |

Why the runtime types and not `RESERVED`: both are kept, but Aleph0 needs a
code type for its image, which runs in the guest on the firmware's page
tables too (the event in section 4), and firmware with DXE memory protection
maps the data types no-execute, `RESERVED` included (EDK2's
`PcdDxeNxMemoryProtectionPolicy` has a bit per type; the usual value sets
every data type's). `RUNTIME_SERVICES_CODE` is the kept code type, and
`RUNTIME_SERVICES_DATA` its data counterpart. The cost: the OS sees the pages
as runtime memory, maps them for runtime services and gives them a virtual
address in `SetVirtualAddressMap`. It never writes them; hiding them from the
guest is EPT's job, after the first boot (ROADMAP section 5).

The test guest's pages are resident too, although the test guest never runs
after `ExitBootServices`: `Ept::build` keeps its data page read-only for the
firmware guest as well, so an OS that reused that page would stop at an EPT
violation.

Every resident allocation is listed (`page::resident_allocations`, up to
64). Before the launch, bring-up reads the memory map, prints each
allocation's type, and refuses to launch if one is reclaimable or in no
region (`BringUpError::NotResident`). On Hyper-V, in the regression mode:

```text
Resident allocation at 0x000000007ea23000: 143 page(s), RUNTIME_SERVICES_CODE.
Resident allocation at 0x000000007ff81000: 1 page(s), RUNTIME_SERVICES_DATA.
Resident allocation at 0x000000007ff80000: 1 page(s), RUNTIME_SERVICES_DATA.
Resident allocation at 0x000000007ea13000: 16 page(s), RUNTIME_SERVICES_DATA.
Resident allocation at 0x000000007ff46000: 2 page(s), RUNTIME_SERVICES_CODE.
   ... 22 more, all RUNTIME_SERVICES_DATA
Resident memory checked: 325 pages, all kept by the OS after ExitBootServices.
```

In order: the image copy, the context TSS and GDT, the exit stack, the test
guest's code and data pages. After a return to the firmware (the test
guest, or a failed bring-up) the pages stay allocated, so the OS booted next
loses about 1.3 MiB.

## 3. The image: a relocated copy in `RUNTIME_SERVICES_CODE`

The exit stub, the handler and every static (`READY` and `PORT` in
`serial.rs`, `PHASE` in `output.rs`, `VMX_LAUNCH_RSP`, the handler's counters
and NMI state, the EPT handles, the exit history) are in the `.efi` image.
The firmware loads an application's image as `LOADER_CODE` and unloads it
when its entry point returns. Two ways to keep it:

**(a) Build Aleph0 as an EFI runtime driver** (PE subsystem 12). The firmware
loads it into runtime memory and keeps it loaded after its entry point
returns `EFI_SUCCESS`. But it also registers the image for relocation: in
`SetVirtualAddressMap`, EDK2's RuntimeDxe (`RuntimeDriverSetVirtualAddressMap`)
applies the image's base relocations again, in place, for the virtual
address the OS chose. Every absolute address in Aleph0 (the vtables
`core::fmt` uses, pointers in statics) would then point into the OS's
virtual address space, while Aleph0's host code keeps running on its own
identity map (HOST_CR3, #22): the next exit that formats a line would jump
through a vtable entry nothing maps. Hyper-V's firmware was not checked, but
it would have to differ from EDK2 for (a) to work.

**(b) Stay an application and copy the image** into `RUNTIME_SERVICES_CODE`
pages. The copy is not an image the firmware loaded, so
`SetVirtualAddressMap` knows nothing of it and leaves it alone. Chosen.

`main` does it first thing after serial output is up
(`resident::ResidentImage::copy`):

```text
firmware: LoadImage  ─▶ image at L (LOADER_CODE), its fixups applied for L
main (in the image):   serial::init, log
                       copy = AllocatePages(RUNTIME_SERVICES_CODE, SizeOfImage)
                       copy[..] = image[..]               statics included
                       pe::relocate(copy, delta = C - L)  every DIR64 fixup += delta
                       call the copy of `run`  ──────────┐
                                                         ▼
run (in the copy at C): bring-up, the launch, ...   every static now lives at C
                       return ───────────────────────────┐
main (in the image):   return status to the firmware ◀───┘  the firmware unloads L
```

Relocation (`resident::pe`, host-tested): the PE32+ headers give
`SizeOfImage` and the base relocation table (data directory 5). Each block
of the table covers one 4 KiB page; each 2-byte entry is a type and an
offset, and for type 10 (DIR64) the 8 bytes at that offset hold an absolute
address, to which the copy adds `delta`. Type 0 only pads a block; any other
type, a block that does not fit, or a fixup outside the image refuses the
copy, and `main` returns `ABORTED`. The debug image has 921 fixups and
nothing but DIR64 and padding.

Copying a running image is sound only because nothing has stored an address
inside the image yet: relocation moves only what the linker listed. At the
copy, the only statics written are the serial port and its readiness, the
output phase, and the `uefi` crate's image handle and system table pointer,
none of them an address in the image.

From the call on, everything runs from the copy: bring-up, the guest's
in-place launch, every exit. The firmware guest returns through the copy's
`run`, then through `main` in the original image, which the firmware unloads
once `StartImage` returns; nothing refers to it any more.

On Hyper-V the test guest ran its 24 exits from the copy and returned
`SUCCESS`; the firmware guest launched from it (section 7).

### `SetVirtualAddressMap`

Under (b) the call cannot touch Aleph0: the firmware relocates only the
images it loaded as runtime drivers, and converts only the pointers it
registered. Aleph0's code keeps running on its own page tables, which VM
exits load, and the OS's virtual addresses never reach it. The harness
(section 6) has a switch to make the call, as Linux does, before it checks
its exits.

Fallback for the first boot: Linux 6.18 does not call `SetVirtualAddressMap`
at all with `efi=noruntime`. That option clears `EFI_RUNTIME_SERVICES`
(`efi_init`), and `arch_cpu_finalize_init` enters virtual mode only when it
is set.

## 4. Learning that boot services ended

Aleph0 runs only at VM exits, so nothing tells it when the guest calls
`ExitBootServices`. Before the launch, bring-up creates an
`EVT_SIGNAL_EXIT_BOOT_SERVICES` event (`resident::watch_exit_boot_services`)
whose notify function is in the copy. The firmware calls it inside
`ExitBootServices`, in the guest, and it executes one VMCALL:

```text
guest (firmware)               Aleph0 (root operation)
ExitBootServices
  ─▶ on_exit_boot_services
       mov rax, "Aleph0EB"
       vmcall  ─────────────────▶ decide: VMCALL, firmware, RAX = BOOT_SERVICES_ENDED
                                   ─▶ ExitEvent::BootServicesEnded: resume past it
                                  resume_phase: Phase::Runtime from now on
       ret     ◀─────────────────
  ... rest of ExitBootServices
```

If the launch fails, bring-up closes the event again: outside VMX operation
the VMCALL would raise #UD inside `ExitBootServices`.

The other way would be to replace `gBS->ExitBootServices` with a wrapper
that makes the VMCALL after the real call returns. The event is the
documented mechanism and changes no firmware table, which the firmware may
checksum (the boot services table has a CRC32). Its only drawback: the
notify function runs before the firmware has finished `ExitBootServices`, so
a stop inside the rest of the call would already be reported in the runtime
phase.

### Aleph0's own VMCALLs

`vmx::vmcall` holds the values a guest puts in RCX to make a VMCALL a call
to Aleph0. Each is eight ASCII bytes read big-endian, so a register dump
shows text:

| Constant | RCX | `ExitEvent` | What Aleph0 does |
|---|---|---|---|
| `BOOT_SERVICES_ENDED` | `0x416c657068304542` "Aleph0EB" | `BootServicesEnded` | resumes past it, switches to the runtime phase |
| `TEST` | `0x416c657068305453` "Aleph0TS" | `TestVmcall` | resumes past it |

Hyper-V's hypercalls take their input value in RCX too, and both values
set bit 62, which is reserved there, so no hypercall Hyper-V takes is
mistaken for one of these; every other VMCALL from CPL 0 is a hypercall,
and Aleph0 forwards it to Hyper-V ([HYPERV_INTERFACE.md](HYPERV_INTERFACE.md)
section 2). Until #27 they were told apart by RAX, which a hypercall
ignores. Both are handled for the firmware (and the OS after it) only, and
from CPL 0 only: the test guest's VMCALLs are its script's. A guest may make either at any time; the worst a
fake `BOOT_SERVICES_ENDED` does is turn Aleph0's console output off early.

### The runtime phase

`Phase::Runtime` existed since section 0b of the roadmap; now the handler
sets it. It puts the phase it found back whenever it resumes the guest,
except after `BootServicesEnded`, which it resumes in `Runtime` for good
(`resume_phase`, host-tested). In that phase `log!` and the panic handler
skip the firmware console, which is gone, and write serial only. A stop
already halts for the firmware guest (`FIRMWARE_GUEST.md`, section 3), so it
does so after `ExitBootServices` too, with no jump into `vmx_launch`'s frame;
the OS-mode stop policy is #28.

Serial needs nothing else: its state (`READY`, `PORT`) is in the copy.

## 5. Not covered here

- Making the console unreachable from runtime code at compile time; the
  phase check skips it at run time.
- A control run with the resident types set back to `LOADER_*`, to show the
  harness catches the problem.
- Removing Aleph0's pages from the guest's EPT view, and several vCPUs:
  after the first boot.

## 6. The test harness

`tools/ebs-harness` is a small EFI application in the same Cargo workspace
(`cargo build -p ebs-harness`). It does what an OS loader and an early OS
do to memory, and checks that Aleph0 survives it:

1. Reads `\EFI\BOOT\aleph0.efi` from its own volume, loads and starts it.
   When `StartImage` returns, the harness runs as Aleph0's guest; it checks
   that CPUID hides VMX, so a test-guest build of Aleph0 is caught.
2. Calls `ExitBootServices` (the `uefi` crate retries once with a fresh map
   key), turns interrupts off (the firmware may turn them back on inside the
   call), and loads its own GDT, an empty IDT, an identity map of at least 4
   GiB in 2 MiB pages, and a 64 KiB stack, all statics in its image.
3. With `-SetVirtualAddressMap` (its `set-virtual-address-map` feature):
   calls `SetVirtualAddressMap` with each runtime region moved up by
   `0xFFFF_FF00_0000_0000`.
4. Overwrites with `0xCCCC_CCCC_CCCC_CCCC` every range of the final memory
   map that `is_reclaimable` names (Aleph0's own classification), except
   its own image (`regions::reclaimable_except`, host-tested).
5. Makes known exits: CPUID leaf 1, WRMSR and RDMSR of `IA32_KERNEL_GS_BASE`
   (intercepted), the `TEST` VMCALL; prints what they returned on COM1, and
   idles with HLT, each of which exits too.

Any exception in the harness hits its empty IDT and becomes a triple fault,
which Aleph0 stops on and reports with the harness's RIP. The harness shares
Aleph0's sources for the UART driver, the VMCALL values and the memory
classification (`#[path]` modules), so both agree on them.

```powershell
.\scripts\run-hyperv.ps1 -Harness -ProcessorCount 1
.\scripts\run-hyperv.ps1 -Harness -SetVirtualAddressMap -ProcessorCount 1
```

Aleph0's lines go to `run\serial.log` (COM2), the harness's to
`run\guest-serial.log` (COM1).

Until #27 the firmware stopped before `StartImage` returned, so the
harness never reached step 2 under Aleph0. `-WithoutAleph0` builds it with its
`without-aleph0` feature instead: no step 1, no VMCALL, and steps 2 to 4
(`ExitBootServices`, the switch to its own tables, `SetVirtualAddressMap`,
the overwrite) run on the firmware alone. Its COM1 then streams to the
console:

```powershell
.\scripts\run-hyperv.ps1 -Harness -WithoutAleph0 -ProcessorCount 1
.\scripts\run-hyperv.ps1 -Harness -WithoutAleph0 -SetVirtualAddressMap -ProcessorCount 1
```

A pass ends with `idling with HLT; done.` and the VM staying up. A fault
after `ExitBootServices` hits the empty IDT and resets the VM, which then
boots the harness again: its first line twice in the log.

## 7. Verified so far

On Hyper-V:

- `-TestGuest`: the image copied (`0x7eab2000 -> 0x7ea23000`, 585728 bytes,
  927 fixups), 27 resident allocations, all `RUNTIME_SERVICES_*` (325
  pages), then the same 24 exits and statistics as before, from guest code
  in `RUNTIME_SERVICES_CODE`, teardown, `Firmware timer fired` and
  `SUCCESS`, all from the copy.
- `-ProcessorCount 1`: the image copied (921 fixups), `Resident memory
  checked: 324 pages`, `ExitBootServices event created`, the launch, then
  the stop `FIRMWARE_GUEST.md` section 5 describes, unchanged: exits #1 to
  #6 CPUID, #7 `RDMSR 0x40000020`, which gets #GP, and the firmware's
  deliberate triple fault at #8.
- `-Harness -ProcessorCount 1`: the harness printed `starting Aleph0 from
  \EFI\BOOT\aleph0.efi`; Aleph0, loaded from there, copied itself, checked
  324 resident pages, created the event and launched, and stopped at the
  same `RDMSR 0x40000020`, still inside its own `main`, before `StartImage`
  returned to the harness.

So the harness could not reach `ExitBootServices` until #27 decided what
the guest sees of Hyper-V's synthetic MSRs and hypercalls; Hyper-V's VMBus
drivers also make hypercalls in their own `ExitBootServices` handlers. #27
forwards both now ([HYPERV_INTERFACE.md](HYPERV_INTERFACE.md)), and the
firmware runs on past `0x40000020`. What the harness run had to show: on COM2 the
`BootServicesEnded` exit and the switch to the runtime phase, then the
harness's CPUID, RDMSR, WRMSR and VMCALL exits, each resumed, and HLT exits
for 60 s without a stop; on COM1 how much memory was overwritten and the
results of the checks. The same with `-SetVirtualAddressMap`.

### The harness runs after #27

`-Harness -ProcessorCount 1`, the harness's COM1:

```text
[ebs-harness] starting Aleph0 from \EFI\BOOT\aleph0.efi.
[ebs-harness] Aleph0 returned SUCCESS; the harness runs as its guest (CPUID hides VMX).
[ebs-harness] own image 0x7eac5000..0x7eb41000; calling ExitBootServices.
[ebs-harness] boot services exited; loading the harness's own GDT, IDT, page tables (identity, 4 GiB) and stack.
[ebs-harness] running on the harness's own tables and stack.
[ebs-harness] overwrote 2045 MiB in 22 ranges with 0xcccccccccccccccc: every page the OS may reclaim but the harness's image.
[ebs-harness] CPUID.1: ecx=0xf7fa3203, VMX hidden: Aleph0 answered.
[ebs-harness] IA32_KERNEL_GS_BASE: wrote 0xffff8000eb5e0000, read back 0xffff8000eb5e0000: match.
[ebs-harness] test VMCALL (rcx=0x416c657068305453): resumed past it.
[ebs-harness] idling with HLT; Aleph0 resumes the guest after each one.
```

Aleph0's COM2 from the event's VMCALL on:

```text
VM exit #123091: VMCALL from Aleph0's ExitBootServices event (rcx=0x416c657068304542): boot services are over; output phase now runtime (serial only); going on at rip=0x000000007e935dfa.
VM exit #123092: hypercall 0x005c (rcx=0x5c) forwarded to Hyper-V -> status 0x0 (rax=0x0); resuming at rip=0x000000007f60b003.
VM exit #123099: WRMSR 0x400000b1 (synthetic) <- 0x0000000000000000 forwarded to Hyper-V; resuming at rip=0x000000007ff1da59.
   (#123100 to #123106: 0x400000b0 to 0x400000b7, the synthetic timers, set to 0)
VM exit #123107: WRMSR 0x40000090 (synthetic) <- 0x0000000000010000 forwarded to Hyper-V; resuming at rip=0x000000007ff1da59.
   (#123108 to #123113: 0x40000091 to 0x40000096, the next SINTs, masked; the rest past the print policy's 16 WRMSRs)
VM exit #123136: test VMCALL (rcx=0x416c657068305453); going on at rip=0x000000007eaca0d2.
VM exit #131748: reason=12 (HLT), 131072 exits of this reason so far.
...
VM exit #16777892: reason=12 (HLT), 16777216 exits of this reason so far.
```

Every line after #123091 was printed in the runtime phase, from the
resident copy, after the event fired, and from #123136 on after the
harness had overwritten every reclaimable page. Between the event and the
harness's exits, the firmware's own VMBus drivers tore down: an
`HvCallPostMessage` (`0x5c`), the synthetic timers zeroed and the SINTs
masked, all forwarded. The harness's CPUID, WRMSR and RDMSR exits fall
past the print policy's first 16 of their reasons, so COM2 shows only
their counts; the values on COM1 came from Aleph0 (VMX hidden, the MSR
read back through the intercepted IA32_KERNEL_GS_BASE). The VM ran 2
minutes with no stop.

`-Harness -SetVirtualAddressMap -ProcessorCount 1`: the same lines, with
`[ebs-harness] SetVirtualAddressMap: 5 runtime regions moved up by
0xffffff0000000000.` before the overwrite; on COM2 the ExitBootServices
exit at #96973, the test VMCALL at #97018, and 2 minutes with no stop
(16777216 HLT exits).

Not made: the optional control run with the resident types set back to
`LOADER_DATA`, which would show the harness catching the problem.

## Cheat sheet

| Name | Where | What |
|---|---|---|
| `RESIDENT_DATA`, `RESIDENT_CODE` | `vmx/page.rs` | `RUNTIME_SERVICES_DATA`, `RUNTIME_SERVICES_CODE` |
| `resident_allocations` | `vmx/page.rs` | every resident allocation, for the check |
| `is_reclaimable` | `resident/memory.rs` | whether the OS may reuse a memory type |
| `memory_type_at` | `resident/mod.rs` | the memory-map type of an address |
| `check_resident_memory` | `bring_up/mod.rs` | prints and checks each allocation's type |
| `ResidentImage::copy`, `call` | `resident/mod.rs` | copies and relocates the image, runs the copy |
| `Headers::parse`, `relocate` | `resident/pe.rs` | PE32+ headers, DIR64 fixups |
| `watch_exit_boot_services` | `resident/mod.rs` | the event whose VMCALL ends boot services |
| `BOOT_SERVICES_ENDED`, `TEST` | `vmx/vmcall.rs` | Aleph0's VMCALLs, by RCX |
| `resume_phase` | `vmexit/handler.rs` | `Runtime` after `BootServicesEnded` |
| `-Harness`, `-SetVirtualAddressMap` | `run-hyperv.ps1` | stage and run `tools/ebs-harness` |
