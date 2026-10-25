# The host environment: what Aleph0 runs on in VMX root operation

Every VM exit switches the CPU to the *host state* in the VMCS: a CR3, a
GDT, a TSS, an IDT and the selectors that index them. This page explains
the host state Aleph0 builds for itself (`src/vmx/host/`), why it no longer
borrows the firmware's, and how NMIs and faults that arrive in root
operation are handled.

Code: `src/vmx/host/` (`mod.rs`, `page_tables.rs`, `gdt.rs`, `idt.rs`,
`handlers.rs`), the TSS in `src/vmx/context_tables.rs`, the NMI fold in
`src/vmx/exit_decision/mod.rs`, and teardown in `src/bring_up/teardown.rs`.
Issue #22.

## 1. Why not the firmware's

Until this step the VMCS host fields came from the running firmware:

| Field | Before | Problem |
|---|---|---|
| HOST_CR3 | the firmware's CR3 | its page tables are `BOOT_SERVICES_DATA`, which the OS may reuse after `ExitBootServices` |
| HOST_IDTR_BASE | the firmware's IDT | an NMI in root operation ran the firmware's NMI handler, which dead-loops; a fault ran a firmware handler from exit context |
| HOST_GDTR_BASE, HOST_TR_BASE | a copy of the firmware's GDT, with a TSS appended | no interrupt stacks, and the copy is shared with the guest |

Now every one of them comes from `HostEnvironment`, built during bring-up
and never freed:

| Field | Now |
|---|---|
| HOST_CR3 | Aleph0's identity map (section 2) |
| HOST_GDTR_BASE, host selectors | Aleph0's GDT (section 3) |
| HOST_TR_BASE, HOST_TR_SELECTOR | Aleph0's TSS with three interrupt stacks (section 4) |
| HOST_IDTR_BASE | Aleph0's IDT, 256 gates (section 5) |

Only VM exits load them. Bring-up and the test guest keep running on the
firmware's page tables and IDT and on the GDT copy (`context_tables.rs`), and
teardown switches back to the firmware's (section 7).

The pages still come from `page.rs` (`LOADER_DATA`). Moving them to memory
the OS keeps is the next step (#23).

## 2. The page tables

An identity map (linear = physical) of every address the UEFI memory map
reaches, rounded up to 1 GiB (`Ept::memory_map_end`). That range holds the
image with the exit handler, every allocation (the EPT tables included),
and the firmware stack that `vmx_return_to_launcher` returns to after a
stop. EPT maps more for the guest, the whole guest-physical address space
([EPT.md](EPT.md) section 4), but root operation never touches the device
memory above the memory map.

```text
with 1 GiB pages (CPUID.80000001H:EDX bit 26):
CR3 ─▶ PML4[0] ─▶ PDPT[0..gibs] = 1 GiB pages                     2 table pages

without:
CR3 ─▶ PML4[0] ─▶ PDPT[0..gibs] ─▶ PD[0..512] = 2 MiB pages        2 + gibs table pages
```

On the Hyper-V test VM the map is `0x0..0x80000000` (2 GiB): with 1 GiB
pages that is a PML4, a PDPT and two PDPT entries.

Every entry is:

| Bit | Value | Why |
|---|---|---|
| P (0), R/W (1) | 1 | present, writable |
| U/S (2) | 0 | supervisor only |
| PWT (3), PCD (4), PAT (12) | 0 | PAT entry 0, WB; the MTRRs still make device memory UC |
| A (5), D (6 in a leaf) | 1 | set in advance, so the CPU never writes the tables |
| PS (7) | 1 in a leaf | 1 GiB or 2 MiB page |
| XD (63) | 0 | the host does not switch IA32_EFER on VM exit, so the tables must work with EFER.NXE either way |

A table entry for the PDPT at `0x7f000000`, for example, is
`0x7f000023`; a 1 GiB page at 1 GiB is `0x400000e3`.

The entries are typed like EPT's (`HostEntry<L>` over the levels in
`ept::level`): a PDPT entry has `huge_page`, a PD entry `large_page`, and
only the levels above PT have `table`. Bring-up refuses CR4.LA57: HOST_CR4
is the running CR4, and these tables have 4 levels.

## 3. The GDT

A VM exit loads GDTR (with limit 0xFFFF) and the selectors from the VMCS,
and gives CS, SS and the data segments fixed flat attributes without
reading the GDT. The GDT still matters: IRETQ reloads CS and SS from it, as
does any interrupt return in firmware later.

The descriptors sit at the firmware's selector indices. On Hyper-V the
firmware runs with CS = `0x28` and SS = DS = ES = FS = GS = `0x08`:

```text
index  selector  descriptor
  0     0x00     null
  1     0x08     data: flat, read/write          0x00cf93000000ffff
  2-4            null
  5     0x28     code: flat, 64-bit, execute/read 0x00af9b000000ffff
  6-7   0x30     TSS (16 bytes)
```

Why the firmware's indices: after a stop, teardown loads the firmware's
GDTR, but CS keeps the selector the VM exit loaded until something reloads
it, which takes a far return. When both tables hold the code and data
descriptors at the same indices, a later interrupt return in firmware
reloads CS = `0x28` from the firmware's own GDT and finds its own code
descriptor. No segment register needs reloading.

`gdt::layout` refuses what would break that: a null CS, a selector with RPL
or TI set (VM entry requires both clear), or a data selector in CS's slot.

## 4. The TSS and the interrupt stacks

In long mode the TSS holds stack pointers only. Aleph0's has IST1-IST3,
each the top of its own 8 KiB stack:

| IST | Vector | Why its own stack |
|---|---|---|
| 1 | NMI (2) | can arrive at any instruction, including mid-push |
| 2 | #DF (8) | follows a fault while delivering a fault, for example a stack overflow |
| 3 | #MC (18) | can arrive at any time |

RSP0-2 stay 0 (the host never changes privilege level), and the I/O-map
base lies past the limit, so there is no I/O permission bitmap. VM exits
load TR with limit `0x67` and never mark the descriptor busy.

## 5. The IDT and the handlers

256 gates, one page. Every vector has a handler:

```text
vector 2 (NMI)     ─▶ host_nmi_entry ─▶ host_nmi_handler   (section 6), IRETQ
every other vector ─▶ stub n ─▶ host_exception_common ─▶ host_exception_handler: print, halt
```

The stubs are 16 bytes apart, from `host_vector_stubs`. Each pushes a 0
where the CPU pushes no error code, then its vector, so every frame looks
alike:

```text
rsp+0   vector          (stub)
rsp+8   error code / 0  (CPU / stub)
rsp+16  RIP, CS, RFLAGS, RSP, SS (CPU)
```

The CPU pushes an error code for vectors 8, 10-14, 17, 21, 29 and 30
(`idt::has_error_code`). A host test reads the assembled stubs and checks
every one against that list.

A fault in root operation is a bug in Aleph0, so the handler prints and
halts:

```text
HOST EXCEPTION in VMX root operation: vector 13 (#GP general protection).
HOST EXCEPTION: error code 0x0.
HOST EXCEPTION: rip=0x... cs=0x0028 rflags=0x... rsp=0x... ss=0x0008 cr2=0x....
HOST EXCEPTION: halting this CPU.
```

Maskable interrupts never arrive: a VM exit loads RFLAGS as `0x2` (IF = 0),
and nothing in root operation sets IF. Their gates exist so a stray `int n`
prints instead of hitting a missing gate.

## 6. NMIs in root operation

An NMI belongs to the guest wherever it lands: had the guest been running,
it would have caused an NMI exit. One that arrives while Aleph0 runs goes
through the host IDT instead.

```text
NMI in root ─▶ host_nmi_handler: NMI_PENDING = true; NMI-window exiting on; IRETQ
                     │
next exit's judge ───┴─▶ ExitState::with_host_nmi: nmi_pending = true
                         decide(...) as usual
                         ResumePlan::keeping_pending_nmi: NMI-window exiting stays on
NMI-window exit ──────▶ scenario::nmi_window injects it (0x80000202)
```

The handler cannot inject the NMI itself: whether VM_ENTRY_INTERRUPTION_INFO
is free depends on the exit being handled. So it marks the NMI pending, and
the guest gets it through the same NMI-window path as an NMI the guest
blocked.

**The late NMI.** Turning NMI-window exiting on in the handler covers an NMI
that arrives after the exit handler last looked at `NMI_PENDING` and before
VMRESUME. The exit handler orders its work so that no write can undo it:

1. The exit handler takes `NMI_PENDING` (`take_pending_nmi`) just before
   `judge` calls `decide`.
2. `prepare_resume` writes the VMCS, including the NMI-window bit
   (VMREAD, change, VMWRITE).
3. `keep_nmi_window_for_host_nmi` runs last: if `NMI_PENDING` is set again,
   it turns NMI-window exiting on.

An NMI between steps 1 and 3 may have its window bit overwritten by step 2,
but step 3 sees its flag and sets the bit again. An NMI after step 3 sets
the bit itself, and nothing writes the primary controls after that.

**NMI blocking after an NMI exit.** An NMI-caused VM exit blocks NMIs until
the next IRET or VM entry (Intel SDM Vol. 3C, "Architectural State Before a
VM Exit"). The exit handler never executes IRET, so the next VMRESUME
unblocks them. An NMI that arrives in between is held by the CPU and causes
an NMI exit right after the entry, so it is not lost. If the guest stops at
an NMI exit, NMIs stay blocked until firmware's next interrupt handler runs
IRET, as before.

NMIs that arrive after the guest stopped, before teardown loads the
firmware's IDT, set the flag and reach no guest.

## 7. Teardown

After a stop, bring-up keeps running on the host CR3, GDT and IDT the last
VM exit loaded, until teardown's first step loads the firmware's CR3, GDTR
and IDTR, in that order and before anything can call firmware. Both page
tables identity-map the running code and stack, so the CR3 switch moves
nothing. The line now reads:

```text
Teardown: CR4.VMXE=0 firmware CR3 restored=true firmware GDTR/IDTR restored=true IF=1.
```

TR keeps Aleph0's TSS selector, as before (see `teardown.rs`).

## 8. Testing it

Host tests (`tests/unit/vmx/host/`):
- the page tables, walked with `paging::walk`;
- the GDT layout and encoding;
- the gates and the IST assignment;
- the bytes of all 256 stubs;
- the NMI fold (`tests/unit/vmx/exit_decision.rs`).

On Hyper-V, bring-up prints the environment before VMXON:

```text
Host page tables: identity 0x0..0x80000000 (2 GiB), 1 GiB pages, 2 table pages; HOST_CR3=0x... (firmware CR3=0x4401000).
Host GDT at 0x... (limit 0x003f): code 0x0028, data 0x0008, TSS 0x0030 at 0x...; IDT at 0x... (256 gates).
Host interrupt stack: NMI IST1 top=0x....
Host interrupt stack: #DF IST2 top=0x....
Host interrupt stack: #MC IST3 top=0x....
```

Two test-only Cargo features, off by default, exercise the handlers
(`run-hyperv.ps1 -Features ...`):

| Run | What it shows |
|---|---|
| `-Features host-fault-test` | the exit handler reads a non-canonical address at exit #1; serial shows the `HOST EXCEPTION` lines for vector 13 and the VM stays halted |
| `-Features host-nmi-test -InjectNmi` | after main VMCALL #1 the exit handler waits in root operation; the job's NMI reaches the host NMI handler, then the guest through an NMI-window exit |

The expected lines of the second run:

```text
VM exit #12: expected VMCALL (rax=0xa1e0); resuming the guest at rip=...
VM exit #12: host-nmi-test: waiting in VMX root operation for an NMI.
VM exit #12: host-nmi-test: the host NMI handler ran (1 NMI(s) in root operation so far).
VM exit #12: an NMI arrived in root operation during this exit; NMI-window exiting on.
VM exit #13: reason=8 (NMI window)
...
VM exit #13: an NMI arrived while Aleph0 ran in root operation (1 so far); pending for the guest.
VM exit #13: NMI window open; reinjecting the pending NMI at rip=...
VM exit #14: guest NMI handler ran (rax=0x4e4d49); ...
VM exit #15: ... NMIs: 1 reinjected, 1 handled by the guest.
```

## 9. Not covered yet

- **The memory type of these pages**, and keeping the image with the
  handlers loaded after `ExitBootServices`: #23.
- **The guest's own tables** once the firmware runs as the guest: #21.
- **Hiding these pages from the guest** through EPT: after the first boot.
- **Per-CPU tables** for several vCPUs: after the first boot.
- **Host EFER**: the exit controls do not load it, so the bits of the
  guest's value other than LME and LMA (NXE, SCE) still apply to host
  accesses. IA32_PAT is switched when the CPU allows the controls for it
  (`vmcs::pat_switch`: VM exit saves the guest's and loads `HOST_IA32_PAT`,
  VM entry loads the guest's); on a CPU without them the guest's PAT still
  applies to host accesses too.

## Cheat sheet

| Item | Value |
|---|---|
| Host page-table entry bits | table `0x23` (P, R/W, A); leaf `0xE3` (+ D, PS) |
| 1 GiB pages | CPUID.80000001H:EDX bit 26 |
| Host GDT on Hyper-V | data `0x08`, code `0x28`, TSS `0x30`, limit `0x3f` |
| `CODE_64` / `DATA` | `0x00af9b000000ffff` / `0x00cf93000000ffff` |
| IST1 / IST2 / IST3 | NMI / #DF / #MC, 8 KiB each |
| Vectors with an error code | 8, 10-14, 17, 21, 29, 30 |
| Stub address | `host_vector_stubs + 16 * vector` |
| Host NMI | `NMI_PENDING`, NMI-window exiting on, folded by `ExitState::with_host_nmi` |
| Test features | `host-fault-test`, `host-nmi-test` |
