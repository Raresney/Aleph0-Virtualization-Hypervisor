# EPT: a second translation that Aleph0 controls

How Aleph0 turns on Extended Page Tables (EPT), and what that changes:
- why the guest needs a translation stage it cannot touch;
- the EPT entries and the EPT pointer;
- how Aleph0 checks support and builds an identity map, with the memory
  types of the MTRRs;
- the guest's read-only data page and the EPT violation it causes on purpose;
- how Aleph0 handles that violation (grant write, INVEPT, retry);
- what the Hyper-V runs printed;
- what the identity map does *not* hide, and what is not covered yet.

Code:
- `src/vmx/ept.rs`: support check, entry encodings, identity map, `ProtectedPage::grant_write`, INVEPT;
- `src/vmx/mtrr.rs`: the memory type of each address, from the MTRRs (see [MTRR.md](MTRR.md));
- `src/vmx/guest.rs`: the data page and the guest code that writes it;
- `src/vmx/exit_decision/`: which EPT violation is accepted (`scenario.rs`, reached from `decide` in `mod.rs`);
- `src/vmx/vmexit/`: the handler that reports and applies it;
- `src/vmx/vmcs/mod.rs` and `fields.rs`: secondary controls, `EPT_POINTER`;
- `src/bring_up/mod.rs`: where EPT is checked, built and enabled.

## 1. Why EPT

Before this step the guest used the host's page tables (guest CR3 = host
CR3), and nothing came after them. A guest-physical address *was* a
host-physical address. Aleph0 could not protect or hide any memory from the
guest: whatever the page tables mapped, the guest could reach, and the
guest can edit its own page tables.

With EPT on, every guest memory access is translated twice:

```text
guest linear ──(guest page tables, guest CR3)──▶ guest-physical (GPA)
GPA          ──(EPT tables, built by Aleph0)───▶ host-physical  (HPA)
```

The guest owns the first stage and may change it as it likes. The second
stage lives in memory Aleph0 chooses, and the CPU walks it on **every**
guest access, including the CPU's own reads of the guest's page tables
(those tables sit at GPAs too). If an EPT entry does not allow the access,
the CPU does not perform it: it exits to Aleph0 with **exit reason 48, EPT
violation**.

This is the basis for everything later:
- an OS guest gets memory isolated from Aleph0;
- Aleph0 can hide its own pages from the guest;
- for anti-cheat (ROADMAP section 6), it can make a game's pages read-only
  or execute-only and see every write to them.

## 2. EPT entries and the EPT pointer

EPT tables have the same shape as ordinary 4-level page tables: PML4, PDPT,
PD, PT; one 4 KiB table holds 512 entries of 8 bytes, and each level takes
9 bits of the address (`docs/PAGE_TABLE_WALK.md` explains the walk). The
entry bits differ:

```text
 63    52 51               12 11   8  7   6  5   3  2  1  0
┌────────┬───────────────────┬──────┬───┬────┬─────┬──┬──┬──┐
│ ignored│ address of next   │ ign. │ PS│IPAT│ type│ X│ W│ R│
│        │ table or the page │      │   │    │(leaf)  │  │  │
└────────┴───────────────────┴──────┴───┴────┴─────┴──┴──┴──┘
```

| Bits | Meaning |
|---|---|
| 0, 1, 2 | **R, W, X**: read, write, execute allowed. No separate "present" bit: R = W = X = 0 means not present. |
| 5:3 | memory type, in leaf entries only: 0 = UC, 6 = write-back (WB), the type of ordinary RAM; Aleph0 copies it from the MTRRs ([MTRR.md](MTRR.md)) |
| 6 | IPAT: ignore the guest's PAT. Aleph0 leaves it 0. |
| 7 | in a PD entry: this entry maps a 2 MiB page directly (no PT below) |
| 51:12 | physical address of the next table, or of the page |

Some combinations are not just "forbidden" but invalid, for example W = 1
with R = 0. The CPU reports those as **exit reason 49, EPT
misconfiguration**, which Aleph0 never handles.

The encodings Aleph0 uses (`ept.rs`, all host-tested). `EptEntry<L>` is
generic over its table level (`Pml4`, `Pdpt`, `Pd`, `Pt` in `ept::level`),
so each constructor exists only where the entry is valid: calling
`large_page` on a PT entry, or `table` on one, does not compile.

| Function | Levels | Value | Example |
|---|---|---|---|
| `EptEntry::table(addr)` | PML4, PDPT, PD | `addr \| 0b111` | `0x7e00_1007` |
| `EptEntry::large_page(addr, type)` | PD | `addr \| RWX \| type << 3 \| 1 << 7` | `0x4020_00B7` (WB) |
| `EptEntry::page(addr, R, type)` | PT | `addr \| R \| type << 3` | `0x7eb1_d031` (read-only, WB) |
| `Eptp::new(pml4)` | — | `pml4 \| 6 \| 3 << 3` | low bits always `0x1E` |

The **EPT pointer** (EPTP, VMCS field `0x201A`) tells the CPU where the
PML4 is:

```text
EPTP = PML4 address | bit 6: accessed/dirty flags (0) | bits 5:3: walk length - 1 (3 = 4 levels) | bits 2:0: memory type of the tables (6 = WB)
```

EPT is switched on by **secondary control bit 1** ("enable EPT"). The
secondary controls are a fourth control field (`0x401E`), read by the CPU
only while **primary control bit 31** ("activate secondary controls") is
set. `configure_controls` sets both when `DesiredControls::secondary` asks
for anything.

## 3. Checking support

Two MSRs answer whether EPT is usable, and each exists only if the one
before says so (reading a missing MSR raises #GP):

```text
IA32_VMX_PROCBASED_CTLS (primary) allows bit 31
  └─▶ IA32_VMX_PROCBASED_CTLS2 (0x48B, secondary) allows bit 1 (EPT) or bit 5 (VPID)
        └─▶ IA32_VMX_EPT_VPID_CAP (0x48C)
```

`ept::check_support` requires these bits of `IA32_VMX_EPT_VPID_CAP`:

| Bit | Meaning | Why Aleph0 needs it |
|---|---|---|
| 6 | 4-level page walk | the EPTP Aleph0 writes |
| 14 | WB for the EPT tables | the EPTP's memory type |
| 16 | 2 MiB pages | the identity map uses them |
| 20 | INVEPT | `ProtectedPage::grant_write` |
| 25 or 26 | single- or all-context INVEPT | single-context is preferred |

Hyper-V (nested) reported:

```text
VMX secondary: required=0x00000000 allowed=0x065018ae; EPT/VPID capabilities=0x00000f0106f34041
EPT supported: 4-level walk, WB, 2 MiB pages, INVEPT single-context.
```

Decoded, `0x06f34041` (low half) has bits 0, 6, 14, 16, 17, 20, 21, 22, 23,
25 and 26 set. Beyond what Aleph0 requires, that means:
- execute-only pages (bit 0), which EPT split views need later;
- 1 GiB pages (bit 17);
- accessed/dirty flags (bit 21);
- advanced EPT-violation information (bit 22, see section 6).

The high half, `0x00000f01`, is about INVVPID, unused so far.

## 4. The identity map

Aleph0 builds an **identity map**: GPA = HPA everywhere. The guest then
runs exactly as before, because every address it used still reaches the
same memory. Only the permissions can now differ.

`Ept::build` (before VMXON, while boot services run):

1. Reads the UEFI memory map and takes the highest address any region
   reaches, rounded up to 1 GiB (`identity_map_end`). Every region counts,
   whatever its type. One PDPT reaches 512 GiB, so that is the limit.
2. Counts the 2 MiB regions that need a PT (`split_regions`): those whose
   pages differ in memory type ([MTRR.md](MTRR.md)), and the one holding
   the guest's data page.
3. Allocates one PML4, one PDPT, one PD per GiB, and those PTs.
4. Points PML4 entry 0 at the PDPT and PDPT entry *i* at PD *i*.
5. Fills every PD entry with a 2 MiB page, RWX, of the region's memory
   type, except for the regions counted in step 2. Their PD entry points to
   the next PT, which maps the region in 512 pages of 4 KiB, all RWX and
   each of its own memory type, **except the data page, which gets R only**.

2 MiB pages keep the tables small. Only the regions that need a 4 KiB
exception pay for a PT.

On Hyper-V (2 GiB of RAM), before the memory types came from the MTRRs
(every page was WB, and the data page's region had the only PT):

```text
EPT built: identity 0x0..0x80000000 (2 GiB) with 2 MiB pages, 5 table pages; data page 0x000000007eb01000 read-only (R=1 W=0 X=0).
VMCS EPT pointer 0x000000007eafc01e (WB, 4-level) written and read back.
```

The 5 pages are the PML4, the PDPT, 2 PDs and the PT. For the data page
`0x7eb01000`:

```text
PDPT index = bits 38:30 = 1       (second GiB)
PD index   = bits 29:21 = 0x1F5   (PD entry 1 * 512 + 0x1F5 = 0x3F5 across both PDs: the split)
PT index   = bits 20:12 = 0x101   (the read-only entry)
```

## 5. The guest's data page

The guest gets one more page: the **data page**, allocated together with
the code page as two contiguous `LOADER_CODE` pages. Contiguity lets the
copied guest code find it RIP-relative, without being told an address.
Aleph0 writes a seed, `0xDA7A`, at its start before launch.

New guest code, before main VMCALL #1 (offsets in the code page):

```text
+0   xor ebx, ebx
+2   lea rdi, [rip + guest_code_start]   ; start of the code page
+9   add rdi, 0x1000                     ; data page (its GPA, under identity)
+16  mov ecx, [rdi]                      ; read: R=1, allowed -> ecx = 0xda7a
+18  mov dword ptr [rdi], 0x455054       ; write: W=0 -> EPT violation
+24  mov edx, [rdi]                      ; read back -> edx = 0x455054 ("EPT")
+26  mov eax, 0xa1e0
+31  vmcall                              ; main VMCALL #1
     ... the NMI wait loop, VMCALL #2 and the NMI handler, unchanged ...
```

At main VMCALL #1 the registers prove each part: RCX shows the allowed
read went through EPT, RDX shows the retried write landed, and the EPT exit
before it shows the protection caught the write.

`check_mappings` also requires the data page to be **writable in the
guest's page tables**. Otherwise the write would fault in the first
translation stage (#PF, an exception exit) and never reach EPT, and the
test would prove nothing.

## 6. The EPT violation

When the guest writes the data page, the CPU stops before the write and
exits. Three VMCS fields describe the violation:

| Field | Encoding | Hyper-V value |
|---|---|---|
| `GUEST_PHYSICAL_ADDRESS` | `0x2400` | `0x7eb01000`: the data page |
| `GUEST_LINEAR_ADDRESS` | `0x640A` | `0x7eb01000`: the same, under identity |
| `EXIT_QUALIFICATION` | `0x6400` | `0x58a` |

The exit qualification, bit by bit:

```text
0x58a = 0101 1000 1010
bit 0  = 0  not a read
bit 1  = 1  a write
bit 2  = 0  not an instruction fetch
bit 3  = 1  the EPT entries allow reads    ─┐
bit 4  = 0  ... but not writes              ├─ R=1 W=0 X=0, as built
bit 5  = 0  ... nor execution              ─┘
bit 7  = 1  GUEST_LINEAR_ADDRESS is valid
bit 8  = 1  the access was to the address the guest used, not to its page tables
bit 9  = 0  a supervisor-mode address            ─┐ advanced information
bit 10 = 1  the guest's page tables allow writes  ├─ (cap bit 22)
bit 11 = 0  ... and execution                    ─┘
bit 12 = 0  not during an IRET that ended NMI blocking
```

Bit 10 confirms directly what `check_mappings` checked: as far as the
guest's own page tables go the page is writable, so EPT alone refused the
write.

`exit_decision::decide` (through `scenario::ept_violation`) accepts exactly
one EPT violation, and only if all
of these hold:
- the GPA's page is the protected page;
- bits 1, 3, 7 and 8 are set and bit 4 is clear: a write to a readable,
  non-writable page, through the guest's own address;
- bit 12 is clear (after such an IRET, resuming would need NMI blocking set
  again by hand, which Aleph0 does not do);
- no write was granted yet (a second violation would mean the grant did not
  work).

Anything else stops the guest as unexpected. And if main VMCALL #1 arrives
**before** any violation, the guest's write went through unnoticed: EPT did
not protect the page, and the guest stops with a message saying so
(`EptWriteMissing`).

### Grant and retry

For the accepted violation, the handler:
1. sets W = 1 in the data page's PT entry (`ept::ProtectedPage::grant_write`);
2. runs INVEPT (section 7);
3. resumes **without advancing RIP**.

The guest then runs the same `mov dword ptr [rdi], 0x455054` again, and
this time the write is allowed.

Not advancing RIP is the only option anyway: for an EPT violation the CPU
does not report the instruction's length (`instruction length=0` in the
log), because the instruction did not complete. Skipping a write would
require decoding it.

## 7. INVEPT

The CPU caches EPT translations (TLB, paging-structure caches), tagged by
EPTP. After changing an EPT entry, the cached copy may still be used.
**INVEPT** drops them:

```text
invept type, [descriptor]       descriptor = { EPTP, 0 }  (128 bits)
type 1 = single-context: only translations from this EPTP
type 2 = all-context:    translations from every EPTP
```

Like other VMX instructions it reports failure through CF/ZF;
`ProtectedPage::grant_write` returns the failure (`VmxFail`) and the guest stops if it fails.

Strictly, this INVEPT is not needed: an EPT violation already drops the
cached translations for the address that caused it, so the retried write
would see W = 1 anyway. It is still the architectural way to publish an
EPT change, and changes not caused by a violation (protecting a page while
the guest runs, for example) will need it.

## 8. The Hyper-V runs

> Since the emulated-exits step the guest first causes nine emulated exits
> (CPUID, four MSR, four I/O; see [EMULATED_EXITS.md](EMULATED_EXITS.md)), so
> in a current run these lines come with exit numbers nine higher. The guest
> RIPs and addresses differ too.

Plain run (`.\scripts\run-hyperv.ps1`), three exits:

```text
VM exit #1: reason=48 (EPT violation)
VM exit #1: qualification=0x000000000000058a
VM exit #1: EPT violation at GPA 0x000000007eb01000 (linear 0x000000007eb01000): write; page R=1 W=0 X=0.
VM exit #1: guest rip=0x000000007eb00012 instruction length=0
VM exit #1: guest rax=0x0000000000000000 rbx=0x0000000000000000 rcx=0x000000000000da7a rdx=0x0000000000000000
VM exit #1: write to the protected data page: write granted (W=1), INVEPT single-context; retrying the write at rip=0x000000007eb00012.
VM exit #2: reason=18 (VMCALL)
VM exit #2: guest rax=0x000000000000a1e0 rbx=0x0000000000000000 rcx=0x000000000000da7a rdx=0x0000000000455054
VM exit #3: expected VMCALL (rax=0xa1e1); all 2 planned VMCALLs handled; no NMI arrived.
VM exit #3: EPT: 1 write violation(s) on the protected data page, write granted.
```

- Exit #1, RIP `+0x12` (18): the write. RCX already holds `0xda7a`, so the
  read before it passed through EPT without an exit. RDX is still 0.
- The retry resumes at the same RIP.
- Exit #2, VMCALL #1 at `+0x1f` (31): RDX = `0x455054`, the retried write
  landed.
- Exit #3: VMCALL #2, the EPT summary, teardown, `SUCCESS`.

With `-InjectNmi`, five exits: the same EPT violation and VMCALL #1, then
the NMI flow from `docs/NMI.md`, unchanged under EPT:

```text
VM exit #3: reason=0 (exception or NMI)
VM exit #3: guest rip=0x000000007eb0002d ...
VM exit #3: NMI (interruption info=0x80000202); reinjecting it into the guest at rip=0x000000007eb0002d.
VM exit #4: guest NMI handler ran (rax=0x4e4d49); the reinjected NMI was delivered; resuming the guest at rip=0x000000007eb00041.
VM exit #5: expected VMCALL (rax=0xa1e1); all 2 planned VMCALLs handled; NMIs: 1 reinjected, 1 handled by the guest.
VM exit #5: EPT: 1 write violation(s) on the protected data page, write granted.
```

The NMI arrived at `+0x2d` (45, `dec ecx` in the wait loop, 24 bytes later
than before because of the new instructions). The CPU delivered it through
the guest IDT at `0x7eafe000` and ran the handler on the guest stack
`0x7eaff000`, both reached through EPT.

## 9. What the identity map does not hide

Identity means the guest sees **all** physical memory up to the map's end,
including Aleph0's own pages: its code and statics in the `.efi` image,
the VM-exit stack, the VMXON region and VMCS, the host GDT and TSS, **and
the EPT tables themselves**. In the run above the PML4 sits at
`0x7eafc000`, in the same 2 MiB region as the guest pages, mapped RWX by
the very PT Aleph0 built.

So a guest that wanted to could:
- scan memory and find Aleph0;
- rewrite the PT entry of the data page itself, making it writable without
  any exit;
- change the exit handler's code or stack, and run its own code in VMX root
  operation at the next exit.

The tiny guest here is Aleph0's own code, so this does not matter yet. For
an OS guest, and above all for anti-cheat, where the adversary has kernel
rights, Aleph0's pages must be removed from the guest's view (see
section 10).

## 10. What is not covered yet

- **Following the guest's MTRR changes.** The memory types are copied
  from the MTRRs once, at bring-up ([MTRR.md](MTRR.md), section 7).
- **Hiding Aleph0's own pages** (section 9). Each of them must become not
  present in EPT, with the access redirected or a #PF injected, or be
  mapped to a zero-filled shadow page. Aleph0 then has to track every page
  it allocates.
- **EPT split views** (ROADMAP section 6): one GPA mapped to one host page
  for execution (execute-only, cap bit 0, which Hyper-V has) and to another
  for reads.
- **More than 512 GiB**: a second PDPT, or 1 GiB pages.
- **VPID**: tags TLB entries per guest so VM entries and exits need not
  flush them. A performance feature, independent of EPT.
- **INVEPT before VMXOFF**: the EPT pages are never freed, so cached
  translations of them cannot point at reused memory.
- **Persistence after `ExitBootServices`**: the EPT tables are
  `LOADER_DATA`, which the OS may reclaim. They must live in memory the OS
  does not touch, and be hidden from it.

## Cheat sheet

| Item | Value |
|---|---|
| Primary control bit 31 | activate secondary controls |
| Secondary control bit 1 | enable EPT |
| `SECONDARY_VM_EXEC_CONTROL` | `0x401E` |
| `EPT_POINTER` | `0x201A`; low bits `0x1E` = WB, 4 levels |
| `IA32_VMX_PROCBASED_CTLS2` | `0x48B` |
| `IA32_VMX_EPT_VPID_CAP` | `0x48C`; bits 6, 14, 16, 20, 25/26 required |
| EPT entry bits | 0 R, 1 W, 2 X, 5:3 type (from the MTRRs; 0 = UC, 6 = WB), 6 IPAT, 7 2 MiB page |
| Exit reason 48 | EPT violation: `GUEST_PHYSICAL_ADDRESS` `0x2400`, `GUEST_LINEAR_ADDRESS` `0x640A` |
| Exit reason 49 | EPT misconfiguration: never handled |
| Qualification | 0 read, 1 write, 2 fetch, 3/4/5 R/W/X allowed, 7 linear valid, 8 translated access, 12 NMI-unblocking IRET |
| Accepted violation | write to the protected page, `0x58a` on Hyper-V |
| After it | W = 1, INVEPT, resume at the same RIP |
| `GUEST_DATA_SEED` / `GUEST_EPT_VALUE` | `0xDA7A` / `0x455054` ("EPT") |
| Hyper-V map (before the MTRR types) | `0x0..0x80000000`, 5 table pages, EPTP `0x7eafc01e` |
