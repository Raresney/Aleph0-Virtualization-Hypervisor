# EPT: a second translation that Aleph0 controls

How Aleph0 turns on Extended Page Tables (EPT), and what that changes:
- why the guest needs a translation stage it cannot touch;
- the EPT entries and the EPT pointer;
- how Aleph0 checks support and builds an identity map of the whole
  guest-physical address space, with the memory types of the MTRRs for RAM
  and UC 1 GiB pages above it;
- the Local APIC, the device page the test guest reads through it;
- the guest's read-only data page and the EPT violation it causes on purpose;
- how Aleph0 handles that violation (grant write, INVEPT, retry), and how
  it stops on any other EPT exit with a walk of the GPA through the tables;
- what the Hyper-V runs printed;
- what the identity map does *not* hide, and what is not covered yet.

Code:
- `src/vmx/ept/mod.rs`: support check, entry encodings, the map's layout (`MapLayout`), identity map, `ProtectedPage::grant_write`, INVEPT;
- `src/vmx/ept/walk.rs`: what the CPU refuses in an entry (`check_entry`), and the walk of a GPA (`walk`);
- `src/vmx/apic.rs`: IA32_APIC_BASE, and the check that the test guest can read the Local APIC;
- `src/vmx/mtrr/mod.rs`: the memory type of each address, from the MTRRs (see [MTRR.md](MTRR.md));
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
| 7 | in a PDPT or PD entry: this entry maps a 1 GiB or 2 MiB page directly (no table below) |
| 51:12 | physical address of the next table, or of the page |

Some combinations are not just "forbidden" but invalid, for example W = 1
with R = 0. The CPU reports those as **exit reason 49, EPT
misconfiguration**. Aleph0 makes no such entry, so one stops the guest with
a walk of the GPA that names the bad entry (section 6).

The encodings Aleph0 uses (`ept/mod.rs`, all host-tested). `EptEntry<L>` is
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

It also reads two bits it does not require, into `EntryRules` with
MAXPHYADDR:

| Bit | Meaning | What it changes |
|---|---|---|
| 0 | execute-only pages | whether X = 1 with R = W = 0 is a misconfiguration (section 6) |
| 17 | 1 GiB pages | the map above RAM (section 4) |

Hyper-V (nested) reported:

```text
VMX secondary: required=0x00000000 allowed=0x065018ae; EPT/VPID capabilities=0x00000f0106f34041
EPT supported: 4-level walk, WB, 2 MiB pages, INVEPT single-context.
```

Decoded, `0x06f34041` (low half) has bits 0, 6, 14, 16, 17, 20, 21, 22, 23,
25 and 26 set. Beyond what Aleph0 requires, that means:
- execute-only pages (bit 0), which EPT split views need later;
- 1 GiB pages (bit 17), which the map above RAM uses;
- accessed/dirty flags (bit 21);
- advanced EPT-violation information (bit 22, see section 6).

The high half, `0x00000f01`, is about INVVPID, unused so far.

## 4. The identity map

Aleph0 builds an **identity map**: GPA = HPA everywhere. The guest then
runs exactly as before, because every address it used still reaches the
same memory. Only the permissions can now differ.

The map covers the whole guest-physical address space:
`[0, 2^min(MAXPHYADDR, 48))` (`address_space_end`). MAXPHYADDR is
CPUID.80000008H:EAX[7:0] (`cpuid::physical_address_bits`), and a 4-level
walk translates 48 bits whatever MAXPHYADDR says. Device memory can be
anywhere in that space: the Local APIC at `0xFEE00000`, the IOAPIC, PCI
BARs, the VMBus windows Hyper-V puts above RAM. A GPA without an entry
would stop the guest at its first access to it (section 6).

`MapLayout` lays the map out GiB by GiB:

```text
0 ── PDs (2 MiB and 4 KiB pages) ── pd_end ── 1 GiB pages, UC ── end
     the GiBs the UEFI memory map        no RAM above the memory map
     reaches: RAM, retyped when the
     guest writes its MTRRs
```

- The GiBs the UEFI memory map reaches keep a PD each, even a GiB of one
  type, so the guest's MTRR writes can retype its RAM 2 MiB or 4 KiB at a
  time (section 7, [MTRR.md](MTRR.md) section 7) without splitting a 1 GiB
  page.
- Above them there is no RAM, so every GiB is UC whatever the MTRRs say
  (`EptTypes`, [MTRR.md](MTRR.md) section 5), and is never retyped: one UC
  1 GiB page each, in a PDPT entry.
- One PDPT per 512 GiB, each in its own PML4 entry: 128 for a 46-bit space.
- Without 1 GiB pages (capability bit 17 clear), a PD per GiB of a 46-bit
  space would take 256 MiB of tables, so the PDs stop at
  `max(memory map end, 4 GiB)` instead. The 32-bit device window, with the
  Local APIC and the IOAPIC, is still mapped; an access above it stops the
  guest with the walk of section 6.

`Ept::build` (before VMXON, while boot services run):

1. Reads the UEFI memory map and takes the highest address any region
   reaches, rounded up to 1 GiB (`memory_map_end`). Every region counts,
   whatever its type. `MapLayout::new` refuses a memory map that reaches
   past the address space.
2. Gathers the memory map's RAM into sorted, merged ranges (`RamMap`):
   RAM takes the MTRRs' memory type, and everything else (MMIO, reserved
   memory, holes) is UC (`EptTypes`, [MTRR.md](MTRR.md) section 5).
   Counts the 2 MiB regions that need a PT (`split_regions`): those whose
   pages differ in memory type or are only partly RAM, and the one holding
   the guest's data page.
3. Allocates one PML4, the PDPTs, one PD per GiB below `pd_end`, and those
   PTs, plus spare PTs for regions the guest's MTRR writes split later
   (`spare_pts`), and a stack of the free PTs' indices.
4. Points PML4 entry *k* at PDPT *k*, and PDPT entry *g* at PD *g* below
   `pd_end`; above it, PDPT entry *g* is a UC 1 GiB page.
5. Fills every PD entry with a 2 MiB page, RWX, of the region's memory
   type, except for the regions counted in step 2. Their PD entry points to
   the next PT, which maps the region in 512 pages of 4 KiB, all RWX and
   each of its own memory type, **except the data page, which gets R only**.

2 MiB pages keep the tables small. Only the regions that need a 4 KiB
exception pay for a PT.

Aleph0's own page tables (HOST_CR3) map only up to the memory map's end
(`Ept::memory_map_end`, [HOST_ENVIRONMENT.md](HOST_ENVIRONMENT.md)): root
operation needs Aleph0's memory and the EPT tables, never device memory.

`Ept::build` also returns the `TypeTables` the exit handler keeps: the PDs,
the PTs with the spare ones, and the free stack. When the guest writes its
MTRRs, `TypeTables::apply` rewrites the entries whose memory type changed,
takes a spare PT for a region whose pages come to differ in type, gives the
PT of a region of one type again back, and runs INVEPT (section 7,
[MTRR.md](MTRR.md) section 7).

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

### The Local APIC

The Local APIC is the device every OS, and the firmware once it is the
guest (#21), touches first. In xAPIC mode its registers are a 4 KiB page of
MMIO at IA32_APIC_BASE (MSR `0x1B`), `0xFEE00000` unless the firmware moved
it: above RAM on the test VM, so in a UC 1 GiB page. `vmx/apic.rs` decodes
the MSR: the page's address (bits MAXPHYADDR-1:12), the BSP flag, and the
mode from bits 11:10, named as KVM's `enum lapic_mode` names them
(disabled, xAPIC, x2APIC, invalid).

Before VMXON, bring-up checks that the test guest can read the page
(`check_local_apic`). Only xAPIC mode (EN = 1, EXTD = 0) has one: in x2APIC
mode the registers are MSRs and the page decodes nothing, so in any other
mode bring-up prints that the guest skips its read, and the guest jumps
past it. In xAPIC mode bring-up stops with `LocalApic` unless:
- the page tables the guest shares with bring-up (the firmware's) map the
  page to itself, since the guest reads it through that linear address;
- the walk of the page through EPT (section 6) maps it to itself, UC and
  readable.

The test guest then reads it, after its MTRR writes and before its `hlt`:

```text
mov ecx, 0x1b                ; IA32_APIC_BASE, which the MSR bitmap passes through
rdmsr
mov ecx, eax
and ecx, 0xc00               ; EN and EXTD
cmp ecx, 0x800               ; xAPIC mode, or straight to the hlt
...
and rax, r10                 ; bits below MAXPHYADDR (R10, from the MTRR part)
and rax, -0x1000             ; the register page
mov eax, [rax + 0x30]        ; the version register: no exit
cmp al, 0x10 / cmp al, 0x15  ; an integrated APIC, or ud2 (0xFF: nothing answered)
hlt                          ; the HLT exit shows the register in RAX
```

The read adds no exit: with the page mapped RWX, it never leaves the
guest. A missing entry would be an EPT violation, and the walk would show
which level lacks it.

## 5. The guest's data page

The guest gets one more page: the **data page**, allocated together with
the code page as two contiguous `RUNTIME_SERVICES_CODE` pages (`LOADER_CODE`
until #23, [RESIDENT.md](RESIDENT.md) section 2). Contiguity lets the
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

`exit_decision::decide` (through `scenario::ept_violation`) accepts one EPT
violation per read-only page — the guest's data page, and the stack page the
reinjected NMI's delivery faults on as the CPU pushes the interrupt frame —
and only if all of these hold:
- the GPA's page is one of the protected pages (the data page or the stack
  page; the two are told apart by which page the GPA is in, not by the
  vectoring field, since a hypervisor underneath may report the interrupted
  NMI's type as 3, not 2);
- bits 1, 3, 7 and 8 are set and bit 4 is clear: a write to a readable,
  non-writable page, through the guest's own address;
- bit 12 is clear (after such an IRET, resuming would need NMI blocking set
  again by hand, which Aleph0 does not do);
- no write was granted yet for that page (a second violation on it would mean
  the grant did not work).

Any other EPT violation stops the guest as `EptViolation`, with a walk of
the GPA (below). And if main VMCALL #1 arrives **before** any violation, the
guest's write went through unnoticed: EPT did not protect the page, and the
guest stops with a message saying so (`EptWriteMissing`).

### Grant and retry

For the accepted violation, the handler:
1. sets W = 1 in the faulting protected page's PT entry (`ept::ProtectedPage::grant_write`);
2. runs INVEPT (section 7);
3. resumes **without advancing RIP**.

The guest then runs the same `mov dword ptr [rdi], 0x455054` again, and
this time the write is allowed.

Not advancing RIP is the only option anyway: for an EPT violation the CPU
does not report the instruction's length (`instruction length=0` in the
log), because the instruction did not complete. Skipping a write would
require decoding it.

### Any other EPT exit: the walk

The map allows every access to every GPA it covers, but one write. So any
other EPT violation, and every EPT misconfiguration (exit reason 49: an
entry the CPU refuses to use at all), means the map is wrong, not that an
access needs emulating. Each stops the guest as its own event,
`ExitEvent::EptViolation` or `ExitEvent::EptMisconfig`, and the report
prints the GPA's walk through the tables, the way KVM prints the hierarchy
of an EPT entry with reserved bits set (`get_mmio_spte`). Unlike KVM, which
misconfigures entries on purpose for MMIO and emulates those accesses in
`handle_ept_misconfig`, Aleph0 passes devices through, so it makes no
misconfigured entry.

`ept::walk` (`ept/walk.rs`) follows a GPA from the EPTP down, one entry
per level, as the CPU does, until an entry maps a page, is not present, or
is one the CPU refuses. It returns every entry it read, with what the CPU
refuses in it, and how the walk ended: mapped (with the HPA, page size,
access and memory type), not present, misconfigured, a pointer outside
the tables, or a GPA above the 48 bits a 4-level walk translates, which
it does not walk: its levels would index it like the GPA 2^48 below. It reads entries through a function its caller gives it.
`TypeTables::walk`, which the exit handler uses, gives it one that reads
only the table pages `Ept::build` allocated, so a corrupt pointer is
reported, never followed into memory that is not EPT. The walk starts from
the EPTP the VMCS holds.

`check_entry` names what the CPU refuses in an entry (Intel SDM Vol. 3C,
"EPT Misconfigurations"), as KVM's `is_rsvd_spte` does with the masks
`__reset_rsvds_bits_mask_ep` builds:

| Entry | Bits reserved (must be 0) |
|---|---|
| any | 51:MAXPHYADDR |
| PML4 | 7:3: no memory type, IPAT or page size |
| PDPT or PD pointing to a table | 6:3: no memory type or IPAT |
| PDPT mapping a 1 GiB page | 29:12, below the page's alignment; and 7 itself on a CPU without 1 GiB pages |
| PD mapping a 2 MiB page | 20:12 |
| PT | nothing more |

Besides reserved bits: bits 2:0 must not allow writes without reads (010b,
110b), nor execution alone (100b) on a CPU without execute-only pages; and
a page's memory type must not be 2, 3 or 7. An entry with bits 2:0 = 000b
is not present: a walk reaching it is an EPT violation, never a
misconfiguration.

The test-only `ept-misconfig-test` Cargo feature (`run-hyperv.ps1
-Features ept-misconfig-test`) plants one on purpose: before VMLAUNCH,
bring-up clears R in the PDPT entry of the Local APIC's GiB
(`TypeTables::misconfigure`), so the guest's read of the version register
is an EPT misconfiguration. On Hyper-V the CPU refused the same entry the
walk names:

```text
ept-misconfig-test: the PDPT entry of GiB 0x3 is now W without R.
...
VM exit #21: reason=49 (EPT misconfiguration)
VM exit #21: EPT misconfiguration at GPA 0x00000000fee00030: an EPT entry for it is invalid.
VM exit #21: guest rip=0x000000007eaa613f instruction length=2
VM exit #21: EPT walk of GPA 0x00000000fee00030 from EPTP 0x7eaa101e:
VM exit #21:   PML4 entry 0x0 at 0x7eaa1000 = 0x000000007ea21007: ok
VM exit #21:   PDPT entry 0x3 at 0x7ea21018 = 0x00000000c0000086: write without read
VM exit #21:   the CPU refuses the last entry: an EPT misconfiguration.
VM exit #21: stopping the guest; returning to bring-up.
...
Guest stopped at VM exit #21: reason=49 (EPT misconfiguration); Aleph0 did not resume the guest.
```

The walk ran in exit context, on Aleph0's own page tables, from the EPTP
the VMCS holds. The entry is the 1 GiB UC page at `0xc0000000`, RWX
(`0x87`) less R: `0x86`. The run then tears down as for any stop, and
returns `ABORTED`.

The host tests check each rule at each level, every entry `Ept::build`
makes, walks through hand-built tables and through the full Hyper-V map,
and the bounds-checked reader on real page-aligned tables, with a planted
pointer it must not follow.

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
EPT change, and changes not caused by a violation need it. The first such
change is a guest MTRR write: `TypeTables::apply` changes the memory types
of entries the CPU may have cached, then runs the same INVEPT.

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

### The whole address space (#20)

```text
EPT supported: 4-level walk, WB, 2 MiB pages, INVEPT single-context; 1 GiB pages=true; MAXPHYADDR 46 bits.
EPT built: identity 0x0..0x400000000000 (65536 GiB), 142 table pages: 128 PDPT(s); 2 PD(s), for 0x0..0x80000000, with 2 PTs for 2 MiB regions mapped in 4 KiB pages and 9 spare PTs for the guest's MTRR writes; 65534 GiB above as 1 GiB pages; data page 0x000000007eaa7000 read-only (R=1 W=0 X=0).
EPT 0x000000000000..0x000000200000: 4 KiB pages (a PT each)
EPT 0x000000200000..0x00007ea00000: 2 MiB pages, WB
EPT 0x00007ea00000..0x00007ec00000: 4 KiB pages (a PT each)
EPT 0x00007ec00000..0x000080000000: 2 MiB pages, WB
EPT 0x000080000000..0x400000000000: 1 GiB pages, UC
Local APIC: IA32_APIC_BASE=0xfee00900 (xAPIC, BSP); its registers at 0xfee00000 are mapped to HPA 0xfee00000 by a 1 GiB page, UC, R=1 W=1 X=1; the test guest reads the version register at 0xfee00030.
Host page tables: identity 0x0..0x80000000 (2 GiB), 1 GiB pages, 2 table pages; HOST_CR3=0x7ea10000 (firmware CR3=0x4401000).
...
VM exit #21: reason=12 (HLT)
VM exit #21: guest rax=0x0000000000050014 rbx=0x0000000000000000 rcx=0x0000000000000800 rdx=0x0000000000000000
```

- The 142 table pages are the PML4, 128 PDPTs, 2 PDs and 11 PTs: the
  first 2 MiB's, the data page region's and the 9 spare ones.
- Host CR3 still maps only the memory map's 2 GiB.
- RAX at the HLT is the version register: version `0x14` (bits 7:0), and
  bits 23:16 = 5, so 6 LVT entries. RCX is `0x800`, the xAPIC mode bits
  the guest checked. Nested Hyper-V let the guest read the VM's own Local
  APIC through Aleph0's EPT, and the read added no exit: the run ended
  after 24 exits with `SUCCESS`, and the `-InjectNmi` run after 26, the
  same as before #20.
- No EPT stop came. `-Features ept-misconfig-test` shows the
  misconfiguration stop and its walk on real VMX (section 6); an
  `EptViolation` stop prints the same walk after its own line, and is
  host-tested only.

## 9. Hiding Aleph0's own pages

Identity means the guest would see **all** physical memory up to the map's
end, including Aleph0's own pages: its code and statics in the `.efi` image
copy, the VM-exit stack, the VMXON region and VMCS, the host GDT and TSS,
**and the EPT tables themselves**. Left RWX, a guest with kernel rights
could scan memory and find Aleph0, rewrite the PT entry of a page to make
it writable without any exit, or change the exit handler's code or stack
and run its own code in VMX root operation at the next exit.

Issue #51 hides them. After every page Aleph0 keeps is allocated
(`finalize_memory`, just before VMLAUNCH, so no INVEPT is needed: the CPU
has not yet walked the tables), `TypeTables::hide` walks
`page::resident_allocations()` and redirects each page:

- a **data** page (EPT tables, VMCS, VMXON region, host GDT/TSS and page
  tables, VM-exit stack, exit bitmaps) → a shared zero **shadow** page,
  read-write. The guest reads zeros, and its writes land in the decoy,
  never in Aleph0's real page.
- a **code** page (the image copy) → its own address, read-only and
  executable. It cannot be rewritten, but the guest can still execute it,
  which the `ExitBootServices` event callback needs (it runs in the guest
  from the copy, [RESIDENT.md](RESIDENT.md)).

Aleph0's own accesses are untouched: the exit handler runs in root
operation on HOST_CR3, which EPT does not translate, so it still reads and
writes its real pages (its stack, its statics) at their real addresses. A
2 MiB region holding a hidden page is split into a PT (one of `HIDE_PTS`
set aside at build) and, because a redirected or read-only entry is not
full RWX, kept a PT by `retype` (`pt_pinned`): a later MTRR write cannot
fold it back into one RWX 2 MiB page and re-expose the page. Bring-up
refuses to launch (`NoHidePt`, `HiddenPageOutsideMap`) rather than leave a
page exposed. The built-in test guest, whose code, stack and data are
Aleph0's own resident pages, skips hiding; the firmware (and an OS) run
from their own, non-resident memory, so hiding never touches the guest.
One exception: the in-place firmware guest runs on Aleph0's *context* GDT
and TSS (GDTR `0x7ff80000`, TR base `0x7ff81000` on the test VM), and the
CPU reads them through EPT on every interrupt and segment load. They stay
visible (`ContextTables::guest_visible_tables`): with them redirected, the
first Hyper-V run triple-faulted at exit #1, when the firmware's timer
interrupt met a zeroed GDT. The guest may read or rewrite its own
descriptor tables, which gives it nothing it lacks; Aleph0 itself uses the
host GDT and TSS, which stay hidden.

On Hyper-V: `242 data page(s) redirected to the EPT shadow, 152 code
page(s) read-only, 2 region(s) split into a PT`; the firmware ran 2 minutes
(25 million exits) with no stop, and the `ExitBootServices` harness went
through the event's VMCALL (from the read-only copy), the forwarded VMBus
teardown, the overwrite of every reclaimable page and its test VMCALL.

EPT does not cover the GPAs Hyper-V reads or overlays for a forwarded
access (the hypercall input/output pages and the overlay MSRs); those are
guarded separately ([HYPERV_INTERFACE.md](HYPERV_INTERFACE.md) section 8).
What stays open: the image copy's code and statics are read-only but still
readable by the guest; execute-only EPT (capability bit 0) or a tiny
visible trampoline for the callback would let the code be hidden too (see
section 10, EPT split views).

## 10. What is not covered yet

- **EPT split views** (ROADMAP section 6): one GPA mapped to one host page
  for execution (execute-only, cap bit 0, which Hyper-V has) and to another
  for reads.
- **1 GiB pages for RAM**: the GiBs the memory map reaches keep their PDs,
  so MTRR writes retype them 2 MiB or 4 KiB at a time. A GiB of RAM of one
  type mapped as one 1 GiB page would have to be split, with spare PDs, when
  an MTRR write gives part of it another type.
- **The guest's MAXPHYADDR**: CPUID passes it through. On a CPU that reports
  more than 48 bits, the guest could use GPAs a 4-level walk does not
  translate; KVM caps the guest's physical-address width for that (#25).
- **VPID**: tags TLB entries per guest so VM entries and exits need not
  flush them. A performance feature, independent of EPT.
- **INVEPT before VMXOFF**: the EPT pages are never freed, so cached
  translations of them cannot point at reused memory.

## Cheat sheet

| Item | Value |
|---|---|
| Primary control bit 31 | activate secondary controls |
| Secondary control bit 1 | enable EPT |
| `SECONDARY_VM_EXEC_CONTROL` | `0x401E` |
| `EPT_POINTER` | `0x201A`; low bits `0x1E` = WB, 4 levels |
| `IA32_VMX_PROCBASED_CTLS2` | `0x48B` |
| `IA32_VMX_EPT_VPID_CAP` | `0x48C`; bits 6, 14, 16, 20, 25/26 required; 0 (execute-only) and 17 (1 GiB pages) read |
| EPT entry bits | 0 R, 1 W, 2 X, 5:3 type (from the MTRRs for RAM, UC for the rest; 0 = UC, 6 = WB), 6 IPAT, 7 1 GiB or 2 MiB page |
| The map | `[0, 2^min(MAXPHYADDR, 48))`: PDs up to the memory map's end, UC 1 GiB pages above |
| Exit reason 48 | EPT violation: `GUEST_PHYSICAL_ADDRESS` `0x2400`, `GUEST_LINEAR_ADDRESS` `0x640A`; any but the accepted one stops with the walk |
| Exit reason 49 | EPT misconfiguration: stops with the walk, which names the bad entry |
| IA32_APIC_BASE | `0x1B`; xAPIC registers at its bits MAXPHYADDR-1:12, the version register at `+0x30` |
| Qualification | 0 read, 1 write, 2 fetch, 3/4/5 R/W/X allowed, 7 linear valid, 8 translated access, 12 NMI-unblocking IRET |
| Accepted violation | write to a protected page (the data page or the NMI stack page), `0x58a` on Hyper-V |
| After it | W = 1, INVEPT, resume at the same RIP |
| `GUEST_DATA_SEED` / `GUEST_EPT_VALUE` | `0xDA7A` / `0x455054` ("EPT") |
| Hyper-V map (before the MTRR types) | `0x0..0x80000000`, 5 table pages, EPTP `0x7eafc01e` |
