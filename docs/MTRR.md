# MTRRs: giving guest memory the right memory type under EPT

How Aleph0 gives every EPT entry the memory type the guest would get without
EPT:
- what a memory type is, and why device memory must not be write-back;
- the memory type range registers (MTRRs) and how the CPU combines them;
- why EPT makes Aleph0 responsible for memory types;
- how Aleph0 reads the MTRRs and copies their types into EPT;
- what bring-up prints;
- how the guest's writes to its MTRRs reach a copy instead of the CPU's,
  and how EPT follows them;
- what is not covered yet.

Code:
- `src/vmx/mtrr/mod.rs`: decoding the MTRRs, the type of an address
  (`Mtrrs::memory_type`) and of a block (`Mtrrs::block_type`);
- `src/vmx/mtrr/registers.rs`: the MTRR MSRs a CPU has
  (`MtrrCapabilities`), the values WRMSR refuses (`MtrrCapabilities::check`),
  reading them (`read`), and the guest's copy (`MtrrState`);
- `src/vmx/cpuid.rs`: `has_mtrr`, the CPUID check before any MTRR MSR is
  read, and `physical_address_bits` (MAXPHYADDR);
- `src/vmx/ept/mod.rs`: `large_page_type`, `split_regions` and
  `fill_identity_map`, which put the types into the identity map;
  `spare_pts`, `retype` and `TypeTables`, which change them when the guest
  writes its MTRRs;
- `src/vmx/exit_bitmaps.rs`: the MSR bitmap, which intercepts every MTRR
  MSR;
- `src/vmx/exit_decision/emulation.rs`: `rdmsr` and `wrmsr`, which route an
  MTRR MSR to the copy, or to a #GP;
- `src/vmx/vmexit/guest_mtrrs.rs`: the copy and the EPT tables in exit
  context; `report.rs` prints each MTRR access;
- `src/bring_up/mod.rs` and `report.rs`: where the MTRRs are read and printed,
  and checked again after the guest.

## 1. Memory types

Not everything at a physical address is RAM. Part of the physical address
space belongs to devices: the Local APIC's registers at `0xFEE00000`, the
IOAPIC, PCI BARs, a framebuffer. A **memory type** tells the CPU how to cache
accesses to an address:

| Type | Value | Caching | Typical use |
|---|---|---|---|
| UC, uncacheable | 0 | none; every access reaches memory or the device, in program order | device registers (MMIO) |
| WC, write-combining | 1 | reads not cached; writes gathered into bursts | framebuffers |
| WT, write-through | 4 | reads cached; writes go to memory at once | rare |
| WP, write-protected | 5 | reads cached; writes go to memory and do not update the cache | ROM shadows |
| WB, write-back | 6 | reads and writes cached | ordinary RAM |

Values 2, 3 and 7 and up are reserved.

RAM must be WB to be fast. Device registers must be UC to work at all: a
status register read from the cache returns an old value, and a write that
stays in the cache never reaches the device.

## 2. The MTRRs

Firmware describes physical memory with the **memory type range registers**,
MSRs that exist when CPUID.1:EDX bit 12 is set (Intel SDM Vol. 3A, "Memory
Type Range Registers"):

| MSR | Address | Contents |
|---|---|---|
| `IA32_MTRRCAP` | `0xFE` | bits 7:0 number of variable ranges; bit 8 fixed ranges exist |
| `IA32_MTRR_DEF_TYPE` | `0x2FF` | bits 7:0 default type; bit 10 (FE) fixed ranges on; bit 11 (E) MTRRs on |
| `IA32_MTRR_FIX64K_00000` | `0x250` | 8 ranges of 64 KiB: `0x00000..0x80000` |
| `IA32_MTRR_FIX16K_80000`, `_A0000` | `0x258`, `0x259` | 8 ranges of 16 KiB each: `0x80000..0xC0000` |
| `IA32_MTRR_FIX4K_C0000` .. `_F8000` | `0x268` .. `0x26F` | 8 ranges of 4 KiB each: `0xC0000..0x100000` |
| `IA32_MTRR_PHYSBASEn` | `0x200 + 2n` | bits 7:0 type; bits 51:12 base |
| `IA32_MTRR_PHYSMASKn` | `0x201 + 2n` | bit 11 valid; bits 51:12 mask |

The **fixed ranges** cover only the first MiB, the legacy PC layout: RAM up
to `0xA0000`, the VGA window, option ROMs and the BIOS. Each byte of a fixed
MSR is the type of one range.

A **variable range** covers the addresses whose masked bits equal its base's:

```text
address is in range n  ⇔  address & PHYSMASKn.mask == PHYSBASEn.base & PHYSMASKn.mask
```

A contiguous mask makes a naturally aligned power-of-two range. With 39
physical-address bits, 2 GiB at 0 is:

```text
PHYSBASE = 0x0000_0000_0000_0006   base 0, type 6 (WB)
PHYSMASK = 0x0000_007F_8000_0800   mask bits 38:31 set; bit 11 = valid
```

Every address below 2 GiB has bits 38:31 clear, like the base, so it is in
the range.

## 3. Which type an address gets

For one address, in this order (SDM, "MTRR Precedences"):

1. MTRRs disabled (E = 0): **UC**, whatever else the MSRs hold.
2. Below 1 MiB, with the fixed ranges on (FE = 1): the **fixed range's** type.
3. Covered by one variable range: **its type**. Covered by several:
   - all the same type: that type;
   - any of them UC: **UC**;
   - only WT and WB: **WT**;
   - anything else is undefined. Aleph0 uses **UC**, the one choice that
     cannot hand a device stale data.
4. Covered by none: the **default type**.

A typical layout on a PC: default type UC, one variable range making RAM WB,
and the device window just below 4 GiB left UC by the default. Or the
reverse: default WB, and a variable range making the device window UC.

Without EPT, the type the MTRRs give is then combined with the type the page
tables select through the PAT (for example, PAT UC wins over MTRR WB).

## 4. Why EPT makes this Aleph0's job

With EPT on, the MTRRs **no longer apply** to guest accesses (SDM Vol. 3C,
"Memory Type Used for Translated Guest-Physical Addresses"). The type comes
from the EPT leaf entry instead, bits 5:3, combined with the guest's PAT as
long as IPAT (bit 6) is clear. Aleph0 leaves IPAT clear.

So the EPT entry plays exactly the role the MTRRs played. If Aleph0 copies
the MTRRs' type into each entry, the guest gets the same types it would get
on bare metal. Before this change every entry was WB, which was right for the
RAM the test guest uses but wrong for any device memory an OS guest touches.

## 5. How Aleph0 does it

Bring-up, before `Ept::build`:

1. `mtrr::read` checks CPUID first: reading an MTRR MSR on a CPU without
   them raises #GP. Without MTRRs every address is treated as WB, which is
   what such a CPU does (only the PAT then sets types), and what Aleph0 did
   before.
2. It reads `IA32_MTRRCAP`, `IA32_MTRR_DEF_TYPE`, the fixed MSRs if
   `IA32_MTRRCAP` says they exist, and the PHYSBASE/PHYSMASK pair of every
   variable range it counts. Each value must be one WRMSR would accept
   (section 7.3). No CPU can hold another, so one would come from a broken
   VMM below Aleph0, and bring-up stops with the MSR that holds it.
3. `Mtrrs::decode` checks every type the CPU actually uses. A reserved type
   would make an EPT entry an EPT misconfiguration (exit reason 49), so it
   stops bring-up with the MSR that holds it.

`Ept::build` then maps memory as before, 2 MiB at a time, but asks
`EptTypes::region_type` for each 2 MiB region first. For RAM that is
`Mtrrs::block_type`; memory that is not RAM is UC whatever the MTRRs say
(below):

- **One type for the whole region:** a 2 MiB page of that type.
- **Pages of different types, or RAM and memory that is not:** a PT, and
  512 pages of 4 KiB, each with its own type. An EPT entry has one type, so
  a 2 MiB page would give part of the region the wrong one.

The region holding the guest's data page still gets a PT too, for the
read-only page. If that region is mixed already, it shares the PT.

`split_regions` counts the PTs first, so they are allocated in one go, and
`fill_identity_map` uses them in address order. More PTs are allocated
after them and left unused, for the regions the guest's MTRR writes split
later (section 7.5).

### Finding mixed regions cheaply

Looking up 512 pages for every 2 MiB region would be slow for large
machines. `block_type` only does that when it has to: the pages of a 2 MiB
block differ in address bits 20:12 only. A variable range whose mask tests
none of those bits covers the whole block or none of it. Only a range that
tests some of them, and whose upper bits match the block, can cover part of
it (`VariableRange::may_split`). The other case is the first 2 MiB, where
the fixed ranges apply below 1 MiB. Everywhere else, one lookup gives the
whole region's type.

### Memory that is not RAM

Copying the MTRRs' type is right for RAM. For device memory it trusts that
the MTRRs make it UC, and two things break that:

- **A VMM below Aleph0 may not bother.** Hyper-V's MTRRs (section 6) make
  all of the first 4 GiB WB, the device window below 4 GiB with the Local
  APIC and IOAPIC included. Hyper-V's own EPT makes its devices UC; Aleph0's
  EPT took WB from the MTRRs.
- **The guest owns its MTRRs** (section 7), and can make any range WB.

WB on a device's registers lets the CPU read them speculatively and keep
them in its caches, which the device does not expect: a read can have side
effects, a cached value goes stale, and some platforms answer with a
machine check, which takes down the whole machine, Aleph0 included.

So `ept::EptTypes` gives each page the MTRRs' type only if the UEFI memory
map calls it RAM (`ept::is_ram`: loader, boot and runtime services code and
data, conventional, ACPI reclaim and NVS, persistent memory), and UC
otherwise: MMIO, reserved and unusable memory, types it does not know, and
the holes the map describes nothing at. `Ept::build` gathers that RAM into
sorted, merged ranges (`RamMap`), kept with the tables, since `retype` needs
them in exit context, where UEFI cannot be asked.

- A 2 MiB region all of RAM is typed by the MTRRs, as above.
- A region with no RAM is one UC 2 MiB page, whatever the guest writes.
- A region only partly RAM always gets a PT, even when its pages happen to
  share a type: the guest's MTRRs could make its RAM WB at any time, and
  that PT must not have to come from the spare ones (section 7.5), which
  only cover what MTRR writes split.

UC from EPT does not take WC away from a framebuffer: with IPAT clear the
guest's PAT still combines with it, and UC from EPT with WC from the PAT is
WC (SDM Vol. 3A, "Selecting Memory Types for Pentium III and More Recent
Processor Families"). KVM does the same: `vmx_get_mt_mask` gives MMIO UC.

This also settles the types of the ranges #20 maps above the memory map's
end: none of them is RAM, so they are UC 1 GiB pages ([EPT.md](EPT.md)
section 4), not the WB Hyper-V's MTRRs give `0x80000000..0x100000000`.

## 6. What bring-up prints

After the VMX capabilities, for example:

```text
MTRRs: enabled, default type UC; fixed ranges enabled; 8 variable ranges, 1 in use.
MTRR variable range 0: base=0x000000000000 mask=0x007f80000000 WB
MTRR fixed 0x00000..0xa0000: WB
MTRR fixed 0xa0000..0xc0000: UC
MTRR fixed 0xc0000..0x100000: WP
EPT built: identity 0x0..0x100000000 (4 GiB), 17 table pages, 2 of them PTs for 2 MiB regions mapped in 4 KiB pages and 9 spare PTs for the guest's MTRR writes; data page 0x000000007eb01000 read-only (R=1 W=0 X=0).
EPT memory types: the MTRRs' for the 2 RAM range(s) of the UEFI memory map, UC for everything else (MMIO, reserved memory, holes).
EPT RAM 0x000000000000..0x0000000a0000
EPT RAM 0x000000100000..0x000080000000
EPT 0x000000000000..0x000000200000: 4 KiB pages (a PT each)
EPT 0x000000200000..0x00007ea00000: 2 MiB pages, WB
EPT 0x00007ea00000..0x00007ec00000: 4 KiB pages (a PT each)
EPT 0x00007ec00000..0x000080000000: 2 MiB pages, WB
EPT 0x000080000000..0x000100000000: 2 MiB pages, UC
```

The lines above show the format on an example layout; the Hyper-V run
follows. It predates the spare PTs of section 7, so its `EPT built` line
has no spare PTs and nine table pages fewer than a run now prints, and the
RAM lines of section 5 ("Memory that is not RAM"). The fixed-range lines show the first MiB in runs of one type. The `EPT`
lines are read back from the PD entries `Ept::build` filled, the ones the
CPU walks, rather than worked out again from the MTRRs: runs of 2 MiB pages
with the type in their entries, and runs of regions mapped through a PT. Here
the first 2 MiB has a PT because the fixed ranges give it three types (and
because `0xa0000..0x100000` is not RAM), and `0x7ea00000` is the data page's
region. From `0x80000000` on nothing is RAM, so it is UC whatever the MTRRs
say.

### On Hyper-V

The plain run (`.\scripts\run-hyperv.ps1`, two vCPUs) printed:

```text
MTRRs: enabled, default type UC; fixed ranges enabled; 8 variable ranges, 1 in use.
MTRR variable range 0: base=0x000000000000 mask=0x3fff00000000 WB
MTRR fixed 0x00000..0xa0000: WB
MTRR fixed 0xa0000..0x100000: UC
EPT built: identity 0x0..0x80000000 (2 GiB), 6 table pages, 2 of them PTs for 2 MiB regions mapped in 4 KiB pages; data page 0x000000007eae2000 read-only (R=1 W=0 X=0).
EPT 0x000000000000..0x000000200000: 4 KiB pages (a PT each)
EPT 0x000000200000..0x00007ea00000: 2 MiB pages, WB
EPT 0x00007ea00000..0x00007ec00000: 4 KiB pages (a PT each)
EPT 0x00007ec00000..0x000080000000: 2 MiB pages, WB
VMCS EPT pointer 0x000000007eada01e (WB, 4-level) written and read back.
```

The `-InjectNmi` run (one vCPU) printed the same lines. Aleph0 reads the
MTRRs on the bootstrap processor only, and the firmware programmed them the
same way for both VM shapes.

- **Variable range 0** has mask `0x3fff00000000`: address bits 45:32 must
  equal its base, 0, and bits 31:12 are free. So it covers
  `0x0..0x100000000`, the first 4 GiB, as WB. The mask stops at bit 45, so
  the VM's MAXPHYADDR is 46 bits.
- **The fixed ranges** make `0x0..0xa0000` WB and `0xa0000..0x100000` (the
  legacy VGA and ROM hole) UC. The first 2 MiB region therefore mixes WB and
  UC pages and is mapped through a PT. Before the MTRR types, the same map
  took 5 table pages; this one is 6: PML4, PDPT, two PDs, and two PTs (this
  region, and the data page's at `0x7ea00000`).
- **Everything else up to the end of the memory map** (`0x80000000`) is one
  type, WB, in 2 MiB pages.
- **The guest ran as before:** the EPT violation was exit #11 (qualification
  `0x58a`), and VMCALL #1 (exit #12) read back `rcx=0xda7a` and
  `rdx=0x455054` through the data page's PT, whose 4 KiB entries each carry
  their page's type. No EPT misconfiguration exit: no entry holds a reserved
  type. The run ended after 13 exits with `SUCCESS`, the `-InjectNmi` run
  after 15 with `NMIs: 1 reinjected, 1 handled by the guest`.

**Beyond the memory map** (for #20, which maps it): the MTRRs make
`0x80000000..0x100000000` WB, as part of variable range 0, and everything
above 4 GiB UC, the default type. That WB range includes the Local APIC at
`0xFEE00000` and the IOAPIC at `0xFEC00000`. On real hardware the firmware
usually marks the hole below 4 GiB UC with a variable range; Hyper-V's does
not. Copying the MTRR types would map those devices WB. Hyper-V emulates them,
so their accesses are trapped whatever the type, but EPT decides on purpose
rather than inherit WB: the range is not RAM, so it is UC (section 5), and
since #20 the map covers it, as UC 1 GiB pages ([EPT.md](EPT.md)
section 4).

## 7. Guest writes to the MTRRs

### 7.1 Why the guest must not write the CPU's

If the MSR bitmap does not intercept the MTRR MSRs, a guest's WRMSR to one
of them reaches the CPU. That causes two problems:

- **The EPT types go stale.** `Ept::build` copies the MTRRs' types into the
  EPT entries at bring-up. With EPT on, guest accesses use those entries,
  not the MTRRs (section 4), so a guest that reprograms its MTRRs would see
  no effect. Linux, for example, writes them on every CPU it brings up.
- **The guest changes Aleph0's own memory types.** Root operation has no
  EPT, so the CPU's MTRRs still set the memory types of the hypervisor's own
  accesses. A guest could make Aleph0's code, data or stacks UC or WP. That
  is an isolation problem, not only a correctness one.

### 7.2 A copy for the guest

Aleph0 now keeps a copy of the MTRRs for the guest, and never writes the
CPU's. KVM does the same per vCPU (`vcpu->arch.mtrr_state`).

- The MSR bitmap intercepts RDMSR and WRMSR of every address an MTRR MSR
  can have (`mtrr::every_msr_address`): `IA32_MTRR_DEF_TYPE`, the 11
  fixed-range MSRs, and the PHYSBASE/PHYSMASK pairs of the 32 variable
  ranges Aleph0 can keep (`0x200..0x240`), 76 addresses. The copy holds
  those the CPU has (`MtrrCapabilities::msrs`): `IA32_MTRR_DEF_TYPE`, the
  fixed-range MSRs if `IA32_MTRRCAP` says they exist, and one pair per
  variable range it counts, 28 MSRs under Hyper-V. The guest gets #GP for
  the others, as a CPU without them gives. Intercepting only the MSRs the
  CPU has would pass the others through to the CPU: safe only as long as
  `IA32_MTRRCAP` counts every MTRR the CPU (or the VMM below Aleph0)
  implements, which nothing checks. `IA32_MTRRCAP` itself is read-only and
  stays the guest's: RDMSR of it does not exit to Aleph0, and WRMSR faults
  as on bare metal.
- The copy starts as the CPU's MTRRs, read at bring-up, and lives in exit
  context (`vmexit/guest_mtrrs.rs`), like the vCPU's statistics.
- **RDMSR** reads the copy, so the guest reads back what it wrote.
- **WRMSR** writes the copy, never the CPU's. Emulating it with a real
  WRMSR in root operation, as Aleph0 does for the MSRs it passes through
  ([EMULATED_EXITS.md](EMULATED_EXITS.md) section 4), is exactly what must
  not happen here, so the MTRR MSRs have their own route in
  `exit_decision::emulation`:

| MSR | Route | Event |
|---|---|---|
| in `INTERCEPTED_MSRS` | the real RDMSR/WRMSR | `Emulated(Rdmsr)`, `Emulated(Wrmsr)` |
| an MTRR MSR the CPU has, RDMSR | the copy | `Emulated(MtrrRead)` |
| an MTRR MSR the CPU has, WRMSR of a value the CPU takes | the copy, then EPT | `Emulated(MtrrWrite)` |
| an MTRR MSR the CPU has, WRMSR of a value the CPU refuses | #GP(0), copy unchanged | `GuestGeneralProtection` |
| an MTRR address the CPU has no MSR at, RDMSR or WRMSR | #GP(0) | `GuestGeneralProtection` |

### 7.3 What WRMSR refuses

Before anything changes, `wrmsr` checks the value on its own, as the CPU
does (`MtrrCapabilities::check`, the same rules as KVM's
`kvm_mtrr_valid`). The CPU refuses with #GP a reserved memory type in any
type field, or a reserved bit set:

| MSR | Bits that may be set |
|---|---|
| `IA32_MTRR_DEF_TYPE` | 7:0 default type, 10 FE, 11 E |
| fixed-range MSRs | all 64: eight type bytes |
| `IA32_MTRR_PHYSBASEn` | 7:0 type, MAXPHYADDR-1:12 base |
| `IA32_MTRR_PHYSMASKn` | 11 valid, MAXPHYADDR-1:12 mask |

MAXPHYADDR comes from CPUID.80000008H:EAX bits 7:0
(`cpuid::physical_address_bits`); it is 46 under Hyper-V. A refused value
gets the guest a #GP and leaves the copy as it was: the #GP is all that
happens, as on bare metal.

This check cannot be `Mtrrs::decode`. `decode` only checks the types of the
MTRRs in use (nothing while E is clear, the fixed ranges only with FE set,
a variable range only with its valid bit set), and never reserved bits. An
OS updates its MTRRs by clearing E, writing the ranges, then setting E
again. With `decode` alone, a bad PHYSBASE written while E is clear would be
accepted, and the #GP would come only at the later write that sets E. The
CPU refuses it at its own WRMSR, and so does Aleph0.

### 7.4 Following the copy in EPT

A value the CPU takes goes into the copy (`MtrrState::write`), which then
decodes it with `Mtrrs::decode`. If no address changes type, which is the
case for every write while E is clear, EPT is left alone. During the OS
sequence above, only the write that clears E and the one that sets it again
change types.

Otherwise `ept::retype` gives each 2 MiB region of the identity map the
types the copy now gives, and changes only the entries that differ:

| The region's pages now | It was | It becomes |
|---|---|---|
| one type | a 2 MiB page | the same page with new type bits; nothing else in the PD entry changes |
| one type | mapped through a PT | a 2 MiB page; the PT goes back to the spare ones |
| of different types | mapped through a PT | the same PT, each entry with its page's type |
| of different types | a 2 MiB page | a spare PT, filled before the PD entry points at it |

The last row runs in a second pass, over just the regions the first pass
found needing a PT, so the PTs the first pass gave back are spare again by
then. In a single pass in address order, a region could find no PT left
when the one it needs is given back only by a region above it, as when the
guest moves a small range down. Since `retype` runs again only when a type
changes, that region could stay UC (section 7.5) for good.

The protected data page's region keeps its PT whatever the types, and
retyping a PT entry keeps its access bits, so that page stays read-only, or
writable once its write was granted. Then INVEPT drops the translations the
CPU cached with the old types. `retype` works on slices, so all of this is
host-tested on vectors; `TypeTables::apply` runs it on the real tables and
adds the INVEPT.

Clearing E makes all memory UC, as on bare metal: every region becomes one
UC page, and every PT but the protected region's goes back to the spare
ones. Setting E again rebuilds the map bring-up built.

### 7.5 Spare PTs

The exit handler cannot allocate (CONTRIBUTING, "Exit context"), so
`Ept::build` allocates the PTs a split can need up front: one per variable
range, plus one for the first 2 MiB, which the fixed ranges can split
(`ept::spare_pts`). That is 9 under Hyper-V. A small stack of free PT
indices, allocated with them, hands them out and takes them back.

That is enough for every layout of contiguous masks, the ones the SDM
describes. A variable range of 2 MiB or more is aligned to its size, so it
covers whole regions. A smaller one lies inside one region. At most one
region per variable range, plus the first, has pages of different types,
and a region that becomes one type again gives its PT back.

Only a non-contiguous mask, one that tests an address bit below 21 and
leaves a higher one free, can split more regions than that. If a region
needs a PT when none is left, it stays one 2 MiB page and becomes UC: the
one type that cannot hand a device stale data, as for an undefined overlap
(section 3). Only the speed of its RAM suffers, and it gets a PT at a later
MTRR write that gives one back. The report says how many regions are left
so.

### 7.6 What serial shows

Bring-up adds a line for the intercepted MSRs, the spare PTs to the
`EPT built` line, and the RAM that takes the MTRRs' types (section 5,
"Memory that is not RAM"). The number of PTs below is what the MTRRs alone
need; regions only partly RAM add one each, so the Hyper-V run will show
how many its memory map has:

```text
EPT built: identity 0x0..0x80000000 (2 GiB), 15 table pages, 2 of them PTs for 2 MiB regions mapped in 4 KiB pages and 9 spare PTs for the guest's MTRR writes; data page ... read-only (R=1 W=0 X=0).
EPT memory types: the MTRRs' for the N RAM range(s) of the UEFI memory map, UC for everything else (MMIO, reserved memory, holes).
EPT RAM <start>..<end>          (one line per range)
Intercepted MTRR addresses (read and write): all 76. The guest reads and writes a copy of the 28 MSRs the CPU has (IA32_MTRR_DEF_TYPE, 11 fixed-range MSRs and 8 variable ranges); the other 48 get #GP.
```

The test guest moves its last variable range, range 7, to the 2 MiB at
`GUEST_MTRR_BASE` (`0x200000`) and back (`src/vmx/guest.rs`): it turns the
range off, gives it that base and type UC, turns it on for 2 MiB, reads
the mask back, narrows it to 4 KiB, then turns it off and restores the
pair. On the Hyper-V layout of section 6, where range 7 is unused, the
write that turns it on for 2 MiB was exit #15 and printed these lines, the
values the host tests compute for that layout:

```text
VM exit #15: WRMSR 0x20f (IA32_MTRR_PHYSMASK7) <- 0x00003fffffe00800, into the guest's MTRRs; the CPU's IA32_MTRR_PHYSMASK7 stays 0x0000000000000000.
VM exit #15: guest MTRRs: enabled, default type UC; fixed ranges enabled; 8 variable ranges, 2 in use.
VM exit #15: guest MTRR variable range 0: base=0x000000000000 mask=0x3fff00000000 WB
VM exit #15: guest MTRR variable range 7: base=0x000000200000 mask=0x3fffffe00000 UC
VM exit #15: EPT: 1 region(s) retyped (0 split into a spare PT, 0 merged back into one 2 MiB page); 9 spare PT(s) left; INVEPT single-context.
VM exit #15: EPT 0x000000200000..0x000000400000: 2 MiB pages, UC
```

Then, for the 4 KiB mask (exit #17), `1 split into a spare PT`, `8 spare
PT(s) left` and `4 KiB pages (a PT each)`; for turning the range off
(exit #18), `1 merged back into one 2 MiB page`, `9 spare PT(s) left` and `2 MiB pages, WB`. A write
that changes no type prints `every address keeps its memory type; EPT
unchanged`, and a refused one, host-tested only since the test guest's IDT
has no #GP gate:

```text
VM exit #N: WRMSR 0x20f (IA32_MTRR_PHYSMASK7) <- 0x0000400000000800 refused: reserved bits 0x400000000000 set in MSR 0x20f; the guest's MTRRs unchanged; injecting #GP(0) at rip=<the WRMSR>.
```

Three checks back the lines up:
- **The guest** checks that RDMSR reads back the mask it wrote, and stops
  with `ud2` otherwise ([EMULATED_EXITS.md](EMULATED_EXITS.md) section 6).
- **The statistics** count MTRR reads and writes apart from the MSRs passed
  through (`mtrr_read_exits=3 mtrr_write_exits=7`), so an MTRR access that
  ran without an exit, or was passed through, fails the run.
- **Bring-up** reads the CPU's MTRRs before and after the guest, prints
  `MTRRs after the guest: the CPU's unchanged=true; the guest's copy
  restored=true.`, and stops with `MtrrsChanged` if the CPU's differ.

## 8. What is not covered yet

- **Several CPUs.** The MTRRs are read on the bootstrap processor only, and
  the guest has one copy. Firmware programs every CPU the same way, so that
  holds until Aleph0 runs several vCPUs, each with MTRRs of its own. A PT
  that `retype` takes back is reused at once, which is sound only while no
  other vCPU can still hold a translation through it.
- **The guest's CR0.CD and WBINVD** around an MTRR update: Aleph0 does
  nothing for them beyond what the CPU does.
- **Hiding the MTRRs** from the guest altogether (CPUID.1:EDX bit 12).
- **Hiding MMIO from the guest.** The identity map still passes every device
  through; EPT only makes the caching right, UC for whatever is not RAM.

## Cheat sheet

| Item | Value |
|---|---|
| CPUID.1:EDX bit 12 | MTRRs exist |
| `IA32_MTRRCAP` | `0xFE`; bits 7:0 variable count, bit 8 fixed ranges |
| `IA32_MTRR_DEF_TYPE` | `0x2FF`; bits 7:0 default type, bit 10 FE, bit 11 E |
| Fixed MSRs | `0x250`, `0x258`, `0x259`, `0x268`..`0x26F`; 1 byte per range |
| Variable range n | PHYSBASE `0x200 + 2n` (type 7:0), PHYSMASK `0x201 + 2n` (valid bit 11) |
| Types | 0 UC, 1 WC, 4 WT, 5 WP, 6 WB; others reserved |
| Overlaps | UC wins; WT + WB = WT; others undefined (Aleph0: UC) |
| EPT leaf entry | type in bits 5:3, IPAT bit 6 left clear |
| A 2 MiB region of mixed types | a PT of 4 KiB pages, each with its own type |
| Memory the UEFI map does not call RAM | UC in EPT, whatever the MTRRs say; a region only partly RAM always has a PT |
| Guest RDMSR/WRMSR of an MTRR | its copy (`vmexit/guest_mtrrs.rs`), never the CPU's |
| WRMSR refuses | a reserved type in any type field; DEF_TYPE bits 9:8 and 63:12; PHYSBASE bits 11:8; PHYSMASK bits 10:0; PHYSBASE/PHYSMASK bits from MAXPHYADDR up |
| Spare PTs | one per variable range, plus one for the first 2 MiB |
| No spare PT left | the region is one UC 2 MiB page until one is free |
