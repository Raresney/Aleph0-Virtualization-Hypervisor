# MTRRs: giving guest memory the right memory type under EPT

How Aleph0 gives every EPT entry the memory type the guest would get without
EPT:
- what a memory type is, and why device memory must not be write-back;
- the memory type range registers (MTRRs) and how the CPU combines them;
- why EPT makes Aleph0 responsible for memory types;
- how Aleph0 reads the MTRRs and copies their types into EPT;
- what bring-up prints, and what is not covered yet.

Code:
- `src/vmx/mtrr.rs`: the MTRR MSRs, decoding and checking them, the type of
  an address (`Mtrrs::memory_type`) and of a block (`Mtrrs::block_type`);
- `src/vmx/cpuid.rs`: `has_mtrr`, the CPUID check before any MTRR MSR is read;
- `src/vmx/ept.rs`: `large_page_type`, `split_regions` and
  `fill_identity_map`, which put the types into the identity map;
- `src/bring_up/mod.rs` and `report.rs`: where the MTRRs are read and printed.

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
   variable range it counts.
3. `Mtrrs::decode` checks every type the CPU actually uses. A reserved type
   would make an EPT entry an EPT misconfiguration (exit reason 49), so it
   stops bring-up with the MSR that holds it. Types the CPU ignores (with the
   MTRRs or the fixed ranges off, or in a range without the valid bit) are
   not checked.

`Ept::build` then maps memory as before, 2 MiB at a time, but asks
`Mtrrs::block_type` for each 2 MiB region first:

- **One type for the whole region:** a 2 MiB page of that type.
- **Pages of different types:** a PT, and 512 pages of 4 KiB, each with its
  own type. An EPT entry has one type, so a 2 MiB page would give part of
  the region the wrong one.

The region holding the guest's data page still gets a PT too, for the
read-only page. If that region is mixed already, it shares the PT.

`split_regions` counts the PTs first, so they are allocated in one go, and
`fill_identity_map` uses them in address order.

### Finding mixed regions cheaply

Looking up 512 pages for every 2 MiB region would be slow for large
machines. `block_type` only does that when it has to: the pages of a 2 MiB
block differ in address bits 20:12 only. A variable range whose mask tests
none of those bits covers the whole block or none of it. Only a range that
tests some of them, and whose upper bits match the block, can cover part of
it (`VariableRange::may_split`). The other case is the first 2 MiB, where
the fixed ranges apply below 1 MiB. Everywhere else, one lookup gives the
whole region's type.

## 6. What bring-up prints

After the VMX capabilities, for example:

```text
MTRRs: enabled, default type UC; fixed ranges enabled; 8 variable ranges, 1 in use.
MTRR variable range 0: base=0x000000000000 mask=0x007f80000000 WB
MTRR fixed 0x00000..0xa0000: WB
MTRR fixed 0xa0000..0xc0000: UC
MTRR fixed 0xc0000..0x100000: WP
EPT built: identity 0x0..0x100000000 (4 GiB), 8 table pages, 2 of them PTs for 2 MiB regions mapped in 4 KiB pages; data page 0x000000007eb01000 read-only (R=1 W=0 X=0).
EPT 0x000000000000..0x000000200000: 4 KiB pages (a PT each)
EPT 0x000000200000..0x00007ea00000: 2 MiB pages, WB
EPT 0x00007ea00000..0x00007ec00000: 4 KiB pages (a PT each)
EPT 0x00007ec00000..0x000080000000: 2 MiB pages, WB
EPT 0x000080000000..0x000100000000: 2 MiB pages, UC
```

The lines above show the format on an example layout, not a Hyper-V run.
The fixed-range lines show the first MiB in runs of one type. The `EPT`
lines are read back from the PD entries `Ept::build` filled, the ones the
CPU walks, rather than worked out again from the MTRRs: runs of 2 MiB pages
with the type in their entries, and runs of regions mapped through a PT. Here
the first 2 MiB has a PT because the fixed ranges give it three types, and
`0x7ea00000` is the data page's region.

## 7. What is not covered yet

- **Guest writes to the MTRRs.** The MSR bitmap does not intercept the MTRR
  MSRs, so a guest's WRMSR to them reaches the CPU, while the EPT types stay
  as they were at bring-up. An OS guest that reprograms its MTRRs needs
  those writes intercepted, the EPT types rebuilt, and INVEPT.
- **Several CPUs.** The MTRRs are read on the bootstrap processor only.
  Firmware programs every CPU the same way, so that holds until Aleph0 runs
  on several vCPUs and a guest can change one CPU's MTRRs.
- **Hiding MMIO from the guest.** The identity map still passes every device
  through; this change only makes the caching right.

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
