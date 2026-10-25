# Walking page tables: how an address becomes a physical address

A reference for x86-64 paging: what virtual and physical addresses are, how
the four levels of page tables turn one into the other, what every bit of a
page-table entry means, and how Aleph0 walks the tables in software.

Aleph0 does this in `src/vmx/paging.rs`. `GuestMemory::check_mappings` in
`src/vmx/guest.rs` uses it before the first VM entry. With EPT off and
guest CR3 = host CR3, the guest translates its addresses through exactly
the tables the host is using. So whatever those tables say about the guest's
code and stack pages is what the guest will get.

## 1. Virtual and physical addresses

Every address a program uses, such as `0x7eb19234`, is a **virtual**
address. It is a *name* for a byte. The RAM chips only understand
**physical** addresses: the byte's real location. On every memory access
the CPU silently translates the name into the location, using the
**page tables**.

```
 your code                 page tables                  RAM
 ─────────                 ───────────                  ───
 mov rax, [0x7eb19234] ──▶ "virtual page 0x7eb19 ──▶ read physical 0x12345234
                            lives at physical
                            page 0x12345"
```

Think of a phone's contact list: "Mom" is a name (virtual), and the phone
looks up and dials the real number (physical). In someone else's phone,
"Mom" leads to a different number.

That is how two processes can both use address `0x400000` and still get
different memory: each process has its own page tables.

```
Process A: virtual 0x400000 ──▶ its tables ──▶ physical 0x1_2345_6000
Process B: virtual 0x400000 ──▶ its tables ──▶ physical 0x0_9abc_d000
```

**Under UEFI the two are equal.** The firmware builds tables that map every
page to the same number (*identity mapping*): virtual `0x7eb19234` is
physical `0x7eb19234`. That is why they look like the same thing during
bring-up. A guest OS, or EPT later, breaks that equality.

## 2. Pages: translation works per page, not per byte

Memory is handled in 4 KiB chunks called **pages**. The page tables never
translate single bytes. They translate **page numbers**, and they hold the
permissions of each **whole page**.

Every address is therefore two parts:

```
address = [ page number | offset ]
             translated   copied unchanged
```

- The **page number** is looked up in the tables.
- The **offset** says which byte inside the page. It is never translated:
  the CPU skips it during the lookup and glues it back on at the end.

```
virtual   0x0000_4000_1234 = page 0x40001, offset 0x234
the tables say: page 0x40001 lives at physical page 0x9f
physical  0x9f234          = page 0x9f,    offset 0x234   ← same offset
```

Consequences:

- **Permissions are per page.** All 4096 bytes of a page share one
  "writable" and one "executable" bit. You cannot make a single variable
  read-only, only the page it is on. A constant is read-only because the
  linker puts all constants into their own section (`.rdata`), starting on a
  page boundary, and the loader maps those pages read-only.
- **One walk covers a whole page.** To check a page, walk any address inside
  it; Aleph0 walks the page's first byte.
- **Memory is handed out in pages.** UEFI's `allocate_pages` returns whole
  4 KiB pages, the smallest unit the tables can describe.

## 3. The four levels

With 4-level paging, a lookup goes through four tables, each one narrowing
the search:

```
CR3 ──▶ PML4  Page Map Level 4              one entry covers 512 GiB
          │
          ▼
        PDPT  Page Directory Pointer Table  one entry covers   1 GiB ──(PS=1)──▶ 1 GiB page
          │
          ▼
        PD    Page Directory                one entry covers   2 MiB ──(PS=1)──▶ 2 MiB page
          │
          ▼
        PT    Page Table                    one entry covers   4 KiB = the page
          │
          ▼
        offset: which byte inside the page
```

Think of a postal address. PML4 is the continent, PDPT the country, PD the
city, PT the street, and the offset the house number.

**Why the odd names?** History. 32-bit x86 had only **PD → PT** (a "page
directory" listing "page tables"). PAE added a level on top, the page
directory *pointer* table, and 64-bit mode added another above that,
"page map level 4". An entry is named after its table: PML4**E**,
PDPT**E**, PD**E**, PT**E**. With 5-level paging (CR4.LA57) there is a fifth
level on top, PML5; Aleph0 refuses that mode.

**Why a tree instead of one big table?** To save memory. A flat table
for all 2^36 possible pages would need 2^36 × 8 bytes = **512 GiB** just for
itself. With levels, tables exist only for regions in use: an unused 512 GiB
region is a single PML4 entry with P = 0, with nothing below it.

**Each level splits its region into 512 pieces:**

| Level | One entry covers | Job |
|---|---|---|
| PML4 | 512 GiB | which 512 GiB region |
| PDPT | 1 GiB | which 1 GiB inside it |
| PD | 2 MiB | which 2 MiB inside that |
| PT | 4 KiB | which exact page |
| offset | 1 byte | which byte inside the page |

## 4. Splitting the virtual address

```
 63         48 47      39 38      30 29      21 20      12 11         0
┌─────────────┬──────────┬──────────┬──────────┬──────────┬────────────┐
│  sign ext.  │ PML4 idx │ PDPT idx │  PD idx  │  PT idx  │   offset   │
└─────────────┴──────────┴──────────┴──────────┴──────────┴────────────┘
    16 bits      9 bits     9 bits     9 bits     9 bits     12 bits
```

**Why 12 and 9?**

- A page is 4096 = 2^12 bytes, so **12 bits** pick a byte inside it.
- A table fills exactly one page with 8-byte entries: 4096 / 8 = 512 = 2^9
  entries, so **9 bits** pick an entry.
- 4 × 9 + 12 = **48 bits** are translated.

**Canonical addresses.** Bits 63:48 are not translated, but they must be
copies of bit 47. Otherwise using the address raises #GP.

```
0x0000_7fff_ffff_ffff   ✔  bit 47 = 0, top bits 0    (lower half; user space in an OS)
0xffff_8000_0000_0000   ✔  bit 47 = 1, top bits 1    (upper half; kernel in an OS)
0x0000_8000_0000_0000   ✗  bit 47 = 1, top bits 0 → #GP
```

That is why kernel addresses in Linux and Windows look like `0xffff...`.

**Example: Aleph0's guest code page, `0x7eb19000`:**

```
 47:39       38:30       29:21       20:12       11:0
 000000000 | 000000001 | 111110101 | 100011001 | 000000000000
 PML4 = 0    PDPT = 1    PD = 0x1F5  PT = 0x119  offset = 0
```

In code, each index is "shift this level's 9 bits to the bottom, keep 9
bits":

```rust
let shift = 12 + 9 * (level - 1);               // 39, 30, 21, 12 for levels 4..1
let index = (virtual_address >> shift) & 0x1FF; // 0x1FF = nine 1-bits = 511
```

The address itself does not "know" its split. The same number is read
differently depending on where the walk stops (section 8):

```
4 KiB page:  [ PML4 | PDPT | PD | PT |   offset 12 bits     ]
2 MiB page:  [ PML4 | PDPT | PD |       offset 21 bits      ]
1 GiB page:  [ PML4 | PDPT |           offset 30 bits       ]
```

## 5. CR3: where the walk starts

CR3 holds the physical address of the PML4 table, the root of the tree.

```
 63      52 51                       12 11      5  4   3   2   0
┌──────────┬───────────────────────────┬─────────┬───┬───┬─────┐
│ reserved │   PML4 table address      │ ignored │PCD│PWT│ ign │
└──────────┴───────────────────────────┴─────────┴───┴───┴─────┘
```

- The low 12 address bits are always 0, because tables are 4 KiB-aligned,
  so they are not stored. With CR4.PCIDE = 1, bits 11:0 hold a process-context
  ID instead.
- **CR3 does not change per address.** Every lookup starts from the same
  CR3; different addresses just take different rows on the way down.
- **CR3 is a register in each CPU core.** An OS keeps one tree per process
  and loads that process's CR3 on every switch. Threads of one process share
  it.
- **VM entry and exit swap it.** The CPU loads GUEST_CR3 from the VMCS on
  entry and HOST_CR3 on exit.
- **Aleph0 runs on two trees.** The UEFI firmware built its tables and
  loaded CR3 before `aleph0hypervisor.efi` started; bring-up, the walk and
  GUEST_CR3 use that one. HOST_CR3 is Aleph0's own identity map
  (`vmx::host`, [HOST_ENVIRONMENT.md](HOST_ENVIRONMENT.md) section 2), which
  every VM exit loads. Teardown is the one place Aleph0 writes CR3: it loads
  the firmware's back.

## 6. The entry format

Every entry is one 64-bit number: an address plus flag bits.

### An entry that points to the next table

This is any PML4E, and any PDPTE or PDE with PS = 0.

```
 63  62    52 51                    12 11  8  7   6  5   4   3   2   1   0
┌───┬────────┬────────────────────────┬─────┬───┬───┬──┬───┬───┬───┬───┬───┐
│XD │ignored │  next table address    │ ign │PS │ign│A │PCD│PWT│U/S│R/W│ P │
└───┴────────┴────────────────────────┴─────┴───┴───┴──┴───┴───┴───┴───┴───┘
```

### An entry that maps a 4 KiB page (PTE)

```
 63  62 59 58 52 51                    12 11 9  8   7   6   5  4   3   2   1   0
┌───┬─────┬─────┬────────────────────────┬────┬───┬───┬───┬──┬───┬───┬───┬───┬───┐
│XD │PKey │ ign │   4 KiB page address   │ign │ G │PAT│ D │A │PCD│PWT│U/S│R/W│ P │
└───┴─────┴─────┴────────────────────────┴────┴───┴───┴───┴──┴───┴───┴───┴───┴───┘
```

### Large pages: a PDE or PDPTE with PS = 1

Same as a PTE, except that bit 7 is PS = 1, PAT moves to bit 12, and the
address field is shorter:

| Entry | Address bits | Below the address |
|---|---|---|
| table pointer, or PTE (4 KiB) | 51:12 | 11:0 flags |
| PDE, PS = 1 (2 MiB page) | 51:21 | 20:13 reserved (0), 12 PAT, 11:0 flags |
| PDPTE, PS = 1 (1 GiB page) | 51:30 | 29:13 reserved (0), 12 PAT, 11:0 flags |

### What each bit means

| Bit | Name | Meaning |
|---|---|---|
| 0 | P | Present. 0 = nothing mapped here; the CPU ignores every other bit, and an access raises a page fault (#PF). |
| 1 | R/W | Writes allowed in this region. 0 = read-only. |
| 2 | U/S | User mode (ring 3) may access it. 0 = kernel (supervisor) only. |
| 3, 4 | PWT, PCD | Caching: write-through, cache-disable. |
| 5 | A | Accessed. The CPU sets it when it uses the entry. |
| 6 | D | Dirty (page entries only). The CPU sets it when the page is written. |
| 7 | PS | In a PDPTE/PDE: 1 = this entry *is* the page (1 GiB / 2 MiB). Must be 0 in a PML4E. |
| 7 or 12 | PAT | Memory type, together with PCD/PWT. Bit 7 in a PTE, bit 12 in a large page. |
| 8 | G | Global (pages only): keep in the TLB when CR3 changes. |
| 51:12 | address | Next table or page. Bits above the CPU's MAXPHYADDR must be 0. |
| 62:59 | PKey | Protection key (pages only); unused by Aleph0. |
| 63 | XD | Execute-disable: no instruction fetch from this region (if EFER.NXE = 1). |

### Why the address field is shorter for bigger pages

A page always starts at a multiple of its own size, so the start address of
a big page ends in many zeros:

```
4 KiB page:  0x7eb19000   low 12 bits always 0
2 MiB page:  0x7ea00000   low 21 bits always 0
1 GiB page:  0x40000000   low 30 bits always 0
```

Storing bits that are always 0 would be pointless, so the entry stores only
the rest, and the CPU fills in the zeros. It works like writing city
addresses where every building starts at a multiple of 1,000: you write
`12345` and everyone knows it means `12,345,000`.

The top is similar: physical addresses are at most 52 bits, so entry bits
63:52 are free and hold XD and the protection key.

The bits that are zero in the page start are **exactly** the bits the offset
fills in. The bigger the page, the shorter the stored address and the longer
the offset.

## 7. The walk, step by step

1. `table = CR3 bits 51:12`, the PML4.
2. For level 4, 3, 2, 1:
   1. `index = (virtual >> shift) & 0x1FF`, which picks the row (from the
      **virtual address**).
   2. `entry = read 8 bytes at table + index × 8`.
   3. P = 0 → stop: not mapped.
   4. Remember R/W (AND) and XD (OR); see section 10.
   5. PS = 1 at level 3 or 2, or level 1 reached → **this entry maps the
      page**; go to section 9.
   6. Otherwise `table = entry bits 51:12`, which gives the next table (from
      the **entry**), and go one level down.

At every level, two different things decide where to look:

- **which row** comes from the virtual address;
- **where the table is** comes from the row read one level up (or from CR3).

### Worked example: `0x7eb19000` on Hyper-V

The table locations and entry values below are illustrative. The result
matches what Aleph0 printed on Hyper-V:
`phys=0x000000007eb19000 identity=true size=Size4K writable=true xd=false`.

```
virtual = 0x7eb19000 → PML4 0, PDPT 1, PD 0x1F5, PT 0x119, offset 0

CR3 = 0x7f801000                                   → PML4 at 0x7f801000
L4: row 0     at 0x7f801000 + 0x000 = 0x7f801000   entry 0x7f802023 → PDPT at 0x7f802000
L3: row 1     at 0x7f802000 + 0x008 = 0x7f802008   entry 0x7f803023 → PD   at 0x7f803000
L2: row 0x1F5 at 0x7f803000 + 0xFA8 = 0x7f803fa8   entry 0x7f9a0023 → PT   at 0x7f9a0000
L1: row 0x119 at 0x7f9a0000 + 0x8C8 = 0x7f9a08c8   entry 0x7eb19063 → page at 0x7eb19000

physical = 0x7eb19000 + offset 0 = 0x7eb19000
```

Decoding the flag bits:

```
0x023 = 0000 0010 0011 → bit 0 P = 1, bit 1 R/W = 1, bit 5 A = 1, bit 7 PS = 0
0x063 = 0000 0110 0011 → P, R/W, A, plus bit 6 D = 1 (bit 7 is PAT in a PTE, here 0)
bit 63 (XD) = 0 in all four entries
```

The neighbouring stack page `0x7eb18000` takes the same first three rows
and only a different last one (PT row `0x118`).

## 8. Large pages: when the walk stops early

The walk stops at the PD (2 MiB page) or PDPT (1 GiB page) when **whoever
built the tables** set PS = 1 in that entry. That choice belongs to the
tables, not to the address. Every address inside that 2 MiB or 1 GiB region
stops at the same entry.

Table builders choose a large page when:

1. the region maps to **one contiguous, aligned** block of physical memory;
2. the whole region can share **one set of permissions**;
3. they want **fewer tables and fewer TLB entries**. One TLB entry then
   covers 2 MiB or 1 GiB instead of 4 KiB.

Firmware often identity-maps RAM with large pages. Kernels map all of RAM
with them, and hypervisors use them in EPT. The cost is coarse permissions:
to make one 4 KiB piece read-only or non-executable, the large page must be
**split** into a table of smaller ones. Hyper-V's firmware mapped both of
Aleph0's guest pages as 4 KiB pages, probably because it sets per-page
permissions in that region.

1 GiB pages need CPU support (CPUID `0x80000001`, EDX bit 26, almost every
64-bit CPU). There is no 512 GiB page: PS must be 0 in a PML4E.

## 9. From the entry to the physical address

Once the walk has the entry that maps the page, it needs only masks, with
**no shifting**. The entry stores the address bits in their real
positions.

```rust
let offset_mask = (1u64 << shift) - 1;                   // 0xFFF, 0x1FFFFF or 0x3FFFFFFF
let frame = entry & ADDRESS_MASK & !offset_mask;         // page start: drop flags and PAT
let physical = frame | (virtual_address & offset_mask);  // + offset from the virtual address
```

- `ADDRESS_MASK` keeps bits 51:12. It removes the flags and XD that share
  the same 8 bytes.
- `& !offset_mask` also clears the bits below the page size. For large
  pages that removes **bit 12, PAT**, which is a caching flag there and not
  an address bit. Without it, a 2 MiB page at `0x40200000` with PAT set
  would wrongly come out as `0x40201000`.
- `|` works like `+` because the page start is zero exactly where the offset
  has its bits.

Only the **indexes** need shifting (section 4), because they are used as small
numbers from 0 to 511 to pick a row.

"Physical address" means **the exact byte** (page start + offset). The
**page start** (the *frame*) is a separate thing; they are only equal when
the offset is 0.

### The same virtual address, three page sizes

`virtual = 0x7eb19234`, with made-up, non-identity entries, so you can see
which part comes from where. `|` marks where the page start ends and the
offset begins (low 32 bits shown).

**4 KiB**: the walk stopped at the PT, shift = 12, entry `0x12345063`:

```
frame     0001 0010 0011 0100 0101 | 0000 0000 0000    0x12345000   from the entry
offset    0000 0000 0000 0000 0000 | 0010 0011 0100         0x234   from the virtual address
physical  0001 0010 0011 0100 0101 | 0010 0011 0100    0x12345234
```

**2 MiB**: the walk stopped at the PD, shift = 21, entry `0x122010E3`
(`0xE3` = P, R/W, A, D, PS; bit 12 = PAT):

```
entry & ADDRESS_MASK   = 0x12201000   ← PAT still in
      & !0x1FFFFF      = 0x12200000   ← frame

frame     00010010001 | 000000000000000000000    0x12200000
offset    00000000000 | 100011001001000110100      0x119234
physical  00010010001 | 100011001001000110100    0x12319234
```

**1 GiB**: the walk stopped at the PDPT, shift = 30, entry `0x80001083`
(`0x083` = P, R/W, PS; bit 12 = PAT):

```
entry & ADDRESS_MASK   = 0x80001000   ← PAT still in
      & !0x3FFFFFFF    = 0x80000000   ← frame

frame     10 | 000000000000000000000000000000    0x80000000
offset    00 | 111110101100011001001000110100    0x3eb19234
physical  10 | 111110101100011001001000110100    0xbeb19234
```

| | 4 KiB | 2 MiB | 1 GiB |
|---|---|---|---|
| Walk stops at | PT (level 1) | PD (level 2) | PDPT (level 3) |
| Offset bits | 12 | 21 | 30 |
| Page-start bits in the entry | 51:12 | 51:21 | 51:30 |
| frame | `0x12345000` | `0x12200000` | `0x80000000` |
| physical | `0x12345234` | `0x12319234` | `0xbeb19234` |

The offset can never point outside its page: it has exactly as many bits as
the page has bytes.

## 10. Permissions: every level counts

The **last** entry gives the address, but the **permissions come from every
entry on the path**. The CPU checks all of them and the strictest one wins,
like doors in a row:

| Bit | Combined with | Rule |
|---|---|---|
| P | every level | P = 0 anywhere → not mapped, #PF |
| R/W | AND | writable only if R/W = 1 at **every** level |
| U/S | AND | a user page only if U/S = 1 at **every** level |
| XD | OR | one XD = 1 at **any** level blocks execution |

```
            R/W
PML4 entry   1
PDPT entry   1
PD   entry   0    ← read-only here
PT   entry   1    ← the last entry says "writable"

last entry alone:  writable   ✗ wrong
all levels (AND):  read-only  ✔ what the CPU does
```

In practice, firmware and OSes leave the upper levels permissive and put the
real restrictions in the last entry. The CPU still checks every level, and
so does Aleph0.

### The registers that change what the bits mean

| Setting | Effect |
|---|---|
| EFER.NXE = 1 | XD is a permission. With NXE = 0, XD is a *reserved* bit and **any** access to that page faults. |
| CR0.WP = 1 | Read-only applies to ring 0 too. With WP = 0, the kernel may write read-only pages. |
| CR4.SMEP = 1 | Ring 0 may not **execute** from user pages (U/S = 1). |
| CR4.SMAP = 1 | Ring 0 may not **read or write** user pages, unless RFLAGS.AC = 1. |

There is no "readable" bit: if a page is present, it can be read.

## 11. How Aleph0 uses this

### `paging::walk`: pure logic

```rust
pub fn walk(cr3: u64, virtual_address: u64, read_entry: impl Fn(u64) -> u64)
    -> Result<Mapping, WalkError>
```

- It never touches memory itself. The caller passes `read_entry`, a function
  that returns the 8-byte entry at a physical address.
- It returns a `Mapping`: `physical`, `size` (`Size4K` / `Size2M` /
  `Size1G`), `writable`, `user`, `execute_disable`. Or it returns
  `WalkError::NotPresent { level }`, naming the level where P was 0.
- Because memory is a parameter, the host unit tests
  (`tests/unit/vmx/paging.rs`) build small fake page
  tables in a `HashMap` (address → entry). They check 4 KiB, 2 MiB and
  1 GiB pages, the PAT bit, CR3's ignored low bits, AND/OR combining, and
  missing entries.

### `paging::walk_current`: the real tables

It reads the live CR3 and passes `walk` a function that reads each entry
straight from memory at its physical address. That only works because
**UEFI identity-maps memory while boot services are active**, so a table's
physical address is also a usable pointer. It refuses 5-level paging
(CR4.LA57).

### `GuestMemory::check_mappings`: the guest pages

Before any VMX work, bring-up walks the guest code page and the guest stack
page, then `check_permissions` requires that:

| Page | Must | Error otherwise |
|---|---|---|
| code | XD = 0 at every level | `CodeNotExecutable` |
| code | not a user page while CR4.SMEP = 1 | `CodeBlockedBySmep` |
| stack | R/W = 1 at every level | `StackNotWritable` |
| stack | not a user page while CR4.SMAP = 1 | `StackBlockedBySmap` |

The guest runs at ring 0 with the host's CR4 and RFLAGS.AC = 0, so SMEP and
SMAP apply to it. The guest code page is allocated as a code type
(`LOADER_CODE` then, `RUNTIME_SERVICES_CODE` since #23) because firmware with
memory protection often maps the data types no-execute.

On Hyper-V both pages came back **identity-mapped, 4 KiB, writable, XD
clear**, with host **EFER.NXE = 1**. That last value matters for guest
state: the guest shares these tables, so it must also run with NXE = 1, or
every XD bit in them becomes a reserved-bit fault.

### What the walk does not check

- that the address is canonical (guest pages come from UEFI, so they are);
- reserved bits and MAXPHYADDR (masking bits 51:12 is safe, since unused
  high address bits are 0 in a valid entry);
- protection keys and memory types (PAT/MTRR).

The real proof is the first `VMLAUNCH`. If the guest's `VMCALL` exit shows
up with the marker in RAX, the CPU fetched and executed the code page.

## 12. Two side notes

**Little-endian.** x86 stores multi-byte numbers lowest byte first, so the
entry `0x0000_0000_8000_1083` sits in memory as
`83 10 00 80 00 00 00 00`. That does not affect the walk: `walk_current`
reads each entry as a whole `u64`, and from then on every mask works on the
number. Bit numbers (bit 0 = P, bit 63 = XD) number the value, not memory
bytes.

**The TLB.** The CPU does not walk on every access. It caches finished
translations in the **TLB** (translation lookaside buffer), one entry per
page, so a 2 MiB or 1 GiB page saves many entries. Writing CR3 flushes most
of the TLB (all but global pages), because the old answers may no longer be
true.

## Where this goes next

- **Translating guest pointers.** When a guest passes a pointer in a
  register (say `VMCALL` with RCX = a buffer address), an exit handler must
  walk the guest's tables to find where that buffer really is. That walk
  starts at the guest's CR3, and it must handle buffers that cross a page
  boundary: two pages, two walks, possibly far apart.
- **Leaving the firmware's tables.** After `ExitBootServices` the OS may
  reuse the memory holding them. VM exits already run on Aleph0's own host
  page tables ([HOST_ENVIRONMENT.md](HOST_ENVIRONMENT.md)); their pages
  still have to move to memory the OS keeps (ROADMAP section 5).
- **EPT.** A second, hypervisor-owned translation under the guest's: guest
  virtual → (guest page tables) → guest physical → (EPT) → host physical.
  EPT entries have a similar shape, with their own read, write and execute
  bits. That turns "the guest shares the host's memory" into real isolation.

## Cheat sheet

- A virtual address is a **name**; the page tables map it to a **physical**
  location. UEFI maps them **identically**.
- Translation is **per page**: page number translated, **offset copied**.
  Permissions are per page.
- 4 levels: **PML4 → PDPT → PD → PT**, 9 index bits each, 12 offset bits:
  48-bit addresses, bits 63:48 copies of bit 47.
- **CR3** = PML4's physical address; one per core, the same for every
  lookup; firmware set it, Aleph0 only reads it.
- Row = `table + index × 8`; the index comes from the **address**, the next
  table from the **entry** (bits 51:12).
- **PS = 1** in a PDPTE/PDE ends the walk: 1 GiB / 2 MiB page, 30 / 21
  offset bits; PAT moves to bit 12.
- Frame = `entry & ADDRESS_MASK & !offset_mask` (no shift); physical =
  `frame | (virtual & offset_mask)`.
- **P** everywhere; **R/W** and **U/S** combine with AND; **XD** with OR.
- XD needs EFER.NXE; SMEP/SMAP stop ring 0 from executing/accessing user
  pages.
- Aleph0: `paging::walk` (pure, tested on fake tables) →
  `walk_current` (live CR3) → `GuestMemory::check_mappings` (guest code
  executable, stack writable).
