# Port I/O: how the CPU talks to devices through I/O ports

A reference for the `in` and `out` instructions: what the I/O address space
is, how a port access travels from the CPU to a device, the rules that make
it different from memory, and how a hypervisor intercepts it. Aleph0 uses
port I/O for the serial port (`src/serial.rs`, see
[SERIAL_LOGGING.md](SERIAL_LOGGING.md)); the same mechanism drives the timer,
the interrupt controller, the keyboard controller and PCI configuration.

## 1. Two address spaces

An x86 CPU can reach two completely separate address spaces:

```
Memory address space                     I/O address space
────────────────────                     ─────────────────
0x0000_0000_0000_0000                    0x0000
        │  RAM, firmware, and devices         │  65,536 ports, one byte each
        │  mapped into memory (MMIO)          │  only devices live here,
        │                                     │  never RAM
        ▼                                     ▼
up to 2^52 bytes or more                 0xFFFF

reached with ordinary instructions:      reached ONLY with:
  mov, add, push, ...                      in, out (and ins, outs)
```

The I/O address space is **16 bits wide**: a port number is a `u16`, from
`0x0000` to `0xFFFF`, which gives **65,536 ports**. Each port number names one
**byte**. Port `0x3F8` and memory address `0x3F8` are unrelated: the same
number in two different spaces.

Rust types follow directly from this: a port is always `u16`.

```rust
pub const COM1: u16 = 0x3F8;   // a port number, not a memory address
```

## 2. The instructions

### The two ways to name a port

| Form | Port range | Example | Notes |
|---|---|---|---|
| immediate | `0x00`–`0xFF` | `out 0x80, al` | the port number is an 8-bit constant inside the instruction |
| register `DX` | `0x0000`–`0xFFFF` | `out dx, al` | the port number is in the 16-bit DX register |

Only ports below `0x100` fit in the immediate form. **COM1 is at `0x3F8`, above
`0xFF`, so it must use the `DX` form.** That is why Aleph0's helpers always
pass the port in DX.

### The data sizes

The data always travels through the **A register**, in one of three sizes:

| Size | Read | Write | Common name |
|---|---|---|---|
| 8 bits | `in al, dx` | `out dx, al` | `inb` / `outb` (byte) |
| 16 bits | `in ax, dx` | `out dx, ax` | `inw` / `outw` (word) |
| 32 bits | `in eax, dx` | `out dx, eax` | `inl` / `outl` (long) |

There is **no 64-bit port I/O**. A 16-bit access to port `P` covers ports `P`
and `P + 1`; a 32-bit access covers `P` to `P + 3`. Use the size the device
register expects: the UART's registers are all 8-bit, so serial code only
uses `inb`/`outb`. Aleph0 keeps all six functions in `src/port.rs`.

The string forms `ins`/`outs` (usually with `rep`) move a block of data
between memory and one port; disk controllers used them. Aleph0 does not.

### In Rust

```rust
use core::arch::asm;

/// 8-bit write: the byte in AL goes to port DX.
unsafe fn outb(port: u16, value: u8) {
    unsafe { asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags)) }
}

/// 8-bit read: the byte from port DX lands in AL.
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe { asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags)) }
    value
}

/// 16- and 32-bit versions differ only in the register size.
unsafe fn outw(port: u16, value: u16) {
    unsafe { asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags)) }
}
unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    unsafe { asm!("in eax, dx", out("eax") value, in("dx") port, options(nomem, nostack, preserves_flags)) }
    value
}
```

How to read the `asm!` lines:

- `in("dx") port`: before the instruction, put `port` into DX.
- `in("al") value`: before the instruction, put `value` into AL.
- `out("al") value`: after the instruction, copy AL into `value`.
- `options(...)`: promises to the compiler, explained in section 5.

## 3. What happens in the hardware

When the CPU executes `out dx, al` with DX = `0x3F8`:

```
 CPU ──"I/O write, port 0x3F8, data 'H'"──▶ chipset (PCH)
                                              │ which device owns 0x3F8?
                                              │ legacy ranges go out on the
                                              ▼ LPC / eSPI bus
                                         Super I/O chip ──▶ its UART decodes
                                                            0x3F8–0x3FF and
                                                            stores 'H' in THR
```

1. The CPU marks the bus transaction as **I/O, not memory**. Early x86
   chips had a dedicated pin for this (M/IO#); today it is a transaction
   type sent to the chipset.
2. The chipset routes it to whichever device claims that port range.
   Legacy devices such as the UART sit on a slow side bus inside a "Super
   I/O" chip. PCI devices can also claim I/O ranges through their BARs.
3. The device **decodes** the address: a UART claims 8 ports starting at its
   base and treats the low 3 bits as the register number. That is why the
   registers are "base + 0" through "base + 7".
4. For `in`, the device puts a byte back on the bus and the CPU writes it
   into AL. **If no device claims the port, a read returns all ones
   (`0xFF`)**, which is why Aleph0's loopback probe can detect a missing
   UART.

Port accesses to legacy devices are **slow**, often around a microsecond
each on real hardware. Old code even used `out 0x80, al` (a write to the
POST diagnostic port) as a deliberate short delay.

## 4. Rules that differ from memory

### Ports are not memory: reads and writes can have side effects

| Memory | Device ports |
|---|---|
| reading changes nothing | reading can change the device: reading the UART's data port **removes** the received byte; reading its line status **clears** the error bits |
| you read back what you wrote | the same port can mean different things by direction: writing `0x3F8` **sends** a byte, reading it **receives** one |
| writing the same value twice = writing once | each write is an action: two writes to `0x3F8` send two bytes |

So never read a device port "just to look" unless you know that read is
harmless, and never assume a port holds what you last wrote.

### Not cached, strictly ordered

The CPU never caches port I/O and does not reorder it with other
instructions the way it may reorder ordinary memory accesses. Earlier
memory writes are completed before an I/O instruction runs, and the next
instructions wait until it finishes. That is what makes "write the data,
then write the command" sequences safe without extra fences.

### Privilege: who may use `in`/`out`

| Situation | Result |
|---|---|
| current privilege level (CPL) ≤ `RFLAGS.IOPL` | allowed, any port |
| otherwise, the port's bit in the TSS **I/O permission bitmap** is 0 | allowed for that port |
| otherwise | `#GP` fault |

Aleph0 runs at ring 0 (CPL 0), so every port is allowed. Its host TSS sets
`iomap_base` past the end of the TSS (`src/vmx/host_tables.rs`), which means
"no permission bitmap": if code ever ran at ring 3 with this TSS, every port
access would fault. That is the safe default.

## 5. The compiler side: `asm!` options

`options(nomem, nostack, preserves_flags)` are promises that let the
compiler optimise around the instruction:

- `nostack`: the instruction does not push or pop.
- `preserves_flags`: it does not change RFLAGS. True for `in`/`out`.
- `nomem`: it does not read or write **memory**. The compiler may then move
  ordinary memory accesses across it.

`nomem` is right for the UART because the device never touches RAM. It
would be **wrong** for a device that uses DMA (reads or writes RAM itself),
for example "fill a buffer in memory, then `out` a command telling the
device to read it". With `nomem`, the compiler could move the buffer writes
after the `out`. **When adding port I/O for a DMA device, drop `nomem`.**

## 6. Port I/O versus memory-mapped I/O

Newer devices are **memory-mapped** (MMIO) instead: their registers appear
at physical memory addresses and are accessed with ordinary `mov`, through
a pointer with volatile reads and writes.

| | Port I/O | Memory-mapped I/O |
|---|---|---|
| Address space | separate, 16-bit, 64 Ki ports | the normal memory space |
| Instructions | `in`/`out` only | any memory instruction (`mov`) |
| Typical devices | UART, PIT timer, legacy PIC, PS/2, CMOS, PCI config (`0xCF8`) | local APIC (`0xFEE0_0000`), HPET, PCIe device BARs, framebuffer |
| How a hypervisor intercepts it | I/O exits, reason 30 (next section) | EPT violations, reason 48 |

## 7. Port I/O under virtualization

A guest's `in`/`out` causes a VM exit only if the VMCS asks for it, through
two primary processor-based execution controls:

| Control (bit) | Effect |
|---|---|
| unconditional I/O exiting (bit 24) | every `in`/`out` exits |
| use I/O bitmaps (bit 25) | exit only for ports whose bitmap bit is 1; overrides bit 24 |

With bitmaps, two 4 KiB pages hold **one bit per port**:

```
I/O bitmap A (VMCS field 0x2000): ports 0x0000–0x7FFF   (32,768 bits = 4 KiB)
I/O bitmap B (VMCS field 0x2002): ports 0x8000–0xFFFF   (32,768 bits = 4 KiB)

bit for port P in bitmap A:  byte P / 8, bit P % 8
COM1 (0x3F8 = 1016):         byte 127, bit 0  ...  0x3FF: byte 127, bit 7
```

An access that spans several ports exits if any of their bits is 1.

Aleph0 turns on "use I/O bitmaps" (`DesiredControls::minimal_64_bit_guest`)
and sets one bit, for the COM1 scratch register `0x3FF`
(`vmx::exit_bitmaps::INTERCEPTED_PORTS`). Every other port goes straight to
the hardware. Exits for `0x3FF` are emulated by passthrough: see
[EMULATED_EXITS.md](EMULATED_EXITS.md).

### Handling the exit (reason 30)

The **exit qualification** describes the instruction:

| Bits | Meaning |
|---|---|
| 2:0 | size − 1: `0` = 1 byte, `1` = 2 bytes, `3` = 4 bytes |
| 3 | direction: `0` = `out`, `1` = `in` |
| 4 | string instruction (`ins`/`outs`) |
| 5 | `rep` prefix |
| 6 | operand: `0` = port in DX, `1` = immediate |
| 31:16 | port number |

Then the hypervisor does what the device would have done:

1. **`out`**: the value is in the low 1/2/4 bytes of the guest's RAX
   (Aleph0's `RegisterFrame::rax`). Hand it to the emulated device.
2. **`in`**: get the value from the emulated device and write it into the
   guest's RAX. For 1- and 2-byte reads keep the rest of RAX unchanged; for
   a 4-byte read clear the upper 32 bits, as a real 32-bit register write
   does in 64-bit mode.
3. Advance guest RIP by `VM_EXIT_INSTRUCTION_LEN` so the guest continues
   after the `in`/`out`, then `VMRESUME`.

This is exactly what Hyper-V does when Aleph0 writes to COM1; see
[SERIAL_LOGGING.md](SERIAL_LOGGING.md#where-this-goes-next).

### Nested: who handles the exit

Aleph0 runs inside Hyper-V, so a port access by Aleph0's guest always exits
to Hyper-V first. Hyper-V checks Aleph0's VMCS: if Aleph0 asked for that
port to exit, Hyper-V forwards the exit to Aleph0; otherwise Hyper-V
handles it itself, against its own emulated devices.

## 8. Common legacy ports

| Port(s) | Device |
|---|---|
| `0x20`–`0x21`, `0xA0`–`0xA1` | 8259 interrupt controllers (master, slave) |
| `0x40`–`0x43` | 8254 programmable interval timer (PIT) |
| `0x60`, `0x64` | PS/2 keyboard controller (data, status/command) |
| `0x70`–`0x71` | CMOS / real-time clock (index, data) |
| `0x80` | POST diagnostic code; writes are also used as a tiny delay |
| `0x2F8`–`0x2FF` | COM2 |
| `0x3F8`–`0x3FF` | **COM1**, Aleph0's serial log |
| `0xCF8`, `0xCFC` | PCI configuration address and data |
| `0xE9` | "debugcon": Bochs, and QEMU started with `-debugcon`, print any byte written here (not Hyper-V) |

## Cheat sheet

- Port numbers are **16-bit** (`u16`): 65,536 ports, one byte each, in their
  own address space separate from memory.
- Only `in`/`out` reach it. Ports above `0xFF` need the **`DX`** form.
- Data is 8/16/32 bits through **AL/AX/EAX**; match the device register size.
- An unclaimed port reads as **`0xFF`**.
- Reads can have **side effects**; a port is not memory.
- I/O is **uncached and strictly ordered**, and slow on legacy hardware.
- Ring 0 may use any port; ring 3 needs IOPL or the TSS permission bitmap.
- In `asm!`, `nomem` is fine for the UART and wrong for DMA devices.
- Hypervisors intercept port I/O with **I/O bitmaps** (bit 25) and handle
  **exit reason 30** using the exit qualification, guest RAX, and RIP +
  instruction length.
