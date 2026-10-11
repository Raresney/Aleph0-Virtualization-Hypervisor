# Serial logging

How Aleph0 gets debug output out of places where the firmware console cannot
be used, and how to read it. The code is `src/serial.rs`; its module comment
covers the register-level details.

- New to this? Read the [beginner walkthrough](#beginner-walkthrough) first.
- How `in`/`out` and the 16-bit I/O port space work in general:
  [PORT_IO.md](PORT_IO.md).

## The problem

`uefi::println!` asks the firmware's console driver to draw text. That only
works while the CPU is in ordinary firmware context, which stops being true
in exactly the places a hypervisor most needs debug output:

- **The VM-exit handler.** After a VM exit the CPU jumps to `HOST_RIP` with
  interrupts disabled, on the dedicated exit stack, while the firmware may
  have been in the middle of anything when the guest was launched. Calling
  back into the firmware from there is unsafe: its console code can take
  locks, depend on timers, or assume state that does not hold.
- **After `ExitBootServices`.** Once an OS takes over, the firmware console
  no longer exists.
- **When things go wrong.** A triple fault or a hang can leave the screen
  half-drawn. Bytes already sent over serial have left the machine.

## The solution: talk to the hardware directly

PCs have a standard serial port controller, the 16550 UART, at I/O port
`0x3F8` (COM1). Every VMM emulates one. Sending a byte takes two
instructions' worth of work:

1. Read the line status register (`0x3FD`) until bit 5, "ready for another
   byte", is set.
2. Write the byte to the data register (`0x3F8`) with `out`.

No firmware, allocator, interrupts or locks are involved, so this works
anywhere the CPU runs at ring 0, including the exit handler.

`serial::init` does a one-time setup: no UART interrupts (the driver polls),
115200 baud, 8 data bits, no parity, 1 stop bit, FIFOs on. It then checks
that a UART is really present by putting it in **loopback mode**, where the
chip feeds its own output back into its input, and checking that a test byte
comes back. If it doesn't, serial output stays off instead of poking an
unknown device, and the console says so.

## Beginner walkthrough

The same driver, one step at a time, in the order the code runs. The step
numbers match the `Step N` comments in `src/serial.rs`.

```
 Your Rust code            The UART chip              The outside world
 ──────────────            ─────────────              ─────────────────
 serial_println!("Hi")
   → write_byte('H')  ──▶  "send this byte"  ──▶  (Hyper-V) ──▶ pipe ──▶ PowerShell window
   → write_byte('i')  ──▶  "send this byte"  ──▶      ...
```

The chip only understands "here is one byte, send it". Strings, formatting
and newlines are all built on top of that in software.

### Step 0: talk to the hardware through ports

The CPU reaches the UART through **I/O ports**: numbered addresses
`0x0000`–`0xFFFF` (16 bits) in their own address space, separate from memory.
Only two instructions use them:

| Instruction | Meaning |
|---|---|
| `out dx, al` | send the byte in AL to port number DX |
| `in al, dx` | read a byte from port number DX into AL |

`serial.rs` wraps them in `outb(port, value)` and `inb(port) -> u8`. Every
other step is just calls to these two. The full story (instruction forms,
what happens on the bus, ordering, privilege, virtualization) is in
[PORT_IO.md](PORT_IO.md).

### Step 1: find the chip

COM1 occupies **8 consecutive ports starting at `0x3F8`**. Each one is a
**register**: a one-byte box inside the chip with a specific job.

| Port | Offset | Register | Used for |
|---|---|---|---|
| `0x3F8` | +0 | data | write = send a byte, read = receive a byte |
| `0x3F9` | +1 | interrupt enable | turned off (0) |
| `0x3FA` | +2 | FIFO control | turn the 16-byte queues on |
| `0x3FB` | +3 | line control | data format; bit 7 is the DLAB switch |
| `0x3FC` | +4 | modem control | "ready" signals; bit 4 is loopback |
| `0x3FD` | +5 | line status | bit 0 = byte received, bit 5 = can take a byte |
| `0x3FE` | +6 | modem status | unused |
| `0x3FF` | +7 | scratch | unused |

### Step 2: configure the chip (`init`, once per boot)

```rust
outb(COM1 + 1, 0x00);         // 2a. no interrupts: we poll instead
outb(COM1 + 3, 0b1000_0000);  // 2b. DLAB on ("hold Shift")
outb(COM1 + 0, 0x01);         //     0x3F8 is now divisor low  = 1
outb(COM1 + 1, 0x00);         //     0x3F9 is now divisor high = 0 → 115200 baud
outb(COM1 + 3, 0b0000_0011);  // 2c. 8 data bits, no parity, 1 stop bit; DLAB off
outb(COM1 + 2, 0b1100_0111);  // 2d. FIFOs on, both emptied
outb(COM1 + 4, 0b0000_1011);  // 2e. DTR + RTS + OUT2 = "ready"
```

In `serial.rs`, step 2e is done at the end of step 3, because the loopback
test also writes the modem control register.

- **Baud** is bits per second on the wire. Both ends must agree; 115200 is
  the standard for debugging.
- **Divisor**: the chip runs at a fixed 115200 internally and divides it:
  `baud = 115200 / divisor`, so divisor 1 = 115200.
- **DLAB** (divisor latch access bit) is bit 7 of port +3. While it is on,
  ports +0 and +1 hold the divisor instead of data and interrupt enable,
  like a Shift key. Forgetting to turn it off is a classic bug: every "send"
  would change the speed instead.
- **8N1** is the frame format: 8 data bits, No parity, 1 stop bit.

### Step 3: check the chip is really there (loopback)

A port with no device behind it reads as `0xFF`. To be sure a UART answers,
`init` turns on **loopback** (the chip wires its output to its own input),
sends a test byte, and checks the same byte comes back:

```rust
outb(COM1 + 4, 0b0001_1011);           // loopback ON (bit 4) + ready
outb(COM1 + 0, 0xAE);                  // send 0xAE to ourselves
// wait (bounded) until line status bit 0 says "byte received", then:
let received = inb(COM1 + 0);          // should be 0xAE
outb(COM1 + 4, 0b0000_1011);           // loopback OFF, always
```

Loopback is on only for this test. While it is on, nothing leaves the chip.

### Step 4: send one byte (`write_byte`)

Wait until the chip can take a byte, then hand it over:

```rust
while inb(COM1 + 5) & 0b0010_0000 == 0 {}  // line status bit 5: ready?
outb(COM1 + 0, byte);                      // send
```

```
write 'H'  → bit 5 = 0   (busy)
             the CHIP finishes with the byte by itself
           → bit 5 = 1   (ready)
write 'i'  → bit 5 = 0 ...
```

Reading the status does not make it ready; it is like looking at a light.
The chip turns the light back on. On Hyper-V that happens instantly.

### Step 5: send text (`write_str`)

Send each byte of the string. Terminals need `\r\n` to start a new line, so
every `\n` is preceded by `\r`:

```rust
for byte in text.bytes() {
    if byte == b'\n' { write_byte(b'\r'); }
    write_byte(byte);
}
```

### Step 6: formatting (`serial_println!`)

Implementing `core::fmt::Write` for a marker type lets Rust's formatting
write straight to the port, with no allocation:

```rust
pub struct Serial;
impl fmt::Write for Serial {
    fn write_str(&mut self, text: &str) -> fmt::Result { write_str(text); Ok(()) }
}

crate::serial_println!("VM exit: reason={reason} rip={rip:#x}");
```

### Step 7: from `out` to your screen

```
1. Aleph0 runs  out dx, al        (DX = 0x3F8, AL = 'H')
2. Hyper-V marked port 0x3F8 to cause a VM exit (reason 30), so the CPU stops Aleph0
3. Hyper-V reads the exit: "OUT, port 0x3F8, 1 byte", and AL = 'H'
4. Hyper-V's software UART (in vmwp.exe on the host) writes 'H' into \\.\pipe\aleph0-com1
5. Hyper-V moves Aleph0's RIP past the `out` and resumes it
6. scripts/read-serial.ps1 reads 'H' from the pipe → PowerShell window + run\serial.log
```

Aleph0 cannot tell the chip is software. Steps 2–5 are the same work
Aleph0 will do itself when it emulates a device for its own guest (see
[Where this goes next](#where-this-goes-next)).

### Bonus: receiving a byte

Not used by Aleph0 yet, but it mirrors sending: wait for line status bit 0,
then read the data port. Reading the data clears bit 0.

```rust
if inb(COM1 + 5) & 0b0000_0001 != 0 {
    let byte = inb(COM1 + 0);
}
```

## Using it in code

| Macro | Goes to | Use from |
|---|---|---|
| `log!(...)` | firmware console **and** COM1, prefixed with `TAG` | `main` and the bring-up steps (ordinary UEFI context) |
| `serial_println!(...)` / `serial_print!(...)` | COM1 only, no prefix | anywhere, **required** in the VM-exit handler |

Both take normal `format!` arguments. `log!` is defined in `main.rs`; the
serial macros are exported from `serial.rs` and are usable as
`crate::serial_println!`.

The rule to remember: **never call `uefi::println!` or `log!` from code that
can run in the VM-exit handler.**

## Reading the output

### Hyper-V

`scripts/run-hyperv.ps1` attaches COM1 to the named pipe `\\.\pipe\aleph0-com1`,
starts the VM, opens the video console, and then runs `scripts/read-serial.ps1`.
That script connects to the pipe and prints every line in your PowerShell
window, while also saving it to `run\serial.log`. It exits when the VM turns
off.

- Hyper-V drops serial output written while nothing is connected to the
  pipe, which is why the reader connects right after `Start-VM`.
- To reattach to a VM that is already running, run `.\scripts\read-serial.ps1`.
  Lines sent before you connected are lost.
- `-NoSerial` skips the reader (COM1 is still attached). You can also
  connect with PuTTY: connection type *Serial*, serial line
  `\\.\pipe\aleph0-com1`.

### QEMU

`scripts/run.ps1` already passes `-serial stdio`, so COM1 appears in the terminal.
OVMF also copies its own console to COM1, so every `log!` line shows up
twice: one copy comes through OVMF (sometimes with terminal escape codes),
and one comes straight from Aleph0. `serial_println!` lines appear once.

## What the output looks like

A normal boot, in `run\serial.log`:

```text
[Aleph0 Virtualization Hypervisor] Initializing UEFI helpers...
[Aleph0 Virtualization Hypervisor] UEFI helpers initialized successfully.
[Aleph0 Virtualization Hypervisor] Serial output enabled on COM1 (0x3f8).
[Aleph0 Virtualization Hypervisor] Host TSS allocated at 0x...
...
```

After `VMLAUNCH`, the exit handler and then bring-up add lines like these (confirmed on Hyper-V):

```text
[Aleph0 Virtualization Hypervisor] Launching the guest with VMLAUNCH; its VM exits are reported on serial only.
[Aleph0 Virtualization Hypervisor] VM exit #1: reason=18 (VMCALL)
[Aleph0 Virtualization Hypervisor] VM exit #1: qualification=0x0000000000000000
[Aleph0 Virtualization Hypervisor] VM exit #1: guest rip=0x000000007eb0c007 instruction length=3
[Aleph0 Virtualization Hypervisor] VM exit #1: guest rax=0x000000000000a1e0 rbx=0x0000000000000000 rcx=0x0000000004722378 rdx=0x0000000000000000
[Aleph0 Virtualization Hypervisor] VM exit #1: expected VMCALL (rax=0xa1e0); resuming the guest at rip=0x000000007eb0c00a.
[Aleph0 Virtualization Hypervisor] VM exit #2: reason=18 (VMCALL)
[Aleph0 Virtualization Hypervisor] VM exit #2: qualification=0x0000000000000000
[Aleph0 Virtualization Hypervisor] VM exit #2: guest rip=0x000000007eb0c01b instruction length=3
[Aleph0 Virtualization Hypervisor] VM exit #2: guest rax=0x000000000000a1e1 rbx=0x0000000000000000 rcx=0x0000000000000000 rdx=0x0000000000000000
[Aleph0 Virtualization Hypervisor] VM exit #2: expected VMCALL (rax=0xa1e1); all 2 planned VMCALLs handled; no NMI arrived.
[Aleph0 Virtualization Hypervisor] VM exit #2: stopping the guest; returning to bring-up.
[Aleph0 Virtualization Hypervisor] Teardown: CR4.VMXE=0 firmware GDTR/IDTR restored=true IF=1.
[Aleph0 Virtualization Hypervisor] Guest finished after 2 VM exits; VMX operation left.
[Aleph0 Virtualization Hypervisor] Waiting 1 s on a firmware timer event...
[Aleph0 Virtualization Hypervisor] Firmware timer fired: interrupts reach the firmware again.
[Aleph0 Virtualization Hypervisor] Returning to firmware with SUCCESS.
```

With `.\scripts\run-hyperv.ps1 -InjectNmi`, two exits appear between those two VMCALLs: the NMI exit, and the VMCALL of the guest's NMI handler (see [NMI.md](NMI.md)).

If the reason line ends in `[VM entry failed; guest did not run]`, the CPU
rejected the guest state before running a single guest instruction. Reason 33
(invalid guest state) is the most common one; the next step is to compare
every guest field against Intel SDM Vol. 3C, "Checks on the Guest State Area".

## Common questions

**Is there a real chip?** Not under Hyper-V or QEMU: the 16550 is emulated
in software, register for register. On a physical PC it is a real chip
(today part of the chipset or a Super I/O chip), and the code is identical.

**Doesn't a UART send to another UART?** On real hardware, yes: a wire can
only carry bits over time, so a second UART at the far end turns them back
into bytes. Hyper-V never turns the byte into bits; it passes the whole
byte into the named pipe, so there is no wire and no second UART, and the
baud rate is ignored.

**What would real hardware need?** A COM port at `0x3F8` on the test PC
(UART #1), a USB-to-RS-232 adapter on the reading PC (UART #2), a
null-modem cable (TX crossed to RX), and PuTTY set to 115200 8N1 with no
flow control. Do not connect a 3.3 V/5 V "TTL" adapter to a ±12 V RS-232
port.

**Does the status become ready because I read it?** No. Reading line status
only looks. The chip sets bit 5 itself once it has taken the previous byte.
Reading does change some things: reading the data port removes the received
byte (clearing bit 0), and reading line status clears error bits 1–4.

**Does loopback stay on?** No. It is on only during the presence test in
`init`, once per boot, and turned off right after. Left on, nothing would
leave the chip.

**Why use a serial port at all in 2026?** It is the simplest output device
(two instructions per byte), needs no drivers, works in the exit handler and
after `ExitBootServices`, survives crashes, and every VMM emulates it. Linux
(`console=ttyS0`), cloud serial consoles (AWS, Azure) and hypervisor
developers rely on it.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Console says `Serial output disabled: LoopbackFailed` | No UART at `0x3F8`: COM1 not attached to the VM (`Get-VMComPort -VMName Aleph0Test`). |
| Reader times out connecting | VM not running, or `-PipeName` differs between the two scripts. |
| Reader connects but shows nothing | It connected after the hypervisor printed. Restart the VM with `scripts/run-hyperv.ps1`. |
| Doubled lines under QEMU | Expected: OVMF mirrors its console to COM1. |

## Where this goes next

Today the first guest will mirror the host, so if the guest itself writes
to port `0x3F8`, the write goes straight to the (emulated) UART: I/O
instructions do not cause VM exits unless asked to.

Turning on I/O exiting for that port, through the "use I/O bitmaps" control
and a bit in the I/O bitmap, makes every guest `out` to COM1 cause a VM exit
(reason 30). The hypervisor then reads the port and value from the exit
qualification and guest registers, prints the byte itself, advances guest
RIP, and resumes. That is a **virtual device**: the guest thinks it talks to
a UART, but the hypervisor is handling it. It is the usual first device a
hypervisor emulates.

When multiple vCPUs exist, output from several CPUs can interleave mid-line.
At that point the serial driver needs a spinlock, and the lock must not
deadlock if a CPU takes a VM exit while holding it.
