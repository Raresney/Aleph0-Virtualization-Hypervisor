# The Linux target: a kernel the firmware can start

The first OS that is to boot as Aleph0's guest (#15) is a Linux kernel with
the EFI stub and a built-in initramfs, on one vCPU, with its console on
`ttyS0` (COM1). This page covers how that image is built and put on the
Hyper-V test VM, why its command line and initramfs are built in, and what it
printed when the firmware booted it directly, without Aleph0 (#17). #28 boots
the same file under Aleph0; this run is what a working boot looks like.

Code: `scripts/linux/build.sh` (the build), `scripts/linux/aleph0.config` (the
kernel configuration fragment), `scripts/linux/init` (the initramfs's
`/init`), `scripts/run-hyperv.ps1` (`-Kernel`, `-WithoutAleph0`,
`-ProcessorCount`).

## 1. What the image is

- **Linux 6.18.58**, the newest long-term release when this was written,
  built from `x86_64_defconfig` plus `aleph0.config`.
- **The EFI stub** makes the kernel image (`bzImage`) a PE/COFF EFI
  application, so the firmware starts it the way it starts Aleph0.
- **A built-in initramfs** holding a static BusyBox 1.35.0 (the musl binary
  busybox.net publishes) and `/init`. It needs no disk, so the VMBus storage
  path is not needed.
- **One vCPU** keeps INIT/SIPI out of the first boot.
- **Console on COM1**; Aleph0's own output stays on COM2.

## 2. Building it

`build.sh` runs on Linux or WSL. On Ubuntu or Debian it needs:

```sh
sudo apt install build-essential flex bison bc libelf-dev libssl-dev curl xz-utils
bash scripts/linux/build.sh
```

From Windows, with a WSL distribution installed, run it from the repository:
`wsl -d Ubuntu-26.04 bash scripts/linux/build.sh`.

It then:

1. downloads the kernel tarball from `cdn.kernel.org` and the BusyBox binary
   from `busybox.net` once, and checks both against SHA-256 hashes pinned in
   the script on every run. The kernel's hash is the one kernel.org lists in
   `sha256sums.asc`; busybox.net lists none, so BusyBox's is the hash of the
   binary as first downloaded;
2. unpacks the kernel into `$ALEPH0_LINUX_WORK` (default
   `~/.cache/aleph0-linux`). That directory must be on a Linux filesystem:
   the kernel tree has file names that differ only in case, which a Windows
   drive under `/mnt` would merge;
3. writes the initramfs list (section 4);
4. merges `aleph0.config` onto `x86_64_defconfig` with the kernel's
   `scripts/kconfig/merge_config.sh`, then fails if any line of the fragment
   is missing from the final `.config`: Kconfig drops a value whose
   dependencies are unmet with only a warning. `merge_config.sh` also warns
   about a few of `x86_64_defconfig`'s own values, iptables options that
   now depend on `NETFILTER_XTABLES_LEGACY`, which it leaves off; those do
   not matter here;
5. builds `bzImage` and copies `linux.efi`, `System.map` and the final
   `.config` to `run/linux/`, which git ignores.

Later runs reuse the download and the build tree, so a change to `init` or the
fragment rebuilds only what depends on it.

WSL needs outbound network for the downloads and the packages. On the
development host, WSL's default NAT networking had none (no TCP connection
went through, not even to its gateway); `networkingMode=mirrored` under
`[wsl2]` in `%USERPROFILE%\.wslconfig`, then `wsl --shutdown`, fixed it.

## 3. Why the command line is built in

The EFI stub reads its command line from the load options its loader passes
(Linux `Documentation/admin-guide/efi-stub.rst`). Started as
`\EFI\BOOT\BOOTX64.EFI` by the firmware's boot manager, it gets none: the run
prints an empty `Command line:` first. So the fragment builds the line in:

```
CONFIG_CMDLINE_BOOL=y
CONFIG_CMDLINE="console=ttyS0,115200 earlycon=uart8250,io,0x3f8,115200 nokaslr"
CONFIG_CMDLINE_OVERRIDE=y
```

`CONFIG_CMDLINE_OVERRIDE` ignores whatever a boot entry passes, so the kernel
always runs with this line. One file then boots with no loader in between,
and it is the file #28 starts. The alternative, a kernel and an initramfs
file started from an EFI shell's `startup.nsh` with `initrd=`, adds a shell
binary to the boot path that Aleph0 would have to run virtualized as well.

- `console=ttyS0,115200` puts the console, and `/init`'s output, on COM1.
- `earlycon=uart8250,io,0x3f8,115200` prints from the start of the kernel,
  before the 8250 driver is up. Under Aleph0 that shows how far the kernel
  got.
- `nokaslr` keeps kernel addresses the same on every boot, so guest RIPs that
  Aleph0 prints can be looked up in the build's `System.map`. The EFI stub
  is what acts on it: it parses the built-in line too
  (`drivers/firmware/efi/libstub/x86-stub.c`), and then neither moves nor
  offsets the kernel. The kernel proper does not know the option and prints
  `Unknown kernel command line parameters "nokaslr", will be passed to user
  space.`, which is harmless. `/init` prints `_text` from `/proc/kallsyms`,
  which shows it worked: `ffffffff81000000`, the address in `System.map`.

## 4. The initramfs and `/init`

`build.sh` writes a `gen_init_cpio` list (the kernel's `usr/gen_init_cpio`
format) and points `CONFIG_INITRAMFS_SOURCE` at it:

```
dir /dev 0755 0 0
nod /dev/console 0600 0 0 c 5 1
dir /bin 0755 0 0
dir /proc 0755 0 0
dir /sys 0755 0 0
file /bin/busybox <work>/busybox-1.35.0 0755 0 0
file /init <work>/init 0755 0 0
```

`/dev/console` is a device node in the list, so the kernel can open a console
for `/init` before anything mounts `/dev`, and the build needs no root.

`/init` (`#!/bin/busybox sh`) mounts `/proc`, links BusyBox's applets into
`/bin`, mounts sysfs and devtmpfs, prints these lines, and starts a shell
with `exec setsid cttyhack sh`, which gives it `ttyS0` as its controlling
terminal:

| Line | Shows |
| --- | --- |
| `aleph0-linux: init` | userspace started |
| `aleph0-linux: nproc <n>` | the CPUs the kernel brought up |
| `aleph0-linux: cmdline <line>` | `/proc/cmdline` |
| `aleph0-linux: <address> T _text` | the kernel's base address, from `/proc/kallsyms` |
| `aleph0-linux: clocksource <name>` | the clocksource the kernel settled on |
| `aleph0-linux: flags : <flags>` | the `flags` line of `/proc/cpuinfo` |
| `aleph0-linux: iomem`, then `/proc/iomem` | RAM and device ranges |
| `aleph0-linux: uptime <s> <idle>` | `/proc/uptime`, when userspace got to the shell |
| `aleph0-linux: shell` | the shell starts next |

Every line ends in a newline: `read-serial.ps1` logs whole lines only
(`ReadLine`), so the shell's prompt alone never appears in the log. Kernel
lines carry their time since boot (`CONFIG_PRINTK_TIME`); `/init`'s do not.

## 5. Putting it on the test VM

`run-hyperv.ps1` takes three parameters for it:

- `-Kernel <path>` copies the image to `\EFI\aleph0\linux.efi` on the ESP,
  next to Aleph0's `\EFI\BOOT\BOOTX64.EFI`.
- `-WithoutAleph0` puts the kernel at `\EFI\BOOT\BOOTX64.EFI` instead of
  Aleph0, so the firmware boots it directly, and skips building Aleph0. It
  needs `-Kernel`, and refuses `-InjectNmi`, whose job waits for a line only
  Aleph0 prints. Nothing writes COM2 then, so the runner reads only COM1,
  and streams it to the console as well as `run\guest-serial.log`.
- `-ProcessorCount <n>` sets the vCPUs: 2 by default, 1 with `-InjectNmi`,
  which refuses any other count, since `Debug-VM` may deliver the NMI to any
  vCPU.

The checks run before the VM is touched. The baseline run:

```powershell
.\scripts\run-hyperv.ps1 -Kernel run\linux\linux.efi -WithoutAleph0 -ProcessorCount 1
```

The kernel never turns the VM off: it waits in the shell. Ctrl+C stops the
streaming, and `Stop-VM Aleph0Test -TurnOff` ends the run. Typing into the
shell needs a client that writes to the pipe: run with `-NoSerial` and
connect, for example, PuTTY to `\\.\pipe\aleph0-com1`
([SERIAL_LOGGING.md](SERIAL_LOGGING.md)).

## 6. The Hyper-V run

Two runs printed the same marker lines and device ranges; the RAM layout
differed. From the first:

```text
[    0.000000] Linux version 6.18.58 (root@DESKTOP-HSQ4ND5) (gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0, GNU ld (GNU Binutils for Ubuntu) 2.46) #3 SMP PREEMPT_DYNAMIC Sat Oct 24 16:45:20 EEST 2026
[    0.000000] Command line: 
[    0.000000] earlycon: uart8250 at I/O port 0x3f8 (options '115200')
[    0.000000] Hypervisor detected: Microsoft Hyper-V
[    0.000000] Hyper-V: LAPIC Timer Frequency: 0x30d40
[    0.000000] tsc: Detected 3187.199 MHz processor
[    0.130363] Kernel command line: console=ttyS0,115200 earlycon=uart8250,io,0x3f8,115200 nokaslr
[    0.175116] Using NULL legacy PIC
[    0.188886] Failed to register legacy timer interrupt
[    0.276364] PCI: System does not support PCI
[    0.336220] clocksource: Switched to clocksource tsc
[    0.356732] 00:00: ttyS0 at I/O 0x3f8 (irq = 4, base_baud = 115200) is a 16550A
[    0.358534] 00:01: ttyS1 at I/O 0x2f8 (irq = 3, base_baud = 115200) is a 16550A
[    0.426670] Run /init as init process
aleph0-linux: init
aleph0-linux: nproc 1
aleph0-linux: cmdline console=ttyS0,115200 earlycon=uart8250,io,0x3f8,115200 nokaslr
aleph0-linux: ffffffff81000000 T _text
aleph0-linux: clocksource tsc
aleph0-linux: iomem
00000000-00000fff : Reserved
00001000-0009ffff : System RAM
000c0000-000fffff : Reserved
  000f0000-000fffff : System ROM
00100000-7ff40fff : System RAM
  01000000-022a110f : Kernel code
  02400000-02b6afff : Kernel rodata
  02c00000-02ed75ff : Kernel data
  037c9000-039fffff : Kernel bss
7ffc5000-7ffd1fff : System RAM
7ffd2000-7fffafff : ACPI Tables
7fffb000-7fffefff : ACPI Non-volatile Storage
7ffff000-7fffffff : System RAM
fec00000-fec00fff : PNP0003:00
fee00000-fee00fff : PNP0003:00
aleph0-linux: uptime 0.63 0.00
aleph0-linux: shell
```

The second run had `Run /init as init process` at 0.428960 s and uptime
0.64 s, and its `/proc/iomem` left `0x7ee85000..0x7ee8bfff` out of System
RAM (`00100000-7ee84fff` and `7ee8c000-7ff40fff`). The firmware's own
allocations moved between the boots as well (`MEMATTR`, and 13680K against
18492K of boot-services memory freed): the RAM layout changes from boot to
boot, the device ranges do not.

The CPU flags, the same in both runs:

```text
fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology tsc_reliable nonstop_tsc cpuid aperfmperf tsc_known_freq pni pclmulqdq vmx ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch ssbd ibrs ibpb stibp ibrs_enhanced tpr_shadow ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves avx_vnni vnmi umip waitpkg gfni vaes vpclmulqdq rdpid movdiri movdir64b fsrm md_clear serialize ibt flush_l1d arch_capabilities
```

What the lines say:

- **Hyper-V.** The kernel detects it (`CONFIG_HYPERVISOR_GUEST`, with the
  VMBus drivers off) and takes the TSC and LAPIC timer frequencies from
  Hyper-V's synthetic MSRs (`HV_X64_MSR_TSC_FREQUENCY`, `0x40000022`, behind
  the `tsc_known_freq` flag; `HV_X64_MSR_APIC_FREQUENCY`, `0x40000023`, the
  `LAPIC Timer Frequency` line). It also writes
  `HV_X64_MSR_TSC_INVARIANT_CONTROL` (`0x40000118`) to expose the invariant
  TSC, and then marks the TSC reliable (`tsc_reliable`). Those MSRs lie in
  the range that gets a #GP under Aleph0 today; how the guest sees Hyper-V
  is #27.
- **Timer and clock.** The VM has no legacy PIC: the kernel's 8259 probe
  fails (`Using NULL legacy PIC`), so IRQ 0 cannot be requested (`Failed to
  register legacy timer interrupt`), and the kernel's Hyper-V code skips the
  IO-APIC timer check. With no legacy PIC and no HPET, its timer is the
  Local APIC's, and its clocksource ends up `tsc`. Whether a PIT answers at
  ports `0x40-0x43`, the run does not show.
- **Devices** (#20). `/proc/iomem` shows the IOAPIC at `0xfec00000` and the
  Local APIC at `0xfee00000`, and no other device range: the VM has no PCI
  bus (`PCI: System does not support PCI`), and without the VMBus drivers no
  VMBus window is claimed. `[mem 0x80000000-0xffffffff] available for PCI
  devices` names the gap above RAM. COM1 and COM2 are 16550A UARTs at
  `0x3f8` and `0x2f8`.
- **CPU features** (#25). The guest sees XSAVE with `xsaveopt`, `xsavec` and
  `xsaves`, `rdtscp`, `pcid` and `invpcid`, `fsgsbase`, `umip`, `waitpkg`,
  `smep` and `smap`, `x2apic` and `tsc_deadline_timer`, and, from nested
  virtualization, `vmx`, `ept` and `vpid`.
- **Time.** About 0.43 s of kernel time to `/init`, and 0.64 s at the shell.

## 7. What is not covered yet

- Starting this image under Aleph0, by returning to the boot manager or by
  LoadImage/StartImage of `\EFI\aleph0\linux.efi`: #28.
- A kernel built without Hyper-V guest support, for the "do not advertise
  Hyper-V" option: #27. `-Kernel` takes any image, so that is a different
  build, not a different runner.
- Mapping the ranges above into EPT: #20.
- More than one vCPU, a VMBus disk, Windows: after the first boot.
