# Aleph0 Virtualization Hypervisor

[![CI](https://github.com/alephc0rporation/Aleph0-Virtualization-Hypervisor/actions/workflows/ci.yml/badge.svg)](https://github.com/alephc0rporation/Aleph0-Virtualization-Hypervisor/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](rust-toolchain.toml)
[![Target: x86_64-unknown-uefi](https://img.shields.io/badge/target-x86__64--unknown--uefi-informational.svg)](.cargo/config.toml)

An Intel VT-x hypervisor written in Rust and booted as a UEFI application.
Aleph0 is being built to stay resident after `ExitBootServices` and run an
operating system as its guest, with EPT memory isolation and multiple vCPUs.
The end goal is research into game anti-cheat: running below the guest OS,
the hypervisor can watch and protect a game's memory where kernel-mode cheats
cannot reach. The project is also a study of AI-driven development in
low-level `unsafe` Rust, and of AI-assisted reverse-engineering tooling for
the analysis the anti-cheat needs.

## Status

Verified on Hyper-V with nested virtualization:

- [x] Enters VMX root operation and fills in a complete VMCS
- [x] Runs root operation on its own page tables, GDT, TSS and IDT
- [x] Launches a minimal guest and resumes it with VMRESUME after each exit
- [x] EPT identity map with the memory types the MTRRs give to RAM, and UC for
      MMIO and everything else; a read-only guest page whose write exits to
      Aleph0, which grants the write and retries it
- [x] Keeps the guest's MTRR writes in a copy, never the CPU's, with the #GP
      of a value the CPU would refuse, and gives EPT the types the copy gives
      (the #GP host-tested only)
- [x] Emulates CPUID, RDMSR/WRMSR and IN/OUT by passthrough, with MSR and I/O
      bitmaps limiting which MSRs and ports exit
- [x] Catches an NMI that arrives while the guest runs and reinjects it into
      the guest's own IDT
- [x] Reports every exit over serial, then leaves VMX operation and returns to
      firmware
- [ ] Stay resident after `ExitBootServices`
- [ ] Hide Aleph0's own memory from the guest through EPT
- [ ] An OS guest on multiple vCPUs
- [ ] Anti-cheat research: guest memory introspection, EPT protection and
      split views, watching privileged changes

See [ROADMAP.md](ROADMAP.md) for the details of each step and what comes next.

## What it looks like

An excerpt of Aleph0's serial output (COM2) from a Hyper-V run, with the
`[Aleph0 Virtualization Hypervisor]` prefix trimmed from each line:

```text
Entered VMX root operation.
Launching the guest with VMLAUNCH; its VM exits are reported on serial only.
VM exit #1: reason=10 (CPUID)
VM exit #1: CPUID leaf=0x1 subleaf=0x0 -> eax=0x00090672 ebx=0x00020800 ecx=0xf7fa3203 edx=0x1f8bfbff (processor ecx=0xf7fa3223); resuming at rip=0x000000007ead4009.
...
VM exit #11: reason=48 (EPT violation)
VM exit #11: EPT violation at GPA 0x000000007ead5000 (linear 0x000000007ead5000): write; page R=1 W=0 X=0.
VM exit #11: write to the protected data page: write granted (W=1), INVEPT single-context; retrying the write at rip=0x000000007ead406c.
...
VM exit #13: reason=18 (VMCALL)
VM exit #13: expected VMCALL (rax=0xa1e1); all 2 planned VMCALLs handled; no NMI arrived.
VM exit #13: emulated exits: cpuid=1 rdmsr=2 wrmsr=2 in=2 out=2 hlt=1.
VM exit #13: stopping the guest; returning to bring-up.
...
Teardown: CR4.VMXE=0 firmware CR3 restored=true firmware GDTR/IDTR restored=true IF=1.
Guest finished after 13 VM exits; VMX operation left.
Returning to firmware with SUCCESS.
```

## Requirements

- Rust stable (edition 2024, Rust 1.85+). `rust-toolchain.toml` installs the
  `x86_64-unknown-uefi` target automatically.
- An Intel CPU with VT-x. VMX instructions only run under a VMM that exposes
  nested virtualization (Hyper-V is the tested path).

## Build

```powershell
cargo build            # produces target\x86_64-unknown-uefi\debug\aleph0hypervisor.efi
```

`.cargo/config.toml` makes the UEFI target the default.

## Test

```powershell
cargo test-host        # alias for: cargo test --target x86_64-pc-windows-msvc
cargo fmt --check      # formatting (rustfmt.toml: 120 columns)
cargo clippy           # lints for the UEFI build
cargo clippy --target x86_64-pc-windows-msvc --tests   # lints for the tests
```

All four pass without warnings, and CI runs them with `cargo build` on every
push to `master` and every pull request. `clippy::undocumented_unsafe_blocks` is on,
so every `unsafe` block needs a `// SAFETY:` comment saying why it is sound,
and every `unsafe fn` has a `# Safety` section for its callers.

Unit tests cover the pure logic (RFLAGS decoding, control-value selection,
descriptor encoding/decoding) and run on the host. Nothing that executes VMX
instructions can be unit-tested; that still needs a boot under Hyper-V.

The tests live in `tests/unit/`, which mirrors `src/`: the tests for
`src/vmx/vmexit/handler.rs` are in `tests/unit/vmx/vmexit/handler.rs`. Each source file
includes its test file with `#[cfg(test)] #[path = "..."] mod tests;`, so the
tests stay a child module that can reach private items, and none of them is
compiled into the `.efi`.

## Run

**Hyper-V (VMX available):** from an elevated PowerShell session,

```powershell
.\scripts\run-hyperv.ps1
```

This turns off and reconfigures the `Aleph0Test` VM and recreates its ESP disk
under `run/`; keep nothing important there. It then streams Aleph0's serial
output (COM2) into the PowerShell window and `run\serial.log`, and saves the
guest's COM1 to `run\guest-serial.log`
(`-NoSerial` skips this; `.\scripts\read-serial.ps1` reattaches later). VM-exit
diagnostics only appear there, not on the VM console. See
[docs/SERIAL_LOGGING.md](docs/SERIAL_LOGGING.md). `-InjectNmi` sends the
guest an NMI after its first VMCALL, and `-Features` builds with the
test-only switches in `Cargo.toml`: `host-fault-test` and `host-nmi-test` (see
[docs/HOST_ENVIRONMENT.md](docs/HOST_ENVIRONMENT.md) section 8),
`unexpected-exit-test` and `trace-exits` (see
[docs/SERIAL_LOGGING.md](docs/SERIAL_LOGGING.md)). `-ProcessorCount` sets the
vCPUs (2 by default, 1 with `-InjectNmi`).

**The Linux target:** `scripts/linux/build.sh` (Linux or WSL) builds the
kernel that is to boot as Aleph0's guest, as one EFI file in `run\linux\`.
`-Kernel run\linux\linux.efi` puts it on the ESP next to Aleph0, and
`-WithoutAleph0` boots it in Aleph0's place, streaming its console (COM1). See
[docs/LINUX_GUEST.md](docs/LINUX_GUEST.md).

**QEMU + OVMF (no VMX):** put `OVMF_CODE.fd` and `OVMF_VARS.fd` from
[rust-osdev/ovmf-prebuilt](https://github.com/rust-osdev/ovmf-prebuilt) in
`ovmf/`, then run `.\scripts\run.ps1`. Without nested VMX this only exercises the
diagnostics that run before VMXON.

## Layout

| Path | Purpose |
| --- | --- |
| `src/main.rs` | UEFI entry point and the `log!` macro |
| `src/bring_up/` | The bring-up sequence (`mod.rs`), its errors (`error.rs`), status lines (`report.rs`) and the return to firmware (`teardown.rs`) |
| `src/output.rs` | Output phases and the firmware-free panic handler |
| `src/serial.rs` | Serial logger usable without firmware, on COM2 (`SerialPort`); COM1 is left to the guest |
| `src/port.rs` | in/out of 1, 2 and 4 bytes, for the serial driver and the exit handler |
| `src/vmx/cpuid.rs`, `msr.rs`, `cr.rs` | CPU feature, MSR and control-register access |
| `src/vmx/context_tables.rs`, `segment.rs` | The GDT copy with a TSS that bring-up and the test guest run on, and the TSS layout; gate and descriptor encoding, segmentation state |
| `src/vmx/host/` | What VMX root operation runs on: Aleph0's page tables (`page_tables.rs`), GDT (`gdt.rs`), IDT with interrupt stacks (`idt.rs`) and the NMI and fault handlers (`handlers.rs`) |
| `src/vmx/vmxon.rs` | Entering and leaving VMX root operation |
| `src/vmx/region.rs` | The revision-stamped 4 KiB page that both the VMXON region and the VMCS are |
| `src/vmx/guest.rs`, `paging.rs` | Guest code, data, stack and IDT pages; the page-table walk that checks them |
| `src/vmx/ept.rs` | EPT: support check, identity map with the guest's data page read-only, write grant and INVEPT, and the memory types that follow the guest's MTRRs, with spare PTs |
| `src/vmx/mtrr/` | The MTRRs: decoding them and the memory type of each address, which the EPT entries copy (`mod.rs`); the MTRR MSRs a CPU has, the values WRMSR refuses, reading them, and the guest's copy (`registers.rs`) |
| `src/vmx/exit_bitmaps.rs` | The MSR and I/O bitmaps: which MSRs and ports exit, and their pages |
| `src/vmx/guest_state.rs` | Guest-state VMCS fields, copied from the host CPU |
| `src/vmx/vmcs/mod.rs`, `fields.rs`, `launch.rs` | VMCS lifecycle, field access, controls and host state; every field encoding; the launch stub that returns when the guest stops |
| `src/vmx/vmexit/` | VM-exit stack and entry stub with the VMRESUME path (`mod.rs`); the exit handler, as read, judge, carry out and report (`handler.rs`); the guest's copy of its MTRRs (`guest_mtrrs.rs`); its report lines (`report.rs`), how much of each exit they print (`policy.rs`), and what every stop adds: the guest's state and registers (`dump.rs`) and the last 64 exits (`history.rs`) |
| `src/vmx/exit_decision/` | The pure decision for each exit: shared exit types and the dispatch on the exit reason (`mod.rs`), and one handler per reason; the instructions Aleph0 executes for any guest (CPUID, RDMSR/WRMSR, IN/OUT) and the routing of the guest's MTRR MSRs to its copy are in `emulation.rs`, the test guest's own exits (EPT write, VMCALLs, NMI reinjection) in `scenario.rs` |
| `tests/unit/` | Host unit tests, mirroring `src/` (see [Test](#test)) |
| `scripts/run.ps1` | Build and boot under QEMU + OVMF (no VMX) |
| `scripts/run-hyperv.ps1`, `scripts/read-serial.ps1` | Hyper-V test VM runner and serial reader (Windows PowerShell) |
| `scripts/linux/` | The Linux target's build (`build.sh`, bash for Linux or WSL), its kernel configuration fragment (`aleph0.config`) and its initramfs's `/init` (see [docs/LINUX_GUEST.md](docs/LINUX_GUEST.md)) |
| `docs/` | Background explanations (see [Documentation](#documentation)) |

## Documentation

Each page explains the mechanism the code implements, with the Intel SDM
references it relies on:

- [SERIAL_LOGGING.md](docs/SERIAL_LOGGING.md): the serial logger, a beginner walkthrough
- [PORT_IO.md](docs/PORT_IO.md): `in`/`out` and the I/O port space
- [PAGE_TABLE_WALK.md](docs/PAGE_TABLE_WALK.md): page tables and how Aleph0 walks them
- [HOST_ENVIRONMENT.md](docs/HOST_ENVIRONMENT.md): the page tables, GDT, TSS and IDT that VM exits load, and NMIs in root operation
- [EPT.md](docs/EPT.md): the second translation stage, the identity map and the intentional EPT violation
- [MTRR.md](docs/MTRR.md): memory types, the MTRRs, how EPT entries get them, and the guest's copy of its MTRRs
- [EMULATED_EXITS.md](docs/EMULATED_EXITS.md): CPUID, MSR and port-I/O exits, the bitmaps, passthrough emulation
- [NMI.md](docs/NMI.md): catching NMIs in the guest and reinjecting them
- [CLEAN_STOP.md](docs/CLEAN_STOP.md): stopping the guest, leaving VMX and returning to firmware
- [LINUX_GUEST.md](docs/LINUX_GUEST.md): the Linux target, how it is built and staged, and its boot without Aleph0

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md): the checks every pull request must
pass, the code conventions, and how to verify a change on Hyper-V.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
