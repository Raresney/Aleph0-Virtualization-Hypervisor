# Aleph0 Virtualization Hypervisor

An Intel VT-x hypervisor written in Rust and booted as a UEFI application.
Aleph0 is being built to stay resident after `ExitBootServices` and run an
operating system as its guest, with EPT memory isolation and multiple vCPUs.
The end goal is research into game anti-cheat: running below the guest OS,
the hypervisor can watch and protect a game's memory where kernel-mode cheats
cannot reach. The project is also a study of AI-driven development in
low-level `unsafe` Rust, and of AI-assisted reverse-engineering tooling for
the analysis the anti-cheat needs.

It currently enters VMX root operation, fills in a complete VMCS, launches
a minimal guest, and resumes it after its first VMCALL exit; every exit is
reported over serial. Guest memory goes through EPT: an identity map of all
memory, with the memory types the MTRRs give it and one guest page
read-only, so the guest's write to it exits to Aleph0, which grants the
write and retries it. The guest also executes CPUID,
RDMSR/WRMSR and IN/OUT, which Aleph0 emulates by passthrough, with MSR and I/O
bitmaps limiting which MSRs and ports exit. An NMI that arrives while
the guest runs is caught and reinjected into the guest's own IDT. After the
last exit it leaves VMX operation and returns to firmware.
See [ROADMAP.md](ROADMAP.md) for what has been verified and what comes next.

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

All four pass without warnings. `clippy::undocumented_unsafe_blocks` is on,
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
test-only switches in `Cargo.toml` (`host-fault-test`, `host-nmi-test`; see
[docs/HOST_ENVIRONMENT.md](docs/HOST_ENVIRONMENT.md) section 8).

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
| `src/vmx/ept.rs` | EPT: support check, identity map with the guest's data page read-only, write grant and INVEPT |
| `src/vmx/mtrr.rs` | The MTRRs: reading and checking them, and the memory type of each address, which the EPT entries copy |
| `src/vmx/exit_bitmaps.rs` | The MSR and I/O bitmaps: which MSRs and ports exit, and their pages |
| `src/vmx/guest_state.rs` | Guest-state VMCS fields, copied from the host CPU |
| `src/vmx/vmcs/mod.rs`, `fields.rs`, `launch.rs` | VMCS lifecycle, field access, controls and host state; every field encoding; the launch stub that returns when the guest stops |
| `src/vmx/vmexit/` | VM-exit stack and entry stub with the VMRESUME path (`mod.rs`); the exit handler, as read, judge and apply (`handler.rs`); its report lines (`report.rs`) |
| `src/vmx/exit_decision/` | The pure decision for each exit: shared exit types and the dispatch on the exit reason (`mod.rs`), and one handler per reason; the instructions Aleph0 executes for any guest (CPUID, RDMSR/WRMSR, IN/OUT) are in `emulation.rs`, the test guest's own exits (EPT write, VMCALLs, NMI reinjection) in `scenario.rs` |
| `tests/unit/` | Host unit tests, mirroring `src/` (see [Test](#test)) |
| `scripts/run.ps1` | Build and boot under QEMU + OVMF (no VMX) |
| `scripts/run-hyperv.ps1`, `scripts/read-serial.ps1` | Hyper-V test VM runner and serial reader (Windows PowerShell) |
| `docs/` | Background explanations: [SERIAL_LOGGING.md](docs/SERIAL_LOGGING.md) (serial logger, beginner walkthrough), [PORT_IO.md](docs/PORT_IO.md) (`in`/`out` and the I/O port space), [PAGE_TABLE_WALK.md](docs/PAGE_TABLE_WALK.md) (page tables and how Aleph0 walks them), [CLEAN_STOP.md](docs/CLEAN_STOP.md) (stopping the guest, leaving VMX and returning to firmware), [NMI.md](docs/NMI.md) (catching NMIs in the guest and reinjecting them), [EPT.md](docs/EPT.md) (the second translation stage, the identity map and the intentional EPT violation), [MTRR.md](docs/MTRR.md) (memory types, the MTRRs and how EPT entries get them), [EMULATED_EXITS.md](docs/EMULATED_EXITS.md) (CPUID, MSR and port-I/O exits, the bitmaps, passthrough emulation), [HOST_ENVIRONMENT.md](docs/HOST_ENVIRONMENT.md) (the page tables, GDT, TSS and IDT VM exits load, and NMIs in root operation) |

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
