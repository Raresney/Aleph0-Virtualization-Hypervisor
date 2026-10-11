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
a minimal guest, and resumes it after its first VMCALL exit; both exits are
reported over serial. An NMI that arrives while the guest runs is caught
and reinjected into the guest's own IDT. After the last exit it leaves VMX
operation and returns to firmware.
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
```

Unit tests cover the pure logic (RFLAGS decoding, control-value selection,
descriptor encoding/decoding) and run on the host. Nothing that executes VMX
instructions can be unit-tested; that still needs a boot under Hyper-V.

The tests live in `tests/unit/`, which mirrors `src/`: the tests for
`src/vmx/vmexit.rs` are in `tests/unit/vmx/vmexit.rs`. Each source file
includes its test file with `#[cfg(test)] #[path = "..."] mod tests;`, so the
tests stay a child module that can reach private items, and none of them is
compiled into the `.efi`.

## Run

**Hyper-V (VMX available):** from an elevated PowerShell session,

```powershell
.\scripts\run-hyperv.ps1
```

This turns off and reconfigures the `Aleph0Test` VM and recreates its ESP disk
under `run/`; keep nothing important there. It then streams the VM's COM1
serial output into the PowerShell window and `run\serial.log`
(`-NoSerial` skips this; `.\scripts\read-serial.ps1` reattaches later). VM-exit
diagnostics only appear there, not on the VM console. See
[docs/SERIAL_LOGGING.md](docs/SERIAL_LOGGING.md).

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
| `src/serial.rs` | COM1 serial logger usable without firmware |
| `src/vmx/cpuid.rs`, `msr.rs`, `cr.rs` | CPU feature, MSR and control-register access |
| `src/vmx/host_tables.rs`, `segment.rs` | Host GDT/TSS setup and segmentation state |
| `src/vmx/vmxon.rs` | Entering and leaving VMX root operation |
| `src/vmx/guest.rs`, `paging.rs` | Guest code, stack and IDT pages; the page-table walk that checks them |
| `src/vmx/guest_state.rs` | Guest-state VMCS fields, copied from the host CPU |
| `src/vmx/vmcs/mod.rs`, `fields.rs`, `launch.rs` | VMCS lifecycle, field access, controls and host state; every field encoding; the launch stub that returns when the guest stops |
| `src/vmx/vmexit.rs`, `exit_decision.rs` | VM-exit stack, entry stub (with the VMRESUME path) and exit handler; the pure decision for each exit (VMCALLs, NMI reinjection) |
| `tests/unit/` | Host unit tests, mirroring `src/` (see [Test](#test)) |
| `scripts/run.ps1` | Build and boot under QEMU + OVMF (no VMX) |
| `scripts/run-hyperv.ps1`, `scripts/read-serial.ps1` | Hyper-V test VM runner and serial reader (Windows PowerShell) |
| `docs/` | Background explanations: [SERIAL_LOGGING.md](docs/SERIAL_LOGGING.md) (serial logger, beginner walkthrough), [PORT_IO.md](docs/PORT_IO.md) (`in`/`out` and the I/O port space), [PAGE_TABLE_WALK.md](docs/PAGE_TABLE_WALK.md) (page tables and how Aleph0 walks them), [CLEAN_STOP.md](docs/CLEAN_STOP.md) (stopping the guest, leaving VMX and returning to firmware) |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
