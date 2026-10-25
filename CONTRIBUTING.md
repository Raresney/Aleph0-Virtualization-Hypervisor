# Contributing to Aleph0

Aleph0 is a research hypervisor: low-level, mostly `unsafe` Rust that runs in
VMX root operation, where a mistake hangs or resets the machine instead of
printing an error. These guidelines keep changes small, explained and
verified. [README.md](README.md) covers building and running;
[ROADMAP.md](ROADMAP.md) says what is done and what comes next.

## Before you start

- Check [ROADMAP.md](ROADMAP.md). Work that follows the next open item is the
  easiest to review and merge.
- For anything larger than a fix or a small refactor (a new exit, a change to
  the VMCS setup, the EPT layout or the exit-handler flow), open an issue first
  and describe the approach.
- Read the `docs/` page for the area you touch. Each one explains the
  mechanism the code implements, often with the Intel SDM references the code
  relies on.

## Setup

- Rust stable, edition 2024. `rust-toolchain.toml` installs the
  `x86_64-unknown-uefi` target.
- The host tests need a host target. `cargo test-host` is an alias for
  `cargo test --target x86_64-pc-windows-msvc`; on Linux or macOS, pass your
  own host triple instead, for example
  `cargo test --target x86_64-unknown-linux-gnu`.
- Running the hypervisor itself needs an Intel CPU with VT-x and a VMM that
  exposes nested virtualization. Hyper-V is the tested path (see
  [Verifying on Hyper-V](#verifying-on-hyper-v)).

## Checks before every pull request

```powershell
cargo build                                            # the .efi
cargo test-host                                        # host unit tests
cargo fmt --check                                      # rustfmt.toml: 120 columns
cargo clippy                                           # lints for the UEFI build
cargo clippy --features test-guest                     # lints for the regression mode
cargo clippy --target x86_64-pc-windows-msvc --tests   # lints for the tests
```

All of them must pass without warnings. Use your host triple instead of
`x86_64-pc-windows-msvc` on Linux or macOS.

## Code conventions

### `unsafe`

- `clippy::undocumented_unsafe_blocks` is on. Every `unsafe` block has a
  `// SAFETY:` comment that says why it is sound here, not what it does.
- Every `unsafe fn` has a `# Safety` section listing what its callers must
  guarantee (for example "VMX root operation, with the guest's VMCS current").
- Keep `unsafe` blocks as small as the operation that needs them.

### Separate deciding from doing

Code that executes VMX instructions or touches hardware cannot be unit-tested.
Keep it thin, and put the logic in pure functions that can be:

- The exit handler reads, judges and applies (`src/vmx/vmexit/handler.rs`).
  The judgement, `exit_decision::decide`, is a pure function of the exit
  fields and the handler's state, and is host-tested.
- Decoding and encoding of raw values (RFLAGS, descriptors, control MSRs, EPT
  entries, interruption info) live in pure functions or types with tests.

A new exit or feature should follow the same split: a pure decision with host
tests, and a small `unsafe` part that only carries it out.

### Types and constants

- Give raw hardware values their own types (`EptEntry`, `Eptp`,
  `InterruptionInfo`, `ControlCapability`, ...) instead of passing `u64`
  around, and make invalid combinations impossible to construct where it is
  practical (for example `EptEntry<L>` has only the constructors valid at
  level `L`).
- Define each architectural constant once, with a doc comment naming the bit,
  field or MSR and what it means. Cite the Intel SDM when the reason for a
  check is not obvious.

### Exit context

The VM-exit handler runs with interrupts off, on its own stack, and must keep
working after `ExitBootServices`. In code reachable from it:

- no firmware calls: print with `serial_println!` (or `log!`, which skips the
  console once the handler has set the `VmExit` output phase), never with
  `uefi::println!`;
- no allocation: the crate has no allocator, and the exit handler must not
  call UEFI to get memory;
- no panics on guest-controlled input: an unexpected exit stops the guest
  through the normal stop path instead.

### Style

- `rustfmt` with the repository's `rustfmt.toml` (120 columns).
- Comments explain why, and the hardware behaviour the code depends on. Match
  the comment density of the surrounding code.
- Prefer clear names over abbreviations, except for the SDM's own names
  (`VMCS`, `EPTP`, `GPA`, `CPL`, ...).

## Tests

Unit tests live in `tests/unit/`, which mirrors `src/`: the tests for
`src/vmx/paging.rs` are in `tests/unit/vmx/paging.rs`. Each source file includes its
tests with

```rust
#[cfg(test)]
#[path = "../../tests/unit/vmx/ept.rs"]
mod tests;
```

so the tests are a child module that can reach private items, and none of
them ends up in the `.efi`.

Add tests for every pure function you add or change. Name tests after the
behaviour they check (`map_end_past_one_pdpt_is_refused`), not after the
function.

## Verifying on Hyper-V

Host tests cannot prove that VM entry succeeds or that an exit behaves as
planned. A change that affects what runs in VMX operation needs a boot:

```powershell
# From an elevated PowerShell session.
.\scripts\run-hyperv.ps1 -ProcessorCount 1   # the firmware, virtualized in place
.\scripts\run-hyperv.ps1 -TestGuest          # the test guest: the regression mode
.\scripts\run-hyperv.ps1 -InjectNmi          # the test guest, with NMI reinjection
```

A default build virtualizes the running firmware: Aleph0 returns to it in
VMX non-root operation, and it runs until an exit Aleph0 does not handle,
which halts after the stop's report. The test guest (Cargo feature
`test-guest`) runs a fixed script, then teardown, and returns `SUCCESS`, so
its exits can be compared run by run. A change to VM exits is checked in
both modes.

VM-exit diagnostics appear only on serial (the PowerShell window and
`run\serial.log`). Put the relevant serial lines in the pull request, and
record what was observed in [ROADMAP.md](ROADMAP.md) the way existing entries
do: the values printed, not just "it worked".

QEMU with OVMF (`.\scripts\run.ps1`) has no nested VMX. It only exercises the
code that runs before VMXON; say so if that is all a change was tested with.

## Documentation

Update the documentation in the same pull request as the code:

- [README.md](README.md): the summary of what Aleph0 does and the Layout table,
  when files or behaviour change;
- [ROADMAP.md](ROADMAP.md): check items off, with what was observed;
- `docs/`: the page for the mechanism you changed, or a new page for a new
  mechanism, linked from the README's Layout table.

## Commits

- One logical change per commit. Keep behaviour-preserving refactors in
  separate commits (or pull requests) from behaviour changes.
- Subject line in the imperative, capitalized, without a trailing period, for
  example `Emulate RDMSR and WRMSR of intercepted MSRs`.
- Use the body, when needed, for why the change is made and anything a reviewer
  would otherwise have to work out.

## Pull requests

- Branch from `master` and keep the pull request focused on one change.
- In the description, say what changed, why, and how it was verified: which of
  the checks above ran, and the serial output of a Hyper-V boot when the change
  runs in VMX operation.
- Address review comments with new commits; do not rewrite history that a
  reviewer has already seen.

## Scope

The end goal is anti-cheat research (see [ROADMAP.md](ROADMAP.md), section 6).
Contributions must stay within that: research only, no deployment against
third-party services, and nothing whose purpose is to evade or defeat
anti-cheat or other security software.

## License

Aleph0 is dual-licensed under MIT or Apache-2.0, at your option. Unless you
explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
