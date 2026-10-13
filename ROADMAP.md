# Aleph0 hypervisor roadmap

Aleph0 is an Intel VT-x hypervisor booted as a UEFI application. This roadmap tracks it from the first VM entry to running an operating system as its guest, with EPT memory isolation, multiple vCPUs, and Aleph0 resident after `ExitBootServices`. Each milestone ends in a result that is verified on Hyper-V before the next piece is built. EPT is enabled with an identity map; the immediate goals are the rest of section 5: the exits a larger guest needs, EPT memory types from the MTRRs, and hiding Aleph0's own memory from the guest.

## Current state

- [x] Build a `x86_64-unknown-uefi` application with `cargo build`.
- [x] Boot the EFI application with the Hyper-V Gen 2 runner (`scripts/run-hyperv.ps1`); nested virtualization exposes VMX. The runner requires an elevated PowerShell session.
- [x] Check CPUID VMX support and firmware's `IA32_FEATURE_CONTROL` settings.
- [x] Set `CR4.VMXE`, apply the VMX CR0/CR4 fixed bits, allocate a VMXON region, and enter VMX root operation.
- [x] Allocate and load a VMCS; verify a `VMWRITE`/`VMREAD` round trip.
- [x] Read and print current selectors, descriptor-table registers, and FS/GS/TR bases.
- [x] Establish a usable host task register. The tested Hyper-V boot reported a nonzero `TR`; activation checks GDTR, TR, and the decoded TSS base against the prepared values.
- [x] Discover VMX control MSRs, select legal control values, and write/read back the four VMCS control fields.
- [x] Write/read back host selectors, CRs, segment/table bases, SYSENTER state, and `HOST_RSP`/`HOST_RIP`. The Hyper-V run reported host PAT and EFER load controls both false, so those conditional fields were skipped.
- [x] Allocate a dedicated four-page VM-exit stack and compile an inactive entry stub that saves general-purpose registers and calls a non-returning Rust handler. Since section 4 the handler returns 0 to resume the guest, and the stub restores the registers and executes VMRESUME; to stop the guest it returns a stop value, and the stub jumps back into `vmcs::launch`.
- [x] Add a firmware-independent COM1 serial logger and stream it from the Hyper-V VM to the host console and `run\serial.log` (see section 0).
- [x] Replace the `uefi` panic handler with one that needs no firmware, and gate console output by an output phase (see section 0b).

- [x] Launch a minimal guest with `VMLAUNCH` and observe its first VM exit (`VMCALL`, reason 18, marker `0xa1e0` in guest RAX) over serial (see section 3).

- [x] Resume the guest with `VMRESUME` after its first exit and recognise its second `VMCALL` exit (see section 4).

- [x] Stop the guest after its last planned exit, leave VMX operation (`VMCLEAR`, `VMXOFF`, CR0/CR4 restored), restore the firmware's GDTR, IDTR and interrupt flag, and return from the EFI application to firmware (see section 4).

- [x] Catch NMIs that arrive while the guest runs (NMI exiting, virtual NMIs) and reinject them into the guest's own IDT, with NMI-window exiting when the guest blocks NMIs (see section 4).

- [x] Enable EPT with an identity map of all memory, make the guest's data page read-only, and handle the guest's write to it: an intentional EPT violation after which Aleph0 grants write, runs INVEPT and retries the write (see section 5 and [docs/EPT.md](docs/EPT.md)).

There is no OS boot yet.

**Next:** section 5: the necessary exits (CPUID, I/O) toward a larger guest, and before an OS guest, EPT memory types from the MTRRs and hiding Aleph0's own pages through EPT. EPT is confirmed on Hyper-V.

## 0. Debug output that works without firmware

`uefi::println!` calls the firmware console, which is unsafe in the VM-exit handler (interrupts off, arbitrary firmware state) and gone after `ExitBootServices`. Serial output drives the UART directly with `in`/`out`, so it works in both. Background and usage: [docs/SERIAL_LOGGING.md](docs/SERIAL_LOGGING.md).

- [x] Drive the 16550 UART at COM1 (`0x3F8`) from `src/serial.rs`: 115200 8N1, polled, no interrupts. Probe with loopback before enabling output, and bound every wait so a missing UART cannot hang the hypervisor.
- [x] Provide `serial_print!`/`serial_println!` through `core::fmt` with no allocation, for use in exit context.
- [x] Route bring-up messages through `log!`, which writes each line to both the firmware console and COM1.
- [x] Attach COM1 to `\\.\pipe\aleph0-com1` in `scripts/run-hyperv.ps1` and stream it with `scripts/read-serial.ps1`, which also saves `run\serial.log`. The reader was tested against a local pipe server, not yet against Hyper-V.
- [x] Confirm on Hyper-V: the console prints `Serial output enabled on COM1`, and the PowerShell window and `run\serial.log` show the same bring-up lines as the VM console.

**Checkpoint:** A Hyper-V run produces a `run\serial.log` that matches the VM console. Only then rely on serial as the observation path for the first VM exit.

### 0b. Output in exit context and after `ExitBootServices`

After `ExitBootServices` the OS runs as Aleph0's guest, Aleph0 only runs during VM exits, and serial is its only output. Facts this plan is based on:

- `uefi::println!` (uefi 0.40, `helpers/println.rs`) checks `boot::are_boot_services_active()`. After `ExitBootServices` it silently prints nothing. Before it, the check passes, so a call from the VM-exit handler **would** call the firmware console.
- The `uefi` crate's panic handler (`panic_handler` feature) calls that `println!`, then `boot::stall` and `runtime::reset`: three firmware calls. A panic in the exit handler therefore enters firmware from exit context, and after `ExitBootServices` the panic message is lost.
- The OS will want COM1 too: Linux probes `ttyS0`, including its own loopback test, and Windows may use COM1 for debugging. Unarbitrated sharing loses or interleaves output.
- Under Hyper-V every serial byte is itself a VM exit to Hyper-V, so printing on every guest exit slows the guest dramatically.

Before the first `VMLAUNCH` (section 3):

- [x] Replace the `uefi` panic handler with Aleph0's own and drop the crate's `panic_handler` feature. Always print the panic over serial, print on the console only in ordinary boot-services context, then halt with `cli; hlt`. No `stall`, no `runtime::reset`, no other firmware calls. Done in `src/output.rs`; a recursion guard halts on a nested panic. On Hyper-V a test panic in `main` printed on the console and in `run\serial.log`, and the VM stayed halted instead of resetting.
- [x] Track the output phase in one global (boot services, inside the VM-exit handler, runtime after `ExitBootServices`). `log!` writes to the console only in the boot-services phase and to serial in every phase. `output::Phase`; `vmexit_handler` sets `VmExit` first. On Hyper-V a panic after setting `VmExit` from `main` reached `run\serial.log` only, not the console, and the VM stayed halted. A panic in a real exit is first exercised at `VMLAUNCH`.

At the `ExitBootServices` milestone (section 5):

- [ ] Make the serial port base a parameter instead of the fixed `COM1`. Send hypervisor output to COM2 (`0x2F8`) and leave COM1 to the guest OS, without interception at first. In `scripts/run-hyperv.ps1`, attach COM2 to `\\.\pipe\aleph0-com2` and point `scripts/read-serial.ps1` at it.
- [ ] Switch the phase to runtime immediately after `ExitBootServices`. Ideally make the console unreachable from runtime code, so a mistake fails to compile rather than silently printing nothing.
- [ ] Keep the logging code and its state (`serial.rs` statics such as `READY`) in memory the OS will not reclaim. This is part of the persistence item in section 5, not a separate mechanism.

At multiple vCPUs (section 5):

- [ ] Serialize output per line, not per byte, with a spinlock, and prefix each line with the CPU number (`[cpu2] VM exit: ...`). Never hold the lock across `VMRESUME`. The panic path uses a try-lock and writes anyway if the lock is held, so an NMI or a panic cannot deadlock on it.

When guest exits become frequent (OS guest):

- [ ] Add log levels (error, warn, info, trace; trace off by default) and rate-limit repeated messages, for example "CPUID exit x1000".
- [ ] Optionally keep an in-memory ring buffer of recent events and send it over serial only on panic or when a guest tool asks for it with `VMCALL`.

At the virtual-device milestone (section 5):

- [ ] Intercept COM1 with I/O bitmaps (exit reason 30). Either hide it (reads return `0xFF`, writes ignored) or emulate a 16550 for the guest and forward its output tagged `[guest]`. See [docs/PORT_IO.md](docs/PORT_IO.md), section 7.

**Checkpoint:** A deliberate panic inside the VM-exit handler prints its message over serial and halts without any firmware call. After `ExitBootServices`, hypervisor lines arrive on COM2 while the guest OS uses COM1 undisturbed.

## 1. Establish a host TSS

- [x] Allocate a long-lived 64-bit TSS and a GDT that preserves the descriptors used by the current CS/SS and other active selectors; append a present 16-byte, 64-bit available-TSS descriptor.
- [x] Load that GDT and use `LTR` with its TSS selector. Keep the GDT and TSS alive while the CPU uses them; do not modify the firmware's GDT in place.
- [x] Re-read `STR`, GDTR, and the TSS base. Confirm `TR` is nonzero and its descriptor resolves to the allocated TSS before copying this state into the VMCS.
- [x] Check firmware interactions on the current boot path: after VMXON, the VMCS self-test, and UEFI calls, GDTR, TR, TSS base, and IDTR still match the activated state.

**Checkpoint:** The reported Hyper-V boot had no failures and printed a nonzero TR selector; activation verified its descriptor's base against the allocated TSS, and the post-VMX check reported the tables preserved. No `VMLAUNCH` yet. Recheck if new firmware call paths are added.

## 2. Prepare a minimal VMCS

- [x] Read `IA32_VMX_BASIC` and check bit 55. Read the true-control MSRs if available, otherwise the ordinary control MSRs, for pin-based, primary processor-based, VM-exit, and VM-entry controls. Print each MSR's low and high 32-bit halves. The Hyper-V boot printed all four values without faulting.
- [x] Derive legal values from those MSRs: the low halves specify bits that must be 1, and the high halves specify bits allowed to be 1. Reject requested features the CPU cannot enable. Write the four controls to the VMCS and read them back. A successful `VMWRITE`/`VMREAD` proves storage, not that VM entry will succeed.
- [x] Add a guest-memory owner (for example, `src/vmx/guest.rs`) that allocates and retains separate guest code and guest stack pages. Start with tiny guest code whose first test instruction is `VMCALL`; keep both pages alive for as long as the CPU stays in VMX operation. `GuestMemory` copies the guest code (since section 4: `mov eax, GUEST_MARKER; vmcall`, a wait loop for an NMI, `inc eax; vmcall`, and an NMI handler) from a `global_asm!` block into a `LOADER_CODE` page (firmware may map `LOADER_DATA` no-execute) and allocates a `LOADER_DATA` stack page and, since section 4, a `LOADER_DATA` guest IDT page with one gate at vector 2. Since section 5 the code page is a two-page `LOADER_CODE` allocation whose second page is the guest's data page, which EPT maps read-only (see [docs/EPT.md](docs/EPT.md)); bring-up keeps all of them allocated (their types cannot free on drop, asserted at compile time in `src/bring_up/mod.rs`). The marker in RAX shows on serial that the guest's own instructions ran. Hyper-V printed `Guest memory allocated: code=0x000000007eb1c000 (10 bytes copied)` (before `inc eax` was added; the guest code is now 73 bytes).
- [x] Decide and verify guest address translation before using those pages. With EPT disabled, guest virtual addresses translate through guest CR3; confirm the code page is executable and the separate stack page is writable under those page tables. Do not assume a UEFI allocation address is automatically usable by the guest. Decided: guest CR3 = host CR3, no EPT. Written: `src/vmx/paging.rs` walks the live 4-level tables (reading them through UEFI's identity mapping), combines R/W and XD over every level, and `GuestMemory::check_mappings` stops bring-up unless the code page has XD clear and the stack page is writable. It also combines U/S over every level and refuses a user code page under CR4.SMEP or a user stack page under CR4.SMAP, since the guest runs in ring 0 with the host's CR4; that check also passed on Hyper-V. Host tests cover 4 KiB/2 MiB/1 GiB leaves, permission combining and missing entries. On Hyper-V both pages were identity-mapped 4 KiB pages, writable, with XD clear (so this firmware does not map `LOADER_DATA` no-execute; `LOADER_CODE` stays as a portable precaution), and host EFER.NXE=1. Step 3 must give the guest EFER.NXE=1 too, or any XD bit in these shared tables becomes a reserved-bit fault.
- [x] Build a known, simple 64-bit guest context: valid CR0/CR3/CR4, segment selectors/bases/limits/access rights, GDTR/IDTR, RIP pointing at the guest code, RSP pointing at the guest stack, RFLAGS bit 1 set, and a VMCS link pointer of all ones. Initialize all other guest fields required by the selected controls and retain their backing memory. Written: `GuestState::from_current` in `src/vmx/guest_state.rs` copies the host's live CR0/CR3/CR4, selectors, GDTR and SYSENTER MSRs (the IDTR is the guest's own IDT since section 4), decodes each segment's limit and access rights from its GDT descriptor (`segment::descriptor_*`, host-tested), sets the accessed bit on code/data segments, makes LDTR unusable, and writes guest PAT/EFER only when the entry controls load them (otherwise the guest keeps the host's EFER, including NXE). It refuses a CS that is not 64-bit code or a TR that is not a busy 64-bit TSS. On Hyper-V both checks passed.
- [x] Add a guest-state writer and read back the fields it writes. This checks VMCS storage only; the CPU's VM-entry checks happen when entry is attempted. `GuestState::write` writes and reads back every field, reporting the first mismatch by encoding; `bring_up::report::guest_state` logs every segment's selector, base, limit and access rights for diagnosing a later exit reason 33. Hyper-V printed `VMCS guest fields written and read back; VM entry not attempted.` followed by `Host GDTR, TR, TSS base and IDTR preserved after VMX/UEFI calls.`
- [x] Write/read back host fields from the current root-mode state: selectors, CRs, FS/GS/TR and GDTR/IDTR bases, SYSENTER MSRs, and the dedicated VM-exit stack top and stub address. Load host PAT/EFER fields only if the selected exit controls require them.
- [x] Complete VM-entry validation of host selectors, CRs, and addresses; write/readback alone does not prove the host state will pass VM-entry checks. The first VMLAUNCH on Hyper-V passed the CPU's own host-state checks (no VM-instruction error 8).
- [x] Document the UEFI memory and address-translation assumptions of the current bring-up. A shared, identity-mapped address space without EPT is a bring-up stage, not guest memory isolation; EPT (section 5) provides that. Documented in [docs/EPT.md](docs/EPT.md): the guest still shares the host's page tables, EPT adds a second, identity-mapped stage built from the UEFI memory map, and that identity map still shows the guest all of Aleph0's memory (section 9 there).

**Checkpoint:** Hyper-V reported successful control, host-state, SYSENTER, and `HOST_RSP`/`HOST_RIP` write/readback. Both host PAT and EFER load controls were false, so those conditional writes were not exercised. Guest memory, its page-table mappings and every guest-state field are also confirmed on Hyper-V. The first `VMLAUNCH` (section 3) then passed the CPU's own control, host-state and guest-state checks.

## 3. Launch and observe one guest exit

- [x] Assemble and link an inactive VM-exit entry stub that saves guest general-purpose registers, prepares the UEFI x64 call frame, and calls a non-returning handler. Do not mistake compilation or `HOST_RIP` readback for a tested exit.
- [x] Replace the spin-only handler with a deliberate first-exit diagnostic: read `VM_EXIT_REASON`, record it through a mechanism that can be observed, and stop safely. Do not assume UEFI printing is safe in the low-level exit handler; there is no `VMRESUME` path yet. `vmexit_handler` reads the exit reason (basic reason plus the VM-entry-failure bit), exit qualification, guest RIP, instruction length and the saved guest RAX-RDX, prints them with `serial_println!`, and halts with `cli; hlt`. It ran for the first time on the first `VMLAUNCH` on Hyper-V, and printed the guest's `VMCALL` exit.
- [x] Before the first launch, finish the "Before the first `VMLAUNCH`" items in section 0b (own panic handler, output phase), so a panic in exit context never calls firmware.
- [x] After guest memory/state readback and the observable exit path are ready, execute `VMLAUNCH` to enter the tiny guest. `VMLAUNCH` enters the guest for the first time; the guest then executes `VMCALL`, which causes the VM exit. `bring_up::run` ends with `vmcs::launch`. On Hyper-V, serial showed `VM exit: reason=18 (VMCALL)`, `instruction length=3`, and guest `rax=0x000000000000a1e0`.
- [x] On instruction failure, distinguish VMfailInvalid, VMfailValid (read `VM_INSTRUCTION_ERROR`), and VM-entry failure reported as a VM exit. Do not treat every return as a successful guest run. `vmcs::launch` returns only on failure and maps CF to `VmFailInvalid`, ZF to `VmFailValid` (decoded by `report_vmcs_error`), and a fall-through with clear flags to `LaunchReturned`, never to success (host-tested). Invalid guest state arrives as an exit with bit 31 set, which the exit handler prints.
- [x] Handle only the expected `VMCALL` at first. Define a controlled stop/observation path; do not blindly `VMRESUME` at the same guest RIP. The handler checks reason 18 plus the guest marker in RAX (`is_expected_first_exit`, renamed `is_expected_vmcall_exit` in section 4; host-tested; since the NMI step: `exit_decision::decide`, host-tested), prints whether this was the expected exit, and halts with `cli; hlt`.

**Checkpoint:** A Hyper-V run confirms that the guest executed and records the expected `VMCALL` exit reason, not merely a successful VMCS write. Reached: serial printed `VM exit: expected first exit: the guest ran and executed VMCALL (marker 0xa1e0 in RAX).`

## 4. Make guest execution repeatable

- [x] Advance guest RIP by the VM-exit instruction length when appropriate, then `VMRESUME` and handle a second known exit. The handler writes GUEST_RIP = RIP + `VM_EXIT_INSTRUCTION_LEN` and returns (since the NMI step: `exit_decision::decide`, host-tested); the entry stub restores the guest registers and executes `VMRESUME`. The guest runs `inc eax` before its second main `VMCALL`. On Hyper-V, exit #2 showed the same RIP as exit #1 and guest `rax=0x000000000000a1e1`, so the guest resumed past the first `VMCALL`.
- [x] Handle unexpected exits and failed resume paths explicitly. `exit_action` (host-tested; since the NMI step: `exit_decision::decide`, host-tested) resumes only the expected `VMCALL` exits; anything else prints `NOT an expected guest VMCALL exit` (now `NOT an expected exit`) and stops the guest. A failed `VMRESUME` falls through to `vmresume_failed`, which decodes the flags and `VM_INSTRUCTION_ERROR`. Bring-up now stops instead of launching if the host descriptor tables changed.
- [x] Add clean VMCS/VMX shutdown and restore host state before returning control to firmware. A VM exit sets the host GDTR and IDTR limits to 0xFFFF and the TR limit to 0x67, so the return to firmware must reload the firmware's descriptor tables, not only leave VMX operation. `vmx_launch` (`src/vmx/vmcs/launch.rs`) saves the caller's frame before VMLAUNCH; to stop, the exit handler returns a stop value and the exit stub jumps back into that frame, so `vmcs::launch` returns a `GuestStop`. `bring_up::teardown` then loads the firmware's GDTR and IDTR, runs `VMCLEAR` and `VMXOFF`, restores CR0/CR4 and the interrupt flag, and `main` returns to firmware after a UEFI timer event fires. Every failure after VMXON takes the same path. TR stays on Aleph0's TSS, whose pages are never freed. On Hyper-V, serial showed `Teardown: CR4.VMXE=0 firmware GDTR/IDTR restored=true IF=1.`, the timer fired, and the application returned `SUCCESS`.
- [x] Plan for interrupts, exceptions, and firmware calls while in VMX root operation; avoid assuming a UEFI print call is safe inside a low-level exit stub. Exceptions: the exception bitmap is all ones, so a guest fault exits with reason 0 and its vector is printed, instead of running the firmware's handler inside the guest. NMIs: NMI exiting and virtual NMIs are on. `exit_decision::decide` (host-tested) reinjects each NMI through `VM_ENTRY_INTERRUPTION_INFO` (`0x80000202`) into the guest's own IDT (`GuestMemory::idt`, one gate at vector 2), or, while STI, MOV SS or NMI blocking prevents injection, waits for an NMI-window exit. On Hyper-V, `run-hyperv.ps1 -InjectNmi` injected an NMI with `Debug-VM` while the guest waited; serial showed the NMI exit, the guest NMI handler's VMCALL, and `NMIs: 1 reinjected, 1 handled by the guest`. Interrupts: the guest runs with RFLAGS.IF=0 and no interrupt exiting; external-interrupt exiting comes with an OS guest. Still open: NMIs that arrive while the exit handler or teardown runs go to the firmware IDT (a host IDT with its own NMI handler is part of the resident-hypervisor work in section 5), an exit that interrupted an event's delivery (IDT-vectoring info) stops the guest instead of re-delivering it, and an NMI-window exit taken while STI blocking still holds would repeat until the guest runs an instruction; the guest runs with IF=0, so it never has STI blocking.

**Checkpoint:** A short guest sequence produces predictable multiple exits and terminates cleanly. Reached on Hyper-V: two VMCALL exits, then teardown and a return to firmware with `SUCCESS`.

## 5. Add isolation and devices incrementally

- [x] Check CPU support for secondary execution controls and EPT; allocate and validate EPT tables before enabling them. Verify allowed guest physical accesses and an intentional EPT-violation exit. `ept::check_support` requires a 4-level walk, WB, 2 MiB pages and INVEPT (host-tested); Hyper-V reported EPT/VPID capabilities `0x00000f0106f34041` and single-context INVEPT. `Ept::build` identity-maps memory up to the highest UEFI memory-map address, rounded up to 1 GiB, with 2 MiB pages, and splits the region holding the guest's data page into 4 KiB pages so that page is read-only (host-tested). On Hyper-V: `identity 0x0..0x80000000 (2 GiB)`, 5 table pages, EPTP `0x7eafc01e`. The guest reads the data page (allowed, RCX = `0xda7a`), writes it, which caused exit 48 at GPA `0x7eb01000` with qualification `0x58a` (write; R=1 W=0 X=0); Aleph0 set W=1, ran INVEPT and resumed at the same RIP, and VMCALL #1 showed RDX = `0x455054`, the retried write. A main VMCALL before the violation would stop the guest (`EptWriteMissing`). The `-InjectNmi` run reinjected an NMI under EPT as before. See [docs/EPT.md](docs/EPT.md).
- [ ] Add only the necessary exits first (for example CPUID and I/O), then define the virtual devices needed by a larger guest.
- [ ] EPT memory types from the MTRRs, before an OS guest. With EPT on, the MTRRs no longer apply to guest accesses; the EPT entry's type does. Read `IA32_MTRR_DEF_TYPE` and the fixed and variable MTRRs, set each region's EPT memory type, and split 2 MiB regions of mixed type into 4 KiB pages. Today everything is WB, which would break device memory (Local APIC, IOAPIC, PCI BARs, framebuffer).
- [ ] Hide Aleph0's own pages from the guest through EPT: code, stacks, VMXON region, VMCS, host GDT/TSS and the EPT tables themselves. The identity map shows the guest all of them, so a guest with kernel rights could read Aleph0, rewrite its EPT entries or its exit handler. Each page becomes not present (the access redirected or a #PF injected, rather than stopping the guest) or maps to a zero-filled shadow page. Aleph0 then has to track every page it allocates. Belongs with the persistence item below.
- [ ] Decide how the hypervisor will own memory and persist after `ExitBootServices`. Loader-data pages and UEFI identity mapping are only assumptions for the current boot-services stage. After `ExitBootServices` the OS may reuse all `LOADER_CODE` (the `.efi` image, including its statics), `LOADER_DATA` (every page from `page.rs`) and `BOOT_SERVICES_DATA`. That last one holds the firmware page tables that `HOST_CR3` currently points at, so Aleph0 needs its own host page tables, not only a different memory type. Output changes for this milestone are in section 0b.
- [ ] Expand to multiple vCPUs, scheduling, and an OS guest only after the single-vCPU lifecycle is reliable. Per-line output locking and CPU-numbered log lines are in section 0b.

## 6. End goal: anti-cheat research on top of the hypervisor

Once an OS guest boots reliably under Aleph0, the hypervisor becomes the base for research into game anti-cheat. Running below the guest OS, Aleph0 sees memory and CPU state that a kernel-mode cheat cannot hide from or tamper with. The design is not decided yet. The items below are candidate directions, not commitments.

The project is also a study of its own method: AI-driven development of low-level `unsafe` Rust, and AI-assisted reverse-engineering tooling for analysing the game and cheats the anti-cheat has to deal with.

Candidate directions:

- [ ] **Guest memory introspection.** Read a game process's memory from outside the guest by walking the guest's own page tables (from its CR3) and then EPT. `src/vmx/paging.rs` already walks 4-level tables; it would start from the guest's CR3 instead of the host's.
- [ ] **EPT-based protection.** Mark selected guest-physical pages read-only or execute-only in EPT, so writes to protected game code or anti-cheat data cause an EPT-violation exit (reason 48) that Aleph0 can log or block. Section 5 already does this for one page of its own guest.
- [ ] **EPT split views.** Map one guest-physical page to one host page for execution (execute-only, EPT/VPID capability bit 0, which Hyper-V reports) and to another for reads, switching on EPT violations, to watch or protect code without changing the bytes the guest can read.
- [ ] **Watching privileged changes.** Exit on writes to sensitive MSRs (for example `IA32_LSTAR`, the system-call entry point), to control registers, and to descriptor tables, to detect kernel hooks.
- [ ] **Detecting nested hypervisors.** Treat a guest `VMXON` (which always exits) as a signal that something in the guest is trying to run its own hypervisor.
- [ ] **Process tracking.** Follow guest CR3 changes to know which process is running, so protection applies to the game's address space only.

Open questions to settle before this section starts: which game or test target, which guest OS and version, what the anti-cheat reports and to whom, and how to keep Aleph0 itself hard to detect and to tamper with. Research only: no deployment against third-party services.

## How to verify each milestone

- Run `cargo build --target x86_64-unknown-uefi` after each change. It checks compilation, not VM-entry validity.
- Run `cargo test-host` for the host unit tests of pure logic (RFLAGS decoding, control selection, descriptor encoding). They do not execute VMX instructions. They live in `tests/unit/`, mirroring `src/`.
- Run `scripts/run-hyperv.ps1` from an elevated PowerShell session and inspect the VM console and the serial stream in the PowerShell window (also saved to `run\serial.log`). The runner turns off the named test VM and recreates its ESP VHDX; do not keep irreplaceable data there. VM-exit diagnostics appear only on serial.
- Record observed VMX instruction errors and VM-exit reasons as milestones are reached. QEMU without nested VMX can still test non-VMX diagnostics, but cannot validate `VMLAUNCH`.

Relevant code: `src/main.rs`, `src/bring_up/`, `src/serial.rs`, `src/output.rs`, `src/vmx/segment.rs`, `src/vmx/vmxon.rs`, `src/vmx/vmcs/`, `src/vmx/vmexit.rs`, `src/vmx/exit_decision.rs`, `src/vmx/ept.rs`, `src/vmx/guest.rs`, `src/vmx/paging.rs`, `src/vmx/guest_state.rs`, `scripts/run-hyperv.ps1`, and `scripts/read-serial.ps1`.