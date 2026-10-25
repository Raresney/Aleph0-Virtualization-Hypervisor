//! The `ExitBootServices` test harness: an EFI application that starts
//! Aleph0, runs on as its guest, exits boot services, overwrites every page
//! the OS could reclaim, and then checks that Aleph0 still handles its VM
//! exits (docs/RESIDENT.md, section 6).
//!
//! 1. Loads `\EFI\BOOT\aleph0.efi` from its own volume and starts it. When
//!    `StartImage` returns, the harness runs as Aleph0's guest, which it
//!    checks: Aleph0 hides VMX from CPUID.
//! 2. Calls `ExitBootServices` (the `uefi` crate retries once with a fresh
//!    map key, as the UEFI spec requires), turns interrupts off, and loads
//!    its own GDT, an empty IDT, identity-mapped page tables and a stack,
//!    all statics in its own image.
//! 3. With the `set-virtual-address-map` feature, calls
//!    `SetVirtualAddressMap` with virtual addresses that differ from the
//!    physical ones, as Linux does.
//! 4. Overwrites every range of the final memory map the OS may reclaim,
//!    except its own image ([`regions`]).
//! 5. Makes known exits (CPUID leaf 1, WRMSR and RDMSR of an intercepted MSR,
//!    the test VMCALL), prints what they returned, and idles with HLT, each
//!    of which exits too.
//!
//! With the `without-aleph0` feature it skips step 1 and the VMCALL, so
//! steps 2 to 4 can be checked on the firmware alone, under Hyper-V
//! without nested VMX in the way.
//!
//! The harness prints on COM1; Aleph0 prints on COM2. From step 2 on it
//! calls no firmware and allocates nothing. Its IDT is empty, so any
//! exception or NMI in it ends as a triple fault, which Aleph0 stops on and
//! reports with the harness's RIP.

// Host unit tests build with std and the test harness; the UEFI build is
// no_std with a firmware entry point.
#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), no_std)]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

// Aleph0's own sources, so that the harness and Aleph0 agree: the UART
// driver, the VMCALL values, and which memory the OS may reclaim. Aleph0
// uses all of them; the harness only some.
#[allow(dead_code)]
#[path = "../../../src/resident/memory.rs"]
mod memory;
#[allow(dead_code)]
#[path = "../../../src/port.rs"]
mod port;
#[allow(dead_code)]
#[path = "../../../src/serial.rs"]
mod serial;
#[allow(dead_code)]
#[path = "../../../src/vmx/vmcall.rs"]
mod vmcall;

mod paging;
mod regions;

use core::arch::asm;
use core::arch::x86_64::__cpuid;
use core::cell::UnsafeCell;

use uefi::boot::{self, LoadImageSource};
use uefi::mem::memory_map::{MemoryMap, MemoryMapOwned};
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;
use uefi::{CStr16, cstr16};

use paging::PageTables;
use serial::SerialPort;

/// Prefix of every line the harness prints.
const TAG: &str = "[ebs-harness]";

/// Prints a tagged line on COM1.
macro_rules! say {
    ($($arg:tt)*) => {
        crate::serial_println!("{} {}", crate::TAG, format_args!($($arg)*))
    };
}

/// Aleph0's image, next to the harness (`run-hyperv.ps1 -Harness`).
const ALEPH0_PATH: &CStr16 = cstr16!("\\EFI\\BOOT\\aleph0.efi");

/// Whether the harness starts Aleph0 and runs as its guest. The
/// `without-aleph0` feature skips Aleph0, and so step 1 and the VMCALL, to
/// check steps 2 to 4 on the firmware alone.
const WITH_ALEPH0: bool = !cfg!(feature = "without-aleph0");

/// CPUID.1:ECX bit 5: VMX, which Aleph0 hides from its guest.
const CPUID_1_ECX_VMX: u32 = 1 << 5;
/// An MSR Aleph0's MSR bitmap intercepts, and emulates by passthrough.
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;
/// What the harness writes to it: canonical, so WRMSR takes it.
const MSR_TEST_VALUE: u64 = 0xFFFF_8000_EB5E_0000;
/// What every reclaimable byte becomes: INT3 if executed, and non-canonical
/// as an address.
const PATTERN: u64 = 0xCCCC_CCCC_CCCC_CCCC;

/// GDT selectors: a 64-bit code segment and a data segment.
const CODE_SELECTOR: u16 = 0x08;
const DATA_SELECTOR: u16 = 0x10;
/// Null, 64-bit code (ring 0, execute/read), data (ring 0, read/write),
/// with the accessed bit already set, so the CPU never writes them.
static GDT: [u64; 3] = [0, 0x00AF_9B00_0000_FFFF, 0x00CF_9300_0000_FFFF];

/// Stack the harness runs on after `ExitBootServices`: the firmware's is
/// `BOOT_SERVICES_DATA`, which it overwrites.
const STACK_SIZE: usize = 64 * 1024;

/// Most ranges the harness overwrites, and most runtime regions it moves.
const MAX_RANGES: usize = 256;

/// What the harness works from after `ExitBootServices`, copied out of the
/// memory map, whose pages it overwrites too.
struct Plan {
    /// `[start, end)` to overwrite.
    ranges: [(u64, u64); MAX_RANGES],
    count: usize,
    /// The runtime regions with their new virtual addresses, for
    /// `SetVirtualAddressMap`.
    #[cfg(feature = "set-virtual-address-map")]
    runtime: [uefi::mem::memory_map::MemoryDescriptor; MAX_RANGES],
    #[cfg(feature = "set-virtual-address-map")]
    runtime_count: usize,
}

/// A static the harness fills in before it uses it. One CPU runs the
/// harness, with interrupts off from `ExitBootServices` on, so nothing else
/// touches one meanwhile.
struct Scratch<T>(UnsafeCell<T>);

// SAFETY: see `Scratch`: one CPU, no interrupts, no concurrent access.
unsafe impl<T> Sync for Scratch<T> {}

#[repr(C, align(16))]
struct Stack([u8; STACK_SIZE]);

static STACK: Scratch<Stack> = Scratch(UnsafeCell::new(Stack([0; STACK_SIZE])));
static TABLES: Scratch<PageTables> = Scratch(UnsafeCell::new(PageTables::EMPTY));
static PLAN: Scratch<Plan> = Scratch(UnsafeCell::new(Plan {
    ranges: [(0, 0); MAX_RANGES],
    count: 0,
    #[cfg(feature = "set-virtual-address-map")]
    runtime: [svam::EMPTY_DESCRIPTOR; MAX_RANGES],
    #[cfg(feature = "set-virtual-address-map")]
    runtime_count: 0,
}));

#[cfg_attr(not(test), entry)]
fn main() -> Status {
    if serial::init(SerialPort::COM1).is_err() {
        // Nowhere to report anything.
        return Status::DEVICE_ERROR;
    }
    if WITH_ALEPH0 {
        say!("starting Aleph0 from {ALEPH0_PATH}.");
        if let Err(error) = start_aleph0() {
            say!("Aleph0 did not start: {:?}.", error.status());
            return error.status();
        }
        if __cpuid(1).ecx & CPUID_1_ECX_VMX != 0 {
            say!("Aleph0 returned, but CPUID shows VMX: the harness is not its guest. Was it built with -TestGuest?");
            return Status::ABORTED;
        }
        say!("Aleph0 returned SUCCESS; the harness runs as its guest (CPUID hides VMX).");
    } else {
        say!("built without-aleph0: Aleph0 not started; the harness runs on the firmware alone.");
    }
    let keep = match own_image() {
        Ok(keep) => keep,
        Err(error) => {
            say!("the harness's LoadedImage is unavailable: {:?}.", error.status());
            return error.status();
        }
    };
    say!("own image {:#x}..{:#x}; calling ExitBootServices.", keep.0, keep.1);

    // SAFETY: nothing the harness uses from here on lives in boot-services
    // memory: no protocol, no pool allocation; its state is in its image.
    let map = unsafe { boot::exit_boot_services(None) };
    // SAFETY: CLI only clears IF. The firmware may have turned interrupts
    // back on inside ExitBootServices, and the harness's IDT handles none.
    unsafe { asm!("cli", options(nomem, nostack)) };
    leave_firmware(map, keep)
}

/// Reads Aleph0's image from the harness's own volume, loads it and starts
/// it. Returns once Aleph0's `main` has returned.
fn start_aleph0() -> uefi::Result {
    let image = {
        let mut volume = uefi::fs::FileSystem::new(boot::get_image_file_system(boot::image_handle())?);
        let bytes = volume
            .read(ALEPH0_PATH)
            .map_err(|_| uefi::Error::from(Status::NOT_FOUND))?;
        boot::load_image(
            boot::image_handle(),
            LoadImageSource::FromBuffer {
                buffer: &bytes,
                file_path: None,
            },
        )?
    };
    boot::start_image(image)
}

/// `[start, end)` of the harness's loaded image, rounded out to pages.
fn own_image() -> uefi::Result<(u64, u64)> {
    let image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())?;
    let (base, size) = image.info();
    let base = base as u64;
    Ok((base, (base + size).next_multiple_of(4096)))
}

/// Copies what the harness needs out of the final memory map `map`, builds
/// its page tables, and switches to its own tables and stack. `keep` is the
/// harness's image.
fn leave_firmware(map: MemoryMapOwned, keep: (u64, u64)) -> ! {
    // SAFETY: see `Scratch`; nothing else refers to them yet.
    let (plan, tables) = unsafe { (&mut *PLAN.0.get(), &mut *TABLES.0.get()) };
    let regions = map
        .entries()
        .map(|region| (region.phys_start, region.page_count, region.ty));
    plan.count = regions::reclaimable_except(regions, keep, &mut plan.ranges);
    #[cfg(feature = "set-virtual-address-map")]
    {
        plan.runtime_count = svam::collect(map.entries(), &mut plan.runtime);
    }
    let gibs = paging::gibs_to_map(map.entries().map(|region| (region.phys_start, region.page_count)));
    let cr3 = tables.identity_map(gibs);
    // Its Drop would free the map's pages through boot services, which are
    // gone; the plan holds what the harness needs from it.
    core::mem::forget(map);

    if plan.count > MAX_RANGES {
        say!("{} ranges to overwrite, more than {MAX_RANGES}; stopping.", plan.count);
        halt_forever();
    }
    let Some(cr3) = cr3 else {
        say!(
            "the memory map needs {gibs} GiB mapped, more than {}; stopping.",
            paging::MAX_GIBS
        );
        halt_forever();
    };
    say!("boot services exited; loading the harness's own GDT, IDT, page tables (identity, {gibs} GiB) and stack.");
    // SAFETY: interrupts are off; `cr3` maps the harness's image, where the
    // GDT, the stack and every static are, to itself, as the firmware's
    // tables did; `GDT` holds the selectors loaded.
    unsafe { switch_tables(cr3) }
}

/// A GDTR or IDTR value for LGDT and LIDT.
#[repr(C, packed)]
struct TablePointer {
    limit: u16,
    base: u64,
}

/// Loads the harness's GDT, an empty IDT, the page tables at `cr3` and the
/// harness's stack, reloads every segment register, and calls
/// [`on_own_tables`].
///
/// # Safety
///
/// Interrupts must be off, and `cr3` must map the harness's image to itself.
unsafe fn switch_tables(cr3: u64) -> ! {
    let gdtr = TablePointer {
        limit: (size_of_val(&GDT) - 1) as u16,
        base: GDT.as_ptr() as u64,
    };
    // Limit 0: no vector fits, so any exception becomes a triple fault.
    let idtr = TablePointer { limit: 0, base: 0 };
    let stack_top = STACK.0.get() as u64 + STACK_SIZE as u64;
    // SAFETY: the caller guarantees IF = 0 and a CR3 that maps the image,
    // so the code, the GDT and the stack stay reachable across the switch.
    // The far return loads CS from the new GDT; the data selectors follow.
    // Every register operand is used before RAX is overwritten, so any of
    // them may be RAX. The 32 bytes below the call are the efiapi shadow
    // space, and leave RSP 16-byte aligned at the call, as the ABI wants.
    unsafe {
        asm!(
            "lgdt [{gdtr}]",
            "lidt [{idtr}]",
            "mov cr3, {cr3}",
            "mov rsp, {stack}",
            "push {code}",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            "mov eax, {data}",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "mov fs, ax",
            "mov gs, ax",
            "sub rsp, 32",
            "call {entry}",
            "ud2",
            gdtr = in(reg) &gdtr,
            idtr = in(reg) &idtr,
            cr3 = in(reg) cr3,
            stack = in(reg) stack_top,
            code = const CODE_SELECTOR,
            data = const DATA_SELECTOR,
            entry = sym on_own_tables,
            options(noreturn),
        )
    }
}

/// Runs on the harness's own tables and stack: steps 3 to 5.
extern "efiapi" fn on_own_tables() -> ! {
    say!("running on the harness's own tables and stack.");
    // SAFETY: see `Scratch`; `leave_firmware` is done with it.
    let plan = unsafe { &mut *PLAN.0.get() };
    #[cfg(feature = "set-virtual-address-map")]
    svam::call(&mut plan.runtime[..plan.runtime_count]);
    let ranges = &plan.ranges[..plan.count];
    // SAFETY: each range is memory the OS may reclaim, without the
    // harness's image, so nothing the harness still uses lies in it.
    let bytes = unsafe { overwrite(ranges) };
    say!(
        "overwrote {} MiB in {} ranges with {PATTERN:#x}: every page the OS may reclaim but the harness's image.",
        bytes >> 20,
        ranges.len()
    );
    check_exits();
    if WITH_ALEPH0 {
        say!("idling with HLT; Aleph0 resumes the guest after each one.");
    } else {
        say!("idling with HLT; done.");
    }
    loop {
        // SAFETY: HLT with IF = 0: an exit to Aleph0, which resumes past it,
        // or without Aleph0 a halt that only an NMI ends.
        unsafe { asm!("hlt", options(nomem, nostack)) };
    }
}

/// Fills every range with [`PATTERN`], and returns how many bytes that was.
///
/// # Safety
///
/// Nothing the harness still uses may lie in a range, and each range must be
/// mapped, identity, and a whole number of 8-byte words.
unsafe fn overwrite(ranges: &[(u64, u64)]) -> u64 {
    for &(start, end) in ranges {
        // SAFETY: the caller guarantees the range is free to write and
        // mapped. REP STOSQ, not a Rust write, because a range may start at
        // address 0. DF is 0, as the ABI guarantees.
        unsafe {
            asm!(
                "rep stosq",
                inout("rdi") start => _,
                inout("rcx") (end - start) / 8 => _,
                in("rax") PATTERN,
                options(nostack),
            );
        }
    }
    ranges.iter().map(|&(start, end)| end - start).sum()
}

/// Makes one exit of each kind Aleph0 handles for the guest, and prints
/// what came back.
fn check_exits() {
    let ecx = __cpuid(1).ecx;
    let hidden = ecx & CPUID_1_ECX_VMX == 0;
    say!(
        "CPUID.1: ecx={ecx:#010x}, VMX {}.",
        match (WITH_ALEPH0, hidden) {
            (false, _) => "as the CPU reports it, with no Aleph0 to hide it",
            (true, true) => "hidden: Aleph0 answered",
            (true, false) => "visible: NOT Aleph0's answer",
        }
    );

    // SAFETY: IA32_KERNEL_GS_BASE exists on every 64-bit CPU and takes any
    // canonical value; the harness never uses it, and puts it back.
    let read = unsafe {
        let original = rdmsr(IA32_KERNEL_GS_BASE);
        wrmsr(IA32_KERNEL_GS_BASE, MSR_TEST_VALUE);
        let read = rdmsr(IA32_KERNEL_GS_BASE);
        wrmsr(IA32_KERNEL_GS_BASE, original);
        read
    };
    say!(
        "IA32_KERNEL_GS_BASE: wrote {MSR_TEST_VALUE:#x}, read back {read:#x}: {}.",
        if read == MSR_TEST_VALUE { "match" } else { "MISMATCH" }
    );

    // Without Aleph0 nothing handles it: #UD, and a triple fault.
    if WITH_ALEPH0 {
        // SAFETY: the harness is Aleph0's guest (checked in `main`), so the
        // VMCALL exits to Aleph0, which resumes past it and changes no register.
        unsafe { asm!("vmcall", inout("rax") vmcall::TEST => _, options(nomem, nostack)) };
        say!("test VMCALL (rax={:#x}): resumed past it.", vmcall::TEST);
    }
}

/// # Safety
///
/// `msr` must exist.
unsafe fn rdmsr(msr: u32) -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: the caller guarantees the MSR exists.
    unsafe { asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high, options(nomem, nostack)) };
    u64::from(high) << 32 | u64::from(low)
}

/// # Safety
///
/// `msr` must exist and take `value`, and changing it must be harmless.
unsafe fn wrmsr(msr: u32, value: u64) {
    // SAFETY: the caller guarantees the MSR takes the value harmlessly.
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack),
        );
    }
}

/// Stops this CPU: CLI and HLT, again after any NMI.
fn halt_forever() -> ! {
    loop {
        // SAFETY: CLI and HLT only stop this CPU.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

/// Prints the panic on COM1 and halts. The `uefi` crate's handler would
/// call the firmware, which is gone after `ExitBootServices`.
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    say!("PANIC: {info}");
    halt_forever();
}

/// `SetVirtualAddressMap` with addresses that differ from the physical ones,
/// as Linux calls it: only the runtime regions, each moved up by
/// [`svam::OFFSET`] into the upper half.
#[cfg(feature = "set-virtual-address-map")]
mod svam {
    use uefi::mem::memory_map::{MemoryAttribute, MemoryDescriptor, MemoryType};

    /// Where each runtime region moves: physical + this, canonical for
    /// every physical address below 1 TiB.
    pub const OFFSET: u64 = 0xFFFF_FF00_0000_0000;

    pub const EMPTY_DESCRIPTOR: MemoryDescriptor = MemoryDescriptor {
        ty: MemoryType::RESERVED,
        padding: 0,
        phys_start: 0,
        virt_start: 0,
        page_count: 0,
        att: MemoryAttribute::empty(),
    };

    /// Copies the runtime regions of `entries` into `out` with their new
    /// virtual addresses, and returns how many it copied.
    pub fn collect<'a>(entries: impl Iterator<Item = &'a MemoryDescriptor>, out: &mut [MemoryDescriptor]) -> usize {
        let runtime = entries.filter(|region| region.att.contains(MemoryAttribute::RUNTIME));
        let mut count = 0;
        for (slot, region) in out.iter_mut().zip(runtime) {
            *slot = MemoryDescriptor {
                virt_start: region.phys_start + OFFSET,
                ..*region
            };
            count += 1;
        }
        count
    }

    /// Calls `SetVirtualAddressMap` with `runtime`, and prints the result.
    pub fn call(runtime: &mut [MemoryDescriptor]) {
        let Some(system_table) = uefi::table::system_table_raw() else {
            say!("SetVirtualAddressMap skipped: no system table.");
            return;
        };
        let virtual_table = (system_table.as_ptr() as u64 + OFFSET) as *const _;
        // SAFETY: after ExitBootServices, with the runtime regions of the
        // final memory map, each given an address; the system table is in
        // one of them. The harness calls no runtime service afterwards.
        match unsafe { uefi::runtime::set_virtual_address_map(runtime, virtual_table) } {
            Ok(()) => say!(
                "SetVirtualAddressMap: {} runtime regions moved up by {OFFSET:#x}.",
                runtime.len()
            ),
            Err(error) => say!("SetVirtualAddressMap failed: {:?}.", error.status()),
        }
    }
}
