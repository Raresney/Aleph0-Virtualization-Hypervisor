//! Which UEFI memory the OS may take for itself once `ExitBootServices`
//! has returned, after the UEFI spec's table "Memory Type Usage after
//! ExitBootServices()".
//!
//! Aleph0 checks every allocation it keeps against [`is_reclaimable`]
//! (`bring_up`), and the `ExitBootServices` test harness
//! (`tools/ebs-harness`) overwrites what it names, to show that nothing
//! Aleph0 needs is there. This file depends on nothing but `uefi`, because
//! the harness includes it too.

use uefi::boot::MemoryType;

/// Whether the OS may reuse memory of type `memory_type` as its own once
/// `ExitBootServices` has returned:
///
/// | Type | After `ExitBootServices` |
/// |---|---|
/// | `LOADER_CODE`, `LOADER_DATA` | the OS loader and the OS use it as they see fit |
/// | `BOOT_SERVICES_CODE`, `BOOT_SERVICES_DATA`, `CONVENTIONAL` | available for general use |
/// | `ACPI_RECLAIM` | general use once the OS has enabled ACPI |
/// | `PERSISTENT_MEMORY` | works as conventional memory that keeps its contents |
/// | `UNACCEPTED` | general use once the OS has accepted it |
///
/// Everything else is kept: `RESERVED`, `RUNTIME_SERVICES_CODE`,
/// `RUNTIME_SERVICES_DATA`, `ACPI_NON_VOLATILE` and `PAL_CODE`, which the OS
/// preserves, `UNUSABLE` memory, which it avoids, MMIO and MMIO port space,
/// which are not memory, and the OEM and OS-loader types (`0x7000_0000` and
/// up), whose use only their owner knows.
pub fn is_reclaimable(memory_type: MemoryType) -> bool {
    use MemoryType as Type;
    [
        Type::LOADER_CODE,
        Type::LOADER_DATA,
        Type::BOOT_SERVICES_CODE,
        Type::BOOT_SERVICES_DATA,
        Type::CONVENTIONAL,
        Type::ACPI_RECLAIM,
        Type::PERSISTENT_MEMORY,
        Type::UNACCEPTED,
    ]
    .contains(&memory_type)
}

#[cfg(test)]
#[path = "../../tests/unit/resident/memory.rs"]
mod tests;
