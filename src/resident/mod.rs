//! Staying resident after `ExitBootServices`: what lets Aleph0 go on
//! handling VM exits once the OS owns the machine. docs/RESIDENT.md has the
//! whole design.
//!
//! - Its pages: everything Aleph0 keeps is allocated as a resident type
//!   (`vmx::page`), and bring-up checks each allocation's type in the
//!   memory map ([`memory_type_at`], [`memory::is_reclaimable`]).
//! - Its image: the firmware loads Aleph0 as an application, in
//!   `LOADER_CODE`, and unloads it when `main` returns. `main` therefore
//!   copies the image into resident code pages, applies its base
//!   relocations for the new address ([`pe`]), and runs everything else
//!   from the copy ([`ResidentImage`]): its code and its statics.
//! - Knowing when boot services end: an `EVT_SIGNAL_EXIT_BOOT_SERVICES`
//!   event, whose notify function lives in the copy, makes a VMCALL in the
//!   guest ([`watch_exit_boot_services`]); the exit handler then switches
//!   the output phase to runtime.

pub mod memory;
pub mod pe;

use core::arch::asm;
use core::ffi::c_void;
use core::ptr::NonNull;

use uefi::boot::{self, EventType, MemoryType, Tpl};
use uefi::proto::loaded_image::LoadedImage;
use uefi::{Event, Status};

use crate::vmx::page::{self, PAGE_SIZE, RESIDENT_CODE};
use crate::vmx::vmcall;
use pe::{Headers, PeError};

/// Why the image could not be copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageError {
    /// The firmware's LoadedImage protocol for Aleph0's image could not be
    /// opened.
    LoadedImageUnavailable(Status),
    /// The image the firmware reports is smaller than its headers say.
    ImageTruncated { loaded: usize, size_of_image: usize },
    /// UEFI could not provide the pages for the copy.
    AllocationFailed,
    /// The headers or the base relocation table are not usable.
    Pe(PeError),
}

impl From<PeError> for ImageError {
    fn from(error: PeError) -> Self {
        Self::Pe(error)
    }
}

/// Aleph0's image, copied into [`RESIDENT_CODE`] pages and relocated for
/// its address there. The pages are never freed.
pub struct ResidentImage {
    /// Where the firmware loaded the image.
    loaded: u64,
    /// Where the copy is.
    base: u64,
    /// Bytes copied: the loaded image's size.
    size: usize,
    /// DIR64 fixups applied to the copy.
    fixups: usize,
}

impl ResidentImage {
    /// Copies the running image, statics included, into resident code
    /// pages, and applies its base relocations for the copy's address.
    ///
    /// # Safety
    ///
    /// Boot services must still be active, with memory identity-mapped.
    /// No static may hold an address inside the image that the code stored
    /// at run time: relocation moves only the addresses the linker listed,
    /// so such a value would still point into the loaded image in the copy.
    pub unsafe fn copy() -> Result<Self, ImageError> {
        let (loaded, size) = {
            let image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())
                .map_err(|error| ImageError::LoadedImageUnavailable(error.status()))?;
            let (base, size) = image.info();
            (base as u64, size as usize)
        };
        // SAFETY: the firmware loaded the image at `loaded`, `size` bytes,
        // and keeps it there until `main` returns; nothing writes it
        // concurrently.
        let image = unsafe { core::slice::from_raw_parts(loaded as *const u8, size) };
        let headers = Headers::parse(image)?;
        if headers.size_of_image > size {
            return Err(ImageError::ImageTruncated {
                loaded: size,
                size_of_image: headers.size_of_image,
            });
        }

        let base =
            page::allocate_zeroed_pages_of_type(size.div_ceil(PAGE_SIZE), RESIDENT_CODE, ImageError::AllocationFailed)?;
        // SAFETY: a fresh allocation of at least `size` bytes, which nothing
        // else refers to; never freed.
        let copy = unsafe { core::slice::from_raw_parts_mut(base.as_ptr(), size) };
        copy.copy_from_slice(image);
        let base = base.as_ptr() as u64;
        let fixups = pe::relocate(copy, headers.relocations, base.wrapping_sub(loaded))?;
        Ok(Self {
            loaded,
            base,
            size,
            fixups,
        })
    }

    /// Where the copy is.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Where the firmware loaded the image.
    pub fn loaded(&self) -> u64 {
        self.loaded
    }

    /// Bytes copied.
    pub fn size(&self) -> usize {
        self.size
    }

    /// DIR64 fixups applied to the copy.
    pub fn fixups(&self) -> usize {
        self.fixups
    }

    /// Calls the copy of `function`, a function of this image, and returns
    /// what it returns.
    ///
    /// # Safety
    ///
    /// `self` must come from [`ResidentImage::copy`] of this image. From
    /// the call on, the copy's statics are the live ones, so the caller must
    /// not rely on its own afterwards.
    pub unsafe fn call(&self, function: fn() -> Status) -> Status {
        let offset = (function as usize as u64).wrapping_sub(self.loaded);
        assert!(offset < self.size as u64, "the function is not in the image");
        // SAFETY: the copy holds this image byte for byte, relocated for its
        // address, so the same offset there is the same function, with the
        // same signature.
        let copied = unsafe { core::mem::transmute::<usize, fn() -> Status>((self.base + offset) as usize) };
        copied()
    }
}

/// The type of the memory-map region holding `address`, among `regions`
/// (start, pages, type), or `None` if no region holds it.
pub fn memory_type_at(mut regions: impl Iterator<Item = (u64, u64, MemoryType)>, address: u64) -> Option<MemoryType> {
    regions
        .find(|&(start, pages, _)| address >= start && address - start < pages.saturating_mul(PAGE_SIZE as u64))
        .map(|(_, _, memory_type)| memory_type)
}

/// Has the firmware call [`on_exit_boot_services`] during
/// `ExitBootServices`: the event that tells Aleph0 when boot services end.
///
/// The firmware calls it in the guest, from the copy, so this must run in
/// the resident image, and the event must be closed if the firmware never
/// becomes the guest: outside VMX operation its VMCALL would raise #UD.
pub fn watch_exit_boot_services() -> uefi::Result<Event> {
    // SAFETY: the notify function takes no context, and only makes its
    // VMCALL, which needs nothing from the firmware.
    unsafe {
        boot::create_event(
            EventType::SIGNAL_EXIT_BOOT_SERVICES,
            Tpl::CALLBACK,
            Some(on_exit_boot_services),
            None,
        )
    }
}

/// Called by the firmware inside `ExitBootServices`, in the guest: tells
/// Aleph0 with a VMCALL ([`vmcall::BOOT_SERVICES_ENDED`]), which it resumes
/// past (`ExitEvent::BootServicesEnded`).
unsafe extern "efiapi" fn on_exit_boot_services(_event: Event, _context: Option<NonNull<c_void>>) {
    // SAFETY: the event exists only while the firmware runs as Aleph0's
    // guest (bring-up closes it when the launch fails), so the VMCALL exits
    // to Aleph0, which changes no guest register for it and resumes past
    // it. It touches no memory and no stack.
    unsafe {
        asm!(
            "vmcall",
            inout("rax") vmcall::BOOT_SERVICES_ENDED => _,
            options(nomem, nostack),
        );
    }
}

#[cfg(test)]
#[path = "../../tests/unit/resident.rs"]
mod tests;
