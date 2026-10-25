//! Unit tests for `src/vmx/guest.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;

#[test]
fn guest_code_moves_an_mtrr_reads_the_local_apic_halts_writes_its_data_page_then_waits_for_an_nmi_between_two_vmcalls()
{
    assert_eq!(
        guest_code(),
        [
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x31, 0xC9, // xor ecx, ecx
            0x0F, 0xA2, // cpuid
            0x0F, 0xBA, 0xE1, 0x05, // bt ecx, 5
            0x0F, 0x82, 0x81, 0x01, 0x00, 0x00, // jc guest_emulation_failed (+385)
            0xB9, 0x02, 0x01, 0x00, 0xC0, // mov ecx, IA32_KERNEL_GS_BASE
            0x0F, 0x32, // rdmsr
            0x89, 0xC6, // mov esi, eax
            0x89, 0xD7, // mov edi, edx
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, GUEST_MSR_VALUE as u32
            0xBA, 0x1E, 0x7A, 0x00, 0x00, // mov edx, GUEST_MSR_VALUE >> 32
            0x0F, 0x30, // wrmsr
            0x31, 0xC0, // xor eax, eax
            0x31, 0xD2, // xor edx, edx
            0x0F, 0x32, // rdmsr
            0x83, 0xF8, 0x00, // cmp eax, GUEST_MSR_VALUE as u32
            0x0F, 0x85, 0x5B, 0x01, 0x00, 0x00, // jne guest_emulation_failed (+347, too far for a rel8)
            0x81, 0xFA, 0x1E, 0x7A, 0x00, 0x00, // cmp edx, GUEST_MSR_VALUE >> 32
            0x0F, 0x85, 0x4F, 0x01, 0x00, 0x00, // jne guest_emulation_failed (+335)
            0x89, 0xF0, // mov eax, esi
            0x89, 0xFA, // mov edx, edi
            0x0F, 0x30, // wrmsr
            0x66, 0xBA, 0xFF, 0x03, // mov dx, GUEST_SCRATCH_PORT
            0xEC, // in al, dx
            0x40, 0x88, 0xC6, // mov sil, al
            0xB0, 0xA5, // mov al, GUEST_IO_VALUE
            0xEE, // out dx, al
            0x31, 0xC0, // xor eax, eax
            0xEC, // in al, dx
            0x3C, 0xA5, // cmp al, GUEST_IO_VALUE
            0x0F, 0x85, 0x33, 0x01, 0x00, 0x00, // jne guest_emulation_failed (+307)
            0x40, 0x88, 0xF0, // mov al, sil
            0xEE, // out dx, al
            0xB8, 0x08, 0x00, 0x00, 0x80, // mov eax, ADDRESS_SIZES
            0x0F, 0xA2, // cpuid
            0x89, 0xC1, // mov ecx, eax
            0x41, 0xBA, 0x01, 0x00, 0x00, 0x00, // mov r10d, 1
            0x49, 0xD3, 0xE2, // shl r10, cl
            0x49, 0xFF, 0xCA, // dec r10
            0xB9, 0xFE, 0x00, 0x00, 0x00, // mov ecx, IA32_MTRRCAP
            0x0F, 0x32, // rdmsr (not intercepted)
            0x0F, 0xB6, 0xC8, // movzx ecx, al
            0x8D, 0x8C, 0x09, 0xFE, 0x01, 0x00, 0x00, // lea ecx, [rcx + rcx + IA32_MTRR_PHYSBASE0 - 2]
            0x0F, 0x32, // rdmsr (PHYSBASE)
            0x41, 0x89, 0xC0, // mov r8d, eax
            0x41, 0x89, 0xD1, // mov r9d, edx
            0xFF, 0xC1, // inc ecx
            0x0F, 0x32, // rdmsr (PHYSMASK)
            0x41, 0x89, 0xC3, // mov r11d, eax
            0x41, 0x89, 0xD4, // mov r12d, edx
            0x31, 0xC0, // xor eax, eax
            0x31, 0xD2, // xor edx, edx
            0x0F, 0x30, // wrmsr (PHYSMASK: off)
            0xFF, 0xC9, // dec ecx
            0xB8, 0x00, 0x00, 0x20, 0x00, // mov eax, GUEST_MTRR_BASE | UC
            0x0F, 0x30, // wrmsr (PHYSBASE)
            0xFF, 0xC1, // inc ecx
            0x4D, 0x89, 0xD5, // mov r13, r10
            0x49, 0x81, 0xE5, 0x00, 0x00, 0xE0, 0xFF, // and r13, -SIZE_2M
            0x49, 0x81, 0xCD, 0x00, 0x08, 0x00, 0x00, // or r13, PHYSMASK_VALID
            0x44, 0x89, 0xE8, // mov eax, r13d
            0x4C, 0x89, 0xEA, // mov rdx, r13
            0x48, 0xC1, 0xEA, 0x20, // shr rdx, 32
            0x0F, 0x30, // wrmsr (PHYSMASK: 2 MiB)
            0x31, 0xC0, // xor eax, eax
            0x31, 0xD2, // xor edx, edx
            0x0F, 0x32, // rdmsr (PHYSMASK)
            0x48, 0xC1, 0xE2, 0x20, // shl rdx, 32
            0x48, 0x09, 0xD0, // or rax, rdx
            0x4C, 0x39, 0xE8, // cmp rax, r13
            0x0F, 0x85, 0xB3, 0x00, 0x00, 0x00, // jne guest_emulation_failed (+179)
            0x4D, 0x89, 0xD5, // mov r13, r10
            0x49, 0x81, 0xE5, 0x00, 0xF0, 0xFF, 0xFF, // and r13, -PAGE_SIZE
            0x49, 0x81, 0xCD, 0x00, 0x08, 0x00, 0x00, // or r13, PHYSMASK_VALID
            0x44, 0x89, 0xE8, // mov eax, r13d
            0x4C, 0x89, 0xEA, // mov rdx, r13
            0x48, 0xC1, 0xEA, 0x20, // shr rdx, 32
            0x0F, 0x30, // wrmsr (PHYSMASK: 4 KiB)
            0x31, 0xC0, // xor eax, eax
            0x31, 0xD2, // xor edx, edx
            0x0F, 0x30, // wrmsr (PHYSMASK: off)
            0xFF, 0xC9, // dec ecx
            0x44, 0x89, 0xC0, // mov eax, r8d
            0x44, 0x89, 0xCA, // mov edx, r9d
            0x0F, 0x30, // wrmsr (PHYSBASE: as it was)
            0xFF, 0xC1, // inc ecx
            0x44, 0x89, 0xD8, // mov eax, r11d
            0x44, 0x89, 0xE2, // mov edx, r12d
            0x0F, 0x30, // wrmsr (PHYSMASK: as it was)
            0xB9, 0x1B, 0x00, 0x00, 0x00, // mov ecx, IA32_APIC_BASE
            0x0F, 0x32, // rdmsr (not intercepted)
            0x89, 0xC1, // mov ecx, eax
            0x81, 0xE1, 0x00, 0x0C, 0x00, 0x00, // and ecx, APIC_BASE_MODE
            0x81, 0xF9, 0x00, 0x08, 0x00, 0x00, // cmp ecx, APIC_BASE_XAPIC
            0x75, 0x65, // jne guest_emulation_failed (+101)
            0x48, 0xC1, 0xE2, 0x20, // shl rdx, 32
            0x48, 0x09, 0xD0, // or rax, rdx
            0x4C, 0x21, 0xD0, // and rax, r10
            0x48, 0x25, 0x00, 0xF0, 0xFF, 0xFF, // and rax, -PAGE_SIZE
            0x8B, 0x40, 0x30, // mov eax, [rax + LAPIC_VERSION]
            0x3C, 0x10, // cmp al, 0x10
            0x72, 0x4E, // jb guest_emulation_failed (+78)
            0x3C, 0x15, // cmp al, 0x15
            0x77, 0x4A, // ja guest_emulation_failed (+74)
            0xF4, // hlt
            0x31, 0xDB, // xor ebx, ebx
            0x48, 0x8D, 0x3D, // lea rdi, [rip + guest_code_start]:
            0xAC, 0xFE, 0xFF, 0xFF, //   -340, back to byte 0
            0x48, 0x81, 0xC7, // add rdi, 0x1000
            0x00, 0x10, 0x00, 0x00, 0x8B, 0x0F, // mov ecx, [rdi]
            0xC7, 0x07, // mov dword ptr [rdi], GUEST_EPT_VALUE
            0x54, 0x50, 0x45, 0x00, 0x8B, 0x17, // mov edx, [rdi]
            0xB8, 0xE0, 0xA1, 0x00, 0x00, // mov eax, GUEST_MARKER
            0x0F, 0x01, 0xC1, // vmcall (main VMCALL #1)
            0xB9, 0x00, 0x00, 0x00, 0x04, // mov ecx, GUEST_WAIT_ITERATIONS
            0x85, 0xDB, // wait: test ebx, ebx
            0x75, 0x06, // jnz done (+6)
            0xF3, 0x90, // pause
            0xFF, 0xC9, // dec ecx
            0x75, 0xF6, // jnz wait (-10)
            0xFF, 0xC0, // done: inc eax
            0x0F, 0x01, 0xC1, // vmcall (main VMCALL #2)
            0x0F, 0x0B, // ud2
            0x50, // nmi handler: push rax
            0xB8, 0x49, 0x4D, 0x4E, 0x00, // mov eax, GUEST_NMI_MARKER
            0x0F, 0x01, 0xC1, // vmcall
            0x58, // pop rax
            0xBB, 0x01, 0x00, 0x00, 0x00, // mov ebx, 1
            0x48, 0xCF, // iretq
            0xB8, 0x11, 0xFA, 0x00, 0x00, // guest_emulation_failed: mov eax, GUEST_EMULATION_FAIL_MARKER
            0x0F, 0x0B, // ud2
        ],
    );
}

#[test]
fn nmi_handler_starts_after_the_main_code() {
    // Byte 387 in the listing above: right after the ud2.
    assert_eq!(nmi_handler_offset(), 387);
}

#[test]
fn the_mtrr_base_is_uc_in_a_physbase_and_2_mib_aligned() {
    // `mov eax` loads it whole: it fits in 32 bits, with the type, UC (0),
    // in bits 7:0.
    let physbase = GUEST_MTRR_BASE | crate::vmx::mtrr::MemoryType::Uncacheable as u64;
    assert_eq!(physbase, 0x20_0000);
    assert!(GUEST_MTRR_BASE.is_multiple_of(SIZE_2M));
}

#[test]
fn ept_value_spells_ept() {
    assert_eq!(GUEST_EPT_VALUE.to_be_bytes(), [0, b'E', b'P', b'T']);
}

#[test]
fn guest_code_fits_in_one_page() {
    assert!(guest_code().len() <= PAGE_SIZE);
}

/// A supervisor, writable, executable 4 KiB page.
fn kernel_page() -> Mapping {
    Mapping {
        physical: 0x7eb1_9000,
        size: paging::PageSize::Size4K,
        writable: true,
        user: false,
        execute_disable: false,
    }
}

const SMEP_AND_SMAP: u64 = cr::CR4_SMEP | cr::CR4_SMAP;

#[test]
fn identity_mapped_page_passes() {
    assert_eq!(check_identity(0x7eb1_9000, &kernel_page()), Ok(()));
}

#[test]
fn page_mapped_elsewhere_is_refused() {
    assert_eq!(
        check_identity(0xffff_8000_7eb1_9000, &kernel_page()),
        Err(GuestMemoryError::NotIdentityMapped {
            virtual_address: 0xffff_8000_7eb1_9000,
            physical: 0x7eb1_9000,
        }),
    );
}

#[test]
fn kernel_pages_pass_even_with_smep_and_smap() {
    assert_eq!(check_permissions(&kernel_page(), &kernel_page(), SMEP_AND_SMAP), Ok(()));
}

#[test]
fn code_with_xd_is_refused() {
    let code = Mapping {
        execute_disable: true,
        ..kernel_page()
    };
    assert_eq!(
        check_permissions(&code, &kernel_page(), 0),
        Err(GuestMemoryError::CodeNotExecutable)
    );
}

#[test]
fn user_code_is_refused_only_under_smep() {
    let code = Mapping {
        user: true,
        ..kernel_page()
    };
    assert_eq!(check_permissions(&code, &kernel_page(), 0), Ok(()));
    assert_eq!(
        check_permissions(&code, &kernel_page(), cr::CR4_SMEP),
        Err(GuestMemoryError::CodeBlockedBySmep),
    );
}

#[test]
fn read_only_stack_is_refused() {
    let stack = Mapping {
        writable: false,
        ..kernel_page()
    };
    assert_eq!(
        check_permissions(&kernel_page(), &stack, 0),
        Err(GuestMemoryError::StackNotWritable)
    );
}

#[test]
fn user_stack_is_refused_only_under_smap() {
    let stack = Mapping {
        user: true,
        ..kernel_page()
    };
    assert_eq!(check_permissions(&kernel_page(), &stack, 0), Ok(()));
    assert_eq!(
        check_permissions(&kernel_page(), &stack, cr::CR4_SMAP),
        Err(GuestMemoryError::StackBlockedBySmap),
    );
}

#[test]
fn kernel_idt_passes_under_smap() {
    assert_eq!(check_idt_permissions(&kernel_page(), SMEP_AND_SMAP), Ok(()));
}

#[test]
fn writable_kernel_data_page_passes_under_smap() {
    assert_eq!(check_data_permissions(&kernel_page(), SMEP_AND_SMAP), Ok(()));
}

#[test]
fn read_only_data_page_is_refused() {
    let data = Mapping {
        writable: false,
        ..kernel_page()
    };
    assert_eq!(check_data_permissions(&data, 0), Err(GuestMemoryError::DataNotWritable));
}

#[test]
fn user_data_page_is_refused_only_under_smap() {
    let data = Mapping {
        user: true,
        ..kernel_page()
    };
    assert_eq!(check_data_permissions(&data, 0), Ok(()));
    assert_eq!(
        check_data_permissions(&data, cr::CR4_SMAP),
        Err(GuestMemoryError::DataBlockedBySmap)
    );
}

#[test]
fn user_idt_is_refused_only_under_smap() {
    let idt = Mapping {
        user: true,
        ..kernel_page()
    };
    assert_eq!(check_idt_permissions(&idt, 0), Ok(()));
    assert_eq!(
        check_idt_permissions(&idt, cr::CR4_SMAP),
        Err(GuestMemoryError::IdtBlockedBySmap)
    );
}

#[test]
fn expected_stats_keep_what_an_nmi_changes_and_nothing_else() {
    // A run with -InjectNmi: two more exits, one NMI injected.
    let with_nmi = VcpuStats {
        exits: 15,
        nmi_injections: 1,
        ..expected_stats(&VcpuStats::ZERO)
    };
    assert_eq!(expected_stats(&with_nmi), with_nmi);
    // A run whose HLT never exited, or that got a #GP it should not have.
    for wrong in [
        VcpuStats {
            halt_exits: 0,
            ..with_nmi
        },
        VcpuStats {
            exception_injections: 1,
            ..with_nmi
        },
    ] {
        assert_ne!(expected_stats(&wrong), wrong);
    }
}
