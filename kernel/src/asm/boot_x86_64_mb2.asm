; x86_64 Multiboot2 boot path (separate from the current i686 boot.asm path)
;
; Purpose:
; - Provide a dedicated Multiboot2 + long-mode handoff stub while the Rust
;   kernel body is still being incrementally ported.
; - Preserve the current i686 path untouched.

[bits 32]

MB2_MAGIC        equ 0xE85250D6
MB2_ARCH_I386    equ 0
MB2_HDR_LEN      equ mb2_header_end - mb2_header_start
MB2_CHECKSUM     equ -(MB2_MAGIC + MB2_ARCH_I386 + MB2_HDR_LEN)

CR0_PE           equ (1 << 0)
CR0_PG           equ (1 << 31)
CR4_PAE          equ (1 << 5)
EFER_MSR         equ 0xC0000080
EFER_LME         equ (1 << 8)

PTE_P            equ (1 << 0)
PTE_RW           equ (1 << 1)
PTE_PS           equ (1 << 7)

section .multiboot2
align 8
mb2_header_start:
    dd MB2_MAGIC
    dd MB2_ARCH_I386
    dd MB2_HDR_LEN
    dd MB2_CHECKSUM

    ; End tag
    dw 0
    dw 0
    dd 8
mb2_header_end:

section .text
global _start
extern rust_main
extern arch_x86_record_boot_handoff
extern sbss
extern ebss

_start:
    ; Multiboot{1,2} entry registers:
    ;   EAX = magic
    ;   EBX = info structure pointer
    mov esi, eax
    mov edx, ebx

    ; Clear BSS (also clears page tables / boot state storage below)
    mov edi, sbss
    mov ecx, ebss
    sub ecx, sbss
    shr ecx, 2
    xor eax, eax
    rep stosd

    ; Save boot handoff after BSS clear
    mov [boot_magic_saved], esi
    mov [boot_info_saved], edx

    ; Minimal VGA marker for early debug
    mov word [0xB8000], 0x1F36    ; '6' white on blue
    mov word [0xB8002], 0x1F34    ; '4'

    ; Check long mode support (CPUID.80000001H:EDX[29])
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .hang
    mov eax, 0x80000001
    cpuid
    bt edx, 29
    jnc .hang

    ; Build identity mapping for first 1 GiB using 2 MiB pages:
    ; PML4[0] -> PDPT[0] -> PD[0..511]
    mov eax, pdpt_table
    or eax, PTE_P | PTE_RW
    mov [pml4_table + 0], eax
    mov dword [pml4_table + 4], 0

    mov eax, pd_table0
    or eax, PTE_P | PTE_RW
    mov [pdpt_table + 0], eax
    mov dword [pdpt_table + 4], 0

    xor ecx, ecx
.fill_pd:
    mov eax, ecx
    shl eax, 21                    ; 2 MiB per PDE
    or eax, PTE_P | PTE_RW | PTE_PS
    mov [pd_table0 + ecx*8 + 0], eax
    mov dword [pd_table0 + ecx*8 + 4], 0
    inc ecx
    cmp ecx, 512
    jne .fill_pd

    lgdt [gdt64_ptr]

    ; Enable PAE
    mov eax, cr4
    or eax, CR4_PAE
    mov cr4, eax

    ; Load PML4 into CR3
    mov eax, pml4_table
    mov cr3, eax

    ; Set EFER.LME
    mov ecx, EFER_MSR
    rdmsr
    or eax, EFER_LME
    wrmsr

    ; Enable paging (PE already set by GRUB, but keep it asserted)
    mov eax, cr0
    or eax, CR0_PE | CR0_PG
    mov cr0, eax

    ; Far jump into 64-bit mode
    jmp 0x08:long_mode_start

.hang:
    cli
    hlt
    jmp .hang

[bits 64]
long_mode_start:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax

    mov rsp, stack_top

    ; Record boot handoff in Rust-side arch storage.
    mov edi, dword [rel boot_magic_saved]
    mov esi, dword [rel boot_info_saved]
    call arch_x86_record_boot_handoff

    ; Optional VGA marker after long mode transition
    mov word [0xB8004], 0x2F4C     ; 'L'
    mov word [0xB8006], 0x2F4D     ; 'M'

    call rust_main

.hang64:
    cli
    hlt
    jmp .hang64

section .rodata
align 8
gdt64:
    dq 0x0000000000000000          ; null
    dq 0x00AF9A000000FFFF          ; 64-bit code
    dq 0x00AF92000000FFFF          ; data
gdt64_end:

gdt64_ptr:
    dw gdt64_end - gdt64 - 1
    dd gdt64

section .bss
alignb 4096
pml4_table:
    resq 512
alignb 4096
pdpt_table:
    resq 512
alignb 4096
pd_table0:
    resq 512

boot_magic_saved:
    resd 1
boot_info_saved:
    resd 1

alignb 16
stack_bottom:
    resb 131072
stack_top:
