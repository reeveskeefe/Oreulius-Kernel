; Multiboot header for GRUB
MULTIBOOT_MAGIC equ 0x1BADB002
MULTIBOOT_FLAGS equ 0x0
MULTIBOOT_CHECKSUM equ -(MULTIBOOT_MAGIC + MULTIBOOT_FLAGS)

section .multiboot
align 4
    dd MULTIBOOT_MAGIC
    dd MULTIBOOT_FLAGS
    dd MULTIBOOT_CHECKSUM

section .text
global _start
extern rust_main
extern arch_x86_record_boot_handoff
extern sbss
extern ebss

_start:
    ; Preserve multiboot bootloader handoff before clobbering EAX/EBX.
    ; EAX = boot magic, EBX = multiboot info pointer.
    mov esi, eax
    mov edx, ebx

    ; Direct VGA write - no BIOS interrupts (we're in protected mode)
    ; Clear screen
    mov edi, 0xb8000
    mov ecx, 2000
    mov ax, 0x0720  ; Light gray on black space
    rep stosw
    
    ; Write "BOOT" at top left
    mov word [0xb8000], 0x0742  ; 'B' light gray
    mov word [0xb8002], 0x074f  ; 'O' light gray
    mov word [0xb8004], 0x074f  ; 'O' light gray
    mov word [0xb8006], 0x0754  ; 'T' light gray

    ; Zero BSS section (vital for static Mutexes)
    mov edi, sbss
    mov ecx, ebss
    sub ecx, sbss
    shr ecx, 2      ; Convert bytes to dwords
    xor eax, eax
    rep stosd
    
    ; Set up stack
    mov esp, stack_top

    ; Record bootloader handoff in Rust-side storage (after BSS clear).
    ; cdecl: push args right-to-left => info_ptr, then magic.
    push edx
    push esi
    call arch_x86_record_boot_handoff
    add esp, 8
    
    ; Write "CALL" before calling rust_main
    mov word [0xb8008], 0x0743  ; 'C'
    mov word [0xb800a], 0x0741  ; 'A'
    mov word [0xb800c], 0x074c  ; 'L'
    mov word [0xb800e], 0x074c  ; 'L'
    
    call rust_main
    
    ; If we return (shouldn't happen), show "FAIL"
    mov word [0xb8010], 0x0446  ; 'F' red
    mov word [0xb8012], 0x0441  ; 'A' red
    mov word [0xb8014], 0x0449  ; 'I' red
    mov word [0xb8016], 0x044c  ; 'L' red
    
    cli
.hang:
    hlt
    jmp .hang

section .bss
align 16
stack_bottom:
    resb 131072
stack_top:

section .note.GNU-stack noalloc noexec nowrite progbits
