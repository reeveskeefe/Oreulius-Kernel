; Absolute minimal multiboot kernel to test GRUB
bits 32

; Multiboot header
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
_start:
    ; Fill screen with 'A' characters
    mov edi, 0xb8000
    mov ecx, 2000
    mov ax, 0x0741  ; 'A' light gray on black
.loop:
    stosw
    loop .loop
    
.hang:
    cli
    hlt
    jmp .hang
