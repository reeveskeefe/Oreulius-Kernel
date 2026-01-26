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

_start:
    mov esp, stack_top
    call rust_main
    cli
.hang:
    hlt
    jmp .hang

section .bss
align 16
stack_bottom:
    resb 16384
stack_top:
