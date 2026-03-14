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
    ; Write "BOOT!" to VGA
    mov word [0xB8000], 0x2F42  ; 'B' green on black
    mov word [0xB8002], 0x2F4F  ; 'O'
    mov word [0xB8004], 0x2F4F  ; 'O'
    mov word [0xB8006], 0x2F54  ; 'T'
    mov word [0xB8008], 0x2F21  ; '!'
    
    cli
    hlt
    jmp $
