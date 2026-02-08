; GDT load and segment reload
[BITS 32]

section .text

global gdt_load

; void gdt_load(GdtPointer* ptr)
gdt_load:
    mov eax, [esp + 4]
    lgdt [eax]
    
    ; Reload data segments
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    
    ; Far jump to reload CS
    jmp 0x08:flush_cs

flush_cs:
    ret
