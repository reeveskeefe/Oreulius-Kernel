; x86_64_pic.asm — 8259A Programmable Interrupt Controller (PIC) management
;
; Replaces STUB_ZERO shims for:
;   pic_remap     — remap master (IRQ0-7→IDT 0x20-0x27) and slave (IRQ8-15→IDT 0x28-0x2F)
;   pic_send_eoi  — send End-Of-Interrupt to master (and slave if IRQ >= 8)
;   pic_mask_irq  — mask (disable) a specific IRQ line
;   pic_unmask_irq — unmask (enable) a specific IRQ line
;   pic_disable   — mask all IRQs on both PICs (used before switching to APIC)
;
; PIC I/O port addresses
;   Master PIC: command = 0x20, data = 0x21
;   Slave PIC:  command = 0xA0, data = 0xA1
;
; ABI: System V AMD64

[bits 64]
default rel

PIC_MASTER_CMD  equ 0x20
PIC_MASTER_DAT  equ 0x21
PIC_SLAVE_CMD   equ 0xA0
PIC_SLAVE_DAT   equ 0xA1

; ICW1 flags
ICW1_INIT       equ 0x10        ; must be set for initialization
ICW1_ICW4       equ 0x01        ; ICW4 needed
; ICW4 flags
ICW4_8086       equ 0x01        ; 8086/88 mode (not MCS-80/85)

; EOI command
PIC_EOI         equ 0x20

; New IDT vector offsets
PIC_MASTER_VECTOR equ 0x20      ; IRQ0 → IDT vector 32
PIC_SLAVE_VECTOR  equ 0x28      ; IRQ8 → IDT vector 40

; Helper macro: I/O write
; io_wait: write to port 0x80 (POST port) to introduce ~1µs delay
; This is required after sending ICW commands to old 8259 chips.
%macro IO_WAIT 0
    push    rax
    xor     eax, eax
    out     0x80, al
    pop     rax
%endmacro

section .text

; ---------------------------------------------------------------------------
; void pic_remap(void)
; Remap both PICs so their IRQ vectors don't clash with CPU exceptions.
; Master: IRQ0-7  → IDT vectors 0x20-0x27
; Slave:  IRQ8-15 → IDT vectors 0x28-0x2F
; ---------------------------------------------------------------------------
global pic_remap
pic_remap:
    ; Save existing masks
    in      al, PIC_MASTER_DAT
    push    rax                 ; save master mask
    in      al, PIC_SLAVE_DAT
    push    rax                 ; save slave mask

    ; ICW1: start initialization sequence
    mov     al, (ICW1_INIT | ICW1_ICW4)
    out     PIC_MASTER_CMD, al
    IO_WAIT
    out     PIC_SLAVE_CMD, al
    IO_WAIT

    ; ICW2: set vector offsets
    mov     al, PIC_MASTER_VECTOR
    out     PIC_MASTER_DAT, al
    IO_WAIT
    mov     al, PIC_SLAVE_VECTOR
    out     PIC_SLAVE_DAT, al
    IO_WAIT

    ; ICW3: tell master about slave on IRQ2, tell slave its cascade identity
    mov     al, 0x04            ; master: slave on IRQ2 (bit 2)
    out     PIC_MASTER_DAT, al
    IO_WAIT
    mov     al, 0x02            ; slave: cascade identity = 2
    out     PIC_SLAVE_DAT, al
    IO_WAIT

    ; ICW4: set 8086 mode
    mov     al, ICW4_8086
    out     PIC_MASTER_DAT, al
    IO_WAIT
    out     PIC_SLAVE_DAT, al
    IO_WAIT

    ; Restore saved masks
    pop     rax
    out     PIC_SLAVE_DAT, al
    IO_WAIT
    pop     rax
    out     PIC_MASTER_DAT, al
    IO_WAIT

    ret

; ---------------------------------------------------------------------------
; void pic_send_eoi(u8 irq)
; Send End-Of-Interrupt. For IRQ >= 8 (slave-connected), send EOI to
; slave first then master.
; rdi = IRQ number (0-15)
; ---------------------------------------------------------------------------
global pic_send_eoi
pic_send_eoi:
    cmp     rdi, 8
    jl      .master_only
    ; Slave EOI required first
    mov     al, PIC_EOI
    out     PIC_SLAVE_CMD, al
.master_only:
    mov     al, PIC_EOI
    out     PIC_MASTER_CMD, al
    ret

; ---------------------------------------------------------------------------
; void pic_mask_irq(u8 irq)
; Disable (mask) a specific IRQ line.
; rdi = IRQ number (0-15)
; ---------------------------------------------------------------------------
global pic_mask_irq
pic_mask_irq:
    cmp     rdi, 8
    jge     .slave_mask
    ; Master: read current mask, set the bit, write back
    in      al, PIC_MASTER_DAT
    mov     cl, dil
    or      al, (1 << 0)        ; placeholder: use shift below
    ; Correct: al |= (1 << irq)
    in      al, PIC_MASTER_DAT
    mov     cl, dil
    mov     ah, 1
    shl     ah, cl
    or      al, ah
    out     PIC_MASTER_DAT, al
    ret
.slave_mask:
    sub     rdi, 8
    in      al, PIC_SLAVE_DAT
    mov     cl, dil
    mov     ah, 1
    shl     ah, cl
    or      al, ah
    out     PIC_SLAVE_DAT, al
    ret

; ---------------------------------------------------------------------------
; void pic_unmask_irq(u8 irq)
; Enable a specific IRQ line.
; rdi = IRQ number (0-15)
; ---------------------------------------------------------------------------
global pic_unmask_irq
pic_unmask_irq:
    cmp     rdi, 8
    jge     .slave_unmask
    in      al, PIC_MASTER_DAT
    mov     cl, dil
    mov     ah, 1
    shl     ah, cl
    not     ah
    and     al, ah
    out     PIC_MASTER_DAT, al
    ret
.slave_unmask:
    sub     rdi, 8
    in      al, PIC_SLAVE_DAT
    mov     cl, dil
    mov     ah, 1
    shl     ah, cl
    not     ah
    and     al, ah
    out     PIC_SLAVE_DAT, al
    ret

; ---------------------------------------------------------------------------
; void pic_disable(void)
; Mask all IRQ lines on both PICs. Used before enabling the APIC or IOAPIC.
; ---------------------------------------------------------------------------
global pic_disable
pic_disable:
    ; Mask all: write 0xFF to both data ports
    mov     al, 0xFF
    out     PIC_MASTER_DAT, al
    IO_WAIT
    out     PIC_SLAVE_DAT, al
    IO_WAIT
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
