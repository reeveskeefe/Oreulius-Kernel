; Interrupt Descriptor Table (IDT) Management
; Hardware interrupt handlers and exception vectors
; x86 32-bit architecture

[BITS 32]

section .text

; ============================================================================
; IDT Setup and Management
; ============================================================================

global idt_load
global idt_set_gate

; IDT entry structure (8 bytes):
; Offset 0-1: Handler address low 16 bits
; Offset 2-3: Code segment selector
; Offset 4:    Reserved (zero)
; Offset 5:    Type and attributes
; Offset 6-7:  Handler address high 16 bits

; Load IDT
; void idt_load(void* idt_ptr) // Points to IDTR structure
idt_load:
    mov eax, [esp + 4]
    lidt [eax]
    ret

; Set IDT gate
; void idt_set_gate(u32* idt, u8 num, u32 handler, u16 selector, u8 flags)
idt_set_gate:
    push ebp
    mov ebp, esp
    push eax
    push ebx
    push ecx
    push edx
    
    mov eax, [ebp + 8]      ; IDT base
    movzx ebx, byte [ebp + 12] ; Interrupt number
    shl ebx, 3              ; * 8 (size of entry)
    add eax, ebx            ; IDT[num]
    
    mov edx, [ebp + 16]     ; Handler address
    
    ; Low word of handler
    mov [eax], dx
    
    ; Selector
    mov cx, [ebp + 20]
    mov [eax + 2], cx
    
    ; Reserved byte
    mov byte [eax + 4], 0
    
    ; Flags
    mov cl, [ebp + 24]
    mov [eax + 5], cl
    
    ; High word of handler
    shr edx, 16
    mov [eax + 6], dx
    
    pop edx
    pop ecx
    pop ebx
    pop eax
    pop ebp
    ret

; ============================================================================
; Exception Handlers (0-31)
; ============================================================================

extern rust_exception_handler
extern KPTI_USER_CR3

; Macro for exception without error code
%macro ISR_NOERRCODE 1
global isr%1
isr%1:
    cli
    push dword 0            ; Dummy error code
    push dword %1           ; Exception number
    jmp isr_common_stub
%endmacro

; Macro for exception with error code
%macro ISR_ERRCODE 1
global isr%1
isr%1:
    cli
    ; Error code already pushed by CPU
    push dword %1           ; Exception number
    jmp isr_common_stub
%endmacro

; CPU Exceptions
ISR_NOERRCODE 0     ; Divide by zero
ISR_NOERRCODE 1     ; Debug
ISR_NOERRCODE 2     ; Non-maskable interrupt
ISR_NOERRCODE 3     ; Breakpoint
ISR_NOERRCODE 4     ; Overflow
ISR_NOERRCODE 5     ; Bound range exceeded
ISR_NOERRCODE 6     ; Invalid opcode
ISR_NOERRCODE 7     ; Device not available
ISR_ERRCODE   8     ; Double fault
ISR_NOERRCODE 9     ; Coprocessor segment overrun
ISR_ERRCODE   10    ; Invalid TSS
ISR_ERRCODE   11    ; Segment not present
ISR_ERRCODE   12    ; Stack-segment fault
ISR_ERRCODE   13    ; General protection fault
ISR_ERRCODE   14    ; Page fault (handled in cow.asm)
ISR_NOERRCODE 15    ; Reserved
ISR_NOERRCODE 16    ; x87 FPU error
ISR_ERRCODE   17    ; Alignment check
ISR_NOERRCODE 18    ; Machine check
ISR_NOERRCODE 19    ; SIMD floating-point exception
ISR_NOERRCODE 20    ; Virtualization exception
ISR_ERRCODE   21    ; Control protection exception
ISR_NOERRCODE 22    ; Reserved
ISR_NOERRCODE 23    ; Reserved
ISR_NOERRCODE 24    ; Reserved
ISR_NOERRCODE 25    ; Reserved
ISR_NOERRCODE 26    ; Reserved
ISR_NOERRCODE 27    ; Reserved
ISR_NOERRCODE 28    ; Reserved
ISR_NOERRCODE 29    ; Reserved
ISR_ERRCODE   30    ; Security exception
ISR_NOERRCODE 31    ; Reserved

; Common exception handler stub
isr_common_stub:
    ; Save all registers
    pushad                  ; Push EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI
    
    ; Save segment registers
    push ds
    push es
    push fs
    push gs
    
    ; Load kernel data segment
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    
    ; Push interrupt frame pointer
    mov eax, esp
    push eax
    
    ; Call Rust handler
    call rust_exception_handler
    
    ; Pop frame pointer
    add esp, 4
    
    ; Restore segment registers
    pop gs
    pop fs
    pop es
    pop ds
    
    ; Restore general registers
    popad
    
    ; Clean up error code and interrupt number
    add esp, 8

    ; KPTI: restore user CR3 if returning to ring 3
    mov eax, [KPTI_USER_CR3]
    test eax, eax
    je .isr_kpti_done
    mov edx, [esp + 4]      ; CS selector on stack
    test dl, 0x3            ; CPL == 3?
    jz .isr_kpti_done
    mov cr3, eax
.isr_kpti_done:
    
    ; Return from interrupt
    iretd

; ============================================================================
; IRQ Handlers (32-47)
; ============================================================================

extern rust_irq_handler

; Macro for hardware IRQ
%macro IRQ 2
global irq%1
irq%1:
    cli
    push dword 0            ; Dummy error code
    push dword %2           ; IRQ number
    jmp irq_common_stub
%endmacro

; Hardware IRQs (remapped to 32-47)
IRQ 0, 32               ; PIT timer
IRQ 1, 33               ; Keyboard
IRQ 2, 34               ; Cascade
IRQ 3, 35               ; COM2
IRQ 4, 36               ; COM1
IRQ 5, 37               ; LPT2
IRQ 6, 38               ; Floppy
IRQ 7, 39               ; LPT1
IRQ 8, 40               ; CMOS RTC
IRQ 9, 41               ; Free
IRQ 10, 42              ; Free
IRQ 11, 43              ; Free
IRQ 12, 44              ; PS/2 Mouse
IRQ 13, 45              ; FPU
IRQ 14, 46              ; Primary ATA
IRQ 15, 47              ; Secondary ATA

; Common IRQ handler stub
irq_common_stub:
    ; Save all registers
    pushad
    
    ; Save segment registers
    push ds
    push es
    push fs
    push gs
    
    ; Load kernel data segment
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    
    ; Push interrupt frame
    mov eax, esp
    push eax
    
    ; Call Rust handler
    call rust_irq_handler
    
    ; Pop frame pointer
    add esp, 4
    
    ; Restore segment registers
    pop gs
    pop fs
    pop es
    pop ds
    
    ; Restore registers
    popad
    
    ; Clean up error code and IRQ number
    add esp, 8

    ; KPTI: restore user CR3 if returning to ring 3
    mov eax, [KPTI_USER_CR3]
    test eax, eax
    je .irq_kpti_done
    mov edx, [esp + 4]      ; CS selector on stack
    test dl, 0x3            ; CPL == 3?
    jz .irq_kpti_done
    mov cr3, eax
.irq_kpti_done:
    
    ; Return from interrupt
    iretd

; ============================================================================
; PIC (8259) Management
; ============================================================================

global pic_send_eoi
global pic_remap
global pic_disable

; Send End-Of-Interrupt to PIC
; void pic_send_eoi(u8 irq)
pic_send_eoi:
    mov al, [esp + 4]       ; IRQ number
    
    ; If IRQ >= 8, send EOI to slave
    cmp al, 8
    jl .master_only
    
    ; Send EOI to slave PIC
    mov al, 0x20
    out 0xA0, al
    
.master_only:
    ; Always send EOI to master PIC
    mov al, 0x20
    out 0x20, al
    ret

; Remap PIC interrupts
; void pic_remap(u8 offset1, u8 offset2)
pic_remap:
    push eax
    push ebx
    
    ; Save masks
    in al, 0x21
    mov bl, al
    in al, 0xA1
    mov bh, al
    
    ; Start initialization
    mov al, 0x11
    out 0x20, al            ; ICW1: Init master
    out 0x80, al            ; wait
    out 0xA0, al            ; ICW1: Init slave
    out 0x80, al            ; wait
    
    ; Set vector offsets
    mov al, [esp + 12]      ; offset1
    out 0x21, al            ; ICW2: Master offset
    out 0x80, al            ; wait
    
    mov al, [esp + 16]      ; offset2
    out 0xA1, al            ; ICW2: Slave offset
    out 0x80, al            ; wait
    
    ; Set up cascade
    mov al, 4
    out 0x21, al            ; ICW3: Master has slave at IRQ2
    out 0x80, al            ; wait
    
    mov al, 2
    out 0xA1, al            ; ICW3: Slave cascade identity
    out 0x80, al            ; wait
    
    ; Set mode
    mov al, 0x01
    out 0x21, al            ; ICW4: 8086 mode
    out 0x80, al            ; wait
    out 0xA1, al
    out 0x80, al            ; wait
    
    ; Restore masks
    mov al, bl
    out 0x21, al
    mov al, bh
    out 0xA1, al
    
    pop ebx
    pop eax
    ret

; Disable PIC (mask all interrupts)
; void pic_disable(void)
pic_disable:
    mov al, 0xFF
    out 0x21, al            ; Mask all master IRQs
    out 0xA1, al            ; Mask all slave IRQs
    ret

; ============================================================================
; APIC Operations (for modern systems)
; ============================================================================

global apic_write
global apic_read
global apic_send_eoi

; Write to APIC register
; void apic_write(u32 reg, u32 value)
apic_write:
    push eax
    push edx
    
    mov edx, [esp + 12]     ; Register offset
    mov eax, [esp + 16]     ; Value
    
    ; APIC base is typically 0xFEE00000
    ; For now, assume it's memory-mapped
    ; In real implementation, get base from MSR
    
    pop edx
    pop eax
    ret

; Read from APIC register
; u32 apic_read(u32 reg)
apic_read:
    push edx
    
    mov edx, [esp + 8]      ; Register offset
    xor eax, eax
    
    ; Read from APIC base + offset
    
    pop edx
    ret

; Send EOI to APIC
; void apic_send_eoi(void)
apic_send_eoi:
    ; Write 0 to EOI register (0xB0)
    push eax
    xor eax, eax
    ; Write to 0xFEE000B0 in real implementation
    pop eax
    ret

; ============================================================================
; Fast Interrupt Disable/Enable
; ============================================================================

global fast_cli
global fast_sti
global fast_cli_save
global fast_sti_restore

; Fast interrupt disable
; void fast_cli(void)
fast_cli:
    cli
    ret

; Fast interrupt enable
; void fast_sti(void)
fast_sti:
    sti
    ret

; Disable interrupts and save state
; u32 fast_cli_save(void)
fast_cli_save:
    pushfd
    cli
    pop eax
    ret

; Restore interrupt state
; void fast_sti_restore(u32 flags)
fast_sti_restore:
    push dword [esp + 4]
    popfd
    ret

; ============================================================================
; Software Interrupts
; ============================================================================

global trigger_interrupt
; void trigger_interrupt(u8 vector)
trigger_interrupt:
    mov al, [esp + 4]
    
    ; Generate interrupt dynamically
    ; This is tricky in x86 - need self-modifying code
    ; or use INT imm8 with specific vectors
    
    ; For demo, support common vectors
    cmp al, 0x80
    je .int80
    cmp al, 3
    je .int3
    ret
    
.int80:
    int 0x80
    ret
    
.int3:
    int 3
    ret

; ============================================================================
; Interrupt Statistics
; ============================================================================

section .data
align 4
interrupt_counts: times 256 dd 0

section .text

global get_interrupt_count
global increment_interrupt_count
global clear_interrupt_counts

; Get interrupt count for specific vector
; u32 get_interrupt_count(u8 vector)
get_interrupt_count:
    movzx eax, byte [esp + 4]
    mov eax, [interrupt_counts + eax * 4]
    ret

; Increment interrupt count
; void increment_interrupt_count(u8 vector)
increment_interrupt_count:
    push eax
    movzx eax, byte [esp + 8]
    lock inc dword [interrupt_counts + eax * 4]
    pop eax
    ret

; Clear all interrupt counts
; void clear_interrupt_counts(void)
clear_interrupt_counts:
    push ecx
    push edi
    
    mov edi, interrupt_counts
    xor eax, eax
    mov ecx, 256
    rep stosd
    
    pop edi
    pop ecx
    ret

; ============================================================================
; NMI Handling
; ============================================================================

global enable_nmi
global disable_nmi

; Enable NMI
; void enable_nmi(void)
enable_nmi:
    in al, 0x70
    and al, 0x7F            ; Clear bit 7
    out 0x70, al
    in al, 0x71             ; Dummy read
    ret

; Disable NMI
; void disable_nmi(void)
disable_nmi:
    in al, 0x70
    or al, 0x80             ; Set bit 7
    out 0x70, al
    in al, 0x71             ; Dummy read
    ret

; ============================================================================
; Exception Info
; ============================================================================

section .rodata
exception_names:
    dd .exc0, .exc1, .exc2, .exc3, .exc4, .exc5, .exc6, .exc7
    dd .exc8, .exc9, .exc10, .exc11, .exc12, .exc13, .exc14, .exc15
    dd .exc16, .exc17, .exc18, .exc19, .exc20, .exc21, .exc22, .exc23
    dd .exc24, .exc25, .exc26, .exc27, .exc28, .exc29, .exc30, .exc31

.exc0:  db "Divide-by-zero", 0
.exc1:  db "Debug", 0
.exc2:  db "Non-maskable Interrupt", 0
.exc3:  db "Breakpoint", 0
.exc4:  db "Overflow", 0
.exc5:  db "Bound Range Exceeded", 0
.exc6:  db "Invalid Opcode", 0
.exc7:  db "Device Not Available", 0
.exc8:  db "Double Fault", 0
.exc9:  db "Coprocessor Segment Overrun", 0
.exc10: db "Invalid TSS", 0
.exc11: db "Segment Not Present", 0
.exc12: db "Stack-Segment Fault", 0
.exc13: db "General Protection Fault", 0
.exc14: db "Page Fault", 0
.exc15: db "Reserved", 0
.exc16: db "x87 FPU Error", 0
.exc17: db "Alignment Check", 0
.exc18: db "Machine Check", 0
.exc19: db "SIMD Floating-Point Exception", 0
.exc20: db "Virtualization Exception", 0
.exc21: db "Control Protection Exception", 0
.exc22: db "Reserved", 0
.exc23: db "Reserved", 0
.exc24: db "Reserved", 0
.exc25: db "Reserved", 0
.exc26: db "Reserved", 0
.exc27: db "Reserved", 0
.exc28: db "Reserved", 0
.exc29: db "Reserved", 0
.exc30: db "Security Exception", 0
.exc31: db "Reserved", 0

section .text

global get_exception_name
; char* get_exception_name(u8 vector)
get_exception_name:
    movzx eax, byte [esp + 4]
    cmp eax, 31
    ja .invalid
    mov eax, [exception_names + eax * 4]
    ret
.invalid:
    xor eax, eax
    ret
