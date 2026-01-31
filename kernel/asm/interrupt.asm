; kernel/asm/interrupt.asm
; Low-latency interrupt and CPU control operations
; Provides direct hardware access for kernel operations

global asm_enable_interrupts
global asm_disable_interrupts
global asm_halt
global asm_read_tsc
global asm_io_wait
global asm_read_cr0
global asm_read_cr3
global asm_write_cr3

section .text

; Enable CPU interrupts (STI instruction)
; Allows hardware interrupts to be processed
asm_enable_interrupts:
    sti
    ret

; Disable CPU interrupts (CLI instruction)
; Prevents hardware interrupts during critical sections
asm_disable_interrupts:
    cli
    ret

; Halt CPU until next interrupt (HLT instruction)
; Reduces power consumption when idle
asm_halt:
    hlt
    ret

; Read CPU Time Stamp Counter (RDTSC instruction)
; Returns 64-bit cycle count in EDX:EAX
; Used for high-precision timing and performance measurement
asm_read_tsc:
    rdtsc  ; Result: EDX (high 32 bits), EAX (low 32 bits)
    ret

; I/O wait operation (port 0x80 delay)
; Provides ~1μs delay for legacy hardware compatibility
; Port 0x80 is unused and safe for delays
asm_io_wait:
    push eax
    mov al, 0
    out 0x80, al
    pop eax
    ret

; Read CR0 control register
; CR0 controls CPU operating mode (protected mode, paging, etc.)
asm_read_cr0:
    mov eax, cr0
    ret

; Read CR3 page directory register
; CR3 points to the page directory base address
asm_read_cr3:
    mov eax, cr3
    ret

; Write CR3 page directory register
; Args: (page_dir_addr: u32)
; Updates page directory and flushes TLB
asm_write_cr3:
    mov eax, [esp + 4]
    mov cr3, eax
    ret
