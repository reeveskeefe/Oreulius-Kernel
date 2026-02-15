; kernel/asm/interrupt.asm
; Low-latency interrupt and CPU control operations
; Provides direct hardware access for kernel operations

global asm_enable_interrupts
global asm_disable_interrupts
global asm_halt
global asm_read_tsc
global asm_io_wait
global asm_read_cr0
global asm_write_cr0
global asm_read_cr3
global asm_write_cr3
global asm_read_cr4
global asm_write_cr4
global asm_stac
global asm_clac
global asm_jit_fault_resume
global asm_outb
global asm_inb

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

; Write CR0 control register
; Args: (value: u32)
asm_write_cr0:
    mov eax, [esp + 4]
    mov cr0, eax
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

; Read CR4 control register
; Returns: EAX = CR4
asm_read_cr4:
    mov eax, cr4
    ret

; Write CR4 control register
; Args: (value: u32)
asm_write_cr4:
    mov eax, [esp + 4]
    mov cr4, eax
    ret

; Set AC flag (SMAP: allow supervisor access to user pages)
asm_stac:
    stac
    ret

; Clear AC flag (SMAP: disallow supervisor access to user pages)
asm_clac:
    clac
    ret

; Resume from a JIT sandbox page fault by unwinding the JIT frame.
; Assumes EBP still points to the JIT frame base.
asm_jit_fault_resume:
    mov esp, ebp
    pop ebp
    ret

; Output byte to port (OUT DX, AL)
; Args: (port: u16, value: u8)
asm_outb:
    mov dx, [esp + 4]  ; port
    mov al, [esp + 8]  ; value
    out dx, al
    ret

; Input byte from port (IN AL, DX)
; Args: (port: u16)
; Returns: AL (read value)
asm_inb:
    mov dx, [esp + 4]  ; port
    xor eax, eax       ; clear eax
    in al, dx
    ret
