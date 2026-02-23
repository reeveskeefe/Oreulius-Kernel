; x86_64 shim/runtime bridge for incremental Oreulia bring-up
; - Provides real low-level primitives needed by the x86_64 bring-up path.
; - Provides real x86_64 ISR/IRQ stubs for a minimal IDT/trap pipeline.
; - Keeps generic zero-return stubs for the rest of the unported asm backend.

[bits 64]
default rel

extern x86_64_trap_dispatch

%macro STUB_ZERO 1
    global %1
%1:
    xor eax, eax
    ret
%endmacro

%macro PUSH_GPRS 0
    push rax
    push rbx
    push rcx
    push rdx
    push rbp
    push rdi
    push rsi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
%endmacro

%macro POP_GPRS 0
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rsi
    pop rdi
    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

section .text

; ---- Minimal real primitives used by early x86_64 bring-up / common paths ----

global asm_enable_interrupts
asm_enable_interrupts:
    sti
    ret

global asm_disable_interrupts
asm_disable_interrupts:
    cli
    ret

global asm_halt
asm_halt:
.hang:
    cli
    hlt
    jmp .hang

global fast_sti
fast_sti:
    sti
    ret

global fast_cli_save
fast_cli_save:
    pushfq
    pop rax
    cli
    ret

global fast_sti_restore
fast_sti_restore:
    test edi, 0x200
    jz .done
    sti
.done:
    ret

global get_interrupt_state
get_interrupt_state:
    pushfq
    pop rax
    shr rax, 9
    and eax, 1
    ret

global asm_outb
asm_outb:
    mov dx, di
    mov al, sil
    out dx, al
    ret

global asm_inb
asm_inb:
    mov dx, di
    xor eax, eax
    in al, dx
    ret

global asm_read_cr0
asm_read_cr0:
    mov rax, cr0
    ret

global asm_write_cr0
asm_write_cr0:
    mov eax, edi
    mov cr0, rax
    ret

global asm_read_cr4
asm_read_cr4:
    mov rax, cr4
    ret

global asm_write_cr4
asm_write_cr4:
    mov eax, edi
    mov cr4, rax
    ret

global get_page_directory
get_page_directory:
    mov rax, cr3
    ret

global load_page_directory
load_page_directory:
    mov eax, edi
    mov cr3, rax
    ret

global flush_tlb_single
flush_tlb_single:
    invlpg [rdi]
    ret

global flush_tlb_all
flush_tlb_all:
    mov rax, cr3
    mov cr3, rax
    ret

global enable_paging
enable_paging:
    mov rax, cr0
    bts rax, 31
    mov cr0, rax
    ret

global is_paging_enabled
is_paging_enabled:
    mov rax, cr0
    shr rax, 31
    and eax, 1
    ret

global read_msr
read_msr:
    mov ecx, edi
    rdmsr
    shl rdx, 32
    or rax, rdx
    ret

global write_msr
write_msr:
    mov ecx, edi
    mov eax, esi
    wrmsr
    ret

global memory_barrier
memory_barrier:
    mfence
    ret

global load_barrier
load_barrier:
    lfence
    ret

global store_barrier
store_barrier:
    sfence
    ret

global gdt_load
gdt_load:
    lgdt [rdi]
    ret

global idt_load
idt_load:
    lidt [rdi]
    ret

global tss_load
tss_load:
    mov ax, di
    ltr ax
    ret

global tss_set_kernel_stack
tss_set_kernel_stack:
    ; Compatibility shim for legacy signature:
    ;   rdi = TSS base (treated as x86_64 TSS base)
    ;   esi = esp0 low32 (used as rsp0 low32 during bring-up)
    ;   dx  = ss0 (ignored in long mode TSS)
    mov dword [rdi + 4], esi
    mov dword [rdi + 8], 0
    ret

; ---- Real x86_64 exception/IRQ stubs for bring-up ----

global x64_interrupt_common
x64_interrupt_common:
    cld
    PUSH_GPRS
    mov rdi, [rsp + 15*8]          ; vector
    mov rsi, [rsp + 16*8]          ; error code
    lea rdx, [rsp + 17*8]          ; RIP/CS/RFLAGS frame head (and possibly more)
    call x86_64_trap_dispatch
    POP_GPRS
    add rsp, 16                    ; drop vector + error code
    iretq

%macro ISR_NOERR 1
    global isr%1
isr%1:
    push qword 0
    push qword %1
    jmp x64_interrupt_common
%endmacro

%macro ISR_ERR 1
    global isr%1
isr%1:
    push qword %1
    jmp x64_interrupt_common
%endmacro

%macro IRQ_STUB 1
    global irq%1
irq%1:
    push qword 0
    push qword (32 + %1)
    jmp x64_interrupt_common
%endmacro

ISR_NOERR 0
ISR_NOERR 1
ISR_NOERR 2
ISR_NOERR 3
ISR_NOERR 4
ISR_NOERR 5
ISR_NOERR 6
ISR_NOERR 7
ISR_ERR   8
ISR_NOERR 9
ISR_ERR   10
ISR_ERR   11
ISR_ERR   12
ISR_ERR   13
ISR_ERR   14
ISR_NOERR 15
ISR_NOERR 16
ISR_ERR   17
ISR_NOERR 18
ISR_NOERR 19
ISR_NOERR 20
ISR_ERR   21
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_ERR   29
ISR_ERR   30
ISR_NOERR 31

IRQ_STUB 0
IRQ_STUB 1
IRQ_STUB 2
IRQ_STUB 3
IRQ_STUB 4
IRQ_STUB 5
IRQ_STUB 6
IRQ_STUB 7
IRQ_STUB 8
IRQ_STUB 9
IRQ_STUB 10
IRQ_STUB 11
IRQ_STUB 12
IRQ_STUB 13
IRQ_STUB 14
IRQ_STUB 15

; ---- Generic zero-return stubs for unported x86-only backends ----
STUB_ZERO asm_atomic_add
STUB_ZERO asm_atomic_and
STUB_ZERO asm_atomic_cmpxchg
STUB_ZERO asm_atomic_dec
STUB_ZERO asm_atomic_inc
STUB_ZERO asm_atomic_load
STUB_ZERO asm_atomic_or
STUB_ZERO asm_atomic_store
STUB_ZERO asm_atomic_sub
STUB_ZERO asm_atomic_swap
STUB_ZERO asm_atomic_xor
STUB_ZERO asm_benchmark_add
STUB_ZERO asm_benchmark_div
STUB_ZERO asm_benchmark_load
STUB_ZERO asm_benchmark_lock
STUB_ZERO asm_benchmark_mul
STUB_ZERO asm_benchmark_nop
STUB_ZERO asm_benchmark_store
STUB_ZERO asm_checksum_ip
STUB_ZERO asm_cpuid
STUB_ZERO asm_fast_memcmp
STUB_ZERO asm_fast_memcpy
STUB_ZERO asm_fast_memset
STUB_ZERO asm_get_cpu_vendor
STUB_ZERO asm_has_avx
STUB_ZERO asm_has_sse
STUB_ZERO asm_has_sse2
STUB_ZERO asm_has_sse3
STUB_ZERO asm_has_sse4_1
STUB_ZERO asm_has_sse4_2
STUB_ZERO asm_hash_djb2
STUB_ZERO asm_hash_fnv1a
STUB_ZERO asm_hash_sdbm
STUB_ZERO asm_jit_fault_resume
STUB_ZERO asm_load_context
STUB_ZERO asm_rdrand
STUB_ZERO asm_rdtsc_begin
STUB_ZERO asm_rdtsc_end
STUB_ZERO asm_read_tsc
STUB_ZERO asm_spinlock_init
STUB_ZERO asm_spinlock_lock
STUB_ZERO asm_spinlock_trylock
STUB_ZERO asm_spinlock_unlock
STUB_ZERO asm_swap_endian_16
STUB_ZERO asm_swap_endian_32
STUB_ZERO asm_switch_context
STUB_ZERO asm_xsave_supported
STUB_ZERO atomic_dec_refcount
STUB_ZERO atomic_inc_refcount
STUB_ZERO enter_user_mode
STUB_ZERO get_interrupt_count
STUB_ZERO increment_interrupt_count
STUB_ZERO jit_user_enter
STUB_ZERO pic_remap
STUB_ZERO pic_send_eoi
STUB_ZERO sgx_encls
STUB_ZERO sgx_enclu
STUB_ZERO syscall_entry
STUB_ZERO sysenter_entry
STUB_ZERO temporal_copy_bytes
STUB_ZERO temporal_fnv1a32
STUB_ZERO temporal_hash_pair
STUB_ZERO temporal_merkle_root_u32
STUB_ZERO thread_start_trampoline

section .bss
alignb 8
%macro STUB_QWORD 1
    global %1
%1:
    resq 1
%endmacro

; Debug/diagnostic extern statics read by idt/context debug paths
STUB_QWORD asm_dbg_ctx_ptr
STUB_QWORD asm_dbg_eip_target
STUB_QWORD asm_dbg_entry_popped
STUB_QWORD asm_dbg_esp_loaded
STUB_QWORD asm_dbg_stage
STUB_QWORD asm_sw_new_eip
STUB_QWORD asm_sw_new_esp
STUB_QWORD asm_sw_new_ptr
STUB_QWORD asm_sw_old_ptr
STUB_QWORD asm_sw_saved_old_eip
STUB_QWORD asm_sw_stage

section .note.GNU-stack noalloc noexec nowrite progbits
