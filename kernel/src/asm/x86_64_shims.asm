; x86_64 shim/runtime bridge for incremental Oreulia bring-up
; - Provides real low-level primitives needed by the x86_64 bring-up path.
; - Provides real x86_64 ISR/IRQ stubs for a minimal IDT/trap pipeline.
; - Keeps generic zero-return stubs for the rest of the unported asm backend.

[bits 64]
default rel

extern x86_64_trap_dispatch
extern JIT_USER_RETURN_PENDING
extern JIT_USER_RETURN_EIP
extern JIT_USER_RETURN_ESP
extern JIT_USER_ACTIVE
extern JIT_USER_SYSCALL_VIOLATION
extern JIT_USER_DBG_SAVE_ESP
extern JIT_USER_DBG_SAVE_EIP
extern JIT_USER_DBG_SAVE_SEQ
extern JIT_USER_DBG_SYSCALL_ESP
extern JIT_USER_DBG_SYSCALL_EIP
extern JIT_USER_DBG_SYSCALL_SEQ
extern JIT_USER_DBG_SYSCALL_PATH
extern JIT_USER_DBG_SYSCALL_FLAGS
extern JIT_USER_DBG_SYSCALL_NR
extern JIT_USER_DBG_SYSCALL_FROM_EIP
extern JIT_USER_DBG_SYSCALL_FROM_CS

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

; x87/SSE FPU context save/restore used by scheduler FPU trap handling.
; Signature parity with legacy asm process backend:
;   void save_fpu_state(void* buffer)
;   void restore_fpu_state(const void* buffer)
global save_fpu_state
save_fpu_state:
    fxsave64 [rdi]
    ret

global restore_fpu_state
restore_fpu_state:
    fxrstor64 [rdi]
    ret

; Cooperative scheduler context for x86_64 kernel threads.
; Layout matches kernel/src/scheduler_platform.rs:
;   +0  rbx
;   +8  rbp
;   +16 r12
;   +24 r13
;   +32 r14
;   +40 r15
;   +48 rsp
;   +56 rip
;   +64 rflags
;   +72 cr3
global x86_64_sched_switch_context
x86_64_sched_switch_context:
    test rdi, rdi
    jz .x64_load_only

    mov [rdi + 0], rbx
    mov [rdi + 8], rbp
    mov [rdi + 16], r12
    mov [rdi + 24], r13
    mov [rdi + 32], r14
    mov [rdi + 40], r15
    mov [rdi + 48], rsp
    mov rax, [rsp]
    mov [rdi + 56], rax
    pushfq
    pop rax
    mov [rdi + 64], rax
    mov rax, cr3
    mov [rdi + 72], rax

.x64_load_only:
    mov rax, [rsi + 72]
    test rax, rax
    jz .x64_skip_cr3_switch
    mov rdx, cr3
    cmp rdx, rax
    je .x64_skip_cr3_switch
    mov cr3, rax

.x64_skip_cr3_switch:
    mov rax, [rsi + 56]
    mov rdx, [rsi + 48]
    mov rcx, [rsi + 64]
    mov rbx, [rsi + 0]
    mov rbp, [rsi + 8]
    mov r12, [rsi + 16]
    mov r13, [rsi + 24]
    mov r14, [rsi + 32]
    mov r15, [rsi + 40]
    mov rsp, rdx
    push rcx
    popfq
    add rsp, 8
    jmp rax

global x86_64_sched_load_context
x86_64_sched_load_context:
    cli
    mov rax, [rdi + 72]
    test rax, rax
    jz .x64_skip_cr3_load
    mov rdx, cr3
    cmp rdx, rax
    je .x64_skip_cr3_load
    mov cr3, rax

.x64_skip_cr3_load:
    mov rax, [rdi + 56]
    mov rdx, [rdi + 48]
    mov rcx, [rdi + 64]
    mov rbx, [rdi + 0]
    mov rbp, [rdi + 8]
    mov r12, [rdi + 16]
    mov r13, [rdi + 24]
    mov r14, [rdi + 32]
    mov r15, [rdi + 40]
    mov rsp, rdx
    push rcx
    popfq
    add rsp, 8
    jmp rax

global x86_64_thread_start_trampoline
x86_64_thread_start_trampoline:
    pop rax
    call rax

.x64_thread_halt:
    cli
    hlt
    jmp .x64_thread_halt

; Keep legacy scheduler symbol names linkable for the old 32-bit-only
; scheduler module that still compiles on x86_64, but route unexpected use
; into a safe halt instead of pretending the 32-bit context layout works here.
global asm_switch_context
asm_switch_context:
    ret

global asm_load_context
asm_load_context:
    jmp asm_halt

global thread_start_trampoline
thread_start_trampoline:
    jmp asm_halt

; Execute a JIT user-call descriptor (x86_64 SysV ABI) from a 32-bit-addressed
; call page used by the current x86-style JIT metadata layout.
; Signature: i32 x64_jit_callpage_exec(u32 call_ptr)
global x64_jit_callpage_exec
x64_jit_callpage_exec:
    push rbp
    mov rbp, rsp
    push rbx
    sub rsp, 8                      ; keep 16-byte alignment before nested call

    mov ebx, edi                    ; call-page pointer (low 32 bits)
    mov r10d, [rbx + 0]             ; entry

    ; First 6 args in registers (SysV x86_64 ABI)
    mov edi, [rbx + 4]              ; stack_ptr
    mov esi, [rbx + 8]              ; sp_ptr
    mov edx, [rbx + 12]             ; mem_ptr
    mov ecx, [rbx + 16]             ; mem_len
    mov r8d, [rbx + 20]             ; locals_ptr
    mov r9d, [rbx + 24]             ; instr_fuel_ptr

    ; Remaining args on stack (right-to-left): mem_fuel, trap, shadow_stack, shadow_sp
    mov eax, [rbx + 40]             ; shadow_sp_ptr
    push rax
    mov eax, [rbx + 36]             ; shadow_stack_ptr
    push rax
    mov eax, [rbx + 32]             ; trap_ptr
    push rax
    mov eax, [rbx + 28]             ; mem_fuel_ptr
    push rax

    call r10
    add rsp, 32

    mov [rbx + 44], eax             ; store return value into call page

    add rsp, 8
    pop rbx
    pop rbp
    ret

; Resume from a ring0 JIT fault by unwinding the x86_64 JIT prologue frame.
; The emitted JIT prologue is:
;   push rbp; mov rbp,rsp; push rbx,r12,r13,r14,r15; sub rsp,0x20
; so we restore callee-saved regs from [rbp-*] slots and return to caller.
global asm_jit_fault_resume
asm_jit_fault_resume:
    mov r15, [rbp - 40]
    mov r14, [rbp - 32]
    mov r13, [rbp - 24]
    mov r12, [rbp - 16]
    mov rbx, [rbp - 8]
    xor eax, eax
    mov rsp, rbp
    pop rbp
    ret

; Enter long-mode ring3 using an iretq frame.
; Signature compatibility with legacy path:
;   void jit_user_enter(u32 esp, u32 eip, u16 cs, u16 ds)
global jit_user_enter
jit_user_enter:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13

    mov rax, rsp
    mov qword [rel JIT_USER_RETURN_ESP], rax
    mov qword [rel JIT_USER_DBG_SAVE_ESP], rax
    lea rax, [rel .jit_return]
    mov qword [rel JIT_USER_RETURN_EIP], rax
    mov qword [rel JIT_USER_DBG_SAVE_EIP], rax
    mov eax, dword [rel JIT_USER_DBG_SAVE_SEQ]
    add eax, 1
    mov dword [rel JIT_USER_DBG_SAVE_SEQ], eax
    mov eax, 1
    xchg eax, dword [rel JIT_USER_ACTIVE]

    mov r12d, edi                ; user rsp
    mov r13d, esi                ; user rip
    movzx ebx, dx                ; user cs
    movzx eax, cx                ; user ds/ss

    cli
    mov ds, ax
    mov es, ax

    push rax                     ; SS
    push r12                     ; RSP
    pushfq
    pop rax
    and eax, 0xFFFFFDFF          ; clear IF for deterministic JIT sandbox execution
    push rax                     ; RFLAGS
    push rbx                     ; CS
    push r13                     ; RIP
    iretq

.jit_return:
    xor eax, eax
    xchg eax, dword [rel JIT_USER_ACTIVE]
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; Generic user entry helper used by usermode.rs tests (same ABI/signature).
global enter_user_mode
enter_user_mode:
    movzx r8d, dx                ; CS
    movzx r9d, cx                ; DS/SS
    cli
    mov ax, r9w
    mov ds, ax
    mov es, ax
    push r9                      ; SS
    mov r10d, edi
    push r10                     ; RSP
    pushfq
    pop rax
    or eax, 0x200                ; enable IF
    push rax
    push r8                      ; CS
    mov r11d, esi
    push r11                     ; RIP
    iretq

; x86_64 INT 0x80 handler for JIT return path (minimal bring-up implementation).
; On JIT return/violation, jump directly back to the saved kernel continuation.
global syscall_entry
syscall_entry:
    mov edx, dword [rsp + 0]     ; user RIP (low32)
    mov dword [rel JIT_USER_DBG_SYSCALL_FROM_EIP], edx
    mov edx, dword [rsp + 8]     ; user CS (low32)
    mov dword [rel JIT_USER_DBG_SYSCALL_FROM_CS], edx

    mov ecx, dword [rel JIT_USER_ACTIVE]
    test ecx, ecx
    je .sysret_iret
    cmp eax, 250
    je .jit_return_now
    mov dword [rel JIT_USER_SYSCALL_VIOLATION], 1
    mov dword [rel JIT_USER_DBG_SYSCALL_PATH], 2
    jmp .jit_handoff

.jit_return_now:
    mov dword [rel JIT_USER_DBG_SYSCALL_PATH], 1

.jit_handoff:
    mov dword [rel JIT_USER_RETURN_PENDING], 1
    xor ecx, ecx
    xchg ecx, dword [rel JIT_USER_ACTIVE]
    mov rdx, qword [rel JIT_USER_RETURN_ESP]
    mov rcx, qword [rel JIT_USER_RETURN_EIP]
    mov qword [rel JIT_USER_DBG_SYSCALL_ESP], rdx
    mov qword [rel JIT_USER_DBG_SYSCALL_EIP], rcx
    mov dword [rel JIT_USER_DBG_SYSCALL_NR], eax
    mov dword [rel JIT_USER_DBG_SYSCALL_FLAGS], 0
    mov ebx, dword [rel JIT_USER_DBG_SYSCALL_SEQ]
    add ebx, 1
    mov dword [rel JIT_USER_DBG_SYSCALL_SEQ], ebx
    mov rsp, rdx
    jmp rcx

.sysret_iret:
    iretq

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
STUB_ZERO asm_xsave_supported
STUB_ZERO atomic_dec_refcount
STUB_ZERO atomic_inc_refcount
STUB_ZERO get_interrupt_count
STUB_ZERO increment_interrupt_count
STUB_ZERO pic_remap
STUB_ZERO pic_send_eoi
STUB_ZERO sgx_encls
STUB_ZERO sgx_enclu
STUB_ZERO sysenter_entry
STUB_ZERO temporal_copy_bytes
STUB_ZERO temporal_fnv1a32
STUB_ZERO temporal_hash_pair
STUB_ZERO temporal_merkle_root_u32

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
