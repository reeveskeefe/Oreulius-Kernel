; x86_64_atomics.asm — Real x86_64 atomic primitives for Oreulius kernel
;
; Replaces all STUB_ZERO shims in x86_64_shims.asm for:
;   asm_atomic_add, asm_atomic_and, asm_atomic_cmpxchg, asm_atomic_dec,
;   asm_atomic_inc, asm_atomic_load, asm_atomic_or, asm_atomic_store,
;   asm_atomic_sub, asm_atomic_swap, asm_atomic_xor,
;   atomic_inc_refcount, atomic_dec_refcount
;
; ABI: System V AMD64 (args in rdi, rsi, rdx, rcx, r8, r9; return in rax)
; All operations are sequentially consistent (full fence semantics via LOCK prefix).

[bits 64]
default rel

section .text

; ---------------------------------------------------------------------------
; i64 asm_atomic_load(volatile i64 *ptr)
; Load a 64-bit value with acquire semantics.
; On x86_64, aligned loads are already atomic; LFENCE provides acquire barrier.
; ---------------------------------------------------------------------------
global asm_atomic_load
asm_atomic_load:
    mov     rax, [rdi]
    lfence
    ret

; ---------------------------------------------------------------------------
; void asm_atomic_store(volatile i64 *ptr, i64 val)
; Store a 64-bit value with release semantics.
; On x86_64, aligned stores are atomic; SFENCE provides release barrier.
; ---------------------------------------------------------------------------
global asm_atomic_store
asm_atomic_store:
    sfence
    mov     [rdi], rsi
    ret

; ---------------------------------------------------------------------------
; i64 asm_atomic_add(volatile i64 *ptr, i64 val)
; Atomically add val to *ptr. Returns the OLD value.
; ---------------------------------------------------------------------------
global asm_atomic_add
asm_atomic_add:
    mov     rax, rsi
    lock xadd [rdi], rax       ; rax = old value; *ptr += old+val
    ret

; ---------------------------------------------------------------------------
; i64 asm_atomic_sub(volatile i64 *ptr, i64 val)
; Atomically subtract val from *ptr. Returns the OLD value.
; ---------------------------------------------------------------------------
global asm_atomic_sub
asm_atomic_sub:
    neg     rsi
    mov     rax, rsi
    lock xadd [rdi], rax
    ret

; ---------------------------------------------------------------------------
; i64 asm_atomic_inc(volatile i64 *ptr)
; Atomically increment *ptr. Returns the NEW value.
; ---------------------------------------------------------------------------
global asm_atomic_inc
asm_atomic_inc:
    mov     rax, 1
    lock xadd [rdi], rax
    inc     rax                 ; xadd returns old; add 1 for new value
    ret

; ---------------------------------------------------------------------------
; i64 asm_atomic_dec(volatile i64 *ptr)
; Atomically decrement *ptr. Returns the NEW value.
; ---------------------------------------------------------------------------
global asm_atomic_dec
asm_atomic_dec:
    mov     rax, -1
    lock xadd [rdi], rax
    dec     rax                 ; xadd returns old; sub 1 for new value
    ret

; ---------------------------------------------------------------------------
; i64 asm_atomic_swap(volatile i64 *ptr, i64 new_val)
; Atomically exchange *ptr with new_val. Returns the OLD value.
; ---------------------------------------------------------------------------
global asm_atomic_swap
asm_atomic_swap:
    mov     rax, rsi
    lock xchg [rdi], rax       ; xchg is always locked on x86
    ret

; ---------------------------------------------------------------------------
; i64 asm_atomic_cmpxchg(volatile i64 *ptr, i64 expected, i64 new_val)
; If *ptr == expected, store new_val. Returns the OLD value.
; Caller checks: if (ret == expected) then swap succeeded.
; ---------------------------------------------------------------------------
global asm_atomic_cmpxchg
asm_atomic_cmpxchg:
    mov     rax, rsi            ; expected → rax (CMPXCHG source)
    lock cmpxchg [rdi], rdx    ; if [rdi]==rax then [rdi]=rdx; rax=old
    ret

; ---------------------------------------------------------------------------
; i64 asm_atomic_and(volatile i64 *ptr, i64 mask)
; Atomically AND *ptr with mask. Returns the NEW value.
; Uses lock cmpxchg loop since there is no lock AND with return.
; ---------------------------------------------------------------------------
global asm_atomic_and
asm_atomic_and:
.retry:
    mov     rax, [rdi]          ; load current value
    mov     rcx, rax
    and     rcx, rsi            ; compute new = old & mask
    lock cmpxchg [rdi], rcx    ; if *ptr == rax, store rcx
    jnz     .retry              ; ZF=0 means CAS failed; retry
    mov     rax, rcx            ; return new value
    ret

; ---------------------------------------------------------------------------
; i64 asm_atomic_or(volatile i64 *ptr, i64 mask)
; Atomically OR *ptr with mask. Returns the NEW value.
; ---------------------------------------------------------------------------
global asm_atomic_or
asm_atomic_or:
.retry:
    mov     rax, [rdi]
    mov     rcx, rax
    or      rcx, rsi
    lock cmpxchg [rdi], rcx
    jnz     .retry
    mov     rax, rcx
    ret

; ---------------------------------------------------------------------------
; i64 asm_atomic_xor(volatile i64 *ptr, i64 mask)
; Atomically XOR *ptr with mask. Returns the NEW value.
; ---------------------------------------------------------------------------
global asm_atomic_xor
asm_atomic_xor:
.retry:
    mov     rax, [rdi]
    mov     rcx, rax
    xor     rcx, rsi
    lock cmpxchg [rdi], rcx
    jnz     .retry
    mov     rax, rcx
    ret

; ---------------------------------------------------------------------------
; i32 atomic_inc_refcount(volatile i32 *refcount)
; Increment a 32-bit reference counter. Returns the NEW count.
; Used by capability table reference tracking.
; ---------------------------------------------------------------------------
global atomic_inc_refcount
atomic_inc_refcount:
    mov     eax, 1
    lock xadd dword [rdi], eax
    inc     eax                 ; return new value
    ret

; ---------------------------------------------------------------------------
; i32 atomic_dec_refcount(volatile i32 *refcount)
; Decrement a 32-bit reference counter. Returns the NEW count.
; Returns 0 when the last reference is dropped.
; ---------------------------------------------------------------------------
global atomic_dec_refcount
atomic_dec_refcount:
    mov     eax, -1
    lock xadd dword [rdi], eax
    dec     eax                 ; return new value
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
