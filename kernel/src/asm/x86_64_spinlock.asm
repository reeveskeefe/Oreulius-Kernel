; x86_64_spinlock.asm — x86_64 spinlock primitives with timeout
;
; Replaces STUB_ZERO shims for:
;   asm_spinlock_init     — initialize spinlock to unlocked state
;   asm_spinlock_lock     — acquire spinlock (spin with PAUSE, no timeout)
;   asm_spinlock_trylock  — attempt to acquire; returns 1 on success, 0 if busy
;   asm_spinlock_unlock   — release spinlock
;   asm_spinlock_lock_timeout — acquire with RDTSC deadline; returns 0 on timeout
;
; Spinlock layout: single 32-bit word.
;   0 = unlocked, 1 = locked
;
; ABI: System V AMD64

[bits 64]
default rel

; Default timeout: ~10 million TSC cycles (~3ms at 3 GHz)
SPINLOCK_DEFAULT_TIMEOUT_CYCLES equ 10000000

section .text

; ---------------------------------------------------------------------------
; void asm_spinlock_init(u32 *lock)
; Initialize a spinlock to the unlocked state (0).
; rdi = pointer to lock word
; ---------------------------------------------------------------------------
global asm_spinlock_init
asm_spinlock_init:
    mov     dword [rdi], 0
    sfence
    ret

; ---------------------------------------------------------------------------
; void asm_spinlock_lock(u32 *lock)
; Acquire spinlock. Spins indefinitely using PAUSE to reduce bus pressure.
; rdi = pointer to lock word
; ---------------------------------------------------------------------------
global asm_spinlock_lock
asm_spinlock_lock:
.try:
    ; Optimistically try to grab the lock with BTS (Bit Test and Set)
    ; BTS atomically reads the bit and sets it; returns old value in CF.
    lock bts dword [rdi], 0
    jnc     .acquired            ; CF=0 → was 0 (unlocked) → now locked
.spin:
    ; Already locked — spin-wait using PAUSE to avoid memory order violation
    ; in the store buffer and to be kind to HyperThreading siblings.
    pause
    test    dword [rdi], 1      ; non-atomic read for fast check
    jnz     .spin               ; still locked → keep waiting
    jmp     .try                ; may be unlocked now → retry with atomic BTS

.acquired:
    ; Memory barrier: prevent compiler/CPU from reordering subsequent loads
    ; before the lock acquire. The LOCK prefix of BTS already provides acquire
    ; semantics on x86, but an explicit lfence makes intent clear.
    lfence
    ret

; ---------------------------------------------------------------------------
; int asm_spinlock_trylock(u32 *lock)
; Attempt to acquire the spinlock in one shot. Does NOT spin.
; Returns 1 (eax) if lock was acquired, 0 if the lock was already held.
; rdi = pointer to lock word
; ---------------------------------------------------------------------------
global asm_spinlock_trylock
asm_spinlock_trylock:
    lock bts dword [rdi], 0
    setc    al          ; CF=1 → was already locked → return 0 (failure)
    xor     al, 1       ; invert: CF=0 (acquired) → al=1 (success)
    movzx   eax, al
    lfence
    ret

; ---------------------------------------------------------------------------
; void asm_spinlock_unlock(u32 *lock)
; Release spinlock. Uses BTR (Bit Test and Reset) for an atomic clear.
; rdi = pointer to lock word
; ---------------------------------------------------------------------------
global asm_spinlock_unlock
asm_spinlock_unlock:
    ; mfence ensures all prior stores (inside the critical section) are
    ; visible before we release the lock.
    mfence
    lock btr dword [rdi], 0
    ret

; ---------------------------------------------------------------------------
; int asm_spinlock_lock_timeout(u32 *lock, u64 timeout_cycles)
; Acquire spinlock with a TSC-based deadline.
; rdi = lock pointer
; rsi = timeout in TSC cycles (0 = use default SPINLOCK_DEFAULT_TIMEOUT_CYCLES)
; Returns 1 (eax) on success, 0 on timeout.
; ---------------------------------------------------------------------------
global asm_spinlock_lock_timeout
asm_spinlock_lock_timeout:
    ; Compute deadline
    test    rsi, rsi
    jnz     .has_timeout
    mov     rsi, SPINLOCK_DEFAULT_TIMEOUT_CYCLES
.has_timeout:
    ; Read start TSC (unserialized — fine for relative timing)
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    add     rsi, rax            ; deadline = now + timeout_cycles
    mov     r8, rsi             ; r8 = deadline

.timeout_try:
    lock bts dword [rdi], 0
    jnc     .timeout_acquired

.timeout_spin:
    pause
    ; Check deadline
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    cmp     rax, r8
    jae     .timeout_expired    ; current TSC >= deadline → give up

    test    dword [rdi], 1
    jnz     .timeout_spin
    jmp     .timeout_try

.timeout_acquired:
    lfence
    mov     eax, 1
    ret

.timeout_expired:
    xor     eax, eax
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
