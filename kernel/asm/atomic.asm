; kernel/asm/atomic.asm
; Atomic operations and synchronization primitives
; Lock-free data structures and thread-safe operations

global asm_atomic_load
global asm_atomic_store
global asm_atomic_add
global asm_atomic_sub
global asm_atomic_inc
global asm_atomic_dec
global asm_atomic_swap
global asm_atomic_cmpxchg
global asm_atomic_cmpxchg_weak
global asm_atomic_and
global asm_atomic_or
global asm_atomic_xor
global asm_spinlock_init
global asm_spinlock_lock
global asm_spinlock_unlock
global asm_spinlock_trylock
global asm_pause
global asm_mfence
global asm_lfence
global asm_sfence

section .text

; Atomic load (acquire semantics)
; Args: (ptr: *const u32) -> u32
; Ensures memory ordering - all subsequent loads/stores see this value
asm_atomic_load:
    mov eax, [esp + 4]   ; ptr
    mov eax, [eax]       ; Load value
    lfence               ; Load fence for acquire semantics
    ret

; Atomic store (release semantics)
; Args: (ptr: *mut u32, value: u32)
; Ensures all previous stores complete before this one
asm_atomic_store:
    mov eax, [esp + 4]   ; ptr
    mov edx, [esp + 8]   ; value
    sfence               ; Store fence for release semantics
    mov [eax], edx       ; Store value
    ret

; Atomic add and return old value
; Args: (ptr: *mut u32, value: u32) -> u32
asm_atomic_add:
    mov ecx, [esp + 4]   ; ptr
    mov eax, [esp + 8]   ; value
    lock xadd [ecx], eax ; Atomic exchange and add
    ret                  ; Returns old value in EAX

; Atomic subtract and return old value
; Args: (ptr: *mut u32, value: u32) -> u32
asm_atomic_sub:
    mov ecx, [esp + 4]   ; ptr
    mov eax, [esp + 8]   ; value
    neg eax              ; Negate to subtract
    lock xadd [ecx], eax ; Atomic exchange and add
    ret                  ; Returns old value in EAX

; Atomic increment and return new value
; Args: (ptr: *mut u32) -> u32
asm_atomic_inc:
    mov ecx, [esp + 4]   ; ptr
    mov eax, 1
    lock xadd [ecx], eax ; Atomic increment
    inc eax              ; Return new value (old + 1)
    ret

; Atomic decrement and return new value
; Args: (ptr: *mut u32) -> u32
asm_atomic_dec:
    mov ecx, [esp + 4]   ; ptr
    mov eax, -1
    lock xadd [ecx], eax ; Atomic decrement
    dec eax              ; Return new value (old - 1)
    ret

; Atomic swap (exchange)
; Args: (ptr: *mut u32, new_value: u32) -> u32
; Returns old value
asm_atomic_swap:
    mov ecx, [esp + 4]   ; ptr
    mov eax, [esp + 8]   ; new_value
    lock xchg [ecx], eax ; Atomic exchange
    ret                  ; Returns old value in EAX

; Atomic compare-and-swap (strong version)
; Args: (ptr: *mut u32, expected: u32, desired: u32) -> u32
; Returns old value; if old == expected, stores desired
asm_atomic_cmpxchg:
    mov ecx, [esp + 4]   ; ptr
    mov eax, [esp + 8]   ; expected
    mov edx, [esp + 12]  ; desired
    lock cmpxchg [ecx], edx  ; Compare and exchange
    ret                  ; Returns old value; ZF set if successful

; Atomic compare-and-swap (weak version - may spuriously fail)
; Same as strong version on x86, but provided for API compatibility
; Args: (ptr: *mut u32, expected: u32, desired: u32) -> u32
asm_atomic_cmpxchg_weak:
    mov ecx, [esp + 4]   ; ptr
    mov eax, [esp + 8]   ; expected
    mov edx, [esp + 12]  ; desired
    lock cmpxchg [ecx], edx
    ret

; Atomic bitwise AND
; Args: (ptr: *mut u32, value: u32)
asm_atomic_and:
    mov ecx, [esp + 4]   ; ptr
    mov eax, [esp + 8]   ; value
    lock and [ecx], eax  ; Atomic AND
    ret

; Atomic bitwise OR
; Args: (ptr: *mut u32, value: u32)
asm_atomic_or:
    mov ecx, [esp + 4]   ; ptr
    mov eax, [esp + 8]   ; value
    lock or [ecx], eax   ; Atomic OR
    ret

; Atomic bitwise XOR
; Args: (ptr: *mut u32, value: u32)
asm_atomic_xor:
    mov ecx, [esp + 4]   ; ptr
    mov eax, [esp + 8]   ; value
    lock xor [ecx], eax  ; Atomic XOR
    ret

; ===== Spinlock Implementation =====

; Initialize spinlock (set to unlocked state)
; Args: (lock: *mut u32)
asm_spinlock_init:
    mov eax, [esp + 4]   ; lock pointer
    mov dword [eax], 0   ; 0 = unlocked
    ret

; Acquire spinlock (busy-wait until acquired)
; Args: (lock: *mut u32)
; Lock value: 0 = unlocked, 1 = locked
asm_spinlock_lock:
    mov ecx, [esp + 4]   ; lock pointer
    
.spin:
    ; Try to acquire lock
    xor eax, eax         ; Expected value (0 = unlocked)
    mov edx, 1           ; Desired value (1 = locked)
    lock cmpxchg [ecx], edx
    jz .acquired         ; Jump if we got the lock (ZF set)
    
    ; Lock not acquired - spin with PAUSE
.pause_loop:
    pause                ; Hint to CPU we're spinning
    cmp dword [ecx], 0   ; Check if lock is still held
    jne .pause_loop      ; Keep spinning if locked
    jmp .spin            ; Try to acquire again

.acquired:
    ret

; Release spinlock
; Args: (lock: *mut u32)
asm_spinlock_unlock:
    mov eax, [esp + 4]   ; lock pointer
    mov dword [eax], 0   ; 0 = unlocked (no need for LOCK prefix on x86)
    ret

; Try to acquire spinlock without blocking
; Args: (lock: *mut u32) -> i32
; Returns 1 if acquired, 0 if already locked
asm_spinlock_trylock:
    mov ecx, [esp + 4]   ; lock pointer
    xor eax, eax         ; Expected value (0 = unlocked)
    mov edx, 1           ; Desired value (1 = locked)
    lock cmpxchg [ecx], edx
    jz .acquired         ; Jump if we got the lock
    
    xor eax, eax         ; Return 0 (failed to acquire)
    ret

.acquired:
    mov eax, 1           ; Return 1 (successfully acquired)
    ret

; ===== Memory Fence Instructions =====

; PAUSE instruction - hint to CPU that we're in a spin-wait loop
; Improves performance and reduces power consumption
asm_pause:
    pause
    ret

; Full memory fence (MFENCE)
; Ensures all previous loads and stores complete before subsequent ones
asm_mfence:
    mfence
    ret

; Load fence (LFENCE)
; Ensures all previous loads complete before subsequent loads/stores
asm_lfence:
    lfence
    ret

; Store fence (SFENCE)
; Ensures all previous stores complete before subsequent stores
asm_sfence:
    sfence
    ret
