; x86_64_perf.asm — Micro-benchmark loop helpers using serialized RDTSC
;
; Replaces STUB_ZERO shims for:
;   asm_benchmark_nop   — calibration loop: NOP × N, returns elapsed cycles
;   asm_benchmark_load  — cache-warm load loop: MOV × N from same address
;   asm_benchmark_store — store loop: MOV × N to the same address
;   asm_benchmark_add   — ALU loop: ADD × N (register-register)
;   asm_benchmark_mul   — MUL loop: IMUL × N (register-register)
;   asm_benchmark_div   — DIV loop: IDIV × N (register-register)
;   asm_benchmark_lock  — locked-increment loop: LOCK INC × N, returns cycles
;
; Each function takes:
;   rdi = iteration count (u64)
; Returns:
;   rax = elapsed TSC cycles (u64)
;
; Timing uses CPUID-serialized RDTSC at start and RDTSCP+LFENCE at end
; to prevent out-of-order execution from leaking across measurement boundaries.

[bits 64]
default rel

; Macro: serialize and read TSC → result in r10 (clobbers rax,rbx,rcx,rdx)
%macro TSC_START 0
    push    rbx
    xor     eax, eax
    cpuid                   ; serialize instruction stream
    rdtsc
    shl     rdx, 32
    or      rdx, rax
    mov     r10, rdx        ; r10 = start TSC
    pop     rbx
%endmacro

; Macro: read TSC (serialized end) → elapsed in rax; clobbers rdx,rcx
%macro TSC_END 0
    rdtscp                  ; ecx = IA32_TSC_AUX; rdx:rax = TSC
    lfence                  ; prevent later reads from reordering before rdtscp
    shl     rdx, 32
    or      rax, rdx
    sub     rax, r10        ; elapsed = end - start
%endmacro

section .text

; ---------------------------------------------------------------------------
; u64 asm_benchmark_nop(u64 iterations)
; Tight NOP loop — used to measure loop overhead for calibration.
; ---------------------------------------------------------------------------
global asm_benchmark_nop
asm_benchmark_nop:
    mov     r9, rdi             ; iteration count
    TSC_START
    test    r9, r9
    jz      .nop_done
.nop_loop:
    nop
    dec     r9
    jnz     .nop_loop
.nop_done:
    TSC_END
    ret

; ---------------------------------------------------------------------------
; u64 asm_benchmark_load(u64 iterations)
; Repeatedly loads from a cache-warm stack slot. Measures L1 load latency × N.
; ---------------------------------------------------------------------------
global asm_benchmark_load
asm_benchmark_load:
    mov     r9, rdi
    ; Use a stack slot as the load target — it will be in L1 after one touch
    sub     rsp, 8
    mov     qword [rsp], 0xDEADBEEFCAFEBABE
    TSC_START
    test    r9, r9
    jz      .load_done
.load_loop:
    mov     r8, [rsp]           ; load from stack (L1 hit after first iteration)
    dec     r9
    jnz     .load_loop
.load_done:
    TSC_END
    add     rsp, 8
    ret

; ---------------------------------------------------------------------------
; u64 asm_benchmark_store(u64 iterations)
; Repeatedly stores to a stack slot. Measures store throughput.
; ---------------------------------------------------------------------------
global asm_benchmark_store
asm_benchmark_store:
    mov     r9, rdi
    sub     rsp, 8
    TSC_START
    test    r9, r9
    jz      .store_done
    xor     r8, r8
.store_loop:
    mov     [rsp], r8           ; store to stack
    dec     r9
    jnz     .store_loop
.store_done:
    TSC_END
    add     rsp, 8
    ret

; ---------------------------------------------------------------------------
; u64 asm_benchmark_add(u64 iterations)
; Register-register ADD loop. Measures integer ALU throughput.
; ---------------------------------------------------------------------------
global asm_benchmark_add
asm_benchmark_add:
    mov     r9, rdi
    TSC_START
    test    r9, r9
    jz      .add_done
    xor     r8, r8
    mov     r11, 1
.add_loop:
    add     r8, r11             ; register-register add (no memory)
    dec     r9
    jnz     .add_loop
.add_done:
    TSC_END
    ret

; ---------------------------------------------------------------------------
; u64 asm_benchmark_mul(u64 iterations)
; Register-register IMUL loop. Measures multiplier throughput.
; ---------------------------------------------------------------------------
global asm_benchmark_mul
asm_benchmark_mul:
    mov     r9, rdi
    TSC_START
    test    r9, r9
    jz      .mul_done
    mov     r8, 7               ; operand (odd, so no factors-of-2 pattern)
    mov     r11, 3
.mul_loop:
    imul    r8, r11             ; r8 = r8 * 3 (result will wrap, but that's fine)
    dec     r9
    jnz     .mul_loop
.mul_done:
    TSC_END
    ret

; ---------------------------------------------------------------------------
; u64 asm_benchmark_div(u64 iterations)
; Integer division loop. Measures divider throughput.
; IDIV on x86 is 20-90 cycles — this exposes the worst case.
; ---------------------------------------------------------------------------
global asm_benchmark_div
asm_benchmark_div:
    mov     r9, rdi
    TSC_START
    test    r9, r9
    jz      .div_done
    mov     r11, 7              ; divisor
.div_loop:
    ; Use a dependency-chain-broken setup: load a fresh dividend each time
    ; from a known value so the loop body is just the IDIV itself.
    mov     rax, 0xABCDEF01DEADBEEF
    cqo                         ; sign-extend rax into rdx:rax
    idiv    r11                 ; rax = quotient, rdx = remainder (clobbers both)
    dec     r9
    jnz     .div_loop
.div_done:
    TSC_END
    ret

; ---------------------------------------------------------------------------
; u64 asm_benchmark_lock(u64 iterations)
; LOCK INC loop on a stack cell. Measures locked bus bandwidth.
; ---------------------------------------------------------------------------
global asm_benchmark_lock
asm_benchmark_lock:
    mov     r9, rdi
    sub     rsp, 8
    mov     qword [rsp], 0
    TSC_START
    test    r9, r9
    jz      .lock_done
.lock_loop:
    lock inc qword [rsp]
    dec     r9
    jnz     .lock_loop
.lock_done:
    TSC_END
    add     rsp, 8
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
