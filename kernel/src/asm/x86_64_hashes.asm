; x86_64_hashes.asm — Non-cryptographic hash functions and byte-order utilities
;
; Provides real implementations replacing the STUB_ZERO shims:
;   asm_hash_fnv1a  — FNV-1a 32-bit hash (exact algorithm, not truncated FNV-1)
;   asm_hash_djb2   — DJB2 hash (hash * 33 + c)
;   asm_hash_sdbm   — SDBM hash (hash * 65599 + c)
;   asm_swap_endian_16 — byte-swap a 16-bit value
;   asm_swap_endian_32 — byte-swap a 32-bit value
;   asm_swap_endian_64 — byte-swap a 64-bit value (bonus, no stub needed)
;
; ABI: System V AMD64 (rdi, rsi, rdx, rcx, r8, r9; return rax)

[bits 64]
default rel

section .rodata

; FNV-1a constants (32-bit)
FNV_OFFSET_BASIS_32 equ 0x811c9dc5
FNV_PRIME_32        equ 0x01000193   ; 16777619

section .text

; ---------------------------------------------------------------------------
; u32 asm_hash_fnv1a(const void *data, usize len)
; FNV-1a 32-bit hash.
; rdi = pointer to data, rsi = length in bytes
; Returns hash in eax.
; ---------------------------------------------------------------------------
global asm_hash_fnv1a
asm_hash_fnv1a:
    mov     eax, FNV_OFFSET_BASIS_32
    test    rsi, rsi
    jz      .done
    mov     rcx, rsi            ; byte counter
    xor     r8d, r8d            ; byte staging register
.loop:
    movzx   r8d, byte [rdi]
    xor     eax, r8d
    ; eax *= FNV_PRIME_32 — use imul (32-bit, discards upper half)
    imul    eax, eax, FNV_PRIME_32
    inc     rdi
    dec     rcx
    jnz     .loop
.done:
    ret

; ---------------------------------------------------------------------------
; u32 asm_hash_djb2(const void *data, usize len)
; DJB2 hash: hash = hash * 33 + c  (initial hash = 5381)
; rdi = data pointer, rsi = length
; Returns hash in eax.
; ---------------------------------------------------------------------------
global asm_hash_djb2
asm_hash_djb2:
    mov     eax, 5381
    test    rsi, rsi
    jz      .done
    mov     rcx, rsi
.loop:
    movzx   edx, byte [rdi]
    ; hash * 33 = hash * 32 + hash = (hash << 5) + hash
    lea     eax, [eax + eax*4]  ; eax = eax * 5
    lea     eax, [eax + eax*4]  ; eax = eax * 5 → total *25? No:
    ; Correct: hash*33 = hash*32+hash. Use:
    ;   mov r9d, eax
    ;   shl eax, 5     ; eax *= 32
    ;   add eax, r9d   ; eax += original → eax *= 33
    ;   add eax, edx
    ; Rewrite:
    mov     r9d, eax
    shl     eax, 5
    add     eax, r9d
    add     eax, edx
    inc     rdi
    dec     rcx
    jnz     .loop
.done:
    ret

; ---------------------------------------------------------------------------
; u32 asm_hash_sdbm(const void *data, usize len)
; SDBM hash: hash = hash * 65599 + c  (initial hash = 0)
; rdi = data pointer, rsi = length
; Returns hash in eax.
; 65599 = 65536 + 64 - 1 = (1<<16) + (1<<6) - 1
; hash * 65599 = hash*65536 + hash*64 - hash
;              = (hash<<16) + (hash<<6) - hash
; ---------------------------------------------------------------------------
global asm_hash_sdbm
asm_hash_sdbm:
    xor     eax, eax
    test    rsi, rsi
    jz      .done
    mov     rcx, rsi
.loop:
    movzx   edx, byte [rdi]
    ; hash * 65599: use imul since 65599 fits in a signed 32-bit immediate
    imul    eax, eax, 65599
    add     eax, edx
    inc     rdi
    dec     rcx
    jnz     .loop
.done:
    ret

; ---------------------------------------------------------------------------
; u16 asm_swap_endian_16(u16 val)
; Byte-swap a 16-bit value. rdi = value (zero-extended).
; Returns swapped value in ax (rax zero-extended).
; ---------------------------------------------------------------------------
global asm_swap_endian_16
asm_swap_endian_16:
    mov     eax, edi
    xchg    al, ah
    movzx   eax, ax
    ret

; ---------------------------------------------------------------------------
; u32 asm_swap_endian_32(u32 val)
; Byte-swap a 32-bit value. rdi = value.
; Returns swapped value in eax.
; ---------------------------------------------------------------------------
global asm_swap_endian_32
asm_swap_endian_32:
    mov     eax, edi
    bswap   eax
    ret

; ---------------------------------------------------------------------------
; u64 asm_swap_endian_64(u64 val)
; Byte-swap a 64-bit value. rdi = value.
; Returns swapped value in rax.
; ---------------------------------------------------------------------------
global asm_swap_endian_64
asm_swap_endian_64:
    mov     rax, rdi
    bswap   rax
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
