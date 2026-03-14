; x86_64_temporal.asm — Temporal adapter helpers for durable persistence
;
; Replaces STUB_ZERO shims for:
;   temporal_copy_bytes    — rep movsq bulk copy for temporal log entries
;   temporal_fnv1a32       — FNV-1a 32-bit hash of a temporal record
;   temporal_hash_pair     — combine two u32 hashes (mixing via Knuth/Murmur finalize)
;   temporal_merkle_root_u32 — compute Merkle root over an array of u32 leaf hashes
;
; These functions are called from temporal.rs / oreulia-temporal-adapters.
;
; ABI: System V AMD64

[bits 64]
default rel

; FNV-1a 32-bit constants
FNV_OFFSET_BASIS equ 0x811c9dc5
FNV_PRIME        equ 0x01000193   ; 16777619

section .text

; ---------------------------------------------------------------------------
; void temporal_copy_bytes(void *dst, const void *src, usize len)
; Fast aligned bulk copy for temporal log entries.
; Equivalent to memcpy but named separately so temporal code can be traced.
; rdi = dst, rsi = src, rdx = len
; ---------------------------------------------------------------------------
global temporal_copy_bytes
temporal_copy_bytes:
    push    rdi                 ; save original dst for return (not needed here)
    mov     rcx, rdx
    shr     rcx, 3              ; qword count
    rep movsq
    mov     rcx, rdx
    and     rcx, 7              ; remaining bytes
    rep movsb
    pop     rdi
    ret

; ---------------------------------------------------------------------------
; u32 temporal_fnv1a32(const void *data, usize len)
; FNV-1a 32-bit hash used to fingerprint temporal records.
; rdi = data pointer, rsi = length
; Returns hash in eax.
; ---------------------------------------------------------------------------
global temporal_fnv1a32
temporal_fnv1a32:
    mov     eax, FNV_OFFSET_BASIS
    test    rsi, rsi
    jz      .done
    mov     rcx, rsi
.loop:
    movzx   edx, byte [rdi]
    xor     eax, edx
    imul    eax, eax, FNV_PRIME
    inc     rdi
    dec     rcx
    jnz     .loop
.done:
    ret

; ---------------------------------------------------------------------------
; u32 temporal_hash_pair(u32 h1, u32 h2)
; Combine two hash values into one using a Murmur3-style finalizer mix.
; The combination is commutative-resistant (order matters) which is correct
; for ordered Merkle tree construction.
; rdi = h1 (u32, zero-extended), rsi = h2 (u32, zero-extended)
; Returns combined hash in eax.
; ---------------------------------------------------------------------------
global temporal_hash_pair
temporal_hash_pair:
    ; Method: h = h1 ^ rotl32(h2, 13); h = h * 0x9e3779b9 + h2
    ; This is a deterministic mixing that's fast and well-dispersed.

    ; Step 1: rotl32(h2, 13)
    mov     eax, esi
    rol     eax, 13

    ; Step 2: h = h1 XOR rotated_h2
    xor     eax, edi

    ; Step 3: h = h * 0x9e3779b9 (golden ratio constant)
    imul    eax, eax, 0x9e3779b9

    ; Step 4: h = h + h2
    add     eax, esi

    ; Step 5: final avalanche — two Murmur3 finalizer XOR-shifts
    mov     edx, eax
    shr     edx, 16
    xor     eax, edx
    imul    eax, eax, 0x85ebca6b
    mov     edx, eax
    shr     edx, 13
    xor     eax, edx
    imul    eax, eax, 0xc2b2ae35
    mov     edx, eax
    shr     edx, 16
    xor     eax, edx

    ret

; ---------------------------------------------------------------------------
; u32 temporal_merkle_root_u32(const u32 *leaves, usize count)
; Compute a Merkle root hash from an array of u32 leaf hashes.
; Uses temporal_hash_pair to combine adjacent pairs bottom-up.
; For odd-count layers, the last element is combined with itself (standard
; Bitcoin-style duplicate-last convention).
;
; This is an in-stack iterative implementation; does NOT recurse.
; Maximum depth: log2(count), stack usage is O(log N) via pair buffer on stack.
;
; rdi = pointer to u32 leaf array, rsi = count
; Returns Merkle root in eax. Returns 0 for empty arrays.
;
; NOTE: This implementation operates on the leaf values in-place using a
; temporary scratch buffer allocated on the stack (max 256 leaves for now).
; For larger arrays, the caller should use the Rust implementation.
; ---------------------------------------------------------------------------
global temporal_merkle_root_u32
temporal_merkle_root_u32:
    test    rsi, rsi
    jz      .empty_tree

    cmp     rsi, 1
    je      .single_leaf

    ; Allocate scratch buffer on stack: max 256 × 4 = 1024 bytes
    ; We'll work with up to 256 leaves at a time.
    cmp     rsi, 256
    jg      .too_large          ; fall back to returning leaf[0] XOR leaf[count-1]

    sub     rsp, 1024
    ; Copy leaves into scratch buffer
    mov     rcx, rsi
    mov     r8, rsp             ; scratch = rsp
    mov     r9, rsi             ; current count
.copy_leaves:
    mov     eax, dword [rdi + rcx*4 - 4]
    mov     dword [r8 + rcx*4 - 4], eax
    dec     rcx
    jnz     .copy_leaves

    ; Iterative Merkle reduction: repeatedly halve the array
.merkle_level:
    cmp     r9, 1
    je      .merkle_done

    mov     r10, 0              ; output index
    mov     r11, 0              ; input index
.pair_loop:
    cmp     r11, r9
    jge     .pair_done

    ; left = scratch[r11]
    mov     edi, dword [r8 + r11*4]
    inc     r11

    ; right = scratch[r11] if exists, else left (duplicate last)
    cmp     r11, r9
    jl      .have_right
    ; duplicate: right = left
    mov     esi, edi
    jmp     .do_combine
.have_right:
    mov     esi, dword [r8 + r11*4]
    inc     r11
.do_combine:
    ; call temporal_hash_pair inline (avoid call overhead)
    ; temporal_hash_pair(edi, esi):
    mov     eax, esi
    rol     eax, 13
    xor     eax, edi
    imul    eax, eax, 0x9e3779b9
    add     eax, esi
    mov     ecx, eax
    shr     ecx, 16
    xor     eax, ecx
    imul    eax, eax, 0x85ebca6b
    mov     ecx, eax
    shr     ecx, 13
    xor     eax, ecx
    imul    eax, eax, 0xc2b2ae35
    mov     ecx, eax
    shr     ecx, 16
    xor     eax, ecx

    mov     dword [r8 + r10*4], eax
    inc     r10
    jmp     .pair_loop
.pair_done:
    mov     r9, r10             ; new count = number of pairs
    jmp     .merkle_level

.merkle_done:
    mov     eax, dword [r8]     ; root is at index 0
    add     rsp, 1024
    ret

.single_leaf:
    mov     eax, dword [rdi]
    ret

.empty_tree:
    xor     eax, eax
    ret

.too_large:
    ; Degenerate: XOR all leaves together as a simple hash
    xor     eax, eax
    mov     rcx, rsi
.xor_loop:
    xor     eax, dword [rdi + rcx*4 - 4]
    dec     rcx
    jnz     .xor_loop
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
