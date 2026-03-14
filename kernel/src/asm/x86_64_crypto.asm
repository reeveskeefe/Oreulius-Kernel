; x86_64_crypto.asm — Hardware-accelerated SHA-256 and AES-NI for Oreulia kernel
;
; Provides hardware acceleration for crypto.rs (currently pure-Rust SHA-256 loop)
; and fills the unimplemented asm_aesni_* / asm_sha256_* symbol gaps in memopt_asm.rs.
;
; Exported symbols:
;   sha256_compress_block  — one SHA-256 block compression using SHA-NI extensions
;   sha256_transform_hw    — full message schedule + compression (complete SHA-256 round)
;   aes128_key_expand      — AES-128 key schedule (11 round keys)
;   aes128_block_encrypt   — single block AES-128 encryption
;   aes128_block_decrypt   — single block AES-128 decryption
;   asm_aesni_encrypt      — AES-NI block encrypt (matches memopt_asm.rs declaration)
;   asm_aesni_decrypt      — AES-NI block decrypt
;   asm_sha256_init        — initialize SHA-256 state vector to FIPS 180-4 IV
;   asm_sha256_update      — process one 64-byte block into state
;   asm_crc32c_u8          — CRC32C of one byte (SSE4.2)
;   asm_crc32c_u32         — CRC32C of one dword (SSE4.2)
;   asm_crc32c_buf         — CRC32C of a buffer (SSE4.2, 8-byte inner loop)
;
; CPU requirements:
;   SHA-256 functions: Intel SHA extensions (CPUID leaf 7, EBX bit 29)
;   AES functions:     AES-NI           (CPUID leaf 1, ECX bit 25)
;   CRC32C functions:  SSE4.2           (CPUID leaf 1, ECX bit 20)
;
; ABI: System V AMD64
; All functions are safe to call from Rust with #[inline(never)] extern "C" wrappers.

[bits 64]
default rel

; ---------------------------------------------------------------------------
; SHA-256 initial hash values (FIPS 180-4 §5.3.3) — first 32 bits of
; the fractional parts of the square roots of the first 8 primes.
; ---------------------------------------------------------------------------
section .rodata
align 16
sha256_init_state:
    dd  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    dd  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

; SHA-256 round constants K[0..63] — first 32 bits of the fractional parts
; of the cube roots of the first 64 prime numbers.
align 16
sha256_k:
    dd  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    dd  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    dd  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    dd  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    dd  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    dd  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    dd  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    dd  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    dd  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    dd  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    dd  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    dd  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    dd  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    dd  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    dd  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    dd  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

section .text

; ---------------------------------------------------------------------------
; void asm_sha256_init(u32 state[8])
; Initialize a SHA-256 state vector to the FIPS 180-4 IV.
; rdi = pointer to 8×u32 state array
; ---------------------------------------------------------------------------
global asm_sha256_init
asm_sha256_init:
    lea     rsi, [rel sha256_init_state]
    movdqu  xmm0, [rsi]
    movdqu  xmm1, [rsi + 16]
    movdqu  [rdi], xmm0
    movdqu  [rdi + 16], xmm1
    ret

; ---------------------------------------------------------------------------
; void asm_sha256_update(u32 state[8], const u8 block[64])
; Process one 64-byte message block using Intel SHA extensions.
; rdi = state pointer (8 × u32, big-endian word order)
; rsi = 64-byte message block pointer
;
; Intel SHA-NI register conventions:
;   xmm0 = ABEF (state words A,B,E,F packed as [E,F,B,A] in low→high dword order)
;   xmm1 = CDGH (state words C,D,G,H)
;   xmm2-xmm5 = message schedule W[0..15] as groups of 4 dwords
; ---------------------------------------------------------------------------
global asm_sha256_update
asm_sha256_update:
    ; Save callee-saved XMM registers (ABI requirement on Windows; good practice)
    sub     rsp, 80
    movdqu  [rsp +  0], xmm6
    movdqu  [rsp + 16], xmm7
    movdqu  [rsp + 32], xmm8
    movdqu  [rsp + 48], xmm9
    movdqu  [rsp + 64], xmm10  ; only need [rsp+64] if we use xmm10

    lea     rdx, [rel sha256_k]

    ; Load current state
    movdqu  xmm6, [rdi]         ; H0-H3 (A,B,C,D)
    movdqu  xmm7, [rdi + 16]   ; H4-H7 (E,F,G,H)

    ; SHA-NI packs state as: xmm0=[E,F,B,A] xmm1=[G,H,D,C]
    ; Rearrange: state[0]=A,state[1]=B,...,state[7]=H in memory (big-endian words)
    ; pshufb with sha256_mask to swap byte order within each dword
    ; For simplicity we use pshufd to rearrange dwords.
    ;
    ; Input memory layout: [A][B][C][D][E][F][G][H]
    ; ABEF register wants dwords in order [F,E,B,A] (little-endian dword index 0=A,1=B,2=E,3=F)
    movdqu  xmm0, [rdi]         ; [A,B,C,D]
    movdqu  xmm1, [rdi + 16]   ; [E,F,G,H]
    ; Shuffle: ABEF = [A,B,E,F] as dwords 0,1,2,3 → pshufd selects from two regs
    ; We need xmm0=[A,B,E,F] but E,F are in xmm1 dwords 0,1
    ; Use PUNPCKLQDQ / PUNPCKHQDQ
    movdqa  xmm8, xmm0          ; [A,B,C,D]
    punpcklqdq  xmm0, xmm1     ; [A,B,E,F] — lo64 of xmm0 + lo64 of xmm1
    punpckhqdq  xmm8, xmm1     ; [C,D,G,H]
    movdqa  xmm1, xmm8          ; xmm1 = [C,D,G,H]
    ; Intel SHA-NI CDGH convention is [H,G,D,C] — reverse dword order
    pshufd  xmm0, xmm0, 0xB1   ; swap pairs: [B,A,F,E]
    pshufd  xmm1, xmm1, 0xB1   ; swap pairs: [D,C,H,G]
    ; Now: xmm0=[B,A,F,E] but SHA-NI wants [F,E,B,A] dword order
    ; One more pshufd: 0x1B reverses 4 dwords
    ; Actually the exact packing needed: ABEF has dword0=A,1=B,2=E,3=F
    ; We have [B,A,F,E] so pshufd 0x1B gives [E,F,A,B] — not right.
    ; Use blend: we want xmm_ABEF=[A,B,E,F]
    ; Restart with correct shuffle sequence:
    movdqu  xmm0, [rdi]         ; [A,B,C,D]
    movdqu  xmm1, [rdi + 16]   ; [E,F,G,H]
    ; ABEF: xmm_lo64=[A,B], xmm_hi64=[E,F]
    movdqa  xmm9, xmm0
    movlhps xmm0, xmm1          ; xmm0 = [A,B,E,F] (lo64 from old xmm0, hi64 from xmm1)
    movhlps xmm9, xmm1          ; xmm9 = [G,H,C,D]
    pshufd  xmm1, xmm9, 0x4E   ; swap 64-bit halves: xmm1=[C,D,G,H]
    ; Save initial state for final add
    movdqa  xmm6, xmm0          ; initial ABEF
    movdqa  xmm7, xmm1          ; initial CDGH

    ; Load and byte-swap message schedule (16 dwords = 4 xmm registers)
    ; The message words must be in big-endian byte order.
    movdqu  xmm2, [rsi +  0]
    movdqu  xmm3, [rsi + 16]
    movdqu  xmm4, [rsi + 32]
    movdqu  xmm5, [rsi + 48]
    ; Byte-swap each dword (network order → host for SHA-NI)
    movdqa  xmm10, [rel .bswap_mask]
    pshufb  xmm2, xmm10
    pshufb  xmm3, xmm10
    pshufb  xmm4, xmm10
    pshufb  xmm5, xmm10

    ; ---- SHA-256 rounds 0-3 ----
    movdqa  xmm9, xmm2
    paddd   xmm9, [rdx + 0*16]
    sha256rnds2 xmm1, xmm0, xmm9      ; rounds with low two words of xmm9
    pshufd  xmm9, xmm9, 0x0E          ; high two words
    sha256rnds2 xmm0, xmm1, xmm9

    ; ---- rounds 4-7 ----
    movdqa  xmm9, xmm3
    paddd   xmm9, [rdx + 1*16]
    sha256rnds2 xmm1, xmm0, xmm9
    pshufd  xmm9, xmm9, 0x0E
    sha256rnds2 xmm0, xmm1, xmm9
    sha256msg1  xmm2, xmm3

    ; ---- rounds 8-11 ----
    movdqa  xmm9, xmm4
    paddd   xmm9, [rdx + 2*16]
    sha256rnds2 xmm1, xmm0, xmm9
    pshufd  xmm9, xmm9, 0x0E
    sha256rnds2 xmm0, xmm1, xmm9
    sha256msg1  xmm3, xmm4

    ; ---- rounds 12-15 ----
    movdqa  xmm9, xmm5
    paddd   xmm9, [rdx + 3*16]
    sha256rnds2 xmm1, xmm0, xmm9
    pshufd  xmm9, xmm9, 0x0E
    sha256rnds2 xmm0, xmm1, xmm9
    movdqa  xmm8, xmm5
    palignr xmm8, xmm4, 4
    paddd   xmm2, xmm8
    sha256msg2  xmm2, xmm5
    sha256msg1  xmm4, xmm5

    ; ---- rounds 16-19 ----
    movdqa  xmm9, xmm2
    paddd   xmm9, [rdx + 4*16]
    sha256rnds2 xmm1, xmm0, xmm9
    pshufd  xmm9, xmm9, 0x0E
    sha256rnds2 xmm0, xmm1, xmm9
    movdqa  xmm8, xmm2
    palignr xmm8, xmm5, 4
    paddd   xmm3, xmm8
    sha256msg2  xmm3, xmm2
    sha256msg1  xmm5, xmm2

    ; ---- rounds 20-23 ----
    movdqa  xmm9, xmm3
    paddd   xmm9, [rdx + 5*16]
    sha256rnds2 xmm1, xmm0, xmm9
    pshufd  xmm9, xmm9, 0x0E
    sha256rnds2 xmm0, xmm1, xmm9
    movdqa  xmm8, xmm3
    palignr xmm8, xmm2, 4
    paddd   xmm4, xmm8
    sha256msg2  xmm4, xmm3
    sha256msg1  xmm2, xmm3

    ; ---- rounds 24-27 ----
    movdqa  xmm9, xmm4
    paddd   xmm9, [rdx + 6*16]
    sha256rnds2 xmm1, xmm0, xmm9
    pshufd  xmm9, xmm9, 0x0E
    sha256rnds2 xmm0, xmm1, xmm9
    movdqa  xmm8, xmm4
    palignr xmm8, xmm3, 4
    paddd   xmm5, xmm8
    sha256msg2  xmm5, xmm4
    sha256msg1  xmm3, xmm4

    ; ---- rounds 28-31 ----
    movdqa  xmm9, xmm5
    paddd   xmm9, [rdx + 7*16]
    sha256rnds2 xmm1, xmm0, xmm9
    pshufd  xmm9, xmm9, 0x0E
    sha256rnds2 xmm0, xmm1, xmm9
    movdqa  xmm8, xmm5
    palignr xmm8, xmm4, 4
    paddd   xmm2, xmm8
    sha256msg2  xmm2, xmm5
    sha256msg1  xmm4, xmm5

    ; ---- rounds 32-35 ----
    movdqa  xmm9, xmm2
    paddd   xmm9, [rdx + 8*16]
    sha256rnds2 xmm1, xmm0, xmm9
    pshufd  xmm9, xmm9, 0x0E
    sha256rnds2 xmm0, xmm1, xmm9
    movdqa  xmm8, xmm2
    palignr xmm8, xmm5, 4
    paddd   xmm3, xmm8
    sha256msg2  xmm3, xmm2
    sha256msg1  xmm5, xmm2

    ; ---- rounds 36-39 ----
    movdqa  xmm9, xmm3
    paddd   xmm9, [rdx + 9*16]
    sha256rnds2 xmm1, xmm0, xmm9
    pshufd  xmm9, xmm9, 0x0E
    sha256rnds2 xmm0, xmm1, xmm9
    movdqa  xmm8, xmm3
    palignr xmm8, xmm2, 4
    paddd   xmm4, xmm8
    sha256msg2  xmm4, xmm3
    sha256msg1  xmm2, xmm3

    ; ---- rounds 40-43 ----
    movdqa  xmm9, xmm4
    paddd   xmm9, [rdx + 10*16]
    sha256rnds2 xmm1, xmm0, xmm9
    pshufd  xmm9, xmm9, 0x0E
    sha256rnds2 xmm0, xmm1, xmm9
    movdqa  xmm8, xmm4
    palignr xmm8, xmm3, 4
    paddd   xmm5, xmm8
    sha256msg2  xmm5, xmm4
    sha256msg1  xmm3, xmm4

    ; ---- rounds 44-47 ----
    movdqa  xmm9, xmm5
    paddd   xmm9, [rdx + 11*16]
    sha256rnds2 xmm1, xmm0, xmm9
    pshufd  xmm9, xmm9, 0x0E
    sha256rnds2 xmm0, xmm1, xmm9
    movdqa  xmm8, xmm5
    palignr xmm8, xmm4, 4
    paddd   xmm2, xmm8
    sha256msg2  xmm2, xmm5

    ; ---- rounds 48-51 ----
    movdqa  xmm9, xmm2
    paddd   xmm9, [rdx + 12*16]
    sha256rnds2 xmm1, xmm0, xmm9
    pshufd  xmm9, xmm9, 0x0E
    sha256rnds2 xmm0, xmm1, xmm9
    movdqa  xmm8, xmm2
    palignr xmm8, xmm5, 4
    paddd   xmm3, xmm8
    sha256msg2  xmm3, xmm2

    ; ---- rounds 52-55 ----
    movdqa  xmm9, xmm3
    paddd   xmm9, [rdx + 13*16]
    sha256rnds2 xmm1, xmm0, xmm9
    pshufd  xmm9, xmm9, 0x0E
    sha256rnds2 xmm0, xmm1, xmm9
    movdqa  xmm8, xmm3
    palignr xmm8, xmm2, 4
    paddd   xmm4, xmm8
    sha256msg2  xmm4, xmm3

    ; ---- rounds 56-59 ----
    movdqa  xmm9, xmm4
    paddd   xmm9, [rdx + 14*16]
    sha256rnds2 xmm1, xmm0, xmm9
    pshufd  xmm9, xmm9, 0x0E
    sha256rnds2 xmm0, xmm1, xmm9
    movdqa  xmm8, xmm4
    palignr xmm8, xmm3, 4
    paddd   xmm5, xmm8
    sha256msg2  xmm5, xmm4

    ; ---- rounds 60-63 ----
    movdqa  xmm9, xmm5
    paddd   xmm9, [rdx + 15*16]
    sha256rnds2 xmm1, xmm0, xmm9
    pshufd  xmm9, xmm9, 0x0E
    sha256rnds2 xmm0, xmm1, xmm9

    ; Add compressed state back to initial state
    paddd   xmm0, xmm6
    paddd   xmm1, xmm7

    ; Unpack ABEF/CDGH back to [A,B,C,D,E,F,G,H] memory order
    ; xmm0=[A,B,E,F] xmm1=[C,D,G,H]
    ; We want: [A,B,C,D] in first 16 bytes, [E,F,G,H] in next 16
    movdqa  xmm8, xmm0
    movlhps xmm0, xmm1         ; xmm0 = [A,B] lo64 + [C,D] lo64  ... actually:
    ; movlhps: dst_hi = src_lo, dst_lo unchanged
    ; so xmm0_lo=[A,B], xmm0_hi=[C,D] → xmm0=[A,B,C,D] ✓
    movhlps xmm1, xmm8          ; xmm1_lo = xmm8_hi = [E,F]
    ; xmm1_hi was [G,H], xmm1_lo is now [E,F] → xmm1=[E,F,G,H] ✓
    movdqu  [rdi], xmm0
    movdqu  [rdi + 16], xmm1

    ; Restore saved XMM registers
    movdqu  xmm6,  [rsp +  0]
    movdqu  xmm7,  [rsp + 16]
    movdqu  xmm8,  [rsp + 32]
    movdqu  xmm9,  [rsp + 48]
    movdqu  xmm10, [rsp + 64]
    add     rsp, 80
    ret

align 16
.bswap_mask:
    db 3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12

; Alias for the Rust crypto.rs calling convention
global sha256_compress_block
sha256_compress_block equ asm_sha256_update

global sha256_transform_hw
sha256_transform_hw equ asm_sha256_update

; ---------------------------------------------------------------------------
; AES-128 key expansion
; void aes128_key_expand(const u8 key[16], u8 round_keys[176])
; Produces 11 round keys (11 × 16 bytes = 176 bytes) for AES-128.
; rdi = 16-byte input key
; rsi = 176-byte output round key buffer (must be 16-byte aligned)
; ---------------------------------------------------------------------------
global aes128_key_expand
aes128_key_expand:
    movdqu  xmm1, [rdi]
    movdqu  [rsi], xmm1

%macro AESKEYGENASSIST_ROUND 2
    aeskeygenassist xmm2, xmm1, %1
    pshufd  xmm2, xmm2, 0xFF
    movdqa  xmm3, xmm1
    pslldq  xmm3, 4
    pxor    xmm1, xmm3
    pslldq  xmm3, 4
    pxor    xmm1, xmm3
    pslldq  xmm3, 4
    pxor    xmm1, xmm3
    pxor    xmm1, xmm2
    movdqu  [rsi + %2], xmm1
%endmacro

    AESKEYGENASSIST_ROUND 0x01, 16
    AESKEYGENASSIST_ROUND 0x02, 32
    AESKEYGENASSIST_ROUND 0x04, 48
    AESKEYGENASSIST_ROUND 0x08, 64
    AESKEYGENASSIST_ROUND 0x10, 80
    AESKEYGENASSIST_ROUND 0x20, 96
    AESKEYGENASSIST_ROUND 0x40, 112
    AESKEYGENASSIST_ROUND 0x80, 128
    AESKEYGENASSIST_ROUND 0x1B, 144
    AESKEYGENASSIST_ROUND 0x36, 160
    ret

; ---------------------------------------------------------------------------
; void aes128_block_encrypt(const u8 block[16], u8 out[16],
;                           const u8 round_keys[176])
; Single AES-128 block encryption (ECB, no mode).
; rdi = input block, rsi = output block, rdx = round keys (176 bytes, aligned)
; ---------------------------------------------------------------------------
global aes128_block_encrypt
global asm_aesni_encrypt
aes128_block_encrypt:
asm_aesni_encrypt:
    movdqu  xmm0, [rdi]
    pxor    xmm0, [rdx +   0]
    aesenc  xmm0, [rdx +  16]
    aesenc  xmm0, [rdx +  32]
    aesenc  xmm0, [rdx +  48]
    aesenc  xmm0, [rdx +  64]
    aesenc  xmm0, [rdx +  80]
    aesenc  xmm0, [rdx +  96]
    aesenc  xmm0, [rdx + 112]
    aesenc  xmm0, [rdx + 128]
    aesenc  xmm0, [rdx + 144]
    aesenclast xmm0, [rdx + 160]
    movdqu  [rsi], xmm0
    ret

; ---------------------------------------------------------------------------
; void aes128_block_decrypt(const u8 block[16], u8 out[16],
;                           const u8 round_keys[176])
; Single AES-128 block decryption (ECB). Requires equivalent expanded keys.
; rdi = input block, rsi = output block, rdx = round keys (176 bytes)
; ---------------------------------------------------------------------------
global aes128_block_decrypt
global asm_aesni_decrypt
aes128_block_decrypt:
asm_aesni_decrypt:
    movdqu  xmm0, [rdi]
    pxor    xmm0, [rdx + 160]
    ; For decryption, round keys are applied in reverse order
    ; and intermediate keys need the InvMixColumns transform.
    ; Here we apply AESIMC on-the-fly for correctness.
    aesimc  xmm1, [rdx + 144]
    aesdec  xmm0, xmm1
    aesimc  xmm1, [rdx + 128]
    aesdec  xmm0, xmm1
    aesimc  xmm1, [rdx + 112]
    aesdec  xmm0, xmm1
    aesimc  xmm1, [rdx +  96]
    aesdec  xmm0, xmm1
    aesimc  xmm1, [rdx +  80]
    aesdec  xmm0, xmm1
    aesimc  xmm1, [rdx +  64]
    aesdec  xmm0, xmm1
    aesimc  xmm1, [rdx +  48]
    aesdec  xmm0, xmm1
    aesimc  xmm1, [rdx +  32]
    aesdec  xmm0, xmm1
    aesimc  xmm1, [rdx +  16]
    aesdec  xmm0, xmm1
    aesdeclast xmm0, [rdx +   0]
    movdqu  [rsi], xmm0
    ret

; ---------------------------------------------------------------------------
; u32 asm_crc32c_u8(u32 crc, u8 data)
; CRC32C (Castagnoli) of one byte using SSE4.2 CRC32 instruction.
; rdi = initial CRC value, rsi = data byte
; Returns updated CRC in eax.
; ---------------------------------------------------------------------------
global asm_crc32c_u8
asm_crc32c_u8:
    mov     eax, edi
    crc32   eax, sil
    ret

; ---------------------------------------------------------------------------
; u32 asm_crc32c_u32(u32 crc, u32 data)
; CRC32C of one dword.
; ---------------------------------------------------------------------------
global asm_crc32c_u32
asm_crc32c_u32:
    mov     eax, edi
    crc32   eax, esi
    ret

; ---------------------------------------------------------------------------
; u32 asm_crc32c_buf(u32 crc, const void *buf, usize len)
; CRC32C of an arbitrary buffer. Inner loop processes 8 bytes per iteration.
; rdi = initial CRC, rsi = buffer pointer, rdx = length
; Returns final CRC in eax.
; ---------------------------------------------------------------------------
global asm_crc32c_buf
asm_crc32c_buf:
    mov     rax, rdi            ; crc accumulator (use rax for 64-bit crc32)
    mov     rcx, rdx            ; length
    ; 8-byte loop
    shr     rcx, 3
    jz      .dword_check
.qword_loop:
    crc32   rax, qword [rsi]
    add     rsi, 8
    dec     rcx
    jnz     .qword_loop
.dword_check:
    test    rdx, 4
    jz      .word_check
    crc32   eax, dword [rsi]
    add     rsi, 4
.word_check:
    test    rdx, 2
    jz      .byte_check
    crc32   eax, word [rsi]
    add     rsi, 2
.byte_check:
    test    rdx, 1
    jz      .done
    crc32   eax, byte [rsi]
.done:
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
