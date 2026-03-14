; x86_64_memory.asm — Fast 64-bit memory operations for Oreulia kernel
;
; Replaces STUB_ZERO shims for:
;   asm_fast_memcpy, asm_fast_memset, asm_fast_memcmp, asm_checksum_ip
;
; All functions use 64-bit REP string ops for bulk throughput and handle
; trailing bytes with byte loops. asm_checksum_ip implements RFC 1071
; one's-complement 16-bit checksum with 64-bit aligned inner loop.
;
; ABI: System V AMD64

[bits 64]
default rel

section .text

; ---------------------------------------------------------------------------
; void *asm_fast_memcpy(void *dst, const void *src, usize len)
; Copy len bytes from src to dst. Regions must not overlap.
; Returns dst (rdi).
; ---------------------------------------------------------------------------
global asm_fast_memcpy
asm_fast_memcpy:
    push    rdi                 ; save dst — we return it
    mov     rcx, rdx            ; len → rcx
    ; Bulk copy: qword loop
    mov     rax, rcx
    shr     rcx, 3              ; qword count
    rep movsq
    ; Trailing bytes
    mov     rcx, rax
    and     rcx, 7
    rep movsb
    pop     rax                 ; return original dst
    ret

; ---------------------------------------------------------------------------
; void *asm_fast_memset(void *dst, int val, usize len)
; Fill len bytes at dst with val (low byte of rsi).
; Returns dst (rdi).
; ---------------------------------------------------------------------------
global asm_fast_memset
asm_fast_memset:
    push    rdi                 ; save dst for return
    ; Broadcast the byte value into a qword fill pattern
    movzx   rax, sil            ; byte value
    mov     r8, 0x0101010101010101
    imul    rax, r8             ; replicate byte into all 8 positions
    mov     rcx, rdx            ; len
    ; Bulk fill: qword loop
    mov     r9, rcx
    shr     rcx, 3
    rep stosq
    ; Trailing bytes — rax still has fill byte in AL
    mov     rcx, r9
    and     rcx, 7
    rep stosb
    pop     rax                 ; return original dst
    ret

; ---------------------------------------------------------------------------
; i32 asm_fast_memcmp(const void *a, const void *b, usize len)
; Compare len bytes. Returns:
;   0   if equal
;  <0   if first differing byte in a < b
;  >0   if first differing byte in a > b
; ---------------------------------------------------------------------------
global asm_fast_memcmp
asm_fast_memcmp:
    mov     rcx, rdx            ; len → rcx
    ; Bulk compare: qword loop
    mov     rax, rcx
    shr     rcx, 3
    repe cmpsq
    jnz     .qword_diff         ; found a differing qword
    ; Trailing bytes
    mov     rcx, rax
    and     rcx, 7
    repe cmpsb
    jnz     .byte_diff
    xor     eax, eax            ; equal
    ret
.qword_diff:
    ; Back up to the start of the differing qword and compare byte by byte
    sub     rsi, 8
    sub     rdi, 8
    mov     rcx, 8
    repe cmpsb
    jnz     .byte_diff
    xor     eax, eax
    ret
.byte_diff:
    ; rdi points one past the differing byte (SCASB/CMPSB advances ptr)
    movzx   eax, byte [rdi - 1]
    movzx   ecx, byte [rsi - 1]
    sub     eax, ecx
    ret

; ---------------------------------------------------------------------------
; u16 asm_checksum_ip(const void *data, usize len)
; RFC 1071 one's-complement 16-bit checksum.
; Processes 8 bytes per iteration in the inner loop.
; Returns the one's-complement sum in AX (caller should ~result & 0xFFFF).
; ---------------------------------------------------------------------------
global asm_checksum_ip
asm_checksum_ip:
    xor     rax, rax            ; accumulator
    mov     rcx, rsi            ; len
    ; 8-byte (qword) loop
    shr     rcx, 3
    jz      .dword_check
.qword_loop:
    add     rax, [rdi]
    adc     rax, 0              ; fold carry
    add     rdi, 8
    dec     rcx
    jnz     .qword_loop
.dword_check:
    ; remaining 4-byte chunk
    test    rsi, 4
    jz      .word_check
    mov     ecx, dword [rdi]
    add     rax, rcx
    adc     rax, 0
    add     rdi, 4
.word_check:
    ; remaining 2-byte chunk
    test    rsi, 2
    jz      .byte_check
    movzx   ecx, word [rdi]
    add     rax, rcx
    adc     rax, 0
    add     rdi, 2
.byte_check:
    ; remaining 1-byte chunk (pad with 0)
    test    rsi, 1
    jz      .fold
    movzx   ecx, byte [rdi]
    shl     ecx, 8              ; high byte
    add     rax, rcx
    adc     rax, 0
.fold:
    ; Fold 64-bit accumulator down to 16 bits
    mov     rcx, rax
    shr     rcx, 32
    add     eax, ecx
    adc     eax, 0
    mov     ecx, eax
    shr     ecx, 16
    add     eax, ecx
    adc     eax, 0
    and     eax, 0xFFFF
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
