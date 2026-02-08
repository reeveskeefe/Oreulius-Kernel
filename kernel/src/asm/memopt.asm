; Memory Optimization and Advanced Algorithms Assembly
; Cache management, prefetching, and high-performance operations
; x86 32-bit architecture with SSE/SSE2/AVX support

[BITS 32]

section .text

; ============================================================================
; Cache Management
; ============================================================================

global cache_flush_line
global cache_prefetch
global cache_flush_all
global cache_invalidate_all

; Flush single cache line
; void cache_flush_line(void* addr)
cache_flush_line:
    mov eax, [esp + 4]
    clflush [eax]
    ret

; Prefetch cache line
; void cache_prefetch(void* addr, u8 locality)
cache_prefetch:
    mov eax, [esp + 4]          ; Address
    movzx ecx, byte [esp + 8]   ; Locality (0-3)
    
    cmp ecx, 0
    je .nta
    cmp ecx, 1
    je .t2
    cmp ecx, 2
    je .t1
    
.t0:
    prefetcht0 [eax]
    ret
.t1:
    prefetcht1 [eax]
    ret
.t2:
    prefetcht2 [eax]
    ret
.nta:
    prefetchnta [eax]
    ret

; Flush all cache
; void cache_flush_all(void)
cache_flush_all:
    wbinvd
    ret

; Invalidate all cache (no writeback)
; void cache_invalidate_all(void)
cache_invalidate_all:
    invd
    ret

; ============================================================================
; Memory Streaming Operations (Non-temporal)
; ============================================================================

global memcpy_nt
global memset_nt
global memcpy_nt_sse
global memcpy_nt_avx

; Non-temporal memory copy (bypasses cache)
; void memcpy_nt(void* dst, void* src, u32 count)
memcpy_nt:
    push edi
    push esi
    push ecx
    
    mov edi, [esp + 16]         ; Destination
    mov esi, [esp + 20]         ; Source
    mov ecx, [esp + 24]         ; Count
    
    ; Check alignment
    test edi, 15
    jnz .unaligned
    test esi, 15
    jnz .unaligned
    
    ; Use SSE non-temporal stores
    mov eax, ecx
    shr ecx, 4                  ; Count of 16-byte blocks
    jz .remaining
    
.sse_loop:
    movdqa xmm0, [esi]
    movntdq [edi], xmm0
    add esi, 16
    add edi, 16
    dec ecx
    jnz .sse_loop
    
.remaining:
    mov ecx, eax
    and ecx, 15
    rep movsb
    
    sfence                      ; Ensure stores complete
    jmp .done
    
.unaligned:
    rep movsb
    
.done:
    pop ecx
    pop esi
    pop edi
    ret

; Non-temporal memory set
; void memset_nt(void* dst, u8 value, u32 count)
memset_nt:
    push edi
    push ecx
    
    mov edi, [esp + 12]
    movzx eax, byte [esp + 16]
    mov ecx, [esp + 20]
    
    ; Replicate byte to 16 bytes
    mov ah, al
    movzx edx, ax
    shl eax, 16
    mov ax, dx
    movd xmm0, eax
    pshufd xmm0, xmm0, 0        ; Broadcast to all 4 dwords
    
    ; Check alignment
    test edi, 15
    jnz .unaligned
    
    mov eax, ecx
    shr ecx, 4
    jz .remaining
    
.sse_loop:
    movntdq [edi], xmm0
    add edi, 16
    dec ecx
    jnz .sse_loop
    
.remaining:
    mov ecx, eax
    and ecx, 15
    mov al, [esp + 16]
    rep stosb
    
    sfence
    jmp .done
    
.unaligned:
    mov al, [esp + 16]
    rep stosb
    
.done:
    pop ecx
    pop edi
    ret

; SSE-optimized non-temporal copy (large blocks)
; void memcpy_nt_sse(void* dst, void* src, u32 count)
memcpy_nt_sse:
    push edi
    push esi
    push ecx
    
    mov edi, [esp + 16]
    mov esi, [esp + 20]
    mov ecx, [esp + 24]
    
    ; Must be 64-byte aligned for optimal performance
    shr ecx, 6                  ; Count of 64-byte blocks
    jz .done
    
.loop:
    ; Load 4x 16-byte blocks
    movdqa xmm0, [esi]
    movdqa xmm1, [esi + 16]
    movdqa xmm2, [esi + 32]
    movdqa xmm3, [esi + 48]
    
    ; Non-temporal stores
    movntdq [edi], xmm0
    movntdq [edi + 16], xmm1
    movntdq [edi + 32], xmm2
    movntdq [edi + 48], xmm3
    
    add esi, 64
    add edi, 64
    dec ecx
    jnz .loop
    
    sfence
    
.done:
    pop ecx
    pop esi
    pop edi
    ret

; AVX-optimized non-temporal copy (requires AVX support)
; void memcpy_nt_avx(void* dst, void* src, u32 count)
memcpy_nt_avx:
    push edi
    push esi
    push ecx
    
    mov edi, [esp + 16]
    mov esi, [esp + 20]
    mov ecx, [esp + 24]
    
    ; 128-byte blocks (4x 32-byte AVX registers)
    shr ecx, 7
    jz .done
    
.loop:
    vmovdqa ymm0, [esi]
    vmovdqa ymm1, [esi + 32]
    vmovdqa ymm2, [esi + 64]
    vmovdqa ymm3, [esi + 96]
    
    vmovntdq [edi], ymm0
    vmovntdq [edi + 32], ymm1
    vmovntdq [edi + 64], ymm2
    vmovntdq [edi + 96], ymm3
    
    add esi, 128
    add edi, 128
    dec ecx
    jnz .loop
    
    sfence
    vzeroupper                  ; Clean up AVX state
    
.done:
    pop ecx
    pop esi
    pop edi
    ret

; ============================================================================
; String Operations with SSE
; ============================================================================

global strlen_sse
global strcmp_sse
global memchr_sse

; SSE-optimized strlen
; u32 strlen_sse(char* str)
strlen_sse:
    push esi
    push ecx
    
    mov esi, [esp + 12]
    xor eax, eax                ; Length counter
    pxor xmm0, xmm0             ; Zero register
    
.loop:
    movdqu xmm1, [esi]          ; Load 16 bytes
    pcmpeqb xmm1, xmm0          ; Compare with zero
    pmovmskb ecx, xmm1          ; Extract comparison mask
    
    test ecx, ecx
    jnz .found_zero
    
    add esi, 16
    add eax, 16
    jmp .loop
    
.found_zero:
    bsf ecx, ecx                ; Find first set bit
    add eax, ecx
    
    pop ecx
    pop esi
    ret

; SSE-optimized strcmp
; i32 strcmp_sse(char* s1, char* s2)
strcmp_sse:
    push esi
    push edi
    push ecx
    
    mov esi, [esp + 16]
    mov edi, [esp + 20]
    pxor xmm0, xmm0
    
.loop:
    movdqu xmm1, [esi]
    movdqu xmm2, [edi]
    
    ; Check for null in either string
    movdqa xmm3, xmm1
    pcmpeqb xmm3, xmm0
    pmovmskb eax, xmm3
    
    movdqa xmm3, xmm2
    pcmpeqb xmm3, xmm0
    pmovmskb ecx, xmm3
    
    or eax, ecx
    test eax, eax
    jnz .check_difference
    
    ; Compare bytes
    pcmpeqb xmm1, xmm2
    pmovmskb eax, xmm1
    cmp eax, 0xFFFF
    jne .found_difference
    
    add esi, 16
    add edi, 16
    jmp .loop
    
.check_difference:
    ; Find position of null or difference
    bsf eax, eax
    movzx ecx, byte [esi + eax]
    movzx edx, byte [edi + eax]
    sub ecx, edx
    mov eax, ecx
    jmp .done
    
.found_difference:
    not eax
    bsf eax, eax
    movzx ecx, byte [esi + eax]
    movzx edx, byte [edi + eax]
    sub ecx, edx
    mov eax, ecx
    
.done:
    pop ecx
    pop edi
    pop esi
    ret

; SSE-optimized memchr
; void* memchr_sse(void* ptr, u8 value, u32 count)
memchr_sse:
    push esi
    push ecx
    push ebx
    
    mov esi, [esp + 16]         ; Pointer
    movzx eax, byte [esp + 20]  ; Value to find
    mov ecx, [esp + 24]         ; Count
    
    ; Broadcast value to all bytes
    movd xmm0, eax
    punpcklbw xmm0, xmm0
    punpcklwd xmm0, xmm0
    pshufd xmm0, xmm0, 0
    
.loop:
    cmp ecx, 16
    jb .remaining
    
    movdqu xmm1, [esi]
    pcmpeqb xmm1, xmm0
    pmovmskb eax, xmm1
    
    test eax, eax
    jnz .found
    
    add esi, 16
    sub ecx, 16
    jmp .loop
    
.found:
    bsf eax, eax
    add eax, esi
    jmp .done
    
.remaining:
    test ecx, ecx
    jz .not_found
    
    mov al, [esp + 20]
    mov edi, esi
    repne scasb
    jne .not_found
    
    lea eax, [edi - 1]
    jmp .done
    
.not_found:
    xor eax, eax
    
.done:
    pop ebx
    pop ecx
    pop esi
    ret

; ============================================================================
; CRC32 Calculation (Hardware accelerated)
; ============================================================================

global crc32_hw
global crc32_update

; Hardware CRC32 calculation
; u32 crc32_hw(u32 crc, void* data, u32 length)
crc32_hw:
    push ebx
    push esi
    push ecx
    
    mov eax, [esp + 16]         ; Initial CRC
    mov esi, [esp + 20]         ; Data
    mov ecx, [esp + 24]         ; Length
    
    ; Check for SSE4.2 support
    push eax
    push ebx
    push ecx
    push edx
    
    mov eax, 1
    cpuid
    test ecx, 0x00100000        ; SSE4.2 bit
    
    pop edx
    pop ecx
    pop ebx
    pop eax
    jz .software_crc
    
    ; Hardware CRC32
.hw_loop:
    test ecx, ecx
    jz .done
    
    crc32 eax, byte [esi]
    inc esi
    dec ecx
    jmp .hw_loop
    
.software_crc:
    ; Fallback to software implementation
    call .crc32_software
    
.done:
    pop ecx
    pop esi
    pop ebx
    ret

.crc32_software:
    ; Software CRC32 implementation
    not eax
    
.sw_loop:
    test ecx, ecx
    jz .sw_done
    
    movzx edx, byte [esi]
    xor al, dl
    
    mov edx, 8
.bit_loop:
    shr eax, 1
    jnc .no_xor
    xor eax, 0xEDB88320
.no_xor:
    dec edx
    jnz .bit_loop
    
    inc esi
    dec ecx
    jmp .sw_loop
    
.sw_done:
    not eax
    ret

; Update CRC32 incrementally
; u32 crc32_update(u32 crc, u8 byte)
crc32_update:
    mov eax, [esp + 4]
    movzx edx, byte [esp + 8]
    
    ; Check for SSE4.2
    push ebx
    push ecx
    
    mov ebx, eax
    mov eax, 1
    cpuid
    test ecx, 0x00100000
    
    pop ecx
    pop ebx
    
    mov eax, ebx
    jz .software
    
    crc32 eax, dl
    ret
    
.software:
    xor al, dl
    mov ecx, 8
.loop:
    shr eax, 1
    jnc .no_xor
    xor eax, 0xEDB88320
.no_xor:
    loop .loop
    ret

; ============================================================================
; AES-NI Operations (Hardware AES)
; ============================================================================

global aes_encrypt_block
global aes_decrypt_block

; AES encrypt single block (128-bit)
; void aes_encrypt_block(u8* output, u8* input, u8* key, u32 rounds)
aes_encrypt_block:
    push ebp
    mov ebp, esp
    push esi
    push edi
    
    mov edi, [ebp + 8]          ; Output
    mov esi, [ebp + 12]         ; Input
    mov eax, [ebp + 16]         ; Key schedule
    mov ecx, [ebp + 20]         ; Rounds
    
    ; Load input
    movdqu xmm0, [esi]
    
    ; Initial round
    movdqu xmm1, [eax]
    pxor xmm0, xmm1
    add eax, 16
    
    ; Middle rounds
    dec ecx
.encrypt_loop:
    movdqu xmm1, [eax]
    aesenc xmm0, xmm1
    add eax, 16
    loop .encrypt_loop
    
    ; Final round
    movdqu xmm1, [eax]
    aesenclast xmm0, xmm1
    
    ; Store output
    movdqu [edi], xmm0
    
    pop edi
    pop esi
    pop ebp
    ret

; AES decrypt single block (128-bit)
; void aes_decrypt_block(u8* output, u8* input, u8* key, u32 rounds)
aes_decrypt_block:
    push ebp
    mov ebp, esp
    push esi
    push edi
    
    mov edi, [ebp + 8]
    mov esi, [ebp + 12]
    mov eax, [ebp + 16]
    mov ecx, [ebp + 20]
    
    ; Load input
    movdqu xmm0, [esi]
    
    ; Calculate last round key offset
    mov edx, ecx
    shl edx, 4
    add eax, edx
    
    ; Initial round
    movdqu xmm1, [eax]
    pxor xmm0, xmm1
    sub eax, 16
    
    ; Middle rounds
    dec ecx
.decrypt_loop:
    movdqu xmm1, [eax]
    aesdec xmm0, xmm1
    sub eax, 16
    loop .decrypt_loop
    
    ; Final round
    movdqu xmm1, [eax]
    aesdeclast xmm0, xmm1
    
    ; Store output
    movdqu [edi], xmm0
    
    pop edi
    pop esi
    pop ebp
    ret

; ============================================================================
; Memory Allocation Optimization
; ============================================================================

global mempool_alloc_fast
global mempool_free_fast

; Fast memory pool allocation (no locks, fixed-size)
; void* mempool_alloc_fast(void* pool, u32* free_list)
mempool_alloc_fast:
    mov eax, [esp + 8]          ; Free list pointer
    mov edx, [eax]              ; Get first free block
    
    test edx, edx
    jz .no_memory
    
    ; Update free list (atomic)
    mov ecx, [edx]              ; Next free block
    lock cmpxchg [eax], ecx
    jne mempool_alloc_fast      ; Retry if changed
    
    mov eax, edx
    ret
    
.no_memory:
    xor eax, eax
    ret

; Fast memory pool free
; void mempool_free_fast(void* pool, void* ptr, u32* free_list)
mempool_free_fast:
    mov eax, [esp + 4]          ; Pointer to free
    mov edx, [esp + 12]         ; Free list pointer
    
.retry:
    mov ecx, [edx]              ; Current head
    mov [eax], ecx              ; Link to current head
    
    lock cmpxchg [edx], eax
    jne .retry                  ; Retry if changed
    
    ret

; ============================================================================
; Statistics
; ============================================================================

section .data
align 4
cache_flushes: dd 0
nt_copies: dd 0
hw_crc_calls: dd 0
aes_encryptions: dd 0

section .text

global get_memopt_stats

; Get memory optimization statistics
; void get_memopt_stats(u32* flushes, u32* nt, u32* crc, u32* aes)
get_memopt_stats:
    push ebp
    mov ebp, esp
    push eax
    push ebx
    
    mov ebx, [ebp + 8]
    test ebx, ebx
    jz .skip1
    mov eax, [cache_flushes]
    mov [ebx], eax
    
.skip1:
    mov ebx, [ebp + 12]
    test ebx, ebx
    jz .skip2
    mov eax, [nt_copies]
    mov [ebx], eax
    
.skip2:
    mov ebx, [ebp + 16]
    test ebx, ebx
    jz .skip3
    mov eax, [hw_crc_calls]
    mov [ebx], eax
    
.skip3:
    mov ebx, [ebp + 20]
    test ebx, ebx
    jz .done
    mov eax, [aes_encryptions]
    mov [ebx], eax
    
.done:
    pop ebx
    pop eax
    pop ebp
    ret
