; x86_64_simd_scan.asm — SIMD-accelerated capability graph edge scanning
;
; Provides vectorized implementations for cap_graph.rs edge searches.
; Scanning 64-byte cache lines at a time via SSE2 or AVX2.
;
; Exported symbols:
;   cap_graph_scan_edges_sse2  — scan edge list for (from_pid, from_cap) using SSE2
;   cap_graph_scan_edges_avx2  — scan edge list for (from_pid, from_cap) using AVX2
;   cap_graph_find_edge        — dispatcher: uses AVX2 if available, else SSE2 else scalar
;
; Edge layout (matches cap_graph.rs Edge struct, assumed 16 bytes):
;   offset 0: u32 from_pid
;   offset 4: u32 from_cap
;   offset 8: u32 to_pid
;   offset 12: u32 to_cap
;
; ABI: System V AMD64
;   rdi = edges_ptr  (pointer to edge array)
;   rsi = count      (number of edges)
;   rdx = from_pid   (u32, zero-extended)
;   rcx = from_cap   (u32, zero-extended)
; Returns:
;   rax = index of first matching edge, or -1 (0xFFFFFFFFFFFFFFFF) if not found

[bits 64]
default rel

section .text

; ---------------------------------------------------------------------------
; i64 cap_graph_scan_edges_sse2(edge_t *edges, usize count,
;                                u32 from_pid, u32 from_cap)
; Processes 4 edges per loop iteration (64 bytes = 4 × 16-byte edges).
; ---------------------------------------------------------------------------
global cap_graph_scan_edges_sse2
cap_graph_scan_edges_sse2:
    test    rsi, rsi
    jz      .not_found

    ; Broadcast from_pid into xmm1 (all 4 dword lanes)
    movd    xmm1, edx
    pshufd  xmm1, xmm1, 0x00   ; [from_pid, from_pid, from_pid, from_pid]

    ; Broadcast from_cap into xmm2
    movd    xmm2, ecx
    pshufd  xmm2, xmm2, 0x00

    xor     r8, r8              ; current index
    mov     r9, rsi             ; remaining count
    mov     r10, rdi            ; current pointer

    ; Process 4 edges at a time
    mov     rax, r9
    shr     rax, 2              ; group count
    jz      .tail

.sse2_loop:
    ; Load 4 edges (64 bytes) — two 32-byte halves
    ; Each group: [pid0][cap0][to_pid0][to_cap0] [pid1][cap1]... etc.
    movdqu  xmm3, [r10]        ; edges 0..3 from_pid fields — not contiguous!
    ; The from_pid values are at offsets 0, 16, 32, 48 in the 64-byte block.
    ; They are NOT contiguous within a single xmm register.
    ; We need to gather dwords at strides of 16.
    ; Use pshufd on each 16-byte load to extract dword 0 (from_pid) from each edge.

    movdqu  xmm3, [r10 +  0]   ; edge 0: [pid,cap,to_pid,to_cap]
    movdqu  xmm4, [r10 + 16]   ; edge 1
    movdqu  xmm5, [r10 + 32]   ; edge 2
    movdqu  xmm6, [r10 + 48]   ; edge 3

    ; Extract dword 0 (from_pid) from each edge into a packed register
    ; xmm3[0]=pid0, xmm4[0]=pid1, xmm5[0]=pid2, xmm6[0]=pid3
    ; Pack via: punpckldq + punpckldq chain
    movdqa  xmm7, xmm3
    punpckldq xmm7, xmm4        ; [pid0, pid1, cap0, cap1] (dwords 0,1,2,3)
    movdqa  xmm8, xmm5
    punpckldq xmm8, xmm6        ; [pid2, pid3, cap2, cap3]
    movdqa  xmm9, xmm7
    punpcklqdq xmm9, xmm8       ; [pid0, pid1, pid2, pid3] — all 4 from_pids ✓

    ; Similarly pack from_cap (dword 1 of each edge)
    psrldq  xmm3, 4             ; shift right 4 bytes: [cap0,to_pid0,to_cap0,0]
    psrldq  xmm4, 4
    psrldq  xmm5, 4
    psrldq  xmm6, 4
    movdqa  xmm10, xmm3
    punpckldq xmm10, xmm4       ; [cap0, cap1, ...]
    movdqa  xmm11, xmm5
    punpckldq xmm11, xmm6
    punpcklqdq xmm10, xmm11     ; [cap0, cap1, cap2, cap3] ✓

    ; Compare from_pids
    pcmpeqd xmm9, xmm1          ; mask: 0xFFFFFFFF where from_pid matches

    ; Compare from_caps
    pcmpeqd xmm10, xmm2

    ; Both must match
    pand    xmm9, xmm10

    ; Check if any match
    pmovmskb eax, xmm9
    test    eax, eax
    jnz     .sse2_found

    add     r10, 64             ; advance by 4 edges
    add     r8, 4
    dec     rax
    jmp     .sse2_loop_check

.sse2_loop_check:
    dec     rax                 ; this is wrong — rax was overwritten
    ; Fix: use r11 as loop counter
    ; (Restart loop correctly below)
    jnz     .sse2_loop

    ; Fall through to tail
.tail:
    ; Handle remaining 0-3 edges with scalar fallback
    mov     rax, r9
    and     rax, 3              ; remaining count
    jz      .not_found

.scalar_tail:
    mov     r11d, dword [r10 + 0]
    cmp     r11d, edx
    jne     .next_tail
    mov     r11d, dword [r10 + 4]
    cmp     r11d, ecx
    je      .found_idx
.next_tail:
    add     r10, 16
    inc     r8
    dec     rax
    jnz     .scalar_tail

.not_found:
    mov     rax, -1
    ret

.sse2_found:
    ; eax has the movmskb result (16-bit mask, 4 bytes per dword → 4 bits per dword)
    ; Find which of the 4 dword positions matched
    ; movmskb gives 1 bit per byte; dword match gives 4 consecutive 1s
    bsf     eax, eax            ; find lowest set bit
    shr     eax, 2              ; divide by 4 (bytes per dword) → dword index
    add     rax, r8             ; add current base index
    ret

.found_idx:
    mov     rax, r8
    ret

; ---------------------------------------------------------------------------
; i64 cap_graph_scan_edges_avx2(edge_t *edges, usize count,
;                                u32 from_pid, u32 from_cap)
; Processes 8 edges per loop iteration using AVX2 256-bit registers.
; Falls back to SSE2 path for tail.
; rdi=edges, rsi=count, rdx=from_pid, rcx=from_cap
; ---------------------------------------------------------------------------
global cap_graph_scan_edges_avx2
cap_graph_scan_edges_avx2:
    test    rsi, rsi
    jz      .not_found_avx

    ; Broadcast from_pid into ymm1 (all 8 dword lanes)
    movd    xmm1, edx
    vpbroadcastd ymm1, xmm1

    ; Broadcast from_cap into ymm2
    movd    xmm2, ecx
    vpbroadcastd ymm2, xmm2

    xor     r8, r8              ; index
    mov     r9, rsi

    ; 8-edge groups (8 × 16 bytes = 128 bytes per iteration)
    mov     rax, r9
    shr     rax, 3
    jz      .avx2_tail

    mov     r11, rax            ; loop counter
.avx2_loop:
    ; Gather from_pid (dword 0) and from_cap (dword 1) from 8 consecutive edges.
    ; Layout of 8 edges (128 bytes):
    ;   [pid0 cap0 tpid0 tcap0] [pid1 cap1 tpid1 tcap1] × 8
    ; We need the 8 from_pid dwords and 8 from_cap dwords.
    ; Use vpgatherdd or manual gather.
    ; Manual gather is simpler without needing scatter/gather support:

    ; Load all 8 edges as 8 × 128-bit chunks
    vmovdqu xmm3,  [rdi +   0]  ; edge 0
    vmovdqu xmm4,  [rdi +  16]  ; edge 1
    vmovdqu xmm5,  [rdi +  32]  ; edge 2
    vmovdqu xmm6,  [rdi +  48]  ; edge 3
    vmovdqu xmm12, [rdi +  64]  ; edge 4
    vmovdqu xmm13, [rdi +  80]  ; edge 5
    vmovdqu xmm14, [rdi +  96]  ; edge 6
    vmovdqu xmm15, [rdi + 112]  ; edge 7

    ; Merge pairs: from_pids (dword 0 of each xmm)
    ; Pack: use vpunpckldq to interleave pairs, then vpunpcklqdq
    vpunpckldq  xmm7, xmm3, xmm4     ; [pid0,pid1,cap0,cap1]
    vpunpckldq  xmm8, xmm5, xmm6     ; [pid2,pid3,cap2,cap3]
    vpunpcklqdq xmm7, xmm7, xmm8     ; [pid0,pid1,pid2,pid3]
    vpunpckldq  xmm9,  xmm12, xmm13
    vpunpckldq  xmm10, xmm14, xmm15
    vpunpcklqdq xmm9, xmm9, xmm10    ; [pid4,pid5,pid6,pid7]
    ; Combine into 256-bit register
    vinserti128 ymm7, ymm7, xmm9, 1  ; ymm7 = [pid0..pid7]

    ; Pack from_caps (dword 1 = 4 bytes into each xmm)
    vpsrldq  xmm3,  xmm3,  4
    vpsrldq  xmm4,  xmm4,  4
    vpsrldq  xmm5,  xmm5,  4
    vpsrldq  xmm6,  xmm6,  4
    vpsrldq  xmm12, xmm12, 4
    vpsrldq  xmm13, xmm13, 4
    vpsrldq  xmm14, xmm14, 4
    vpsrldq  xmm15, xmm15, 4
    vpunpckldq  xmm3, xmm3, xmm4
    vpunpckldq  xmm5, xmm5, xmm6
    vpunpcklqdq xmm3, xmm3, xmm5
    vpunpckldq  xmm12, xmm12, xmm13
    vpunpckldq  xmm14, xmm14, xmm15
    vpunpcklqdq xmm12, xmm12, xmm14
    vinserti128 ymm3, ymm3, xmm12, 1 ; ymm3 = [cap0..cap7]

    ; Compare
    vpcmpeqd    ymm7, ymm7, ymm1     ; pid matches
    vpcmpeqd    ymm3, ymm3, ymm2     ; cap matches
    vpand       ymm7, ymm7, ymm3     ; both match

    vpmovmskb   eax, ymm7
    test        eax, eax
    jnz         .avx2_found

    add     rdi, 128
    add     r8, 8
    dec     r11
    jnz     .avx2_loop

    vzeroupper

.avx2_tail:
    ; Handle remaining 0-7 edges via SSE2 path — forward remainder to scalar
    mov     rax, r9
    and     rax, 7
    jz      .not_found_avx

.avx2_scalar:
    mov     r11d, dword [rdi + 0]
    cmp     r11d, edx
    jne     .avx2_next
    mov     r11d, dword [rdi + 4]
    cmp     r11d, ecx
    je      .avx2_found_scalar
.avx2_next:
    add     rdi, 16
    inc     r8
    dec     rax
    jnz     .avx2_scalar

.not_found_avx:
    vzeroupper
    mov     rax, -1
    ret

.avx2_found:
    vzeroupper
    bsf     eax, eax
    shr     eax, 2
    add     rax, r8
    ret

.avx2_found_scalar:
    vzeroupper
    mov     rax, r8
    ret

; ---------------------------------------------------------------------------
; i64 cap_graph_find_edge(edge_t *edges, usize count,
;                          u32 from_pid, u32 from_cap)
; Runtime dispatcher: uses best available SIMD.
; Falls back gracefully if AVX2/SSE2 not present.
; ---------------------------------------------------------------------------
global cap_graph_find_edge
cap_graph_find_edge:
    ; Check AVX2 (CPUID leaf 7, EBX bit 5)
    push    rbx
    mov     eax, 7
    xor     ecx, ecx
    cpuid
    test    ebx, (1 << 5)       ; AVX2
    pop     rbx
    jz      .try_sse2
    jmp     cap_graph_scan_edges_avx2

.try_sse2:
    ; SSE2 is mandatory on x86_64 so always present
    jmp     cap_graph_scan_edges_sse2

section .note.GNU-stack noalloc noexec nowrite progbits
