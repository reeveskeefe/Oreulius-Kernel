; x86_64_cpu_features.asm — CPUID, feature detection, TSC, RDRAND for x86_64
;
; Replaces STUB_ZERO shims for:
;   asm_cpuid, asm_get_cpu_vendor, asm_has_avx, asm_has_sse, asm_has_sse2,
;   asm_has_sse3, asm_has_sse4_1, asm_has_sse4_2, asm_xsave_supported,
;   asm_rdrand, asm_rdtsc_begin, asm_rdtsc_end, asm_read_tsc,
;   get_interrupt_count, increment_interrupt_count
;
; ABI: System V AMD64

[bits 64]
default rel

section .bss
alignb 8

; Monotonic interrupt counter, incremented from IRQ dispatch path.
global _interrupt_count
_interrupt_count:   resq 1

section .text

; ---------------------------------------------------------------------------
; void asm_cpuid(u32 leaf, u32 subleaf, CpuIdResult *out)
; Execute CPUID for the given leaf/subleaf and write all four output registers
; into the result struct laid out as { eax, ebx, ecx, edx }.
; rdi=leaf, rsi=subleaf, rdx=*out
; ---------------------------------------------------------------------------
global asm_cpuid
asm_cpuid:
    push    rbx                 ; rbx is callee-saved in SysV ABI
    mov     r8, rdx             ; preserve result pointer across CPUID
    mov     eax, edi            ; leaf
    mov     ecx, esi            ; subleaf
    cpuid
    mov     [r8 + 0], eax
    mov     [r8 + 4], ebx
    mov     [r8 + 8], ecx
    mov     [r8 + 12], edx
    pop     rbx
    ret

; ---------------------------------------------------------------------------
; void asm_get_cpu_vendor(char *buf)
; Write the 12-byte vendor string (EBX:EDX:ECX of CPUID leaf 0) to buf.
; buf must be at least 13 bytes; null-terminated by caller convention.
; ---------------------------------------------------------------------------
global asm_get_cpu_vendor
asm_get_cpu_vendor:
    push    rbx
    xor     eax, eax            ; leaf 0
    cpuid
    ; EBX/EDX/ECX contain vendor string in that order
    mov     dword [rdi + 0], ebx
    mov     dword [rdi + 4], edx
    mov     dword [rdi + 8], ecx
    mov     byte  [rdi + 12], 0 ; null terminator
    pop     rbx
    ret

; ---------------------------------------------------------------------------
; Internal helper: run CPUID leaf 1 and return ECX in rax.
; Clobbers: rax, rbx, rcx, rdx
; ---------------------------------------------------------------------------
_cpuid1_ecx:
    push    rbx
    mov     eax, 1
    xor     ecx, ecx
    cpuid
    mov     eax, ecx
    pop     rbx
    ret

; Internal helper: run CPUID leaf 7, sub-leaf 0; return EBX in rax.
_cpuid7_ebx:
    push    rbx
    mov     eax, 7
    xor     ecx, ecx
    cpuid
    mov     eax, ebx
    pop     rbx
    ret

; ---------------------------------------------------------------------------
; u32 asm_has_sse(void)   — bit 25 of CPUID.1:EDX
; ---------------------------------------------------------------------------
global asm_has_sse
asm_has_sse:
    push    rbx
    mov     eax, 1
    xor     ecx, ecx
    cpuid
    shr     edx, 25
    and     eax, 0              ; clear eax
    and     edx, 1
    mov     eax, edx
    pop     rbx
    ret

; ---------------------------------------------------------------------------
; u32 asm_has_sse2(void)  — bit 26 of CPUID.1:EDX
; ---------------------------------------------------------------------------
global asm_has_sse2
asm_has_sse2:
    push    rbx
    mov     eax, 1
    xor     ecx, ecx
    cpuid
    shr     edx, 26
    and     edx, 1
    mov     eax, edx
    pop     rbx
    ret

; ---------------------------------------------------------------------------
; u32 asm_has_sse3(void)  — bit 0 of CPUID.1:ECX
; ---------------------------------------------------------------------------
global asm_has_sse3
asm_has_sse3:
    call    _cpuid1_ecx
    and     eax, 1
    ret

; ---------------------------------------------------------------------------
; u32 asm_has_sse4_1(void) — bit 19 of CPUID.1:ECX
; ---------------------------------------------------------------------------
global asm_has_sse4_1
asm_has_sse4_1:
    call    _cpuid1_ecx
    shr     eax, 19
    and     eax, 1
    ret

; ---------------------------------------------------------------------------
; u32 asm_has_sse4_2(void) — bit 20 of CPUID.1:ECX
; ---------------------------------------------------------------------------
global asm_has_sse4_2
asm_has_sse4_2:
    call    _cpuid1_ecx
    shr     eax, 20
    and     eax, 1
    ret

; ---------------------------------------------------------------------------
; u32 asm_has_avx(void) — bit 28 of CPUID.1:ECX + OSXSAVE check (bit 27)
; AVX requires OS support (XSAVE/XRSTOR enabled in XCR0).
; ---------------------------------------------------------------------------
global asm_has_avx
asm_has_avx:
    call    _cpuid1_ecx
    ; check both OSXSAVE (bit 27) and AVX (bit 28)
    mov     edx, eax
    shr     edx, 27
    and     edx, 3              ; bits 27+28 → bottom two bits
    cmp     edx, 3
    jne     .no_avx
    ; Check XCR0 bits 1 and 2 (XMM and YMM state enabled by OS)
    xor     ecx, ecx
    xgetbv
    and     eax, 6
    cmp     eax, 6
    jne     .no_avx
    mov     eax, 1
    ret
.no_avx:
    xor     eax, eax
    ret

; ---------------------------------------------------------------------------
; u32 asm_xsave_supported(void) — bit 26 of CPUID.1:ECX
; ---------------------------------------------------------------------------
global asm_xsave_supported
asm_xsave_supported:
    call    _cpuid1_ecx
    shr     eax, 26
    and     eax, 1
    ret

; ---------------------------------------------------------------------------
; i32 asm_rdrand(u32 *out)
; Read a hardware random value via RDRAND. Retries up to 10 times.
; Returns 1 on success and writes the value to *out, otherwise returns 0.
; ---------------------------------------------------------------------------
global asm_rdrand
asm_rdrand:
    mov     ecx, 10             ; retry limit
.retry:
    rdrand  eax
    jc      .done               ; CF=1 means valid value
    dec     ecx
    jnz     .retry
    xor     eax, eax            ; failed — return 0
    ret
.done:
    mov     [rdi], eax
    mov     eax, 1
    ret

; ---------------------------------------------------------------------------
; u64 asm_rdtsc_begin(void)
; Serialized RDTSC for benchmark start. Uses CPUID to serialize.
; Returns 64-bit TSC value.
; ---------------------------------------------------------------------------
global asm_rdtsc_begin
asm_rdtsc_begin:
    push    rbx
    xor     eax, eax
    cpuid                       ; serialize instruction stream
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    pop     rbx
    ret

; ---------------------------------------------------------------------------
; u64 asm_rdtsc_end(void)
; Serialized RDTSC for benchmark end. Uses RDTSCP to serialize.
; Returns 64-bit TSC value.
; ---------------------------------------------------------------------------
global asm_rdtsc_end
asm_rdtsc_end:
    rdtscp                      ; waits for all prior instructions to retire
    shl     rdx, 32
    or      rax, rdx
    ; ecx contains IA32_TSC_AUX (processor/socket ID) — ignored
    lfence                      ; prevent subsequent instructions from executing before RDTSCP
    ret

; ---------------------------------------------------------------------------
; u64 asm_read_tsc(void)
; Unserialized fast TSC read. For use in non-benchmark timing paths.
; ---------------------------------------------------------------------------
global asm_read_tsc
asm_read_tsc:
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    ret

; ---------------------------------------------------------------------------
; u64 get_interrupt_count(void)
; Return the current monotonic interrupt counter.
; ---------------------------------------------------------------------------
global get_interrupt_count
get_interrupt_count:
    mov     rax, [rel _interrupt_count]
    ret

; ---------------------------------------------------------------------------
; void increment_interrupt_count(void)
; Atomically increment the interrupt counter.
; Called from IRQ dispatch path (already in interrupt context — use LOCK anyway
; for correctness on SMP if/when that path is added).
; ---------------------------------------------------------------------------
global increment_interrupt_count
increment_interrupt_count:
    lock inc qword [rel _interrupt_count]
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
