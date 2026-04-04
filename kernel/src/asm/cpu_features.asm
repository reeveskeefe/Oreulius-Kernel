; kernel/asm/cpu_features.asm
; CPU feature detection and advanced processor operations
; Provides CPUID access, SSE detection, and CPU identification

global asm_cpuid
global asm_has_sse
global asm_has_sse2
global asm_has_sse3
global asm_has_sse4_1
global asm_has_sse4_2
global asm_has_avx
global asm_get_cpu_vendor
global asm_get_cpu_features
global asm_get_cache_info
global asm_rdrand
global asm_xsave_supported
global asm_fxsave
global asm_fxrstor

section .text

; Execute CPUID instruction
; Args: (eax_in: u32, ecx_in: u32, result: *mut CpuIdResult)
; CpuIdResult layout: eax (0), ebx (4), ecx (8), edx (12)
asm_cpuid:
    push ebx
    push esi
    
    mov eax, [esp + 12]  ; eax_in
    mov ecx, [esp + 16]  ; ecx_in
    
    cpuid
    
    mov esi, [esp + 20]  ; result pointer
    mov [esi + 0], eax
    mov [esi + 4], ebx
    mov [esi + 8], ecx
    mov [esi + 12], edx
    
    pop esi
    pop ebx
    ret

; Check if SSE is supported
; Returns 1 if supported, 0 otherwise
asm_has_sse:
    push ebx
    
    mov eax, 1
    cpuid
    
    ; Check EDX bit 25 (SSE support)
    shr edx, 25
    and edx, 1
    mov eax, edx
    
    pop ebx
    ret

; Check if SSE2 is supported
; Returns 1 if supported, 0 otherwise
asm_has_sse2:
    push ebx
    
    mov eax, 1
    cpuid
    
    ; Check EDX bit 26 (SSE2 support)
    shr edx, 26
    and edx, 1
    mov eax, edx
    
    pop ebx
    ret

; Check if SSE3 is supported
; Returns 1 if supported, 0 otherwise
asm_has_sse3:
    push ebx
    
    mov eax, 1
    cpuid
    
    ; Check ECX bit 0 (SSE3 support)
    and ecx, 1
    mov eax, ecx
    
    pop ebx
    ret

; Check if SSE4.1 is supported
; Returns 1 if supported, 0 otherwise
asm_has_sse4_1:
    push ebx
    
    mov eax, 1
    cpuid
    
    ; Check ECX bit 19 (SSE4.1 support)
    shr ecx, 19
    and ecx, 1
    mov eax, ecx
    
    pop ebx
    ret

; Check if SSE4.2 is supported
; Returns 1 if supported, 0 otherwise
asm_has_sse4_2:
    push ebx
    
    mov eax, 1
    cpuid
    
    ; Check ECX bit 20 (SSE4.2 support)
    shr ecx, 20
    and ecx, 1
    mov eax, ecx
    
    pop ebx
    ret

; Check if AVX is supported
; Returns 1 if supported, 0 otherwise
asm_has_avx:
    push ebx
    
    mov eax, 1
    cpuid
    
    ; Check ECX bit 28 (AVX support)
    shr ecx, 28
    and ecx, 1
    mov eax, ecx
    
    pop ebx
    ret

; Get CPU vendor string (12 bytes)
; Args: (vendor_str: *mut [u8; 12])
; GenuineIntel, AuthenticAMD, etc.
asm_get_cpu_vendor:
    push ebx
    push edi
    
    xor eax, eax  ; CPUID function 0
    cpuid
    
    mov edi, [esp + 12]  ; vendor_str pointer
    
    ; EBX contains first 4 chars
    mov [edi + 0], ebx
    ; EDX contains next 4 chars
    mov [edi + 4], edx
    ; ECX contains last 4 chars
    mov [edi + 8], ecx
    
    pop edi
    pop ebx
    ret

; Get CPU feature flags
; Args: (features: *mut CpuFeatures)
; CpuFeatures layout: ecx_features (0), edx_features (4)
asm_get_cpu_features:
    push ebx
    push edi
    
    mov eax, 1
    cpuid
    
    mov edi, [esp + 12]  ; features pointer
    mov [edi + 0], ecx   ; ECX feature flags
    mov [edi + 4], edx   ; EDX feature flags
    
    pop edi
    pop ebx
    ret

; Get CPU cache information
; Args: (cache_info: *mut CacheInfo)
; Returns basic cache size information
asm_get_cache_info:
    push ebx
    push edi
    
    mov eax, 2  ; Cache descriptor information
    cpuid
    
    mov edi, [esp + 12]  ; cache_info pointer
    mov [edi + 0], eax
    mov [edi + 4], ebx
    mov [edi + 8], ecx
    mov [edi + 12], edx
    
    pop edi
    pop ebx
    ret

; Read hardware random number (RDRAND instruction)
; Args: (value: *mut u32) -> i32
; Returns 1 if successful, 0 if failed (retry needed)
asm_rdrand:
    push ebx
    
    ; Try RDRAND instruction
    rdrand eax
    jnc .failed  ; Carry flag clear = no random value available
    
    ; Success - store value
    mov ebx, [esp + 8]  ; value pointer
    mov [ebx], eax
    mov eax, 1  ; Return success
    pop ebx
    ret

.failed:
    xor eax, eax  ; Return failure
    pop ebx
    ret

; Check if XSAVE is supported
; Returns 1 if supported, 0 otherwise
asm_xsave_supported:
    push ebx
    
    mov eax, 1
    cpuid
    
    ; Check ECX bit 26 (XSAVE support)
    shr ecx, 26
    and ecx, 1
    mov eax, ecx
    
    pop ebx
    ret

; Save x87 FPU, MMX, SSE, and SSE2 state (FXSAVE instruction)
; Args: (save_area: *mut [u8; 512])
; Requires 16-byte aligned memory
asm_fxsave:
    mov eax, [esp + 4]  ; save_area pointer
    fxsave [eax]
    ret

; Restore x87 FPU, MMX, SSE, and SSE2 state (FXRSTOR instruction)
; Args: (save_area: *const [u8; 512])
; Requires 16-byte aligned memory
asm_fxrstor:
    mov eax, [esp + 4]  ; save_area pointer
    fxrstor [eax]
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
