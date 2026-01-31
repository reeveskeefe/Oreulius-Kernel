; kernel/asm/perf.asm
; Performance measurement and profiling utilities
; High-precision timing and CPU cycle counting

global asm_rdtsc_begin
global asm_rdtsc_end
global asm_rdpmc
global asm_serialize
global asm_lfence_rdtsc
global asm_benchmark_nop
global asm_benchmark_add
global asm_benchmark_mul
global asm_benchmark_div
global asm_benchmark_load
global asm_benchmark_store
global asm_benchmark_lock
global asm_clflush
global asm_prefetch_t0
global asm_prefetch_t1
global asm_prefetch_t2
global asm_prefetch_nta

section .text

; Begin cycle-accurate timing measurement
; Returns TSC value with serialization to prevent out-of-order execution
; Use before the code you want to measure
asm_rdtsc_begin:
    push ebx
    
    xor eax, eax
    cpuid                ; Serialize execution
    rdtsc                ; Read timestamp counter
    
    pop ebx
    ret                  ; Returns EDX:EAX (64-bit timestamp)

; End cycle-accurate timing measurement
; Returns TSC value with serialization
; Use after the code you want to measure
asm_rdtsc_end:
    push ebx
    
    rdtscp               ; Read timestamp counter and processor ID
    mov ecx, eax         ; Save low 32 bits
    mov eax, edx         ; Move high 32 bits to EAX temporarily
    xor eax, eax
    cpuid                ; Serialize execution
    mov eax, ecx         ; Restore timestamp
    
    pop ebx
    ret                  ; Returns EDX:EAX (64-bit timestamp)

; Read Performance Monitoring Counter
; Args: (counter: u32) -> u64
; Reads a specific PMC (requires ring 0)
asm_rdpmc:
    mov ecx, [esp + 4]   ; Counter index
    rdpmc                ; Read performance counter
    ret                  ; Returns EDX:EAX (64-bit counter)

; Serialize instruction execution
; Ensures all previous instructions complete before continuing
asm_serialize:
    push ebx
    xor eax, eax
    cpuid
    pop ebx
    ret

; LFENCE + RDTSC (load fence before reading TSC)
; Alternative timing method with different serialization
asm_lfence_rdtsc:
    lfence
    rdtsc
    ret

; ===== Microbenchmarks =====

; Benchmark NOP instruction throughput
; Args: (iterations: u32) -> u64
; Returns cycle count for N NOP instructions
asm_benchmark_nop:
    push ebx
    push ecx
    
    mov ecx, [esp + 12]  ; iterations
    
    ; Start timing
    xor eax, eax
    cpuid
    rdtsc
    mov ebx, eax         ; Save start low
    mov esi, edx         ; Save start high
    
    ; Execute NOPs
.loop:
    nop
    dec ecx
    jnz .loop
    
    ; End timing
    rdtscp
    sub eax, ebx         ; Calculate cycles (low)
    sbb edx, esi         ; Calculate cycles (high) with borrow
    
    pop ecx
    pop ebx
    ret

; Benchmark ADD instruction throughput
; Args: (iterations: u32) -> u64
asm_benchmark_add:
    push ebx
    push ecx
    
    mov ecx, [esp + 12]  ; iterations
    
    xor eax, eax
    cpuid
    rdtsc
    mov ebx, eax
    mov esi, edx
    
    xor edi, edi         ; Clear accumulator
.loop:
    add edi, 1           ; ADD operation
    dec ecx
    jnz .loop
    
    rdtscp
    sub eax, ebx
    sbb edx, esi
    
    pop ecx
    pop ebx
    ret

; Benchmark MUL instruction throughput
; Args: (iterations: u32) -> u64
asm_benchmark_mul:
    push ebx
    push ecx
    
    mov ecx, [esp + 12]  ; iterations
    
    xor eax, eax
    cpuid
    rdtsc
    mov ebx, eax
    mov esi, edx
    
    mov edi, 1           ; Multiplicand
.loop:
    mov eax, edi
    mov edx, 3           ; Multiplier
    mul edx              ; MUL operation
    dec ecx
    jnz .loop
    
    rdtscp
    sub eax, ebx
    sbb edx, esi
    
    pop ecx
    pop ebx
    ret

; Benchmark DIV instruction throughput
; Args: (iterations: u32) -> u64
asm_benchmark_div:
    push ebx
    push ecx
    
    mov ecx, [esp + 12]  ; iterations
    
    xor eax, eax
    cpuid
    rdtsc
    mov ebx, eax
    mov esi, edx
    
    mov edi, 1000        ; Dividend
.loop:
    mov eax, edi
    xor edx, edx
    mov ebx, 3           ; Divisor
    div ebx              ; DIV operation
    dec ecx
    jnz .loop
    
    mov ebx, [esp + 12]  ; Restore for timing calc
    rdtscp
    sub eax, ebx
    sbb edx, esi
    
    pop ecx
    pop ebx
    ret

; Benchmark memory LOAD throughput
; Args: (ptr: *const u32, iterations: u32) -> u64
asm_benchmark_load:
    push ebx
    push ecx
    push esi
    
    mov esi, [esp + 16]  ; ptr
    mov ecx, [esp + 20]  ; iterations
    
    xor eax, eax
    cpuid
    rdtsc
    mov ebx, eax
    push edx             ; Save start high
    
.loop:
    mov edi, [esi]       ; LOAD operation
    dec ecx
    jnz .loop
    
    rdtscp
    pop esi              ; Restore start high
    sub eax, ebx
    sbb edx, esi
    
    pop esi
    pop ecx
    pop ebx
    ret

; Benchmark memory STORE throughput
; Args: (ptr: *mut u32, iterations: u32) -> u64
asm_benchmark_store:
    push ebx
    push ecx
    push esi
    
    mov esi, [esp + 16]  ; ptr
    mov ecx, [esp + 20]  ; iterations
    
    xor eax, eax
    cpuid
    rdtsc
    mov ebx, eax
    push edx
    
.loop:
    mov [esi], edi       ; STORE operation
    dec ecx
    jnz .loop
    
    rdtscp
    pop esi
    sub eax, ebx
    sbb edx, esi
    
    pop esi
    pop ecx
    pop ebx
    ret

; Benchmark LOCK prefix overhead
; Args: (ptr: *mut u32, iterations: u32) -> u64
asm_benchmark_lock:
    push ebx
    push ecx
    push esi
    
    mov esi, [esp + 16]  ; ptr
    mov ecx, [esp + 20]  ; iterations
    
    xor eax, eax
    cpuid
    rdtsc
    mov ebx, eax
    push edx
    
.loop:
    lock add dword [esi], 1  ; Atomic ADD
    dec ecx
    jnz .loop
    
    rdtscp
    pop esi
    sub eax, ebx
    sbb edx, esi
    
    pop esi
    pop ecx
    pop ebx
    ret

; ===== Cache Control =====

; Flush cache line containing address
; Args: (addr: *const u8)
; Forces cache line to be written back and invalidated
asm_clflush:
    mov eax, [esp + 4]   ; addr
    clflush [eax]
    ret

; Prefetch data into L1 cache (temporal locality)
; Args: (addr: *const u8)
asm_prefetch_t0:
    mov eax, [esp + 4]
    prefetcht0 [eax]
    ret

; Prefetch data into L2 cache
; Args: (addr: *const u8)
asm_prefetch_t1:
    mov eax, [esp + 4]
    prefetcht1 [eax]
    ret

; Prefetch data into L3 cache
; Args: (addr: *const u8)
asm_prefetch_t2:
    mov eax, [esp + 4]
    prefetcht2 [eax]
    ret

; Prefetch data (non-temporal - minimal cache pollution)
; Args: (addr: *const u8)
asm_prefetch_nta:
    mov eax, [esp + 4]
    prefetchnta [eax]
    ret
