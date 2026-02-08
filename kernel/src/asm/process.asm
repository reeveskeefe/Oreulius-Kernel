; Advanced Process Management Assembly
; Context switching, task state, and privilege level transitions
; x86 32-bit architecture

[BITS 32]

section .text

; ============================================================================
; Task State Segment (TSS) Operations
; ============================================================================

global tss_load
global tss_set_kernel_stack
global tss_get_esp0

; TSS structure offsets
TSS_ESP0    equ 4
TSS_SS0     equ 8
TSS_ESP1    equ 12
TSS_SS1     equ 16
TSS_ESP2    equ 20
TSS_SS2     equ 24

; Load TSS into task register
; void tss_load(u16 tss_selector)
tss_load:
    mov ax, [esp + 4]       ; TSS selector
    ltr ax                  ; Load task register
    ret

; Set kernel stack in TSS (for privilege level transitions)
; void tss_set_kernel_stack(u32* tss_addr, u32 esp0, u16 ss0)
tss_set_kernel_stack:
    push ebp
    mov ebp, esp
    push eax
    push ebx
    
    mov eax, [ebp + 8]      ; TSS address
    mov ebx, [ebp + 12]     ; ESP0
    mov [eax + TSS_ESP0], ebx
    
    mov bx, [ebp + 16]      ; SS0
    mov [eax + TSS_SS0], bx
    
    pop ebx
    pop eax
    pop ebp
    ret

; Get current kernel stack pointer from TSS
; u32 tss_get_esp0(u32* tss_addr)
tss_get_esp0:
    mov eax, [esp + 4]      ; TSS address
    mov eax, [eax + TSS_ESP0]
    ret

; ============================================================================
; Fast Context Switch (optimized)
; ============================================================================

global fast_context_switch
; void fast_context_switch(TaskContext* from, TaskContext* to)
; TaskContext layout:
;   +0:  ESP
;   +4:  EBP
;   +8:  EBX
;   +12: ESI
;   +16: EDI
;   +20: EIP (return address)
;   +24: EFLAGS
;   +28: CR3 (page directory)

fast_context_switch:
    push ebp
    mov ebp, esp
    
    ; Get pointers
    mov eax, [ebp + 8]      ; from
    mov edx, [ebp + 12]     ; to
    
    ; Save current context
    mov [eax + 0], esp
    mov [eax + 4], ebp
    mov [eax + 8], ebx
    mov [eax + 12], esi
    mov [eax + 16], edi
    
    ; Save return address
    mov ecx, [ebp + 4]
    mov [eax + 20], ecx
    
    ; Save EFLAGS
    pushfd
    pop ecx
    mov [eax + 24], ecx
    
    ; Save CR3 (current page directory)
    mov ecx, cr3
    mov [eax + 28], ecx
    
    ; Switch to new page directory if different
    mov ecx, [edx + 28]
    cmp ecx, [eax + 28]
    je .skip_cr3_load
    mov cr3, ecx
.skip_cr3_load:
    
    ; Restore new context
    mov esp, [edx + 0]
    mov ebp, [edx + 4]
    mov ebx, [edx + 8]
    mov esi, [edx + 12]
    mov edi, [edx + 16]
    
    ; Restore EFLAGS
    mov ecx, [edx + 24]
    push ecx
    popfd
    
    ; Jump to return address
    mov eax, [edx + 20]
    jmp eax

; ============================================================================
; User to Kernel Mode Transition (Syscall Entry)
; ============================================================================

global enter_kernel_mode
; void enter_kernel_mode(void)
; Transitions from user mode (ring 3) to kernel mode (ring 0)
; Assumes interrupt/syscall has already saved state
enter_kernel_mode:
    ; Switch to kernel data segments
    mov ax, 0x10            ; Kernel data segment
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    
    ; Stack already switched by CPU during interrupt
    ret

global enter_user_mode
; void enter_user_mode(u32 esp, u32 eip, u16 cs, u16 ds)
; Transitions from kernel to user mode
; Prepares for IRET to user space
enter_user_mode:
    cli                     ; Disable interrupts
    
    mov ax, [esp + 16]      ; User data segment
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    
    ; Build IRET frame
    mov eax, [esp + 16]     ; User DS
    push eax                ; SS
    
    mov eax, [esp + 4]      ; User ESP
    push eax
    
    pushfd                  ; EFLAGS
    pop eax
    or eax, 0x200           ; Enable interrupts in user mode
    push eax
    
    mov eax, [esp + 16]     ; User CS
    push eax
    
    mov eax, [esp + 12]     ; User EIP
    push eax
    
    iretd                   ; Return to user mode

; ============================================================================
; Process State Management
; ============================================================================

global save_fpu_state
global restore_fpu_state

; Save FPU/SSE state
; void save_fpu_state(void* fpu_buffer) // 512 bytes
save_fpu_state:
    mov eax, [esp + 4]      ; Buffer address
    
    ; Check if we have FXSAVE (SSE)
    push ebx
    push ecx
    push edx
    
    mov eax, 1
    cpuid
    test edx, 0x01000000    ; FXSR bit
    pop edx
    pop ecx
    pop ebx
    
    mov eax, [esp + 4]
    jz .use_fsave
    
.use_fxsave:
    fxsave [eax]
    ret
    
.use_fsave:
    fsave [eax]
    ret

; Restore FPU/SSE state
; void restore_fpu_state(void* fpu_buffer)
restore_fpu_state:
    mov eax, [esp + 4]
    
    ; Check for FXRSTOR
    push ebx
    push ecx
    push edx
    
    mov eax, 1
    cpuid
    test edx, 0x01000000
    pop edx
    pop ecx
    pop ebx
    
    mov eax, [esp + 4]
    jz .use_frstor
    
.use_fxrstor:
    fxrstor [eax]
    ret
    
.use_frstor:
    frstor [eax]
    ret

; ============================================================================
; Interrupt Management
; ============================================================================

global get_interrupt_state
global set_interrupt_state
global disable_interrupts_save
global restore_interrupts

; Get current interrupt state
; u32 get_interrupt_state(void)
; Returns 1 if interrupts enabled, 0 otherwise
get_interrupt_state:
    pushfd
    pop eax
    shr eax, 9              ; IF flag is bit 9
    and eax, 1
    ret

; Set interrupt state
; void set_interrupt_state(u32 enabled)
set_interrupt_state:
    mov eax, [esp + 4]
    test eax, eax
    jz .disable
    sti
    ret
.disable:
    cli
    ret

; Disable interrupts and return old state
; u32 disable_interrupts_save(void)
disable_interrupts_save:
    pushfd
    pop eax
    cli
    shr eax, 9
    and eax, 1
    ret

; Restore interrupt state
; void restore_interrupts(u32 old_state)
restore_interrupts:
    mov eax, [esp + 4]
    test eax, eax
    jz .done
    sti
.done:
    ret

; ============================================================================
; Spinlock Implementation (for SMP)
; ============================================================================

global spinlock_acquire
global spinlock_release
global spinlock_try_acquire

; Acquire spinlock
; void spinlock_acquire(u32* lock)
spinlock_acquire:
    mov edx, [esp + 4]      ; Lock address
    mov eax, 1
.retry:
    pause                   ; Hint to CPU we're spinning
    xchg [edx], eax         ; Atomic exchange
    test eax, eax
    jnz .retry              ; If was locked, retry
    ret

; Release spinlock
; void spinlock_release(u32* lock)
spinlock_release:
    mov edx, [esp + 4]
    mov dword [edx], 0
    ret

; Try to acquire spinlock (non-blocking)
; u32 spinlock_try_acquire(u32* lock)
; Returns 1 if acquired, 0 if already locked
spinlock_try_acquire:
    mov edx, [esp + 4]
    mov eax, 1
    xchg [edx], eax
    xor eax, 1              ; Invert: was 0 = success (now 1)
    ret

; ============================================================================
; CPU Identification and Features
; ============================================================================

global get_cpu_vendor
global get_cpu_features
global has_sse
global has_sse2
global has_avx

; Get CPU vendor string
; void get_cpu_vendor(char* buffer) // 12 bytes
get_cpu_vendor:
    push ebp
    mov ebp, esp
    push ebx
    push ecx
    push edx
    push edi
    
    mov edi, [ebp + 8]      ; Buffer
    
    xor eax, eax
    cpuid
    
    ; EBX, EDX, ECX contain vendor string
    mov [edi], ebx
    mov [edi + 4], edx
    mov [edi + 8], ecx
    
    pop edi
    pop edx
    pop ecx
    pop ebx
    pop ebp
    ret

; Get CPU feature flags
; u32 get_cpu_features(void)
; Returns EDX from CPUID(1)
get_cpu_features:
    push ebx
    push ecx
    
    mov eax, 1
    cpuid
    mov eax, edx
    
    pop ecx
    pop ebx
    ret

; Check for SSE support
; u32 has_sse(void)
has_sse:
    push ebx
    push ecx
    push edx
    
    mov eax, 1
    cpuid
    shr edx, 25
    and edx, 1
    mov eax, edx
    
    pop edx
    pop ecx
    pop ebx
    ret

; Check for SSE2 support
; u32 has_sse2(void)
has_sse2:
    push ebx
    push ecx
    push edx
    
    mov eax, 1
    cpuid
    shr edx, 26
    and edx, 1
    mov eax, edx
    
    pop edx
    pop ecx
    pop ebx
    ret

; Check for AVX support
; u32 has_avx(void)
has_avx:
    push ebx
    push edx
    
    mov eax, 1
    cpuid
    shr ecx, 28
    and ecx, 1
    mov eax, ecx
    
    pop edx
    pop ebx
    ret

; ============================================================================
; Port I/O Operations
; ============================================================================

global inb
global inw
global inl
global outb
global outw
global outl

; Read byte from port
; u8 inb(u16 port)
inb:
    mov dx, [esp + 4]
    xor eax, eax
    in al, dx
    ret

; Read word from port
; u16 inw(u16 port)
inw:
    mov dx, [esp + 4]
    xor eax, eax
    in ax, dx
    ret

; Read dword from port
; u32 inl(u16 port)
inl:
    mov dx, [esp + 4]
    in eax, dx
    ret

; Write byte to port
; void outb(u16 port, u8 value)
outb:
    mov dx, [esp + 4]
    mov al, [esp + 8]
    out dx, al
    ret

; Write word to port
; void outw(u16 port, u16 value)
outw:
    mov dx, [esp + 4]
    mov ax, [esp + 8]
    out dx, ax
    ret

; Write dword to port
; void outl(u16 port, u32 value)
outl:
    mov dx, [esp + 4]
    mov eax, [esp + 8]
    out dx, eax
    ret

; ============================================================================
; MSR (Model Specific Register) Operations
; ============================================================================

global read_msr
global write_msr

; Read MSR
; u64 read_msr(u32 msr)
; Returns EDX:EAX
read_msr:
    push ecx
    
    mov ecx, [esp + 8]      ; MSR number
    rdmsr                   ; Read into EDX:EAX
    
    pop ecx
    ret                     ; Caller gets EDX:EAX

; Write MSR
; void write_msr(u32 msr, u32 low, u32 high)
write_msr:
    push ecx
    
    mov ecx, [esp + 8]      ; MSR number
    mov eax, [esp + 12]     ; Low 32 bits
    mov edx, [esp + 16]     ; High 32 bits
    wrmsr
    
    pop ecx
    ret

; ============================================================================
; Performance Counters
; ============================================================================

global read_pmc
global read_tsc_64

; Read performance counter
; u64 read_pmc(u32 counter)
read_pmc:
    push ecx
    
    mov ecx, [esp + 8]
    rdpmc                   ; Read into EDX:EAX
    
    pop ecx
    ret

; Read timestamp counter (64-bit)
; u64 read_tsc_64(void)
read_tsc_64:
    rdtsc                   ; EDX:EAX = TSC
    ret

; ============================================================================
; Memory Operations (optimized)
; ============================================================================

global fast_memcpy
global fast_memset
global fast_memcmp

; Fast memory copy
; void fast_memcpy(void* dst, void* src, u32 count)
fast_memcpy:
    push edi
    push esi
    push ecx
    
    mov edi, [esp + 16]     ; dst
    mov esi, [esp + 20]     ; src
    mov ecx, [esp + 24]     ; count
    
    ; Copy dwords first
    mov eax, ecx
    shr ecx, 2
    cld
    rep movsd
    
    ; Copy remaining bytes
    mov ecx, eax
    and ecx, 3
    rep movsb
    
    pop ecx
    pop esi
    pop edi
    ret

; Fast memory set
; void fast_memset(void* dst, u8 value, u32 count)
fast_memset:
    push edi
    push ecx
    
    mov edi, [esp + 12]     ; dst
    mov al, [esp + 16]      ; value
    mov ecx, [esp + 20]     ; count
    
    ; Replicate byte to dword
    mov ah, al
    mov dx, ax
    shl eax, 16
    mov ax, dx
    
    ; Set dwords first
    mov edx, ecx
    shr ecx, 2
    cld
    rep stosd
    
    ; Set remaining bytes
    mov ecx, edx
    and ecx, 3
    rep stosb
    
    pop ecx
    pop edi
    ret

; Fast memory compare
; i32 fast_memcmp(void* s1, void* s2, u32 count)
fast_memcmp:
    push esi
    push edi
    push ecx
    
    mov esi, [esp + 16]     ; s1
    mov edi, [esp + 20]     ; s2
    mov ecx, [esp + 24]     ; count
    
    cld
    repe cmpsb
    
    xor eax, eax
    jz .equal
    
    ; Return difference
    mov al, [esi - 1]
    mov dl, [edi - 1]
    sub eax, edx
    
.equal:
    pop ecx
    pop edi
    pop esi
    ret

; ============================================================================
; Bit Operations
; ============================================================================

global find_first_set_bit
global find_last_set_bit
global count_set_bits

; Find first set bit (LSB)
; u32 find_first_set_bit(u32 value)
; Returns bit position (0-31) or 32 if no bits set
find_first_set_bit:
    mov eax, [esp + 4]
    bsf eax, eax
    jnz .found
    mov eax, 32
.found:
    ret

; Find last set bit (MSB)
; u32 find_last_set_bit(u32 value)
; Returns bit position (0-31) or 32 if no bits set
find_last_set_bit:
    mov eax, [esp + 4]
    bsr eax, eax
    jnz .found
    mov eax, 32
.found:
    ret

; Count set bits (population count)
; u32 count_set_bits(u32 value)
count_set_bits:
    mov eax, [esp + 4]
    
    ; Check for POPCNT instruction
    push ebx
    push ecx
    push edx
    
    mov eax, 1
    cpuid
    test ecx, 0x00800000    ; POPCNT bit
    pop edx
    pop ecx
    pop ebx
    
    mov eax, [esp + 4]
    jz .software_count
    
    ; Use hardware POPCNT
    popcnt eax, eax
    ret
    
.software_count:
    ; Software fallback
    xor ecx, ecx
.loop:
    test eax, eax
    jz .done
    mov edx, eax
    dec edx
    and eax, edx
    inc ecx
    jmp .loop
.done:
    mov eax, ecx
    ret

section .data
align 4
context_switch_count: dd 0
; interrupt_count is defined in idt.asm

section .text

global get_context_switch_count
get_context_switch_count:
    mov eax, [context_switch_count]
    ret

global increment_context_switch_count
increment_context_switch_count:
    lock inc dword [context_switch_count]
    ret

; interrupt_count functions are defined in idt.asm

