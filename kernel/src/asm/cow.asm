; Copy-on-Write (COW) Assembly Implementation
; Provides low-level page fault handling and page copying primitives
;
; x86 32-bit architecture
; Called from Rust paging module

[BITS 32]

section .text

; ============================================================================
; Page Fault Handler
; ============================================================================

global page_fault_handler
extern rust_page_fault_handler

; Page fault interrupt handler (INT 14)
; Error code is pushed by CPU automatically
page_fault_handler:
    ; Save all registers
    pushad                  ; Push EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI
    
    ; Get CR2 (faulting address)
    mov eax, cr2
    push eax                ; Push faulting address
    
    ; Get error code (already on stack above return address)
    mov eax, [esp + 36]     ; Error code at ESP + 32 (pushad) + 4 (CR2)
    push eax                ; Push error code
    
    ; Call Rust handler
    ; rust_page_fault_handler(error_code: u32, fault_addr: usize)
    call rust_page_fault_handler
    add esp, 8              ; Clean up arguments
    
    ; Restore registers
    popad
    
    ; Remove error code from stack
    add esp, 4
    
    ; Return from interrupt
    iret

; ============================================================================
; Physical Page Copy
; ============================================================================

global copy_page_physical
; void copy_page_physical(u32 src_phys, u32 dst_phys)
; Copies 4096 bytes from src to dst physical addresses.
;
; Strategy: uses a static 4-KB scratch page table (cow_scratch_pt, in .bss,
; identity-mapped so virt == phys) installed into PDE[1023] of the active
; page directory.  Two PTE slots in that table are used as temporary windows:
;
;   PTE[1022] → src_phys   (virtual 0xFFFFE000)
;   PTE[1023] → dst_phys   (virtual 0xFFFFF000)
;
; PDE[1023] covers virtual 0xFFC00000–0xFFFFFFFF which is reserved / unmapped
; by the kernel layout, so there are no conflicts.
;
; The kernel is loaded at physical 0x100000 with identity paging, therefore
; CR3 (physical PD base) equals its virtual address, and cow_scratch_pt's
; symbol value is also its physical address.
copy_page_physical:
    push ebp
    mov  ebp, esp
    push esi
    push edi
    push ecx
    push eax
    push ebx
    push edx

    mov  eax, [ebp + 8]          ; eax = src_phys (page-aligned)
    mov  ebx, [ebp + 12]         ; ebx = dst_phys (page-aligned)

    ; --- 1. Get page directory base (phys == virt, identity mapped) ---
    mov  edx, cr3                ; edx = physical/virtual PD base

    ; --- 2. Ensure PDE[1023] points to cow_scratch_pt ---
    ; PDE[1023] byte offset in PD = 1023 * 4 = 4092
    mov  ecx, [edx + 4092]       ; read PDE[1023]
    test ecx, 0x1                ; P (present) bit set?
    jnz  .pt_installed

    ; First-time setup: install cow_scratch_pt into PDE[1023].
    ; Save registers clobbered by the zeroing rep stosd below.
    push eax
    push edi

    mov  ecx, cow_scratch_pt     ; symbol value = physical address (identity mapped)
    and  ecx, 0xFFFFF000         ; page-align (should already be due to align 4096)
    or   ecx, 0x3                ; P | W
    mov  [edx + 4092], ecx       ; PDE[1023] = (phys_of_scratch_pt | P | W)

    ; Zero the scratch page table (defensive; .bss is zeroed at boot but
    ; be explicit in case copy_page_physical is called unusually early).
    mov  edi, cow_scratch_pt     ; virtual addr of scratch PT
    xor  eax, eax
    mov  ecx, 1024               ; 1024 dwords = 4096 bytes
    cld
    rep  stosd

    pop  edi
    pop  eax                     ; restore eax = src_phys

.pt_installed:
    ; --- 3. Map src_phys → virt 0xFFFFE000 via PTE[1022] ---
    ; PTE[1022] byte offset in PT = 1022 * 4 = 4088
    mov  ecx, eax                ; src_phys
    and  ecx, 0xFFFFF000
    or   ecx, 0x3                ; P | W
    mov  [cow_scratch_pt + 4088], ecx

    ; --- 4. Map dst_phys → virt 0xFFFFF000 via PTE[1023] ---
    ; PTE[1023] byte offset in PT = 1023 * 4 = 4092
    mov  ecx, ebx                ; dst_phys
    and  ecx, 0xFFFFF000
    or   ecx, 0x3                ; P | W
    mov  [cow_scratch_pt + 4092], ecx

    ; --- 5. Flush TLB for both virtual windows ---
    mov  eax, 0xFFFFE000
    invlpg [eax]
    mov  eax, 0xFFFFF000
    invlpg [eax]

    ; --- 6. Copy 4096 bytes through the virtual windows ---
    mov  esi, 0xFFFFE000
    mov  edi, 0xFFFFF000
    mov  ecx, 1024               ; 1024 dwords = 4096 bytes
    cld
    rep  movsd

    ; --- 7. Tear down: zero PTEs and flush TLB ---
    mov  dword [cow_scratch_pt + 4088], 0
    mov  dword [cow_scratch_pt + 4092], 0
    mov  eax, 0xFFFFE000
    invlpg [eax]
    mov  eax, 0xFFFFF000
    invlpg [eax]

    pop  edx
    pop  ebx
    pop  eax
    pop  ecx
    pop  edi
    pop  esi
    pop  ebp
    ret

; ============================================================================
; Fast Page Copy (using SSE if available)
; ============================================================================

global copy_page_fast
; void copy_page_fast(void* src, void* dst)
; Fast copy using largest available instructions
copy_page_fast:
    push ebp
    mov ebp, esp
    push esi
    push edi
    push ecx
    
    mov esi, [ebp + 8]      ; src
    mov edi, [ebp + 12]     ; dst
    
    ; Check if SSE is available (bit 25 of EDX after CPUID)
    push eax
    push ebx
    push edx
    mov eax, 1
    cpuid
    test edx, 0x02000000    ; SSE bit
    pop edx
    pop ebx
    pop eax
    jz .no_sse
    
.use_sse:
    ; Copy using movaps (16 bytes at a time)
    ; 4096 / 16 = 256 iterations
    mov ecx, 256
.sse_loop:
    movaps xmm0, [esi]
    movaps [edi], xmm0
    add esi, 16
    add edi, 16
    loop .sse_loop
    jmp .done
    
.no_sse:
    ; Fallback to regular DWORD copy
    mov ecx, 1024           ; 4096 / 4
    cld
    rep movsd
    
.done:
    pop ecx
    pop edi
    pop esi
    pop ebp
    ret

; ============================================================================
; Zero Page (for new allocations)
; ============================================================================

global zero_page
; void zero_page(void* addr)
; Zeros out 4096 bytes at given address
zero_page:
    push ebp
    mov ebp, esp
    push edi
    push ecx
    push eax
    
    mov edi, [ebp + 8]      ; addr
    xor eax, eax            ; Zero
    mov ecx, 1024           ; 4096 / 4
    cld
    rep stosd               ; Store EAX to ES:EDI, ECX times
    
    pop eax
    pop ecx
    pop edi
    pop ebp
    ret

; ============================================================================
; Zero Page Fast (using SSE)
; ============================================================================

global zero_page_fast
; void zero_page_fast(void* addr)
; Fast zero using SSE if available
zero_page_fast:
    push ebp
    mov ebp, esp
    push edi
    push ecx
    
    mov edi, [ebp + 8]      ; addr
    
    ; Check SSE availability
    push eax
    push ebx
    push edx
    mov eax, 1
    cpuid
    test edx, 0x02000000
    pop edx
    pop ebx
    pop eax
    jz .no_sse
    
.use_sse:
    ; Zero XMM register
    pxor xmm0, xmm0
    
    ; Write 16 bytes at a time (256 iterations)
    mov ecx, 256
.sse_loop:
    movaps [edi], xmm0
    add edi, 16
    loop .sse_loop
    jmp .done
    
.no_sse:
    ; Fallback
    push eax
    xor eax, eax
    mov ecx, 1024
    cld
    rep stosd
    pop eax
    
.done:
    pop ecx
    pop edi
    pop ebp
    ret

; ============================================================================
; TLB Flush Operations
; ============================================================================

global flush_tlb_single
; void flush_tlb_single(u32 virt_addr)
; Flushes single TLB entry
flush_tlb_single:
    mov eax, [esp + 4]      ; virt_addr
    invlpg [eax]            ; Invalidate page
    ret

global flush_tlb_all
; void flush_tlb_all(void)
; Flushes entire TLB by reloading CR3
flush_tlb_all:
    mov eax, cr3
    mov cr3, eax            ; Reload CR3 flushes TLB
    ret

; ============================================================================
; CR3 Operations (Page Directory Base)
; ============================================================================

global load_page_directory
; void load_page_directory(u32 phys_addr)
; Loads page directory physical address into CR3
load_page_directory:
    push ebp
    mov ebp, esp
    push eax
    
    mov eax, [ebp + 8]      ; phys_addr
    mov cr3, eax            ; Load CR3
    
    pop eax
    pop ebp
    ret

global get_page_directory
; u32 get_page_directory(void)
; Returns current CR3 value
get_page_directory:
    mov eax, cr3
    ret

; ============================================================================
; Paging Enable/Disable
; ============================================================================

global enable_paging
; void enable_paging(void)
; Sets CR0.PG bit to enable paging
enable_paging:
    push eax
    mov eax, cr0
    or eax, 0x80000000      ; Set PG bit (bit 31)
    mov cr0, eax
    pop eax
    ret

global disable_paging
; void disable_paging(void)
; Clears CR0.PG bit to disable paging
disable_paging:
    push eax
    mov eax, cr0
    and eax, 0x7FFFFFFF     ; Clear PG bit
    mov cr0, eax
    pop eax
    ret

global is_paging_enabled
; u32 is_paging_enabled(void)
; Returns 1 if paging enabled, 0 otherwise
is_paging_enabled:
    mov eax, cr0
    shr eax, 31             ; Get bit 31 into bit 0
    and eax, 1
    ret

; ============================================================================
; Page Table Entry Manipulation
; ============================================================================

global set_page_flags
; void set_page_flags(u32* pte_addr, u32 flags)
; Sets flags in page table entry
set_page_flags:
    push ebp
    mov ebp, esp
    push eax
    push ebx
    
    mov eax, [ebp + 8]      ; pte_addr
    mov ebx, [ebp + 12]     ; flags
    
    ; Read current PTE
    mov ecx, [eax]
    
    ; Clear flag bits (keep address)
    and ecx, 0xFFFFF000
    
    ; Set new flags
    or ecx, ebx
    
    ; Write back
    mov [eax], ecx
    
    ; Flush TLB for this page
    ; (caller should know virtual address for invlpg)
    
    pop ebx
    pop eax
    pop ebp
    ret

global clear_page_flags
; void clear_page_flags(u32* pte_addr, u32 flags)
; Clears specified flags in page table entry
clear_page_flags:
    push ebp
    mov ebp, esp
    push eax
    push ebx
    
    mov eax, [ebp + 8]      ; pte_addr
    mov ebx, [ebp + 12]     ; flags to clear
    
    ; Read current PTE
    mov ecx, [eax]
    
    ; Clear specified flags
    not ebx
    and ecx, ebx
    
    ; Write back
    mov [eax], ecx
    
    pop ebx
    pop eax
    pop ebp
    ret

; ============================================================================
; COW-Specific Operations
; ============================================================================

global mark_page_cow
; void mark_page_cow(u32* pte_addr)
; Marks page as copy-on-write (sets COW bit, clears writable bit)
mark_page_cow:
    push ebp
    mov ebp, esp
    push eax
    push ebx
    
    mov eax, [ebp + 8]      ; pte_addr
    mov ebx, [eax]          ; Read PTE
    
    ; Clear writable bit (bit 1)
    and ebx, 0xFFFFFFFD
    
    ; Set COW bit (bit 9 - available for OS use)
    or ebx, 0x00000200
    
    ; Write back
    mov [eax], ebx
    
    pop ebx
    pop eax
    pop ebp
    ret

global is_page_cow
; u32 is_page_cow(u32 pte_value)
; Returns 1 if page has COW flag set, 0 otherwise
is_page_cow:
    mov eax, [esp + 4]      ; pte_value
    shr eax, 9              ; Shift COW bit to bit 0
    and eax, 1
    ret

global clear_page_cow
; void clear_page_cow(u32* pte_addr)
; Clears COW flag and sets writable bit
clear_page_cow:
    push ebp
    mov ebp, esp
    push eax
    push ebx
    
    mov eax, [ebp + 8]      ; pte_addr
    mov ebx, [eax]          ; Read PTE
    
    ; Clear COW bit (bit 9)
    and ebx, 0xFFFFFDFF
    
    ; Set writable bit (bit 1)
    or ebx, 0x00000002
    
    ; Write back
    mov [eax], ebx
    
    pop ebx
    pop eax
    pop ebp
    ret

; ============================================================================
; Atomic Page Operations (for SMP safety)
; ============================================================================

global atomic_set_page_flags
; void atomic_set_page_flags(u32* pte_addr, u32 flags)
; Atomically sets flags using LOCK OR
atomic_set_page_flags:
    push ebp
    mov ebp, esp
    push eax
    push ebx
    
    mov eax, [ebp + 8]      ; pte_addr
    mov ebx, [ebp + 12]     ; flags
    
    ; Atomic OR operation
    lock or [eax], ebx
    
    pop ebx
    pop eax
    pop ebp
    ret

global atomic_clear_page_flags
; void atomic_clear_page_flags(u32* pte_addr, u32 flags)
; Atomically clears flags using LOCK AND
atomic_clear_page_flags:
    push ebp
    mov ebp, esp
    push eax
    push ebx
    
    mov eax, [ebp + 8]      ; pte_addr
    mov ebx, [ebp + 12]     ; flags to clear
    not ebx                 ; Invert for AND operation
    
    ; Atomic AND operation
    lock and [eax], ebx
    
    pop ebx
    pop eax
    pop ebp
    ret

; ============================================================================
; Reference Counting Support (for shared pages)
; ============================================================================

global atomic_inc_refcount
; u32 atomic_inc_refcount(u32* refcount_addr)
; Atomically increments reference count, returns new value
atomic_inc_refcount:
    mov eax, [esp + 4]      ; refcount_addr
    mov ecx, 1
    lock xadd [eax], ecx    ; Atomic exchange and add
    inc ecx                 ; ECX now has old value, increment for new
    mov eax, ecx
    ret

global atomic_dec_refcount
; u32 atomic_dec_refcount(u32* refcount_addr)
; Atomically decrements reference count, returns new value
atomic_dec_refcount:
    mov eax, [esp + 4]      ; refcount_addr
    mov ecx, -1
    lock xadd [eax], ecx    ; Atomic exchange and add
    dec ecx                 ; ECX now has old value, decrement for new
    mov eax, ecx
    ret

; ============================================================================
; Memory Barrier Operations
; ============================================================================

global memory_barrier
; void memory_barrier(void)
; Full memory barrier
memory_barrier:
    mfence                  ; Memory fence (SSE2+)
    ret

global load_barrier
; void load_barrier(void)
; Load fence
load_barrier:
    lfence
    ret

global store_barrier
; void store_barrier(void)
; Store fence
store_barrier:
    sfence
    ret

section .data
; Statistics and debugging
align 4
page_fault_count: dd 0
cow_fault_count: dd 0
page_copy_count: dd 0

section .text

global get_page_fault_count
get_page_fault_count:
    mov eax, [page_fault_count]
    ret

global get_cow_fault_count
get_cow_fault_count:
    mov eax, [cow_fault_count]
    ret

global get_page_copy_count
get_page_copy_count:
    mov eax, [page_copy_count]
    ret

global increment_page_fault_count
increment_page_fault_count:
    lock inc dword [page_fault_count]
    ret

global increment_cow_fault_count
increment_cow_fault_count:
    lock inc dword [cow_fault_count]
    ret

global increment_page_copy_count
increment_page_copy_count:
    lock inc dword [page_copy_count]
    ret

; ============================================================================
; Process Fork Implementation (COW-enabled)
; ============================================================================

global asm_fork_process
extern rust_create_process
extern rust_copy_page_table

; int asm_fork_process(u32 parent_pid, u32 flags)
; Returns: child PID on success (> 0), -1 on failure
; Flags: bit 0 = share memory, bit 1 = share file descriptors
asm_fork_process:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    
    mov ebx, [ebp + 8]      ; parent_pid
    mov ecx, [ebp + 12]     ; flags
    
    ; 1. Call rust_create_process(parent_pid, flags)
    push ecx                ; flags
    push ebx                ; parent_pid argument
    call rust_create_process
    add esp, 8              ; Cleanup args
    
    cmp eax, -1             ; Check error. Note: rust_create_process returns u32::MAX on error which is -1
    je .error
    
    mov esi, eax            ; Save child_pid in ESI
    
    ; 2. Copy parent's page table with COW flag
    ; rust_copy_page_table(parent_pid, child_pid)
    push esi                ; child_pid
    push ebx                ; parent_pid
    call rust_copy_page_table
    add esp, 8
    
    test eax, eax
    jnz .error              ; If not 0 (success), error
    
    ; 3. Mark all writable pages as read-only... (handled by rust_copy_page_table)
    ; 4. Set up COW page fault handler... (handled by initialization)
    
    ; 5. Return child PID
    mov eax, esi
    jmp .exit

.error:
    mov eax, -1

.exit:
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

; ============================================================================
; BSS: Scratch page table for copy_page_physical temporary mappings
; ============================================================================
;
; cow_scratch_pt is installed into PDE[1023] of the active page directory on
; the first call to copy_page_physical.  Because the kernel is loaded at
; physical 0x100000 with identity paging, the symbol value is simultaneously
; the virtual address and the physical address of this page table.
;
; Virtual range served by PDE[1023]: 0xFFC00000-0xFFFFFFFF (4 MB window).
; Temporary slots used:
;   PTE[1022] -> src window at virt 0xFFFFE000
;   PTE[1023] -> dst window at virt 0xFFFFF000

section .bss
align 4096
cow_scratch_pt: resb 4096
