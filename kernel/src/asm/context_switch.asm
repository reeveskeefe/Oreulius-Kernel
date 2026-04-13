; kernel/asm/context_switch.asm
; Ultra-fast process context switching for Oreulius OS
; Optimized for i686 architecture

global asm_switch_context
global asm_save_context
global asm_load_context
global thread_start_trampoline
global _thread_start_trampoline
global kernel_user_entry_trampoline
global asm_dbg_ctx_ptr
global asm_dbg_eip_target
global asm_dbg_esp_loaded
global asm_dbg_entry_popped
global asm_dbg_stage
global asm_sw_old_ptr
global asm_sw_new_ptr
global asm_sw_saved_old_eip
global asm_sw_new_eip
global asm_sw_new_esp
global asm_sw_stage

section .text

; Fast context switch between two processes
; Arguments: (old_ctx: *mut Context, new_ctx: *const Context)
; Saves current context to old_ctx, loads from new_ctx
; Context layout (40 bytes):
;   +0:  EBX, +4:  ECX, +8:  EDX, +12: ESI
;   +16: EDI, +20: EBP, +24: ESP, +28: EIP, +32: EFLAGS, +36: CR3
asm_switch_context:
    ; Save old context
    mov eax, [esp + 4]  ; old_ctx pointer
    mov [asm_sw_old_ptr], eax
    mov dword [asm_sw_stage], 1
    test eax, eax
    jz .load_only
    
    ; Save general-purpose registers to old context
    mov [eax + 0], ebx
    mov [eax + 4], ecx
    mov [eax + 8], edx
    mov [eax + 12], esi
    mov [eax + 16], edi
    mov [eax + 20], ebp
    mov [eax + 24], esp
    
    ; Save return address as EIP
    mov ecx, [esp]
    mov [eax + 28], ecx
    mov [asm_sw_saved_old_eip], ecx
    
    ; Save EFLAGS
    pushfd
    pop ecx
    mov [eax + 32], ecx

.load_only:
    ; Load new context
    mov eax, [esp + 8]  ; new_ctx pointer
    mov [asm_sw_new_ptr], eax
    mov dword [asm_sw_stage], 2
    
    ; Load general-purpose registers
    mov ebx, [eax + 0]
    mov ecx, [eax + 4]
    mov edx, [eax + 8]
    mov esi, [eax + 12]
    mov edi, [eax + 16]
    mov ebp, [eax + 20]
    mov esp, [eax + 24]
    mov [asm_sw_new_esp], esp
    
    ; Load EFLAGS
    push dword [eax + 32]
    popfd
    
    ; Simulate ret: Increment ESP to skip the saved EIP slot, then jump to it
    add esp, 4
    mov edx, [eax + 28]
    mov [asm_sw_new_eip], edx
    mov dword [asm_sw_stage], 3
    jmp edx

; Save current context to memory
; Returns 0 (used to distinguish from context restoration)
asm_save_context:
    mov eax, [esp + 4]  ; ctx pointer
    
    ; Save all registers
    mov [eax + 0], ebx
    mov [eax + 4], ecx
    mov [eax + 8], edx
    mov [eax + 12], esi
    mov [eax + 16], edi
    mov [eax + 20], ebp
    mov [eax + 24], esp
    
    ; Save return address
    mov ecx, [esp]
    mov [eax + 28], ecx
    
    ; Save EFLAGS
    pushfd
    pop ecx
    mov [eax + 32], ecx
    
    xor eax, eax  ; Return 0
    ret

; Load context from memory (does not return)
; This function loads a saved processor context and jumps to it
asm_load_context:
    cli                 ; Disable interrupts during context switch
    mov edi, [esp + 4]  ; Get ctx pointer from stack into EDI
    mov dword [asm_dbg_stage], 1
    mov [asm_dbg_ctx_ptr], edi
    
    ; REMOVED: CR3 reload - all kernel tasks share same page directory
    ; Reloading CR3 with same value only flushes TLB, causing page table
    ; walk on next stack access which triggers triple fault
    ; mov eax, [edi + 36]
    ; mov cr3, eax
    
    ; Load the target EIP into EAX (we'll jump to it after loading other registers)
    ; EAX is safe to use because ProcessContext doesn't store EAX
    mov eax, [edi + 28]
    mov dword [asm_dbg_stage], 2
    mov [asm_dbg_eip_target], eax
    
    ; Load new stack pointer
    mov esp, [edi + 24]
    mov dword [asm_dbg_stage], 3
    mov [asm_dbg_esp_loaded], esp
    
    ; Load ALL general-purpose registers from context (except EAX)
    mov ebx, [edi + 0]
    mov ecx, [edi + 4]
    mov edx, [edi + 8]
    mov esi, [edi + 12]
    mov ebp, [edi + 20]
    
    ; Load EFLAGS (restore interrupt state)
    push dword [edi + 32]
    popfd
    mov dword [asm_dbg_stage], 4

    ; Load EDI last (we need it for addressing until now)
    push dword [edi + 16]
    pop edi
    
    ; EAX still has the target EIP - jump directly to it
    add esp, 4
    mov dword [asm_dbg_stage], 5
    jmp eax

; Thread start trampoline — i686 kernel thread launch point
;
; Jumped to (not called) by asm_load_context / asm_switch_context when a new
; thread is first dispatched by the slice scheduler.
;
; Stack state on arrival, constructed by add_kernel_thread +
; scheduler_platform::init_kernel_thread_context:
;
;   esp  →  [ entry_fn_ptr ]          ← consumed by `pop eax`
;            (stack grows DOWN into the allocation below)
;
; add_kernel_thread writes entry_fn_ptr at (stack_top - 4).
; init_kernel_thread_context stores ctx.esp = stack_top - 8.
; asm_load_context loads esp from ctx, then `add esp, 4` skips the synthetic
; dummy "saved-EIP" slot — so [esp] == entry_fn_ptr when we arrive here.
;
; SysV i686 ABI §3.2.2 stack-alignment invariant:
;   esp % 16 == 0  immediately before any `call` instruction.
; (`call` pushes a 4-byte return address, leaving the callee's first
;  instruction with esp ≡ 12 (mod 16), as every function prologue expects.)
;
; The scheduler guarantees stack_top is 16-byte aligned (`& !15usize`), so
; after `pop eax`, esp == stack_top which is already 0 mod 16.  The `and esp`
; below enforces this invariant defensively, independently of any future
; change to upstream stack-alignment guarantees, and always rounds DOWN
; (toward lower, already-mapped addresses — never above the allocation).
thread_start_trampoline:
_thread_start_trampoline:
    mov     dword [asm_dbg_stage], 6

    ; Consume the entry function pointer placed here by add_kernel_thread.
    pop     eax
    mov     [asm_dbg_entry_popped], eax     ; save before advancing stage
    mov     dword [asm_dbg_stage], 7

    ; Enforce 16-byte alignment before `call` (SysV ABI pre-call invariant).
    ; Rounds DOWN — stays within the allocated stack region.
    and     esp, 0xFFFFFFF0

    ; Call the thread entry point.  All kernel thread functions are declared
    ; `extern "C" fn() -> !` and must not return.
    call    eax

    ; -----------------------------------------------------------------------
    ; Defence-in-depth: thread entry function returned unexpectedly.
    ; Write a visible sentinel to asm_dbg_stage for post-mortem memory dumps,
    ; then halt permanently with interrupts disabled.
    ; -----------------------------------------------------------------------
    mov     dword [asm_dbg_stage], 0xFF
.halt:
    cli
    hlt
    jmp     .halt

; User-mode entry trampoline for 32-bit processes.
; Expected stack layout:
;   [esp+0] = user EIP
;   [esp+4] = user ESP
kernel_user_entry_trampoline:
    pop ebx                 ; user EIP
    pop edx                 ; user ESP

    cli
    mov ax, 0x23            ; user data selector (ring 3)
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    push dword 0x23         ; SS
    push edx                ; ESP
    pushfd
    pop ecx
    or ecx, 0x200           ; IF=1 in user mode
    push ecx
    push dword 0x1B         ; CS
    push ebx                ; EIP
    iretd

section .bss
align 4
asm_dbg_ctx_ptr: resd 1
asm_dbg_eip_target: resd 1
asm_dbg_esp_loaded: resd 1
asm_dbg_entry_popped: resd 1
asm_dbg_stage: resd 1
asm_sw_old_ptr: resd 1
asm_sw_new_ptr: resd 1
asm_sw_saved_old_eip: resd 1
asm_sw_new_eip: resd 1
asm_sw_new_esp: resd 1
asm_sw_stage: resd 1

section .note.GNU-stack noalloc noexec nowrite progbits
