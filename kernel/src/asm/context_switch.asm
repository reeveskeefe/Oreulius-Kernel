; kernel/asm/context_switch.asm
; Ultra-fast process context switching for Oreulia OS
; Optimized for i686 architecture

global asm_switch_context
global asm_save_context
global asm_load_context
global thread_start_trampoline
global _thread_start_trampoline
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

; Thread start trampoline
; Called when a new thread starts. The entry function pointer is on top of stack.
; FIX #5: Simplified - no alignment to avoid corrupting stack pointer
thread_start_trampoline:
_thread_start_trampoline:
    mov dword [asm_dbg_stage], 6
    ; DON'T enable interrupts here - let the task enable them when ready
    
    pop eax             ; Pop entry function pointer from stack
    mov dword [asm_dbg_stage], 7
    mov [asm_dbg_entry_popped], eax
    
    ; Don't align - just use current ESP to avoid moving to unmapped region
    call eax            ; Call the thread entry function
    
    ; If thread returns, halt
.halt:
    hlt
    jmp .halt

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
