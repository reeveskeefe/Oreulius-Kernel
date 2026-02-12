; kernel/asm/context_switch.asm
; Ultra-fast process context switching for Oreulia OS
; Optimized for i686 architecture

global asm_switch_context
global asm_save_context
global asm_load_context
global thread_start_trampoline
global _thread_start_trampoline

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
    
    ; Save EFLAGS
    pushfd
    pop ecx
    or ecx, 0x200           ; Ensure IF stays enabled for saved context
    mov [eax + 32], ecx

.load_only:
    ; Load new context
    mov eax, [esp + 8]  ; new_ctx pointer
    
    ; Load general-purpose registers
    mov ebx, [eax + 0]
    mov ecx, [eax + 4]
    mov edx, [eax + 8]
    mov esi, [eax + 12]
    mov edi, [eax + 16]
    mov ebp, [eax + 20]
    mov esp, [eax + 24]
    
    ; Load EFLAGS
    push dword [eax + 32]
    popfd
    
    ; Simulate ret: Increment ESP to skip the saved EIP slot, then jump to it
    add esp, 4
    jmp [eax + 28]

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
    ; Debug: Print 'L'
    push eax
    push dx
    mov dx, 0x3F8
    mov al, 'L'
    out dx, al
    pop dx
    pop eax

    cli                 ; Disable interrupts during context switch
    mov edi, [esp + 4]  ; Get ctx pointer from stack into EDI
    
    ; REMOVED: CR3 reload - all kernel tasks share same page directory
    ; Reloading CR3 with same value only flushes TLB, causing page table
    ; walk on next stack access which triggers triple fault
    ; mov eax, [edi + 36]
    ; mov cr3, eax
    
    ; Load the target EIP into EAX (we'll jump to it after loading other registers)
    ; EAX is safe to use because ProcessContext doesn't store EAX
    mov eax, [edi + 28]
    
    ; Load new stack pointer
    mov esp, [edi + 24]
    
    ; Load ALL general-purpose registers from context (except EAX)
    mov ebx, [edi + 0]
    mov ecx, [edi + 4]
    mov edx, [edi + 8]
    mov esi, [edi + 12]
    mov ebp, [edi + 20]
    
    ; Load EFLAGS (restore interrupt state)
    push dword [edi + 32]
    popfd

    ; Load EDI last (we need it for addressing until now)
    push dword [edi + 16]
    pop edi
    
    ; EAX still has the target EIP - jump directly to it
    add esp, 4
    jmp eax

; Thread start trampoline
; Called when a new thread starts. The entry function pointer is on top of stack.
; FIX #5: Simplified - no alignment to avoid corrupting stack pointer
thread_start_trampoline:
_thread_start_trampoline:
    ; Debug: Print 'T' to serial to confirm trampoline entry
    push dx
    push eax
    mov dx, 0x3F8
    mov al, 'T'
    out dx, al
    pop eax
    pop dx

    ; DON'T enable interrupts here - let the task enable them when ready
    
    pop eax             ; Pop entry function pointer from stack
    
    ; Don't align - just use current ESP to avoid moving to unmapped region
    call eax            ; Call the thread entry function
    
    ; If thread returns, halt
.halt:
    hlt
    jmp .halt
