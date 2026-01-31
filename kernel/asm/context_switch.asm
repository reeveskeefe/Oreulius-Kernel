; kernel/asm/context_switch.asm
; Ultra-fast process context switching for Oreulia OS
; Optimized for i686 architecture

global asm_switch_context
global asm_save_context
global asm_load_context

section .text

; Fast context switch between two processes
; Arguments: (old_ctx: *mut Context, new_ctx: *const Context)
; Saves current context to old_ctx, loads from new_ctx
; Context layout (36 bytes):
;   +0:  EBX, +4:  ECX, +8:  EDX, +12: ESI
;   +16: EDI, +20: EBP, +24: ESP, +28: EIP, +32: EFLAGS
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
    
    ; Jump to saved EIP (process resumes execution)
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
asm_load_context:
    mov eax, [esp + 4]  ; ctx pointer
    
    ; Load all registers
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
    
    ; Jump to saved EIP (never returns)
    jmp [eax + 28]
