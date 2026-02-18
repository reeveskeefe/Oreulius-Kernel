; System call entry point (INT 0x80)
; 32-bit x86 syscall convention:
;   EAX = syscall number
;   EBX = arg1
;   ECX = arg2
;   EDX = arg3
;   ESI = arg4
;   EDI = arg5
; Returns:
;   EAX = return value
;   EDX = errno

[BITS 32]

extern syscall_handler_rust
extern JIT_USER_RETURN_PENDING
extern JIT_USER_RETURN_EIP
extern JIT_USER_RETURN_ESP
extern JIT_USER_ACTIVE
extern JIT_USER_SYSCALL_VIOLATION
extern JIT_USER_DBG_SYSCALL_ESP
extern JIT_USER_DBG_SYSCALL_EIP
extern JIT_USER_DBG_SYSCALL_SEQ
extern JIT_USER_DBG_SYSCALL_PATH
extern JIT_USER_DBG_SYSCALL_FLAGS
extern JIT_USER_DBG_SYSCALL_NR
extern JIT_USER_DBG_SYSCALL_FROM_EIP
extern JIT_USER_DBG_SYSCALL_FROM_CS
extern KPTI_KERNEL_CR3
extern KPTI_USER_CR3

global syscall_entry
syscall_entry:
    ; Preserve user EAX (syscall number) across KPTI CR3 switching.
    push eax
    ; KPTI: switch to kernel page directory if coming from user mode
    mov eax, [KPTI_USER_CR3]
    test eax, eax
    je .kpti_enter_done
    mov eax, [KPTI_KERNEL_CR3]
    mov cr3, eax
.kpti_enter_done:
    pop eax
    mov edx, [esp]
    mov [JIT_USER_DBG_SYSCALL_FROM_EIP], edx
    mov edx, [esp + 4]
    mov [JIT_USER_DBG_SYSCALL_FROM_CS], edx

    ; While JIT user sandbox is active, only allow JIT return syscall.
    mov ecx, [JIT_USER_ACTIVE]
    test ecx, ecx
    je .full_dispatch
    cmp eax, 250
    je .jit_return
    ; Hardened fallback: if syscall originated from the JIT return trampoline
    ; site, accept it as a JIT return even when EAX was clobbered.
    mov edx, [JIT_USER_DBG_SYSCALL_FROM_EIP]
    cmp edx, 0x20000036
    je .jit_return_force
    cmp edx, 0x20000107
    je .jit_return_force
    jne .jit_violation
.jit_return:
    mov dword [JIT_USER_RETURN_PENDING], 1
    xor ecx, ecx
    xchg ecx, [JIT_USER_ACTIVE]
    mov edx, [JIT_USER_RETURN_ESP]
    mov ecx, [JIT_USER_RETURN_EIP]
    mov [JIT_USER_DBG_SYSCALL_ESP], edx
    mov [JIT_USER_DBG_SYSCALL_EIP], ecx
    mov [JIT_USER_DBG_SYSCALL_NR], eax
    mov dword [JIT_USER_DBG_SYSCALL_PATH], 1
    xor ebx, ebx
    test edx, edx
    jnz .jit_ret_esp_ok
    or ebx, 1
.jit_ret_esp_ok:
    test ecx, ecx
    jnz .jit_ret_eip_ok
    or ebx, 2
.jit_ret_eip_ok:
    test edx, 3
    jz .jit_ret_align_ok
    or ebx, 4
.jit_ret_align_ok:
    mov [JIT_USER_DBG_SYSCALL_FLAGS], ebx
    mov ebx, [JIT_USER_DBG_SYSCALL_SEQ]
    add ebx, 1
    mov [JIT_USER_DBG_SYSCALL_SEQ], ebx
    mov esp, edx
    jmp ecx

.jit_return_force:
    mov eax, 250
    jmp .jit_return

.jit_violation:
    mov dword [JIT_USER_SYSCALL_VIOLATION], 1
    mov dword [JIT_USER_RETURN_PENDING], 1
    xor ecx, ecx
    xchg ecx, [JIT_USER_ACTIVE]
    mov edx, [JIT_USER_RETURN_ESP]
    mov ecx, [JIT_USER_RETURN_EIP]
    mov [JIT_USER_DBG_SYSCALL_ESP], edx
    mov [JIT_USER_DBG_SYSCALL_EIP], ecx
    mov [JIT_USER_DBG_SYSCALL_NR], eax
    mov dword [JIT_USER_DBG_SYSCALL_PATH], 2
    xor ebx, ebx
    test edx, edx
    jnz .jit_violate_esp_ok
    or ebx, 1
.jit_violate_esp_ok:
    test ecx, ecx
    jnz .jit_violate_eip_ok
    or ebx, 2
.jit_violate_eip_ok:
    test edx, 3
    jz .jit_violate_align_ok
    or ebx, 4
.jit_violate_align_ok:
    mov [JIT_USER_DBG_SYSCALL_FLAGS], ebx
    mov ebx, [JIT_USER_DBG_SYSCALL_SEQ]
    add ebx, 1
    mov [JIT_USER_DBG_SYSCALL_SEQ], ebx
    mov esp, edx
    jmp ecx

.full_dispatch:
    ; Save all registers
    push ebp
    push edi
    push esi
    push edx
    push ecx
    push ebx
    push eax
    
    ; Get current ESP (points to saved registers)
    mov eax, esp
    
    ; Call Rust handler with pointer to saved registers
    push eax
    call syscall_handler_rust
    add esp, 4

    ; If JIT user-mode requested a kernel return, jump back to saved kernel frame.
    xor eax, eax
    xchg eax, [JIT_USER_RETURN_PENDING]
    test eax, eax
    je .normal_return
    xor eax, eax
    xchg eax, [JIT_USER_ACTIVE]
    mov edx, [JIT_USER_RETURN_ESP]
    mov eax, [JIT_USER_RETURN_EIP]
    mov [JIT_USER_DBG_SYSCALL_ESP], edx
    mov [JIT_USER_DBG_SYSCALL_EIP], eax
    mov dword [JIT_USER_DBG_SYSCALL_NR], 250
    mov dword [JIT_USER_DBG_SYSCALL_PATH], 3
    xor ebx, ebx
    test edx, edx
    jnz .jit_pending_esp_ok
    or ebx, 1
.jit_pending_esp_ok:
    test eax, eax
    jnz .jit_pending_eip_ok
    or ebx, 2
.jit_pending_eip_ok:
    test edx, 3
    jz .jit_pending_align_ok
    or ebx, 4
.jit_pending_align_ok:
    mov [JIT_USER_DBG_SYSCALL_FLAGS], ebx
    mov ebx, [JIT_USER_DBG_SYSCALL_SEQ]
    add ebx, 1
    mov [JIT_USER_DBG_SYSCALL_SEQ], ebx
    mov esp, edx
    jmp eax

.normal_return:
    ; EAX:EDX already carry syscall return (value/errno).
    ; Restore interrupted callee-saved state without clobbering EAX/EDX.
    add esp, 4      ; Drop saved EAX
    pop ebx         ; Restore EBX
    pop ecx         ; Restore ECX
    add esp, 4      ; Drop saved EDX (preserve return errno in EDX)
    pop esi         ; Restore ESI
    pop edi         ; Restore EDI
    pop ebp         ; Restore EBP

    ; KPTI: restore user page directory before returning to ring 3
    mov ebx, [KPTI_USER_CR3]
    test ebx, ebx
    je .kpti_exit_done
    mov cr3, ebx
.kpti_exit_done:

    iret

section .note.GNU-stack noalloc noexec nowrite progbits
