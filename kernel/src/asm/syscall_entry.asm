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
extern KPTI_KERNEL_CR3
extern KPTI_USER_CR3

global syscall_entry
syscall_entry:
    ; KPTI: switch to kernel page directory if coming from user mode
    mov eax, [KPTI_USER_CR3]
    test eax, eax
    je .kpti_enter_done
    mov eax, [KPTI_KERNEL_CR3]
    mov cr3, eax
.kpti_enter_done:
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
    mov esp, [JIT_USER_RETURN_ESP]
    mov eax, [JIT_USER_RETURN_EIP]
    jmp eax

.normal_return:
    
    ; EAX:EDX now contain result (EAX = value, EDX = errno)
    ; Save return values
    mov ebx, eax    ; Save value
    mov ecx, edx    ; Save errno
    
    ; Restore registers (except EAX/EDX which have return values)
    add esp, 4      ; Skip saved EAX
    pop ebx         ; Restore EBX (will be overwritten below)
    add esp, 16     ; Skip ECX, EDX, ESI, EDI
    pop ebp
    
    ; Put return values in correct registers
    mov eax, ebx    ; Return value
    mov edx, ecx    ; Errno

    ; KPTI: restore user page directory before returning to ring 3
    mov ebx, [KPTI_USER_CR3]
    test ebx, ebx
    je .kpti_exit_done
    mov cr3, ebx
.kpti_exit_done:

    iret

section .note.GNU-stack noalloc noexec nowrite progbits
