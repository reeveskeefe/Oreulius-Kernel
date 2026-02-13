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

global syscall_entry
syscall_entry:
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
    cmp dword [JIT_USER_RETURN_PENDING], 0
    je .normal_return
    mov dword [JIT_USER_RETURN_PENDING], 0
    mov dword [JIT_USER_ACTIVE], 0
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
    
    iret
