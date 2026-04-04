; SYSENTER/SYSEXIT fast syscall entry
[BITS 32]

extern sysenter_handler_rust
extern KPTI_KERNEL_CR3
extern KPTI_USER_CR3
global sysenter_entry

sysenter_entry:
    ; KPTI: switch to kernel page directory if coming from user mode
    mov eax, [KPTI_USER_CR3]
    test eax, eax
    je .kpti_enter_done
    mov eax, [KPTI_KERNEL_CR3]
    mov cr3, eax
.kpti_enter_done:
    ; Save registers
    push ebp
    push edi
    push esi
    push edx                ; user EIP
    push ecx                ; user ESP
    push ebx
    push eax
    
    mov eax, esp
    push eax
    call sysenter_handler_rust
    add esp, 4
    
    ; Restore user return info for sysexit
    mov ecx, [esp + 8]      ; user ESP
    mov edx, [esp + 12]     ; user EIP
    
    add esp, 28             ; pop saved regs

    ; KPTI: restore user page directory before returning to ring 3
    mov eax, [KPTI_USER_CR3]
    test eax, eax
    je .kpti_exit_done
    mov cr3, eax
.kpti_exit_done:
    
    sysexit

section .note.GNU-stack noalloc noexec nowrite progbits
