; SYSENTER/SYSEXIT fast syscall entry
[BITS 32]

extern sysenter_handler_rust
global sysenter_entry

sysenter_entry:
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
    
    sysexit
