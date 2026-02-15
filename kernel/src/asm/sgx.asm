; Intel SGX primitive wrappers (32-bit)
; C ABI:
;   u32 sgx_encls(u32 leaf, u32 rbx, u32 rcx, u32 rdx)
;   u32 sgx_enclu(u32 leaf, u32 rbx, u32 rcx, u32 rdx)

BITS 32

section .text

global sgx_encls
sgx_encls:
    push ebp
    mov ebp, esp
    push ebx

    mov eax, [ebp + 8]
    mov ebx, [ebp + 12]
    mov ecx, [ebp + 16]
    mov edx, [ebp + 20]

    ; ENCLS opcode
    db 0x0F, 0x01, 0xCF

    pop ebx
    pop ebp
    ret

global sgx_enclu
sgx_enclu:
    push ebp
    mov ebp, esp
    push ebx

    mov eax, [ebp + 8]
    mov ebx, [ebp + 12]
    mov ecx, [ebp + 16]
    mov edx, [ebp + 20]

    ; ENCLU opcode
    db 0x0F, 0x01, 0xD7

    pop ebx
    pop ebp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
