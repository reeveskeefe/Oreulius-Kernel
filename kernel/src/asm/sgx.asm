; Intel SGX primitive wrappers (32-bit)
; C ABI:
;   u32 sgx_encls(u32 leaf, u32 rbx, u32 rcx, u32 rdx)
;   u32 sgx_enclu(u32 leaf, u32 rbx, u32 rcx, u32 rdx)

BITS 32

section .text

global sgx_encls
global sgx_cpuid_leaf12
global sgx_read_feature_ctrl
global sgx_write_sgxlepubkeyhash
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

; void sgx_cpuid_leaf12(u32 sub_leaf, u32* eax, u32* ebx, u32* ecx, u32* edx)
sgx_cpuid_leaf12:
    push ebp
    mov ebp, esp
    push ebx
    push esi

    mov ecx, [ebp + 8]
    mov eax, 0x12
    cpuid

    mov esi, [ebp + 12]
    test esi, esi
    jz .skip_out_eax
    mov [esi], eax
.skip_out_eax:
    mov esi, [ebp + 16]
    test esi, esi
    jz .skip_out_ebx
    mov [esi], ebx
.skip_out_ebx:
    mov esi, [ebp + 20]
    test esi, esi
    jz .skip_out_ecx
    mov [esi], ecx
.skip_out_ecx:
    mov esi, [ebp + 24]
    test esi, esi
    jz .skip_out_edx
    mov [esi], edx
.skip_out_edx:
    pop esi
    pop ebx
    pop ebp
    ret

; u64 sgx_read_feature_ctrl(void)
sgx_read_feature_ctrl:
    mov ecx, 0x3A
    rdmsr
    ret

; void sgx_write_sgxlepubkeyhash(u64 h0, u64 h1, u64 h2, u64 h3)
sgx_write_sgxlepubkeyhash:
    push ebp
    mov ebp, esp

    mov ecx, 0x8C
    mov eax, [ebp + 8]
    mov edx, [ebp + 12]
    wrmsr

    mov ecx, 0x8D
    mov eax, [ebp + 16]
    mov edx, [ebp + 20]
    wrmsr

    mov ecx, 0x8E
    mov eax, [ebp + 24]
    mov edx, [ebp + 28]
    wrmsr

    mov ecx, 0x8F
    mov eax, [ebp + 32]
    mov edx, [ebp + 36]
    wrmsr

    pop ebp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
