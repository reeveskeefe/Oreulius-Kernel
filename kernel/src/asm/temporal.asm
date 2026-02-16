; Temporal Objects Assembly Primitives
; Hashing, Merkle reduction, and byte movement helpers for versioned kernel state.

[BITS 32]

section .text

global temporal_fnv1a32
global temporal_hash_pair
global temporal_merkle_root_u32
global temporal_copy_bytes
global temporal_zero_bytes

; u32 temporal_fnv1a32(const u8* data, u32 len, u32 seed)
temporal_fnv1a32:
    push ebx
    push esi

    mov esi, [esp + 12]
    mov ecx, [esp + 16]
    mov eax, [esp + 20]

    test ecx, ecx
    jz .done

.loop:
    movzx ebx, byte [esi]
    xor eax, ebx
    imul eax, eax, 16777619
    inc esi
    dec ecx
    jnz .loop

.done:
    pop esi
    pop ebx
    ret

; u32 temporal_hash_pair(u32 left, u32 right)
temporal_hash_pair:
    push ebx

    mov eax, [esp + 8]
    mov ebx, [esp + 12]

    xor eax, 0x9E3779B9
    rol eax, 5
    add eax, ebx
    xor eax, 0x85EBCA6B
    imul eax, eax, 0xC2B2AE35

    pop ebx
    ret

; u32 temporal_merkle_root_u32(u32* words, u32 count)
; In-place pairwise reduction. For odd levels, the last node is duplicated.
temporal_merkle_root_u32:
    push ebx
    push esi
    push edi
    push ebp

    mov esi, [esp + 20]
    mov ecx, [esp + 24]

    test esi, esi
    jz .zero
    test ecx, ecx
    jz .zero
    cmp ecx, 1
    je .single

.outer:
    xor edi, edi                ; dst index
    xor ebx, ebx                ; src index

.inner:
    mov eax, [esi + ebx * 4]    ; left

    lea ebp, [ebx + 1]
    cmp ebp, ecx
    jb .have_right
    mov edx, eax
    jmp .mix

.have_right:
    mov edx, [esi + ebp * 4]    ; right

.mix:
    xor eax, 0x9E3779B9
    rol eax, 5
    add eax, edx
    xor eax, 0x85EBCA6B
    imul eax, eax, 0xC2B2AE35

    mov [esi + edi * 4], eax

    add edi, 1
    add ebx, 2
    cmp ebx, ecx
    jb .inner

    mov ecx, edi
    cmp ecx, 1
    ja .outer

.single:
    mov eax, [esi]
    jmp .done

.zero:
    xor eax, eax

.done:
    pop ebp
    pop edi
    pop esi
    pop ebx
    ret

; void temporal_copy_bytes(u8* dst, const u8* src, u32 len)
temporal_copy_bytes:
    push edi
    push esi
    push ecx

    mov edi, [esp + 16]
    mov esi, [esp + 20]
    mov ecx, [esp + 24]

    cld
    rep movsb

    pop ecx
    pop esi
    pop edi
    ret

; void temporal_zero_bytes(u8* dst, u32 len)
temporal_zero_bytes:
    push edi
    push ecx

    mov edi, [esp + 12]
    mov ecx, [esp + 16]
    xor eax, eax

    cld
    rep stosb

    pop ecx
    pop edi
    ret
