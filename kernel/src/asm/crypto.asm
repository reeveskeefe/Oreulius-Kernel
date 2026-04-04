; kernel/asm/crypto.asm
; Fast hashing and cryptographic operations for capability security
; Optimized non-cryptographic hashes for capability verification

global asm_hash_fnv1a
global asm_hash_djb2
global asm_hash_sdbm
global asm_xor_cipher

section .text

; FNV-1a hash (Fowler-Noll-Vo hash function)
; Args: (data: *const u8, len: usize) -> u32
; Fast non-cryptographic hash, excellent distribution
; Used for capability ID generation and hash tables
asm_hash_fnv1a:
    push esi
    
    mov esi, [esp + 8]   ; data pointer
    mov ecx, [esp + 12]  ; length
    mov eax, 2166136261  ; FNV offset basis (32-bit)
    
.loop:
    cmp ecx, 0
    je .done
    
    ; XOR with byte, then multiply
    movzx edx, byte [esi]
    xor eax, edx
    
    ; Multiply by FNV prime (16777619 = 0x01000193)
    mov edx, 16777619
    imul eax, edx
    
    inc esi
    dec ecx
    jmp .loop
    
.done:
    pop esi
    ret

section .note.GNU-stack noalloc noexec nowrite progbits

; DJB2 hash (Dan Bernstein's algorithm)
; Args: (data: *const u8, len: usize) -> u32
; Simple and fast hash function
; Formula: hash = hash * 33 + c
asm_hash_djb2:
    push esi
    
    mov esi, [esp + 8]   ; data pointer
    mov ecx, [esp + 12]  ; length
    mov eax, 5381        ; Initial hash value
    
.loop:
    cmp ecx, 0
    je .done
    
    ; hash = (hash << 5) + hash + c
    ; Equivalent to: hash = hash * 33 + c
    shl eax, 5           ; hash << 5 (hash * 32)
    mov edx, eax
    shr edx, 5           ; Restore original hash
    add eax, edx         ; hash * 32 + hash = hash * 33
    
    movzx edx, byte [esi]
    add eax, edx         ; Add character
    
    inc esi
    dec ecx
    jmp .loop
    
.done:
    pop esi
    ret

; SDBM hash (used in SDBM database)
; Args: (data: *const u8, len: usize) -> u32
; Formula: hash = hash * 65599 + c
; Alternative fast hash with good distribution
asm_hash_sdbm:
    push esi
    
    mov esi, [esp + 8]   ; data pointer
    mov ecx, [esp + 12]  ; length
    xor eax, eax         ; hash = 0
    
.loop:
    cmp ecx, 0
    je .done
    
    ; hash = hash * 65599 + c
    ; 65599 = 65536 + 63 = (hash << 16) + (hash << 6) - hash
    mov edx, eax
    shl eax, 16          ; hash << 16
    mov ebx, edx
    shl ebx, 6           ; hash << 6
    add eax, ebx
    sub eax, edx         ; (hash << 16) + (hash << 6) - hash
    
    movzx edx, byte [esi]
    add eax, edx
    
    inc esi
    dec ecx
    jmp .loop
    
.done:
    pop esi
    ret

; Simple XOR cipher (for demonstration and obfuscation)
; Args: (data: *mut u8, len: usize, key: u8)
; Not cryptographically secure, but fast for basic obfuscation
; Can be used for simple data scrambling
asm_xor_cipher:
    push esi
    
    mov esi, [esp + 8]   ; data pointer (in-place operation)
    mov ecx, [esp + 12]  ; length
    mov dl, [esp + 16]   ; key byte
    
.loop:
    cmp ecx, 0
    je .done
    
    ; XOR byte with key
    xor byte [esi], dl
    
    inc esi
    dec ecx
    jmp .loop
    
.done:
    pop esi
    ret
