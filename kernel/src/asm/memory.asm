; kernel/asm/memory.asm
; Optimized memory operations for Oreulia OS
; Uses rep string instructions for maximum performance

global asm_fast_memcpy
global asm_fast_memset
global asm_fast_memcmp
global asm_checksum_ip
global asm_checksum_tcp

section .text

; Ultra-fast memcpy using rep movsd (4-byte chunks) + rep movsb (remainder)
; Args: (dest: *mut u8, src: *const u8, count: usize)
; Up to 5x faster than byte-by-byte copy
asm_fast_memcpy:
    push edi
    push esi
    
    mov edi, [esp + 12]  ; dest
    mov esi, [esp + 16]  ; src
    mov ecx, [esp + 20]  ; count
    
    ; Copy in 32-bit chunks (4 bytes at a time)
    mov edx, ecx
    shr ecx, 2
    rep movsd
    
    ; Copy remaining bytes (0-3 bytes)
    mov ecx, edx
    and ecx, 3
    rep movsb
    
    pop esi
    pop edi
    ret

; Fast memset using rep stosd (4-byte chunks) + rep stosb (remainder)
; Args: (dest: *mut u8, value: u8, count: usize)
; Up to 4x faster than byte-by-byte fill
asm_fast_memset:
    push edi
    
    mov edi, [esp + 8]   ; dest
    mov eax, [esp + 12]  ; value (byte)
    mov ecx, [esp + 16]  ; count
    
    ; Replicate byte to all 4 bytes of eax
    ; Example: 0x42 -> 0x42424242
    mov ah, al
    mov edx, eax
    shl eax, 16
    mov ax, dx
    
    ; Fill in 32-bit chunks
    mov edx, ecx
    shr ecx, 2
    rep stosd
    
    ; Fill remaining bytes (0-3 bytes)
    mov ecx, edx
    and ecx, 3
    rep stosb
    
    pop edi
    ret

; Fast memcmp using rep cmpsd (4-byte chunks) + rep cmpsb (remainder)
; Args: (ptr1: *const u8, ptr2: *const u8, count: usize) -> i32
; Returns 0 if equal, 1 if not equal
asm_fast_memcmp:
    push esi
    push edi
    
    mov esi, [esp + 12]  ; ptr1
    mov edi, [esp + 16]  ; ptr2
    mov ecx, [esp + 20]  ; count
    
    ; Compare in 32-bit chunks
    mov edx, ecx
    shr ecx, 2
    repe cmpsd
    jne .not_equal
    
    ; Compare remaining bytes (0-3 bytes)
    mov ecx, edx
    and ecx, 3
    repe cmpsb
    jne .not_equal
    
    xor eax, eax  ; Equal, return 0
    pop edi
    pop esi
    ret

.not_equal:
    mov eax, 1    ; Not equal, return 1
    pop edi
    pop esi
    ret

; IPv4 header checksum calculation (RFC 1071)
; Args: (header: *const u8, len: usize) -> u16
; Used for IP packet verification - critical for network performance
asm_checksum_ip:
    push esi
    
    mov esi, [esp + 8]   ; header pointer
    mov ecx, [esp + 12]  ; length in bytes
    xor eax, eax         ; sum = 0
    xor edx, edx
    
.loop:
    cmp ecx, 0
    je .done
    
    ; Load 16-bit word (network byte order)
    movzx edx, word [esi]
    add eax, edx
    
    ; Handle carry (one's complement addition)
    jnc .no_carry
    inc eax
.no_carry:
    
    add esi, 2
    sub ecx, 2
    jmp .loop
    
.done:
    ; Fold 32-bit sum to 16-bit
    mov edx, eax
    shr edx, 16
    and eax, 0xFFFF
    add eax, edx
    
    ; Another fold if carry occurred
    mov edx, eax
    shr edx, 16
    add eax, edx
    and eax, 0xFFFF
    
    ; One's complement (invert bits)
    not ax
    
    pop esi
    ret

; TCP/UDP checksum calculation including pseudo-header (RFC 793, RFC 768)
; Args: (data: *const u8, len: usize, src_ip: u32, dst_ip: u32, proto: u8) -> u16
; Pseudo-header ensures packets are delivered to correct destination
; Critical for TCP/UDP packet validation
asm_checksum_tcp:
    push ebx
    push esi
    
    mov esi, [esp + 12]  ; data pointer
    mov ecx, [esp + 16]  ; length
    xor eax, eax         ; sum = 0
    
    ; Add pseudo-header: source IP (32-bit)
    mov ebx, [esp + 20]  ; src_ip
    add eax, ebx
    jnc .no_carry1
    inc eax
.no_carry1:
    
    shr ebx, 16
    add eax, ebx
    jnc .no_carry2
    inc eax
.no_carry2:
    
    ; Add pseudo-header: destination IP (32-bit)
    mov ebx, [esp + 24]  ; dst_ip
    add eax, ebx
    jnc .no_carry3
    inc eax
.no_carry3:
    
    shr ebx, 16
    add eax, ebx
    jnc .no_carry4
    inc eax
.no_carry4:
    
    ; Add pseudo-header: protocol (8-bit) + length (16-bit)
    movzx ebx, byte [esp + 28]  ; protocol
    add eax, ebx
    add eax, ecx  ; length
    
    ; Process data payload in 16-bit words
.data_loop:
    cmp ecx, 1
    jle .last_byte
    
    ; Load 16-bit word
    movzx ebx, word [esi]
    add eax, ebx
    jnc .no_carry5
    inc eax
.no_carry5:
    
    add esi, 2
    sub ecx, 2
    jmp .data_loop
    
.last_byte:
    ; Handle odd byte (pad with zero on right)
    cmp ecx, 0
    je .fold
    
    movzx ebx, byte [esi]
    shl ebx, 8  ; Put byte in high order
    add eax, ebx
    
.fold:
    ; Fold 32-bit sum to 16-bit
    mov ebx, eax
    shr ebx, 16
    and eax, 0xFFFF
    add eax, ebx
    
    ; Another fold if needed
    mov ebx, eax
    shr ebx, 16
    add eax, ebx
    and eax, 0xFFFF
    
    ; One's complement
    not ax
    
    pop esi
    pop ebx
    ret
