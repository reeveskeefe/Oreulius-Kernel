; kernel/asm/network.asm
; High-speed network packet processing
; Optimized for packet header parsing and byte order conversion

global asm_swap_endian_16
global asm_swap_endian_32
global asm_parse_ethernet_frame
global asm_parse_ipv4_header

section .text

; Swap 16-bit endianness (network byte order <-> host byte order)
; Args: (value: u16) -> u16
; Example: 0x1234 -> 0x3412
asm_swap_endian_16:
    mov ax, [esp + 4]
    xchg al, ah  ; Swap low and high bytes
    ret

; Swap 32-bit endianness (network byte order <-> host byte order)
; Args: (value: u32) -> u32
; Example: 0x12345678 -> 0x78563412
asm_swap_endian_32:
    mov eax, [esp + 4]
    bswap eax  ; Byte swap on 32-bit register
    ret

; Parse Ethernet frame header (14 bytes)
; Args: (packet: *const u8, dst_mac: *mut [u8; 6], src_mac: *mut [u8; 6], ethertype: *mut u16)
; Extracts: destination MAC (6 bytes), source MAC (6 bytes), EtherType (2 bytes)
asm_parse_ethernet_frame:
    push esi
    push edi
    push ebx
    
    mov esi, [esp + 16]  ; packet pointer
    
    ; Copy destination MAC (6 bytes at offset 0)
    mov edi, [esp + 20]  ; dst_mac buffer
    mov eax, [esi]       ; Load first 4 bytes
    mov [edi], eax
    mov ax, [esi + 4]    ; Load last 2 bytes
    mov [edi + 4], ax
    
    ; Copy source MAC (6 bytes at offset 6)
    mov edi, [esp + 24]  ; src_mac buffer
    mov eax, [esi + 6]   ; Load first 4 bytes
    mov [edi], eax
    mov ax, [esi + 10]   ; Load last 2 bytes
    mov [edi + 4], ax
    
    ; Copy EtherType (2 bytes at offset 12)
    mov edi, [esp + 28]  ; ethertype pointer
    movzx eax, word [esi + 12]
    mov [edi], ax
    
    pop ebx
    pop edi
    pop esi
    ret

; Parse IPv4 header fields (20 bytes minimum)
; Args: (ip_header: *const u8, version_ihl: *mut u8, total_length: *mut u16, 
;        protocol: *mut u8, src_ip: *mut u32, dst_ip: *mut u32)
; Extracts critical IPv4 header fields for fast packet processing
asm_parse_ipv4_header:
    push esi
    push edi
    
    mov esi, [esp + 12]  ; ip_header pointer
    
    ; Extract version and IHL (1 byte at offset 0)
    mov edi, [esp + 16]  ; version_ihl pointer
    mov al, [esi]
    mov [edi], al
    
    ; Extract total length (2 bytes at offset 2, network byte order)
    mov edi, [esp + 20]  ; total_length pointer
    movzx eax, word [esi + 2]
    mov [edi], ax
    
    ; Extract protocol (1 byte at offset 9)
    mov edi, [esp + 24]  ; protocol pointer
    mov al, [esi + 9]
    mov [edi], al
    
    ; Extract source IP (4 bytes at offset 12)
    mov edi, [esp + 28]  ; src_ip pointer
    mov eax, [esi + 12]
    mov [edi], eax
    
    ; Extract destination IP (4 bytes at offset 16)
    mov edi, [esp + 32]  ; dst_ip pointer
    mov eax, [esi + 16]
    mov [edi], eax
    
    pop edi
    pop esi
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
