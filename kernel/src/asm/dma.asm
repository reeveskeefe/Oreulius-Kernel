; Direct Memory Access (DMA) Controller Assembly
; High-speed I/O transfers bypassing CPU
; x86 32-bit architecture - 8237 DMA Controller

[BITS 32]

section .text

; ============================================================================
; DMA Channel Management
; ============================================================================

global dma_init_channel
global dma_start_transfer
global dma_stop_transfer
global dma_is_complete
global dma_get_remaining_count

; DMA Controller Ports
; Master DMA (channels 0-3)
DMA_CHAN0_ADDR      equ 0x00
DMA_CHAN0_COUNT     equ 0x01
DMA_CHAN1_ADDR      equ 0x02
DMA_CHAN1_COUNT     equ 0x03
DMA_CHAN2_ADDR      equ 0x04
DMA_CHAN2_COUNT     equ 0x05
DMA_CHAN3_ADDR      equ 0x06
DMA_CHAN3_COUNT     equ 0x07
DMA_STATUS_CMD      equ 0x08
DMA_REQUEST         equ 0x09
DMA_SINGLE_MASK     equ 0x0A
DMA_MODE            equ 0x0B
DMA_FLIP_FLOP       equ 0x0C
DMA_TEMP            equ 0x0D
DMA_MASTER_CLEAR    equ 0x0D
DMA_CLEAR_MASK      equ 0x0E
DMA_MULTI_MASK      equ 0x0F

; Slave DMA (channels 4-7)
DMA_CHAN4_ADDR      equ 0xC0
DMA_CHAN4_COUNT     equ 0xC2
DMA_CHAN5_ADDR      equ 0xC4
DMA_CHAN5_COUNT     equ 0xC6
DMA_CHAN6_ADDR      equ 0xC8
DMA_CHAN6_COUNT     equ 0xCA
DMA_CHAN7_ADDR      equ 0xCC
DMA_CHAN7_COUNT     equ 0xCE
DMA_STATUS_CMD2     equ 0xD0
DMA_REQUEST2        equ 0xD2
DMA_SINGLE_MASK2    equ 0xD4
DMA_MODE2           equ 0xD6
DMA_FLIP_FLOP2      equ 0xD8
DMA_TEMP2           equ 0xDA
DMA_MASTER_CLEAR2   equ 0xDA
DMA_CLEAR_MASK2     equ 0xDC
DMA_MULTI_MASK2     equ 0xDE

; Page registers (for upper 8 bits of 24-bit address)
DMA_PAGE_CHAN0      equ 0x87
DMA_PAGE_CHAN1      equ 0x83
DMA_PAGE_CHAN2      equ 0x81
DMA_PAGE_CHAN3      equ 0x82
DMA_PAGE_CHAN5      equ 0x8B
DMA_PAGE_CHAN6      equ 0x89
DMA_PAGE_CHAN7      equ 0x8A

; DMA Mode register bits
MODE_TRANSFER_READ      equ 0x04    ; Memory to I/O
MODE_TRANSFER_WRITE     equ 0x08    ; I/O to Memory
MODE_AUTO_INIT          equ 0x10
MODE_ADDRESS_DECREMENT  equ 0x20
MODE_DEMAND             equ 0x00
MODE_SINGLE             equ 0x40
MODE_BLOCK              equ 0x80
MODE_CASCADE            equ 0xC0

; Initialize DMA channel
; void dma_init_channel(u8 channel, u32 buffer, u16 count, u8 mode)
dma_init_channel:
    push ebp
    mov ebp, esp
    push eax
    push ebx
    push ecx
    push edx
    
    movzx ebx, byte [ebp + 8]   ; Channel number (0-7)
    mov ecx, [ebp + 12]         ; Buffer address
    movzx edx, word [ebp + 16]  ; Transfer count
    mov al, [ebp + 20]          ; Mode
    
    ; Mask the channel
    cmp ebx, 4
    jb .master_dma
    
.slave_dma:
    ; Channels 4-7 (slave controller)
    mov ah, bl
    sub ah, 4
    or ah, 0x04                 ; Set mask bit
    mov dx, DMA_SINGLE_MASK2
    out dx, al
    
    ; Clear flip-flop
    mov dx, DMA_FLIP_FLOP2
    xor al, al
    out dx, al
    
    ; Set mode
    mov al, [ebp + 20]
    mov ah, bl
    sub ah, 4
    or al, ah
    mov dx, DMA_MODE2
    out dx, al
    
    ; Set address (16-bit words for channels 5-7)
    shr ecx, 1                  ; Convert to word address
    mov ax, cx
    
    cmp bl, 5
    je .chan5
    cmp bl, 6
    je .chan6
    cmp bl, 7
    je .chan7
    jmp .done
    
.chan5:
    mov dx, DMA_CHAN5_ADDR
    out dx, al
    mov al, ah
    out dx, al
    
    ; Set page
    mov al, [ebp + 14]
    mov dx, DMA_PAGE_CHAN5
    out dx, al
    
    ; Set count
    mov ax, dx
    mov dx, DMA_CHAN5_COUNT
    out dx, al
    mov al, ah
    out dx, al
    jmp .unmask_slave
    
.chan6:
    mov dx, DMA_CHAN6_ADDR
    out dx, al
    mov al, ah
    out dx, al
    
    mov al, [ebp + 14]
    mov dx, DMA_PAGE_CHAN6
    out dx, al
    
    mov ax, dx
    mov dx, DMA_CHAN6_COUNT
    out dx, al
    mov al, ah
    out dx, al
    jmp .unmask_slave
    
.chan7:
    mov dx, DMA_CHAN7_ADDR
    out dx, al
    mov al, ah
    out dx, al
    
    mov al, [ebp + 14]
    mov dx, DMA_PAGE_CHAN7
    out dx, al
    
    mov ax, dx
    mov dx, DMA_CHAN7_COUNT
    out dx, al
    mov al, ah
    out dx, al
    
.unmask_slave:
    ; Unmask channel
    mov al, bl
    sub al, 4
    mov dx, DMA_SINGLE_MASK2
    out dx, al
    jmp .done
    
.master_dma:
    ; Channels 0-3 (master controller)
    mov al, bl
    or al, 0x04                 ; Set mask bit
    mov dx, DMA_SINGLE_MASK
    out dx, al
    
    ; Clear flip-flop
    mov dx, DMA_FLIP_FLOP
    xor al, al
    out dx, al
    
    ; Set mode
    mov al, [ebp + 20]
    or al, bl
    mov dx, DMA_MODE
    out dx, al
    
    ; Set address (byte address)
    mov ax, cx
    
    cmp bl, 0
    je .chan0
    cmp bl, 1
    je .chan1
    cmp bl, 2
    je .chan2
    cmp bl, 3
    je .chan3
    
.chan0:
    mov dx, DMA_CHAN0_ADDR
    out dx, al
    mov al, ah
    out dx, al
    
    mov al, [ebp + 14]
    mov dx, DMA_PAGE_CHAN0
    out dx, al
    
    mov ax, dx
    mov dx, DMA_CHAN0_COUNT
    out dx, al
    mov al, ah
    out dx, al
    jmp .unmask_master
    
.chan1:
    mov dx, DMA_CHAN1_ADDR
    out dx, al
    mov al, ah
    out dx, al
    
    mov al, [ebp + 14]
    mov dx, DMA_PAGE_CHAN1
    out dx, al
    
    mov ax, dx
    mov dx, DMA_CHAN1_COUNT
    out dx, al
    mov al, ah
    out dx, al
    jmp .unmask_master
    
.chan2:
    mov dx, DMA_CHAN2_ADDR
    out dx, al
    mov al, ah
    out dx, al
    
    mov al, [ebp + 14]
    mov dx, DMA_PAGE_CHAN2
    out dx, al
    
    mov ax, dx
    mov dx, DMA_CHAN2_COUNT
    out dx, al
    mov al, ah
    out dx, al
    jmp .unmask_master
    
.chan3:
    mov dx, DMA_CHAN3_ADDR
    out dx, al
    mov al, ah
    out dx, al
    
    mov al, [ebp + 14]
    mov dx, DMA_PAGE_CHAN3
    out dx, al
    
    mov ax, dx
    mov dx, DMA_CHAN3_COUNT
    out dx, al
    mov al, ah
    out dx, al
    
.unmask_master:
    ; Unmask channel
    mov al, bl
    mov dx, DMA_SINGLE_MASK
    out dx, al
    
.done:
    pop edx
    pop ecx
    pop ebx
    pop eax
    pop ebp
    ret

; Start DMA transfer
; void dma_start_transfer(u8 channel)
dma_start_transfer:
    push eax
    push edx
    
    movzx eax, byte [esp + 12]  ; Channel
    
    cmp al, 4
    jb .master
    
    ; Slave DMA
    sub al, 4
    mov dx, DMA_SINGLE_MASK2
    out dx, al
    jmp .done
    
.master:
    mov dx, DMA_SINGLE_MASK
    out dx, al
    
.done:
    pop edx
    pop eax
    ret

; Stop DMA transfer
; void dma_stop_transfer(u8 channel)
dma_stop_transfer:
    push eax
    push edx
    
    movzx eax, byte [esp + 12]
    
    cmp al, 4
    jb .master
    
    ; Slave DMA
    sub al, 4
    or al, 0x04
    mov dx, DMA_SINGLE_MASK2
    out dx, al
    jmp .done
    
.master:
    or al, 0x04
    mov dx, DMA_SINGLE_MASK
    out dx, al
    
.done:
    pop edx
    pop eax
    ret

; Check if DMA transfer is complete
; u32 dma_is_complete(u8 channel)
dma_is_complete:
    push edx
    
    movzx eax, byte [esp + 8]
    
    cmp al, 4
    jb .master
    
    ; Slave DMA
    sub al, 4
    mov dx, DMA_STATUS_CMD2
    in al, dx
    shr al, 1
    and al, 1
    jmp .done
    
.master:
    mov dx, DMA_STATUS_CMD
    in al, dx
    mov cl, [esp + 8]
    shr al, cl
    and al, 1
    
.done:
    movzx eax, al
    pop edx
    ret

; Get remaining transfer count
; u16 dma_get_remaining_count(u8 channel)
dma_get_remaining_count:
    push ebx
    push edx
    
    movzx ebx, byte [esp + 12]
    
    cmp bl, 4
    jb .master
    
    ; Slave DMA
    cmp bl, 5
    je .read_chan5
    cmp bl, 6
    je .read_chan6
    cmp bl, 7
    je .read_chan7
    jmp .done
    
.read_chan5:
    mov dx, DMA_CHAN5_COUNT
    jmp .read_slave
.read_chan6:
    mov dx, DMA_CHAN6_COUNT
    jmp .read_slave
.read_chan7:
    mov dx, DMA_CHAN7_COUNT
    
.read_slave:
    in al, dx
    mov ah, al
    in al, dx
    xchg al, ah
    jmp .done
    
.master:
    cmp bl, 0
    je .read_chan0
    cmp bl, 1
    je .read_chan1
    cmp bl, 2
    je .read_chan2
    cmp bl, 3
    je .read_chan3
    
.read_chan0:
    mov dx, DMA_CHAN0_COUNT
    jmp .read_master
.read_chan1:
    mov dx, DMA_CHAN1_COUNT
    jmp .read_master
.read_chan2:
    mov dx, DMA_CHAN2_COUNT
    jmp .read_master
.read_chan3:
    mov dx, DMA_CHAN3_COUNT
    
.read_master:
    in al, dx
    mov ah, al
    in al, dx
    xchg al, ah
    
.done:
    movzx eax, ax
    pop edx
    pop ebx
    ret

; ============================================================================
; Scatter-Gather DMA
; ============================================================================

global dma_scatter_gather
global dma_setup_descriptor_list

; DMA descriptor structure (16 bytes)
; Offset 0: Source address (32-bit)
; Offset 4: Destination address (32-bit)
; Offset 8: Length (32-bit)
; Offset 12: Next descriptor pointer (32-bit, 0 = end)

; Setup scatter-gather descriptor list
; void dma_setup_descriptor_list(u32* desc_list, u32 desc_count)
dma_setup_descriptor_list:
    push ebp
    mov ebp, esp
    push eax
    push ebx
    push ecx
    
    mov ebx, [ebp + 8]          ; Descriptor list
    mov ecx, [ebp + 12]         ; Count
    
    ; Validate descriptor list
    test ebx, ebx
    jz .done
    test ecx, ecx
    jz .done
    
    ; Link descriptors
.link_loop:
    cmp ecx, 1
    je .last_descriptor
    
    ; Point to next descriptor
    lea eax, [ebx + 16]
    mov [ebx + 12], eax
    
    add ebx, 16
    dec ecx
    jmp .link_loop
    
.last_descriptor:
    ; Mark end of list
    mov dword [ebx + 12], 0
    
.done:
    pop ecx
    pop ebx
    pop eax
    pop ebp
    ret

; Execute scatter-gather DMA
; u32 dma_scatter_gather(u32* desc_list, u8 channel)
dma_scatter_gather:
    push ebp
    mov ebp, esp
    push ebx
    push ecx
    push edx
    push esi
    
    mov esi, [ebp + 8]          ; Descriptor list
    movzx ebx, byte [ebp + 12]  ; Channel
    
    xor eax, eax                ; Transfer count
    
.next_descriptor:
    test esi, esi
    jz .done
    
    ; Get descriptor fields
    mov ecx, [esi + 0]          ; Source
    mov edx, [esi + 4]          ; Destination
    push dword [esi + 8]        ; Length
    push edx
    push ecx
    push ebx
    
    ; Setup and start transfer
    call dma_init_channel
    add esp, 16
    
    ; Wait for completion
.wait_complete:
    push ebx
    call dma_is_complete
    add esp, 4
    test eax, eax
    jz .wait_complete
    
    ; Accumulate transferred bytes
    add eax, [esi + 8]
    
    ; Next descriptor
    mov esi, [esi + 12]
    jmp .next_descriptor
    
.done:
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop ebp
    ret

; ============================================================================
; DMA Statistics and Debugging
; ============================================================================

section .data
align 4
dma_transfer_count: dd 0
dma_bytes_transferred: dd 0
dma_errors: dd 0

section .text

global get_dma_stats
global reset_dma_stats

; Get DMA statistics
; void get_dma_stats(u32* transfers, u32* bytes, u32* errors)
get_dma_stats:
    push ebp
    mov ebp, esp
    push eax
    push ebx
    
    mov ebx, [ebp + 8]          ; transfers
    test ebx, ebx
    jz .skip_transfers
    mov eax, [dma_transfer_count]
    mov [ebx], eax
    
.skip_transfers:
    mov ebx, [ebp + 12]         ; bytes
    test ebx, ebx
    jz .skip_bytes
    mov eax, [dma_bytes_transferred]
    mov [ebx], eax
    
.skip_bytes:
    mov ebx, [ebp + 16]         ; errors
    test ebx, ebx
    jz .done
    mov eax, [dma_errors]
    mov [ebx], eax
    
.done:
    pop ebx
    pop eax
    pop ebp
    ret

; Reset DMA statistics
; void reset_dma_stats(void)
reset_dma_stats:
    xor eax, eax
    mov [dma_transfer_count], eax
    mov [dma_bytes_transferred], eax
    mov [dma_errors], eax
    ret

; ============================================================================
; ISA DMA Controller Reset
; ============================================================================

global dma_reset_controller

; Reset DMA controller
; void dma_reset_controller(u8 controller)
dma_reset_controller:
    push eax
    push edx
    
    movzx eax, byte [esp + 12]
    
    test al, al
    jz .master
    
    ; Reset slave controller
    mov dx, DMA_MASTER_CLEAR2
    out dx, al
    jmp .done
    
.master:
    ; Reset master controller
    mov dx, DMA_MASTER_CLEAR
    out dx, al
    
.done:
    pop edx
    pop eax
    ret
