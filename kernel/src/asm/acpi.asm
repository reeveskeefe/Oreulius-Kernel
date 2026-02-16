

; Advanced Configuration and Power Interface (ACPI) Assembly
; Power management, thermal monitoring, and system control
; x86 32-bit architecture

[BITS 32]

section .text

; ============================================================================
; ACPI Table Discovery and Parsing
; ============================================================================

global acpi_find_rsdp
global acpi_checksum
global acpi_find_table

; RSDP signature
RSDP_SIG: db "RSD PTR ", 0

; Find Root System Description Pointer (RSDP)
; u32 acpi_find_rsdp(void)
; Searches EBDA and BIOS ROM area
acpi_find_rsdp:
    push ebx
    push ecx
    push edx
    push esi
    
    ; Search Extended BIOS Data Area (EBDA)
    ; EBDA segment stored at 0x40E
    xor eax, eax
    mov ax, [0x40E]
    shl eax, 4                  ; Convert to linear address
    test eax, eax
    jz .search_bios_rom
    
    mov esi, eax
    mov ecx, 0x400              ; Search 1KB
    call .search_region
    test eax, eax
    jnz .found
    
.search_bios_rom:
    ; Search BIOS ROM area 0xE0000 - 0xFFFFF
    mov esi, 0xE0000
    mov ecx, 0x20000
    call .search_region
    
.found:
    pop esi
    pop edx
    pop ecx
    pop ebx
    ret

.search_region:
    ; ESI = start address, ECX = length
.search_loop:
    test ecx, ecx
    jz .not_found
    
    ; Check signature
    mov eax, [esi]
    cmp eax, [RSDP_SIG]
    jne .next
    
    mov eax, [esi + 4]
    cmp eax, [RSDP_SIG + 4]
    jne .next
    
    ; Found signature, verify checksum
    push ecx
    push esi
    mov ecx, 20                 ; RSDP 1.0 size
    call .calc_checksum
    pop esi
    pop ecx
    
    test al, al
    jz .found_valid
    
.next:
    add esi, 16                 ; RSDP aligned on 16-byte boundary
    sub ecx, 16
    jmp .search_loop
    
.not_found:
    xor eax, eax
    ret
    
.found_valid:
    mov eax, esi
    ret

.calc_checksum:
    ; ESI = address, ECX = length
    xor al, al
.checksum_loop:
    add al, [esi]
    inc esi
    loop .checksum_loop
    ret

; Calculate ACPI table checksum
; u8 acpi_checksum(u8* table, u32 length)
acpi_checksum:
    push ebx
    push ecx
    push esi
    
    mov esi, [esp + 16]         ; Table address
    mov ecx, [esp + 20]         ; Length
    
    xor al, al
.loop:
    add al, [esi]
    inc esi
    loop .loop
    
    movzx eax, al
    
    pop esi
    pop ecx
    pop ebx
    ret

; Find ACPI table by signature
; u32 acpi_find_table(u32 rsdt_addr, u32 signature)
acpi_find_table:
    push ebp
    mov ebp, esp
    push ebx
    push ecx
    push edx
    push esi
    push edi
    
    mov esi, [ebp + 8]          ; RSDT address
    mov edi, [ebp + 12]         ; Signature to find
    
    test esi, esi
    jz .not_found
    
    ; Get number of entries
    mov ecx, [esi + 4]          ; RSDT length
    sub ecx, 36                 ; Header size
    shr ecx, 2                  ; Divide by 4 (pointer size)
    
    add esi, 36                 ; Skip header
    
.search_loop:
    test ecx, ecx
    jz .not_found
    
    mov ebx, [esi]              ; Get table pointer
    cmp dword [ebx], edi        ; Check signature
    je .found
    
    add esi, 4
    dec ecx
    jmp .search_loop
    
.not_found:
    xor eax, eax
    jmp .done
    
.found:
    mov eax, ebx
    
.done:
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop ebp
    ret

; ============================================================================
; ACPI Register Access
; ============================================================================

global acpi_read_pm1_control
global acpi_write_pm1_control
global acpi_read_pm1_status
global acpi_write_pm1_status

; Read PM1 Control Register
; u16 acpi_read_pm1_control(u16 pm1a_base)
acpi_read_pm1_control:
    push edx
    
    mov dx, [esp + 8]
    in ax, dx
    
    pop edx
    ret

; Write PM1 Control Register
; void acpi_write_pm1_control(u16 pm1a_base, u16 value)
acpi_write_pm1_control:
    push eax
    push edx
    
    mov dx, [esp + 12]
    mov ax, [esp + 16]
    out dx, ax
    
    pop edx
    pop eax
    ret

; Read PM1 Status Register
; u16 acpi_read_pm1_status(u16 pm1a_base)
acpi_read_pm1_status:
    push edx
    
    mov dx, [esp + 8]
    in ax, dx
    
    pop edx
    ret

; Write PM1 Status Register (clear bits)
; void acpi_write_pm1_status(u16 pm1a_base, u16 value)
acpi_write_pm1_status:
    push eax
    push edx
    
    mov dx, [esp + 12]
    mov ax, [esp + 16]
    out dx, ax
    
    pop edx
    pop eax
    ret

; ============================================================================
; Power State Transitions
; ============================================================================

global acpi_enter_sleep_state
global acpi_shutdown
global acpi_reboot

; Enter ACPI sleep state
; void acpi_enter_sleep_state(u16 pm1a_base, u8 sleep_type, u8 sleep_enable)
acpi_enter_sleep_state:
    push eax
    push edx
    
    ; Disable interrupts
    cli
    
    ; Read current PM1 control
    mov dx, [esp + 12]
    in ax, dx
    
    ; Clear sleep type and enable bits
    and ax, 0xC3FF
    
    ; Set new sleep type
    movzx edx, byte [esp + 16]
    shl edx, 10
    or ax, dx
    
    ; Set sleep enable if requested
    test byte [esp + 20], 1
    jz .no_enable
    or ax, 0x2000
    
.no_enable:
    ; Write to PM1 control
    mov dx, [esp + 12]
    out dx, ax
    
    ; Wait for sleep
    hlt
    
    pop edx
    pop eax
    ret

; ACPI Shutdown
; void acpi_shutdown(u16 pm1a_base)
acpi_shutdown:
    push eax
    push edx
    
    cli
    
    ; PM1a control - set SLP_TYPa = 5, SLP_EN = 1
    mov dx, [esp + 12]
    in ax, dx
    and ax, 0xC3FF
    or ax, 0x3400               ; Sleep type 5 + Sleep enable
    out dx, ax
    
    ; Fallback - halt
.halt_loop:
    hlt
    jmp .halt_loop
    
    pop edx
    pop eax
    ret

; ACPI Reboot
; void acpi_reboot(u8 reset_reg_addr)
acpi_reboot:
    push eax
    push edx
    
    ; Triple fault method
    cli
    
    ; Try ACPI reset register first
    movzx edx, byte [esp + 12]
    test dl, dl
    jz .keyboard_reboot
    
    mov al, 0x06
    out dx, al
    
    ; Wait a bit
    mov ecx, 1000
.wait:
    pause
    loop .wait
    
.keyboard_reboot:
    ; Keyboard controller reset
    mov al, 0xFE
    out 0x64, al
    
    ; Wait
    mov ecx, 1000
.wait2:
    pause
    loop .wait2
    
    ; Triple fault as last resort
    lidt [.null_idt]
    int 0
    
.null_idt:
    dw 0
    dd 0
    
    pop edx
    pop eax
    ret

; ============================================================================
; Thermal Monitoring
; ============================================================================

global acpi_read_thermal_zone
global acpi_set_cooling_policy

; Read thermal zone temperature
; u32 acpi_read_thermal_zone(u16 ec_data_port, u8 register)
acpi_read_thermal_zone:
    push edx
    
    ; Read from embedded controller
    mov dx, 0x66                ; EC command port
    mov al, 0x80                ; Read command
    out dx, al
    
    ; Wait for IBF clear
.wait_ibf:
    in al, dx
    test al, 0x02
    jnz .wait_ibf
    
    ; Send register address
    mov dx, 0x62                ; EC data port
    mov al, [esp + 12]
    out dx, al
    
    ; Wait for OBF set
    mov dx, 0x66
.wait_obf:
    in al, dx
    test al, 0x01
    jz .wait_obf
    
    ; Read data
    mov dx, 0x62
    in al, dx
    movzx eax, al
    
    pop edx
    ret

; Set cooling policy
; void acpi_set_cooling_policy(u8 policy)
acpi_set_cooling_policy:
    push eax
    push edx
    
    ; Policy: 0 = active, 1 = passive
    mov al, [esp + 12]
    
    ; Write to EC or ACPI registers
    ; Implementation depends on platform
    
    pop edx
    pop eax
    ret

; ============================================================================
; CPU Power States (C-states)
; ============================================================================

global acpi_enter_c1
global acpi_enter_c2
global acpi_enter_c3

; Enter C1 state (HALT)
; void acpi_enter_c1(void)
acpi_enter_c1:
    hlt
    ret

; Enter C2 state
; void acpi_enter_c2(u16 p_lvl2_port)
acpi_enter_c2:
    push eax
    push edx
    
    mov dx, [esp + 12]
    in al, dx                   ; Read from P_LVL2 port
    
    pop edx
    pop eax
    ret

; Enter C3 state
; void acpi_enter_c3(u16 p_lvl3_port)
acpi_enter_c3:
    push eax
    push edx
    
    ; Flush caches before deep sleep
    wbinvd
    
    mov dx, [esp + 12]
    in al, dx                   ; Read from P_LVL3 port
    
    pop edx
    pop eax
    ret

; ============================================================================
; Processor Performance States (P-states)
; ============================================================================

global acpi_set_pstate
global acpi_get_pstate

; Set processor P-state (frequency/voltage)
; void acpi_set_pstate(u8 pstate)
acpi_set_pstate:
    push eax
    push ebx
    push ecx
    push edx
    
    ; Read current P-state control MSR
    mov ecx, 0x199              ; IA32_PERF_CTL
    rdmsr
    
    ; Clear P-state field
    and eax, 0xFFFF0000
    
    ; Set new P-state
    movzx ebx, byte [esp + 20]
    or eax, ebx
    
    ; Write MSR
    wrmsr
    
    pop edx
    pop ecx
    pop ebx
    pop eax
    ret

; Get current P-state
; u8 acpi_get_pstate(void)
acpi_get_pstate:
    push ecx
    push edx
    
    mov ecx, 0x198              ; IA32_PERF_STATUS
    rdmsr
    
    and eax, 0xFFFF
    
    pop edx
    pop ecx
    ret

; ============================================================================
; Battery Status
; ============================================================================

global acpi_get_battery_status
global acpi_get_battery_capacity

; Get battery status
; u32 acpi_get_battery_status(void)
; Returns: bit 0 = charging, bit 1 = critical
acpi_get_battery_status:
    push edx
    
    ; Read from EC
    mov dx, 0x66
    mov al, 0x80
    out dx, al
    
.wait:
    in al, dx
    test al, 0x02
    jnz .wait
    
    mov dx, 0x62
    mov al, 0x00                ; Battery status register
    out dx, al
    
    mov dx, 0x66
.wait2:
    in al, dx
    test al, 0x01
    jz .wait2
    
    mov dx, 0x62
    in al, dx
    movzx eax, al
    
    pop edx
    ret

; Get battery capacity percentage
; u8 acpi_get_battery_capacity(void)
acpi_get_battery_capacity:
    push edx
    
    mov dx, 0x66
    mov al, 0x80
    out dx, al
    
.wait:
    in al, dx
    test al, 0x02
    jnz .wait
    
    mov dx, 0x62
    mov al, 0x01                ; Battery capacity register
    out dx, al
    
    mov dx, 0x66
.wait2:
    in al, dx
    test al, 0x01
    jz .wait2
    
    mov dx, 0x62
    in al, dx
    movzx eax, al
    
    pop edx
    ret

; ============================================================================
; ACPI Event Handling
; ============================================================================

global acpi_enable_events
global acpi_get_event_status
global acpi_clear_event

; Enable ACPI events
; void acpi_enable_events(u16 pm1a_base, u16 event_mask)
acpi_enable_events:
    push eax
    push edx
    
    mov dx, [esp + 12]
    add dx, 2                   ; PM1 enable register
    mov ax, [esp + 16]
    out dx, ax
    
    pop edx
    pop eax
    ret

; Get event status
; u16 acpi_get_event_status(u16 pm1a_base)
acpi_get_event_status:
    push edx
    
    mov dx, [esp + 8]
    in ax, dx
    
    pop edx
    ret

; Clear ACPI event
; void acpi_clear_event(u16 pm1a_base, u16 event_bits)
acpi_clear_event:
    push eax
    push edx
    
    mov dx, [esp + 12]
    mov ax, [esp + 16]
    out dx, ax
    
    pop edx
    pop eax
    ret

; ============================================================================
; Statistics
; ============================================================================

section .data
align 4
acpi_sleep_count: dd 0
acpi_wake_count: dd 0
acpi_thermal_events: dd 0

section .text

global get_acpi_stats

; Get ACPI statistics
; void get_acpi_stats(u32* sleeps, u32* wakes, u32* thermal)
get_acpi_stats:
    push ebp
    mov ebp, esp
    push eax
    push ebx
    
    mov ebx, [ebp + 8]
    test ebx, ebx
    jz .skip_sleeps
    mov eax, [acpi_sleep_count]
    mov [ebx], eax
    
.skip_sleeps:
    mov ebx, [ebp + 12]
    test ebx, ebx
    jz .skip_wakes
    mov eax, [acpi_wake_count]
    mov [ebx], eax
    
.skip_wakes:
    mov ebx, [ebp + 16]
    test ebx, ebx
    jz .done
    mov eax, [acpi_thermal_events]
    mov [ebx], eax
    
.done:
    pop ebx
    pop eax
    pop ebp
    ret
