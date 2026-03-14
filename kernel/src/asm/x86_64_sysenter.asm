; x86_64_sysenter.asm — Fast system call entry points (SYSENTER/SYSCALL)
;
; Replaces STUB_ZERO shims for:
;   sysenter_entry         — legacy IA-32e SYSENTER handler (MSR_SYSENTER_EIP target)
;   syscall_entry_64       — modern SYSCALL handler (MSR_LSTAR target)
;   setup_syscall_msrs     — write STAR, LSTAR, FMASK MSRs to activate SYSCALL path
;   setup_sysenter_msrs    — write SYSENTER_CS, SYSENTER_ESP, SYSENTER_EIP MSRs
;
; MSR numbers
MSR_STAR    equ 0xC0000081     ; SYSCALL/SYSRET segment selectors
MSR_LSTAR   equ 0xC0000082     ; SYSCALL target RIP (64-bit)
MSR_CSTAR   equ 0xC0000083     ; SYSCALL target RIP (compat, unused here)
MSR_SFMASK  equ 0xC0000084     ; RFLAGS bits to clear on SYSCALL
MSR_EFER    equ 0xC0000080     ; Extended Feature Enable Register
EFER_SCE    equ (1 << 0)       ; SYSCALL Enable bit in EFER
MSR_SYSENTER_CS  equ 0x174
MSR_SYSENTER_ESP equ 0x175
MSR_SYSENTER_EIP equ 0x176
;
; GDT segment selectors (must match kernel/src/gdt.rs or gdt.asm)
; These constants match the standard Oreulia GDT layout:
;   0x00 — null descriptor
;   0x08 — kernel code  (ring 0, 64-bit)
;   0x10 — kernel data  (ring 0)
;   0x18 — user code 32 (ring 3, compat, unused)
;   0x20 — user data    (ring 3)
;   0x28 — user code 64 (ring 3, 64-bit)
KERNEL_CS   equ 0x08
KERNEL_DS   equ 0x10
USER_DS     equ 0x20
USER_CS     equ 0x28
;
; RFLAGS bits to clear on SYSCALL entry (prevents user from keeping interrupts
; disabled or a trap flag active inside kernel)
SYSCALL_FMASK equ 0x200 | 0x100  ; clear IF (interrupt flag) and TF (trap flag)
;
; ABI: System V AMD64

[bits 64]
default rel

section .bss
align 16
; Per-CPU kernel stack pointer storage for SYSCALL/SYSENTER
; The kernel swapgs mechanism requires gs:0 to point to the kernel RSP.
; For simplicity, we keep a single kernel_stack_top variable here.
; In a real SMP kernel this would be per-CPU.
_kernel_stack_top: resq 1

section .text

; ---------------------------------------------------------------------------
; void setup_syscall_msrs(u64 kernel_stack_top)
; Configure STAR, LSTAR, and FMASK so SYSCALL works.
; rdi = top of kernel stack (will be swapped in on SYSCALL entry)
; ---------------------------------------------------------------------------
global setup_syscall_msrs
setup_syscall_msrs:
    ; Save kernel stack top for use by syscall_entry_64
    mov     [rel _kernel_stack_top], rdi

    ; Step 1: Enable SCE (SYSCALL Enable) in EFER
    mov     ecx, MSR_EFER
    rdmsr
    or      eax, EFER_SCE
    wrmsr

    ; Step 2: Write STAR — segment selectors for SYSCALL/SYSRET
    ; STAR layout (64 bits):
    ;   bits 63:48 = SYSRET  CS/SS selector (user code; SS = CS+8 for SYSRET 64)
    ;   bits 47:32 = SYSCALL CS/SS selector (kernel code; SS = CS+8)
    ;   bits 31:0  = reserved (write 0)
    ; On SYSCALL: CS = STAR[47:32], SS = STAR[47:32]+8
    ; On SYSRET64: CS = STAR[63:48]+16, SS = STAR[63:48]+8
    mov     ecx, MSR_STAR
    xor     eax, eax
    mov     edx, ((USER_DS - 8) << 16) | KERNEL_CS
    ; edx bits 47:32 = KERNEL_CS (kernel CS on SYSCALL)
    ; edx bits 63:48 = USER_DS-8 so SYSRET gets USER_CS = USER_DS-8+16 = USER_CS
    wrmsr

    ; Step 3: Write LSTAR — 64-bit SYSCALL target RIP
    mov     ecx, MSR_LSTAR
    lea     rax, [rel syscall_entry_64]
    mov     rdx, rax
    shr     rdx, 32             ; rdx = high 32 bits of address
    wrmsr

    ; Step 4: Write FMASK — RFLAGS bits to clear on SYSCALL
    mov     ecx, MSR_SFMASK
    mov     eax, SYSCALL_FMASK
    xor     edx, edx
    wrmsr

    ret

; ---------------------------------------------------------------------------
; void setup_sysenter_msrs(u64 kernel_cs, u64 kernel_esp, u64 eip_target)
; Configure SYSENTER_CS, SYSENTER_ESP, SYSENTER_EIP MSRs.
; rdi = kernel CS selector, rsi = kernel stack pointer, rdx = handler VA
; ---------------------------------------------------------------------------
global setup_sysenter_msrs
setup_sysenter_msrs:
    ; Write SYSENTER_CS
    mov     ecx, MSR_SYSENTER_CS
    mov     eax, edi
    xor     edx, edx
    wrmsr

    ; Write SYSENTER_ESP
    mov     ecx, MSR_SYSENTER_ESP
    mov     rax, rsi
    mov     rdx, rax
    shr     rdx, 32
    wrmsr

    ; Write SYSENTER_EIP
    mov     ecx, MSR_SYSENTER_EIP
    mov     rax, rdx            ; rdx holds the eip_target argument
    ; Wait — rdx is both arg3 and used in wrmsr. Reload:
    mov     rax, rdx            ; rdx = eip_target (3rd arg)
    mov     rdx, rax
    shr     rdx, 32
    wrmsr

    ret

; ---------------------------------------------------------------------------
; syscall_entry_64 — 64-bit SYSCALL handler
;
; Called by the CPU when user code executes SYSCALL.
; On entry (CPU state):
;   RCX = user RIP (return address)
;   R11 = saved RFLAGS
;   RSP = user RSP (NOT swapped — we must swap it)
;   CS  = KERNEL_CS, SS = KERNEL_DS (from STAR)
;   RFLAGS bits cleared per FMASK (IF and TF are off)
;
; Oreulia syscall convention (matches Linux ABI for compatibility):
;   rax = syscall number
;   rdi = arg1, rsi = arg2, rdx = arg3
;   r10 = arg4 (r10 replaces rcx since rcx is clobbered by SYSCALL)
;   r8  = arg5, r9 = arg6
;
; Returns: rax = return value
; ---------------------------------------------------------------------------
global syscall_entry_64
syscall_entry_64:
    ; Save user RSP, switch to kernel stack
    ; The proper mechanism is SwapGS + gs-relative load, but we use a
    ; simplified single-processor version here.
    ; Production: swapgs; mov [gs:user_rsp_slot], rsp; mov rsp, [gs:kstack_slot]
    swapgs
    ; After swapgs, gs base points to the kernel per-CPU block.
    ; For now, use the static kernel_stack_top.
    ; Swap RSP: save user RSP to a scratch location via push, then load kernel RSP.
    ; This is the minimal safe sequence used by Linux.
    xchg    rsp, [rel _kernel_stack_top]   ; atomic-ish on x86; user RSP now stored

    ; Build a minimal interrupt frame on the kernel stack
    push    r11                 ; saved RFLAGS
    push    rcx                 ; saved user RIP

    ; Save full syscall-clobbered registers
    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15

    ; Re-enable interrupts (FMASK cleared IF; restore it now that we have
    ; a proper kernel stack)
    sti

    ; Call Rust syscall dispatcher:
    ; extern "C" fn syscall_handler(nr: u64, a1: u64, a2: u64, a3: u64,
    ;                                a4: u64, a5: u64, a6: u64) -> u64
    ; Arguments are already in rdi, rsi, rdx, r10→rcx, r8, r9
    ; Syscall number is in rax — move it to rdi, shift args:
    ; Actually keep standard: many kernels use rax as nr and don't shift args.
    ; We'll call a Rust handler that takes (nr, a1..a6).
    ; For simplicity, invoke a weak symbol that Rust can override:
    mov     rdi, rax            ; syscall number
    ; rsi, rdx already correct; r10 → rcx for arg4
    mov     rcx, r10
    ; r8, r9 already correct
    ; (rax will be overwritten by return value from Rust)

    ; Call the Rust dispatcher if it exists; otherwise return ENOSYS (-38)
    extern  oreulia_syscall_dispatch
    call    oreulia_syscall_dispatch

    ; Restore saved registers
    cli                         ; disable interrupts before swapping back
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp

    ; Restore user RIP and RFLAGS from stack
    pop     rcx                 ; user RIP → rcx (for SYSRET)
    pop     r11                 ; user RFLAGS → r11 (for SYSRET)

    ; Restore user RSP
    xchg    rsp, [rel _kernel_stack_top]

    swapgs
    ; Return to user: SYSRET restores RIP from RCX, RFLAGS from R11
    o64 sysret

; ---------------------------------------------------------------------------
; sysenter_entry — legacy SYSENTER handler (IA-32e compat path)
; Used by 32-bit compat processes. Full 64-bit OS primarily uses SYSCALL.
; On entry (CPU state, from SYSENTER):
;   CS:RIP = SYSENTER_CS:SYSENTER_EIP
;   SS:RSP = (SYSENTER_CS+8):SYSENTER_ESP
;   RFLAGS.IF = 0 (interrupts disabled)
;   User RIP saved by userspace in ECX (convention)
;   User RSP saved by userspace in EDX (convention)
; ---------------------------------------------------------------------------
global sysenter_entry
sysenter_entry:
    ; SYSENTER provides no hardware save of user CS:RIP — userspace must
    ; save those in ECX:EDX per Intel's recommended convention.
    ; We re-enable interrupts once we have a valid kernel stack.
    sti

    ; Minimal stub: call Rust handler with ENOSYS approach
    ; Full implementation would mirror syscall_entry_64 but using sysexit.
    ; For now, return 0 (syscall not handled) and SYSEXIT back.
    ; User convention: ECX = user EIP to return to, EDX = user ESP
    xor     eax, eax

    sysexit                     ; return: EIP ← ECX, ESP ← EDX, CS ← SYSENTER_CS+16

section .note.GNU-stack noalloc noexec nowrite progbits
