; x86_64_sysenter.asm — Fast system call entry points (SYSENTER/SYSCALL)
;
; Replaces STUB_ZERO shims for:
;   sysenter_entry         — legacy IA-32e SYSENTER handler (MSR_SYSENTER_EIP target)
;   syscall_entry_64       — modern SYSCALL handler (MSR_LSTAR target)
;   setup_syscall_msrs     — write STAR, LSTAR, FMASK MSRs to activate SYSCALL path
;   setup_sysenter_msrs    — write SYSENTER_CS, SYSENTER_ESP, SYSENTER_EIP MSRs
;
; MSR numbers
MSR_STAR            equ 0xC0000081  ; SYSCALL/SYSRET segment selectors
MSR_LSTAR           equ 0xC0000082  ; SYSCALL target RIP (64-bit)
MSR_CSTAR           equ 0xC0000083  ; SYSCALL target RIP (compat mode)
MSR_SFMASK          equ 0xC0000084  ; RFLAGS bits to clear on SYSCALL
MSR_EFER            equ 0xC0000080  ; Extended Feature Enable Register
EFER_SCE            equ (1 << 0)    ; SYSCALL Enable bit in EFER
MSR_GS_BASE         equ 0xC0000101  ; Current GS base
MSR_KERNEL_GS_BASE  equ 0xC0000102  ; Kernel GS base — loaded into GS by swapgs
MSR_SYSENTER_CS     equ 0x174
MSR_SYSENTER_ESP    equ 0x175
MSR_SYSENTER_EIP    equ 0x176
;
; GDT segment selectors (must match kernel/src/gdt.rs or gdt.asm)
; These constants match the standard Oreulius GDT layout:
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
; RFLAGS bits to clear on SYSCALL entry.
; IF  (bit  9) — re-enabled once we have a valid kernel stack
; TF  (bit  8) — no single-step into kernel
; NT  (bit 14) — no nested task
; AC  (bit 18) — no alignment check in ring 0
SYSCALL_FMASK equ 0x200 | 0x100 | 0x4000 | 0x40000
;
; Per-CPU block offsets (gs base → _pcpu_block after swapgs on SYSCALL entry)
PCPU_KSTACK_TOP equ 0   ; gs:0  — kernel stack top (read-only after setup)
PCPU_USER_RSP   equ 8   ; gs:8  — scratch slot for user RSP during syscall
;
; ABI: System V AMD64

[bits 64]
default rel

section .bss
align 16
; Per-CPU block — single entry for the current uniprocessor implementation.
; MSR_KERNEL_GS_BASE is written to point here by setup_syscall_msrs so that
; after swapgs on SYSCALL entry GS base == _pcpu_block.
;
; Layout:
;   +0  (_pcpu_kstack_top)  kernel stack top; loaded into RSP at SYSCALL entry.
;                           Never written after setup — two dedicated slots avoid
;                           the corruption that a single xchg slot causes.
;   +8  (_pcpu_user_rsp)    Scratch slot for the user RSP across the syscall.
global _pcpu_block
_pcpu_block:
_pcpu_kstack_top:   resq 1   ; gs:PCPU_KSTACK_TOP
_pcpu_user_rsp:     resq 1   ; gs:PCPU_USER_RSP

section .text

; ---------------------------------------------------------------------------
; void setup_syscall_msrs(u64 kernel_stack_top)
; Configure STAR, LSTAR, FMASK, and MSR_KERNEL_GS_BASE so SYSCALL works.
; rdi = top of kernel stack (stored in per-CPU block; used by syscall_entry_64)
; ---------------------------------------------------------------------------
global setup_syscall_msrs
setup_syscall_msrs:
    ; Step 0a: Store the kernel stack top in the per-CPU block.
    mov     [rel _pcpu_kstack_top], rdi

    ; Step 0b: Write MSR_KERNEL_GS_BASE to point at our per-CPU block.
    ; After swapgs on SYSCALL entry, GS base == _pcpu_block, so
    ; [gs:PCPU_KSTACK_TOP] and [gs:PCPU_USER_RSP] are directly addressable.
    mov     ecx, MSR_KERNEL_GS_BASE
    lea     rax, [rel _pcpu_block]
    mov     rdx, rax
    shr     rdx, 32
    wrmsr

    ; Step 1: Enable SCE (SYSCALL Enable) in EFER.
    mov     ecx, MSR_EFER
    rdmsr
    or      eax, EFER_SCE
    wrmsr

    ; Step 2: Write STAR — segment selectors for SYSCALL/SYSRET.
    ; STAR layout:
    ;   bits 63:48 = SYSRET  base selector  → SYSRET64 CS = base+16, SS = base+8
    ;   bits 47:32 = SYSCALL CS             → SS = CS+8 on entry
    ;   bits 31:0  = reserved (zero)
    ; With KERNEL_CS=0x08, KERNEL_DS=0x10, USER_DS=0x20, USER_CS=0x28:
    ;   SYSCALL entry:  CS=0x08, SS=0x10
    ;   SYSRET64 exit:  CS=0x28, SS=0x20  (base=USER_DS-8=0x18; 0x18+16=0x28, 0x18+8=0x20)
    mov     ecx, MSR_STAR
    xor     eax, eax
    mov     edx, ((USER_DS - 8) << 16) | KERNEL_CS
    wrmsr

    ; Step 3: Write LSTAR — 64-bit SYSCALL target RIP.
    mov     ecx, MSR_LSTAR
    lea     rax, [rel syscall_entry_64]
    mov     rdx, rax
    shr     rdx, 32
    wrmsr

    ; Step 4: Write CSTAR for compat-mode SYSCALL.
    ; Route compat-mode SYSCALL through the same hardened entry until a
    ; dedicated compat-mode dispatcher is introduced.
    mov     ecx, MSR_CSTAR
    lea     rax, [rel syscall_entry_64]
    mov     rdx, rax
    shr     rdx, 32
    wrmsr

    ; Step 5: Write SFMASK — RFLAGS bits to clear on SYSCALL.
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
    ; Preserve eip_target (rdx = 3rd argument) BEFORE the first WRMSR call.
    ; WRMSR reads EDX:EAX and leaves rdx modified; failing to save rdx here
    ; means SYSENTER_EIP ends up receiving the high-32 of rsi instead of the
    ; handler address — a silent wrong-address bug.
    mov     r8, rdx             ; r8 = eip_target (safe across WRMSR)

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

    ; Write SYSENTER_EIP — use r8 (the preserved eip_target)
    mov     ecx, MSR_SYSENTER_EIP
    mov     rax, r8
    mov     rdx, r8
    shr     rdx, 32
    wrmsr

    ret

; ---------------------------------------------------------------------------
; syscall_entry_64 — 64-bit SYSCALL handler target (MSR_LSTAR)
;
; CPU state on SYSCALL entry (Intel SDM Vol.2B SYSCALL):
;   RCX    = saved user RIP (return address for SYSRET)
;   R11    = saved user RFLAGS (restored by SYSRET)
;   RSP    = user RSP — CPU does NOT switch the stack; we must
;   CS     = STAR[47:32]   = KERNEL_CS
;   SS     = STAR[47:32]+8 = KERNEL_DS
;   RFLAGS = user_rflags & ~FMASK  (IF=0, TF=0, NT=0, AC=0)
;
; Syscall calling convention (Linux-compatible):
;   rax = syscall number
;   rdi = arg1, rsi = arg2, rdx = arg3
;   r10 = arg4  (rcx is unusable: SYSCALL stores user RIP there)
;   r8  = arg5, r9 = arg6
;
; Rust handler:
;   extern "sysv64" fn oreulius_syscall_dispatch(
;       nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64
;   ) -> u64;
;
; Kernel stack frame layout (lower addr = later push = closer to rsp):
;   [frame+72]  user RSP      pushed first; restored last via `pop rsp`
;   [frame+64]  user RFLAGS   r11 → restored to r11 before SYSRET
;   [frame+56]  user RIP      rcx → restored to rcx before SYSRET
;   [frame+48]  rbp
;   [frame+40]  rbx
;   [frame+32]  r12
;   [frame+24]  r13
;   [frame+16]  r14
;   [frame+ 8]  r15
;   [frame+ 0]  ← rsp after frame complete (9 pushes from aligned kstack_top)
; ---------------------------------------------------------------------------
global syscall_entry_64
syscall_entry_64:
    ; Switch GS base from user to kernel.
    ; MSR_KERNEL_GS_BASE was written to point at _pcpu_block by setup_syscall_msrs.
    ; After swapgs:
    ;   [gs:PCPU_KSTACK_TOP] = kernel stack top (set at boot, never modified)
    ;   [gs:PCPU_USER_RSP]   = scratch for user RSP
    swapgs

    ; Save user RSP to the per-CPU scratch slot, then load the kernel stack.
    ; Two dedicated slots are essential — a single xchg slot overwrites itself
    ; on every exit, causing the next entry to start the kernel stack from a
    ; stale mid-frame pointer.
    mov     [gs:PCPU_USER_RSP],   rsp     ; save user RSP
    mov     rsp, [gs:PCPU_KSTACK_TOP]     ; switch to kernel stack

    ; Push the syscall return frame.  user RSP goes on first so that a single
    ; `pop rsp` at the end of the exit path restores the user stack atomically.
    push    qword [gs:PCPU_USER_RSP]      ; [frame+72] user RSP
    push    r11                           ; [frame+64] user RFLAGS
    push    rcx                           ; [frame+56] user RIP

    ; Save callee-saved registers (System V AMD64 ABI §3.2.1).  SYSCALL
    ; hardware-clobbers rcx and r11 (both already on the frame above); the
    ; Rust dispatcher may clobber any caller-saved register.  Saving the
    ; callee-saved set here makes the kernel call-graph transparent.
    push    rbp                           ; [frame+48]
    push    rbx                           ; [frame+40]
    push    r12                           ; [frame+32]
    push    r13                           ; [frame+24]
    push    r14                           ; [frame+16]
    push    r15                           ; [frame+ 8]
    ; rsp = kstack_top - 72 (9 pushes * 8).  72 mod 16 = 8 → rsp 8-byte aligned.

    ; Re-enable interrupts.  FMASK cleared IF on SYSCALL entry; restore it
    ; now that we are executing with a complete kernel stack frame.
    sti

    ; Map syscall registers → SysV AMD64 calling convention.
    ;
    ; Incoming:  rax=nr  rdi=a1  rsi=a2  rdx=a3  r10=a4  r8=a5  r9=a6
    ; SysV out:  rdi=nr  rsi=a1  rdx=a2  rcx=a3   r8=a4  r9=a5  [rsp+8]=a6
    ;
    ; Shift back-to-front to consume each source register before overwriting it.
    push    r9              ; a6 → 7th arg on stack (rsp = kstack-80; 16-byte aligned)
    mov     r9,  r8         ; a5 → r9
    mov     r8,  r10        ; a4 → r8
    mov     rcx, rdx        ; a3 → rcx  (rdx freed; rcx was user RIP but is on stack)
    mov     rdx, rsi        ; a2 → rdx
    mov     rsi, rdi        ; a1 → rsi  (rdi freed; a1 safely in rsi before next line)
    mov     rdi, rax        ; nr → rdi
    ; Stack is 16-byte aligned — `call` will push return addr making rsp+8 aligned.

    extern  oreulius_syscall_dispatch
    call    oreulius_syscall_dispatch

    add     rsp, 8          ; discard pushed a6; rsp = kstack-72 (back to frame base)
    ; rax = syscall return value — do not clobber.

    ; Disable interrupts before unwinding to user context.
    cli

    ; Restore callee-saved registers.
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp

    ; Restore SYSRET context.
    pop     rcx             ; user RIP   → rcx  (SYSRET64 restores RIP from RCX)
    pop     r11             ; user RFLAGS → r11 (SYSRET64 restores RFLAGS from R11)

    ; Force IF=1 in the RFLAGS delivered to userspace.  User code cannot
    ; execute CLI (privileged), so IF should always be set; enforce it as a
    ; defensive invariant.
    or      r11, 0x200      ; RFLAGS.IF = 1

    ; Restore user RSP and abandon the kernel stack in one instruction.
    ; After this point RSP = user stack; no further use of the kernel frame.
    pop     rsp

    ; Restore user GS base.
    swapgs

    ; Return to userspace.
    ; SYSRET64 (REX.W): RIP←RCX, RFLAGS←R11, CS←USER_CS, SS←USER_DS, CPL←3.
    ; RSP is already the user stack from `pop rsp` above.
    o64 sysret

; ---------------------------------------------------------------------------
; sysenter_entry — legacy IA-32e SYSENTER handler
;
; Serves 32-bit compat processes that call SYSENTER.
; CPU state on SYSENTER entry:
;   CS:RIP  = SYSENTER_CS : SYSENTER_EIP   (kernel ring-0 code, this label)
;   SS:RSP  = (SYSENTER_CS+8) : SYSENTER_ESP  (kernel stack)
;   RFLAGS.IF = 0,  RFLAGS.VM = 0
;
; Oreulius compat-SYSENTER software convention:
;   ECX = user return EIP   (SYSEXIT delivers EIP ← ECX)
;   EDX = user return ESP   (SYSEXIT delivers ESP ← EDX)
;   EAX = syscall number
;   EBX = arg1,  ESI = arg2,  EDI = arg3,  EBP = arg4
;   (ECX and EDX carry return pointers, not args — they are clobbered)
;
; SYSEXIT (no REX.W) returns to 32-bit compat mode:
;   EIP ← ECX,  ESP ← EDX
;   CS  = SYSENTER_CS+16  (ring-3 compat code)
;   SS  = SYSENTER_CS+24  (ring-3 compat data)
; ---------------------------------------------------------------------------
global sysenter_entry
sysenter_entry:
    ; Capture the user return pointers onto the kernel stack BEFORE
    ; re-enabling interrupts.  Although the interrupt handler would preserve
    ; RCX/RDX across the interrupt frame, pushing them immediately is the
    ; correct defensive practice and matches the exit pop order exactly.
    push    rcx             ; [frame+48] user return EIP (ECX convention)
    push    rdx             ; [frame+40] user return ESP (EDX convention)

    ; Safe to re-enable interrupts: the kernel stack is live and the return
    ; context is already saved.
    sti

    ; Save callee-saved registers that the Rust dispatcher may clobber.
    ; These also hold the syscall arguments — save them before shifting.
    push    rbp             ; [frame+32] arg4 (EBP)
    push    rbx             ; [frame+24] arg1 (EBX)
    push    rsi             ; [frame+16] arg2 (ESI)
    push    rdi             ; [frame+ 8] arg3 (EDI)
    ; rsp = SYSENTER_ESP - 56 (7 pushes).  56 mod 16 = 8 → 8-byte aligned.

    ; Map compat-ABI registers → SysV AMD64 for the Rust dispatcher.
    ; Work higher args first to avoid clobbering sources before they are read.
    ;
    ;   Compat source:  EAX=nr  EBX=a1  ESI=a2  EDI=a3  EBP=a4
    ;   SysV target:    rdi     rsi     rdx     rcx     r8
    mov     r8d, ebp        ; a4 ← EBP  (mov r32,r32 zero-extends to 64-bit; before EBP overwritten)
    mov     ecx, edi        ; a3 ← EDI
    mov     edx, esi        ; a2 ← ESI  (before RSI is overwritten)
    mov     esi, ebx        ; a1 ← EBX  (overwrites RSI; original ESI already in RDX)
    mov     edi, eax        ; nr ← EAX  (overwrites RDI; original EDI already in RCX)
    xor     r9d, r9d        ; a5 = 0
    push    0               ; a6 = 0 → 7th arg (rsp = SYSENTER_ESP-64; 16-byte aligned)
    ; `call` will push return addr → rsp+8 = 16-byte aligned ✓ (SysV ABI)

    extern  oreulius_syscall_dispatch
    call    oreulius_syscall_dispatch

    add     rsp, 8          ; discard pushed a6; rsp = SYSENTER_ESP-56 (frame base)
    ; rax = return value for userspace.

    cli                     ; disable interrupts before returning to user

    ; Restore callee-saved registers (reverse of push order above).
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp

    pop     rdx             ; user return ESP → EDX  (SYSEXIT: ESP ← EDX)
    pop     rcx             ; user return EIP → ECX  (SYSEXIT: EIP ← ECX)

    ; Return to 32-bit compat userspace.
    ; SYSEXIT (no REX.W): EIP←ECX, ESP←EDX, CS/SS from SYSENTER_CS+{16,24}.
    sysexit

section .note.GNU-stack noalloc noexec nowrite progbits
