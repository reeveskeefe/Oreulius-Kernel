; x86_64_fpu.asm — FPU/SSE/AVX context management and trapping
;
; Provides the FPU context save/restore functions used by the scheduler
; when switching between tasks that use floating-point or SIMD state.
;
; Exported symbols:
;   fpu_init            — initialize FPU to default state (FNINIT + MXCSR default)
;   fpu_trap_enable     — set CR0.TS so next FP instruction causes #NM trap
;   fpu_trap_disable    — clear CR0.TS (CLTS) — used in #NM handler
;   fpu_context_save    — save FPU/SSE/AVX state (XSAVE, fallback FXSAVE)
;   fpu_context_restore — restore FPU/SSE/AVX state (XRSTOR, fallback FXRSTOR)
;   fpu_context_size    — return size of context save area in bytes
;
; XSAVE region layout (used when XSAVE is available):
;   bytes 0-511:   legacy region (FPU + SSE, same as FXSAVE)
;   bytes 512+:    extended region (AVX, etc.)
;   Total size:    512 + CPUID.(EAX=0Dh,ECX=0).ECX bytes (typically 832 or 1088)
;   Alignment:     64 bytes required
;
; For simplicity the context buffer is assumed to be large enough
; (caller must allocate at least 4096 bytes per context slot).
;
; ABI: System V AMD64

[bits 64]
default rel

; MXCSR default: all exceptions masked, round-to-nearest, flush-to-zero off
MXCSR_DEFAULT equ 0x1F80

; XSAVE feature bits (XCR0):
;   bit 0 = x87 FPU state
;   bit 1 = SSE state
;   bit 2 = AVX state
XSAVE_FEATURES equ 0x7     ; x87 + SSE + AVX

section .text

; ---------------------------------------------------------------------------
; void fpu_init(void)
; Initialize FPU to clean state. Must be called once per CPU during boot.
; ---------------------------------------------------------------------------
global fpu_init
fpu_init:
    fninit                      ; initialize FPU, clear exceptions, tags, etc.
    ; Set MXCSR to default (all exceptions masked, round nearest)
    sub     rsp, 4
    mov     dword [rsp], MXCSR_DEFAULT
    ldmxcsr [rsp]
    add     rsp, 4
    ret

; ---------------------------------------------------------------------------
; void fpu_trap_enable(void)
; Set CR0.TS (Task Switched) bit — causes the next FP/SSE instruction to
; raise #NM (Device Not Available), allowing lazy FPU context switching.
; ---------------------------------------------------------------------------
global fpu_trap_enable
fpu_trap_enable:
    mov     rax, cr0
    or      rax, (1 << 3)       ; bit 3 = TS (Task Switched)
    mov     cr0, rax
    ret

; ---------------------------------------------------------------------------
; void fpu_trap_disable(void)
; Clear CR0.TS bit via CLTS (Clear Task-Switched Flag).
; Must be called in the #NM handler before restoring the FPU context.
; ---------------------------------------------------------------------------
global fpu_trap_disable
fpu_trap_disable:
    clts
    ret

; ---------------------------------------------------------------------------
; void fpu_context_save(void *buf)
; Save current FPU/SSE/AVX state to buf.
; Uses XSAVE if supported, else FXSAVE.
; rdi = 64-byte-aligned buffer (minimum 4096 bytes)
; ---------------------------------------------------------------------------
global fpu_context_save
fpu_context_save:
    ; Check for XSAVE support: CPUID.1:ECX bit 26
    push    rbx
    mov     eax, 1
    cpuid
    test    ecx, (1 << 26)
    pop     rbx
    jz      .use_fxsave

    ; XSAVE: save requested feature bitmap in edx:eax
    ; We want to save x87, SSE, and AVX (bits 0,1,2)
    mov     eax, XSAVE_FEATURES
    xor     edx, edx
    xsave   [rdi]
    ret

.use_fxsave:
    ; FXSAVE saves 512 bytes of x87+SSE state
    fxsave  [rdi]
    ret

; ---------------------------------------------------------------------------
; void fpu_context_restore(const void *buf)
; Restore FPU/SSE/AVX state from buf (inverse of fpu_context_save).
; rdi = 64-byte-aligned buffer previously written by fpu_context_save
; ---------------------------------------------------------------------------
global fpu_context_restore
fpu_context_restore:
    push    rbx
    mov     eax, 1
    cpuid
    test    ecx, (1 << 26)
    pop     rbx
    jz      .use_fxrstor

    mov     eax, XSAVE_FEATURES
    xor     edx, edx
    xrstor  [rdi]
    ret

.use_fxrstor:
    fxrstor [rdi]
    ret

; ---------------------------------------------------------------------------
; usize fpu_context_size(void)
; Return the number of bytes needed for an FPU context save area.
; Returns 4096 as a safe upper bound (XSAVE area is at most ~2688 bytes;
; 4096 ensures natural alignment with page granularity).
; ---------------------------------------------------------------------------
global fpu_context_size
fpu_context_size:
    ; Query XSAVE area size via CPUID leaf 0Dh, sub-leaf 0
    push    rbx
    mov     eax, 0x0D
    xor     ecx, ecx
    cpuid
    ; ecx = size of XSAVE area for all features supported by OS (in ECX/XCR0)
    ; eax = size of required save area for supported sub-leaves
    ; Return the larger of ecx and 512 (FXSAVE minimum)
    cmp     ecx, 512
    cmovl   ecx, eax            ; if ecx < 512, use eax
    ; Round up to 64-byte alignment
    add     ecx, 63
    and     ecx, ~63
    movsx   rax, ecx
    pop     rbx
    ; Ensure minimum of 512 (FXSAVE)
    cmp     rax, 512
    jge     .ok
    mov     rax, 512
.ok:
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
