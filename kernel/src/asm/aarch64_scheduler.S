/* AArch64 scheduler context-switch hooks for the shared scheduler platform.
 *
 * Context layout matches `kernel/src/scheduler_platform.rs` (AArch64 ProcessContext):
 *   x19..x28, x29(fp), x30(lr), sp, pc, daif, ttbr0_el1, esp_shadow(u32), pad(u32)
 */

    .section .text.aarch64_scheduler, "ax"
    .align 2

    .global aarch64_sched_load_context
    .global aarch64_sched_switch_context
    .global aarch64_thread_start_trampoline
    .global aarch64_kernel_user_entry_trampoline

    .set CTX_X19,      0
    .set CTX_X21,      16
    .set CTX_X23,      32
    .set CTX_X25,      48
    .set CTX_X27,      64
    .set CTX_X29,      80
    .set CTX_SP,       96
    .set CTX_PC,       104
    .set CTX_DAIF,     112
    .set CTX_TTBR0,    120
    .set CTX_ESP_LO32, 128

    .macro SAVE_CALLEE ctx
    stp x19, x20, [\ctx, #(CTX_X19)]
    stp x21, x22, [\ctx, #(CTX_X21)]
    stp x23, x24, [\ctx, #(CTX_X23)]
    stp x25, x26, [\ctx, #(CTX_X25)]
    stp x27, x28, [\ctx, #(CTX_X27)]
    stp x29, x30, [\ctx, #(CTX_X29)]
    .endm

    .macro RESTORE_CALLEE ctx
    ldp x19, x20, [\ctx, #(CTX_X19)]
    ldp x21, x22, [\ctx, #(CTX_X21)]
    ldp x23, x24, [\ctx, #(CTX_X23)]
    ldp x25, x26, [\ctx, #(CTX_X25)]
    ldp x27, x28, [\ctx, #(CTX_X27)]
    ldp x29, x30, [\ctx, #(CTX_X29)]
    .endm

/* x0 = *const ProcessContext, does not return */
aarch64_sched_load_context:
    cbz x0, .Lhalt_forever
    b .Lrestore_context_x0

/* x0 = *mut old_ctx (nullable), x1 = *const new_ctx */
aarch64_sched_switch_context:
    cbz x1, .Lresume_after_switch
    cbz x0, .Lload_only

    SAVE_CALLEE x0
    mov x9, sp
    str x9, [x0, #(CTX_SP)]
    adr x9, .Lresume_after_switch
    str x9, [x0, #(CTX_PC)]
    mrs x9, DAIF
    str x9, [x0, #(CTX_DAIF)]
    mrs x9, TTBR0_EL1
    str x9, [x0, #(CTX_TTBR0)]
    mov x9, sp
    str w9, [x0, #(CTX_ESP_LO32)]

.Lload_only:
    mov x0, x1

.Lrestore_context_x0:
    ldr x10, [x0, #(CTX_TTBR0)]
    cbz x10, 1f
    msr TTBR0_EL1, x10
    dsb ish
    isb
1:
    ldr x11, [x0, #(CTX_DAIF)]
    msr DAIF, x11
    ldr x12, [x0, #(CTX_SP)]
    mov sp, x12
    RESTORE_CALLEE x0
    ldr x13, [x0, #(CTX_PC)]
    br x13

.Lresume_after_switch:
    ret

/* Entry point for a fresh kernel thread context. init_kernel_thread_context() places
 * the target thread entry in x19 and sets pc to this symbol.
 */
aarch64_thread_start_trampoline:
    mov x0, x19
    blr x0
.Lthread_halt:
    wfe
    b .Lthread_halt

/* Fresh user-process entry point.
 *
 * Expected register setup from add_user_process():
 *   x19 = EL0 entry VA
 *   x20 = EL0 stack top
 *   sp  = kernel exception stack
 *
 * SPSR_EL1 is constructed explicitly to reflect AArch64 EL0t mode:
 *   [3:0]  M[3:0]  = 0b0000  (EL0t)
 *   [4]    M[4]    = 0       (AArch64)
 *   [6]    F       = 0       (FIQ not masked — allow preemption from EL1)
 *   [7]    I       = 0       (IRQ not masked)
 *   [8]    A       = 0       (SError not masked)
 *   [9]    D       = 0       (debug not masked for EL0 watchpoint support)
 *   [20]   IL      = 0       (instruction length, set by hardware)
 *   [21]   SS      = 0       (software step, clear)
 *
 * FP/SIMD access (CPACR_EL1.FPEN) is set to 0b11 (no trapping) before the
 * first eret so that EL0 code can use NEON immediately.  This matches the
 * "trap-on-first-use lazy FP save" model we will add once the FP context
 * save/restore path is fully validated; for now we grant FP unconditionally
 * at process creation and save the full V0-V31 register file on each EL0→EL1
 * transition (cost: 512 bytes per context switch — acceptable for MVP).
 */
aarch64_kernel_user_entry_trampoline:
    msr SP_EL0, x20

    /* Enable FP/SIMD for EL0 (CPACR_EL1.FPEN = 0b11, bits [21:20]) */
    mrs x9, CPACR_EL1
    orr x9, x9, #(3 << 20)
    msr CPACR_EL1, x9

    /* Build SPSR_EL1 = EL0t, all mask bits clear */
    mov x9, xzr          /* M[4:0]=0b00000 = EL0t, DAIF=0 */
    msr SPSR_EL1, x9
    msr ELR_EL1, x19
    isb
    eret

.Lhalt_forever:
    wfe
    b .Lhalt_forever
