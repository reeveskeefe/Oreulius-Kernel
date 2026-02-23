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
    /* Keep the scheduler in the active kernel TTBR0 for now.
     * AArch64 shared scheduler bring-up currently runs kernel threads in the
     * same address space; reloading TTBR0 here can switch into an incomplete
     * root during bring-up and fault before the thread starts.
     */
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

.Lhalt_forever:
    wfe
    b .Lhalt_forever
