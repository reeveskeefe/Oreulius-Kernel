/* Minimal AArch64 QEMU virt boot stub for Rust bring-up.
 *
 * Assumptions:
 * - QEMU `virt` loads this ELF and jumps to `_start`
 * - x0 contains the DTB pointer (QEMU/Linux-style handoff)
 * - EL1 is available for `rust_main` bring-up
 */

    .section .text.boot, "ax"
    .global _start
    .extern rust_main
    .extern arch_aarch64_record_boot_handoff
    .extern sbss
    .extern ebss
    .extern __boot_stack_top

_start:
    /* Preserve x0 (DTB pointer) across BSS clear and Rust calls. */
    mov x19, x0
    /* QEMU direct ELF `-kernel` does not populate x0 on some builds.
     * Fallback to a conventional RAM address where the build/run flow can
     * inject a DTB blob via `-device loader,file=...,addr=...`.
     */
    cbnz x19, 0f
    movz x19, #0x0000
    movk x19, #0x4400, lsl #16   /* 0x4400_0000 */
0:

    /* Install an early boot stack before any BL. */
    ldr x1, =__boot_stack_top
    mov sp, x1

    /* Clear .bss [sbss, ebss). */
    ldr x1, =sbss
    ldr x2, =ebss
1:
    cmp x1, x2
    b.hs 2f
    str xzr, [x1], #8
    b 1b

2:
    mov x0, x19
    bl arch_aarch64_record_boot_handoff
    bl rust_main

3:
    wfe
    b 3b
