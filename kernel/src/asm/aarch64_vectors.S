/* AArch64 exception vector table and common handlers for bring-up.
 *
 * The Rust dispatch hook logs synchronous exceptions and may request an
 * `ELR_EL1` advance (e.g. BRK/SVC self-tests) by returning a nonzero byte
 * delta in x0. The Rust hook also receives a pointer to the saved GPR frame
 * so lower-EL SVC exceptions can reuse the shared syscall core.
 */

    .section .text.aarch64_vectors, "ax"
    .align 11

    .global __oreulia_aarch64_vectors_start
    .extern oreulia_aarch64_vector_dispatch

    .set VEC_FRAME_SIZE, 256

    .macro SAVE_GPRS
    sub sp, sp, #VEC_FRAME_SIZE
    stp x0,  x1,  [sp, #0]
    stp x2,  x3,  [sp, #16]
    stp x4,  x5,  [sp, #32]
    stp x6,  x7,  [sp, #48]
    stp x8,  x9,  [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
    .endm

    .macro RESTORE_GPRS
    ldp x0,  x1,  [sp, #0]
    ldp x2,  x3,  [sp, #16]
    ldp x4,  x5,  [sp, #32]
    ldp x6,  x7,  [sp, #48]
    ldp x8,  x9,  [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
    add sp, sp, #VEC_FRAME_SIZE
    .endm

    .macro VECTOR_TABLE_ENTRY handler
    b \handler
    .space (0x80 - 4)
    .endm

    .macro VECTOR_HANDLER name, slot
\name:
    SAVE_GPRS
    mrs x1, ESR_EL1
    mrs x2, ELR_EL1
    mrs x3, SPSR_EL1
    mrs x4, FAR_EL1
    mov x5, sp
    mov x0, #\slot
    bl oreulia_aarch64_vector_dispatch
    cbz x0, 9f
    mrs x1, ELR_EL1
    add x1, x1, x0
    msr ELR_EL1, x1
    isb
9:
    RESTORE_GPRS
    eret
    .endm

__oreulia_aarch64_vectors_start:
    /* Current EL with SP0 */
    VECTOR_TABLE_ENTRY __oreulia_vec_slot0
    VECTOR_TABLE_ENTRY __oreulia_vec_slot1
    VECTOR_TABLE_ENTRY __oreulia_vec_slot2
    VECTOR_TABLE_ENTRY __oreulia_vec_slot3

    /* Current EL with SPx */
    VECTOR_TABLE_ENTRY __oreulia_vec_slot4
    VECTOR_TABLE_ENTRY __oreulia_vec_slot5
    VECTOR_TABLE_ENTRY __oreulia_vec_slot6
    VECTOR_TABLE_ENTRY __oreulia_vec_slot7

    /* Lower EL using AArch64 */
    VECTOR_TABLE_ENTRY __oreulia_vec_slot8
    VECTOR_TABLE_ENTRY __oreulia_vec_slot9
    VECTOR_TABLE_ENTRY __oreulia_vec_slot10
    VECTOR_TABLE_ENTRY __oreulia_vec_slot11

    /* Lower EL using AArch32 */
    VECTOR_TABLE_ENTRY __oreulia_vec_slot12
    VECTOR_TABLE_ENTRY __oreulia_vec_slot13
    VECTOR_TABLE_ENTRY __oreulia_vec_slot14
    VECTOR_TABLE_ENTRY __oreulia_vec_slot15

    VECTOR_HANDLER __oreulia_vec_slot0, 0
    VECTOR_HANDLER __oreulia_vec_slot1, 1
    VECTOR_HANDLER __oreulia_vec_slot2, 2
    VECTOR_HANDLER __oreulia_vec_slot3, 3
    VECTOR_HANDLER __oreulia_vec_slot4, 4
    VECTOR_HANDLER __oreulia_vec_slot5, 5
    VECTOR_HANDLER __oreulia_vec_slot6, 6
    VECTOR_HANDLER __oreulia_vec_slot7, 7
    VECTOR_HANDLER __oreulia_vec_slot8, 8
    VECTOR_HANDLER __oreulia_vec_slot9, 9
    VECTOR_HANDLER __oreulia_vec_slot10, 10
    VECTOR_HANDLER __oreulia_vec_slot11, 11
    VECTOR_HANDLER __oreulia_vec_slot12, 12
    VECTOR_HANDLER __oreulia_vec_slot13, 13
    VECTOR_HANDLER __oreulia_vec_slot14, 14
    VECTOR_HANDLER __oreulia_vec_slot15, 15
