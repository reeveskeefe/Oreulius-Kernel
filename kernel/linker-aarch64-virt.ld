OUTPUT_FORMAT(elf64-littleaarch64)
OUTPUT_ARCH(aarch64)
ENTRY(_start)

PHDRS {
    text   PT_LOAD FLAGS(5);  /* R + X */
    rodata PT_LOAD FLAGS(4);  /* R */
    data   PT_LOAD FLAGS(6);  /* R + W */
}

SECTIONS {
    /* QEMU virt commonly loads direct kernels around 0x4008_0000. */
    . = 0x40080000;
    __jit_arena_size = 0x4000000; /* 64 MiB - supports multi-MB WASM memories */

    .text.boot : {
        KEEP(*(.text.boot))
        KEEP(*(.text.boot.*))
        . = ALIGN(0x1000);
    } :text

    .text : {
        _text_start = .;
        *(.text)
        *(.text.*)
        . = ALIGN(0x1000);
        _text_end = .;
    } :text

    .rodata : {
        _rodata_start = .;
        *(.rodata)
        *(.rodata.*)
        . = ALIGN(0x1000);
        _rodata_end = .;
    } :rodata

    .data : {
        _data_start = .;
        *(.data)
        *(.data.*)
        . = ALIGN(0x1000);
        _data_end = .;
    } :data

    .bss (NOLOAD) : {
        _bss_start = .;
        . = ALIGN(8);
        sbss = .;
        *(.bss)
        *(.bss.*)
        *(COMMON)
        . = ALIGN(8);
        ebss = .;
        . = ALIGN(16);
        _bss_end = .;
    } :data

    .boot_stack (NOLOAD) : {
        . = ALIGN(16);
        __boot_stack_start = .;
        . += 0x4000; /* 16 KiB early stack */
        __boot_stack_top = .;
    } :data

    . = ALIGN(0x1000);
    _jit_arena_start = .;
    .jit_arena (NOLOAD) : {
        . += __jit_arena_size;
    } :data
    _jit_arena_end = .;

    . = ALIGN(0x1000);
    _heap_start = .;
    .heap (NOLOAD) : {
        . += 0x400000; /* 4 MiB minimal heap for bring-up */
    } :data
    _heap_end = .;
}

