OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS {
    text   PT_LOAD FLAGS(5);  /* R + X */
    rodata PT_LOAD FLAGS(4);  /* R */
    data   PT_LOAD FLAGS(6);  /* R + W */
}

SECTIONS {
    . = 0x100000;
    __jit_arena_size = 0x4000000; /* 64 MB dedicated JIT arena - supports multi-MB WASM memories */

    .multiboot2 : {
        KEEP(*(.multiboot2))
    } :text

    .text : {
        _text_start = .;
        *(.text)
        *(.text.*)
        . = ALIGN(4096);
        _text_end = .;
    } :text

    .rodata : {
        _rodata_start = .;
        *(.rodata)
        *(.rodata.*)
        . = ALIGN(4096);
        _rodata_end = .;
    } :rodata

    .data : {
        _data_start = .;
        *(.data)
        *(.data.*)
        . = ALIGN(4096);
        _data_end = .;
    } :data

    .bss : {
        _bss_start = .;
        sbss = .;
        *(.bss)
        *(.bss.*)
        *(COMMON)
        ebss = .;
        . = ALIGN(4096);
        _bss_end = .;
    } :data

    . = ALIGN(4096);
    _jit_arena_start = .;
    .jit_arena (NOLOAD) : {
        . += __jit_arena_size;
    } :data
    _jit_arena_end = .;

    . = ALIGN(4096);
    _heap_start = .;
    .heap (NOLOAD) : {
        . += 0x1000000; /* 16 MB heap */
    } :data
    _heap_end = .;
}
