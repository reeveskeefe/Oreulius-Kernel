ENTRY(_start)

SECTIONS {
    . = 0x100000;
    __jit_arena_size = 0x200000; /* 2 MB dedicated JIT arena */
    
    .multiboot : {
        KEEP(*(.multiboot))
    }
    
    .text : {
        _text_start = .;
        *(.text)
        *(.text.*)
        . = ALIGN(4096);
        _text_end = .;
    }
    
    .rodata : {
        _rodata_start = .;
        *(.rodata)
        *(.rodata.*)
        . = ALIGN(4096);
        _rodata_end = .;
    }
    
    .data : {
        _data_start = .;
        *(.data)
        *(.data.*)
        . = ALIGN(4096);
        _data_end = .;
    }
    
    .bss : {
        _bss_start = .;
        sbss = .;
        *(.bss)
        *(.bss.*)
        *(COMMON)
        ebss = .;
        . = ALIGN(4096);
        _bss_end = .;
    }

    /* Dedicated JIT arena (NOLOAD = not included in binary) */
    . = ALIGN(4096);
    _jit_arena_start = .;
    .jit_arena (NOLOAD) : {
        . += __jit_arena_size;
    }
    _jit_arena_end = .;
    
    /* Define heap region after BSS (NOLOAD = not included in binary) */
    . = ALIGN(4096);
    _heap_start = .;
    .heap (NOLOAD) : {
        . += 0x1000000;  /* 16 MB heap */
    }
    _heap_end = .;
}
