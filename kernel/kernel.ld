ENTRY(_start)

SECTIONS {
    . = 0x100000;
    
    .multiboot : {
        KEEP(*(.multiboot))
    }
    
    .text : {
        *(.text)
        *(.text.*)
    }
    
    .rodata : {
        *(.rodata)
        *(.rodata.*)
    }
    
    .data : {
        *(.data)
        *(.data.*)
    }
    
    .bss : {
        *(.bss)
        *(.bss.*)
        *(COMMON)
    }
    
    /* Define heap region after BSS */
    . = ALIGN(4096);
    _heap_start = .;
    . += 0x1000000;  /* 16 MB heap */
    _heap_end = .;
}
