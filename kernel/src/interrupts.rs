use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
use lazy_static::lazy_static;
use x86_64::instructions::port::Port;
use crate::serial_println;

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt[32].set_handler_fn(timer_handler);
        idt
    };
}

pub fn init_idt() {
    IDT.load();
}

pub fn init_pic() {
    unsafe {
        // ICW1
        Port::<u8>::new(0x20).write(0x11);
        Port::<u8>::new(0xA0).write(0x11);
        // ICW2
        Port::<u8>::new(0x21).write(0x20);
        Port::<u8>::new(0xA1).write(0x28);
        // ICW3
        Port::<u8>::new(0x21).write(0x04);
        Port::<u8>::new(0xA1).write(0x02);
        // ICW4
        Port::<u8>::new(0x21).write(0x01);
        Port::<u8>::new(0xA1).write(0x01);
        // Mask all interrupts except timer
        Port::<u8>::new(0x21).write(0xFE);
        Port::<u8>::new(0xA1).write(0xFF);
    }
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    serial_println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn timer_handler(_stack_frame: InterruptStackFrame) {
    static mut TICKS: u64 = 0;
    unsafe {
        TICKS += 1;
        if TICKS % 1000 == 0 {
            serial_println!("Timer: {} seconds", TICKS / 1000);
        }
    }
    // Acknowledge PIC
    unsafe {
        Port::<u8>::new(0x20).write(0x20);
    }
}