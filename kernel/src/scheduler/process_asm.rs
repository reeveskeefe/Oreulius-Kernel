/*!
 * Oreulius Kernel Project
 *
 * License-Identifier: Oreulius Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulius Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulius.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

// Process management assembly bindings
// Fast context switching, TSS operations, and privilege transitions

/// Task context structure for fast context switching
#[repr(C)]
pub struct TaskContext {
    pub esp: u32,    // Stack pointer
    pub ebp: u32,    // Base pointer
    pub ebx: u32,    // Callee-saved
    pub esi: u32,    // Callee-saved
    pub edi: u32,    // Callee-saved
    pub eip: u32,    // Return address
    pub eflags: u32, // CPU flags
    pub cr3: u32,    // Page directory
}

impl TaskContext {
    pub const fn new() -> Self {
        Self {
            esp: 0,
            ebp: 0,
            ebx: 0,
            esi: 0,
            edi: 0,
            eip: 0,
            eflags: 0x202, // IF flag set
            cr3: 0,
        }
    }
}

extern "C" {
    // TSS Operations
    pub fn tss_load(tss_selector: u16);
    pub fn tss_set_kernel_stack(tss_addr: *mut u32, esp0: u32, ss0: u16);
    pub fn tss_get_esp0(tss_addr: *const u32) -> u32;

    // Context Switching
    pub fn fast_context_switch(from: *mut TaskContext, to: *const TaskContext);

    // Privilege Level Transitions
    pub fn enter_kernel_mode();
    pub fn enter_user_mode(esp: u32, eip: u32, cs: u16, ds: u16);
    pub fn jit_user_enter(esp: u32, eip: u32, cs: u16, ds: u16);

    // FPU/SSE State Management
    pub fn save_fpu_state(buffer: *mut u8); // 512 bytes
    pub fn restore_fpu_state(buffer: *const u8);

    // Interrupt State
    pub fn get_interrupt_state() -> u32;
    pub fn set_interrupt_state(enabled: u32);
    pub fn disable_interrupts_save() -> u32;
    pub fn restore_interrupts(old_state: u32);

    // Spinlocks
    pub fn spinlock_acquire(lock: *mut u32);
    pub fn spinlock_release(lock: *mut u32);
    pub fn spinlock_try_acquire(lock: *mut u32) -> u32;

    // CPU Features
    pub fn get_cpu_vendor(buffer: *mut u8); // 12 bytes
    pub fn get_cpu_features() -> u32;
    pub fn has_sse() -> u32;
    pub fn has_sse2() -> u32;
    pub fn has_avx() -> u32;

    // Port I/O
    pub fn inb(port: u16) -> u8;
    pub fn inw(port: u16) -> u16;
    pub fn inl(port: u16) -> u32;
    pub fn outb(port: u16, value: u8);
    pub fn outw(port: u16, value: u16);
    pub fn outl(port: u16, value: u32);

    // MSR Operations
    pub fn read_msr(msr: u32) -> u64;
    pub fn write_msr(msr: u32, low: u32, high: u32);

    // Performance Counters
    pub fn read_pmc(counter: u32) -> u64;
    pub fn read_tsc_64() -> u64;

    // Memory Operations
    pub fn fast_memcpy(dst: *mut u8, src: *const u8, count: u32);
    pub fn fast_memset(dst: *mut u8, value: u8, count: u32);
    pub fn fast_memcmp(s1: *const u8, s2: *const u8, count: u32) -> i32;

    // Bit Operations
    pub fn find_first_set_bit(value: u32) -> u32;
    pub fn find_last_set_bit(value: u32) -> u32;
    pub fn count_set_bits(value: u32) -> u32;

    // Statistics
    pub fn get_context_switch_count() -> u32;
    pub fn increment_context_switch_count();
    // Note: interrupt_count functions are in idt_asm module
}

/// Safe wrapper for spinlock
pub struct Spinlock {
    lock: u32,
}

impl Spinlock {
    pub const fn new() -> Self {
        Self { lock: 0 }
    }

    pub fn acquire(&mut self) {
        unsafe { spinlock_acquire(&mut self.lock as *mut u32) }
    }

    pub fn release(&mut self) {
        unsafe { spinlock_release(&mut self.lock as *mut u32) }
    }

    pub fn try_acquire(&mut self) -> bool {
        unsafe { spinlock_try_acquire(&mut self.lock as *mut u32) != 0 }
    }
}

/// Safe wrapper for interrupt state management
pub struct InterruptGuard {
    old_state: u32,
}

impl InterruptGuard {
    pub fn new() -> Self {
        Self {
            old_state: unsafe { disable_interrupts_save() },
        }
    }
}

impl Drop for InterruptGuard {
    fn drop(&mut self) {
        unsafe { restore_interrupts(self.old_state) }
    }
}

/// CPU vendor information
pub struct CpuVendor {
    pub vendor: [u8; 12],
}

impl CpuVendor {
    pub fn detect() -> Self {
        let mut vendor = [0u8; 12];
        unsafe { get_cpu_vendor(vendor.as_mut_ptr()) }
        Self { vendor }
    }

    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.vendor).ok()
    }
}

/// CPU feature flags
#[derive(Debug, Clone, Copy)]
pub struct CpuFeatures {
    pub flags: u32,
}

impl CpuFeatures {
    pub fn detect() -> Self {
        Self {
            flags: unsafe { get_cpu_features() },
        }
    }

    pub fn has_sse(&self) -> bool {
        unsafe { has_sse() != 0 }
    }

    pub fn has_sse2(&self) -> bool {
        unsafe { has_sse2() != 0 }
    }

    pub fn has_avx(&self) -> bool {
        unsafe { has_avx() != 0 }
    }

    pub fn has_fpu(&self) -> bool {
        (self.flags & (1 << 0)) != 0
    }

    pub fn has_pse(&self) -> bool {
        (self.flags & (1 << 3)) != 0
    }

    pub fn has_pae(&self) -> bool {
        (self.flags & (1 << 6)) != 0
    }

    pub fn has_apic(&self) -> bool {
        (self.flags & (1 << 9)) != 0
    }
}

/// Port I/O abstraction
pub struct Port<T> {
    port: u16,
    _phantom: core::marker::PhantomData<T>,
}

impl Port<u8> {
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _phantom: core::marker::PhantomData,
        }
    }

    pub fn read(&self) -> u8 {
        unsafe { inb(self.port) }
    }

    pub fn write(&self, value: u8) {
        unsafe { outb(self.port, value) }
    }
}

impl Port<u16> {
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _phantom: core::marker::PhantomData,
        }
    }

    pub fn read(&self) -> u16 {
        unsafe { inw(self.port) }
    }

    pub fn write(&self, value: u16) {
        unsafe { outw(self.port, value) }
    }
}

impl Port<u32> {
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _phantom: core::marker::PhantomData,
        }
    }

    pub fn read(&self) -> u32 {
        unsafe { inl(self.port) }
    }

    pub fn write(&self, value: u32) {
        unsafe { outl(self.port, value) }
    }
}

/// MSR (Model Specific Register) abstraction
pub struct Msr {
    msr: u32,
}

impl Msr {
    pub const fn new(msr: u32) -> Self {
        Self { msr }
    }

    pub fn read(&self) -> u64 {
        unsafe { read_msr(self.msr) }
    }

    pub fn write(&self, value: u64) {
        let low = value as u32;
        let high = (value >> 32) as u32;
        unsafe { write_msr(self.msr, low, high) }
    }
}

// Common MSRs
pub const MSR_APIC_BASE: u32 = 0x1B;
pub const MSR_EFER: u32 = 0xC0000080;
pub const MSR_STAR: u32 = 0xC0000081;
pub const MSR_LSTAR: u32 = 0xC0000082;
pub const MSR_CSTAR: u32 = 0xC0000083;
pub const MSR_SFMASK: u32 = 0xC0000084;
pub const MSR_FS_BASE: u32 = 0xC0000100;
pub const MSR_GS_BASE: u32 = 0xC0000101;
pub const MSR_KERNEL_GS_BASE: u32 = 0xC0000102;
pub const MSR_IA32_SYSENTER_CS: u32 = 0x174;
pub const MSR_IA32_SYSENTER_ESP: u32 = 0x175;
pub const MSR_IA32_SYSENTER_EIP: u32 = 0x176;

/// Performance counter
pub struct PerfCounter {
    counter: u32,
}

impl PerfCounter {
    pub const fn new(counter: u32) -> Self {
        Self { counter }
    }

    pub fn read(&self) -> u64 {
        unsafe { read_pmc(self.counter) }
    }
}

/// Timestamp counter
pub struct Tsc;

impl Tsc {
    pub fn read() -> u64 {
        unsafe { read_tsc_64() }
    }
}

/// Fast memory operations
pub struct FastMem;

impl FastMem {
    pub unsafe fn copy(dst: *mut u8, src: *const u8, count: usize) {
        fast_memcpy(dst, src, count as u32);
    }

    pub unsafe fn set(dst: *mut u8, value: u8, count: usize) {
        fast_memset(dst, value, count as u32);
    }

    pub unsafe fn compare(s1: *const u8, s2: *const u8, count: usize) -> i32 {
        fast_memcmp(s1, s2, count as u32)
    }
}

/// Bit manipulation utilities
pub struct BitOps;

impl BitOps {
    pub fn find_first_set(value: u32) -> Option<u32> {
        let pos = unsafe { find_first_set_bit(value) };
        if pos == 32 {
            None
        } else {
            Some(pos)
        }
    }

    pub fn find_last_set(value: u32) -> Option<u32> {
        let pos = unsafe { find_last_set_bit(value) };
        if pos == 32 {
            None
        } else {
            Some(pos)
        }
    }

    pub fn count_ones(value: u32) -> u32 {
        unsafe { count_set_bits(value) }
    }
}

/// Process statistics
pub struct ProcessStats;

impl ProcessStats {
    pub fn context_switches() -> u32 {
        unsafe { get_context_switch_count() }
    }

    pub fn total_interrupts() -> u32 {
        // Use IDT's interrupt count - pass 0xFF for total count
        unsafe { crate::idt_asm::get_interrupt_count(0xFF) }
    }
}
