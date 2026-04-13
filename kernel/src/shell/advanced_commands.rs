/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

//! Advanced System Commands - Addendum
//!
//! Additional commands for testing advanced scheduler, memory allocator,
//! and other hardened kernel features

use crate::drivers::x86::vga;

// Helper functions for printing numbers (imported from commands.rs functionality)
fn print_u32(n: u32) {
    if n == 0 {
        vga::print_char('0');
        return;
    }

    let mut buf = [0u8; 10];
    let mut i = 0;
    let mut num = n;

    while num > 0 {
        buf[i] = (num % 10) as u8 + b'0';
        num /= 10;
        i += 1;
    }

    while i > 0 {
        i -= 1;
        vga::print_char(buf[i] as char);
    }
}

fn print_usize(n: usize) {
    print_u32(n as u32);
}

/// Show slice scheduler statistics and process accounting
pub fn cmd_slice_stats() {
    use crate::scheduler::slice_scheduler;

    vga::print_str("Slice Scheduler Statistics\n");
    vga::print_str("============================\n\n");

    let stats = slice_scheduler::scheduler().lock().get_stats();

    vga::print_str("Context Switches:\n");
    vga::print_str("  Total:       ");
    print_u64(stats.total_switches);
    vga::print_str("\n  Preemptions: ");
    print_u64(stats.preemptions);
    vga::print_str("\n  Voluntary:   ");
    print_u64(stats.voluntary_yields);
    vga::print_str("\n\n");

    vga::print_str("Idle Time:\n");
    vga::print_str("  Idle ticks:  ");
    print_u64(stats.idle_ticks);
    vga::print_str("\n\n");

    // List processes with accounting
    vga::print_str("Process Accounting:\n");
    vga::print_str("  PID | CPU Time | Wait Time | Switches | Timeslice\n");
    vga::print_str("  ----+----------+-----------+----------+--------\n");

    let scheduler_guard = slice_scheduler::scheduler().lock();
    let processes = scheduler_guard.list_processes();
    for (pid, info) in processes {
        vga::print_str("  ");
        print_u32(pid.0);
        vga::print_str("   | ");
        print_u64(info.total_cpu_time);
        vga::print_str(" | ");
        print_u64(info.total_wait_time);
        vga::print_str(" | ");
        print_u64(info.switches);
        vga::print_str(" | ");
        print_u32(info.slice_remaining);
        vga::print_str("\n");
    }

    vga::print_str("\n");
}

pub fn cmd_sched_entropy_bench() {
    use crate::scheduler::slice_scheduler;

    vga::print_str("Scheduler Entropy Bench\n");
    vga::print_str("=======================\n\n");
    vga::print_str(
        "Scenarios use the scheduler's canonical EWMA roll + timeslice adjust helpers.\n\n",
    );

    for scenario in slice_scheduler::entropy_bench_results() {
        vga::print_str("Scenario: ");
        vga::print_str(scenario.name);
        vga::print_str("\n  Base timeslice:      ");
        print_u32(scenario.base_slice);
        vga::print_str("\n  Rolled yield EWMA: ");
        print_u32(scenario.rolled_yield_ewma);
        vga::print_str("\n  Rolled fault EWMA: ");
        print_u32(scenario.rolled_fault_ewma);
        vga::print_str("\n  Adjusted timeslice:  ");
        print_u32(scenario.adjusted_slice);
        vga::print_str("\n\n");
    }
}

/// Show hardened allocator statistics
pub fn cmd_alloc_stats() {
    use crate::memory::hardened_allocator;

    vga::print_str("Hardened Allocator Statistics\n");
    vga::print_str("=============================\n\n");

    let stats = hardened_allocator::get_stats();

    vga::print_str("Allocations:\n");
    vga::print_str("  Total allocations:   ");
    print_u64(stats.total_allocations);
    vga::print_str("\n  Total deallocations: ");
    print_u64(stats.total_deallocations);
    vga::print_str("\n  Current allocations: ");
    print_u64(stats.current_allocations);
    vga::print_str("\n  Peak allocations:    ");
    print_u64(stats.peak_allocations);
    vga::print_str("\n\n");

    vga::print_str("Memory Usage:\n");
    vga::print_str("  Bytes allocated:     ");
    print_usize(stats.bytes_allocated);
    vga::print_str("\n  Bytes freed:         ");
    print_usize(stats.bytes_freed);
    vga::print_str("\n  Bytes in use:        ");
    print_usize(stats.bytes_in_use);
    vga::print_str("\n  Peak bytes in use:   ");
    print_usize(stats.peak_bytes_in_use);
    vga::print_str("\n\n");

    vga::print_str("Health:\n");
    vga::print_str("  Fragmentation score: ");
    print_u32((stats.fragmentation_score * 100.0) as u32);
    vga::print_str("%\n");
    vga::print_str("  Guard violations:    ");
    print_u64(stats.guard_page_violations);
    vga::print_str("\n  Canary violations:   ");
    print_u64(stats.canary_violations);
    vga::print_str("\n\n");

    if stats.guard_page_violations > 0 || stats.canary_violations > 0 {
        vga::print_str("⚠ WARNING: Memory corruption detected!\n\n");
    } else {
        vga::print_str("✓ No memory corruption detected\n\n");
    }
}

/// Check for memory leaks (debug builds only)
#[cfg(debug_assertions)]
pub fn cmd_leak_check() {
    use crate::memory::hardened_allocator;

    vga::print_str("Memory Leak Detection\n");
    vga::print_str("=====================\n\n");

    let leaks = hardened_allocator::check_leaks();

    if leaks.is_empty() {
        vga::print_str("✓ No memory leaks detected\n\n");
    } else {
        vga::print_str("⚠ Potential memory leaks:\n\n");
        vga::print_str("  Address          | Size     | Alloc ID\n");
        vga::print_str("  -----------------+----------+---------\n");

        for (addr, size, id) in leaks {
            vga::print_str("  0x");
            print_hex(addr);
            vga::print_str(" | ");
            print_usize(size);
            vga::print_str(" | ");
            print_u64(id);
            vga::print_str("\n");
        }

        vga::print_str("\n");
    }
}

#[cfg(not(debug_assertions))]
pub fn cmd_leak_check() {
    vga::print_str("Leak detection only available in debug builds\n");
}

/// Test futex-like blocking primitives
pub fn cmd_futex_test() {
    use crate::scheduler::slice_scheduler;

    vga::print_str("Futex-like Blocking Primitive Test\n");
    vga::print_str("===================================\n\n");

    // Simulated futex address
    let futex_addr = 0x1000 as usize;

    vga::print_str("1. Testing wait queue creation:\n");
    match slice_scheduler::block_on(futex_addr) {
        Ok(_) => vga::print_str("   ✓ Blocked on address 0x1000\n"),
        Err(e) => {
            vga::print_str("   ✗ Error: ");
            vga::print_str(e);
            vga::print_str("\n");
        }
    }

    vga::print_str("\n2. Testing wake_one:\n");
    match slice_scheduler::wake_one(futex_addr) {
        Ok(true) => vga::print_str("   ✓ Woke one process\n"),
        Ok(false) => vga::print_str("   - No processes waiting\n"),
        Err(e) => {
            vga::print_str("   ✗ Error: ");
            vga::print_str(e);
            vga::print_str("\n");
        }
    }

    vga::print_str("\n3. Testing wake_all:\n");
    match slice_scheduler::wake_all(futex_addr) {
        Ok(count) => {
            vga::print_str("   ✓ Woke ");
            print_usize(count);
            vga::print_str(" processes\n");
        }
        Err(e) => {
            vga::print_str("   ✗ Error: ");
            vga::print_str(e);
            vga::print_str("\n");
        }
    }

    vga::print_str("\nFutex tests completed.\n\n");
}

/// Update fragmentation metrics
pub fn cmd_update_frag() {
    use crate::memory::hardened_allocator;

    vga::print_str("Updating fragmentation metrics...\n");
    let score = hardened_allocator::update_fragmentation();
    vga::print_str("Current fragmentation score: ");
    print_u32((score * 100.0) as u32);
    vga::print_str("%\n");

    if score < 0.1 {
        vga::print_str("Status: Excellent\n");
    } else if score < 0.3 {
        vga::print_str("Status: Good\n");
    } else if score < 0.5 {
        vga::print_str("Status: Moderate\n");
    } else {
        vga::print_str("Status: High fragmentation - consider defragmentation\n");
    }
    vga::print_str("\n");
}

/// Helper to print 64-bit numbers
fn print_u64(n: u64) {
    if n == 0 {
        vga::print_char('0');
        return;
    }

    let mut buf = [0u8; 20];
    let mut i = 0;
    let mut num = n;

    while num > 0 {
        buf[i] = (num % 10) as u8 + b'0';
        num /= 10;
        i += 1;
    }

    while i > 0 {
        i -= 1;
        vga::print_char(buf[i] as char);
    }
}

/// Helper to print hexadecimal
pub fn print_hex(n: usize) {
    let hex_chars = b"0123456789ABCDEF";
    let mut buf = [0u8; 16];
    let mut i = 0;
    let mut num = n;

    if num == 0 {
        vga::print_char('0');
        return;
    }

    while num > 0 {
        buf[i] = hex_chars[(num & 0xF) as usize];
        num >>= 4;
        i += 1;
    }

    while i > 0 {
        i -= 1;
        vga::print_char(buf[i] as char);
    }
}
