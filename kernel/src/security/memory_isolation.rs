/*!
 * Oreulia Kernel Project
 *
 * License-Identifier: Oreulia Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulia.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

//! Software memory tagging and hardware isolation capability reporting.
//!
//! This module enforces a tagged-physical-range policy for user mappings.
//! Hardware-backed isolation capabilities (SGX/TrustZone) are detected and
//! surfaced so policy can be tightened when those features are present.

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

use crate::asm_bindings;

const PAGE_SIZE: usize = 4096;
const MAX_TAGGED_RANGES: usize = 256;

extern "C" {
    static _text_start: usize;
    static _text_end: usize;
    static _rodata_start: usize;
    static _rodata_end: usize;
    static _data_start: usize;
    static _data_end: usize;
    static _bss_start: usize;
    static _bss_end: usize;
    static _heap_start: usize;
    static _heap_end: usize;
    static _jit_arena_start: usize;
    static _jit_arena_end: usize;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IsolationDomain {
    Unknown = 0,
    KernelText = 1,
    KernelRodata = 2,
    KernelData = 3,
    KernelBss = 4,
    KernelHeap = 5,
    JitArena = 6,
    JitCode = 7,
    WasmLinearMemory = 8,
    JitUserTrampoline = 9,
    JitUserState = 10,
    JitUserStack = 11,
    DeviceMmio = 12,
    EnclaveCode = 13,
    EnclaveData = 14,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessPolicy {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub user_map: bool,
}

impl AccessPolicy {
    pub const fn new(read: bool, write: bool, execute: bool, user_map: bool) -> Self {
        Self {
            read,
            write,
            execute,
            user_map,
        }
    }

    pub const fn kernel_rx() -> Self {
        Self::new(true, false, true, false)
    }

    pub const fn kernel_ro() -> Self {
        Self::new(true, false, false, false)
    }

    pub const fn kernel_rw() -> Self {
        Self::new(true, true, false, false)
    }

    pub const fn user_rx() -> Self {
        Self::new(true, false, true, true)
    }

    pub const fn user_rw() -> Self {
        Self::new(true, true, false, true)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct HardwareIsolationCaps {
    pub sgx_supported: bool,
    pub sgx1_supported: bool,
    pub sgx2_supported: bool,
    pub sgx_launch_control: bool,
    pub trustzone_supported: bool,
}

impl HardwareIsolationCaps {
    pub const fn none() -> Self {
        Self {
            sgx_supported: false,
            sgx1_supported: false,
            sgx2_supported: false,
            sgx_launch_control: false,
            trustzone_supported: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IsolationStatus {
    pub tagging_enabled: bool,
    pub tagged_ranges: usize,
    pub denied_user_mappings: u32,
    pub sgx_supported: bool,
    pub sgx1_supported: bool,
    pub sgx2_supported: bool,
    pub sgx_launch_control: bool,
    pub trustzone_supported: bool,
}

#[derive(Clone, Copy, Debug)]
struct TaggedRange {
    start: usize,
    end: usize,
    domain: IsolationDomain,
    policy: AccessPolicy,
    generation: u32,
    persistent: bool,
}

struct TagTable {
    entries: [Option<TaggedRange>; MAX_TAGGED_RANGES],
    count: usize,
    generation: u32,
}

impl TagTable {
    const fn new() -> Self {
        Self {
            entries: [None; MAX_TAGGED_RANGES],
            count: 0,
            generation: 1,
        }
    }

    fn clear(&mut self) {
        self.entries = [None; MAX_TAGGED_RANGES];
        self.count = 0;
        self.generation = 1;
    }

    fn next_generation(&mut self) -> u32 {
        let out = self.generation.max(1);
        self.generation = self.generation.wrapping_add(1).max(1);
        out
    }

    fn insert(
        &mut self,
        start: usize,
        end: usize,
        domain: IsolationDomain,
        policy: AccessPolicy,
        persistent: bool,
    ) -> Result<(), &'static str> {
        if end <= start {
            return Err("Invalid tag range");
        }

        let aligned_start = align_down(start, PAGE_SIZE);
        let aligned_end = align_up(end, PAGE_SIZE)?;
        if aligned_end <= aligned_start {
            return Err("Invalid aligned tag range");
        }

        let mut target_idx = None;
        let mut empty_idx = None;
        let mut oldest_dynamic_idx = None;
        let mut oldest_generation = u32::MAX;

        for i in 0..self.entries.len() {
            match self.entries[i] {
                Some(entry) => {
                    if entry.start == aligned_start && entry.end == aligned_end {
                        target_idx = Some(i);
                        break;
                    }
                    if !entry.persistent && entry.generation < oldest_generation {
                        oldest_generation = entry.generation;
                        oldest_dynamic_idx = Some(i);
                    }
                }
                None => {
                    if empty_idx.is_none() {
                        empty_idx = Some(i);
                    }
                }
            }
        }

        if target_idx.is_none() {
            target_idx = empty_idx.or(oldest_dynamic_idx);
        }
        let idx = target_idx.ok_or("Tag table exhausted")?;

        let replacing_empty = self.entries[idx].is_none();
        self.entries[idx] = Some(TaggedRange {
            start: aligned_start,
            end: aligned_end,
            domain,
            policy,
            generation: self.next_generation(),
            persistent,
        });
        if replacing_empty {
            self.count += 1;
        }
        Ok(())
    }

    fn find_covering(&self, start: usize, end: usize) -> Option<TaggedRange> {
        let mut best: Option<TaggedRange> = None;
        for entry in self.entries.iter().flatten() {
            if entry.start <= start && end <= entry.end {
                let should_replace = match best {
                    None => true,
                    Some(cur) => {
                        entry.generation > cur.generation
                            || (entry.generation == cur.generation
                                && (entry.end - entry.start) < (cur.end - cur.start))
                    }
                };
                if should_replace {
                    best = Some(*entry);
                }
            }
        }
        best
    }
}

static TAGGING_ENABLED: AtomicBool = AtomicBool::new(false);
static DENIED_USER_MAPPINGS: AtomicU32 = AtomicU32::new(0);
static TAG_TABLE: Mutex<TagTable> = Mutex::new(TagTable::new());
static HW_CAPS: Mutex<HardwareIsolationCaps> = Mutex::new(HardwareIsolationCaps::none());

#[inline]
fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

#[inline]
fn align_up(value: usize, align: usize) -> Result<usize, &'static str> {
    let mask = align - 1;
    value
        .checked_add(mask)
        .map(|v| v & !mask)
        .ok_or("Range overflow")
}

fn detect_hardware_caps() -> HardwareIsolationCaps {
    let max_basic = asm_bindings::cpuid(0, 0).eax;
    let mut caps = HardwareIsolationCaps::none();

    if max_basic >= 7 {
        let leaf7 = asm_bindings::cpuid(7, 0);
        caps.sgx_supported = (leaf7.ebx & (1 << 2)) != 0;
        caps.sgx_launch_control = (leaf7.ecx & (1 << 30)) != 0;
    }

    if caps.sgx_supported && max_basic >= 0x12 {
        let sgx0 = asm_bindings::cpuid(0x12, 0);
        caps.sgx1_supported = (sgx0.eax & 0x1) != 0;
        caps.sgx2_supported = (sgx0.eax & 0x2) != 0;
    }

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    {
        caps.trustzone_supported = true;
    }
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    {
        caps.trustzone_supported = false;
    }

    caps
}

fn register_bootstrap_ranges(table: &mut TagTable) {
    macro_rules! sym {
        ($name:ident) => {{
            unsafe { core::ptr::addr_of!($name) as usize }
        }};
    }

    let _ = table.insert(
        sym!(_text_start),
        sym!(_text_end),
        IsolationDomain::KernelText,
        AccessPolicy::kernel_rx(),
        true,
    );
    let _ = table.insert(
        sym!(_rodata_start),
        sym!(_rodata_end),
        IsolationDomain::KernelRodata,
        AccessPolicy::kernel_ro(),
        true,
    );
    let _ = table.insert(
        sym!(_data_start),
        sym!(_data_end),
        IsolationDomain::KernelData,
        AccessPolicy::kernel_rw(),
        true,
    );
    let _ = table.insert(
        sym!(_bss_start),
        sym!(_bss_end),
        IsolationDomain::KernelBss,
        AccessPolicy::kernel_rw(),
        true,
    );
    let _ = table.insert(
        sym!(_heap_start),
        sym!(_heap_end),
        IsolationDomain::KernelHeap,
        AccessPolicy::kernel_rw(),
        true,
    );
    let _ = table.insert(
        sym!(_jit_arena_start),
        sym!(_jit_arena_end),
        IsolationDomain::JitArena,
        AccessPolicy::kernel_rw(),
        true,
    );
}

pub fn init() {
    let caps = detect_hardware_caps();
    *HW_CAPS.lock() = caps;

    {
        let mut table = TAG_TABLE.lock();
        table.clear();
        register_bootstrap_ranges(&mut table);
    }
    TAGGING_ENABLED.store(true, Ordering::SeqCst);

    crate::vga::print_str("[ISOLATION] Memory tagging enabled\n");
    crate::vga::print_str("[ISOLATION] SGX: ");
    crate::vga::print_str(if caps.sgx_supported {
        "supported"
    } else {
        "unsupported"
    });
    crate::vga::print_str(", TrustZone: ");
    crate::vga::print_str(if caps.trustzone_supported {
        "supported"
    } else {
        "unsupported"
    });
    crate::vga::print_str("\n");
}

pub fn status() -> IsolationStatus {
    let caps = *HW_CAPS.lock();
    let table = TAG_TABLE.lock();
    IsolationStatus {
        tagging_enabled: TAGGING_ENABLED.load(Ordering::SeqCst),
        tagged_ranges: table.count,
        denied_user_mappings: DENIED_USER_MAPPINGS.load(Ordering::SeqCst),
        sgx_supported: caps.sgx_supported,
        sgx1_supported: caps.sgx1_supported,
        sgx2_supported: caps.sgx2_supported,
        sgx_launch_control: caps.sgx_launch_control,
        trustzone_supported: caps.trustzone_supported,
    }
}

pub fn tag_range(
    start: usize,
    len: usize,
    domain: IsolationDomain,
    policy: AccessPolicy,
) -> Result<(), &'static str> {
    struct IrqGuard(u32);
    impl Drop for IrqGuard {
        fn drop(&mut self) {
            unsafe { crate::idt_asm::fast_sti_restore(self.0) };
        }
    }

    if !TAGGING_ENABLED.load(Ordering::SeqCst) {
        return Ok(());
    }
    if start == 0 || len == 0 {
        return Err("Invalid runtime tag range");
    }
    let end = start.checked_add(len).ok_or("Runtime tag overflow")?;
    let mut table = TAG_TABLE.lock();
    // Prevent interrupt-path register/context perturbation while mutating the
    // compact tag table metadata.
    let irq_flags = unsafe { crate::idt_asm::fast_cli_save() };
    let _irq_guard = IrqGuard(irq_flags);
    table.insert(start, end, domain, policy, false)
}

pub fn tag_jit_code_kernel(start: usize, len: usize, sealed_rx: bool) -> Result<(), &'static str> {
    let policy = if sealed_rx {
        AccessPolicy::kernel_rx()
    } else {
        AccessPolicy::kernel_rw()
    };
    tag_range(start, len, IsolationDomain::JitCode, policy)
}

pub fn tag_jit_code_user(start: usize, len: usize) -> Result<(), &'static str> {
    tag_range(
        start,
        len,
        IsolationDomain::JitCode,
        AccessPolicy::user_rx(),
    )
}

pub fn tag_jit_user_trampoline(
    start: usize,
    len: usize,
    user_visible: bool,
) -> Result<(), &'static str> {
    let policy = if user_visible {
        AccessPolicy::user_rx()
    } else {
        AccessPolicy::kernel_rx()
    };
    tag_range(start, len, IsolationDomain::JitUserTrampoline, policy)
}

pub fn tag_jit_user_state(
    start: usize,
    len: usize,
    user_visible: bool,
) -> Result<(), &'static str> {
    let policy = if user_visible {
        AccessPolicy::user_rw()
    } else {
        AccessPolicy::kernel_rw()
    };
    tag_range(start, len, IsolationDomain::JitUserState, policy)
}

pub fn tag_jit_user_stack(
    start: usize,
    len: usize,
    user_visible: bool,
) -> Result<(), &'static str> {
    let policy = if user_visible {
        AccessPolicy::user_rw()
    } else {
        AccessPolicy::kernel_rw()
    };
    tag_range(start, len, IsolationDomain::JitUserStack, policy)
}

pub fn tag_wasm_linear_memory(
    start: usize,
    len: usize,
    user_visible: bool,
) -> Result<(), &'static str> {
    let policy = if user_visible {
        AccessPolicy::user_rw()
    } else {
        AccessPolicy::kernel_rw()
    };
    tag_range(start, len, IsolationDomain::WasmLinearMemory, policy)
}

pub fn validate_mapping_request(
    phys_addr: usize,
    size: usize,
    writable: bool,
    user_accessible: bool,
) -> Result<(), &'static str> {
    if !TAGGING_ENABLED.load(Ordering::SeqCst) || !user_accessible {
        return Ok(());
    }
    if size == 0 {
        return Err("Invalid mapping size");
    }

    let map_start = align_down(phys_addr, PAGE_SIZE);
    let map_end = align_up(
        phys_addr
            .checked_add(size)
            .ok_or("Mapping range overflow")?,
        PAGE_SIZE,
    )?;

    let table = TAG_TABLE.lock();
    let tagged = table
        .find_covering(map_start, map_end)
        .ok_or("Memory isolation denied untagged user mapping")?;
    if !tagged.policy.user_map {
        DENIED_USER_MAPPINGS.fetch_add(1, Ordering::SeqCst);
        return Err("Memory isolation denied supervisor-only range");
    }
    if writable && !tagged.policy.write {
        DENIED_USER_MAPPINGS.fetch_add(1, Ordering::SeqCst);
        return Err("Memory isolation denied writable user mapping");
    }
    Ok(())
}
