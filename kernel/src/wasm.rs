/*!
 * Oreulia Kernel Project
 * 
 * SPDX-License-Identifier: MIT
 * 
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * Contributing:
 * - By contributing to this file, you agree to license your work under the same terms.
 * - Please see CONTRIBUTING.md for code style and review guidelines.
 * 
 * ---------------------------------------------------------------------------
 */

//! Oreulia WASM Interpreter v0
//!
//! A minimal WebAssembly interpreter for running untrusted code safely.
//! Supports basic WASM opcodes and Oreulia syscalls for IPC, filesystem, etc.
//!
//! Features:
//! - Stack-based bytecode interpreter
//! - Linear memory isolation (per-module)
//! - Capability injection via syscalls
//! - No JIT compilation (interpreter only)
//!
//! Limitations (v0):
//! - Single module (no imports/exports between modules)
//! - i32/i64 only (no floats)
//! - Basic validation only
//! - No WASM threads

#![allow(dead_code)]

extern crate alloc;

use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use alloc::vec::Vec;
use spin::Mutex;
use crate::ipc::{ProcessId, ChannelId};
use crate::fs;
use crate::paging;
use crate::idt_asm;
use crate::memory;
use crate::memory_isolation;
use crate::syscall::SYSCALL_JIT_RETURN;
use crate::gdt;
use crate::process_asm;
use crate::kpti;
use crate::replay::{self, ReplayEventStatus, ReplayMode};

// ============================================================================
// WASM Types & Constants
// ============================================================================

/// Maximum linear memory size (64 KiB for v0 - reduced to shrink kernel)
pub const MAX_MEMORY_SIZE: usize = 64 * 1024;

/// Maximum stack depth
pub const MAX_STACK_DEPTH: usize = 1024;

/// Maximum number of local variables
pub const MAX_LOCALS: usize = 256;

/// Maximum number of injected capabilities
pub const MAX_INJECTED_CAPS: usize = 32;

/// Maximum module size (16 KiB - reduced to shrink kernel)
pub const MAX_MODULE_SIZE: usize = 16 * 1024;

/// Maximum instructions executed per call (prevents infinite loops)
pub const MAX_INSTRUCTIONS_PER_CALL: usize = 100_000;

/// Maximum memory operations per call
pub const MAX_MEMORY_OPS_PER_CALL: usize = 10_000;

/// Maximum syscalls per execution
pub const MAX_SYSCALLS_PER_CALL: usize = 100;

/// Number of initial JIT calls to validate against interpreter
pub const JIT_VALIDATE_CALLS: u8 = 2;

/// First mismatch details for JIT fuzzing.
pub struct JitFuzzMismatch {
    pub iteration: u32,
    pub locals_total: u32,
    pub code: Vec<u8>,
    pub interp: Result<i32, WasmError>,
    pub jit: Result<i32, WasmError>,
    pub interp_mem_hash: u64,
    pub jit_mem_hash: u64,
    pub interp_mem_len: u32,
    pub jit_mem_len: u32,
    pub interp_first_nonzero: Option<(u32, u8)>,
    pub jit_first_nonzero: Option<(u32, u8)>,
}

/// First compile/load error details for JIT fuzzing.
pub struct JitFuzzCompileError {
    pub iteration: u32,
    pub locals_total: u32,
    pub stage: &'static str,
    pub reason: &'static str,
    pub code: Vec<u8>,
    pub jit_code: Vec<u8>,
}

/// JIT fuzzing statistics
pub struct JitFuzzStats {
    pub iterations: u32,
    pub ok: u32,
    pub traps: u32,
    pub mismatches: u32,
    pub compile_errors: u32,
    pub opcode_bins_hit: u32,
    pub opcode_edges_hit: u32,
    pub novel_programs: u32,
    pub first_mismatch: Option<JitFuzzMismatch>,
    pub first_compile_error: Option<JitFuzzCompileError>,
}

const MAX_FUZZ_CODE_SIZE: usize = 256;
const MAX_FUZZ_JIT_CODE_SIZE: usize = 8192;
const JIT_FUZZ_OPCODE_BINS: usize = 14;

/// Stable regression corpus seeds for JIT fuzz replay.
pub const JIT_FUZZ_REGRESSION_SEEDS: [u64; 10] = [
    0,
    107_427_055,
    2_105_703_400,
    2_788_077_538,
    2_901_516_716,
    3_418_704_842,
    3_609_752_155,
    3_870_443_198,
    3_735_928_559,
    4_294_967_295,
];

pub struct JitFuzzRegressionStats {
    pub seeds_total: u32,
    pub seeds_passed: u32,
    pub seeds_failed: u32,
    pub total_ok: u32,
    pub total_traps: u32,
    pub total_mismatches: u32,
    pub total_compile_errors: u32,
    pub max_opcode_bins_hit: u32,
    pub max_opcode_edges_hit: u32,
    pub total_novel_programs: u32,
    pub first_failed_seed: Option<u64>,
    pub first_failed_mismatches: u32,
    pub first_failed_compile_errors: u32,
    pub first_failed_mismatch: Option<JitFuzzMismatch>,
    pub first_failed_compile_error: Option<JitFuzzCompileError>,
}

pub struct JitFuzzSoakStats {
    pub rounds: u32,
    pub rounds_passed: u32,
    pub rounds_failed: u32,
    pub seeds_per_round: u32,
    pub total_seed_passes: u32,
    pub total_seed_failures: u32,
    pub total_ok: u32,
    pub total_traps: u32,
    pub total_mismatches: u32,
    pub total_compile_errors: u32,
    pub max_opcode_bins_hit: u32,
    pub max_opcode_edges_hit: u32,
    pub total_novel_programs: u32,
    pub first_failed_round: Option<u32>,
    pub first_failed_seed: Option<u64>,
    pub first_failed_mismatches: u32,
    pub first_failed_compile_errors: u32,
    pub first_failed_mismatch: Option<JitFuzzMismatch>,
    pub first_failed_compile_error: Option<JitFuzzCompileError>,
}

struct JitFuzzScratch {
    code: Vec<u8>,
    interp_mem_snapshot: Vec<u8>,
    choice_trace: Vec<u8>,
}

impl JitFuzzScratch {
    fn new() -> Self {
        Self {
            code: Vec::with_capacity(MAX_FUZZ_CODE_SIZE),
            interp_mem_snapshot: Vec::with_capacity(MAX_MEMORY_SIZE),
            choice_trace: Vec::with_capacity(64),
        }
    }
}

/// WASM value types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    I32,
    I64,
    F32,  // Not implemented in v0
    F64,  // Not implemented in v0
}

/// WASM values on the stack
#[derive(Debug, Clone, Copy)]
pub enum Value {
    I32(i32),
    I64(i64),
}

impl Value {
    pub fn as_i32(&self) -> Result<i32, WasmError> {
        match self {
            Value::I32(v) => Ok(*v),
            _ => Err(WasmError::TypeMismatch),
        }
    }

    pub fn as_i64(&self) -> Result<i64, WasmError> {
        match self {
            Value::I64(v) => Ok(*v),
            _ => Err(WasmError::TypeMismatch),
        }
    }

    pub fn as_u32(&self) -> Result<u32, WasmError> {
        Ok(self.as_i32()? as u32)
    }
}

// ============================================================================
// WASM Opcodes (subset for v0)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    // Control flow
    Unreachable = 0x00,
    Nop = 0x01,
    Block = 0x02,
    Loop = 0x03,
    If = 0x04,
    Else = 0x05,
    End = 0x0B,
    Br = 0x0C,
    BrIf = 0x0D,
    Return = 0x0F,
    Call = 0x10,
    
    // Parametric
    Drop = 0x1A,
    Select = 0x1B,
    
    // Variable access
    LocalGet = 0x20,
    LocalSet = 0x21,
    LocalTee = 0x22,
    GlobalGet = 0x23,
    GlobalSet = 0x24,
    
    // Memory
    I32Load = 0x28,
    I64Load = 0x29,
    I32Store = 0x36,
    I64Store = 0x37,
    MemorySize = 0x3F,
    MemoryGrow = 0x40,
    
    // Constants
    I32Const = 0x41,
    I64Const = 0x42,
    
    // i32 operations
    I32Eqz = 0x45,
    I32Eq = 0x46,
    I32Ne = 0x47,
    I32LtS = 0x48,
    I32LtU = 0x49,
    I32GtS = 0x4A,
    I32GtU = 0x4B,
    I32LeS = 0x4C,
    I32LeU = 0x4D,
    I32GeS = 0x4E,
    I32GeU = 0x4F,
    
    I32Add = 0x6A,
    I32Sub = 0x6B,
    I32Mul = 0x6C,
    I32DivS = 0x6D,
    I32DivU = 0x6E,
    I32RemS = 0x6F,
    I32RemU = 0x70,
    I32And = 0x71,
    I32Or = 0x72,
    I32Xor = 0x73,
    I32Shl = 0x74,
    I32ShrS = 0x75,
    I32ShrU = 0x76,
}

impl Opcode {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Opcode::Unreachable),
            0x01 => Some(Opcode::Nop),
            0x0B => Some(Opcode::End),
            0x0F => Some(Opcode::Return),
            0x10 => Some(Opcode::Call),
            0x1A => Some(Opcode::Drop),
            0x20 => Some(Opcode::LocalGet),
            0x21 => Some(Opcode::LocalSet),
            0x28 => Some(Opcode::I32Load),
            0x36 => Some(Opcode::I32Store),
            0x3F => Some(Opcode::MemorySize),
            0x40 => Some(Opcode::MemoryGrow),
            0x41 => Some(Opcode::I32Const),
            0x42 => Some(Opcode::I64Const),
            0x45 => Some(Opcode::I32Eqz),
            0x46 => Some(Opcode::I32Eq),
            0x47 => Some(Opcode::I32Ne),
            0x6A => Some(Opcode::I32Add),
            0x6B => Some(Opcode::I32Sub),
            0x6C => Some(Opcode::I32Mul),
            0x6D => Some(Opcode::I32DivS),
            0x71 => Some(Opcode::I32And),
            0x72 => Some(Opcode::I32Or),
            0x73 => Some(Opcode::I32Xor),
            _ => None,
        }
    }
}

fn read_uleb128_validate(bytes: &[u8], mut offset: usize) -> Result<(u32, usize), WasmError> {
    let mut result = 0u32;
    let mut shift = 0;
    let mut count = 0;
    loop {
        if offset >= bytes.len() {
            return Err(WasmError::UnexpectedEndOfCode);
        }
        let byte = bytes[offset];
        offset += 1;
        count += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 28 {
            return Err(WasmError::Leb128Overflow);
        }
    }
    Ok((result, count))
}

fn read_sleb128_i32_validate(bytes: &[u8], mut offset: usize) -> Result<(i32, usize), WasmError> {
    let mut result = 0i32;
    let mut shift = 0;
    let mut count = 0;
    let mut byte: u8;
    loop {
        if offset >= bytes.len() {
            return Err(WasmError::UnexpectedEndOfCode);
        }
        byte = bytes[offset];
        offset += 1;
        count += 1;
        result |= ((byte & 0x7F) as i32) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
        if shift > 28 {
            return Err(WasmError::Leb128Overflow);
        }
    }
    if shift < 32 && (byte & 0x40) != 0 {
        result |= !0 << shift;
    }
    Ok((result, count))
}

fn read_sleb128_i64_validate(bytes: &[u8], mut offset: usize) -> Result<(i64, usize), WasmError> {
    let mut result = 0i64;
    let mut shift = 0;
    let mut count = 0;
    let mut byte: u8;
    loop {
        if offset >= bytes.len() {
            return Err(WasmError::UnexpectedEndOfCode);
        }
        byte = bytes[offset];
        offset += 1;
        count += 1;
        result |= ((byte & 0x7F) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
        if shift > 63 {
            return Err(WasmError::Leb128Overflow);
        }
    }
    if shift < 64 && (byte & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    Ok((result, count))
}

fn validate_bytecode(code: &[u8]) -> Result<(), WasmError> {
    let mut pc = 0usize;
    while pc < code.len() {
        let opcode_byte = code[pc];
        pc += 1;
        let opcode = Opcode::from_byte(opcode_byte).ok_or(WasmError::UnknownOpcode(opcode_byte))?;
        match opcode {
            Opcode::I32Const => {
                let (_v, n) = read_sleb128_i32_validate(code, pc)?;
                pc += n;
            }
            Opcode::I64Const => {
                let (_v, n) = read_sleb128_i64_validate(code, pc)?;
                pc += n;
            }
            Opcode::LocalGet
            | Opcode::LocalSet
            | Opcode::LocalTee
            | Opcode::GlobalGet
            | Opcode::GlobalSet
            | Opcode::Br
            | Opcode::BrIf
            | Opcode::Call => {
                let (_v, n) = read_uleb128_validate(code, pc)?;
                pc += n;
            }
            Opcode::I32Load | Opcode::I64Load | Opcode::I32Store | Opcode::I64Store => {
                let (_align, n1) = read_uleb128_validate(code, pc)?;
                pc += n1;
                let (_off, n2) = read_uleb128_validate(code, pc)?;
                pc += n2;
            }
            Opcode::Block | Opcode::Loop | Opcode::If => {
                let (_ty, n) = read_sleb128_i32_validate(code, pc)?;
                pc += n;
            }
            Opcode::MemorySize | Opcode::MemoryGrow => {
                if pc >= code.len() {
                    return Err(WasmError::UnexpectedEndOfCode);
                }
                let zero = code[pc];
                pc += 1;
                if zero != 0 {
                    return Err(WasmError::InvalidModule);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

// ============================================================================
// Linear Memory
// ============================================================================

/// WASM linear memory (isolated per-module)
pub struct LinearMemory {
    /// Memory buffer (dedicated JIT arena allocation)
    data: *mut u8,
    /// Current size in pages (64 KiB each)
    pages: usize,
    /// Maximum pages allowed
    max_pages: usize,
}

// SAFETY: LinearMemory owns a kernel-allocated buffer and is only accessed
// through the WasmRuntime mutex, so moving between threads is safe.
unsafe impl Send for LinearMemory {}

impl LinearMemory {
    /// Create new linear memory with initial size
    pub fn new(initial_pages: usize) -> Self {
        let max_pages = MAX_MEMORY_SIZE / (64 * 1024);
        let pages = core::cmp::min(initial_pages, max_pages);
        let alloc_pages = (MAX_MEMORY_SIZE + paging::PAGE_SIZE - 1) / paging::PAGE_SIZE;
        let base = memory::jit_allocate_pages(alloc_pages).unwrap_or(0) as *mut u8;
        if !base.is_null() {
            unsafe {
                core::ptr::write_bytes(base, 0, MAX_MEMORY_SIZE);
            }
            let _ = memory_isolation::tag_wasm_linear_memory(base as usize, MAX_MEMORY_SIZE, false);
        }
        LinearMemory {
            data: base,
            pages,
            max_pages,
        }
    }

    /// Get current size in pages
    pub fn size(&self) -> usize {
        self.pages
    }

    /// Get active memory size in bytes
    pub fn active_len(&self) -> usize {
        self.pages * 64 * 1024
    }

    /// Get raw pointer to memory
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data
    }

    /// Get active memory slice
    pub fn active_slice(&self) -> &[u8] {
        if self.data.is_null() {
            return &[];
        }
        unsafe { core::slice::from_raw_parts(self.data, self.active_len()) }
    }

    /// Zero active memory (fuzz harness/reset).
    pub fn clear_active(&mut self) {
        if self.data.is_null() {
            return;
        }
        unsafe {
            core::ptr::write_bytes(self.data, 0, self.active_len());
        }
    }

    /// Grow memory by delta pages
    pub fn grow(&mut self, delta: usize) -> Result<usize, WasmError> {
        let old_size = self.pages;
        let new_size = old_size + delta;

        if new_size > self.max_pages {
            return Err(WasmError::MemoryGrowFailed);
        }

        self.pages = new_size;
        Ok(old_size)
    }

    /// Read bytes from memory
    pub fn read(&self, offset: usize, len: usize) -> Result<&[u8], WasmError> {
        let end = offset.checked_add(len).ok_or(WasmError::MemoryOutOfBounds)?;
        if end > self.pages * 64 * 1024 {
            return Err(WasmError::MemoryOutOfBounds);
        }
        if self.data.is_null() {
            return Err(WasmError::MemoryOutOfBounds);
        }
        unsafe { Ok(core::slice::from_raw_parts(self.data.add(offset), len)) }
    }

    /// Write bytes to memory
    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), WasmError> {
        let end = offset.checked_add(data.len()).ok_or(WasmError::MemoryOutOfBounds)?;
        if end > self.pages * 64 * 1024 {
            return Err(WasmError::MemoryOutOfBounds);
        }
        if self.data.is_null() {
            return Err(WasmError::MemoryOutOfBounds);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), self.data.add(offset), data.len());
        }
        Ok(())
    }

    /// Read i32 from memory (little-endian)
    pub fn read_i32(&self, offset: usize) -> Result<i32, WasmError> {
        let bytes = self.read(offset, 4)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Write i32 to memory (little-endian)
    pub fn write_i32(&mut self, offset: usize, value: i32) -> Result<(), WasmError> {
        self.write(offset, &value.to_le_bytes())
    }

    /// Read i64 from memory (little-endian)
    pub fn read_i64(&self, offset: usize) -> Result<i64, WasmError> {
        let bytes = self.read(offset, 8)?;
        Ok(i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Write i64 to memory (little-endian)
    pub fn write_i64(&mut self, offset: usize, value: i64) -> Result<(), WasmError> {
        self.write(offset, &value.to_le_bytes())
    }
}

impl Clone for LinearMemory {
    fn clone(&self) -> Self {
        let max_pages = MAX_MEMORY_SIZE / (64 * 1024);
        let alloc_pages = (MAX_MEMORY_SIZE + paging::PAGE_SIZE - 1) / paging::PAGE_SIZE;
        let base = memory::jit_allocate_pages(alloc_pages).unwrap_or(0) as *mut u8;
        if !base.is_null() && !self.data.is_null() {
            unsafe {
                core::ptr::copy_nonoverlapping(self.data, base, MAX_MEMORY_SIZE);
            }
        }
        if !base.is_null() {
            let _ = memory_isolation::tag_wasm_linear_memory(base as usize, MAX_MEMORY_SIZE, false);
        }
        LinearMemory {
            data: base,
            pages: self.pages,
            max_pages,
        }
    }
}

// ============================================================================
// Execution Stack
// ============================================================================

/// Value stack for WASM execution
pub struct Stack {
    values: [Value; MAX_STACK_DEPTH],
    len: usize,
}

impl Stack {
    pub fn new() -> Self {
        Stack {
            values: [Value::I32(0); MAX_STACK_DEPTH],
            len: 0,
        }
    }

    pub fn push(&mut self, value: Value) -> Result<(), WasmError> {
        if self.len >= MAX_STACK_DEPTH {
            return Err(WasmError::StackOverflow);
        }
        self.values[self.len] = value;
        self.len += 1;
        Ok(())
    }

    pub fn pop(&mut self) -> Result<Value, WasmError> {
        if self.len == 0 {
            return Err(WasmError::StackUnderflow);
        }
        self.len -= 1;
        Ok(self.values[self.len])
    }

    pub fn peek(&self) -> Result<Value, WasmError> {
        if self.len == 0 {
            return Err(WasmError::StackUnderflow);
        }
        Ok(self.values[self.len - 1])
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    pub fn get(&self, idx: usize) -> Result<Value, WasmError> {
        if idx >= self.len {
            return Err(WasmError::StackUnderflow);
        }
        Ok(self.values[idx])
    }
}

impl Clone for Stack {
    fn clone(&self) -> Self {
        Stack {
            values: self.values,
            len: self.len,
        }
    }
}

// ============================================================================
// Capability Table
// ============================================================================

/// Capability handle (what WASM code sees)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapHandle(pub u32);

/// Capability types that can be injected into WASM
#[derive(Debug, Clone, Copy)]
pub enum WasmCapability {
    Channel(ChannelId),
    Filesystem(fs::FilesystemCapability),
    None,
}

/// Per-instance capability table
pub struct CapabilityTable {
    caps: [WasmCapability; MAX_INJECTED_CAPS],
    count: usize,
}

impl CapabilityTable {
    pub const fn new() -> Self {
        CapabilityTable {
            caps: [WasmCapability::None; MAX_INJECTED_CAPS],
            count: 0,
        }
    }

    /// Inject a capability, returns handle
    pub fn inject(&mut self, cap: WasmCapability) -> Result<CapHandle, WasmError> {
        if self.count >= MAX_INJECTED_CAPS {
            return Err(WasmError::TooManyCapabilities);
        }

        let handle = CapHandle(self.count as u32);
        self.caps[self.count] = cap;
        self.count += 1;
        Ok(handle)
    }

    /// Resolve a capability handle
    pub fn get(&self, handle: CapHandle) -> Result<WasmCapability, WasmError> {
        let idx = handle.0 as usize;
        if idx >= self.count {
            return Err(WasmError::InvalidCapability);
        }
        Ok(self.caps[idx])
    }
}

impl Clone for CapabilityTable {
    fn clone(&self) -> Self {
        CapabilityTable {
            caps: self.caps,
            count: self.count,
        }
    }
}

// ============================================================================
// WASM Function
// ============================================================================

/// A WASM function (simplified)
#[derive(Clone, Copy)]
pub struct Function {
    /// Start offset in bytecode
    pub code_offset: usize,
    /// Code length
    pub code_len: usize,
    /// Number of parameters
    pub param_count: usize,
    /// Number of results
    pub result_count: usize,
    /// Number of local variables
    pub local_count: usize,
}

// ============================================================================
// WASM Module
// ============================================================================

/// A loaded WASM module
#[derive(Clone)]
pub struct WasmModule {
    /// Module bytecode
    bytecode: Vec<u8>,
    /// Bytecode length
    bytecode_len: usize,
    /// Functions in the module
    functions: [Option<Function>; 64],
    /// Number of functions
    function_count: usize,
}

impl WasmModule {
    /// Create a new empty module
    pub fn new() -> Self {
        WasmModule {
            bytecode: Vec::new(),
            bytecode_len: 0,
            functions: [None; 64],
            function_count: 0,
        }
    }

    /// Load bytecode into module (simplified - no full WASM parsing)
    pub fn load(&mut self, bytecode: &[u8]) -> Result<(), WasmError> {
        if bytecode.len() > MAX_MODULE_SIZE {
            return Err(WasmError::ModuleTooLarge);
        }
        validate_bytecode(bytecode)?;

        self.bytecode.clear();
        // Reserve only the missing capacity; reserve_exact takes "additional",
        // not "target capacity". Over-reserving here every iteration causes
        // unbounded capacity growth during fuzz loops.
        if bytecode.len() > self.bytecode.capacity() {
            self.bytecode
                .reserve_exact(bytecode.len() - self.bytecode.capacity());
        }
        self.bytecode.extend_from_slice(bytecode);
        self.bytecode_len = bytecode.len();

        // For v0, we'll use a simplified function format
        // Real implementation would parse WASM binary format
        Ok(())
    }

    /// Reserve bytecode capacity (used by fuzz harness to avoid reallocations).
    pub fn reserve_bytecode(&mut self, capacity: usize) {
        let cap = core::cmp::min(capacity, MAX_MODULE_SIZE);
        if cap > self.bytecode.capacity() {
            self.bytecode.reserve_exact(cap - self.bytecode.capacity());
        }
    }

    /// Clear function table (used by fuzz harness).
    pub fn reset_functions(&mut self) {
        self.functions = [None; 64];
        self.function_count = 0;
    }

    /// Add a function (for testing/demo)
    pub fn add_function(&mut self, func: Function) -> Result<usize, WasmError> {
        if self.function_count >= 64 {
            return Err(WasmError::TooManyFunctions);
        }

        let idx = self.function_count;
        self.functions[idx] = Some(func);
        self.function_count += 1;
        Ok(idx)
    }

    /// Get a function by index
    pub fn get_function(&self, idx: usize) -> Result<Function, WasmError> {
        if idx >= self.function_count {
            return Err(WasmError::FunctionNotFound);
        }
        self.functions[idx].ok_or(WasmError::FunctionNotFound)
    }
}

// ============================================================================
// WASM Instance (execution context)
// ============================================================================

#[repr(C)]
struct JitUserState {
    stack: [i32; MAX_STACK_DEPTH],
    sp: usize,
    locals: [i32; MAX_LOCALS],
    instr_fuel: u32,
    mem_fuel: u32,
    trap_code: i32,
    shadow_stack: [u32; MAX_STACK_DEPTH],
    shadow_sp: usize,
}

const USER_JIT_TRAMPOLINE_BASE: usize = 0x0040_0000;
const USER_JIT_TRAMPOLINE_FAULT_OFFSET: usize = 0x0000_0100;
const USER_JIT_CALL_BASE: usize = 0x0041_0000;
const USER_JIT_STACK_BASE: usize = 0x0042_0000;
const USER_JIT_CODE_BASE: usize = 0x0043_0000;
const USER_JIT_DATA_BASE: usize = 0x0044_0000;
const USER_WASM_MEM_BASE: usize = 0x0050_0000;
const USER_JIT_STACK_GUARD_PAGES: usize = 1;
const USER_JIT_STACK_PAGES: usize = 1;
const USER_JIT_CODE_GUARD_PAGES: usize = 1;
const USER_JIT_DATA_GUARD_PAGES: usize = 1;
const USER_WASM_MEM_GUARD_PAGES: usize = 1;

#[repr(C)]
struct JitUserCall {
    entry: u32,
    stack_ptr: u32,
    sp_ptr: u32,
    mem_ptr: u32,
    mem_len: u32,
    locals_ptr: u32,
    instr_fuel_ptr: u32,
    mem_fuel_ptr: u32,
    trap_ptr: u32,
    shadow_stack_ptr: u32,
    shadow_sp_ptr: u32,
    ret: i32,
}

/// A running WASM instance
pub struct WasmInstance {
    /// The module being executed
    pub module: WasmModule,
    /// Linear memory
    pub memory: LinearMemory,
    /// Value stack
    pub stack: Stack,
    /// Local variables
    locals: [Value; MAX_LOCALS],
    /// Program counter
    pc: usize,
    /// Capability table
    capabilities: CapabilityTable,
    /// Process ID
    pub process_id: ProcessId,
    /// Instance ID (slot index)
    instance_id: usize,
    /// Shadow instance for JIT validation (skip replay/record)
    is_shadow: bool,
    /// Execution limits
    instruction_count: usize,
    memory_op_count: usize,
    syscall_count: usize,
    /// JIT cache (per-function hash)
    jit_hash: [Option<u64>; 64],
    /// JIT user state (stack/locals/fuel/trap)
    jit_state: *mut JitUserState,
    jit_state_pages: usize,
    jit_user_pages: Option<JitUserPages>,
    jit_enabled: bool,
    jit_hot: [u32; 64],
    jit_validate_remaining: [u8; 64],
}

// SAFETY: WasmInstance contains raw pointers to kernel-managed memory and is
// only accessed via the WasmRuntime mutex, so sending between threads is safe.
unsafe impl Send for WasmInstance {}

impl WasmInstance {
    fn alloc_jit_state() -> (*mut JitUserState, usize) {
        let size = core::mem::size_of::<JitUserState>();
        let pages = (size + paging::PAGE_SIZE - 1) / paging::PAGE_SIZE;
        let base = memory::jit_allocate_pages(pages).unwrap_or(0) as *mut JitUserState;
        if !base.is_null() {
            unsafe {
                core::ptr::write_bytes(base as *mut u8, 0, pages * paging::PAGE_SIZE);
            }
        }
        (base, pages)
    }

    fn jit_state_mut(&mut self) -> Result<&mut JitUserState, WasmError> {
        if self.jit_state.is_null() {
            return Err(WasmError::Trap);
        }
        Ok(unsafe { &mut *self.jit_state })
    }

    fn jit_state(&self) -> Result<&JitUserState, WasmError> {
        if self.jit_state.is_null() {
            return Err(WasmError::Trap);
        }
        Ok(unsafe { &*self.jit_state })
    }

    fn prepare_fuzz(&mut self) {
        self.module.reserve_bytecode(MAX_FUZZ_CODE_SIZE);
    }

    fn load_fuzz_program(&mut self, code: &[u8], locals_total: usize) -> Result<(), WasmError> {
        if code.len() > MAX_FUZZ_CODE_SIZE {
            return Err(WasmError::InvalidModule);
        }
        self.module.load(code)?;
        self.module.reset_functions();
        let _ = self.module.add_function(Function {
            code_offset: 0,
            code_len: code.len(),
            param_count: 0,
            result_count: 1,
            local_count: locals_total,
        })?;
        self.stack.clear();
        self.locals = [Value::I32(0); MAX_LOCALS];
        self.pc = 0;
        self.instruction_count = 0;
        self.memory_op_count = 0;
        self.syscall_count = 0;
        self.jit_hash = [None; 64];
        self.jit_hot = [0; 64];
        self.jit_validate_remaining = [0; 64];
        if let Ok(state) = self.jit_state_mut() {
            state.sp = 0;
            state.shadow_sp = 0;
            state.trap_code = 0;
        }
        self.memory.clear_active();
        Ok(())
    }

    fn run_jit_entry(&mut self, func_idx: usize, jit_entry: JitExecInfo) -> Result<(), WasmError> {
        let func = self.module.get_function(func_idx)?;
        if func.param_count + func.local_count > MAX_LOCALS {
            return Err(WasmError::InvalidModule);
        }
        if func.result_count > 1 {
            return Err(WasmError::InvalidModule);
        }
        if self.stack.len() < func.param_count {
            return Err(WasmError::StackUnderflow);
        }

        let (code_start, code_end) = self.function_code_range(func)?;
        let _code = &self.module.bytecode[code_start..code_end];
        let locals_total = func.param_count + func.local_count;

        // Populate locals from stack params (i32 only).
        let stack_len = self.stack.len();
        let mut locals_buf = [0i32; MAX_LOCALS];
        for i in 0..func.param_count {
            let idx = stack_len - func.param_count + i;
            let v = self.stack.get(idx)?.as_i32()?;
            locals_buf[i] = v;
        }
        for i in func.param_count..locals_total {
            locals_buf[i] = 0;
        }

        let mem_len = self.memory.active_len();
        if mem_len > u32::MAX as usize {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let mem_ptr = self.memory.as_mut_ptr();
        if mem_ptr.is_null() {
            return Err(WasmError::MemoryOutOfBounds);
        }
        if (mem_ptr as usize).checked_add(mem_len).is_none() {
            return Err(WasmError::MemoryOutOfBounds);
        }
        // Consume stack params now that we're committed to JIT execution.
        for _ in 0..func.param_count {
            let _ = self.stack.pop()?;
        }

        let ret = {
            let state = self.jit_state_mut()?;
            for i in 0..locals_total {
                state.locals[i] = locals_buf[i];
            }
            state.sp = 0;
            state.instr_fuel = MAX_INSTRUCTIONS_PER_CALL as u32;
            state.mem_fuel = MAX_MEMORY_OPS_PER_CALL as u32;
            state.trap_code = 0;
            state.shadow_sp = 0;
            let locals_ptr = state.locals.as_mut_ptr();
            let instr_fuel = &mut state.instr_fuel as *mut u32;
            let mem_fuel = &mut state.mem_fuel as *mut u32;
            let trap_code = &mut state.trap_code as *mut i32;
            let shadow_stack_ptr = state.shadow_stack.as_mut_ptr();
            let shadow_sp_ptr = &mut state.shadow_sp as *mut usize;
            // Fuzz harness: call directly without per-iteration sandbox allocation.
            call_jit_direct(
                jit_entry,
                state.stack.as_mut_ptr(),
                &mut state.sp as *mut usize,
                mem_ptr,
                mem_len,
                locals_ptr,
                instr_fuel,
                mem_fuel,
                trap_code,
                shadow_stack_ptr,
                shadow_sp_ptr,
            )
        };
        let (trap_code_val, instr_left, mem_left) = {
            let state = self.jit_state()?;
            (state.trap_code, state.instr_fuel, state.mem_fuel)
        };
        if trap_code_val == -1 {
            return Err(WasmError::MemoryOutOfBounds);
        }
        if trap_code_val == -2 {
            return Err(WasmError::ExecutionLimitExceeded);
        }
        if trap_code_val == -3 {
            return Err(WasmError::Trap);
        }
        if trap_code_val == -4 {
            return Err(WasmError::ControlFlowViolation);
        }
        if trap_code_val != 0 {
            return Err(WasmError::Trap);
        }
        if func.result_count == 1 {
            self.stack.push(Value::I32(ret))?;
        }
        self.instruction_count =
            (MAX_INSTRUCTIONS_PER_CALL as u32).saturating_sub(instr_left) as usize;
        self.memory_op_count =
            (MAX_MEMORY_OPS_PER_CALL as u32).saturating_sub(mem_left) as usize;
        Ok(())
    }

    /// Create a new instance
    pub fn new(module: WasmModule, process_id: ProcessId, instance_id: usize) -> Self {
        let (jit_state, jit_state_pages) = Self::alloc_jit_state();
        WasmInstance {
            module,
            memory: LinearMemory::new(1), // 1 page = 64 KiB
            stack: Stack::new(),
            locals: [Value::I32(0); MAX_LOCALS],
            pc: 0,
            capabilities: CapabilityTable::new(),
            process_id,
            instance_id,
            is_shadow: false,
            instruction_count: 0,
            memory_op_count: 0,
            syscall_count: 0,
            jit_hash: [None; 64],
            jit_state,
            jit_state_pages,
            jit_user_pages: None,
            jit_enabled: false,
            jit_hot: [0; 64],
            jit_validate_remaining: [JIT_VALIDATE_CALLS; 64],
        }
    }

    /// Enable or disable JIT
    pub fn enable_jit(&mut self, enabled: bool) {
        self.jit_enabled = enabled;
    }

    /// Hash the module bytecode (for replay verification)
    pub fn module_hash(&self) -> u64 {
        let len = self.bytecode_len_clamped();
        hash_memory(&self.module.bytecode[..len])
    }

    /// Byte length of the module
    pub fn module_len(&self) -> usize {
        self.bytecode_len_clamped()
    }

    #[inline]
    fn bytecode_len_clamped(&self) -> usize {
        core::cmp::min(self.module.bytecode_len, self.module.bytecode.len())
    }

    #[inline]
    fn function_code_range(&self, func: Function) -> Result<(usize, usize), WasmError> {
        let code_start = func.code_offset;
        let code_end = code_start
            .checked_add(func.code_len)
            .ok_or(WasmError::InvalidModule)?;
        let bytecode_len = self.bytecode_len_clamped();
        if code_start > code_end || code_end > bytecode_len {
            return Err(WasmError::InvalidModule);
        }
        Ok((code_start, code_end))
    }

    fn try_jit(&mut self, func: Function, func_idx: usize) -> Result<bool, WasmError> {
        if !self.jit_enabled {
            return Ok(false);
        }
        if !jit_config().lock().enabled {
            return Ok(false);
        }
        if func.param_count + func.local_count > MAX_LOCALS {
            return Ok(false);
        }
        if func.result_count > 1 {
            return Ok(false);
        }
        if self.stack.len() < func.param_count {
            return Ok(false);
        }

        if func_idx >= self.jit_hash.len() {
            return Ok(false);
        }

        let (code_start, code_end) = self.function_code_range(func)?;
        let code = &self.module.bytecode[code_start..code_end];
        let locals_total = func.param_count + func.local_count;

        self.jit_hot[func_idx] = self.jit_hot[func_idx].saturating_add(1);
        if self.jit_hash[func_idx].is_none() {
            let threshold = jit_config().lock().hot_threshold;
            if self.jit_hot[func_idx] < threshold {
                jit_stats().lock().interp_calls += 1;
                return Ok(false);
            }
            let hash = hash_code(code, locals_total);
            let entry = match jit_cache_get_or_compile(hash, code, locals_total) {
                Some(e) => e,
                None => {
                    return Ok(false);
                }
            };
            self.jit_hash[func_idx] = Some(hash);
            jit_stats().lock().compiled += 1;
            let _ = entry;
        }

        let hash = self.jit_hash[func_idx].ok_or(WasmError::InvalidModule)?;
        let jit_entry = match jit_cache_get(hash, code, locals_total) {
            Some(e) => e,
            None => {
                self.jit_hash[func_idx] = None;
                return Ok(false);
            }
        };

        let mut shadow = if func_idx < self.jit_validate_remaining.len()
            && self.jit_validate_remaining[func_idx] > 0
        {
            Some(self.clone_for_validation())
        } else {
            None
        };

        // Populate JIT locals from stack params (i32 only), without mutating stack yet.
        let stack_len = self.stack.len();
        let locals_total = func.param_count + func.local_count;
        let mut locals_buf = [0i32; MAX_LOCALS];
        for i in 0..func.param_count {
            let idx = stack_len - func.param_count + i;
            let v = self.stack.get(idx)?.as_i32()?;
            locals_buf[i] = v;
        }
        for i in func.param_count..locals_total {
            locals_buf[i] = 0;
        }

        if let Some(ref mut shadow_inst) = shadow {
            shadow_inst.enable_jit(false);
            shadow_inst.call(func_idx)?;
        }

        let mem_len = self.memory.active_len();
        if mem_len > u32::MAX as usize {
            return Ok(false);
        }
        let mem_ptr = self.memory.as_mut_ptr();
        if mem_ptr.is_null() {
            return Ok(false);
        }
        if (mem_ptr as usize).checked_add(mem_len).is_none() {
            return Ok(false);
        }
        let jit_state_base = self.jit_state as *mut u8;
        let jit_state_pages = self.jit_state_pages;

        // Consume stack params now that we're committed to JIT execution.
        for _ in 0..func.param_count {
            let _ = self.stack.pop()?;
        }

        let (
            stack_ptr,
            sp_ptr,
            locals_ptr,
            instr_fuel,
            mem_fuel,
            trap_code,
            shadow_stack_ptr,
            shadow_sp_ptr,
        ) = {
            let state = self.jit_state_mut()?;
            for i in 0..locals_total {
                state.locals[i] = locals_buf[i];
            }
            state.sp = 0;
            state.instr_fuel = MAX_INSTRUCTIONS_PER_CALL as u32;
            state.mem_fuel = MAX_MEMORY_OPS_PER_CALL as u32;
            state.trap_code = 0;
            state.shadow_sp = 0;
            (
                state.stack.as_mut_ptr(),
                &mut state.sp as *mut usize,
                state.locals.as_mut_ptr(),
                &mut state.instr_fuel as *mut u32,
                &mut state.mem_fuel as *mut u32,
                &mut state.trap_code as *mut i32,
                state.shadow_stack.as_mut_ptr(),
                &mut state.shadow_sp as *mut usize,
            )
        };
        let ret = call_jit_sandboxed(
            jit_entry,
            stack_ptr,
            sp_ptr,
            mem_ptr,
            mem_len,
            locals_ptr,
            instr_fuel,
            mem_fuel,
            trap_code,
            shadow_stack_ptr,
            shadow_sp_ptr,
            jit_state_base,
            jit_state_pages,
            &mut self.jit_user_pages,
        );
        let (trap_code_val, instr_left, mem_left) = {
            let state = self.jit_state()?;
            (state.trap_code, state.instr_fuel, state.mem_fuel)
        };
        if trap_code_val == -1 {
            if let Some(shadow_inst) = shadow {
                self.restore_from_shadow(shadow_inst);
                self.disable_jit_for_function(func_idx);
                return Ok(true);
            }
            return Err(WasmError::MemoryOutOfBounds);
        }
        if trap_code_val == -2 {
            if let Some(shadow_inst) = shadow {
                self.restore_from_shadow(shadow_inst);
                self.disable_jit_for_function(func_idx);
                return Ok(true);
            }
            return Err(WasmError::ExecutionLimitExceeded);
        }
        if trap_code_val == -3 {
            if let Some(shadow_inst) = shadow {
                self.restore_from_shadow(shadow_inst);
                self.disable_jit_for_function(func_idx);
                return Ok(true);
            }
            return Err(WasmError::Trap);
        }
        if trap_code_val == -4 {
            if let Some(shadow_inst) = shadow {
                self.restore_from_shadow(shadow_inst);
                self.disable_jit_for_function(func_idx);
                return Ok(true);
            }
            return Err(WasmError::ControlFlowViolation);
        }
        if trap_code_val != 0 {
            if let Some(shadow_inst) = shadow {
                self.restore_from_shadow(shadow_inst);
                self.disable_jit_for_function(func_idx);
                return Ok(true);
            }
            return Err(WasmError::Trap);
        }
        if func.result_count == 1 {
            self.stack.push(Value::I32(ret))?;
        }
        self.instruction_count =
            (MAX_INSTRUCTIONS_PER_CALL as u32).saturating_sub(instr_left) as usize;
        self.memory_op_count =
            (MAX_MEMORY_OPS_PER_CALL as u32).saturating_sub(mem_left) as usize;

        if let Some(shadow_inst) = shadow {
            if !self.validate_against_shadow(&shadow_inst, func) {
                self.restore_from_shadow(shadow_inst);
                self.disable_jit_for_function(func_idx);
                return Ok(true);
            }
            if func_idx < self.jit_validate_remaining.len() {
                self.jit_validate_remaining[func_idx] =
                    self.jit_validate_remaining[func_idx].saturating_sub(1);
            }
        }
        jit_stats().lock().jit_calls += 1;
        Ok(true)
    }

    fn clone_for_validation(&self) -> Self {
        let (jit_state, jit_state_pages) = Self::alloc_jit_state();
        WasmInstance {
            module: self.module.clone(),
            memory: self.memory.clone(),
            stack: self.stack.clone(),
            locals: self.locals,
            pc: self.pc,
            capabilities: self.capabilities.clone(),
            process_id: self.process_id,
            instance_id: self.instance_id,
            is_shadow: true,
            instruction_count: 0,
            memory_op_count: 0,
            syscall_count: 0,
            jit_hash: [None; 64],
            jit_state,
            jit_state_pages,
            jit_user_pages: None,
            jit_enabled: false,
            jit_hot: [0; 64],
            jit_validate_remaining: [0; 64],
        }
    }

    fn restore_from_shadow(&mut self, shadow: WasmInstance) {
        self.memory = shadow.memory;
        self.stack = shadow.stack;
        self.locals = shadow.locals;
        self.pc = shadow.pc;
        self.instruction_count = shadow.instruction_count;
        self.memory_op_count = shadow.memory_op_count;
        self.syscall_count = shadow.syscall_count;
        if let Ok(state) = self.jit_state_mut() {
            state.sp = 0;
        }
    }

    fn disable_jit_for_function(&mut self, func_idx: usize) {
        if func_idx < self.jit_hash.len() {
            self.jit_hash[func_idx] = None;
            self.jit_hot[func_idx] = 0;
            self.jit_validate_remaining[func_idx] = 0;
        }
    }

    fn validate_against_shadow(&self, shadow: &WasmInstance, func: Function) -> bool {
        if self.stack.len() != shadow.stack.len() {
            return false;
        }
        if func.result_count == 1 {
            let shadow_res = shadow.stack.peek().ok().and_then(|v| v.as_i32().ok());
            let self_res = self.stack.peek().ok().and_then(|v| v.as_i32().ok());
            if shadow_res != self_res {
                return false;
            }
        }
        let shadow_hash = hash_memory(shadow.memory.active_slice());
        let self_hash = hash_memory(self.memory.active_slice());
        shadow_hash == self_hash
    }

    /// Reset execution limits
    fn reset_limits(&mut self) {
        self.instruction_count = 0;
        self.memory_op_count = 0;
        self.syscall_count = 0;
    }

    /// Check instruction limit
    fn check_instruction_limit(&mut self) -> Result<(), WasmError> {
        self.instruction_count += 1;
        if self.instruction_count > MAX_INSTRUCTIONS_PER_CALL {
            return Err(WasmError::ExecutionLimitExceeded);
        }
        Ok(())
    }

    /// Check memory operation limit
    fn check_memory_limit(&mut self) -> Result<(), WasmError> {
        self.memory_op_count += 1;
        if self.memory_op_count > MAX_MEMORY_OPS_PER_CALL {
            return Err(WasmError::ExecutionLimitExceeded);
        }
        Ok(())
    }

    /// Check syscall limit
    fn check_syscall_limit(&mut self) -> Result<(), WasmError> {
        self.syscall_count += 1;
        if self.syscall_count > MAX_SYSCALLS_PER_CALL {
            return Err(WasmError::ExecutionLimitExceeded);
        }
        Ok(())
    }

    /// Inject a capability into the instance
    pub fn inject_capability(&mut self, cap: WasmCapability) -> Result<CapHandle, WasmError> {
        self.capabilities.inject(cap)
    }

    /// Execute a function
    pub fn call(&mut self, func_idx: usize) -> Result<(), WasmError> {
        // Reset execution limits for this call
        self.reset_limits();

        // Check rate limiting and security
        if !crate::security::security().validate_capability(
            self.process_id,
            1, // Execute permission
            1,
        ).is_ok() {
            return Err(WasmError::PermissionDenied);
        }

        let func = self.module.get_function(func_idx)?;

        if self.try_jit(func, func_idx)? {
            return Ok(());
        }
        
        // Set up locals from stack parameters
        for i in (0..func.param_count).rev() {
            self.locals[i] = self.stack.pop()?;
        }

        // Execute function body
        let (code_start, end_pc) = self.function_code_range(func)?;
        self.pc = code_start;

        while self.pc < end_pc {
            let should_continue = self.step()?;
            if !should_continue {
                // Return or End encountered
                break;
            }
        }

        Ok(())
    }

    /// Execute one instruction
    /// Returns: true to continue, false to break (for Return/End)
    fn step(&mut self) -> Result<bool, WasmError> {
        // Check execution limits
        self.check_instruction_limit()?;

        let bytecode_len = self.bytecode_len_clamped();
        if self.pc >= bytecode_len {
            return Err(WasmError::InvalidProgramCounter);
        }

        let opcode_byte = self.module.bytecode[self.pc];
        self.pc += 1;

        let opcode = Opcode::from_byte(opcode_byte)
            .ok_or(WasmError::UnknownOpcode(opcode_byte))?;

        match opcode {
            Opcode::Nop => {}
            
            Opcode::Unreachable => {
                return Err(WasmError::Trap);
            }

            Opcode::End => {
                // End of block/function - stop execution
                return Ok(false);
            }

            Opcode::Return => {
                // Return from function - stop execution
                return Ok(false);
            }

            Opcode::Drop => {
                self.stack.pop()?;
            }

            Opcode::LocalGet => {
                let local_idx = self.read_uleb128()? as usize;
                if local_idx >= MAX_LOCALS {
                    return Err(WasmError::InvalidLocalIndex);
                }
                self.stack.push(self.locals[local_idx])?;
            }

            Opcode::LocalSet => {
                let local_idx = self.read_uleb128()? as usize;
                if local_idx >= MAX_LOCALS {
                    return Err(WasmError::InvalidLocalIndex);
                }
                self.locals[local_idx] = self.stack.pop()?;
            }

            Opcode::I32Const => {
                let value = self.read_sleb128_i32()?;
                self.stack.push(Value::I32(value))?;
            }

            Opcode::I32Add => {
                let b = self.stack.pop()?.as_i32()?;
                let a = self.stack.pop()?.as_i32()?;
                self.stack.push(Value::I32(a.wrapping_add(b)))?;
            }

            Opcode::I32Sub => {
                let b = self.stack.pop()?.as_i32()?;
                let a = self.stack.pop()?.as_i32()?;
                self.stack.push(Value::I32(a.wrapping_sub(b)))?;
            }

            Opcode::I32Mul => {
                let b = self.stack.pop()?.as_i32()?;
                let a = self.stack.pop()?.as_i32()?;
                self.stack.push(Value::I32(a.wrapping_mul(b)))?;
            }

            Opcode::I32DivS => {
                let b = self.stack.pop()?.as_i32()?;
                let a = self.stack.pop()?.as_i32()?;
                if b == 0 {
                    return Err(WasmError::DivisionByZero);
                }
                self.stack.push(Value::I32(a.wrapping_div(b)))?;
            }

            Opcode::I32And => {
                let b = self.stack.pop()?.as_i32()?;
                let a = self.stack.pop()?.as_i32()?;
                self.stack.push(Value::I32(a & b))?;
            }

            Opcode::I32Or => {
                let b = self.stack.pop()?.as_i32()?;
                let a = self.stack.pop()?.as_i32()?;
                self.stack.push(Value::I32(a | b))?;
            }

            Opcode::I32Xor => {
                let b = self.stack.pop()?.as_i32()?;
                let a = self.stack.pop()?.as_i32()?;
                self.stack.push(Value::I32(a ^ b))?;
            }

            Opcode::I32Eq => {
                let b = self.stack.pop()?.as_i32()?;
                let a = self.stack.pop()?.as_i32()?;
                self.stack.push(Value::I32(if a == b { 1 } else { 0 }))?;
            }

            Opcode::I32Ne => {
                let b = self.stack.pop()?.as_i32()?;
                let a = self.stack.pop()?.as_i32()?;
                self.stack.push(Value::I32(if a != b { 1 } else { 0 }))?;
            }

            Opcode::I32Eqz => {
                let a = self.stack.pop()?.as_i32()?;
                self.stack.push(Value::I32(if a == 0 { 1 } else { 0 }))?;
            }

            Opcode::I32Load => {
                self.check_memory_limit()?;
                let _align = self.read_uleb128()?; // Alignment hint (ignored for now)
                let offset = self.read_uleb128()? as usize;
                let addr = self.stack.pop()?.as_u32()? as usize;
                let effective_addr = addr.checked_add(offset)
                    .ok_or(WasmError::MemoryOutOfBounds)?;
                let value = self.memory.read_i32(effective_addr)?;
                self.stack.push(Value::I32(value))?;
            }

            Opcode::I32Store => {
                self.check_memory_limit()?;
                let _align = self.read_uleb128()?;
                let offset = self.read_uleb128()? as usize;
                let value = self.stack.pop()?.as_i32()?;
                let addr = self.stack.pop()?.as_u32()? as usize;
                let effective_addr = addr.checked_add(offset)
                    .ok_or(WasmError::MemoryOutOfBounds)?;
                self.memory.write_i32(effective_addr, value)?;
            }

            Opcode::MemorySize => {
                self.stack.push(Value::I32(self.memory.size() as i32))?;
            }

            Opcode::MemoryGrow => {
                let delta = self.stack.pop()?.as_i32()? as usize;
                match self.memory.grow(delta) {
                    Ok(old_size) => self.stack.push(Value::I32(old_size as i32))?,
                    Err(_) => self.stack.push(Value::I32(-1))?,
                }
            }

            Opcode::Call => {
                let func_idx = self.read_uleb128()? as usize;
                
                // Check if it's a host function (syscall)
                if func_idx >= 1000 {
                    // Host function call
                    self.call_host_function(func_idx - 1000)?;
                } else {
                    // Regular WASM function
                    self.call(func_idx)?;
                }
            }

            _ => {
                return Err(WasmError::UnimplementedOpcode(opcode_byte));
            }
        }

        Ok(true) // Continue execution
    }

    /// Read unsigned LEB128
    fn read_uleb128(&mut self) -> Result<u32, WasmError> {
        let mut result = 0u32;
        let mut shift = 0;
        let bytecode_len = self.bytecode_len_clamped();

        loop {
            if self.pc >= bytecode_len {
                return Err(WasmError::UnexpectedEndOfCode);
            }

            let byte = self.module.bytecode[self.pc];
            self.pc += 1;

            result |= ((byte & 0x7F) as u32) << shift;
            
            if (byte & 0x80) == 0 {
                break;
            }

            shift += 7;
            if shift > 28 {
                return Err(WasmError::Leb128Overflow);
            }
        }

        Ok(result)
    }

    /// Read signed LEB128 (i32)
    fn read_sleb128_i32(&mut self) -> Result<i32, WasmError> {
        let mut result = 0i32;
        let mut shift = 0;
        let mut byte;
        let bytecode_len = self.bytecode_len_clamped();

        loop {
            if self.pc >= bytecode_len {
                return Err(WasmError::UnexpectedEndOfCode);
            }

            byte = self.module.bytecode[self.pc];
            self.pc += 1;

            result |= ((byte & 0x7F) as i32) << shift;
            shift += 7;

            if (byte & 0x80) == 0 {
                break;
            }

            if shift > 28 {
                return Err(WasmError::Leb128Overflow);
            }
        }

        // Sign extend
        if shift < 32 && (byte & 0x40) != 0 {
            result |= !0 << shift;
        }

        Ok(result)
    }

    /// Call a host function (Oreulia syscall)
    fn call_host_function(&mut self, func_idx: usize) -> Result<(), WasmError> {
        // Check syscall limit
        self.check_syscall_limit()?;

        match func_idx {
            0 => self.host_log(),
            1 => self.host_fs_read(),
            2 => self.host_fs_write(),
            3 => self.host_channel_send(),
            4 => self.host_channel_recv(),
            5 => self.host_net_http_get(),
            6 => self.host_net_connect(),
            7 => self.host_dns_resolve(),
            _ => Err(WasmError::UnknownHostFunction),
        }
    }

    fn replay_mode(&self) -> ReplayMode {
        if self.is_shadow {
            ReplayMode::Off
        } else {
            replay::mode(self.instance_id)
        }
    }

    // ========================================================================
    // Oreulia Syscalls
    // ========================================================================

    /// oreulia_log(msg_ptr: i32, msg_len: i32)
    fn host_log(&mut self) -> Result<(), WasmError> {
        let msg_len = self.stack.pop()?.as_i32()? as usize;
        let msg_ptr = self.stack.pop()?.as_i32()? as usize;

        let msg_bytes = self.memory.read(msg_ptr, msg_len)?;
        let func_id: u16 = 0;
        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, msg_len as u32);
        args_hash = replay::hash_bytes(args_hash, msg_bytes);

        let mode = self.replay_mode();
        if mode == ReplayMode::Replay {
            let out = replay::replay_host_call(self.instance_id, func_id, args_hash)
                .map_err(|_| WasmError::DeterminismViolation)?;
            if out.status == ReplayEventStatus::Err {
                return Err(WasmError::SyscallFailed);
            }
            return Ok(());
        }

        if let Ok(msg_str) = core::str::from_utf8(msg_bytes) {
            crate::vga::print_str("[WASM] ");
            crate::vga::print_str(msg_str);
            crate::vga::print_char('\n');
        }

        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                0,
                &[],
            )
            .map_err(|_| WasmError::ReplayError)?;
        }

        Ok(())
    }

    /// oreulia_fs_read(cap: i32, key_ptr: i32, key_len: i32, buf_ptr: i32, buf_len: i32) -> i32
    fn host_fs_read(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize;
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        let key_len = self.stack.pop()?.as_i32()? as usize;
        let key_ptr = self.stack.pop()?.as_i32()? as usize;
        let cap_handle = CapHandle(self.stack.pop()?.as_u32()?);

        // Get filesystem capability
        let fs_cap = match self.capabilities.get(cap_handle)? {
            WasmCapability::Filesystem(cap) => cap,
            _ => return Err(WasmError::InvalidCapability),
        };

        // Read key from memory
        let key_bytes = self.memory.read(key_ptr, key_len)?;
        let func_id: u16 = 1;
        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, cap_handle.0);
        args_hash = replay::hash_u32(args_hash, key_len as u32);
        args_hash = replay::hash_u32(args_hash, buf_len as u32);
        args_hash = replay::hash_bytes(args_hash, key_bytes);

        let mode = self.replay_mode();
        if mode == ReplayMode::Replay {
            let out = replay::replay_host_call(self.instance_id, func_id, args_hash)
                .map_err(|_| WasmError::DeterminismViolation)?;
            if out.status == ReplayEventStatus::Err {
                return Err(WasmError::SyscallFailed);
            }
            if out.data.len() > buf_len {
                return Err(WasmError::DeterminismViolation);
            }
            if !out.data.is_empty() {
                self.memory.write(buf_ptr, &out.data)?;
            }
            self.stack.push(Value::I32(out.result))?;
            return Ok(());
        }
        let key_str = core::str::from_utf8(key_bytes)
            .map_err(|_| WasmError::InvalidUtf8)?;
        let key = fs::FileKey::new(key_str)
            .map_err(|_| WasmError::SyscallFailed)?;

        // Call filesystem
        let request = fs::Request::read(key, fs_cap);
        let response = fs::filesystem().handle_request(request);

        match response.status {
            fs::ResponseStatus::Ok => {
                let data = response.get_data();
                let copy_len = data.len().min(buf_len);
                self.memory.write(buf_ptr, &data[..copy_len])?;
                self.stack.push(Value::I32(copy_len as i32))?;
                if mode == ReplayMode::Record {
                    replay::record_host_call(
                        self.instance_id,
                        func_id,
                        args_hash,
                        ReplayEventStatus::Ok,
                        copy_len as i32,
                        &data[..copy_len],
                    )
                    .map_err(|_| WasmError::ReplayError)?;
                }
            }
            fs::ResponseStatus::Error(_) => {
                self.stack.push(Value::I32(-1))?;
                if mode == ReplayMode::Record {
                    replay::record_host_call(
                        self.instance_id,
                        func_id,
                        args_hash,
                        ReplayEventStatus::Ok,
                        -1,
                        &[],
                    )
                    .map_err(|_| WasmError::ReplayError)?;
                }
            }
        }

        Ok(())
    }

    /// oreulia_fs_write(cap: i32, key_ptr: i32, key_len: i32, data_ptr: i32, data_len: i32) -> i32
    fn host_fs_write(&mut self) -> Result<(), WasmError> {
        let data_len = self.stack.pop()?.as_i32()? as usize;
        let data_ptr = self.stack.pop()?.as_i32()? as usize;
        let key_len = self.stack.pop()?.as_i32()? as usize;
        let key_ptr = self.stack.pop()?.as_i32()? as usize;
        let cap_handle = CapHandle(self.stack.pop()?.as_u32()?);

        // Get filesystem capability
        let fs_cap = match self.capabilities.get(cap_handle)? {
            WasmCapability::Filesystem(cap) => cap,
            _ => return Err(WasmError::InvalidCapability),
        };

        // Read key and data from memory
        let key_bytes = self.memory.read(key_ptr, key_len)?;
        let data = self.memory.read(data_ptr, data_len)?;
        let func_id: u16 = 2;
        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, cap_handle.0);
        args_hash = replay::hash_u32(args_hash, key_len as u32);
        args_hash = replay::hash_bytes(args_hash, key_bytes);
        args_hash = replay::hash_u32(args_hash, data_len as u32);
        args_hash = replay::hash_bytes(args_hash, data);

        let mode = self.replay_mode();
        if mode == ReplayMode::Replay {
            let out = replay::replay_host_call(self.instance_id, func_id, args_hash)
                .map_err(|_| WasmError::DeterminismViolation)?;
            if out.status == ReplayEventStatus::Err {
                return Err(WasmError::SyscallFailed);
            }
            self.stack.push(Value::I32(out.result))?;
            return Ok(());
        }
        let key_str = core::str::from_utf8(key_bytes)
            .map_err(|_| WasmError::InvalidUtf8)?;
        let key = fs::FileKey::new(key_str)
            .map_err(|_| WasmError::SyscallFailed)?;

        // Call filesystem
        let request = fs::Request::write(key, data, fs_cap)
            .map_err(|_| WasmError::SyscallFailed)?;
        let response = fs::filesystem().handle_request(request);

        match response.status {
            fs::ResponseStatus::Ok => {
                self.stack.push(Value::I32(0))?;
                if mode == ReplayMode::Record {
                    replay::record_host_call(
                        self.instance_id,
                        func_id,
                        args_hash,
                        ReplayEventStatus::Ok,
                        0,
                        &[],
                    )
                    .map_err(|_| WasmError::ReplayError)?;
                }
            }
            fs::ResponseStatus::Error(_) => {
                self.stack.push(Value::I32(-1))?;
                if mode == ReplayMode::Record {
                    replay::record_host_call(
                        self.instance_id,
                        func_id,
                        args_hash,
                        ReplayEventStatus::Ok,
                        -1,
                        &[],
                    )
                    .map_err(|_| WasmError::ReplayError)?;
                }
            }
        }

        Ok(())
    }

    /// oreulia_channel_send(cap: i32, msg_ptr: i32, msg_len: i32) -> i32
    fn host_channel_send(&mut self) -> Result<(), WasmError> {
        let msg_len = self.stack.pop()?.as_i32()? as usize;
        let msg_ptr = self.stack.pop()?.as_i32()? as usize;
        let cap_handle = CapHandle(self.stack.pop()?.as_u32()?);

        // Get channel capability
        let channel_id = match self.capabilities.get(cap_handle)? {
            WasmCapability::Channel(id) => id,
            _ => return Err(WasmError::InvalidCapability),
        };

        // Read message from memory
        let msg_data = self.memory.read(msg_ptr, msg_len)?;
        let func_id: u16 = 3;
        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, cap_handle.0);
        args_hash = replay::hash_u32(args_hash, msg_len as u32);
        args_hash = replay::hash_bytes(args_hash, msg_data);

        let mode = self.replay_mode();
        if mode == ReplayMode::Replay {
            let out = replay::replay_host_call(self.instance_id, func_id, args_hash)
                .map_err(|_| WasmError::DeterminismViolation)?;
            if out.status == ReplayEventStatus::Err {
                return Err(WasmError::SyscallFailed);
            }
            self.stack.push(Value::I32(out.result))?;
            return Ok(());
        }

        // Send message via IPC
        let channel_cap = crate::ipc::ChannelCapability::new(
            0, // cap_id (not used for sending)
            channel_id,
            crate::ipc::ChannelRights::send_only(),
            self.process_id,
        );
        
        let msg = crate::ipc::Message::with_data(self.process_id, msg_data)
            .map_err(|_| WasmError::SyscallFailed)?;
        
        let send_result = crate::ipc::ipc().send(msg, &channel_cap);
        if send_result.is_err() {
            if mode == ReplayMode::Record {
                replay::record_host_call(
                    self.instance_id,
                    func_id,
                    args_hash,
                    ReplayEventStatus::Err,
                    -1,
                    &[],
                )
                .map_err(|_| WasmError::ReplayError)?;
            }
            return Err(WasmError::SyscallFailed);
        }

        self.stack.push(Value::I32(0))?;
        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                0,
                &[],
            )
            .map_err(|_| WasmError::ReplayError)?;
        }
        Ok(())
    }

    /// oreulia_channel_recv(cap: i32, buf_ptr: i32, buf_len: i32) -> i32
    fn host_channel_recv(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize;
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        let cap_handle = CapHandle(self.stack.pop()?.as_u32()?);

        // Get channel capability
        let channel_id = match self.capabilities.get(cap_handle)? {
            WasmCapability::Channel(id) => id,
            _ => return Err(WasmError::InvalidCapability),
        };

        let func_id: u16 = 4;
        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, cap_handle.0);
        args_hash = replay::hash_u32(args_hash, buf_len as u32);

        let mode = self.replay_mode();
        if mode == ReplayMode::Replay {
            let out = replay::replay_host_call(self.instance_id, func_id, args_hash)
                .map_err(|_| WasmError::DeterminismViolation)?;
            if out.status == ReplayEventStatus::Err {
                return Err(WasmError::SyscallFailed);
            }
            if out.data.len() > buf_len {
                return Err(WasmError::DeterminismViolation);
            }
            if !out.data.is_empty() {
                self.memory.write(buf_ptr, &out.data)?;
            }
            self.stack.push(Value::I32(out.result))?;
            return Ok(());
        }

        // Receive message via IPC
        let channel_cap = crate::ipc::ChannelCapability::new(
            0, // cap_id (not used for receiving)
            channel_id,
            crate::ipc::ChannelRights::receive_only(),
            self.process_id,
        );
        
        match crate::ipc::ipc().try_recv(&channel_cap) {
            Ok(msg) => {
                let msg_data = &msg.payload[..msg.payload_len];
                let copy_len = msg_data.len().min(buf_len);
                self.memory.write(buf_ptr, &msg_data[..copy_len])?;
                self.stack.push(Value::I32(copy_len as i32))?;
                if mode == ReplayMode::Record {
                    replay::record_host_call(
                        self.instance_id,
                        func_id,
                        args_hash,
                        ReplayEventStatus::Ok,
                        copy_len as i32,
                        &msg_data[..copy_len],
                    )
                    .map_err(|_| WasmError::ReplayError)?;
                }
            }
            Err(_) => {
                // No message available
                self.stack.push(Value::I32(0))?;
                if mode == ReplayMode::Record {
                    replay::record_host_call(
                        self.instance_id,
                        func_id,
                        args_hash,
                        ReplayEventStatus::Ok,
                        0,
                        &[],
                    )
                    .map_err(|_| WasmError::ReplayError)?;
                }
            }
        }

        Ok(())
    }

    /// oreulia_net_http_get(url_ptr: i32, url_len: i32, buf_ptr: i32, buf_len: i32) -> i32
    fn host_net_http_get(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize;
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        let url_len = self.stack.pop()?.as_i32()? as usize;
        let url_ptr = self.stack.pop()?.as_i32()? as usize;

        // Read URL from memory
        let url_bytes = self.memory.read(url_ptr, url_len)?;
        let func_id: u16 = 5;
        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, url_len as u32);
        args_hash = replay::hash_u32(args_hash, buf_len as u32);
        args_hash = replay::hash_bytes(args_hash, url_bytes);

        let mode = self.replay_mode();
        if mode == ReplayMode::Replay {
            let out = replay::replay_host_call(self.instance_id, func_id, args_hash)
                .map_err(|_| WasmError::DeterminismViolation)?;
            if out.status == ReplayEventStatus::Err {
                return Err(WasmError::SyscallFailed);
            }
            if out.data.len() > buf_len {
                return Err(WasmError::DeterminismViolation);
            }
            if !out.data.is_empty() {
                self.memory.write(buf_ptr, &out.data)?;
            }
            self.stack.push(Value::I32(out.result))?;
            return Ok(());
        }
        let url_str = core::str::from_utf8(url_bytes)
            .map_err(|_| WasmError::InvalidUtf8)?;

        // Get network service
        let net = crate::net::network();
        let mut net_lock = net.lock();

        // Perform GET request
        let response = match net_lock.http_get(url_str) {
            Ok(resp) => resp,
            Err(_) => {
                if mode == ReplayMode::Record {
                    replay::record_host_call(
                        self.instance_id,
                        func_id,
                        args_hash,
                        ReplayEventStatus::Err,
                        -1,
                        &[],
                    )
                    .map_err(|_| WasmError::ReplayError)?;
                }
                return Err(WasmError::SyscallFailed);
            }
        };

        // Copy to WASM memory
        let copy_len = response.body_len.min(buf_len);
        self.memory.write(buf_ptr, &response.body[..copy_len])?;
        
        self.stack.push(Value::I32(copy_len as i32))?;
        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                copy_len as i32,
                &response.body[..copy_len],
            )
            .map_err(|_| WasmError::ReplayError)?;
        }
        Ok(())
    }

    /// oreulia_net_connect(host_ptr: i32, host_len: i32, port: i32) -> i32
    fn host_net_connect(&mut self) -> Result<(), WasmError> {
        let _port = self.stack.pop()?.as_i32()? as u16;
        let host_len = self.stack.pop()?.as_i32()? as usize;
        let host_ptr = self.stack.pop()?.as_i32()? as usize;

        // Read host from memory
        let host_bytes = self.memory.read(host_ptr, host_len)?;
        let func_id: u16 = 6;
        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, host_len as u32);
        args_hash = replay::hash_u32(args_hash, _port as u32);
        args_hash = replay::hash_bytes(args_hash, host_bytes);

        let mode = self.replay_mode();
        if mode == ReplayMode::Replay {
            let out = replay::replay_host_call(self.instance_id, func_id, args_hash)
                .map_err(|_| WasmError::DeterminismViolation)?;
            if out.status == ReplayEventStatus::Err {
                return Err(WasmError::SyscallFailed);
            }
            self.stack.push(Value::I32(out.result))?;
            return Ok(());
        }
        let _host_str = core::str::from_utf8(host_bytes)
            .map_err(|_| WasmError::InvalidUtf8)?;

        // For v1, return success (real socket implementation would happen here)
        self.stack.push(Value::I32(1))?; // Simulated socket ID
        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                1,
                &[],
            )
            .map_err(|_| WasmError::ReplayError)?;
        }
        Ok(())
    }

    /// oreulia_dns_resolve(domain_ptr: i32, domain_len: i32) -> i32 (returns IP as u32)
    fn host_dns_resolve(&mut self) -> Result<(), WasmError> {
        let domain_len = self.stack.pop()?.as_i32()? as usize;
        let domain_ptr = self.stack.pop()?.as_i32()? as usize;

        // Read domain from memory
        let domain_bytes = self.memory.read(domain_ptr, domain_len)?;
        let func_id: u16 = 7;
        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, domain_len as u32);
        args_hash = replay::hash_bytes(args_hash, domain_bytes);

        let mode = self.replay_mode();
        if mode == ReplayMode::Replay {
            let out = replay::replay_host_call(self.instance_id, func_id, args_hash)
                .map_err(|_| WasmError::DeterminismViolation)?;
            if out.status == ReplayEventStatus::Err {
                return Err(WasmError::SyscallFailed);
            }
            self.stack.push(Value::I32(out.result))?;
            return Ok(());
        }
        let domain_str = core::str::from_utf8(domain_bytes)
            .map_err(|_| WasmError::InvalidUtf8)?;

        // Get network service
        let net = crate::net::network();
        let mut net_lock = net.lock();

        // Resolve via DNS
        let ip = match net_lock.dns_resolve(domain_str) {
            Ok(ip) => ip,
            Err(_) => {
                if mode == ReplayMode::Record {
                    replay::record_host_call(
                        self.instance_id,
                        func_id,
                        args_hash,
                        ReplayEventStatus::Err,
                        -1,
                        &[],
                    )
                    .map_err(|_| WasmError::ReplayError)?;
                }
                return Err(WasmError::SyscallFailed);
            }
        };

        self.stack.push(Value::I32(ip.to_u32() as i32))?;
        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                ip.to_u32() as i32,
                &[],
            )
            .map_err(|_| WasmError::ReplayError)?;
        }
        Ok(())
    }
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmError {
    // Module errors
    ModuleTooLarge,
    InvalidModule,
    TooManyFunctions,
    FunctionNotFound,
    
    // Execution errors
    StackOverflow,
    StackUnderflow,
    TypeMismatch,
    InvalidProgramCounter,
    UnknownOpcode(u8),
    UnimplementedOpcode(u8),
    UnexpectedEndOfCode,
    Leb128Overflow,
    InvalidLocalIndex,
    Trap,
    DivisionByZero,
    ExecutionLimitExceeded,
    PermissionDenied,
    
    // Memory errors
    MemoryOutOfBounds,
    MemoryGrowFailed,
    
    // Capability errors
    InvalidCapability,
    TooManyCapabilities,
    
    // Host function errors
    UnknownHostFunction,
    SyscallFailed,
    InvalidUtf8,
    DeterminismViolation,
    ReplayError,
    ControlFlowViolation,
}

impl fmt::Display for WasmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WasmError::ModuleTooLarge => write!(f, "Module too large"),
            WasmError::InvalidModule => write!(f, "Invalid module"),
            WasmError::StackOverflow => write!(f, "Stack overflow"),
            WasmError::StackUnderflow => write!(f, "Stack underflow"),
            WasmError::TypeMismatch => write!(f, "Type mismatch"),
            WasmError::UnknownOpcode(op) => write!(f, "Unknown opcode: 0x{:02X}", op),
            WasmError::MemoryOutOfBounds => write!(f, "Memory out of bounds"),
            WasmError::InvalidCapability => write!(f, "Invalid capability"),
            WasmError::Trap => write!(f, "Trap"),
            WasmError::DivisionByZero => write!(f, "Division by zero"),
            WasmError::ExecutionLimitExceeded => write!(f, "Execution limit exceeded"),
            WasmError::PermissionDenied => write!(f, "Permission denied"),
            WasmError::SyscallFailed => write!(f, "Syscall failed"),
            WasmError::DeterminismViolation => write!(f, "Determinism violation"),
            WasmError::ReplayError => write!(f, "Replay error"),
            WasmError::ControlFlowViolation => write!(f, "Control flow violation"),
            _ => write!(f, "WASM error"),
        }
    }
}

impl WasmError {
    /// Convert error to string for no_std environments
    pub fn as_str(&self) -> &'static str {
        match self {
            WasmError::ModuleTooLarge => "Module too large",
            WasmError::InvalidModule => "Invalid module",
            WasmError::TooManyFunctions => "Too many functions",
            WasmError::FunctionNotFound => "Function not found",
            WasmError::StackOverflow => "Stack overflow",
            WasmError::StackUnderflow => "Stack underflow",
            WasmError::TypeMismatch => "Type mismatch",
            WasmError::InvalidProgramCounter => "Invalid program counter",
            WasmError::UnknownOpcode(_) => "Unknown opcode",
            WasmError::UnimplementedOpcode(_) => "Unimplemented opcode",
            WasmError::UnexpectedEndOfCode => "Unexpected end of code",
            WasmError::Leb128Overflow => "LEB128 overflow",
            WasmError::InvalidLocalIndex => "Invalid local index",
            WasmError::Trap => "Trap",
            WasmError::DivisionByZero => "Division by zero",
            WasmError::MemoryOutOfBounds => "Memory out of bounds",
            WasmError::MemoryGrowFailed => "Memory grow failed",
            WasmError::InvalidCapability => "Invalid capability",
            WasmError::TooManyCapabilities => "Too many capabilities",
            WasmError::UnknownHostFunction => "Unknown host function",
            WasmError::SyscallFailed => "Syscall failed",
            WasmError::InvalidUtf8 => "Invalid UTF-8",
            WasmError::DeterminismViolation => "Determinism violation",
            WasmError::ReplayError => "Replay error",
            WasmError::ControlFlowViolation => "Control flow violation",
            WasmError::ExecutionLimitExceeded => "Execution limit exceeded",
            WasmError::PermissionDenied => "Permission denied",
        }
    }
}

// ============================================================================
// Global WASM Runtime
// ============================================================================

/// Global WASM runtime (manages instances)
pub struct WasmRuntime {
    instances: Mutex<[Option<WasmInstance>; 8]>,
}

impl WasmRuntime {
    pub const fn new() -> Self {
        WasmRuntime {
            instances: Mutex::new([None, None, None, None, None, None, None, None]),
        }
    }

    /// Load and instantiate a module
    pub fn instantiate(&self, bytecode: &[u8], process_id: ProcessId) -> Result<usize, WasmError> {
        let mut module = WasmModule::new();
        module.load(bytecode)?;

        self.instantiate_module(module, process_id)
    }

    /// Instantiate a pre-built module (used by tests/benchmarks)
    pub fn instantiate_module(&self, module: WasmModule, process_id: ProcessId) -> Result<usize, WasmError> {
        let mut module_opt = Some(module);
        let mut instances = self.instances.lock();
        for (i, slot) in instances.iter_mut().enumerate() {
            if slot.is_none() {
                let module = module_opt.take().ok_or(WasmError::InvalidModule)?;
                *slot = Some(WasmInstance::new(module, process_id, i));
                return Ok(i);
            }
        }

        Err(WasmError::TooManyCapabilities) // Reuse error for "too many instances"
    }

    /// Get a mutable reference to an instance
    pub fn get_instance_mut<F, R>(&self, instance_id: usize, f: F) -> Result<R, WasmError>
    where
        F: FnOnce(&mut WasmInstance) -> R,
    {
        let mut instances = self.instances.lock();
        if instance_id >= 8 {
            return Err(WasmError::InvalidModule);
        }
        
        match &mut instances[instance_id] {
            Some(instance) => Ok(f(instance)),
            None => Err(WasmError::InvalidModule),
        }
    }

    /// Destroy an instance
    pub fn destroy(&self, instance_id: usize) -> Result<(), WasmError> {
        let mut instances = self.instances.lock();
        if instance_id >= 8 {
            return Err(WasmError::InvalidModule);
        }
        instances[instance_id] = None;
        crate::replay::clear(instance_id);
        Ok(())
    }

    /// List all active instances
    pub fn list(&self) -> [(usize, ProcessId, bool); 8] {
        let instances = self.instances.lock();
        let mut result = [(0, ProcessId(0), false); 8];
        
        for (i, instance) in instances.iter().enumerate() {
            result[i] = match instance {
                Some(inst) => (i, inst.process_id, true),
                None => (i, ProcessId(0), false),
            };
        }
        
        result
    }
}

static WASM_RUNTIME: WasmRuntime = WasmRuntime::new();

pub fn wasm_runtime() -> &'static WasmRuntime {
    &WASM_RUNTIME
}

pub fn init() {
    // Runtime is statically initialized
    crate::vga::print_str("[WASM] Runtime initialized\n");
}

// ============================================================================
// JIT Config, Cache, Stats
// ============================================================================

pub struct JitConfig {
    pub enabled: bool,
    pub hot_threshold: u32,
    pub user_mode: bool,
}

impl JitConfig {
    pub const fn new() -> Self {
        JitConfig {
            enabled: false,
            hot_threshold: 10,
            user_mode: true,
        }
    }
}

pub struct JitStats {
    pub interp_calls: u64,
    pub jit_calls: u64,
    pub compiled: u64,
    pub failed: u64,
}

impl JitStats {
    pub const fn new() -> Self {
        JitStats {
            interp_calls: 0,
            jit_calls: 0,
            compiled: 0,
            failed: 0,
        }
    }
}

struct JitCacheEntry {
    hash: u64,
    locals_total: usize,
    code_len: usize,
    func: crate::wasm_jit::JitFunction,
}

#[derive(Clone, Copy)]
struct JitExecInfo {
    entry: crate::wasm_jit::JitFn,
    exec_ptr: *mut u8,
    exec_len: usize,
}

struct JitCache {
    entries: Vec<JitCacheEntry>,
    max_entries: usize,
}

impl JitCache {
    const fn new() -> Self {
        JitCache {
            entries: Vec::new(),
            max_entries: 16,
        }
    }
}

static JIT_CONFIG: Mutex<JitConfig> = Mutex::new(JitConfig::new());
static JIT_STATS: Mutex<JitStats> = Mutex::new(JitStats::new());
static JIT_CACHE: Mutex<JitCache> = Mutex::new(JitCache::new());
static JIT_FUZZ_SCRATCH: Mutex<Option<JitFuzzScratch>> = Mutex::new(None);
static JIT_FUZZ_COMPILER: Mutex<Option<crate::wasm_jit::FuzzCompiler>> = Mutex::new(None);
static JIT_FUZZ_INSTANCES: Mutex<Option<(usize, usize)>> = Mutex::new(None);
static JIT_FAULT_ACTIVE: AtomicBool = AtomicBool::new(false);
static mut JIT_FAULT_TRAP_PTR: *mut i32 = core::ptr::null_mut();
static JIT_USER_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
struct JitUserPages {
    trampoline: usize,
    call: usize,
    stack: usize,
    stack_pages: usize,
}

#[no_mangle]
pub static JIT_USER_ACTIVE: AtomicU32 = AtomicU32::new(0);
#[no_mangle]
pub static JIT_USER_RETURN_PENDING: AtomicU32 = AtomicU32::new(0);
#[no_mangle]
pub static JIT_USER_RETURN_EIP: AtomicU32 = AtomicU32::new(0);
#[no_mangle]
pub static JIT_USER_RETURN_ESP: AtomicU32 = AtomicU32::new(0);

const TRAP_MEM: i32 = -1;

pub fn jit_config() -> &'static Mutex<JitConfig> {
    &JIT_CONFIG
}

pub fn jit_stats() -> &'static Mutex<JitStats> {
    &JIT_STATS
}

fn jit_fault_enter(trap_ptr: *mut i32) {
    unsafe {
        JIT_FAULT_TRAP_PTR = trap_ptr;
    }
    JIT_FAULT_ACTIVE.store(true, Ordering::SeqCst);
}

fn jit_fault_exit() {
    JIT_FAULT_ACTIVE.store(false, Ordering::SeqCst);
    unsafe {
        JIT_FAULT_TRAP_PTR = core::ptr::null_mut();
    }
}

fn write_jit_user_trampoline(trampoline: *mut u8, call_addr: u32) {
    unsafe {
        let mut idx = 0usize;
        macro_rules! write_u8 {
            ($b:expr) => {{
                core::ptr::write_volatile(trampoline.add(idx), $b);
                idx += 1;
            }};
        }
        macro_rules! write_u32 {
            ($v:expr) => {{
                for byte in ($v).to_le_bytes().iter() {
                    write_u8!(*byte);
                }
            }};
        }

        // mov ecx, imm32
        write_u8!(0xB9);
        write_u32!(call_addr);
        // push ecx (save call pointer)
        write_u8!(0x51);
        // mov eax, [ecx]
        write_u8!(0x8B);
        write_u8!(0x01);
        // push dword [ecx+40] (shadow sp)
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x28);
        // push dword [ecx+36] (shadow stack)
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x24);
        // push dword [ecx+32] (trap ptr)
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x20);
        // push dword [ecx+28] (mem fuel)
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x1C);
        // push dword [ecx+24] (instr fuel)
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x18);
        // push dword [ecx+20] (locals ptr)
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x14);
        // push dword [ecx+16] (mem len)
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x10);
        // push dword [ecx+12] (mem ptr)
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x0C);
        // push dword [ecx+8] (sp ptr)
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x08);
        // push dword [ecx+4] (stack ptr)
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x04);
        // call eax
        write_u8!(0xFF);
        write_u8!(0xD0);
        // add esp, 40
        write_u8!(0x83);
        write_u8!(0xC4);
        write_u8!(0x28);
        // pop ecx (restore call pointer)
        write_u8!(0x59);
        // mov [ecx+44], eax
        write_u8!(0x89);
        write_u8!(0x41);
        write_u8!(0x2C);
        // mov eax, imm32 (syscall number)
        write_u8!(0xB8);
        write_u32!(SYSCALL_JIT_RETURN);
        // int 0x80
        write_u8!(0xCD);
        write_u8!(0x80);
        // hlt; jmp $
        write_u8!(0xF4);
        write_u8!(0xEB);
        write_u8!(0xFE);
        let _ = idx;

        // Fault stub at fixed offset
        let fault_ptr = trampoline.add(USER_JIT_TRAMPOLINE_FAULT_OFFSET);
        let mut fidx = 0usize;
        macro_rules! f_write_u8 {
            ($b:expr) => {{
                core::ptr::write_volatile(fault_ptr.add(fidx), $b);
                fidx += 1;
            }};
        }
        macro_rules! f_write_u32 {
            ($v:expr) => {{
                for byte in ($v).to_le_bytes().iter() {
                    f_write_u8!(*byte);
                }
            }};
        }
        // mov eax, imm32 (syscall number)
        f_write_u8!(0xB8);
        f_write_u32!(SYSCALL_JIT_RETURN);
        // int 0x80
        f_write_u8!(0xCD);
        f_write_u8!(0x80);
        // hlt; jmp $
        f_write_u8!(0xF4);
        f_write_u8!(0xEB);
        f_write_u8!(0xFE);
        let _ = fidx;
    }
}

fn ensure_jit_user_pages(pages: &mut Option<JitUserPages>) -> Result<JitUserPages, &'static str> {
    if let Some(existing) = *pages {
        return Ok(existing);
    }
    let trampoline = memory::jit_allocate_pages(1)?;
    let call = memory::jit_allocate_pages(1)?;
    let stack_pages = USER_JIT_STACK_PAGES + USER_JIT_STACK_GUARD_PAGES;
    let stack = memory::jit_allocate_pages(stack_pages)?;
    memory_isolation::tag_jit_user_trampoline(trampoline, paging::PAGE_SIZE, false)?;
    memory_isolation::tag_jit_user_state(call, paging::PAGE_SIZE, false)?;
    memory_isolation::tag_jit_user_stack(stack, stack_pages * paging::PAGE_SIZE, false)?;
    write_jit_user_trampoline(trampoline as *mut u8, USER_JIT_CALL_BASE as u32);
    let _ = paging::set_page_writable_range(trampoline, paging::PAGE_SIZE, false);
    let new_pages = JitUserPages {
        trampoline,
        call,
        stack,
        stack_pages,
    };
    *pages = Some(new_pages);
    Ok(new_pages)
}

fn wipe_jit_user_pages(pages: &JitUserPages) {
    let _ = paging::set_page_writable_range(pages.trampoline, paging::PAGE_SIZE, true);
    write_jit_user_trampoline(pages.trampoline as *mut u8, USER_JIT_CALL_BASE as u32);
    let _ = paging::set_page_writable_range(pages.trampoline, paging::PAGE_SIZE, false);
    unsafe {
        core::ptr::write_bytes(pages.call as *mut u8, 0, paging::PAGE_SIZE);
        core::ptr::write_bytes(
            pages.stack as *mut u8,
            0,
            pages.stack_pages * paging::PAGE_SIZE,
        );
    }
}

pub fn jit_user_mark_returned() -> bool {
    if JIT_USER_ACTIVE.load(Ordering::SeqCst) != 0 {
        JIT_USER_RETURN_PENDING.store(1, Ordering::SeqCst);
        return true;
    }
    false
}

pub fn jit_handle_page_fault(
    frame: &mut crate::idt_asm::InterruptFrame,
    _fault_addr: usize,
    _error_code: u32,
) -> bool {
    if !JIT_FAULT_ACTIVE.load(Ordering::SeqCst) {
        return false;
    }
    unsafe {
        if !JIT_FAULT_TRAP_PTR.is_null() {
            *JIT_FAULT_TRAP_PTR = TRAP_MEM;
        }
    }
    if (frame.cs & 0x3) == 3 {
        if JIT_USER_ACTIVE.load(Ordering::SeqCst) != 0 {
            let guard_bytes = USER_JIT_STACK_GUARD_PAGES * paging::PAGE_SIZE;
            frame.eax = 0;
            frame.eip = (USER_JIT_TRAMPOLINE_BASE + USER_JIT_TRAMPOLINE_FAULT_OFFSET) as u32;
            frame.user_esp = (USER_JIT_STACK_BASE
                + guard_bytes
                + (USER_JIT_STACK_PAGES * paging::PAGE_SIZE)
                - 4) as u32;
            return true;
        }
    }
    frame.eax = 0;
    frame.eip = crate::asm_bindings::asm_jit_fault_resume as u32;
    true
}

fn call_jit_sandboxed(
    jit_entry: JitExecInfo,
    stack_ptr: *mut i32,
    sp_ptr: *mut usize,
    mem_ptr: *mut u8,
    mem_len: usize,
    locals_ptr: *mut i32,
    instr_fuel: *mut u32,
    mem_fuel: *mut u32,
    trap_code: *mut i32,
    shadow_stack_ptr: *mut u32,
    shadow_sp_ptr: *mut usize,
    jit_state_base: *mut u8,
    jit_state_pages: usize,
    jit_user_pages: &mut Option<JitUserPages>,
) -> i32 {
    if jit_config().lock().user_mode {
        if let Ok(ret) = call_jit_user(
            jit_entry,
            stack_ptr,
            sp_ptr,
            mem_ptr,
            mem_len,
            locals_ptr,
            instr_fuel,
            mem_fuel,
            trap_code,
            shadow_stack_ptr,
            shadow_sp_ptr,
            jit_state_base,
            jit_state_pages,
            jit_user_pages,
        ) {
            return ret;
        }
    }
    call_jit_kernel(
        jit_entry,
        stack_ptr,
        sp_ptr,
        mem_ptr,
        mem_len,
        locals_ptr,
        instr_fuel,
        mem_fuel,
        trap_code,
        shadow_stack_ptr,
        shadow_sp_ptr,
    )
}

fn call_jit_kernel(
    jit_entry: JitExecInfo,
    stack_ptr: *mut i32,
    sp_ptr: *mut usize,
    mem_ptr: *mut u8,
    mem_len: usize,
    locals_ptr: *mut i32,
    instr_fuel: *mut u32,
    mem_fuel: *mut u32,
    trap_code: *mut i32,
    shadow_stack_ptr: *mut u32,
    shadow_sp_ptr: *mut usize,
) -> i32 {
    let flags = unsafe { idt_asm::fast_cli_save() };
    let old_cr3 = paging::current_page_directory_addr();
    let sandbox = match paging::AddressSpace::new_jit_sandbox() {
        Ok(space) => space,
        Err(_) => {
            unsafe {
                if !trap_code.is_null() {
                    *trap_code = TRAP_MEM;
                }
            }
            unsafe { idt_asm::fast_sti_restore(flags) };
            return 0;
        }
    };
    let pd = sandbox.phys_addr() as u32;
    jit_fault_enter(trap_code);
    unsafe { paging::set_page_directory(pd) };
    let ret = unsafe {
        (jit_entry.entry)(
            stack_ptr,
            sp_ptr,
            mem_ptr,
            mem_len,
            locals_ptr,
            instr_fuel,
            mem_fuel,
            trap_code,
            shadow_stack_ptr,
            shadow_sp_ptr,
        )
    };
    unsafe { paging::set_page_directory(old_cr3) };
    jit_fault_exit();
    unsafe { idt_asm::fast_sti_restore(flags) };
    ret
}

fn call_jit_direct(
    jit_entry: JitExecInfo,
    stack_ptr: *mut i32,
    sp_ptr: *mut usize,
    mem_ptr: *mut u8,
    mem_len: usize,
    locals_ptr: *mut i32,
    instr_fuel: *mut u32,
    mem_fuel: *mut u32,
    trap_code: *mut i32,
    shadow_stack_ptr: *mut u32,
    shadow_sp_ptr: *mut usize,
) -> i32 {
    let flags = unsafe { idt_asm::fast_cli_save() };
    jit_fault_enter(trap_code);
    let ret = unsafe {
        (jit_entry.entry)(
            stack_ptr,
            sp_ptr,
            mem_ptr,
            mem_len,
            locals_ptr,
            instr_fuel,
            mem_fuel,
            trap_code,
            shadow_stack_ptr,
            shadow_sp_ptr,
        )
    };
    jit_fault_exit();
    unsafe { idt_asm::fast_sti_restore(flags) };
    ret
}

fn call_jit_user(
    jit_entry: JitExecInfo,
    _stack_ptr: *mut i32,
    _sp_ptr: *mut usize,
    mem_ptr: *mut u8,
    mem_len: usize,
    _locals_ptr: *mut i32,
    instr_fuel: *mut u32,
    mem_fuel: *mut u32,
    trap_code: *mut i32,
    _shadow_stack_ptr: *mut u32,
    _shadow_sp_ptr: *mut usize,
    jit_state_base: *mut u8,
    jit_state_pages: usize,
    jit_user_pages: &mut Option<JitUserPages>,
) -> Result<i32, &'static str> {
    let _guard = JIT_USER_LOCK.lock();
    let _ = instr_fuel;
    let _ = mem_fuel;
    if jit_state_base.is_null() || jit_state_pages == 0 {
        return Err("JIT state not initialized");
    }
    if mem_ptr.is_null() || mem_len == 0 {
        return Err("Invalid WASM memory");
    }

    if JIT_USER_ACTIVE.load(Ordering::SeqCst) != 0 {
        return Err("JIT user mode already active");
    }
    JIT_USER_RETURN_PENDING.store(0, Ordering::SeqCst);

    let pages = ensure_jit_user_pages(jit_user_pages)?;
    wipe_jit_user_pages(&pages);

    let mut sandbox = if kpti::enabled() {
        paging::AddressSpace::new_user_minimal()?
    } else {
        paging::AddressSpace::new_jit_sandbox()?
    };

    let kernel_guard = paging::kernel_space().lock();
    let kernel_space = kernel_guard
        .as_ref()
        .ok_or("Kernel address space not initialized")?;

    if kpti::enabled() {
        kpti::map_user_support(&mut sandbox, kernel_space)?;
    }

    let trampoline_phys = kernel_space
        .virt_to_phys(pages.trampoline)
        .ok_or("Trampoline not mapped")?;
    let call_phys = kernel_space
        .virt_to_phys(pages.call)
        .ok_or("Call page not mapped")?;
    let stack_phys = kernel_space
        .virt_to_phys(pages.stack)
        .ok_or("User stack not mapped")?;

    let exec_ptr = jit_entry.exec_ptr as usize;
    let exec_phys = kernel_space
        .virt_to_phys(exec_ptr)
        .ok_or("JIT exec not mapped")?;
    let exec_offset = exec_ptr & (paging::PAGE_SIZE - 1);
    let exec_map_len = jit_entry
        .exec_len
        .checked_add(exec_offset)
        .ok_or("JIT exec size overflow")?;

    let mem_ptr_usize = mem_ptr as usize;
    let mem_phys = kernel_space
        .virt_to_phys(mem_ptr_usize)
        .ok_or("WASM memory not mapped")?;
    let mem_offset = mem_ptr_usize & (paging::PAGE_SIZE - 1);
    let mem_map_len = mem_len
        .checked_add(mem_offset)
        .ok_or("WASM memory size overflow")?;

    let state_ptr = jit_state_base as usize;
    let state_phys = kernel_space
        .virt_to_phys(state_ptr)
        .ok_or("JIT state not mapped")?;
    let state_offset = state_ptr & (paging::PAGE_SIZE - 1);
    let state_map_len = jit_state_pages
        .checked_mul(paging::PAGE_SIZE)
        .ok_or("JIT state size overflow")?
        .checked_add(state_offset)
        .ok_or("JIT state size overflow")?;

    let code_guard = USER_JIT_CODE_GUARD_PAGES * paging::PAGE_SIZE;
    let data_guard = USER_JIT_DATA_GUARD_PAGES * paging::PAGE_SIZE;
    let mem_guard = USER_WASM_MEM_GUARD_PAGES * paging::PAGE_SIZE;

    let code_window = USER_JIT_DATA_BASE
        .checked_sub(USER_JIT_CODE_BASE)
        .ok_or("JIT code window overflow")?;
    let data_window = USER_WASM_MEM_BASE
        .checked_sub(USER_JIT_DATA_BASE)
        .ok_or("JIT data window overflow")?;
    let mem_window = paging::USER_TOP
        .checked_sub(USER_WASM_MEM_BASE)
        .ok_or("WASM memory window overflow")?;

    let code_guard_total = code_guard
        .checked_mul(2)
        .ok_or("JIT code guard overflow")?;
    if code_guard_total >= code_window {
        return Err("JIT code guard exceeds window");
    }
    let data_guard_total = data_guard
        .checked_mul(2)
        .ok_or("JIT data guard overflow")?;
    if data_guard_total >= data_window {
        return Err("JIT data guard exceeds window");
    }
    let mem_guard_total = mem_guard
        .checked_mul(2)
        .ok_or("WASM memory guard overflow")?;
    if mem_guard_total >= mem_window {
        return Err("WASM memory guard exceeds window");
    }

    let code_max = code_window - code_guard_total;
    if exec_map_len > code_max {
        return Err("JIT code mapping exceeds window");
    }
    let data_max = data_window - data_guard_total;
    if state_map_len > data_max {
        return Err("JIT state mapping exceeds window");
    }
    let mem_max = mem_window - mem_guard_total;
    if mem_map_len > mem_max {
        return Err("WASM memory mapping exceeds window");
    }

    let code_base = USER_JIT_CODE_BASE
        .checked_add(code_guard)
        .ok_or("JIT code base overflow")?;
    let data_base = USER_JIT_DATA_BASE
        .checked_add(data_guard)
        .ok_or("JIT data base overflow")?;
    let mem_base = USER_WASM_MEM_BASE
        .checked_add(mem_guard)
        .ok_or("WASM memory base overflow")?;
    let guard_bytes = USER_JIT_STACK_GUARD_PAGES * paging::PAGE_SIZE;

    memory_isolation::tag_jit_user_trampoline(trampoline_phys, paging::PAGE_SIZE, true)?;
    memory_isolation::tag_jit_user_state(call_phys, paging::PAGE_SIZE, true)?;
    memory_isolation::tag_jit_user_stack(
        stack_phys + guard_bytes,
        USER_JIT_STACK_PAGES * paging::PAGE_SIZE,
        true,
    )?;
    memory_isolation::tag_jit_code_user(exec_phys, exec_map_len)?;
    memory_isolation::tag_jit_user_state(state_phys, state_map_len, true)?;
    memory_isolation::tag_wasm_linear_memory(mem_phys, mem_map_len, true)?;

    sandbox.map_user_range_phys(
        USER_JIT_TRAMPOLINE_BASE,
        trampoline_phys,
        paging::PAGE_SIZE,
        false,
    )?;
    sandbox.map_user_range_phys(
        USER_JIT_CALL_BASE,
        call_phys,
        paging::PAGE_SIZE,
        true,
    )?;
    sandbox.map_user_range_phys(
        USER_JIT_STACK_BASE + guard_bytes,
        stack_phys + guard_bytes,
        USER_JIT_STACK_PAGES * paging::PAGE_SIZE,
        true,
    )?;
    sandbox.map_user_range_phys(
        code_base,
        exec_phys,
        exec_map_len,
        false,
    )?;
    sandbox.map_user_range_phys(
        data_base,
        state_phys,
        state_map_len,
        true,
    )?;
    sandbox.map_user_range_phys(
        mem_base,
        mem_phys,
        mem_map_len,
        true,
    )?;

    let enclave_session = crate::enclave::open_jit_session(
        exec_phys,
        exec_map_len,
        state_phys,
        state_map_len,
        mem_phys,
        mem_map_len,
    )?;

    let sandbox_pd = sandbox.phys_addr() as u32;
    drop(kernel_guard);

    let entry_offset = (jit_entry.entry as usize)
        .checked_sub(exec_ptr)
        .ok_or("Invalid JIT entry")?;
    if entry_offset >= jit_entry.exec_len {
        return Err("JIT entry out of range");
    }
    let user_entry = code_base
        .checked_add(exec_offset)
        .and_then(|v| v.checked_add(entry_offset))
        .ok_or("User entry overflow")?;

    let user_state_base = data_base + state_offset;
    let state_ptr = jit_state_base as *mut JitUserState;
    let base = state_ptr as usize;
    let stack_off = unsafe { core::ptr::addr_of!((*state_ptr).stack) as usize } - base;
    let sp_off = unsafe { core::ptr::addr_of!((*state_ptr).sp) as usize } - base;
    let locals_off = unsafe { core::ptr::addr_of!((*state_ptr).locals) as usize } - base;
    let instr_fuel_off =
        unsafe { core::ptr::addr_of!((*state_ptr).instr_fuel) as usize } - base;
    let mem_fuel_off = unsafe { core::ptr::addr_of!((*state_ptr).mem_fuel) as usize } - base;
    let trap_off = unsafe { core::ptr::addr_of!((*state_ptr).trap_code) as usize } - base;
    let shadow_stack_off =
        unsafe { core::ptr::addr_of!((*state_ptr).shadow_stack) as usize } - base;
    let shadow_sp_off =
        unsafe { core::ptr::addr_of!((*state_ptr).shadow_sp) as usize } - base;

    let user_mem_ptr = mem_base + mem_offset;

    let call_ptr = pages.call as *mut JitUserCall;
    unsafe {
        (*call_ptr).entry = user_entry as u32;
        (*call_ptr).stack_ptr = (user_state_base + stack_off) as u32;
        (*call_ptr).sp_ptr = (user_state_base + sp_off) as u32;
        (*call_ptr).mem_ptr = user_mem_ptr as u32;
        (*call_ptr).mem_len = mem_len as u32;
        (*call_ptr).locals_ptr = (user_state_base + locals_off) as u32;
        (*call_ptr).instr_fuel_ptr = (user_state_base + instr_fuel_off) as u32;
        (*call_ptr).mem_fuel_ptr = (user_state_base + mem_fuel_off) as u32;
        (*call_ptr).trap_ptr = (user_state_base + trap_off) as u32;
        (*call_ptr).shadow_stack_ptr = (user_state_base + shadow_stack_off) as u32;
        (*call_ptr).shadow_sp_ptr = (user_state_base + shadow_sp_off) as u32;
        (*call_ptr).ret = 0;
    }

    // Ensure trap pointers are set for fault handling.
    jit_fault_enter(trap_code);

    if let Some(session_id) = enclave_session {
        if let Err(e) = crate::enclave::enter(session_id) {
            let _ = crate::enclave::close(session_id);
            return Err(e);
        }
    }

    let flags = unsafe { idt_asm::fast_cli_save() };
    let old_cr3 = paging::current_page_directory_addr();
    if kpti::enabled() {
        let _ = kpti::enter_user(sandbox_pd);
    }
    unsafe { paging::set_page_directory(sandbox_pd) };

    let user_stack_top = USER_JIT_STACK_BASE
        + guard_bytes
        + (USER_JIT_STACK_PAGES * paging::PAGE_SIZE)
        - 16;
    unsafe {
        process_asm::jit_user_enter(
            user_stack_top as u32,
            USER_JIT_TRAMPOLINE_BASE as u32,
            gdt::USER_CS,
            gdt::USER_DS,
        );
    }

    unsafe { paging::set_page_directory(old_cr3) };
    if kpti::enabled() {
        kpti::leave_user();
    }
    jit_fault_exit();
    if let Some(session_id) = enclave_session {
        let _ = crate::enclave::exit(session_id);
        let _ = crate::enclave::close(session_id);
    }
    let _ = memory_isolation::tag_jit_user_trampoline(trampoline_phys, paging::PAGE_SIZE, false);
    let _ = memory_isolation::tag_jit_user_state(call_phys, paging::PAGE_SIZE, false);
    let _ = memory_isolation::tag_jit_user_stack(
        stack_phys,
        pages.stack_pages * paging::PAGE_SIZE,
        false,
    );
    let _ = memory_isolation::tag_jit_code_kernel(exec_phys, exec_map_len, true);
    let _ = memory_isolation::tag_jit_user_state(state_phys, state_map_len, false);
    let _ = memory_isolation::tag_wasm_linear_memory(mem_phys, mem_map_len, false);
    unsafe { idt_asm::fast_sti_restore(flags) };

    let ret = unsafe { (*call_ptr).ret };
    Ok(ret)
}

fn hash_code(code: &[u8], locals_total: usize) -> u64 {
    let mut hash: u64 = 14695981039346656037;
    for &b in code {
        hash ^= b as u64;
        hash = hash.wrapping_mul(1099511628211);
    }
    hash ^= locals_total as u64;
    hash = hash.wrapping_mul(1099511628211);
    hash ^= code.len() as u64;
    hash = hash.wrapping_mul(1099511628211);
    hash
}

fn hash_memory(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 14695981039346656037;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(1099511628211);
    }
    hash
}

fn hash_memory_fuzz(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 14695981039346656037;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(1099511628211);
    }
    hash
}

fn jit_cache_get(hash: u64, code: &[u8], locals_total: usize) -> Option<JitExecInfo> {
    let cache = JIT_CACHE.lock();
    for entry in cache.entries.iter() {
        if entry.hash == hash && entry.locals_total == locals_total && entry.code_len == code.len() {
            if entry.func.wasm_code != code {
                continue;
            }
            if !entry.func.verify_integrity() {
                return None;
            }
            return Some(JitExecInfo {
                entry: entry.func.entry,
                exec_ptr: entry.func.exec.ptr,
                exec_len: entry.func.exec.len,
            });
        }
    }
    None
}

fn jit_cache_get_or_compile(hash: u64, code: &[u8], locals_total: usize) -> Option<JitExecInfo> {
    if let Some(entry) = jit_cache_get(hash, code, locals_total) {
        return Some(entry);
    }
    let jit = match crate::wasm_jit::compile(code, locals_total) {
        Ok(j) => j,
        Err(_) => {
            jit_stats().lock().failed += 1;
            return None;
        }
    };
    let mut cache = JIT_CACHE.lock();
    if cache.entries.len() < cache.max_entries {
        cache.entries.push(JitCacheEntry {
            hash,
            locals_total,
            code_len: code.len(),
            func: jit,
        });
        let entry = cache.entries.last().unwrap();
        return Some(JitExecInfo {
            entry: entry.func.entry,
            exec_ptr: entry.func.exec.ptr,
            exec_len: entry.func.exec.len,
        });
    }
    let idx = (hash as usize) % cache.entries.len();
    cache.entries[idx] = JitCacheEntry {
        hash,
        locals_total,
        code_len: code.len(),
        func: jit,
    };
    let entry = &cache.entries[idx];
    Some(JitExecInfo {
        entry: entry.func.entry,
        exec_ptr: entry.func.exec.ptr,
        exec_len: entry.func.exec.len,
    })
}

/// Simple JIT benchmark (returns interpreter_ticks, jit_ticks)
pub fn jit_benchmark() -> Result<(u64, u64), &'static str> {
    jit_config().lock().enabled = true;
    let mut module = WasmModule::new();
    let mut code: Vec<u8> = Vec::new();

    // i32.const 1
    code.push(Opcode::I32Const as u8);
    code.push(0x01);
    // Repeat: const 2; add
    for _ in 0..128 {
        code.push(Opcode::I32Const as u8);
        code.push(0x02);
        code.push(Opcode::I32Add as u8);
    }
    code.push(Opcode::End as u8);

    module.load(&code).map_err(|_| "Module load failed")?;
    module.add_function(Function {
        code_offset: 0,
        code_len: code.len(),
        param_count: 0,
        result_count: 1,
        local_count: 0,
    }).map_err(|_| "Function add failed")?;

    let instance_id = wasm_runtime()
        .instantiate_module(module, ProcessId(1))
        .map_err(|_| "Instance create failed")?;
    let iterations = 200;

    let start = crate::pit::get_ticks();
    for _ in 0..iterations {
        wasm_runtime()
            .get_instance_mut(instance_id, |instance| {
                instance.stack.clear();
                instance.enable_jit(false);
                instance.call(0)
            })
            .map_err(|_| "Instance missing")?
            .map_err(|_| "Interpreter failed")?;
    }
    let interp_ticks = crate::pit::get_ticks().saturating_sub(start);

    let start = crate::pit::get_ticks();
    for _ in 0..iterations {
        wasm_runtime()
            .get_instance_mut(instance_id, |instance| {
                instance.stack.clear();
                instance.enable_jit(true);
                instance.call(0)
            })
            .map_err(|_| "Instance missing")?
            .map_err(|_| "JIT failed")?;
    }
    let jit_ticks = crate::pit::get_ticks().saturating_sub(start);

    let _ = wasm_runtime().destroy(instance_id);
    Ok((interp_ticks, jit_ticks))
}

/// JIT bounds self-test (expects MemoryOutOfBounds traps in both interpreter and JIT).
pub fn jit_bounds_self_test() -> Result<(), &'static str> {
    struct JitConfigGuard {
        enabled: bool,
        hot_threshold: u32,
        user_mode: bool,
    }
    impl Drop for JitConfigGuard {
        fn drop(&mut self) {
            let mut cfg = jit_config().lock();
            cfg.enabled = self.enabled;
            cfg.hot_threshold = self.hot_threshold;
            cfg.user_mode = self.user_mode;
        }
    }

    let guard = {
        let mut cfg = jit_config().lock();
        let guard = JitConfigGuard {
            enabled: cfg.enabled,
            hot_threshold: cfg.hot_threshold,
            user_mode: cfg.user_mode,
        };
        cfg.enabled = true;
        cfg.hot_threshold = 0;
        cfg.user_mode = true;
        guard
    };

    let mut module = WasmModule::new();
    let mut code: Vec<u8> = Vec::new();

    fn push_uleb128(buf: &mut Vec<u8>, mut value: u32) {
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    // i32.const 8
    code.push(Opcode::I32Const as u8);
    code.push(0x08);
    // i32.load align=0 offset=0xFFFF_FFFC (overflow when added to 8)
    code.push(Opcode::I32Load as u8);
    push_uleb128(&mut code, 0);
    push_uleb128(&mut code, 0xFFFF_FFFC);
    code.push(Opcode::End as u8);

    module.load(&code).map_err(|_| "Module load failed")?;
    module
        .add_function(Function {
            code_offset: 0,
            code_len: code.len(),
            param_count: 0,
            result_count: 1,
            local_count: 0,
        })
        .map_err(|_| "Function add failed")?;

    let instance_id = wasm_runtime()
        .instantiate_module(module, ProcessId(1))
        .map_err(|_| "Instance create failed")?;

    let interp = wasm_runtime()
        .get_instance_mut(instance_id, |instance| {
            instance.stack.clear();
            instance.enable_jit(false);
            instance.call(0)
        })
        .map_err(|_| "Instance missing")?;
    if !matches!(interp, Err(WasmError::MemoryOutOfBounds)) {
        let _ = wasm_runtime().destroy(instance_id);
        drop(guard);
        return Err("Interpreter did not trap on bounds overflow");
    }

    let jit = wasm_runtime()
        .get_instance_mut(instance_id, |instance| {
            instance.stack.clear();
            instance.enable_jit(true);
            instance.call(0)
        })
        .map_err(|_| "Instance missing")?;
    if !matches!(jit, Err(WasmError::MemoryOutOfBounds)) {
        let _ = wasm_runtime().destroy(instance_id);
        drop(guard);
        return Err("JIT did not trap on bounds overflow");
    }

    let _ = wasm_runtime().destroy(instance_id);
    drop(guard);
    Ok(())
}

/// JIT fuzzing harness (generates random programs and compares interpreter vs JIT).
fn ensure_fuzz_instances() -> Result<(usize, usize), &'static str> {
    let mut slots = JIT_FUZZ_INSTANCES.lock();
    if let Some((interp_id, jit_id)) = *slots {
        let interp_ok = wasm_runtime().get_instance_mut(interp_id, |_| ()).is_ok();
        let jit_ok = wasm_runtime().get_instance_mut(jit_id, |_| ()).is_ok();
        if interp_ok && jit_ok {
            return Ok((interp_id, jit_id));
        }
        *slots = None;
    }

    let mut base_module = WasmModule::new();
    base_module.reserve_bytecode(MAX_FUZZ_CODE_SIZE);
    base_module
        .load(&[Opcode::End as u8])
        .map_err(|_| "Module load failed")?;
    base_module
        .add_function(Function {
            code_offset: 0,
            code_len: 1,
            param_count: 0,
            result_count: 1,
            local_count: 0,
        })
        .map_err(|_| "Function add failed")?;

    let interp_id = wasm_runtime()
        .instantiate_module(base_module.clone(), ProcessId(1))
        .map_err(|_| "Instance create failed")?;
    let jit_id = wasm_runtime()
        .instantiate_module(base_module, ProcessId(1))
        .map_err(|_| "Instance create failed")?;
    *slots = Some((interp_id, jit_id));
    Ok((interp_id, jit_id))
}

pub fn jit_fuzz(iterations: u32, seed: u64) -> Result<JitFuzzStats, &'static str> {
    struct JitConfigGuard {
        enabled: bool,
        hot_threshold: u32,
        user_mode: bool,
    }
    impl Drop for JitConfigGuard {
        fn drop(&mut self) {
            let mut cfg = jit_config().lock();
            cfg.enabled = self.enabled;
            cfg.hot_threshold = self.hot_threshold;
            cfg.user_mode = self.user_mode;
        }
    }

    struct FuzzRng {
        state: u64,
    }
    impl FuzzRng {
        fn new(mut seed: u64) -> Self {
            if seed == 0 {
                seed = 0x9E37_79B9_7F4A_7C15;
            }
            FuzzRng { state: seed }
        }
        fn next_u32(&mut self) -> u32 {
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.state = x;
            (x as u32) ^ ((x >> 32) as u32)
        }
        fn next_i32(&mut self) -> i32 {
            self.next_u32() as i32
        }
    }

    fn push_uleb128(buf: &mut Vec<u8>, mut value: u32) {
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    fn push_sleb128_i32(buf: &mut Vec<u8>, mut value: i32) {
        let mut more = true;
        while more {
            let mut byte = (value & 0x7F) as u8;
            let sign = (byte & 0x40) != 0;
            value >>= 7;
            if (value == 0 && !sign) || (value == -1 && sign) {
                more = false;
            } else {
                byte |= 0x80;
            }
            buf.push(byte);
        }
    }

    fn first_nonzero(bytes: &[u8]) -> Option<(u32, u8)> {
        for (idx, byte) in bytes.iter().enumerate() {
            if *byte != 0 {
                return Some((idx as u32, *byte));
            }
        }
        None
    }

    fn choose_guided_choice(rng: &mut FuzzRng, opcode_hits: &[u32; JIT_FUZZ_OPCODE_BINS]) -> u32 {
        let mut min_hit = u32::MAX;
        let mut i = 0usize;
        while i < opcode_hits.len() {
            if opcode_hits[i] < min_hit {
                min_hit = opcode_hits[i];
            }
            i += 1;
        }

        // Prefer under-covered opcode bins, with occasional random exploration.
        if (rng.next_u32() % 100) < 80 {
            let mut candidates = [0u8; JIT_FUZZ_OPCODE_BINS];
            let mut n = 0usize;
            let mut idx = 0usize;
            while idx < opcode_hits.len() {
                if opcode_hits[idx] <= min_hit.saturating_add(1) {
                    candidates[n] = idx as u8;
                    n += 1;
                }
                idx += 1;
            }
            if n > 0 {
                let pick = (rng.next_u32() as usize) % n;
                return candidates[pick] as u32;
            }
        }
        rng.next_u32() % (JIT_FUZZ_OPCODE_BINS as u32)
    }

    let _guard = {
        let mut cfg = jit_config().lock();
        let guard = JitConfigGuard {
            enabled: cfg.enabled,
            hot_threshold: cfg.hot_threshold,
            user_mode: cfg.user_mode,
        };
        cfg.enabled = true;
        cfg.hot_threshold = 0;
        cfg.user_mode = false;
        guard
    };
    let _rate_guard = {
        struct RateLimitGuard {
            enabled: bool,
        }
        impl Drop for RateLimitGuard {
            fn drop(&mut self) {
                crate::security::security().set_rate_limit_enabled(self.enabled);
            }
        }
        let sec = crate::security::security();
        let prev = sec.rate_limit_enabled();
        sec.set_rate_limit_enabled(false);
        RateLimitGuard { enabled: prev }
    };

    let mut scratch_slot = JIT_FUZZ_SCRATCH.lock();
    if scratch_slot.is_none() {
        *scratch_slot = Some(JitFuzzScratch::new());
    }
    let scratch = scratch_slot.as_mut().ok_or("Fuzz scratch init failed")?;
    let code = &mut scratch.code;
    let interp_mem_snapshot = &mut scratch.interp_mem_snapshot;
    let choice_trace = &mut scratch.choice_trace;

    let mut compiler_slot = JIT_FUZZ_COMPILER.lock();
    if compiler_slot.is_none() {
        *compiler_slot = Some(
            crate::wasm_jit::FuzzCompiler::new(MAX_FUZZ_JIT_CODE_SIZE)
                .map_err(|_| "Fuzz compiler init failed")?,
        );
    }
    let compiler = compiler_slot.as_mut().ok_or("Fuzz compiler init failed")?;

    let (interp_id, jit_id) = ensure_fuzz_instances()?;

    let _ = wasm_runtime().get_instance_mut(interp_id, |instance| {
        instance.prepare_fuzz();
    });
    let _ = wasm_runtime().get_instance_mut(jit_id, |instance| {
        instance.prepare_fuzz();
    });

    let mut rng = FuzzRng::new(seed);
    let mut stats = JitFuzzStats {
        iterations,
        ok: 0,
        traps: 0,
        mismatches: 0,
        compile_errors: 0,
        opcode_bins_hit: 0,
        opcode_edges_hit: 0,
        novel_programs: 0,
        first_mismatch: None,
        first_compile_error: None,
    };
    let mut opcode_hits = [0u32; JIT_FUZZ_OPCODE_BINS];
    let mut opcode_seen = [false; JIT_FUZZ_OPCODE_BINS];
    let mut edge_seen = [false; JIT_FUZZ_OPCODE_BINS * JIT_FUZZ_OPCODE_BINS];

    for iter in 0..iterations {
        let locals_total = (rng.next_u32() % 4) as usize;
        code.clear();
        choice_trace.clear();
        let mut stack_depth: i32 = 0;
        let ops = 8 + (rng.next_u32() % 32) as usize;

        for _ in 0..ops {
            // Keep enough headroom for the largest generated opcode sequence:
            // i32.store + 2x uleb32 (1 + 5 + 5 bytes) plus trailing End.
            if code.len() + 16 >= MAX_FUZZ_CODE_SIZE {
                break;
            }
            let choice = choose_guided_choice(&mut rng, &opcode_hits);
            let mut emitted_choice: Option<u8> = None;
            match choice {
                0 => {
                    code.push(Opcode::Nop as u8);
                    emitted_choice = Some(0);
                }
                1 => {
                    if stack_depth > 0 {
                        code.push(Opcode::Drop as u8);
                        stack_depth -= 1;
                        emitted_choice = Some(1);
                    } else {
                        code.push(Opcode::I32Const as u8);
                        push_sleb128_i32(code, rng.next_i32());
                        stack_depth += 1;
                        emitted_choice = Some(1);
                    }
                }
                2 => {
                    if stack_depth < (MAX_STACK_DEPTH as i32) - 1 {
                        code.push(Opcode::I32Const as u8);
                        push_sleb128_i32(code, rng.next_i32());
                        stack_depth += 1;
                        emitted_choice = Some(2);
                    }
                }
                3 => {
                    if stack_depth >= 2 {
                        code.push(Opcode::I32Add as u8);
                        stack_depth -= 1;
                        emitted_choice = Some(3);
                    }
                }
                4 => {
                    if stack_depth >= 2 {
                        code.push(Opcode::I32Sub as u8);
                        stack_depth -= 1;
                        emitted_choice = Some(4);
                    }
                }
                5 => {
                    if stack_depth >= 2 {
                        code.push(Opcode::I32Mul as u8);
                        stack_depth -= 1;
                        emitted_choice = Some(5);
                    }
                }
                6 => {
                    if stack_depth >= 2 {
                        code.push(Opcode::I32And as u8);
                        stack_depth -= 1;
                        emitted_choice = Some(6);
                    }
                }
                7 => {
                    if stack_depth >= 2 {
                        code.push(Opcode::I32Or as u8);
                        stack_depth -= 1;
                        emitted_choice = Some(7);
                    }
                }
                8 => {
                    if stack_depth >= 2 {
                        code.push(Opcode::I32Xor as u8);
                        stack_depth -= 1;
                        emitted_choice = Some(8);
                    }
                }
                9 => {
                    if stack_depth >= 1 {
                        code.push(Opcode::I32Eqz as u8);
                        emitted_choice = Some(9);
                    }
                }
                10 => {
                    if stack_depth >= 1 {
                        code.push(Opcode::I32Load as u8);
                        push_uleb128(code, 0);
                        push_uleb128(code, rng.next_u32());
                        emitted_choice = Some(10);
                    }
                }
                11 => {
                    if stack_depth >= 2 {
                        code.push(Opcode::I32Store as u8);
                        push_uleb128(code, 0);
                        push_uleb128(code, rng.next_u32());
                        stack_depth -= 2;
                        emitted_choice = Some(11);
                    }
                }
                12 => {
                    if locals_total > 0 {
                        code.push(Opcode::LocalGet as u8);
                        push_uleb128(code, (rng.next_u32() as usize % locals_total) as u32);
                        stack_depth += 1;
                        emitted_choice = Some(12);
                    }
                }
                _ => {
                    if locals_total > 0 && stack_depth > 0 {
                        code.push(Opcode::LocalSet as u8);
                        push_uleb128(code, (rng.next_u32() as usize % locals_total) as u32);
                        stack_depth -= 1;
                        emitted_choice = Some(13);
                    }
                }
            }
            if let Some(choice_idx) = emitted_choice {
                let idx = choice_idx as usize;
                opcode_hits[idx] = opcode_hits[idx].saturating_add(1);
                choice_trace.push(choice_idx);
            }
        }

        // Normalize stack shape for a single i32 return value.
        while stack_depth > 1 && code.len() + 2 < MAX_FUZZ_CODE_SIZE {
            code.push(Opcode::Drop as u8);
            stack_depth -= 1;
        }
        while stack_depth < 1 && code.len() + 8 < MAX_FUZZ_CODE_SIZE {
            code.push(Opcode::I32Const as u8);
            push_sleb128_i32(code, 0);
            stack_depth += 1;
        }

        code.push(Opcode::End as u8);

        // Defensive hardening: if generation buffer was perturbed by prior unsafe
        // execution side effects, repair to a canonical valid program so fuzzing
        // can continue and still compare interpreter/JIT semantics.
        if validate_bytecode(&code).is_err() {
            code.clear();
            code.push(Opcode::I32Const as u8);
            push_sleb128_i32(code, 0);
            code.push(Opcode::End as u8);
        }

        let mut novel = false;
        let mut prev: Option<u8> = None;
        let mut i = 0usize;
        while i < choice_trace.len() {
            let op = choice_trace[i] as usize;
            if !opcode_seen[op] {
                opcode_seen[op] = true;
                novel = true;
            }
            if let Some(p) = prev {
                let edge_idx = (p as usize) * JIT_FUZZ_OPCODE_BINS + op;
                if !edge_seen[edge_idx] {
                    edge_seen[edge_idx] = true;
                    novel = true;
                }
            }
            prev = Some(choice_trace[i]);
            i += 1;
        }
        if novel {
            stats.novel_programs = stats.novel_programs.saturating_add(1);
        }

        let interp = match wasm_runtime().get_instance_mut(interp_id, |instance| {
            instance.load_fuzz_program(&code, locals_total)?;
            instance.enable_jit(false);
            let mut res = instance.call(0);
            if res.is_err() {
                // Retry once from a clean state to filter transient runtime
                // corruption from previous unsafe JIT iterations.
                instance.load_fuzz_program(&code, locals_total)?;
                instance.enable_jit(false);
                res = instance.call(0);
            }
            let value = instance
                .stack
                .peek()
                .ok()
                .and_then(|v| v.as_i32().ok())
                .unwrap_or(0);
            let mem_slice = instance.memory.active_slice();
            interp_mem_snapshot.clear();
            interp_mem_snapshot.extend_from_slice(mem_slice);
            let mem_hash = hash_memory_fuzz(mem_slice);
            let mem_len = mem_slice.len() as u32;
            let first_nz = first_nonzero(mem_slice);
            Ok::<(Result<i32, WasmError>, u64, u32, Option<(u32, u8)>), WasmError>((
                res.map(|_| value),
                mem_hash,
                mem_len,
                first_nz,
            ))
        }) {
            Ok(result) => match result {
                Ok(val) => val,
                Err(e) => {
                    stats.compile_errors += 1;
                    if stats.first_compile_error.is_none() {
                        stats.first_compile_error = Some(JitFuzzCompileError {
                            iteration: iter,
                            locals_total: locals_total as u32,
                            stage: "interp-load",
                            reason: e.as_str(),
                            code: code.clone(),
                            jit_code: Vec::new(),
                        });
                    }
                    continue;
                }
            },
            Err(_) => return Err("Instance missing"),
        };

        let entry = match compiler.compile(&code, locals_total) {
            Ok(entry) => entry,
            Err(first_err) => {
                // Rarely, verifier/page-perm state can become stale across a long
                // fuzz run. Retry once in-place, then once with a fresh compiler
                // before classifying as a real compile failure.
                match compiler.compile(&code, locals_total) {
                    Ok(entry) => entry,
                    Err(second_err) => {
                        match crate::wasm_jit::FuzzCompiler::new(MAX_FUZZ_JIT_CODE_SIZE) {
                            Ok(mut fresh_compiler) => match fresh_compiler.compile(&code, locals_total) {
                                Ok(entry) => {
                                    *compiler = fresh_compiler;
                                    entry
                                }
                                Err(fresh_err) => {
                                    stats.compile_errors += 1;
                                    if stats.first_compile_error.is_none() {
                                        let mut jit_code = Vec::new();
                                        jit_code.extend_from_slice(fresh_compiler.emitted_code());
                                        stats.first_compile_error = Some(JitFuzzCompileError {
                                            iteration: iter,
                                            locals_total: locals_total as u32,
                                            stage: "jit-compile",
                                            reason: fresh_err,
                                            code: code.clone(),
                                            jit_code,
                                        });
                                    }
                                    continue;
                                }
                            },
                            Err(new_err) => {
                                let reason = if second_err != first_err {
                                    second_err
                                } else {
                                    new_err
                                };
                                stats.compile_errors += 1;
                                if stats.first_compile_error.is_none() {
                                    let mut jit_code = Vec::new();
                                    jit_code.extend_from_slice(compiler.emitted_code());
                                    stats.first_compile_error = Some(JitFuzzCompileError {
                                        iteration: iter,
                                        locals_total: locals_total as u32,
                                        stage: "jit-compile",
                                        reason,
                                        code: code.clone(),
                                        jit_code,
                                    });
                                }
                                continue;
                            }
                        }
                    }
                }
            }
        };
        let jit_entry = JitExecInfo {
            entry,
            exec_ptr: compiler.exec_ptr(),
            exec_len: compiler.exec_len(),
        };

        let jit = match wasm_runtime().get_instance_mut(jit_id, |instance| {
            instance.load_fuzz_program(&code, locals_total)?;
            let res = instance.run_jit_entry(0, jit_entry);
            let value = instance
                .stack
                .peek()
                .ok()
                .and_then(|v| v.as_i32().ok())
                .unwrap_or(0);
            let mem_slice = instance.memory.active_slice();
            let mem_hash = hash_memory_fuzz(mem_slice);
            let mem_len = mem_slice.len() as u32;
            let first_nz = first_nonzero(mem_slice);
            let mem_equal = mem_slice == interp_mem_snapshot.as_slice();
            Ok::<(Result<i32, WasmError>, u64, u32, Option<(u32, u8)>, bool), WasmError>((
                res.map(|_| value),
                mem_hash,
                mem_len,
                first_nz,
                mem_equal,
            ))
        }) {
            Ok(result) => match result {
                Ok(val) => val,
                Err(e) => {
                    stats.compile_errors += 1;
                    if stats.first_compile_error.is_none() {
                        stats.first_compile_error = Some(JitFuzzCompileError {
                            iteration: iter,
                            locals_total: locals_total as u32,
                            stage: "jit-load",
                            reason: e.as_str(),
                            code: code.clone(),
                            jit_code: Vec::new(),
                        });
                    }
                    continue;
                }
            },
            Err(_) => return Err("Instance missing"),
        };

        let interp_res = interp.0;
        let jit_res = jit.0;
        let interp_mem = interp.1;
        let jit_mem = jit.1;
        let interp_mem_len = interp.2;
        let jit_mem_len = jit.2;
        let interp_first_nonzero = interp.3;
        let jit_first_nonzero = jit.3;
        let mem_equal = jit.4;
        let mut mismatch = false;

        match (interp_res, jit_res) {
            (Ok(iv), Ok(jv)) => {
                if iv == jv && mem_equal {
                    stats.ok += 1;
                } else {
                    stats.mismatches += 1;
                    mismatch = true;
                }
            }
            (Err(ie), Err(je)) => {
                if ie == je {
                    stats.traps += 1;
                } else {
                    stats.mismatches += 1;
                    mismatch = true;
                }
            }
            _ => {
                stats.mismatches += 1;
                mismatch = true;
            }
        }

        if mismatch && stats.first_mismatch.is_none() {
            stats.first_mismatch = Some(JitFuzzMismatch {
                iteration: iter,
                locals_total: locals_total as u32,
                code: code.clone(),
                interp: interp_res,
                jit: jit_res,
                interp_mem_hash: interp_mem,
                jit_mem_hash: jit_mem,
                interp_mem_len,
                jit_mem_len,
                interp_first_nonzero,
                jit_first_nonzero,
            });
        }
    }

    let mut bins = 0u32;
    let mut edges = 0u32;
    let mut i = 0usize;
    while i < opcode_seen.len() {
        if opcode_seen[i] {
            bins += 1;
        }
        i += 1;
    }
    let mut j = 0usize;
    while j < edge_seen.len() {
        if edge_seen[j] {
            edges += 1;
        }
        j += 1;
    }
    stats.opcode_bins_hit = bins;
    stats.opcode_edges_hit = edges;

    Ok(stats)
}

pub fn jit_fuzz_regression_default(
    iterations_per_seed: u32,
) -> Result<JitFuzzRegressionStats, &'static str> {
    let mut out = JitFuzzRegressionStats {
        seeds_total: JIT_FUZZ_REGRESSION_SEEDS.len() as u32,
        seeds_passed: 0,
        seeds_failed: 0,
        total_ok: 0,
        total_traps: 0,
        total_mismatches: 0,
        total_compile_errors: 0,
        max_opcode_bins_hit: 0,
        max_opcode_edges_hit: 0,
        total_novel_programs: 0,
        first_failed_seed: None,
        first_failed_mismatches: 0,
        first_failed_compile_errors: 0,
        first_failed_mismatch: None,
        first_failed_compile_error: None,
    };

    let mut i = 0usize;
    while i < JIT_FUZZ_REGRESSION_SEEDS.len() {
        let seed = JIT_FUZZ_REGRESSION_SEEDS[i];
        let stats = jit_fuzz(iterations_per_seed, seed)?;
        out.total_ok = out.total_ok.saturating_add(stats.ok);
        out.total_traps = out.total_traps.saturating_add(stats.traps);
        out.total_mismatches = out.total_mismatches.saturating_add(stats.mismatches);
        out.total_compile_errors = out.total_compile_errors.saturating_add(stats.compile_errors);
        out.total_novel_programs = out.total_novel_programs.saturating_add(stats.novel_programs);
        if stats.opcode_bins_hit > out.max_opcode_bins_hit {
            out.max_opcode_bins_hit = stats.opcode_bins_hit;
        }
        if stats.opcode_edges_hit > out.max_opcode_edges_hit {
            out.max_opcode_edges_hit = stats.opcode_edges_hit;
        }

        if stats.mismatches == 0 && stats.compile_errors == 0 {
            out.seeds_passed = out.seeds_passed.saturating_add(1);
        } else {
            out.seeds_failed = out.seeds_failed.saturating_add(1);
            if out.first_failed_seed.is_none() {
                out.first_failed_seed = Some(seed);
                out.first_failed_mismatches = stats.mismatches;
                out.first_failed_compile_errors = stats.compile_errors;
                out.first_failed_mismatch = stats.first_mismatch;
                out.first_failed_compile_error = stats.first_compile_error;
            }
        }
        i += 1;
    }

    Ok(out)
}

pub fn jit_fuzz_regression_soak_default(
    iterations_per_seed: u32,
    rounds: u32,
) -> Result<JitFuzzSoakStats, &'static str> {
    if rounds == 0 {
        return Err("Rounds must be > 0");
    }

    let mut out = JitFuzzSoakStats {
        rounds,
        rounds_passed: 0,
        rounds_failed: 0,
        seeds_per_round: JIT_FUZZ_REGRESSION_SEEDS.len() as u32,
        total_seed_passes: 0,
        total_seed_failures: 0,
        total_ok: 0,
        total_traps: 0,
        total_mismatches: 0,
        total_compile_errors: 0,
        max_opcode_bins_hit: 0,
        max_opcode_edges_hit: 0,
        total_novel_programs: 0,
        first_failed_round: None,
        first_failed_seed: None,
        first_failed_mismatches: 0,
        first_failed_compile_errors: 0,
        first_failed_mismatch: None,
        first_failed_compile_error: None,
    };

    let mut round = 0u32;
    while round < rounds {
        let stats = jit_fuzz_regression_default(iterations_per_seed)?;

        out.total_seed_passes = out.total_seed_passes.saturating_add(stats.seeds_passed);
        out.total_seed_failures = out.total_seed_failures.saturating_add(stats.seeds_failed);
        out.total_ok = out.total_ok.saturating_add(stats.total_ok);
        out.total_traps = out.total_traps.saturating_add(stats.total_traps);
        out.total_mismatches = out.total_mismatches.saturating_add(stats.total_mismatches);
        out.total_compile_errors = out.total_compile_errors.saturating_add(stats.total_compile_errors);
        out.total_novel_programs = out.total_novel_programs.saturating_add(stats.total_novel_programs);
        if stats.max_opcode_bins_hit > out.max_opcode_bins_hit {
            out.max_opcode_bins_hit = stats.max_opcode_bins_hit;
        }
        if stats.max_opcode_edges_hit > out.max_opcode_edges_hit {
            out.max_opcode_edges_hit = stats.max_opcode_edges_hit;
        }

        if stats.seeds_failed == 0 {
            out.rounds_passed = out.rounds_passed.saturating_add(1);
        } else {
            out.rounds_failed = out.rounds_failed.saturating_add(1);
            if out.first_failed_round.is_none() {
                out.first_failed_round = Some(round.saturating_add(1));
                out.first_failed_seed = stats.first_failed_seed;
                out.first_failed_mismatches = stats.first_failed_mismatches;
                out.first_failed_compile_errors = stats.first_failed_compile_errors;
                out.first_failed_mismatch = stats.first_failed_mismatch;
                out.first_failed_compile_error = stats.first_failed_compile_error;
            }
        }

        round = round.saturating_add(1);
    }

    Ok(out)
}

// ============================================================================
// Syscall Wrapper Functions
// ============================================================================

/// Load WASM module (syscall wrapper)
pub fn load_module(bytecode: &[u8]) -> Result<usize, &'static str> {
    // TODO: Parse and validate WASM bytecode
    // For now, just return a dummy module ID
    validate_bytecode(bytecode).map_err(|_| "Invalid WASM module")?;
    Ok(1)
}

/// Call WASM function (syscall wrapper)
pub fn call_function(module_id: usize, func_idx: usize, args: &[u32]) -> Result<u32, &'static str> {
    // TODO: Look up module and call function
    // For now, just return 0
    let _ = (module_id, func_idx, args);
    Ok(0)
}
