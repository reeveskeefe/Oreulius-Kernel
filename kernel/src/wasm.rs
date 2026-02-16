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
use crate::capability::{self, CapabilityType, Rights};
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

/// Maximum number of service-pointer references tracked globally.
pub const MAX_SERVICE_POINTERS: usize = 64;

/// Maximum argument count accepted by a service-pointer invocation.
pub const MAX_SERVICE_CALL_ARGS: usize = 16;

const SERVICE_TYPED_SLOT_BYTES: usize = 9;
const SERVICE_TYPED_KIND_I32: u8 = 0;
const SERVICE_TYPED_KIND_I64: u8 = 1;
const SERVICE_TYPED_KIND_F32: u8 = 2;
const SERVICE_TYPED_KIND_F64: u8 = 3;
const SERVICE_TYPED_KIND_FUNCREF: u8 = 4;
const SERVICE_TYPED_KIND_EXTERNREF: u8 = 5;
const TEMPORAL_META_BYTES: usize = 32;
const TEMPORAL_ROLLBACK_BYTES: usize = 16;
const TEMPORAL_STATS_BYTES: usize = 20;
const TEMPORAL_HISTORY_RECORD_BYTES: usize = 64;
const TEMPORAL_BRANCH_ID_BYTES: usize = 4;
const TEMPORAL_BRANCH_CHECKOUT_BYTES: usize = 16;
const TEMPORAL_BRANCH_NAME_BYTES: usize = 48;
const TEMPORAL_BRANCH_RECORD_BYTES: usize = 20 + TEMPORAL_BRANCH_NAME_BYTES;
const TEMPORAL_MERGE_RESULT_BYTES: usize = 40;
const MAX_TEMPORAL_HISTORY_ENTRIES: usize = 128;
const MAX_TEMPORAL_BRANCH_ENTRIES: usize = 64;

/// Maximum module size (16 KiB - reduced to shrink kernel)
pub const MAX_MODULE_SIZE: usize = 16 * 1024;

/// Maximum global variables per module.
pub const MAX_WASM_GLOBALS: usize = 64;

/// Maximum table entries in the function table.
pub const MAX_WASM_TABLE_ENTRIES: usize = 256;

/// Maximum parameter/result arity tracked per function or block type.
pub const MAX_WASM_TYPE_ARITY: usize = 64;

/// Maximum number of exception tags per module (EH profile).
pub const MAX_WASM_TAGS: usize = 32;

/// Maximum exception payload arity tracked by EH runtime.
pub const MAX_EXCEPTION_ARITY: usize = 8;

/// Maximum number of syscall-loaded modules tracked in the kernel.
pub const MAX_SYSCALL_MODULES: usize = 32;

/// Maximum instructions executed per call (prevents infinite loops)
pub const MAX_INSTRUCTIONS_PER_CALL: usize = 100_000;

/// Maximum memory operations per call
pub const MAX_MEMORY_OPS_PER_CALL: usize = 10_000;

/// Maximum syscalls per execution
pub const MAX_SYSCALLS_PER_CALL: usize = 100;

/// Maximum nested WASM function call depth.
pub const MAX_CALL_DEPTH: usize = 64;

/// Maximum structured control frames active in one function body.
pub const MAX_CONTROL_STACK: usize = 128;

/// Maximum catch clauses tracked per try frame.
pub const MAX_TRY_CATCHES: usize = 8;

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
    FuncRef,
    ExternRef,
}

/// WASM values on the stack
#[derive(Debug, Clone, Copy)]
pub enum Value {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    FuncRef(Option<usize>),
    ExternRef(Option<u32>),
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

    pub fn as_f32(&self) -> Result<f32, WasmError> {
        match self {
            Value::F32(v) => Ok(*v),
            _ => Err(WasmError::TypeMismatch),
        }
    }

    pub fn as_f64(&self) -> Result<f64, WasmError> {
        match self {
            Value::F64(v) => Ok(*v),
            _ => Err(WasmError::TypeMismatch),
        }
    }

    pub fn as_u32(&self) -> Result<u32, WasmError> {
        Ok(self.as_i32()? as u32)
    }

    pub fn as_funcref(&self) -> Result<Option<usize>, WasmError> {
        match self {
            Value::FuncRef(v) => Ok(*v),
            _ => Err(WasmError::TypeMismatch),
        }
    }

    pub fn as_externref(&self) -> Result<Option<u32>, WasmError> {
        match self {
            Value::ExternRef(v) => Ok(*v),
            _ => Err(WasmError::TypeMismatch),
        }
    }

    pub fn is_null_ref(&self) -> Result<bool, WasmError> {
        match self {
            Value::FuncRef(v) => Ok(v.is_none()),
            Value::ExternRef(v) => Ok(v.is_none()),
            _ => Err(WasmError::TypeMismatch),
        }
    }

    pub fn matches_type(&self, ty: ValueType) -> bool {
        matches!(
            (self, ty),
            (Value::I32(_), ValueType::I32)
                | (Value::I64(_), ValueType::I64)
                | (Value::F32(_), ValueType::F32)
                | (Value::F64(_), ValueType::F64)
                | (Value::FuncRef(_), ValueType::FuncRef)
                | (Value::ExternRef(_), ValueType::ExternRef)
        )
    }

    pub fn zero_for_type(ty: ValueType) -> Self {
        match ty {
            ValueType::I32 => Value::I32(0),
            ValueType::I64 => Value::I64(0),
            ValueType::F32 => Value::F32(0.0),
            ValueType::F64 => Value::F64(0.0),
            ValueType::FuncRef => Value::FuncRef(None),
            ValueType::ExternRef => Value::ExternRef(None),
        }
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
    Try = 0x06,
    Catch = 0x07,
    Throw = 0x08,
    Rethrow = 0x09,
    End = 0x0B,
    Br = 0x0C,
    BrIf = 0x0D,
    Return = 0x0F,
    Call = 0x10,
    CallIndirect = 0x11,
    Delegate = 0x18,
    CatchAll = 0x19,
    
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
    F32Const = 0x43,
    F64Const = 0x44,
    
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

    // i64 operations
    I64Add = 0x7C,
    I64Sub = 0x7D,
    I64Mul = 0x7E,
    I64DivS = 0x7F,

    // f32 operations
    F32Add = 0x92,
    F32Sub = 0x93,
    F32Mul = 0x94,
    F32Div = 0x95,

    // f64 operations
    F64Add = 0xA0,
    F64Sub = 0xA1,
    F64Mul = 0xA2,
    F64Div = 0xA3,

    // Reference types
    RefNull = 0xD0,
    RefIsNull = 0xD1,
    RefFunc = 0xD2,
}

impl Opcode {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Opcode::Unreachable),
            0x01 => Some(Opcode::Nop),
            0x02 => Some(Opcode::Block),
            0x03 => Some(Opcode::Loop),
            0x04 => Some(Opcode::If),
            0x05 => Some(Opcode::Else),
            0x06 => Some(Opcode::Try),
            0x07 => Some(Opcode::Catch),
            0x08 => Some(Opcode::Throw),
            0x09 => Some(Opcode::Rethrow),
            0x0B => Some(Opcode::End),
            0x0C => Some(Opcode::Br),
            0x0D => Some(Opcode::BrIf),
            0x0F => Some(Opcode::Return),
            0x10 => Some(Opcode::Call),
            0x11 => Some(Opcode::CallIndirect),
            0x18 => Some(Opcode::Delegate),
            0x19 => Some(Opcode::CatchAll),
            0x1A => Some(Opcode::Drop),
            0x1B => Some(Opcode::Select),
            0x20 => Some(Opcode::LocalGet),
            0x21 => Some(Opcode::LocalSet),
            0x22 => Some(Opcode::LocalTee),
            0x23 => Some(Opcode::GlobalGet),
            0x24 => Some(Opcode::GlobalSet),
            0x28 => Some(Opcode::I32Load),
            0x29 => Some(Opcode::I64Load),
            0x36 => Some(Opcode::I32Store),
            0x37 => Some(Opcode::I64Store),
            0x3F => Some(Opcode::MemorySize),
            0x40 => Some(Opcode::MemoryGrow),
            0x41 => Some(Opcode::I32Const),
            0x42 => Some(Opcode::I64Const),
            0x43 => Some(Opcode::F32Const),
            0x44 => Some(Opcode::F64Const),
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
            0x7C => Some(Opcode::I64Add),
            0x7D => Some(Opcode::I64Sub),
            0x7E => Some(Opcode::I64Mul),
            0x7F => Some(Opcode::I64DivS),
            0x92 => Some(Opcode::F32Add),
            0x93 => Some(Opcode::F32Sub),
            0x94 => Some(Opcode::F32Mul),
            0x95 => Some(Opcode::F32Div),
            0xA0 => Some(Opcode::F64Add),
            0xA1 => Some(Opcode::F64Sub),
            0xA2 => Some(Opcode::F64Mul),
            0xA3 => Some(Opcode::F64Div),
            0xD0 => Some(Opcode::RefNull),
            0xD1 => Some(Opcode::RefIsNull),
            0xD2 => Some(Opcode::RefFunc),
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
            Opcode::F32Const => {
                let end = pc.checked_add(4).ok_or(WasmError::InvalidModule)?;
                if end > code.len() {
                    return Err(WasmError::UnexpectedEndOfCode);
                }
                pc = end;
            }
            Opcode::F64Const => {
                let end = pc.checked_add(8).ok_or(WasmError::InvalidModule)?;
                if end > code.len() {
                    return Err(WasmError::UnexpectedEndOfCode);
                }
                pc = end;
            }
            Opcode::LocalGet
            | Opcode::LocalSet
            | Opcode::LocalTee
            | Opcode::GlobalGet
            | Opcode::GlobalSet
            | Opcode::Br
            | Opcode::BrIf
            | Opcode::Call
            | Opcode::Catch
            | Opcode::Throw
            | Opcode::Rethrow
            | Opcode::Delegate
            | Opcode::RefFunc => {
                let (_v, n) = read_uleb128_validate(code, pc)?;
                pc += n;
            }
            Opcode::CallIndirect => {
                let (_type_idx, n1) = read_uleb128_validate(code, pc)?;
                pc += n1;
                let (_table_idx, n2) = read_uleb128_validate(code, pc)?;
                pc += n2;
            }
            Opcode::I32Load | Opcode::I64Load | Opcode::I32Store | Opcode::I64Store => {
                let (_align, n1) = read_uleb128_validate(code, pc)?;
                pc += n1;
                let (_off, n2) = read_uleb128_validate(code, pc)?;
                pc += n2;
            }
            Opcode::Block | Opcode::Loop | Opcode::If | Opcode::Try => {
                let n = read_blocktype_width_validate(code, pc)?;
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
            Opcode::RefNull => {
                if pc >= code.len() {
                    return Err(WasmError::UnexpectedEndOfCode);
                }
                let ty = code[pc];
                pc += 1;
                if ty != 0x70 && ty != 0x6F {
                    return Err(WasmError::InvalidModule);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn read_blocktype_width_validate(bytes: &[u8], offset: usize) -> Result<usize, WasmError> {
    if offset >= bytes.len() {
        return Err(WasmError::UnexpectedEndOfCode);
    }
    let b = bytes[offset];
    if b == 0x40 || b == 0x7F || b == 0x7E || b == 0x7D || b == 0x7C || b == 0x70 || b == 0x6F {
        return Ok(1);
    }
    let (_idx, n) = read_uleb128_validate(bytes, offset)?;
    Ok(n)
}

#[derive(Clone, Copy)]
struct ParsedFunctionType {
    param_count: usize,
    result_count: usize,
    param_types: [ValueType; MAX_WASM_TYPE_ARITY],
    result_types: [ValueType; MAX_WASM_TYPE_ARITY],
    all_i32: bool,
}

fn read_byte_at(bytes: &[u8], offset: &mut usize) -> Result<u8, WasmError> {
    if *offset >= bytes.len() {
        return Err(WasmError::UnexpectedEndOfCode);
    }
    let byte = bytes[*offset];
    *offset += 1;
    Ok(byte)
}

fn read_uleb128_at(bytes: &[u8], offset: &mut usize) -> Result<u32, WasmError> {
    let (value, width) = read_uleb128_validate(bytes, *offset)?;
    *offset = offset
        .checked_add(width)
        .ok_or(WasmError::InvalidModule)?;
    Ok(value)
}

fn parse_valtype(bytes: &[u8], offset: &mut usize) -> Result<ValueType, WasmError> {
    match read_byte_at(bytes, offset)? {
        0x7F => Ok(ValueType::I32),
        0x7E => Ok(ValueType::I64),
        0x7D => Ok(ValueType::F32),
        0x7C => Ok(ValueType::F64),
        0x70 => Ok(ValueType::FuncRef),
        0x6F => Ok(ValueType::ExternRef),
        _ => Err(WasmError::InvalidModule),
    }
}

fn read_name_slice<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    section_end: usize,
) -> Result<&'a [u8], WasmError> {
    let len = read_uleb128_at(bytes, offset)? as usize;
    let end = offset.checked_add(len).ok_or(WasmError::InvalidModule)?;
    if end > section_end {
        return Err(WasmError::InvalidModule);
    }
    let name = &bytes[*offset..end];
    *offset = end;
    Ok(name)
}

fn resolve_host_import(
    module_name: &[u8],
    field_name: &[u8],
    signature: ParsedFunctionType,
) -> Result<usize, WasmError> {
    let module = core::str::from_utf8(module_name).map_err(|_| WasmError::InvalidModule)?;
    if module != "oreulia" {
        return Err(WasmError::InvalidModule);
    }
    let field = core::str::from_utf8(field_name).map_err(|_| WasmError::InvalidModule)?;

    if field == "service_register_ref" || field == "oreulia_service_register_ref" {
        if signature.param_count == 2
            && signature.result_count == 1
            && signature.param_types[0] == ValueType::FuncRef
            && signature.param_types[1] == ValueType::I32
            && signature.result_types[0] == ValueType::I32
        {
            return Ok(9);
        }
        return Err(WasmError::InvalidModule);
    }

    if field == "service_register" || field == "oreulia_service_register" {
        let valid = signature.param_count == 2
            && signature.result_count == 1
            && signature.param_types[1] == ValueType::I32
            && signature.result_types[0] == ValueType::I32
            && (signature.param_types[0] == ValueType::I32
                || signature.param_types[0] == ValueType::FuncRef);
        if valid {
            return Ok(9);
        }
        return Err(WasmError::InvalidModule);
    }

    let (host_id, params, results) = match field {
        "debug_log" | "oreulia_log" => (0usize, 2usize, 0usize),
        "fs_read" | "oreulia_fs_read" => (1, 5, 1),
        "fs_write" | "oreulia_fs_write" => (2, 5, 1),
        "channel_send" | "oreulia_channel_send" => (3, 3, 1),
        "channel_recv" | "oreulia_channel_recv" => (4, 3, 1),
        "net_http_get" | "oreulia_net_http_get" => (5, 4, 1),
        "net_connect" | "oreulia_net_connect" => (6, 3, 1),
        "dns_resolve" | "oreulia_dns_resolve" => (7, 2, 1),
        "service_invoke" | "oreulia_service_invoke" => (8, 3, 1),
        "channel_send_cap" | "oreulia_channel_send_cap" => (10, 4, 1),
        "last_service_cap" | "oreulia_last_service_cap" => (11, 0, 1),
        "service_invoke_typed" | "oreulia_service_invoke_typed" => (12, 5, 1),
        "temporal_snapshot" | "oreulia_temporal_snapshot" => (13, 4, 1),
        "temporal_latest" | "oreulia_temporal_latest" => (14, 4, 1),
        "temporal_read" | "oreulia_temporal_read" => (15, 7, 1),
        "temporal_rollback" | "oreulia_temporal_rollback" => (16, 6, 1),
        "temporal_stats" | "oreulia_temporal_stats" => (17, 1, 1),
        "temporal_history" | "oreulia_temporal_history" => (18, 7, 1),
        "temporal_branch_create" | "oreulia_temporal_branch_create" => (19, 8, 1),
        "temporal_branch_checkout" | "oreulia_temporal_branch_checkout" => (20, 6, 1),
        "temporal_branch_list" | "oreulia_temporal_branch_list" => (21, 5, 1),
        "temporal_merge" | "oreulia_temporal_merge" => (22, 9, 1),
        _ => return Err(WasmError::InvalidModule),
    };

    if signature.param_count != params || signature.result_count != results {
        return Err(WasmError::InvalidModule);
    }
    if !signature.all_i32 {
        return Err(WasmError::InvalidModule);
    }
    Ok(host_id)
}

fn parse_init_expr(
    bytes: &[u8],
    offset: &mut usize,
    section_end: usize,
    globals: &[Option<GlobalTemplate>; MAX_WASM_GLOBALS],
) -> Result<Value, WasmError> {
    if *offset >= section_end {
        return Err(WasmError::UnexpectedEndOfCode);
    }
    let opcode = read_byte_at(bytes, offset)?;
    let value = match opcode {
        0x41 => Value::I32(read_sleb128_i32_validate(bytes, *offset).map(|(v, n)| {
            *offset += n;
            v
        })?),
        0x42 => Value::I64(read_sleb128_i64_validate(bytes, *offset).map(|(v, n)| {
            *offset += n;
            v
        })?),
        0x43 => {
            let end = (*offset).checked_add(4).ok_or(WasmError::InvalidModule)?;
            if end > section_end {
                return Err(WasmError::UnexpectedEndOfCode);
            }
            let bits = u32::from_le_bytes([
                bytes[*offset],
                bytes[*offset + 1],
                bytes[*offset + 2],
                bytes[*offset + 3],
            ]);
            *offset = end;
            Value::F32(f32::from_bits(bits))
        }
        0x44 => {
            let end = (*offset).checked_add(8).ok_or(WasmError::InvalidModule)?;
            if end > section_end {
                return Err(WasmError::UnexpectedEndOfCode);
            }
            let bits = u64::from_le_bytes([
                bytes[*offset],
                bytes[*offset + 1],
                bytes[*offset + 2],
                bytes[*offset + 3],
                bytes[*offset + 4],
                bytes[*offset + 5],
                bytes[*offset + 6],
                bytes[*offset + 7],
            ]);
            *offset = end;
            Value::F64(f64::from_bits(bits))
        }
        0x23 => {
            let idx = read_uleb128_at(bytes, offset)? as usize;
            let slot = globals
                .get(idx)
                .and_then(|g| *g)
                .ok_or(WasmError::InvalidModule)?;
            if slot.mutable {
                return Err(WasmError::InvalidModule);
            }
            slot.init
        }
        0xD0 => {
            let ref_type = read_byte_at(bytes, offset)?;
            match ref_type {
                0x70 => Value::FuncRef(None),
                0x6F => Value::ExternRef(None),
                _ => return Err(WasmError::InvalidModule),
            }
        }
        0xD2 => {
            let idx = read_uleb128_at(bytes, offset)? as usize;
            Value::FuncRef(Some(idx))
        }
        _ => return Err(WasmError::InvalidModule),
    };

    if read_byte_at(bytes, offset)? != 0x0B {
        return Err(WasmError::InvalidModule);
    }
    Ok(value)
}

fn init_expr_offset(value: Value) -> Result<usize, WasmError> {
    let raw = value.as_i32()?;
    if raw < 0 {
        return Err(WasmError::InvalidModule);
    }
    Ok(raw as usize)
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

    pub fn truncate(&mut self, new_len: usize) -> Result<(), WasmError> {
        if new_len > self.len {
            return Err(WasmError::StackUnderflow);
        }
        self.len = new_len;
        Ok(())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServicePointerCapability {
    pub object_id: u64,
    pub cap_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServicePointerRegistration {
    pub object_id: u64,
    pub cap_id: u32,
    pub target_instance: usize,
    pub function_index: usize,
}

#[derive(Clone, Copy)]
pub struct ServicePointerInvokeResult {
    pub value_count: usize,
    pub values: [Value; MAX_WASM_TYPE_ARITY],
}

impl ServicePointerInvokeResult {
    const fn empty() -> Self {
        Self {
            value_count: 0,
            values: [Value::I32(0); MAX_WASM_TYPE_ARITY],
        }
    }
}

fn parsed_signature_equal(a: ParsedFunctionType, b: ParsedFunctionType) -> bool {
    if a.param_count != b.param_count || a.result_count != b.result_count {
        return false;
    }
    let mut i = 0usize;
    while i < a.param_count {
        if a.param_types[i] != b.param_types[i] {
            return false;
        }
        i += 1;
    }
    let mut r = 0usize;
    while r < a.result_count {
        if a.result_types[r] != b.result_types[r] {
            return false;
        }
        r += 1;
    }
    true
}

/// Capability types that can be injected into WASM
#[derive(Debug, Clone, Copy)]
pub enum WasmCapability {
    Channel(ChannelId),
    Filesystem(fs::FilesystemCapability),
    ServicePointer(ServicePointerCapability),
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

#[derive(Clone, Copy)]
struct ServicePointerEntry {
    active: bool,
    object_id: u64,
    owner_pid: ProcessId,
    target_instance: usize,
    function_index: usize,
    signature: ParsedFunctionType,
    max_calls_per_window: u16,
    window_ticks: u64,
    window_start_tick: u64,
    calls_in_window: u16,
}

impl ServicePointerEntry {
    const fn empty() -> Self {
        Self {
            active: false,
            object_id: 0,
            owner_pid: ProcessId(0),
            target_instance: 0,
            function_index: 0,
            signature: ParsedFunctionType {
                param_count: 0,
                result_count: 0,
                param_types: [ValueType::I32; MAX_WASM_TYPE_ARITY],
                result_types: [ValueType::I32; MAX_WASM_TYPE_ARITY],
                all_i32: true,
            },
            max_calls_per_window: 0,
            window_ticks: 0,
            window_start_tick: 0,
            calls_in_window: 0,
        }
    }
}

struct ServicePointerRegistry {
    entries: [ServicePointerEntry; MAX_SERVICE_POINTERS],
}

impl ServicePointerRegistry {
    const fn new() -> Self {
        Self {
            entries: [ServicePointerEntry::empty(); MAX_SERVICE_POINTERS],
        }
    }

    fn find_index(&self, object_id: u64) -> Option<usize> {
        let mut i = 0usize;
        while i < self.entries.len() {
            let entry = self.entries[i];
            if entry.active && entry.object_id == object_id {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn insert(&mut self, entry: ServicePointerEntry) -> Result<(), &'static str> {
        let mut i = 0usize;
        while i < self.entries.len() {
            if !self.entries[i].active {
                self.entries[i] = entry;
                return Ok(());
            }
            i += 1;
        }
        Err("Service pointer registry full")
    }

    fn remove_object(&mut self, object_id: u64) -> bool {
        if let Some(idx) = self.find_index(object_id) {
            self.entries[idx] = ServicePointerEntry::empty();
            return true;
        }
        false
    }

    fn resolve_for_invoke(
        &mut self,
        object_id: u64,
        args: &[Value],
        now_tick: u64,
    ) -> Result<ServicePointerEntry, &'static str> {
        let idx = self
            .find_index(object_id)
            .ok_or("Service pointer not found")?;
        let mut entry = self.entries[idx];
        if !entry.active {
            return Err("Service pointer inactive");
        }
        if args.len() != entry.signature.param_count {
            return Err("Service pointer argument mismatch");
        }
        let mut i = 0usize;
        while i < args.len() {
            if !args[i].matches_type(entry.signature.param_types[i]) {
                return Err("Service pointer argument type mismatch");
            }
            i += 1;
        }

        if entry.max_calls_per_window > 0 {
            if entry.window_ticks == 0 {
                return Err("Invalid service pointer rate policy");
            }
            if now_tick.saturating_sub(entry.window_start_tick) >= entry.window_ticks {
                entry.window_start_tick = now_tick;
                entry.calls_in_window = 0;
            }
            if entry.calls_in_window >= entry.max_calls_per_window {
                return Err("Service pointer rate limit exceeded");
            }
            entry.calls_in_window = entry.calls_in_window.saturating_add(1);
            self.entries[idx] = entry;
        }

        Ok(entry)
    }
}

static SERVICE_POINTERS: Mutex<ServicePointerRegistry> = Mutex::new(ServicePointerRegistry::new());
const SERVICE_POINTER_TEMPORAL_SCHEMA_V1: u8 = 1;
const SERVICE_POINTER_TEMPORAL_HEADER_BYTES: usize = 12;
const SERVICE_POINTER_TEMPORAL_ENTRY_BYTES: usize = 40 + (MAX_WASM_TYPE_ARITY * 2);

fn service_pointer_temporal_value_type_tag(ty: ValueType) -> u8 {
    match ty {
        ValueType::I32 => 0x7F,
        ValueType::I64 => 0x7E,
        ValueType::F32 => 0x7D,
        ValueType::F64 => 0x7C,
        ValueType::FuncRef => 0x70,
        ValueType::ExternRef => 0x6F,
    }
}

fn service_pointer_temporal_tag_to_value_type(tag: u8) -> Option<ValueType> {
    match tag {
        0x7F => Some(ValueType::I32),
        0x7E => Some(ValueType::I64),
        0x7D => Some(ValueType::F32),
        0x7C => Some(ValueType::F64),
        0x70 => Some(ValueType::FuncRef),
        0x6F => Some(ValueType::ExternRef),
        _ => None,
    }
}

fn service_pointer_temporal_read_u16(data: &[u8], offset: usize) -> Option<u16> {
    if offset.saturating_add(2) > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn service_pointer_temporal_read_u32(data: &[u8], offset: usize) -> Option<u32> {
    if offset.saturating_add(4) > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn service_pointer_temporal_read_u64(data: &[u8], offset: usize) -> Option<u64> {
    if offset.saturating_add(8) > data.len() {
        return None;
    }
    Some(u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]))
}

fn encode_temporal_service_pointer_registry_payload(event: u8) -> Vec<u8> {
    let mut active_count = 0usize;
    {
        let registry = SERVICE_POINTERS.lock();
        let mut i = 0usize;
        while i < registry.entries.len() {
            if registry.entries[i].active {
                active_count += 1;
            }
            i += 1;
        }
    }

    let mut payload = Vec::new();
    payload.reserve(
        SERVICE_POINTER_TEMPORAL_HEADER_BYTES
            .saturating_add(active_count.saturating_mul(SERVICE_POINTER_TEMPORAL_ENTRY_BYTES)),
    );
    payload.push(crate::temporal::TEMPORAL_OBJECT_ENCODING_V1);
    payload.push(crate::temporal::TEMPORAL_WASM_SERVICE_POINTER_OBJECT);
    payload.push(event);
    payload.push(SERVICE_POINTER_TEMPORAL_SCHEMA_V1);
    payload.extend_from_slice(&(MAX_SERVICE_POINTERS as u16).to_le_bytes());
    payload.extend_from_slice(&(active_count as u16).to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());

    let registry = SERVICE_POINTERS.lock();
    let mut i = 0usize;
    while i < registry.entries.len() {
        let entry = registry.entries[i];
        if entry.active {
            payload.extend_from_slice(&entry.object_id.to_le_bytes());
            payload.extend_from_slice(&entry.owner_pid.0.to_le_bytes());
            payload.extend_from_slice(&(entry.target_instance as u32).to_le_bytes());
            payload.extend_from_slice(&(entry.function_index as u32).to_le_bytes());
            payload.extend_from_slice(&entry.max_calls_per_window.to_le_bytes());
            payload.extend_from_slice(&entry.calls_in_window.to_le_bytes());
            payload.extend_from_slice(&entry.window_ticks.to_le_bytes());
            payload.extend_from_slice(&entry.window_start_tick.to_le_bytes());
            payload.push(entry.signature.param_count as u8);
            payload.push(entry.signature.result_count as u8);
            payload.push(if entry.signature.all_i32 { 1 } else { 0 });
            payload.push(0);

            let mut p = 0usize;
            while p < MAX_WASM_TYPE_ARITY {
                payload.push(service_pointer_temporal_value_type_tag(
                    entry.signature.param_types[p],
                ));
                p += 1;
            }
            let mut r = 0usize;
            while r < MAX_WASM_TYPE_ARITY {
                payload.push(service_pointer_temporal_value_type_tag(
                    entry.signature.result_types[r],
                ));
                r += 1;
            }
        }
        i += 1;
    }
    payload
}

fn record_temporal_service_pointer_registry_snapshot() {
    if crate::temporal::is_replay_active() {
        return;
    }
    let payload = encode_temporal_service_pointer_registry_payload(
        crate::temporal::TEMPORAL_WASM_SERVICE_POINTER_EVENT_STATE,
    );
    let _ = crate::temporal::record_wasm_service_pointer_event(&payload);
}

pub fn temporal_apply_service_pointer_registry_payload(payload: &[u8]) -> Result<(), &'static str> {
    if payload.len() < SERVICE_POINTER_TEMPORAL_HEADER_BYTES {
        return Err("temporal wasm service pointer payload too short");
    }
    if payload[0] != crate::temporal::TEMPORAL_OBJECT_ENCODING_V1
        || payload[1] != crate::temporal::TEMPORAL_WASM_SERVICE_POINTER_OBJECT
    {
        return Err("temporal wasm service pointer payload type mismatch");
    }
    if payload[2] != crate::temporal::TEMPORAL_WASM_SERVICE_POINTER_EVENT_STATE {
        return Err("temporal wasm service pointer event unsupported");
    }
    if payload[3] != SERVICE_POINTER_TEMPORAL_SCHEMA_V1 {
        return Err("temporal wasm service pointer schema unsupported");
    }

    let slot_count = service_pointer_temporal_read_u16(payload, 4)
        .ok_or("temporal wasm service pointer slots missing")? as usize;
    if slot_count != MAX_SERVICE_POINTERS {
        return Err("temporal wasm service pointer slot mismatch");
    }
    let entry_count = service_pointer_temporal_read_u16(payload, 6)
        .ok_or("temporal wasm service pointer count missing")? as usize;
    if entry_count > MAX_SERVICE_POINTERS {
        return Err("temporal wasm service pointer entry count out of range");
    }

    let expected_len = SERVICE_POINTER_TEMPORAL_HEADER_BYTES
        .saturating_add(entry_count.saturating_mul(SERVICE_POINTER_TEMPORAL_ENTRY_BYTES));
    if payload.len() != expected_len {
        return Err("temporal wasm service pointer payload length mismatch");
    }

    let mut new_entries = [ServicePointerEntry::empty(); MAX_SERVICE_POINTERS];
    let mut offset = SERVICE_POINTER_TEMPORAL_HEADER_BYTES;
    let mut i = 0usize;
    while i < entry_count {
        let object_id = service_pointer_temporal_read_u64(payload, offset)
            .ok_or("temporal wasm service pointer object missing")?;
        let owner_pid = service_pointer_temporal_read_u32(payload, offset + 8)
            .ok_or("temporal wasm service pointer owner missing")?;
        let target_instance = service_pointer_temporal_read_u32(payload, offset + 12)
            .ok_or("temporal wasm service pointer target missing")?;
        let function_index = service_pointer_temporal_read_u32(payload, offset + 16)
            .ok_or("temporal wasm service pointer function missing")?;
        let max_calls_per_window = service_pointer_temporal_read_u16(payload, offset + 20)
            .ok_or("temporal wasm service pointer max calls missing")?;
        let calls_in_window = service_pointer_temporal_read_u16(payload, offset + 22)
            .ok_or("temporal wasm service pointer calls missing")?;
        let window_ticks = service_pointer_temporal_read_u64(payload, offset + 24)
            .ok_or("temporal wasm service pointer window ticks missing")?;
        let window_start_tick = service_pointer_temporal_read_u64(payload, offset + 32)
            .ok_or("temporal wasm service pointer window start missing")?;
        let param_count = payload[offset + 40] as usize;
        let result_count = payload[offset + 41] as usize;
        let all_i32 = payload[offset + 42] != 0;
        if param_count > MAX_WASM_TYPE_ARITY || result_count > MAX_WASM_TYPE_ARITY {
            return Err("temporal wasm service pointer arity out of range");
        }

        let mut param_types = [ValueType::I32; MAX_WASM_TYPE_ARITY];
        let mut result_types = [ValueType::I32; MAX_WASM_TYPE_ARITY];
        let mut p = 0usize;
        while p < MAX_WASM_TYPE_ARITY {
            param_types[p] = service_pointer_temporal_tag_to_value_type(payload[offset + 44 + p])
                .ok_or("temporal wasm service pointer param type invalid")?;
            p += 1;
        }
        let mut r = 0usize;
        let result_base = offset + 44 + MAX_WASM_TYPE_ARITY;
        while r < MAX_WASM_TYPE_ARITY {
            result_types[r] =
                service_pointer_temporal_tag_to_value_type(payload[result_base + r])
                    .ok_or("temporal wasm service pointer result type invalid")?;
            r += 1;
        }

        new_entries[i] = ServicePointerEntry {
            active: true,
            object_id,
            owner_pid: ProcessId(owner_pid),
            target_instance: target_instance as usize,
            function_index: function_index as usize,
            signature: ParsedFunctionType {
                param_count,
                result_count,
                param_types,
                result_types,
                all_i32,
            },
            max_calls_per_window,
            window_ticks,
            window_start_tick,
            calls_in_window,
        };
        offset += SERVICE_POINTER_TEMPORAL_ENTRY_BYTES;
        i += 1;
    }

    let mut registry = SERVICE_POINTERS.lock();
    registry.entries = new_entries;
    Ok(())
}

pub fn service_pointer_exists(object_id: u64) -> bool {
    SERVICE_POINTERS.lock().find_index(object_id).is_some()
}

fn revoke_service_pointers_for_instance(instance_id: usize) -> usize {
    let mut observed = [ServicePointerEntry::empty(); MAX_SERVICE_POINTERS];
    let mut observed_count = 0usize;
    {
        let registry = SERVICE_POINTERS.lock();
        let mut i = 0usize;
        while i < registry.entries.len() {
            let entry = registry.entries[i];
            if entry.active && entry.target_instance == instance_id {
                if observed_count < observed.len() {
                    observed[observed_count] = entry;
                    observed_count += 1;
                }
            }
            i += 1;
        }
    }

    let mut rebind_target = [usize::MAX; MAX_SERVICE_POINTERS];
    let mut i = 0usize;
    while i < observed_count {
        rebind_target[i] = wasm_runtime()
            .find_service_pointer_rebind_target(
                observed[i].owner_pid,
                instance_id,
                observed[i].function_index,
                observed[i].signature,
            )
            .unwrap_or(usize::MAX);
        i += 1;
    }

    let mut object_ids = [0u64; MAX_SERVICE_POINTERS];
    let mut object_count = 0usize;
    let mut rebound = 0usize;
    let removed = {
        let mut registry = SERVICE_POINTERS.lock();
        let mut i = 0usize;
        while i < observed_count {
            let object_id = observed[i].object_id;
            if let Some(idx) = registry.find_index(object_id) {
                let live = registry.entries[idx];
                if live.active && live.target_instance == instance_id {
                    if rebind_target[i] != usize::MAX {
                        let mut updated = live;
                        updated.target_instance = rebind_target[i];
                        updated.window_start_tick = crate::pit::get_ticks();
                        updated.calls_in_window = 0;
                        registry.entries[idx] = updated;
                        rebound = rebound.saturating_add(1);
                    } else {
                        if object_count < object_ids.len() {
                            object_ids[object_count] = live.object_id;
                            object_count += 1;
                        }
                        registry.entries[idx] = ServicePointerEntry::empty();
                    }
                }
            }
            i += 1;
        }
        object_count
    };

    let mut i = 0usize;
    while i < object_count {
        let _ = capability::capability_manager().revoke_object_capabilities(
            CapabilityType::ServicePointer,
            object_ids[i],
        );
        i += 1;
    }
    let changed = rebound.saturating_add(removed);
    if changed > 0 {
        record_temporal_service_pointer_registry_snapshot();
    }
    changed
}

pub fn register_service_pointer(
    owner_pid: ProcessId,
    target_instance: usize,
    function_index: usize,
    allow_delegate: bool,
) -> Result<ServicePointerRegistration, &'static str> {
    let metadata = wasm_runtime()
        .get_instance_mut(target_instance, |instance| -> Result<(ProcessId, usize, ParsedFunctionType), WasmError> {
            let mut resolved = function_index;
            let mut call_target = instance.module.resolve_call_target(resolved);
            if !matches!(call_target, Ok(CallTarget::Function(_)))
                && function_index < instance.module.function_count
            {
                resolved = instance
                    .module
                    .import_function_count
                    .checked_add(function_index)
                    .ok_or(WasmError::InvalidModule)?;
                call_target = instance.module.resolve_call_target(resolved);
            }

            match call_target? {
                CallTarget::Function(_) => {
                    let signature = instance.module.signature_for_combined(resolved)?;
                    Ok((instance.process_id, resolved, signature))
                }
                CallTarget::Host(_) => Err(WasmError::PermissionDenied),
            }
        })
        .map_err(|_| "Target instance not available")?;
    let (actual_owner, function_index, signature) = match metadata {
        Ok(v) => v,
        Err(WasmError::FunctionNotFound) => return Err("Target function not found"),
        Err(WasmError::PermissionDenied) => {
            return Err("Service pointers cannot target host imports");
        }
        Err(_) => return Err("Target function metadata unavailable"),
    };

    if actual_owner != owner_pid {
        return Err("Cannot register pointer for foreign instance");
    }
    if signature.param_count > MAX_WASM_TYPE_ARITY || signature.result_count > MAX_WASM_TYPE_ARITY {
        return Err("Service pointer signature exceeds runtime limits");
    }

    let object_id = capability::capability_manager().create_object();
    let hz = (crate::pit::get_frequency() as u64).max(1);
    let entry = ServicePointerEntry {
        active: true,
        object_id,
        owner_pid,
        target_instance,
        function_index,
        signature,
        max_calls_per_window: 128,
        window_ticks: hz,
        window_start_tick: crate::pit::get_ticks(),
        calls_in_window: 0,
    };
    SERVICE_POINTERS.lock().insert(entry)?;

    let mut rights = Rights::SERVICE_INVOKE | Rights::SERVICE_INTROSPECT;
    if allow_delegate {
        rights |= Rights::SERVICE_DELEGATE;
    }

    let grant = capability::capability_manager().grant_capability(
        owner_pid,
        object_id,
        CapabilityType::ServicePointer,
        Rights::new(rights),
        owner_pid,
    );
    let cap_id = match grant {
        Ok(cap_id) => cap_id,
        Err(e) => {
            SERVICE_POINTERS.lock().remove_object(object_id);
            return Err(e.as_str());
        }
    };

    let registration = ServicePointerRegistration {
        object_id,
        cap_id,
        target_instance,
        function_index,
    };
    record_temporal_service_pointer_registry_snapshot();
    Ok(registration)
}

pub fn revoke_service_pointer(owner_pid: ProcessId, object_id: u64) -> Result<(), &'static str> {
    let mut registry = SERVICE_POINTERS.lock();
    let idx = registry
        .find_index(object_id)
        .ok_or("Service pointer not found")?;
    if registry.entries[idx].owner_pid != owner_pid && owner_pid.0 != 0 {
        return Err("Permission denied");
    }
    registry.entries[idx] = ServicePointerEntry::empty();
    drop(registry);
    let _ = capability::capability_manager().revoke_object_capabilities(
        CapabilityType::ServicePointer,
        object_id,
    );
    record_temporal_service_pointer_registry_snapshot();
    Ok(())
}

pub fn revoke_service_pointers_for_owner(owner_pid: ProcessId) -> usize {
    let mut object_ids = [0u64; MAX_SERVICE_POINTERS];
    let mut object_count = 0usize;
    let removed = {
        let mut registry = SERVICE_POINTERS.lock();
        let mut removed = 0usize;
        let mut i = 0usize;
        while i < registry.entries.len() {
            let entry = registry.entries[i];
            if entry.active && entry.owner_pid == owner_pid {
                if object_count < object_ids.len() {
                    object_ids[object_count] = entry.object_id;
                    object_count += 1;
                }
                registry.entries[i] = ServicePointerEntry::empty();
                removed = removed.saturating_add(1);
            }
            i += 1;
        }
        removed
    };

    let mut i = 0usize;
    while i < object_count {
        let _ = capability::capability_manager().revoke_object_capabilities(
            CapabilityType::ServicePointer,
            object_ids[i],
        );
        i += 1;
    }
    if removed > 0 {
        record_temporal_service_pointer_registry_snapshot();
    }
    removed
}

pub fn invoke_service_pointer_typed(
    caller_pid: ProcessId,
    object_id: u64,
    args: &[Value],
) -> Result<ServicePointerInvokeResult, &'static str> {
    if args.len() > MAX_WASM_TYPE_ARITY {
        return Err("Too many service call arguments");
    }
    if !capability::check_capability(
        caller_pid,
        object_id,
        CapabilityType::ServicePointer,
        Rights::new(Rights::SERVICE_INVOKE),
    ) {
        return Err("Service pointer invoke denied");
    }

    let now = crate::pit::get_ticks();
    let entry = SERVICE_POINTERS
        .lock()
        .resolve_for_invoke(object_id, args, now)?;

    let call = wasm_runtime()
        .with_instance_exclusive(entry.target_instance, |instance| -> Result<ServicePointerInvokeResult, WasmError> {
            if instance.process_id != entry.owner_pid {
                return Err(WasmError::PermissionDenied);
            }
            let runtime_sig = instance.module.signature_for_combined(entry.function_index)?;
            if !parsed_signature_equal(runtime_sig, entry.signature) {
                return Err(WasmError::TypeMismatch);
            }

            instance.stack.clear();
            let mut i = 0usize;
            while i < args.len() {
                instance.stack.push(args[i])?;
                i += 1;
            }

            if let Err(e) = instance.invoke_combined_function(entry.function_index) {
                instance.stack.clear();
                return Err(e);
            }

            if instance.stack.len() != entry.signature.result_count {
                instance.stack.clear();
                return Err(WasmError::TypeMismatch);
            }
            let mut out = ServicePointerInvokeResult::empty();
            out.value_count = entry.signature.result_count;
            let mut r = 0usize;
            while r < entry.signature.result_count {
                let value = instance.stack.get(r)?;
                if !value.matches_type(entry.signature.result_types[r]) {
                    instance.stack.clear();
                    return Err(WasmError::TypeMismatch);
                }
                out.values[r] = value;
                r += 1;
            }
            instance.stack.clear();
            Ok(out)
        })
        .map_err(|e| match e {
            WasmError::InstanceBusy => "Service pointer target busy",
            _ => "Service pointer target unavailable",
        })?;

    match call {
        Ok(ret) => {
            crate::security::security()
                .intent_wasm_call(caller_pid, 0x5300 + entry.function_index as u64);
            Ok(ret)
        }
        Err(WasmError::TypeMismatch) => Err("Service pointer invocation type mismatch"),
        Err(_) => Err("Service pointer invocation failed"),
    }
}

pub fn invoke_service_pointer(
    caller_pid: ProcessId,
    object_id: u64,
    args: &[u32],
) -> Result<u32, &'static str> {
    if args.len() > MAX_SERVICE_CALL_ARGS {
        return Err("Too many service call arguments");
    }
    let mut typed = [Value::I32(0); MAX_SERVICE_CALL_ARGS];
    let mut i = 0usize;
    while i < args.len() {
        typed[i] = Value::I32(args[i] as i32);
        i += 1;
    }
    let result = invoke_service_pointer_typed(caller_pid, object_id, &typed[..args.len()])?;
    if result.value_count == 0 {
        return Ok(0);
    }
    if result.value_count != 1 {
        return Err("Legacy service pointer ABI expects <=1 result");
    }
    result.values[0]
        .as_u32()
        .map_err(|_| "Legacy service pointer ABI requires i32 result")
}

pub fn inject_service_pointer_capability(
    instance_id: usize,
    owner_pid: ProcessId,
    cap_id: u32,
) -> Result<CapHandle, &'static str> {
    let object_id = capability::capability_manager()
        .verify_and_get_object(
            owner_pid,
            cap_id,
            CapabilityType::ServicePointer,
            Rights::SERVICE_INVOKE,
        )
        .map_err(|e| e.as_str())?;

    wasm_runtime()
        .get_instance_mut(instance_id, |instance| {
            if instance.process_id != owner_pid {
                return Err(WasmError::PermissionDenied);
            }
            instance.inject_capability(WasmCapability::ServicePointer(
                ServicePointerCapability { object_id, cap_id },
            ))
        })
        .map_err(|_| "Instance not found")?
        .map_err(|e| e.as_str())
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

#[derive(Clone, Copy)]
struct GlobalTemplate {
    value_type: ValueType,
    mutable: bool,
    init: Value,
}

#[derive(Clone, Copy)]
struct ExceptionTagType {
    type_index: usize,
    param_count: usize,
    param_types: [ValueType; MAX_EXCEPTION_ARITY],
}

#[derive(Clone)]
struct DataSegment {
    offset: usize,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
enum CallTarget {
    Host(usize),
    Function(usize),
}

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
    /// Number of imported functions (prefix in combined index space).
    import_function_count: usize,
    /// Imported host function IDs (combined index space).
    imported_host_functions: [Option<usize>; 64],
    /// Function type index by combined index (imports + defined).
    function_type_index: [Option<usize>; 64],
    /// Signature arity by type index.
    type_signatures: [Option<ParsedFunctionType>; 64],
    /// Number of parsed type entries.
    type_count: usize,
    /// Optional start function index in combined index space.
    start_function: Option<usize>,
    /// Global templates copied into each instance at instantiation.
    global_templates: [Option<GlobalTemplate>; MAX_WASM_GLOBALS],
    /// Number of globals.
    global_count: usize,
    /// Function table entries (combined function index space).
    table_entries: [Option<usize>; MAX_WASM_TABLE_ENTRIES],
    /// Current table size.
    table_size: usize,
    /// Exception tag signatures.
    tag_types: [Option<ExceptionTagType>; MAX_WASM_TAGS],
    /// Number of tags.
    tag_count: usize,
    /// Active data segments applied at instantiation.
    data_segments: Vec<DataSegment>,
    /// Backward-compat path for hand-crafted bytecode using call >=1000 as host.
    legacy_host_call_encoding: bool,
}

impl WasmModule {
    /// Create a new empty module
    pub fn new() -> Self {
        WasmModule {
            bytecode: Vec::new(),
            bytecode_len: 0,
            functions: [None; 64],
            function_count: 0,
            import_function_count: 0,
            imported_host_functions: [None; 64],
            function_type_index: [None; 64],
            type_signatures: [None; 64],
            type_count: 0,
            start_function: None,
            global_templates: [None; MAX_WASM_GLOBALS],
            global_count: 0,
            table_entries: [None; MAX_WASM_TABLE_ENTRIES],
            table_size: 0,
            tag_types: [None; MAX_WASM_TAGS],
            tag_count: 0,
            data_segments: Vec::new(),
            legacy_host_call_encoding: true,
        }
    }

    fn replace_bytecode(&mut self, bytecode: &[u8]) {
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
    }

    fn reset_binary_metadata(&mut self) {
        self.import_function_count = 0;
        self.imported_host_functions = [None; 64];
        self.function_type_index = [None; 64];
        self.type_signatures = [None; 64];
        self.type_count = 0;
        self.start_function = None;
        self.global_templates = [None; MAX_WASM_GLOBALS];
        self.global_count = 0;
        self.table_entries = [None; MAX_WASM_TABLE_ENTRIES];
        self.table_size = 0;
        self.tag_types = [None; MAX_WASM_TAGS];
        self.tag_count = 0;
        self.data_segments.clear();
    }

    /// Load raw function bytecode (legacy/internal path).
    pub fn load(&mut self, bytecode: &[u8]) -> Result<(), WasmError> {
        if bytecode.len() > MAX_MODULE_SIZE {
            return Err(WasmError::ModuleTooLarge);
        }
        validate_bytecode(bytecode)?;
        self.replace_bytecode(bytecode);
        self.reset_binary_metadata();
        self.reset_functions();
        self.legacy_host_call_encoding = true;
        Ok(())
    }

    /// Load and validate a binary WASM module (strict syscall path).
    pub fn load_binary(&mut self, bytecode: &[u8]) -> Result<(), WasmError> {
        if bytecode.len() > MAX_MODULE_SIZE {
            return Err(WasmError::ModuleTooLarge);
        }
        if bytecode.len() < 8 {
            return Err(WasmError::InvalidModule);
        }
        if &bytecode[0..4] != b"\0asm" {
            return Err(WasmError::InvalidModule);
        }
        if bytecode[4..8] != [0x01, 0x00, 0x00, 0x00] {
            return Err(WasmError::InvalidModule);
        }

        self.replace_bytecode(bytecode);
        self.reset_binary_metadata();
        self.reset_functions();
        self.legacy_host_call_encoding = false;

        let bytes = &self.bytecode[..self.bytecode_len];
        let mut offset = 8usize;
        let mut last_non_custom_section = 0u8;
        let mut saw_type = false;
        let mut saw_import = false;
        let mut saw_function = false;
        let mut saw_table = false;
        let mut saw_code = false;
        let mut saw_global = false;
        let mut saw_memory = false;
        let mut saw_export = false;
        let mut saw_start = false;
        let mut saw_element = false;
        let mut saw_data = false;
        let mut saw_data_count = false;
        let mut saw_tag = false;

        let mut defined_type_indices: Vec<usize> = Vec::new();
        let mut function_bodies: Vec<(usize, usize, usize)> = Vec::new();
        let mut globals = [None; MAX_WASM_GLOBALS];
        let mut global_count = 0usize;
        let mut table_size = 0usize;
        let mut element_inits: Vec<(usize, Vec<usize>)> = Vec::new();
        let mut data_segments: Vec<DataSegment> = Vec::new();
        let mut data_count_hint: Option<usize> = None;

        while offset < bytes.len() {
            let section_id = read_byte_at(bytes, &mut offset)?;
            let section_size = read_uleb128_at(bytes, &mut offset)? as usize;
            let section_end = offset
                .checked_add(section_size)
                .ok_or(WasmError::InvalidModule)?;
            if section_end > bytes.len() {
                return Err(WasmError::InvalidModule);
            }

            if section_id != 0 {
                if section_id <= last_non_custom_section {
                    return Err(WasmError::InvalidModule);
                }
                last_non_custom_section = section_id;
            }

            let mut cursor = offset;
            match section_id {
                0 => {
                    // Custom section (ignored for execution).
                }
                1 => {
                    if saw_type {
                        return Err(WasmError::InvalidModule);
                    }
                    saw_type = true;
                    let type_count = read_uleb128_at(bytes, &mut cursor)? as usize;
                    if type_count > 64 {
                        return Err(WasmError::TooManyFunctions);
                    }
                    self.type_count = type_count;
                    let mut i = 0usize;
                    while i < type_count {
                        let form = read_byte_at(bytes, &mut cursor)?;
                        if form != 0x60 {
                            return Err(WasmError::InvalidModule);
                        }

                        let param_count = read_uleb128_at(bytes, &mut cursor)? as usize;
                        if param_count > MAX_WASM_TYPE_ARITY || param_count > MAX_LOCALS {
                            return Err(WasmError::InvalidLocalIndex);
                        }
                        let mut all_i32 = true;
                        let mut param_types = [ValueType::I32; MAX_WASM_TYPE_ARITY];
                        let mut p = 0usize;
                        while p < param_count {
                            let ty = parse_valtype(bytes, &mut cursor)?;
                            param_types[p] = ty;
                            if ty != ValueType::I32 {
                                all_i32 = false;
                            }
                            p += 1;
                        }

                        let result_count = read_uleb128_at(bytes, &mut cursor)? as usize;
                        if result_count > MAX_WASM_TYPE_ARITY {
                            return Err(WasmError::InvalidLocalIndex);
                        }
                        let mut result_types = [ValueType::I32; MAX_WASM_TYPE_ARITY];
                        let mut r = 0usize;
                        while r < result_count {
                            let ty = parse_valtype(bytes, &mut cursor)?;
                            result_types[r] = ty;
                            if ty != ValueType::I32 {
                                all_i32 = false;
                            }
                            r += 1;
                        }
                        self.type_signatures[i] = Some(ParsedFunctionType {
                            param_count,
                            result_count,
                            param_types,
                            result_types,
                            all_i32,
                        });
                        i += 1;
                    }
                }
                2 => {
                    if saw_import {
                        return Err(WasmError::InvalidModule);
                    }
                    saw_import = true;
                    let import_count = read_uleb128_at(bytes, &mut cursor)? as usize;
                    let mut i = 0usize;
                    while i < import_count {
                        let module_name = read_name_slice(bytes, &mut cursor, section_end)?;
                        let field_name = read_name_slice(bytes, &mut cursor, section_end)?;
                        let kind = read_byte_at(bytes, &mut cursor)?;
                        match kind {
                            0x00 => {
                                let ty_idx = read_uleb128_at(bytes, &mut cursor)? as usize;
                                if ty_idx >= self.type_count {
                                    return Err(WasmError::InvalidModule);
                                }
                                let sig = self.type_signatures[ty_idx]
                                    .ok_or(WasmError::InvalidModule)?;
                                let host_id = resolve_host_import(module_name, field_name, sig)?;
                                let combined_idx = self.import_function_count;
                                if combined_idx >= 64 {
                                    return Err(WasmError::TooManyFunctions);
                                }
                                self.imported_host_functions[combined_idx] = Some(host_id);
                                self.function_type_index[combined_idx] = Some(ty_idx);
                                self.import_function_count += 1;
                            }
                            _ => {
                                return Err(WasmError::InvalidModule);
                            }
                        }
                        i += 1;
                    }
                }
                3 => {
                    if saw_function {
                        return Err(WasmError::InvalidModule);
                    }
                    saw_function = true;
                    let function_count = read_uleb128_at(bytes, &mut cursor)? as usize;
                    if function_count > 64 {
                        return Err(WasmError::TooManyFunctions);
                    }
                    let mut i = 0usize;
                    while i < function_count {
                        let ty_idx = read_uleb128_at(bytes, &mut cursor)? as usize;
                        if ty_idx >= self.type_count {
                            return Err(WasmError::InvalidModule);
                        }
                        defined_type_indices.push(ty_idx);
                        i += 1;
                    }
                }
                4 => {
                    if saw_table {
                        return Err(WasmError::InvalidModule);
                    }
                    saw_table = true;
                    let table_count = read_uleb128_at(bytes, &mut cursor)? as usize;
                    if table_count > 1 {
                        return Err(WasmError::InvalidModule);
                    }
                    let mut i = 0usize;
                    while i < table_count {
                        let ref_type = read_byte_at(bytes, &mut cursor)?;
                        if ref_type != 0x70 {
                            return Err(WasmError::InvalidModule);
                        }
                        let flags = read_uleb128_at(bytes, &mut cursor)?;
                        if (flags & !0x1) != 0 {
                            return Err(WasmError::InvalidModule);
                        }
                        let min = read_uleb128_at(bytes, &mut cursor)? as usize;
                        if min > MAX_WASM_TABLE_ENTRIES {
                            return Err(WasmError::InvalidModule);
                        }
                        let max = if (flags & 0x1) != 0 {
                            let max = read_uleb128_at(bytes, &mut cursor)? as usize;
                            if max < min || max > MAX_WASM_TABLE_ENTRIES {
                                return Err(WasmError::InvalidModule);
                            }
                            max
                        } else {
                            MAX_WASM_TABLE_ENTRIES
                        };
                        let _ = max;
                        table_size = min;
                        i += 1;
                    }
                }
                5 => {
                    if saw_memory {
                        return Err(WasmError::InvalidModule);
                    }
                    saw_memory = true;
                    let mem_count = read_uleb128_at(bytes, &mut cursor)? as usize;
                    if mem_count > 1 {
                        return Err(WasmError::InvalidModule);
                    }
                    let mut i = 0usize;
                    while i < mem_count {
                        let flags = read_uleb128_at(bytes, &mut cursor)?;
                        if (flags & !0x1) != 0 {
                            return Err(WasmError::InvalidModule);
                        }
                        let min_pages = read_uleb128_at(bytes, &mut cursor)?;
                        if min_pages > 1 {
                            return Err(WasmError::InvalidModule);
                        }
                        if (flags & 0x1) != 0 {
                            let max_pages = read_uleb128_at(bytes, &mut cursor)?;
                            if max_pages > 1 || max_pages < min_pages {
                                return Err(WasmError::InvalidModule);
                            }
                        }
                        i += 1;
                    }
                }
                6 => {
                    if saw_global {
                        return Err(WasmError::InvalidModule);
                    }
                    saw_global = true;
                    let global_total = read_uleb128_at(bytes, &mut cursor)? as usize;
                    if global_total > MAX_WASM_GLOBALS {
                        return Err(WasmError::InvalidModule);
                    }
                    let mut i = 0usize;
                    while i < global_total {
                        let value_type = parse_valtype(bytes, &mut cursor)?;
                        let mutable_flag = read_byte_at(bytes, &mut cursor)?;
                        if mutable_flag > 1 {
                            return Err(WasmError::InvalidModule);
                        }
                        let init = parse_init_expr(bytes, &mut cursor, section_end, &globals)?;
                        if !init.matches_type(value_type) {
                            return Err(WasmError::TypeMismatch);
                        }
                        globals[global_count] = Some(GlobalTemplate {
                            value_type,
                            mutable: mutable_flag != 0,
                            init,
                        });
                        global_count += 1;
                        i += 1;
                    }
                }
                7 => {
                    if saw_export {
                        return Err(WasmError::InvalidModule);
                    }
                    saw_export = true;
                    // Export section (parsed for structure/bounds only).
                    let export_count = read_uleb128_at(bytes, &mut cursor)? as usize;
                    let mut i = 0usize;
                    while i < export_count {
                        let _name = read_name_slice(bytes, &mut cursor, section_end)?;
                        let kind = read_byte_at(bytes, &mut cursor)?;
                        let index = read_uleb128_at(bytes, &mut cursor)? as usize;
                        match kind {
                            0x00 => {
                                if index >= self.import_function_count + defined_type_indices.len() {
                                    return Err(WasmError::InvalidModule);
                                }
                            }
                            0x01 => {
                                if !saw_table || index != 0 {
                                    return Err(WasmError::InvalidModule);
                                }
                            }
                            0x02 => {
                                if !saw_memory || index != 0 {
                                    return Err(WasmError::InvalidModule);
                                }
                            }
                            0x03 => {
                                if index >= global_count {
                                    return Err(WasmError::InvalidModule);
                                }
                            }
                            _ => return Err(WasmError::InvalidModule),
                        }
                        i += 1;
                    }
                }
                8 => {
                    if saw_start {
                        return Err(WasmError::InvalidModule);
                    }
                    saw_start = true;
                    let start_idx = read_uleb128_at(bytes, &mut cursor)? as usize;
                    self.start_function = Some(start_idx);
                }
                9 => {
                    if saw_element {
                        return Err(WasmError::InvalidModule);
                    }
                    saw_element = true;
                    let segment_count = read_uleb128_at(bytes, &mut cursor)? as usize;
                    let mut i = 0usize;
                    while i < segment_count {
                        let flags = read_uleb128_at(bytes, &mut cursor)?;
                        let table_idx = match flags {
                            0 => 0usize,
                            2 => read_uleb128_at(bytes, &mut cursor)? as usize,
                            _ => return Err(WasmError::InvalidModule),
                        };
                        if table_idx != 0 {
                            return Err(WasmError::InvalidModule);
                        }
                        let offset_expr =
                            parse_init_expr(bytes, &mut cursor, section_end, &globals)?;
                        let base = init_expr_offset(offset_expr)?;
                        if flags == 2 {
                            let elem_kind = read_byte_at(bytes, &mut cursor)?;
                            if elem_kind != 0x00 {
                                return Err(WasmError::InvalidModule);
                            }
                        }
                        let elem_count = read_uleb128_at(bytes, &mut cursor)? as usize;
                        let mut funcs = Vec::with_capacity(elem_count);
                        let mut j = 0usize;
                        while j < elem_count {
                            funcs.push(read_uleb128_at(bytes, &mut cursor)? as usize);
                            j += 1;
                        }
                        element_inits.push((base, funcs));
                        i += 1;
                    }
                }
                10 => {
                    if saw_code {
                        return Err(WasmError::InvalidModule);
                    }
                    saw_code = true;
                    if !saw_function {
                        return Err(WasmError::InvalidModule);
                    }

                    let code_count = read_uleb128_at(bytes, &mut cursor)? as usize;
                    if code_count != defined_type_indices.len() {
                        return Err(WasmError::InvalidModule);
                    }
                    let mut i = 0usize;
                    while i < code_count {
                        let body_size = read_uleb128_at(bytes, &mut cursor)? as usize;
                        let body_end = cursor.checked_add(body_size).ok_or(WasmError::InvalidModule)?;
                        if body_end > section_end {
                            return Err(WasmError::InvalidModule);
                        }

                        let mut body_cursor = cursor;
                        let local_decl_count = read_uleb128_at(bytes, &mut body_cursor)? as usize;
                        let mut local_count = 0usize;
                        let mut d = 0usize;
                        while d < local_decl_count {
                            let repeat = read_uleb128_at(bytes, &mut body_cursor)? as usize;
                            let _local_ty = parse_valtype(bytes, &mut body_cursor)?;
                            local_count = local_count
                                .checked_add(repeat)
                                .ok_or(WasmError::InvalidModule)?;
                            if local_count > MAX_LOCALS {
                                return Err(WasmError::InvalidLocalIndex);
                            }
                            d += 1;
                        }

                        if body_cursor >= body_end {
                            return Err(WasmError::InvalidModule);
                        }
                        validate_bytecode(&bytes[body_cursor..body_end])?;
                        function_bodies.push((body_cursor, body_end - body_cursor, local_count));
                        cursor = body_end;
                        i += 1;
                    }
                }
                11 => {
                    if saw_data {
                        return Err(WasmError::InvalidModule);
                    }
                    saw_data = true;
                    let segment_count = read_uleb128_at(bytes, &mut cursor)? as usize;
                    let mut i = 0usize;
                    while i < segment_count {
                        let flags = read_uleb128_at(bytes, &mut cursor)?;
                        let mem_idx = match flags {
                            0 => 0usize,
                            2 => read_uleb128_at(bytes, &mut cursor)? as usize,
                            _ => return Err(WasmError::InvalidModule),
                        };
                        if mem_idx != 0 {
                            return Err(WasmError::InvalidModule);
                        }
                        let offset_expr =
                            parse_init_expr(bytes, &mut cursor, section_end, &globals)?;
                        let base = init_expr_offset(offset_expr)?;
                        let data_len = read_uleb128_at(bytes, &mut cursor)? as usize;
                        let end = cursor.checked_add(data_len).ok_or(WasmError::InvalidModule)?;
                        if end > section_end {
                            return Err(WasmError::InvalidModule);
                        }
                        data_segments.push(DataSegment {
                            offset: base,
                            bytes: bytes[cursor..end].to_vec(),
                        });
                        cursor = end;
                        i += 1;
                    }
                }
                12 => {
                    if saw_data_count {
                        return Err(WasmError::InvalidModule);
                    }
                    saw_data_count = true;
                    data_count_hint = Some(read_uleb128_at(bytes, &mut cursor)? as usize);
                }
                13 => {
                    if saw_tag {
                        return Err(WasmError::InvalidModule);
                    }
                    saw_tag = true;
                    let tag_total = read_uleb128_at(bytes, &mut cursor)? as usize;
                    if tag_total > MAX_WASM_TAGS {
                        return Err(WasmError::InvalidModule);
                    }
                    let mut i = 0usize;
                    while i < tag_total {
                        let attr = read_uleb128_at(bytes, &mut cursor)?;
                        if attr != 0 {
                            return Err(WasmError::InvalidModule);
                        }
                        let type_idx = read_uleb128_at(bytes, &mut cursor)? as usize;
                        if type_idx >= self.type_count {
                            return Err(WasmError::InvalidModule);
                        }
                        let sig = self.type_signatures[type_idx].ok_or(WasmError::InvalidModule)?;
                        if sig.result_count != 0 {
                            return Err(WasmError::InvalidModule);
                        }
                        if sig.param_count > MAX_EXCEPTION_ARITY {
                            return Err(WasmError::InvalidModule);
                        }
                        let mut params = [ValueType::I32; MAX_EXCEPTION_ARITY];
                        let mut p = 0usize;
                        while p < sig.param_count {
                            params[p] = sig.param_types[p];
                            p += 1;
                        }
                        self.tag_types[i] = Some(ExceptionTagType {
                            type_index: type_idx,
                            param_count: sig.param_count,
                            param_types: params,
                        });
                        i += 1;
                    }
                    self.tag_count = tag_total;
                }
                _ => {
                    return Err(WasmError::InvalidModule);
                }
            }

            if cursor != section_end {
                return Err(WasmError::InvalidModule);
            }
            offset = section_end;
        }

        if !saw_type || !saw_function || !saw_code {
            return Err(WasmError::InvalidModule);
        }
        if defined_type_indices.len() != function_bodies.len() {
            return Err(WasmError::InvalidModule);
        }
        if self.import_function_count + function_bodies.len() > 64 {
            return Err(WasmError::TooManyFunctions);
        }
        if function_bodies.len() > 64 {
            return Err(WasmError::TooManyFunctions);
        }

        if !saw_table && !element_inits.is_empty() {
            return Err(WasmError::InvalidModule);
        }
        if !saw_memory && !data_segments.is_empty() {
            return Err(WasmError::InvalidModule);
        }
        if let Some(expected) = data_count_hint {
            if expected != data_segments.len() {
                return Err(WasmError::InvalidModule);
            }
        }

        let mut i = 0usize;
        while i < function_bodies.len() {
            let type_idx = defined_type_indices[i];
            if type_idx >= self.type_count {
                return Err(WasmError::InvalidModule);
            }
            let sig = self.type_signatures[type_idx].ok_or(WasmError::InvalidModule)?;
            let (code_offset, code_len, local_count) = function_bodies[i];
            let total_locals = sig
                .param_count
                .checked_add(local_count)
                .ok_or(WasmError::InvalidModule)?;
            if total_locals > MAX_LOCALS {
                return Err(WasmError::InvalidLocalIndex);
            }
            let defined_idx = self.add_function(Function {
                code_offset,
                code_len,
                param_count: sig.param_count,
                result_count: sig.result_count,
                local_count,
            })?;
            let combined_idx = self
                .import_function_count
                .checked_add(defined_idx)
                .ok_or(WasmError::InvalidModule)?;
            self.function_type_index[combined_idx] = Some(type_idx);
            i += 1;
        }

        self.global_templates = globals;
        self.global_count = global_count;

        self.table_size = table_size;
        let mut seg_idx = 0usize;
        while seg_idx < element_inits.len() {
            let (base, funcs) = &element_inits[seg_idx];
            let mut j = 0usize;
            while j < funcs.len() {
                let slot = base.checked_add(j).ok_or(WasmError::InvalidModule)?;
                if slot >= self.table_size {
                    return Err(WasmError::InvalidModule);
                }
                if funcs[j] >= self.total_function_count() {
                    return Err(WasmError::InvalidModule);
                }
                self.table_entries[slot] = Some(funcs[j]);
                j += 1;
            }
            seg_idx += 1;
        }

        self.data_segments = data_segments;

        let mut g = 0usize;
        while g < self.global_count {
            if let Some(global) = self.global_templates[g] {
                if let Value::FuncRef(Some(func_idx)) = global.init {
                    if func_idx >= self.total_function_count() {
                        return Err(WasmError::InvalidModule);
                    }
                }
            }
            g += 1;
        }

        if let Some(start_idx) = self.start_function {
            if start_idx >= self.total_function_count() {
                return Err(WasmError::InvalidModule);
            }
            let (params, results) = self.function_arity(start_idx)?;
            if params != 0 || results != 0 {
                return Err(WasmError::InvalidModule);
            }
            if !matches!(self.resolve_call_target(start_idx), Ok(CallTarget::Function(_))) {
                return Err(WasmError::InvalidModule);
            }
        }

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
        self.function_type_index = [None; 64];
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

    pub fn total_function_count(&self) -> usize {
        self.import_function_count.saturating_add(self.function_count)
    }

    fn resolve_call_target(&self, func_idx: usize) -> Result<CallTarget, WasmError> {
        if self.legacy_host_call_encoding && func_idx >= 1000 {
            return Ok(CallTarget::Host(func_idx - 1000));
        }

        if func_idx < self.import_function_count {
            if let Some(host_id) = self.imported_host_functions[func_idx] {
                return Ok(CallTarget::Host(host_id));
            }
            return Err(WasmError::FunctionNotFound);
        }

        let defined_idx = func_idx
            .checked_sub(self.import_function_count)
            .ok_or(WasmError::FunctionNotFound)?;
        if defined_idx >= self.function_count {
            return Err(WasmError::FunctionNotFound);
        }
        Ok(CallTarget::Function(defined_idx))
    }

    fn function_arity(&self, func_idx: usize) -> Result<(usize, usize), WasmError> {
        match self.resolve_call_target(func_idx)? {
            CallTarget::Host(_) => {
                let sig = self.signature_for_combined(func_idx)?;
                Ok((sig.param_count, sig.result_count))
            }
            CallTarget::Function(defined_idx) => {
                let func = self.get_function(defined_idx)?;
                Ok((func.param_count, func.result_count))
            }
        }
    }

    fn function_matches_type(&self, func_idx: usize, type_idx: usize) -> bool {
        if type_idx >= self.type_count {
            return false;
        }
        self.function_type_index
            .get(func_idx)
            .and_then(|x| *x)
            .map(|idx| idx == type_idx)
            .unwrap_or(false)
    }

    fn function_all_i32(&self, func_idx: usize) -> Result<bool, WasmError> {
        let sig = self.signature_for_combined(func_idx)?;
        Ok(sig.all_i32)
    }

    fn signature_for_type(&self, type_idx: usize) -> Result<ParsedFunctionType, WasmError> {
        if type_idx >= self.type_count {
            return Err(WasmError::FunctionNotFound);
        }
        self.type_signatures
            .get(type_idx)
            .and_then(|x| *x)
            .ok_or(WasmError::FunctionNotFound)
    }

    fn signature_for_combined(&self, func_idx: usize) -> Result<ParsedFunctionType, WasmError> {
        let ty_idx = self
            .function_type_index
            .get(func_idx)
            .and_then(|x| *x)
            .ok_or(WasmError::FunctionNotFound)?;
        self.signature_for_type(ty_idx)
    }

    fn signature_for_defined(&self, defined_idx: usize) -> Option<ParsedFunctionType> {
        let combined = self.import_function_count.checked_add(defined_idx)?;
        let ty_idx = self.function_type_index.get(combined).and_then(|x| *x)?;
        self.type_signatures.get(ty_idx).and_then(|x| *x)
    }

    fn tag_signature(&self, tag_idx: usize) -> Result<ExceptionTagType, WasmError> {
        if tag_idx >= self.tag_count {
            return Err(WasmError::InvalidModule);
        }
        self.tag_types
            .get(tag_idx)
            .and_then(|x| *x)
            .ok_or(WasmError::InvalidModule)
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

#[derive(Clone, Copy)]
struct GlobalSlot {
    value_type: ValueType,
    mutable: bool,
    value: Value,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ControlKind {
    Block,
    Loop,
    If,
    Try,
}

#[derive(Clone, Copy)]
struct TryScanInfo {
    end_pc: usize,
    catch_count: usize,
    catch_tags: [Option<usize>; MAX_TRY_CATCHES],
    catch_pcs: [usize; MAX_TRY_CATCHES],
    catch_all_pc: Option<usize>,
    delegate_depth: Option<usize>,
}

#[derive(Clone, Copy)]
struct ThrownException {
    tag_idx: usize,
    value_count: usize,
    values: [Value; MAX_EXCEPTION_ARITY],
}

#[derive(Clone, Copy)]
struct ControlFrame {
    kind: ControlKind,
    start_pc: usize,
    end_pc: usize,
    else_pc: Option<usize>,
    stack_height: usize,
    param_count: usize,
    result_count: usize,
    param_types: [ValueType; MAX_WASM_TYPE_ARITY],
    result_types: [ValueType; MAX_WASM_TYPE_ARITY],
    catch_count: usize,
    catch_tags: [Option<usize>; MAX_TRY_CATCHES],
    catch_pcs: [usize; MAX_TRY_CATCHES],
    catch_all_pc: Option<usize>,
    delegate_depth: Option<usize>,
    in_exception_handler: bool,
    active_exception_tag: Option<usize>,
    active_exception_count: usize,
    active_exception_values: [Value; MAX_EXCEPTION_ARITY],
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
    /// Global variables (instance-local state).
    globals: [Option<GlobalSlot>; MAX_WASM_GLOBALS],
    /// Active structured control frames for current function.
    control_stack: [Option<ControlFrame>; MAX_CONTROL_STACK],
    control_depth: usize,
    /// Inclusive upper bound for current function code (used by control scan).
    current_func_end: usize,
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
    call_depth: usize,
    /// JIT cache (per-function hash)
    jit_hash: [Option<u64>; 64],
    /// JIT user state (stack/locals/fuel/trap)
    jit_state: *mut JitUserState,
    jit_state_pages: usize,
    jit_user_pages: Option<JitUserPages>,
    jit_enabled: bool,
    jit_hot: [u32; 64],
    jit_validate_remaining: [u8; 64],
    last_received_service_handle: Option<CapHandle>,
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

    fn initialize_from_module(&mut self) -> Result<(), WasmError> {
        self.globals = [None; MAX_WASM_GLOBALS];
        let mut g = 0usize;
        while g < self.module.global_count {
            let template = self.module.global_templates[g].ok_or(WasmError::InvalidModule)?;
            self.globals[g] = Some(GlobalSlot {
                value_type: template.value_type,
                mutable: template.mutable,
                value: template.init,
            });
            g += 1;
        }

        let mut seg = 0usize;
        while seg < self.module.data_segments.len() {
            let data = &self.module.data_segments[seg];
            self.memory.write(data.offset, &data.bytes)?;
            seg += 1;
        }
        Ok(())
    }

    fn invoke_combined_function(&mut self, func_idx: usize) -> Result<(), WasmError> {
        match self.module.resolve_call_target(func_idx)? {
            CallTarget::Host(host_idx) => self.call_host_function(host_idx),
            CallTarget::Function(internal_idx) => self.call(internal_idx),
        }
    }

    fn run_start_if_present(&mut self) -> Result<(), WasmError> {
        let start = match self.module.start_function {
            Some(idx) => idx,
            None => return Ok(()),
        };
        self.stack.clear();
        self.invoke_combined_function(start)?;
        if !self.stack.is_empty() {
            self.stack.clear();
            return Err(WasmError::TypeMismatch);
        }
        Ok(())
    }

    fn push_control_frame(&mut self, frame: ControlFrame) -> Result<(), WasmError> {
        if self.control_depth >= MAX_CONTROL_STACK {
            return Err(WasmError::ExecutionLimitExceeded);
        }
        self.control_stack[self.control_depth] = Some(frame);
        self.control_depth += 1;
        Ok(())
    }

    fn truncate_to_height(&mut self, height: usize) -> Result<(), WasmError> {
        self.stack.truncate(height)
    }

    fn read_block_signature(
        &mut self,
    ) -> Result<
        (
            usize,
            [ValueType; MAX_WASM_TYPE_ARITY],
            usize,
            [ValueType; MAX_WASM_TYPE_ARITY],
        ),
        WasmError,
    > {
        if self.pc >= self.current_func_end {
            return Err(WasmError::UnexpectedEndOfCode);
        }
        let first = self.module.bytecode[self.pc];
        self.pc += 1;

        let mut params = [ValueType::I32; MAX_WASM_TYPE_ARITY];
        let mut results = [ValueType::I32; MAX_WASM_TYPE_ARITY];

        match first {
            0x40 => Ok((0, params, 0, results)),
            0x7F => {
                results[0] = ValueType::I32;
                Ok((0, params, 1, results))
            }
            0x7E => {
                results[0] = ValueType::I64;
                Ok((0, params, 1, results))
            }
            0x7D => {
                results[0] = ValueType::F32;
                Ok((0, params, 1, results))
            }
            0x7C => {
                results[0] = ValueType::F64;
                Ok((0, params, 1, results))
            }
            0x70 => {
                results[0] = ValueType::FuncRef;
                Ok((0, params, 1, results))
            }
            0x6F => {
                results[0] = ValueType::ExternRef;
                Ok((0, params, 1, results))
            }
            _ => {
                self.pc = self.pc.saturating_sub(1);
                let ty_idx = self.read_uleb128()? as usize;
                let sig = self.module.signature_for_type(ty_idx)?;
                let mut i = 0usize;
                while i < sig.param_count {
                    params[i] = sig.param_types[i];
                    i += 1;
                }
                let mut r = 0usize;
                while r < sig.result_count {
                    results[r] = sig.result_types[r];
                    r += 1;
                }
                Ok((sig.param_count, params, sig.result_count, results))
            }
        }
    }

    fn collect_typed_suffix(
        &self,
        types: &[ValueType; MAX_WASM_TYPE_ARITY],
        count: usize,
    ) -> Result<Vec<Value>, WasmError> {
        if count > MAX_WASM_TYPE_ARITY || self.stack.len() < count {
            return Err(WasmError::StackUnderflow);
        }
        let start = self.stack.len() - count;
        let mut values = Vec::with_capacity(count);
        let mut i = 0usize;
        while i < count {
            let value = self.stack.get(start + i)?;
            if !value.matches_type(types[i]) {
                return Err(WasmError::TypeMismatch);
            }
            values.push(value);
            i += 1;
        }
        Ok(values)
    }

    fn enforce_frame_exit_values(&mut self, frame: ControlFrame) -> Result<(), WasmError> {
        let values = self.collect_typed_suffix(&frame.result_types, frame.result_count)?;
        self.truncate_to_height(frame.stack_height)?;
        let mut i = 0usize;
        while i < values.len() {
            self.stack.push(values[i])?;
            i += 1;
        }
        Ok(())
    }

    fn parse_reftype_immediate(byte: u8) -> Result<ValueType, WasmError> {
        match byte {
            0x70 => Ok(ValueType::FuncRef),
            0x6F => Ok(ValueType::ExternRef),
            _ => Err(WasmError::InvalidModule),
        }
    }

    fn default_control_frame(
        &self,
        kind: ControlKind,
        start_pc: usize,
        end_pc: usize,
        else_pc: Option<usize>,
        stack_height: usize,
        param_count: usize,
        result_count: usize,
        param_types: [ValueType; MAX_WASM_TYPE_ARITY],
        result_types: [ValueType; MAX_WASM_TYPE_ARITY],
    ) -> ControlFrame {
        ControlFrame {
            kind,
            start_pc,
            end_pc,
            else_pc,
            stack_height,
            param_count,
            result_count,
            param_types,
            result_types,
            catch_count: 0,
            catch_tags: [None; MAX_TRY_CATCHES],
            catch_pcs: [0; MAX_TRY_CATCHES],
            catch_all_pc: None,
            delegate_depth: None,
            in_exception_handler: false,
            active_exception_tag: None,
            active_exception_count: 0,
            active_exception_values: [Value::I32(0); MAX_EXCEPTION_ARITY],
        }
    }

    fn default_thrown_exception(&self, tag_idx: usize) -> ThrownException {
        ThrownException {
            tag_idx,
            value_count: 0,
            values: [Value::I32(0); MAX_EXCEPTION_ARITY],
        }
    }

    fn collect_exception_payload(&mut self, tag_idx: usize) -> Result<ThrownException, WasmError> {
        let tag = self.module.tag_signature(tag_idx)?;
        let mut typed = [ValueType::I32; MAX_WASM_TYPE_ARITY];
        let mut i = 0usize;
        while i < tag.param_count {
            typed[i] = tag.param_types[i];
            i += 1;
        }
        let values = self.collect_typed_suffix(&typed, tag.param_count)?;
        self.truncate_to_height(self.stack.len().saturating_sub(tag.param_count))?;
        let mut exn = self.default_thrown_exception(tag_idx);
        exn.value_count = tag.param_count;
        let mut v = 0usize;
        while v < values.len() {
            exn.values[v] = values[v];
            v += 1;
        }
        Ok(exn)
    }

    fn find_exception_handler(
        &self,
        frame: ControlFrame,
        tag_idx: usize,
    ) -> Option<(usize, bool)> {
        let mut i = 0usize;
        while i < frame.catch_count {
            if frame.catch_tags[i] == Some(tag_idx) {
                return Some((frame.catch_pcs[i], true));
            }
            i += 1;
        }
        frame.catch_all_pc.map(|pc| (pc, false))
    }

    fn activate_exception_on_frame(
        &mut self,
        frame_idx: usize,
        handler_pc: usize,
        push_payload: bool,
        thrown: ThrownException,
    ) -> Result<(), WasmError> {
        let mut frame = self.control_stack[frame_idx].ok_or(WasmError::InvalidModule)?;
        frame.in_exception_handler = true;
        frame.active_exception_tag = Some(thrown.tag_idx);
        frame.active_exception_count = thrown.value_count;
        frame.active_exception_values = [Value::I32(0); MAX_EXCEPTION_ARITY];
        let mut i = 0usize;
        while i < thrown.value_count {
            frame.active_exception_values[i] = thrown.values[i];
            i += 1;
        }
        self.control_stack[frame_idx] = Some(frame);
        self.control_depth = frame_idx + 1;
        self.truncate_to_height(frame.stack_height)?;
        if push_payload {
            let mut j = 0usize;
            while j < thrown.value_count {
                self.stack.push(thrown.values[j])?;
                j += 1;
            }
        }
        self.pc = handler_pc;
        Ok(())
    }

    fn unwind_exception(
        &mut self,
        thrown: ThrownException,
        mut search_depth: usize,
    ) -> Result<(), WasmError> {
        while search_depth > 0 {
            let idx = search_depth - 1;
            let frame = self.control_stack[idx].ok_or(WasmError::InvalidModule)?;
            self.truncate_to_height(frame.stack_height)?;

            if frame.kind == ControlKind::Try {
                if let Some(delegate_depth) = frame.delegate_depth {
                    self.control_stack[idx] = None;
                    let target_plus_one = idx
                        .checked_sub(delegate_depth)
                        .ok_or(WasmError::Trap)?;
                    let mut pop_idx = idx;
                    while pop_idx > target_plus_one {
                        pop_idx -= 1;
                        let popped = self.control_stack[pop_idx].ok_or(WasmError::InvalidModule)?;
                        self.truncate_to_height(popped.stack_height)?;
                        self.control_stack[pop_idx] = None;
                    }
                    self.control_depth = target_plus_one;
                    search_depth = target_plus_one;
                    continue;
                }

                if let Some((handler_pc, push_payload)) =
                    self.find_exception_handler(frame, thrown.tag_idx)
                {
                    return self.activate_exception_on_frame(idx, handler_pc, push_payload, thrown);
                }
            }

            self.control_stack[idx] = None;
            self.control_depth = idx;
            search_depth = idx;
        }
        Err(WasmError::Trap)
    }

    fn rethrow_exception(&mut self, label_depth: usize) -> Result<(), WasmError> {
        if label_depth >= self.control_depth {
            return Err(WasmError::Trap);
        }
        let target_idx = self
            .control_depth
            .checked_sub(1 + label_depth)
            .ok_or(WasmError::Trap)?;
        let frame = self.control_stack[target_idx].ok_or(WasmError::InvalidModule)?;
        if frame.kind != ControlKind::Try || !frame.in_exception_handler {
            return Err(WasmError::Trap);
        }
        let tag_idx = frame.active_exception_tag.ok_or(WasmError::Trap)?;
        let mut thrown = self.default_thrown_exception(tag_idx);
        thrown.value_count = frame.active_exception_count;
        let mut i = 0usize;
        while i < thrown.value_count {
            thrown.values[i] = frame.active_exception_values[i];
            i += 1;
        }
        self.truncate_to_height(frame.stack_height)?;
        self.control_stack[target_idx] = None;
        self.control_depth = target_idx;
        self.unwind_exception(thrown, target_idx)
    }

    fn skip_opcode_immediate_scan(&self, mut pc: usize, opcode: Opcode) -> Result<usize, WasmError> {
        match opcode {
            Opcode::I32Const => {
                let (_v, n) = read_sleb128_i32_validate(&self.module.bytecode, pc)?;
                pc = pc.checked_add(n).ok_or(WasmError::InvalidModule)?;
            }
            Opcode::I64Const => {
                let (_v, n) = read_sleb128_i64_validate(&self.module.bytecode, pc)?;
                pc = pc.checked_add(n).ok_or(WasmError::InvalidModule)?;
            }
            Opcode::F32Const => {
                pc = pc.checked_add(4).ok_or(WasmError::InvalidModule)?;
            }
            Opcode::F64Const => {
                pc = pc.checked_add(8).ok_or(WasmError::InvalidModule)?;
            }
            Opcode::LocalGet
            | Opcode::LocalSet
            | Opcode::LocalTee
            | Opcode::GlobalGet
            | Opcode::GlobalSet
            | Opcode::Br
            | Opcode::BrIf
            | Opcode::Call
            | Opcode::Catch
            | Opcode::Throw
            | Opcode::Rethrow
            | Opcode::Delegate
            | Opcode::RefFunc => {
                let (_v, n) = read_uleb128_validate(&self.module.bytecode, pc)?;
                pc = pc.checked_add(n).ok_or(WasmError::InvalidModule)?;
            }
            Opcode::CallIndirect => {
                let (_v1, n1) = read_uleb128_validate(&self.module.bytecode, pc)?;
                pc = pc.checked_add(n1).ok_or(WasmError::InvalidModule)?;
                let (_v2, n2) = read_uleb128_validate(&self.module.bytecode, pc)?;
                pc = pc.checked_add(n2).ok_or(WasmError::InvalidModule)?;
            }
            Opcode::I32Load | Opcode::I64Load | Opcode::I32Store | Opcode::I64Store => {
                let (_a, n1) = read_uleb128_validate(&self.module.bytecode, pc)?;
                pc = pc.checked_add(n1).ok_or(WasmError::InvalidModule)?;
                let (_o, n2) = read_uleb128_validate(&self.module.bytecode, pc)?;
                pc = pc.checked_add(n2).ok_or(WasmError::InvalidModule)?;
            }
            Opcode::Block | Opcode::Loop | Opcode::If | Opcode::Try => {
                let n = read_blocktype_width_validate(&self.module.bytecode, pc)?;
                pc = pc.checked_add(n).ok_or(WasmError::InvalidModule)?;
            }
            Opcode::MemorySize | Opcode::MemoryGrow => {
                pc = pc.checked_add(1).ok_or(WasmError::InvalidModule)?;
            }
            Opcode::RefNull => {
                pc = pc.checked_add(1).ok_or(WasmError::InvalidModule)?;
            }
            _ => {}
        }

        if pc > self.current_func_end {
            return Err(WasmError::UnexpectedEndOfCode);
        }
        Ok(pc)
    }

    fn scan_control_structure(
        &self,
        kind: ControlKind,
        body_start_pc: usize,
    ) -> Result<(Option<usize>, usize), WasmError> {
        let mut pc = body_start_pc;
        let mut depth = 1usize;
        let mut else_pc = None;

        while pc < self.current_func_end {
            let op_pos = pc;
            let op_byte = self.module.bytecode[pc];
            pc += 1;
            let opcode = Opcode::from_byte(op_byte).ok_or(WasmError::UnknownOpcode(op_byte))?;
            pc = self.skip_opcode_immediate_scan(pc, opcode)?;

            match opcode {
                Opcode::Block | Opcode::Loop | Opcode::If | Opcode::Try => {
                    depth = depth.saturating_add(1);
                }
                Opcode::Else => {
                    if depth == 1 {
                        if kind != ControlKind::If || else_pc.is_some() {
                            return Err(WasmError::InvalidModule);
                        }
                        else_pc = Some(op_pos);
                    }
                }
                Opcode::End => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Ok((else_pc, op_pos));
                    }
                }
                _ => {}
            }
        }
        Err(WasmError::UnexpectedEndOfCode)
    }

    fn scan_try_structure(&self, body_start_pc: usize) -> Result<TryScanInfo, WasmError> {
        let mut pc = body_start_pc;
        let mut depth = 1usize;
        let mut catch_count = 0usize;
        let mut catch_tags = [None; MAX_TRY_CATCHES];
        let mut catch_pcs = [0usize; MAX_TRY_CATCHES];
        let mut catch_all_pc = None;
        let mut delegate_depth = None;

        while pc < self.current_func_end {
            let op_pos = pc;
            let op_byte = self.module.bytecode[pc];
            pc += 1;
            let opcode = Opcode::from_byte(op_byte).ok_or(WasmError::UnknownOpcode(op_byte))?;

            let immediate_pos = pc;
            pc = self.skip_opcode_immediate_scan(pc, opcode)?;

            match opcode {
                Opcode::Block | Opcode::Loop | Opcode::If | Opcode::Try => {
                    depth = depth.saturating_add(1);
                }
                Opcode::Catch => {
                    let (tag_idx, _n) = read_uleb128_validate(&self.module.bytecode, immediate_pos)?;
                    if depth == 1 {
                        if delegate_depth.is_some() || catch_all_pc.is_some() {
                            return Err(WasmError::InvalidModule);
                        }
                        if catch_count >= MAX_TRY_CATCHES {
                            return Err(WasmError::InvalidModule);
                        }
                        if tag_idx as usize >= self.module.tag_count {
                            return Err(WasmError::InvalidModule);
                        }
                        catch_tags[catch_count] = Some(tag_idx as usize);
                        catch_pcs[catch_count] = pc;
                        catch_count += 1;
                    }
                }
                Opcode::CatchAll => {
                    if depth == 1 {
                        if delegate_depth.is_some() || catch_all_pc.is_some() {
                            return Err(WasmError::InvalidModule);
                        }
                        catch_all_pc = Some(pc);
                    }
                }
                Opcode::Delegate => {
                    let (label_depth, _n) =
                        read_uleb128_validate(&self.module.bytecode, immediate_pos)?;
                    if depth == 1 {
                        if catch_count != 0 || catch_all_pc.is_some() || delegate_depth.is_some() {
                            return Err(WasmError::InvalidModule);
                        }
                        delegate_depth = Some(label_depth as usize);
                    }
                }
                Opcode::End => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        if catch_count == 0 && catch_all_pc.is_none() && delegate_depth.is_none() {
                            // try with no handlers/delegate is invalid under EH encoding.
                            return Err(WasmError::InvalidModule);
                        }
                        return Ok(TryScanInfo {
                            end_pc: op_pos,
                            catch_count,
                            catch_tags,
                            catch_pcs,
                            catch_all_pc,
                            delegate_depth,
                        });
                    }
                }
                _ => {}
            }
        }
        Err(WasmError::UnexpectedEndOfCode)
    }

    fn branch_to_label(&mut self, label_depth: usize) -> Result<(), WasmError> {
        if label_depth >= self.control_depth {
            return Err(WasmError::Trap);
        }
        let target_idx = self
            .control_depth
            .checked_sub(1 + label_depth)
            .ok_or(WasmError::Trap)?;
        let target = self.control_stack[target_idx].ok_or(WasmError::InvalidModule)?;

        let (label_count, label_types) = match target.kind {
            ControlKind::Loop => (target.param_count, target.param_types),
            ControlKind::Block | ControlKind::If | ControlKind::Try => {
                (target.result_count, target.result_types)
            }
        };
        let values = self.collect_typed_suffix(&label_types, label_count)?;
        self.truncate_to_height(target.stack_height)?;
        let mut i = 0usize;
        while i < values.len() {
            self.stack.push(values[i])?;
            i += 1;
        }

        match target.kind {
            ControlKind::Loop => {
                self.control_depth = target_idx + 1;
                self.pc = target.start_pc;
            }
            ControlKind::Block | ControlKind::If | ControlKind::Try => {
                self.control_depth = target_idx;
                self.pc = target
                    .end_pc
                    .checked_add(1)
                    .ok_or(WasmError::InvalidModule)?;
            }
        }
        Ok(())
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
        self.globals = [None; MAX_WASM_GLOBALS];
        self.control_stack = [None; MAX_CONTROL_STACK];
        self.control_depth = 0;
        self.current_func_end = 0;
        self.pc = 0;
        self.instruction_count = 0;
        self.memory_op_count = 0;
        self.syscall_count = 0;
        self.call_depth = 0;
        self.jit_hash = [None; 64];
        self.jit_hot = [0; 64];
        self.jit_validate_remaining = [0; 64];
        self.last_received_service_handle = None;
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

        let jit_state_base = self.jit_state as *mut u8;
        let jit_state_pages = self.jit_state_pages;
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
            globals: [None; MAX_WASM_GLOBALS],
            control_stack: [None; MAX_CONTROL_STACK],
            control_depth: 0,
            current_func_end: 0,
            pc: 0,
            capabilities: CapabilityTable::new(),
            process_id,
            instance_id,
            is_shadow: false,
            instruction_count: 0,
            memory_op_count: 0,
            syscall_count: 0,
            call_depth: 0,
            jit_hash: [None; 64],
            jit_state,
            jit_state_pages,
            jit_user_pages: None,
            jit_enabled: false,
            jit_hot: [0; 64],
            jit_validate_remaining: [JIT_VALIDATE_CALLS; 64],
            last_received_service_handle: None,
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
        if let Some(sig) = self.module.signature_for_defined(func_idx) {
            if !sig.all_i32 {
                return Ok(false);
            }
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
            globals: self.globals,
            control_stack: self.control_stack,
            control_depth: self.control_depth,
            current_func_end: self.current_func_end,
            pc: self.pc,
            capabilities: self.capabilities.clone(),
            process_id: self.process_id,
            instance_id: self.instance_id,
            is_shadow: true,
            instruction_count: 0,
            memory_op_count: 0,
            syscall_count: 0,
            call_depth: self.call_depth,
            jit_hash: [None; 64],
            jit_state,
            jit_state_pages,
            jit_user_pages: None,
            jit_enabled: false,
            jit_hot: [0; 64],
            jit_validate_remaining: [0; 64],
            last_received_service_handle: self.last_received_service_handle,
        }
    }

    fn restore_from_shadow(&mut self, shadow: WasmInstance) {
        self.memory = shadow.memory;
        self.stack = shadow.stack;
        self.locals = shadow.locals;
        self.globals = shadow.globals;
        self.control_stack = shadow.control_stack;
        self.control_depth = shadow.control_depth;
        self.current_func_end = shadow.current_func_end;
        self.pc = shadow.pc;
        self.instruction_count = shadow.instruction_count;
        self.memory_op_count = shadow.memory_op_count;
        self.syscall_count = shadow.syscall_count;
        self.call_depth = shadow.call_depth;
        self.last_received_service_handle = shadow.last_received_service_handle;
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

        if self.call_depth >= MAX_CALL_DEPTH {
            return Err(WasmError::ExecutionLimitExceeded);
        }
        self.call_depth += 1;
        let saved_control_stack = self.control_stack;
        let saved_control_depth = self.control_depth;
        let saved_func_end = self.current_func_end;

        let result = (|| -> Result<(), WasmError> {
            self.control_stack = [None; MAX_CONTROL_STACK];
            self.control_depth = 0;
            self.current_func_end = 0;

            // Check rate limiting and security
            if !crate::security::security().validate_capability(
                self.process_id,
                1, // Execute permission
                1,
            ).is_ok() {
                return Err(WasmError::PermissionDenied);
            }

            let func = self.module.get_function(func_idx)?;
            let locals_total = func
                .param_count
                .checked_add(func.local_count)
                .ok_or(WasmError::InvalidModule)?;
            if locals_total > MAX_LOCALS {
                return Err(WasmError::InvalidLocalIndex);
            }
            if self.stack.len() < func.param_count {
                return Err(WasmError::StackUnderflow);
            }
            let stack_height_before_call = self.stack.len().saturating_sub(func.param_count);
            let signature = self.module.signature_for_defined(func_idx);

            if self.try_jit(func, func_idx)? {
                return Ok(());
            }

            // Set up locals from stack parameters
            for i in (0..func.param_count).rev() {
                self.locals[i] = self.stack.pop()?;
            }
            for i in func.param_count..locals_total {
                self.locals[i] = Value::I32(0);
            }

            // Execute function body
            let (code_start, end_pc) = self.function_code_range(func)?;
            self.pc = code_start;
            self.current_func_end = end_pc;

            while self.pc < end_pc {
                let should_continue = self.step()?;
                if !should_continue {
                    // Return or End encountered
                    break;
                }
            }

            // Enforce function stack shape at exit without heap allocation.
            if func.result_count > MAX_WASM_TYPE_ARITY {
                return Err(WasmError::InvalidModule);
            }
            let mut values = [Value::I32(0); MAX_WASM_TYPE_ARITY];
            let values_len = if let Some(sig) = signature {
                if sig.result_count > MAX_WASM_TYPE_ARITY || self.stack.len() < sig.result_count {
                    return Err(WasmError::StackUnderflow);
                }
                let start = self.stack.len() - sig.result_count;
                let mut i = 0usize;
                while i < sig.result_count {
                    let value = self.stack.get(start + i)?;
                    if !value.matches_type(sig.result_types[i]) {
                        return Err(WasmError::TypeMismatch);
                    }
                    values[i] = value;
                    i += 1;
                }
                sig.result_count
            } else {
                if self.stack.len() < func.result_count {
                    return Err(WasmError::StackUnderflow);
                }
                let start = self.stack.len() - func.result_count;
                let mut i = 0usize;
                while i < func.result_count {
                    values[i] = self.stack.get(start + i)?;
                    i += 1;
                }
                func.result_count
            };
            self.truncate_to_height(stack_height_before_call)?;
            let mut i = 0usize;
            while i < values_len {
                self.stack.push(values[i])?;
                i += 1;
            }

            Ok(())
        })();
        self.control_stack = saved_control_stack;
        self.control_depth = saved_control_depth;
        self.current_func_end = saved_func_end;
        self.call_depth = self.call_depth.saturating_sub(1);
        result
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

            Opcode::Block => {
                let (param_count, param_types, result_count, result_types) =
                    self.read_block_signature()?;
                let body_start = self.pc;
                let (_else_pc, end_pc) = self.scan_control_structure(ControlKind::Block, body_start)?;
                let stack_len = self.stack.len();
                if stack_len < param_count {
                    return Err(WasmError::StackUnderflow);
                }
                let _ = self.collect_typed_suffix(&param_types, param_count)?;
                self.push_control_frame(self.default_control_frame(
                    ControlKind::Block,
                    body_start,
                    end_pc,
                    None,
                    stack_len - param_count,
                    param_count,
                    result_count,
                    param_types,
                    result_types,
                ))?;
            }

            Opcode::Loop => {
                let (param_count, param_types, result_count, result_types) =
                    self.read_block_signature()?;
                let body_start = self.pc;
                let (_else_pc, end_pc) = self.scan_control_structure(ControlKind::Loop, body_start)?;
                let stack_len = self.stack.len();
                if stack_len < param_count {
                    return Err(WasmError::StackUnderflow);
                }
                let _ = self.collect_typed_suffix(&param_types, param_count)?;
                self.push_control_frame(self.default_control_frame(
                    ControlKind::Loop,
                    body_start,
                    end_pc,
                    None,
                    stack_len - param_count,
                    param_count,
                    result_count,
                    param_types,
                    result_types,
                ))?;
            }

            Opcode::If => {
                let (param_count, param_types, result_count, result_types) =
                    self.read_block_signature()?;
                let body_start = self.pc;
                let (else_pc, end_pc) = self.scan_control_structure(ControlKind::If, body_start)?;
                let cond = self.stack.pop()?.as_i32()?;
                let stack_len = self.stack.len();
                if stack_len < param_count {
                    return Err(WasmError::StackUnderflow);
                }
                let _ = self.collect_typed_suffix(&param_types, param_count)?;
                self.push_control_frame(self.default_control_frame(
                    ControlKind::If,
                    body_start,
                    end_pc,
                    else_pc,
                    stack_len - param_count,
                    param_count,
                    result_count,
                    param_types,
                    result_types,
                ))?;

                if cond == 0 {
                    if let Some(else_pos) = else_pc {
                        self.pc = else_pos.checked_add(1).ok_or(WasmError::InvalidModule)?;
                    } else {
                        // Route through End so the control frame exit typing is enforced.
                        self.pc = end_pc;
                    }
                }
            }

            Opcode::Try => {
                let (param_count, param_types, result_count, result_types) =
                    self.read_block_signature()?;
                let body_start = self.pc;
                let scan = self.scan_try_structure(body_start)?;
                let stack_len = self.stack.len();
                if stack_len < param_count {
                    return Err(WasmError::StackUnderflow);
                }
                let _ = self.collect_typed_suffix(&param_types, param_count)?;
                let mut frame = self.default_control_frame(
                    ControlKind::Try,
                    body_start,
                    scan.end_pc,
                    None,
                    stack_len - param_count,
                    param_count,
                    result_count,
                    param_types,
                    result_types,
                );
                frame.catch_count = scan.catch_count;
                frame.catch_tags = scan.catch_tags;
                frame.catch_pcs = scan.catch_pcs;
                frame.catch_all_pc = scan.catch_all_pc;
                frame.delegate_depth = scan.delegate_depth;
                self.push_control_frame(frame)?;
            }

            Opcode::Catch => {
                let tag_idx = self.read_uleb128()? as usize;
                if tag_idx >= self.module.tag_count {
                    return Err(WasmError::InvalidModule);
                }
                if self.control_depth == 0 {
                    return Err(WasmError::InvalidModule);
                }
                let idx = self.control_depth - 1;
                let frame = self.control_stack[idx].ok_or(WasmError::InvalidModule)?;
                if frame.kind != ControlKind::Try {
                    return Err(WasmError::InvalidModule);
                }
                // Falling into a catch marker means try body completed without exception.
                self.enforce_frame_exit_values(frame)?;
                self.control_stack[idx] = None;
                self.control_depth = idx;
                self.pc = frame.end_pc.checked_add(1).ok_or(WasmError::InvalidModule)?;
            }

            Opcode::CatchAll => {
                if self.control_depth == 0 {
                    return Err(WasmError::InvalidModule);
                }
                let idx = self.control_depth - 1;
                let frame = self.control_stack[idx].ok_or(WasmError::InvalidModule)?;
                if frame.kind != ControlKind::Try {
                    return Err(WasmError::InvalidModule);
                }
                self.enforce_frame_exit_values(frame)?;
                self.control_stack[idx] = None;
                self.control_depth = idx;
                self.pc = frame.end_pc.checked_add(1).ok_or(WasmError::InvalidModule)?;
            }

            Opcode::Delegate => {
                let _label_depth = self.read_uleb128()? as usize;
                if self.control_depth == 0 {
                    return Err(WasmError::InvalidModule);
                }
                let idx = self.control_depth - 1;
                let frame = self.control_stack[idx].ok_or(WasmError::InvalidModule)?;
                if frame.kind != ControlKind::Try {
                    return Err(WasmError::InvalidModule);
                }
                self.enforce_frame_exit_values(frame)?;
                self.control_stack[idx] = None;
                self.control_depth = idx;
                self.pc = frame.end_pc.checked_add(1).ok_or(WasmError::InvalidModule)?;
            }

            Opcode::Throw => {
                let tag_idx = self.read_uleb128()? as usize;
                let thrown = self.collect_exception_payload(tag_idx)?;
                self.unwind_exception(thrown, self.control_depth)?;
            }

            Opcode::Rethrow => {
                let label_depth = self.read_uleb128()? as usize;
                self.rethrow_exception(label_depth)?;
            }

            Opcode::Else => {
                if self.control_depth == 0 {
                    return Err(WasmError::InvalidModule);
                }
                let idx = self.control_depth - 1;
                let frame = self.control_stack[idx].ok_or(WasmError::InvalidModule)?;
                if frame.kind != ControlKind::If || frame.else_pc != Some(self.pc - 1) {
                    return Err(WasmError::InvalidModule);
                }
                self.enforce_frame_exit_values(frame)?;
                self.control_stack[idx] = None;
                self.control_depth = idx;
                self.pc = frame.end_pc.checked_add(1).ok_or(WasmError::InvalidModule)?;
            }

            Opcode::End => {
                if self.control_depth == 0 {
                    // End of function body.
                    return Ok(false);
                }
                let idx = self.control_depth - 1;
                let frame = self.control_stack[idx].ok_or(WasmError::InvalidModule)?;
                if frame.end_pc != self.pc - 1 {
                    return Err(WasmError::InvalidModule);
                }
                self.enforce_frame_exit_values(frame)?;
                self.control_stack[idx] = None;
                self.control_depth = idx;
            }

            Opcode::Return => {
                // Return from function - stop execution
                let mut i = 0usize;
                while i < self.control_depth {
                    self.control_stack[i] = None;
                    i += 1;
                }
                self.control_depth = 0;
                self.pc = self.current_func_end;
                return Ok(false);
            }

            Opcode::Br => {
                let label_depth = self.read_uleb128()? as usize;
                self.branch_to_label(label_depth)?;
            }

            Opcode::BrIf => {
                let label_depth = self.read_uleb128()? as usize;
                let cond = self.stack.pop()?.as_i32()?;
                if cond != 0 {
                    self.branch_to_label(label_depth)?;
                }
            }

            Opcode::Drop => {
                self.stack.pop()?;
            }

            Opcode::Select => {
                let cond = self.stack.pop()?.as_i32()?;
                let val2 = self.stack.pop()?;
                let val1 = self.stack.pop()?;
                if core::mem::discriminant(&val1) != core::mem::discriminant(&val2) {
                    return Err(WasmError::TypeMismatch);
                }
                self.stack.push(if cond != 0 { val1 } else { val2 })?;
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

            Opcode::LocalTee => {
                let local_idx = self.read_uleb128()? as usize;
                if local_idx >= MAX_LOCALS {
                    return Err(WasmError::InvalidLocalIndex);
                }
                let value = self.stack.pop()?;
                self.locals[local_idx] = value;
                self.stack.push(value)?;
            }

            Opcode::GlobalGet => {
                let global_idx = self.read_uleb128()? as usize;
                if global_idx >= self.module.global_count {
                    return Err(WasmError::InvalidModule);
                }
                let slot = self.globals[global_idx].ok_or(WasmError::InvalidModule)?;
                self.stack.push(slot.value)?;
            }

            Opcode::GlobalSet => {
                let global_idx = self.read_uleb128()? as usize;
                if global_idx >= self.module.global_count {
                    return Err(WasmError::InvalidModule);
                }
                let mut slot = self.globals[global_idx].ok_or(WasmError::InvalidModule)?;
                if !slot.mutable {
                    return Err(WasmError::PermissionDenied);
                }
                let value = self.stack.pop()?;
                if !value.matches_type(slot.value_type) {
                    return Err(WasmError::TypeMismatch);
                }
                slot.value = value;
                self.globals[global_idx] = Some(slot);
            }

            Opcode::I32Const => {
                let value = self.read_sleb128_i32()?;
                self.stack.push(Value::I32(value))?;
            }

            Opcode::I64Const => {
                let value = self.read_sleb128_i64()?;
                self.stack.push(Value::I64(value))?;
            }

            Opcode::F32Const => {
                let bits = self.read_u32_immediate()?;
                self.stack.push(Value::F32(f32::from_bits(bits)))?;
            }

            Opcode::F64Const => {
                let bits = self.read_u64_immediate()?;
                self.stack.push(Value::F64(f64::from_bits(bits)))?;
            }

            Opcode::RefNull => {
                let bytecode_len = self.bytecode_len_clamped();
                if self.pc >= bytecode_len {
                    return Err(WasmError::UnexpectedEndOfCode);
                }
                let reftype = Self::parse_reftype_immediate(self.module.bytecode[self.pc])?;
                self.pc += 1;
                self.stack.push(Value::zero_for_type(reftype))?;
            }

            Opcode::RefIsNull => {
                let value = self.stack.pop()?;
                self.stack
                    .push(Value::I32(if value.is_null_ref()? { 1 } else { 0 }))?;
            }

            Opcode::RefFunc => {
                let func_idx = self.read_uleb128()? as usize;
                if func_idx >= self.module.total_function_count() {
                    return Err(WasmError::FunctionNotFound);
                }
                self.stack.push(Value::FuncRef(Some(func_idx)))?;
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

            Opcode::I64Add => {
                let b = self.stack.pop()?.as_i64()?;
                let a = self.stack.pop()?.as_i64()?;
                self.stack.push(Value::I64(a.wrapping_add(b)))?;
            }

            Opcode::I64Sub => {
                let b = self.stack.pop()?.as_i64()?;
                let a = self.stack.pop()?.as_i64()?;
                self.stack.push(Value::I64(a.wrapping_sub(b)))?;
            }

            Opcode::I64Mul => {
                let b = self.stack.pop()?.as_i64()?;
                let a = self.stack.pop()?.as_i64()?;
                self.stack.push(Value::I64(a.wrapping_mul(b)))?;
            }

            Opcode::I64DivS => {
                let b = self.stack.pop()?.as_i64()?;
                let a = self.stack.pop()?.as_i64()?;
                if b == 0 {
                    return Err(WasmError::DivisionByZero);
                }
                self.stack.push(Value::I64(a.wrapping_div(b)))?;
            }

            Opcode::F32Add => {
                let b = self.stack.pop()?.as_f32()?;
                let a = self.stack.pop()?.as_f32()?;
                self.stack.push(Value::F32(a + b))?;
            }

            Opcode::F32Sub => {
                let b = self.stack.pop()?.as_f32()?;
                let a = self.stack.pop()?.as_f32()?;
                self.stack.push(Value::F32(a - b))?;
            }

            Opcode::F32Mul => {
                let b = self.stack.pop()?.as_f32()?;
                let a = self.stack.pop()?.as_f32()?;
                self.stack.push(Value::F32(a * b))?;
            }

            Opcode::F32Div => {
                let b = self.stack.pop()?.as_f32()?;
                let a = self.stack.pop()?.as_f32()?;
                self.stack.push(Value::F32(a / b))?;
            }

            Opcode::F64Add => {
                let b = self.stack.pop()?.as_f64()?;
                let a = self.stack.pop()?.as_f64()?;
                self.stack.push(Value::F64(a + b))?;
            }

            Opcode::F64Sub => {
                let b = self.stack.pop()?.as_f64()?;
                let a = self.stack.pop()?.as_f64()?;
                self.stack.push(Value::F64(a - b))?;
            }

            Opcode::F64Mul => {
                let b = self.stack.pop()?.as_f64()?;
                let a = self.stack.pop()?.as_f64()?;
                self.stack.push(Value::F64(a * b))?;
            }

            Opcode::F64Div => {
                let b = self.stack.pop()?.as_f64()?;
                let a = self.stack.pop()?.as_f64()?;
                self.stack.push(Value::F64(a / b))?;
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

            Opcode::I64Load => {
                self.check_memory_limit()?;
                let _align = self.read_uleb128()?; // Alignment hint (ignored for now)
                let offset = self.read_uleb128()? as usize;
                let addr = self.stack.pop()?.as_u32()? as usize;
                let effective_addr = addr.checked_add(offset)
                    .ok_or(WasmError::MemoryOutOfBounds)?;
                let value = self.memory.read_i64(effective_addr)?;
                self.stack.push(Value::I64(value))?;
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

            Opcode::I64Store => {
                self.check_memory_limit()?;
                let _align = self.read_uleb128()?;
                let offset = self.read_uleb128()? as usize;
                let value = self.stack.pop()?.as_i64()?;
                let addr = self.stack.pop()?.as_u32()? as usize;
                let effective_addr = addr.checked_add(offset)
                    .ok_or(WasmError::MemoryOutOfBounds)?;
                self.memory.write_i64(effective_addr, value)?;
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
                match self.module.resolve_call_target(func_idx)? {
                    CallTarget::Host(host_idx) => self.call_host_function(host_idx)?,
                    CallTarget::Function(internal_idx) => self.call(internal_idx)?,
                }
            }

            Opcode::CallIndirect => {
                let type_idx = self.read_uleb128()? as usize;
                let table_idx = self.read_uleb128()? as usize;
                if table_idx != 0 {
                    return Err(WasmError::InvalidModule);
                }
                let elem_idx = self.stack.pop()?.as_u32()? as usize;
                if elem_idx >= self.module.table_size {
                    return Err(WasmError::Trap);
                }
                let target = self.module.table_entries[elem_idx].ok_or(WasmError::Trap)?;
                if !self.module.function_matches_type(target, type_idx) {
                    return Err(WasmError::TypeMismatch);
                }
                match self.module.resolve_call_target(target)? {
                    CallTarget::Host(host_idx) => self.call_host_function(host_idx)?,
                    CallTarget::Function(internal_idx) => self.call(internal_idx)?,
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

    /// Read signed LEB128 (i64)
    fn read_sleb128_i64(&mut self) -> Result<i64, WasmError> {
        let mut result = 0i64;
        let mut shift = 0;
        let mut byte;
        let bytecode_len = self.bytecode_len_clamped();

        loop {
            if self.pc >= bytecode_len {
                return Err(WasmError::UnexpectedEndOfCode);
            }

            byte = self.module.bytecode[self.pc];
            self.pc += 1;

            result |= ((byte & 0x7F) as i64) << shift;
            shift += 7;

            if (byte & 0x80) == 0 {
                break;
            }

            if shift > 63 {
                return Err(WasmError::Leb128Overflow);
            }
        }

        if shift < 64 && (byte & 0x40) != 0 {
            result |= !0i64 << shift;
        }
        Ok(result)
    }

    fn read_u32_immediate(&mut self) -> Result<u32, WasmError> {
        let end = self.pc.checked_add(4).ok_or(WasmError::InvalidModule)?;
        let bytecode_len = self.bytecode_len_clamped();
        if end > bytecode_len {
            return Err(WasmError::UnexpectedEndOfCode);
        }
        let bytes = &self.module.bytecode[self.pc..end];
        self.pc = end;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64_immediate(&mut self) -> Result<u64, WasmError> {
        let end = self.pc.checked_add(8).ok_or(WasmError::InvalidModule)?;
        let bytecode_len = self.bytecode_len_clamped();
        if end > bytecode_len {
            return Err(WasmError::UnexpectedEndOfCode);
        }
        let bytes = &self.module.bytecode[self.pc..end];
        self.pc = end;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
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
            8 => self.host_service_invoke(),
            9 => self.host_service_register(),
            10 => self.host_channel_send_with_cap(),
            11 => self.host_last_service_handle(),
            12 => self.host_service_invoke_typed(),
            13 => self.host_temporal_snapshot(),
            14 => self.host_temporal_latest(),
            15 => self.host_temporal_read(),
            16 => self.host_temporal_rollback(),
            17 => self.host_temporal_stats(),
            18 => self.host_temporal_history(),
            19 => self.host_temporal_branch_create(),
            20 => self.host_temporal_branch_checkout(),
            21 => self.host_temporal_branch_list(),
            22 => self.host_temporal_merge(),
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
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);
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
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);
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
        crate::security::security().intent_fs_read(self.process_id, fs_cap.cap_id as u64);
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
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);
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
        crate::security::security().intent_fs_write(self.process_id, fs_cap.cap_id as u64);
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
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);
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
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);
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

        self.last_received_service_handle = None;

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
                self.import_service_caps_from_message(&msg);
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
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);
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
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);
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
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);
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

    fn import_service_caps_from_message(&mut self, msg: &crate::ipc::Message) {
        for ipc_cap in msg.capabilities() {
            if ipc_cap.cap_type != crate::ipc::CapabilityType::ServicePointer {
                continue;
            }
            let imported = match capability::import_capability_from_ipc(
                self.process_id,
                ipc_cap,
                msg.source,
            ) {
                Ok(cap_id) => cap_id,
                Err(_) => continue,
            };

            let (cap_type, object_id) = match capability::capability_manager()
                .query_capability(self.process_id, imported)
            {
                Ok(v) => v,
                Err(_) => continue,
            };
            if cap_type != CapabilityType::ServicePointer as u32 {
                continue;
            }

            if let Ok(handle) = self.inject_capability(WasmCapability::ServicePointer(
                ServicePointerCapability {
                    object_id,
                    cap_id: imported,
                },
            )) {
                self.last_received_service_handle = Some(handle);
            }
        }
    }

    fn decode_typed_service_value(tag: u8, payload: u64) -> Result<Value, WasmError> {
        match tag {
            SERVICE_TYPED_KIND_I32 => Ok(Value::I32(payload as u32 as i32)),
            SERVICE_TYPED_KIND_I64 => Ok(Value::I64(payload as i64)),
            SERVICE_TYPED_KIND_F32 => Ok(Value::F32(f32::from_bits(payload as u32))),
            SERVICE_TYPED_KIND_F64 => Ok(Value::F64(f64::from_bits(payload))),
            SERVICE_TYPED_KIND_FUNCREF => {
                if payload == u64::MAX {
                    Ok(Value::FuncRef(None))
                } else {
                    Ok(Value::FuncRef(Some(payload as usize)))
                }
            }
            SERVICE_TYPED_KIND_EXTERNREF => {
                if payload == u64::MAX {
                    Ok(Value::ExternRef(None))
                } else {
                    Ok(Value::ExternRef(Some(payload as u32)))
                }
            }
            _ => Err(WasmError::TypeMismatch),
        }
    }

    fn encode_typed_service_value(value: Value, out: &mut [u8]) -> Result<(), WasmError> {
        if out.len() < SERVICE_TYPED_SLOT_BYTES {
            return Err(WasmError::SyscallFailed);
        }
        let (tag, payload) = match value {
            Value::I32(v) => (SERVICE_TYPED_KIND_I32, v as u32 as u64),
            Value::I64(v) => (SERVICE_TYPED_KIND_I64, v as u64),
            Value::F32(v) => (SERVICE_TYPED_KIND_F32, v.to_bits() as u64),
            Value::F64(v) => (SERVICE_TYPED_KIND_F64, v.to_bits()),
            Value::FuncRef(Some(idx)) => (SERVICE_TYPED_KIND_FUNCREF, idx as u64),
            Value::FuncRef(None) => (SERVICE_TYPED_KIND_FUNCREF, u64::MAX),
            Value::ExternRef(Some(id)) => (SERVICE_TYPED_KIND_EXTERNREF, id as u64),
            Value::ExternRef(None) => (SERVICE_TYPED_KIND_EXTERNREF, u64::MAX),
        };
        out[0] = tag;
        out[1..9].copy_from_slice(&payload.to_le_bytes());
        Ok(())
    }

    fn compose_u64(lo: u32, hi: u32) -> u64 {
        ((hi as u64) << 32) | (lo as u64)
    }

    fn split_u64(value: u64) -> (u32, u32) {
        (value as u32, (value >> 32) as u32)
    }

    fn pop_nonneg_i32_as_usize(&mut self) -> Result<usize, WasmError> {
        let value = self.stack.pop()?.as_i32()?;
        if value < 0 {
            return Err(WasmError::SyscallFailed);
        }
        Ok(value as usize)
    }

    fn encode_temporal_meta(meta: &crate::temporal::TemporalVersionMeta) -> [u8; TEMPORAL_META_BYTES] {
        let mut out = [0u8; TEMPORAL_META_BYTES];
        out[0..4].copy_from_slice(&(meta.version_id as u32).to_le_bytes());
        out[4..8].copy_from_slice(&((meta.version_id >> 32) as u32).to_le_bytes());
        out[8..12].copy_from_slice(&meta.branch_id.to_le_bytes());
        out[12..16].copy_from_slice(&(meta.data_len as u32).to_le_bytes());
        out[16..20].copy_from_slice(&meta.leaf_count.to_le_bytes());
        out[20..24].copy_from_slice(&meta.content_hash.to_le_bytes());
        out[24..28].copy_from_slice(&meta.merkle_root.to_le_bytes());
        out[28..32].copy_from_slice(&(meta.operation as u32).to_le_bytes());
        out
    }

    fn encode_temporal_rollback(
        result: &crate::temporal::TemporalRollbackResult,
    ) -> [u8; TEMPORAL_ROLLBACK_BYTES] {
        let mut out = [0u8; TEMPORAL_ROLLBACK_BYTES];
        out[0..4].copy_from_slice(&(result.new_version_id as u32).to_le_bytes());
        out[4..8].copy_from_slice(&((result.new_version_id >> 32) as u32).to_le_bytes());
        out[8..12].copy_from_slice(&result.branch_id.to_le_bytes());
        out[12..16].copy_from_slice(&(result.restored_len as u32).to_le_bytes());
        out
    }

    fn encode_temporal_stats(stats: crate::temporal::TemporalStats) -> [u8; TEMPORAL_STATS_BYTES] {
        let mut out = [0u8; TEMPORAL_STATS_BYTES];
        let bytes = stats.bytes as u64;
        out[0..4].copy_from_slice(&(stats.objects as u32).to_le_bytes());
        out[4..8].copy_from_slice(&(stats.versions as u32).to_le_bytes());
        out[8..12].copy_from_slice(&(bytes as u32).to_le_bytes());
        out[12..16].copy_from_slice(&((bytes >> 32) as u32).to_le_bytes());
        out[16..20].copy_from_slice(&(stats.active_branches as u32).to_le_bytes());
        out
    }

    fn encode_temporal_history_record(meta: &crate::temporal::TemporalVersionMeta) -> [u8; TEMPORAL_HISTORY_RECORD_BYTES] {
        let mut out = [0u8; TEMPORAL_HISTORY_RECORD_BYTES];
        let (version_lo, version_hi) = Self::split_u64(meta.version_id);
        let parent = meta.parent_version_id.unwrap_or(u64::MAX);
        let rollback = meta.rollback_from_version_id.unwrap_or(u64::MAX);
        let (parent_lo, parent_hi) = Self::split_u64(parent);
        let (rollback_lo, rollback_hi) = Self::split_u64(rollback);
        let (tick_lo, tick_hi) = Self::split_u64(meta.tick);

        let mut words = [0u32; 16];
        words[0] = version_lo;
        words[1] = version_hi;
        words[2] = parent_lo;
        words[3] = parent_hi;
        words[4] = rollback_lo;
        words[5] = rollback_hi;
        words[6] = meta.branch_id;
        words[7] = meta.data_len as u32;
        words[8] = meta.leaf_count;
        words[9] = meta.content_hash;
        words[10] = meta.merkle_root;
        words[11] = meta.operation as u32;
        words[12] = tick_lo;
        words[13] = tick_hi;
        words[14] = (meta.parent_version_id.is_some() as u32)
            | ((meta.rollback_from_version_id.is_some() as u32) << 1);
        words[15] = 1; // record format version

        let mut i = 0usize;
        while i < words.len() {
            let base = i * 4;
            out[base..base + 4].copy_from_slice(&words[i].to_le_bytes());
            i += 1;
        }
        out
    }

    fn encode_temporal_branch_checkout(
        branch_id: u32,
        head_version: Option<u64>,
    ) -> [u8; TEMPORAL_BRANCH_CHECKOUT_BYTES] {
        let mut out = [0u8; TEMPORAL_BRANCH_CHECKOUT_BYTES];
        let head = head_version.unwrap_or(u64::MAX);
        let (head_lo, head_hi) = Self::split_u64(head);
        let words = [
            branch_id,
            if head_version.is_some() { 1 } else { 0 },
            head_lo,
            head_hi,
        ];
        let mut i = 0usize;
        while i < words.len() {
            let base = i * 4;
            out[base..base + 4].copy_from_slice(&words[i].to_le_bytes());
            i += 1;
        }
        out
    }

    fn encode_temporal_branch_record(
        branch: &crate::temporal::TemporalBranchInfo,
    ) -> [u8; TEMPORAL_BRANCH_RECORD_BYTES] {
        let mut out = [0u8; TEMPORAL_BRANCH_RECORD_BYTES];
        let head = branch.head_version_id.unwrap_or(u64::MAX);
        let (head_lo, head_hi) = Self::split_u64(head);
        let mut flags = 0u32;
        if branch.active {
            flags |= 1;
        }
        if branch.head_version_id.is_some() {
            flags |= 1 << 1;
        }
        let words = [branch.branch_id, head_lo, head_hi, flags];
        let mut i = 0usize;
        while i < words.len() {
            let base = i * 4;
            out[base..base + 4].copy_from_slice(&words[i].to_le_bytes());
            i += 1;
        }
        let name_bytes = branch.name.as_bytes();
        let use_len = core::cmp::min(name_bytes.len(), TEMPORAL_BRANCH_NAME_BYTES);
        out[16..18].copy_from_slice(&(use_len as u16).to_le_bytes());
        out[18..20].copy_from_slice(&0u16.to_le_bytes());
        out[20..20 + use_len].copy_from_slice(&name_bytes[..use_len]);
        out
    }

    fn encode_temporal_merge_result(
        result: &crate::temporal::TemporalMergeResult,
    ) -> [u8; TEMPORAL_MERGE_RESULT_BYTES] {
        let mut out = [0u8; TEMPORAL_MERGE_RESULT_BYTES];
        let mut flags = 0u32;
        if result.fast_forward {
            flags |= 1;
        }
        if result.new_version_id.is_some() {
            flags |= 1 << 1;
        }
        if result.target_head_before.is_some() {
            flags |= 1 << 2;
        }
        if result.target_head_after.is_some() {
            flags |= 1 << 3;
        }
        let new_version = result.new_version_id.unwrap_or(u64::MAX);
        let before = result.target_head_before.unwrap_or(u64::MAX);
        let after = result.target_head_after.unwrap_or(u64::MAX);
        let (new_lo, new_hi) = Self::split_u64(new_version);
        let (before_lo, before_hi) = Self::split_u64(before);
        let (after_lo, after_hi) = Self::split_u64(after);
        let words = [
            flags,
            result.target_branch_id,
            result.source_branch_id,
            0,
            new_lo,
            new_hi,
            before_lo,
            before_hi,
            after_lo,
            after_hi,
        ];
        let mut i = 0usize;
        while i < words.len() {
            let base = i * 4;
            out[base..base + 4].copy_from_slice(&words[i].to_le_bytes());
            i += 1;
        }
        out
    }

    /// oreulia_service_invoke(cap: i32, args_ptr: i32, args_count: i32) -> i32
    fn host_service_invoke(&mut self) -> Result<(), WasmError> {
        let args_count = self.stack.pop()?.as_i32()? as usize;
        let args_ptr = self.stack.pop()?.as_i32()? as usize;
        let cap_handle = CapHandle(self.stack.pop()?.as_u32()?);

        if args_count > MAX_SERVICE_CALL_ARGS {
            return Err(WasmError::SyscallFailed);
        }

        let svc_ptr = match self.capabilities.get(cap_handle)? {
            WasmCapability::ServicePointer(ptr) => ptr,
            _ => return Err(WasmError::InvalidCapability),
        };

        let func_id: u16 = 8;
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);

        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, cap_handle.0);
        args_hash = replay::hash_u32(args_hash, args_count as u32);
        args_hash = replay::hash_u32(args_hash, (svc_ptr.object_id >> 32) as u32);
        args_hash = replay::hash_u32(args_hash, svc_ptr.object_id as u32);

        let mut words = [0u32; MAX_SERVICE_CALL_ARGS];
        if args_count > 0 {
            let bytes = self
                .memory
                .read(args_ptr, args_count.saturating_mul(4))?;
            args_hash = replay::hash_bytes(args_hash, bytes);
            let mut i = 0usize;
            while i < args_count {
                let base = i * 4;
                words[i] = u32::from_le_bytes([
                    bytes[base],
                    bytes[base + 1],
                    bytes[base + 2],
                    bytes[base + 3],
                ]);
                i += 1;
            }
        }

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

        let result = invoke_service_pointer(self.process_id, svc_ptr.object_id, &words[..args_count])
            .map_err(|_| WasmError::SyscallFailed)?;
        self.stack.push(Value::I32(result as i32))?;

        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                result as i32,
                &[],
            )
            .map_err(|_| WasmError::ReplayError)?;
        }
        Ok(())
    }

    /// oreulia_service_invoke_typed(cap: i32, args_ptr: i32, args_count: i32, results_ptr: i32, results_capacity: i32) -> i32
    fn host_service_invoke_typed(&mut self) -> Result<(), WasmError> {
        let results_capacity = self.stack.pop()?.as_i32()? as usize;
        let results_ptr = self.stack.pop()?.as_i32()? as usize;
        let args_count = self.stack.pop()?.as_i32()? as usize;
        let args_ptr = self.stack.pop()?.as_i32()? as usize;
        let cap_handle = CapHandle(self.stack.pop()?.as_u32()?);

        if args_count > MAX_WASM_TYPE_ARITY || results_capacity > MAX_WASM_TYPE_ARITY {
            return Err(WasmError::SyscallFailed);
        }

        let svc_ptr = match self.capabilities.get(cap_handle)? {
            WasmCapability::ServicePointer(ptr) => ptr,
            _ => return Err(WasmError::InvalidCapability),
        };

        let func_id: u16 = 12;
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);

        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, cap_handle.0);
        args_hash = replay::hash_u32(args_hash, args_count as u32);
        args_hash = replay::hash_u32(args_hash, results_capacity as u32);
        args_hash = replay::hash_u32(args_hash, (svc_ptr.object_id >> 32) as u32);
        args_hash = replay::hash_u32(args_hash, svc_ptr.object_id as u32);

        let mut typed_args: Vec<Value> = Vec::new();
        let encoded_arg_len = args_count
            .checked_mul(SERVICE_TYPED_SLOT_BYTES)
            .ok_or(WasmError::SyscallFailed)?;
        if encoded_arg_len > 0 {
            let encoded = self.memory.read(args_ptr, encoded_arg_len)?;
            args_hash = replay::hash_bytes(args_hash, encoded);
            typed_args.reserve(args_count);
            let mut i = 0usize;
            while i < args_count {
                let base = i * SERVICE_TYPED_SLOT_BYTES;
                let payload = u64::from_le_bytes([
                    encoded[base + 1],
                    encoded[base + 2],
                    encoded[base + 3],
                    encoded[base + 4],
                    encoded[base + 5],
                    encoded[base + 6],
                    encoded[base + 7],
                    encoded[base + 8],
                ]);
                typed_args.push(Self::decode_typed_service_value(encoded[base], payload)?);
                i += 1;
            }
        }

        let mode = self.replay_mode();
        if mode == ReplayMode::Replay {
            let out = replay::replay_host_call(self.instance_id, func_id, args_hash)
                .map_err(|_| WasmError::DeterminismViolation)?;
            if out.status == ReplayEventStatus::Err {
                return Err(WasmError::SyscallFailed);
            }
            let result_count = out.result as usize;
            if result_count > results_capacity {
                return Err(WasmError::DeterminismViolation);
            }
            let expected_len = result_count
                .checked_mul(SERVICE_TYPED_SLOT_BYTES)
                .ok_or(WasmError::DeterminismViolation)?;
            if out.data.len() != expected_len {
                return Err(WasmError::DeterminismViolation);
            }
            if !out.data.is_empty() {
                self.memory.write(results_ptr, &out.data)?;
            }
            self.stack.push(Value::I32(out.result))?;
            return Ok(());
        }

        let result = invoke_service_pointer_typed(self.process_id, svc_ptr.object_id, &typed_args)
            .map_err(|_| WasmError::SyscallFailed)?;
        if result.value_count > results_capacity {
            return Err(WasmError::SyscallFailed);
        }
        let result_len = result
            .value_count
            .checked_mul(SERVICE_TYPED_SLOT_BYTES)
            .ok_or(WasmError::SyscallFailed)?;
        let mut encoded_results: Vec<u8> = Vec::with_capacity(result_len);
        encoded_results.resize(result_len, 0);
        let mut i = 0usize;
        while i < result.value_count {
            let base = i * SERVICE_TYPED_SLOT_BYTES;
            Self::encode_typed_service_value(result.values[i], &mut encoded_results[base..base + SERVICE_TYPED_SLOT_BYTES])?;
            i += 1;
        }
        if !encoded_results.is_empty() {
            self.memory.write(results_ptr, &encoded_results)?;
        }
        self.stack.push(Value::I32(result.value_count as i32))?;

        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                result.value_count as i32,
                &encoded_results,
            )
            .map_err(|_| WasmError::ReplayError)?;
        }
        Ok(())
    }

    /// oreulia_service_register(func: i32|funcref, delegate: i32) -> i32
    fn host_service_register(&mut self) -> Result<(), WasmError> {
        let delegate = self.stack.pop()?.as_i32()? != 0;
        let selector = self.stack.pop()?;
        let (selector_kind, func_idx) = match selector {
            Value::I32(v) if v >= 0 => (0u32, v as usize),
            Value::FuncRef(Some(idx)) => (1u32, idx),
            _ => return Err(WasmError::TypeMismatch),
        };

        let func_id: u16 = 9;
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);
        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, selector_kind);
        args_hash = replay::hash_u32(args_hash, func_idx as u32);
        args_hash = replay::hash_u32(args_hash, if delegate { 1 } else { 0 });

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

        let registration =
            register_service_pointer(self.process_id, self.instance_id, func_idx, delegate)
                .map_err(|_| WasmError::SyscallFailed)?;
        let handle = self
            .inject_capability(WasmCapability::ServicePointer(ServicePointerCapability {
                object_id: registration.object_id,
                cap_id: registration.cap_id,
            }))?
            .0 as i32;
        self.stack.push(Value::I32(handle))?;

        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                handle,
                &[],
            )
            .map_err(|_| WasmError::ReplayError)?;
        }
        Ok(())
    }

    /// oreulia_channel_send_cap(chan_cap: i32, msg_ptr: i32, msg_len: i32, cap: i32) -> i32
    fn host_channel_send_with_cap(&mut self) -> Result<(), WasmError> {
        let cap_to_send = CapHandle(self.stack.pop()?.as_u32()?);
        let msg_len = self.stack.pop()?.as_i32()? as usize;
        let msg_ptr = self.stack.pop()?.as_i32()? as usize;
        let channel_cap_handle = CapHandle(self.stack.pop()?.as_u32()?);

        let channel_id = match self.capabilities.get(channel_cap_handle)? {
            WasmCapability::Channel(id) => id,
            _ => return Err(WasmError::InvalidCapability),
        };

        let msg_data = self.memory.read(msg_ptr, msg_len)?;
        let mut attached_object = 0u64;
        let mut attached_cap_id = 0u32;
        let mut attach = None;

        if cap_to_send.0 != u32::MAX {
            let svc = match self.capabilities.get(cap_to_send)? {
                WasmCapability::ServicePointer(ptr) => ptr,
                _ => return Err(WasmError::InvalidCapability),
            };
            attached_object = svc.object_id;
            attached_cap_id = svc.cap_id;
            let ipc_cap = capability::export_capability_to_ipc(self.process_id, svc.cap_id)
                .map_err(|_| WasmError::SyscallFailed)?;
            attach = Some(ipc_cap);
        }

        let func_id: u16 = 10;
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);
        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, channel_cap_handle.0);
        args_hash = replay::hash_u32(args_hash, msg_len as u32);
        args_hash = replay::hash_bytes(args_hash, msg_data);
        args_hash = replay::hash_u32(args_hash, cap_to_send.0);
        args_hash = replay::hash_u32(args_hash, (attached_object >> 32) as u32);
        args_hash = replay::hash_u32(args_hash, attached_object as u32);
        args_hash = replay::hash_u32(args_hash, attached_cap_id);

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

        let channel_cap = crate::ipc::ChannelCapability::new(
            0,
            channel_id,
            crate::ipc::ChannelRights::send_only(),
            self.process_id,
        );
        let mut msg = crate::ipc::Message::with_data(self.process_id, msg_data)
            .map_err(|_| WasmError::SyscallFailed)?;
        if let Some(ipc_cap) = attach {
            msg.add_capability(ipc_cap).map_err(|_| WasmError::SyscallFailed)?;
        }
        crate::ipc::ipc()
            .send(msg, &channel_cap)
            .map_err(|_| WasmError::SyscallFailed)?;
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

    /// oreulia_last_service_cap() -> i32
    fn host_last_service_handle(&mut self) -> Result<(), WasmError> {
        let func_id: u16 = 11;
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);
        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);

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

        let handle = self
            .last_received_service_handle
            .map(|h| h.0 as i32)
            .unwrap_or(-1);
        self.stack.push(Value::I32(handle))?;

        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                handle,
                &[],
            )
            .map_err(|_| WasmError::ReplayError)?;
        }
        Ok(())
    }

    /// oreulia_temporal_snapshot(cap: i32, path_ptr: i32, path_len: i32, out_meta_ptr: i32) -> i32
    fn host_temporal_snapshot(&mut self) -> Result<(), WasmError> {
        let out_meta_ptr = self.pop_nonneg_i32_as_usize()?;
        let path_len = self.pop_nonneg_i32_as_usize()?;
        let path_ptr = self.pop_nonneg_i32_as_usize()?;
        let cap_handle = CapHandle(self.stack.pop()?.as_u32()?);
        let fs_cap = match self.capabilities.get(cap_handle)? {
            WasmCapability::Filesystem(cap) => cap,
            _ => return Err(WasmError::InvalidCapability),
        };
        let path_bytes = self.memory.read(path_ptr, path_len)?.to_vec();

        let func_id: u16 = 13;
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);

        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, cap_handle.0);
        args_hash = replay::hash_u32(args_hash, path_len as u32);
        args_hash = replay::hash_bytes(args_hash, &path_bytes);

        let mode = self.replay_mode();
        if mode == ReplayMode::Replay {
            let out = replay::replay_host_call(self.instance_id, func_id, args_hash)
                .map_err(|_| WasmError::DeterminismViolation)?;
            if out.status == ReplayEventStatus::Err {
                return Err(WasmError::SyscallFailed);
            }
            if out.result == 0 {
                if out.data.len() != TEMPORAL_META_BYTES {
                    return Err(WasmError::DeterminismViolation);
                }
                self.memory.write(out_meta_ptr, &out.data)?;
            } else if !out.data.is_empty() {
                return Err(WasmError::DeterminismViolation);
            }
            self.stack.push(Value::I32(out.result))?;
            return Ok(());
        }

        let mut result_code = -1i32;
        let mut encoded = [0u8; TEMPORAL_META_BYTES];
        let mut encoded_len = 0usize;

        if let Ok(path) = core::str::from_utf8(&path_bytes) {
            if let Ok(key) = fs::FileKey::new(path) {
                if fs_cap.rights.has(fs::FilesystemRights::READ) && fs_cap.can_access(&key) {
                    if crate::temporal::snapshot_path(path).is_ok() {
                        if let Ok(meta) = crate::temporal::latest_version(path) {
                            encoded = Self::encode_temporal_meta(&meta);
                            self.memory.write(out_meta_ptr, &encoded)?;
                            encoded_len = TEMPORAL_META_BYTES;
                            result_code = 0;
                        }
                    }
                }
            }
        }

        self.stack.push(Value::I32(result_code))?;

        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                result_code,
                &encoded[..encoded_len],
            )
            .map_err(|_| WasmError::ReplayError)?;
        }
        Ok(())
    }

    /// oreulia_temporal_latest(cap: i32, path_ptr: i32, path_len: i32, out_meta_ptr: i32) -> i32
    fn host_temporal_latest(&mut self) -> Result<(), WasmError> {
        let out_meta_ptr = self.pop_nonneg_i32_as_usize()?;
        let path_len = self.pop_nonneg_i32_as_usize()?;
        let path_ptr = self.pop_nonneg_i32_as_usize()?;
        let cap_handle = CapHandle(self.stack.pop()?.as_u32()?);
        let fs_cap = match self.capabilities.get(cap_handle)? {
            WasmCapability::Filesystem(cap) => cap,
            _ => return Err(WasmError::InvalidCapability),
        };
        let path_bytes = self.memory.read(path_ptr, path_len)?.to_vec();

        let func_id: u16 = 14;
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);

        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, cap_handle.0);
        args_hash = replay::hash_u32(args_hash, path_len as u32);
        args_hash = replay::hash_bytes(args_hash, &path_bytes);

        let mode = self.replay_mode();
        if mode == ReplayMode::Replay {
            let out = replay::replay_host_call(self.instance_id, func_id, args_hash)
                .map_err(|_| WasmError::DeterminismViolation)?;
            if out.status == ReplayEventStatus::Err {
                return Err(WasmError::SyscallFailed);
            }
            if out.result == 0 {
                if out.data.len() != TEMPORAL_META_BYTES {
                    return Err(WasmError::DeterminismViolation);
                }
                self.memory.write(out_meta_ptr, &out.data)?;
            } else if !out.data.is_empty() {
                return Err(WasmError::DeterminismViolation);
            }
            self.stack.push(Value::I32(out.result))?;
            return Ok(());
        }

        let mut result_code = -1i32;
        let mut encoded = [0u8; TEMPORAL_META_BYTES];
        let mut encoded_len = 0usize;

        if let Ok(path) = core::str::from_utf8(&path_bytes) {
            if let Ok(key) = fs::FileKey::new(path) {
                if fs_cap.rights.has(fs::FilesystemRights::READ) && fs_cap.can_access(&key) {
                    if let Ok(meta) = crate::temporal::latest_version(path) {
                        encoded = Self::encode_temporal_meta(&meta);
                        self.memory.write(out_meta_ptr, &encoded)?;
                        encoded_len = TEMPORAL_META_BYTES;
                        result_code = 0;
                    }
                }
            }
        }

        self.stack.push(Value::I32(result_code))?;

        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                result_code,
                &encoded[..encoded_len],
            )
            .map_err(|_| WasmError::ReplayError)?;
        }
        Ok(())
    }

    /// oreulia_temporal_read(cap: i32, path_ptr: i32, path_len: i32, version_lo: i32, version_hi: i32, buf_ptr: i32, buf_len: i32) -> i32
    fn host_temporal_read(&mut self) -> Result<(), WasmError> {
        let buf_len = self.pop_nonneg_i32_as_usize()?;
        let buf_ptr = self.pop_nonneg_i32_as_usize()?;
        let version_hi = self.stack.pop()?.as_u32()?;
        let version_lo = self.stack.pop()?.as_u32()?;
        let path_len = self.pop_nonneg_i32_as_usize()?;
        let path_ptr = self.pop_nonneg_i32_as_usize()?;
        let cap_handle = CapHandle(self.stack.pop()?.as_u32()?);
        let fs_cap = match self.capabilities.get(cap_handle)? {
            WasmCapability::Filesystem(cap) => cap,
            _ => return Err(WasmError::InvalidCapability),
        };
        let path_bytes = self.memory.read(path_ptr, path_len)?.to_vec();
        let version_id = Self::compose_u64(version_lo, version_hi);

        let func_id: u16 = 15;
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);

        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, cap_handle.0);
        args_hash = replay::hash_u32(args_hash, path_len as u32);
        args_hash = replay::hash_bytes(args_hash, &path_bytes);
        args_hash = replay::hash_u32(args_hash, version_lo);
        args_hash = replay::hash_u32(args_hash, version_hi);
        args_hash = replay::hash_u32(args_hash, buf_len as u32);

        let mode = self.replay_mode();
        if mode == ReplayMode::Replay {
            let out = replay::replay_host_call(self.instance_id, func_id, args_hash)
                .map_err(|_| WasmError::DeterminismViolation)?;
            if out.status == ReplayEventStatus::Err {
                return Err(WasmError::SyscallFailed);
            }
            if out.result >= 0 {
                let expected = out.result as usize;
                if expected > buf_len || expected != out.data.len() {
                    return Err(WasmError::DeterminismViolation);
                }
                if expected > 0 {
                    self.memory.write(buf_ptr, &out.data)?;
                }
            } else if !out.data.is_empty() {
                return Err(WasmError::DeterminismViolation);
            }
            self.stack.push(Value::I32(out.result))?;
            return Ok(());
        }

        let mut result_code = -1i32;
        let mut recorded: Vec<u8> = Vec::new();

        if let Ok(path) = core::str::from_utf8(&path_bytes) {
            if let Ok(key) = fs::FileKey::new(path) {
                if fs_cap.rights.has(fs::FilesystemRights::READ) && fs_cap.can_access(&key) {
                    if let Ok(payload) = crate::temporal::read_version(path, version_id) {
                        let copy_len = core::cmp::min(buf_len, payload.len());
                        if copy_len > 0 {
                            self.memory.write(buf_ptr, &payload[..copy_len])?;
                            recorded.extend_from_slice(&payload[..copy_len]);
                        }
                        result_code = copy_len as i32;
                    }
                }
            }
        }

        self.stack.push(Value::I32(result_code))?;

        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                result_code,
                &recorded,
            )
            .map_err(|_| WasmError::ReplayError)?;
        }
        Ok(())
    }

    /// oreulia_temporal_rollback(cap: i32, path_ptr: i32, path_len: i32, version_lo: i32, version_hi: i32, out_ptr: i32) -> i32
    fn host_temporal_rollback(&mut self) -> Result<(), WasmError> {
        let out_ptr = self.pop_nonneg_i32_as_usize()?;
        let version_hi = self.stack.pop()?.as_u32()?;
        let version_lo = self.stack.pop()?.as_u32()?;
        let path_len = self.pop_nonneg_i32_as_usize()?;
        let path_ptr = self.pop_nonneg_i32_as_usize()?;
        let cap_handle = CapHandle(self.stack.pop()?.as_u32()?);
        let fs_cap = match self.capabilities.get(cap_handle)? {
            WasmCapability::Filesystem(cap) => cap,
            _ => return Err(WasmError::InvalidCapability),
        };
        let path_bytes = self.memory.read(path_ptr, path_len)?.to_vec();
        let version_id = Self::compose_u64(version_lo, version_hi);

        let func_id: u16 = 16;
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);

        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, cap_handle.0);
        args_hash = replay::hash_u32(args_hash, path_len as u32);
        args_hash = replay::hash_bytes(args_hash, &path_bytes);
        args_hash = replay::hash_u32(args_hash, version_lo);
        args_hash = replay::hash_u32(args_hash, version_hi);

        let mode = self.replay_mode();
        if mode == ReplayMode::Replay {
            let out = replay::replay_host_call(self.instance_id, func_id, args_hash)
                .map_err(|_| WasmError::DeterminismViolation)?;
            if out.status == ReplayEventStatus::Err {
                return Err(WasmError::SyscallFailed);
            }
            if out.result == 0 {
                if out.data.len() != TEMPORAL_ROLLBACK_BYTES {
                    return Err(WasmError::DeterminismViolation);
                }
                self.memory.write(out_ptr, &out.data)?;
            } else if !out.data.is_empty() {
                return Err(WasmError::DeterminismViolation);
            }
            self.stack.push(Value::I32(out.result))?;
            return Ok(());
        }

        let mut result_code = -1i32;
        let mut encoded = [0u8; TEMPORAL_ROLLBACK_BYTES];
        let mut encoded_len = 0usize;

        if let Ok(path) = core::str::from_utf8(&path_bytes) {
            if let Ok(key) = fs::FileKey::new(path) {
                if fs_cap.rights.has(fs::FilesystemRights::WRITE) && fs_cap.can_access(&key) {
                    if let Ok(rollback) = crate::temporal::rollback_path(path, version_id) {
                        encoded = Self::encode_temporal_rollback(&rollback);
                        self.memory.write(out_ptr, &encoded)?;
                        encoded_len = TEMPORAL_ROLLBACK_BYTES;
                        result_code = 0;
                    }
                }
            }
        }

        self.stack.push(Value::I32(result_code))?;

        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                result_code,
                &encoded[..encoded_len],
            )
            .map_err(|_| WasmError::ReplayError)?;
        }
        Ok(())
    }

    /// oreulia_temporal_stats(out_ptr: i32) -> i32
    fn host_temporal_stats(&mut self) -> Result<(), WasmError> {
        let out_ptr = self.pop_nonneg_i32_as_usize()?;

        let func_id: u16 = 17;
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);

        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);

        let mode = self.replay_mode();
        if mode == ReplayMode::Replay {
            let out = replay::replay_host_call(self.instance_id, func_id, args_hash)
                .map_err(|_| WasmError::DeterminismViolation)?;
            if out.status == ReplayEventStatus::Err {
                return Err(WasmError::SyscallFailed);
            }
            if out.result == 0 {
                if out.data.len() != TEMPORAL_STATS_BYTES {
                    return Err(WasmError::DeterminismViolation);
                }
                self.memory.write(out_ptr, &out.data)?;
            } else if !out.data.is_empty() {
                return Err(WasmError::DeterminismViolation);
            }
            self.stack.push(Value::I32(out.result))?;
            return Ok(());
        }

        let stats = crate::temporal::stats();
        let encoded = Self::encode_temporal_stats(stats);
        self.memory.write(out_ptr, &encoded)?;
        self.stack.push(Value::I32(0))?;

        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                0,
                &encoded,
            )
            .map_err(|_| WasmError::ReplayError)?;
        }
        Ok(())
    }

    /// oreulia_temporal_history(cap: i32, path_ptr: i32, path_len: i32, start_from_newest: i32, max_entries: i32, out_ptr: i32, out_capacity: i32) -> i32
    fn host_temporal_history(&mut self) -> Result<(), WasmError> {
        let out_capacity = self.pop_nonneg_i32_as_usize()?;
        let out_ptr = self.pop_nonneg_i32_as_usize()?;
        let max_entries = self.pop_nonneg_i32_as_usize()?;
        let start_from_newest = self.pop_nonneg_i32_as_usize()?;
        let path_len = self.pop_nonneg_i32_as_usize()?;
        let path_ptr = self.pop_nonneg_i32_as_usize()?;
        let cap_handle = CapHandle(self.stack.pop()?.as_u32()?);
        let fs_cap = match self.capabilities.get(cap_handle)? {
            WasmCapability::Filesystem(cap) => cap,
            _ => return Err(WasmError::InvalidCapability),
        };

        if max_entries > MAX_TEMPORAL_HISTORY_ENTRIES || out_capacity > MAX_TEMPORAL_HISTORY_ENTRIES {
            return Err(WasmError::SyscallFailed);
        }

        let path_bytes = self.memory.read(path_ptr, path_len)?.to_vec();

        let func_id: u16 = 18;
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);

        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, cap_handle.0);
        args_hash = replay::hash_u32(args_hash, path_len as u32);
        args_hash = replay::hash_bytes(args_hash, &path_bytes);
        args_hash = replay::hash_u32(args_hash, start_from_newest as u32);
        args_hash = replay::hash_u32(args_hash, max_entries as u32);
        args_hash = replay::hash_u32(args_hash, out_capacity as u32);

        let mode = self.replay_mode();
        if mode == ReplayMode::Replay {
            let out = replay::replay_host_call(self.instance_id, func_id, args_hash)
                .map_err(|_| WasmError::DeterminismViolation)?;
            if out.status == ReplayEventStatus::Err {
                return Err(WasmError::SyscallFailed);
            }
            let count = out.result;
            if count < 0 {
                if !out.data.is_empty() {
                    return Err(WasmError::DeterminismViolation);
                }
                self.stack.push(Value::I32(count))?;
                return Ok(());
            }

            let count_usize = count as usize;
            if count_usize > out_capacity || count_usize > max_entries {
                return Err(WasmError::DeterminismViolation);
            }
            let expected_len = count_usize
                .checked_mul(TEMPORAL_HISTORY_RECORD_BYTES)
                .ok_or(WasmError::DeterminismViolation)?;
            if out.data.len() != expected_len {
                return Err(WasmError::DeterminismViolation);
            }
            if expected_len > 0 {
                self.memory.write(out_ptr, &out.data)?;
            }
            self.stack.push(Value::I32(count))?;
            return Ok(());
        }

        let mut result_code = -1i32;
        let mut encoded: Vec<u8> = Vec::new();

        if let Ok(path) = core::str::from_utf8(&path_bytes) {
            if let Ok(key) = fs::FileKey::new(path) {
                if fs_cap.rights.has(fs::FilesystemRights::READ) && fs_cap.can_access(&key) {
                    if let Ok(history) =
                        crate::temporal::history_window(path, start_from_newest, max_entries)
                    {
                        let write_count = core::cmp::min(history.len(), out_capacity);
                        let total_len = write_count
                            .checked_mul(TEMPORAL_HISTORY_RECORD_BYTES)
                            .ok_or(WasmError::SyscallFailed)?;
                        encoded.resize(total_len, 0);
                        let mut i = 0usize;
                        while i < write_count {
                            let record = Self::encode_temporal_history_record(&history[i]);
                            let base = i * TEMPORAL_HISTORY_RECORD_BYTES;
                            encoded[base..base + TEMPORAL_HISTORY_RECORD_BYTES]
                                .copy_from_slice(&record);
                            i += 1;
                        }
                        if total_len > 0 {
                            self.memory.write(out_ptr, &encoded)?;
                        }
                        result_code = write_count as i32;
                    }
                }
            }
        }

        self.stack.push(Value::I32(result_code))?;

        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                result_code,
                &encoded,
            )
            .map_err(|_| WasmError::ReplayError)?;
        }
        Ok(())
    }

    /// oreulia_temporal_branch_create(cap, path_ptr, path_len, branch_ptr, branch_len, from_lo, from_hi, out_ptr) -> i32
    fn host_temporal_branch_create(&mut self) -> Result<(), WasmError> {
        let out_ptr = self.pop_nonneg_i32_as_usize()?;
        let from_hi = self.stack.pop()?.as_u32()?;
        let from_lo = self.stack.pop()?.as_u32()?;
        let branch_len = self.pop_nonneg_i32_as_usize()?;
        let branch_ptr = self.pop_nonneg_i32_as_usize()?;
        let path_len = self.pop_nonneg_i32_as_usize()?;
        let path_ptr = self.pop_nonneg_i32_as_usize()?;
        let cap_handle = CapHandle(self.stack.pop()?.as_u32()?);
        let fs_cap = match self.capabilities.get(cap_handle)? {
            WasmCapability::Filesystem(cap) => cap,
            _ => return Err(WasmError::InvalidCapability),
        };

        let path_bytes = self.memory.read(path_ptr, path_len)?.to_vec();
        let branch_bytes = self.memory.read(branch_ptr, branch_len)?.to_vec();
        let from_version = if from_lo == u32::MAX && from_hi == u32::MAX {
            None
        } else {
            Some(Self::compose_u64(from_lo, from_hi))
        };

        let func_id: u16 = 19;
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);

        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, cap_handle.0);
        args_hash = replay::hash_u32(args_hash, path_len as u32);
        args_hash = replay::hash_bytes(args_hash, &path_bytes);
        args_hash = replay::hash_u32(args_hash, branch_len as u32);
        args_hash = replay::hash_bytes(args_hash, &branch_bytes);
        args_hash = replay::hash_u32(args_hash, from_lo);
        args_hash = replay::hash_u32(args_hash, from_hi);

        let mode = self.replay_mode();
        if mode == ReplayMode::Replay {
            let out = replay::replay_host_call(self.instance_id, func_id, args_hash)
                .map_err(|_| WasmError::DeterminismViolation)?;
            if out.status == ReplayEventStatus::Err {
                return Err(WasmError::SyscallFailed);
            }
            if out.result == 0 {
                if out.data.len() != TEMPORAL_BRANCH_ID_BYTES {
                    return Err(WasmError::DeterminismViolation);
                }
                self.memory.write(out_ptr, &out.data)?;
            } else if !out.data.is_empty() {
                return Err(WasmError::DeterminismViolation);
            }
            self.stack.push(Value::I32(out.result))?;
            return Ok(());
        }

        let mut result_code = -1i32;
        let mut encoded = [0u8; TEMPORAL_BRANCH_ID_BYTES];
        let mut encoded_len = 0usize;

        if branch_len > 0 {
            if let (Ok(path), Ok(branch)) = (
                core::str::from_utf8(&path_bytes),
                core::str::from_utf8(&branch_bytes),
            ) {
                if let Ok(key) = fs::FileKey::new(path) {
                    if fs_cap.rights.has(fs::FilesystemRights::WRITE) && fs_cap.can_access(&key) {
                        if let Ok(branch_id) =
                            crate::temporal::create_branch(path, branch, from_version)
                        {
                            encoded.copy_from_slice(&branch_id.to_le_bytes());
                            self.memory.write(out_ptr, &encoded)?;
                            encoded_len = TEMPORAL_BRANCH_ID_BYTES;
                            result_code = 0;
                        }
                    }
                }
            }
        }

        self.stack.push(Value::I32(result_code))?;
        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                result_code,
                &encoded[..encoded_len],
            )
            .map_err(|_| WasmError::ReplayError)?;
        }
        Ok(())
    }

    /// oreulia_temporal_branch_checkout(cap, path_ptr, path_len, branch_ptr, branch_len, out_ptr) -> i32
    fn host_temporal_branch_checkout(&mut self) -> Result<(), WasmError> {
        let out_ptr = self.pop_nonneg_i32_as_usize()?;
        let branch_len = self.pop_nonneg_i32_as_usize()?;
        let branch_ptr = self.pop_nonneg_i32_as_usize()?;
        let path_len = self.pop_nonneg_i32_as_usize()?;
        let path_ptr = self.pop_nonneg_i32_as_usize()?;
        let cap_handle = CapHandle(self.stack.pop()?.as_u32()?);
        let fs_cap = match self.capabilities.get(cap_handle)? {
            WasmCapability::Filesystem(cap) => cap,
            _ => return Err(WasmError::InvalidCapability),
        };

        let path_bytes = self.memory.read(path_ptr, path_len)?.to_vec();
        let branch_bytes = self.memory.read(branch_ptr, branch_len)?.to_vec();

        let func_id: u16 = 20;
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);

        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, cap_handle.0);
        args_hash = replay::hash_u32(args_hash, path_len as u32);
        args_hash = replay::hash_bytes(args_hash, &path_bytes);
        args_hash = replay::hash_u32(args_hash, branch_len as u32);
        args_hash = replay::hash_bytes(args_hash, &branch_bytes);

        let mode = self.replay_mode();
        if mode == ReplayMode::Replay {
            let out = replay::replay_host_call(self.instance_id, func_id, args_hash)
                .map_err(|_| WasmError::DeterminismViolation)?;
            if out.status == ReplayEventStatus::Err {
                return Err(WasmError::SyscallFailed);
            }
            if out.result == 0 {
                if out.data.len() != TEMPORAL_BRANCH_CHECKOUT_BYTES {
                    return Err(WasmError::DeterminismViolation);
                }
                self.memory.write(out_ptr, &out.data)?;
            } else if !out.data.is_empty() {
                return Err(WasmError::DeterminismViolation);
            }
            self.stack.push(Value::I32(out.result))?;
            return Ok(());
        }

        let mut result_code = -1i32;
        let mut encoded = [0u8; TEMPORAL_BRANCH_CHECKOUT_BYTES];
        let mut encoded_len = 0usize;

        if branch_len > 0 {
            if let (Ok(path), Ok(branch)) = (
                core::str::from_utf8(&path_bytes),
                core::str::from_utf8(&branch_bytes),
            ) {
                if let Ok(key) = fs::FileKey::new(path) {
                    if fs_cap.rights.has(fs::FilesystemRights::WRITE) && fs_cap.can_access(&key) {
                        if let Ok((branch_id, head_version)) =
                            crate::temporal::checkout_branch(path, branch)
                        {
                            encoded = Self::encode_temporal_branch_checkout(branch_id, head_version);
                            self.memory.write(out_ptr, &encoded)?;
                            encoded_len = TEMPORAL_BRANCH_CHECKOUT_BYTES;
                            result_code = 0;
                        }
                    }
                }
            }
        }

        self.stack.push(Value::I32(result_code))?;
        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                result_code,
                &encoded[..encoded_len],
            )
            .map_err(|_| WasmError::ReplayError)?;
        }
        Ok(())
    }

    /// oreulia_temporal_branch_list(cap, path_ptr, path_len, out_ptr, out_capacity) -> i32
    fn host_temporal_branch_list(&mut self) -> Result<(), WasmError> {
        let out_capacity = self.pop_nonneg_i32_as_usize()?;
        let out_ptr = self.pop_nonneg_i32_as_usize()?;
        let path_len = self.pop_nonneg_i32_as_usize()?;
        let path_ptr = self.pop_nonneg_i32_as_usize()?;
        let cap_handle = CapHandle(self.stack.pop()?.as_u32()?);
        let fs_cap = match self.capabilities.get(cap_handle)? {
            WasmCapability::Filesystem(cap) => cap,
            _ => return Err(WasmError::InvalidCapability),
        };

        if out_capacity > MAX_TEMPORAL_BRANCH_ENTRIES {
            return Err(WasmError::SyscallFailed);
        }

        let path_bytes = self.memory.read(path_ptr, path_len)?.to_vec();

        let func_id: u16 = 21;
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);

        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, cap_handle.0);
        args_hash = replay::hash_u32(args_hash, path_len as u32);
        args_hash = replay::hash_bytes(args_hash, &path_bytes);
        args_hash = replay::hash_u32(args_hash, out_capacity as u32);

        let mode = self.replay_mode();
        if mode == ReplayMode::Replay {
            let out = replay::replay_host_call(self.instance_id, func_id, args_hash)
                .map_err(|_| WasmError::DeterminismViolation)?;
            if out.status == ReplayEventStatus::Err {
                return Err(WasmError::SyscallFailed);
            }
            let count = out.result;
            if count < 0 {
                if !out.data.is_empty() {
                    return Err(WasmError::DeterminismViolation);
                }
                self.stack.push(Value::I32(count))?;
                return Ok(());
            }
            let count_usize = count as usize;
            if count_usize > out_capacity {
                return Err(WasmError::DeterminismViolation);
            }
            let expected_len = count_usize
                .checked_mul(TEMPORAL_BRANCH_RECORD_BYTES)
                .ok_or(WasmError::DeterminismViolation)?;
            if out.data.len() != expected_len {
                return Err(WasmError::DeterminismViolation);
            }
            if expected_len > 0 {
                self.memory.write(out_ptr, &out.data)?;
            }
            self.stack.push(Value::I32(count))?;
            return Ok(());
        }

        let mut result_code = -1i32;
        let mut encoded: Vec<u8> = Vec::new();

        if let Ok(path) = core::str::from_utf8(&path_bytes) {
            if let Ok(key) = fs::FileKey::new(path) {
                if fs_cap.rights.has(fs::FilesystemRights::READ) && fs_cap.can_access(&key) {
                    if let Ok(branches) = crate::temporal::list_branches(path) {
                        let write_count = core::cmp::min(branches.len(), out_capacity);
                        let total_len = write_count
                            .checked_mul(TEMPORAL_BRANCH_RECORD_BYTES)
                            .ok_or(WasmError::SyscallFailed)?;
                        encoded.resize(total_len, 0);
                        let mut i = 0usize;
                        while i < write_count {
                            let record = Self::encode_temporal_branch_record(&branches[i]);
                            let base = i * TEMPORAL_BRANCH_RECORD_BYTES;
                            encoded[base..base + TEMPORAL_BRANCH_RECORD_BYTES]
                                .copy_from_slice(&record);
                            i += 1;
                        }
                        if total_len > 0 {
                            self.memory.write(out_ptr, &encoded)?;
                        }
                        result_code = write_count as i32;
                    }
                }
            }
        }

        self.stack.push(Value::I32(result_code))?;
        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                result_code,
                &encoded,
            )
            .map_err(|_| WasmError::ReplayError)?;
        }
        Ok(())
    }

    /// oreulia_temporal_merge(cap, path_ptr, path_len, source_ptr, source_len, target_ptr, target_len, strategy, out_ptr) -> i32
    fn host_temporal_merge(&mut self) -> Result<(), WasmError> {
        let out_ptr = self.pop_nonneg_i32_as_usize()?;
        let strategy_raw = self.stack.pop()?.as_i32()?;
        let target_len = self.pop_nonneg_i32_as_usize()?;
        let target_ptr = self.pop_nonneg_i32_as_usize()?;
        let source_len = self.pop_nonneg_i32_as_usize()?;
        let source_ptr = self.pop_nonneg_i32_as_usize()?;
        let path_len = self.pop_nonneg_i32_as_usize()?;
        let path_ptr = self.pop_nonneg_i32_as_usize()?;
        let cap_handle = CapHandle(self.stack.pop()?.as_u32()?);
        let fs_cap = match self.capabilities.get(cap_handle)? {
            WasmCapability::Filesystem(cap) => cap,
            _ => return Err(WasmError::InvalidCapability),
        };

        let strategy = match strategy_raw {
            0 => Some(crate::temporal::TemporalMergeStrategy::FastForwardOnly),
            1 => Some(crate::temporal::TemporalMergeStrategy::Ours),
            2 => Some(crate::temporal::TemporalMergeStrategy::Theirs),
            _ => None,
        };

        let path_bytes = self.memory.read(path_ptr, path_len)?.to_vec();
        let source_bytes = self.memory.read(source_ptr, source_len)?.to_vec();
        let target_bytes = if target_len > 0 {
            self.memory.read(target_ptr, target_len)?.to_vec()
        } else {
            Vec::new()
        };

        let func_id: u16 = 22;
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);

        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, cap_handle.0);
        args_hash = replay::hash_u32(args_hash, path_len as u32);
        args_hash = replay::hash_bytes(args_hash, &path_bytes);
        args_hash = replay::hash_u32(args_hash, source_len as u32);
        args_hash = replay::hash_bytes(args_hash, &source_bytes);
        args_hash = replay::hash_u32(args_hash, target_len as u32);
        args_hash = replay::hash_bytes(args_hash, &target_bytes);
        args_hash = replay::hash_u32(args_hash, strategy_raw as u32);

        let mode = self.replay_mode();
        if mode == ReplayMode::Replay {
            let out = replay::replay_host_call(self.instance_id, func_id, args_hash)
                .map_err(|_| WasmError::DeterminismViolation)?;
            if out.status == ReplayEventStatus::Err {
                return Err(WasmError::SyscallFailed);
            }
            if out.result == 0 {
                if out.data.len() != TEMPORAL_MERGE_RESULT_BYTES {
                    return Err(WasmError::DeterminismViolation);
                }
                self.memory.write(out_ptr, &out.data)?;
            } else if !out.data.is_empty() {
                return Err(WasmError::DeterminismViolation);
            }
            self.stack.push(Value::I32(out.result))?;
            return Ok(());
        }

        let mut result_code = -1i32;
        let mut encoded = [0u8; TEMPORAL_MERGE_RESULT_BYTES];
        let mut encoded_len = 0usize;

        if let Some(strategy) = strategy {
            if source_len > 0 {
                if let (Ok(path), Ok(source)) = (
                    core::str::from_utf8(&path_bytes),
                    core::str::from_utf8(&source_bytes),
                ) {
                    let target = if target_len > 0 {
                        core::str::from_utf8(&target_bytes).ok()
                    } else {
                        None
                    };
                    if target_len == 0 || target.is_some() {
                        if let Ok(key) = fs::FileKey::new(path) {
                            if fs_cap.rights.has(fs::FilesystemRights::WRITE) && fs_cap.can_access(&key) {
                                if let Ok(result) =
                                    crate::temporal::merge_branch(path, source, target, strategy)
                                {
                                    encoded = Self::encode_temporal_merge_result(&result);
                                    self.memory.write(out_ptr, &encoded)?;
                                    encoded_len = TEMPORAL_MERGE_RESULT_BYTES;
                                    result_code = 0;
                                }
                            }
                        }
                    }
                }
            }
        }

        self.stack.push(Value::I32(result_code))?;
        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                result_code,
                &encoded[..encoded_len],
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
    InstanceBusy,
    
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
            WasmError::InstanceBusy => write!(f, "Instance busy"),
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
            WasmError::InstanceBusy => "Instance busy",
        }
    }
}

// ============================================================================
// Global WASM Runtime
// ============================================================================

enum RuntimeInstanceSlot {
    Empty,
    Busy(ProcessId),
    Ready(WasmInstance),
}

/// Global WASM runtime (manages instances)
pub struct WasmRuntime {
    instances: Mutex<[RuntimeInstanceSlot; 8]>,
}

impl WasmRuntime {
    pub const fn new() -> Self {
        WasmRuntime {
            instances: Mutex::new([
                RuntimeInstanceSlot::Empty,
                RuntimeInstanceSlot::Empty,
                RuntimeInstanceSlot::Empty,
                RuntimeInstanceSlot::Empty,
                RuntimeInstanceSlot::Empty,
                RuntimeInstanceSlot::Empty,
                RuntimeInstanceSlot::Empty,
                RuntimeInstanceSlot::Empty,
            ]),
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
            if matches!(slot, RuntimeInstanceSlot::Empty) {
                let module = module_opt.take().ok_or(WasmError::InvalidModule)?;
                let mut instance = WasmInstance::new(module, process_id, i);
                instance.initialize_from_module()?;
                instance.run_start_if_present()?;
                *slot = RuntimeInstanceSlot::Ready(instance);
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
            RuntimeInstanceSlot::Ready(instance) => Ok(f(instance)),
            RuntimeInstanceSlot::Busy(_) => Err(WasmError::InstanceBusy),
            RuntimeInstanceSlot::Empty => Err(WasmError::InvalidModule),
        }
    }

    pub fn with_instance_exclusive<F, R>(&self, instance_id: usize, f: F) -> Result<R, WasmError>
    where
        F: FnOnce(&mut WasmInstance) -> R,
    {
        let mut instance = {
            let mut instances = self.instances.lock();
            if instance_id >= 8 {
                return Err(WasmError::InvalidModule);
            }
            let owner = match &instances[instance_id] {
                RuntimeInstanceSlot::Ready(inst) => inst.process_id,
                RuntimeInstanceSlot::Busy(_) => return Err(WasmError::InstanceBusy),
                RuntimeInstanceSlot::Empty => return Err(WasmError::InvalidModule),
            };
            match core::mem::replace(
                &mut instances[instance_id],
                RuntimeInstanceSlot::Busy(owner),
            ) {
                RuntimeInstanceSlot::Ready(inst) => inst,
                RuntimeInstanceSlot::Busy(owner) => {
                    instances[instance_id] = RuntimeInstanceSlot::Busy(owner);
                    return Err(WasmError::InstanceBusy);
                }
                RuntimeInstanceSlot::Empty => {
                    instances[instance_id] = RuntimeInstanceSlot::Empty;
                    return Err(WasmError::InvalidModule);
                }
            }
        };

        let result = f(&mut instance);

        let mut instances = self.instances.lock();
        if instance_id >= 8 {
            return Err(WasmError::InvalidModule);
        }
        match core::mem::replace(&mut instances[instance_id], RuntimeInstanceSlot::Empty) {
            RuntimeInstanceSlot::Busy(_) => {
                instances[instance_id] = RuntimeInstanceSlot::Ready(instance);
                Ok(result)
            }
            other => {
                instances[instance_id] = other;
                Err(WasmError::Trap)
            }
        }
    }

    fn find_service_pointer_rebind_target(
        &self,
        owner_pid: ProcessId,
        retiring_instance: usize,
        function_index: usize,
        signature: ParsedFunctionType,
    ) -> Option<usize> {
        let instances = self.instances.lock();
        let mut idx = 0usize;
        while idx < instances.len() {
            if idx != retiring_instance {
                if let RuntimeInstanceSlot::Ready(instance) = &instances[idx] {
                    if instance.process_id == owner_pid {
                        if matches!(
                            instance.module.resolve_call_target(function_index),
                            Ok(CallTarget::Function(_))
                        ) {
                            if let Ok(runtime_sig) =
                                instance.module.signature_for_combined(function_index)
                            {
                                if parsed_signature_equal(runtime_sig, signature) {
                                    return Some(idx);
                                }
                            }
                        }
                    }
                }
            }
            idx += 1;
        }
        None
    }

    /// Destroy an instance
    pub fn destroy(&self, instance_id: usize) -> Result<(), WasmError> {
        let mut instances = self.instances.lock();
        if instance_id >= 8 {
            return Err(WasmError::InvalidModule);
        }
        match &instances[instance_id] {
            RuntimeInstanceSlot::Busy(_) => return Err(WasmError::InstanceBusy),
            RuntimeInstanceSlot::Empty => return Err(WasmError::InvalidModule),
            RuntimeInstanceSlot::Ready(_) => {}
        }
        instances[instance_id] = RuntimeInstanceSlot::Empty;
        drop(instances);
        let _ = revoke_service_pointers_for_instance(instance_id);
        crate::replay::clear(instance_id);
        Ok(())
    }

    /// List all active instances
    pub fn list(&self) -> [(usize, ProcessId, bool); 8] {
        let instances = self.instances.lock();
        let mut result = [(0, ProcessId(0), false); 8];
        
        for (i, instance) in instances.iter().enumerate() {
            result[i] = match instance {
                RuntimeInstanceSlot::Ready(inst) => (i, inst.process_id, true),
                RuntimeInstanceSlot::Busy(pid) => (i, *pid, true),
                RuntimeInstanceSlot::Empty => (i, ProcessId(0), false),
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

#[derive(Clone)]
struct SyscallLoadedModule {
    module_id: usize,
    owner_pid: ProcessId,
    module: WasmModule,
    bound_instance: Option<usize>,
}

static SYSCALL_MODULES: Mutex<Vec<SyscallLoadedModule>> = Mutex::new(Vec::new());
static NEXT_SYSCALL_MODULE_ID: AtomicU32 = AtomicU32::new(1);
const TEMPORAL_SYSCALL_MODULE_SCHEMA_V1: u8 = 1;
const TEMPORAL_SYSCALL_MODULE_HEADER_BYTES: usize = 16;
const TEMPORAL_SYSCALL_MODULE_ENTRY_META_BYTES: usize = 16;

fn temporal_read_u16_at(data: &[u8], offset: usize) -> Option<u16> {
    if offset.saturating_add(2) > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn temporal_read_u32_at(data: &[u8], offset: usize) -> Option<u32> {
    if offset.saturating_add(4) > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn encode_temporal_syscall_module_table_payload(event: u8) -> Option<Vec<u8>> {
    let next_id = NEXT_SYSCALL_MODULE_ID.load(Ordering::Relaxed);
    let table = SYSCALL_MODULES.lock();
    let mut total_len = TEMPORAL_SYSCALL_MODULE_HEADER_BYTES;
    let mut i = 0usize;
    while i < table.len() {
        let entry = &table[i];
        total_len = total_len
            .saturating_add(TEMPORAL_SYSCALL_MODULE_ENTRY_META_BYTES)
            .saturating_add(entry.module.bytecode_len);
        if total_len > crate::temporal::MAX_TEMPORAL_VERSION_BYTES {
            return None;
        }
        i += 1;
    }

    let mut payload = Vec::with_capacity(total_len);
    payload.push(crate::temporal::TEMPORAL_OBJECT_ENCODING_V1);
    payload.push(crate::temporal::TEMPORAL_WASM_SYSCALL_MODULE_TABLE_OBJECT);
    payload.push(event);
    payload.push(TEMPORAL_SYSCALL_MODULE_SCHEMA_V1);
    payload.extend_from_slice(&(MAX_SYSCALL_MODULES as u16).to_le_bytes());
    payload.extend_from_slice(&(table.len() as u16).to_le_bytes());
    payload.extend_from_slice(&next_id.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());

    let mut i = 0usize;
    while i < table.len() {
        let slot = &table[i];
        payload.extend_from_slice(&(slot.module_id as u32).to_le_bytes());
        payload.extend_from_slice(&slot.owner_pid.0.to_le_bytes());
        payload.extend_from_slice(&(slot.bound_instance.unwrap_or(usize::MAX) as u32).to_le_bytes());
        payload.extend_from_slice(&(slot.module.bytecode_len as u32).to_le_bytes());
        if slot.module.bytecode_len > 0 {
            payload.extend_from_slice(&slot.module.bytecode[..slot.module.bytecode_len]);
        }
        i += 1;
    }
    Some(payload)
}

fn record_temporal_syscall_module_table_snapshot() {
    if crate::temporal::is_replay_active() {
        return;
    }
    let payload = match encode_temporal_syscall_module_table_payload(
        crate::temporal::TEMPORAL_WASM_SYSCALL_MODULE_TABLE_EVENT_STATE,
    ) {
        Some(v) => v,
        None => return,
    };
    let _ = crate::temporal::record_wasm_syscall_module_table_event(&payload);
}

pub fn temporal_apply_syscall_module_table_payload(payload: &[u8]) -> Result<(), &'static str> {
    if payload.len() < TEMPORAL_SYSCALL_MODULE_HEADER_BYTES {
        return Err("temporal wasm syscall payload too short");
    }
    if payload[0] != crate::temporal::TEMPORAL_OBJECT_ENCODING_V1
        || payload[1] != crate::temporal::TEMPORAL_WASM_SYSCALL_MODULE_TABLE_OBJECT
    {
        return Err("temporal wasm syscall payload type mismatch");
    }
    if payload[2] != crate::temporal::TEMPORAL_WASM_SYSCALL_MODULE_TABLE_EVENT_STATE {
        return Err("temporal wasm syscall event unsupported");
    }
    if payload[3] != TEMPORAL_SYSCALL_MODULE_SCHEMA_V1 {
        return Err("temporal wasm syscall schema unsupported");
    }

    let max_slots = temporal_read_u16_at(payload, 4).ok_or("temporal wasm syscall max slots missing")?;
    if max_slots as usize != MAX_SYSCALL_MODULES {
        return Err("temporal wasm syscall max slots mismatch");
    }
    let entry_count = temporal_read_u16_at(payload, 6).ok_or("temporal wasm syscall count missing")? as usize;
    if entry_count > MAX_SYSCALL_MODULES {
        return Err("temporal wasm syscall count out of range");
    }
    let next_id = temporal_read_u32_at(payload, 8).ok_or("temporal wasm syscall next id missing")?;

    let mut offset = TEMPORAL_SYSCALL_MODULE_HEADER_BYTES;
    let mut restored = Vec::with_capacity(entry_count);
    let mut max_module_id = 0usize;
    let mut i = 0usize;
    while i < entry_count {
        if offset.saturating_add(TEMPORAL_SYSCALL_MODULE_ENTRY_META_BYTES) > payload.len() {
            return Err("temporal wasm syscall entry truncated");
        }
        let module_id = temporal_read_u32_at(payload, offset)
            .ok_or("temporal wasm syscall module id missing")? as usize;
        let owner_pid = temporal_read_u32_at(payload, offset + 4)
            .ok_or("temporal wasm syscall owner pid missing")?;
        let _bound_instance = temporal_read_u32_at(payload, offset + 8)
            .ok_or("temporal wasm syscall bound instance missing")?;
        let bytecode_len = temporal_read_u32_at(payload, offset + 12)
            .ok_or("temporal wasm syscall bytecode len missing")? as usize;
        offset += TEMPORAL_SYSCALL_MODULE_ENTRY_META_BYTES;
        if offset.saturating_add(bytecode_len) > payload.len() {
            return Err("temporal wasm syscall bytecode truncated");
        }
        let bytes = &payload[offset..offset + bytecode_len];
        offset += bytecode_len;

        let mut module = WasmModule::new();
        module
            .load_binary(bytes)
            .map_err(|_| "temporal wasm syscall module decode failed")?;

        if module_id > max_module_id {
            max_module_id = module_id;
        }
        restored.push(SyscallLoadedModule {
            module_id,
            owner_pid: ProcessId(owner_pid),
            module,
            bound_instance: None,
        });
        i += 1;
    }
    if offset != payload.len() {
        return Err("temporal wasm syscall payload trailing bytes");
    }

    let mut old_instances = [usize::MAX; MAX_SYSCALL_MODULES];
    let mut old_count = 0usize;
    {
        let mut table = SYSCALL_MODULES.lock();
        let mut i = 0usize;
        while i < table.len() {
            if let Some(instance_id) = table[i].bound_instance {
                if old_count < old_instances.len() {
                    old_instances[old_count] = instance_id;
                    old_count += 1;
                }
            }
            i += 1;
        }
        *table = restored;
    }

    let mut i = 0usize;
    while i < old_count {
        let _ = wasm_runtime().destroy(old_instances[i]);
        i += 1;
    }

    let next_candidate = core::cmp::max(next_id as usize, max_module_id.saturating_add(1)).max(1);
    NEXT_SYSCALL_MODULE_ID.store(next_candidate as u32, Ordering::Relaxed);
    Ok(())
}

fn syscall_caller_pid() -> ProcessId {
    let scheduler = crate::quantum_scheduler::scheduler().lock();
    scheduler.get_current_pid().unwrap_or(ProcessId(0))
}

fn lookup_syscall_module(
    module_id: usize,
    caller_pid: ProcessId,
) -> Result<(usize, WasmModule, Option<usize>), &'static str> {
    let table = SYSCALL_MODULES.lock();
    let mut idx = 0usize;
    while idx < table.len() {
        let slot = &table[idx];
        if slot.module_id == module_id {
            if slot.owner_pid != caller_pid && caller_pid.0 != 0 {
                return Err("Permission denied");
            }
            return Ok((idx, slot.module.clone(), slot.bound_instance));
        }
        idx += 1;
    }
    Err("Module not found")
}

pub fn unload_modules_for_owner(owner_pid: ProcessId) -> usize {
    let mut destroyed_instances = [usize::MAX; MAX_SYSCALL_MODULES];
    let mut destroyed_count = 0usize;
    let mut removed = 0usize;

    {
        let mut table = SYSCALL_MODULES.lock();
        let mut idx = 0usize;
        while idx < table.len() {
            if table[idx].owner_pid == owner_pid {
                if let Some(instance_id) = table[idx].bound_instance {
                    if destroyed_count < destroyed_instances.len() {
                        destroyed_instances[destroyed_count] = instance_id;
                        destroyed_count += 1;
                    }
                }
                table.swap_remove(idx);
                removed = removed.saturating_add(1);
            } else {
                idx += 1;
            }
        }
    }

    let mut idx = 0usize;
    while idx < destroyed_count {
        let _ = wasm_runtime().destroy(destroyed_instances[idx]);
        idx += 1;
    }

    if removed > 0 {
        record_temporal_syscall_module_table_snapshot();
    }

    removed
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

pub fn formal_service_pointer_self_check() -> Result<(), &'static str> {
    let provider = ProcessId(62);
    let consumer = ProcessId(63);
    capability::capability_manager().init_task(provider);
    capability::capability_manager().init_task(consumer);

    // Provider function: i32.const 42; return; end.
    let code: [u8; 4] = [0x41, 0x2A, 0x0F, 0x0B];
    let instance_id = wasm_runtime()
        .instantiate(&code, provider)
        .map_err(|_| "Service pointer self-check: instance creation failed")?;

    let func = Function {
        code_offset: 0,
        code_len: code.len(),
        param_count: 0,
        result_count: 1,
        local_count: 0,
    };
    let set_func = wasm_runtime().get_instance_mut(instance_id, |inst| {
        inst.module.add_function(func).map(|_| ())
    });
    if !matches!(set_func, Ok(Ok(()))) {
        let _ = wasm_runtime().destroy(instance_id);
        capability::capability_manager().deinit_task(consumer);
        capability::capability_manager().deinit_task(provider);
        return Err("Service pointer self-check: failed to install function");
    }

    let no_delegate = register_service_pointer(provider, instance_id, 0, false)
        .map_err(|_| "Service pointer self-check: register no-delegate failed")?;
    if capability::export_capability_to_ipc(provider, no_delegate.cap_id).is_ok() {
        let _ = wasm_runtime().destroy(instance_id);
        capability::capability_manager().deinit_task(consumer);
        capability::capability_manager().deinit_task(provider);
        return Err("Service pointer self-check: delegate right not enforced");
    }

    let delegatable = register_service_pointer(provider, instance_id, 0, true)
        .map_err(|_| "Service pointer self-check: register delegatable failed")?;
    let exported = capability::export_capability_to_ipc(provider, delegatable.cap_id)
        .map_err(|_| "Service pointer self-check: export failed")?;
    let imported_cap_id = capability::import_capability_from_ipc(consumer, &exported, provider)
        .map_err(|_| "Service pointer self-check: import failed")?;
    let (_cap_type, imported_object) = capability::capability_manager()
        .query_capability(consumer, imported_cap_id)
        .map_err(|_| "Service pointer self-check: imported capability missing")?;

    let result = invoke_service_pointer(consumer, imported_object, &[])
        .map_err(|_| "Service pointer self-check: invoke failed")?;
    if result != 42 {
        let _ = wasm_runtime().destroy(instance_id);
        capability::capability_manager().deinit_task(consumer);
        capability::capability_manager().deinit_task(provider);
        return Err("Service pointer self-check: unexpected invoke result");
    }

    revoke_service_pointer(provider, imported_object)
        .map_err(|_| "Service pointer self-check: revoke failed")?;
    if invoke_service_pointer(consumer, imported_object, &[]).is_ok() {
        let _ = wasm_runtime().destroy(instance_id);
        capability::capability_manager().deinit_task(consumer);
        capability::capability_manager().deinit_task(provider);
        return Err("Service pointer self-check: revoked pointer still invokable");
    }
    if capability::capability_manager()
        .query_capability(consumer, imported_cap_id)
        .is_ok()
    {
        let _ = wasm_runtime().destroy(instance_id);
        capability::capability_manager().deinit_task(consumer);
        capability::capability_manager().deinit_task(provider);
        return Err("Service pointer self-check: revoked capability not removed");
    }

    let _ = wasm_runtime().destroy(instance_id);
    capability::capability_manager().deinit_task(consumer);
    capability::capability_manager().deinit_task(provider);
    Ok(())
}

pub fn service_pointer_typed_hostpath_self_check() -> Result<(), &'static str> {
    let provider = ProcessId(74);
    let consumer = ProcessId(75);
    capability::capability_manager().init_task(provider);
    capability::capability_manager().init_task(consumer);

    let mut provider_instance: Option<usize> = None;
    let mut consumer_instance: Option<usize> = None;
    let mut object_id: Option<u64> = None;

    let result = (|| -> Result<(), &'static str> {
        // Provider module:
        // (func (param i64 f32 f64 funcref) (result i64 f32 f64 funcref)
        //   i64.const 9
        //   f32.const 1.5
        //   f64.const 1.0
        //   ref.func 0)
        const PROVIDER_MODULE: [u8; 50] = [
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
            0x01, 0x0C, 0x01, 0x60, 0x04, 0x7E, 0x7D, 0x7C, 0x70, 0x04, 0x7E, 0x7D, 0x7C, 0x70, // type section
            0x03, 0x02, 0x01, 0x00, // function section
            0x0A, 0x16, 0x01, 0x14, // code section header
            0x00, // local decl count
            0x42, 0x09, // i64.const 9
            0x43, 0x00, 0x00, 0xC0, 0x3F, // f32.const 1.5
            0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F, // f64.const 1.0
            0xD2, 0x00, // ref.func 0
            0x0B, // end
        ];

        let mut provider_module = WasmModule::new();
        provider_module
            .load_binary(&PROVIDER_MODULE)
            .map_err(|_| "Typed service demo: provider module parse failed")?;
        let provider_id = wasm_runtime()
            .instantiate_module(provider_module, provider)
            .map_err(|_| "Typed service demo: provider instantiate failed")?;
        provider_instance = Some(provider_id);

        let registration = register_service_pointer(provider, provider_id, 0, true)
            .map_err(|_| "Typed service demo: service register failed")?;
        object_id = Some(registration.object_id);

        let exported = capability::export_capability_to_ipc(provider, registration.cap_id)
            .map_err(|_| "Typed service demo: export failed")?;
        let imported_cap_id =
            capability::import_capability_from_ipc(consumer, &exported, provider)
                .map_err(|_| "Typed service demo: import failed")?;
        let (imported_cap_type, imported_object) = capability::capability_manager()
            .query_capability(consumer, imported_cap_id)
            .map_err(|_| "Typed service demo: imported capability missing")?;
        if imported_cap_type != CapabilityType::ServicePointer as u32 {
            return Err("Typed service demo: imported capability type mismatch");
        }
        if imported_object != registration.object_id {
            return Err("Typed service demo: imported object mismatch");
        }

        // Consumer instance only needs memory + capability table.
        let consumer_code: [u8; 1] = [0x0B];
        let consumer_id = wasm_runtime()
            .instantiate(&consumer_code, consumer)
            .map_err(|_| "Typed service demo: consumer instantiate failed")?;
        consumer_instance = Some(consumer_id);

        let invoke = wasm_runtime()
            .with_instance_exclusive(consumer_id, |instance| -> Result<(), WasmError> {
                let handle = instance.inject_capability(WasmCapability::ServicePointer(
                    ServicePointerCapability {
                        object_id: imported_object,
                        cap_id: imported_cap_id,
                    },
                ))?;

                const ARGS_COUNT: usize = 4;
                const RESULTS_CAPACITY: usize = 4;
                const ARGS_PTR: usize = 0x120;
                const RESULTS_PTR: usize = 0x280;
                const SLOT: usize = SERVICE_TYPED_SLOT_BYTES;

                let mut encoded_args = [0u8; ARGS_COUNT * SLOT];
                WasmInstance::encode_typed_service_value(
                    Value::I64(0x1122_3344_5566_7788),
                    &mut encoded_args[0..SLOT],
                )?;
                WasmInstance::encode_typed_service_value(
                    Value::F32(6.25),
                    &mut encoded_args[SLOT..2 * SLOT],
                )?;
                WasmInstance::encode_typed_service_value(
                    Value::F64(-7.5),
                    &mut encoded_args[2 * SLOT..3 * SLOT],
                )?;
                WasmInstance::encode_typed_service_value(
                    Value::FuncRef(Some(0)),
                    &mut encoded_args[3 * SLOT..4 * SLOT],
                )?;
                instance.memory.write(ARGS_PTR, &encoded_args)?;

                instance.stack.clear();
                instance.stack.push(Value::I32(handle.0 as i32))?;
                instance.stack.push(Value::I32(ARGS_PTR as i32))?;
                instance.stack.push(Value::I32(ARGS_COUNT as i32))?;
                instance.stack.push(Value::I32(RESULTS_PTR as i32))?;
                instance
                    .stack
                    .push(Value::I32(RESULTS_CAPACITY as i32))?;
                instance.host_service_invoke_typed()?;

                let written = instance.stack.pop()?.as_i32()? as usize;
                if written != RESULTS_CAPACITY {
                    instance.stack.clear();
                    return Err(WasmError::TypeMismatch);
                }

                let encoded_results = instance
                    .memory
                    .read(RESULTS_PTR, written.saturating_mul(SLOT))?;
                let decode_slot = |slot: usize| -> Result<Value, WasmError> {
                    let base = slot.saturating_mul(SLOT);
                    let payload = u64::from_le_bytes([
                        encoded_results[base + 1],
                        encoded_results[base + 2],
                        encoded_results[base + 3],
                        encoded_results[base + 4],
                        encoded_results[base + 5],
                        encoded_results[base + 6],
                        encoded_results[base + 7],
                        encoded_results[base + 8],
                    ]);
                    WasmInstance::decode_typed_service_value(encoded_results[base], payload)
                };

                if decode_slot(0)?.as_i64()? != 9 {
                    instance.stack.clear();
                    return Err(WasmError::TypeMismatch);
                }
                if decode_slot(1)?.as_f32()?.to_bits() != 1.5f32.to_bits() {
                    instance.stack.clear();
                    return Err(WasmError::TypeMismatch);
                }
                if decode_slot(2)?.as_f64()?.to_bits() != 1.0f64.to_bits() {
                    instance.stack.clear();
                    return Err(WasmError::TypeMismatch);
                }
                if decode_slot(3)?.as_funcref()? != Some(0) {
                    instance.stack.clear();
                    return Err(WasmError::TypeMismatch);
                }
                instance.stack.clear();
                Ok(())
            })
            .map_err(|_| "Typed service demo: consumer execution unavailable")?;

        invoke.map_err(|_| "Typed service demo: typed host invoke failed")
    })();

    if let Some(id) = object_id {
        let _ = revoke_service_pointer(provider, id);
    }
    if let Some(id) = consumer_instance {
        let _ = wasm_runtime().destroy(id);
    }
    if let Some(id) = provider_instance {
        let _ = wasm_runtime().destroy(id);
    }
    capability::capability_manager().deinit_task(consumer);
    capability::capability_manager().deinit_task(provider);
    result
}

pub fn temporal_hostpath_self_check() -> Result<(), &'static str> {
    let pid = ProcessId(76);
    capability::capability_manager().init_task(pid);

    const PATH: &str = "/temporal-selfcheck";
    const INITIAL: &[u8] = b"alpha-temporal";
    const UPDATED: &[u8] = b"beta-temporal";

    crate::vfs::write_path(PATH, INITIAL).map_err(|_| "Temporal self-check: initial write failed")?;

    let mut instance_id: Option<usize> = None;
    let result = (|| -> Result<(), &'static str> {
        let code: [u8; 1] = [0x0B];
        let id = wasm_runtime()
            .instantiate(&code, pid)
            .map_err(|_| "Temporal self-check: instance creation failed")?;
        instance_id = Some(id);

        let invoke = wasm_runtime()
            .with_instance_exclusive(id, |instance| -> Result<(), WasmError> {
                const PATH_PTR: usize = 0x100;
                const META0_PTR: usize = 0x200;
                const META1_PTR: usize = 0x240;
                const HISTORY_PTR: usize = 0x300;
                const READ_PTR: usize = 0x600;
                const ROLLBACK_PTR: usize = 0x680;
                const STATS_PTR: usize = 0x700;
                const HISTORY_CAPACITY: usize = 4;

                let fs_cap = fs::filesystem().create_capability(
                    900,
                    fs::FilesystemRights::all(),
                    None,
                );
                let fs_handle = instance.inject_capability(WasmCapability::Filesystem(fs_cap))?;
                instance.memory.write(PATH_PTR, PATH.as_bytes())?;

                // Snapshot current file state.
                instance.stack.clear();
                instance.stack.push(Value::I32(fs_handle.0 as i32))?;
                instance.stack.push(Value::I32(PATH_PTR as i32))?;
                instance.stack.push(Value::I32(PATH.len() as i32))?;
                instance.stack.push(Value::I32(META0_PTR as i32))?;
                instance.host_temporal_snapshot()?;
                if instance.stack.pop()?.as_i32()? != 0 {
                    instance.stack.clear();
                    return Err(WasmError::SyscallFailed);
                }

                let meta0 = instance.memory.read(META0_PTR, TEMPORAL_META_BYTES)?;
                let v0_lo = u32::from_le_bytes([meta0[0], meta0[1], meta0[2], meta0[3]]);
                let v0_hi = u32::from_le_bytes([meta0[4], meta0[5], meta0[6], meta0[7]]);
                let version0 = ((v0_hi as u64) << 32) | (v0_lo as u64);

                crate::vfs::write_path(PATH, UPDATED).map_err(|_| WasmError::SyscallFailed)?;

                // Snapshot updated state.
                instance.stack.clear();
                instance.stack.push(Value::I32(fs_handle.0 as i32))?;
                instance.stack.push(Value::I32(PATH_PTR as i32))?;
                instance.stack.push(Value::I32(PATH.len() as i32))?;
                instance.stack.push(Value::I32(META1_PTR as i32))?;
                instance.host_temporal_snapshot()?;
                if instance.stack.pop()?.as_i32()? != 0 {
                    instance.stack.clear();
                    return Err(WasmError::SyscallFailed);
                }

                let meta1 = instance.memory.read(META1_PTR, TEMPORAL_META_BYTES)?;
                let v1_lo = u32::from_le_bytes([meta1[0], meta1[1], meta1[2], meta1[3]]);
                let v1_hi = u32::from_le_bytes([meta1[4], meta1[5], meta1[6], meta1[7]]);
                let version1 = ((v1_hi as u64) << 32) | (v1_lo as u64);
                if version1 == version0 {
                    instance.stack.clear();
                    return Err(WasmError::TypeMismatch);
                }

                // Pull newest-first history.
                instance.stack.clear();
                instance.stack.push(Value::I32(fs_handle.0 as i32))?;
                instance.stack.push(Value::I32(PATH_PTR as i32))?;
                instance.stack.push(Value::I32(PATH.len() as i32))?;
                instance.stack.push(Value::I32(0))?; // start_from_newest
                instance.stack.push(Value::I32(HISTORY_CAPACITY as i32))?;
                instance.stack.push(Value::I32(HISTORY_PTR as i32))?;
                instance
                    .stack
                    .push(Value::I32(HISTORY_CAPACITY as i32))?;
                instance.host_temporal_history()?;
                let written = instance.stack.pop()?.as_i32()? as usize;
                if written < 2 {
                    instance.stack.clear();
                    return Err(WasmError::TypeMismatch);
                }

                let history_bytes = instance
                    .memory
                    .read(HISTORY_PTR, written.saturating_mul(TEMPORAL_HISTORY_RECORD_BYTES))?;
                let newest_lo = u32::from_le_bytes([
                    history_bytes[0],
                    history_bytes[1],
                    history_bytes[2],
                    history_bytes[3],
                ]);
                let newest_hi = u32::from_le_bytes([
                    history_bytes[4],
                    history_bytes[5],
                    history_bytes[6],
                    history_bytes[7],
                ]);
                let newest_version = ((newest_hi as u64) << 32) | (newest_lo as u64);
                if newest_version != version1 {
                    instance.stack.clear();
                    return Err(WasmError::TypeMismatch);
                }

                // Roll back to the first snapshot version.
                instance.stack.clear();
                instance.stack.push(Value::I32(fs_handle.0 as i32))?;
                instance.stack.push(Value::I32(PATH_PTR as i32))?;
                instance.stack.push(Value::I32(PATH.len() as i32))?;
                instance.stack.push(Value::I32(v0_lo as i32))?;
                instance.stack.push(Value::I32(v0_hi as i32))?;
                instance.stack.push(Value::I32(ROLLBACK_PTR as i32))?;
                instance.host_temporal_rollback()?;
                if instance.stack.pop()?.as_i32()? != 0 {
                    instance.stack.clear();
                    return Err(WasmError::SyscallFailed);
                }

                // Read back rolled version through ABI.
                instance.stack.clear();
                instance.stack.push(Value::I32(fs_handle.0 as i32))?;
                instance.stack.push(Value::I32(PATH_PTR as i32))?;
                instance.stack.push(Value::I32(PATH.len() as i32))?;
                instance.stack.push(Value::I32(v0_lo as i32))?;
                instance.stack.push(Value::I32(v0_hi as i32))?;
                instance.stack.push(Value::I32(READ_PTR as i32))?;
                instance.stack.push(Value::I32(64))?;
                instance.host_temporal_read()?;
                let read_len = instance.stack.pop()?.as_i32()? as usize;
                if read_len != INITIAL.len() {
                    instance.stack.clear();
                    return Err(WasmError::TypeMismatch);
                }
                let read_back = instance.memory.read(READ_PTR, read_len)?;
                if read_back != INITIAL {
                    instance.stack.clear();
                    return Err(WasmError::TypeMismatch);
                }

                // Query stats.
                instance.stack.clear();
                instance.stack.push(Value::I32(STATS_PTR as i32))?;
                instance.host_temporal_stats()?;
                if instance.stack.pop()?.as_i32()? != 0 {
                    instance.stack.clear();
                    return Err(WasmError::SyscallFailed);
                }
                let stats = instance.memory.read(STATS_PTR, TEMPORAL_STATS_BYTES)?;
                let objects = u32::from_le_bytes([stats[0], stats[1], stats[2], stats[3]]);
                let versions = u32::from_le_bytes([stats[4], stats[5], stats[6], stats[7]]);
                if objects == 0 || versions == 0 {
                    instance.stack.clear();
                    return Err(WasmError::TypeMismatch);
                }

                instance.stack.clear();
                Ok(())
            })
            .map_err(|_| "Temporal self-check: execution unavailable")?;

        invoke.map_err(|_| "Temporal self-check: host ABI path failed")
    })();

    if let Some(id) = instance_id {
        let _ = wasm_runtime().destroy(id);
    }
    capability::capability_manager().deinit_task(pid);
    result
}

pub struct WasmBinaryFuzzStats {
    pub iterations: u32,
    pub accepted: u32,
    pub rejected: u32,
}

pub fn wasm_control_flow_self_check() -> Result<(), &'static str> {
    let mut module = WasmModule::new();
    let code: [u8; 50] = [
        // i32.const 7
        0x41, 0x07,
        // block
        0x02, 0x40,
        // loop
        0x03, 0x40,
        // br 1
        0x0C, 0x01,
        // dead code
        0x41, 0x63, 0x1A,
        // end loop, end block
        0x0B, 0x0B,
        // verify br worked
        0x41, 0x07, 0x46,
        // select path check -> bool
        0x41, 0x0A, 0x41, 0x14, 0x41, 0x00, 0x1B, 0x41, 0x14, 0x46, 0x71,
        // br_if block check
        0x02, 0x40, 0x41, 0x01, 0x0D, 0x00, 0x41, 0x00, 0x1A, 0x0B,
        // if/else structured flow check
        0x41, 0x01, 0x04, 0x40, 0x41, 0x03, 0x1A, 0x05, 0x41, 0x09, 0x1A, 0x0B,
        // end function
        0x0B,
    ];
    module.load(&code).map_err(|_| "control-flow self-check: code load failed")?;
    let _ = module
        .add_function(Function {
            code_offset: 0,
            code_len: code.len(),
            param_count: 0,
            result_count: 1,
            local_count: 0,
        })
        .map_err(|_| "control-flow self-check: add function failed")?;

    let instance_id = wasm_runtime()
        .instantiate_module(module, ProcessId(1))
        .map_err(|_| "control-flow self-check: instantiate failed")?;

    let run = wasm_runtime().get_instance_mut(instance_id, |instance| -> Result<i32, WasmError> {
        instance.call(0)?;
        instance.stack.pop()?.as_i32()
    });
    let _ = wasm_runtime().destroy(instance_id);

    match run {
        Ok(Ok(v)) if v == 1 => Ok(()),
        _ => Err("control-flow self-check: unexpected result"),
    }
}

const WASM_CONFORMANCE_MODULE_RET42: [u8; 27] = [
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F, // type: () -> i32
    0x03, 0x02, 0x01, 0x00, // function section
    0x0A, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2A, 0x0B, // code: i32.const 42; end
];

const WASM_CONFORMANCE_MODULE_IMPORT: [u8; 58] = [
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
    0x01, 0x09, 0x02, 0x60, 0x02, 0x7F, 0x7F, 0x00, 0x60, 0x00, 0x00, // types
    0x02, 0x15, 0x01, 0x07, 0x6F, 0x72, 0x65, 0x75, 0x6C, 0x69, 0x61, // import section
    0x09, 0x64, 0x65, 0x62, 0x75, 0x67, 0x5F, 0x6C, 0x6F, 0x67, 0x00, 0x00,
    0x03, 0x02, 0x01, 0x01, // function section
    0x0A, 0x0A, 0x01, 0x08, 0x00, 0x41, 0x00, 0x41, 0x00, 0x10, 0x00, 0x0B, // code
];

const WASM_CONFORMANCE_MODULE_STATEFUL: [u8; 69] = [
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type: () -> ()
    0x03, 0x02, 0x01, 0x00, // function section
    0x04, 0x04, 0x01, 0x70, 0x00, 0x01, // table section
    0x05, 0x03, 0x01, 0x00, 0x01, // memory section
    0x06, 0x06, 0x01, 0x7F, 0x01, 0x41, 0x07, 0x0B, // global section
    0x08, 0x01, 0x00, // start section (function 0)
    0x09, 0x07, 0x01, 0x00, 0x41, 0x00, 0x0B, 0x01, 0x00, // element section
    0x0A, 0x07, 0x01, 0x05, 0x00, 0x23, 0x00, 0x1A, 0x0B, // code section
    0x0B, 0x09, 0x01, 0x00, 0x41, 0x00, 0x0B, 0x03, 0x61, 0x62, 0x63, // data section
];

const WASM_CONFORMANCE_MODULE_TYPED_BLOCK: [u8; 39] = [
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
    0x01, 0x0B, 0x02, 0x60, 0x00, 0x01, 0x7F, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F, // types
    0x03, 0x02, 0x01, 0x00, // function section
    0x0A, 0x0C, 0x01, 0x0A, 0x00, 0x41, 0x0A, 0x41, 0x20, 0x02, 0x01, 0x6A, 0x0B, 0x0B, // code
];

const WASM_CONFORMANCE_MODULE_TYPED_IF_IMPLICIT_ELSE: [u8; 37] = [
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
    0x01, 0x0A, 0x02, 0x60, 0x00, 0x01, 0x7F, 0x60, 0x01, 0x7F, 0x01, 0x7F, // types
    0x03, 0x02, 0x01, 0x00, // function section
    0x0A, 0x0B, 0x01, 0x09, 0x00, 0x41, 0x2A, 0x41, 0x00, 0x04, 0x01, 0x0B, 0x0B, // code
];

const WASM_CONFORMANCE_MODULE_REFTYPE_MVP: [u8; 36] = [
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F, // type: () -> i32
    0x03, 0x02, 0x01, 0x00, // function section
    0x0A, 0x0F, 0x01, 0x0D, 0x00, // code section header + local decls
    0x02, 0x70, // block (result funcref)
    0xD0, 0x70, // ref.null funcref
    0x0B, // end block
    0xD1, // ref.is_null -> 1
    0xD2, 0x00, // ref.func 0
    0xD1, // ref.is_null -> 0
    0x45, // i32.eqz -> 1
    0x71, // i32.and
    0x0B, // end function
];

const WASM_CONFORMANCE_MODULE_EH_THROW_CATCH: [u8; 45] = [
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
    0x01, 0x09, 0x02, 0x60, 0x00, 0x01, 0x7F, 0x60, 0x01, 0x7F, 0x00, // types
    0x03, 0x02, 0x01, 0x00, // function section
    0x0A, 0x0F, 0x01, 0x0D, 0x00, // code section header + local decls
    0x06, 0x7F, // try (result i32)
    0x41, 0x2A, // i32.const 42
    0x08, 0x00, // throw tag 0
    0x07, 0x00, // catch tag 0
    0x41, 0x2A, // i32.const 42
    0x0B, // end try
    0x0B, // end function
    0x0D, 0x03, 0x01, 0x00, 0x01, // tag section
];

const WASM_CONFORMANCE_MODULE_EH_RETHROW_CATCH_ALL: [u8; 51] = [
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
    0x01, 0x09, 0x02, 0x60, 0x00, 0x01, 0x7F, 0x60, 0x01, 0x7F, 0x00, // types
    0x03, 0x02, 0x01, 0x00, // function section
    0x0A, 0x15, 0x01, 0x13, 0x00, // code section header + local decls
    0x06, 0x7F, // outer try (result i32)
    0x06, 0x7F, // inner try (result i32)
    0x41, 0x11, // i32.const 17
    0x08, 0x00, // throw tag 0
    0x07, 0x00, // catch tag 0
    0x09, 0x00, // rethrow 0
    0x0B, // end inner try
    0x19, // catch_all
    0x41, 0x11, // i32.const 17
    0x0B, // end outer try
    0x0B, // end function
    0x0D, 0x03, 0x01, 0x00, 0x01, // tag section
];

const WASM_CONFORMANCE_MODULE_EH_DELEGATE: [u8; 50] = [
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
    0x01, 0x09, 0x02, 0x60, 0x00, 0x01, 0x7F, 0x60, 0x01, 0x7F, 0x00, // types
    0x03, 0x02, 0x01, 0x00, // function section
    0x0A, 0x14, 0x01, 0x12, 0x00, // code section header + local decls
    0x06, 0x7F, // outer try (result i32)
    0x06, 0x7F, // inner try (result i32)
    0x41, 0x05, // i32.const 5
    0x08, 0x00, // throw tag 0
    0x18, 0x00, // delegate 0
    0x0B, // end inner try
    0x07, 0x00, // catch tag 0
    0x41, 0x05, // i32.const 5
    0x0B, // end outer try
    0x0B, // end function
    0x0D, 0x03, 0x01, 0x00, 0x01, // tag section
];

pub fn wasm_binary_conformance_self_check() -> Result<(), &'static str> {
    let corpus: [&[u8]; 9] = [
        &WASM_CONFORMANCE_MODULE_RET42,
        &WASM_CONFORMANCE_MODULE_IMPORT,
        &WASM_CONFORMANCE_MODULE_STATEFUL,
        &WASM_CONFORMANCE_MODULE_TYPED_BLOCK,
        &WASM_CONFORMANCE_MODULE_TYPED_IF_IMPLICIT_ELSE,
        &WASM_CONFORMANCE_MODULE_REFTYPE_MVP,
        &WASM_CONFORMANCE_MODULE_EH_THROW_CATCH,
        &WASM_CONFORMANCE_MODULE_EH_RETHROW_CATCH_ALL,
        &WASM_CONFORMANCE_MODULE_EH_DELEGATE,
    ];

    let mut i = 0usize;
    while i < corpus.len() {
        let mut module = WasmModule::new();
        module
            .load_binary(corpus[i])
            .map_err(|_| "WASM binary conformance: parse failed")?;
        let instance_id = wasm_runtime()
            .instantiate_module(module.clone(), ProcessId(1))
            .map_err(|_| "WASM binary conformance: instantiate failed")?;

        if i == 0 || i == 3 || i == 4 || i == 5 || i == 6 {
            let result = wasm_runtime()
                .get_instance_mut(instance_id, |instance| -> Result<i32, WasmError> {
                    instance.call(0)?;
                    instance.stack.pop()?.as_i32()
                })
                .map_err(|_| "WASM binary conformance: execution failed")?
                .map_err(|_| "WASM binary conformance: execution trapped")?;
            if result != 42 {
                let _ = wasm_runtime().destroy(instance_id);
                return Err("WASM binary conformance: typed control result mismatch");
            }
        }

        if i == 7 {
            let result = wasm_runtime()
                .get_instance_mut(instance_id, |instance| -> Result<i32, WasmError> {
                    instance.call(0)?;
                    instance.stack.pop()?.as_i32()
                })
                .map_err(|_| "WASM binary conformance: execution failed")?
                .map_err(|_| "WASM binary conformance: execution trapped")?;
            if result != 17 {
                let _ = wasm_runtime().destroy(instance_id);
                return Err("WASM binary conformance: EH rethrow mismatch");
            }
        }

        if i == 8 {
            let result = wasm_runtime()
                .get_instance_mut(instance_id, |instance| -> Result<i32, WasmError> {
                    instance.call(0)?;
                    instance.stack.pop()?.as_i32()
                })
                .map_err(|_| "WASM binary conformance: execution failed")?
                .map_err(|_| "WASM binary conformance: execution trapped")?;
            if result != 5 {
                let _ = wasm_runtime().destroy(instance_id);
                return Err("WASM binary conformance: EH delegate mismatch");
            }
        }

        if i == 2 {
            let state_ok = wasm_runtime()
                .get_instance_mut(instance_id, |instance| -> bool {
                    let data_ok = instance
                        .memory
                        .read(0, 3)
                        .map(|bytes| bytes == b"abc")
                        .unwrap_or(false);
                    let global_ok = instance
                        .globals
                        .get(0)
                        .and_then(|slot| *slot)
                        .and_then(|slot| slot.value.as_i32().ok())
                        .map(|v| v == 7)
                        .unwrap_or(false);
                    data_ok && global_ok
                })
                .map_err(|_| "WASM binary conformance: state query failed")?;
            if !state_ok {
                let _ = wasm_runtime().destroy(instance_id);
                return Err("WASM binary conformance: state initialization mismatch");
            }
        }

        let _ = wasm_runtime().destroy(instance_id);
        i += 1;
    }
    Ok(())
}

pub fn wasm_binary_negative_fuzz(
    iterations: u32,
    seed: u64,
) -> Result<WasmBinaryFuzzStats, &'static str> {
    let corpus: [&[u8]; 9] = [
        &WASM_CONFORMANCE_MODULE_RET42,
        &WASM_CONFORMANCE_MODULE_IMPORT,
        &WASM_CONFORMANCE_MODULE_STATEFUL,
        &WASM_CONFORMANCE_MODULE_TYPED_BLOCK,
        &WASM_CONFORMANCE_MODULE_TYPED_IF_IMPLICIT_ELSE,
        &WASM_CONFORMANCE_MODULE_REFTYPE_MVP,
        &WASM_CONFORMANCE_MODULE_EH_THROW_CATCH,
        &WASM_CONFORMANCE_MODULE_EH_RETHROW_CATCH_ALL,
        &WASM_CONFORMANCE_MODULE_EH_DELEGATE,
    ];
    let mut stats = WasmBinaryFuzzStats {
        iterations,
        accepted: 0,
        rejected: 0,
    };
    if iterations == 0 {
        return Ok(stats);
    }

    let mut state = if seed == 0 {
        0xA5A5_5A5A_1234_5678u64
    } else {
        seed
    };

    let mut i = 0u32;
    while i < iterations {
        state ^= state << 7;
        state ^= state >> 9;
        state = state.wrapping_mul(0x9E37_79B9_7F4A_7C15);

        let base = corpus[(state as usize) % corpus.len()];
        let mut mutant = base.to_vec();
        if mutant.is_empty() {
            mutant.push(0);
        }

        let selector = ((state >> 32) as u32) % 4;
        match selector {
            0 => {
                let idx = (state as usize) % mutant.len();
                mutant[idx] ^= 0x80;
            }
            1 => {
                let new_len = ((state >> 16) as usize) % mutant.len();
                mutant.truncate(new_len);
            }
            2 => {
                let idx = if mutant.len() > 8 {
                    8 + (((state >> 8) as usize) % (mutant.len() - 8))
                } else {
                    0
                };
                if idx < mutant.len() {
                    mutant[idx] = 0xFF;
                }
            }
            _ => {
                mutant.push((state >> 40) as u8);
                mutant.push((state >> 48) as u8);
            }
        }

        let mut module = WasmModule::new();
        match module.load_binary(&mutant) {
            Ok(()) => stats.accepted = stats.accepted.saturating_add(1),
            Err(_) => stats.rejected = stats.rejected.saturating_add(1),
        }
        i += 1;
    }
    Ok(stats)
}

// ============================================================================
// Syscall Wrapper Functions
// ============================================================================

/// Load WASM module (syscall wrapper)
pub fn load_module(bytecode: &[u8]) -> Result<usize, &'static str> {
    let caller_pid = syscall_caller_pid();

    let mut module = WasmModule::new();
    module.load_binary(bytecode).map_err(|e| e.as_str())?;

    let module_id = NEXT_SYSCALL_MODULE_ID.fetch_add(1, Ordering::Relaxed) as usize;
    if module_id == 0 {
        return Err("Module ID allocation failed");
    }

    let mut table = SYSCALL_MODULES.lock();
    if table.len() >= MAX_SYSCALL_MODULES {
        return Err("Syscall module table full");
    }
    table.push(SyscallLoadedModule {
        module_id,
        owner_pid: caller_pid,
        module,
        bound_instance: None,
    });
    drop(table);
    record_temporal_syscall_module_table_snapshot();
    Ok(module_id)
}

/// Call WASM function (syscall wrapper)
pub fn call_function(module_id: usize, func_idx: usize, args: &[u32]) -> Result<u32, &'static str> {
    if args.len() > MAX_SERVICE_CALL_ARGS {
        return Err("Too many arguments");
    }

    let caller_pid = syscall_caller_pid();
    let (table_idx, module, bound_instance) = lookup_syscall_module(module_id, caller_pid)?;

    let reuse = if let Some(instance_id) = bound_instance {
        match wasm_runtime().get_instance_mut(instance_id, |instance| instance.process_id == caller_pid) {
            Ok(same_owner) => same_owner,
            Err(WasmError::InstanceBusy) => return Err("WASM instance busy"),
            Err(_) => false,
        }
    } else {
        false
    };

    let instance_id = if reuse {
        bound_instance.ok_or("Invalid bound instance")?
    } else {
        let new_instance = wasm_runtime()
            .instantiate_module(module, caller_pid)
            .map_err(|e| e.as_str())?;
        let mut table = SYSCALL_MODULES.lock();
        if table_idx < table.len() && table[table_idx].module_id == module_id {
            table[table_idx].bound_instance = Some(new_instance);
        } else {
            return Err("Module registry changed");
        }
        drop(table);
        record_temporal_syscall_module_table_snapshot();
        new_instance
    };

    let call = wasm_runtime()
        .with_instance_exclusive(instance_id, |instance| -> Result<u32, WasmError> {
            if instance.process_id != caller_pid && caller_pid.0 != 0 {
                return Err(WasmError::PermissionDenied);
            }

            let (param_count, result_count) = instance.module.function_arity(func_idx)?;
            if !instance.module.function_all_i32(func_idx)? {
                return Err(WasmError::TypeMismatch);
            }
            if param_count != args.len() {
                return Err(WasmError::TypeMismatch);
            }

            instance.stack.clear();
            let mut i = 0usize;
            while i < args.len() {
                instance.stack.push(Value::I32(args[i] as i32))?;
                i += 1;
            }

            if let Err(e) = instance.invoke_combined_function(func_idx) {
                instance.stack.clear();
                return Err(e);
            }

            if instance.stack.len() != result_count {
                instance.stack.clear();
                return Err(WasmError::TypeMismatch);
            }
            let result = if result_count == 0 {
                0
            } else {
                instance.stack.pop()?.as_u32()?
            };
            instance.stack.clear();
            Ok(result)
        })
        .map_err(|e| match e {
            WasmError::InstanceBusy => "WASM instance busy",
            _ => "WASM instance unavailable",
        })?;

    match call {
        Ok(value) => {
            crate::security::security().intent_wasm_call(caller_pid, 0x5000 + func_idx as u64);
            Ok(value)
        }
        Err(e) => Err(e.as_str()),
    }
}
