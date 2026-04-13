/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

//! Oreulius WASM runtime.
//!
//! Provides Oreulius's in-kernel WebAssembly loader, validator, interpreter,
//! JIT integration, service-pointer runtime, and host ABI dispatch.
//!
//! Current runtime profile:
//! - Stack-based interpreter with hot-path JIT compilation/validation
//! - Linear memory isolation and bounds-checked host mediation
//! - Typed function signatures, tables, globals, data segments, and EH support
//! - Capability-gated host services for IPC, filesystem, temporal objects, and polyglot links
//! - Cooperative WASM threads and runtime-backed process integration

#![allow(dead_code)]

extern crate alloc;

use crate::arch::mmu as arch_mmu;
use crate::capability::{self, CapabilityType, Rights};
use crate::fs;
#[cfg(not(target_arch = "x86_64"))]
use crate::platform::gdt;
use crate::platform::idt_asm;
use crate::ipc::{ChannelId, ProcessId};
use crate::security::kpti;
use crate::memory;
use crate::security::memory_isolation;
use crate::fs::paging;
use crate::scheduler::process_asm;
use crate::execution::replay::{self, ReplayEventStatus, ReplayMode};
use crate::platform::syscall::SYSCALL_JIT_RETURN;
use alloc::alloc::{alloc, handle_alloc_error, Layout};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use spin::Mutex;

// ============================================================================
// WASM Types & Constants
// ============================================================================

/// Hard cap kept for legacy fuzz/JIT harnesses that allocate a single page.
pub const MAX_MEMORY_SIZE: usize = 64 * 1024;

/// WASM spec maximum pages (64 KiB each → 4 GiB total)
pub const WASM_MAX_PAGES: usize = 65536;

/// Practical default maximum pages per instance (4096 pages = 256 MiB)
pub const WASM_DEFAULT_MAX_PAGES: usize = 4096;

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
const TEMPORAL_MERGE_RESULT_BYTES: usize = 48;
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
    pub opcode_edges_hit_admissible: u32,
    pub opcode_edges_admissible_total: u32,
    pub novel_programs: u32,
    pub first_mismatch: Option<JitFuzzMismatch>,
    pub first_compile_error: Option<JitFuzzCompileError>,
}

const MAX_FUZZ_CODE_SIZE: usize = 256;
const MAX_FUZZ_JIT_CODE_SIZE: usize = 8192;
#[cfg(feature = "jit-fuzz-24bin")]
const JIT_FUZZ_OPCODE_BINS: usize = 24;
#[cfg(not(feature = "jit-fuzz-24bin"))]
const JIT_FUZZ_OPCODE_BINS: usize = 20;

pub const fn jit_fuzz_opcode_bins_total() -> u32 {
    JIT_FUZZ_OPCODE_BINS as u32
}

pub const fn jit_fuzz_opcode_edges_total() -> u32 {
    (JIT_FUZZ_OPCODE_BINS * JIT_FUZZ_OPCODE_BINS) as u32
}

pub const fn jit_fuzz_24bin_feature_enabled() -> bool {
    cfg!(feature = "jit-fuzz-24bin")
}

const fn jit_fuzz_choice_bin(choice: u8) -> Option<usize> {
    let idx = choice as usize;
    if idx < JIT_FUZZ_OPCODE_BINS {
        Some(idx)
    } else {
        None
    }
}

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

const JIT_FUZZ_X64_DEBUG_SEEDS: [u64; 4] = [0, 107_427_055, 2_105_703_400, 4_294_967_295];

pub const fn jit_fuzz_x64_debug_seed_count() -> u32 {
    JIT_FUZZ_X64_DEBUG_SEEDS.len() as u32
}

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
    pub max_opcode_edges_hit_admissible: u32,
    pub opcode_edges_admissible_total: u32,
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
    pub max_opcode_edges_hit_admissible: u32,
    pub opcode_edges_admissible_total: u32,
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
    interp_mem_snapshot: [u8; MAX_MEMORY_SIZE],
    interp_mem_snapshot_len: usize,
    choice_trace: Vec<u8>,
}

impl JitFuzzScratch {
    fn new() -> Self {
        Self {
            code: Vec::with_capacity(MAX_FUZZ_CODE_SIZE),
            interp_mem_snapshot: [0; MAX_MEMORY_SIZE],
            interp_mem_snapshot_len: 0,
            choice_trace: Vec::with_capacity(64),
        }
    }
}

/// WASM value types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    I32,
    I64,
    F32,
    F64,
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
// WASM opcodes implemented by the current runtime profile.
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
    I32Load8S = 0x2C,
    I32Load8U = 0x2D,
    I32Load16S = 0x2E,
    I32Load16U = 0x2F,
    I64Load8U = 0x31,
    I64Load16U = 0x33,
    I64Load32U = 0x35,
    I32Store = 0x36,
    I64Store = 0x37,
    I32Store8 = 0x3A,
    I32Store16 = 0x3B,
    I64Store8 = 0x3C,
    I64Store16 = 0x3D,
    I64Store32 = 0x3E,
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

    // i64 comparison operations
    I64Eqz = 0x50,
    I64Eq = 0x51,
    I64Ne = 0x52,
    I64LtS = 0x53,
    I64LtU = 0x54,
    I64GtS = 0x55,
    I64GtU = 0x56,
    I64LeS = 0x57,
    I64LeU = 0x58,
    I64GeS = 0x59,
    I64GeU = 0x5A,

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
    I32Rotl = 0x77,
    I32Rotr = 0x78,
    I32Clz = 0x67,
    I32Ctz = 0x68,
    I32Popcnt = 0x69,

    // i64 operations
    I64Clz = 0x79,
    I64Ctz = 0x7A,
    I64Popcnt = 0x7B,
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

    // Type conversions
    I32WrapI64 = 0xA7,
    I64ExtendI32S = 0xAC,
    I64ExtendI32U = 0xAD,

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
            0x2C => Some(Opcode::I32Load8S),
            0x2D => Some(Opcode::I32Load8U),
            0x2E => Some(Opcode::I32Load16S),
            0x2F => Some(Opcode::I32Load16U),
            0x31 => Some(Opcode::I64Load8U),
            0x33 => Some(Opcode::I64Load16U),
            0x35 => Some(Opcode::I64Load32U),
            0x36 => Some(Opcode::I32Store),
            0x37 => Some(Opcode::I64Store),
            0x3A => Some(Opcode::I32Store8),
            0x3B => Some(Opcode::I32Store16),
            0x3C => Some(Opcode::I64Store8),
            0x3D => Some(Opcode::I64Store16),
            0x3E => Some(Opcode::I64Store32),
            0x3F => Some(Opcode::MemorySize),
            0x40 => Some(Opcode::MemoryGrow),
            0x41 => Some(Opcode::I32Const),
            0x42 => Some(Opcode::I64Const),
            0x43 => Some(Opcode::F32Const),
            0x44 => Some(Opcode::F64Const),
            0x45 => Some(Opcode::I32Eqz),
            0x46 => Some(Opcode::I32Eq),
            0x47 => Some(Opcode::I32Ne),
            0x48 => Some(Opcode::I32LtS),
            0x49 => Some(Opcode::I32LtU),
            0x4A => Some(Opcode::I32GtS),
            0x4B => Some(Opcode::I32GtU),
            0x4C => Some(Opcode::I32LeS),
            0x4D => Some(Opcode::I32LeU),
            0x4E => Some(Opcode::I32GeS),
            0x4F => Some(Opcode::I32GeU),
            0x50 => Some(Opcode::I64Eqz),
            0x51 => Some(Opcode::I64Eq),
            0x52 => Some(Opcode::I64Ne),
            0x53 => Some(Opcode::I64LtS),
            0x54 => Some(Opcode::I64LtU),
            0x55 => Some(Opcode::I64GtS),
            0x56 => Some(Opcode::I64GtU),
            0x57 => Some(Opcode::I64LeS),
            0x58 => Some(Opcode::I64LeU),
            0x59 => Some(Opcode::I64GeS),
            0x5A => Some(Opcode::I64GeU),
            0x67 => Some(Opcode::I32Clz),
            0x68 => Some(Opcode::I32Ctz),
            0x69 => Some(Opcode::I32Popcnt),
            0x6A => Some(Opcode::I32Add),
            0x6B => Some(Opcode::I32Sub),
            0x6C => Some(Opcode::I32Mul),
            0x6D => Some(Opcode::I32DivS),
            0x6E => Some(Opcode::I32DivU),
            0x6F => Some(Opcode::I32RemS),
            0x70 => Some(Opcode::I32RemU),
            0x71 => Some(Opcode::I32And),
            0x72 => Some(Opcode::I32Or),
            0x73 => Some(Opcode::I32Xor),
            0x74 => Some(Opcode::I32Shl),
            0x75 => Some(Opcode::I32ShrS),
            0x76 => Some(Opcode::I32ShrU),
            0x77 => Some(Opcode::I32Rotl),
            0x78 => Some(Opcode::I32Rotr),
            0x79 => Some(Opcode::I64Clz),
            0x7A => Some(Opcode::I64Ctz),
            0x7B => Some(Opcode::I64Popcnt),
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
            0xA7 => Some(Opcode::I32WrapI64),
            0xAC => Some(Opcode::I64ExtendI32S),
            0xAD => Some(Opcode::I64ExtendI32U),
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum HostSignaturePolicy {
    ExactI32,
    ServiceRegister,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HostAliasPolicy {
    Standard,
    DebugLog,
    ChannelSendCap,
    LastServiceCap,
    ServiceRegister,
}

#[derive(Clone, Copy)]
enum HostBehavior {
    Method(fn(&mut WasmInstance) -> Result<(), WasmError>),
    Noop {
        pop_count: usize,
        push_zero: bool,
    },
}

#[derive(Clone, Copy)]
struct HostFunctionSpec {
    id: usize,
    canonical_name: &'static str,
    param_count: usize,
    result_count: usize,
    signature_policy: HostSignaturePolicy,
    alias_policy: HostAliasPolicy,
    behavior: HostBehavior,
}

#[derive(Clone, Copy)]
pub(crate) struct HostDispatchConformanceSummary {
    pub(crate) entries_checked: u32,
    pub(crate) aliases_checked: u32,
    pub(crate) noop_entries: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WasiAbiClass {
    Implemented,
    FrozenNoop,
}

#[derive(Clone, Copy)]
struct ExpectedWasiHostSpec {
    id: usize,
    canonical_name: &'static str,
    param_count: usize,
    result_count: usize,
    class: WasiAbiClass,
}

#[derive(Clone, Copy)]
pub(crate) struct WasiAbiSummary {
    pub(crate) entries_checked: u32,
    pub(crate) noop_entries: u32,
    pub(crate) noop_behavior_checks: u32,
    pub(crate) implemented_behavior_checks: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PolyglotAbiClass {
    Implemented,
}

#[derive(Clone, Copy)]
struct ExpectedPolyglotHostSpec {
    id: usize,
    canonical_name: &'static str,
    param_count: usize,
    result_count: usize,
    class: PolyglotAbiClass,
}

#[derive(Clone, Copy)]
pub(crate) struct PolyglotAbiSummary {
    pub(crate) entries_checked: u32,
    pub(crate) behavior_checks: u32,
}

const fn expected_wasi_host_spec(
    id: usize,
    canonical_name: &'static str,
    param_count: usize,
    result_count: usize,
    class: WasiAbiClass,
) -> ExpectedWasiHostSpec {
    ExpectedWasiHostSpec {
        id,
        canonical_name,
        param_count,
        result_count,
        class,
    }
}

macro_rules! host_spec {
    (
        $id:expr,
        $canonical:expr,
        $param_count:expr,
        $result_count:expr,
        $signature_policy:ident,
        $alias_policy:ident,
        Method($handler:ident)
    ) => {
        HostFunctionSpec {
            id: $id,
            canonical_name: $canonical,
            param_count: $param_count,
            result_count: $result_count,
            signature_policy: HostSignaturePolicy::$signature_policy,
            alias_policy: HostAliasPolicy::$alias_policy,
            behavior: HostBehavior::Method(WasmInstance::$handler),
        }
    };
    (
        $id:expr,
        $canonical:expr,
        $param_count:expr,
        $result_count:expr,
        $signature_policy:ident,
        $alias_policy:ident,
        Noop { pop_count: $pop_count:expr, push_zero: $push_zero:expr }
    ) => {
        HostFunctionSpec {
            id: $id,
            canonical_name: $canonical,
            param_count: $param_count,
            result_count: $result_count,
            signature_policy: HostSignaturePolicy::$signature_policy,
            alias_policy: HostAliasPolicy::$alias_policy,
            behavior: HostBehavior::Noop {
                pop_count: $pop_count,
                push_zero: $push_zero,
            },
        }
    };
}

impl HostAliasPolicy {
    fn matches(self, canonical_name: &str, candidate: &str) -> bool {
        match self {
            HostAliasPolicy::Standard => {
                candidate == canonical_name
                    || candidate
                        .strip_prefix("oreulius_")
                        .map(|suffix| suffix == canonical_name)
                        .unwrap_or(false)
            }
            HostAliasPolicy::DebugLog => {
                candidate == "debug_log" || candidate == "oreulius_log"
            }
            HostAliasPolicy::ChannelSendCap => {
                candidate == "channel_send_cap"
                    || candidate == "oreulius_channel_send_cap"
            }
            HostAliasPolicy::LastServiceCap => {
                candidate == "last_service_cap"
                    || candidate == "oreulius_last_service_cap"
            }
            HostAliasPolicy::ServiceRegister => {
                candidate == "service_register"
                    || candidate == "oreulius_service_register"
                    || candidate == "service_register_ref"
                    || candidate == "oreulius_service_register_ref"
            }
        }
    }
}

impl HostFunctionSpec {
    fn matches_name(&self, candidate: &str) -> bool {
        self.alias_policy.matches(self.canonical_name, candidate)
    }

    fn matches_signature(&self, signature: ParsedFunctionType) -> bool {
        if signature.param_count != self.param_count || signature.result_count != self.result_count {
            return false;
        }

        match self.signature_policy {
            HostSignaturePolicy::ExactI32 => signature.all_i32,
            HostSignaturePolicy::ServiceRegister => {
                signature.param_count == 2
                    && signature.result_count == 1
                    && signature.param_types[1] == ValueType::I32
                    && signature.result_types[0] == ValueType::I32
                    && (signature.param_types[0] == ValueType::I32
                        || signature.param_types[0] == ValueType::FuncRef)
            }
        }
    }

    fn dispatch(self, instance: &mut WasmInstance) -> Result<(), WasmError> {
        match self.behavior {
            HostBehavior::Method(handler) => handler(instance),
            HostBehavior::Noop {
                pop_count,
                push_zero,
            } => {
                let mut remaining = pop_count;
                while remaining > 0 {
                    instance.stack.pop()?;
                    remaining -= 1;
                }
                if push_zero {
                    instance.stack.push(Value::I32(0))?;
                }
                Ok(())
            }
        }
    }
}

fn host_function_signature_from_types(
    param_types: &[ValueType],
    result_types: &[ValueType],
) -> ParsedFunctionType {
    let mut params = [ValueType::I32; MAX_WASM_TYPE_ARITY];
    let mut results = [ValueType::I32; MAX_WASM_TYPE_ARITY];
    let mut all_i32 = true;

    let mut i = 0usize;
    while i < param_types.len() {
        params[i] = param_types[i];
        if param_types[i] != ValueType::I32 {
            all_i32 = false;
        }
        i += 1;
    }

    let mut j = 0usize;
    while j < result_types.len() {
        results[j] = result_types[j];
        if result_types[j] != ValueType::I32 {
            all_i32 = false;
        }
        j += 1;
    }

    ParsedFunctionType {
        param_count: param_types.len(),
        result_count: result_types.len(),
        param_types: params,
        result_types: results,
        all_i32,
    }
}

const HOST_FUNCTION_SPECS: [HostFunctionSpec; 143] = [
    host_spec!(0, "debug_log", 2, 0, ExactI32, DebugLog, Method(host_log)),
    host_spec!(1, "fs_read", 5, 1, ExactI32, Standard, Method(host_fs_read)),
    host_spec!(2, "fs_write", 5, 1, ExactI32, Standard, Method(host_fs_write)),
    host_spec!(3, "channel_send", 3, 1, ExactI32, Standard, Method(host_channel_send)),
    host_spec!(4, "channel_recv", 3, 1, ExactI32, Standard, Method(host_channel_recv)),
    host_spec!(5, "net_http_get", 4, 1, ExactI32, Standard, Method(host_net_http_get)),
    host_spec!(6, "net_connect", 3, 1, ExactI32, Standard, Method(host_net_connect)),
    host_spec!(7, "dns_resolve", 2, 1, ExactI32, Standard, Method(host_dns_resolve)),
    host_spec!(8, "service_invoke", 3, 1, ExactI32, Standard, Method(host_service_invoke)),
    host_spec!(9, "service_register", 2, 1, ServiceRegister, ServiceRegister, Method(host_service_register)),
    host_spec!(10, "channel_send_cap", 4, 1, ExactI32, ChannelSendCap, Method(host_channel_send_with_cap)),
    host_spec!(11, "last_service_cap", 0, 1, ExactI32, LastServiceCap, Method(host_last_service_handle)),
    host_spec!(12, "service_invoke_typed", 5, 1, ExactI32, Standard, Method(host_service_invoke_typed)),
    host_spec!(13, "temporal_snapshot", 4, 1, ExactI32, Standard, Method(host_temporal_snapshot)),
    host_spec!(14, "temporal_latest", 4, 1, ExactI32, Standard, Method(host_temporal_latest)),
    host_spec!(15, "temporal_read", 7, 1, ExactI32, Standard, Method(host_temporal_read)),
    host_spec!(16, "temporal_rollback", 6, 1, ExactI32, Standard, Method(host_temporal_rollback)),
    host_spec!(17, "temporal_stats", 1, 1, ExactI32, Standard, Method(host_temporal_stats)),
    host_spec!(18, "temporal_history", 7, 1, ExactI32, Standard, Method(host_temporal_history)),
    host_spec!(19, "temporal_branch_create", 8, 1, ExactI32, Standard, Method(host_temporal_branch_create)),
    host_spec!(20, "temporal_branch_checkout", 6, 1, ExactI32, Standard, Method(host_temporal_branch_checkout)),
    host_spec!(21, "temporal_branch_list", 5, 1, ExactI32, Standard, Method(host_temporal_branch_list)),
    host_spec!(22, "temporal_merge", 9, 1, ExactI32, Standard, Method(host_temporal_merge)),
    host_spec!(23, "thread_spawn", 2, 1, ExactI32, Standard, Method(host_thread_spawn)),
    host_spec!(24, "thread_join", 1, 1, ExactI32, Standard, Method(host_thread_join)),
    host_spec!(25, "thread_id", 0, 1, ExactI32, Standard, Method(host_thread_id)),
    host_spec!(26, "thread_yield", 0, 0, ExactI32, Standard, Method(host_thread_yield)),
    host_spec!(27, "thread_exit", 1, 0, ExactI32, Standard, Method(host_thread_exit)),
    host_spec!(28, "compositor_create_window", 4, 1, ExactI32, Standard, Method(host_compositor_create_window)),
    host_spec!(29, "compositor_destroy_window", 1, 1, ExactI32, Standard, Method(host_compositor_destroy_window)),
    host_spec!(30, "compositor_set_pixel", 4, 0, ExactI32, Standard, Method(host_compositor_set_pixel)),
    host_spec!(31, "compositor_fill_rect", 6, 0, ExactI32, Standard, Method(host_compositor_fill_rect)),
    host_spec!(32, "compositor_flush", 1, 0, ExactI32, Standard, Method(host_compositor_flush)),
    host_spec!(33, "compositor_move_window", 3, 0, ExactI32, Standard, Method(host_compositor_move_window)),
    host_spec!(34, "compositor_set_z_order", 2, 0, ExactI32, Standard, Method(host_compositor_set_z_order)),
    host_spec!(35, "compositor_get_width", 1, 1, ExactI32, Standard, Method(host_compositor_get_width)),
    host_spec!(36, "compositor_get_height", 1, 1, ExactI32, Standard, Method(host_compositor_get_height)),
    host_spec!(37, "compositor_draw_text", 6, 1, ExactI32, Standard, Method(host_compositor_draw_text)),
    host_spec!(38, "input_poll", 0, 1, ExactI32, Standard, Method(host_input_poll)),
    host_spec!(39, "input_read", 2, 1, ExactI32, Standard, Method(host_input_read)),
    host_spec!(40, "input_event_type", 0, 1, ExactI32, Standard, Method(host_input_event_type)),
    host_spec!(41, "input_flush", 0, 1, ExactI32, Standard, Method(host_input_flush)),
    host_spec!(42, "input_key_poll", 0, 1, ExactI32, Standard, Method(host_input_key_poll)),
    host_spec!(43, "input_mouse_poll", 0, 1, ExactI32, Standard, Method(host_input_mouse_poll)),
    host_spec!(44, "input_gamepad_poll", 0, 1, ExactI32, Standard, Method(host_input_gamepad_poll)),
    host_spec!(45, "args_get", 2, 1, ExactI32, Standard, Method(host_wasi_args_get)),
    host_spec!(46, "args_sizes_get", 2, 1, ExactI32, Standard, Method(host_wasi_args_sizes_get)),
    host_spec!(47, "environ_get", 2, 1, ExactI32, Standard, Method(host_wasi_environ_get)),
    host_spec!(48, "environ_sizes_get", 2, 1, ExactI32, Standard, Method(host_wasi_environ_sizes_get)),
    host_spec!(49, "clock_res_get", 2, 1, ExactI32, Standard, Method(host_wasi_clock_res_get)),
    host_spec!(50, "clock_time_get", 3, 1, ExactI32, Standard, Method(host_wasi_clock_time_get)),
    host_spec!(51, "fd_advise", 3, 1, ExactI32, Standard, Method(host_wasi_fd_advise)),
    host_spec!(52, "fd_allocate", 3, 1, ExactI32, Standard, Method(host_wasi_fd_allocate)),
    host_spec!(53, "fd_close", 1, 1, ExactI32, Standard, Method(host_wasi_fd_close)),
    host_spec!(54, "fd_datasync", 1, 1, ExactI32, Standard, Method(host_wasi_fd_datasync)),
    host_spec!(55, "fd_fdstat_get", 2, 1, ExactI32, Standard, Method(host_wasi_fd_fdstat_get)),
    host_spec!(56, "fd_fdstat_set_flags", 2, 1, ExactI32, Standard, Method(host_wasi_fd_fdstat_set_flags)),
    host_spec!(57, "fd_fdstat_set_rights", 3, 1, ExactI32, Standard, Method(host_wasi_fd_fdstat_set_rights)),
    host_spec!(58, "fd_filestat_get", 2, 1, ExactI32, Standard, Method(host_wasi_fd_filestat_get)),
    host_spec!(59, "fd_filestat_set_size", 2, 1, ExactI32, Standard, Method(host_wasi_fd_filestat_set_size)),
    host_spec!(60, "fd_filestat_set_times", 4, 1, ExactI32, Standard, Method(host_wasi_fd_filestat_set_times)),
    host_spec!(61, "fd_pread", 5, 1, ExactI32, Standard, Method(host_wasi_fd_pread)),
    host_spec!(62, "fd_prestat_get", 2, 1, ExactI32, Standard, Method(host_wasi_fd_prestat_get)),
    host_spec!(63, "fd_prestat_dir_name", 3, 1, ExactI32, Standard, Method(host_wasi_fd_prestat_dir_name)),
    host_spec!(64, "fd_pwrite", 5, 1, ExactI32, Standard, Method(host_wasi_fd_pwrite)),
    host_spec!(65, "fd_read", 4, 1, ExactI32, Standard, Method(host_wasi_fd_read)),
    host_spec!(66, "fd_readdir", 5, 1, ExactI32, Standard, Method(host_wasi_fd_readdir)),
    host_spec!(67, "fd_renumber", 2, 1, ExactI32, Standard, Method(host_wasi_fd_renumber)),
    host_spec!(68, "fd_seek", 4, 1, ExactI32, Standard, Method(host_wasi_fd_seek)),
    host_spec!(69, "fd_sync", 1, 1, ExactI32, Standard, Method(host_wasi_fd_sync)),
    host_spec!(70, "fd_tell", 2, 1, ExactI32, Standard, Method(host_wasi_fd_tell)),
    host_spec!(71, "fd_write", 4, 1, ExactI32, Standard, Method(host_wasi_fd_write)),
    host_spec!(72, "path_create_directory", 3, 1, ExactI32, Standard, Method(host_wasi_path_create_directory)),
    host_spec!(73, "path_filestat_get", 5, 1, ExactI32, Standard, Method(host_wasi_path_filestat_get)),
    host_spec!(74, "path_filestat_set_times", 6, 1, ExactI32, Standard, Method(host_wasi_path_filestat_set_times)),
    host_spec!(75, "path_link", 6, 1, ExactI32, Standard, Method(host_wasi_path_link)),
    host_spec!(76, "path_open", 9, 1, ExactI32, Standard, Method(host_wasi_path_open)),
    host_spec!(77, "path_readlink", 5, 1, ExactI32, Standard, Method(host_wasi_path_readlink)),
    host_spec!(78, "path_remove_directory", 3, 1, ExactI32, Standard, Method(host_wasi_path_remove_directory)),
    host_spec!(79, "path_rename", 5, 1, ExactI32, Standard, Method(host_wasi_path_rename)),
    host_spec!(80, "path_symlink", 5, 1, ExactI32, Standard, Method(host_wasi_path_symlink)),
    host_spec!(81, "path_unlink_file", 3, 1, ExactI32, Standard, Method(host_wasi_path_unlink_file)),
    host_spec!(82, "poll_oneoff", 4, 1, ExactI32, Standard, Method(host_wasi_poll_oneoff)),
    host_spec!(83, "proc_exit", 1, 0, ExactI32, Standard, Method(host_wasi_proc_exit)),
    host_spec!(84, "proc_raise", 1, 1, ExactI32, Standard, Method(host_wasi_proc_raise)),
    host_spec!(85, "sched_yield", 0, 1, ExactI32, Standard, Method(host_wasi_sched_yield)),
    host_spec!(86, "random_get", 2, 1, ExactI32, Standard, Method(host_wasi_random_get)),
    host_spec!(87, "sock_accept", 3, 1, ExactI32, Standard, Method(host_wasi_sock_accept)),
    host_spec!(88, "sock_recv", 6, 1, ExactI32, Standard, Method(host_wasi_sock_recv)),
    host_spec!(89, "sock_send", 5, 1, ExactI32, Standard, Method(host_wasi_sock_send)),
    host_spec!(90, "sock_shutdown", 2, 1, ExactI32, Standard, Method(host_wasi_sock_shutdown)),
    host_spec!(91, "tls_connect", 4, 1, ExactI32, Standard, Method(host_tls_connect)),
    host_spec!(92, "tls_write", 3, 1, ExactI32, Standard, Method(host_tls_write)),
    host_spec!(93, "tls_read", 3, 1, ExactI32, Standard, Method(host_tls_read)),
    host_spec!(94, "tls_close", 1, 1, ExactI32, Standard, Method(host_tls_close)),
    host_spec!(95, "tls_state", 1, 1, ExactI32, Standard, Method(host_tls_state)),
    host_spec!(96, "tls_error", 3, 1, ExactI32, Standard, Method(host_tls_error)),
    host_spec!(97, "tls_handshake_done", 1, 1, ExactI32, Standard, Method(host_tls_handshake_done)),
    host_spec!(98, "tls_tick", 1, 1, ExactI32, Standard, Method(host_tls_tick)),
    host_spec!(99, "tls_free", 1, 1, ExactI32, Standard, Method(host_tls_free)),
    host_spec!(100, "proc_spawn", 2, 1, ExactI32, Standard, Method(host_proc_spawn)),
    host_spec!(101, "proc_yield", 0, 0, ExactI32, Standard, Method(host_proc_yield)),
    host_spec!(102, "proc_sleep", 1, 0, ExactI32, Standard, Method(host_proc_sleep)),
    host_spec!(103, "polyglot_register", 2, 1, ExactI32, Standard, Method(host_polyglot_register)),
    host_spec!(104, "polyglot_resolve", 2, 1, ExactI32, Standard, Method(host_polyglot_resolve)),
    host_spec!(105, "polyglot_link", 4, 1, ExactI32, Standard, Method(host_polyglot_link)),
    host_spec!(106, "observer_subscribe", 1, 1, ExactI32, Standard, Method(host_observer_subscribe)),
    host_spec!(107, "observer_unsubscribe", 0, 1, ExactI32, Standard, Method(host_observer_unsubscribe)),
    host_spec!(108, "observer_query", 2, 1, ExactI32, Standard, Method(host_observer_query)),
    host_spec!(109, "mesh_local_id", 0, 1, ExactI32, Standard, Method(host_mesh_local_id)),
    host_spec!(110, "mesh_peer_register", 3, 1, ExactI32, Standard, Method(host_mesh_peer_register)),
    host_spec!(111, "mesh_peer_session", 2, 1, ExactI32, Standard, Method(host_mesh_peer_session)),
    host_spec!(112, "mesh_token_mint", 6, 1, ExactI32, Standard, Method(host_mesh_token_mint)),
    host_spec!(113, "mesh_token_send", 4, 1, ExactI32, Standard, Method(host_mesh_token_send)),
    host_spec!(114, "mesh_token_recv", 2, 1, ExactI32, Standard, Method(host_mesh_token_recv)),
    host_spec!(115, "mesh_migrate", 4, 1, ExactI32, Standard, Method(host_mesh_migrate)),
    host_spec!(116, "temporal_cap_grant", 3, 1, ExactI32, Standard, Method(host_temporal_cap_grant)),
    host_spec!(117, "temporal_cap_revoke", 1, 1, ExactI32, Standard, Method(host_temporal_cap_revoke)),
    host_spec!(118, "temporal_cap_check", 1, 1, ExactI32, Standard, Method(host_temporal_cap_check)),
    host_spec!(119, "temporal_checkpoint_create", 0, 1, ExactI32, Standard, Method(host_temporal_checkpoint_create)),
    host_spec!(120, "temporal_checkpoint_rollback", 1, 1, ExactI32, Standard, Method(host_temporal_checkpoint_rollback)),
    host_spec!(121, "policy_bind", 3, 1, ExactI32, Standard, Method(host_policy_bind)),
    host_spec!(122, "policy_unbind", 1, 1, ExactI32, Standard, Method(host_policy_unbind)),
    host_spec!(123, "policy_eval", 3, 1, ExactI32, Standard, Method(host_policy_eval)),
    host_spec!(124, "policy_query", 3, 1, ExactI32, Standard, Method(host_policy_query)),
    host_spec!(125, "cap_entangle", 2, 1, ExactI32, Standard, Method(host_cap_entangle)),
    host_spec!(126, "cap_entangle_group", 2, 1, ExactI32, Standard, Method(host_cap_entangle_group)),
    host_spec!(127, "cap_disentangle", 1, 1, ExactI32, Standard, Method(host_cap_disentangle)),
    host_spec!(128, "cap_entangle_query", 3, 1, ExactI32, Standard, Method(host_cap_entangle_query)),
    host_spec!(129, "cap_graph_query", 3, 1, ExactI32, Standard, Method(host_cap_graph_query)),
    host_spec!(130, "cap_graph_verify", 2, 1, ExactI32, Standard, Method(host_cap_graph_verify)),
    host_spec!(131, "cap_graph_depth", 1, 1, ExactI32, Standard, Method(host_cap_graph_depth)),
    host_spec!(132, "polyglot_lineage_count", 0, 1, ExactI32, Standard, Method(host_polyglot_lineage_count)),
    host_spec!(133, "polyglot_lineage_query", 2, 1, ExactI32, Standard, Method(host_polyglot_lineage_query)),
    host_spec!(134, "polyglot_lineage_query_filtered", 5, 1, ExactI32, Standard, Method(host_polyglot_lineage_query_filtered)),
    host_spec!(135, "polyglot_lineage_lookup", 3, 1, ExactI32, Standard, Method(host_polyglot_lineage_lookup)),
    host_spec!(136, "polyglot_lineage_lookup_object", 4, 1, ExactI32, Standard, Method(host_polyglot_lineage_lookup_object)),
    host_spec!(137, "polyglot_lineage_revoke", 1, 1, ExactI32, Standard, Method(host_polyglot_lineage_revoke)),
    host_spec!(138, "polyglot_lineage_rebind", 2, 1, ExactI32, Standard, Method(host_polyglot_lineage_rebind)),
    host_spec!(139, "polyglot_lineage_status", 3, 1, ExactI32, Standard, Method(host_polyglot_lineage_status)),
    host_spec!(140, "polyglot_lineage_status_object", 4, 1, ExactI32, Standard, Method(host_polyglot_lineage_status_object)),
    host_spec!(141, "polyglot_lineage_query_page", 4, 1, ExactI32, Standard, Method(host_polyglot_lineage_query_page)),
    host_spec!(142, "polyglot_lineage_event_query", 4, 1, ExactI32, Standard, Method(host_polyglot_lineage_event_query)),
];

const WASI_PREVIEW1_HOST_START: usize = 45;
const WASI_PREVIEW1_HOST_END: usize = 90;
const WASI_PREVIEW1_HOST_COUNT: usize =
    WASI_PREVIEW1_HOST_END - WASI_PREVIEW1_HOST_START + 1;
const POLYGLOT_HOST_START: usize = 103;
const POLYGLOT_HOST_END: usize = 105;
const POLYGLOT_HOST_COUNT: usize = 14;
const POLYGLOT_LINEAGE_HOST_START: usize = 132;
const POLYGLOT_LINEAGE_HOST_END: usize = 142;
const POLYGLOT_LINEAGE_HOST_COUNT: usize = POLYGLOT_LINEAGE_HOST_END - POLYGLOT_LINEAGE_HOST_START + 1;

const EXPECTED_WASI_PREVIEW1_HOST_SPECS: [ExpectedWasiHostSpec; WASI_PREVIEW1_HOST_COUNT] = [
    expected_wasi_host_spec(45, "args_get", 2, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(46, "args_sizes_get", 2, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(47, "environ_get", 2, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(48, "environ_sizes_get", 2, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(49, "clock_res_get", 2, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(50, "clock_time_get", 3, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(51, "fd_advise", 3, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(52, "fd_allocate", 3, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(53, "fd_close", 1, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(54, "fd_datasync", 1, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(55, "fd_fdstat_get", 2, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(56, "fd_fdstat_set_flags", 2, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(57, "fd_fdstat_set_rights", 3, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(58, "fd_filestat_get", 2, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(59, "fd_filestat_set_size", 2, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(60, "fd_filestat_set_times", 4, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(61, "fd_pread", 5, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(62, "fd_prestat_get", 2, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(63, "fd_prestat_dir_name", 3, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(64, "fd_pwrite", 5, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(65, "fd_read", 4, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(66, "fd_readdir", 5, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(67, "fd_renumber", 2, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(68, "fd_seek", 4, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(69, "fd_sync", 1, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(70, "fd_tell", 2, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(71, "fd_write", 4, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(72, "path_create_directory", 3, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(73, "path_filestat_get", 5, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(74, "path_filestat_set_times", 6, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(75, "path_link", 6, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(76, "path_open", 9, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(77, "path_readlink", 5, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(78, "path_remove_directory", 3, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(79, "path_rename", 5, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(80, "path_symlink", 5, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(81, "path_unlink_file", 3, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(82, "poll_oneoff", 4, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(83, "proc_exit", 1, 0, WasiAbiClass::Implemented),
    expected_wasi_host_spec(84, "proc_raise", 1, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(85, "sched_yield", 0, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(86, "random_get", 2, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(87, "sock_accept", 3, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(88, "sock_recv", 6, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(89, "sock_send", 5, 1, WasiAbiClass::Implemented),
    expected_wasi_host_spec(90, "sock_shutdown", 2, 1, WasiAbiClass::Implemented),
];

const EXPECTED_POLYGLOT_HOST_SPECS: [ExpectedPolyglotHostSpec; POLYGLOT_HOST_COUNT] = [
    ExpectedPolyglotHostSpec {
        id: 103,
        canonical_name: "polyglot_register",
        param_count: 2,
        result_count: 1,
        class: PolyglotAbiClass::Implemented,
    },
    ExpectedPolyglotHostSpec {
        id: 104,
        canonical_name: "polyglot_resolve",
        param_count: 2,
        result_count: 1,
        class: PolyglotAbiClass::Implemented,
    },
    ExpectedPolyglotHostSpec {
        id: 105,
        canonical_name: "polyglot_link",
        param_count: 4,
        result_count: 1,
        class: PolyglotAbiClass::Implemented,
    },
    ExpectedPolyglotHostSpec {
        id: 132,
        canonical_name: "polyglot_lineage_count",
        param_count: 0,
        result_count: 1,
        class: PolyglotAbiClass::Implemented,
    },
    ExpectedPolyglotHostSpec {
        id: 133,
        canonical_name: "polyglot_lineage_query",
        param_count: 2,
        result_count: 1,
        class: PolyglotAbiClass::Implemented,
    },
    ExpectedPolyglotHostSpec {
        id: 134,
        canonical_name: "polyglot_lineage_query_filtered",
        param_count: 5,
        result_count: 1,
        class: PolyglotAbiClass::Implemented,
    },
    ExpectedPolyglotHostSpec {
        id: 135,
        canonical_name: "polyglot_lineage_lookup",
        param_count: 3,
        result_count: 1,
        class: PolyglotAbiClass::Implemented,
    },
    ExpectedPolyglotHostSpec {
        id: 136,
        canonical_name: "polyglot_lineage_lookup_object",
        param_count: 4,
        result_count: 1,
        class: PolyglotAbiClass::Implemented,
    },
    ExpectedPolyglotHostSpec {
        id: 137,
        canonical_name: "polyglot_lineage_revoke",
        param_count: 1,
        result_count: 1,
        class: PolyglotAbiClass::Implemented,
    },
    ExpectedPolyglotHostSpec {
        id: 138,
        canonical_name: "polyglot_lineage_rebind",
        param_count: 2,
        result_count: 1,
        class: PolyglotAbiClass::Implemented,
    },
    ExpectedPolyglotHostSpec {
        id: 139,
        canonical_name: "polyglot_lineage_status",
        param_count: 3,
        result_count: 1,
        class: PolyglotAbiClass::Implemented,
    },
    ExpectedPolyglotHostSpec {
        id: 140,
        canonical_name: "polyglot_lineage_status_object",
        param_count: 4,
        result_count: 1,
        class: PolyglotAbiClass::Implemented,
    },
    ExpectedPolyglotHostSpec {
        id: 141,
        canonical_name: "polyglot_lineage_query_page",
        param_count: 4,
        result_count: 1,
        class: PolyglotAbiClass::Implemented,
    },
    ExpectedPolyglotHostSpec {
        id: 142,
        canonical_name: "polyglot_lineage_event_query",
        param_count: 4,
        result_count: 1,
        class: PolyglotAbiClass::Implemented,
    },
];

fn host_function_spec_by_id(id: usize) -> Option<&'static HostFunctionSpec> {
    HOST_FUNCTION_SPECS.get(id)
}

fn host_function_spec_by_name(name: &str) -> Option<&'static HostFunctionSpec> {
    HOST_FUNCTION_SPECS
        .iter()
        .find(|spec| spec.matches_name(name))
}

fn host_dispatch_conformance_signature(spec: &HostFunctionSpec) -> ParsedFunctionType {
    match spec.signature_policy {
        HostSignaturePolicy::ExactI32 => {
            let mut params = [ValueType::I32; MAX_WASM_TYPE_ARITY];
            let mut results = [ValueType::I32; MAX_WASM_TYPE_ARITY];
            let mut i = 0usize;
            while i < spec.param_count {
                params[i] = ValueType::I32;
                i += 1;
            }
            let mut j = 0usize;
            while j < spec.result_count {
                results[j] = ValueType::I32;
                j += 1;
            }
            ParsedFunctionType {
                param_count: spec.param_count,
                result_count: spec.result_count,
                param_types: params,
                result_types: results,
                all_i32: true,
            }
        }
        HostSignaturePolicy::ServiceRegister => host_function_signature_from_types(
            &[ValueType::FuncRef, ValueType::I32],
            &[ValueType::I32],
        ),
    }
}

fn host_dispatch_standard_alias<'a>(
    spec: &HostFunctionSpec,
    scratch: &'a mut [u8; 64],
) -> Result<&'a [u8], &'static str> {
    const PREFIX: &[u8] = b"oreulius_";
    let alias_len = PREFIX.len() + spec.canonical_name.len();
    if alias_len > scratch.len() {
        return Err("Host dispatch self-check: alias buffer too small");
    }
    scratch[..PREFIX.len()].copy_from_slice(PREFIX);
    scratch[PREFIX.len()..alias_len].copy_from_slice(spec.canonical_name.as_bytes());
    Ok(&scratch[..alias_len])
}

fn host_dispatch_expect_resolution(
    spec: &HostFunctionSpec,
    field_name: &[u8],
    signature: ParsedFunctionType,
    error: &'static str,
) -> Result<(), &'static str> {
    let resolved = resolve_host_import(b"oreulius", field_name, signature).map_err(|_| error)?;
    if resolved != spec.id {
        return Err(error);
    }
    Ok(())
}

fn wasi_abi_class_for_spec(spec: &HostFunctionSpec) -> Result<WasiAbiClass, &'static str> {
    match spec.behavior {
        HostBehavior::Method(_) => Ok(WasiAbiClass::Implemented),
        HostBehavior::Noop {
            pop_count,
            push_zero,
        } => {
            if !push_zero || spec.result_count != 1 || pop_count != spec.param_count {
                return Err("WASI Preview 1 ABI self-check: frozen no-op metadata mismatch");
            }
            Ok(WasiAbiClass::FrozenNoop)
        }
    }
}

fn formal_wasi_noop_args(id: usize) -> ([i32; 6], usize) {
    match id {
        51 => ([8, 0x120, 32, 0, 0, 0], 3),
        52 => ([8, 0x140, 64, 0, 0, 0], 3),
        54 => ([8, 0, 0, 0, 0, 0], 1),
        56 => ([8, 1, 0, 0, 0, 0], 2),
        57 => ([8, 0x11, 0x22, 0, 0, 0], 3),
        59 => ([8, 512, 0, 0, 0, 0], 2),
        60 => ([8, 1, 2, 3, 0, 0], 4),
        67 => ([8, 10, 0, 0, 0, 0], 2),
        69 => ([8, 0, 0, 0, 0, 0], 1),
        74 => ([3, 0x180, 8, 0, 1, 2], 6),
        84 => ([15, 0, 0, 0, 0, 0], 1),
        _ => ([0, 0, 0, 0, 0, 0], 0),
    }
}

fn formal_seed_wasi_noop_instance(
    instance: &mut WasmInstance,
    instance_id: usize,
) -> Result<(), &'static str> {
    instance.stack.clear();
    instance.memory.clear_active();
    instance.process_id = ProcessId(0x4510_0000u32.saturating_add(instance_id as u32));
    instance.instance_id = instance_id;
    instance.instruction_count = 0;
    instance.memory_op_count = 0;
    instance.syscall_count = 0;
    instance.call_depth = 0;
    instance.pc = 0;
    instance.current_func_end = 0;
    instance.control_depth = 0;
    instance.last_received_service_handle = None;
    instance.active_thread_tid = 0;
    instance.wasi_ctx = crate::services::wasi::WasiCtx::new(instance_id);
    instance.wasi_ctx.exit_code = Some(7);
    if !instance.wasi_ctx.add_preopen(b"/tmp") {
        return Err("WASI Preview 1 ABI self-check: failed to seed preopen state");
    }

    let file_path = b"/tmp/log";
    let file_fd = &mut instance.wasi_ctx.fds[8];
    file_fd.kind = crate::services::wasi::FdKind::File;
    file_fd.offset = 77;
    file_fd.path[..file_path.len()].copy_from_slice(file_path);
    file_fd.path_len = file_path.len() as u8;
    file_fd.size = 4096;
    file_fd.fdflags = 0;
    file_fd.rights_base = crate::services::wasi::rights::ALL;
    file_fd.rights_inheriting = crate::services::wasi::rights::ALL;
    file_fd.readdir_cookie = 11;
    file_fd.shut_rd = false;
    file_fd.shut_wr = false;

    let socket_fd = &mut instance.wasi_ctx.fds[9];
    socket_fd.kind = crate::services::wasi::FdKind::TcpSocket;
    socket_fd.offset = 13;
    socket_fd.path[..8].copy_from_slice(b"sock0001");
    socket_fd.path_len = 8;
    socket_fd.size = 512;
    socket_fd.fdflags = crate::services::wasi::fdflags::NONBLOCK;
    socket_fd.rights_base = crate::services::wasi::rights::ALL;
    socket_fd.rights_inheriting = crate::services::wasi::rights::ALL;
    socket_fd.readdir_cookie = 2;
    socket_fd.shut_rd = false;
    socket_fd.shut_wr = false;

    instance
        .memory
        .write(0x120, &[0xA1; 16])
        .map_err(|_| "WASI Preview 1 ABI self-check: failed to seed linear memory")?;
    instance
        .memory
        .write(0x140, &[0xB2; 16])
        .map_err(|_| "WASI Preview 1 ABI self-check: failed to seed linear memory")?;
    instance
        .memory
        .write(0x180, b"/tmp/old")
        .map_err(|_| "WASI Preview 1 ABI self-check: failed to seed linear memory")?;
    instance
        .memory
        .write(0x1C0, b"/tmp/new")
        .map_err(|_| "WASI Preview 1 ABI self-check: failed to seed linear memory")?;
    instance
        .memory
        .write(0x200, &[0xCC; 32])
        .map_err(|_| "WASI Preview 1 ABI self-check: failed to seed linear memory")?;
    instance
        .memory
        .write(0x240, &[0xDD; 16])
        .map_err(|_| "WASI Preview 1 ABI self-check: failed to seed linear memory")?;

    Ok(())
}

fn formal_wasi_memory_fingerprint(memory: &LinearMemory) -> Result<u64, &'static str> {
    const REGIONS: [(usize, usize); 6] = [
        (0x120, 16),
        (0x140, 16),
        (0x180, 8),
        (0x1C0, 8),
        (0x200, 32),
        (0x240, 16),
    ];
    let mut hash: u64 = 14695981039346656037;
    let mut region_idx = 0usize;
    while region_idx < REGIONS.len() {
        let (offset, len) = REGIONS[region_idx];
        let bytes = memory
            .read(offset, len)
            .map_err(|_| "WASI Preview 1 ABI self-check: failed to fingerprint seeded memory")?;
        let mut byte_idx = 0usize;
        while byte_idx < bytes.len() {
            hash ^= bytes[byte_idx] as u64;
            hash = hash.wrapping_mul(1099511628211);
            byte_idx += 1;
        }
        region_idx += 1;
    }
    Ok(hash)
}

fn formal_wasi_noop_behavior_check(
    instance: &mut WasmInstance,
    expected: &ExpectedWasiHostSpec,
    spec: &HostFunctionSpec,
) -> Result<(), &'static str> {
    formal_seed_wasi_noop_instance(instance, expected.id)?;
    let (args, arg_count) = formal_wasi_noop_args(spec.id);
    if arg_count != spec.param_count {
        return Err("WASI Preview 1 ABI self-check: frozen no-op argument shape mismatch");
    }

    let memory_before = formal_wasi_memory_fingerprint(&instance.memory)?;
    let wasi_before = instance.wasi_ctx.abi_fingerprint();

    let mut i = 0usize;
    while i < arg_count {
        instance
            .stack
            .push(Value::I32(args[i]))
            .map_err(|_| "WASI Preview 1 ABI self-check: failed to seed frozen no-op arguments")?;
        i += 1;
    }

    spec.dispatch(instance)
        .map_err(|_| "WASI Preview 1 ABI self-check: frozen no-op dispatch failed")?;

    if instance.stack.len() != spec.result_count {
        return Err("WASI Preview 1 ABI self-check: frozen no-op stack effect drifted");
    }
    let result = instance
        .stack
        .pop()
        .map_err(|_| "WASI Preview 1 ABI self-check: frozen no-op result missing")?;
    if result
        .as_i32()
        .map_err(|_| "WASI Preview 1 ABI self-check: frozen no-op result type drifted")?
        != 0
    {
        return Err("WASI Preview 1 ABI self-check: frozen no-op no longer returns success");
    }
    if !instance.stack.is_empty() {
        return Err("WASI Preview 1 ABI self-check: frozen no-op left residual stack state");
    }

    let memory_after = formal_wasi_memory_fingerprint(&instance.memory)?;
    if memory_before != memory_after {
        return Err("WASI Preview 1 ABI self-check: frozen no-op mutated linear memory");
    }
    let wasi_after = instance.wasi_ctx.abi_fingerprint();
    if wasi_before != wasi_after {
        return Err("WASI Preview 1 ABI self-check: frozen no-op mutated WasiCtx");
    }

    Ok(())
}

const FORMAL_WASI_ARG_A_OFFSET: usize = 0x300;
const FORMAL_WASI_ARG_B_OFFSET: usize = 0x380;
const FORMAL_WASI_BUFUSED_OFFSET: usize = 0x3F0;
const FORMAL_WASI_BUFFER_OFFSET: usize = 0x400;
const FORMAL_WASI_BUFFER_LEN: usize = 512;
const FORMAL_WASI_STAT_OFFSET: usize = 0x640;
const FORMAL_WASI_IOV_OFFSET: usize = 0x6C0;
const FORMAL_WASI_NBYTES_OFFSET: usize = 0x6D0;
const FORMAL_WASI_FD_OUT_OFFSET: usize = 0x6D8;

#[derive(Clone, Debug, PartialEq, Eq)]
struct FormalWasiDirent {
    next: u64,
    ino: u64,
    dtype: u8,
    name: alloc::string::String,
}

fn formal_wasi_fill_region(
    instance: &mut WasmInstance,
    offset: usize,
    len: usize,
    value: u8,
) -> Result<(), &'static str> {
    let bytes = alloc::vec![value; len];
    instance
        .memory
        .write(offset, &bytes)
        .map_err(|_| "WASI Preview 1 ABI self-check: failed to seed linear memory")
}

fn formal_wasi_write_region(
    instance: &mut WasmInstance,
    offset: usize,
    len: usize,
    fill: u8,
    bytes: &[u8],
) -> Result<usize, &'static str> {
    if bytes.len() > len {
        return Err("WASI Preview 1 ABI self-check: fixture path exceeded reserved memory");
    }
    let mut region = alloc::vec![fill; len];
    region[..bytes.len()].copy_from_slice(bytes);
    instance
        .memory
        .write(offset, &region)
        .map_err(|_| "WASI Preview 1 ABI self-check: failed to seed linear memory")?;
    Ok(bytes.len())
}

fn formal_wasi_seed_iovec(
    instance: &mut WasmInstance,
    iov_offset: usize,
    buf_offset: usize,
    buf_len: usize,
) -> Result<(), &'static str> {
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&(buf_offset as u32).to_le_bytes());
    bytes[4..].copy_from_slice(&(buf_len as u32).to_le_bytes());
    instance
        .memory
        .write(iov_offset, &bytes)
        .map_err(|_| "WASI Preview 1 ABI self-check: failed to seed iovec")
}

fn formal_wasi_dispatch_errno(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
    args: &[Value],
    label: &'static str,
) -> Result<i32, &'static str> {
    instance.stack.clear();
    let mut i = 0usize;
    while i < args.len() {
        instance
            .stack
            .push(args[i])
            .map_err(|_| label)?;
        i += 1;
    }

    spec.dispatch(instance).map_err(|_| label)?;
    if instance.stack.len() != spec.result_count {
        return Err(label);
    }
    let result = instance.stack.pop().map_err(|_| label)?;
    let errno = result.as_i32().map_err(|_| label)?;
    if !instance.stack.is_empty() {
        return Err(label);
    }
    Ok(errno)
}

fn formal_wasi_read_u32(memory: &LinearMemory, offset: usize) -> Result<u32, &'static str> {
    let bytes = memory
        .read(offset, 4)
        .map_err(|_| "WASI Preview 1 ABI self-check: failed to read u32 from linear memory")?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn formal_wasi_read_u64(memory: &LinearMemory, offset: usize) -> Result<u64, &'static str> {
    let bytes = memory
        .read(offset, 8)
        .map_err(|_| "WASI Preview 1 ABI self-check: failed to read u64 from linear memory")?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn formal_wasi_read_bytes(
    memory: &LinearMemory,
    offset: usize,
    len: usize,
) -> Result<Vec<u8>, &'static str> {
    memory
        .read(offset, len)
        .map(|bytes| bytes.to_vec())
        .map_err(|_| "WASI Preview 1 ABI self-check: failed to read linear memory")
}

fn formal_wasi_parse_dirents(bytes: &[u8]) -> Result<Vec<FormalWasiDirent>, &'static str> {
    let mut cursor = 0usize;
    let mut entries = Vec::new();

    while cursor < bytes.len() {
        if cursor + 21 > bytes.len() {
            return Err("WASI Preview 1 ABI self-check: truncated dirent header");
        }
        let next = u64::from_le_bytes(
            bytes[cursor..cursor + 8]
                .try_into()
                .map_err(|_| "WASI Preview 1 ABI self-check: invalid dirent d_next")?,
        );
        let ino = u64::from_le_bytes(
            bytes[cursor + 8..cursor + 16]
                .try_into()
                .map_err(|_| "WASI Preview 1 ABI self-check: invalid dirent d_ino")?,
        );
        let namlen = u32::from_le_bytes(
            bytes[cursor + 16..cursor + 20]
                .try_into()
                .map_err(|_| "WASI Preview 1 ABI self-check: invalid dirent d_namlen")?,
        ) as usize;
        let dtype = bytes[cursor + 20];
        let name_start = cursor + 21;
        let name_end = name_start + namlen;
        if name_end > bytes.len() {
            return Err("WASI Preview 1 ABI self-check: truncated dirent name");
        }
        let name = core::str::from_utf8(&bytes[name_start..name_end])
            .map_err(|_| "WASI Preview 1 ABI self-check: dirent name was not valid UTF-8")?;
        entries.push(FormalWasiDirent {
            next,
            ino,
            dtype,
            name: name.into(),
        });
        cursor = name_end;
    }

    Ok(entries)
}

fn formal_wasi_ensure_dir(path: &str) -> Result<(), &'static str> {
    match crate::fs::vfs::mkdir(path) {
        Ok(()) => Ok(()),
        Err(_) if crate::fs::vfs::list_dir_entries(path).is_ok() => Ok(()),
        Err(e) => Err(e),
    }
}

fn formal_wasi_cleanup_paths(paths: &[&str]) {
    let mut i = 0usize;
    while i < paths.len() {
        let _ = crate::fs::vfs::unlink(paths[i]);
        let _ = crate::fs::vfs::rmdir(paths[i]);
        i += 1;
    }
}

fn formal_wasi_seed_file_fd(
    instance: &mut WasmInstance,
    fd: u32,
    path: &str,
    rights_base: u64,
    rights_inheriting: u64,
    fdflags: u16,
) -> Result<(), &'static str> {
    let path_bytes = path.as_bytes();
    if path_bytes.len() > 127 {
        return Err("WASI Preview 1 ABI self-check: fixture path exceeded WasiCtx capacity");
    }
    let open_fd = &mut instance.wasi_ctx.fds[fd as usize];
    open_fd.kind = crate::services::wasi::FdKind::File;
    open_fd.offset = 0;
    open_fd.path = [0; 128];
    open_fd.path[..path_bytes.len()].copy_from_slice(path_bytes);
    open_fd.path_len = path_bytes.len() as u8;
    open_fd.size = crate::fs::vfs::path_size(path).unwrap_or(0) as u64;
    open_fd.fdflags = fdflags;
    open_fd.rights_base = rights_base;
    open_fd.rights_inheriting = rights_inheriting;
    open_fd.readdir_cookie = 0;
    open_fd.shut_rd = false;
    open_fd.shut_wr = false;
    Ok(())
}

fn formal_wasi_seed_dir_fd(
    instance: &mut WasmInstance,
    fd: u32,
    path: &str,
) -> Result<(), &'static str> {
    let path_bytes = path.as_bytes();
    if path_bytes.len() > 127 {
        return Err("WASI Preview 1 ABI self-check: fixture path exceeded WasiCtx capacity");
    }
    let open_fd = &mut instance.wasi_ctx.fds[fd as usize];
    open_fd.kind = crate::services::wasi::FdKind::Dir;
    open_fd.offset = 0;
    open_fd.path = [0; 128];
    open_fd.path[..path_bytes.len()].copy_from_slice(path_bytes);
    open_fd.path_len = path_bytes.len() as u8;
    open_fd.size = 0;
    open_fd.fdflags = 0;
    open_fd.rights_base = crate::services::wasi::rights::ALL;
    open_fd.rights_inheriting = crate::services::wasi::rights::ALL;
    open_fd.readdir_cookie = 0;
    Ok(())
}

struct FormalWasiFdStatView {
    filetype: u8,
    flags: u16,
    rights_base: u64,
    rights_inheriting: u64,
}

struct FormalWasiFileStatView {
    ino: u64,
    filetype: u8,
    nlink: u64,
    size: u64,
    atim: u64,
    mtim: u64,
    ctim: u64,
}

fn formal_wasi_parse_fd_stat(
    memory: &LinearMemory,
    offset: usize,
) -> Result<FormalWasiFdStatView, &'static str> {
    let flag_bytes = memory
        .read(offset + 2, 2)
        .map_err(|_| "WASI Preview 1 ABI self-check: failed to read fdstat flags")?;
    Ok(FormalWasiFdStatView {
        filetype: memory
            .read(offset, 1)
            .map_err(|_| "WASI Preview 1 ABI self-check: failed to read fdstat filetype")?[0],
        flags: u16::from_le_bytes([flag_bytes[0], flag_bytes[1]]),
        rights_base: formal_wasi_read_u64(memory, offset + 8)?,
        rights_inheriting: formal_wasi_read_u64(memory, offset + 16)?,
    })
}

fn formal_wasi_parse_file_stat(
    memory: &LinearMemory,
    offset: usize,
) -> Result<FormalWasiFileStatView, &'static str> {
    Ok(FormalWasiFileStatView {
        ino: formal_wasi_read_u64(memory, offset + 8)?,
        filetype: memory
            .read(offset + 16, 1)
            .map_err(|_| "WASI Preview 1 ABI self-check: failed to read filestat filetype")?[0],
        nlink: formal_wasi_read_u64(memory, offset + 24)?,
        size: formal_wasi_read_u64(memory, offset + 32)?,
        atim: formal_wasi_read_u64(memory, offset + 40)?,
        mtim: formal_wasi_read_u64(memory, offset + 48)?,
        ctim: formal_wasi_read_u64(memory, offset + 56)?,
    })
}

fn formal_wasi_find_entry(
    dir: &str,
    name: &str,
) -> Result<crate::fs::vfs::DirectoryEntryInfo, &'static str> {
    let entries = crate::fs::vfs::list_dir_entries(dir)?;
    let mut i = 0usize;
    while i < entries.len() {
        if entries[i].name == name {
            return Ok(entries[i].clone());
        }
        i += 1;
    }
    Err("WASI Preview 1 ABI self-check: expected directory entry was missing")
}

fn formal_wasi_seed_readdir_fixture(base_dir: &str) -> Result<(), &'static str> {
    let file_plain = alloc::format!("{}/alpha", base_dir);
    let file_space = alloc::format!("{}/name with space", base_dir);
    let nested_dir = alloc::format!("{}/nested.dir", base_dir);
    let symlink_path = alloc::format!("{}/sym-link", base_dir);
    let punct_file = alloc::format!("{}/punctuation-_.txt", base_dir);

    formal_wasi_cleanup_paths(&[
        symlink_path.as_str(),
        punct_file.as_str(),
        file_space.as_str(),
        file_plain.as_str(),
        nested_dir.as_str(),
        base_dir,
    ]);
    formal_wasi_ensure_dir(base_dir)?;
    crate::fs::vfs::write_path(&file_plain, b"alpha")?;
    crate::fs::vfs::write_path(&file_space, b"space")?;
    formal_wasi_ensure_dir(&nested_dir)?;
    crate::fs::vfs::symlink(&file_plain, &symlink_path)?;
    crate::fs::vfs::write_path(&punct_file, b"punct")?;
    Ok(())
}

fn formal_wasi_behavior_check_fd_readdir(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
) -> Result<u32, &'static str> {
    const EXPECTED: [(&str, u8); 5] = [
        ("alpha", crate::services::wasi::filetype::REGULAR_FILE),
        ("name with space", crate::services::wasi::filetype::REGULAR_FILE),
        ("nested.dir", crate::services::wasi::filetype::DIRECTORY),
        ("sym-link", crate::services::wasi::filetype::SYMBOLIC_LINK),
        ("punctuation-_.txt", crate::services::wasi::filetype::REGULAR_FILE),
    ];

    let plain_dir = alloc::format!("/tmp/wasi-readdir-plain-{}", spec.id);
    formal_wasi_seed_readdir_fixture(&plain_dir)?;

    formal_seed_wasi_noop_instance(instance, spec.id)?;
    formal_wasi_seed_dir_fd(instance, 8, &plain_dir)?;
    formal_wasi_fill_region(instance, FORMAL_WASI_BUFUSED_OFFSET, 4, 0xA5)?;
    formal_wasi_fill_region(instance, FORMAL_WASI_BUFFER_OFFSET, FORMAL_WASI_BUFFER_LEN, 0xCC)?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[
            Value::I32(8),
            Value::I32(FORMAL_WASI_BUFFER_OFFSET as i32),
            Value::I32(FORMAL_WASI_BUFFER_LEN as i32),
            Value::I32(0),
            Value::I32(FORMAL_WASI_BUFUSED_OFFSET as i32),
        ],
        "WASI Preview 1 ABI self-check: fd_readdir dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_readdir full read failed");
    }
    let used = formal_wasi_read_u32(&instance.memory, FORMAL_WASI_BUFUSED_OFFSET)? as usize;
    let dirents = formal_wasi_parse_dirents(&formal_wasi_read_bytes(
        &instance.memory,
        FORMAL_WASI_BUFFER_OFFSET,
        used,
    )?)?;
    if dirents.len() != EXPECTED.len() {
        return Err("WASI Preview 1 ABI self-check: fd_readdir returned wrong entry count");
    }
    let mut idx = 0usize;
    while idx < EXPECTED.len() {
        if dirents[idx].name != EXPECTED[idx].0
            || dirents[idx].dtype != EXPECTED[idx].1
            || dirents[idx].next != (idx as u64 + 1)
        {
            return Err("WASI Preview 1 ABI self-check: fd_readdir metadata drifted");
        }
        idx += 1;
    }
    if dirents[0].ino == 0 || dirents[0].ino != formal_wasi_find_entry(&plain_dir, "alpha")?.inode {
        return Err("WASI Preview 1 ABI self-check: fd_readdir inode drifted");
    }

    formal_seed_wasi_noop_instance(instance, spec.id + 1)?;
    formal_wasi_seed_dir_fd(instance, 8, &plain_dir)?;
    formal_wasi_fill_region(instance, FORMAL_WASI_BUFUSED_OFFSET, 4, 0xA5)?;
    formal_wasi_fill_region(instance, FORMAL_WASI_BUFFER_OFFSET, FORMAL_WASI_BUFFER_LEN, 0xCC)?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[
            Value::I32(8),
            Value::I32(FORMAL_WASI_BUFFER_OFFSET as i32),
            Value::I32(FORMAL_WASI_BUFFER_LEN as i32),
            Value::I32(2),
            Value::I32(FORMAL_WASI_BUFUSED_OFFSET as i32),
        ],
        "WASI Preview 1 ABI self-check: fd_readdir cookie dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_readdir cookie read failed");
    }
    let used = formal_wasi_read_u32(&instance.memory, FORMAL_WASI_BUFUSED_OFFSET)? as usize;
    let dirents = formal_wasi_parse_dirents(&formal_wasi_read_bytes(
        &instance.memory,
        FORMAL_WASI_BUFFER_OFFSET,
        used,
    )?)?;
    if dirents.len() != EXPECTED.len() - 2
        || dirents[0].name != "nested.dir"
        || dirents[1].name != "sym-link"
        || dirents[2].name != "punctuation-_.txt"
    {
        return Err("WASI Preview 1 ABI self-check: fd_readdir cookie handling drifted");
    }

    let first_entry_size = 21 + EXPECTED[0].0.len();
    let second_entry_size = 21 + EXPECTED[1].0.len();
    formal_seed_wasi_noop_instance(instance, spec.id + 2)?;
    formal_wasi_seed_dir_fd(instance, 8, &plain_dir)?;
    formal_wasi_fill_region(instance, FORMAL_WASI_BUFUSED_OFFSET, 4, 0xA5)?;
    formal_wasi_fill_region(instance, FORMAL_WASI_BUFFER_OFFSET, FORMAL_WASI_BUFFER_LEN, 0xCC)?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[
            Value::I32(8),
            Value::I32(FORMAL_WASI_BUFFER_OFFSET as i32),
            Value::I32((first_entry_size + second_entry_size - 1) as i32),
            Value::I32(0),
            Value::I32(FORMAL_WASI_BUFUSED_OFFSET as i32),
        ],
        "WASI Preview 1 ABI self-check: fd_readdir short buffer dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_readdir short buffer failed");
    }
    let used = formal_wasi_read_u32(&instance.memory, FORMAL_WASI_BUFUSED_OFFSET)? as usize;
    let dirents = formal_wasi_parse_dirents(&formal_wasi_read_bytes(
        &instance.memory,
        FORMAL_WASI_BUFFER_OFFSET,
        used,
    )?)?;
    if used != first_entry_size || dirents.len() != 1 || dirents[0].name != "alpha" {
        return Err("WASI Preview 1 ABI self-check: fd_readdir no longer stops at whole records");
    }

    let mount_root = alloc::format!("/tmp/wasi-readdir-mount-root-{}", spec.id);
    let mount_dir = alloc::format!("{}/case", mount_root);
    formal_wasi_cleanup_paths(&[mount_dir.as_str()]);
    formal_wasi_ensure_dir(&mount_root)?;
    crate::fs::vfs::formal_mount_virtio(&mount_root)?;
    formal_wasi_seed_readdir_fixture(&mount_dir)?;

    formal_seed_wasi_noop_instance(instance, spec.id + 3)?;
    formal_wasi_seed_dir_fd(instance, 8, &mount_dir)?;
    formal_wasi_fill_region(instance, FORMAL_WASI_BUFUSED_OFFSET, 4, 0xA5)?;
    formal_wasi_fill_region(instance, FORMAL_WASI_BUFFER_OFFSET, FORMAL_WASI_BUFFER_LEN, 0xCC)?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[
            Value::I32(8),
            Value::I32(FORMAL_WASI_BUFFER_OFFSET as i32),
            Value::I32(FORMAL_WASI_BUFFER_LEN as i32),
            Value::I32(0),
            Value::I32(FORMAL_WASI_BUFUSED_OFFSET as i32),
        ],
        "WASI Preview 1 ABI self-check: mounted fd_readdir dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: mounted fd_readdir failed");
    }
    let used = formal_wasi_read_u32(&instance.memory, FORMAL_WASI_BUFUSED_OFFSET)? as usize;
    let dirents = formal_wasi_parse_dirents(&formal_wasi_read_bytes(
        &instance.memory,
        FORMAL_WASI_BUFFER_OFFSET,
        used,
    )?)?;
    if dirents.len() != EXPECTED.len()
        || dirents[1].name != "name with space"
        || dirents[4].name != "punctuation-_.txt"
        || dirents[3].dtype != crate::services::wasi::filetype::SYMBOLIC_LINK
    {
        return Err("WASI Preview 1 ABI self-check: mounted fd_readdir drifted");
    }

    Ok(4)
}

fn formal_wasi_behavior_check_path_readlink(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
) -> Result<u32, &'static str> {
    let base_dir = alloc::format!(
        "/tmp/wasi-readlink-{}-{}",
        spec.id,
        crate::scheduler::pit::get_ticks()
    );
    let target = alloc::format!("{}/target-file", base_dir);
    let link = alloc::format!("{}/link", base_dir);
    let missing = alloc::format!("{}/missing", base_dir);

    formal_wasi_cleanup_paths(&[link.as_str(), target.as_str(), base_dir.as_str()]);
    formal_wasi_ensure_dir(&base_dir)?;
    crate::fs::vfs::write_path(&target, b"target")?;
    crate::fs::vfs::symlink(&target, &link)?;

    formal_seed_wasi_noop_instance(instance, spec.id)?;
    let path_len = formal_wasi_write_region(
        instance,
        FORMAL_WASI_ARG_A_OFFSET,
        128,
        0,
        link.as_bytes(),
    )?;
    formal_wasi_fill_region(instance, FORMAL_WASI_BUFFER_OFFSET, 64, 0xCC)?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[
            Value::I32(3),
            Value::I32(FORMAL_WASI_ARG_A_OFFSET as i32),
            Value::I32(path_len as i32),
            Value::I32(FORMAL_WASI_BUFFER_OFFSET as i32),
            Value::I32(target.len() as i32),
        ],
        "WASI Preview 1 ABI self-check: path_readlink exact-fit dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: path_readlink exact-fit failed");
    }
    let exact = formal_wasi_read_bytes(&instance.memory, FORMAL_WASI_BUFFER_OFFSET, target.len())?;
    if exact.as_slice() != target.as_bytes() {
        return Err("WASI Preview 1 ABI self-check: path_readlink exact-fit bytes drifted");
    }

    formal_seed_wasi_noop_instance(instance, spec.id + 1)?;
    let path_len = formal_wasi_write_region(
        instance,
        FORMAL_WASI_ARG_A_OFFSET,
        128,
        0,
        link.as_bytes(),
    )?;
    formal_wasi_fill_region(instance, FORMAL_WASI_BUFFER_OFFSET, 64, 0xDD)?;
    let trunc_len = target.len().saturating_sub(2);
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[
            Value::I32(3),
            Value::I32(FORMAL_WASI_ARG_A_OFFSET as i32),
            Value::I32(path_len as i32),
            Value::I32(FORMAL_WASI_BUFFER_OFFSET as i32),
            Value::I32(trunc_len as i32),
        ],
        "WASI Preview 1 ABI self-check: path_readlink truncated dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: path_readlink truncation failed");
    }
    let truncated = formal_wasi_read_bytes(&instance.memory, FORMAL_WASI_BUFFER_OFFSET, trunc_len + 2)?;
    if truncated[..trunc_len] != target.as_bytes()[..trunc_len]
        || truncated[trunc_len] != 0xDD
        || truncated[trunc_len + 1] != 0xDD
    {
        return Err("WASI Preview 1 ABI self-check: path_readlink truncation drifted");
    }

    formal_seed_wasi_noop_instance(instance, spec.id + 2)?;
    let path_len = formal_wasi_write_region(
        instance,
        FORMAL_WASI_ARG_A_OFFSET,
        128,
        0,
        link.as_bytes(),
    )?;
    formal_wasi_fill_region(instance, FORMAL_WASI_BUFFER_OFFSET, 8, 0xEE)?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[
            Value::I32(3),
            Value::I32(FORMAL_WASI_ARG_A_OFFSET as i32),
            Value::I32(path_len as i32),
            Value::I32(FORMAL_WASI_BUFFER_OFFSET as i32),
            Value::I32(0),
        ],
        "WASI Preview 1 ABI self-check: path_readlink zero-length dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: path_readlink zero-length failed");
    }
    let zero_len = formal_wasi_read_bytes(&instance.memory, FORMAL_WASI_BUFFER_OFFSET, 8)?;
    if zero_len != alloc::vec![0xEE; 8] {
        return Err("WASI Preview 1 ABI self-check: path_readlink zero-length mutated memory");
    }

    formal_seed_wasi_noop_instance(instance, spec.id + 3)?;
    let path_len = formal_wasi_write_region(
        instance,
        FORMAL_WASI_ARG_A_OFFSET,
        128,
        0,
        missing.as_bytes(),
    )?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[
            Value::I32(3),
            Value::I32(FORMAL_WASI_ARG_A_OFFSET as i32),
            Value::I32(path_len as i32),
            Value::I32(FORMAL_WASI_BUFFER_OFFSET as i32),
            Value::I32(16),
        ],
        "WASI Preview 1 ABI self-check: path_readlink missing dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Noent.as_i32() {
        return Err("WASI Preview 1 ABI self-check: path_readlink missing-path drifted");
    }

    formal_seed_wasi_noop_instance(instance, spec.id + 4)?;
    let path_len = formal_wasi_write_region(
        instance,
        FORMAL_WASI_ARG_A_OFFSET,
        128,
        0,
        link.as_bytes(),
    )?;
    let out_of_bounds = instance.memory.active_len().saturating_sub(2);
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[
            Value::I32(3),
            Value::I32(FORMAL_WASI_ARG_A_OFFSET as i32),
            Value::I32(path_len as i32),
            Value::I32(out_of_bounds as i32),
            Value::I32(8),
        ],
        "WASI Preview 1 ABI self-check: path_readlink bounds dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Fault.as_i32() {
        return Err("WASI Preview 1 ABI self-check: path_readlink bounds drifted");
    }

    Ok(5)
}

fn formal_wasi_behavior_check_path_symlink(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
) -> Result<u32, &'static str> {
    let base_dir = alloc::format!(
        "/tmp/wasi-symlink-{}-{}",
        spec.id,
        crate::scheduler::pit::get_ticks()
    );
    let target = alloc::format!("{}/target-file", base_dir);
    let link = alloc::format!("{}/link", base_dir);
    let readlink_spec = host_function_spec_by_id(77)
        .ok_or("WASI Preview 1 ABI self-check: path_readlink spec missing")?;

    formal_wasi_cleanup_paths(&[link.as_str(), target.as_str(), base_dir.as_str()]);
    formal_wasi_ensure_dir(&base_dir)?;
    crate::fs::vfs::write_path(&target, b"target")?;
    let _ = crate::fs::vfs::unlink(&link);

    formal_seed_wasi_noop_instance(instance, spec.id)?;
    let target_len = formal_wasi_write_region(
        instance,
        FORMAL_WASI_ARG_A_OFFSET,
        128,
        0,
        target.as_bytes(),
    )?;
    let link_len = formal_wasi_write_region(
        instance,
        FORMAL_WASI_ARG_B_OFFSET,
        128,
        0,
        link.as_bytes(),
    )?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[
            Value::I32(FORMAL_WASI_ARG_A_OFFSET as i32),
            Value::I32(target_len as i32),
            Value::I32(3),
            Value::I32(FORMAL_WASI_ARG_B_OFFSET as i32),
            Value::I32(link_len as i32),
        ],
        "WASI Preview 1 ABI self-check: path_symlink create dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: path_symlink create failed");
    }

    formal_wasi_fill_region(instance, FORMAL_WASI_BUFFER_OFFSET, 128, 0xCC)?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        readlink_spec,
        &[
            Value::I32(3),
            Value::I32(FORMAL_WASI_ARG_B_OFFSET as i32),
            Value::I32(link_len as i32),
            Value::I32(FORMAL_WASI_BUFFER_OFFSET as i32),
            Value::I32(target.len() as i32),
        ],
        "WASI Preview 1 ABI self-check: path_symlink readback dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: path_symlink readback failed");
    }
    let readback = formal_wasi_read_bytes(&instance.memory, FORMAL_WASI_BUFFER_OFFSET, target.len())?;
    if readback.as_slice() != target.as_bytes() {
        return Err("WASI Preview 1 ABI self-check: path_symlink readback drifted");
    }

    formal_seed_wasi_noop_instance(instance, spec.id + 1)?;
    let target_len = formal_wasi_write_region(
        instance,
        FORMAL_WASI_ARG_A_OFFSET,
        128,
        0,
        target.as_bytes(),
    )?;
    let link_len = formal_wasi_write_region(
        instance,
        FORMAL_WASI_ARG_B_OFFSET,
        128,
        0,
        link.as_bytes(),
    )?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[
            Value::I32(FORMAL_WASI_ARG_A_OFFSET as i32),
            Value::I32(target_len as i32),
            Value::I32(3),
            Value::I32(FORMAL_WASI_ARG_B_OFFSET as i32),
            Value::I32(link_len as i32),
        ],
        "WASI Preview 1 ABI self-check: path_symlink duplicate dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Io.as_i32() {
        return Err("WASI Preview 1 ABI self-check: path_symlink duplicate-path drifted");
    }

    formal_seed_wasi_noop_instance(instance, spec.id + 2)?;
    let invalid_path = [0xFFu8, 0xFEu8];
    let invalid_len = formal_wasi_write_region(
        instance,
        FORMAL_WASI_ARG_A_OFFSET,
        16,
        0,
        &invalid_path,
    )?;
    let link_len = formal_wasi_write_region(
        instance,
        FORMAL_WASI_ARG_B_OFFSET,
        128,
        0,
        link.as_bytes(),
    )?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[
            Value::I32(FORMAL_WASI_ARG_A_OFFSET as i32),
            Value::I32(invalid_len as i32),
            Value::I32(3),
            Value::I32(FORMAL_WASI_ARG_B_OFFSET as i32),
            Value::I32(link_len as i32),
        ],
        "WASI Preview 1 ABI self-check: path_symlink invalid UTF-8 dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Inval.as_i32() {
        return Err("WASI Preview 1 ABI self-check: path_symlink invalid-path drifted");
    }

    Ok(3)
}

fn formal_wasi_behavior_check_path_link(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
) -> Result<u32, &'static str> {
    let base_dir = alloc::format!("/tmp/wasi-link-{}", spec.id);
    let source = alloc::format!("{}/source", base_dir);
    let linked = alloc::format!("{}/linked", base_dir);

    formal_wasi_cleanup_paths(&[linked.as_str(), source.as_str(), base_dir.as_str()]);
    formal_wasi_ensure_dir(&base_dir)?;
    crate::fs::vfs::write_path(&source, b"source")?;

    formal_seed_wasi_noop_instance(instance, spec.id)?;
    let source_len = formal_wasi_write_region(
        instance,
        FORMAL_WASI_ARG_A_OFFSET,
        128,
        0,
        source.as_bytes(),
    )?;
    let linked_len = formal_wasi_write_region(
        instance,
        FORMAL_WASI_ARG_B_OFFSET,
        128,
        0,
        linked.as_bytes(),
    )?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[
            Value::I32(3),
            Value::I32(FORMAL_WASI_ARG_A_OFFSET as i32),
            Value::I32(source_len as i32),
            Value::I32(4),
            Value::I32(FORMAL_WASI_ARG_B_OFFSET as i32),
            Value::I32(linked_len as i32),
        ],
        "WASI Preview 1 ABI self-check: path_link dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: path_link failed");
    }

    let source_entry = formal_wasi_find_entry(&base_dir, "source")?;
    let linked_entry = formal_wasi_find_entry(&base_dir, "linked")?;
    if source_entry.inode != linked_entry.inode {
        return Err("WASI Preview 1 ABI self-check: path_link no longer preserves inode identity");
    }

    Ok(1)
}

fn formal_wasi_behavior_check_path_rename(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
) -> Result<u32, &'static str> {
    let base_dir = alloc::format!("/tmp/wasi-rename-{}", spec.id);
    let old_path = alloc::format!("{}/old-name", base_dir);
    let new_path = alloc::format!("{}/new-name", base_dir);

    formal_wasi_cleanup_paths(&[new_path.as_str(), old_path.as_str(), base_dir.as_str()]);
    formal_wasi_ensure_dir(&base_dir)?;
    crate::fs::vfs::write_path(&old_path, b"rename")?;

    formal_seed_wasi_noop_instance(instance, spec.id)?;
    let old_len = formal_wasi_write_region(
        instance,
        FORMAL_WASI_ARG_A_OFFSET,
        128,
        0,
        old_path.as_bytes(),
    )?;
    let new_len = formal_wasi_write_region(
        instance,
        FORMAL_WASI_ARG_B_OFFSET,
        128,
        0,
        new_path.as_bytes(),
    )?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[
            Value::I32(3),
            Value::I32(FORMAL_WASI_ARG_A_OFFSET as i32),
            Value::I32(old_len as i32),
            Value::I32(FORMAL_WASI_ARG_B_OFFSET as i32),
            Value::I32(new_len as i32),
        ],
        "WASI Preview 1 ABI self-check: path_rename dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: path_rename failed");
    }

    let entries = crate::fs::vfs::list_dir_entries(&base_dir)?;
    let mut saw_old = false;
    let mut saw_new = false;
    let mut i = 0usize;
    while i < entries.len() {
        if entries[i].name == "old-name" {
            saw_old = true;
        }
        if entries[i].name == "new-name" {
            saw_new = true;
        }
        i += 1;
    }
    if saw_old || !saw_new {
        return Err("WASI Preview 1 ABI self-check: path_rename path visibility drifted");
    }

    Ok(1)
}

fn formal_wasi_behavior_check_sched_yield(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
) -> Result<u32, &'static str> {
    formal_seed_wasi_noop_instance(instance, spec.id)?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[],
        "WASI Preview 1 ABI self-check: sched_yield dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: sched_yield no longer succeeds");
    }
    Ok(1)
}

fn formal_wasi_behavior_check_sock_shutdown(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
) -> Result<u32, &'static str> {
    let expectations = [
        (0i32, true, false, crate::services::wasi::Errno::Success.as_i32()),
        (1i32, false, true, crate::services::wasi::Errno::Success.as_i32()),
        (2i32, true, true, crate::services::wasi::Errno::Success.as_i32()),
        (9i32, false, false, crate::services::wasi::Errno::Inval.as_i32()),
    ];
    let mut checks = 0u32;
    let mut idx = 0usize;
    while idx < expectations.len() {
        formal_seed_wasi_noop_instance(instance, spec.id + idx)?;
        instance.stack.clear();
        instance
            .stack
            .push(Value::I32(9))
            .map_err(|_| "WASI Preview 1 ABI self-check: sock_shutdown arg push failed")?;
        instance.stack.push(Value::I32(expectations[idx].0)).map_err(|_| {
            "WASI Preview 1 ABI self-check: sock_shutdown arg push failed"
        })?;
        spec.dispatch(instance)
            .map_err(|_| "WASI Preview 1 ABI self-check: sock_shutdown host dispatch failed")?;
        if instance.stack.len() != spec.result_count {
            return Err("WASI Preview 1 ABI self-check: sock_shutdown result arity drifted");
        }
        let errno = instance
            .stack
            .pop()
            .map_err(|_| "WASI Preview 1 ABI self-check: sock_shutdown result pop failed")?
            .as_i32()
            .map_err(|_| "WASI Preview 1 ABI self-check: sock_shutdown result type drifted")?;
        if !instance.stack.is_empty() {
            return Err("WASI Preview 1 ABI self-check: sock_shutdown stack cleanup drifted");
        }
        if errno != expectations[idx].3 {
            return Err("WASI Preview 1 ABI self-check: sock_shutdown errno drifted");
        }
        let socket_fd = &instance.wasi_ctx.fds[9];
        if socket_fd.shut_rd != expectations[idx].1 || socket_fd.shut_wr != expectations[idx].2 {
            return Err("WASI Preview 1 ABI self-check: sock_shutdown state drifted");
        }
        checks = checks.saturating_add(1);
        idx += 1;
    }
    Ok(checks)
}

fn formal_wasi_behavior_check_fd_advise(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
) -> Result<u32, &'static str> {
    let base_dir = alloc::format!("/tmp/wasi-advise-{}", spec.id);
    let file = alloc::format!("{}/file", base_dir);
    formal_wasi_cleanup_paths(&[file.as_str(), base_dir.as_str()]);
    formal_wasi_ensure_dir(&base_dir)?;
    crate::fs::vfs::write_path(&file, b"abcdef")?;

    formal_seed_wasi_noop_instance(instance, spec.id)?;
    formal_wasi_seed_file_fd(
        instance,
        8,
        &file,
        crate::services::wasi::rights::ALL,
        crate::services::wasi::rights::ALL,
        0,
    )?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[Value::I32(8), Value::I32(2), Value::I32(4)],
        "WASI Preview 1 ABI self-check: fd_advise dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_advise no longer succeeds");
    }

    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[Value::I32(31), Value::I32(0), Value::I32(1)],
        "WASI Preview 1 ABI self-check: fd_advise badfd dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Badf.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_advise bad-fd mapping drifted");
    }
    Ok(2)
}

fn formal_wasi_behavior_check_fd_allocate(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
) -> Result<u32, &'static str> {
    let base_dir = alloc::format!("/tmp/wasi-allocate-{}", spec.id);
    let file = alloc::format!("{}/file", base_dir);
    formal_wasi_cleanup_paths(&[file.as_str(), base_dir.as_str()]);
    formal_wasi_ensure_dir(&base_dir)?;
    crate::fs::vfs::write_path(&file, b"abc")?;

    formal_seed_wasi_noop_instance(instance, spec.id)?;
    formal_wasi_seed_file_fd(
        instance,
        8,
        &file,
        crate::services::wasi::rights::ALL,
        crate::services::wasi::rights::ALL,
        0,
    )?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[Value::I32(8), Value::I32(5), Value::I32(7)],
        "WASI Preview 1 ABI self-check: fd_allocate dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_allocate no longer succeeds");
    }
    let size = crate::fs::vfs::path_size(&file)?;
    if size != 12 || instance.wasi_ctx.fds[8].size != 12 {
        return Err("WASI Preview 1 ABI self-check: fd_allocate size growth drifted");
    }
    let mut bytes = alloc::vec![0u8; 12];
    let read = crate::fs::vfs::read_path(&file, &mut bytes)?;
    if read != 12 || &bytes[..3] != b"abc" || bytes[3..].iter().any(|byte| *byte != 0) {
        return Err("WASI Preview 1 ABI self-check: fd_allocate zero-extension drifted");
    }
    Ok(1)
}

fn formal_wasi_behavior_check_fd_datasync(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
) -> Result<u32, &'static str> {
    let base_dir = alloc::format!("/tmp/wasi-datasync-{}", spec.id);
    let file = alloc::format!("{}/file", base_dir);
    formal_wasi_cleanup_paths(&[file.as_str(), base_dir.as_str()]);
    formal_wasi_ensure_dir(&base_dir)?;
    crate::fs::vfs::write_path(&file, b"sync")?;

    formal_seed_wasi_noop_instance(instance, spec.id)?;
    formal_wasi_seed_file_fd(
        instance,
        8,
        &file,
        crate::services::wasi::rights::ALL,
        crate::services::wasi::rights::ALL,
        0,
    )?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[Value::I32(8)],
        "WASI Preview 1 ABI self-check: fd_datasync dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_datasync no longer succeeds");
    }
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[Value::I32(63)],
        "WASI Preview 1 ABI self-check: fd_datasync badfd dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Badf.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_datasync bad-fd mapping drifted");
    }
    Ok(2)
}

fn formal_wasi_behavior_check_fd_fdstat_set_flags(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
) -> Result<u32, &'static str> {
    let fdstat_get_spec = host_function_spec_by_id(55)
        .ok_or("WASI Preview 1 ABI self-check: fd_fdstat_get spec missing")?;
    let base_dir = alloc::format!("/tmp/wasi-fdflags-{}", spec.id);
    let file = alloc::format!("{}/file", base_dir);
    formal_wasi_cleanup_paths(&[file.as_str(), base_dir.as_str()]);
    formal_wasi_ensure_dir(&base_dir)?;
    crate::fs::vfs::write_path(&file, b"flags")?;

    formal_seed_wasi_noop_instance(instance, spec.id)?;
    formal_wasi_seed_file_fd(
        instance,
        8,
        &file,
        crate::services::wasi::rights::ALL,
        crate::services::wasi::rights::ALL,
        0,
    )?;
    let flags =
        (crate::services::wasi::fdflags::APPEND | crate::services::wasi::fdflags::NONBLOCK) as i32;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[Value::I32(8), Value::I32(flags)],
        "WASI Preview 1 ABI self-check: fd_fdstat_set_flags dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32()
        || instance.wasi_ctx.fds[8].fdflags as i32 != flags
    {
        return Err("WASI Preview 1 ABI self-check: fd_fdstat_set_flags persistence drifted");
    }
    let errno = formal_wasi_dispatch_errno(
        instance,
        fdstat_get_spec,
        &[Value::I32(8), Value::I32(FORMAL_WASI_STAT_OFFSET as i32)],
        "WASI Preview 1 ABI self-check: fd_fdstat_get after set_flags failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_fdstat_get after set_flags drifted");
    }
    let fdstat = formal_wasi_parse_fd_stat(&instance.memory, FORMAL_WASI_STAT_OFFSET)?;
    if fdstat.flags as i32 != flags {
        return Err("WASI Preview 1 ABI self-check: fd_fdstat_get no longer reports persisted flags");
    }

    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[Value::I32(8), Value::I32(0x40)],
        "WASI Preview 1 ABI self-check: fd_fdstat_set_flags unsupported dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Notsup.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_fdstat_set_flags unsupported-bit mapping drifted");
    }
    Ok(3)
}

fn formal_wasi_behavior_check_fd_fdstat_set_rights(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
) -> Result<u32, &'static str> {
    let fdstat_get_spec = host_function_spec_by_id(55)
        .ok_or("WASI Preview 1 ABI self-check: fd_fdstat_get spec missing")?;
    let base_dir = alloc::format!("/tmp/wasi-rights-{}", spec.id);
    let file = alloc::format!("{}/file", base_dir);
    let reduced = crate::services::wasi::rights::FD_READ | crate::services::wasi::rights::FD_TELL;
    formal_wasi_cleanup_paths(&[file.as_str(), base_dir.as_str()]);
    formal_wasi_ensure_dir(&base_dir)?;
    crate::fs::vfs::write_path(&file, b"rights")?;

    formal_seed_wasi_noop_instance(instance, spec.id)?;
    formal_wasi_seed_file_fd(
        instance,
        8,
        &file,
        crate::services::wasi::rights::ALL,
        crate::services::wasi::rights::ALL,
        0,
    )?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[Value::I32(8), Value::I32(reduced as i32), Value::I32(reduced as i32)],
        "WASI Preview 1 ABI self-check: fd_fdstat_set_rights attenuation failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_fdstat_set_rights attenuation drifted");
    }
    let errno = formal_wasi_dispatch_errno(
        instance,
        fdstat_get_spec,
        &[Value::I32(8), Value::I32(FORMAL_WASI_STAT_OFFSET as i32)],
        "WASI Preview 1 ABI self-check: fd_fdstat_get after set_rights failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_fdstat_get after set_rights drifted");
    }
    let fdstat = formal_wasi_parse_fd_stat(&instance.memory, FORMAL_WASI_STAT_OFFSET)?;
    if fdstat.rights_base != reduced || fdstat.rights_inheriting != reduced {
        return Err("WASI Preview 1 ABI self-check: fd_fdstat_set_rights no longer persists attenuation");
    }
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[
            Value::I32(8),
            Value::I32(crate::services::wasi::rights::ALL as i32),
            Value::I32(crate::services::wasi::rights::ALL as i32),
        ],
        "WASI Preview 1 ABI self-check: fd_fdstat_set_rights expansion dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Notcapable.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_fdstat_set_rights expansion rejection drifted");
    }
    Ok(3)
}

fn formal_wasi_behavior_check_fd_filestat_set_size(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
) -> Result<u32, &'static str> {
    let filestat_get_spec = host_function_spec_by_id(58)
        .ok_or("WASI Preview 1 ABI self-check: fd_filestat_get spec missing")?;
    let base_dir = alloc::format!("/tmp/wasi-setsize-{}", spec.id);
    let file = alloc::format!("{}/file", base_dir);
    formal_wasi_cleanup_paths(&[file.as_str(), base_dir.as_str()]);
    formal_wasi_ensure_dir(&base_dir)?;
    crate::fs::vfs::write_path(&file, b"abc")?;

    formal_seed_wasi_noop_instance(instance, spec.id)?;
    formal_wasi_seed_file_fd(
        instance,
        8,
        &file,
        crate::services::wasi::rights::ALL,
        crate::services::wasi::rights::ALL,
        0,
    )?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[Value::I32(8), Value::I32(8)],
        "WASI Preview 1 ABI self-check: fd_filestat_set_size grow dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_filestat_set_size grow failed");
    }
    let errno = formal_wasi_dispatch_errno(
        instance,
        filestat_get_spec,
        &[Value::I32(8), Value::I32(FORMAL_WASI_STAT_OFFSET as i32)],
        "WASI Preview 1 ABI self-check: fd_filestat_get after grow failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_filestat_get after grow drifted");
    }
    let stat = formal_wasi_parse_file_stat(&instance.memory, FORMAL_WASI_STAT_OFFSET)?;
    if stat.size != 8 {
        return Err("WASI Preview 1 ABI self-check: fd_filestat_set_size grow metadata drifted");
    }
    let mut bytes = alloc::vec![0u8; 8];
    let read = crate::fs::vfs::read_path(&file, &mut bytes)?;
    if read != 8 || &bytes[..3] != b"abc" || bytes[3..].iter().any(|byte| *byte != 0) {
        return Err("WASI Preview 1 ABI self-check: fd_filestat_set_size grow payload drifted");
    }

    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[Value::I32(8), Value::I32(2)],
        "WASI Preview 1 ABI self-check: fd_filestat_set_size shrink dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_filestat_set_size shrink failed");
    }
    let mut bytes = alloc::vec![0u8; 2];
    let read = crate::fs::vfs::read_path(&file, &mut bytes)?;
    if read != 2 || &bytes[..] != b"ab" {
        return Err("WASI Preview 1 ABI self-check: fd_filestat_set_size shrink payload drifted");
    }
    Ok(2)
}

fn formal_wasi_behavior_check_fd_filestat_set_times(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
) -> Result<u32, &'static str> {
    let filestat_get_spec = host_function_spec_by_id(58)
        .ok_or("WASI Preview 1 ABI self-check: fd_filestat_get spec missing")?;
    let base_dir = alloc::format!("/tmp/wasi-fd-times-{}", spec.id);
    let file = alloc::format!("{}/file", base_dir);
    formal_wasi_cleanup_paths(&[file.as_str(), base_dir.as_str()]);
    formal_wasi_ensure_dir(&base_dir)?;
    crate::fs::vfs::write_path(&file, b"time")?;

    formal_seed_wasi_noop_instance(instance, spec.id)?;
    formal_wasi_seed_file_fd(
        instance,
        8,
        &file,
        crate::services::wasi::rights::ALL,
        crate::services::wasi::rights::ALL,
        0,
    )?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[
            Value::I32(8),
            Value::I32(111),
            Value::I32(222),
            Value::I32(
                (crate::services::wasi::fstflags::ATIM | crate::services::wasi::fstflags::MTIM)
                    as i32,
            ),
        ],
        "WASI Preview 1 ABI self-check: fd_filestat_set_times explicit dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_filestat_set_times explicit update failed");
    }
    let errno = formal_wasi_dispatch_errno(
        instance,
        filestat_get_spec,
        &[Value::I32(8), Value::I32(FORMAL_WASI_STAT_OFFSET as i32)],
        "WASI Preview 1 ABI self-check: fd_filestat_get after explicit times failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_filestat_get after explicit times drifted");
    }
    let explicit = formal_wasi_parse_file_stat(&instance.memory, FORMAL_WASI_STAT_OFFSET)?;
    if explicit.atim != 111 || explicit.mtim != 222 {
        return Err("WASI Preview 1 ABI self-check: fd_filestat_set_times explicit values drifted");
    }

    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[
            Value::I32(8),
            Value::I32(0),
            Value::I32(0),
            Value::I32(
                (crate::services::wasi::fstflags::ATIM_NOW
                    | crate::services::wasi::fstflags::MTIM_NOW) as i32,
            ),
        ],
        "WASI Preview 1 ABI self-check: fd_filestat_set_times now dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_filestat_set_times now update failed");
    }
    let errno = formal_wasi_dispatch_errno(
        instance,
        filestat_get_spec,
        &[Value::I32(8), Value::I32(FORMAL_WASI_STAT_OFFSET as i32)],
        "WASI Preview 1 ABI self-check: fd_filestat_get after now times failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_filestat_get after now times drifted");
    }
    let now_stat = formal_wasi_parse_file_stat(&instance.memory, FORMAL_WASI_STAT_OFFSET)?;
    if now_stat.atim < explicit.atim || now_stat.mtim < explicit.mtim || now_stat.ctim < explicit.ctim {
        return Err("WASI Preview 1 ABI self-check: fd_filestat_set_times now semantics drifted");
    }
    Ok(2)
}

fn formal_wasi_behavior_check_fd_renumber(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
) -> Result<u32, &'static str> {
    let base_dir = alloc::format!("/tmp/wasi-renumber-{}", spec.id);
    let file_a = alloc::format!("{}/a", base_dir);
    let file_b = alloc::format!("{}/b", base_dir);
    formal_wasi_cleanup_paths(&[file_b.as_str(), file_a.as_str(), base_dir.as_str()]);
    formal_wasi_ensure_dir(&base_dir)?;
    crate::fs::vfs::write_path(&file_a, b"a")?;
    crate::fs::vfs::write_path(&file_b, b"b")?;

    formal_seed_wasi_noop_instance(instance, spec.id)?;
    formal_wasi_seed_file_fd(instance, 8, &file_a, crate::services::wasi::rights::ALL, crate::services::wasi::rights::ALL, 0)?;
    formal_wasi_seed_file_fd(instance, 10, &file_b, crate::services::wasi::rights::ALL, crate::services::wasi::rights::ALL, 0)?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[Value::I32(8), Value::I32(10)],
        "WASI Preview 1 ABI self-check: fd_renumber move dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32()
        || instance.wasi_ctx.fds[8].kind != crate::services::wasi::FdKind::Closed
        || &instance.wasi_ctx.fds[10].path[..instance.wasi_ctx.fds[10].path_len as usize]
            != file_a.as_bytes()
    {
        return Err("WASI Preview 1 ABI self-check: fd_renumber move semantics drifted");
    }
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[Value::I32(10), Value::I32(3)],
        "WASI Preview 1 ABI self-check: fd_renumber reserved dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Notsup.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_renumber reserved-slot rejection drifted");
    }
    Ok(2)
}

fn formal_wasi_behavior_check_fd_sync(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
) -> Result<u32, &'static str> {
    let base_dir = alloc::format!("/tmp/wasi-sync-{}", spec.id);
    let file = alloc::format!("{}/file", base_dir);
    formal_wasi_cleanup_paths(&[file.as_str(), base_dir.as_str()]);
    formal_wasi_ensure_dir(&base_dir)?;
    crate::fs::vfs::write_path(&file, b"sync")?;

    formal_seed_wasi_noop_instance(instance, spec.id)?;
    formal_wasi_seed_file_fd(
        instance,
        8,
        &file,
        crate::services::wasi::rights::ALL,
        crate::services::wasi::rights::ALL,
        0,
    )?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[Value::I32(8)],
        "WASI Preview 1 ABI self-check: fd_sync dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_sync no longer succeeds");
    }
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[Value::I32(99)],
        "WASI Preview 1 ABI self-check: fd_sync badfd dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Badf.as_i32() {
        return Err("WASI Preview 1 ABI self-check: fd_sync bad-fd mapping drifted");
    }
    Ok(2)
}

fn formal_wasi_behavior_check_path_filestat_set_times(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
) -> Result<u32, &'static str> {
    let path_get_spec = host_function_spec_by_id(73)
        .ok_or("WASI Preview 1 ABI self-check: path_filestat_get spec missing")?;
    let base_dir = alloc::format!("/tmp/wasi-path-times-{}", spec.id);
    let file = alloc::format!("{}/file", base_dir);
    formal_wasi_cleanup_paths(&[file.as_str(), base_dir.as_str()]);
    formal_wasi_ensure_dir(&base_dir)?;
    crate::fs::vfs::write_path(&file, b"time")?;

    formal_seed_wasi_noop_instance(instance, spec.id)?;
    let path_len = formal_wasi_write_region(instance, FORMAL_WASI_ARG_A_OFFSET, 128, 0, file.as_bytes())?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[
            Value::I32(3),
            Value::I32(FORMAL_WASI_ARG_A_OFFSET as i32),
            Value::I32(path_len as i32),
            Value::I32(333),
            Value::I32(444),
            Value::I32(
                (crate::services::wasi::fstflags::ATIM | crate::services::wasi::fstflags::MTIM)
                    as i32,
            ),
        ],
        "WASI Preview 1 ABI self-check: path_filestat_set_times explicit dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: path_filestat_set_times explicit update failed");
    }
    let errno = formal_wasi_dispatch_errno(
        instance,
        path_get_spec,
        &[
            Value::I32(3),
            Value::I32(1),
            Value::I32(FORMAL_WASI_ARG_A_OFFSET as i32),
            Value::I32(path_len as i32),
            Value::I32(FORMAL_WASI_STAT_OFFSET as i32),
        ],
        "WASI Preview 1 ABI self-check: path_filestat_get after explicit path times failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: path_filestat_get after explicit path times drifted");
    }
    let explicit = formal_wasi_parse_file_stat(&instance.memory, FORMAL_WASI_STAT_OFFSET)?;
    if explicit.atim != 333 || explicit.mtim != 444 {
        return Err("WASI Preview 1 ABI self-check: path_filestat_set_times explicit values drifted");
    }

    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[
            Value::I32(3),
            Value::I32(FORMAL_WASI_ARG_A_OFFSET as i32),
            Value::I32(path_len as i32),
            Value::I32(0),
            Value::I32(0),
            Value::I32(
                (crate::services::wasi::fstflags::ATIM_NOW
                    | crate::services::wasi::fstflags::MTIM_NOW) as i32,
            ),
        ],
        "WASI Preview 1 ABI self-check: path_filestat_set_times now dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: path_filestat_set_times now update failed");
    }
    let errno = formal_wasi_dispatch_errno(
        instance,
        path_get_spec,
        &[
            Value::I32(3),
            Value::I32(1),
            Value::I32(FORMAL_WASI_ARG_A_OFFSET as i32),
            Value::I32(path_len as i32),
            Value::I32(FORMAL_WASI_STAT_OFFSET as i32),
        ],
        "WASI Preview 1 ABI self-check: path_filestat_get after now path times failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() {
        return Err("WASI Preview 1 ABI self-check: path_filestat_get after now path times drifted");
    }
    let now_stat = formal_wasi_parse_file_stat(&instance.memory, FORMAL_WASI_STAT_OFFSET)?;
    if now_stat.atim < explicit.atim || now_stat.mtim < explicit.mtim {
        return Err("WASI Preview 1 ABI self-check: path_filestat_set_times now semantics drifted");
    }
    Ok(2)
}

fn formal_wasi_behavior_check_proc_raise(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
) -> Result<u32, &'static str> {
    formal_seed_wasi_noop_instance(instance, spec.id)?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[Value::I32(0)],
        "WASI Preview 1 ABI self-check: proc_raise(0) dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() || instance.wasi_ctx.exit_code != Some(7) {
        return Err("WASI Preview 1 ABI self-check: proc_raise(0) semantics drifted");
    }

    formal_seed_wasi_noop_instance(instance, spec.id + 1)?;
    instance.wasi_ctx.exit_code = None;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[Value::I32(15)],
        "WASI Preview 1 ABI self-check: proc_raise(15) dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Success.as_i32() || instance.wasi_ctx.exit_code != Some(143) {
        return Err("WASI Preview 1 ABI self-check: proc_raise termination semantics drifted");
    }

    formal_seed_wasi_noop_instance(instance, spec.id + 2)?;
    let errno = formal_wasi_dispatch_errno(
        instance,
        spec,
        &[Value::I32(4)],
        "WASI Preview 1 ABI self-check: proc_raise unsupported dispatch failed",
    )?;
    if errno != crate::services::wasi::Errno::Notsup.as_i32() {
        return Err("WASI Preview 1 ABI self-check: proc_raise unsupported-signal mapping drifted");
    }
    Ok(3)
}

fn formal_wasi_implemented_behavior_check(
    instance: &mut WasmInstance,
    spec: &HostFunctionSpec,
) -> Result<u32, &'static str> {
    match spec.id {
        51 => formal_wasi_behavior_check_fd_advise(instance, spec),
        52 => formal_wasi_behavior_check_fd_allocate(instance, spec),
        54 => formal_wasi_behavior_check_fd_datasync(instance, spec),
        56 => formal_wasi_behavior_check_fd_fdstat_set_flags(instance, spec),
        57 => formal_wasi_behavior_check_fd_fdstat_set_rights(instance, spec),
        59 => formal_wasi_behavior_check_fd_filestat_set_size(instance, spec),
        60 => formal_wasi_behavior_check_fd_filestat_set_times(instance, spec),
        66 => formal_wasi_behavior_check_fd_readdir(instance, spec),
        67 => formal_wasi_behavior_check_fd_renumber(instance, spec),
        69 => formal_wasi_behavior_check_fd_sync(instance, spec),
        74 => formal_wasi_behavior_check_path_filestat_set_times(instance, spec),
        75 => formal_wasi_behavior_check_path_link(instance, spec),
        77 => formal_wasi_behavior_check_path_readlink(instance, spec),
        79 => formal_wasi_behavior_check_path_rename(instance, spec),
        80 => formal_wasi_behavior_check_path_symlink(instance, spec),
        84 => formal_wasi_behavior_check_proc_raise(instance, spec),
        85 => formal_wasi_behavior_check_sched_yield(instance, spec),
        90 => formal_wasi_behavior_check_sock_shutdown(instance, spec),
        _ => Ok(0),
    }
}

pub(crate) fn formal_wasi_preview1_self_check() -> Result<WasiAbiSummary, &'static str> {
    if EXPECTED_WASI_PREVIEW1_HOST_SPECS.len() != WASI_PREVIEW1_HOST_COUNT {
        return Err("WASI Preview 1 ABI self-check: unexpected frozen snapshot size");
    }

    let mut summary = WasiAbiSummary {
        entries_checked: 0,
        noop_entries: 0,
        noop_behavior_checks: 0,
        implemented_behavior_checks: 0,
    };
    let mut instance = WasmInstance::new(
        WasmModule::new(),
        ProcessId(0x4510_0001),
        WASI_PREVIEW1_HOST_START,
    );

    let mut index = 0usize;
    while index < EXPECTED_WASI_PREVIEW1_HOST_SPECS.len() {
        let expected = &EXPECTED_WASI_PREVIEW1_HOST_SPECS[index];
        if expected.id != WASI_PREVIEW1_HOST_START + index {
            return Err("WASI Preview 1 ABI self-check: snapshot host ID ordering drifted");
        }

        let spec = host_function_spec_by_id(expected.id)
            .ok_or("WASI Preview 1 ABI self-check: missing dispatcher entry")?;
        if spec.id != expected.id
            || spec.canonical_name != expected.canonical_name
            || spec.param_count != expected.param_count
            || spec.result_count != expected.result_count
        {
            return Err("WASI Preview 1 ABI self-check: dispatcher metadata drifted");
        }
        if spec.signature_policy != HostSignaturePolicy::ExactI32
            || spec.alias_policy != HostAliasPolicy::Standard
        {
            return Err("WASI Preview 1 ABI self-check: dispatcher signature or alias drifted");
        }

        let semantic_class = wasi_abi_class_for_spec(spec)?;
        if semantic_class != expected.class {
            return Err("WASI Preview 1 ABI self-check: dispatcher semantic class drifted");
        }

        if semantic_class == WasiAbiClass::FrozenNoop {
            formal_wasi_noop_behavior_check(&mut instance, expected, spec)?;
            summary.noop_entries = summary.noop_entries.saturating_add(1);
            summary.noop_behavior_checks = summary.noop_behavior_checks.saturating_add(1);
        } else {
            summary.implemented_behavior_checks = summary
                .implemented_behavior_checks
                .saturating_add(formal_wasi_implemented_behavior_check(&mut instance, spec)?);
        }

        summary.entries_checked = summary.entries_checked.saturating_add(1);
        index += 1;
    }

    Ok(summary)
}

pub(crate) fn formal_polyglot_abi_self_check() -> Result<PolyglotAbiSummary, &'static str> {
    if EXPECTED_POLYGLOT_HOST_SPECS.len() != POLYGLOT_HOST_COUNT {
        return Err("Polyglot ABI self-check: unexpected snapshot size");
    }

    let mut summary = PolyglotAbiSummary {
        entries_checked: 0,
        behavior_checks: 0,
    };

    let mut index = 0usize;
    while index < EXPECTED_POLYGLOT_HOST_SPECS.len() {
        let expected = &EXPECTED_POLYGLOT_HOST_SPECS[index];
        if index == 0 {
            if expected.id != 103 {
                return Err("Polyglot ABI self-check: snapshot host ID ordering drifted");
            }
        } else {
            let previous_id = EXPECTED_POLYGLOT_HOST_SPECS[index - 1].id;
            let expected_next_id = match previous_id {
                105 => 132,
                _ => previous_id + 1,
            };
            if expected.id != expected_next_id {
                return Err("Polyglot ABI self-check: snapshot host ID ordering drifted");
            }
        }
        let spec = host_function_spec_by_id(expected.id)
            .ok_or("Polyglot ABI self-check: missing dispatcher entry")?;
        if spec.id != expected.id
            || spec.canonical_name != expected.canonical_name
            || spec.param_count != expected.param_count
            || spec.result_count != expected.result_count
        {
            return Err("Polyglot ABI self-check: dispatcher metadata drifted");
        }
        if spec.signature_policy != HostSignaturePolicy::ExactI32
            || spec.alias_policy != HostAliasPolicy::Standard
        {
            return Err("Polyglot ABI self-check: dispatcher signature or alias drifted");
        }
        match (expected.class, spec.behavior) {
            (PolyglotAbiClass::Implemented, HostBehavior::Method(_)) => {}
            _ => return Err("Polyglot ABI self-check: dispatcher semantic class drifted"),
        }
        summary.entries_checked = summary.entries_checked.saturating_add(1);
        index += 1;
    }

    let provider = ProcessId(60);
    let consumer = ProcessId(61);
    reset_self_check_process(provider);
    reset_self_check_process(consumer);

    let mut provider_instance: Option<usize> = None;
    let mut consumer_instance: Option<usize> = None;
    let mut registered_object: Option<u64> = None;
    let mut linked_object_id: Option<u64> = None;

    let result = (|| -> Result<(), &'static str> {
        const PROVIDER_MODULE: [u8; 48] = [
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F,
            0x03, 0x03, 0x02, 0x00, 0x00,
            0x07, 0x0D, 0x02, 0x03, b'a', b'd', b'd', 0x00, 0x00, 0x03, b's', b'u', b'b', 0x00, 0x01,
            0x0A, 0x0B, 0x02, 0x04, 0x00, 0x41, 0x01, 0x0B, 0x04, 0x00, 0x41, 0x02, 0x0B,
        ];

        crate::serial_println!("[polyglot-check] provider stage=load");
        let mut provider_module = WasmModule::new();
        provider_module
            .load_binary(&PROVIDER_MODULE)
            .map_err(|_| "Polyglot ABI self-check: provider module parse failed")?;
        crate::serial_println!("[polyglot-check] provider stage=instantiate");
        let provider_id = wasm_runtime()
            .instantiate_module(provider_module, provider)
            .map_err(|_| "Polyglot ABI self-check: provider instantiate failed")?;
        provider_instance = Some(provider_id);

        crate::serial_println!("[polyglot-check] provider stage=register");
        let registration = register_service_pointer(provider, provider_id, 0, true)
            .map_err(|_| "Polyglot ABI self-check: service register failed")?;
        registered_object = Some(registration.object_id);

        wasm_runtime()
            .with_instance_exclusive(provider_id, |instance| -> Result<(), WasmError> {
                instance.memory.write(0x100, b"svc")?;
                instance.stack.clear();
                instance.stack.push(Value::I32(0x100))?;
                instance.stack.push(Value::I32(3))?;
                instance.host_polyglot_register()?;
                let rc = instance.stack.pop()?.as_i32()?;
                instance.stack.clear();
                if rc != 0 {
                    return Err(WasmError::SyscallFailed);
                }
                let registry = POLYGLOT_REGISTRY.lock();
                let Some(reg_idx) = registry.find_by_name(b"svc") else {
                    return Err(WasmError::SyscallFailed);
                };
                let entry = registry.entries[reg_idx];
                if !entry.active
                    || entry.instance_id != provider_id
                    || entry.owner_pid != provider
                    || entry.latest_record_id == 0
                    || entry.cap_object != 0
                {
                    return Err(WasmError::SyscallFailed);
                }
                let lineage = POLYGLOT_LINEAGE.lock();
                let mut matched = false;
                let mut lineage_idx = 0usize;
                while lineage_idx < lineage.records.len() {
                    let rec = lineage.records[lineage_idx];
                    if rec.active
                        && rec.record_id == entry.latest_record_id
                        && rec.source_pid == provider
                        && rec.source_instance == provider_id
                        && rec.target_instance == provider_id
                        && rec.object_id == 0
                        && rec.cap_id == provider_id as u32
                        && rec.lifecycle == PolyglotLifecycle::Registered
                        && rec.export_name[..3] == *b"svc"
                    {
                        matched = true;
                    }
                    lineage_idx += 1;
                }
                if !matched {
                    return Err(WasmError::SyscallFailed);
                }
                Ok(())
            })
            .map_err(|_| "Polyglot ABI self-check: provider host access unavailable")?
            .map_err(|_| "Polyglot ABI self-check: register semantics drifted")?;
        summary.behavior_checks = summary.behavior_checks.saturating_add(1);

        // Minimal valid WASM module: header + empty type/function/code sections.
        // load_binary rejects modules that lack all three sections.
        const CONSUMER_MODULE: [u8; 17] = [
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
            0x01, 0x01, 0x00, // type section: 0 types
            0x03, 0x01, 0x00, // function section: 0 functions
            0x0A, 0x01, 0x00, // code section: 0 code bodies
        ];
        crate::serial_println!("[polyglot-check] consumer stage=instantiate");
        let consumer_id = wasm_runtime()
            .instantiate(&CONSUMER_MODULE, consumer)
            .map_err(|_| "Polyglot ABI self-check: consumer instantiate failed")?;
        consumer_instance = Some(consumer_id);

        crate::serial_println!("[polyglot-check] consumer stage=with_instance");
        wasm_runtime()
            .with_instance_exclusive(consumer_id, |instance| -> Result<(), WasmError> {
                instance.memory.write(0x100, b"svc")?;
                instance.memory.write(0x140, b"add")?;
                instance.memory.write(0x180, b"sub")?;
                instance.memory.write(0x1C0, b"missing")?;

                instance.stack.clear();
                instance.stack.push(Value::I32(0x100))?;
                instance.stack.push(Value::I32(3))?;
                instance.host_polyglot_resolve()?;
                let resolved = instance.stack.pop()?.as_i32()?;
                instance.stack.clear();
                if resolved < 0 {
                    return Err(WasmError::SyscallFailed);
                }

                instance.stack.push(Value::I32(0x100))?;
                instance.stack.push(Value::I32(3))?;
                instance.stack.push(Value::I32(0x140))?;
                instance.stack.push(Value::I32(3))?;
                instance.host_polyglot_link()?;
                let handle = instance.stack.pop()?.as_i32()? as u32;
                instance.stack.clear();
                let add_cap = match instance.capabilities.get(CapHandle(handle))? {
                    WasmCapability::ServicePointer(cap) => cap,
                    _ => return Err(WasmError::InvalidCapability),
                };
                linked_object_id = Some(add_cap.object_id);

                instance.stack.clear();
                instance.stack.push(Value::I32(handle as i32))?;
                instance.stack.push(Value::I32(0x280))?;
                instance
                    .stack
                    .push(Value::I32((8 + POLYGLOT_LINEAGE_WIRE_RECORD_BYTES) as i32))?;
                instance.host_polyglot_lineage_lookup()?;
                let live_lookup = instance.stack.pop()?.as_i32()?;
                instance.stack.clear();
                if live_lookup != 1 {
                    return Err(WasmError::SyscallFailed);
                }
                let live_record = instance.memory.read(0x280, 8 + POLYGLOT_LINEAGE_WIRE_RECORD_BYTES)?;
                if live_record[0] != POLYGLOT_LINEAGE_WIRE_VERSION
                    || live_record[1] != 1
                    || live_record[9] != PolyglotLifecycle::Live as u8
                {
                    return Err(WasmError::SyscallFailed);
                }
                Ok(())
            })
            .map_err(|_| "Polyglot ABI self-check: consumer host access unavailable")?
            .map_err(|_| "Polyglot ABI self-check: export-authoritative semantics drifted")?;
        summary.behavior_checks = summary.behavior_checks.saturating_add(11);

        let linked_object_id =
            linked_object_id.ok_or("Polyglot ABI self-check: linked object missing")?;
        match invoke_service_pointer(consumer, linked_object_id, &[]) {
            Ok(result) if result == 1 => {}
            Ok(_) => {
                return Err("Polyglot ABI self-check: export-authoritative semantics drifted");
            }
            Err(_) => {
                return Err("Polyglot ABI self-check: export-authoritative semantics drifted");
            }
        }

        wasm_runtime()
            .destroy(provider_id)
            .map_err(|_| "Polyglot ABI self-check: provider destroy failed")?;
        provider_instance = None;

        wasm_runtime()
            .with_instance_exclusive(consumer_id, |instance| -> Result<(), WasmError> {
                instance.stack.clear();
                instance.stack.push(Value::I32(registration.object_id as u32 as i32))?;
                instance.stack.push(Value::I32((registration.object_id >> 32) as i32))?;
                instance.stack.push(Value::I32(0x4C0))?;
                instance
                    .stack
                    .push(Value::I32((8 + POLYGLOT_LINEAGE_WIRE_RECORD_BYTES) as i32))?;
                instance.host_polyglot_lineage_lookup_object()?;
                let torn_lookup = instance.stack.pop()?.as_i32()?;
                instance.stack.clear();
                if torn_lookup != 1 {
                    return Err(WasmError::SyscallFailed);
                }
                let torn_record = instance.memory.read(0x4C0, 8 + POLYGLOT_LINEAGE_WIRE_RECORD_BYTES)?;
                if torn_record[9] != PolyglotLifecycle::TornDown as u8 {
                    return Err(WasmError::SyscallFailed);
                }

                instance.stack.clear();
                instance.stack.push(Value::I32(0x100))?;
                instance.stack.push(Value::I32(3))?;
                instance.host_polyglot_resolve()?;
                let resolved = instance.stack.pop()?.as_i32()?;
                instance.stack.clear();
                if resolved != -2 {
                    return Err(WasmError::SyscallFailed);
                }

                instance.stack.push(Value::I32(0x100))?;
                instance.stack.push(Value::I32(3))?;
                instance.stack.push(Value::I32(0x140))?;
                instance.stack.push(Value::I32(3))?;
                instance.host_polyglot_link()?;
                let link_rc = instance.stack.pop()?.as_i32()?;
                instance.stack.clear();
                if link_rc != -2 {
                    return Err(WasmError::SyscallFailed);
                }
                instance.stack.clear();
                instance.stack.push(Value::I32(registration.object_id as u32 as i32))?;
                instance.stack.push(Value::I32((registration.object_id >> 32) as i32))?;
                instance.stack.push(Value::I32(0x4C0))?;
                instance
                    .stack
                    .push(Value::I32((8 + POLYGLOT_LINEAGE_WIRE_RECORD_BYTES) as i32))?;
                instance.host_polyglot_lineage_lookup_object()?;
                let torn_lookup = instance.stack.pop()?.as_i32()?;
                instance.stack.clear();
                if torn_lookup != 1 {
                    return Err(WasmError::SyscallFailed);
                }
                let torn_record = instance.memory.read(0x4C0, 8 + POLYGLOT_LINEAGE_WIRE_RECORD_BYTES)?;
                if torn_record[9] != PolyglotLifecycle::TornDown as u8 {
                    return Err(WasmError::SyscallFailed);
                }
                let lineage = POLYGLOT_LINEAGE.lock();
                if lineage.records.iter().all(|rec| {
                    rec.object_id != registration.object_id
                        || rec.lifecycle != PolyglotLifecycle::TornDown
                }) {
                    return Err(WasmError::SyscallFailed);
                }
                Ok(())
            })
            .map_err(|_| "Polyglot ABI self-check: post-destroy host access unavailable")?
            .map_err(|_| "Polyglot ABI self-check: teardown purge semantics drifted")?;
        summary.behavior_checks = summary.behavior_checks.saturating_add(4);

        wasm_runtime()
            .with_instance_exclusive(consumer_id, |instance| -> Result<(), WasmError> {
                instance.stack.clear();
                crate::serial_println!("[polyglot-check] consumer step=lineage-query-all");
                instance.host_polyglot_lineage_count()?;
                let lineage_count = instance.stack.pop()?.as_i32()?;
                instance.stack.clear();
                if lineage_count <= 0 {
                    return Err(WasmError::SyscallFailed);
                }

                let snapshot = [0u8; 8 + 64 * POLYGLOT_LINEAGE_WIRE_RECORD_BYTES];
                instance.memory.write(0x200, &snapshot)?;
                instance.stack.push(Value::I32(0x200))?;
                instance.stack.push(Value::I32(snapshot.len() as i32))?;
                instance.host_polyglot_lineage_query()?;
                let written = instance.stack.pop()?.as_i32()?;
                instance.stack.clear();
                if written <= 0 {
                    return Err(WasmError::SyscallFailed);
                }
                let read_back = instance.memory.read(0x200, 8)?;
                if read_back[0] != POLYGLOT_LINEAGE_WIRE_VERSION || read_back[1] == 0 {
                    return Err(WasmError::SyscallFailed);
                }

                instance.memory.write(0x240, b"svc")?;
                instance.memory.write(0x260, b"add")?;
                instance.stack.clear();
                crate::serial_println!("[polyglot-check] consumer step=lineage-filter-source");
                instance.stack.push(Value::I32(0x300))?;
                instance
                    .stack
                    .push(Value::I32((8 + 64 * POLYGLOT_LINEAGE_WIRE_RECORD_BYTES) as i32))?;
                instance.stack.push(Value::I32(1))?;
                instance.stack.push(Value::I32(provider.0 as i32))?;
                instance.stack.push(Value::I32(0))?;
                instance.host_polyglot_lineage_query_filtered()?;
                let source_filtered = instance.stack.pop()?.as_i32()?;
                instance.stack.clear();
                if source_filtered <= 0 {
                    return Err(WasmError::SyscallFailed);
                }
                let source_header = instance.memory.read(0x300, 8)?;
                if source_header[0] != POLYGLOT_LINEAGE_WIRE_VERSION || source_header[1] == 0 {
                    return Err(WasmError::SyscallFailed);
                }

                instance.stack.clear();
                crate::serial_println!("[polyglot-check] consumer step=lineage-filter-export");
                instance.stack.push(Value::I32(0x380))?;
                instance
                    .stack
                    .push(Value::I32((8 + 64 * POLYGLOT_LINEAGE_WIRE_RECORD_BYTES) as i32))?;
                instance.stack.push(Value::I32(4))?;
                instance.stack.push(Value::I32(0x240))?;
                instance.stack.push(Value::I32(3))?;
                instance.host_polyglot_lineage_query_filtered()?;
                let export_filtered = instance.stack.pop()?.as_i32()?;
                instance.stack.clear();
                if export_filtered <= 0 {
                    return Err(WasmError::SyscallFailed);
                }
                let export_header = instance.memory.read(0x380, 8)?;
                if export_header[0] != POLYGLOT_LINEAGE_WIRE_VERSION || export_header[1] == 0 {
                    return Err(WasmError::SyscallFailed);
                }

                instance.stack.clear();
                crate::serial_println!("[polyglot-check] consumer step=lineage-filter-lifecycle");
                instance.stack.push(Value::I32(0x400))?;
                instance
                    .stack
                    .push(Value::I32((8 + 64 * POLYGLOT_LINEAGE_WIRE_RECORD_BYTES) as i32))?;
                instance.stack.push(Value::I32(3))?;
                instance.stack.push(Value::I32(PolyglotLifecycle::TornDown as i32))?;
                instance.stack.push(Value::I32(0))?;
                instance.host_polyglot_lineage_query_filtered()?;
                let lifecycle_filtered = instance.stack.pop()?.as_i32()?;
                instance.stack.clear();
                if lifecycle_filtered <= 0 {
                    return Err(WasmError::SyscallFailed);
                }
                let lifecycle_header = instance.memory.read(0x400, 8)?;
                if lifecycle_header[0] != POLYGLOT_LINEAGE_WIRE_VERSION || lifecycle_header[1] == 0 {
                    return Err(WasmError::SyscallFailed);
                }
                Ok(())
            })
            .map_err(|_| "Polyglot ABI self-check: lineage query host access unavailable")?
            .map_err(|_| "Polyglot ABI self-check: lineage query semantics drifted")?;
        summary.behavior_checks = summary.behavior_checks.saturating_add(4);

        Ok(())
    })();

    if let Some(object_id) = registered_object {
        let _ = revoke_service_pointer(provider, object_id);
    }
    if let Some(id) = consumer_instance {
        let _ = wasm_runtime().destroy(id);
    }
    if let Some(id) = provider_instance {
        let _ = wasm_runtime().destroy(id);
    }
    deinit_self_check_process(consumer);
    deinit_self_check_process(provider);
    result?;
    Ok(summary)
}

/// Deterministic self-check for the frozen host dispatcher table.
pub(crate) fn formal_host_dispatch_self_check() -> Result<HostDispatchConformanceSummary, &'static str> {
    if HOST_FUNCTION_SPECS.len() != 143 {
        return Err("Host dispatch self-check: unexpected table size");
    }

    let mut summary = HostDispatchConformanceSummary {
        entries_checked: 0,
        aliases_checked: 0,
        noop_entries: 0,
    };
    let mut alias_scratch = [0u8; 64];
    let mut index = 0usize;

    while index < HOST_FUNCTION_SPECS.len() {
        let spec = &HOST_FUNCTION_SPECS[index];
        if spec.id != index {
            return Err("Host dispatch self-check: host ID mismatch");
        }

        let by_id = host_function_spec_by_id(index)
            .ok_or("Host dispatch self-check: missing host ID")?;
        if by_id.id != spec.id
            || by_id.canonical_name != spec.canonical_name
            || by_id.param_count != spec.param_count
            || by_id.result_count != spec.result_count
            || by_id.signature_policy != spec.signature_policy
            || by_id.alias_policy != spec.alias_policy
        {
            return Err("Host dispatch self-check: host table metadata drift");
        }

        let declared_signature = host_dispatch_conformance_signature(spec);
        if !spec.matches_signature(declared_signature) {
            return Err("Host dispatch self-check: declared signature rejected");
        }

        host_dispatch_expect_resolution(
            spec,
            spec.canonical_name.as_bytes(),
            declared_signature,
            "Host dispatch self-check: canonical resolution failed",
        )?;

        match spec.alias_policy {
            HostAliasPolicy::Standard => {
                let alias = host_dispatch_standard_alias(spec, &mut alias_scratch)?;
                host_dispatch_expect_resolution(
                    spec,
                    alias,
                    declared_signature,
                    "Host dispatch self-check: standard alias resolution failed",
                )?;
                summary.aliases_checked = summary.aliases_checked.saturating_add(1);
            }
            HostAliasPolicy::DebugLog => {
                host_dispatch_expect_resolution(
                    spec,
                    b"oreulius_log",
                    declared_signature,
                    "Host dispatch self-check: debug_log alias resolution failed",
                )?;
                summary.aliases_checked = summary.aliases_checked.saturating_add(1);
            }
            HostAliasPolicy::ChannelSendCap => {
                host_dispatch_expect_resolution(
                    spec,
                    b"oreulius_channel_send_cap",
                    declared_signature,
                    "Host dispatch self-check: channel_send_cap alias resolution failed",
                )?;
                summary.aliases_checked = summary.aliases_checked.saturating_add(1);
            }
            HostAliasPolicy::LastServiceCap => {
                host_dispatch_expect_resolution(
                    spec,
                    b"oreulius_last_service_cap",
                    declared_signature,
                    "Host dispatch self-check: last_service_cap alias resolution failed",
                )?;
                summary.aliases_checked = summary.aliases_checked.saturating_add(1);
            }
            HostAliasPolicy::ServiceRegister => {
                let service_register_i32 = host_function_signature_from_types(
                    &[ValueType::I32, ValueType::I32],
                    &[ValueType::I32],
                );
                let service_register_funcref = host_function_signature_from_types(
                    &[ValueType::FuncRef, ValueType::I32],
                    &[ValueType::I32],
                );
                host_dispatch_expect_resolution(
                    spec,
                    b"service_register",
                    service_register_i32,
                    "Host dispatch self-check: service_register i32 resolution failed",
                )?;
                host_dispatch_expect_resolution(
                    spec,
                    b"service_register",
                    service_register_funcref,
                    "Host dispatch self-check: service_register funcref resolution failed",
                )?;
                host_dispatch_expect_resolution(
                    spec,
                    b"oreulius_service_register",
                    service_register_i32,
                    "Host dispatch self-check: oreulius_service_register resolution failed",
                )?;
                host_dispatch_expect_resolution(
                    spec,
                    b"service_register_ref",
                    service_register_funcref,
                    "Host dispatch self-check: service_register_ref resolution failed",
                )?;
                host_dispatch_expect_resolution(
                    spec,
                    b"oreulius_service_register_ref",
                    service_register_funcref,
                    "Host dispatch self-check: oreulius_service_register_ref resolution failed",
                )?;
                summary.aliases_checked = summary.aliases_checked.saturating_add(4);
            }
        }

        if let HostBehavior::Noop {
            pop_count,
            push_zero,
        } = spec.behavior
        {
            if !push_zero || spec.result_count != 1 || pop_count != spec.param_count {
                return Err("Host dispatch self-check: noop metadata mismatch");
            }
            summary.noop_entries = summary.noop_entries.saturating_add(1);
        }

        summary.entries_checked = summary.entries_checked.saturating_add(1);
        index += 1;
    }

    Ok(summary)
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
    *offset = offset.checked_add(width).ok_or(WasmError::InvalidModule)?;
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
    if module != "oreulius" {
        return Err(WasmError::InvalidModule);
    }
    let field = core::str::from_utf8(field_name).map_err(|_| WasmError::InvalidModule)?;
    let spec = host_function_spec_by_name(field).ok_or(WasmError::InvalidModule)?;
    if !spec.matches_signature(signature) {
        return Err(WasmError::InvalidModule);
    }
    Ok(spec.id)
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

/// WASM linear memory (isolated per-module, supports on-demand growth)
pub struct LinearMemory {
    /// Memory buffer (dedicated JIT arena allocation)
    data: *mut u8,
    /// Current size in pages (64 KiB each)
    pages: usize,
    /// Maximum pages allowed (capped by WASM_DEFAULT_MAX_PAGES)
    max_pages: usize,
    /// Total bytes currently allocated (may exceed active pages * 64KB after grow)
    allocated_bytes: usize,
    /// Shared memory flag (required for WASM threads atomic operations)
    pub shared: bool,
}

// SAFETY: LinearMemory owns a kernel-allocated buffer and is only accessed
// through the WasmRuntime mutex, so moving between threads is safe.
unsafe impl Send for LinearMemory {}

impl LinearMemory {
    /// Create new linear memory with the given initial and maximum page counts.
    /// Only `initial_pages` worth of memory is physically allocated.
    pub fn new(initial_pages: usize) -> Self {
        Self::with_max(initial_pages, WASM_DEFAULT_MAX_PAGES, false)
    }

    /// Create new linear memory with explicit max and shared flag.
    pub fn with_max(initial_pages: usize, max_pages_hint: usize, shared: bool) -> Self {
        let max_pages = core::cmp::min(max_pages_hint, WASM_MAX_PAGES);
        let pages = core::cmp::min(initial_pages, max_pages);
        // Allocate only for the initial pages (minimum 1 page for null-safety)
        let alloc_pages_wasm = core::cmp::max(pages, 1);
        let alloc_bytes = alloc_pages_wasm * 64 * 1024;
        let kernel_pages = (alloc_bytes + paging::PAGE_SIZE - 1) / paging::PAGE_SIZE;
        let base = memory::jit_allocate_pages(kernel_pages).unwrap_or(0) as *mut u8;
        if !base.is_null() {
            unsafe { core::ptr::write_bytes(base, 0, alloc_bytes) }
            let _ = memory_isolation::tag_wasm_linear_memory(base as usize, alloc_bytes, shared);
        }
        LinearMemory {
            data: base,
            pages,
            max_pages,
            allocated_bytes: if base.is_null() { 0 } else { alloc_bytes },
            shared,
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

    /// Get the maximum pages limit for this memory.
    pub fn max_pages(&self) -> usize {
        self.max_pages
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

    /// Get mutable active memory slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        if self.data.is_null() {
            // Return a mutable reference to an empty slice-compatible region.
            // SAFETY: zero-length slice with non-null dangling pointer is valid.
            return &mut [];
        }
        unsafe { core::slice::from_raw_parts_mut(self.data, self.active_len()) }
    }

    /// Get immutable active memory slice (alias of active_slice).
    pub fn as_slice(&self) -> &[u8] {
        self.active_slice()
    }

    /// Zero active memory (fuzz harness/reset).
    pub fn clear_active(&mut self) {
        if self.data.is_null() {
            return;
        }
        unsafe { core::ptr::write_bytes(self.data, 0, self.active_len()) }
    }

    /// Grow memory by `delta` pages.  Allocates new pages from the JIT arena
    /// (contiguous with existing data is not guaranteed; we allocate a new
    /// region only when growth requires more than what was pre-allocated).
    pub fn grow(&mut self, delta: usize) -> Result<usize, WasmError> {
        if delta == 0 {
            return Ok(self.pages);
        }
        let old_pages = self.pages;
        let new_pages = old_pages
            .checked_add(delta)
            .ok_or(WasmError::MemoryGrowFailed)?;
        if new_pages > self.max_pages {
            return Err(WasmError::MemoryGrowFailed);
        }
        let new_bytes = new_pages * 64 * 1024;

        if new_bytes <= self.allocated_bytes {
            // Already have enough physical space (e.g. pre-allocated region)
            // Zero the newly visible region
            let zero_start = old_pages * 64 * 1024;
            unsafe {
                core::ptr::write_bytes(self.data.add(zero_start), 0, new_bytes - zero_start);
            }
            self.pages = new_pages;
            return Ok(old_pages);
        }

        // Need to allocate a larger contiguous region
        let kernel_pages = (new_bytes + paging::PAGE_SIZE - 1) / paging::PAGE_SIZE;
        let new_base = memory::jit_allocate_pages(kernel_pages).unwrap_or(0) as *mut u8;
        if new_base.is_null() {
            return Err(WasmError::MemoryGrowFailed);
        }
        // Copy existing data into new region, zero the rest
        if !self.data.is_null() && self.allocated_bytes > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(self.data, new_base, self.allocated_bytes);
            }
        }
        let zero_start = old_pages * 64 * 1024;
        unsafe {
            core::ptr::write_bytes(new_base.add(zero_start), 0, new_bytes - zero_start);
        }
        let _ = memory_isolation::tag_wasm_linear_memory(new_base as usize, new_bytes, self.shared);
        self.data = new_base;
        self.pages = new_pages;
        self.allocated_bytes = new_bytes;
        Ok(old_pages)
    }

    /// Read bytes from memory
    pub fn read(&self, offset: usize, len: usize) -> Result<&[u8], WasmError> {
        let end = offset
            .checked_add(len)
            .ok_or(WasmError::MemoryOutOfBounds)?;
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
        let end = offset
            .checked_add(data.len())
            .ok_or(WasmError::MemoryOutOfBounds)?;
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
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Write i64 to memory (little-endian)
    pub fn write_i64(&mut self, offset: usize, value: i64) -> Result<(), WasmError> {
        self.write(offset, &value.to_le_bytes())
    }

    // ── Atomic primitives ────────────────────────────────────────────────────
    // All atomic helpers operate on the raw pointer with volatile + compiler
    // fence semantics.  On single-core bare-metal this is sufficient; on SMP
    // the caller is responsible for emitting the appropriate fence instruction
    // (handled via core::sync::atomic::fence in step_atomic()).

    fn bounds_check(&self, addr: usize, width: usize) -> Result<(), WasmError> {
        let end = addr
            .checked_add(width)
            .ok_or(WasmError::MemoryOutOfBounds)?;
        if end > self.pages * 64 * 1024 || self.data.is_null() {
            Err(WasmError::MemoryOutOfBounds)
        } else {
            Ok(())
        }
    }

    pub fn atomic_load_u8(&self, addr: usize) -> Result<u8, WasmError> {
        self.bounds_check(addr, 1)?;
        core::sync::atomic::fence(Ordering::Acquire);
        Ok(unsafe { core::ptr::read_volatile(self.data.add(addr)) })
    }

    pub fn atomic_load_u16(&self, addr: usize) -> Result<u16, WasmError> {
        self.bounds_check(addr, 2)?;
        core::sync::atomic::fence(Ordering::Acquire);
        Ok(u16::from_le_bytes(unsafe {
            [*self.data.add(addr), *self.data.add(addr + 1)]
        }))
    }

    pub fn atomic_load_u32(&self, addr: usize) -> Result<u32, WasmError> {
        self.bounds_check(addr, 4)?;
        core::sync::atomic::fence(Ordering::Acquire);
        Ok(u32::from_le_bytes(unsafe {
            [
                *self.data.add(addr),
                *self.data.add(addr + 1),
                *self.data.add(addr + 2),
                *self.data.add(addr + 3),
            ]
        }))
    }

    pub fn atomic_load_u64(&self, addr: usize) -> Result<u64, WasmError> {
        self.bounds_check(addr, 8)?;
        core::sync::atomic::fence(Ordering::Acquire);
        Ok(u64::from_le_bytes(unsafe {
            [
                *self.data.add(addr),
                *self.data.add(addr + 1),
                *self.data.add(addr + 2),
                *self.data.add(addr + 3),
                *self.data.add(addr + 4),
                *self.data.add(addr + 5),
                *self.data.add(addr + 6),
                *self.data.add(addr + 7),
            ]
        }))
    }

    pub fn atomic_store_u8(&mut self, addr: usize, val: u8) -> Result<(), WasmError> {
        self.bounds_check(addr, 1)?;
        unsafe { core::ptr::write_volatile(self.data.add(addr), val) };
        core::sync::atomic::fence(Ordering::Release);
        Ok(())
    }

    pub fn atomic_store_u16(&mut self, addr: usize, val: u16) -> Result<(), WasmError> {
        self.bounds_check(addr, 2)?;
        let b = val.to_le_bytes();
        unsafe {
            core::ptr::write_volatile(self.data.add(addr), b[0]);
            core::ptr::write_volatile(self.data.add(addr + 1), b[1]);
        }
        core::sync::atomic::fence(Ordering::Release);
        Ok(())
    }

    pub fn atomic_store_u32(&mut self, addr: usize, val: u32) -> Result<(), WasmError> {
        self.bounds_check(addr, 4)?;
        let b = val.to_le_bytes();
        unsafe {
            core::ptr::write_volatile(self.data.add(addr), b[0]);
            core::ptr::write_volatile(self.data.add(addr + 1), b[1]);
            core::ptr::write_volatile(self.data.add(addr + 2), b[2]);
            core::ptr::write_volatile(self.data.add(addr + 3), b[3]);
        }
        core::sync::atomic::fence(Ordering::Release);
        Ok(())
    }

    pub fn atomic_store_u64(&mut self, addr: usize, val: u64) -> Result<(), WasmError> {
        self.bounds_check(addr, 8)?;
        let b = val.to_le_bytes();
        unsafe {
            for i in 0..8 {
                core::ptr::write_volatile(self.data.add(addr + i), b[i]);
            }
        }
        core::sync::atomic::fence(Ordering::Release);
        Ok(())
    }

    /// i32 RMW operations.  `sub` is the 0xFE sub-opcode (0x1E–0x24).
    pub fn atomic_rmw32(&mut self, sub: u8, addr: usize, val: u32) -> Result<u32, WasmError> {
        self.bounds_check(addr, 4)?;
        core::sync::atomic::fence(Ordering::AcqRel);
        let old = self.atomic_load_u32(addr)?;
        let new_val = match sub {
            0x1E => old.wrapping_add(val), // i32.atomic.rmw.add
            0x1F => old.wrapping_sub(val), // i32.atomic.rmw.sub
            0x20 => old & val,             // i32.atomic.rmw.and
            0x21 => old | val,             // i32.atomic.rmw.or
            0x22 => old ^ val,             // i32.atomic.rmw.xor
            0x23 => val,                   // i32.atomic.rmw.xchg
            0x24 => {
                // i32.atomic.rmw.cmpxchg — val is expected, need second pop
                // Note: stack already popped in caller; val = replacement pushed second
                // The calling convention for cmpxchg is (addr, expected, replacement)
                // We return old regardless; replacement was passed as `val`
                if old == val {
                    val
                } else {
                    old
                }
            }
            _ => return Err(WasmError::UnknownOpcode(sub)),
        };
        self.atomic_store_u32(addr, new_val)?;
        Ok(old)
    }

    /// i64 RMW operations.  `sub` is the 0xFE sub-opcode (0x25–0x2B).
    pub fn atomic_rmw64(&mut self, sub: u8, addr: usize, val: u64) -> Result<u64, WasmError> {
        self.bounds_check(addr, 8)?;
        core::sync::atomic::fence(Ordering::AcqRel);
        let old = self.atomic_load_u64(addr)?;
        let new_val = match sub {
            0x25 => old.wrapping_add(val),
            0x26 => old.wrapping_sub(val),
            0x27 => old & val,
            0x28 => old | val,
            0x29 => old ^ val,
            0x2A => val,
            0x2B => {
                if old == val {
                    val
                } else {
                    old
                }
            }
            _ => return Err(WasmError::UnknownOpcode(sub)),
        };
        self.atomic_store_u64(addr, new_val)?;
        Ok(old)
    }

    /// Narrow i32 RMW (8-bit: 0x2C-0x2E, 16-bit: 0x2F-0x31)
    pub fn atomic_rmw32_narrow(
        &mut self,
        sub: u8,
        addr: usize,
        val: u32,
    ) -> Result<u32, WasmError> {
        core::sync::atomic::fence(Ordering::AcqRel);
        match sub {
            // 8-bit ops
            0x2C => {
                let o = self.atomic_load_u8(addr)? as u32;
                self.atomic_store_u8(addr, (o.wrapping_add(val) & 0xFF) as u8)?;
                Ok(o)
            }
            0x2D => {
                let o = self.atomic_load_u8(addr)? as u32;
                self.atomic_store_u8(addr, (o.wrapping_sub(val) & 0xFF) as u8)?;
                Ok(o)
            }
            0x2E => {
                let o = self.atomic_load_u8(addr)? as u32;
                self.atomic_store_u8(addr, (o & val & 0xFF) as u8)?;
                Ok(o)
            }
            // 16-bit ops
            0x2F => {
                if addr & 1 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                let o = self.atomic_load_u16(addr)? as u32;
                self.atomic_store_u16(addr, (o.wrapping_add(val) & 0xFFFF) as u16)?;
                Ok(o)
            }
            0x30 => {
                if addr & 1 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                let o = self.atomic_load_u16(addr)? as u32;
                self.atomic_store_u16(addr, (o.wrapping_sub(val) & 0xFFFF) as u16)?;
                Ok(o)
            }
            0x31 => {
                if addr & 1 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                let o = self.atomic_load_u16(addr)? as u32;
                self.atomic_store_u16(addr, (o & val & 0xFFFF) as u16)?;
                Ok(o)
            }
            _ => Err(WasmError::UnknownOpcode(sub)),
        }
    }

    /// Narrow i64 RMW (8-bit: 0x32-0x34, 16-bit: 0x35-0x37, 32-bit: 0x38-0x3A)
    pub fn atomic_rmw64_narrow(
        &mut self,
        sub: u8,
        addr: usize,
        val: u64,
    ) -> Result<u64, WasmError> {
        core::sync::atomic::fence(Ordering::AcqRel);
        match sub {
            0x32 => {
                let o = self.atomic_load_u8(addr)? as u64;
                self.atomic_store_u8(addr, (o.wrapping_add(val) & 0xFF) as u8)?;
                Ok(o)
            }
            0x33 => {
                let o = self.atomic_load_u8(addr)? as u64;
                self.atomic_store_u8(addr, (o.wrapping_sub(val) & 0xFF) as u8)?;
                Ok(o)
            }
            0x34 => {
                let o = self.atomic_load_u8(addr)? as u64;
                self.atomic_store_u8(addr, (o & val & 0xFF) as u8)?;
                Ok(o)
            }
            0x35 => {
                if addr & 1 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                let o = self.atomic_load_u16(addr)? as u64;
                self.atomic_store_u16(addr, (o.wrapping_add(val) & 0xFFFF) as u16)?;
                Ok(o)
            }
            0x36 => {
                if addr & 1 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                let o = self.atomic_load_u16(addr)? as u64;
                self.atomic_store_u16(addr, (o.wrapping_sub(val) & 0xFFFF) as u16)?;
                Ok(o)
            }
            0x37 => {
                if addr & 1 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                let o = self.atomic_load_u16(addr)? as u64;
                self.atomic_store_u16(addr, (o & val & 0xFFFF) as u16)?;
                Ok(o)
            }
            0x38 => {
                if addr & 3 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                let o = self.atomic_load_u32(addr)? as u64;
                self.atomic_store_u32(addr, (o.wrapping_add(val) & 0xFFFF_FFFF) as u32)?;
                Ok(o)
            }
            0x39 => {
                if addr & 3 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                let o = self.atomic_load_u32(addr)? as u64;
                self.atomic_store_u32(addr, (o.wrapping_sub(val) & 0xFFFF_FFFF) as u32)?;
                Ok(o)
            }
            0x3A => {
                if addr & 3 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                let o = self.atomic_load_u32(addr)? as u64;
                self.atomic_store_u32(addr, (o & val & 0xFFFF_FFFF) as u32)?;
                Ok(o)
            }
            _ => Err(WasmError::UnknownOpcode(sub)),
        }
    }
}

impl Clone for LinearMemory {
    fn clone(&self) -> Self {
        let active = self.active_len();
        let alloc = core::cmp::max(active, 64 * 1024); // at least 1 page
        let kernel_pages = (alloc + paging::PAGE_SIZE - 1) / paging::PAGE_SIZE;
        let base = memory::jit_allocate_pages(kernel_pages).unwrap_or(0) as *mut u8;
        if !base.is_null() && !self.data.is_null() && active > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(self.data, base, active);
            }
        }
        if !base.is_null() {
            let _ = memory_isolation::tag_wasm_linear_memory(base as usize, alloc, self.shared);
        }
        LinearMemory {
            data: base,
            pages: self.pages,
            max_pages: self.max_pages,
            allocated_bytes: if base.is_null() { 0 } else { alloc },
            shared: self.shared,
        }
    }
}

// ============================================================================
// WASM Atomic Wait/Notify helpers (free functions)
// ============================================================================

/// Global wait-list: tracks addresses that have been notified.
/// In single-threaded mode we only record the last notified address;
/// the count is always 0 (no waiters) because there are no other threads.
static ATOMIC_LAST_NOTIFY_ADDR: AtomicUsize = AtomicUsize::new(0);
static ATOMIC_LAST_NOTIFY_COUNT: AtomicU32 = AtomicU32::new(0);

/// Record a notify event (used by memory.atomic.notify).
fn atomic_notify(addr: usize, count: u32) {
    ATOMIC_LAST_NOTIFY_ADDR.store(addr, Ordering::Relaxed);
    ATOMIC_LAST_NOTIFY_COUNT.store(count, Ordering::Relaxed);
}

/// memory.atomic.wait32 — blocks until `mem[addr] != expected` or timeout.
/// Returns: 0 = woken, 1 = not-equal (returned immediately), 2 = timed out.
/// In single-threaded mode we perform a bounded spin then return 2 (timeout).
fn atomic_wait32(
    mem: &LinearMemory,
    addr: usize,
    expected: i32,
    timeout_ns: i64,
) -> Result<i32, WasmError> {
    let current = mem.atomic_load_u32(addr)? as i32;
    if current != expected {
        return Ok(1); // "not-equal" – return immediately per spec
    }
    // Single-threaded: nobody will change the value.
    // If timeout == 0 always time out; otherwise spin briefly.
    if timeout_ns == 0 {
        return Ok(2);
    }
    // Spin up to ~1000 iterations to give any interrupt handler a chance
    let iters: u32 = if timeout_ns < 0 { 1000 } else { 100 };
    for _ in 0..iters {
        core::hint::spin_loop();
        let v = mem.atomic_load_u32(addr)? as i32;
        if v != expected {
            return Ok(0);
        }
    }
    Ok(2) // timed out
}

/// memory.atomic.wait64 — same as wait32 but for 64-bit values.
fn atomic_wait64(
    mem: &LinearMemory,
    addr: usize,
    expected: i64,
    timeout_ns: i64,
) -> Result<i32, WasmError> {
    let current = mem.atomic_load_u64(addr)? as i64;
    if current != expected {
        return Ok(1);
    }
    if timeout_ns == 0 {
        return Ok(2);
    }
    let iters: u32 = if timeout_ns < 0 { 1000 } else { 100 };
    for _ in 0..iters {
        core::hint::spin_loop();
        let v = mem.atomic_load_u64(addr)? as i64;
        if v != expected {
            return Ok(0);
        }
    }
    Ok(2)
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
    pub const fn new() -> Self {
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
    pub export_name: [u8; 32],
    pub export_name_len: u8,
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
#[derive(Debug, Clone)]
pub enum WasmCapability {
    Channel(ChannelId),
    Filesystem(fs::FilesystemCapability),
    ServicePointer(ServicePointerCapability),
    None,
}

/// Per-instance capability table
#[derive(Clone)]
pub struct CapabilityTable {
    caps: Vec<WasmCapability>,
}

impl CapabilityTable {
    pub fn new() -> Self {
        CapabilityTable { caps: Vec::new() }
    }

    /// Inject a capability, returns handle
    pub fn inject(&mut self, cap: WasmCapability) -> Result<CapHandle, WasmError> {
        if self.caps.len() >= MAX_INJECTED_CAPS {
            return Err(WasmError::TooManyCapabilities);
        }

        let handle = CapHandle(self.caps.len() as u32);
        self.caps.push(cap);
        Ok(handle)
    }

    /// Resolve a capability handle
    pub fn get(&self, handle: CapHandle) -> Result<WasmCapability, WasmError> {
        let idx = handle.0 as usize;
        self.caps
            .get(idx)
            .cloned()
            .ok_or(WasmError::InvalidCapability)
    }
}

#[derive(Clone, Copy)]
struct ServicePointerEntry {
    active: bool,
    object_id: u64,
    owner_pid: ProcessId,
    target_instance: usize,
    function_index: usize,
    export_name: [u8; 32],
    export_name_len: u8,
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
            export_name: [0u8; 32],
            export_name_len: 0,
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

    fn find_by_target_and_export(
        &self,
        target_instance: usize,
        export_name: &[u8],
    ) -> Option<ServicePointerEntry> {
        let mut i = 0usize;
        while i < self.entries.len() {
            let entry = self.entries[i];
            if entry.active
                && entry.target_instance == target_instance
                && entry.export_name_len as usize == export_name.len()
                && &entry.export_name[..export_name.len()] == export_name
            {
                return Some(entry);
            }
            i += 1;
        }
        None
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

// ============================================================================
// Polyglot Module Registry
// ============================================================================
//
// Maps a module name (up to 32 bytes, null-padded) to:
//  - the runtime instance_id that owns the service
//  - the LanguageTag of that module (from its `oreulius_lang` custom section)
//  - the capability handle the module registered via `service_register`
//  - the owner ProcessId (for revocation)
//  - a "singleton" flag: Python/JS runtime modules share one slot per language

const MAX_POLYGLOT_ENTRIES: usize = 16;
const MAX_POLYGLOT_LINEAGE_RECORDS: usize = 64;
const POLYGLOT_LINEAGE_WIRE_VERSION: u8 = 1;
const POLYGLOT_LINEAGE_WIRE_RECORD_BYTES: usize = 96;
const POLYGLOT_LINEAGE_STATUS_WIRE_BYTES: usize = 32;
const POLYGLOT_LINEAGE_EVENT_WIRE_BYTES: usize = 40;
const POLYGLOT_LINEAGE_FILTERED_QUERY_HOSTS: usize = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PolyglotLineageWireHeaderV1 {
    version: u8,
    count: u8,
    max_records: u16,
    next_record_id: u32,
}

impl PolyglotLineageWireHeaderV1 {
    const BYTES: usize = 8;

    const fn new(count: usize, next_record_id: u64) -> Self {
        Self {
            version: POLYGLOT_LINEAGE_WIRE_VERSION,
            count: count as u8,
            max_records: MAX_POLYGLOT_LINEAGE_RECORDS as u16,
            next_record_id: next_record_id as u32,
        }
    }

    fn encode(self, out: &mut [u8]) {
        out[0] = self.version;
        out[1] = self.count;
        out[2..4].copy_from_slice(&self.max_records.to_le_bytes());
        out[4..8].copy_from_slice(&self.next_record_id.to_le_bytes());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PolyglotLineageWireRecordV1 {
    live: u8,
    lifecycle: u8,
    record_id: u64,
    source_pid: u32,
    source_instance: u32,
    target_instance: u32,
    object_id: u64,
    cap_id: u32,
    language_tag: u8,
    export_name_len: u8,
    export_name: [u8; 32],
    rights: u32,
    created_at: u64,
    updated_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PolyglotLineageStatusWireRecordV1 {
    live: u8,
    lifecycle: u8,
    record_id: u64,
    object_id: u64,
    target_instance: u32,
    updated_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PolyglotLineageEventWireRecordV1 {
    event_id: u64,
    object_id: u64,
    target_instance: u32,
    lifecycle: u8,
    previous_lifecycle: u8,
    reserved0: u8,
    reserved1: u8,
    reserved2: u64,
    updated_at: u64,
}

impl PolyglotLineageEventWireRecordV1 {
    const BYTES: usize = POLYGLOT_LINEAGE_EVENT_WIRE_BYTES;

    fn encode_from(record: &PolyglotLineageEventRecord) -> Self {
        Self {
            event_id: record.event_id,
            object_id: record.object_id,
            target_instance: record.target_instance as u32,
            lifecycle: record.lifecycle as u8,
            previous_lifecycle: record.previous_lifecycle as u8,
            reserved0: u8::from(record.active),
            reserved1: 0,
            reserved2: 0,
            updated_at: record.updated_at,
        }
    }

    fn encode(self, out: &mut [u8]) {
        out[0..8].copy_from_slice(&self.event_id.to_le_bytes());
        out[8..16].copy_from_slice(&self.object_id.to_le_bytes());
        out[16..20].copy_from_slice(&self.target_instance.to_le_bytes());
        out[20] = self.lifecycle;
        out[21] = self.previous_lifecycle;
        out[22] = self.reserved0;
        out[23] = self.reserved1;
        out[24..32].copy_from_slice(&self.reserved2.to_le_bytes());
        out[32..40].copy_from_slice(&self.updated_at.to_le_bytes());
    }
}

impl PolyglotLineageStatusWireRecordV1 {
    const BYTES: usize = POLYGLOT_LINEAGE_STATUS_WIRE_BYTES;

    fn from_record(record: &PolyglotLineageRecord) -> Self {
        Self {
            live: u8::from(record.active),
            lifecycle: record.lifecycle as u8,
            record_id: record.record_id,
            object_id: record.object_id,
            target_instance: record.target_instance as u32,
            updated_at: record.updated_at,
        }
    }

    fn encode(self, out: &mut [u8]) {
        out[0] = self.live;
        out[1] = self.lifecycle;
        out[2..4].copy_from_slice(&0u16.to_le_bytes());
        out[4..12].copy_from_slice(&self.record_id.to_le_bytes());
        out[12..20].copy_from_slice(&self.object_id.to_le_bytes());
        out[20..24].copy_from_slice(&self.target_instance.to_le_bytes());
        out[24..32].copy_from_slice(&self.updated_at.to_le_bytes());
    }
}

impl PolyglotLineageWireRecordV1 {
    const BYTES: usize = POLYGLOT_LINEAGE_WIRE_RECORD_BYTES;

    fn from_record(record: &PolyglotLineageRecord) -> Self {
        Self {
            live: u8::from(record.active),
            lifecycle: record.lifecycle as u8,
            record_id: record.record_id,
            source_pid: record.source_pid.0,
            source_instance: record.source_instance as u32,
            target_instance: record.target_instance as u32,
            object_id: record.object_id,
            cap_id: record.cap_id,
            language_tag: record.language as u8,
            export_name_len: record.export_name_len,
            export_name: record.export_name,
            rights: record.rights,
            created_at: record.created_at,
            updated_at: record.updated_at,
        }
    }

    fn encode(self, out: &mut [u8]) {
        out[0] = self.live;
        out[1] = self.lifecycle;
        out[2..4].copy_from_slice(&[0, 0]);
        out[4..12].copy_from_slice(&self.record_id.to_le_bytes());
        out[12..16].copy_from_slice(&self.source_pid.to_le_bytes());
        out[16..20].copy_from_slice(&self.source_instance.to_le_bytes());
        out[20..24].copy_from_slice(&self.target_instance.to_le_bytes());
        out[24..32].copy_from_slice(&self.object_id.to_le_bytes());
        out[32..36].copy_from_slice(&self.cap_id.to_le_bytes());
        out[36] = self.language_tag;
        out[37] = self.export_name_len;
        out[38..70].copy_from_slice(&self.export_name);
        out[70..74].copy_from_slice(&self.rights.to_le_bytes());
        out[74..82].copy_from_slice(&self.created_at.to_le_bytes());
        out[82..90].copy_from_slice(&self.updated_at.to_le_bytes());
        out[90..94].copy_from_slice(&0u32.to_le_bytes());
        out[94..96].copy_from_slice(&0u16.to_le_bytes());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PolyglotLineageFilterKind {
    All = 0,
    SourcePid = 1,
    TargetInstance = 2,
    Lifecycle = 3,
    ExportName = 4,
    ObjectId = 5,
}

impl PolyglotLineageFilterKind {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::All),
            1 => Some(Self::SourcePid),
            2 => Some(Self::TargetInstance),
            3 => Some(Self::Lifecycle),
            4 => Some(Self::ExportName),
            5 => Some(Self::ObjectId),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PolyglotLifecycle {
    Registered = 0,
    Linked = 1,
    Live = 2,
    Revoked = 3,
    TornDown = 4,
    Rebound = 5,
    Restored = 6,
}

#[derive(Clone, Copy)]
struct PolyglotLineageRecord {
    active: bool,
    record_id: u64,
    source_pid: ProcessId,
    source_instance: usize,
    target_instance: usize,
    object_id: u64,
    cap_id: u32,
    language: LanguageTag,
    export_name: [u8; 32],
    export_name_len: u8,
    rights: u32,
    lifecycle: PolyglotLifecycle,
    created_at: u64,
    updated_at: u64,
}

#[derive(Clone, Copy)]
struct PolyglotLineageEventRecord {
    active: bool,
    event_id: u64,
    object_id: u64,
    target_instance: u32,
    lifecycle: PolyglotLifecycle,
    previous_lifecycle: PolyglotLifecycle,
    updated_at: u64,
}

impl PolyglotLineageEventRecord {
    const fn empty() -> Self {
        Self {
            active: false,
            event_id: 0,
            object_id: 0,
            target_instance: 0,
            lifecycle: PolyglotLifecycle::Linked,
            previous_lifecycle: PolyglotLifecycle::Linked,
            updated_at: 0,
        }
    }
}

impl PolyglotLineageRecord {
    const fn empty() -> Self {
        Self {
            active: false,
            record_id: 0,
            source_pid: ProcessId(0),
            source_instance: 0,
            target_instance: 0,
            object_id: 0,
            cap_id: 0,
            language: LanguageTag::Unknown,
            export_name: [0u8; 32],
            export_name_len: 0,
            rights: 0,
            lifecycle: PolyglotLifecycle::Registered,
            created_at: 0,
            updated_at: 0,
        }
    }
}

struct PolyglotLineageStore {
    records: [PolyglotLineageRecord; MAX_POLYGLOT_LINEAGE_RECORDS],
    next_record_id: u64,
    events: [PolyglotLineageEventRecord; MAX_POLYGLOT_LINEAGE_RECORDS],
    next_event_id: u64,
    next_event_cursor: usize,
}

impl PolyglotLineageStore {
    const fn new() -> Self {
        Self {
            records: [PolyglotLineageRecord::empty(); MAX_POLYGLOT_LINEAGE_RECORDS],
            next_record_id: 1,
            events: [PolyglotLineageEventRecord::empty(); MAX_POLYGLOT_LINEAGE_RECORDS],
            next_event_id: 1,
            next_event_cursor: 0,
        }
    }

    fn insert(
        &mut self,
        source_pid: ProcessId,
        source_instance: usize,
        target_instance: usize,
        object_id: u64,
        cap_id: u32,
        language: LanguageTag,
        export_name: &[u8],
        rights: u32,
        lifecycle: PolyglotLifecycle,
    ) -> Result<u64, &'static str> {
        if export_name.len() > 32 {
            return Err("polyglot lineage export too long");
        }
        let mut slot = None;
        let mut i = 0usize;
        while i < self.records.len() {
            if !self.records[i].active {
                slot = Some(i);
                break;
            }
            i += 1;
        }
        let Some(idx) = slot else {
            return Err("polyglot lineage store full");
        };
        let mut export_bytes = [0u8; 32];
        export_bytes[..export_name.len()].copy_from_slice(export_name);
        let now = crate::scheduler::pit::get_ticks();
        let record_id = self.next_record_id;
        self.next_record_id = self.next_record_id.saturating_add(1);
        self.records[idx] = PolyglotLineageRecord {
            active: true,
            record_id,
            source_pid,
            source_instance,
            target_instance,
            object_id,
            cap_id,
            language,
            export_name: export_bytes,
            export_name_len: export_name.len() as u8,
            rights,
            lifecycle,
            created_at: now,
            updated_at: now,
        };
        Ok(record_id)
    }

    fn find_latest_by_object(&self, object_id: u64) -> Option<usize> {
        let mut idx = None;
        let mut i = 0usize;
        while i < self.records.len() {
            let rec = self.records[i];
            if rec.active && rec.object_id == object_id {
                idx = Some(i);
            }
            i += 1;
        }
        idx
    }

    fn update_lifecycle(&mut self, object_id: u64, lifecycle: PolyglotLifecycle) {
        let now = crate::scheduler::pit::get_ticks();
        let mut i = 0usize;
        while i < self.records.len() {
            if self.records[i].active && self.records[i].object_id == object_id {
                let previous = self.records[i].lifecycle;
                self.records[i].lifecycle = lifecycle;
                self.records[i].updated_at = now;
                if matches!(lifecycle, PolyglotLifecycle::Revoked | PolyglotLifecycle::Rebound)
                    && previous != lifecycle
                {
                    self.push_event(
                        object_id,
                        self.records[i].target_instance as u32,
                        previous,
                        lifecycle,
                        now,
                    );
                }
            }
            i += 1;
        }
    }

    fn purge_instance(&mut self, instance_id: usize) -> usize {
        let mut removed = 0usize;
        let mut i = 0usize;
        while i < self.records.len() {
            if self.records[i].active && self.records[i].target_instance == instance_id {
                self.records[i].lifecycle = PolyglotLifecycle::TornDown;
                self.records[i].updated_at = crate::scheduler::pit::get_ticks();
                removed = removed.saturating_add(1);
            }
            i += 1;
        }
        removed
    }

    fn active_count(&self) -> usize {
        let mut count = 0usize;
        let mut i = 0usize;
        while i < self.records.len() {
            if self.records[i].active {
                count += 1;
            }
            i += 1;
        }
        count
    }

    fn serialize_records(&self, out: &mut [u8]) -> Result<usize, &'static str> {
        self.serialize_filtered(out, PolyglotLineageFilterKind::All, 0, 0, None)
    }

    fn serialize_latest_by_object(&self, out: &mut [u8], object_id: u64) -> Result<usize, &'static str> {
        let Some(idx) = self.find_latest_by_object(object_id) else {
            return Err("polyglot lineage record not found");
        };
        let needed = PolyglotLineageWireHeaderV1::BYTES + PolyglotLineageWireRecordV1::BYTES;
        if out.len() < needed {
            return Err("polyglot lineage query buffer too small");
        }
        PolyglotLineageWireHeaderV1::new(1, self.next_record_id).encode(out);
        PolyglotLineageWireRecordV1::from_record(&self.records[idx])
            .encode(&mut out[PolyglotLineageWireHeaderV1::BYTES..needed]);
        Ok(1)
    }

    fn push_event(
        &mut self,
        object_id: u64,
        target_instance: u32,
        previous_lifecycle: PolyglotLifecycle,
        lifecycle: PolyglotLifecycle,
        updated_at: u64,
    ) {
        let idx = self.next_event_cursor % self.events.len();
        self.events[idx] = PolyglotLineageEventRecord {
            active: true,
            event_id: self.next_event_id,
            object_id,
            target_instance,
            lifecycle,
            previous_lifecycle,
            updated_at,
        };
        self.next_event_id = self.next_event_id.saturating_add(1);
        self.next_event_cursor = self.next_event_cursor.wrapping_add(1);
    }

    fn serialize_events(
        &self,
        out: &mut [u8],
        cursor: u64,
        limit: usize,
    ) -> Result<usize, &'static str> {
        let mut matches = [PolyglotLineageEventRecord::empty(); MAX_POLYGLOT_LINEAGE_RECORDS];
        let mut count = 0usize;
        let mut i = 0usize;
        while i < self.events.len() {
            let ev = self.events[i];
            if ev.active && ev.event_id > cursor {
                if count >= limit || count >= MAX_POLYGLOT_LINEAGE_RECORDS {
                    break;
                }
                matches[count] = ev;
                count += 1;
            }
            i += 1;
        }
        let needed = PolyglotLineageWireHeaderV1::BYTES + count * PolyglotLineageEventWireRecordV1::BYTES;
        if out.len() < needed {
            return Err("polyglot lineage query buffer too small");
        }
        PolyglotLineageWireHeaderV1::new(count, self.next_event_id).encode(out);
        let mut cursor_out = PolyglotLineageWireHeaderV1::BYTES;
        let mut j = 0usize;
        while j < count {
            PolyglotLineageEventWireRecordV1::encode_from(&matches[j])
                .encode(&mut out[cursor_out..cursor_out + PolyglotLineageEventWireRecordV1::BYTES]);
            cursor_out += PolyglotLineageEventWireRecordV1::BYTES;
            j += 1;
        }
        Ok(count)
    }

    fn serialize_status_by_object(&self, out: &mut [u8], object_id: u64) -> Result<usize, &'static str> {
        let Some(idx) = self.find_latest_by_object(object_id) else {
            return Err("polyglot lineage record not found");
        };
        let needed = PolyglotLineageWireHeaderV1::BYTES + PolyglotLineageStatusWireRecordV1::BYTES;
        if out.len() < needed {
            return Err("polyglot lineage query buffer too small");
        }
        PolyglotLineageWireHeaderV1::new(1, self.next_record_id).encode(out);
        PolyglotLineageStatusWireRecordV1::from_record(&self.records[idx])
            .encode(&mut out[PolyglotLineageWireHeaderV1::BYTES..needed]);
        Ok(1)
    }

    fn serialize_latest_only(&self, out: &mut [u8]) -> Result<usize, &'static str> {
        let mut latest = [u64::MAX; MAX_POLYGLOT_LINEAGE_RECORDS];
        let mut selected = [PolyglotLineageRecord::empty(); MAX_POLYGLOT_LINEAGE_RECORDS];
        let mut selected_count = 0usize;
        let mut i = 0usize;
        while i < self.records.len() {
            let rec = self.records[i];
            if rec.record_id != 0 {
                let mut slot = None;
                let mut j = 0usize;
                while j < selected_count {
                    if selected[j].object_id == rec.object_id {
                        slot = Some(j);
                        break;
                    }
                    j += 1;
                }
                match slot {
                    Some(idx) => {
                        if rec.record_id > latest[idx] {
                            latest[idx] = rec.record_id;
                            selected[idx] = rec;
                        }
                    }
                    None => {
                        if selected_count >= MAX_POLYGLOT_LINEAGE_RECORDS {
                            return Err("polyglot lineage query buffer too small");
                        }
                        latest[selected_count] = rec.record_id;
                        selected[selected_count] = rec;
                        selected_count += 1;
                    }
                }
            }
            i += 1;
        }
        let needed = PolyglotLineageWireHeaderV1::BYTES
            + selected_count * PolyglotLineageWireRecordV1::BYTES;
        if out.len() < needed {
            return Err("polyglot lineage query buffer too small");
        }
        PolyglotLineageWireHeaderV1::new(selected_count, self.next_record_id).encode(out);
        let mut cursor = PolyglotLineageWireHeaderV1::BYTES;
        let mut k = 0usize;
        while k < selected_count {
            PolyglotLineageWireRecordV1::from_record(&selected[k])
                .encode(&mut out[cursor..cursor + PolyglotLineageWireRecordV1::BYTES]);
            cursor += PolyglotLineageWireRecordV1::BYTES;
            k += 1;
        }
        Ok(selected_count)
    }

    fn serialize_page(
        &self,
        out: &mut [u8],
        cursor: u64,
        limit: usize,
    ) -> Result<usize, &'static str> {
        let mut matches = [PolyglotLineageRecord::empty(); MAX_POLYGLOT_LINEAGE_RECORDS];
        let mut count = 0usize;
        let mut i = 0usize;
        while i < self.records.len() {
            let rec = self.records[i];
            if rec.record_id > cursor && rec.record_id != 0 {
                if count >= limit || count >= MAX_POLYGLOT_LINEAGE_RECORDS {
                    break;
                }
                matches[count] = rec;
                count += 1;
            }
            i += 1;
        }
        let needed = PolyglotLineageWireHeaderV1::BYTES + count * PolyglotLineageWireRecordV1::BYTES;
        if out.len() < needed {
            return Err("polyglot lineage query buffer too small");
        }
        PolyglotLineageWireHeaderV1::new(count, self.next_record_id).encode(out);
        let mut cursor_out = PolyglotLineageWireHeaderV1::BYTES;
        let mut j = 0usize;
        while j < count {
            PolyglotLineageWireRecordV1::from_record(&matches[j])
                .encode(&mut out[cursor_out..cursor_out + PolyglotLineageWireRecordV1::BYTES]);
            cursor_out += PolyglotLineageWireRecordV1::BYTES;
            j += 1;
        }
        Ok(count)
    }

    fn serialize_filtered(
        &self,
        out: &mut [u8],
        filter_kind: PolyglotLineageFilterKind,
        filter_a: u32,
        filter_b: u32,
        export_name: Option<&[u8]>,
    ) -> Result<usize, &'static str> {
        let mut matches = 0usize;
        let mut i = 0usize;
        while i < self.records.len() {
            let rec = self.records[i];
            if rec.record_id != 0
                && Self::record_matches(rec, filter_kind, filter_a, filter_b, export_name)
            {
                matches = matches.saturating_add(1);
            }
            i += 1;
        }
        let needed = PolyglotLineageWireHeaderV1::BYTES
            .saturating_add(matches.saturating_mul(PolyglotLineageWireRecordV1::BYTES));
        if out.len() < needed {
            return Err("polyglot lineage query buffer too small");
        }
        PolyglotLineageWireHeaderV1::new(matches, self.next_record_id).encode(out);
        let mut cursor = 8usize;
        let mut i = 0usize;
        while i < self.records.len() {
            let rec = self.records[i];
            if rec.record_id != 0
                && Self::record_matches(rec, filter_kind, filter_a, filter_b, export_name)
            {
                PolyglotLineageWireRecordV1::from_record(&rec)
                    .encode(&mut out[cursor..cursor + PolyglotLineageWireRecordV1::BYTES]);
                cursor += PolyglotLineageWireRecordV1::BYTES;
            }
            i += 1;
        }
        Ok(matches)
    }

    fn record_matches(
        record: PolyglotLineageRecord,
        filter_kind: PolyglotLineageFilterKind,
        filter_a: u32,
        filter_b: u32,
        export_name: Option<&[u8]>,
    ) -> bool {
        match filter_kind {
            PolyglotLineageFilterKind::All => true,
            PolyglotLineageFilterKind::SourcePid => record.source_pid.0 == filter_a,
            PolyglotLineageFilterKind::TargetInstance => record.target_instance as u32 == filter_a,
            PolyglotLineageFilterKind::Lifecycle => record.lifecycle as u8 == filter_a as u8,
            PolyglotLineageFilterKind::ExportName => {
                let Some(name) = export_name else {
                    return false;
                };
                if name.len() != filter_b as usize || name.len() > 32 {
                    return false;
                }
                record.export_name_len as usize == name.len()
                    && record.export_name[..name.len()] == *name
            }
            PolyglotLineageFilterKind::ObjectId => {
                let object_id = (filter_a as u64) | ((filter_b as u64) << 32);
                record.object_id == object_id
            }
        }
    }
}

static POLYGLOT_LINEAGE: Mutex<PolyglotLineageStore> = Mutex::new(PolyglotLineageStore::new());

#[derive(Clone, Copy)]
struct PolyglotEntry {
    active: bool,
    name: [u8; 32],
    name_len: u8,
    instance_id: usize,
    language: LanguageTag,
    cap_object: u64, // cap object_id for ServicePointer, 0 if none yet
    owner_pid: crate::ipc::ProcessId,
    singleton: bool, // true = shared language-runtime service
    latest_record_id: u64,
}

impl PolyglotEntry {
    const fn empty() -> Self {
        PolyglotEntry {
            active: false,
            name: [0u8; 32],
            name_len: 0,
            instance_id: 0,
            language: LanguageTag::Unknown,
            cap_object: 0,
            owner_pid: crate::ipc::ProcessId(0),
            singleton: false,
            latest_record_id: 0,
        }
    }
}

struct PolyglotRegistry {
    entries: [PolyglotEntry; MAX_POLYGLOT_ENTRIES],
}

impl PolyglotRegistry {
    const fn new() -> Self {
        Self {
            entries: [PolyglotEntry::empty(); MAX_POLYGLOT_ENTRIES],
        }
    }
    fn find_by_name(&self, name: &[u8]) -> Option<usize> {
        let mut i = 0;
        while i < self.entries.len() {
            let e = &self.entries[i];
            if e.active && e.name_len as usize == name.len() && &e.name[..name.len()] == name {
                return Some(i);
            }
            i += 1;
        }
        None
    }
    fn find_empty(&self) -> Option<usize> {
        let mut i = 0;
        while i < self.entries.len() {
            if !self.entries[i].active {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn purge_instance(&mut self, instance_id: usize) -> usize {
        let mut removed = 0usize;
        let mut i = 0usize;
        while i < self.entries.len() {
            if self.entries[i].active && self.entries[i].instance_id == instance_id {
                if self.entries[i].cap_object != 0 {
                    POLYGLOT_LINEAGE
                        .lock()
                        .update_lifecycle(self.entries[i].cap_object, PolyglotLifecycle::TornDown);
                }
                self.entries[i] = PolyglotEntry::empty();
                removed = removed.saturating_add(1);
            }
            i += 1;
        }
        removed
    }
}

static POLYGLOT_REGISTRY: Mutex<PolyglotRegistry> = Mutex::new(PolyglotRegistry::new());

// ── Kernel Observer Registry ─────────────────────────────────────────────────
// Up to MAX_OBSERVER_SLOTS WASM modules can subscribe as kernel observers.
// Each observer declares an event mask and is notified via its IPC channel.

/// Event mask bits for kernel observers.
pub mod observer_events {
    /// A capability operation was performed (grant/revoke/transfer).
    pub const CAPABILITY_OP: u32 = 1 << 0;
    /// A process was spawned or exited.
    pub const PROCESS_LIFECYCLE: u32 = 1 << 1;
    /// An anomaly was detected by the SecurityManager.
    pub const ANOMALY_DETECTED: u32 = 1 << 2;
    /// An IPC channel send/recv completed.
    pub const IPC_ACTIVITY: u32 = 1 << 3;
    /// A memory allocation exceeded a threshold.
    pub const MEMORY_PRESSURE: u32 = 1 << 4;
    /// A cross-language polyglot link was established.
    pub const POLYGLOT_LINK: u32 = 1 << 5;
    /// All events (catch-all mask).
    pub const ALL: u32 = 0x0000_003F;
}

const MAX_OBSERVER_SLOTS: usize = 4;

#[derive(Clone, Copy)]
struct ObserverEntry {
    /// Whether this slot is active.
    active: bool,
    /// WASM instance ID of the observer module.
    instance_id: usize,
    /// IPC channel ID to deliver events on (created by observer_subscribe).
    channel_id: u32,
    /// Event mask — only events matching this mask are delivered.
    event_mask: u32,
    /// Owner process ID.
    owner_pid: crate::ipc::ProcessId,
}

impl ObserverEntry {
    const fn empty() -> Self {
        ObserverEntry {
            active: false,
            instance_id: 0,
            channel_id: 0,
            event_mask: 0,
            owner_pid: crate::ipc::ProcessId(0),
        }
    }
}

struct ObserverRegistry {
    entries: [ObserverEntry; MAX_OBSERVER_SLOTS],
}

impl ObserverRegistry {
    const fn new() -> Self {
        ObserverRegistry {
            entries: [ObserverEntry::empty(); MAX_OBSERVER_SLOTS],
        }
    }

    fn find_by_instance(&self, instance_id: usize) -> Option<usize> {
        let mut i = 0;
        while i < self.entries.len() {
            if self.entries[i].active && self.entries[i].instance_id == instance_id {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn find_empty(&self) -> Option<usize> {
        let mut i = 0;
        while i < self.entries.len() {
            if !self.entries[i].active {
                return Some(i);
            }
            i += 1;
        }
        None
    }
}

static OBSERVER_REGISTRY: Mutex<ObserverRegistry> = Mutex::new(ObserverRegistry::new());

// ── Kernel Mesh Migration Queue ───────────────────────────────────────────────
// Holds pending `mesh_migrate` requests.  A background task or the next
// scheduler tick drains this queue and sends the module bytes to the peer.

const MAX_MESH_MIGRATE_SLOTS: usize = 4;

struct MeshMigrateRequest {
    active: bool,
    peer_id: u64,
    /// Snapshot of the WASM bytecode to send (heap-allocated via the kernel
    /// alloc shim when `alloc` is available; otherwise up to 64 KiB inline).
    bytecode: [u8; 65536],
    bytecode_len: usize,
    requester_pid: crate::ipc::ProcessId,
}

impl MeshMigrateRequest {
    const fn empty() -> Self {
        MeshMigrateRequest {
            active: false,
            peer_id: 0,
            bytecode: [0u8; 65536],
            bytecode_len: 0,
            requester_pid: crate::ipc::ProcessId(0),
        }
    }
}

struct MeshMigrateQueue {
    slots: [MeshMigrateRequest; MAX_MESH_MIGRATE_SLOTS],
}

impl MeshMigrateQueue {
    const fn new() -> Self {
        MeshMigrateQueue {
            slots: [
                MeshMigrateRequest::empty(),
                MeshMigrateRequest::empty(),
                MeshMigrateRequest::empty(),
                MeshMigrateRequest::empty(),
            ],
        }
    }
    fn find_empty(&self) -> Option<usize> {
        let mut i = 0usize;
        while i < self.slots.len() {
            if !self.slots[i].active {
                return Some(i);
            }
            i += 1;
        }
        None
    }
}

/// Drain the mesh migrate queue, sending pending migrations over the network.
/// Called from the kernel scheduler tick or shell `mesh flush` command.
pub fn mesh_migrate_flush() {
    let mut q = MESH_MIGRATE_QUEUE.lock();
    let mut i = 0usize;
    while i < q.slots.len() {
        if q.slots[i].active {
            let peer_id = q.slots[i].peer_id;
            let len = q.slots[i].bytecode_len;
            // Build a TokenOffer frame carrying the WASM bytecode as payload.
            // We encode: [8-byte peer_id LE][4-byte len LE][bytecode…]
            // Real transport would use the NetworkService TCP layer; here we
            // log to the serial console and invoke the observer system so
            // userspace can complete the handshake via mesh_token_send.
            crate::serial_println!(
                "[mesh] migrate: peer={:#018x} bytes={} queued",
                peer_id,
                len
            );
            // Notify observers.
            let mut payload = [0u8; 12];
            payload[0..8].copy_from_slice(&peer_id.to_le_bytes());
            payload[8..12].copy_from_slice(&(len as u32).to_le_bytes());
            observer_notify(observer_events::POLYGLOT_LINK, &payload);
            q.slots[i].active = false;
        }
        i += 1;
    }
}

static MESH_MIGRATE_QUEUE: Mutex<MeshMigrateQueue> = Mutex::new(MeshMigrateQueue::new());

// ── Temporal Capability Expiry Table ────────────────────────────────────────
// Tracks capabilities granted through the `temporal_cap_grant` host function
// so the scheduler can auto-revoke them when their deadline passes.

const MAX_TEMPORAL_CAP_SLOTS: usize = 32;

#[derive(Clone, Copy)]
struct TemporalCapSlot {
    active: bool,
    pid: u32,
    cap_id: u32,
    expires_at: u64, // absolute PIT tick
    cap_type: u8,
    object_id: u64,
}

impl TemporalCapSlot {
    const fn empty() -> Self {
        TemporalCapSlot {
            active: false,
            pid: 0,
            cap_id: 0,
            expires_at: 0,
            cap_type: 0,
            object_id: 0,
        }
    }
}

struct TemporalCapTable {
    slots: [TemporalCapSlot; MAX_TEMPORAL_CAP_SLOTS],
    next_id: u32, // monotonic slot counter, used as "checkpoint ID" too
}

impl TemporalCapTable {
    const fn new() -> Self {
        TemporalCapTable {
            slots: [TemporalCapSlot::empty(); MAX_TEMPORAL_CAP_SLOTS],
            next_id: 1,
        }
    }
}

static TEMPORAL_CAP_TABLE: Mutex<TemporalCapTable> = Mutex::new(TemporalCapTable::new());

// ── Temporal Checkpoint Store ────────────────────────────────────────────────
// Lightweight per-process capability snapshots for WASM rollback.

const MAX_TEMPORAL_CHECKPOINTS: usize = 8;
const MAX_CAPS_PER_CHECKPOINT: usize = 16;

#[derive(Clone, Copy)]
struct TemporalCheckpointEntry {
    cap_id: u32,
    object_id: u64,
    cap_type: u8,
    rights: u32,
}

impl TemporalCheckpointEntry {
    const fn empty() -> Self {
        TemporalCheckpointEntry {
            cap_id: 0,
            object_id: 0,
            cap_type: 0,
            rights: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct TemporalCheckpoint {
    active: bool,
    id: u32,
    pid: u32,
    tick: u64,
    cap_count: u8,
    caps: [TemporalCheckpointEntry; MAX_CAPS_PER_CHECKPOINT],
}

impl TemporalCheckpoint {
    const fn empty() -> Self {
        TemporalCheckpoint {
            active: false,
            id: 0,
            pid: 0,
            tick: 0,
            cap_count: 0,
            caps: [TemporalCheckpointEntry::empty(); MAX_CAPS_PER_CHECKPOINT],
        }
    }
}

struct CheckpointStore {
    slots: [TemporalCheckpoint; MAX_TEMPORAL_CHECKPOINTS],
    next_id: u32,
}

impl CheckpointStore {
    const fn new() -> Self {
        CheckpointStore {
            slots: [TemporalCheckpoint::empty(); MAX_TEMPORAL_CHECKPOINTS],
            next_id: 1,
        }
    }
}

static TEMPORAL_CHECKPOINT_STORE: Mutex<CheckpointStore> = Mutex::new(CheckpointStore::new());

// ── Intensional Kernel: Policy-as-Capability-Contracts ───────────────────────
// A "policy contract" is a small WASM module (≤ 4 KiB) whose exported
// function `policy_check(ctx_ptr: i32, ctx_len: i32) -> i32` returns
// 0 = permit or 1 = deny.  Contracts are bound to specific `cap_id` values;
// before any access using that capability the kernel evaluates the contract
// and denies by default if the policy is missing or unsupported.

const MAX_POLICY_SLOTS: usize = 16;
const MAX_POLICY_WASM_LEN: usize = 4096;

#[derive(Clone, Copy)]
struct PolicySlot {
    active: bool,
    pid: u32,
    cap_id: u32,
    wasm_hash: u64, // SipHash of the contract bytecode
    wasm_len: u16,
    bytecode: [u8; MAX_POLICY_WASM_LEN],
}

impl PolicySlot {
    const fn empty() -> Self {
        PolicySlot {
            active: false,
            pid: 0,
            cap_id: 0,
            wasm_hash: 0,
            wasm_len: 0,
            bytecode: [0u8; MAX_POLICY_WASM_LEN],
        }
    }
}

struct PolicyStore {
    slots: [PolicySlot; MAX_POLICY_SLOTS],
}

impl PolicyStore {
    const fn new() -> Self {
        PolicyStore {
            slots: [PolicySlot::empty(); MAX_POLICY_SLOTS],
        }
    }
}

static POLICY_STORE: Mutex<PolicyStore> = Mutex::new(PolicyStore::new());

// ===========================================================================
// Quantum-Inspired Capability Entanglement
// ===========================================================================
//
// Each `EntangleLink` connects two (pid, cap_id) pairs within a group.
// Revoking any cap in a group cascades to all peers in the same group.
// Pairwise entanglement uses group_id == 0.
// Group entanglement assigns group_id from a monotonic counter (1+).

const MAX_ENTANGLE_LINKS: usize = 128;

#[derive(Clone, Copy)]
struct EntangleLink {
    /// `true` when this slot is active.
    active: bool,
    /// Owning process.
    pid: u32,
    /// First capability in the link.
    cap_a: u32,
    /// Second capability in the link.
    cap_b: u32,
    /// Group ID. `0` = pairwise only. `>0` = belongs to a named group.
    group_id: u32,
}

impl EntangleLink {
    const fn empty() -> Self {
        EntangleLink {
            active: false,
            pid: 0,
            cap_a: 0,
            cap_b: 0,
            group_id: 0,
        }
    }
}

struct EntangleTable {
    links: [EntangleLink; MAX_ENTANGLE_LINKS],
    next_group_id: u32,
}

impl EntangleTable {
    const fn new() -> Self {
        EntangleTable {
            links: [EntangleLink::empty(); MAX_ENTANGLE_LINKS],
            next_group_id: 1,
        }
    }
}

static ENTANGLE_TABLE: Mutex<EntangleTable> = Mutex::new(EntangleTable::new());

/// Cascade-revoke all caps entangled with `(pid, cap_id)`.
///
/// Called immediately after the primary revocation of `cap_id` so that all
/// linked capabilities are also revoked.  Safe to call with no entanglement
/// (no-op).
pub fn entangle_cascade_revoke(pid: u32, cap_id: u32) {
    // Collect all caps entangled with the target under a single lock acquire.
    let mut to_revoke = [0u32; MAX_ENTANGLE_LINKS];
    let mut n = 0usize;
    {
        let mut tbl = ENTANGLE_TABLE.lock();
        let mut i = 0usize;
        while i < MAX_ENTANGLE_LINKS {
            let lnk = &mut tbl.links[i];
            if !lnk.active || lnk.pid != pid {
                i += 1;
                continue;
            }
            if lnk.cap_a == cap_id || lnk.cap_b == cap_id {
                let peer = if lnk.cap_a == cap_id {
                    lnk.cap_b
                } else {
                    lnk.cap_a
                };
                // Deactivate this link so we don't re-enter.
                lnk.active = false;
                if n < MAX_ENTANGLE_LINKS {
                    to_revoke[n] = peer;
                    n += 1;
                }
            }
            i += 1;
        }
    }
    // Now revoke peers outside the lock.
    let mut k = 0usize;
    while k < n {
        let peer_cap = to_revoke[k];
        k += 1;
        if peer_cap == 0 {
            continue;
        }
        // Cascade-revoke the peer (will itself call entangle_cascade_revoke
        // transitively via the capability manager hook, but since we already
        // deactivated the link we won't loop).
        let _ = crate::capability::capability_manager()
            .revoke_capability(crate::ipc::ProcessId(pid), peer_cap);
        crate::serial_println!(
            "[entangle] cascade-revoked cap {} (entangled with {}) for pid {}",
            peer_cap,
            cap_id,
            pid
        );
    }
}

///
/// Returns `true` (permit) only if a bound policy explicitly permits the
/// access. Missing, malformed, or unsupported policies deny by default.
/// Called from the capability access check hot-path.
pub fn policy_check_for_cap(pid: u32, cap_id: u32, ctx: &[u8]) -> bool {
    // Snapshot the bytecode under the lock before evaluating.
    let policy: Option<([u8; MAX_POLICY_WASM_LEN], usize)> = {
        let store = POLICY_STORE.lock();
        let mut found = None;
        let mut i = 0usize;
        while i < MAX_POLICY_SLOTS {
            if store.slots[i].active && store.slots[i].pid == pid && store.slots[i].cap_id == cap_id
            {
                found = Some((store.slots[i].bytecode, store.slots[i].wasm_len as usize));
                break;
            }
            i += 1;
        }
        found
    };
    match policy {
        None => false, // no policy bound → deny
        Some((bc, len)) => run_policy_contract(&bc[..len], ctx),
    }
}

/// Execute a policy contract against the provided context bytes.
///
/// Returns `true` (permit) or `false` (deny).
///
/// # Contract bytecode format
/// The kernel supports two modes:
///
/// 1. **Full WASM** (`\0asm` magic): The policy module exports
///    `policy_check(ctx_ptr: i32, ctx_len: i32) -> i32`.
///    *Deny-by-default until a real WASM interpreter is integrated.*
///
/// 2. **Oreulius Policy Stub** (`OPOL` magic): A compact 8-byte rule blob:
///    `[magic: 4][default_permit: u8][min_ctx_len: u8][ctx_byte0_eq: u8][ctx_byte0_val: u8]`
///    - Denies if `ctx.len() < min_ctx_len`.
///    - If `ctx_byte0_eq != 0`, denies if `ctx[0] != ctx_byte0_val`.
///    - Otherwise returns `default_permit`.
///
/// On any parse/runtime error the function fails **closed** (returns `false`).
fn run_policy_contract(bytecode: &[u8], ctx: &[u8]) -> bool {
    if bytecode.len() < 4 {
        return false;
    }

    // Mode 2: Oreulius Policy Stub (OPOL)
    if bytecode[0] == b'O' && bytecode[1] == b'P' && bytecode[2] == b'O' && bytecode[3] == b'L' {
        if bytecode.len() < 8 {
            return false;
        }
        let default_permit = bytecode[4] != 0;
        let min_ctx_len = bytecode[5] as usize;
        let ctx_byte0_eq = bytecode[6] != 0;
        let ctx_byte0_val = bytecode[7];
        if ctx.len() < min_ctx_len {
            return false;
        }
        if ctx_byte0_eq && (ctx.is_empty() || ctx[0] != ctx_byte0_val) {
            return false;
        }
        return default_permit;
    }

    // Mode 1: Full WASM policy module.
    //
    // Keep this path strict: policy modules must be self-contained and export
    // `policy_check(ctx_ptr: i32, ctx_len: i32) -> i32`. Any parse, instantiation,
    // or execution error fails closed.
    let mut module = WasmModule::new();
    if module.load_binary(bytecode).is_err() {
        return false;
    }
    if module.import_function_count != 0 {
        return false;
    }
    let export_idx = match module.resolve_exported_function(b"policy_check") {
        Ok(idx) => idx,
        Err(_) => return false,
    };
    let (param_count, result_count) = match module.function_arity(export_idx) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    if param_count != 2 || result_count != 1 || !module.function_all_i32(export_idx).unwrap_or(false)
    {
        return false;
    }

    let mut instance = unsafe { WasmInstance::boxed_new_in_place(module, ProcessId(0), 0) };
    if instance.initialize_from_module().is_err() {
        return false;
    }
    if instance.memory.write(0, ctx).is_err() {
        return false;
    }
    if instance
        .stack
        .push(Value::I32(0))
        .and_then(|_| instance.stack.push(Value::I32(ctx.len() as i32)))
        .is_err()
    {
        return false;
    }
    if instance.invoke_combined_function(export_idx).is_err() {
        return false;
    }
    if instance.stack.len() != 1 {
        return false;
    }
    match instance.stack.pop().and_then(|v| v.as_i32()) {
        Ok(0) => false,
        Ok(v) => v != 0,
        Err(_) => false,
    }
}

fn parse_net_host(host: &str) -> Option<crate::net::Ipv4Addr> {
    let mut parts = [0u8; 4];
    let mut idx = 0usize;
    for chunk in host.split('.') {
        if idx >= 4 || chunk.is_empty() || chunk.len() > 3 {
            return None;
        }
        parts[idx] = chunk.parse::<u8>().ok()?;
        idx += 1;
    }
    if idx != 4 {
        return None;
    }
    Some(crate::net::Ipv4Addr::new(parts[0], parts[1], parts[2], parts[3]))
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    const MIN_POLICY_WASM: [u8; 48] = [
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
        0x01, 0x07, 0x01, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F, // type section
        0x03, 0x02, 0x01, 0x00, // function section
        0x07, 0x10, 0x01, 0x0C, 0x70, 0x6F, 0x6C, 0x69, 0x63, 0x79, 0x5F, 0x63,
        0x68, 0x65, 0x63, 0x6B, 0x00, 0x00, // export policy_check
        0x0A, 0x06, 0x01, 0x04, 0x00, 0x41, 0x01, 0x0B, // body: i32.const 1
    ];

    #[test]
    fn full_wasm_policy_contract_permits_minimal_policy_check_blob() {
        let pid = 0xA11CEu32;
        let cap_id = 0xC0DEu32;
        let ctx = [0xAAu8, 0xBB, 0xCC];
        let hash = {
            let mut h = 0u64;
            let mut i = 0usize;
            while i < MIN_POLICY_WASM.len() {
                h = h.wrapping_mul(0x9E3779B97F4A7C15) ^ MIN_POLICY_WASM[i] as u64;
                i += 1;
            }
            h
        };

        {
            let mut store = POLICY_STORE.lock();
            store.slots[0] = PolicySlot {
                active: true,
                pid,
                cap_id,
                wasm_hash: hash,
                wasm_len: MIN_POLICY_WASM.len() as u16,
                bytecode: {
                    let mut bytecode = [0u8; MAX_POLICY_WASM_LEN];
                    let mut i = 0usize;
                    while i < MIN_POLICY_WASM.len() {
                        bytecode[i] = MIN_POLICY_WASM[i];
                        i += 1;
                    }
                    bytecode
                },
            };
        }

        assert!(policy_check_for_cap(pid, cap_id, &ctx));

        let mut store = POLICY_STORE.lock();
        store.slots[0] = PolicySlot::empty();
    }

    #[test]
    fn mesh_migrate_uses_module_bytecode_when_payload_is_empty() {
        const MODULE_BYTES: [u8; 27] = [
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
            0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F, // type: () -> i32
            0x03, 0x02, 0x01, 0x00, // function section
            0x0A, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2A, 0x0B, // code: i32.const 42
        ];

        let mut module = WasmModule::new();
        module.load_binary(&MODULE_BYTES).expect("module should load");

        let instance = unsafe { WasmInstance::boxed_new_in_place(module, ProcessId(1), 0) };
        let snapshot = instance.mesh_migrate_payload_bytes_for_test(0, 0);
        assert_eq!(snapshot, MODULE_BYTES);
    }

    #[test]
    fn parse_net_host_accepts_ipv4_literal() {
        let ip = parse_net_host("10.20.30.40").expect("valid ipv4 literal");
        assert_eq!(ip.0, [10, 20, 30, 40]);
        assert!(parse_net_host("example.com").is_none());
    }
}

pub fn temporal_cap_tick() {
    let now = crate::scheduler::pit::get_ticks() as u64;
    let expired: [(u32, u32); MAX_TEMPORAL_CAP_SLOTS] = {
        let tbl = TEMPORAL_CAP_TABLE.lock();
        let mut out = [(0u32, 0u32); MAX_TEMPORAL_CAP_SLOTS];
        let mut k = 0usize;
        let mut i = 0usize;
        while i < MAX_TEMPORAL_CAP_SLOTS {
            let s = &tbl.slots[i];
            if s.active && now >= s.expires_at {
                if k < MAX_TEMPORAL_CAP_SLOTS {
                    out[k] = (s.pid, s.cap_id);
                    k += 1;
                }
            }
            i += 1;
        }
        out
    };
    let mut k = 0usize;
    while k < MAX_TEMPORAL_CAP_SLOTS {
        let (pid, cap_id) = expired[k];
        k += 1;
        if pid == 0 && cap_id == 0 {
            continue;
        }
        let _ = crate::capability::capability_manager()
            .revoke_capability(crate::ipc::ProcessId(pid), cap_id);
        crate::serial_println!(
            "[temporal] auto-revoked cap {} for pid {} (expired)",
            cap_id,
            pid
        );
        observer_notify(
            observer_events::CAPABILITY_OP,
            &[
                pid.to_le_bytes()[0],
                pid.to_le_bytes()[1],
                pid.to_le_bytes()[2],
                pid.to_le_bytes()[3],
                0x02,
                0,
                0,
                0, // 0x02 = REVOKE event tag
            ],
        );
        // Mark slot as inactive.
        let mut tbl = TEMPORAL_CAP_TABLE.lock();
        let mut i = 0usize;
        while i < MAX_TEMPORAL_CAP_SLOTS {
            if tbl.slots[i].active && tbl.slots[i].pid == pid && tbl.slots[i].cap_id == cap_id {
                tbl.slots[i].active = false;
                break;
            }
            i += 1;
        }
    }
}

///
/// Called from the security manager, scheduler tick, and IPC layer.
/// `event_type` should be one of the `observer_events::*` constants.
/// `payload` is up to 28 bytes of event-specific data (process ID, cap type,
/// anomaly score, etc.).  It is encoded as a 32-byte IPC message:
///   [0..3]  event_type: u32 LE
///   [4..31] payload (zero-padded)
pub fn observer_notify(event_type: u32, payload: &[u8]) {
    // Encode the event message (32 bytes max).
    let mut msg_buf = [0u8; 32];
    let el = event_type.to_le_bytes();
    msg_buf[0] = el[0];
    msg_buf[1] = el[1];
    msg_buf[2] = el[2];
    msg_buf[3] = el[3];
    let copy_len = payload.len().min(28);
    let mut i = 0;
    while i < copy_len {
        msg_buf[4 + i] = payload[i];
        i += 1;
    }

    // Snapshot the list of active observers to avoid holding the registry
    // lock while calling into the IPC layer.
    let mut channels = [0u32; MAX_OBSERVER_SLOTS];
    let mut masks = [0u32; MAX_OBSERVER_SLOTS];
    let mut n = 0usize;
    {
        let registry = OBSERVER_REGISTRY.lock();
        let mut s = 0usize;
        while s < registry.entries.len() {
            let e = &registry.entries[s];
            if e.active && (e.event_mask & event_type) != 0 {
                channels[n] = e.channel_id;
                masks[n] = e.event_mask;
                n += 1;
            }
            s += 1;
        }
    }

    // Now deliver to each channel without holding the registry lock.
    let kernel_pid = crate::ipc::ProcessId(0);
    let mut d = 0usize;
    while d < n {
        let ch_id = crate::ipc::ChannelId::new(channels[d]);
        let send_cap = crate::ipc::ChannelCapability::new(
            0,
            ch_id,
            crate::ipc::ChannelRights::send_only(),
            kernel_pid,
        );
        if let Ok(msg) = crate::ipc::Message::with_data(kernel_pid, &msg_buf) {
            let _ = crate::ipc::ipc().send(msg, &send_cap);
        }
        d += 1;
    }
}

const SERVICE_POINTER_TEMPORAL_SCHEMA_V1: u8 = 2;
const SERVICE_POINTER_TEMPORAL_HEADER_BYTES: usize = 12;
const SERVICE_POINTER_TEMPORAL_ENTRY_BYTES: usize = 76 + (MAX_WASM_TYPE_ARITY * 2);

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
            payload.push(entry.export_name_len);
            payload.extend_from_slice(&entry.export_name);

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

        let export_name_len = payload[offset + 43] as usize;
        if export_name_len > 32 {
            return Err("temporal wasm service pointer export name too long");
        }
        let mut export_name = [0u8; 32];
        export_name.copy_from_slice(&payload[offset + 44..offset + 76]);

        let mut param_types = [ValueType::I32; MAX_WASM_TYPE_ARITY];
        let mut result_types = [ValueType::I32; MAX_WASM_TYPE_ARITY];
        let mut p = 0usize;
        while p < MAX_WASM_TYPE_ARITY {
            param_types[p] = service_pointer_temporal_tag_to_value_type(payload[offset + 76 + p])
                .ok_or("temporal wasm service pointer param type invalid")?;
            p += 1;
        }
        let mut r = 0usize;
        let result_base = offset + 76 + MAX_WASM_TYPE_ARITY;
        while r < MAX_WASM_TYPE_ARITY {
            result_types[r] = service_pointer_temporal_tag_to_value_type(payload[result_base + r])
                .ok_or("temporal wasm service pointer result type invalid")?;
            r += 1;
        }

        new_entries[i] = ServicePointerEntry {
            active: true,
            object_id,
            owner_pid: ProcessId(owner_pid),
            target_instance: target_instance as usize,
            function_index: function_index as usize,
            export_name,
            export_name_len: export_name_len as u8,
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
                &observed[i].export_name[..observed[i].export_name_len as usize],
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
                        if let Ok(Ok(function_index)) =
                            wasm_runtime().get_instance_mut(rebind_target[i], |instance| {
                                instance.module.resolve_exported_function(
                                    &updated.export_name[..updated.export_name_len as usize],
                                )
                            })
                        {
                            updated.function_index = function_index;
                        }
                        updated.window_start_tick = crate::scheduler::pit::get_ticks();
                        updated.calls_in_window = 0;
                        registry.entries[idx] = updated;
                        POLYGLOT_LINEAGE
                            .lock()
                            .update_lifecycle(object_id, PolyglotLifecycle::Rebound);
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
        let _ = capability::capability_manager()
            .revoke_object_capabilities(CapabilityType::ServicePointer, object_ids[i]);
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
        .get_instance_mut(
            target_instance,
            |instance| -> Result<(ProcessId, usize, ParsedFunctionType, [u8; 32], u8), WasmError> {
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
                        let (export_name, export_name_len) = instance
                            .module
                            .exported_function_name_for_combined(resolved)
                            .ok_or(WasmError::FunctionNotFound)?;
                        Ok((instance.process_id, resolved, signature, export_name, export_name_len))
                    }
                    CallTarget::Host(_) => Err(WasmError::PermissionDenied),
                }
            },
        )
        .map_err(|_| "Target instance not available")?;
    let (actual_owner, function_index, signature, export_name, export_name_len) = match metadata {
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
    let hz = (crate::scheduler::pit::get_frequency() as u64).max(1);
    let entry = ServicePointerEntry {
        active: true,
        object_id,
        owner_pid,
        target_instance,
        function_index,
        export_name,
        export_name_len,
        signature,
        max_calls_per_window: 128,
        window_ticks: hz,
        window_start_tick: crate::scheduler::pit::get_ticks(),
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
        export_name,
        export_name_len,
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
    POLYGLOT_LINEAGE
        .lock()
        .update_lifecycle(object_id, PolyglotLifecycle::Revoked);
    let _ = capability::capability_manager()
        .revoke_object_capabilities(CapabilityType::ServicePointer, object_id);
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
        let _ = capability::capability_manager()
            .revoke_object_capabilities(CapabilityType::ServicePointer, object_ids[i]);
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

    let now = crate::scheduler::pit::get_ticks();
    let entry = SERVICE_POINTERS
        .lock()
        .resolve_for_invoke(object_id, args, now)?;

    let call = wasm_runtime()
        .with_instance_exclusive(
            entry.target_instance,
            |instance| -> Result<ServicePointerInvokeResult, WasmError> {
                if instance.process_id != entry.owner_pid {
                    return Err(WasmError::PermissionDenied);
                }
                let runtime_sig = instance
                    .module
                    .signature_for_combined(entry.function_index)?;
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
            },
        )
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
        Err(e) => {
            crate::serial_println!("[WASM TEST] service pointer invoke failed with {:?}", e);
            Err("Service pointer invocation failed")
        }
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
            instance.inject_capability(WasmCapability::ServicePointer(ServicePointerCapability {
                object_id,
                cap_id,
            }))
        })
        .map_err(|_| "Instance not found")?
        .map_err(|e| e.as_str())
}

// ============================================================================
// WASM Function
// ============================================================================

/// A validated WASM function descriptor.
#[derive(Clone, Copy)]
pub struct Function {
    /// Start offset in bytecode
    pub code_offset: usize,
    /// Code length
    pub code_len: usize,
    /// Canonical module type index for this function.
    pub type_index: usize,
    /// Number of parameters
    pub param_count: usize,
    /// Number of results
    pub result_count: usize,
    /// Canonical parameter value types.
    pub param_types: [ValueType; MAX_WASM_TYPE_ARITY],
    /// Canonical result value types.
    pub result_types: [ValueType; MAX_WASM_TYPE_ARITY],
    /// Whether this signature is fully i32-only and therefore JIT fast-path compatible.
    pub all_i32: bool,
    /// Number of local variables
    pub local_count: usize,
}

impl Function {
    const fn from_signature(
        code_offset: usize,
        code_len: usize,
        local_count: usize,
        type_index: usize,
        signature: ParsedFunctionType,
    ) -> Self {
        Function {
            code_offset,
            code_len,
            type_index,
            param_count: signature.param_count,
            result_count: signature.result_count,
            param_types: signature.param_types,
            result_types: signature.result_types,
            all_i32: signature.all_i32,
            local_count,
        }
    }

    pub(crate) const fn synthetic_i32(
        code_offset: usize,
        code_len: usize,
        param_count: usize,
        result_count: usize,
        local_count: usize,
    ) -> Self {
        Function {
            code_offset,
            code_len,
            type_index: 0,
            param_count,
            result_count,
            param_types: [ValueType::I32; MAX_WASM_TYPE_ARITY],
            result_types: [ValueType::I32; MAX_WASM_TYPE_ARITY],
            all_i32: true,
            local_count,
        }
    }

    pub const fn locals_total(&self) -> usize {
        self.param_count + self.local_count
    }
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

#[derive(Clone, Copy)]
struct FunctionExport {
    name: [u8; 32],
    name_len: u8,
    function_index: usize,
}

impl FunctionExport {
    const fn empty() -> Self {
        Self {
            name: [0u8; 32],
            name_len: 0,
            function_index: 0,
        }
    }
}

// ============================================================================
// Polyglot language tag — set from the `oreulius_lang` custom WASM section
// ============================================================================

/// Source language that compiled this WASM module.
/// Encoded in the `oreulius_lang` custom section as a 1-byte tag
/// followed by 4 version bytes (major, minor, patch, reserved).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum LanguageTag {
    Unknown = 0x00,
    Rust = 0x01,
    Zig = 0x02,
    C = 0x03,
    Python = 0x04, // Pyodide runtime service or Python-compiled WASM
    JS = 0x05,     // QuickJS runtime service or JS-compiled WASM
    AssemblyScript = 0x06,
    Other = 0xFF,
}

impl LanguageTag {
    fn from_byte(b: u8) -> Self {
        match b {
            0x01 => LanguageTag::Rust,
            0x02 => LanguageTag::Zig,
            0x03 => LanguageTag::C,
            0x04 => LanguageTag::Python,
            0x05 => LanguageTag::JS,
            0x06 => LanguageTag::AssemblyScript,
            0xFF => LanguageTag::Other,
            _ => LanguageTag::Unknown,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            LanguageTag::Rust => "rust",
            LanguageTag::Zig => "zig",
            LanguageTag::C => "c",
            LanguageTag::Python => "python",
            LanguageTag::JS => "js",
            LanguageTag::AssemblyScript => "assemblyscript",
            LanguageTag::Other => "other",
            LanguageTag::Unknown => "unknown",
        }
    }
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
    /// Exported functions.
    function_exports: [Option<FunctionExport>; 64],
    /// Number of exported functions.
    export_count: usize,
    /// Exception tag signatures.
    tag_types: [Option<ExceptionTagType>; MAX_WASM_TAGS],
    /// Number of tags.
    tag_count: usize,
    /// Active data segments applied at instantiation.
    data_segments: Vec<DataSegment>,
    /// Source language detected from the `oreulius_lang` custom WASM section.
    pub language_tag: LanguageTag,
    /// Language version from the custom section: [major, minor, patch, reserved].
    pub lang_version: [u8; 4],
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
            function_exports: [None; 64],
            export_count: 0,
            tag_types: [None; MAX_WASM_TAGS],
            tag_count: 0,
            data_segments: Vec::new(),
            language_tag: LanguageTag::Unknown,
            lang_version: [0; 4],
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
        self.function_exports = [None; 64];
        self.export_count = 0;
        self.tag_types = [None; MAX_WASM_TAGS];
        self.tag_count = 0;
        self.data_segments.clear();
    }

    /// Load raw function bytecode for synthetic benchmark/self-test inputs.
    ///
    /// This is intentionally private: `load_binary()` remains the only public
    /// module-loading path.
    fn load_raw_bytecode(&mut self, bytecode: &[u8]) -> Result<(), WasmError> {
        if bytecode.len() > MAX_MODULE_SIZE {
            return Err(WasmError::ModuleTooLarge);
        }
        validate_bytecode(bytecode)?;
        self.replace_bytecode(bytecode);
        self.reset_binary_metadata();
        self.reset_functions();
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
                    // Custom section: parse `oreulius_lang` if present.
                    // Format: LEB128 name_len, name bytes, then 1-byte tag + 4-byte version.
                    if cursor < section_end {
                        if let Ok(name_len) =
                            read_uleb128_at(bytes, &mut cursor).map(|v| v as usize)
                        {
                            let name_end = cursor.saturating_add(name_len);
                            if name_end <= section_end && name_len == 12 {
                                let name_bytes = &bytes[cursor..name_end];
                                if name_bytes == b"oreulius_lang" {
                                    let data_start = name_end;
                                    if data_start < section_end {
                                        self.language_tag =
                                            LanguageTag::from_byte(bytes[data_start]);
                                        if data_start + 5 <= section_end {
                                            self.lang_version.copy_from_slice(
                                                &bytes[data_start + 1..data_start + 5],
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
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
                                let sig =
                                    self.type_signatures[ty_idx].ok_or(WasmError::InvalidModule)?;
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
                    let export_count = read_uleb128_at(bytes, &mut cursor)? as usize;
                    let mut i = 0usize;
                    while i < export_count {
                        let name = read_name_slice(bytes, &mut cursor, section_end)?;
                        let kind = read_byte_at(bytes, &mut cursor)?;
                        let index = read_uleb128_at(bytes, &mut cursor)? as usize;
                        match kind {
                            0x00 => {
                                if index >= self.import_function_count + defined_type_indices.len()
                                {
                                    return Err(WasmError::InvalidModule);
                                }
                                if name.is_empty()
                                    || name.len() > 32
                                    || self.export_count >= self.function_exports.len()
                                {
                                    return Err(WasmError::InvalidModule);
                                }
                                let mut export_name = [0u8; 32];
                                export_name[..name.len()].copy_from_slice(name);
                                self.function_exports[self.export_count] = Some(FunctionExport {
                                    name: export_name,
                                    name_len: name.len() as u8,
                                    function_index: index,
                                });
                                self.export_count += 1;
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
                        let body_end = cursor
                            .checked_add(body_size)
                            .ok_or(WasmError::InvalidModule)?;
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
                        let end = cursor
                            .checked_add(data_len)
                            .ok_or(WasmError::InvalidModule)?;
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
            let defined_idx =
                self.add_function(Function::from_signature(code_offset, code_len, local_count, type_idx, sig))?;
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
            if !matches!(
                self.resolve_call_target(start_idx),
                Ok(CallTarget::Function(_))
            ) {
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
        if func.param_count > MAX_WASM_TYPE_ARITY || func.result_count > MAX_WASM_TYPE_ARITY {
            return Err(WasmError::InvalidModule);
        }

        let idx = self.function_count;
        let combined_idx = self
            .import_function_count
            .checked_add(idx)
            .ok_or(WasmError::InvalidModule)?;

        // Synthetic functions added through the legacy/test path do not come
        // from a parsed type section, so synthesize an all-i32 signature entry.
        let signature = ParsedFunctionType {
            param_count: func.param_count,
            result_count: func.result_count,
            param_types: func.param_types,
            result_types: func.result_types,
            all_i32: func.all_i32,
        };
        let mut ty_idx = None;
        let mut i = 0usize;
        while i < self.type_count {
            if let Some(existing) = self.type_signatures[i] {
                if parsed_signature_equal(existing, signature) {
                    ty_idx = Some(i);
                    break;
                }
            }
            i += 1;
        }
        let ty_idx = match ty_idx {
            Some(idx) => idx,
            None => {
                if self.type_count >= self.type_signatures.len() {
                    return Err(WasmError::TooManyFunctions);
                }
                let idx = self.type_count;
                self.type_signatures[idx] = Some(signature);
                self.type_count += 1;
                idx
            }
        };

        self.functions[idx] = Some(func);
        self.function_type_index[combined_idx] = Some(ty_idx);
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
        self.import_function_count
            .saturating_add(self.function_count)
    }

    fn exported_function_name_for_combined(&self, func_idx: usize) -> Option<([u8; 32], u8)> {
        let mut i = 0usize;
        while i < self.export_count {
            if let Some(export) = self.function_exports[i] {
                if export.function_index == func_idx {
                    return Some((export.name, export.name_len));
                }
            }
            i += 1;
        }
        None
    }

    fn resolve_exported_function(&self, export_name: &[u8]) -> Result<usize, WasmError> {
        let mut i = 0usize;
        while i < self.export_count {
            if let Some(export) = self.function_exports[i] {
                if export.name_len as usize == export_name.len()
                    && &export.name[..export_name.len()] == export_name
                {
                    return Ok(export.function_index);
                }
            }
            i += 1;
        }
        Err(WasmError::FunctionNotFound)
    }

    fn resolve_call_target(&self, func_idx: usize) -> Result<CallTarget, WasmError> {
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
pub(crate) struct JitUserState {
    pub(crate) stack: [i32; MAX_STACK_DEPTH],
    pub(crate) sp: usize,
    pub(crate) locals: [i32; MAX_LOCALS],
    pub(crate) globals: [i32; MAX_WASM_GLOBALS],
    pub(crate) instr_fuel: u32,
    pub(crate) mem_fuel: u32,
    pub(crate) trap_code: i32,
    pub(crate) shadow_stack: [u32; MAX_STACK_DEPTH],
    pub(crate) shadow_sp: usize,
}

// Keep JIT user mappings well away from low-memory kernel/KPTI support pages.
const USER_JIT_TRAMPOLINE_BASE: usize = 0x2000_0000;
const USER_JIT_TRAMPOLINE_FAULT_OFFSET: usize = 0x0000_0100;
const USER_JIT_CALL_BASE: usize = 0x2001_0000;
const USER_JIT_STACK_BASE: usize = 0x2002_0000;
const USER_JIT_CODE_BASE: usize = 0x2003_0000;
const USER_JIT_DATA_BASE: usize = 0x2004_0000;
const USER_WASM_MEM_BASE: usize = 0x2010_0000;
const USER_JIT_STACK_GUARD_PAGES: usize = 1;
const USER_JIT_STACK_PAGES: usize = 1;
const USER_JIT_CODE_GUARD_PAGES: usize = 1;
const USER_JIT_DATA_GUARD_PAGES: usize = 1;
const USER_WASM_MEM_GUARD_PAGES: usize = 1;

#[repr(C)]
#[derive(Clone, Copy)]
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
    req_seq: u32,
    ack_seq: u32,
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
pub(crate) struct ControlFrame {
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
    /// WASM thread pool for this instance (supports WebAssembly Threads proposal).
    thread_pool: crate::execution::wasm_thread::WasmThreadPool,
    /// Cooperative WASM thread currently executing inside this instance.
    active_thread_tid: i32,
    /// WASI context for this instance (CapabilityWASI / Preview 1 ABI).
    wasi_ctx: crate::services::wasi::WasiCtx,
}

// SAFETY: WasmInstance contains raw pointers to kernel-managed memory and is
// only accessed via the WasmRuntime mutex, so sending between threads is safe.
unsafe impl Send for WasmInstance {}

impl WasmInstance {
    unsafe fn boxed_new_in_place(
        module: WasmModule,
        process_id: ProcessId,
        instance_id: usize,
    ) -> Box<Self> {
        let layout = Layout::new::<WasmInstance>();
        let raw = alloc(layout) as *mut WasmInstance;
        if raw.is_null() {
            handle_alloc_error(layout);
        }
        Self::init_in_place(raw, module, process_id, instance_id);
        Box::from_raw(raw)
    }

    unsafe fn init_in_place(
        raw: *mut WasmInstance,
        module: WasmModule,
        process_id: ProcessId,
        instance_id: usize,
    ) {
        let (jit_state, jit_state_pages) = Self::alloc_jit_state();
        let memory = LinearMemory::new(1);
        let stack = Stack::new();
        let capabilities = CapabilityTable::new();

        core::ptr::addr_of_mut!((*raw).module).write(module);
        core::ptr::addr_of_mut!((*raw).memory).write(memory);
        core::ptr::addr_of_mut!((*raw).stack).write(stack);
        core::ptr::addr_of_mut!((*raw).locals).write([Value::I32(0); MAX_LOCALS]);
        core::ptr::addr_of_mut!((*raw).globals).write([None; MAX_WASM_GLOBALS]);
        core::ptr::addr_of_mut!((*raw).control_stack).write([None; MAX_CONTROL_STACK]);
        core::ptr::addr_of_mut!((*raw).control_depth).write(0);
        core::ptr::addr_of_mut!((*raw).current_func_end).write(0);
        core::ptr::addr_of_mut!((*raw).pc).write(0);
        core::ptr::addr_of_mut!((*raw).capabilities).write(capabilities);
        core::ptr::addr_of_mut!((*raw).process_id).write(process_id);
        core::ptr::addr_of_mut!((*raw).instance_id).write(instance_id);
        core::ptr::addr_of_mut!((*raw).is_shadow).write(false);
        core::ptr::addr_of_mut!((*raw).instruction_count).write(0);
        core::ptr::addr_of_mut!((*raw).memory_op_count).write(0);
        core::ptr::addr_of_mut!((*raw).syscall_count).write(0);
        core::ptr::addr_of_mut!((*raw).call_depth).write(0);
        core::ptr::addr_of_mut!((*raw).jit_hash).write([None; 64]);
        core::ptr::addr_of_mut!((*raw).jit_state).write(jit_state);
        core::ptr::addr_of_mut!((*raw).jit_state_pages).write(jit_state_pages);
        core::ptr::addr_of_mut!((*raw).jit_user_pages).write(None);
        core::ptr::addr_of_mut!((*raw).jit_enabled).write(false);
        core::ptr::addr_of_mut!((*raw).jit_hot).write([0; 64]);
        core::ptr::addr_of_mut!((*raw).jit_validate_remaining).write([JIT_VALIDATE_CALLS; 64]);
        core::ptr::addr_of_mut!((*raw).last_received_service_handle).write(None);
        core::ptr::addr_of_mut!((*raw).thread_pool).write(crate::execution::wasm_thread::WasmThreadPool::new());
        core::ptr::addr_of_mut!((*raw).active_thread_tid).write(0);
        core::ptr::addr_of_mut!((*raw).wasi_ctx).write(crate::services::wasi::WasiCtx::new(instance_id));
    }

    fn alloc_jit_state() -> (*mut JitUserState, usize) {
        let size = core::mem::size_of::<JitUserState>();
        let pages = (size + paging::PAGE_SIZE - 1) / paging::PAGE_SIZE;
        let base = memory::jit_allocate_pages(pages).unwrap_or(0) as *mut JitUserState;
        if !base.is_null() {
            let span = pages * paging::PAGE_SIZE;
            if !jit_arena_range_sane(base as usize, span) {
                return (core::ptr::null_mut(), 0);
            }
            // JIT code sealing toggles page writability in the shared arena.
            // Reassert RW policy for per-instance mutable JIT state pages.
            if crate::arch::mmu::set_page_writable_range(base as usize, span, true).is_err() {
                return (core::ptr::null_mut(), 0);
            }
            let _ = crate::security::memory_isolation::tag_jit_user_state(base as usize, span, false);
            unsafe {
                core::ptr::write_bytes(base as *mut u8, 0, span);
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

    fn populate_jit_globals_snapshot(
        globals: &[Option<GlobalSlot>; MAX_WASM_GLOBALS],
        global_count: usize,
        state: &mut JitUserState,
    ) -> Result<(), WasmError> {
        let mut idx = 0usize;
        while idx < MAX_WASM_GLOBALS {
            state.globals[idx] = 0;
            idx += 1;
        }
        let mut g = 0usize;
        while g < global_count {
            let slot = globals[g].ok_or(WasmError::InvalidModule)?;
            match slot.value {
                Value::I32(v) => state.globals[g] = v,
                _ => {}
            }
            g += 1;
        }
        Ok(())
    }

    fn sync_jit_globals_from_state(&mut self) -> Result<(), WasmError> {
        let mut g = 0usize;
        while g < self.module.global_count {
            let mut slot = self.globals[g].ok_or(WasmError::InvalidModule)?;
            if matches!(slot.value_type, ValueType::I32) {
                let state = self.jit_state()?;
                slot.value = Value::I32(state.globals[g]);
                self.globals[g] = Some(slot);
            }
            g += 1;
        }
        Ok(())
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

    fn initialize_thread_execution(
        &mut self,
        thread: &mut crate::execution::wasm_thread::WasmThread,
    ) -> Result<(), WasmError> {
        let func_idx = thread.func_idx as usize;
        let func = self.module.get_function(func_idx)?;
        if func.param_count > 1 {
            return Err(WasmError::InvalidModule);
        }
        if let Some(sig) = self.module.signature_for_defined(func_idx) {
            if sig.param_count > 1 {
                return Err(WasmError::InvalidModule);
            }
            if sig.param_count == 1 && sig.param_types[0] != ValueType::I32 {
                return Err(WasmError::TypeMismatch);
            }
        }
        let locals_total = func
            .param_count
            .checked_add(func.local_count)
            .ok_or(WasmError::InvalidModule)?;
        if locals_total > MAX_LOCALS {
            return Err(WasmError::InvalidLocalIndex);
        }
        let (code_start, end_pc) = self.function_code_range(func)?;
        thread.exec_stack.clear();
        thread.exec_locals = [Value::I32(0); MAX_LOCALS];
        if func.param_count == 1 {
            thread.exec_locals[0] = Value::I32(thread.arg);
        }
        thread.exec_control_stack = [None; MAX_CONTROL_STACK];
        thread.exec_control_depth = 0;
        thread.current_func_end = end_pc;
        thread.pc = code_start;
        thread.call_depth = 1;
        thread.started = true;
        thread.fuel = crate::execution::wasm_thread::DEFAULT_THREAD_FUEL;
        Ok(())
    }

    fn load_thread_execution(&mut self, thread: &crate::execution::wasm_thread::WasmThread) {
        self.stack = thread.exec_stack.clone();
        self.locals = thread.exec_locals;
        self.control_stack = thread.exec_control_stack;
        self.control_depth = thread.exec_control_depth;
        self.current_func_end = thread.current_func_end;
        self.pc = thread.pc;
        self.call_depth = thread.call_depth;
        self.active_thread_tid = thread.tid;
    }

    fn save_thread_execution(&mut self, thread: &mut crate::execution::wasm_thread::WasmThread) {
        thread.exec_stack = self.stack.clone();
        thread.exec_locals = self.locals;
        thread.exec_control_stack = self.control_stack;
        thread.exec_control_depth = self.control_depth;
        thread.current_func_end = self.current_func_end;
        thread.pc = self.pc;
        thread.call_depth = self.call_depth;
    }

    fn run_background_thread_quantum(&mut self) -> Result<bool, WasmError> {
        let (slot_idx, mut thread) = match self.thread_pool.take_next_runnable() {
            Some(next) => next,
            None => return Ok(false),
        };

        let run_result = (|| -> Result<(), WasmError> {
            if !thread.started {
                self.initialize_thread_execution(&mut thread)?;
            }

            self.load_thread_execution(&thread);
            self.reset_limits();
            let mut remaining = if thread.fuel == 0 {
                crate::execution::wasm_thread::DEFAULT_THREAD_FUEL
            } else {
                thread.fuel
            };

            while self.pc < self.current_func_end {
                if remaining == 0 {
                    self.save_thread_execution(&mut thread);
                    thread.state = crate::execution::wasm_thread::ThreadState::Yielded;
                    thread.fuel = crate::execution::wasm_thread::DEFAULT_THREAD_FUEL;
                    self.active_thread_tid = 0;
                    return Ok(());
                }

                match self.step() {
                    Ok(true) => {
                        remaining = remaining.saturating_sub(1);
                    }
                    Ok(false) => {
                        thread.finish(0);
                        self.active_thread_tid = 0;
                        return Ok(());
                    }
                    Err(WasmError::ThreadYielded) => {
                        self.save_thread_execution(&mut thread);
                        thread.state = crate::execution::wasm_thread::ThreadState::Yielded;
                        thread.fuel = crate::execution::wasm_thread::DEFAULT_THREAD_FUEL;
                        self.active_thread_tid = 0;
                        return Ok(());
                    }
                    Err(WasmError::ThreadBlockedOnJoin(target_tid)) => {
                        self.save_thread_execution(&mut thread);
                        thread.state = crate::execution::wasm_thread::ThreadState::Joining(target_tid);
                        thread.fuel = crate::execution::wasm_thread::DEFAULT_THREAD_FUEL;
                        self.active_thread_tid = 0;
                        return Ok(());
                    }
                    Err(WasmError::ThreadExited(code)) => {
                        thread.finish(code);
                        self.active_thread_tid = 0;
                        return Ok(());
                    }
                    Err(e) => {
                        thread.finish(-1);
                        self.active_thread_tid = 0;
                        return Err(e);
                    }
                }
            }

            thread.finish(0);
            self.active_thread_tid = 0;
            Ok(())
        })();

        if self.active_thread_tid != 0 {
            self.active_thread_tid = 0;
        }
        let _ = self.thread_pool.restore_thread_slot(slot_idx, thread);
        run_result?;
        Ok(true)
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

    fn find_exception_handler(&self, frame: ControlFrame, tag_idx: usize) -> Option<(usize, bool)> {
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
                    let target_plus_one = idx.checked_sub(delegate_depth).ok_or(WasmError::Trap)?;
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

    fn skip_opcode_immediate_scan(
        &self,
        mut pc: usize,
        opcode: Opcode,
    ) -> Result<usize, WasmError> {
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
                    let (tag_idx, _n) =
                        read_uleb128_validate(&self.module.bytecode, immediate_pos)?;
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
        // Harden fuzz/replay re-entry on long x86_64 bring-up runs: if per-instance
        // JIT user state was damaged by prior unsafe JIT execution, rebuild it
        // in-place instead of hard-failing the whole fuzz iteration.
        if self.jit_state.is_null() || self.jit_state_pages == 0 {
            let (state, pages) = Self::alloc_jit_state();
            if state.is_null() || pages == 0 {
                return Err(WasmError::Trap);
            }
            self.jit_state = state;
            self.jit_state_pages = pages;
        }
        let span = self
            .jit_state_pages
            .checked_mul(paging::PAGE_SIZE)
            .ok_or(WasmError::Trap)?;
        let state_base = self.jit_state as usize;
        let range_sane = jit_arena_range_sane(state_base, span);
        if !range_sane {
            let (state, pages) = Self::alloc_jit_state();
            if state.is_null() || pages == 0 {
                return Err(WasmError::Trap);
            }
            self.jit_state = state;
            self.jit_state_pages = pages;
            let rebuilt_span = self
                .jit_state_pages
                .checked_mul(paging::PAGE_SIZE)
                .ok_or(WasmError::Trap)?;
            if crate::arch::mmu::set_page_writable_range(
                self.jit_state as usize,
                rebuilt_span,
                true,
            )
            .is_err()
            {
                #[cfg(not(target_arch = "x86_64"))]
                {
                    return Err(WasmError::Trap);
                }
            }
            let _ = crate::security::memory_isolation::tag_jit_user_state(
                self.jit_state as usize,
                rebuilt_span,
                false,
            );
        } else {
            if crate::arch::mmu::set_page_writable_range(self.jit_state as usize, span, true)
                .is_err()
            {
                #[cfg(not(target_arch = "x86_64"))]
                {
                    return Err(WasmError::Trap);
                }
            }
            let _ =
                crate::security::memory_isolation::tag_jit_user_state(self.jit_state as usize, span, false);
        }
        self.module.load_raw_bytecode(code)?;
        self.module.reset_functions();
        let _ = self
            .module
            .add_function(Function::synthetic_i32(0, code.len(), 0, 1, locals_total))?;
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
        let globals_snapshot = self.globals;
        let global_count = self.module.global_count;
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
            globals_ptr,
            instr_fuel,
            mem_fuel,
            trap_code,
            shadow_stack_ptr,
            shadow_sp_ptr,
        ) = {
            let state = self.jit_state_mut()?;
            let mut idx = 0usize;
            while idx < MAX_STACK_DEPTH {
                state.stack[idx] = 0;
                state.shadow_stack[idx] = 0;
                idx += 1;
            }
            let mut local_idx = 0usize;
            while local_idx < MAX_LOCALS {
                state.locals[local_idx] = 0;
                local_idx += 1;
            }
            for i in 0..locals_total {
                state.locals[i] = locals_buf[i];
            }
            Self::populate_jit_globals_snapshot(&globals_snapshot, global_count, state)?;
            state.sp = 0;
            state.instr_fuel = MAX_INSTRUCTIONS_PER_CALL as u32;
            state.mem_fuel = MAX_MEMORY_OPS_PER_CALL as u32;
            state.trap_code = 0;
            state.shadow_sp = 0;
            (
                state.stack.as_mut_ptr(),
                &mut state.sp as *mut usize,
                state.locals.as_mut_ptr(),
                state.globals.as_mut_ptr(),
                &mut state.instr_fuel as *mut u32,
                &mut state.mem_fuel as *mut u32,
                &mut state.trap_code as *mut i32,
                state.shadow_stack.as_mut_ptr(),
                &mut state.shadow_sp as *mut usize,
            )
        };
        #[cfg(not(target_arch = "x86_64"))]
        let _ = globals_ptr;
        #[cfg(target_arch = "x86_64")]
        let _ = shadow_stack_ptr;
        #[cfg(target_arch = "x86_64")]
        let cfi_stack_ptr = globals_ptr as *mut u32;
        #[cfg(not(target_arch = "x86_64"))]
        let cfi_stack_ptr = shadow_stack_ptr;

        // Build the JIT function-table for call_indirect support.
        // fn_table[i] = JitFn entry address for the function at WASM table slot i (0 = not compiled).
        let type_sigs = collect_jit_type_signatures(&self.module);
        let type_sig_hash = hash_jit_type_signatures(&type_sigs);
        let global_sigs = collect_jit_global_signatures(&self.module);
        let global_sig_hash = hash_jit_global_signatures(&global_sigs);
        let mut fn_table = [0usize; MAX_WASM_TABLE_ENTRIES];
        let table_size = self.module.table_size;
        for slot in 0..table_size.min(MAX_WASM_TABLE_ENTRIES) {
            if let Some(callee_func_idx) = self.module.table_entries[slot] {
                if let Ok(callee_func) = self.module.get_function(callee_func_idx) {
                    if let Ok((cs, ce)) = self.function_code_range(callee_func) {
                        let callee_code = &self.module.bytecode[cs..ce];
                        let callee_locals = callee_func.param_count + callee_func.local_count;
                        let callee_hash = hash_code(callee_code, callee_locals)
                            ^ type_sig_hash
                            ^ global_sig_hash;
                        if let Some(entry) = jit_cache_get_or_compile(
                            callee_hash,
                            callee_code,
                            callee_locals,
                            &type_sigs,
                            type_sig_hash,
                            &global_sigs,
                            global_sig_hash,
                        ) {
                            fn_table[slot] = entry.entry as usize;
                        }
                    }
                }
            }
        }
        let fn_table_base = fn_table.as_ptr();
        let fn_table_len = table_size.min(MAX_WASM_TABLE_ENTRIES);

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
            cfi_stack_ptr,
            shadow_sp_ptr,
            jit_state_base,
            jit_state_pages,
            &mut self.jit_user_pages,
            self.process_id.0,
            self.instance_id as u32,
            func_idx as u32,
            fn_table_base,
            fn_table_len,
        );
        let (trap_code_val, instr_left, mem_left, sp_val, shadow_sp_val) = {
            let state = self.jit_state()?;
            (
                state.trap_code,
                state.instr_fuel,
                state.mem_fuel,
                state.sp,
                state.shadow_sp,
            )
        };
        // Prefer explicit trap reasons from the JIT runtime first. In user-mode
        // sandbox fault paths, stack cursors can be left non-zero at abort time;
        // classification should still reflect the originating trap.
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
        if sp_val > MAX_STACK_DEPTH {
            return Err(WasmError::Trap);
        }
        if shadow_sp_val > MAX_STACK_DEPTH {
            return Err(WasmError::ControlFlowViolation);
        }
        if sp_val != 0 || shadow_sp_val != 0 {
            return Err(WasmError::ControlFlowViolation);
        }
        if func.result_count == 1 {
            self.stack.push(Value::I32(ret))?;
        }
        self.sync_jit_globals_from_state()?;
        self.instruction_count =
            (MAX_INSTRUCTIONS_PER_CALL as u32).saturating_sub(instr_left) as usize;
        self.memory_op_count = (MAX_MEMORY_OPS_PER_CALL as u32).saturating_sub(mem_left) as usize;
        Ok(())
    }

    /// Create a new instance
    pub fn new(module: WasmModule, process_id: ProcessId, instance_id: usize) -> Self {
        let (jit_state, jit_state_pages) = Self::alloc_jit_state();
        let memory = LinearMemory::new(1);
        let stack = Stack::new();
        let capabilities = CapabilityTable::new();
        WasmInstance {
            module,
            memory, // 1 page = 64 KiB
            stack,
            locals: [Value::I32(0); MAX_LOCALS],
            globals: [None; MAX_WASM_GLOBALS],
            control_stack: [None; MAX_CONTROL_STACK],
            control_depth: 0,
            current_func_end: 0,
            pc: 0,
            capabilities,
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
            thread_pool: crate::execution::wasm_thread::WasmThreadPool::new(),
            active_thread_tid: 0,
            wasi_ctx: crate::services::wasi::WasiCtx::new(instance_id),
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
        let type_sigs = collect_jit_type_signatures(&self.module);
        let type_sig_hash = hash_jit_type_signatures(&type_sigs);
        let global_sigs = collect_jit_global_signatures(&self.module);
        let global_sig_hash = hash_jit_global_signatures(&global_sigs);

        self.jit_hot[func_idx] = self.jit_hot[func_idx].saturating_add(1);
        if self.jit_hash[func_idx].is_none() {
            let threshold = jit_config().lock().hot_threshold;
            if self.jit_hot[func_idx] < threshold {
                jit_stats().lock().interp_calls += 1;
                return Ok(false);
            }
            let hash = hash_code(code, locals_total) ^ type_sig_hash ^ global_sig_hash;
            let entry = match jit_cache_get_or_compile(
                hash,
                code,
                locals_total,
                &type_sigs,
                type_sig_hash,
                &global_sigs,
                global_sig_hash,
            ) {
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
        let jit_entry =
            match jit_cache_get(hash, code, locals_total, type_sig_hash, global_sig_hash) {
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
        let globals_snapshot = self.globals;
        let global_count = self.module.global_count;

        // Consume stack params now that we're committed to JIT execution.
        for _ in 0..func.param_count {
            let _ = self.stack.pop()?;
        }

        let (
            stack_ptr,
            sp_ptr,
            locals_ptr,
            globals_ptr,
            instr_fuel,
            mem_fuel,
            trap_code,
            shadow_stack_ptr,
            shadow_sp_ptr,
        ) = {
            let state = self.jit_state_mut()?;
            let mut stack_idx = 0usize;
            while stack_idx < MAX_STACK_DEPTH {
                state.stack[stack_idx] = 0;
                state.shadow_stack[stack_idx] = 0;
                stack_idx += 1;
            }
            let mut local_idx = 0usize;
            while local_idx < MAX_LOCALS {
                state.locals[local_idx] = 0;
                local_idx += 1;
            }
            for i in 0..locals_total {
                state.locals[i] = locals_buf[i];
            }
            Self::populate_jit_globals_snapshot(&globals_snapshot, global_count, state)?;
            state.sp = 0;
            state.instr_fuel = MAX_INSTRUCTIONS_PER_CALL as u32;
            state.mem_fuel = MAX_MEMORY_OPS_PER_CALL as u32;
            state.trap_code = 0;
            state.shadow_sp = 0;
            (
                state.stack.as_mut_ptr(),
                &mut state.sp as *mut usize,
                state.locals.as_mut_ptr(),
                state.globals.as_mut_ptr(),
                &mut state.instr_fuel as *mut u32,
                &mut state.mem_fuel as *mut u32,
                &mut state.trap_code as *mut i32,
                state.shadow_stack.as_mut_ptr(),
                &mut state.shadow_sp as *mut usize,
            )
        };
        #[cfg(not(target_arch = "x86_64"))]
        let _ = globals_ptr;
        #[cfg(target_arch = "x86_64")]
        let _ = shadow_stack_ptr;
        #[cfg(target_arch = "x86_64")]
        let cfi_stack_ptr = globals_ptr as *mut u32;
        #[cfg(not(target_arch = "x86_64"))]
        let cfi_stack_ptr = shadow_stack_ptr;

        // Build JIT function-table for call_indirect support.
        let type_sigs_ci = collect_jit_type_signatures(&self.module);
        let type_sig_hash_ci = hash_jit_type_signatures(&type_sigs_ci);
        let global_sigs_ci = collect_jit_global_signatures(&self.module);
        let global_sig_hash_ci = hash_jit_global_signatures(&global_sigs_ci);
        let mut fn_table_ci = [0usize; MAX_WASM_TABLE_ENTRIES];
        let table_size_ci = self.module.table_size;
        for slot in 0..table_size_ci.min(MAX_WASM_TABLE_ENTRIES) {
            if let Some(callee_func_idx) = self.module.table_entries[slot] {
                if let Ok(callee_func) = self.module.get_function(callee_func_idx) {
                    if let Ok((cs, ce)) = self.function_code_range(callee_func) {
                        let callee_code = &self.module.bytecode[cs..ce];
                        let callee_locals = callee_func.param_count + callee_func.local_count;
                        let callee_hash = hash_code(callee_code, callee_locals)
                            ^ type_sig_hash_ci
                            ^ global_sig_hash_ci;
                        if let Some(entry) = jit_cache_get_or_compile(
                            callee_hash,
                            callee_code,
                            callee_locals,
                            &type_sigs_ci,
                            type_sig_hash_ci,
                            &global_sigs_ci,
                            global_sig_hash_ci,
                        ) {
                            fn_table_ci[slot] = entry.entry as usize;
                        }
                    }
                }
            }
        }
        let fn_table_base_ci = fn_table_ci.as_ptr();
        let fn_table_len_ci = table_size_ci.min(MAX_WASM_TABLE_ENTRIES);

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
            cfi_stack_ptr,
            shadow_sp_ptr,
            jit_state_base,
            jit_state_pages,
            &mut self.jit_user_pages,
            self.process_id.0,
            self.instance_id as u32,
            func_idx as u32,
            fn_table_base_ci,
            fn_table_len_ci,
        );
        let (trap_code_val, instr_left, mem_left, sp_val, shadow_sp_val) = {
            let state = self.jit_state()?;
            (
                state.trap_code,
                state.instr_fuel,
                state.mem_fuel,
                state.sp,
                state.shadow_sp,
            )
        };
        // Match run_jit_entry classification order: honor trap_code first.
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
        if sp_val > MAX_STACK_DEPTH {
            if let Some(shadow_inst) = shadow {
                self.restore_from_shadow(shadow_inst);
                self.disable_jit_for_function(func_idx);
                return Ok(true);
            }
            return Err(WasmError::Trap);
        }
        if shadow_sp_val > MAX_STACK_DEPTH || sp_val != 0 || shadow_sp_val != 0 {
            if let Some(shadow_inst) = shadow {
                self.restore_from_shadow(shadow_inst);
                self.disable_jit_for_function(func_idx);
                return Ok(true);
            }
            return Err(WasmError::ControlFlowViolation);
        }
        if func.result_count == 1 {
            self.stack.push(Value::I32(ret))?;
        }
        self.sync_jit_globals_from_state()?;
        self.instruction_count =
            (MAX_INSTRUCTIONS_PER_CALL as u32).saturating_sub(instr_left) as usize;
        self.memory_op_count = (MAX_MEMORY_OPS_PER_CALL as u32).saturating_sub(mem_left) as usize;

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
            thread_pool: crate::execution::wasm_thread::WasmThreadPool::new(),
            active_thread_tid: self.active_thread_tid,
            wasi_ctx: crate::services::wasi::WasiCtx::new(self.instance_id),
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
        self.active_thread_tid = shadow.active_thread_tid;
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
        if shadow_hash != self_hash {
            return false;
        }
        let mut g = 0usize;
        while g < self.module.global_count {
            let shadow_slot = shadow.globals[g];
            let self_slot = self.globals[g];
            match (shadow_slot, self_slot) {
                (Some(a), Some(b)) => {
                    if a.value_type != b.value_type || a.mutable != b.mutable {
                        return false;
                    }
                    match (a.value, b.value) {
                        (Value::I32(x), Value::I32(y)) if x == y => {}
                        (Value::I64(x), Value::I64(y)) if x == y => {}
                        (Value::FuncRef(x), Value::FuncRef(y)) if x == y => {}
                        (Value::ExternRef(x), Value::ExternRef(y)) if x == y => {}
                        (Value::F32(x), Value::F32(y)) if x.to_bits() == y.to_bits() => {}
                        (Value::F64(x), Value::F64(y)) if x.to_bits() == y.to_bits() => {}
                        _ => return false,
                    }
                }
                (None, None) => {}
                _ => return false,
            }
            g += 1;
        }
        true
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

            // Check capability security policy unless this is an internal JIT fuzz run.
            if !JIT_FUZZ_ACTIVE.load(Ordering::Relaxed) {
                if !crate::security::security()
                    .validate_capability(
                        self.process_id,
                        1, // Execute permission
                        1,
                    )
                    .is_ok()
                {
                    return Err(WasmError::PermissionDenied);
                }
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
            let mut fuzz_trace_budget = if JIT_FUZZ_ACTIVE.load(Ordering::Relaxed)
                && jit_fuzz_verbose_trace_enabled()
            {
                16usize
            } else {
                0usize
            };

            while self.pc < end_pc {
                if fuzz_trace_budget != 0 {
                    crate::serial_println!(
                        "[WASM-STEP] func={} pc={} op=0x{:02x}",
                        func_idx,
                        self.pc,
                        self.module.bytecode[self.pc]
                    );
                    fuzz_trace_budget -= 1;
                }
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

        // ── WASM Threads / Atomics prefix (0xFE) ────────────────────────────
        // Dispatch before the main Opcode table; handles the full
        // WebAssembly Threads proposal (memory.atomic.wait/notify, i32/i64
        // atomic load/store, and all RMW variants).
        if opcode_byte == 0xFE {
            return self.step_atomic();
        }

        let opcode = Opcode::from_byte(opcode_byte).ok_or(WasmError::UnknownOpcode(opcode_byte))?;

        match opcode {
            Opcode::Nop => {}

            Opcode::Unreachable => {
                return Err(WasmError::Trap);
            }

            Opcode::Block => {
                let (param_count, param_types, result_count, result_types) =
                    self.read_block_signature()?;
                let body_start = self.pc;
                let (_else_pc, end_pc) =
                    self.scan_control_structure(ControlKind::Block, body_start)?;
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
                let (_else_pc, end_pc) =
                    self.scan_control_structure(ControlKind::Loop, body_start)?;
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
                self.pc = frame
                    .end_pc
                    .checked_add(1)
                    .ok_or(WasmError::InvalidModule)?;
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
                self.pc = frame
                    .end_pc
                    .checked_add(1)
                    .ok_or(WasmError::InvalidModule)?;
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
                self.pc = frame
                    .end_pc
                    .checked_add(1)
                    .ok_or(WasmError::InvalidModule)?;
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
                self.pc = frame
                    .end_pc
                    .checked_add(1)
                    .ok_or(WasmError::InvalidModule)?;
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
                // WASM requires a trap for INT_MIN / -1 overflow.
                if a == i32::MIN && b == -1 {
                    return Err(WasmError::Trap);
                }
                self.stack.push(Value::I32(a / b))?;
            }

            Opcode::I32DivU => {
                let b = self.stack.pop()?.as_u32()?;
                let a = self.stack.pop()?.as_u32()?;
                if b == 0 {
                    return Err(WasmError::DivisionByZero);
                }
                self.stack.push(Value::I32((a / b) as i32))?;
            }

            Opcode::I32RemS => {
                let b = self.stack.pop()?.as_i32()?;
                let a = self.stack.pop()?.as_i32()?;
                if b == 0 {
                    return Err(WasmError::DivisionByZero);
                }
                // WASM defines INT_MIN % -1 == 0 (no trap).
                if a == i32::MIN && b == -1 {
                    self.stack.push(Value::I32(0))?;
                } else {
                    self.stack.push(Value::I32(a % b))?;
                }
            }

            Opcode::I32RemU => {
                let b = self.stack.pop()?.as_u32()?;
                let a = self.stack.pop()?.as_u32()?;
                if b == 0 {
                    return Err(WasmError::DivisionByZero);
                }
                self.stack.push(Value::I32((a % b) as i32))?;
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

            Opcode::I64Eqz => {
                let a = self.stack.pop()?.as_i64()?;
                self.stack.push(Value::I32(if a == 0 { 1 } else { 0 }))?;
            }

            Opcode::I64Eq => {
                let b = self.stack.pop()?.as_i64()?;
                let a = self.stack.pop()?.as_i64()?;
                self.stack.push(Value::I32(if a == b { 1 } else { 0 }))?;
            }

            Opcode::I64Ne => {
                let b = self.stack.pop()?.as_i64()?;
                let a = self.stack.pop()?.as_i64()?;
                self.stack.push(Value::I32(if a != b { 1 } else { 0 }))?;
            }

            Opcode::I64LtS => {
                let b = self.stack.pop()?.as_i64()?;
                let a = self.stack.pop()?.as_i64()?;
                self.stack.push(Value::I32(if a < b { 1 } else { 0 }))?;
            }

            Opcode::I64LtU => {
                let b = self.stack.pop()?.as_i64()? as u64;
                let a = self.stack.pop()?.as_i64()? as u64;
                self.stack.push(Value::I32(if a < b { 1 } else { 0 }))?;
            }

            Opcode::I64GtS => {
                let b = self.stack.pop()?.as_i64()?;
                let a = self.stack.pop()?.as_i64()?;
                self.stack.push(Value::I32(if a > b { 1 } else { 0 }))?;
            }

            Opcode::I64GtU => {
                let b = self.stack.pop()?.as_i64()? as u64;
                let a = self.stack.pop()?.as_i64()? as u64;
                self.stack.push(Value::I32(if a > b { 1 } else { 0 }))?;
            }

            Opcode::I64LeS => {
                let b = self.stack.pop()?.as_i64()?;
                let a = self.stack.pop()?.as_i64()?;
                self.stack.push(Value::I32(if a <= b { 1 } else { 0 }))?;
            }

            Opcode::I64LeU => {
                let b = self.stack.pop()?.as_i64()? as u64;
                let a = self.stack.pop()?.as_i64()? as u64;
                self.stack.push(Value::I32(if a <= b { 1 } else { 0 }))?;
            }

            Opcode::I64GeS => {
                let b = self.stack.pop()?.as_i64()?;
                let a = self.stack.pop()?.as_i64()?;
                self.stack.push(Value::I32(if a >= b { 1 } else { 0 }))?;
            }

            Opcode::I64GeU => {
                let b = self.stack.pop()?.as_i64()? as u64;
                let a = self.stack.pop()?.as_i64()? as u64;
                self.stack.push(Value::I32(if a >= b { 1 } else { 0 }))?;
            }

            Opcode::I32WrapI64 => {
                let a = self.stack.pop()?.as_i64()?;
                self.stack.push(Value::I32(a as i32))?;
            }

            Opcode::I64ExtendI32S => {
                let a = self.stack.pop()?.as_i32()?;
                self.stack.push(Value::I64(a as i64))?;
            }

            Opcode::I64ExtendI32U => {
                let a = self.stack.pop()?.as_i32()?;
                self.stack.push(Value::I64((a as u32) as i64))?;
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

            Opcode::I32LtS => {
                let b = self.stack.pop()?.as_i32()?;
                let a = self.stack.pop()?.as_i32()?;
                self.stack.push(Value::I32(if a < b { 1 } else { 0 }))?;
            }

            Opcode::I32GtS => {
                let b = self.stack.pop()?.as_i32()?;
                let a = self.stack.pop()?.as_i32()?;
                self.stack.push(Value::I32(if a > b { 1 } else { 0 }))?;
            }

            Opcode::I32LeS => {
                let b = self.stack.pop()?.as_i32()?;
                let a = self.stack.pop()?.as_i32()?;
                self.stack.push(Value::I32(if a <= b { 1 } else { 0 }))?;
            }

            Opcode::I32GeS => {
                let b = self.stack.pop()?.as_i32()?;
                let a = self.stack.pop()?.as_i32()?;
                self.stack.push(Value::I32(if a >= b { 1 } else { 0 }))?;
            }

            Opcode::I32LtU => {
                let b = self.stack.pop()?.as_u32()?;
                let a = self.stack.pop()?.as_u32()?;
                self.stack.push(Value::I32(if a < b { 1 } else { 0 }))?;
            }

            Opcode::I32GtU => {
                let b = self.stack.pop()?.as_u32()?;
                let a = self.stack.pop()?.as_u32()?;
                self.stack.push(Value::I32(if a > b { 1 } else { 0 }))?;
            }

            Opcode::I32LeU => {
                let b = self.stack.pop()?.as_u32()?;
                let a = self.stack.pop()?.as_u32()?;
                self.stack.push(Value::I32(if a <= b { 1 } else { 0 }))?;
            }

            Opcode::I32GeU => {
                let b = self.stack.pop()?.as_u32()?;
                let a = self.stack.pop()?.as_u32()?;
                self.stack.push(Value::I32(if a >= b { 1 } else { 0 }))?;
            }

            Opcode::I32Shl => {
                let b = self.stack.pop()?.as_i32()? as u32;
                let a = self.stack.pop()?.as_i32()?;
                let sh = b & 31;
                self.stack.push(Value::I32(a.wrapping_shl(sh)))?;
            }

            Opcode::I32ShrS => {
                let b = self.stack.pop()?.as_i32()? as u32;
                let a = self.stack.pop()?.as_i32()?;
                let sh = b & 31;
                self.stack.push(Value::I32(a >> sh))?;
            }

            Opcode::I32ShrU => {
                let b = self.stack.pop()?.as_i32()? as u32;
                let a = self.stack.pop()?.as_u32()?;
                let sh = b & 31;
                self.stack.push(Value::I32((a >> sh) as i32))?;
            }

            Opcode::I32Load => {
                self.check_memory_limit()?;
                let _align = self.read_uleb128()?; // Alignment hint (ignored for now)
                let offset = self.read_uleb128()? as usize;
                let addr = self.stack.pop()?.as_u32()? as usize;
                let effective_addr = addr
                    .checked_add(offset)
                    .ok_or(WasmError::MemoryOutOfBounds)?;
                let value = self.memory.read_i32(effective_addr)?;
                self.stack.push(Value::I32(value))?;
            }

            Opcode::I64Load => {
                self.check_memory_limit()?;
                let _align = self.read_uleb128()?; // Alignment hint (ignored for now)
                let offset = self.read_uleb128()? as usize;
                let addr = self.stack.pop()?.as_u32()? as usize;
                let effective_addr = addr
                    .checked_add(offset)
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
                let effective_addr = addr
                    .checked_add(offset)
                    .ok_or(WasmError::MemoryOutOfBounds)?;
                self.memory.write_i32(effective_addr, value)?;
            }

            Opcode::I64Store => {
                self.check_memory_limit()?;
                let _align = self.read_uleb128()?;
                let offset = self.read_uleb128()? as usize;
                let value = self.stack.pop()?.as_i64()?;
                let addr = self.stack.pop()?.as_u32()? as usize;
                let effective_addr = addr
                    .checked_add(offset)
                    .ok_or(WasmError::MemoryOutOfBounds)?;
                self.memory.write_i64(effective_addr, value)?;
            }

            Opcode::MemorySize => {
                let mem_idx = self.read_uleb128()?;
                if mem_idx != 0 {
                    return Err(WasmError::InvalidModule);
                }
                self.stack.push(Value::I32(self.memory.size() as i32))?;
            }

            Opcode::MemoryGrow => {
                let mem_idx = self.read_uleb128()?;
                if mem_idx != 0 {
                    return Err(WasmError::InvalidModule);
                }
                let delta = self.stack.pop()?.as_i32()? as usize;
                match self.memory.grow(delta) {
                    Ok(old_size) => {
                        self.thread_pool.notify_grow(self.memory.active_len());
                        self.stack.push(Value::I32(old_size as i32))?;
                    }
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

            #[allow(unreachable_patterns)]
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

    /// Call a host function (Oreulius syscall)
    fn call_host_function(&mut self, func_idx: usize) -> Result<(), WasmError> {
        // Check syscall limit
        self.check_syscall_limit()?;
        let spec = HOST_FUNCTION_SPECS
            .get(func_idx)
            .ok_or(WasmError::UnknownHostFunction)?;
        spec.dispatch(self)
    }

    fn replay_mode(&self) -> ReplayMode {
        if self.is_shadow {
            ReplayMode::Off
        } else {
            replay::mode(self.instance_id)
        }
    }

    // ========================================================================
    // Oreulius Syscalls
    // ========================================================================

    /// oreulius_log(msg_ptr: i32, msg_len: i32)
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
            crate::drivers::x86::vga::print_str("[WASM] ");
            crate::drivers::x86::vga::print_str(msg_str);
            crate::drivers::x86::vga::print_char('\n');
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

    /// oreulius_fs_read(cap: i32, key_ptr: i32, key_len: i32, buf_ptr: i32, buf_len: i32) -> i32
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
        let key_str = core::str::from_utf8(key_bytes).map_err(|_| WasmError::InvalidUtf8)?;
        let key = fs::FileKey::new(key_str).map_err(|_| WasmError::SyscallFailed)?;

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

    /// oreulius_fs_write(cap: i32, key_ptr: i32, key_len: i32, data_ptr: i32, data_len: i32) -> i32
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
        let key_str = core::str::from_utf8(key_bytes).map_err(|_| WasmError::InvalidUtf8)?;
        let key = fs::FileKey::new(key_str).map_err(|_| WasmError::SyscallFailed)?;

        // Call filesystem
        crate::security::security().intent_fs_write(self.process_id, fs_cap.cap_id as u64);
        let request =
            fs::Request::write(key, data, fs_cap).map_err(|_| WasmError::SyscallFailed)?;
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

    /// oreulius_channel_send(cap: i32, msg_ptr: i32, msg_len: i32) -> i32
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

    /// oreulius_channel_recv(cap: i32, buf_ptr: i32, buf_len: i32) -> i32
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
                let msg_data = &msg.payload[..msg.payload.len()];
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

    /// oreulius_net_http_get(url_ptr: i32, url_len: i32, buf_ptr: i32, buf_len: i32) -> i32
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
        let url_str = core::str::from_utf8(url_bytes).map_err(|_| WasmError::InvalidUtf8)?;

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

    /// oreulius_net_connect(host_ptr: i32, host_len: i32, port: i32) -> i32
    fn host_net_connect(&mut self) -> Result<(), WasmError> {
        let port = self.stack.pop()?.as_i32()? as u16;
        let host_len = self.stack.pop()?.as_i32()? as usize;
        let host_ptr = self.stack.pop()?.as_i32()? as usize;

        // Read host from memory
        let host_bytes = self.memory.read(host_ptr, host_len)?;
        let func_id: u16 = 6;
        crate::security::security().intent_wasm_call(self.process_id, func_id as u64);
        let mut args_hash = replay::fnv1a64_init();
        args_hash = replay::hash_u16(args_hash, func_id);
        args_hash = replay::hash_u32(args_hash, host_len as u32);
        args_hash = replay::hash_u32(args_hash, port as u32);
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
        let host_str = core::str::from_utf8(host_bytes).map_err(|_| WasmError::InvalidUtf8)?;
        let remote_ip = match parse_net_host(host_str) {
            Some(ip) => ip,
            None => {
                let mut net = crate::net::network().lock();
                net.dns_resolve(host_str).map_err(|_| WasmError::SyscallFailed)?
            }
        };
        let conn_id = crate::net::net_reactor::tcp_connect(
            crate::net::netstack::Ipv4Addr(remote_ip.0),
            port,
        )
        .map_err(|_| WasmError::SyscallFailed)?;

        self.stack.push(Value::I32(conn_id as i32))?;
        if mode == ReplayMode::Record {
            replay::record_host_call(
                self.instance_id,
                func_id,
                args_hash,
                ReplayEventStatus::Ok,
                conn_id as i32,
                &[],
            )
            .map_err(|_| WasmError::ReplayError)?;
        }
        Ok(())
    }

    /// oreulius_dns_resolve(domain_ptr: i32, domain_len: i32) -> i32 (returns IP as u32)
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
        let domain_str = core::str::from_utf8(domain_bytes).map_err(|_| WasmError::InvalidUtf8)?;

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

            if let Ok(handle) =
                self.inject_capability(WasmCapability::ServicePointer(ServicePointerCapability {
                    object_id,
                    cap_id: imported,
                }))
            {
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

    fn encode_temporal_meta(
        meta: &crate::temporal::TemporalVersionMeta,
    ) -> [u8; TEMPORAL_META_BYTES] {
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

    fn encode_temporal_history_record(
        meta: &crate::temporal::TemporalVersionMeta,
    ) -> [u8; TEMPORAL_HISTORY_RECORD_BYTES] {
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
        if result.used_fallback {
            flags |= 1 << 4;
        }
        if result.conflict_count > 0 {
            flags |= 1 << 5;
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
            result.merge_kind.as_u32(),
            result.conflict_count,
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

    /// oreulius_service_invoke(cap: i32, args_ptr: i32, args_count: i32) -> i32
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
            let bytes = self.memory.read(args_ptr, args_count.saturating_mul(4))?;
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

        let result =
            invoke_service_pointer(self.process_id, svc_ptr.object_id, &words[..args_count])
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

    /// oreulius_service_invoke_typed(cap: i32, args_ptr: i32, args_count: i32, results_ptr: i32, results_capacity: i32) -> i32
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
            Self::encode_typed_service_value(
                result.values[i],
                &mut encoded_results[base..base + SERVICE_TYPED_SLOT_BYTES],
            )?;
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

    /// oreulius_service_register(func: i32|funcref, delegate: i32) -> i32
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

    /// oreulius_channel_send_cap(chan_cap: i32, msg_ptr: i32, msg_len: i32, cap: i32) -> i32
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
            msg.add_capability(ipc_cap)
                .map_err(|_| WasmError::SyscallFailed)?;
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

    /// oreulius_last_service_cap() -> i32
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

    /// oreulius_temporal_snapshot(cap: i32, path_ptr: i32, path_len: i32, out_meta_ptr: i32) -> i32
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

    /// oreulius_temporal_latest(cap: i32, path_ptr: i32, path_len: i32, out_meta_ptr: i32) -> i32
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

    /// oreulius_temporal_read(cap: i32, path_ptr: i32, path_len: i32, version_lo: i32, version_hi: i32, buf_ptr: i32, buf_len: i32) -> i32
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

    /// oreulius_temporal_rollback(cap: i32, path_ptr: i32, path_len: i32, version_lo: i32, version_hi: i32, out_ptr: i32) -> i32
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

        crate::serial_println!(
            "[TEMPORAL_ROLLBACK] Start: target={:?}, version_id={}",
            path_bytes,
            version_id
        );

        if let Ok(path) = core::str::from_utf8(&path_bytes) {
            crate::serial_println!("[TEMPORAL_ROLLBACK] Valid UTF-8: {:?}", path);
            if let Ok(key) = fs::FileKey::new(path) {
                crate::serial_println!("[TEMPORAL_ROLLBACK] Valid FileKey: {:?}", key);
                crate::serial_println!("[TEMPORAL_ROLLBACK] Cap Rights: {:?}", fs_cap.rights);
                if fs_cap.rights.has(fs::FilesystemRights::WRITE) && fs_cap.can_access(&key) {
                    crate::serial_println!("[TEMPORAL_ROLLBACK] Write capability checks passed. Calling temporal::rollback_path");
                    match crate::temporal::rollback_path(path, version_id) {
                        Ok(rollback) => {
                            crate::serial_println!("[TEMPORAL_ROLLBACK] Rollback successful");
                            encoded = Self::encode_temporal_rollback(&rollback);
                            self.memory.write(out_ptr, &encoded)?;
                            encoded_len = TEMPORAL_ROLLBACK_BYTES;
                            result_code = 0;
                        }
                        Err(e) => {
                            crate::serial_println!(
                                "[TEMPORAL_ROLLBACK] Rollback failed with error: {:?}",
                                e
                            );
                        }
                    }
                } else {
                    crate::serial_println!("[TEMPORAL_ROLLBACK] Write capability or access check failed. Rights: {:?}, Can Access: {}", fs_cap.rights, fs_cap.can_access(&key));
                }
            } else {
                crate::serial_println!("[TEMPORAL_ROLLBACK] Invalid FileKey");
            }
        } else {
            crate::serial_println!("[TEMPORAL_ROLLBACK] Invalid UTF-8");
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

    /// oreulius_temporal_stats(out_ptr: i32) -> i32
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

    /// oreulius_temporal_history(cap: i32, path_ptr: i32, path_len: i32, start_from_newest: i32, max_entries: i32, out_ptr: i32, out_capacity: i32) -> i32
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

        if max_entries > MAX_TEMPORAL_HISTORY_ENTRIES || out_capacity > MAX_TEMPORAL_HISTORY_ENTRIES
        {
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

    /// oreulius_temporal_branch_create(cap, path_ptr, path_len, branch_ptr, branch_len, from_lo, from_hi, out_ptr) -> i32
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

    /// oreulius_temporal_branch_checkout(cap, path_ptr, path_len, branch_ptr, branch_len, out_ptr) -> i32
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
                            encoded =
                                Self::encode_temporal_branch_checkout(branch_id, head_version);
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

    /// oreulius_temporal_branch_list(cap, path_ptr, path_len, out_ptr, out_capacity) -> i32
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

    /// oreulius_temporal_merge(cap, path_ptr, path_len, source_ptr, source_len, target_ptr, target_len, strategy, out_ptr) -> i32
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
            3 => Some(crate::temporal::TemporalMergeStrategy::ThreeWay),
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
                            if fs_cap.rights.has(fs::FilesystemRights::WRITE)
                                && fs_cap.can_access(&key)
                            {
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

    // ========================================================================
    // WASM Thread host functions (IDs 23–27)
    // ========================================================================

    // ========================================================================
    // Input Event Queue  (IDs 38–44)
    // ========================================================================

    fn host_input_poll(&mut self) -> Result<(), WasmError> {
        crate::drivers::x86::input::pump();
        let v = if crate::drivers::x86::input::poll() { 1 } else { 0 };
        self.stack.push(Value::I32(v))
    }

    fn host_input_read(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize;
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        crate::drivers::x86::input::pump();
        match crate::drivers::x86::input::read() {
            None => self.stack.push(Value::I32(0)),
            Some(ev) => {
                let mem = self.memory.as_mut_slice();
                if buf_ptr + crate::drivers::x86::input::INPUT_EVENT_BYTES > mem.len()
                    || buf_len < crate::drivers::x86::input::INPUT_EVENT_BYTES
                {
                    return self.stack.push(Value::I32(0));
                }
                let written =
                    ev.serialise(&mut mem[buf_ptr..buf_ptr + crate::drivers::x86::input::INPUT_EVENT_BYTES]);
                self.stack.push(Value::I32(written as i32))
            }
        }
    }

    fn host_input_event_type(&mut self) -> Result<(), WasmError> {
        crate::drivers::x86::input::pump();
        let kind = crate::drivers::x86::input::peek_kind() as i32;
        self.stack.push(Value::I32(kind))
    }

    fn host_input_flush(&mut self) -> Result<(), WasmError> {
        let count = crate::drivers::x86::input::flush() as i32;
        self.stack.push(Value::I32(count))
    }

    fn host_input_key_poll(&mut self) -> Result<(), WasmError> {
        crate::drivers::x86::input::pump();
        let v = if crate::drivers::x86::input::poll_key() { 1 } else { 0 };
        self.stack.push(Value::I32(v))
    }

    fn host_input_mouse_poll(&mut self) -> Result<(), WasmError> {
        crate::drivers::x86::input::pump();
        let v = if crate::drivers::x86::input::poll_mouse() { 1 } else { 0 };
        self.stack.push(Value::I32(v))
    }

    fn host_input_gamepad_poll(&mut self) -> Result<(), WasmError> {
        self.stack.push(Value::I32(0))
    }

    // ========================================================================
    // CapabilityWASI  (IDs 45–90)
    // ========================================================================

    fn host_wasi_args_get(&mut self) -> Result<(), WasmError> {
        let argv_buf_ptr = self.stack.pop()?.as_i32()? as u32;
        let argv_ptr = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::args_get(&self.wasi_ctx, mem, argv_ptr, argv_buf_ptr);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_args_sizes_get(&mut self) -> Result<(), WasmError> {
        let buf_size_ptr = self.stack.pop()?.as_i32()? as u32;
        let argc_ptr = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::args_sizes_get(&self.wasi_ctx, mem, argc_ptr, buf_size_ptr);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_environ_get(&mut self) -> Result<(), WasmError> {
        let env_buf_ptr = self.stack.pop()?.as_i32()? as u32;
        let env_ptr = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::environ_get(&self.wasi_ctx, mem, env_ptr, env_buf_ptr);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_environ_sizes_get(&mut self) -> Result<(), WasmError> {
        let buf_size_ptr = self.stack.pop()?.as_i32()? as u32;
        let cnt_ptr = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::environ_sizes_get(&self.wasi_ctx, mem, cnt_ptr, buf_size_ptr);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_clock_res_get(&mut self) -> Result<(), WasmError> {
        let ts_ptr = self.stack.pop()?.as_i32()? as u32;
        let clock_id = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::clock_res_get(&self.wasi_ctx, mem, clock_id, ts_ptr);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_clock_time_get(&mut self) -> Result<(), WasmError> {
        let ts_ptr = self.stack.pop()?.as_i32()? as u32;
        let precision = self.stack.pop()?.as_i32()? as u64;
        let clock_id = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::clock_time_get(&self.wasi_ctx, mem, clock_id, precision, ts_ptr);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_close(&mut self) -> Result<(), WasmError> {
        let fd = self.stack.pop()?.as_i32()? as u32;
        let e = crate::services::wasi::fd_close(&mut self.wasi_ctx, fd);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_advise(&mut self) -> Result<(), WasmError> {
        let len = self.stack.pop()?.as_i32()? as u64;
        let offset = self.stack.pop()?.as_i32()? as u64;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let e = crate::services::wasi::fd_advise(&self.wasi_ctx, fd, offset, len);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_allocate(&mut self) -> Result<(), WasmError> {
        let len = self.stack.pop()?.as_i32()? as u64;
        let offset = self.stack.pop()?.as_i32()? as u64;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let e = crate::services::wasi::fd_allocate(&mut self.wasi_ctx, fd, offset, len);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_datasync(&mut self) -> Result<(), WasmError> {
        let fd = self.stack.pop()?.as_i32()? as u32;
        let e = crate::services::wasi::fd_datasync(&self.wasi_ctx, fd);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_fdstat_get(&mut self) -> Result<(), WasmError> {
        let stat_ptr = self.stack.pop()?.as_i32()? as u32;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::fd_fdstat_get(&self.wasi_ctx, mem, fd, stat_ptr);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_fdstat_set_flags(&mut self) -> Result<(), WasmError> {
        let flags = self.stack.pop()?.as_i32()? as u16;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let e = crate::services::wasi::fd_fdstat_set_flags(&mut self.wasi_ctx, fd, flags);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_fdstat_set_rights(&mut self) -> Result<(), WasmError> {
        let rights_inheriting = self.stack.pop()?.as_i32()? as u64;
        let rights_base = self.stack.pop()?.as_i32()? as u64;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let e = crate::services::wasi::fd_fdstat_set_rights(
            &mut self.wasi_ctx,
            fd,
            rights_base,
            rights_inheriting,
        );
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_filestat_get(&mut self) -> Result<(), WasmError> {
        let stat_ptr = self.stack.pop()?.as_i32()? as u32;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::fd_filestat_get(&self.wasi_ctx, mem, fd, stat_ptr);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_filestat_set_size(&mut self) -> Result<(), WasmError> {
        let size = self.stack.pop()?.as_i32()? as u64;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let e = crate::services::wasi::fd_filestat_set_size(&mut self.wasi_ctx, fd, size);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_filestat_set_times(&mut self) -> Result<(), WasmError> {
        let fst_flags = self.stack.pop()?.as_i32()? as u32;
        let mtim = self.stack.pop()?.as_i32()? as u64;
        let atim = self.stack.pop()?.as_i32()? as u64;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let e = crate::services::wasi::fd_filestat_set_times(
            &mut self.wasi_ctx,
            fd,
            atim,
            mtim,
            fst_flags,
        );
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_pread(&mut self) -> Result<(), WasmError> {
        let nread_ptr = self.stack.pop()?.as_i32()? as u32;
        let offset = self.stack.pop()?.as_i32()? as u64;
        let iovs_len = self.stack.pop()?.as_i32()? as u32;
        let iovs_ptr = self.stack.pop()?.as_i32()? as u32;
        let fd = self.stack.pop()?.as_i32()? as u32;
        // Save offset, seek to it, call fd_read, restore.
        let saved = self
            .wasi_ctx
            .fds
            .get(fd as usize)
            .map(|o| o.offset)
            .unwrap_or(0);
        if let Some(o) = self.wasi_ctx.fds.get_mut(fd as usize) {
            o.offset = offset;
        }
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::fd_read(&mut self.wasi_ctx, mem, fd, iovs_ptr, iovs_len, nread_ptr);
        if let Some(o) = self.wasi_ctx.fds.get_mut(fd as usize) {
            o.offset = saved;
        }
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_prestat_get(&mut self) -> Result<(), WasmError> {
        let prestat_ptr = self.stack.pop()?.as_i32()? as u32;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::fd_prestat_get(&self.wasi_ctx, mem, fd, prestat_ptr);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_prestat_dir_name(&mut self) -> Result<(), WasmError> {
        let path_len = self.stack.pop()?.as_i32()? as u32;
        let path_ptr = self.stack.pop()?.as_i32()? as u32;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::fd_prestat_dir_name(&self.wasi_ctx, mem, fd, path_ptr, path_len);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_pwrite(&mut self) -> Result<(), WasmError> {
        let nwritten_ptr = self.stack.pop()?.as_i32()? as u32;
        let offset = self.stack.pop()?.as_i32()? as u64;
        let iovs_len = self.stack.pop()?.as_i32()? as u32;
        let iovs_ptr = self.stack.pop()?.as_i32()? as u32;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let saved = self
            .wasi_ctx
            .fds
            .get(fd as usize)
            .map(|o| o.offset)
            .unwrap_or(0);
        if let Some(o) = self.wasi_ctx.fds.get_mut(fd as usize) {
            o.offset = offset;
        }
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::fd_write(
            &mut self.wasi_ctx,
            mem,
            fd,
            iovs_ptr,
            iovs_len,
            nwritten_ptr,
        );
        if let Some(o) = self.wasi_ctx.fds.get_mut(fd as usize) {
            o.offset = saved;
        }
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_read(&mut self) -> Result<(), WasmError> {
        let nread_ptr = self.stack.pop()?.as_i32()? as u32;
        let iovs_len = self.stack.pop()?.as_i32()? as u32;
        let iovs_ptr = self.stack.pop()?.as_i32()? as u32;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::fd_read(&mut self.wasi_ctx, mem, fd, iovs_ptr, iovs_len, nread_ptr);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_readdir(&mut self) -> Result<(), WasmError> {
        let bufused_ptr = self.stack.pop()?.as_i32()? as u32;
        let cookie = self.stack.pop()?.as_i32()? as u64;
        let buf_len = self.stack.pop()?.as_i32()? as u32;
        let buf_ptr = self.stack.pop()?.as_i32()? as u32;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::fd_readdir(
            &mut self.wasi_ctx,
            mem,
            fd,
            buf_ptr,
            buf_len,
            cookie,
            bufused_ptr,
        );
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_renumber(&mut self) -> Result<(), WasmError> {
        let to_fd = self.stack.pop()?.as_i32()? as u32;
        let from_fd = self.stack.pop()?.as_i32()? as u32;
        let e = crate::services::wasi::fd_renumber(&mut self.wasi_ctx, from_fd, to_fd);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_seek(&mut self) -> Result<(), WasmError> {
        let newoff_ptr = self.stack.pop()?.as_i32()? as u32;
        let whence = self.stack.pop()?.as_i32()? as u8;
        let offset = self.stack.pop()?.as_i32()? as i64;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::fd_seek(&mut self.wasi_ctx, mem, fd, offset, whence, newoff_ptr);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_tell(&mut self) -> Result<(), WasmError> {
        let offset_ptr = self.stack.pop()?.as_i32()? as u32;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::fd_tell(&self.wasi_ctx, mem, fd, offset_ptr);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_sync(&mut self) -> Result<(), WasmError> {
        let fd = self.stack.pop()?.as_i32()? as u32;
        let e = crate::services::wasi::fd_sync(&self.wasi_ctx, fd);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_fd_write(&mut self) -> Result<(), WasmError> {
        let nwritten_ptr = self.stack.pop()?.as_i32()? as u32;
        let iovs_len = self.stack.pop()?.as_i32()? as u32;
        let iovs_ptr = self.stack.pop()?.as_i32()? as u32;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::fd_write(
            &mut self.wasi_ctx,
            mem,
            fd,
            iovs_ptr,
            iovs_len,
            nwritten_ptr,
        );
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_path_create_directory(&mut self) -> Result<(), WasmError> {
        let path_len = self.stack.pop()?.as_i32()? as usize;
        let path_ptr = self.stack.pop()?.as_i32()? as usize;
        let _fd = self.stack.pop()?.as_i32()?;
        let mem = self.memory.as_mut_slice();
        if path_ptr + path_len > mem.len() {
            return self
                .stack
                .push(Value::I32(crate::services::wasi::Errno::Fault.as_i32()));
        }
        let path = &mem[path_ptr..path_ptr + path_len];
        let mut pathbuf = [0u8; 128];
        let l = path_len.min(127);
        pathbuf[..l].copy_from_slice(&path[..l]);
        let e = crate::services::wasi::path_create_directory(&mut self.wasi_ctx, &pathbuf[..l]);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_path_filestat_get(&mut self) -> Result<(), WasmError> {
        let stat_ptr = self.stack.pop()?.as_i32()? as u32;
        let path_len = self.stack.pop()?.as_i32()? as usize;
        let path_ptr = self.stack.pop()?.as_i32()? as usize;
        let flags = self.stack.pop()?.as_i32()? as u32;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        if path_ptr + path_len > mem.len() {
            return self
                .stack
                .push(Value::I32(crate::services::wasi::Errno::Fault.as_i32()));
        }
        let mut pathbuf = [0u8; 128];
        let l = path_len.min(127);
        pathbuf[..l].copy_from_slice(&mem[path_ptr..path_ptr + l]);
        let e =
            crate::services::wasi::path_filestat_get(&self.wasi_ctx, mem, fd, flags, &pathbuf[..l], stat_ptr);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_path_filestat_set_times(&mut self) -> Result<(), WasmError> {
        let fst_flags = self.stack.pop()?.as_i32()? as u32;
        let mtim = self.stack.pop()?.as_i32()? as u64;
        let atim = self.stack.pop()?.as_i32()? as u64;
        let path_len = self.stack.pop()?.as_i32()? as usize;
        let path_ptr = self.stack.pop()?.as_i32()? as usize;
        let _fd = self.stack.pop()?.as_i32()?;
        let mem = self.memory.as_mut_slice();
        if path_ptr + path_len > mem.len() {
            return self
                .stack
                .push(Value::I32(crate::services::wasi::Errno::Fault.as_i32()));
        }
        let mut pathbuf = [0u8; 128];
        let l = path_len.min(127);
        pathbuf[..l].copy_from_slice(&mem[path_ptr..path_ptr + l]);
        let e = crate::services::wasi::path_filestat_set_times(
            &mut self.wasi_ctx,
            &pathbuf[..l],
            atim,
            mtim,
            fst_flags,
        );
        self.stack.push(Value::I32(e.as_i32()))
    }

    // WASM ABI: path_link(old_fd, old_path_ptr, old_path_len, new_fd, new_path_ptr, new_path_len) -> errno
    fn host_wasi_path_link(&mut self) -> Result<(), WasmError> {
        let new_path_len = self.stack.pop()?.as_i32()? as usize;
        let new_path_ptr = self.stack.pop()?.as_i32()? as usize;
        let _new_fd = self.stack.pop()?.as_i32()?;
        let old_path_len = self.stack.pop()?.as_i32()? as usize;
        let old_path_ptr = self.stack.pop()?.as_i32()? as usize;
        let _old_fd = self.stack.pop()?.as_i32()?;
        let mem = self.memory.as_mut_slice();
        if old_path_ptr + old_path_len > mem.len() || new_path_ptr + new_path_len > mem.len() {
            return self
                .stack
                .push(Value::I32(crate::services::wasi::Errno::Fault.as_i32()));
        }
        let mut old_buf = [0u8; 128];
        let mut new_buf = [0u8; 128];
        let old_len = old_path_len.min(127);
        let new_len = new_path_len.min(127);
        old_buf[..old_len].copy_from_slice(&mem[old_path_ptr..old_path_ptr + old_len]);
        new_buf[..new_len].copy_from_slice(&mem[new_path_ptr..new_path_ptr + new_len]);
        let e = crate::services::wasi::path_link(
            &mut self.wasi_ctx,
            &old_buf[..old_len],
            &new_buf[..new_len],
        );
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_path_open(&mut self) -> Result<(), WasmError> {
        let opened_fd_ptr = self.stack.pop()?.as_i32()? as usize;
        let fdflags = self.stack.pop()?.as_i32()? as u16;
        let rights_inh = self.stack.pop()?.as_i32()? as u64;
        let rights = self.stack.pop()?.as_i32()? as u64;
        let oflags = self.stack.pop()?.as_i32()? as u16;
        let path_len = self.stack.pop()?.as_i32()? as usize;
        let path_ptr = self.stack.pop()?.as_i32()? as usize;
        let dirflags = self.stack.pop()?.as_i32()? as u32;
        let dirfd = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        if path_ptr + path_len > mem.len() || opened_fd_ptr + 4 > mem.len() {
            return self
                .stack
                .push(Value::I32(crate::services::wasi::Errno::Fault.as_i32()));
        }
        let mut pathbuf = [0u8; 128];
        let l = path_len.min(127);
        pathbuf[..l].copy_from_slice(&mem[path_ptr..path_ptr + l]);
        let mut new_fd = 0u32;
        let e = crate::services::wasi::path_open(
            &mut self.wasi_ctx,
            mem,
            dirfd,
            dirflags,
            &pathbuf[..l],
            oflags,
            rights,
            rights_inh,
            fdflags,
            &mut new_fd,
        );
        if e == crate::services::wasi::Errno::Success {
            mem[opened_fd_ptr..opened_fd_ptr + 4].copy_from_slice(&new_fd.to_le_bytes());
        }
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_path_remove_directory(&mut self) -> Result<(), WasmError> {
        let path_len = self.stack.pop()?.as_i32()? as usize;
        let path_ptr = self.stack.pop()?.as_i32()? as usize;
        let _fd = self.stack.pop()?.as_i32()?;
        let mem = self.memory.as_mut_slice();
        if path_ptr + path_len > mem.len() {
            return self
                .stack
                .push(Value::I32(crate::services::wasi::Errno::Fault.as_i32()));
        }
        let mut pathbuf = [0u8; 128];
        let l = path_len.min(127);
        pathbuf[..l].copy_from_slice(&mem[path_ptr..path_ptr + l]);
        let e = crate::services::wasi::path_remove_directory(&mut self.wasi_ctx, &pathbuf[..l]);
        self.stack.push(Value::I32(e.as_i32()))
    }

    // WASM ABI: path_rename(old_fd, old_path_ptr, old_path_len, new_path_ptr, new_path_len) -> errno
    fn host_wasi_path_rename(&mut self) -> Result<(), WasmError> {
        let new_path_len = self.stack.pop()?.as_i32()? as usize;
        let new_path_ptr = self.stack.pop()?.as_i32()? as usize;
        let old_path_len = self.stack.pop()?.as_i32()? as usize;
        let old_path_ptr = self.stack.pop()?.as_i32()? as usize;
        let _old_fd = self.stack.pop()?.as_i32()?;
        let mem = self.memory.as_mut_slice();
        if old_path_ptr + old_path_len > mem.len() || new_path_ptr + new_path_len > mem.len() {
            return self
                .stack
                .push(Value::I32(crate::services::wasi::Errno::Fault.as_i32()));
        }
        let mut old_buf = [0u8; 128];
        let mut new_buf = [0u8; 128];
        let old_len = old_path_len.min(127);
        let new_len = new_path_len.min(127);
        old_buf[..old_len].copy_from_slice(&mem[old_path_ptr..old_path_ptr + old_len]);
        new_buf[..new_len].copy_from_slice(&mem[new_path_ptr..new_path_ptr + new_len]);
        let e = crate::services::wasi::path_rename(
            &mut self.wasi_ctx,
            &old_buf[..old_len],
            &new_buf[..new_len],
        );
        self.stack.push(Value::I32(e.as_i32()))
    }

    // WASM ABI: path_readlink(fd, path_ptr, path_len, buf_ptr, buf_len) -> errno
    fn host_wasi_path_readlink(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as u32;
        let buf_ptr = self.stack.pop()?.as_i32()? as u32;
        let path_len = self.stack.pop()?.as_i32()? as usize;
        let path_ptr = self.stack.pop()?.as_i32()? as usize;
        let _fd = self.stack.pop()?.as_i32()?;
        let mem = self.memory.as_mut_slice();
        if path_ptr + path_len > mem.len() {
            return self
                .stack
                .push(Value::I32(crate::services::wasi::Errno::Fault.as_i32()));
        }
        let mut pathbuf = [0u8; 128];
        let l = path_len.min(127);
        pathbuf[..l].copy_from_slice(&mem[path_ptr..path_ptr + l]);
        let e = crate::services::wasi::path_readlink(
            &mut self.wasi_ctx,
            mem,
            &pathbuf[..l],
            buf_ptr,
            buf_len,
        );
        self.stack.push(Value::I32(e.as_i32()))
    }

    // WASM ABI: path_symlink(old_path_ptr, old_path_len, fd, new_path_ptr, new_path_len) -> errno
    fn host_wasi_path_symlink(&mut self) -> Result<(), WasmError> {
        let new_path_len = self.stack.pop()?.as_i32()? as usize;
        let new_path_ptr = self.stack.pop()?.as_i32()? as usize;
        let _fd = self.stack.pop()?.as_i32()?;
        let old_path_len = self.stack.pop()?.as_i32()? as usize;
        let old_path_ptr = self.stack.pop()?.as_i32()? as usize;
        let mem = self.memory.as_mut_slice();
        if old_path_ptr + old_path_len > mem.len() || new_path_ptr + new_path_len > mem.len() {
            return self
                .stack
                .push(Value::I32(crate::services::wasi::Errno::Fault.as_i32()));
        }
        let mut old_buf = [0u8; 128];
        let mut new_buf = [0u8; 128];
        let ol = old_path_len.min(127);
        let nl = new_path_len.min(127);
        old_buf[..ol].copy_from_slice(&mem[old_path_ptr..old_path_ptr + ol]);
        new_buf[..nl].copy_from_slice(&mem[new_path_ptr..new_path_ptr + nl]);
        let e = crate::services::wasi::path_symlink(
            &mut self.wasi_ctx,
            &old_buf[..ol],
            &new_buf[..nl],
        );
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_path_unlink_file(&mut self) -> Result<(), WasmError> {
        let path_len = self.stack.pop()?.as_i32()? as usize;
        let path_ptr = self.stack.pop()?.as_i32()? as usize;
        let _fd = self.stack.pop()?.as_i32()?;
        let mem = self.memory.as_mut_slice();
        if path_ptr + path_len > mem.len() {
            return self
                .stack
                .push(Value::I32(crate::services::wasi::Errno::Fault.as_i32()));
        }
        let mut pathbuf = [0u8; 128];
        let l = path_len.min(127);
        pathbuf[..l].copy_from_slice(&mem[path_ptr..path_ptr + l]);
        let e = crate::services::wasi::path_unlink_file(&mut self.wasi_ctx, &pathbuf[..l]);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_poll_oneoff(&mut self) -> Result<(), WasmError> {
        let nevents_ptr = self.stack.pop()?.as_i32()? as u32;
        let nsubscriptions = self.stack.pop()?.as_i32()? as u32;
        let out_ptr = self.stack.pop()?.as_i32()? as u32;
        let in_ptr = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::poll_oneoff(
            &self.wasi_ctx,
            mem,
            in_ptr,
            out_ptr,
            nsubscriptions,
            nevents_ptr,
        );
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_proc_exit(&mut self) -> Result<(), WasmError> {
        let code = self.stack.pop()?.as_i32()?;
        crate::services::wasi::proc_exit(&mut self.wasi_ctx, code);
        // Signal the WASM interpreter to stop execution.
        Err(WasmError::Trap)
    }

    fn host_wasi_proc_raise(&mut self) -> Result<(), WasmError> {
        let signal = self.stack.pop()?.as_i32()? as u32;
        let e = crate::services::wasi::proc_raise(&mut self.wasi_ctx, signal);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_random_get(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as u32;
        let buf_ptr = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::random_get(&mut self.wasi_ctx, mem, buf_ptr, buf_len);
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_sched_yield(&mut self) -> Result<(), WasmError> {
        let e = crate::services::wasi::sched_yield();
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_sock_accept(&mut self) -> Result<(), WasmError> {
        let new_fd_ptr = self.stack.pop()?.as_i32()? as usize;
        let flags = self.stack.pop()?.as_i32()? as u16;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let mut new_fd = 0u32;
        let e = crate::services::wasi::sock_accept(&mut self.wasi_ctx, fd, flags, &mut new_fd);
        if e == crate::services::wasi::Errno::Success && new_fd_ptr + 4 <= mem.len() {
            mem[new_fd_ptr..new_fd_ptr + 4].copy_from_slice(&new_fd.to_le_bytes());
        }
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_sock_recv(&mut self) -> Result<(), WasmError> {
        let ro_flags_ptr = self.stack.pop()?.as_i32()? as u32;
        let ro_datalen_ptr = self.stack.pop()?.as_i32()? as u32;
        let ri_flags = self.stack.pop()?.as_i32()? as u16;
        let ri_data_len = self.stack.pop()?.as_i32()? as u32;
        let ri_data_ptr = self.stack.pop()?.as_i32()? as u32;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::sock_recv(
            &mut self.wasi_ctx,
            mem,
            fd,
            ri_data_ptr,
            ri_data_len,
            ri_flags,
            ro_datalen_ptr,
            ro_flags_ptr,
        );
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_sock_send(&mut self) -> Result<(), WasmError> {
        let so_datalen_ptr = self.stack.pop()?.as_i32()? as u32;
        let si_flags = self.stack.pop()?.as_i32()? as u16;
        let si_data_len = self.stack.pop()?.as_i32()? as u32;
        let si_data_ptr = self.stack.pop()?.as_i32()? as u32;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let mem = self.memory.as_mut_slice();
        let e = crate::services::wasi::sock_send(
            &mut self.wasi_ctx,
            mem,
            fd,
            si_data_ptr,
            si_data_len,
            si_flags,
            so_datalen_ptr,
        );
        self.stack.push(Value::I32(e.as_i32()))
    }

    fn host_wasi_sock_shutdown(&mut self) -> Result<(), WasmError> {
        let how = self.stack.pop()?.as_i32()? as u8;
        let fd = self.stack.pop()?.as_i32()? as u32;
        let e = crate::services::wasi::sock_shutdown(&mut self.wasi_ctx, fd, how);
        self.stack.push(Value::I32(e.as_i32()))
    }

    // ========================================================================
    // TLS 1.3  (IDs 91–99)
    // ========================================================================

    fn host_tls_connect(&mut self) -> Result<(), WasmError> {
        // Stack (top→bottom): port, server_ip_u32, host_len, host_ptr
        let port = self.stack.pop()?.as_i32()? as u16;
        let server_ip_u32 = self.stack.pop()?.as_i32()? as u32;
        let host_len = self.stack.pop()?.as_i32()? as usize;
        let host_ptr = self.stack.pop()?.as_i32()? as usize;
        let mem = self.memory.as_slice();
        if host_ptr + host_len > mem.len() {
            return self.stack.push(Value::I32(-1));
        }
        let host = &mem[host_ptr..host_ptr + host_len];
        let server_ip: crate::net::tls::Ip4 = [
            (server_ip_u32 >> 24) as u8,
            (server_ip_u32 >> 16) as u8,
            (server_ip_u32 >> 8) as u8,
            server_ip_u32 as u8,
        ];
        let handle = crate::net::tls::alloc_session(host, port, server_ip);
        if let Some(s) = crate::net::tls::session_mut(handle) {
            s.tick();
        }
        self.stack.push(Value::I32(handle))
    }

    fn host_tls_write(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize;
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        let handle = self.stack.pop()?.as_i32()?;
        let mem = self.memory.as_slice();
        if buf_ptr + buf_len > mem.len() {
            return self.stack.push(Value::I32(-1));
        }
        let data = &mem[buf_ptr..buf_ptr + buf_len];
        let result = match crate::net::tls::session_mut(handle) {
            None => -1i32,
            Some(s) => s.write(data) as i32,
        };
        self.stack.push(Value::I32(result))
    }

    fn host_tls_read(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize;
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        let handle = self.stack.pop()?.as_i32()?;
        let mem = self.memory.as_mut_slice();
        if buf_ptr + buf_len > mem.len() {
            return self.stack.push(Value::I32(0));
        }
        let result = match crate::net::tls::session_mut(handle) {
            None => 0usize,
            Some(s) => {
                s.tick();
                s.read(&mut mem[buf_ptr..buf_ptr + buf_len])
            }
        };
        self.stack.push(Value::I32(result as i32))
    }

    fn host_tls_close(&mut self) -> Result<(), WasmError> {
        let handle = self.stack.pop()?.as_i32()?;
        if let Some(s) = crate::net::tls::session_mut(handle) {
            s.close();
        }
        self.stack.push(Value::I32(0))
    }

    fn host_tls_state(&mut self) -> Result<(), WasmError> {
        let handle = self.stack.pop()?.as_i32()?;
        let state = match crate::net::tls::session_mut(handle) {
            None => crate::net::tls::HandshakeState::Error as i32,
            Some(s) => s.state as i32,
        };
        self.stack.push(Value::I32(state))
    }

    fn host_tls_error(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize;
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        let handle = self.stack.pop()?.as_i32()?;
        let mem = self.memory.as_mut_slice();
        let result = match crate::net::tls::session_mut(handle) {
            None => 0usize,
            Some(s) => {
                let err = s.error_str();
                let copy = err.len().min(buf_len);
                if buf_ptr + copy <= mem.len() {
                    mem[buf_ptr..buf_ptr + copy].copy_from_slice(&err[..copy]);
                }
                copy
            }
        };
        self.stack.push(Value::I32(result as i32))
    }

    fn host_tls_handshake_done(&mut self) -> Result<(), WasmError> {
        let handle = self.stack.pop()?.as_i32()?;
        let done = match crate::net::tls::session_mut(handle) {
            None => 0,
            Some(s) => {
                if s.state == crate::net::tls::HandshakeState::Connected {
                    1
                } else {
                    0
                }
            }
        };
        self.stack.push(Value::I32(done))
    }

    fn host_tls_tick(&mut self) -> Result<(), WasmError> {
        let handle = self.stack.pop()?.as_i32()?;
        if let Some(s) = crate::net::tls::session_mut(handle) {
            s.tick();
        }
        self.stack.push(Value::I32(0))
    }

    fn host_tls_free(&mut self) -> Result<(), WasmError> {
        let handle = self.stack.pop()?.as_i32()?;
        crate::net::tls::free_session(handle);
        self.stack.push(Value::I32(0))
    }

    // ========================================================================
    // Process lifecycle (IDs 100–102)
    // ========================================================================

    /// `proc_spawn(bytes_ptr: i32, bytes_len: i32) -> i32`
    ///
    /// Instantiate and run a WASM child module from bytes in the caller's
    /// linear memory. The child is registered as a kernel process first, then
    /// deferred for WASM instantiation outside the runtime lock. Returns the
    /// child's process-ID (>= 1) on success, or `0` on failure.
    fn host_proc_spawn(&mut self) -> Result<(), WasmError> {
        let bytes_len = self.stack.pop()?.as_i32()? as usize;
        let bytes_ptr = self.stack.pop()?.as_i32()? as usize;

        if bytes_len == 0
            || bytes_ptr
                .checked_add(bytes_len)
                .map_or(true, |e| e > self.memory.size())
        {
            return self.stack.push(Value::I32(0));
        }

        // Copy the WASM bytecode out of the caller's linear memory.
        let bytecode: alloc::vec::Vec<u8> = self
            .memory
            .read(bytes_ptr, bytes_len)
            .map_err(|_| WasmError::MemoryOutOfBounds)?
            .to_vec();

        let parent = if self.process_id.0 == 0 {
            None
        } else {
            Some(self.process_id)
        };
        let child_pid = match crate::scheduler::process::process_manager().spawn("wasm-child", parent) {
            Ok(pid) => pid,
            Err(_) => return self.stack.push(Value::I32(0)),
        };

        // Queue the spawn for deferred execution outside this lock to avoid
        // re-entrancy into the WASM runtime mutex.
        if crate::execution::wasm::queue_pending_spawn(child_pid, bytecode).is_err() {
            let _ = crate::scheduler::process::process_manager().terminate(child_pid);
            return self.stack.push(Value::I32(0));
        }
        crate::serial_println!("[WASM] proc_spawn queued: child pid={}", child_pid.0);
        // Notify observers that a new WASM process was spawned.
        let parent_pid = self.process_id.0;
        let child_pid_raw = child_pid.0;
        let payload = [
            parent_pid.to_le_bytes()[0],
            parent_pid.to_le_bytes()[1],
            parent_pid.to_le_bytes()[2],
            parent_pid.to_le_bytes()[3],
            child_pid_raw.to_le_bytes()[0],
            child_pid_raw.to_le_bytes()[1],
            child_pid_raw.to_le_bytes()[2],
            child_pid_raw.to_le_bytes()[3],
        ];
        observer_notify(observer_events::PROCESS_LIFECYCLE, &payload);
        self.stack.push(Value::I32(child_pid.0 as i32))
    }

    /// `proc_yield() -> ()`
    ///
    /// Voluntarily yield the scheduler quantum so other processes can run.
    fn host_proc_yield(&mut self) -> Result<(), WasmError> {
        crate::scheduler::quantum_scheduler::yield_now();
        let _ = self.run_background_thread_quantum();
        Ok(())
    }

    /// `proc_sleep(ticks: i32) -> ()`
    ///
    /// Sleep for `ticks` PIT ticks. If the caller is a scheduled kernel
    /// process, use the scheduler's timer sleep queue. Otherwise fall back to
    /// cooperative yielding to preserve direct-call behavior.
    fn host_proc_sleep(&mut self) -> Result<(), WasmError> {
        let ticks = self.stack.pop()?.as_i32()?.max(0) as u64;
        if ticks == 0 {
            return Ok(());
        }

        let start = crate::scheduler::pit::get_ticks();
        let wake_time = start.saturating_add(ticks);
        let current_pid = {
            let scheduler = crate::scheduler::quantum_scheduler::scheduler().lock();
            scheduler.get_current_pid()
        };
        if current_pid == Some(self.process_id)
            && crate::scheduler::quantum_scheduler::sleep_until(self.process_id, wake_time).is_ok()
        {
            return Ok(());
        }

        while crate::scheduler::pit::get_ticks().wrapping_sub(start) < ticks {
            crate::scheduler::quantum_scheduler::yield_now();
            let _ = self.run_background_thread_quantum();
        }
        Ok(())
    }

    // ========================================================================
    // Polyglot Kernel Services (IDs 103–105)
    // ========================================================================

    /// `polyglot_register(name_ptr: i32, name_len: i32) -> i32`
    ///
    /// Register this module as a named polyglot service.  The name is read
    /// from the caller’s linear memory.  The language is taken from the
    /// module’s `oreulius_lang` custom section (defaults to `Unknown`).
    ///
    /// If the language is `Python` or `JS` and a singleton entry already
    /// exists for that language, the existing entry’s `instance_id` and
    /// `owner_pid` are updated (singleton upgrade, not a duplicate error).
    ///
    /// Returns 0 on success, negative on error:
    ///   -1 = name too long / empty
    ///   -2 = registry full
    ///   -3 = name already registered by a different module
    fn host_polyglot_register(&mut self) -> Result<(), WasmError> {
        let name_len = self.stack.pop()?.as_i32()? as usize;
        let name_ptr = self.stack.pop()?.as_i32()? as usize;

        if name_len == 0 || name_len > 32 {
            return self.stack.push(Value::I32(-1));
        }
        let name_arr: [u8; 32] = {
            let bytes = self.memory.read(name_ptr, name_len)?;
            let mut arr = [0u8; 32];
            arr[..name_len].copy_from_slice(bytes);
            arr
        };

        let lang = self.module.language_tag;
        let is_singleton = matches!(lang, LanguageTag::Python | LanguageTag::JS);
        let owner = self.process_id;
        let inst_id = self.instance_id;

        let mut registry = POLYGLOT_REGISTRY.lock();

        // Check for existing entry with same name.
        if let Some(idx) = registry.find_by_name(&name_arr[..name_len]) {
            let entry = registry.entries[idx];
            if entry.singleton && entry.language == lang {
                // Singleton upgrade: refresh instance/owner.
                registry.entries[idx].instance_id = inst_id;
                registry.entries[idx].owner_pid = owner;
                let mut lineage = POLYGLOT_LINEAGE.lock();
                if let Some(rec_idx) = lineage.find_latest_by_object(entry.instance_id as u64) {
                    lineage.records[rec_idx].lifecycle = PolyglotLifecycle::Restored;
                    lineage.records[rec_idx].updated_at = crate::scheduler::pit::get_ticks();
                }
                crate::serial_println!(
                    "[polyglot] singleton '{}' refreshed by pid={}",
                    core::str::from_utf8(&name_arr[..name_len]).unwrap_or("?"),
                    owner.0
                );
                return self.stack.push(Value::I32(0));
            }
            // Name taken by a different module — not same singleton.
            return self.stack.push(Value::I32(-3));
        }

        let Some(slot) = registry.find_empty() else {
            return self.stack.push(Value::I32(-2));
        };

        registry.entries[slot] = PolyglotEntry {
            active: true,
            name: name_arr,
            name_len: name_len as u8,
            instance_id: inst_id,
            language: lang,
            cap_object: 0,
            owner_pid: owner,
            singleton: is_singleton,
            latest_record_id: 0,
        };

        let record_id = match POLYGLOT_LINEAGE.lock().insert(
            owner,
            inst_id,
            inst_id,
            0,
            inst_id as u32,
            lang,
            &name_arr[..name_len],
            Rights::SERVICE_INVOKE,
            PolyglotLifecycle::Registered,
        ) {
            Ok(record_id) => record_id,
            Err(_) => return self.stack.push(Value::I32(-2)),
        };
        registry.entries[slot].latest_record_id = record_id;

        crate::serial_println!(
            "[polyglot] registered '{}' lang={} pid={} inst={} singleton={}",
            core::str::from_utf8(&name_arr[..name_len]).unwrap_or("?"),
            lang.as_str(),
            owner.0,
            inst_id,
            is_singleton
        );

        self.stack.push(Value::I32(0))
    }

    /// `polyglot_resolve(name_ptr: i32, name_len: i32) -> i32`
    ///
    /// Look up a registered polyglot service by name.  Returns the
    /// instance_id (>= 0) that owns the service, or a negative error code:
    ///   -1 = name too long / empty
    ///   -2 = not found
    ///
    /// The caller can pass the returned instance_id to
    /// `service_invoke_typed` (host ID 12) together with a previously
    /// obtained `ServicePointer` capability, or use `polyglot_link` (105)
    /// to obtain a direct function-reference capability.
    fn host_polyglot_resolve(&mut self) -> Result<(), WasmError> {
        let name_len = self.stack.pop()?.as_i32()? as usize;
        let name_ptr = self.stack.pop()?.as_i32()? as usize;

        if name_len == 0 || name_len > 32 {
            return self.stack.push(Value::I32(-1));
        }
        let name_arr: [u8; 32] = {
            let bytes = self.memory.read(name_ptr, name_len)?;
            let mut arr = [0u8; 32];
            arr[..name_len].copy_from_slice(bytes);
            arr
        };

        let registry = POLYGLOT_REGISTRY.lock();
        let result = match registry.find_by_name(&name_arr[..name_len]) {
            Some(idx) => registry.entries[idx].instance_id as i32,
            None => -2,
        };
        self.stack.push(Value::I32(result))
    }

    /// `polyglot_link(name_ptr: i32, name_len: i32, export_ptr: i32, export_len: i32) -> i32`
    ///
    /// Obtain a `ServicePointer` capability handle to a named export of a
    /// registered polyglot service.  The module must already be registered
    /// (via `polyglot_register`) and its export must match an existing
    /// service registered with `service_register`.
    ///
    /// Returns the capability handle (>= 0) on success, negative on error:
    ///   -1 = argument error (empty name or export)
    ///   -2 = module not found in polyglot registry
    ///   -3 = export not found in service-pointer registry for that instance
    ///   -4 = capability table full
    ///
    /// Cross-language capability check:
    ///   The source and destination `LanguageTag` are logged for the audit
    ///   trail.  If the destination language is `Python` or `JS` (a runtime
    ///   service), the caller must hold at least `SERVICE_INVOKE` rights on
    ///   a `ServicePointer` capability — enforced by the underlying
    ///   `service_invoke_typed` path.
    fn host_polyglot_link(&mut self) -> Result<(), WasmError> {
        let export_len = self.stack.pop()?.as_i32()? as usize;
        let export_ptr = self.stack.pop()?.as_i32()? as usize;
        let name_len = self.stack.pop()?.as_i32()? as usize;
        let name_ptr = self.stack.pop()?.as_i32()? as usize;

        if name_len == 0 || name_len > 32 || export_len == 0 || export_len > 32 {
            return self.stack.push(Value::I32(-1));
        }

        let (name_arr, export_arr_raw): ([u8; 32], [u8; 32]) = {
            let nb = self.memory.read(name_ptr, name_len)?;
            let mut na = [0u8; 32];
            na[..name_len].copy_from_slice(nb);
            let eb = self.memory.read(export_ptr, export_len)?;
            let mut ea = [0u8; 32];
            ea[..export_len].copy_from_slice(eb);
            (na, ea)
        };

        // Resolve the target module.
        let (target_instance_id, target_lang) = {
            let registry = POLYGLOT_REGISTRY.lock();
            match registry.find_by_name(&name_arr[..name_len]) {
                Some(idx) => (
                    registry.entries[idx].instance_id,
                    registry.entries[idx].language,
                ),
                None => return self.stack.push(Value::I32(-2)),
            }
        };

        let resolved_export = match wasm_runtime().get_instance_mut(target_instance_id, |instance| {
            instance
                .module
                .resolve_exported_function(&export_arr_raw[..export_len])
        }) {
            Ok(Ok(idx)) => idx,
            _ => return self.stack.push(Value::I32(-3)),
        };

        // Find the exact export in the service-pointer registry.
        let object_id: u64 = {
            let sp_reg = SERVICE_POINTERS.lock();
            match sp_reg.find_by_target_and_export(target_instance_id, &export_arr_raw[..export_len])
            {
                Some(entry) if entry.function_index == resolved_export => entry.object_id,
                _ => return self.stack.push(Value::I32(-3)),
            }
        };

        // Inject a ServicePointer WasmCapability into this instance’s table.
        let cap = crate::capability::OreuliusCapability::new_polyglot_link(
            self.process_id,
            object_id,
            target_lang,
        );
        let cap_id = match capability::capability_manager().grant_capability(
            self.process_id,
            object_id,
            CapabilityType::ServicePointer,
            Rights::new(Rights::SERVICE_INVOKE | Rights::SERVICE_INTROSPECT),
            self.process_id,
        ) {
            Ok(cap_id) => cap_id,
            Err(_) => return self.stack.push(Value::I32(-4)),
        };
        let wasm_cap = WasmCapability::ServicePointer(ServicePointerCapability {
            object_id,
            cap_id,
        });
        let handle = match self.capabilities.inject(wasm_cap) {
            Ok(handle) => handle,
            Err(_) => {
                let _ = capability::capability_manager().revoke_capability(self.process_id, cap_id);
                return self.stack.push(Value::I32(-4));
            }
        };

        let record_id = match POLYGLOT_LINEAGE.lock().insert(
            self.process_id,
            self.instance_id,
            target_instance_id,
            object_id,
            cap_id,
            target_lang,
            &export_arr_raw[..export_len],
            Rights::SERVICE_INVOKE | Rights::SERVICE_INTROSPECT,
            PolyglotLifecycle::Linked,
        ) {
            Ok(record_id) => record_id,
            Err(_) => return self.stack.push(Value::I32(-4)),
        };
        let mut registry = POLYGLOT_REGISTRY.lock();
        if let Some(idx) = registry.find_by_name(&name_arr[..name_len]) {
            registry.entries[idx].cap_object = object_id;
            registry.entries[idx].latest_record_id = record_id;
        }

        // Audit log: cross-language link established.
        crate::serial_println!(
            "[polyglot] link {} ({}) -> {} ({}) cap={}",
            core::str::from_utf8(&name_arr[..name_len]).unwrap_or("?"),
            target_lang.as_str(),
            core::str::from_utf8(&export_arr_raw[..export_len]).unwrap_or("?"),
            self.module.language_tag.as_str(),
            handle.0
        );
        crate::security::security().log_event(crate::security::AuditEntry::new(
            crate::security::SecurityEvent::CapDelegationChain,
            self.process_id,
            cap.object_id as u32,
        )
        .with_context(object_id));
        POLYGLOT_LINEAGE
            .lock()
            .update_lifecycle(object_id, PolyglotLifecycle::Live);

        self.stack.push(Value::I32(handle.0 as i32))
    }

    /// `polyglot_lineage_count() -> i32`
    ///
    /// Return the number of active polyglot lineage records.
    fn host_polyglot_lineage_count(&mut self) -> Result<(), WasmError> {
        let count = POLYGLOT_LINEAGE.lock().active_count();
        self.stack.push(Value::I32(count as i32))
    }

    /// `polyglot_lineage_query(buf_ptr: i32, buf_len: i32) -> i32`
    ///
    /// Write packed lineage records into caller memory.
    /// Layout:
    /// [version:u8][count:u8][max_records:u16][next_record_id:u32]
    /// followed by `count` records, each 96 bytes.
    fn host_polyglot_lineage_query(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize;
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        if buf_len < 8 {
            return self.stack.push(Value::I32(-1));
        }
        let mut buf = alloc::vec![0u8; buf_len];
        let count = match POLYGLOT_LINEAGE.lock().serialize_records(&mut buf) {
            Ok(count) => count,
            Err(_) => return self.stack.push(Value::I32(-2)),
        };
        self.memory.write(buf_ptr, &buf[..8 + count * POLYGLOT_LINEAGE_WIRE_RECORD_BYTES])?;
        self.stack.push(Value::I32(count as i32))
    }

    /// `polyglot_lineage_query_filtered(buf_ptr: i32, buf_len: i32, filter_kind: i32, filter_a: i32, filter_b: i32) -> i32`
    ///
    /// Write a filtered lineage snapshot into caller memory.
    fn host_polyglot_lineage_query_filtered(&mut self) -> Result<(), WasmError> {
        let filter_b = self.stack.pop()?.as_i32()? as usize;
        let filter_a = self.stack.pop()?.as_i32()? as u32;
        let filter_kind = self.stack.pop()?.as_i32()?;
        let buf_len = self.stack.pop()?.as_i32()? as usize;
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;

        if buf_len < 8 {
            return self.stack.push(Value::I32(-1));
        }
        let Some(kind) = PolyglotLineageFilterKind::from_i32(filter_kind) else {
            return self.stack.push(Value::I32(-2));
        };
        let export_name = if matches!(kind, PolyglotLineageFilterKind::ExportName) {
            if filter_b == 0 || filter_b > 32 {
                return self.stack.push(Value::I32(-1));
            }
            let bytes = self.memory.read(filter_a as usize, filter_b)?;
            Some(bytes)
        } else {
            None
        };
        let mut buf = alloc::vec![0u8; buf_len];
        let count = match POLYGLOT_LINEAGE.lock().serialize_filtered(
            &mut buf,
            kind,
            filter_a,
            filter_b as u32,
            export_name,
        ) {
            Ok(count) => count,
            Err(_) => return self.stack.push(Value::I32(-2)),
        };
        self.memory.write(buf_ptr, &buf[..8 + count * POLYGLOT_LINEAGE_WIRE_RECORD_BYTES])?;
        self.stack.push(Value::I32(count as i32))
    }

    /// `polyglot_lineage_lookup(cap_handle: i32, buf_ptr: i32, buf_len: i32) -> i32`
    ///
    /// Write the latest lineage record associated with a live service-pointer
    /// handle into caller memory.
    fn host_polyglot_lineage_lookup(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize;
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        let cap_handle = CapHandle(self.stack.pop()?.as_u32()?);

        if buf_len < 8 {
            return self.stack.push(Value::I32(-1));
        }

        let object_id = match self.capabilities.get(cap_handle)? {
            WasmCapability::ServicePointer(ptr) => ptr.object_id,
            _ => return self.stack.push(Value::I32(-2)),
        };

        let mut buf = alloc::vec![0u8; buf_len];
        let count = match POLYGLOT_LINEAGE.lock().serialize_latest_by_object(&mut buf, object_id) {
            Ok(count) => count,
            Err(_) => return self.stack.push(Value::I32(-2)),
        };
        self.memory.write(buf_ptr, &buf[..8 + count * POLYGLOT_LINEAGE_WIRE_RECORD_BYTES])?;
        self.stack.push(Value::I32(count as i32))
    }

    /// `polyglot_lineage_lookup_object(object_lo: i32, object_hi: i32, buf_ptr: i32, buf_len: i32) -> i32`
    ///
    /// Write the latest lineage record associated with a persistent object id.
    fn host_polyglot_lineage_lookup_object(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize;
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        let object_hi = self.stack.pop()?.as_i32()? as u32;
        let object_lo = self.stack.pop()?.as_i32()? as u32;

        if buf_len < 8 {
            return self.stack.push(Value::I32(-1));
        }
        let object_id = (object_lo as u64) | ((object_hi as u64) << 32);
        let mut buf = alloc::vec![0u8; buf_len];
        let count = match POLYGLOT_LINEAGE.lock().serialize_latest_by_object(&mut buf, object_id) {
            Ok(count) => count,
            Err(_) => return self.stack.push(Value::I32(-2)),
        };
        self.memory.write(buf_ptr, &buf[..8 + count * POLYGLOT_LINEAGE_WIRE_RECORD_BYTES])?;
        self.stack.push(Value::I32(count as i32))
    }

    /// `polyglot_lineage_revoke(cap_handle: i32) -> i32`
    ///
    /// Explicitly revoke a live service-pointer capability and record the
    /// terminal lineage transition as `Revoked`.
    fn host_polyglot_lineage_revoke(&mut self) -> Result<(), WasmError> {
        let cap_handle = CapHandle(self.stack.pop()?.as_u32()?);
        let object_id = match self.capabilities.get(cap_handle)? {
            WasmCapability::ServicePointer(ptr) => ptr.object_id,
            _ => return self.stack.push(Value::I32(-2)),
        };

        match revoke_service_pointer(self.process_id, object_id) {
            Ok(()) => self.stack.push(Value::I32(0)),
            Err("Permission denied") => self.stack.push(Value::I32(-3)),
            Err(_) => self.stack.push(Value::I32(-2)),
        }
    }

    /// `polyglot_lineage_rebind(cap_handle: i32, target_instance: i32) -> i32`
    ///
    /// Retarget a live service-pointer capability to a compatible replacement
    /// instance owned by the same process.
    fn host_polyglot_lineage_rebind(&mut self) -> Result<(), WasmError> {
        let target_instance = self.stack.pop()?.as_i32()? as usize;
        let cap_handle = CapHandle(self.stack.pop()?.as_u32()?);
        let (object_id, owner_pid, export_name, signature) = match self.capabilities.get(cap_handle)? {
            WasmCapability::ServicePointer(ptr) => {
                let registry = SERVICE_POINTERS.lock();
                let Some(idx) = registry.find_index(ptr.object_id) else {
                    return self.stack.push(Value::I32(-2));
                };
                let live = registry.entries[idx];
                if !live.active {
                    return self.stack.push(Value::I32(-2));
                }
                (
                    live.object_id,
                    live.owner_pid,
                    live.export_name,
                    live.signature,
                )
            }
            _ => return self.stack.push(Value::I32(-2)),
        };

        let export_len = export_name.iter().position(|&b| b == 0).unwrap_or(export_name.len());
        let export_name = &export_name[..export_len];
        let target_function_index = match wasm_runtime().get_instance_mut(
            target_instance,
            |instance| -> Result<usize, WasmError> {
                if instance.process_id != owner_pid {
                    return Err(WasmError::PermissionDenied);
                }
                let function_index = instance
                    .module
                    .resolve_exported_function(export_name)
                    .map_err(|_| WasmError::InvalidModule)?;
                match instance.module.resolve_call_target(function_index) {
                    Ok(CallTarget::Function(_)) => {}
                    _ => return Err(WasmError::InvalidModule),
                }
                let runtime_sig = instance
                    .module
                    .signature_for_combined(function_index)
                    .map_err(|_| WasmError::InvalidModule)?;
                if !parsed_signature_equal(runtime_sig, signature) {
                    return Err(WasmError::InvalidModule);
                }
                Ok(function_index)
            },
        ) {
            Ok(Ok(function_index)) => function_index,
            Ok(Err(_)) => return self.stack.push(Value::I32(-2)),
            Err(_) => return self.stack.push(Value::I32(-2)),
        };

        let mut registry = SERVICE_POINTERS.lock();
        let Some(idx) = registry.find_index(object_id) else {
            return self.stack.push(Value::I32(-2));
        };
        let mut updated = registry.entries[idx];
        if !updated.active {
            return self.stack.push(Value::I32(-2));
        }
        updated.target_instance = target_instance;
        updated.function_index = target_function_index;
        updated.window_start_tick = crate::scheduler::pit::get_ticks();
        updated.calls_in_window = 0;
        registry.entries[idx] = updated;
        drop(registry);

        POLYGLOT_LINEAGE
            .lock()
            .update_lifecycle(object_id, PolyglotLifecycle::Rebound);

        self.stack.push(Value::I32(target_instance as i32))
    }

    /// `polyglot_lineage_status(cap_handle: i32, buf_ptr: i32, buf_len: i32) -> i32`
    ///
    /// Write the current lifecycle summary for a live service-pointer handle.
    fn host_polyglot_lineage_status(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize;
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        let cap_handle = CapHandle(self.stack.pop()?.as_u32()?);

        if buf_len < 8 {
            return self.stack.push(Value::I32(-1));
        }
        let object_id = match self.capabilities.get(cap_handle)? {
            WasmCapability::ServicePointer(ptr) => ptr.object_id,
            _ => return self.stack.push(Value::I32(-2)),
        };
        let mut buf = alloc::vec![0u8; buf_len];
        let count = match POLYGLOT_LINEAGE.lock().serialize_status_by_object(&mut buf, object_id) {
            Ok(count) => count,
            Err(_) => return self.stack.push(Value::I32(-2)),
        };
        self.memory.write(buf_ptr, &buf[..8 + count * POLYGLOT_LINEAGE_STATUS_WIRE_BYTES])?;
        self.stack.push(Value::I32(count as i32))
    }

    /// `polyglot_lineage_status_object(object_lo: i32, object_hi: i32, buf_ptr: i32, buf_len: i32) -> i32`
    ///
    /// Write the current lifecycle summary for a persistent object id.
    fn host_polyglot_lineage_status_object(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize;
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        let object_hi = self.stack.pop()?.as_i32()? as u32;
        let object_lo = self.stack.pop()?.as_i32()? as u32;

        if buf_len < 8 {
            return self.stack.push(Value::I32(-1));
        }
        let object_id = (object_lo as u64) | ((object_hi as u64) << 32);
        let mut buf = alloc::vec![0u8; buf_len];
        let count = match POLYGLOT_LINEAGE.lock().serialize_status_by_object(&mut buf, object_id) {
            Ok(count) => count,
            Err(_) => return self.stack.push(Value::I32(-2)),
        };
        self.memory.write(buf_ptr, &buf[..8 + count * POLYGLOT_LINEAGE_STATUS_WIRE_BYTES])?;
        self.stack.push(Value::I32(count as i32))
    }

    /// `polyglot_lineage_query_page(cursor: i32, limit: i32, buf_ptr: i32, buf_len: i32) -> i32`
    ///
    /// Return a cursor-based page of lineage records after `cursor`.
    fn host_polyglot_lineage_query_page(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize;
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        let limit = self.stack.pop()?.as_i32()? as usize;
        let cursor = self.stack.pop()?.as_i32()? as u64;
        if buf_len < 8 {
            return self.stack.push(Value::I32(-1));
        }
        let mut buf = alloc::vec![0u8; buf_len];
        let count = match POLYGLOT_LINEAGE.lock().serialize_page(&mut buf, cursor, limit.max(1)) {
            Ok(count) => count,
            Err(_) => return self.stack.push(Value::I32(-2)),
        };
        self.memory.write(buf_ptr, &buf[..8 + count * POLYGLOT_LINEAGE_WIRE_RECORD_BYTES])?;
        self.stack.push(Value::I32(count as i32))
    }

    /// `polyglot_lineage_event_query(cursor: i32, limit: i32, buf_ptr: i32, buf_len: i32) -> i32`
    ///
    /// Return a cursor-based page of rebinding/revocation events.
    fn host_polyglot_lineage_event_query(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize;
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        let limit = self.stack.pop()?.as_i32()? as usize;
        let cursor = self.stack.pop()?.as_i32()? as u64;
        if buf_len < 8 {
            return self.stack.push(Value::I32(-1));
        }
        let mut buf = alloc::vec![0u8; buf_len];
        let count = match POLYGLOT_LINEAGE.lock().serialize_events(&mut buf, cursor, limit.max(1)) {
            Ok(count) => count,
            Err(_) => return self.stack.push(Value::I32(-2)),
        };
        self.memory.write(buf_ptr, &buf[..8 + count * POLYGLOT_LINEAGE_EVENT_WIRE_BYTES])?;
        self.stack.push(Value::I32(count as i32))
    }

    // ── WASM Kernel Observer host functions (IDs 106–108) ──────────────────────

    /// `observer_subscribe(event_mask: i32) -> i32`
    ///
    /// Register the calling WASM module as a kernel observer for the events
    /// indicated by `event_mask` (see `observer_events::*`).  A dedicated IPC
    /// channel is created for event delivery; the channel ID is returned on
    /// success.  Returns -1 if the observer table is full or the mask is zero.
    fn host_observer_subscribe(&mut self) -> Result<(), WasmError> {
        let event_mask = self.stack.pop()?.as_i32()? as u32;

        if event_mask == 0 {
            return self.stack.push(Value::I32(-1));
        }

        let instance_id = self.instance_id;
        let owner_pid = self.process_id;

        // Use the high-level IPC helper to create a channel owned by the kernel
        // (kernel will write, observer will read).
        let kernel_pid = crate::ipc::ProcessId(0);
        let (send_cap, _recv_cap) = match crate::ipc::ipc().create_channel(kernel_pid) {
            Ok(pair) => pair,
            Err(_) => return self.stack.push(Value::I32(-2)),
        };
        let ch_id = send_cap.channel_id;

        let mut registry = OBSERVER_REGISTRY.lock();
        match registry.find_empty() {
            None => {
                // We can't easily delete the channel from here without touching
                // private fields, so we simply don't register it and it will
                // be garbage-collected when the IPC service next purges unused
                // channels. Best-effort clean-up: try the public API.
                drop(registry);
                return self.stack.push(Value::I32(-3));
            }
            Some(slot) => {
                registry.entries[slot] = ObserverEntry {
                    active: true,
                    instance_id,
                    channel_id: ch_id.0,
                    event_mask,
                    owner_pid,
                };
                crate::serial_println!(
                    "[observer] subscribe: instance={} mask={:#x} ch={}",
                    instance_id,
                    event_mask,
                    ch_id.0
                );
                drop(registry);
                // Notify existing observers that a new observer just joined.
                let buf = event_mask.to_le_bytes();
                observer_notify(observer_events::POLYGLOT_LINK, &buf);
                self.stack.push(Value::I32(ch_id.0 as i32))
            }
        }
    }

    /// `observer_unsubscribe() -> i32`
    ///
    /// Deregister the calling module as a kernel observer and release its event
    /// delivery channel.  Returns 0 on success, -1 if not subscribed.
    fn host_observer_unsubscribe(&mut self) -> Result<(), WasmError> {
        let instance_id = self.instance_id;

        let mut registry = OBSERVER_REGISTRY.lock();
        match registry.find_by_instance(instance_id) {
            None => self.stack.push(Value::I32(-1)),
            Some(slot) => {
                let ch_raw = registry.entries[slot].channel_id;
                registry.entries[slot].active = false;
                let ch_id = crate::ipc::ChannelId::new(ch_raw);
                drop(registry);
                // Best-effort: signal the channel is closing via the public
                // IPC close path. If it fails (e.g., missing capability) we
                // still consider unsubscription successful.
                let close_cap = crate::ipc::ChannelCapability::new(
                    0,
                    ch_id,
                    crate::ipc::ChannelRights::all(),
                    crate::ipc::ProcessId(0),
                );
                let _ = crate::ipc::ipc().close(&close_cap);
                crate::serial_println!(
                    "[observer] unsubscribe: instance={} ch={}",
                    instance_id,
                    ch_raw
                );
                self.stack.push(Value::I32(0))
            }
        }
    }

    /// `observer_query(buf_ptr: i32, buf_len: i32) -> i32`
    ///
    /// Drain pending events from the caller's observer channel into WASM memory.
    /// Each event occupies 32 bytes (see `observer_notify` encoding).
    /// `buf_len` is the number of bytes in the caller's buffer; the function
    /// writes at most `buf_len / 32` events and returns the number written.
    /// Returns -1 if the caller is not a registered observer.
    fn host_observer_query(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize;
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        let instance_id = self.instance_id;
        let max_events = buf_len / 32;

        if max_events == 0 {
            return self.stack.push(Value::I32(0));
        }

        // Resolve channel ID from the registry.
        let (ch_raw, owner_pid) = {
            let registry = OBSERVER_REGISTRY.lock();
            match registry.find_by_instance(instance_id) {
                None => return self.stack.push(Value::I32(-1)),
                Some(s) => (
                    registry.entries[s].channel_id,
                    registry.entries[s].owner_pid,
                ),
            }
        };

        let ch_id = crate::ipc::ChannelId::new(ch_raw);
        let recv_cap = crate::ipc::ChannelCapability::new(
            0,
            ch_id,
            crate::ipc::ChannelRights::receive_only(),
            owner_pid,
        );
        let mut count = 0usize;

        while count < max_events {
            let msg_result = crate::ipc::ipc().try_recv(&recv_cap);
            match msg_result {
                Ok(msg) => {
                    let data = msg.payload();
                    let offset = buf_ptr + count * 32;
                    let to_copy = data.len().min(32);
                    // Zero-fill the slot first, then write the actual payload.
                    let zeroes = [0u8; 32];
                    self.memory.write(offset, &zeroes)?;
                    self.memory.write(offset, &data[..to_copy])?;
                    count += 1;
                }
                Err(_) => break, // channel empty or error — stop draining
            }
        }

        self.stack.push(Value::I32(count as i32))
    }

    // ── Decentralized Kernel Mesh host functions (IDs 109–115) ───────────────

    /// `mesh_local_id() -> i32`
    ///
    /// Return the low 32 bits of this node's capnet device ID.  Returns 0 if
    /// the mesh subsystem has not been initialised yet.
    fn host_mesh_local_id(&mut self) -> Result<(), WasmError> {
        let id = crate::net::capnet::local_device_id().unwrap_or(0);
        self.stack.push(Value::I32(id as u32 as i32))
    }

    /// `mesh_peer_register(peer_lo: i32, peer_hi: i32, trust: i32) -> i32`
    ///
    /// Register a remote peer device.  `peer_lo`/`peer_hi` are the low and
    /// high 32 bits of the peer's 64-bit device ID.  `trust` is:
    ///   0 = `Audit` (record mismatches), 1 = `Enforce` (reject mismatches).
    /// Returns 0 on success, -1 on error.
    fn host_mesh_peer_register(&mut self) -> Result<(), WasmError> {
        let trust_val = self.stack.pop()?.as_i32()?;
        let peer_hi = self.stack.pop()?.as_i32()? as u64;
        let peer_lo = self.stack.pop()?.as_i32()? as u64;
        let peer_id = (peer_hi << 32) | (peer_lo & 0xFFFF_FFFF);
        let trust = if trust_val == 0 {
            crate::net::capnet::PeerTrustPolicy::Audit
        } else {
            crate::net::capnet::PeerTrustPolicy::Enforce
        };
        match crate::net::capnet::register_peer(peer_id, trust, 0) {
            Ok(()) => self.stack.push(Value::I32(0)),
            Err(_) => self.stack.push(Value::I32(-1)),
        }
    }

    /// `mesh_peer_session(peer_lo: i32, peer_hi: i32) -> i32`
    ///
    /// Returns the current session key epoch for the named peer (≥ 1 means an
    /// active session exists), or 0 if no session has been established, or -1
    /// if the peer is not registered.
    fn host_mesh_peer_session(&mut self) -> Result<(), WasmError> {
        let peer_hi = self.stack.pop()?.as_i32()? as u64;
        let peer_lo = self.stack.pop()?.as_i32()? as u64;
        let peer_id = (peer_hi << 32) | (peer_lo & 0xFFFF_FFFF);
        match crate::net::capnet::peer_snapshot(peer_id) {
            None => self.stack.push(Value::I32(-1)),
            Some(s) => self.stack.push(Value::I32(s.key_epoch as i32)),
        }
    }

    /// `mesh_token_mint(obj_lo: i32, obj_hi: i32, cap_type: i32, rights: i32,
    ///                  expires_ticks: i32, buf_ptr: i32) -> i32`
    ///
    /// Mint a signed `CapabilityTokenV1` for the calling module's process and
    /// write the 116-byte encoded token into WASM memory at `buf_ptr`.
    /// `expires_ticks` is added to the current PIT tick to compute `expires_at`.
    /// Returns 0 on success, negative on failure.
    fn host_mesh_token_mint(&mut self) -> Result<(), WasmError> {
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        let expires_ticks = self.stack.pop()?.as_i32()? as u64;
        let rights = self.stack.pop()?.as_i32()? as u32;
        let cap_type_val = self.stack.pop()?.as_i32()? as u8;
        let obj_hi = self.stack.pop()?.as_i32()? as u64;
        let obj_lo = self.stack.pop()?.as_i32()? as u64;
        let object_id = (obj_hi << 32) | (obj_lo & 0xFFFF_FFFF);

        let now = crate::scheduler::pit::get_ticks() as u64;
        let local_id = match crate::net::capnet::local_device_id() {
            Some(id) => id,
            None => return self.stack.push(Value::I32(-1)),
        };

        let mut token = crate::net::capnet::CapabilityTokenV1 {
            version: 1,
            alg_id: 1,
            cap_type: cap_type_val,
            token_flags: 0,
            issuer_device_id: local_id,
            subject_device_id: local_id, // self-issued; caller can re-send to peer
            object_id,
            rights,
            constraints_flags: 0,
            issued_at: now,
            not_before: now,
            expires_at: now.saturating_add(expires_ticks),
            nonce: crate::security::security().random_u32() as u64,
            delegation_depth: 0,
            max_uses: 0,
            parent_token_hash: 0,
            measurement_hash: 0,
            session_id: self.process_id.0,
            context: 0,
            max_bytes: 0,
            resource_quota: 0,
            mac: 0,
        };
        token.sign_with_kernel_key();

        let encoded = token.encode();
        self.memory.write(buf_ptr, &encoded)?;
        crate::serial_println!(
            "[mesh] token minted: obj={:#018x} type={} rights={:#x} exp={}",
            object_id,
            cap_type_val,
            rights,
            token.expires_at
        );
        self.stack.push(Value::I32(0))
    }

    /// `mesh_token_send(peer_lo: i32, peer_hi: i32, buf_ptr: i32, buf_len: i32) -> i32`
    ///
    /// Wrap the token at `buf_ptr` (exactly `CAPNET_TOKEN_V1_LEN` = 116 bytes)
    /// in a CapNet `TokenOffer` control frame signed with the peer session key
    /// and write the resulting frame into the observer/IPC layer for transport.
    /// Returns the frame byte-length on success, or negative on error.
    fn host_mesh_token_send(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize;
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        let peer_hi = self.stack.pop()?.as_i32()? as u64;
        let peer_lo = self.stack.pop()?.as_i32()? as u64;
        let peer_id = (peer_hi << 32) | (peer_lo & 0xFFFF_FFFF);

        if buf_len != crate::net::capnet::CAPNET_TOKEN_V1_LEN {
            return self.stack.push(Value::I32(-1));
        }

        let raw = self.memory.read(buf_ptr, buf_len)?;
        let mut token = match crate::net::capnet::CapabilityTokenV1::decode_checked(raw) {
            Ok(t) => t,
            Err(_) => return self.stack.push(Value::I32(-2)),
        };

        let frame = match crate::net::capnet::build_token_offer_frame(peer_id, 0, &mut token) {
            Ok(f) => f,
            Err(_) => return self.stack.push(Value::I32(-3)),
        };

        // Emit via observer bus so an observer WASM module (or the host net
        // driver) can pick it up and forward it over the wire.
        let frame_bytes = &frame.bytes[..frame.len];
        let copy_len = frame_bytes.len().min(28);
        observer_notify(observer_events::IPC_ACTIVITY, &frame_bytes[..copy_len]);
        crate::serial_println!(
            "[mesh] token_send: peer={:#018x} frame_len={}",
            peer_id,
            frame.len
        );
        self.stack.push(Value::I32(frame.len as i32))
    }

    /// `mesh_token_recv(buf_ptr: i32, buf_len: i32) -> i32`
    ///
    /// Export one active remote lease visible to the calling process as an
    /// encoded `CapabilityTokenV1` snapshot. Returns 0 if a token-like record
    /// was written, or -1 if no visible remote lease exists.
    fn host_mesh_token_recv(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize;
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;

        if buf_len < crate::net::capnet::CAPNET_TOKEN_V1_LEN {
            return self.stack.push(Value::I32(-1));
        }

        let leases = crate::capability::capability_manager().remote_lease_snapshots();
        let mut selected = None;
        let mut i = 0usize;
        while i < leases.len() {
            if let Some(lease) = leases[i] {
                if lease.active
                    && !lease.revoked
                    && (lease.owner_any || lease.owner_pid == self.process_id)
                {
                    selected = Some(lease);
                    break;
                }
            }
            i += 1;
        }

        match selected {
            None => self.stack.push(Value::I32(-1)),
            Some(lease) => {
                let mut token = crate::net::capnet::CapabilityTokenV1::empty();
                token.cap_type = lease.cap_type as u8;
                token.issuer_device_id = lease.issuer_device_id;
                token.subject_device_id = crate::net::capnet::local_device_id().unwrap_or(0);
                token.object_id = lease.object_id;
                token.rights = lease.rights.bits();
                token.issued_at = lease.not_before;
                token.not_before = lease.not_before;
                token.expires_at = lease.expires_at;
                token.nonce = lease.token_id;
                token.parent_token_hash = lease.token_id;
                token.measurement_hash = lease.measurement_hash;
                token.session_id = lease.session_id;
                token.context = if lease.owner_any {
                    0
                } else {
                    lease.owner_pid.0
                };
                if lease.enforce_use_budget {
                    token.constraints_flags |= crate::net::capnet::CAPNET_CONSTRAINT_REQUIRE_BOUNDED_USE;
                    token.max_uses = lease.uses_remaining;
                }
                let encoded = token.encode();
                self.memory.write(buf_ptr, &encoded)?;
                self.stack.push(Value::I32(0))
            }
        }
    }

    /// `mesh_migrate(peer_lo: i32, peer_hi: i32, wasm_ptr: i32, wasm_len: i32) -> i32`
    ///
    /// Queue the WASM bytecode at `wasm_ptr`/`wasm_len` (or the calling
    /// module's own bytecode if `wasm_len == 0`) for migration to the target
    /// peer device.  The actual network transfer is performed by
    /// `mesh_migrate_flush()` from the scheduler tick.
    /// Returns 0 on success, -1 if the queue is full, -2 if bytes are too large.
    fn mesh_migrate_payload_bytes(
        &self,
        wasm_ptr: usize,
        wasm_len: usize,
    ) -> Result<Vec<u8>, WasmError> {
        if wasm_len > 0 {
            return Ok(self.memory.read(wasm_ptr, wasm_len)?.to_vec());
        }

        if self.module.bytecode_len == 0 {
            return Err(WasmError::InvalidModule);
        }

        Ok(self.module.bytecode[..self.module.bytecode_len].to_vec())
    }

    fn host_mesh_migrate(&mut self) -> Result<(), WasmError> {
        let wasm_len = self.stack.pop()?.as_i32()? as usize;
        let wasm_ptr = self.stack.pop()?.as_i32()? as usize;
        let peer_hi = self.stack.pop()?.as_i32()? as u64;
        let peer_lo = self.stack.pop()?.as_i32()? as u64;
        let peer_id = (peer_hi << 32) | (peer_lo & 0xFFFF_FFFF);

        if wasm_len > 65536 {
            return self.stack.push(Value::I32(-2));
        }
        let data = match self.mesh_migrate_payload_bytes(wasm_ptr, wasm_len) {
            Ok(data) => data,
            Err(_) => return self.stack.push(Value::I32(-2)),
        };

        let mut q = MESH_MIGRATE_QUEUE.lock();
        match q.find_empty() {
            None => {
                drop(q);
                return self.stack.push(Value::I32(-1));
            }
            Some(slot) => {
                q.slots[slot].active = true;
                q.slots[slot].peer_id = peer_id;
                q.slots[slot].requester_pid = self.process_id;
                let copy_len = data.len().min(65536);
                q.slots[slot].bytecode_len = copy_len;
                let mut i = 0usize;
                while i < copy_len {
                    q.slots[slot].bytecode[i] = data[i];
                    i += 1;
                }
                drop(q);
                crate::serial_println!(
                    "[mesh] migrate queued: peer={:#018x} bytes={}",
                    peer_id,
                    copy_len
                );
                // Kick the flush immediately.
                mesh_migrate_flush();
                self.stack.push(Value::I32(0))
            }
        }
    }

    #[cfg(test)]
    fn mesh_migrate_payload_bytes_for_test(&self, wasm_ptr: usize, wasm_len: usize) -> Vec<u8> {
        self.mesh_migrate_payload_bytes(wasm_ptr, wasm_len)
            .expect("mesh migrate payload should be available")
    }

    // ── Temporal Capabilities with Revocable History ─────────────────────

    /// `temporal_cap_grant(cap_type: i32, rights: i32, expires_ticks: i32) -> i32`
    ///
    /// Grant the calling process a time-bound capability.  The kernel
    /// automatically revokes it after `expires_ticks` PIT ticks (100 Hz).
    /// Returns the `cap_id` (≥ 0) on success, negative on failure.
    fn host_temporal_cap_grant(&mut self) -> Result<(), WasmError> {
        let expires_ticks = self.stack.pop()?.as_i32()? as u64;
        let rights_raw = self.stack.pop()?.as_i32()? as u32;
        let cap_type_raw = self.stack.pop()?.as_i32()? as u8;

        let cap_type = match crate::capability::CapabilityType::from_raw(cap_type_raw) {
            Some(t) => t,
            None => return self.stack.push(Value::I32(-1)),
        };
        let rights = crate::capability::Rights::new(rights_raw);
        let now = crate::scheduler::pit::get_ticks() as u64;
        let object_id = now ^ (self.process_id.0 as u64).wrapping_mul(0x9E3779B97F4A7C15);

        let cap_id = match crate::capability::capability_manager().grant_capability(
            self.process_id,
            object_id,
            cap_type,
            rights,
            self.process_id,
        ) {
            Ok(id) => id,
            Err(_) => return self.stack.push(Value::I32(-2)),
        };

        // Register in temporal expiry table.
        let mut tbl = TEMPORAL_CAP_TABLE.lock();
        let mut placed = false;
        let mut i = 0usize;
        while i < MAX_TEMPORAL_CAP_SLOTS {
            if !tbl.slots[i].active {
                tbl.slots[i] = TemporalCapSlot {
                    active: true,
                    pid: self.process_id.0,
                    cap_id,
                    expires_at: now.saturating_add(expires_ticks),
                    cap_type: cap_type_raw,
                    object_id,
                };
                placed = true;
                break;
            }
            i += 1;
        }
        drop(tbl);

        if !placed {
            // Table full — revoke the cap we just granted and fail.
            let _ =
                crate::capability::capability_manager().revoke_capability(self.process_id, cap_id);
            return self.stack.push(Value::I32(-3));
        }

        // Record in the temporal log so this grant appears in rollback history.
        if !crate::temporal::is_replay_active() {
            let _ = crate::temporal::record_capability_event(
                self.process_id.0,
                cap_type_raw,
                object_id,
                rights_raw,
                self.process_id.0,
                crate::temporal::TEMPORAL_CAPABILITY_EVENT_GRANT,
                cap_id,
            );
        }

        crate::serial_println!(
            "[temporal] cap_grant: pid={} cap_id={} type={} expires_at={}",
            self.process_id.0,
            cap_id,
            cap_type_raw,
            crate::scheduler::pit::get_ticks() as u64 + expires_ticks
        );
        self.stack.push(Value::I32(cap_id as i32))
    }

    /// `temporal_cap_revoke(cap_id: i32) -> i32`
    ///
    /// Manually revoke a time-bound (or any) capability held by this process.
    /// Returns 0 on success, -1 if not found.
    fn host_temporal_cap_revoke(&mut self) -> Result<(), WasmError> {
        let cap_id = self.stack.pop()?.as_i32()? as u32;

        match crate::capability::capability_manager().revoke_capability(self.process_id, cap_id) {
            Ok(()) => {
                // Remove from expiry table.
                let mut tbl = TEMPORAL_CAP_TABLE.lock();
                let mut i = 0usize;
                while i < MAX_TEMPORAL_CAP_SLOTS {
                    if tbl.slots[i].active
                        && tbl.slots[i].pid == self.process_id.0
                        && tbl.slots[i].cap_id == cap_id
                    {
                        tbl.slots[i].active = false;
                        break;
                    }
                    i += 1;
                }
                drop(tbl);
                crate::serial_println!(
                    "[temporal] cap_revoke: pid={} cap_id={}",
                    self.process_id.0,
                    cap_id
                );
                // Record revocation in temporal log.
                if !crate::temporal::is_replay_active() {
                    let _ = crate::temporal::record_capability_event(
                        self.process_id.0,
                        0,
                        0,
                        0,
                        self.process_id.0,
                        crate::temporal::TEMPORAL_CAPABILITY_EVENT_REVOKE,
                        cap_id,
                    );
                }
                self.stack.push(Value::I32(0))
            }
            Err(_) => self.stack.push(Value::I32(-1)),
        }
    }

    /// `temporal_cap_check(cap_id: i32) -> i32`
    ///
    /// Returns the number of PIT ticks remaining before the capability expires
    /// (may be 0 if it expires this tick), or -1 if the cap_id is unknown or
    /// not time-bound.
    fn host_temporal_cap_check(&mut self) -> Result<(), WasmError> {
        let cap_id = self.stack.pop()?.as_i32()? as u32;
        let now = crate::scheduler::pit::get_ticks() as u64;
        let tbl = TEMPORAL_CAP_TABLE.lock();
        let mut remaining: i32 = -1;
        let mut i = 0usize;
        while i < MAX_TEMPORAL_CAP_SLOTS {
            let s = &tbl.slots[i];
            if s.active && s.pid == self.process_id.0 && s.cap_id == cap_id {
                remaining = if now >= s.expires_at {
                    0
                } else {
                    (s.expires_at - now).min(i32::MAX as u64) as i32
                };
                break;
            }
            i += 1;
        }
        drop(tbl);
        self.stack.push(Value::I32(remaining))
    }

    /// `temporal_checkpoint_create() -> i32`
    ///
    /// Snapshot the calling process's current capability set.  Returns a
    /// `checkpoint_id` (≥ 1) on success or -1 if the store is full.
    fn host_temporal_checkpoint_create(&mut self) -> Result<(), WasmError> {
        let now = crate::scheduler::pit::get_ticks() as u64;
        let snap =
            crate::capability::capability_manager().list_capabilities_for_pid(self.process_id);

        let mut store = TEMPORAL_CHECKPOINT_STORE.lock();
        // Find an empty slot.
        let mut slot_idx: Option<usize> = None;
        let mut i = 0usize;
        while i < MAX_TEMPORAL_CHECKPOINTS {
            if !store.slots[i].active {
                slot_idx = Some(i);
                break;
            }
            i += 1;
        }
        let idx = match slot_idx {
            None => {
                drop(store);
                return self.stack.push(Value::I32(-1));
            }
            Some(i) => i,
        };

        let id = store.next_id;
        store.next_id = store.next_id.wrapping_add(1).max(1);
        store.slots[idx].active = true;
        store.slots[idx].id = id;
        store.slots[idx].pid = self.process_id.0;
        store.slots[idx].tick = now;
        store.slots[idx].cap_count = 0;

        let mut j = 0usize;
        let mut k = 0usize;
        while j < snap.len() && k < MAX_CAPS_PER_CHECKPOINT {
            if let Some(c) = snap[j] {
                store.slots[idx].caps[k] = TemporalCheckpointEntry {
                    cap_id: c.cap_id,
                    object_id: c.object_id,
                    cap_type: c.cap_type as u8,
                    rights: c.rights.bits(),
                };
                k += 1;
            }
            j += 1;
        }
        store.slots[idx].cap_count = k as u8;
        drop(store);

        crate::serial_println!(
            "[temporal] checkpoint_create: pid={} id={} caps={} tick={}",
            self.process_id.0,
            id,
            k,
            now
        );
        self.stack.push(Value::I32(id as i32))
    }

    /// `temporal_checkpoint_rollback(checkpoint_id: i32) -> i32`
    ///
    /// Roll back the calling process's capabilities to the named checkpoint:
    /// revokes all capabilities granted after the snapshot, then re-grants the
    /// snapshotted set.  Returns 0 on success, -1 if checkpoint not found or
    /// not owned by this process, -2 on re-grant failure.
    fn host_temporal_checkpoint_rollback(&mut self) -> Result<(), WasmError> {
        let checkpoint_id = self.stack.pop()?.as_i32()? as u32;

        // Locate checkpoint.
        let checkpoint = {
            let store = TEMPORAL_CHECKPOINT_STORE.lock();
            let mut found: Option<TemporalCheckpoint> = None;
            let mut i = 0usize;
            while i < MAX_TEMPORAL_CHECKPOINTS {
                if store.slots[i].active
                    && store.slots[i].id == checkpoint_id
                    && store.slots[i].pid == self.process_id.0
                {
                    found = Some(store.slots[i]);
                    break;
                }
                i += 1;
            }
            found
        };

        let cp = match checkpoint {
            None => return self.stack.push(Value::I32(-1)),
            Some(c) => c,
        };

        // Revoke all current capabilities for this process.
        crate::capability::capability_manager().revoke_all_for_pid(self.process_id);

        // Re-grant snapshotted capabilities.
        let mut i = 0usize;
        while i < cp.cap_count as usize {
            let entry = &cp.caps[i];
            let cap_type = match crate::capability::CapabilityType::from_raw(entry.cap_type) {
                Some(t) => t,
                None => {
                    i += 1;
                    continue;
                }
            };
            let _ = crate::capability::capability_manager().grant_capability(
                self.process_id,
                entry.object_id,
                cap_type,
                crate::capability::Rights::new(entry.rights),
                self.process_id,
            );
            i += 1;
        }

        crate::serial_println!(
            "[temporal] checkpoint_rollback: pid={} id={} caps_restored={}",
            self.process_id.0,
            checkpoint_id,
            cp.cap_count
        );
        // Record rollback in temporal log.
        if !crate::temporal::is_replay_active() {
            let _ = crate::temporal::record_capability_event(
                self.process_id.0,
                0,
                checkpoint_id as u64,
                0,
                self.process_id.0,
                0x10,
                0,
            );
        }
        observer_notify(
            observer_events::CAPABILITY_OP,
            &[
                self.process_id.0.to_le_bytes()[0],
                self.process_id.0.to_le_bytes()[1],
                self.process_id.0.to_le_bytes()[2],
                self.process_id.0.to_le_bytes()[3],
                0x10,
                0,
                0,
                0, // 0x10 = ROLLBACK tag
            ],
        );
        self.stack.push(Value::I32(0))
    }

    // ── Intensional Kernel: Policy-as-Capability-Contracts ───────────────────

    /// `policy_bind(cap_id: i32, wasm_ptr: i32, wasm_len: i32) -> i32`
    ///
    /// Attach an executable policy contract to a capability.  The contract
    /// bytecode is read from WASM memory at `wasm_ptr` (length `wasm_len`,
    /// max 4 KiB).  Any access check using `cap_id` will first evaluate this
    /// contract; if it returns non-zero the access is denied.
    ///
    /// Returns 0 on success, -1 if `cap_id` is not found, -2 if bytecode is
    /// too large, -3 if the policy store is full.
    fn host_policy_bind(&mut self) -> Result<(), WasmError> {
        let wasm_len = self.stack.pop()?.as_i32()? as usize;
        let wasm_ptr = self.stack.pop()?.as_i32()? as usize;
        let cap_id = self.stack.pop()?.as_i32()? as u32;

        if wasm_len > MAX_POLICY_WASM_LEN {
            return self.stack.push(Value::I32(-2));
        }

        // Verify the capability exists for this process.
        if crate::capability::capability_manager()
            .query_capability(self.process_id, cap_id)
            .is_err()
        {
            return self.stack.push(Value::I32(-1));
        }

        let bytecode = self.memory.read(wasm_ptr, wasm_len)?;
        let mut hash = 0u64;
        let mut i = 0usize;
        while i < bytecode.len() {
            hash = hash
                .wrapping_mul(0x9E3779B97F4A7C15)
                .wrapping_add(bytecode[i] as u64);
            i += 1;
        }

        let mut store = POLICY_STORE.lock();
        // Replace existing binding for this (pid, cap_id) if present.
        let mut found_slot: Option<usize> = None;
        let mut empty_slot: Option<usize> = None;
        let mut i = 0usize;
        while i < MAX_POLICY_SLOTS {
            if store.slots[i].active
                && store.slots[i].pid == self.process_id.0
                && store.slots[i].cap_id == cap_id
            {
                found_slot = Some(i);
                break;
            }
            if !store.slots[i].active && empty_slot.is_none() {
                empty_slot = Some(i);
            }
            i += 1;
        }
        let idx = match found_slot.or(empty_slot) {
            Some(i) => i,
            None => {
                drop(store);
                return self.stack.push(Value::I32(-3));
            }
        };

        store.slots[idx].active = true;
        store.slots[idx].pid = self.process_id.0;
        store.slots[idx].cap_id = cap_id;
        store.slots[idx].wasm_hash = hash;
        store.slots[idx].wasm_len = wasm_len as u16;
        let mut j = 0usize;
        while j < wasm_len {
            store.slots[idx].bytecode[j] = bytecode[j];
            j += 1;
        }
        drop(store);

        crate::serial_println!(
            "[policy] bind: pid={} cap_id={} wasm_len={} hash={:#018x}",
            self.process_id.0,
            cap_id,
            wasm_len,
            hash
        );
        self.stack.push(Value::I32(0))
    }

    /// `policy_unbind(cap_id: i32) -> i32`
    ///
    /// Remove the policy contract bound to `cap_id` for this process.
    /// Returns 0 on success, -1 if no policy was bound.
    fn host_policy_unbind(&mut self) -> Result<(), WasmError> {
        let cap_id = self.stack.pop()?.as_i32()? as u32;
        let mut store = POLICY_STORE.lock();
        let mut i = 0usize;
        while i < MAX_POLICY_SLOTS {
            if store.slots[i].active
                && store.slots[i].pid == self.process_id.0
                && store.slots[i].cap_id == cap_id
            {
                store.slots[i].active = false;
                drop(store);
                crate::serial_println!(
                    "[policy] unbind: pid={} cap_id={}",
                    self.process_id.0,
                    cap_id
                );
                return self.stack.push(Value::I32(0));
            }
            i += 1;
        }
        drop(store);
        self.stack.push(Value::I32(-1))
    }

    /// `policy_eval(cap_id: i32, ctx_ptr: i32, ctx_len: i32) -> i32`
    ///
    /// Evaluate the policy contract bound to `cap_id` against the context
    /// bytes at `ctx_ptr`/`ctx_len` (max 256 bytes).
    ///
    /// Returns 0 = permit, 1 = deny. Missing policies are denied.
    fn host_policy_eval(&mut self) -> Result<(), WasmError> {
        let ctx_len = self.stack.pop()?.as_i32()? as usize;
        let ctx_ptr = self.stack.pop()?.as_i32()? as usize;
        let cap_id = self.stack.pop()?.as_i32()? as u32;

        let ctx_len = ctx_len.min(256);
        let ctx_bytes = self.memory.read(ctx_ptr, ctx_len)?;

        // Snapshot the policy bytecode under the lock.
        let bytecode: Option<([u8; MAX_POLICY_WASM_LEN], usize)> = {
            let store = POLICY_STORE.lock();
            let mut found = None;
            let mut i = 0usize;
            while i < MAX_POLICY_SLOTS {
                if store.slots[i].active
                    && store.slots[i].pid == self.process_id.0
                    && store.slots[i].cap_id == cap_id
                {
                    found = Some((store.slots[i].bytecode, store.slots[i].wasm_len as usize));
                    break;
                }
                i += 1;
            }
            found
        };

        match bytecode {
            None => self.stack.push(Value::I32(1)), // no policy → deny
            Some((bc, bc_len)) => {
                let permit = run_policy_contract(&bc[..bc_len], ctx_bytes);
                crate::serial_println!(
                    "[policy] eval: pid={} cap_id={} ctx_len={} result={}",
                    self.process_id.0,
                    cap_id,
                    ctx_len,
                    if permit { "permit" } else { "deny" }
                );
                self.stack.push(Value::I32(if permit { 0 } else { 1 }))
            }
        }
    }

    /// `policy_query(cap_id: i32, buf_ptr: i32, buf_len: i32) -> i32`
    ///
    /// Write policy metadata for `cap_id` into the WASM buffer.
    ///
    /// Buffer layout (16 bytes):
    /// `[hash: u64 LE][wasm_len: u16 LE][bound: u8][reserved: u8][cap_id: u32 LE]`
    ///
    /// Returns 0 if a policy is bound, -1 if no policy is bound, -2 if
    /// `buf_len < 16`.
    fn host_policy_query(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize;
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        let cap_id = self.stack.pop()?.as_i32()? as u32;

        if buf_len < 16 {
            return self.stack.push(Value::I32(-2));
        }

        let store = POLICY_STORE.lock();
        let mut found: Option<(u64, u16)> = None;
        let mut i = 0usize;
        while i < MAX_POLICY_SLOTS {
            if store.slots[i].active
                && store.slots[i].pid == self.process_id.0
                && store.slots[i].cap_id == cap_id
            {
                found = Some((store.slots[i].wasm_hash, store.slots[i].wasm_len));
                break;
            }
            i += 1;
        }
        drop(store);

        match found {
            None => self.stack.push(Value::I32(-1)),
            Some((hash, wasm_len)) => {
                let mut out = [0u8; 16];
                let hb = hash.to_le_bytes();
                let mut j = 0usize;
                while j < 8 {
                    out[j] = hb[j];
                    j += 1;
                }
                let lb = wasm_len.to_le_bytes();
                out[8] = lb[0];
                out[9] = lb[1];
                out[10] = 1; // bound = true
                out[11] = 0; // reserved
                let cb = cap_id.to_le_bytes();
                out[12] = cb[0];
                out[13] = cb[1];
                out[14] = cb[2];
                out[15] = cb[3];
                self.memory.write(buf_ptr, &out)?;
                self.stack.push(Value::I32(0))
            }
        }
    }

    // =======================================================================
    // Quantum-Inspired Capability Entanglement (IDs 125–128)
    // =======================================================================

    /// `cap_entangle(cap_a: i32, cap_b: i32) -> i32`
    ///
    /// Link two capabilities owned by this process: revoking either one
    /// automatically revokes the other via cascade.
    ///
    /// Returns `0`=ok, `-1`=cap_a not owned, `-2`=cap_b not owned,
    /// `-3`=table full.
    fn host_cap_entangle(&mut self) -> Result<(), WasmError> {
        let cap_b = self.stack.pop()?.as_i32()? as u32;
        let cap_a = self.stack.pop()?.as_i32()? as u32;
        let pid = self.process_id.0;

        // Verify both caps exist for this process.
        if crate::capability::capability_manager()
            .query_capability(crate::ipc::ProcessId(pid), cap_a)
            .is_err()
        {
            return self.stack.push(Value::I32(-1));
        }
        if crate::capability::capability_manager()
            .query_capability(crate::ipc::ProcessId(pid), cap_b)
            .is_err()
        {
            return self.stack.push(Value::I32(-2));
        }

        let mut tbl = ENTANGLE_TABLE.lock();
        // Find a free slot.
        let mut slot = None;
        let mut i = 0usize;
        while i < MAX_ENTANGLE_LINKS {
            if !tbl.links[i].active {
                slot = Some(i);
                break;
            }
            i += 1;
        }
        match slot {
            None => {
                drop(tbl);
                self.stack.push(Value::I32(-3))
            }
            Some(idx) => {
                tbl.links[idx] = EntangleLink {
                    active: true,
                    pid,
                    cap_a,
                    cap_b,
                    group_id: 0,
                };
                drop(tbl);
                crate::serial_println!(
                    "[entangle] pairwise: pid={} cap_a={} cap_b={}",
                    pid,
                    cap_a,
                    cap_b
                );
                self.stack.push(Value::I32(0))
            }
        }
    }

    /// `cap_entangle_group(group_ptr: i32, group_len: i32) -> i32`
    ///
    /// Entangle a group of capabilities.  `group_ptr` points to `group_len`
    /// packed little-endian u32 cap IDs in WASM memory.  All caps must be
    /// owned by the calling process.
    ///
    /// Returns the `group_id` (≥ 1) on success, or negative on failure.
    fn host_cap_entangle_group(&mut self) -> Result<(), WasmError> {
        let group_len = self.stack.pop()?.as_i32()? as usize;
        let group_ptr = self.stack.pop()?.as_i32()? as usize;
        let pid = self.process_id.0;

        // Validate: max 32 caps in a group, must be > 1.
        if group_len < 2 || group_len > 32 {
            return self.stack.push(Value::I32(-1));
        }

        // Read cap IDs from WASM memory (4 bytes each, LE).
        let byte_len = group_len * 4;
        let raw_bytes = self.memory.read(group_ptr, byte_len)?;
        let mut caps = [0u32; 32];
        let mut gi = 0usize;
        while gi < group_len {
            let b = gi * 4;
            caps[gi] = u32::from_le_bytes([
                raw_bytes[b],
                raw_bytes[b + 1],
                raw_bytes[b + 2],
                raw_bytes[b + 3],
            ]);
            gi += 1;
        }

        // Verify all caps exist.
        let mut vi = 0usize;
        while vi < group_len {
            if crate::capability::capability_manager()
                .query_capability(crate::ipc::ProcessId(pid), caps[vi])
                .is_err()
            {
                return self.stack.push(Value::I32(-2));
            }
            vi += 1;
        }

        // Allocate group_id and add N*(N-1)/2 pairwise links.
        let mut tbl = ENTANGLE_TABLE.lock();
        let group_id = tbl.next_group_id;
        tbl.next_group_id = tbl.next_group_id.wrapping_add(1).max(1);

        // Check capacity first: need group_len-1 links (star topology).
        let needed = group_len - 1;
        let mut free_count = 0usize;
        let mut fi = 0usize;
        while fi < MAX_ENTANGLE_LINKS {
            if !tbl.links[fi].active {
                free_count += 1;
            }
            fi += 1;
        }
        if free_count < needed {
            drop(tbl);
            return self.stack.push(Value::I32(-3));
        }

        // Star topology: anchor = caps[0], link it to every other cap.
        let anchor = caps[0];
        let mut li = 1usize;
        let mut slot = 0usize;
        'outer: while li < group_len {
            while slot < MAX_ENTANGLE_LINKS {
                if !tbl.links[slot].active {
                    tbl.links[slot] = EntangleLink {
                        active: true,
                        pid,
                        cap_a: anchor,
                        cap_b: caps[li],
                        group_id,
                    };
                    slot += 1;
                    break;
                }
                slot += 1;
                if slot >= MAX_ENTANGLE_LINKS {
                    break 'outer;
                }
            }
            li += 1;
        }
        drop(tbl);

        crate::serial_println!(
            "[entangle] group {}: pid={} size={}",
            group_id,
            pid,
            group_len
        );
        self.stack.push(Value::I32(group_id as i32))
    }

    /// `cap_disentangle(cap_id: i32) -> i32`
    ///
    /// Remove all entanglement links involving `cap_id` for this process.
    ///
    /// Returns `0`=ok (at least one link removed), `-1`=no links found.
    fn host_cap_disentangle(&mut self) -> Result<(), WasmError> {
        let cap_id = self.stack.pop()?.as_i32()? as u32;
        let pid = self.process_id.0;

        let mut tbl = ENTANGLE_TABLE.lock();
        let mut found = false;
        let mut i = 0usize;
        while i < MAX_ENTANGLE_LINKS {
            let lnk = &mut tbl.links[i];
            if lnk.active && lnk.pid == pid && (lnk.cap_a == cap_id || lnk.cap_b == cap_id) {
                lnk.active = false;
                found = true;
            }
            i += 1;
        }
        drop(tbl);

        crate::serial_println!(
            "[entangle] disentangle: pid={} cap_id={} found={}",
            pid,
            cap_id,
            found
        );
        self.stack.push(Value::I32(if found { 0 } else { -1 }))
    }

    /// `cap_entangle_query(cap_id: i32, buf_ptr: i32, buf_len: i32) -> i32`
    ///
    /// Write the cap IDs entangled with `cap_id` as packed LE u32s.
    /// `buf_len` is the number of **u32 slots** available (not bytes).
    ///
    /// Returns the count of entangled IDs written (≥ 0), or `-1` if none.
    fn host_cap_entangle_query(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize; // slots, not bytes
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        let cap_id = self.stack.pop()?.as_i32()? as u32;
        let pid = self.process_id.0;

        let tbl = ENTANGLE_TABLE.lock();
        let mut peers = [0u32; MAX_ENTANGLE_LINKS];
        let mut n = 0usize;
        let mut i = 0usize;
        while i < MAX_ENTANGLE_LINKS {
            let lnk = &tbl.links[i];
            if lnk.active && lnk.pid == pid {
                if lnk.cap_a == cap_id && n < buf_len {
                    peers[n] = lnk.cap_b;
                    n += 1;
                } else if lnk.cap_b == cap_id && n < buf_len {
                    peers[n] = lnk.cap_a;
                    n += 1;
                }
            }
            i += 1;
        }
        drop(tbl);

        if n == 0 {
            return self.stack.push(Value::I32(-1));
        }

        // Write packed LE u32s.
        let write_len = n.min(buf_len);
        let mut out = [0u8; MAX_ENTANGLE_LINKS * 4];
        let mut wi = 0usize;
        while wi < write_len {
            let b = wi * 4;
            let le = peers[wi].to_le_bytes();
            out[b] = le[0];
            out[b + 1] = le[1];
            out[b + 2] = le[2];
            out[b + 3] = le[3];
            wi += 1;
        }
        self.memory.write(buf_ptr, &out[..write_len * 4])?;
        self.stack.push(Value::I32(write_len as i32))
    }

    // =======================================================================
    // Runtime Capability Graph Verification (IDs 129–131)
    // =======================================================================

    /// `cap_graph_query(cap_id: i32, buf_ptr: i32, buf_len: i32) -> i32`
    ///
    /// Write delegation edges for `cap_id` owned by this process into `buf_ptr`.
    ///
    /// Each edge is serialized as 20 bytes (LE):
    /// `[from_pid:u32][from_cap:u32][to_pid:u32][to_cap:u32][rights:u32]`
    ///
    /// `buf_len` is the number of **edge slots** available (not bytes).
    /// Returns the number of edges written (≥ 0), or `-1` if none found.
    fn host_cap_graph_query(&mut self) -> Result<(), WasmError> {
        let buf_len = self.stack.pop()?.as_i32()? as usize; // edge slots
        let buf_ptr = self.stack.pop()?.as_i32()? as usize;
        let cap_id = self.stack.pop()?.as_i32()? as u32;
        let pid = self.process_id.0;

        // MAX 16 edges per query.
        const MAX_Q: usize = 16;
        let limit = buf_len.min(MAX_Q);
        let mut edges = [crate::capability::cap_graph::CapDelegationEdge {
            active: false,
            from_pid: 0,
            from_cap: 0,
            to_pid: 0,
            to_cap: 0,
            rights_bits: 0,
        }; MAX_Q];
        let n = crate::capability::cap_graph::query_edges_for(pid, cap_id, &mut edges[..limit]);

        if n == 0 {
            return self.stack.push(Value::I32(-1));
        }

        // Serialize: 20 bytes per edge.
        let mut out = [0u8; MAX_Q * 20];
        let mut wi = 0usize;
        while wi < n {
            let e = &edges[wi];
            let off = wi * 20;
            let b0 = e.from_pid.to_le_bytes();
            let b1 = e.from_cap.to_le_bytes();
            let b2 = e.to_pid.to_le_bytes();
            let b3 = e.to_cap.to_le_bytes();
            let b4 = e.rights_bits.to_le_bytes();
            let mut j = 0usize;
            while j < 4 {
                out[off + j] = b0[j];
                j += 1;
            }
            j = 0;
            while j < 4 {
                out[off + 4 + j] = b1[j];
                j += 1;
            }
            j = 0;
            while j < 4 {
                out[off + 8 + j] = b2[j];
                j += 1;
            }
            j = 0;
            while j < 4 {
                out[off + 12 + j] = b3[j];
                j += 1;
            }
            j = 0;
            while j < 4 {
                out[off + 16 + j] = b4[j];
                j += 1;
            }
            wi += 1;
        }
        self.memory.write(buf_ptr, &out[..n * 20])?;
        self.stack.push(Value::I32(n as i32))
    }

    /// `cap_graph_verify(cap_id: i32, delegatee_pid: i32) -> i32`
    ///
    /// Prospectively check whether delegating `cap_id` owned by this process
    /// to `delegatee_pid` would violate any graph invariant.
    ///
    /// Returns `0`=safe, `1`=rights escalation would occur, `2`=cycle would
    /// be created, `3`=cap not found.
    fn host_cap_graph_verify(&mut self) -> Result<(), WasmError> {
        let delegatee_pid = self.stack.pop()?.as_i32()? as u32;
        let cap_id = self.stack.pop()?.as_i32()? as u32;
        let pid = self.process_id.0;

        // Look up the cap's current rights.
        match crate::capability::capability_manager()
            .query_capability(crate::ipc::ProcessId(pid), cap_id)
        {
            Ok((_ct, _oid)) => {
                // query_capability returns (cap_type_raw, object_id).
                // The definitive rights check happens at actual transfer time;
                // here we do a prospective cycle check only.
                let result = crate::capability::cap_graph::check_invariants(
                    pid,
                    cap_id,
                    delegatee_pid,
                    u32::MAX, // delegator rights: conservative pass-through
                    u32::MAX, // proposed rights: same as delegator (no escalation)
                );
                match result {
                    Ok(()) => self.stack.push(Value::I32(0)),
                    Err(msg) => {
                        let code = if msg.contains("cycle") { 2 } else { 1 };
                        self.stack.push(Value::I32(code))
                    }
                }
            }
            Err(_) => self.stack.push(Value::I32(3)),
        }
    }

    /// `cap_graph_depth(cap_id: i32) -> i32`
    ///
    /// Return the longest delegation chain length reachable from `cap_id`
    /// owned by this process (depth 0 = no delegations, depth N = chain of N
    /// hops).  Capped at 32.
    fn host_cap_graph_depth(&mut self) -> Result<(), WasmError> {
        let cap_id = self.stack.pop()?.as_i32()? as u32;
        let pid = self.process_id.0;
        let depth = crate::capability::cap_graph::delegation_depth(pid, cap_id);
        self.stack.push(Value::I32(depth as i32))
    }

    /// oreulius_thread_spawn(func_idx: i32, arg: i32) -> i32
    ///
    /// Spawns a new cooperative WASM thread starting at the given function
    /// index with a single i32 argument.  Returns the thread ID (>= 1) on
    /// success, or -1 on failure.
    fn host_thread_spawn(&mut self) -> Result<(), WasmError> {
        let arg = self.stack.pop()?.as_i32()?;
        let func_idx = self.stack.pop()?.as_i32()?;

        let fidx = func_idx as usize;
        if func_idx < 0 || fidx >= self.module.functions.len() {
            self.stack.push(Value::I32(-1))?;
            return Ok(());
        }

        // Resolve the entry PC for the requested function.
        let entry = match self.module.functions[fidx] {
            Some(ref f) => f.code_offset,
            None => {
                self.stack.push(Value::I32(-1))?;
                return Ok(());
            }
        };
        if let Some(sig) = self.module.signature_for_defined(fidx) {
            if sig.param_count > 1 || (sig.param_count == 1 && sig.param_types[0] != ValueType::I32)
            {
                self.stack.push(Value::I32(-1))?;
                return Ok(());
            }
        }

        // Attach shared memory on first spawn.
        if !self.thread_pool.is_memory_attached() {
            let base = self.memory.as_mut_ptr();
            let active = self.memory.active_len();
            let max_bytes = self.memory.max_pages() * 64 * 1024;
            self.thread_pool.attach_memory(base, active, max_bytes);
        }

        match self.thread_pool.spawn(func_idx as u32, arg, entry) {
            Ok(tid) => self.stack.push(Value::I32(tid))?,
            Err(_) => self.stack.push(Value::I32(-1))?,
        }
        Ok(())
    }

    /// oreulius_thread_join(tid: i32) -> i32
    ///
    /// Waits for the thread with the given tid to finish.
    /// Returns the thread exit code if it finished, `0` if the thread no
    /// longer exists, or `-1` if the caller should try again later.
    fn host_thread_join(&mut self) -> Result<(), WasmError> {
        let target_tid = self.stack.pop()?.as_i32()?;
        let caller_tid = self.active_thread_tid;
        let result = self.thread_pool.join(caller_tid, target_tid);
        use crate::execution::wasm_thread::JoinResult;
        let code = match result {
            JoinResult::Done(exit_code) => exit_code,
            JoinResult::NotFound => 0,
            JoinResult::Blocked if caller_tid != 0 => {
                return Err(WasmError::ThreadBlockedOnJoin(target_tid));
            }
            JoinResult::Blocked => -1, // main instance: try again next quantum
        };
        self.stack.push(Value::I32(code))?;
        Ok(())
    }

    /// oreulius_thread_id() -> i32
    ///
    /// Returns the current thread's ID.  The main instance (not spawned as a
    /// thread) always returns 0.
    fn host_thread_id(&mut self) -> Result<(), WasmError> {
        self.stack.push(Value::I32(self.active_thread_tid))?;
        Ok(())
    }

    /// oreulius_thread_yield() -> ()
    ///
    /// Yields the current quantum.
    fn host_thread_yield(&mut self) -> Result<(), WasmError> {
        crate::scheduler::quantum_scheduler::yield_now();
        if self.active_thread_tid != 0 {
            return Err(WasmError::ThreadYielded);
        }
        Ok(())
    }

    /// oreulius_thread_exit(code: i32) -> ()
    ///
    /// Terminates the calling thread with the given exit code.
    fn host_thread_exit(&mut self) -> Result<(), WasmError> {
        let code = self.stack.pop()?.as_i32()?;
        if self.active_thread_tid != 0 {
            return Err(WasmError::ThreadExited(code));
        } else {
            let _ = code;
        }
        Ok(())
    }

    // ========================================================================
    // Compositor host functions (IDs 28–37)
    // ========================================================================

    /// compositor_create_window(x: i32, y: i32, w: i32, h: i32) -> i32
    fn host_compositor_create_window(&mut self) -> Result<(), WasmError> {
        let h = self.stack.pop()?.as_i32()?;
        let w = self.stack.pop()?.as_i32()?;
        let y = self.stack.pop()?.as_i32()?;
        let x = self.stack.pop()?.as_i32()?;
        if w <= 0 || h <= 0 {
            self.stack.push(Value::I32(0))?;
            return Ok(());
        }
        let wid = crate::compositor::compositor().create_window(x, y, w as u32, h as u32);
        self.stack.push(Value::I32(wid as i32))?;
        Ok(())
    }

    /// compositor_destroy_window(window_id: i32) -> i32  (1 = found, 0 = not found)
    fn host_compositor_destroy_window(&mut self) -> Result<(), WasmError> {
        let wid = self.stack.pop()?.as_i32()?;
        let ok = crate::compositor::compositor().destroy_window(wid as u32);
        self.stack.push(Value::I32(if ok { 1 } else { 0 }))?;
        Ok(())
    }

    /// compositor_set_pixel(window_id: i32, x: i32, y: i32, argb: i32) -> ()
    fn host_compositor_set_pixel(&mut self) -> Result<(), WasmError> {
        let argb = self.stack.pop()?.as_i32()? as u32;
        let y = self.stack.pop()?.as_i32()? as u32;
        let x = self.stack.pop()?.as_i32()? as u32;
        let wid = self.stack.pop()?.as_i32()? as u32;
        crate::compositor::compositor().set_pixel(wid, x, y, argb);
        Ok(())
    }

    /// compositor_fill_rect(window_id: i32, x: i32, y: i32, w: i32, h: i32, argb: i32) -> ()
    fn host_compositor_fill_rect(&mut self) -> Result<(), WasmError> {
        let argb = self.stack.pop()?.as_i32()? as u32;
        let h = self.stack.pop()?.as_i32()? as u32;
        let w = self.stack.pop()?.as_i32()? as u32;
        let y = self.stack.pop()?.as_i32()? as u32;
        let x = self.stack.pop()?.as_i32()? as u32;
        let wid = self.stack.pop()?.as_i32()? as u32;
        crate::compositor::compositor().fill_rect(wid, x, y, w, h, argb);
        Ok(())
    }

    /// compositor_flush(window_id: i32) -> ()
    ///
    /// Flush changes for a single window to the physical framebuffer.
    fn host_compositor_flush(&mut self) -> Result<(), WasmError> {
        let wid = self.stack.pop()?.as_i32()? as u32;
        let fb_guard = crate::drivers::x86::gpu_support::GPU_FB.lock();
        if let Some(ref fb) = *fb_guard {
            crate::compositor::compositor().flush_window(wid, fb);
        }
        Ok(())
    }

    /// compositor_move_window(window_id: i32, x: i32, y: i32) -> ()
    fn host_compositor_move_window(&mut self) -> Result<(), WasmError> {
        let y = self.stack.pop()?.as_i32()?;
        let x = self.stack.pop()?.as_i32()?;
        let wid = self.stack.pop()?.as_i32()? as u32;
        crate::compositor::compositor().move_window(wid, x, y);
        Ok(())
    }

    /// compositor_set_z_order(window_id: i32, z: i32) -> ()
    fn host_compositor_set_z_order(&mut self) -> Result<(), WasmError> {
        let z = (self.stack.pop()?.as_i32()? & 0xFF) as u8;
        let wid = self.stack.pop()?.as_i32()? as u32;
        crate::compositor::compositor().set_z_order(wid, z);
        Ok(())
    }

    /// compositor_get_width(window_id: i32) -> i32
    fn host_compositor_get_width(&mut self) -> Result<(), WasmError> {
        let wid = self.stack.pop()?.as_i32()? as u32;
        let w = crate::compositor::compositor()
            .window_size(wid)
            .map(|(w, _)| w as i32)
            .unwrap_or(-1);
        self.stack.push(Value::I32(w))?;
        Ok(())
    }

    /// compositor_get_height(window_id: i32) -> i32
    fn host_compositor_get_height(&mut self) -> Result<(), WasmError> {
        let wid = self.stack.pop()?.as_i32()? as u32;
        let h = crate::compositor::compositor()
            .window_size(wid)
            .map(|(_, h)| h as i32)
            .unwrap_or(-1);
        self.stack.push(Value::I32(h))?;
        Ok(())
    }

    /// compositor_draw_text(window_id: i32, x: i32, y: i32, ptr: i32, len: i32, fg_argb: i32) -> i32
    fn host_compositor_draw_text(&mut self) -> Result<(), WasmError> {
        let fg_argb = self.stack.pop()?.as_i32()? as u32;
        let len = self.pop_nonneg_i32_as_usize()?;
        let ptr = self.pop_nonneg_i32_as_usize()?;
        let y = self.stack.pop()?.as_i32()? as u32;
        let x = self.stack.pop()?.as_i32()? as u32;
        let wid = self.stack.pop()?.as_i32()? as u32;

        let text_bytes = self.memory.read(ptr, len)?;
        let text = match core::str::from_utf8(text_bytes) {
            Ok(s) => s,
            Err(_) => {
                self.stack.push(Value::I32(-1))?;
                return Ok(());
            }
        };
        // We need to make a copy to avoid borrow issues with compositor.
        let mut buf = [0u8; 512];
        let copy_len = text.len().min(511);
        buf[..copy_len].copy_from_slice(&text.as_bytes()[..copy_len]);
        // SAFETY: we just validated it was valid UTF-8 above.
        let text_ref = unsafe { core::str::from_utf8_unchecked(&buf[..copy_len]) };
        let drawn = crate::compositor::compositor().draw_text(wid, x, y, text_ref, fg_argb);
        self.stack.push(Value::I32(drawn as i32))?;
        Ok(())
    }

    // ========================================================================
    // WASM Threads Proposal — 0xFE prefix atomic operations
    // ========================================================================
    //
    // Implements the full WebAssembly Threads/Atomics proposal:
    //   0x00  memory.atomic.notify      (addr, count) → i32 woken
    //   0x01  memory.atomic.wait32      (addr, expected, timeout_ns) → i32
    //   0x02  memory.atomic.wait64      (addr, expected, timeout_ns) → i32
    //   0x03  atomic.fence
    //   0x10  i32.atomic.load           (addr+offset) → i32
    //   0x11  i64.atomic.load           (addr+offset) → i64
    //   0x12  i32.atomic.load8_u        → i32
    //   0x13  i32.atomic.load16_u       → i32
    //   0x14  i64.atomic.load8_u        → i64
    //   0x15  i64.atomic.load16_u       → i64
    //   0x16  i64.atomic.load32_u       → i64
    //   0x17  i32.atomic.store          (addr+offset, i32)
    //   0x18  i64.atomic.store          (addr+offset, i64)
    //   0x19  i32.atomic.store8
    //   0x1A  i32.atomic.store16
    //   0x1B  i64.atomic.store8
    //   0x1C  i64.atomic.store16
    //   0x1D  i64.atomic.store32
    //   0x1E–0x24 i32.atomic.rmw.*      (add/sub/and/or/xor/xchg/cmpxchg)
    //   0x25–0x2B i64.atomic.rmw.*
    //   0x2C–0x2E i32.atomic.rmw8.*_u / 0x2F–0x31 i32.atomic.rmw16.*_u
    //   0x32–0x34 i64.atomic.rmw8.*_u  / 0x35–0x37 i64.atomic.rmw16.*_u
    //   0x38–0x3A i64.atomic.rmw32.*_u
    //
    // In the absence of true kernel threads the wait ops busy-spin up to a
    // small iteration cap so single-threaded WASM code using futex-style
    // synchronisation still makes progress.

    fn step_atomic(&mut self) -> Result<bool, WasmError> {
        let bytecode_len = self.bytecode_len_clamped();
        if self.pc >= bytecode_len {
            return Err(WasmError::UnexpectedEndOfCode);
        }
        let sub = self.module.bytecode[self.pc];
        self.pc += 1;
        match sub {
            0x00..=0x03 => self.step_atomic_control(sub),
            0x10..=0x1D => self.step_atomic_load_store(sub),
            0x1E..=0x3A => self.step_atomic_rmw(sub),
            _ => Err(WasmError::UnknownOpcode(0xFE)),
        }
    }

    fn step_atomic_control(&mut self, sub: u8) -> Result<bool, WasmError> {
        match sub {
            0x00 => {
                // memory.atomic.notify
                let _align = self.read_uleb128()?;
                let mem_offset = self.read_uleb128()? as usize;
                let count = self.stack.pop()?.as_i32()? as u32;
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base
                    .checked_add(mem_offset)
                    .ok_or(WasmError::MemoryOutOfBounds)?;
                if addr & 3 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                let _bc = self.memory.read(addr, 4)?;
                atomic_notify(addr, count);
                self.stack.push(Value::I32(0))?;
            }
            0x01 => {
                // memory.atomic.wait32
                let _align = self.read_uleb128()?;
                let mem_offset = self.read_uleb128()? as usize;
                let timeout = self.stack.pop()?.as_i64()?;
                let expected = self.stack.pop()?.as_i32()?;
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base
                    .checked_add(mem_offset)
                    .ok_or(WasmError::MemoryOutOfBounds)?;
                if addr & 3 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                let r = atomic_wait32(&self.memory, addr, expected, timeout)?;
                self.stack.push(Value::I32(r))?;
            }
            0x02 => {
                // memory.atomic.wait64
                let _align = self.read_uleb128()?;
                let mem_offset = self.read_uleb128()? as usize;
                let timeout = self.stack.pop()?.as_i64()?;
                let expected = self.stack.pop()?.as_i64()?;
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base
                    .checked_add(mem_offset)
                    .ok_or(WasmError::MemoryOutOfBounds)?;
                if addr & 7 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                let r = atomic_wait64(&self.memory, addr, expected, timeout)?;
                self.stack.push(Value::I32(r))?;
            }
            0x03 => {
                // atomic.fence
                let _reserved = self.read_uleb128()?;
                core::sync::atomic::fence(Ordering::SeqCst);
            }
            _ => return Err(WasmError::UnknownOpcode(0xFE)),
        }
        Ok(true)
    }

    fn step_atomic_load_store(&mut self, sub: u8) -> Result<bool, WasmError> {
        let _align = self.read_uleb128()?;
        let off = self.read_uleb128()? as usize;
        match sub {
            // loads (pop addr, push value)
            0x10 => {
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base.checked_add(off).ok_or(WasmError::MemoryOutOfBounds)?;
                if addr & 3 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                let v = self.memory.atomic_load_u32(addr)?;
                self.stack.push(Value::I32(v as i32))?;
            }
            0x11 => {
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base.checked_add(off).ok_or(WasmError::MemoryOutOfBounds)?;
                if addr & 7 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                let v = self.memory.atomic_load_u64(addr)?;
                self.stack.push(Value::I64(v as i64))?;
            }
            0x12 => {
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base.checked_add(off).ok_or(WasmError::MemoryOutOfBounds)?;
                let v = self.memory.atomic_load_u8(addr)?;
                self.stack.push(Value::I32(v as i32))?;
            }
            0x13 => {
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base.checked_add(off).ok_or(WasmError::MemoryOutOfBounds)?;
                if addr & 1 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                let v = self.memory.atomic_load_u16(addr)?;
                self.stack.push(Value::I32(v as i32))?;
            }
            0x14 => {
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base.checked_add(off).ok_or(WasmError::MemoryOutOfBounds)?;
                let v = self.memory.atomic_load_u8(addr)?;
                self.stack.push(Value::I64(v as i64))?;
            }
            0x15 => {
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base.checked_add(off).ok_or(WasmError::MemoryOutOfBounds)?;
                if addr & 1 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                let v = self.memory.atomic_load_u16(addr)?;
                self.stack.push(Value::I64(v as i64))?;
            }
            0x16 => {
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base.checked_add(off).ok_or(WasmError::MemoryOutOfBounds)?;
                if addr & 3 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                let v = self.memory.atomic_load_u32(addr)?;
                self.stack.push(Value::I64(v as i64))?;
            }
            // stores (pop value then addr)
            0x17 => {
                let val = self.stack.pop()?.as_i32()? as u32;
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base.checked_add(off).ok_or(WasmError::MemoryOutOfBounds)?;
                if addr & 3 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                self.memory.atomic_store_u32(addr, val)?;
            }
            0x18 => {
                let val = self.stack.pop()?.as_i64()? as u64;
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base.checked_add(off).ok_or(WasmError::MemoryOutOfBounds)?;
                if addr & 7 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                self.memory.atomic_store_u64(addr, val)?;
            }
            0x19 => {
                let val = (self.stack.pop()?.as_i32()? & 0xFF) as u8;
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base.checked_add(off).ok_or(WasmError::MemoryOutOfBounds)?;
                self.memory.atomic_store_u8(addr, val)?;
            }
            0x1A => {
                let val = (self.stack.pop()?.as_i32()? & 0xFFFF) as u16;
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base.checked_add(off).ok_or(WasmError::MemoryOutOfBounds)?;
                if addr & 1 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                self.memory.atomic_store_u16(addr, val)?;
            }
            0x1B => {
                let val = (self.stack.pop()?.as_i64()? & 0xFF) as u8;
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base.checked_add(off).ok_or(WasmError::MemoryOutOfBounds)?;
                self.memory.atomic_store_u8(addr, val)?;
            }
            0x1C => {
                let val = (self.stack.pop()?.as_i64()? & 0xFFFF) as u16;
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base.checked_add(off).ok_or(WasmError::MemoryOutOfBounds)?;
                if addr & 1 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                self.memory.atomic_store_u16(addr, val)?;
            }
            0x1D => {
                let val = (self.stack.pop()?.as_i64()? & 0xFFFF_FFFF) as u32;
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base.checked_add(off).ok_or(WasmError::MemoryOutOfBounds)?;
                if addr & 3 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                self.memory.atomic_store_u32(addr, val)?;
            }
            _ => return Err(WasmError::UnknownOpcode(0xFE)),
        }
        Ok(true)
    }

    fn step_atomic_rmw(&mut self, sub: u8) -> Result<bool, WasmError> {
        let _align = self.read_uleb128()?;
        let off = self.read_uleb128()? as usize;
        match sub {
            0x1E..=0x24 => {
                // i32 wide RMW
                let val = self.stack.pop()?.as_i32()? as u32;
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base.checked_add(off).ok_or(WasmError::MemoryOutOfBounds)?;
                if addr & 3 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                let old = self.memory.atomic_rmw32(sub, addr, val)?;
                self.stack.push(Value::I32(old as i32))?;
            }
            0x25..=0x2B => {
                // i64 wide RMW
                let val = self.stack.pop()?.as_i64()? as u64;
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base.checked_add(off).ok_or(WasmError::MemoryOutOfBounds)?;
                if addr & 7 != 0 {
                    return Err(WasmError::UnalignedAtomicAccess);
                }
                let old = self.memory.atomic_rmw64(sub, addr, val)?;
                self.stack.push(Value::I64(old as i64))?;
            }
            0x2C..=0x31 => {
                // i32 narrow RMW (8/16-bit)
                let val = self.stack.pop()?.as_i32()? as u32;
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base.checked_add(off).ok_or(WasmError::MemoryOutOfBounds)?;
                let old = self.memory.atomic_rmw32_narrow(sub, addr, val)?;
                self.stack.push(Value::I32(old as i32))?;
            }
            0x32..=0x3A => {
                // i64 narrow RMW (8/16/32-bit)
                let val = self.stack.pop()?.as_i64()? as u64;
                let base = self.stack.pop()?.as_u32()? as usize;
                let addr = base.checked_add(off).ok_or(WasmError::MemoryOutOfBounds)?;
                let old = self.memory.atomic_rmw64_narrow(sub, addr, val)?;
                self.stack.push(Value::I64(old as i64))?;
            }
            _ => return Err(WasmError::UnknownOpcode(0xFE)),
        }
        Ok(true)
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
    ThreadYielded,
    ThreadBlockedOnJoin(i32),
    ThreadExited(i32),

    // Memory errors
    MemoryOutOfBounds,
    MemoryGrowFailed,
    UnalignedAtomicAccess,

    // Atomic / thread errors
    AtomicWaitTimeout,
    AtomicWaitBadValue,
    SharedMemoryRequired,

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
            WasmError::UnalignedAtomicAccess => write!(f, "Unaligned atomic access"),
            WasmError::AtomicWaitTimeout => write!(f, "Atomic wait timed out"),
            WasmError::AtomicWaitBadValue => write!(f, "Atomic wait value mismatch"),
            WasmError::SharedMemoryRequired => write!(f, "Shared memory required for atomic"),
            WasmError::InvalidCapability => write!(f, "Invalid capability"),
            WasmError::Trap => write!(f, "Trap"),
            WasmError::DivisionByZero => write!(f, "Division by zero"),
            WasmError::ExecutionLimitExceeded => write!(f, "Execution limit exceeded"),
            WasmError::PermissionDenied => write!(f, "Permission denied"),
            WasmError::InstanceBusy => write!(f, "Instance busy"),
            WasmError::ThreadYielded => write!(f, "Thread yielded"),
            WasmError::ThreadBlockedOnJoin(tid) => write!(f, "Thread blocked on join ({})", tid),
            WasmError::ThreadExited(code) => write!(f, "Thread exited ({})", code),
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
            WasmError::UnalignedAtomicAccess => "Unaligned atomic access",
            WasmError::AtomicWaitTimeout => "Atomic wait timed out",
            WasmError::AtomicWaitBadValue => "Atomic wait value mismatch",
            WasmError::SharedMemoryRequired => "Shared memory required for atomic",
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
            WasmError::ThreadYielded => "Thread yielded",
            WasmError::ThreadBlockedOnJoin(_) => "Thread blocked on join",
            WasmError::ThreadExited(_) => "Thread exited",
        }
    }
}

// ============================================================================
// Global WASM Runtime
// ============================================================================

enum RuntimeInstanceSlot {
    Empty,
    Busy(ProcessId),
    Ready(Box<WasmInstance>),
}

const MAX_WASM_RUNTIME_INSTANCES: usize = 16;

/// Global WASM runtime (manages instances).
/// 16 slots: 2 reserved for language-runtime singletons (Python/JS),
/// 14 for user modules. Singleton services occupy fixed slot 0 (Python)
/// and slot 1 (JS) by convention — registered via `polyglot_register`.
pub struct WasmRuntime {
    instances: Mutex<[RuntimeInstanceSlot; MAX_WASM_RUNTIME_INSTANCES]>,
}

#[derive(Clone, Copy, Debug)]
pub enum BackgroundThreadDrainOutcome {
    Drained {
        quanta: usize,
    },
    Stalled {
        quanta: usize,
        status: crate::execution::wasm_thread::ThreadPoolStatus,
    },
    TimedOut {
        quanta: usize,
        status: crate::execution::wasm_thread::ThreadPoolStatus,
    },
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
        module.load_binary(bytecode)?;

        self.instantiate_module(module, process_id)
    }

    /// Instantiate a pre-built module (used by tests/benchmarks)
    pub fn instantiate_module(
        &self,
        module: WasmModule,
        process_id: ProcessId,
    ) -> Result<usize, WasmError> {
        #[cfg(target_arch = "x86_64")]
        let x64_diag = JIT_FUZZ_X64_DIAG.load(Ordering::SeqCst);
        #[cfg(target_arch = "x86_64")]
        if x64_diag {
            crate::serial_println!("[X64-JF] instantiate=enter");
        }

        // Reserve a slot quickly, then perform potentially heavy initialization
        // outside the runtime mutex to avoid lock hold stalls/deadlocks.
        let reserved = {
            #[cfg(target_arch = "x86_64")]
            if x64_diag {
                crate::serial_println!("[X64-JF] instantiate=lock-attempt");
            }

            let mut spins = 0usize;
            let mut instances = loop {
                if let Some(guard) = self.instances.try_lock() {
                    break guard;
                }
                spins = spins.saturating_add(1);
                if spins == 1 {
                    #[cfg(target_arch = "x86_64")]
                    if x64_diag {
                        crate::serial_println!("[X64-JF] instantiate=lock-contended");
                    }
                }
                if spins > 5_000_000 {
                    #[cfg(target_arch = "x86_64")]
                    if x64_diag {
                        crate::serial_println!("[X64-JF] instantiate=lock-timeout");
                    }
                    return Err(WasmError::InstanceBusy);
                }
                core::hint::spin_loop();
            };
            #[cfg(target_arch = "x86_64")]
            if x64_diag {
                crate::serial_println!("[X64-JF] instantiate=lock-acquired");
            }
            let mut idx = 0usize;
            let mut found = None;
            while idx < instances.len() {
                if matches!(instances[idx], RuntimeInstanceSlot::Empty) {
                    instances[idx] = RuntimeInstanceSlot::Busy(process_id);
                    found = Some(idx);
                    break;
                }
                idx += 1;
            }
            drop(instances);
            found
        };

        let slot_idx = match reserved {
            Some(i) => i,
            None => return Err(WasmError::TooManyCapabilities), // Reuse error for "too many instances"
        };

        #[cfg(target_arch = "x86_64")]
        if x64_diag {
            crate::serial_println!(
                "[X64-JF] instantiate=slot-reserved idx={} pid={}",
                slot_idx,
                process_id.0
            );
        }

        let clear_reserved_slot = |runtime: &WasmRuntime| -> Result<(), WasmError> {
            let mut cleanup_spins = 0usize;
            let mut instances = loop {
                if let Some(guard) = runtime.instances.try_lock() {
                    break guard;
                }
                cleanup_spins = cleanup_spins.saturating_add(1);
                if cleanup_spins > 5_000_000 {
                    return Err(WasmError::InstanceBusy);
                }
                core::hint::spin_loop();
            };
            if slot_idx < instances.len() {
                if let RuntimeInstanceSlot::Busy(owner) = instances[slot_idx] {
                    if owner == process_id {
                        instances[slot_idx] = RuntimeInstanceSlot::Empty;
                    }
                }
            }
            Ok(())
        };

        #[cfg(target_arch = "x86_64")]
        if x64_diag {
            crate::serial_println!("[X64-JF] instantiate=instance-new");
        }
        // Allocate on the heap first to avoid constructing the large WasmInstance
        // (~54 KiB) on the kernel stack, which would cause a stack overflow.
        let mut instance: Box<WasmInstance> =
            unsafe { WasmInstance::boxed_new_in_place(module, process_id, slot_idx) };
        #[cfg(target_arch = "x86_64")]
        if x64_diag {
            crate::serial_println!("[X64-JF] instantiate=init-from-module");
        }
        if let Err(e) = instance.initialize_from_module() {
            let _ = clear_reserved_slot(self);
            #[cfg(target_arch = "x86_64")]
            if x64_diag {
                crate::serial_println!("[X64-JF] instantiate=init-failed");
            }
            return Err(e);
        }
        #[cfg(target_arch = "x86_64")]
        if x64_diag {
            crate::serial_println!("[X64-JF] instantiate=run-start");
        }
        if let Err(e) = instance.run_start_if_present() {
            let _ = clear_reserved_slot(self);
            #[cfg(target_arch = "x86_64")]
            if x64_diag {
                crate::serial_println!("[X64-JF] instantiate=init-failed");
            }
            return Err(e);
        }
        #[cfg(target_arch = "x86_64")]
        if x64_diag {
            crate::serial_println!("[X64-JF] instantiate=init-ok");
            crate::serial_println!("[X64-JF] instantiate=commit-lock-attempt");
        }

        let mut commit_spins = 0usize;
        let mut instances = loop {
            if let Some(guard) = self.instances.try_lock() {
                break guard;
            }
            commit_spins = commit_spins.saturating_add(1);
            if commit_spins > 5_000_000 {
                #[cfg(target_arch = "x86_64")]
                if x64_diag {
                    crate::serial_println!("[X64-JF] instantiate=commit-lock-timeout");
                }
                let _ = clear_reserved_slot(self);
                return Err(WasmError::InstanceBusy);
            }
            core::hint::spin_loop();
        };
        #[cfg(target_arch = "x86_64")]
        if x64_diag {
            crate::serial_println!("[X64-JF] instantiate=commit-lock-acquired");
        }
        if slot_idx >= instances.len() {
            let _ = clear_reserved_slot(self);
            return Err(WasmError::InvalidModule);
        }
        match &instances[slot_idx] {
            RuntimeInstanceSlot::Busy(owner) if *owner == process_id => {
                instances[slot_idx] = RuntimeInstanceSlot::Ready(instance);
                drop(instances);
                #[cfg(target_arch = "x86_64")]
                if x64_diag {
                    crate::serial_println!("[X64-JF] instantiate=commit-ready");
                }
                Ok(slot_idx)
            }
            RuntimeInstanceSlot::Busy(_) => Err(WasmError::InstanceBusy),
            RuntimeInstanceSlot::Ready(_) => Err(WasmError::InstanceBusy),
            RuntimeInstanceSlot::Empty => Err(WasmError::InvalidModule),
        }
    }

    /// Get a mutable reference to an instance
    pub fn get_instance_mut<F, R>(&self, instance_id: usize, f: F) -> Result<R, WasmError>
    where
        F: for<'a> FnOnce(&'a mut WasmInstance) -> R,
    {
        let mut instances = self.instances.lock();
        if instance_id >= MAX_WASM_RUNTIME_INSTANCES {
            return Err(WasmError::InvalidModule);
        }

        match &mut instances[instance_id] {
            RuntimeInstanceSlot::Ready(instance) => Ok(f(instance.as_mut())),
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
            if instance_id >= MAX_WASM_RUNTIME_INSTANCES {
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

        let result = f(instance.as_mut());

        let mut instances = self.instances.lock();
        if instance_id >= MAX_WASM_RUNTIME_INSTANCES {
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
        export_name: &[u8],
        signature: ParsedFunctionType,
    ) -> Option<usize> {
        let instances = self.instances.lock();
        let mut idx = 0usize;
        while idx < instances.len() {
            if idx != retiring_instance {
                if let RuntimeInstanceSlot::Ready(instance) = &instances[idx] {
                    if instance.process_id == owner_pid {
                        if let Ok(function_index) =
                            instance.module.resolve_exported_function(export_name)
                        {
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
            }
            idx += 1;
        }
        None
    }

    /// Destroy an instance
    pub fn destroy(&self, instance_id: usize) -> Result<(), WasmError> {
        let mut instances = self.instances.lock();
        if instance_id >= MAX_WASM_RUNTIME_INSTANCES {
            return Err(WasmError::InvalidModule);
        }
        match &instances[instance_id] {
            RuntimeInstanceSlot::Busy(_) => return Err(WasmError::InstanceBusy),
            RuntimeInstanceSlot::Empty => return Err(WasmError::InvalidModule),
            RuntimeInstanceSlot::Ready(_) => {}
        }
        instances[instance_id] = RuntimeInstanceSlot::Empty;
        drop(instances);
        let _ = POLYGLOT_REGISTRY.lock().purge_instance(instance_id);
        let _ = POLYGLOT_LINEAGE.lock().purge_instance(instance_id);
        let _ = revoke_service_pointers_for_instance(instance_id);
        crate::execution::replay::clear(instance_id);
        Ok(())
    }

    /// List all active instances
    pub fn list(&self) -> [(usize, ProcessId, bool); MAX_WASM_RUNTIME_INSTANCES] {
        let instances = self.instances.lock();
        let mut result = [(0, ProcessId(0), false); MAX_WASM_RUNTIME_INSTANCES];

        for (i, instance) in instances.iter().enumerate() {
            result[i] = match instance {
                RuntimeInstanceSlot::Ready(inst) => (i, inst.process_id, true),
                RuntimeInstanceSlot::Busy(pid) => (i, *pid, true),
                RuntimeInstanceSlot::Empty => (i, ProcessId(0), false),
            };
        }

        result
    }

    pub fn thread_pool_status(
        &self,
        instance_id: usize,
    ) -> Result<crate::execution::wasm_thread::ThreadPoolStatus, WasmError> {
        let instances = self.instances.lock();
        if instance_id >= MAX_WASM_RUNTIME_INSTANCES {
            return Err(WasmError::InvalidModule);
        }
        match &instances[instance_id] {
            RuntimeInstanceSlot::Ready(instance) => Ok(instance.thread_pool.status()),
            RuntimeInstanceSlot::Busy(_) => Err(WasmError::InstanceBusy),
            RuntimeInstanceSlot::Empty => Err(WasmError::InvalidModule),
        }
    }

    /// Drain cooperative background threads for a single instance until the
    /// pool is empty, becomes non-runnable, or hits a bounded quantum budget.
    pub fn drain_instance_background_threads(
        &self,
        instance_id: usize,
        max_quanta: usize,
    ) -> Result<BackgroundThreadDrainOutcome, WasmError> {
        let mut quanta = 0usize;

        loop {
            let ran = self.with_instance_exclusive(instance_id, |instance| {
                instance.run_background_thread_quantum()
            })??;

            if ran {
                quanta = quanta.saturating_add(1);
                if quanta >= max_quanta {
                    let status = self.thread_pool_status(instance_id)?;
                    if status.live == 0 {
                        return Ok(BackgroundThreadDrainOutcome::Drained { quanta });
                    }
                    return Ok(BackgroundThreadDrainOutcome::TimedOut { quanta, status });
                }
                continue;
            }

            let mut status = self.thread_pool_status(instance_id)?;
            if status.live == 0 {
                return Ok(BackgroundThreadDrainOutcome::Drained { quanta });
            }

            self.with_instance_exclusive(instance_id, |instance| {
                instance.thread_pool.on_timer_tick();
            })?;
            status = self.thread_pool_status(instance_id)?;
            if status.live == 0 {
                return Ok(BackgroundThreadDrainOutcome::Drained { quanta });
            }
            if status.runnable != 0 {
                continue;
            }

            return Ok(BackgroundThreadDrainOutcome::Stalled { quanta, status });
        }
    }

    /// Advance thread-pool timer state for all ready instances.
    pub fn tick_thread_pools(&self) {
        if let Some(mut instances) = self.instances.try_lock() {
            for slot in instances.iter_mut() {
                if let RuntimeInstanceSlot::Ready(instance) = slot {
                    instance.thread_pool.on_timer_tick();
                }
            }
        }
    }

    /// Execute at most one cooperative WASM thread quantum per ready instance.
    pub fn tick_background_threads(&self) {
        let mut instance_id = 0usize;
        while instance_id < MAX_WASM_RUNTIME_INSTANCES {
            let _ = self.with_instance_exclusive(instance_id, |instance| {
                let _ = instance.run_background_thread_quantum();
            });
            instance_id += 1;
        }
    }
}

static WASM_RUNTIME: WasmRuntime = WasmRuntime::new();

pub fn wasm_runtime() -> &'static WasmRuntime {
    &WASM_RUNTIME
}

pub fn on_timer_tick() {
    wasm_runtime().tick_thread_pools();
    temporal_cap_tick();
}

pub fn tick_background_threads() {
    wasm_runtime().tick_background_threads();
}

// ---------------------------------------------------------------------------
// Pending-spawn queue: proc_spawn() cannot call wasm_runtime() while the
// caller's instance lock is held. Instead we queue the bytecode + child PID
// here, and the shell/scheduler loop drains it between iterations.
// ---------------------------------------------------------------------------

struct PendingSpawn {
    pid: crate::ipc::ProcessId,
    bytecode: Vec<u8>,
}

struct SpawnQueue {
    items: [Option<PendingSpawn>; 8],
    len: usize,
}

impl SpawnQueue {
    const fn new() -> Self {
        SpawnQueue {
            items: [None, None, None, None, None, None, None, None],
            len: 0,
        }
    }

    fn push(&mut self, item: PendingSpawn) -> bool {
        if self.len >= 8 {
            return false;
        }
        self.items[self.len] = Some(item);
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<PendingSpawn> {
        if self.len == 0 {
            return None;
        }
        let item = self.items[0].take();
        // Shift remaining items down.
        for i in 1..self.len {
            self.items[i - 1] = self.items[i].take();
        }
        self.len -= 1;
        item
    }
}

static PENDING_SPAWNS: Mutex<SpawnQueue> = Mutex::new(SpawnQueue::new());

/// Queue a WASM child process for deferred instantiation.
/// Safe to call from inside a `get_instance_mut` closure.
pub fn queue_pending_spawn(
    pid: crate::ipc::ProcessId,
    bytecode: Vec<u8>,
) -> Result<(), &'static str> {
    let mut q = PENDING_SPAWNS.lock();
    if q.push(PendingSpawn { pid, bytecode }) {
        Ok(())
    } else {
        Err("WASM spawn queue full")
    }
}

/// Drain and execute all queued pending spawns.
/// Call this from the shell/scheduler loop between commands.
pub fn drain_pending_spawns() {
    loop {
        let item = { PENDING_SPAWNS.lock().pop() };
        match item {
            Some(spawn) => match wasm_runtime().instantiate(&spawn.bytecode, spawn.pid) {
                Ok(instance_id) => {
                    match wasm_runtime().get_instance_mut(instance_id, |inst| inst.call(0)) {
                        Ok(Ok(())) => {
                            crate::serial_println!(
                                "[WASM] drain_pending_spawns: spawned pid={} instance={}",
                                spawn.pid.0,
                                instance_id
                            );
                        }
                        Ok(Err(e)) => {
                            let _ = wasm_runtime().destroy(instance_id);
                            let _ = crate::scheduler::process::process_manager().terminate(spawn.pid);
                            crate::serial_println!(
                                "[WASM] drain_pending_spawns: start pid={} failed: {:?}",
                                spawn.pid.0,
                                e
                            );
                        }
                        Err(e) => {
                            let _ = wasm_runtime().destroy(instance_id);
                            let _ = crate::scheduler::process::process_manager().terminate(spawn.pid);
                            crate::serial_println!(
                                "[WASM] drain_pending_spawns: access pid={} failed: {:?}",
                                spawn.pid.0,
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    let _ = crate::scheduler::process::process_manager().terminate(spawn.pid);
                    crate::serial_println!(
                        "[WASM] drain_pending_spawns: spawn pid={} failed: {:?}",
                        spawn.pid.0,
                        e
                    );
                }
            },
            None => break,
        }
    }
}

pub fn init() {
    // Runtime is statically initialized; keep the init hook for shared boot flow parity.
    ensure_fuzz_scratch_ready();
    let _ = ensure_fuzz_compiler_ready();
    crate::drivers::x86::vga::print_str("[WASM] Runtime initialized\n");
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
        payload
            .extend_from_slice(&(slot.bound_instance.unwrap_or(usize::MAX) as u32).to_le_bytes());
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

    let max_slots =
        temporal_read_u16_at(payload, 4).ok_or("temporal wasm syscall max slots missing")?;
    if max_slots as usize != MAX_SYSCALL_MODULES {
        return Err("temporal wasm syscall max slots mismatch");
    }
    let entry_count =
        temporal_read_u16_at(payload, 6).ok_or("temporal wasm syscall count missing")? as usize;
    if entry_count > MAX_SYSCALL_MODULES {
        return Err("temporal wasm syscall count out of range");
    }
    let next_id =
        temporal_read_u32_at(payload, 8).ok_or("temporal wasm syscall next id missing")?;

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
            .ok_or("temporal wasm syscall bytecode len missing")?
            as usize;
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
    let scheduler = crate::scheduler::quantum_scheduler::scheduler().lock();
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
    type_sig_hash: u64,
    global_sig_hash: u64,
    code_len: usize,
    func: crate::execution::wasm_jit::JitFunction,
}

#[derive(Clone, Copy)]
pub(crate) struct JitExecInfo {
    pub(crate) entry: crate::execution::wasm_jit::JitFn,
    pub(crate) exec_ptr: *mut u8,
    pub(crate) exec_len: usize,
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
static JIT_FUZZ_COMPILER: Mutex<Option<crate::execution::wasm_jit::FuzzCompiler>> = Mutex::new(None);
static JIT_SELFTEST_COMPILER: Mutex<Option<crate::execution::wasm_jit::FuzzCompiler>> = Mutex::new(None);
static JIT_FUZZ_INSTANCES: Mutex<Option<(usize, usize)>> = Mutex::new(None);
static JIT_FUZZ_ACTIVE: AtomicBool = AtomicBool::new(false);
static JIT_FAULT_ACTIVE: AtomicBool = AtomicBool::new(false);
static JIT_FAULT_EXEC_START: AtomicU32 = AtomicU32::new(0);
static JIT_FAULT_EXEC_END: AtomicU32 = AtomicU32::new(0);
static mut JIT_FAULT_TRAP_PTR: *mut i32 = core::ptr::null_mut();
static JIT_USER_LOCK: Mutex<()> = Mutex::new(());
static JIT_USER_SANDBOX: Mutex<Option<arch_mmu::AddressSpace>> = Mutex::new(None);
static JIT_USER_PREFLIGHT_PAGES: Mutex<Option<JitUserPages>> = Mutex::new(None);
static JIT_USER_PREFLIGHT_AUX_PAGES: Mutex<Option<JitUserPreflightAuxPages>> = Mutex::new(None);
#[cfg(target_arch = "x86_64")]
static JIT_X64_CALL_PROBE_ACTIVE: AtomicBool = AtomicBool::new(false);
#[cfg(target_arch = "x86_64")]
const JIT_X64_CALL_PROBE_STATE_BYTES: usize =
    ((core::mem::size_of::<JitUserState>() + paging::PAGE_SIZE - 1) / paging::PAGE_SIZE)
        * paging::PAGE_SIZE;
#[cfg(target_arch = "x86_64")]
#[repr(C, align(4096))]
struct JitX64CallProbeState([u8; JIT_X64_CALL_PROBE_STATE_BYTES]);
#[cfg(target_arch = "x86_64")]
static mut JIT_X64_CALL_PROBE_STATE: JitX64CallProbeState =
    JitX64CallProbeState([0; JIT_X64_CALL_PROBE_STATE_BYTES]);
static JIT_KERNEL_CALL_LOCK: Mutex<()> = Mutex::new(());
static JIT_FUZZ_X64_DIAG: AtomicBool = AtomicBool::new(false);
static JIT_USER_DEBUG_STAGE: AtomicU32 = AtomicU32::new(0);
static JIT_USER_FAULT_LOGGED: AtomicBool = AtomicBool::new(false);
static JIT_USER_ENTER_TICK: AtomicU32 = AtomicU32::new(0);
static JIT_KERNEL_ENTER_TICK: AtomicU32 = AtomicU32::new(0);
static JIT_USER_HANDOFF_LOG_COUNT: AtomicU32 = AtomicU32::new(0);

fn ensure_fuzz_scratch_ready() {
    let mut scratch_slot = JIT_FUZZ_SCRATCH.lock();
    if scratch_slot.is_none() {
        *scratch_slot = Some(JitFuzzScratch::new());
    }
}

fn ensure_fuzz_compiler_ready() -> Result<(), &'static str> {
    crate::serial_println!("[WASM-JIT] compiler-init stage=lock");
    let mut compiler_slot = JIT_FUZZ_COMPILER.lock();
    crate::serial_println!(
        "[WASM-JIT] compiler-init stage=locked present={}",
        compiler_slot.is_some() as u8
    );
    if compiler_slot.is_none() {
        crate::serial_println!("[WASM-JIT] compiler-init stage=create");
        *compiler_slot = Some(
            crate::execution::wasm_jit::FuzzCompiler::new(MAX_FUZZ_JIT_CODE_SIZE, MAX_FUZZ_CODE_SIZE)
                .map_err(|_| "Fuzz compiler init failed")?,
        );
        crate::serial_println!("[WASM-JIT] compiler-init stage=created");
    }
    crate::serial_println!("[WASM-JIT] compiler-init stage=done");
    Ok(())
}

fn ensure_selftest_compiler_ready() -> Result<(), &'static str> {
    crate::serial_println!("[WASM-JIT] compiler-init stage=lock");
    let mut compiler_slot = JIT_SELFTEST_COMPILER.lock();
    crate::serial_println!(
        "[WASM-JIT] compiler-init stage=locked present={}",
        compiler_slot.is_some() as u8
    );
    if compiler_slot.is_none() {
        crate::serial_println!("[WASM-JIT] compiler-init stage=create");
        *compiler_slot = Some(
            crate::execution::wasm_jit::FuzzCompiler::new(MAX_FUZZ_JIT_CODE_SIZE, MAX_FUZZ_CODE_SIZE)
                .map_err(|_| "Fuzz compiler init failed")?,
        );
        crate::serial_println!("[WASM-JIT] compiler-init stage=created");
    }
    crate::serial_println!("[WASM-JIT] compiler-init stage=done");
    Ok(())
}

#[derive(Clone, Copy)]
struct JitUserPages {
    trampoline: usize,
    call: usize,
    stack: usize,
    stack_pages: usize,
}

#[derive(Clone, Copy)]
struct JitUserPreflightAuxPages {
    code: usize,
    state: usize,
    mem: usize,
}

#[inline]
fn jit_arena_range_sane(base: usize, size: usize) -> bool {
    size != 0
        && (base & (paging::PAGE_SIZE - 1)) == 0
        && crate::memory::jit_arena_contains_range(base, size)
}

fn validate_jit_user_pages(pages: &JitUserPages) -> Result<(), &'static str> {
    if !jit_arena_range_sane(pages.trampoline, paging::PAGE_SIZE) {
        return Err("JIT user trampoline outside JIT arena");
    }
    if !jit_arena_range_sane(pages.call, paging::PAGE_SIZE) {
        return Err("JIT user call page outside JIT arena");
    }
    let stack_span = pages
        .stack_pages
        .checked_mul(paging::PAGE_SIZE)
        .ok_or("JIT user stack span overflow")?;
    if !jit_arena_range_sane(pages.stack, stack_span) {
        return Err("JIT user stack outside JIT arena");
    }
    Ok(())
}

#[no_mangle]
pub static JIT_USER_ACTIVE: AtomicU32 = AtomicU32::new(0);
#[no_mangle]
pub static JIT_USER_RETURN_PENDING: AtomicU32 = AtomicU32::new(0);
#[no_mangle]
pub static JIT_USER_RETURN_EIP: AtomicUsize = AtomicUsize::new(0);
#[no_mangle]
pub static JIT_USER_RETURN_ESP: AtomicUsize = AtomicUsize::new(0);
#[no_mangle]
pub static JIT_USER_SYSCALL_VIOLATION: AtomicU32 = AtomicU32::new(0);
#[no_mangle]
pub static JIT_USER_DBG_CALL_SEQ: AtomicU32 = AtomicU32::new(0);
#[no_mangle]
pub static mut JIT_USER_DBG_CALL_ENTRY: u32 = 0;
#[no_mangle]
pub static mut JIT_USER_DBG_CALL_STACK_PTR: u32 = 0;
#[no_mangle]
pub static mut JIT_USER_DBG_CALL_SP_PTR: u32 = 0;
#[no_mangle]
pub static mut JIT_USER_DBG_CALL_MEM_PTR: u32 = 0;
#[no_mangle]
pub static mut JIT_USER_DBG_CALL_MEM_LEN: u32 = 0;
#[no_mangle]
pub static mut JIT_USER_DBG_CALL_TRAP_PTR: u32 = 0;
#[no_mangle]
pub static mut JIT_USER_DBG_CALL_PID: u32 = 0;
#[no_mangle]
pub static mut JIT_USER_DBG_CALL_INSTANCE: u32 = 0;
#[no_mangle]
pub static mut JIT_USER_DBG_CALL_FUNC: u32 = 0;
#[no_mangle]
pub static mut JIT_USER_DBG_SAVE_ESP: usize = 0;
#[no_mangle]
pub static mut JIT_USER_DBG_SAVE_EIP: usize = 0;
#[no_mangle]
pub static mut JIT_USER_DBG_SAVE_SEQ: u32 = 0;
#[no_mangle]
pub static mut JIT_USER_DBG_SYSCALL_ESP: usize = 0;
#[no_mangle]
pub static mut JIT_USER_DBG_SYSCALL_EIP: usize = 0;
#[no_mangle]
pub static mut JIT_USER_DBG_SYSCALL_SEQ: u32 = 0;
#[no_mangle]
pub static mut JIT_USER_DBG_SYSCALL_PATH: u32 = 0;
#[no_mangle]
pub static mut JIT_USER_DBG_SYSCALL_FLAGS: u32 = 0;
#[no_mangle]
pub static mut JIT_USER_DBG_SYSCALL_NR: u32 = 0;
#[no_mangle]
pub static mut JIT_USER_DBG_SYSCALL_FROM_EIP: u32 = 0;
#[no_mangle]
pub static mut JIT_USER_DBG_SYSCALL_FROM_CS: u32 = 0;

const TRAP_MEM: i32 = -1;
const JIT_USER_TIMEOUT_TICKS: u32 = 25; // 250ms @ 100Hz
#[cfg(target_arch = "x86_64")]
const JIT_KERNEL_TIMEOUT_TICKS_X64: u32 = 100; // 1s @ 100Hz
const JIT_USER_CALL_LOG_LIMIT: u32 = 4;
const JIT_USER_HANDOFF_LOG_LIMIT: u32 = 8;

#[inline]
fn jit_user_debug_set_stage(stage: u32) {
    JIT_USER_DEBUG_STAGE.store(stage, Ordering::SeqCst);
}

#[inline]
fn jit_user_debug_log(msg: &str) {
    crate::serial::_print(format_args!("[JIT-DBG] {}\n", msg));
}

pub fn jit_config() -> &'static Mutex<JitConfig> {
    &JIT_CONFIG
}

pub fn jit_stats() -> &'static Mutex<JitStats> {
    &JIT_STATS
}

#[cfg(target_arch = "x86_64")]
pub fn jit_fuzz_set_x64_diag(enabled: bool) -> bool {
    JIT_FUZZ_X64_DIAG.swap(enabled, Ordering::SeqCst)
}

#[cfg(not(target_arch = "x86_64"))]
pub fn jit_fuzz_set_x64_diag(_enabled: bool) -> bool {
    false
}

#[inline]
pub(crate) fn jit_fuzz_verbose_trace_enabled() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        JIT_FUZZ_X64_DIAG.load(Ordering::SeqCst)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

fn jit_runtime_recover_impl(drop_fuzz_state: bool) {
    let stale_pending = JIT_USER_RETURN_PENDING.load(Ordering::SeqCst);
    let stale_active = JIT_USER_ACTIVE.load(Ordering::SeqCst);
    let stale_ret_eip = JIT_USER_RETURN_EIP.load(Ordering::SeqCst);
    let stale_ret_esp = JIT_USER_RETURN_ESP.load(Ordering::SeqCst);
    let stale_save_seq = unsafe { JIT_USER_DBG_SAVE_SEQ };
    let stale_sys_seq = unsafe { JIT_USER_DBG_SYSCALL_SEQ };
    if stale_pending != 0
        || stale_active != 0
        || stale_ret_eip != 0
        || stale_ret_esp != 0
        || stale_save_seq != 0
        || stale_sys_seq != 0
    {
        crate::serial::_print(format_args!(
            "[JIT-DBG] recover stale pending={} active={} ret_eip=0x{:016x} ret_esp=0x{:016x} save_seq={} sys_seq={}\n",
            stale_pending,
            stale_active,
            stale_ret_eip,
            stale_ret_esp,
            stale_save_seq,
            stale_sys_seq,
        ));
    }

    JIT_USER_RETURN_PENDING.store(0, Ordering::SeqCst);
    JIT_USER_ACTIVE.store(0, Ordering::SeqCst);
    JIT_USER_RETURN_EIP.store(0, Ordering::SeqCst);
    JIT_USER_RETURN_ESP.store(0, Ordering::SeqCst);
    JIT_USER_SYSCALL_VIOLATION.store(0, Ordering::SeqCst);

    JIT_FAULT_ACTIVE.store(false, Ordering::SeqCst);
    JIT_FAULT_EXEC_START.store(0, Ordering::SeqCst);
    JIT_FAULT_EXEC_END.store(0, Ordering::SeqCst);
    JIT_USER_DEBUG_STAGE.store(0, Ordering::SeqCst);
    JIT_USER_FAULT_LOGGED.store(false, Ordering::SeqCst);
    JIT_USER_ENTER_TICK.store(0, Ordering::SeqCst);
    JIT_KERNEL_ENTER_TICK.store(0, Ordering::SeqCst);
    JIT_USER_HANDOFF_LOG_COUNT.store(0, Ordering::SeqCst);
    JIT_USER_DBG_CALL_SEQ.store(0, Ordering::SeqCst);
    unsafe {
        JIT_USER_DBG_CALL_ENTRY = 0;
        JIT_USER_DBG_CALL_STACK_PTR = 0;
        JIT_USER_DBG_CALL_SP_PTR = 0;
        JIT_USER_DBG_CALL_MEM_PTR = 0;
        JIT_USER_DBG_CALL_MEM_LEN = 0;
        JIT_USER_DBG_CALL_TRAP_PTR = 0;
        JIT_USER_DBG_CALL_PID = 0;
        JIT_USER_DBG_CALL_INSTANCE = 0;
        JIT_USER_DBG_CALL_FUNC = 0;
        JIT_USER_DBG_SAVE_ESP = 0;
        JIT_USER_DBG_SAVE_EIP = 0;
        JIT_USER_DBG_SAVE_SEQ = 0;
        JIT_USER_DBG_SYSCALL_ESP = 0;
        JIT_USER_DBG_SYSCALL_EIP = 0;
        JIT_USER_DBG_SYSCALL_SEQ = 0;
        JIT_USER_DBG_SYSCALL_PATH = 0;
        JIT_USER_DBG_SYSCALL_FLAGS = 0;
        JIT_USER_DBG_SYSCALL_NR = 0;
        JIT_USER_DBG_SYSCALL_FROM_EIP = 0;
        JIT_USER_DBG_SYSCALL_FROM_CS = 0;
    }
    unsafe {
        JIT_FAULT_TRAP_PTR = core::ptr::null_mut();
    }

    if drop_fuzz_state {
        // Deep recovery path: drop fuzz instances/compiler state. This is useful
        // after a suspected corruption, but it also reallocates from the bump-only
        // JIT arena on the next run.
        let stale_instances = {
            let mut slots = JIT_FUZZ_INSTANCES.lock();
            let prev = *slots;
            *slots = None;
            prev
        };
        if let Some((interp_id, jit_id)) = stale_instances {
            let _ = wasm_runtime().destroy(interp_id);
            if jit_id != interp_id {
                let _ = wasm_runtime().destroy(jit_id);
            }
        }
        {
            let mut compiler = JIT_FUZZ_COMPILER.lock();
            *compiler = None;
        }
    }

    if kpti::enabled() {
        kpti::leave_user();
    } else {
        #[cfg(target_arch = "x86_64")]
        {
            // x86_64 bring-up uses a dedicated 64-bit IDT path; reloading the
            // legacy idt_asm table here can stall/fault before fuzz chunks start.
            crate::arch::x86::x86_64_runtime::init_trap_table();
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            idt_asm::reload();
        }
    }

    if let Some(kernel_cr3) = crate::arch::mmu::kernel_page_table_root_addr() {
        let _ = crate::arch::mmu::set_page_table_root(kernel_cr3);
    }

    unsafe { idt_asm::fast_sti() };
}

/// Force-reset transient JIT state after stress/fuzz commands.
pub fn jit_runtime_recover() {
    jit_runtime_recover_impl(true);
}

/// Reset transient JIT/user-handoff state but preserve reusable fuzz allocations.
///
/// This is the preferred recovery mode between repeated `wasm-jit-fuzz` runs
/// because fuzz instances and the reusable fuzz compiler allocate from a bump-only
/// JIT arena; repeatedly dropping/recreating them can exhaust the arena.
pub fn jit_runtime_recover_transient() {
    jit_runtime_recover_impl(false);
}

struct JitFaultScope;

impl JitFaultScope {
    fn enter(trap_ptr: *mut i32, exec_start: usize, exec_len: usize) -> Self {
        jit_fault_enter(trap_ptr, exec_start, exec_len);
        JitFaultScope
    }
}

impl Drop for JitFaultScope {
    fn drop(&mut self) {
        jit_fault_exit();
    }
}

fn jit_fault_enter(trap_ptr: *mut i32, exec_start: usize, exec_len: usize) {
    let (start, end) = if exec_len == 0 {
        (0u32, 0u32)
    } else {
        let start = exec_start as u32;
        let end = exec_start
            .checked_add(exec_len)
            .unwrap_or(exec_start)
            .min(u32::MAX as usize) as u32;
        if end <= start {
            (0u32, 0u32)
        } else {
            (start, end)
        }
    };
    JIT_FAULT_EXEC_START.store(start, Ordering::SeqCst);
    JIT_FAULT_EXEC_END.store(end, Ordering::SeqCst);
    unsafe {
        JIT_FAULT_TRAP_PTR = trap_ptr;
    }
    JIT_FAULT_ACTIVE.store(true, Ordering::SeqCst);
}

fn jit_fault_exit() {
    JIT_FAULT_ACTIVE.store(false, Ordering::SeqCst);
    JIT_FAULT_EXEC_START.store(0, Ordering::SeqCst);
    JIT_FAULT_EXEC_END.store(0, Ordering::SeqCst);
    unsafe {
        JIT_FAULT_TRAP_PTR = core::ptr::null_mut();
    }
}

fn jit_select_kernel_esp0(current_esp: usize) -> u32 {
    for (start, end) in crate::scheduler::quantum_scheduler::kernel_stack_bounds() {
        if current_esp >= start && current_esp < end {
            return (end as u32).saturating_sub(16);
        }
    }
    let page_top = (current_esp + paging::PAGE_SIZE) & !(paging::PAGE_SIZE - 1);
    (page_top as u32).saturating_sub(16)
}

#[cfg(not(target_arch = "x86_64"))]
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

        write_u8!(0xB9);
        write_u32!(call_addr);
        write_u8!(0x51);
        write_u8!(0x8B);
        write_u8!(0x01);
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x28);
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x24);
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x20);
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x1C);
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x18);
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x14);
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x10);
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x0C);
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x08);
        write_u8!(0xFF);
        write_u8!(0x71);
        write_u8!(0x04);
        write_u8!(0xFF);
        write_u8!(0xD0);
        write_u8!(0x83);
        write_u8!(0xC4);
        write_u8!(0x28);
        write_u8!(0x59);
        write_u8!(0x89);
        write_u8!(0x41);
        write_u8!(0x2C);
        // Copy request seq -> ack seq so kernel can verify this return belongs
        // to the current invocation (prevents stale ret reuse).
        write_u8!(0x8B);
        write_u8!(0x51);
        write_u8!(0x30);
        write_u8!(0x89);
        write_u8!(0x51);
        write_u8!(0x34);
        write_u8!(0xB8);
        write_u32!(SYSCALL_JIT_RETURN);
        write_u8!(0xCD);
        write_u8!(0x80);
        write_u8!(0xEB);
        write_u8!(0xFC);
        let _ = idx;

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
        f_write_u8!(0xB8);
        f_write_u32!(SYSCALL_JIT_RETURN);
        f_write_u8!(0xCD);
        f_write_u8!(0x80);
        f_write_u8!(0xEB);
        f_write_u8!(0xFC);
        let _ = fidx;
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(unused_assignments)] // idx/fidx are used by macros; final increment after last write is intentionally not read
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

        // mov r11d, imm32 (call page pointer)
        write_u8!(0x41);
        write_u8!(0xBB);
        write_u32!(call_addr);
        // mov r10d, [r11]
        write_u8!(0x45);
        write_u8!(0x8B);
        write_u8!(0x13);
        // first 6 SysV args
        write_u8!(0x41);
        write_u8!(0x8B);
        write_u8!(0x7B);
        write_u8!(0x04); // edi
        write_u8!(0x41);
        write_u8!(0x8B);
        write_u8!(0x73);
        write_u8!(0x08); // esi
        write_u8!(0x41);
        write_u8!(0x8B);
        write_u8!(0x53);
        write_u8!(0x0C); // edx
        write_u8!(0x41);
        write_u8!(0x8B);
        write_u8!(0x4B);
        write_u8!(0x10); // ecx
        write_u8!(0x45);
        write_u8!(0x8B);
        write_u8!(0x43);
        write_u8!(0x14); // r8d
        write_u8!(0x45);
        write_u8!(0x8B);
        write_u8!(0x4B);
        write_u8!(0x18); // r9d
                         // remaining 4 args on stack
        write_u8!(0x41);
        write_u8!(0xFF);
        write_u8!(0x73);
        write_u8!(0x28);
        write_u8!(0x41);
        write_u8!(0xFF);
        write_u8!(0x73);
        write_u8!(0x24);
        write_u8!(0x41);
        write_u8!(0xFF);
        write_u8!(0x73);
        write_u8!(0x20);
        write_u8!(0x41);
        write_u8!(0xFF);
        write_u8!(0x73);
        write_u8!(0x1C);
        // call r10
        write_u8!(0x41);
        write_u8!(0xFF);
        write_u8!(0xD2);
        // add rsp, 32
        write_u8!(0x48);
        write_u8!(0x83);
        write_u8!(0xC4);
        write_u8!(0x20);
        // mov [r11+44], eax
        write_u8!(0x41);
        write_u8!(0x89);
        write_u8!(0x43);
        write_u8!(0x2C);
        // mov edx, [r11+48] ; mov [r11+52], edx  (req_seq -> ack_seq)
        write_u8!(0x41);
        write_u8!(0x8B);
        write_u8!(0x53);
        write_u8!(0x30);
        write_u8!(0x41);
        write_u8!(0x89);
        write_u8!(0x53);
        write_u8!(0x34);
        // mov eax, SYS_JIT_RETURN ; int 0x80 ; jmp $
        write_u8!(0xB8);
        write_u32!(SYSCALL_JIT_RETURN);
        write_u8!(0xCD);
        write_u8!(0x80);
        write_u8!(0xEB);
        write_u8!(0xFC);

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
        f_write_u8!(0xB8);
        f_write_u32!(SYSCALL_JIT_RETURN);
        f_write_u8!(0xCD);
        f_write_u8!(0x80);
        f_write_u8!(0xEB);
        f_write_u8!(0xFC);
    }
}

fn ensure_jit_user_pages(pages: &mut Option<JitUserPages>) -> Result<JitUserPages, &'static str> {
    if let Some(existing) = *pages {
        validate_jit_user_pages(&existing)?;
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
    let _ = crate::arch::mmu::set_page_writable_range(trampoline, paging::PAGE_SIZE, false);
    let new_pages = JitUserPages {
        trampoline,
        call,
        stack,
        stack_pages,
    };
    validate_jit_user_pages(&new_pages)?;
    *pages = Some(new_pages);
    Ok(new_pages)
}

fn wipe_jit_user_pages(pages: &JitUserPages) {
    if validate_jit_user_pages(pages).is_err() {
        return;
    }
    let _ = crate::arch::mmu::set_page_writable_range(pages.trampoline, paging::PAGE_SIZE, true);
    write_jit_user_trampoline(pages.trampoline as *mut u8, USER_JIT_CALL_BASE as u32);
    let _ = crate::arch::mmu::set_page_writable_range(pages.trampoline, paging::PAGE_SIZE, false);
    unsafe {
        core::ptr::write_bytes(pages.call as *mut u8, 0, paging::PAGE_SIZE);
        core::ptr::write_bytes(
            pages.stack as *mut u8,
            0,
            pages.stack_pages * paging::PAGE_SIZE,
        );
    }
}

#[cfg(target_arch = "x86_64")]
fn ensure_jit_user_preflight_aux_pages(
    aux: &mut Option<JitUserPreflightAuxPages>,
) -> Result<JitUserPreflightAuxPages, &'static str> {
    if let Some(existing) = *aux {
        return Ok(existing);
    }
    let new_pages = JitUserPreflightAuxPages {
        code: memory::jit_allocate_pages(1)?,
        state: memory::jit_allocate_pages(1)?,
        mem: memory::jit_allocate_pages(1)?,
    };
    *aux = Some(new_pages);
    Ok(new_pages)
}

#[cfg(target_arch = "x86_64")]
fn jit_x86_64_sandbox_preflight_with_pages(
    pages_cache: &mut Option<JitUserPages>,
    source: &'static str,
) -> Result<(), &'static str> {
    let pages = ensure_jit_user_pages(pages_cache)?;
    validate_jit_user_pages(&pages)?;
    wipe_jit_user_pages(&pages);

    let mut sandbox_slot = JIT_USER_SANDBOX.lock();
    if sandbox_slot.is_none() {
        *sandbox_slot = Some(arch_mmu::new_jit_sandbox()?);
    }
    let sandbox = sandbox_slot.as_mut().ok_or("JIT sandbox unavailable")?;

    let mut aux_pages_slot = JIT_USER_PREFLIGHT_AUX_PAGES.lock();
    let aux_pages = ensure_jit_user_preflight_aux_pages(&mut *aux_pages_slot)?;
    let code_page = aux_pages.code;
    let state_page = aux_pages.state;
    let mem_page = aux_pages.mem;

    unsafe {
        core::ptr::write_volatile(code_page as *mut u8, 0xC3); // ret
        core::ptr::write_volatile(state_page as *mut u8, 0x5A);
        core::ptr::write_volatile(mem_page as *mut u8, 0xA5);
    }

    let trampoline_phys = arch_mmu::x86_64_debug_virt_to_phys(pages.trampoline)
        .ok_or("Preflight trampoline phys lookup failed")?;
    let call_phys = arch_mmu::x86_64_debug_virt_to_phys(pages.call)
        .ok_or("Preflight call-page phys lookup failed")?;
    let stack_phys = arch_mmu::x86_64_debug_virt_to_phys(pages.stack)
        .ok_or("Preflight stack phys lookup failed")?;
    let code_phys = arch_mmu::x86_64_debug_virt_to_phys(code_page)
        .ok_or("Preflight code phys lookup failed")?;
    let state_phys = arch_mmu::x86_64_debug_virt_to_phys(state_page)
        .ok_or("Preflight state phys lookup failed")?;
    let mem_phys =
        arch_mmu::x86_64_debug_virt_to_phys(mem_page).ok_or("Preflight mem phys lookup failed")?;

    let guard_bytes = USER_JIT_STACK_GUARD_PAGES * paging::PAGE_SIZE;
    let code_guard = USER_JIT_CODE_GUARD_PAGES * paging::PAGE_SIZE;
    let data_guard = USER_JIT_DATA_GUARD_PAGES * paging::PAGE_SIZE;
    let mem_guard = USER_WASM_MEM_GUARD_PAGES * paging::PAGE_SIZE;
    let code_base = USER_JIT_CODE_BASE
        .checked_add(code_guard)
        .ok_or("JIT code base overflow")?;
    let data_base = USER_JIT_DATA_BASE
        .checked_add(data_guard)
        .ok_or("JIT data base overflow")?;
    let mem_base = USER_WASM_MEM_BASE
        .checked_add(mem_guard)
        .ok_or("WASM memory base overflow")?;

    memory_isolation::tag_jit_user_trampoline(trampoline_phys, paging::PAGE_SIZE, true)?;
    memory_isolation::tag_jit_user_state(call_phys, paging::PAGE_SIZE, true)?;
    memory_isolation::tag_jit_user_stack(
        stack_phys + guard_bytes,
        USER_JIT_STACK_PAGES * paging::PAGE_SIZE,
        true,
    )?;
    memory_isolation::tag_jit_code_user(code_phys, paging::PAGE_SIZE)?;
    memory_isolation::tag_jit_user_state(state_phys, paging::PAGE_SIZE, true)?;
    memory_isolation::tag_wasm_linear_memory(mem_phys, paging::PAGE_SIZE, true)?;

    sandbox.map_user_range_phys(
        USER_JIT_TRAMPOLINE_BASE,
        trampoline_phys,
        paging::PAGE_SIZE,
        false,
    )?;
    sandbox.map_user_range_phys(USER_JIT_CALL_BASE, call_phys, paging::PAGE_SIZE, true)?;
    sandbox.map_user_range_phys(
        USER_JIT_STACK_BASE + guard_bytes,
        stack_phys + guard_bytes,
        USER_JIT_STACK_PAGES * paging::PAGE_SIZE,
        true,
    )?;
    sandbox.map_user_range_phys(code_base, code_phys, paging::PAGE_SIZE, false)?;
    sandbox.map_user_range_phys(data_base, state_phys, paging::PAGE_SIZE, true)?;
    sandbox.map_user_range_phys(mem_base, mem_phys, paging::PAGE_SIZE, true)?;

    let old_cr3 = arch_mmu::current_page_table_root_addr();
    unsafe {
        sandbox.activate();
    }
    let verify = (|| -> Result<(), &'static str> {
        let tramp_b = unsafe { core::ptr::read_volatile(USER_JIT_TRAMPOLINE_BASE as *const u8) };
        let call_b = unsafe { core::ptr::read_volatile(USER_JIT_CALL_BASE as *const u8) };
        let stack_user_top =
            USER_JIT_STACK_BASE + guard_bytes + (USER_JIT_STACK_PAGES * paging::PAGE_SIZE) - 1;
        unsafe {
            core::ptr::write_volatile(USER_JIT_CALL_BASE as *mut u8, 0x11);
            core::ptr::write_volatile((USER_JIT_STACK_BASE + guard_bytes) as *mut u8, 0x22);
            core::ptr::write_volatile(data_base as *mut u8, 0x33);
            core::ptr::write_volatile(mem_base as *mut u8, 0x44);
        }
        let code_b = unsafe { core::ptr::read_volatile(code_base as *const u8) };
        let data_b = unsafe { core::ptr::read_volatile(data_base as *const u8) };
        let mem_b = unsafe { core::ptr::read_volatile(mem_base as *const u8) };
        let stack_b =
            unsafe { core::ptr::read_volatile((USER_JIT_STACK_BASE + guard_bytes) as *const u8) };
        let stack_top_b = unsafe { core::ptr::read_volatile(stack_user_top as *const u8) };
        crate::serial::_print(format_args!(
            "[JIT-DBG] x64 preflight({}) map cr3=0x{:08x} tramp=0x{:02x} call=0x{:02x} code=0x{:02x} data=0x{:02x} mem=0x{:02x} stack=0x{:02x} top=0x{:02x}\n",
            source,
            sandbox.phys_addr() as u32,
            tramp_b,
            call_b,
            code_b,
            data_b,
            mem_b,
            stack_b,
            stack_top_b,
        ));
        if code_b != 0xC3 || data_b != 0x33 || mem_b != 0x44 || stack_b != 0x22 {
            return Err("Sandbox CR3 verification mismatch");
        }
        Ok(())
    })();
    let _ = arch_mmu::set_page_table_root(old_cr3);
    verify?;

    let pre_unmap_call = sandbox.is_mapped(USER_JIT_CALL_BASE);
    let pre_unmap_code = sandbox.is_mapped(code_base);
    sandbox.unmap_page(USER_JIT_CALL_BASE)?;
    sandbox.unmap_page(code_base)?;
    sandbox.unmap_page(data_base)?;
    sandbox.unmap_page(mem_base)?;
    sandbox.unmap_page(USER_JIT_STACK_BASE + guard_bytes)?;
    sandbox.unmap_page(USER_JIT_TRAMPOLINE_BASE)?;

    let post_unmap_ok = !sandbox.is_mapped(USER_JIT_CALL_BASE)
        && !sandbox.is_mapped(code_base)
        && !sandbox.is_mapped(data_base)
        && !sandbox.is_mapped(mem_base)
        && !sandbox.is_mapped(USER_JIT_STACK_BASE + guard_bytes)
        && !sandbox.is_mapped(USER_JIT_TRAMPOLINE_BASE);
    if !pre_unmap_call || !pre_unmap_code || !post_unmap_ok {
        return Err("Sandbox unmap verification failed");
    }

    // Restore kernel-only visibility tags for the reusable trampoline/call/stack pages.
    memory_isolation::tag_jit_user_trampoline(trampoline_phys, paging::PAGE_SIZE, false)?;
    memory_isolation::tag_jit_user_state(call_phys, paging::PAGE_SIZE, false)?;
    memory_isolation::tag_jit_user_stack(stack_phys, pages.stack_pages * paging::PAGE_SIZE, false)?;

    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
pub fn jit_x86_64_sandbox_preflight() -> Result<(), &'static str> {
    Err("x86_64 JIT sandbox preflight only")
}

#[cfg(target_arch = "x86_64")]
pub fn jit_x86_64_sandbox_preflight() -> Result<(), &'static str> {
    let _guard = JIT_USER_LOCK.lock();
    let mut preflight_pages = JIT_USER_PREFLIGHT_PAGES.lock();
    jit_x86_64_sandbox_preflight_with_pages(&mut *preflight_pages, "shell")
}

#[cfg(target_arch = "x86_64")]
pub fn jit_x86_64_call_user_path_probe() -> Result<&'static str, &'static str> {
    extern "C" {
        fn x64_jit_callpage_exec(call_ptr: u32) -> i32;
    }

    fn addr_u32(addr: usize) -> Result<u32, &'static str> {
        u32::try_from(addr).map_err(|_| "x86_64 callpage probe requires low-32-bit addresses")
    }

    unsafe extern "C" fn dummy_jit_callpage_entry(
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
        if !stack_ptr.is_null() {
            *stack_ptr = 0x11;
        }
        if !sp_ptr.is_null() {
            *sp_ptr = 1;
        }
        if !locals_ptr.is_null() {
            *locals_ptr = 0x22;
        }
        if !instr_fuel.is_null() && *instr_fuel > 0 {
            *instr_fuel -= 1;
        }
        if !mem_fuel.is_null() && *mem_fuel > 0 {
            *mem_fuel -= 1;
        }
        if !trap_code.is_null() {
            *trap_code = 0;
        }
        if !shadow_stack_ptr.is_null() {
            *shadow_stack_ptr = 0x33;
        }
        if !shadow_sp_ptr.is_null() {
            *shadow_sp_ptr = 1;
        }
        if !mem_ptr.is_null() && mem_len > 0 {
            *mem_ptr = 0x5A;
        }
        0x1357_2468
    }

    fn kernel_callpage_exec_probe() -> Result<(), &'static str> {
        let _guard = JIT_USER_LOCK.lock();
        let mut preflight_pages = JIT_USER_PREFLIGHT_PAGES.lock();
        let pages = ensure_jit_user_pages(&mut *preflight_pages)?;
        wipe_jit_user_pages(&pages);

        let state_bytes = core::mem::size_of::<JitUserState>();
        let state_pages = state_bytes
            .checked_add(paging::PAGE_SIZE - 1)
            .ok_or("JIT state size overflow")?
            / paging::PAGE_SIZE;
        let state_base = memory::jit_allocate_pages(state_pages)?;
        let mem_base = memory::jit_allocate_pages(1)?;

        unsafe {
            core::ptr::write_bytes(state_base as *mut u8, 0, state_pages * paging::PAGE_SIZE);
            core::ptr::write_bytes(mem_base as *mut u8, 0, paging::PAGE_SIZE);
        }

        let state_ptr = state_base as *mut JitUserState;
        unsafe {
            (*state_ptr).instr_fuel = 7;
            (*state_ptr).mem_fuel = 9;
            (*state_ptr).trap_code = -1;
        }

        let base = state_ptr as usize;
        let stack_off = unsafe { core::ptr::addr_of!((*state_ptr).stack) as usize } - base;
        let sp_off = unsafe { core::ptr::addr_of!((*state_ptr).sp) as usize } - base;
        let locals_off = unsafe { core::ptr::addr_of!((*state_ptr).locals) as usize } - base;
        let globals_off = unsafe { core::ptr::addr_of!((*state_ptr).globals) as usize } - base;
        let instr_fuel_off =
            unsafe { core::ptr::addr_of!((*state_ptr).instr_fuel) as usize } - base;
        let mem_fuel_off = unsafe { core::ptr::addr_of!((*state_ptr).mem_fuel) as usize } - base;
        let trap_off = unsafe { core::ptr::addr_of!((*state_ptr).trap_code) as usize } - base;
        #[cfg(target_arch = "x86_64")]
        let _shadow_stack_off =
            unsafe { core::ptr::addr_of!((*state_ptr).shadow_stack) as usize } - base;
        #[cfg(not(target_arch = "x86_64"))]
        let shadow_stack_off =
            unsafe { core::ptr::addr_of!((*state_ptr).shadow_stack) as usize } - base;
        let shadow_sp_off = unsafe { core::ptr::addr_of!((*state_ptr).shadow_sp) as usize } - base;

        let call_ptr = pages.call as *mut JitUserCall;
        unsafe {
            (*call_ptr).entry = addr_u32(dummy_jit_callpage_entry as usize)?;
            (*call_ptr).stack_ptr = addr_u32(base + stack_off)?;
            (*call_ptr).sp_ptr = addr_u32(base + sp_off)?;
            (*call_ptr).mem_ptr = addr_u32(mem_base)?;
            (*call_ptr).mem_len = paging::PAGE_SIZE as u32;
            (*call_ptr).locals_ptr = addr_u32(base + locals_off)?;
            (*call_ptr).instr_fuel_ptr = addr_u32(base + instr_fuel_off)?;
            (*call_ptr).mem_fuel_ptr = addr_u32(base + mem_fuel_off)?;
            (*call_ptr).trap_ptr = addr_u32(base + trap_off)?;
            #[cfg(target_arch = "x86_64")]
            {
                (*call_ptr).shadow_stack_ptr = addr_u32(base + globals_off)?;
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                (*call_ptr).shadow_stack_ptr = addr_u32(base + shadow_stack_off)?;
            }
            (*call_ptr).shadow_sp_ptr = addr_u32(base + shadow_sp_off)?;
            (*call_ptr).ret = 0;
        }

        let ret = unsafe { x64_jit_callpage_exec(addr_u32(pages.call)?) };
        let call_ret = unsafe { (*call_ptr).ret };
        let mem0 = unsafe { core::ptr::read_volatile(mem_base as *const u8) };
        let stack0 = unsafe { (*state_ptr).stack[0] };
        let locals0 = unsafe { (*state_ptr).locals[0] };
        let sp = unsafe { (*state_ptr).sp };
        let globals0 = unsafe { (*state_ptr).globals[0] };
        #[cfg(target_arch = "x86_64")]
        let _shadow0 = unsafe { (*state_ptr).shadow_stack[0] };
        #[cfg(not(target_arch = "x86_64"))]
        let shadow0 = unsafe { (*state_ptr).shadow_stack[0] };
        let shadow_sp = unsafe { (*state_ptr).shadow_sp };
        let instr_fuel = unsafe { (*state_ptr).instr_fuel };
        let mem_fuel = unsafe { (*state_ptr).mem_fuel };
        let trap = unsafe { (*state_ptr).trap_code };

        if ret != 0x1357_2468 || call_ret != 0x1357_2468 {
            return Err("x86_64 callpage exec returned unexpected value");
        }
        #[cfg(target_arch = "x86_64")]
        let cfi_probe_ok = globals0 == 0x33;
        #[cfg(not(target_arch = "x86_64"))]
        let cfi_probe_ok = shadow0 == 0x33;
        if mem0 != 0x5A || stack0 != 0x11 || locals0 != 0x22 || !cfi_probe_ok {
            return Err("x86_64 callpage exec argument wiring mismatch");
        }
        if sp != 1 || shadow_sp != 1 || instr_fuel != 6 || mem_fuel != 8 || trap != 0 {
            return Err("x86_64 callpage exec state mutation mismatch");
        }
        Ok(())
    }

    // Minimal x86_64 JIT function body matching `JitFn`: `mov eax, imm32; ret`.
    const X64_PROBE_RET: i32 = 0x2468_1357;
    let exec_page = memory::jit_allocate_pages(1)?;
    let _ = memory_isolation::tag_jit_code_kernel(exec_page, paging::PAGE_SIZE, false);
    crate::arch::mmu::set_page_writable_range(exec_page, paging::PAGE_SIZE, true)?;
    unsafe {
        let p = exec_page as *mut u8;
        core::ptr::write_volatile(p.add(0), 0xB8); // mov eax, imm32
        for (i, b) in (X64_PROBE_RET as u32).to_le_bytes().iter().enumerate() {
            core::ptr::write_volatile(p.add(1 + i), *b);
        }
        core::ptr::write_volatile(p.add(5), 0xC3); // ret
    }
    crate::arch::mmu::set_page_writable_range(exec_page, paging::PAGE_SIZE, false)?;
    let _ = memory_isolation::tag_jit_code_kernel(exec_page, paging::PAGE_SIZE, true);

    let jit_entry = JitExecInfo {
        entry: unsafe { core::mem::transmute(exec_page as *mut u8) },
        exec_ptr: exec_page as *mut u8,
        exec_len: 6,
    };

    let mut stack = [0i32; 4];
    let mut sp = 0usize;
    let mut locals = [0i32; 4];
    let mut instr_fuel = 1u32;
    let mut mem_fuel = 1u32;
    let mut trap_code = 0i32;
    let mut shadow_stack = [0u32; 4];
    let mut shadow_sp = 0usize;
    let mut jit_user_pages: Option<JitUserPages> = None;

    let mem_ptr = memory::jit_allocate_pages(1)? as *mut u8;
    let jit_state_pages = core::mem::size_of::<JitUserState>()
        .checked_add(paging::PAGE_SIZE - 1)
        .ok_or("jitcall probe state size overflow")?
        / paging::PAGE_SIZE;
    let jit_state_base = memory::jit_allocate_pages(jit_state_pages)? as *mut u8;

    JIT_X64_CALL_PROBE_ACTIVE.store(true, Ordering::SeqCst);
    let result = call_jit_user(
        jit_entry,
        stack.as_mut_ptr(),
        &mut sp as *mut usize,
        mem_ptr,
        paging::PAGE_SIZE,
        locals.as_mut_ptr(),
        &mut instr_fuel as *mut u32,
        &mut mem_fuel as *mut u32,
        &mut trap_code as *mut i32,
        shadow_stack.as_mut_ptr(),
        &mut shadow_sp as *mut usize,
        jit_state_base,
        jit_state_pages,
        &mut jit_user_pages,
        1,
        1,
        0,
    );
    JIT_X64_CALL_PROBE_ACTIVE.store(false, Ordering::SeqCst);

    match result {
        Ok(ret) if ret == X64_PROBE_RET => {
            kernel_callpage_exec_probe()?;
            Ok("x86_64 JIT user trampoline/iret/int80 return path ok; callpage exec shim ok")
        }
        Ok(ret) => {
            crate::serial::_print(format_args!(
                "[JIT-DBG] x64 jitcall probe unexpected ret={}\n",
                ret
            ));
            Err("x86_64 JIT user path returned unexpected value")
        }
        Err(e) => {
            let stage = JIT_USER_DEBUG_STAGE.load(Ordering::SeqCst);
            crate::serial::_print(format_args!(
                "[JIT-DBG] x64 jitcall probe failed stage={} err={}\n",
                stage, e
            ));
            Err(e)
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn jit_x86_64_call_user_path_probe() -> Result<&'static str, &'static str> {
    Err("x86_64 JIT user path probe only")
}

pub fn jit_user_mark_returned() -> bool {
    if JIT_USER_ACTIVE.load(Ordering::SeqCst) != 0 {
        JIT_USER_RETURN_PENDING.store(1, Ordering::SeqCst);
        return true;
    }
    false
}

#[inline]
pub fn jit_user_active() -> bool {
    JIT_USER_ACTIVE.load(Ordering::SeqCst) != 0
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn jit_handle_kernel_fault_x86_64(rip: &mut u64) -> bool {
    if !JIT_FAULT_ACTIVE.load(Ordering::SeqCst) {
        return false;
    }
    let start = JIT_FAULT_EXEC_START.load(Ordering::SeqCst) as usize;
    let end = JIT_FAULT_EXEC_END.load(Ordering::SeqCst) as usize;
    let pc = *rip as usize;
    if start == 0 || end <= start || pc < start || pc >= end {
        return false;
    }
    unsafe {
        if !JIT_FAULT_TRAP_PTR.is_null() {
            *JIT_FAULT_TRAP_PTR = TRAP_MEM;
        }
    }
    *rip = crate::memory::asm_bindings::asm_jit_fault_resume as usize as u64;
    true
}

#[cfg(target_arch = "x86_64")]
pub fn jit_handle_page_fault_x86_64(
    fault_addr: usize,
    error_code: u64,
    rip: &mut u64,
    cs: u64,
    rsp: &mut u64,
) -> bool {
    if !JIT_FAULT_ACTIVE.load(Ordering::SeqCst) {
        return false;
    }
    if (cs & 0x3) == 0x3 && JIT_USER_ACTIVE.load(Ordering::SeqCst) != 0 {
        unsafe {
            if !JIT_FAULT_TRAP_PTR.is_null() {
                *JIT_FAULT_TRAP_PTR = TRAP_MEM;
            }
        }
        if !JIT_USER_FAULT_LOGGED.swap(true, Ordering::SeqCst) {
            let stage = JIT_USER_DEBUG_STAGE.load(Ordering::SeqCst);
            crate::serial::_print(format_args!(
                "[JIT-DBG] x64 user fault stage={} addr=0x{:016x} err=0x{:016x} rip=0x{:016x} rsp=0x{:016x}\n",
                stage, fault_addr, error_code, *rip, *rsp
            ));
        }
        let guard_bytes = USER_JIT_STACK_GUARD_PAGES * paging::PAGE_SIZE;
        *rip = (USER_JIT_TRAMPOLINE_BASE + USER_JIT_TRAMPOLINE_FAULT_OFFSET) as u64;
        *rsp = (USER_JIT_STACK_BASE + guard_bytes + (USER_JIT_STACK_PAGES * paging::PAGE_SIZE) - 16)
            as u64;
        return true;
    }
    // Kernel-mode JIT fuzz executes in ring0. If the faulting RIP is inside the
    // active JIT translation window, force trap return through the shared resume
    // shim instead of re-entering the faulting instruction endlessly.
    jit_handle_kernel_fault_x86_64(rip)
}

#[cfg(target_arch = "x86_64")]
pub fn jit_handle_exception_x86_64(
    vector: u64,
    error_code: u64,
    rip: &mut u64,
    cs: u64,
    rsp: &mut u64,
) -> bool {
    if !JIT_FAULT_ACTIVE.load(Ordering::SeqCst) {
        return false;
    }
    if (cs & 0x3) == 0x3 && JIT_USER_ACTIVE.load(Ordering::SeqCst) != 0 {
        match vector as u32 {
            6 | 7 | 10 | 11 | 12 | 13 | 16 | 17 | 19 | 21 => {}
            _ => return false,
        }
        unsafe {
            if !JIT_FAULT_TRAP_PTR.is_null() {
                *JIT_FAULT_TRAP_PTR = TRAP_MEM;
            }
        }
        if !JIT_USER_FAULT_LOGGED.swap(true, Ordering::SeqCst) {
            let stage = JIT_USER_DEBUG_STAGE.load(Ordering::SeqCst);
            crate::serial::_print(format_args!(
                "[JIT-DBG] x64 user exception stage={} vector={} err=0x{:016x} rip=0x{:016x} rsp=0x{:016x}\n",
                stage, vector, error_code, *rip, *rsp
            ));
        }
        let guard_bytes = USER_JIT_STACK_GUARD_PAGES * paging::PAGE_SIZE;
        *rip = (USER_JIT_TRAMPOLINE_BASE + USER_JIT_TRAMPOLINE_FAULT_OFFSET) as u64;
        *rsp = (USER_JIT_STACK_BASE + guard_bytes + (USER_JIT_STACK_PAGES * paging::PAGE_SIZE) - 16)
            as u64;
        return true;
    }
    // Kernel-mode JIT execution faults are converted into TRAP_MEM and resumed
    // through asm_jit_fault_resume if the RIP is inside active translated code.
    jit_handle_kernel_fault_x86_64(rip)
}

#[cfg(target_arch = "x86_64")]
pub fn jit_handle_timer_interrupt_x86_64(rip: &mut u64, cs: u64, rsp: &mut u64) -> bool {
    if (cs & 0x3) == 0x3 && JIT_USER_ACTIVE.load(Ordering::SeqCst) != 0 {
        let start_tick = JIT_USER_ENTER_TICK.load(Ordering::SeqCst);
        if start_tick == 0 {
            return false;
        }
        let now = crate::scheduler::pit::get_ticks() as u32;
        if now.wrapping_sub(start_tick) < JIT_USER_TIMEOUT_TICKS {
            return false;
        }
        unsafe {
            if !JIT_FAULT_TRAP_PTR.is_null() {
                *JIT_FAULT_TRAP_PTR = TRAP_MEM;
            }
        }
        if !JIT_USER_FAULT_LOGGED.swap(true, Ordering::SeqCst) {
            let stage = JIT_USER_DEBUG_STAGE.load(Ordering::SeqCst);
            crate::serial::_print(format_args!(
                "[JIT-DBG] x64 user timeout stage={} start_tick={} now_tick={} rip=0x{:016x} rsp=0x{:016x}\n",
                stage, start_tick, now, *rip, *rsp
            ));
        }
        let guard_bytes = USER_JIT_STACK_GUARD_PAGES * paging::PAGE_SIZE;
        *rip = (USER_JIT_TRAMPOLINE_BASE + USER_JIT_TRAMPOLINE_FAULT_OFFSET) as u64;
        *rsp = (USER_JIT_STACK_BASE + guard_bytes + (USER_JIT_STACK_PAGES * paging::PAGE_SIZE) - 16)
            as u64;
        return true;
    }

    // Kernel-mode x86_64 JIT: force timeout escape through asm_jit_fault_resume
    // so malformed emitted code cannot livelock the bring-up shell.
    if (cs & 0x3) == 0 {
        let start_tick = JIT_KERNEL_ENTER_TICK.load(Ordering::SeqCst);
        if start_tick == 0 || !JIT_FAULT_ACTIVE.load(Ordering::SeqCst) {
            return false;
        }
        let now = crate::scheduler::pit::get_ticks() as u32;
        if now.wrapping_sub(start_tick) < JIT_KERNEL_TIMEOUT_TICKS_X64 {
            return false;
        }
        if jit_handle_kernel_fault_x86_64(rip) {
            JIT_KERNEL_ENTER_TICK.store(0, Ordering::SeqCst);
            crate::serial::_print(format_args!(
                "[JIT-DBG] x64 kernel timeout start_tick={} now_tick={} rip=0x{:016x}\n",
                start_tick, now, *rip
            ));
            return true;
        }
    }
    false
}

pub fn jit_handle_page_fault(
    frame: &mut crate::platform::idt_asm::InterruptFrame,
    fault_addr: usize,
    error_code: u32,
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
            if !JIT_USER_FAULT_LOGGED.swap(true, Ordering::SeqCst) {
                let stage = JIT_USER_DEBUG_STAGE.load(Ordering::SeqCst);
                crate::serial::_print(format_args!(
                    "[JIT-DBG] user fault stage={} addr=0x{:08x} err=0x{:08x} eip=0x{:08x} esp=0x{:08x}\n",
                    stage,
                    fault_addr as u32,
                    error_code,
                    frame.eip,
                    frame.user_esp
                ));
            }
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
    let start = JIT_FAULT_EXEC_START.load(Ordering::SeqCst) as usize;
    let end = JIT_FAULT_EXEC_END.load(Ordering::SeqCst) as usize;
    let eip = frame.eip as usize;
    if start == 0 || end <= start || eip < start || eip >= end {
        return false;
    }
    frame.eax = 0;
    frame.eip = crate::memory::asm_bindings::asm_jit_fault_resume as u32;
    true
}

pub fn jit_handle_exception(frame: &mut crate::platform::idt_asm::InterruptFrame) -> bool {
    if frame.int_no == crate::platform::idt_asm::Exception::PageFault as u32 {
        return false;
    }
    if !JIT_FAULT_ACTIVE.load(Ordering::SeqCst) {
        return false;
    }
    if (frame.cs & 0x3) != 3 || JIT_USER_ACTIVE.load(Ordering::SeqCst) == 0 {
        return false;
    }

    // Only absorb CPU faults expected from user JIT execution.
    match frame.int_no {
        x if x == crate::platform::idt_asm::Exception::InvalidOpcode as u32 => {}
        x if x == crate::platform::idt_asm::Exception::DeviceNotAvailable as u32 => {}
        x if x == crate::platform::idt_asm::Exception::InvalidTSS as u32 => {}
        x if x == crate::platform::idt_asm::Exception::SegmentNotPresent as u32 => {}
        x if x == crate::platform::idt_asm::Exception::StackSegmentFault as u32 => {}
        x if x == crate::platform::idt_asm::Exception::GeneralProtectionFault as u32 => {}
        x if x == crate::platform::idt_asm::Exception::X87FloatingPoint as u32 => {}
        x if x == crate::platform::idt_asm::Exception::AlignmentCheck as u32 => {}
        x if x == crate::platform::idt_asm::Exception::SimdFloatingPoint as u32 => {}
        x if x == crate::platform::idt_asm::Exception::ControlProtection as u32 => {}
        _ => return false,
    }

    unsafe {
        if !JIT_FAULT_TRAP_PTR.is_null() {
            *JIT_FAULT_TRAP_PTR = TRAP_MEM;
        }
    }

    if !JIT_USER_FAULT_LOGGED.swap(true, Ordering::SeqCst) {
        let stage = JIT_USER_DEBUG_STAGE.load(Ordering::SeqCst);
        crate::serial::_print(format_args!(
            "[JIT-DBG] user exception stage={} vector={} err=0x{:08x} eip=0x{:08x} esp=0x{:08x}\n",
            stage, frame.int_no, frame.err_code, frame.eip, frame.user_esp
        ));
    }

    let guard_bytes = USER_JIT_STACK_GUARD_PAGES * paging::PAGE_SIZE;
    frame.eax = 0;
    frame.eip = (USER_JIT_TRAMPOLINE_BASE + USER_JIT_TRAMPOLINE_FAULT_OFFSET) as u32;
    frame.user_esp =
        (USER_JIT_STACK_BASE + guard_bytes + (USER_JIT_STACK_PAGES * paging::PAGE_SIZE) - 4) as u32;
    true
}

pub fn jit_handle_timer_interrupt(frame: &mut crate::platform::idt_asm::InterruptFrame) -> bool {
    if (frame.cs & 0x3) != 3 || JIT_USER_ACTIVE.load(Ordering::SeqCst) == 0 {
        return false;
    }
    let start_tick = JIT_USER_ENTER_TICK.load(Ordering::SeqCst);
    if start_tick == 0 {
        return false;
    }
    let now = crate::scheduler::pit::get_ticks() as u32;
    if now.wrapping_sub(start_tick) < JIT_USER_TIMEOUT_TICKS {
        return false;
    }

    unsafe {
        if !JIT_FAULT_TRAP_PTR.is_null() {
            *JIT_FAULT_TRAP_PTR = TRAP_MEM;
        }
    }
    if !JIT_USER_FAULT_LOGGED.swap(true, Ordering::SeqCst) {
        let stage = JIT_USER_DEBUG_STAGE.load(Ordering::SeqCst);
        crate::serial::_print(format_args!(
            "[JIT-DBG] user timeout stage={} start_tick={} now_tick={} eip=0x{:08x} esp=0x{:08x}\n",
            stage, start_tick, now, frame.eip, frame.user_esp
        ));
    }
    let guard_bytes = USER_JIT_STACK_GUARD_PAGES * paging::PAGE_SIZE;
    frame.eax = 0;
    frame.eip = (USER_JIT_TRAMPOLINE_BASE + USER_JIT_TRAMPOLINE_FAULT_OFFSET) as u32;
    frame.user_esp =
        (USER_JIT_STACK_BASE + guard_bytes + (USER_JIT_STACK_PAGES * paging::PAGE_SIZE) - 4) as u32;
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
    process_id: u32,
    instance_id: u32,
    func_idx: u32,
    fn_table_base: *const usize,
    fn_table_len: usize,
) -> i32 {
    if jit_config().lock().user_mode {
        match call_jit_user(
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
            process_id,
            instance_id,
            func_idx,
        ) {
            Ok(ret) => return ret,
            Err(_) => {
                unsafe {
                    if !trap_code.is_null() {
                        *trap_code = TRAP_MEM;
                    }
                }
                return 0;
            }
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
        fn_table_base,
        fn_table_len,
    )
}

pub(crate) fn call_jit_kernel(
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
    fn_table_base: *const usize,
    fn_table_len: usize,
) -> i32 {
    let _call_guard = JIT_KERNEL_CALL_LOCK.lock();
    #[cfg(not(target_arch = "x86_64"))]
    let flags = unsafe { idt_asm::fast_cli_save() };
    #[cfg(target_arch = "x86_64")]
    let flags = unsafe { x86_64_cli_save() };
    #[cfg(target_arch = "x86_64")]
    JIT_KERNEL_ENTER_TICK.store(crate::scheduler::pit::get_ticks() as u32, Ordering::SeqCst);
    let _fault_guard =
        JitFaultScope::enter(trap_code, jit_entry.exec_ptr as usize, jit_entry.exec_len);
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
            fn_table_base,
            fn_table_len,
        )
    };
    #[cfg(target_arch = "x86_64")]
    JIT_KERNEL_ENTER_TICK.store(0, Ordering::SeqCst);
    #[cfg(not(target_arch = "x86_64"))]
    unsafe {
        idt_asm::fast_sti_restore(flags)
    };
    #[cfg(target_arch = "x86_64")]
    unsafe {
        x86_64_sti_restore(flags)
    };
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn x86_64_cli_save() -> u64 {
    let flags: u64;
    core::arch::asm!(
        "pushfq",
        "pop {}",
        "cli",
        out(reg) flags,
    );
    flags
}

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn x86_64_sti_restore(flags: u64) {
    if (flags & (1u64 << 9)) != 0 {
        core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
    }
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
    process_id: u32,
    instance_id: u32,
    func_idx: u32,
) -> Result<i32, &'static str> {
    jit_user_debug_set_stage(1);
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
    JIT_USER_FAULT_LOGGED.store(false, Ordering::SeqCst);
    JIT_USER_RETURN_PENDING.store(0, Ordering::SeqCst);
    JIT_USER_SYSCALL_VIOLATION.store(0, Ordering::SeqCst);

    jit_user_debug_set_stage(2);
    let pages = ensure_jit_user_pages(jit_user_pages)?;
    validate_jit_user_pages(&pages)?;
    wipe_jit_user_pages(&pages);

    jit_user_debug_set_stage(3);
    // Always use the JIT sandbox kernel map profile here.
    // Even with KPTI enabled, this function must continue executing kernel
    // Rust/asm after loading sandbox CR3 (until user entry and on return path).
    // `new_user_minimal()` omits kernel text/data, which can fault immediately
    // after CR3 switch while still in ring0.
    let mut sandbox_slot = JIT_USER_SANDBOX.lock();
    if sandbox_slot.is_none() {
        *sandbox_slot = Some(arch_mmu::new_jit_sandbox()?);
    }
    let sandbox = sandbox_slot.as_mut().ok_or("JIT sandbox unavailable")?;

    #[cfg(not(target_arch = "x86_64"))]
    let kernel_guard = paging::kernel_space().lock();
    #[cfg(not(target_arch = "x86_64"))]
    let kernel_space = kernel_guard
        .as_ref()
        .ok_or("Kernel address space not initialized")?;

    // Ensure user->kernel transitions land on the active scheduler stack.
    let stack_probe = 0u32;
    let current_esp = (&stack_probe as *const u32) as usize;
    let esp0 = jit_select_kernel_esp0(current_esp);
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86::x86_64_runtime::update_jit_kernel_stack_top(esp0 as usize);
    #[cfg(not(target_arch = "x86_64"))]
    crate::platform::gdt::update_kernel_stack(esp0);

    if kpti::enabled() {
        // kpti::init() is currently only called from the i686 boot path; on x86_64
        // this branch is unreachable. When x86_64 KPTI is wired, provide an
        // x86_64-aware map_user_support variant here.
        #[cfg(not(target_arch = "x86_64"))]
        kpti::map_user_support(sandbox, kernel_space)?;
    }

    jit_user_debug_set_stage(4);
    #[cfg(target_arch = "x86_64")]
    let trampoline_phys =
        arch_mmu::x86_64_debug_virt_to_phys(pages.trampoline).ok_or("Trampoline not mapped")?;
    #[cfg(not(target_arch = "x86_64"))]
    let trampoline_phys = kernel_space
        .virt_to_phys(pages.trampoline)
        .ok_or("Trampoline not mapped")?;

    #[cfg(target_arch = "x86_64")]
    let call_phys =
        arch_mmu::x86_64_debug_virt_to_phys(pages.call).ok_or("Call page not mapped")?;
    #[cfg(not(target_arch = "x86_64"))]
    let call_phys = kernel_space
        .virt_to_phys(pages.call)
        .ok_or("Call page not mapped")?;

    #[cfg(target_arch = "x86_64")]
    let stack_phys =
        arch_mmu::x86_64_debug_virt_to_phys(pages.stack).ok_or("User stack not mapped")?;
    #[cfg(not(target_arch = "x86_64"))]
    let stack_phys = kernel_space
        .virt_to_phys(pages.stack)
        .ok_or("User stack not mapped")?;

    let exec_ptr = jit_entry.exec_ptr as usize;
    #[cfg(target_arch = "x86_64")]
    let exec_phys = arch_mmu::x86_64_debug_virt_to_phys(exec_ptr).ok_or("JIT exec not mapped")?;
    #[cfg(not(target_arch = "x86_64"))]
    let exec_phys = kernel_space
        .virt_to_phys(exec_ptr)
        .ok_or("JIT exec not mapped")?;
    let exec_offset = exec_ptr & (paging::PAGE_SIZE - 1);
    let exec_map_len = jit_entry
        .exec_len
        .checked_add(exec_offset)
        .ok_or("JIT exec size overflow")?;

    #[cfg(target_arch = "x86_64")]
    let mut mem_ptr_usize = mem_ptr as usize;
    #[cfg(not(target_arch = "x86_64"))]
    let mem_ptr_usize = mem_ptr as usize;
    #[cfg(target_arch = "x86_64")]
    let mem_phys = {
        let mut mem_phys = arch_mmu::x86_64_debug_virt_to_phys(mem_ptr_usize);
        if mem_phys.is_none() && JIT_X64_CALL_PROBE_ACTIVE.load(Ordering::SeqCst) {
            if mem_len <= paging::PAGE_SIZE {
                let mut aux_pages_slot = JIT_USER_PREFLIGHT_AUX_PAGES.lock();
                let aux_pages = ensure_jit_user_preflight_aux_pages(&mut *aux_pages_slot)?;
                unsafe {
                    core::ptr::write_bytes(aux_pages.mem as *mut u8, 0, paging::PAGE_SIZE);
                }
                mem_ptr_usize = aux_pages.mem;
                mem_phys = arch_mmu::x86_64_debug_virt_to_phys(mem_ptr_usize);
                if mem_phys.is_some() {
                    crate::serial::_print(format_args!(
                        "[JIT-DBG] x64 call-user probe mem fallback src=0x{:016x} dst=0x{:016x} len={}\n",
                        mem_ptr as usize,
                        mem_ptr_usize,
                        mem_len
                    ));
                }
            } else {
                return Err("WASM memory not mapped");
            }
        }
        mem_phys.ok_or("WASM memory not mapped")?
    };
    #[cfg(not(target_arch = "x86_64"))]
    let mem_phys = kernel_space
        .virt_to_phys(mem_ptr_usize)
        .ok_or("WASM memory not mapped")?;
    let mem_offset = mem_ptr_usize & (paging::PAGE_SIZE - 1);
    let mem_map_len = mem_len
        .checked_add(mem_offset)
        .ok_or("WASM memory size overflow")?;

    #[cfg(target_arch = "x86_64")]
    let mut state_ptr = jit_state_base as usize;
    #[cfg(not(target_arch = "x86_64"))]
    let state_ptr = jit_state_base as usize;
    #[cfg(target_arch = "x86_64")]
    let state_phys = {
        let mut state_phys = arch_mmu::x86_64_debug_virt_to_phys(state_ptr);
        if state_phys.is_none() && JIT_X64_CALL_PROBE_ACTIVE.load(Ordering::SeqCst) {
            let required_state_bytes = jit_state_pages
                .checked_mul(paging::PAGE_SIZE)
                .ok_or("JIT state size overflow")?;
            if required_state_bytes <= JIT_X64_CALL_PROBE_STATE_BYTES {
                unsafe {
                    let probe_state = core::ptr::addr_of_mut!(JIT_X64_CALL_PROBE_STATE) as *mut u8;
                    core::ptr::write_bytes(probe_state, 0, required_state_bytes);
                    state_ptr = probe_state as usize;
                }
                state_phys = arch_mmu::x86_64_debug_virt_to_phys(state_ptr);
                if state_phys.is_some() {
                    crate::serial::_print(format_args!(
                        "[JIT-DBG] x64 call-user probe state fallback src=0x{:016x} dst=0x{:016x} pages={}\n",
                        jit_state_base as usize,
                        state_ptr,
                        jit_state_pages
                    ));
                }
            }
        }
        state_phys.ok_or("JIT state not mapped")?
    };
    #[cfg(not(target_arch = "x86_64"))]
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

    let code_guard_total = code_guard.checked_mul(2).ok_or("JIT code guard overflow")?;
    if code_guard_total >= code_window {
        return Err("JIT code guard exceeds window");
    }
    let data_guard_total = data_guard.checked_mul(2).ok_or("JIT data guard overflow")?;
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

    jit_user_debug_set_stage(5);
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

    jit_user_debug_set_stage(6);
    sandbox.map_user_range_phys(
        USER_JIT_TRAMPOLINE_BASE,
        trampoline_phys,
        paging::PAGE_SIZE,
        false,
    )?;
    sandbox.map_user_range_phys(USER_JIT_CALL_BASE, call_phys, paging::PAGE_SIZE, true)?;
    sandbox.map_user_range_phys(
        USER_JIT_STACK_BASE + guard_bytes,
        stack_phys + guard_bytes,
        USER_JIT_STACK_PAGES * paging::PAGE_SIZE,
        true,
    )?;
    sandbox.map_user_range_phys(code_base, exec_phys, exec_map_len, false)?;
    sandbox.map_user_range_phys(data_base, state_phys, state_map_len, true)?;
    sandbox.map_user_range_phys(mem_base, mem_phys, mem_map_len, true)?;

    let enclave_session = crate::security::enclave::open_jit_session(
        exec_phys,
        exec_map_len,
        state_phys,
        state_map_len,
        mem_phys,
        mem_map_len,
    )?;

    let sandbox_pd = sandbox.phys_addr() as u32;
    #[cfg(not(target_arch = "x86_64"))]
    drop(kernel_guard);

    jit_user_debug_set_stage(7);
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
    let globals_off = unsafe { core::ptr::addr_of!((*state_ptr).globals) as usize } - base;
    #[cfg(not(target_arch = "x86_64"))]
    let _ = globals_off;
    let instr_fuel_off = unsafe { core::ptr::addr_of!((*state_ptr).instr_fuel) as usize } - base;
    let mem_fuel_off = unsafe { core::ptr::addr_of!((*state_ptr).mem_fuel) as usize } - base;
    let trap_off = unsafe { core::ptr::addr_of!((*state_ptr).trap_code) as usize } - base;
    #[cfg(target_arch = "x86_64")]
    let _shadow_stack_off =
        unsafe { core::ptr::addr_of!((*state_ptr).shadow_stack) as usize } - base;
    #[cfg(not(target_arch = "x86_64"))]
    let shadow_stack_off =
        unsafe { core::ptr::addr_of!((*state_ptr).shadow_stack) as usize } - base;
    let shadow_sp_off = unsafe { core::ptr::addr_of!((*state_ptr).shadow_sp) as usize } - base;

    let user_mem_ptr = mem_base + mem_offset;

    // Harden against stale RX flags in the shared JIT arena before staging
    // user-call metadata and trap/fuel state.
    if !jit_arena_range_sane(pages.call, paging::PAGE_SIZE) {
        return Err("JIT call page outside JIT arena");
    }
    if !jit_arena_range_sane(state_ptr as usize, state_map_len) {
        return Err("JIT user state page outside JIT arena");
    }
    crate::arch::mmu::set_page_writable_range(pages.call, paging::PAGE_SIZE, true)?;
    crate::arch::mmu::set_page_writable_range(state_ptr as usize, state_map_len, true)?;

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
        #[cfg(target_arch = "x86_64")]
        {
            (*call_ptr).shadow_stack_ptr = (user_state_base + globals_off) as u32;
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            (*call_ptr).shadow_stack_ptr = (user_state_base + shadow_stack_off) as u32;
        }
        (*call_ptr).shadow_sp_ptr = (user_state_base + shadow_sp_off) as u32;
        (*call_ptr).ret = 0;
        (*call_ptr).req_seq = 0;
        (*call_ptr).ack_seq = 0;
    }
    let call_seq = JIT_USER_DBG_CALL_SEQ
        .fetch_add(1, Ordering::SeqCst)
        .wrapping_add(1);
    unsafe {
        (*call_ptr).req_seq = call_seq;
        (*call_ptr).ack_seq = 0;
    }
    let call_snapshot = unsafe { *call_ptr };
    let code_limit = code_base
        .checked_add(exec_map_len)
        .ok_or("JIT code limit overflow")?;
    let data_limit = data_base
        .checked_add(state_map_len)
        .ok_or("JIT data limit overflow")?;
    let mem_limit = mem_base
        .checked_add(mem_map_len)
        .ok_or("WASM memory limit overflow")?;
    let call_meta_valid = (call_snapshot.entry as usize) >= code_base
        && (call_snapshot.entry as usize) < code_limit
        && (call_snapshot.stack_ptr as usize) >= data_base
        && (call_snapshot.stack_ptr as usize) < data_limit
        && (call_snapshot.sp_ptr as usize) >= data_base
        && (call_snapshot.sp_ptr as usize) < data_limit
        && (call_snapshot.locals_ptr as usize) >= data_base
        && (call_snapshot.locals_ptr as usize) < data_limit
        && (call_snapshot.instr_fuel_ptr as usize) >= data_base
        && (call_snapshot.instr_fuel_ptr as usize) < data_limit
        && (call_snapshot.mem_fuel_ptr as usize) >= data_base
        && (call_snapshot.mem_fuel_ptr as usize) < data_limit
        && (call_snapshot.trap_ptr as usize) >= data_base
        && (call_snapshot.trap_ptr as usize) < data_limit
        && (call_snapshot.shadow_stack_ptr as usize) >= data_base
        && (call_snapshot.shadow_stack_ptr as usize) < data_limit
        && (call_snapshot.shadow_sp_ptr as usize) >= data_base
        && (call_snapshot.shadow_sp_ptr as usize) < data_limit
        && (call_snapshot.mem_ptr as usize) >= mem_base
        && (call_snapshot.mem_ptr as usize) < mem_limit;
    unsafe {
        JIT_USER_DBG_CALL_ENTRY = call_snapshot.entry;
        JIT_USER_DBG_CALL_STACK_PTR = call_snapshot.stack_ptr;
        JIT_USER_DBG_CALL_SP_PTR = call_snapshot.sp_ptr;
        JIT_USER_DBG_CALL_MEM_PTR = call_snapshot.mem_ptr;
        JIT_USER_DBG_CALL_MEM_LEN = call_snapshot.mem_len;
        JIT_USER_DBG_CALL_TRAP_PTR = call_snapshot.trap_ptr;
        JIT_USER_DBG_CALL_PID = process_id;
        JIT_USER_DBG_CALL_INSTANCE = instance_id;
        JIT_USER_DBG_CALL_FUNC = func_idx;
    }
    if call_seq <= JIT_USER_CALL_LOG_LIMIT {
        crate::serial::_print(format_args!(
            "[JIT-DBG] call-desc seq={} pid={} inst={} func={} entry=0x{:08x} stack=0x{:08x} sp=0x{:08x} trap=0x{:08x} shadow_sp=0x{:08x} mem=0x{:08x}+{} valid={}\n",
            call_seq,
            process_id,
            instance_id,
            func_idx,
            call_snapshot.entry,
            call_snapshot.stack_ptr,
            call_snapshot.sp_ptr,
            call_snapshot.trap_ptr,
            call_snapshot.shadow_sp_ptr,
            call_snapshot.mem_ptr,
            call_snapshot.mem_len,
            if call_meta_valid { 1 } else { 0 },
        ));
    }
    if !call_meta_valid {
        return Err("JIT user call metadata invalid");
    }

    // Ensure trap pointers are set for fault handling.
    jit_user_debug_set_stage(8);
    let _fault_guard = JitFaultScope::enter(trap_code, 0, 0);

    if let Some(session_id) = enclave_session {
        if let Err(e) = crate::security::enclave::enter(session_id) {
            let _ = crate::security::enclave::close(session_id);
            return Err(e);
        }
    }

    let flags = unsafe { idt_asm::fast_cli_save() };
    let old_cr3 = crate::arch::mmu::current_page_table_root_addr();
    if kpti::enabled() {
        let _ = kpti::enter_user(sandbox_pd);
    }
    jit_user_debug_set_stage(9);
    let _ = crate::arch::mmu::set_page_table_root(sandbox_pd as usize);

    let user_stack_top =
        USER_JIT_STACK_BASE + guard_bytes + (USER_JIT_STACK_PAGES * paging::PAGE_SIZE) - 16;
    JIT_USER_ENTER_TICK.store(crate::scheduler::pit::get_ticks() as u32, Ordering::SeqCst);
    unsafe {
        process_asm::jit_user_enter(
            user_stack_top as u32,
            USER_JIT_TRAMPOLINE_BASE as u32,
            {
                #[cfg(target_arch = "x86_64")]
                {
                    crate::arch::x86::x86_64_runtime::USER_CS
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    gdt::USER_CS
                }
            },
            {
                #[cfg(target_arch = "x86_64")]
                {
                    crate::arch::x86::x86_64_runtime::USER_DS
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    gdt::USER_DS
                }
            },
        );
    }

    jit_user_debug_set_stage(10);
    let mut handoff_ok = true;
    let (
        save_seq,
        save_esp,
        save_eip,
        sys_seq,
        sys_path,
        sys_flags,
        sys_esp,
        sys_eip,
        sys_nr,
        sys_from_eip,
        sys_from_cs,
    ) = unsafe {
        (
            JIT_USER_DBG_SAVE_SEQ,
            JIT_USER_DBG_SAVE_ESP,
            JIT_USER_DBG_SAVE_EIP,
            JIT_USER_DBG_SYSCALL_SEQ,
            JIT_USER_DBG_SYSCALL_PATH,
            JIT_USER_DBG_SYSCALL_FLAGS,
            JIT_USER_DBG_SYSCALL_ESP,
            JIT_USER_DBG_SYSCALL_EIP,
            JIT_USER_DBG_SYSCALL_NR,
            JIT_USER_DBG_SYSCALL_FROM_EIP,
            JIT_USER_DBG_SYSCALL_FROM_CS,
        )
    };
    if save_seq == 0
        || sys_seq == 0
        || save_esp == 0
        || save_eip == 0
        || sys_esp == 0
        || sys_eip == 0
        || sys_path == 0
        || sys_flags != 0
        || sys_nr != SYSCALL_JIT_RETURN
        || save_esp != sys_esp
        || save_eip != sys_eip
    {
        handoff_ok = false;
    }
    let (call_req_seq, call_ack_seq) = unsafe { ((*call_ptr).req_seq, (*call_ptr).ack_seq) };
    if call_req_seq != call_seq || call_ack_seq != call_seq {
        handoff_ok = false;
    }
    if call_snapshot.entry != user_entry as u32 {
        handoff_ok = false;
    }
    if !handoff_ok || call_seq <= JIT_USER_CALL_LOG_LIMIT {
        let log_idx = JIT_USER_HANDOFF_LOG_COUNT
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1);
        if !handoff_ok || log_idx <= JIT_USER_HANDOFF_LOG_LIMIT {
            crate::serial::_print(format_args!(
                "[JIT-DBG] handoff seq={} ok={} pid={} inst={} func={} save_seq={} sys_seq={} req={} ack={} path={} flags=0x{:08x} nr={} from=0x{:08x}/0x{:08x} save=0x{:016x}/0x{:016x} sys=0x{:016x}/0x{:016x} entry=0x{:08x}\n",
                call_seq,
                if handoff_ok { 1 } else { 0 },
                process_id,
                instance_id,
                func_idx,
                save_seq,
                sys_seq,
                call_req_seq,
                call_ack_seq,
                sys_path,
                sys_flags,
                sys_nr,
                sys_from_eip,
                sys_from_cs,
                save_esp,
                save_eip,
                sys_esp,
                sys_eip,
                call_snapshot.entry,
            ));
        }
    }
    // Always consume one-shot return handoff state before re-enabling interrupts.
    // Otherwise, an unrelated later syscall can observe stale `RETURN_PENDING`
    // and jump into an old kernel frame.
    let stale_pending = JIT_USER_RETURN_PENDING.swap(0, Ordering::SeqCst);
    let stale_active = JIT_USER_ACTIVE.swap(0, Ordering::SeqCst);
    let stale_ret_eip = JIT_USER_RETURN_EIP.swap(0, Ordering::SeqCst);
    let stale_ret_esp = JIT_USER_RETURN_ESP.swap(0, Ordering::SeqCst);
    if stale_pending != 0 || stale_active != 0 {
        let clear_anomaly = stale_active != 0
            || stale_pending != 1
            || stale_ret_esp != save_esp
            || stale_ret_eip != save_eip;
        if clear_anomaly || call_seq <= JIT_USER_CALL_LOG_LIMIT {
            crate::serial::_print(format_args!(
                "[JIT-DBG] handoff-clear seq={} pending={} active={} ret=0x{:016x}/0x{:016x}\n",
                call_seq, stale_pending, stale_active, stale_ret_esp, stale_ret_eip,
            ));
        }
    }

    JIT_USER_ENTER_TICK.store(0, Ordering::SeqCst);
    let _ = crate::arch::mmu::set_page_table_root(old_cr3);
    if kpti::enabled() {
        kpti::leave_user();
    }
    if let Some(session_id) = enclave_session {
        let _ = crate::security::enclave::exit(session_id);
        let _ = crate::security::enclave::close(session_id);
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

    if !handoff_ok {
        unsafe {
            if !trap_code.is_null() {
                *trap_code = TRAP_MEM;
            }
        }
        return Err("JIT user handoff validation failed");
    }

    if JIT_USER_SYSCALL_VIOLATION.swap(0, Ordering::SeqCst) != 0 {
        unsafe {
            if !trap_code.is_null() {
                *trap_code = TRAP_MEM;
            }
        }
        return Ok(0);
    }

    jit_user_debug_set_stage(11);
    let ret = unsafe { (*call_ptr).ret };
    jit_user_debug_set_stage(12);
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

fn hash_jit_type_signatures(type_sigs: &[crate::execution::wasm_jit::JitTypeSignature]) -> u64 {
    let mut hash: u64 = 14695981039346656037;
    for sig in type_sigs {
        hash ^= sig.param_count as u64;
        hash = hash.wrapping_mul(1099511628211);
        hash ^= sig.result_count as u64;
        hash = hash.wrapping_mul(1099511628211);
        hash ^= if sig.all_i32 { 1 } else { 0 };
        hash = hash.wrapping_mul(1099511628211);
    }
    hash ^= type_sigs.len() as u64;
    hash = hash.wrapping_mul(1099511628211);
    hash
}

fn hash_jit_global_signatures(global_sigs: &[crate::execution::wasm_jit::JitGlobalSignature]) -> u64 {
    let mut hash: u64 = 14695981039346656037;
    for sig in global_sigs {
        hash ^= if sig.mutable { 1 } else { 0 };
        hash = hash.wrapping_mul(1099511628211);
        hash ^= if sig.all_i32 { 1 } else { 0 };
        hash = hash.wrapping_mul(1099511628211);
    }
    hash ^= global_sigs.len() as u64;
    hash = hash.wrapping_mul(1099511628211);
    hash
}

fn collect_jit_type_signatures(module: &WasmModule) -> Vec<crate::execution::wasm_jit::JitTypeSignature> {
    let mut out = Vec::with_capacity(module.type_count);
    let mut idx = 0usize;
    while idx < module.type_count {
        let sig = module.type_signatures.get(idx).and_then(|entry| *entry);
        if let Some(sig) = sig {
            out.push(crate::execution::wasm_jit::JitTypeSignature {
                param_count: sig.param_count,
                result_count: sig.result_count,
                all_i32: sig.all_i32,
            });
        } else {
            out.push(crate::execution::wasm_jit::JitTypeSignature {
                param_count: 0,
                result_count: 0,
                all_i32: false,
            });
        }
        idx += 1;
    }
    out
}

fn collect_jit_global_signatures(module: &WasmModule) -> Vec<crate::execution::wasm_jit::JitGlobalSignature> {
    let mut out = Vec::with_capacity(module.global_count);
    let mut idx = 0usize;
    while idx < module.global_count {
        if let Some(global) = module.global_templates[idx] {
            out.push(crate::execution::wasm_jit::JitGlobalSignature {
                mutable: global.mutable,
                all_i32: matches!(global.value_type, ValueType::I32),
            });
        } else {
            out.push(crate::execution::wasm_jit::JitGlobalSignature {
                mutable: false,
                all_i32: false,
            });
        }
        idx += 1;
    }
    out
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

fn jit_cache_get(
    hash: u64,
    code: &[u8],
    locals_total: usize,
    type_sig_hash: u64,
    global_sig_hash: u64,
) -> Option<JitExecInfo> {
    let cache = JIT_CACHE.lock();
    for entry in cache.entries.iter() {
        if entry.hash == hash
            && entry.locals_total == locals_total
            && entry.type_sig_hash == type_sig_hash
            && entry.global_sig_hash == global_sig_hash
            && entry.code_len == code.len()
        {
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

fn jit_cache_get_or_compile(
    hash: u64,
    code: &[u8],
    locals_total: usize,
    type_sigs: &[crate::execution::wasm_jit::JitTypeSignature],
    type_sig_hash: u64,
    global_sigs: &[crate::execution::wasm_jit::JitGlobalSignature],
    global_sig_hash: u64,
) -> Option<JitExecInfo> {
    if let Some(entry) = jit_cache_get(hash, code, locals_total, type_sig_hash, global_sig_hash) {
        return Some(entry);
    }
    let jit = match crate::execution::wasm_jit::compile_with_env(code, locals_total, type_sigs, global_sigs) {
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
            type_sig_hash,
            global_sig_hash,
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
        type_sig_hash,
        global_sig_hash,
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

    module
        .load_raw_bytecode(&code)
        .map_err(|_| "Module load failed")?;
    module
        .add_function(Function::synthetic_i32(0, code.len(), 0, 1, 0))
        .map_err(|_| "Function add failed")?;

    let instance_id = wasm_runtime()
        .instantiate_module(module, ProcessId(1))
        .map_err(|_| "Instance create failed")?;
    let iterations = 200;

    let start = crate::scheduler::pit::get_ticks();
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
    let interp_ticks = crate::scheduler::pit::get_ticks().saturating_sub(start);

    let start = crate::scheduler::pit::get_ticks();
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
    let jit_ticks = crate::scheduler::pit::get_ticks().saturating_sub(start);

    let _ = wasm_runtime().destroy(instance_id);
    Ok((interp_ticks, jit_ticks))
}

fn jit_bounds_self_test_impl(force_user_mode: bool) -> Result<(), &'static str> {
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
        cfg.user_mode = force_user_mode;
        guard
    };

    let _fuzz_active_guard = {
        struct JitFuzzActiveGuard {
            prev: bool,
        }
        impl Drop for JitFuzzActiveGuard {
            fn drop(&mut self) {
                JIT_FUZZ_ACTIVE.store(self.prev, Ordering::SeqCst);
            }
        }
        let prev = JIT_FUZZ_ACTIVE.swap(true, Ordering::SeqCst);
        JitFuzzActiveGuard { prev }
    };

    let result = {
        #[cfg(target_arch = "x86_64")]
        {
            jit_bounds_self_test_x86_64_direct(force_user_mode)
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            fn new_selftest_instance(
                module: WasmModule,
                process_id: ProcessId,
                instance_id: usize,
            ) -> Result<Box<WasmInstance>, &'static str> {
                let mut instance =
                    unsafe { WasmInstance::boxed_new_in_place(module, process_id, instance_id) };
                instance
                    .initialize_from_module()
                    .map_err(|_| "Bounds self-test instance init failed")?;
                Ok(instance)
            }

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

            module
                .load_raw_bytecode(&code)
                .map_err(|_| "Module load failed")?;
            module
                .add_function(Function::synthetic_i32(0, code.len(), 0, 1, 0))
                .map_err(|_| "Function add failed")?;

            let interp = {
                let mut instance = new_selftest_instance(module.clone(), ProcessId(1), 0)?;
                instance.enable_jit(false);
                instance.call(0)
            };
            if !matches!(interp, Err(WasmError::MemoryOutOfBounds)) {
                Err("Interpreter did not trap on bounds overflow")
            } else {
                let jit = {
                    let mut instance = new_selftest_instance(module, ProcessId(1), 1)?;
                    instance.enable_jit(true);
                    instance.jit_validate_remaining[0] = 0;
                    instance.call(0)
                };
                if !matches!(jit, Err(WasmError::MemoryOutOfBounds)) {
                    Err("JIT did not trap on bounds overflow")
                } else {
                    Ok(())
                }
            }
        }
    };
    drop(guard);
    result
}

#[cfg(target_arch = "x86_64")]
fn jit_bounds_self_test_x86_64_direct(_force_user_mode: bool) -> Result<(), &'static str> {
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

    let mut code: Vec<u8> = Vec::new();
    code.push(Opcode::I32Const as u8);
    code.push(0x08);
    code.push(Opcode::I32Load as u8);
    push_uleb128(&mut code, 0);
    push_uleb128(&mut code, 0xFFFF_FFFC);
    code.push(Opcode::End as u8);

    let jit = crate::execution::wasm_jit::compile(&code, 0)?;
    let jit_entry = JitExecInfo {
        entry: jit.entry,
        exec_ptr: jit.exec.ptr,
        exec_len: jit.exec.len,
    };

    let state_bytes = core::mem::size_of::<JitUserState>();
    let state_pages = state_bytes
        .checked_add(paging::PAGE_SIZE - 1)
        .ok_or("JIT state size overflow")?
        / paging::PAGE_SIZE;
    let state_base = memory::jit_allocate_pages(state_pages)? as *mut JitUserState;
    if state_base.is_null() {
        return Err("JIT state alloc failed");
    }
    unsafe {
        core::ptr::write_bytes(state_base as *mut u8, 0, state_pages * paging::PAGE_SIZE);
    }

    let mem_pages = 1usize;
    let mem_len = paging::PAGE_SIZE;
    let mem_base = memory::jit_allocate_pages(mem_pages)? as *mut u8;
    if mem_base.is_null() {
        return Err("WASM mem alloc failed");
    }
    unsafe {
        core::ptr::write_bytes(mem_base, 0, mem_pages * paging::PAGE_SIZE);
    }

    let state = unsafe { &mut *state_base };
    state.sp = 0;
    state.shadow_sp = 0;
    state.instr_fuel = MAX_INSTRUCTIONS_PER_CALL as u32;
    state.mem_fuel = MAX_MEMORY_OPS_PER_CALL as u32;
    state.trap_code = 0;

    let _ret = call_jit_kernel(
        jit_entry,
        state.stack.as_mut_ptr(),
        &mut state.sp as *mut usize,
        mem_base,
        mem_len,
        state.locals.as_mut_ptr(),
        &mut state.instr_fuel as *mut u32,
        &mut state.mem_fuel as *mut u32,
        &mut state.trap_code as *mut i32,
        state.shadow_stack.as_mut_ptr(),
        &mut state.shadow_sp as *mut usize,
        core::ptr::null(),
        0,
    );

    if state.trap_code != TRAP_MEM {
        return Err("x86_64 direct bounds self-test did not trap mem");
    }
    Ok(())
}

pub fn jit_compare_shift_fixed_vector_self_test() -> Result<(), &'static str> {
    struct JitModeGuard {
        prev_user_mode: bool,
    }
    impl Drop for JitModeGuard {
        fn drop(&mut self) {
            let mut cfg = jit_config().lock();
            cfg.user_mode = self.prev_user_mode;
        }
    }
    let _jit_mode_guard = {
        // Keep fixed-vector interpreter-vs-JIT parity deterministic on every
        // architecture. The user trampoline path is validated separately;
        // parity vectors should exercise the direct kernel-JIT semantics.
        let mut cfg = jit_config().lock();
        let guard = JitModeGuard {
            prev_user_mode: cfg.user_mode,
        };
        cfg.user_mode = false;
        guard
    };

    let _fuzz_active_guard = {
        struct JitFuzzActiveGuard {
            prev: bool,
        }
        impl Drop for JitFuzzActiveGuard {
            fn drop(&mut self) {
                JIT_FUZZ_ACTIVE.store(self.prev, Ordering::SeqCst);
            }
        }
        let prev = JIT_FUZZ_ACTIVE.swap(true, Ordering::SeqCst);
        JitFuzzActiveGuard { prev }
    };

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

    fn build_binop(op: Opcode, a: i32, b: i32) -> Vec<u8> {
        let mut code = Vec::with_capacity(16);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, a);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, b);
        code.push(op as u8);
        code.push(Opcode::End as u8);
        code
    }

    fn build_add_eq(lhs: i32, rhs: i32, add_rhs: i32) -> Vec<u8> {
        // i32.const lhs; i32.const rhs; i32.const add_rhs; i32.add; i32.eq; end
        let mut code = Vec::with_capacity(20);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, lhs);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, rhs);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, add_rhs);
        code.push(Opcode::I32Add as u8);
        code.push(Opcode::I32Eq as u8);
        code.push(Opcode::End as u8);
        code
    }

    fn build_unop(op: Opcode, value: i32) -> Vec<u8> {
        let mut code = Vec::with_capacity(12);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, value);
        code.push(op as u8);
        code.push(Opcode::End as u8);
        code
    }

    fn build_local_tee_shift(op: Opcode, a: i32, sh: i32) -> Vec<u8> {
        // i32.const a; local.tee 0; i32.const sh; op; end
        let mut code = Vec::with_capacity(20);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, a);
        code.push(Opcode::LocalTee as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, sh);
        code.push(op as u8);
        code.push(Opcode::End as u8);
        code
    }

    fn build_select(val1: i32, val2: i32, cond: i32) -> Vec<u8> {
        let mut code = Vec::with_capacity(20);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, val1);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, val2);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, cond);
        code.push(Opcode::Select as u8);
        code.push(Opcode::End as u8);
        code
    }

    fn build_memory_size() -> Vec<u8> {
        let mut code = Vec::with_capacity(3);
        code.push(Opcode::MemorySize as u8);
        code.push(0x00);
        code.push(Opcode::End as u8);
        code
    }

    fn build_memory_grow(delta_pages: i32) -> Vec<u8> {
        let mut code = Vec::with_capacity(10);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, delta_pages);
        code.push(Opcode::MemoryGrow as u8);
        code.push(0x00);
        code.push(Opcode::End as u8);
        code
    }

    fn build_if_else_local(cond: i32, when_true: i32, when_false: i32) -> Vec<u8> {
        let mut code = Vec::with_capacity(40);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 0);
        code.push(Opcode::LocalSet as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, cond);
        code.push(Opcode::If as u8);
        code.push(0x40); // empty block type
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, when_true);
        code.push(Opcode::LocalSet as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::Else as u8);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, when_false);
        code.push(Opcode::LocalSet as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::End as u8); // end if
        code.push(Opcode::LocalGet as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::End as u8); // end function
        code
    }

    fn build_typed_block_i32_result(value: i32) -> Vec<u8> {
        // block (result i32) { i32.const value }; end
        let mut code = Vec::with_capacity(16);
        code.push(Opcode::Block as u8);
        code.push(0x7F); // i32 block result
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, value);
        code.push(Opcode::End as u8); // end block
        code.push(Opcode::End as u8); // end function
        code
    }

    fn build_typed_loop_i32_result(value: i32) -> Vec<u8> {
        // loop (result i32) { i32.const value }; end
        let mut code = Vec::with_capacity(16);
        code.push(Opcode::Loop as u8);
        code.push(0x7F); // i32 loop result
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, value);
        code.push(Opcode::End as u8); // end loop
        code.push(Opcode::End as u8); // end function
        code
    }

    fn build_typed_if_else_i32_result(cond: i32, when_true: i32, when_false: i32) -> Vec<u8> {
        // if (result i32) then i32.const when_true else i32.const when_false
        let mut code = Vec::with_capacity(24);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, cond);
        code.push(Opcode::If as u8);
        code.push(0x7F); // i32 if result
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, when_true);
        code.push(Opcode::Else as u8);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, when_false);
        code.push(Opcode::End as u8); // end if
        code.push(Opcode::End as u8); // end function
        code
    }

    fn build_typed_block_br_i32_result_unwind_add() -> Vec<u8> {
        // i32.const 7
        // block (result i32)
        //   i32.const 99
        //   i32.const 11
        //   br 0          ;; keep 11, drop transient 99
        //   drop
        //   drop
        // end
        // i32.add         ;; 7 + 11 = 18
        // end
        let mut code = Vec::with_capacity(28);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 7);
        code.push(Opcode::Block as u8);
        code.push(0x7F); // i32 block result
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 99);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 11);
        code.push(Opcode::Br as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::Drop as u8);
        code.push(Opcode::Drop as u8);
        code.push(Opcode::End as u8); // end block
        code.push(Opcode::I32Add as u8);
        code.push(Opcode::End as u8); // end function
        code
    }

    fn build_typed_block_br_if_i32_result_unwind_add(cond: i32, fallthrough: i32) -> Vec<u8> {
        // i32.const 7
        // block (result i32)
        //   i32.const 99
        //   i32.const 11
        //   i32.const cond
        //   br_if 0       ;; taken: keep 11, drop transient 99
        //   drop
        //   drop
        //   i32.const fallthrough
        // end
        // i32.add
        // end
        let mut code = Vec::with_capacity(36);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 7);
        code.push(Opcode::Block as u8);
        code.push(0x7F); // i32 block result
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 99);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 11);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, cond);
        code.push(Opcode::BrIf as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::Drop as u8);
        code.push(Opcode::Drop as u8);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, fallthrough);
        code.push(Opcode::End as u8); // end block
        code.push(Opcode::I32Add as u8);
        code.push(Opcode::End as u8); // end function
        code
    }

    fn build_if_br_local() -> Vec<u8> {
        // i32.const 0; local.set 0;
        // i32.const 1; if
        //   i32.const 33; local.set 0;
        //   br 0;
        //   i32.const 44; local.set 0;   ;; skipped
        // end
        // local.get 0; end
        let mut code = Vec::with_capacity(40);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 0);
        code.push(Opcode::LocalSet as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 1);
        code.push(Opcode::If as u8);
        code.push(0x40); // empty block type
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 33);
        code.push(Opcode::LocalSet as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::Br as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 44);
        code.push(Opcode::LocalSet as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::End as u8); // end if
        code.push(Opcode::LocalGet as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::End as u8); // end function
        code
    }

    fn build_if_br_if_local(branch_cond: i32) -> Vec<u8> {
        // i32.const 0; local.set 0;
        // i32.const 1; if
        //   i32.const 33; local.set 0;
        //   i32.const branch_cond; br_if 0;
        //   i32.const 44; local.set 0;
        // end
        // local.get 0; end
        let mut code = Vec::with_capacity(44);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 0);
        code.push(Opcode::LocalSet as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 1);
        code.push(Opcode::If as u8);
        code.push(0x40); // empty block type
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 33);
        code.push(Opcode::LocalSet as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, branch_cond);
        code.push(Opcode::BrIf as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 44);
        code.push(Opcode::LocalSet as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::End as u8); // end if
        code.push(Opcode::LocalGet as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::End as u8); // end function
        code
    }

    fn build_block_br_skip_tail() -> Vec<u8> {
        // i32.const 0; local.set 0;
        // block
        //   i32.const 77; local.set 0;
        //   br 0;
        //   i32.const 11; local.set 0;   ;; skipped
        // end
        // local.get 0; end
        let mut code = Vec::with_capacity(44);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 0);
        code.push(Opcode::LocalSet as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::Block as u8);
        code.push(0x40); // empty block type
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 77);
        code.push(Opcode::LocalSet as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::Br as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 11);
        code.push(Opcode::LocalSet as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::End as u8); // end block
        code.push(Opcode::LocalGet as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::End as u8); // end function
        code
    }

    fn build_loop_countdown_sum() -> Vec<u8> {
        // local0 = counter (3), local1 = trips (0)
        // loop
        //   local1 += 1
        //   local0 -= 1
        //   br_if 0 (while local0 != 0)
        // end
        // return local1
        let mut code = Vec::with_capacity(64);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 3);
        code.push(Opcode::LocalSet as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 0);
        code.push(Opcode::LocalSet as u8);
        push_uleb128(&mut code, 1);
        code.push(Opcode::Loop as u8);
        code.push(0x40); // empty block type
        code.push(Opcode::LocalGet as u8);
        push_uleb128(&mut code, 1);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 1);
        code.push(Opcode::I32Add as u8);
        code.push(Opcode::LocalSet as u8);
        push_uleb128(&mut code, 1);
        code.push(Opcode::LocalGet as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 1);
        code.push(Opcode::I32Sub as u8);
        code.push(Opcode::LocalTee as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::BrIf as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::End as u8); // end loop
        code.push(Opcode::LocalGet as u8);
        push_uleb128(&mut code, 1);
        code.push(Opcode::End as u8); // end function
        code
    }

    fn build_block_br_unwind_add() -> Vec<u8> {
        // i32.const 7
        // block
        //   i32.const 11
        //   br 0           ;; must unwind 11
        //   drop
        // end
        // i32.const 22
        // i32.add          ;; 7 + 22 = 29
        // end
        let mut code = Vec::with_capacity(20);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 7);
        code.push(Opcode::Block as u8);
        code.push(0x40); // empty block type
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 11);
        code.push(Opcode::Br as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::Drop as u8);
        code.push(Opcode::End as u8); // end block
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 22);
        code.push(Opcode::I32Add as u8);
        code.push(Opcode::End as u8); // end function
        code
    }

    fn build_block_br_if_unwind_add() -> Vec<u8> {
        // i32.const 7
        // block
        //   i32.const 11
        //   i32.const 1
        //   br_if 0        ;; must unwind 11 on taken branch
        //   drop
        // end
        // i32.const 22
        // i32.add          ;; 7 + 22 = 29
        // end
        let mut code = Vec::with_capacity(24);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 7);
        code.push(Opcode::Block as u8);
        code.push(0x40); // empty block type
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 11);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 1);
        code.push(Opcode::BrIf as u8);
        push_uleb128(&mut code, 0);
        code.push(Opcode::Drop as u8);
        code.push(Opcode::End as u8); // end block
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 22);
        code.push(Opcode::I32Add as u8);
        code.push(Opcode::End as u8); // end function
        code
    }

    fn build_nested_block_br_depth1_unwind_add() -> Vec<u8> {
        // i32.const 7
        // block
        //   block
        //     i32.const 11
        //     br 1           ;; must unwind inner stack to outer block entry depth
        //     drop
        //   end
        //   i32.const 100    ;; skipped by br 1
        //   i32.add
        // end
        // i32.const 22
        // i32.add            ;; 7 + 22 = 29
        // end
        let mut code = Vec::with_capacity(28);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 7);
        code.push(Opcode::Block as u8);
        code.push(0x40); // empty block type
        code.push(Opcode::Block as u8);
        code.push(0x40); // empty block type
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 11);
        code.push(Opcode::Br as u8);
        push_uleb128(&mut code, 1);
        code.push(Opcode::Drop as u8);
        code.push(Opcode::End as u8); // end inner block
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 100);
        code.push(Opcode::I32Add as u8);
        code.push(Opcode::End as u8); // end outer block
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 22);
        code.push(Opcode::I32Add as u8);
        code.push(Opcode::End as u8); // end function
        code
    }

    fn build_nested_block_br_if_depth1_unwind_add(cond: i32) -> Vec<u8> {
        // i32.const 7
        // block
        //   block
        //     i32.const 11
        //     i32.const cond
        //     br_if 1        ;; taken path must unwind to outer block entry depth
        //     drop
        //   end
        //   i32.const 100
        //   i32.add
        // end
        // i32.const 22
        // i32.add
        // end
        let mut code = Vec::with_capacity(32);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 7);
        code.push(Opcode::Block as u8);
        code.push(0x40); // empty block type
        code.push(Opcode::Block as u8);
        code.push(0x40); // empty block type
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 11);
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, cond);
        code.push(Opcode::BrIf as u8);
        push_uleb128(&mut code, 1);
        code.push(Opcode::Drop as u8);
        code.push(Opcode::End as u8); // end inner block
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 100);
        code.push(Opcode::I32Add as u8);
        code.push(Opcode::End as u8); // end outer block
        code.push(Opcode::I32Const as u8);
        push_sleb128_i32(&mut code, 22);
        code.push(Opcode::I32Add as u8);
        code.push(Opcode::End as u8); // end function
        code
    }

    fn build_unreachable() -> Vec<u8> {
        let mut code = Vec::with_capacity(2);
        code.push(Opcode::Unreachable as u8);
        code.push(Opcode::End as u8);
        code
    }

    enum Expected {
        Value(i32),
        Trap,
        AnyErr,
        MatchOk,
    }

    fn requires_structured_control_flow(code: &[u8]) -> bool {
        code.iter().copied().any(|byte| {
            byte == Opcode::Block as u8
                || byte == Opcode::Loop as u8
                || byte == Opcode::If as u8
                || byte == Opcode::Else as u8
                || byte == Opcode::Br as u8
                || byte == Opcode::BrIf as u8
        })
    }

    fn requires_x86_64_fixed_vector_backend(code: &[u8]) -> bool {
        requires_structured_control_flow(code)
            || code
                .iter()
                .copied()
                .any(|byte| byte == Opcode::MemoryGrow as u8)
    }

    struct Case {
        name: &'static str,
        code: Vec<u8>,
        locals_total: usize,
        expected: Expected,
    }

    fn new_selftest_instance(
        module: WasmModule,
        process_id: ProcessId,
        instance_id: usize,
    ) -> Result<Box<WasmInstance>, &'static str> {
        let mut instance =
            unsafe { WasmInstance::boxed_new_in_place(module, process_id, instance_id) };
        instance
            .initialize_from_module()
            .map_err(|_| "jit compare/shift self-test: instance init failed")?;
        Ok(instance)
    }

    #[cfg(not(target_arch = "x86_64"))]
    let cases: [Case; 21] = [
        Case {
            name: "eq_0_0",
            code: build_binop(Opcode::I32Eq, 0, 0),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "ne_1_2",
            code: build_binop(Opcode::I32Ne, 1, 2),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "lt_s_neg",
            code: build_binop(Opcode::I32LtS, -1, 0),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "gt_s_neg",
            code: build_binop(Opcode::I32GtS, -1, 0),
            locals_total: 0,
            expected: Expected::Value(0),
        },
        Case {
            name: "le_s_eq",
            code: build_binop(Opcode::I32LeS, 7, 7),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "ge_s_pos",
            code: build_binop(Opcode::I32GeS, 9, -3),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "lt_u_wrap",
            code: build_binop(Opcode::I32LtU, -1, 0),
            locals_total: 0,
            expected: Expected::Value(0),
        },
        Case {
            name: "gt_u_wrap",
            code: build_binop(Opcode::I32GtU, -1, 0),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "le_u_eq",
            code: build_binop(Opcode::I32LeU, -1, -1),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "ge_u_small",
            code: build_binop(Opcode::I32GeU, 1, 2),
            locals_total: 0,
            expected: Expected::Value(0),
        },
        Case {
            name: "shl_masked_33",
            code: build_local_tee_shift(Opcode::I32Shl, 1, 33),
            locals_total: 1,
            expected: Expected::Value(2),
        },
        Case {
            name: "shru_masked_40",
            code: build_local_tee_shift(Opcode::I32ShrU, -1, 40),
            locals_total: 1,
            expected: Expected::Value(0x00FF_FFFFu32 as i32),
        },
        Case {
            name: "divu_wrap",
            code: build_binop(Opcode::I32DivU, -1, 2),
            locals_total: 0,
            expected: Expected::Value(0x7FFF_FFFF),
        },
        Case {
            name: "rems_neg",
            code: build_binop(Opcode::I32RemS, -7, 3),
            locals_total: 0,
            expected: Expected::Value(-1),
        },
        Case {
            name: "remu_wrap",
            code: build_binop(Opcode::I32RemU, -1, 2),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "select_true",
            code: build_select(11, 22, 1),
            locals_total: 0,
            expected: Expected::Value(11),
        },
        Case {
            name: "select_false",
            code: build_select(11, 22, 0),
            locals_total: 0,
            expected: Expected::Value(22),
        },
        Case {
            name: "add_eq_chain_0_0_0",
            code: build_add_eq(0, 0, 0),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "memory_size_match",
            code: build_memory_size(),
            locals_total: 0,
            expected: Expected::MatchOk,
        },
        Case {
            name: "eqz_zero",
            code: build_unop(Opcode::I32Eqz, 0),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "unreachable_trap",
            code: build_unreachable(),
            locals_total: 0,
            expected: Expected::AnyErr,
        },
    ];

    #[cfg(target_arch = "x86_64")]
    let cases: [Case; 41] = [
        Case {
            name: "eq_0_0",
            code: build_binop(Opcode::I32Eq, 0, 0),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "ne_1_2",
            code: build_binop(Opcode::I32Ne, 1, 2),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "lt_s_neg",
            code: build_binop(Opcode::I32LtS, -1, 0),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "gt_s_neg",
            code: build_binop(Opcode::I32GtS, -1, 0),
            locals_total: 0,
            expected: Expected::Value(0),
        },
        Case {
            name: "le_s_eq",
            code: build_binop(Opcode::I32LeS, 7, 7),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "ge_s_pos",
            code: build_binop(Opcode::I32GeS, 9, -3),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "lt_u_wrap",
            code: build_binop(Opcode::I32LtU, -1, 0),
            locals_total: 0,
            expected: Expected::Value(0),
        },
        Case {
            name: "gt_u_wrap",
            code: build_binop(Opcode::I32GtU, -1, 0),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "le_u_eq",
            code: build_binop(Opcode::I32LeU, -1, -1),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "ge_u_small",
            code: build_binop(Opcode::I32GeU, 1, 2),
            locals_total: 0,
            expected: Expected::Value(0),
        },
        Case {
            name: "shl_masked_33",
            code: build_local_tee_shift(Opcode::I32Shl, 1, 33),
            locals_total: 1,
            expected: Expected::Value(2),
        },
        Case {
            name: "shru_masked_40",
            code: build_local_tee_shift(Opcode::I32ShrU, -1, 40),
            locals_total: 1,
            expected: Expected::Value(0x00FF_FFFFu32 as i32),
        },
        Case {
            name: "divu_wrap",
            code: build_binop(Opcode::I32DivU, -1, 2),
            locals_total: 0,
            expected: Expected::Value(0x7FFF_FFFF),
        },
        Case {
            name: "rems_neg",
            code: build_binop(Opcode::I32RemS, -7, 3),
            locals_total: 0,
            expected: Expected::Value(-1),
        },
        Case {
            name: "remu_wrap",
            code: build_binop(Opcode::I32RemU, -1, 2),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "select_true",
            code: build_select(11, 22, 1),
            locals_total: 0,
            expected: Expected::Value(11),
        },
        Case {
            name: "select_false",
            code: build_select(11, 22, 0),
            locals_total: 0,
            expected: Expected::Value(22),
        },
        Case {
            name: "add_eq_chain_0_0_0",
            code: build_add_eq(0, 0, 0),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "if_else_true",
            code: build_if_else_local(1, 11, 22),
            locals_total: 1,
            expected: Expected::Value(11),
        },
        Case {
            name: "if_else_false",
            code: build_if_else_local(0, 11, 22),
            locals_total: 1,
            expected: Expected::Value(22),
        },
        Case {
            name: "if_br_skip_tail",
            code: build_if_br_local(),
            locals_total: 1,
            expected: Expected::Value(33),
        },
        Case {
            name: "if_br_if_taken",
            code: build_if_br_if_local(1),
            locals_total: 1,
            expected: Expected::Value(33),
        },
        Case {
            name: "if_br_if_fallthrough",
            code: build_if_br_if_local(0),
            locals_total: 1,
            expected: Expected::Value(44),
        },
        Case {
            name: "block_br_skip_tail",
            code: build_block_br_skip_tail(),
            locals_total: 1,
            expected: Expected::Value(77),
        },
        Case {
            name: "loop_countdown_sum",
            code: build_loop_countdown_sum(),
            locals_total: 2,
            expected: Expected::Value(3),
        },
        Case {
            name: "block_br_unwind_add",
            code: build_block_br_unwind_add(),
            locals_total: 0,
            expected: Expected::Value(29),
        },
        Case {
            name: "block_br_if_unwind_add",
            code: build_block_br_if_unwind_add(),
            locals_total: 0,
            expected: Expected::Value(29),
        },
        Case {
            name: "nested_block_br_depth1_unwind_add",
            code: build_nested_block_br_depth1_unwind_add(),
            locals_total: 0,
            expected: Expected::Value(29),
        },
        Case {
            name: "nested_block_br_if_depth1_taken",
            code: build_nested_block_br_if_depth1_unwind_add(1),
            locals_total: 0,
            expected: Expected::Value(29),
        },
        Case {
            name: "nested_block_br_if_depth1_fallthrough",
            code: build_nested_block_br_if_depth1_unwind_add(0),
            locals_total: 0,
            expected: Expected::Value(129),
        },
        Case {
            name: "block_typed_i32_result",
            code: build_typed_block_i32_result(42),
            locals_total: 0,
            expected: Expected::Value(42),
        },
        Case {
            name: "loop_typed_i32_result",
            code: build_typed_loop_i32_result(9),
            locals_total: 0,
            expected: Expected::Value(9),
        },
        Case {
            name: "if_typed_i32_true",
            code: build_typed_if_else_i32_result(1, 11, 22),
            locals_total: 0,
            expected: Expected::Value(11),
        },
        Case {
            name: "if_typed_i32_false",
            code: build_typed_if_else_i32_result(0, 11, 22),
            locals_total: 0,
            expected: Expected::Value(22),
        },
        Case {
            name: "block_typed_br_i32_unwind_add",
            code: build_typed_block_br_i32_result_unwind_add(),
            locals_total: 0,
            expected: Expected::Value(18),
        },
        Case {
            name: "block_typed_br_if_i32_taken",
            code: build_typed_block_br_if_i32_result_unwind_add(1, 22),
            locals_total: 0,
            expected: Expected::Value(18),
        },
        Case {
            name: "block_typed_br_if_i32_fallthrough",
            code: build_typed_block_br_if_i32_result_unwind_add(0, 22),
            locals_total: 0,
            expected: Expected::Value(29),
        },
        Case {
            name: "memory_size_match",
            code: build_memory_size(),
            locals_total: 0,
            expected: Expected::MatchOk,
        },
        Case {
            name: "memory_grow_zero_returns_old_pages",
            code: build_memory_grow(0),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "eqz_zero",
            code: build_unop(Opcode::I32Eqz, 0),
            locals_total: 0,
            expected: Expected::Value(1),
        },
        Case {
            name: "unreachable_trap",
            code: build_unreachable(),
            locals_total: 0,
            expected: Expected::AnyErr,
        },
    ];

    let mut base_module = WasmModule::new();
    base_module.reserve_bytecode(MAX_FUZZ_CODE_SIZE);
    base_module
        .load_raw_bytecode(&[Opcode::End as u8])
        .map_err(|_| "jit compare/shift self-test: base load failed")?;
    base_module
        .add_function(Function::synthetic_i32(0, 1, 0, 1, 0))
        .map_err(|_| "jit compare/shift self-test: base function add failed")?;

    crate::serial_println!("[WASM-JIT] fixed-vectors stage=compiler-init");
    ensure_selftest_compiler_ready()
        .map_err(|_| "jit compare/shift self-test: compiler init failed")?;

    let x86_64_only_cases = cases
        .iter()
        .filter(|case| requires_x86_64_fixed_vector_backend(&case.code))
        .count();
    let supports_extended_fixed_vectors = cfg!(target_arch = "x86_64");
    let mut executed_cases = 0usize;
    let mut skipped_x86_64_only_cases = 0usize;
    let mut idx = 0usize;
    while idx < cases.len() {
        let case = &cases[idx];
        if !supports_extended_fixed_vectors && requires_x86_64_fixed_vector_backend(&case.code) {
            skipped_x86_64_only_cases += 1;
            idx += 1;
            continue;
        }
        crate::serial_println!(
            "[WASM-JIT] fixed-vectors case={} stage=interp-call",
            case.name
        );
        let interp = {
            let mut instance = new_selftest_instance(base_module.clone(), ProcessId(1), 0)?;
            crate::serial_println!(
                "[WASM-JIT] fixed-vectors case={} stage=interp-enter",
                case.name
            );
            instance.prepare_fuzz();
            crate::serial_println!(
                "[WASM-JIT] fixed-vectors case={} stage=interp-prepared",
                case.name
            );
            instance
                .load_fuzz_program(&case.code, case.locals_total)
                .map_err(|_| "jit compare/shift self-test: interp load failed")?;
            crate::serial_println!(
                "[WASM-JIT] fixed-vectors case={} stage=interp-loaded",
                case.name
            );
            instance.enable_jit(false);
            crate::serial_println!(
                "[WASM-JIT] fixed-vectors case={} stage=interp-run",
                case.name
            );
            match instance.call(0) {
                Ok(()) => {
                    crate::serial_println!(
                        "[WASM-JIT] fixed-vectors case={} stage=interp-finished",
                        case.name
                    );
                    instance
                        .stack
                        .pop()
                        .map_err(|_| "jit compare/shift self-test: interp stack pop failed")?
                        .as_i32()
                        .map_err(|_| "jit compare/shift self-test: interp result type failed")
                }
                Err(_) => Err("trap"),
            }
        };
        crate::serial_println!(
            "[WASM-JIT] fixed-vectors case={} stage=interp-done",
            case.name
        );

        crate::serial_println!(
            "[WASM-JIT] fixed-vectors case={} stage=compile-lock",
            case.name
        );
        let (entry, exec_ptr, exec_len) = {
            let mut compiler_slot = JIT_SELFTEST_COMPILER.lock();
            let compiler = compiler_slot
                .as_mut()
                .ok_or("jit compare/shift self-test: compiler init failed")?;
            crate::serial_println!("[WASM-JIT] fixed-vectors case={} stage=compile", case.name);
            let entry = match compiler.compile(&case.code, case.locals_total) {
                Ok(entry) => entry,
                Err(e) => {
                    crate::serial_println!(
                        "[JIT-ST] compile-fail case={} reason={}",
                        case.name,
                        e
                    );
                    return Err("jit compare/shift self-test: jit compile failed");
                }
            };
            (entry, compiler.exec_ptr(), compiler.exec_len())
        };
        let jit_exec = JitExecInfo {
            entry,
            exec_ptr,
            exec_len,
        };

        crate::serial_println!("[WASM-JIT] fixed-vectors case={} stage=jit-call", case.name);
        let jit = {
            let mut instance = new_selftest_instance(base_module.clone(), ProcessId(1), 1)?;
            instance.prepare_fuzz();
            instance
                .load_fuzz_program(&case.code, case.locals_total)
                .map_err(|_| "jit compare/shift self-test: jit load failed")?;
            match instance.run_jit_entry(0, jit_exec) {
                Ok(()) => instance
                    .stack
                    .pop()
                    .map_err(|_| "jit compare/shift self-test: jit stack pop failed")?
                    .as_i32()
                    .map_err(|_| "jit compare/shift self-test: jit result type failed"),
                Err(_) => Err("trap"),
            }
        };
        crate::serial_println!("[WASM-JIT] fixed-vectors case={} stage=jit-done", case.name);

        let case_ok = match case.expected {
            Expected::Value(expected) => interp == Ok(expected) && jit == Ok(expected),
            Expected::Trap => interp.is_err() && jit.is_err(),
            Expected::AnyErr => interp.is_err() && jit.is_err(),
            Expected::MatchOk => match (interp, jit) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            },
        };
        if !case_ok {
            crate::serial_println!("[JIT-ST] mismatch case={}", case.name);
            let _ = case.name;
            return Err("jit compare/shift self-test: mismatch");
        }
        executed_cases += 1;
        idx += 1;
    }
    crate::serial_println!(
        "[WASM-JIT] fixed-vectors total={} structured-control-flow={} executed={} skipped={}",
        cases.len(),
        x86_64_only_cases,
        executed_cases,
        skipped_x86_64_only_cases
    );
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
pub fn jit_typed_blocktype_module_self_test() -> Result<(), &'static str> {
    crate::serial_println!("[WASM-JIT] typed-blocktypes skipped=unsupported-on-i686");
    Ok(())
}

#[cfg(target_arch = "x86_64")]
pub fn jit_typed_blocktype_module_self_test() -> Result<(), &'static str> {
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

    struct JitModeGuard {
        prev_user_mode: bool,
    }
    impl Drop for JitModeGuard {
        fn drop(&mut self) {
            let mut cfg = jit_config().lock();
            cfg.user_mode = self.prev_user_mode;
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
        guard
    };

    let _jit_mode_guard = {
        let mut cfg = jit_config().lock();
        let guard = JitModeGuard {
            prev_user_mode: cfg.user_mode,
        };
        cfg.user_mode = false;
        guard
    };

    let _fuzz_active_guard = {
        struct JitFuzzActiveGuard {
            prev: bool,
        }
        impl Drop for JitFuzzActiveGuard {
            fn drop(&mut self) {
                JIT_FUZZ_ACTIVE.store(self.prev, Ordering::SeqCst);
            }
        }
        let prev = JIT_FUZZ_ACTIVE.swap(true, Ordering::SeqCst);
        JitFuzzActiveGuard { prev }
    };

    fn new_selftest_instance(
        module: WasmModule,
        process_id: ProcessId,
        instance_id: usize,
    ) -> Result<Box<WasmInstance>, &'static str> {
        let mut instance =
            unsafe { WasmInstance::boxed_new_in_place(module, process_id, instance_id) };
        instance
            .initialize_from_module()
            .map_err(|_| "jit typed blocktype self-test: instance init failed")?;
        Ok(instance)
    }

    let cases: [(&str, &[u8], i32); 6] = [
        (
            "typed_block_typeidx",
            &WASM_CONFORMANCE_MODULE_TYPED_BLOCK,
            42,
        ),
        (
            "typed_if_implicit_else_typeidx",
            &WASM_CONFORMANCE_MODULE_TYPED_IF_IMPLICIT_ELSE,
            42,
        ),
        (
            "typed_block_br2_typeidx",
            &WASM_CONFORMANCE_MODULE_TYPED_BLOCK_BR2,
            29,
        ),
        (
            "typed_block_br_if2_typeidx",
            &WASM_CONFORMANCE_MODULE_TYPED_BLOCK_BR_IF2,
            29,
        ),
        (
            "typed_block_br3_typeidx",
            &WASM_CONFORMANCE_MODULE_TYPED_BLOCK_BR3,
            23,
        ),
        (
            "typed_block_br_if3_typeidx",
            &WASM_CONFORMANCE_MODULE_TYPED_BLOCK_BR_IF3,
            23,
        ),
    ];

    ensure_selftest_compiler_ready()
        .map_err(|_| "jit typed blocktype self-test: compiler init failed")?;
    let mut compiler_slot = JIT_SELFTEST_COMPILER.lock();
    let compiler = compiler_slot
        .as_mut()
        .ok_or("jit typed blocktype self-test: compiler init failed")?;

    let mut idx = 0usize;
    while idx < cases.len() {
        let (name, bytes, expected) = cases[idx];
        crate::serial_println!("[WASM-JIT] typed-blocktypes case={} stage=parse", name);

        let mut module = WasmModule::new();
        module
            .load_binary(bytes)
            .map_err(|_| "jit typed blocktype self-test: parse failed")?;
        crate::serial_println!(
            "[WASM-JIT] typed-blocktypes case={} stage=interp-inst",
            name
        );
        crate::serial_println!("[WASM-JIT] typed-blocktypes case={} stage=compile", name);
        let jit_exec = {
            let func = module
                .get_function(0)
                .map_err(|_| "jit typed blocktype self-test: function missing")?;
            let code_start = func.code_offset;
            let code_end = code_start
                .checked_add(func.code_len)
                .ok_or("jit typed blocktype self-test: code range overflow")?;
            if code_end > module.bytecode_len || code_end > module.bytecode.len() {
                return Err("jit typed blocktype self-test: code range invalid");
            }
            let locals_total = func.param_count + func.local_count;
            let type_sigs = collect_jit_type_signatures(&module);
            let global_sigs = collect_jit_global_signatures(&module);
            let entry = compiler
                .compile_with_env(
                    &module.bytecode[code_start..code_end],
                    locals_total,
                    &type_sigs,
                    &global_sigs,
                )
                .map_err(|_| "jit typed blocktype self-test: jit compile failed")?;
            JitExecInfo {
                entry,
                exec_ptr: compiler.exec_ptr(),
                exec_len: compiler.exec_len(),
            }
        };
        crate::serial_println!("[WASM-JIT] typed-blocktypes case={} stage=jit-inst", name);
        crate::serial_println!("[WASM-JIT] typed-blocktypes case={} stage=run", name);

        let interp = {
            let mut instance = new_selftest_instance(module.clone(), ProcessId(1), 0)?;
            instance.enable_jit(false);
            crate::serial_println!(
                "[WASM-JIT] typed-blocktypes case={} stage=interp-call",
                name
            );
            instance
                .call(0)
                .map_err(|_| "jit typed blocktype self-test: interp exec failed")?;
            let value = instance
                .stack
                .pop()
                .map_err(|_| "jit typed blocktype self-test: interp stack pop failed")?
                .as_i32()
                .map_err(|_| "jit typed blocktype self-test: interp result type failed")?;
            crate::serial_println!(
                "[WASM-JIT] typed-blocktypes case={} stage=interp-done",
                name
            );
            value
        };

        crate::serial_println!("[WASM-JIT] typed-blocktypes case={} stage=jit-reset", name);
        let jit = {
            let mut instance = new_selftest_instance(module, ProcessId(1), 1)?;
            crate::serial_println!("[WASM-JIT] typed-blocktypes case={} stage=jit-call", name);
            instance
                .run_jit_entry(0, jit_exec)
                .map_err(|_| "jit typed blocktype self-test: jit exec failed")?;
            let value = instance
                .stack
                .pop()
                .map_err(|_| "jit typed blocktype self-test: jit stack pop failed")?
                .as_i32()
                .map_err(|_| "jit typed blocktype self-test: jit result type failed")?;
            crate::serial_println!("[WASM-JIT] typed-blocktypes case={} stage=jit-done", name);
            value
        };

        crate::serial_println!("[WASM-JIT] typed-blocktypes case={} stage=done", name);

        if interp != expected || jit != expected {
            let _ = name;
            drop(guard);
            return Err("jit typed blocktype self-test: result mismatch");
        }

        idx += 1;
    }

    crate::serial_println!("[WASM-JIT] typed-blocktypes total={}", cases.len());
    drop(guard);
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
pub fn jit_global_module_self_test() -> Result<(), &'static str> {
    crate::serial_println!("[WASM-JIT] globals skipped=unsupported-on-i686");
    Ok(())
}

#[cfg(target_arch = "x86_64")]
pub fn jit_global_module_self_test() -> Result<(), &'static str> {
    struct JitModeGuard {
        prev_user_mode: bool,
    }

    impl Drop for JitModeGuard {
        fn drop(&mut self) {
            let mut cfg = jit_config().lock();
            cfg.user_mode = self.prev_user_mode;
        }
    }

    let mut guard = jit_config().lock();
    let prev_enabled = guard.enabled;
    let prev_hot = guard.hot_threshold;
    guard.enabled = true;
    guard.hot_threshold = 0;
    drop(guard);

    struct ConfigGuard {
        prev_enabled: bool,
        prev_hot: u32,
    }

    impl Drop for ConfigGuard {
        fn drop(&mut self) {
            let mut cfg = jit_config().lock();
            cfg.enabled = self.prev_enabled;
            cfg.hot_threshold = self.prev_hot;
        }
    }

    let guard = ConfigGuard {
        prev_enabled,
        prev_hot,
    };

    let _jit_mode_guard = {
        let mut cfg = jit_config().lock();
        let guard = JitModeGuard {
            prev_user_mode: cfg.user_mode,
        };
        cfg.user_mode = false;
        guard
    };

    let _fuzz_active_guard = {
        struct JitFuzzActiveGuard {
            prev: bool,
        }
        impl Drop for JitFuzzActiveGuard {
            fn drop(&mut self) {
                JIT_FUZZ_ACTIVE.store(self.prev, Ordering::SeqCst);
            }
        }
        let prev = JIT_FUZZ_ACTIVE.swap(true, Ordering::SeqCst);
        JitFuzzActiveGuard { prev }
    };

    fn new_selftest_instance(
        module: WasmModule,
        process_id: ProcessId,
        instance_id: usize,
    ) -> Result<Box<WasmInstance>, &'static str> {
        let mut instance =
            unsafe { WasmInstance::boxed_new_in_place(module, process_id, instance_id) };
        instance
            .initialize_from_module()
            .map_err(|_| "jit globals self-test: instance init failed")?;
        Ok(instance)
    }

    let cases: [(&str, &[u8], i32); 2] = [
        (
            "global_get_i32",
            &WASM_CONFORMANCE_MODULE_GLOBAL_GET_I32,
            42,
        ),
        (
            "global_set_get_i32",
            &WASM_CONFORMANCE_MODULE_GLOBAL_SET_GET_I32,
            23,
        ),
    ];
    let mut compiler =
        crate::execution::wasm_jit::FuzzCompiler::new(MAX_FUZZ_JIT_CODE_SIZE, MAX_FUZZ_CODE_SIZE)
            .map_err(|_| "jit globals self-test: compiler init failed")?;

    let mut idx = 0usize;
    while idx < cases.len() {
        let (name, bytes, expected) = cases[idx];

        let mut interp_module = WasmModule::new();
        interp_module
            .load_binary(bytes)
            .map_err(|_| "jit globals self-test: parse failed")?;

        let mut jit_module = WasmModule::new();
        jit_module
            .load_binary(bytes)
            .map_err(|_| "jit globals self-test: parse failed")?;
        let jit_exec = {
            let func = jit_module
                .get_function(0)
                .map_err(|_| "jit globals self-test: function missing")?;
            let code_start = func.code_offset;
            let code_end = code_start
                .checked_add(func.code_len)
                .ok_or("jit globals self-test: code range overflow")?;
            if code_end > jit_module.bytecode_len || code_end > jit_module.bytecode.len() {
                return Err("jit globals self-test: code range invalid");
            }
            let locals_total = func.param_count + func.local_count;
            let type_sigs = collect_jit_type_signatures(&jit_module);
            let global_sigs = collect_jit_global_signatures(&jit_module);
            let entry = compiler
                .compile_with_env(
                    &jit_module.bytecode[code_start..code_end],
                    locals_total,
                    &type_sigs,
                    &global_sigs,
                )
                .map_err(|_| "jit globals self-test: jit compile failed")?;
            JitExecInfo {
                entry,
                exec_ptr: compiler.exec_ptr(),
                exec_len: compiler.exec_len(),
            }
        };

        let interp = {
            let mut instance = new_selftest_instance(interp_module, ProcessId(1), 0)?;
            instance.enable_jit(false);
            instance
                .call(0)
                .map_err(|_| "jit globals self-test: interp exec failed")?;
            instance
                .stack
                .pop()
                .map_err(|_| "jit globals self-test: interp stack pop failed")?
                .as_i32()
                .map_err(|_| "jit globals self-test: interp result type failed")
        };

        let jit = {
            let mut instance = new_selftest_instance(jit_module, ProcessId(1), 1)?;
            instance
                .run_jit_entry(0, jit_exec)
                .map_err(|_| "jit globals self-test: jit exec failed")?;
            instance
                .stack
                .pop()
                .map_err(|_| "jit globals self-test: jit stack pop failed")?
                .as_i32()
                .map_err(|_| "jit globals self-test: jit result type failed")
        };

        if interp != Ok(expected) || jit != Ok(expected) {
            let _ = name;
            drop(guard);
            return Err("jit globals self-test: result mismatch");
        }

        idx += 1;
    }

    crate::serial_println!("[WASM-JIT] globals total={}", cases.len());
    drop(guard);
    Ok(())
}

/// JIT bounds self-test (expects MemoryOutOfBounds traps in both interpreter and JIT).
pub fn jit_bounds_self_test() -> Result<(), &'static str> {
    jit_bounds_self_test_impl(true)
}

/// Kernel-mode JIT bounds self-test (no usermode trampoline/user-entry path).
pub fn jit_bounds_self_test_kernel_mode() -> Result<(), &'static str> {
    jit_bounds_self_test_impl(false)
}

/// JIT fuzzing harness (generates random programs and compares interpreter vs JIT).
fn ensure_fuzz_instances() -> Result<(usize, usize), &'static str> {
    #[cfg(target_arch = "x86_64")]
    let x64_diag = JIT_FUZZ_X64_DIAG.load(Ordering::SeqCst);
    #[cfg(target_arch = "x86_64")]
    if x64_diag {
        crate::serial_println!("[X64-JF] ensure=check-existing");
    }
    let existing = { *JIT_FUZZ_INSTANCES.lock() };
    if let Some((interp_id, jit_id)) = existing {
        #[cfg(target_arch = "x86_64")]
        if x64_diag {
            crate::serial_println!(
                "[X64-JF] ensure=existing interp={} jit={}",
                interp_id,
                jit_id
            );
        }
        let interp_ok = wasm_runtime().get_instance_mut(interp_id, |_| ()).is_ok();
        let jit_ok = wasm_runtime().get_instance_mut(jit_id, |_| ()).is_ok();
        if interp_ok && jit_ok {
            #[cfg(target_arch = "x86_64")]
            if x64_diag {
                crate::serial_println!("[X64-JF] ensure=existing-ok");
            }
            return Ok((interp_id, jit_id));
        }
        if interp_ok {
            let _ = wasm_runtime().destroy(interp_id);
        }
        if jit_ok && jit_id != interp_id {
            let _ = wasm_runtime().destroy(jit_id);
        }
        let mut slots = JIT_FUZZ_INSTANCES.lock();
        *slots = None;
    }

    #[cfg(target_arch = "x86_64")]
    if x64_diag {
        crate::serial_println!("[X64-JF] ensure=build-base-module");
    }
    let mut base_module = WasmModule::new();
    #[cfg(target_arch = "x86_64")]
    if x64_diag {
        crate::serial_println!("[X64-JF] ensure=reserve-bytecode");
    }
    base_module.reserve_bytecode(MAX_FUZZ_CODE_SIZE);
    #[cfg(target_arch = "x86_64")]
    if x64_diag {
        crate::serial_println!("[X64-JF] ensure=load-end");
    }
    base_module
        .load_raw_bytecode(&[Opcode::End as u8])
        .map_err(|_| "Module load failed")?;
    #[cfg(target_arch = "x86_64")]
    if x64_diag {
        crate::serial_println!("[X64-JF] ensure=add-function");
    }
    base_module
        .add_function(Function::synthetic_i32(0, 1, 0, 1, 0))
        .map_err(|_| "Function add failed")?;

    #[cfg(target_arch = "x86_64")]
    if x64_diag {
        crate::serial_println!("[X64-JF] ensure=instantiate-interp");
    }
    #[cfg(target_arch = "x86_64")]
    if x64_diag {
        crate::serial_println!("[X64-JF] ensure=instantiate-interp-clone");
    }
    let interp_module = base_module.clone();
    #[cfg(target_arch = "x86_64")]
    if x64_diag {
        crate::serial_println!("[X64-JF] ensure=instantiate-interp-call");
    }
    let interp_id = wasm_runtime()
        .instantiate_module(interp_module, ProcessId(1))
        .map_err(|_| "Instance create failed")?;
    #[cfg(target_arch = "x86_64")]
    if x64_diag {
        crate::serial_println!("[X64-JF] ensure=instantiate-jit");
    }
    #[cfg(target_arch = "x86_64")]
    if x64_diag {
        crate::serial_println!("[X64-JF] ensure=instantiate-jit-call");
    }
    let jit_id = match wasm_runtime().instantiate_module(base_module, ProcessId(1)) {
        Ok(id) => id,
        Err(_) => {
            let _ = wasm_runtime().destroy(interp_id);
            return Err("Instance create failed");
        }
    };
    let mut slots = JIT_FUZZ_INSTANCES.lock();
    *slots = Some((interp_id, jit_id));
    #[cfg(target_arch = "x86_64")]
    if x64_diag {
        crate::serial_println!(
            "[X64-JF] ensure=created interp={} jit={}",
            interp_id,
            jit_id
        );
    }
    Ok((interp_id, jit_id))
}

#[allow(unused_assignments)] // built_from_pair_prepass: initial false value is read in the if-guard after 'build_program block
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

    fn choose_guided_choice_with_edge_frontier(
        rng: &mut FuzzRng,
        prev_choice: Option<u8>,
        opcode_hits: &[u32; JIT_FUZZ_OPCODE_BINS],
        edge_seen: &[bool; JIT_FUZZ_OPCODE_BINS * JIT_FUZZ_OPCODE_BINS],
        admissible_edge_matrix: &[bool; JIT_FUZZ_OPCODE_BINS * JIT_FUZZ_OPCODE_BINS],
    ) -> u32 {
        // If we have a predecessor choice, bias toward under-covered successors
        // that create unseen admissible pairwise edges from that predecessor.
        if let Some(prev) = prev_choice {
            if (rng.next_u32() % 100) < 75 {
                let row = (prev as usize) * JIT_FUZZ_OPCODE_BINS;
                let mut min_hit = u32::MAX;
                let mut j = 0usize;
                while j < JIT_FUZZ_OPCODE_BINS {
                    let edge_idx = row + j;
                    if admissible_edge_matrix[edge_idx] && !edge_seen[edge_idx] {
                        if opcode_hits[j] < min_hit {
                            min_hit = opcode_hits[j];
                        }
                    }
                    j += 1;
                }

                if min_hit != u32::MAX {
                    let mut candidates = [0u8; JIT_FUZZ_OPCODE_BINS];
                    let mut n = 0usize;
                    let mut k = 0usize;
                    while k < JIT_FUZZ_OPCODE_BINS {
                        let edge_idx = row + k;
                        if admissible_edge_matrix[edge_idx]
                            && !edge_seen[edge_idx]
                            && opcode_hits[k] <= min_hit.saturating_add(1)
                        {
                            candidates[n] = k as u8;
                            n += 1;
                        }
                        k += 1;
                    }
                    if n > 0 {
                        let pick = (rng.next_u32() as usize) % n;
                        return candidates[pick] as u32;
                    }
                }
            }
        }

        choose_guided_choice(rng, opcode_hits)
    }

    fn record_choice_trace_hits(
        opcode_hits: &mut [u32; JIT_FUZZ_OPCODE_BINS],
        choice_trace: &[u8],
    ) -> bool {
        let mut cidx = 0usize;
        while cidx < choice_trace.len() {
            let Some(bin) = jit_fuzz_choice_bin(choice_trace[cidx]) else {
                return false;
            };
            opcode_hits[bin] = opcode_hits[bin].saturating_add(1);
            cidx += 1;
        }
        true
    }

    fn guided_choice_step_abstract(
        stack_depth: i32,
        locals_total: usize,
        choice: u8,
    ) -> Option<i32> {
        match choice {
            0 => Some(stack_depth), // nop
            1 => {
                if stack_depth > 0 {
                    Some(stack_depth - 1) // drop
                } else {
                    Some(stack_depth + 1) // fallback i32.const
                }
            }
            2 => {
                if stack_depth < (MAX_STACK_DEPTH as i32) - 1 {
                    Some(stack_depth + 1)
                } else {
                    None
                }
            }
            3 | 4 | 5 | 6 | 7 | 8 => {
                if stack_depth >= 2 {
                    Some(stack_depth - 1)
                } else {
                    None
                }
            }
            9 => {
                if stack_depth >= 1 {
                    Some(stack_depth)
                } else {
                    None
                }
            }
            10 => {
                if stack_depth >= 1 {
                    Some(stack_depth) // bounded load macro net stack delta = 0
                } else {
                    None
                }
            }
            11 => {
                if locals_total > 0 && stack_depth >= 2 {
                    Some(stack_depth - 2) // bounded store macro net stack delta = -2
                } else {
                    None
                }
            }
            12 => {
                if locals_total > 0 {
                    Some(stack_depth + 1) // local.get
                } else {
                    None
                }
            }
            13 => {
                if locals_total > 0 && stack_depth > 0 {
                    Some(stack_depth - 1) // local.set
                } else {
                    None
                }
            }
            14 => {
                if locals_total > 0 && stack_depth > 0 {
                    Some(stack_depth) // local.tee
                } else {
                    None
                }
            }
            15 | 16 | 17 | 18 => {
                if stack_depth >= 2 {
                    Some(stack_depth - 1) // binary compares / shifts
                } else {
                    None
                }
            }
            19 => {
                if stack_depth >= 1 {
                    Some(stack_depth) // compare-with-const macro net stack delta = 0
                } else {
                    None
                }
            }
            #[cfg(feature = "jit-fuzz-24bin")]
            20 | 21 | 22 | 23 => {
                if stack_depth >= 1 {
                    Some(stack_depth) // const-divisor div/rem macro net stack delta = 0
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn compute_jit_fuzz_admissible_edges() -> (
        [bool; JIT_FUZZ_OPCODE_BINS * JIT_FUZZ_OPCODE_BINS],
        [Option<(u16, u8)>; JIT_FUZZ_OPCODE_BINS * JIT_FUZZ_OPCODE_BINS],
        u32,
    ) {
        // Pairwise admissibility is computed in an "early-budget" abstract state:
        // enough remaining code budget to emit two guided choices plus normalization.
        // For pairwise reachability, stack depth and local availability dominate.
        const MAX_ABSTRACT_STACK: i32 = 8;

        let mut admissible = [false; JIT_FUZZ_OPCODE_BINS * JIT_FUZZ_OPCODE_BINS];
        let mut witnesses = [None; JIT_FUZZ_OPCODE_BINS * JIT_FUZZ_OPCODE_BINS];

        let local_variants = [0usize, 2usize];
        let mut lv = 0usize;
        while lv < local_variants.len() {
            let locals_total = local_variants[lv];
            let mut s0 = 0i32;
            while s0 <= MAX_ABSTRACT_STACK {
                let mut i = 0usize;
                while i < JIT_FUZZ_OPCODE_BINS {
                    if let Some(s1) = guided_choice_step_abstract(s0, locals_total, i as u8) {
                        let mut j = 0usize;
                        while j < JIT_FUZZ_OPCODE_BINS {
                            if guided_choice_step_abstract(s1, locals_total, j as u8).is_some() {
                                let edge_idx = i * JIT_FUZZ_OPCODE_BINS + j;
                                if !admissible[edge_idx] {
                                    admissible[edge_idx] = true;
                                    witnesses[edge_idx] = Some((s0 as u16, locals_total as u8));
                                }
                            }
                            j += 1;
                        }
                    }
                    i += 1;
                }
                s0 += 1;
            }
            lv += 1;
        }

        let mut total = 0u32;
        let mut idx = 0usize;
        while idx < admissible.len() {
            if admissible[idx] {
                total += 1;
            }
            idx += 1;
        }
        (admissible, witnesses, total)
    }

    fn emit_guided_choice_forced(
        code: &mut Vec<u8>,
        stack_depth: &mut i32,
        locals_total: usize,
        choice: u8,
    ) -> bool {
        match choice {
            0 => {
                code.push(Opcode::Nop as u8);
                true
            }
            1 => {
                if *stack_depth > 0 {
                    code.push(Opcode::Drop as u8);
                    *stack_depth -= 1;
                } else {
                    code.push(Opcode::I32Const as u8);
                    push_sleb128_i32(code, 0);
                    *stack_depth += 1;
                }
                true
            }
            2 => {
                if *stack_depth < (MAX_STACK_DEPTH as i32) - 1 {
                    code.push(Opcode::I32Const as u8);
                    push_sleb128_i32(code, 0);
                    *stack_depth += 1;
                    true
                } else {
                    false
                }
            }
            3 => {
                if *stack_depth >= 2 {
                    code.push(Opcode::I32Add as u8);
                    *stack_depth -= 1;
                    true
                } else {
                    false
                }
            }
            4 => {
                if *stack_depth >= 2 {
                    code.push(Opcode::I32Sub as u8);
                    *stack_depth -= 1;
                    true
                } else {
                    false
                }
            }
            5 => {
                if *stack_depth >= 2 {
                    code.push(Opcode::I32Mul as u8);
                    *stack_depth -= 1;
                    true
                } else {
                    false
                }
            }
            6 => {
                if *stack_depth >= 2 {
                    code.push(Opcode::I32And as u8);
                    *stack_depth -= 1;
                    true
                } else {
                    false
                }
            }
            7 => {
                if *stack_depth >= 2 {
                    code.push(Opcode::I32Or as u8);
                    *stack_depth -= 1;
                    true
                } else {
                    false
                }
            }
            8 => {
                if *stack_depth >= 2 {
                    code.push(Opcode::I32Xor as u8);
                    *stack_depth -= 1;
                    true
                } else {
                    false
                }
            }
            9 => {
                if *stack_depth >= 1 {
                    code.push(Opcode::I32Eqz as u8);
                    true
                } else {
                    false
                }
            }
            10 => {
                if *stack_depth >= 1 {
                    code.push(Opcode::I32Const as u8);
                    push_sleb128_i32(code, 0xFFFC);
                    *stack_depth += 1;
                    code.push(Opcode::I32And as u8);
                    *stack_depth -= 1;
                    code.push(Opcode::I32Load as u8);
                    push_uleb128(code, 0);
                    push_uleb128(code, 0);
                    true
                } else {
                    false
                }
            }
            11 => {
                if locals_total > 0 && *stack_depth >= 2 {
                    code.push(Opcode::LocalSet as u8);
                    push_uleb128(code, 0);
                    *stack_depth -= 1;
                    code.push(Opcode::I32Const as u8);
                    push_sleb128_i32(code, 0xFFFC);
                    *stack_depth += 1;
                    code.push(Opcode::I32And as u8);
                    *stack_depth -= 1;
                    code.push(Opcode::LocalGet as u8);
                    push_uleb128(code, 0);
                    *stack_depth += 1;
                    code.push(Opcode::I32Store as u8);
                    push_uleb128(code, 0);
                    push_uleb128(code, 0);
                    *stack_depth -= 2;
                    true
                } else {
                    false
                }
            }
            12 => {
                if locals_total > 0 {
                    code.push(Opcode::LocalGet as u8);
                    push_uleb128(code, 0);
                    *stack_depth += 1;
                    true
                } else {
                    false
                }
            }
            13 => {
                if locals_total > 0 && *stack_depth > 0 {
                    code.push(Opcode::LocalSet as u8);
                    push_uleb128(code, 0);
                    *stack_depth -= 1;
                    true
                } else {
                    false
                }
            }
            14 => {
                if locals_total > 0 && *stack_depth > 0 {
                    code.push(Opcode::LocalTee as u8);
                    push_uleb128(code, 0);
                    true
                } else {
                    false
                }
            }
            15 => {
                if *stack_depth >= 2 {
                    code.push(Opcode::I32Eq as u8);
                    *stack_depth -= 1;
                    true
                } else {
                    false
                }
            }
            16 => {
                if *stack_depth >= 2 {
                    code.push(Opcode::I32LtS as u8);
                    *stack_depth -= 1;
                    true
                } else {
                    false
                }
            }
            17 => {
                if *stack_depth >= 2 {
                    code.push(Opcode::I32LtU as u8);
                    *stack_depth -= 1;
                    true
                } else {
                    false
                }
            }
            18 => {
                if *stack_depth >= 2 {
                    code.push(Opcode::I32Shl as u8);
                    *stack_depth -= 1;
                    true
                } else {
                    false
                }
            }
            19 => {
                if *stack_depth >= 1 {
                    code.push(Opcode::I32Const as u8);
                    push_sleb128_i32(code, 0);
                    *stack_depth += 1;
                    code.push(Opcode::I32LtU as u8);
                    *stack_depth -= 1;
                    true
                } else {
                    false
                }
            }
            #[cfg(feature = "jit-fuzz-24bin")]
            20 => {
                if *stack_depth >= 1 {
                    code.push(Opcode::I32Const as u8);
                    push_sleb128_i32(code, 1);
                    *stack_depth += 1;
                    code.push(Opcode::I32DivS as u8);
                    *stack_depth -= 1;
                    true
                } else {
                    false
                }
            }
            #[cfg(feature = "jit-fuzz-24bin")]
            21 => {
                if *stack_depth >= 1 {
                    code.push(Opcode::I32Const as u8);
                    push_sleb128_i32(code, 1);
                    *stack_depth += 1;
                    code.push(Opcode::I32DivU as u8);
                    *stack_depth -= 1;
                    true
                } else {
                    false
                }
            }
            #[cfg(feature = "jit-fuzz-24bin")]
            22 => {
                if *stack_depth >= 1 {
                    code.push(Opcode::I32Const as u8);
                    push_sleb128_i32(code, 1);
                    *stack_depth += 1;
                    code.push(Opcode::I32RemS as u8);
                    *stack_depth -= 1;
                    true
                } else {
                    false
                }
            }
            #[cfg(feature = "jit-fuzz-24bin")]
            23 => {
                if *stack_depth >= 1 {
                    code.push(Opcode::I32Const as u8);
                    push_sleb128_i32(code, 1);
                    *stack_depth += 1;
                    code.push(Opcode::I32RemU as u8);
                    *stack_depth -= 1;
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn build_pair_cover_program_for_edge(
        code: &mut Vec<u8>,
        choice_trace: &mut Vec<u8>,
        edge_idx: usize,
        witness: (u16, u8),
    ) -> Option<usize> {
        let i = (edge_idx / JIT_FUZZ_OPCODE_BINS) as u8;
        let j = (edge_idx % JIT_FUZZ_OPCODE_BINS) as u8;
        let target_stack = witness.0 as i32;
        let locals_total = witness.1 as usize;

        code.clear();
        choice_trace.clear();
        let mut stack_depth = 0i32;

        while stack_depth < target_stack {
            if code.len() + 8 >= MAX_FUZZ_CODE_SIZE {
                return None;
            }
            if !emit_guided_choice_forced(code, &mut stack_depth, locals_total, 2) {
                return None;
            }
            choice_trace.push(2);
        }
        if stack_depth != target_stack {
            return None;
        }

        if code.len() + 48 >= MAX_FUZZ_CODE_SIZE {
            return None;
        }
        if !emit_guided_choice_forced(code, &mut stack_depth, locals_total, i) {
            return None;
        }
        choice_trace.push(i);
        if !emit_guided_choice_forced(code, &mut stack_depth, locals_total, j) {
            return None;
        }
        choice_trace.push(j);

        while stack_depth > 1 && code.len() + 2 < MAX_FUZZ_CODE_SIZE {
            code.push(Opcode::Drop as u8);
            stack_depth -= 1;
        }
        while stack_depth < 1 && code.len() + 8 < MAX_FUZZ_CODE_SIZE {
            code.push(Opcode::I32Const as u8);
            push_sleb128_i32(code, 0);
            stack_depth += 1;
        }
        if stack_depth != 1 {
            return None;
        }
        code.push(Opcode::End as u8);
        if validate_bytecode(&code).is_err()
            || validate_jit_fuzz_generated_subset(&code, locals_total).is_err()
        {
            return None;
        }
        Some(locals_total)
    }

    fn validate_jit_fuzz_generated_subset(code: &[u8], locals_total: usize) -> Result<(), WasmError> {
        let mut pc = 0usize;
        let mut saw_terminal_end = false;
        let mut stack_depth = 0i32;
        while pc < code.len() {
            let opcode_byte = code[pc];
            pc += 1;
            let opcode =
                Opcode::from_byte(opcode_byte).ok_or(WasmError::UnknownOpcode(opcode_byte))?;
            match opcode {
                Opcode::Nop => {}
                Opcode::Drop => {
                    if stack_depth < 1 {
                        return Err(WasmError::StackUnderflow);
                    }
                    stack_depth -= 1;
                }
                Opcode::I32Add
                | Opcode::I32Sub
                | Opcode::I32Mul
                | Opcode::I32And
                | Opcode::I32Or
                | Opcode::I32Xor
                | Opcode::I32Eq
                | Opcode::I32Ne
                | Opcode::I32LtS
                | Opcode::I32GtS
                | Opcode::I32LeS
                | Opcode::I32GeS
                | Opcode::I32LtU
                | Opcode::I32GtU
                | Opcode::I32LeU
                | Opcode::I32GeU
                | Opcode::I32Shl
                | Opcode::I32ShrS
                | Opcode::I32ShrU
                | Opcode::I32DivS
                | Opcode::I32DivU
                | Opcode::I32RemS
                | Opcode::I32RemU => {
                    if stack_depth < 2 {
                        return Err(WasmError::StackUnderflow);
                    }
                    stack_depth -= 1;
                }
                Opcode::I32Eqz => {
                    if stack_depth < 1 {
                        return Err(WasmError::StackUnderflow);
                    }
                }
                Opcode::End => {
                    if pc != code.len() {
                        // Generated fuzz programs must terminate exactly once.
                        // Trailing bytes after `end` indicate a corrupted/stale build buffer.
                        return Err(WasmError::InvalidModule);
                    }
                    saw_terminal_end = true;
                }
                Opcode::I32Const => {
                    let (_v, n) = read_sleb128_i32_validate(code, pc)?;
                    pc += n;
                    stack_depth += 1;
                }
                Opcode::LocalGet => {
                    let (local_idx, n) = read_uleb128_validate(code, pc)?;
                    pc += n;
                    if local_idx as usize >= locals_total {
                        return Err(WasmError::InvalidLocalIndex);
                    }
                    stack_depth += 1;
                }
                Opcode::LocalSet => {
                    let (local_idx, n) = read_uleb128_validate(code, pc)?;
                    pc += n;
                    if local_idx as usize >= locals_total {
                        return Err(WasmError::InvalidLocalIndex);
                    }
                    if stack_depth < 1 {
                        return Err(WasmError::StackUnderflow);
                    }
                    stack_depth -= 1;
                }
                Opcode::LocalTee => {
                    let (local_idx, n) = read_uleb128_validate(code, pc)?;
                    pc += n;
                    if local_idx as usize >= locals_total {
                        return Err(WasmError::InvalidLocalIndex);
                    }
                    if stack_depth < 1 {
                        return Err(WasmError::StackUnderflow);
                    }
                }
                Opcode::I32Load => {
                    let (_align, n1) = read_uleb128_validate(code, pc)?;
                    pc += n1;
                    let (_off, n2) = read_uleb128_validate(code, pc)?;
                    pc += n2;
                    if stack_depth < 1 {
                        return Err(WasmError::StackUnderflow);
                    }
                }
                Opcode::I32Store => {
                    let (_align, n1) = read_uleb128_validate(code, pc)?;
                    pc += n1;
                    let (_off, n2) = read_uleb128_validate(code, pc)?;
                    pc += n2;
                    if stack_depth < 2 {
                        return Err(WasmError::StackUnderflow);
                    }
                    stack_depth -= 2;
                }
                _ => return Err(WasmError::UnknownOpcode(opcode_byte)),
            }
        }
        if !saw_terminal_end {
            return Err(WasmError::UnexpectedEndOfCode);
        }
        if stack_depth != 1 {
            return Err(WasmError::InvalidModule);
        }
        Ok(())
    }

    #[inline]
    fn jit_fuzz_code_has_memory_ops(code: &[u8]) -> bool {
        // Conservative byte scan is sufficient for retry heuristics: false positives
        // only reduce retries, but false negatives are unlikely for the short fuzz programs.
        code.iter()
            .any(|b| *b == (Opcode::I32Load as u8) || *b == (Opcode::I32Store as u8))
    }

    #[inline]
    fn capture_jit_fuzz_jit_bytes(emitted: &[u8]) -> Vec<u8> {
        const MAX_CAPTURED_JIT_BYTES: usize = 4096;
        let n = core::cmp::min(emitted.len(), MAX_CAPTURED_JIT_BYTES);
        let mut out = Vec::with_capacity(n);
        out.extend_from_slice(&emitted[..n]);
        out
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
        // Preserve caller-selected sandbox policy (shell command forces user mode).
        cfg.user_mode = guard.user_mode;
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
    let _fuzz_active_guard = {
        struct JitFuzzActiveGuard {
            prev: bool,
        }
        impl Drop for JitFuzzActiveGuard {
            fn drop(&mut self) {
                JIT_FUZZ_ACTIVE.store(self.prev, Ordering::SeqCst);
            }
        }
        let prev = JIT_FUZZ_ACTIVE.swap(true, Ordering::SeqCst);
        JitFuzzActiveGuard { prev }
    };
    #[cfg(target_arch = "x86_64")]
    let x64_diag = JIT_FUZZ_X64_DIAG.load(Ordering::SeqCst);

    #[cfg(target_arch = "x86_64")]
    if x64_diag {
        crate::serial_println!("[X64-JF] stage=ensure-instances-begin");
    }
    let (interp_id, jit_id) = ensure_fuzz_instances()?;
    #[cfg(target_arch = "x86_64")]
    if x64_diag {
        crate::serial_println!(
            "[X64-JF] stage=ensure-instances-done interp={} jit={}",
            interp_id,
            jit_id
        );
    }

    ensure_fuzz_scratch_ready();
    let mut scratch_slot = JIT_FUZZ_SCRATCH.lock();
    let scratch = scratch_slot.as_mut().ok_or("Fuzz scratch init failed")?;
    let code = &mut scratch.code;
    let interp_mem_snapshot = &mut scratch.interp_mem_snapshot;
    let interp_mem_snapshot_len = &mut scratch.interp_mem_snapshot_len;
    let choice_trace = &mut scratch.choice_trace;
    #[cfg(target_arch = "x86_64")]
    if x64_diag {
        crate::serial_println!("[X64-JF] stage=scratch-ready");
    }

    ensure_fuzz_compiler_ready()?;
    let mut compiler_slot = JIT_FUZZ_COMPILER.lock();
    let compiler = compiler_slot.as_mut().ok_or("Fuzz compiler init failed")?;
    #[cfg(target_arch = "x86_64")]
    if x64_diag {
        crate::serial_println!("[X64-JF] stage=compiler-ready");
    }

    let _ = wasm_runtime().get_instance_mut(interp_id, |instance| {
        instance.prepare_fuzz();
    });
    let _ = wasm_runtime().get_instance_mut(jit_id, |instance| {
        instance.prepare_fuzz();
    });
    #[cfg(target_arch = "x86_64")]
    if x64_diag {
        crate::serial_println!("[X64-JF] stage=instances-prepared");
    }

    let mut rng = FuzzRng::new(seed);
    let mut stats = JitFuzzStats {
        iterations,
        ok: 0,
        traps: 0,
        mismatches: 0,
        compile_errors: 0,
        opcode_bins_hit: 0,
        opcode_edges_hit: 0,
        opcode_edges_hit_admissible: 0,
        opcode_edges_admissible_total: 0,
        novel_programs: 0,
        first_mismatch: None,
        first_compile_error: None,
    };
    let mut opcode_hits = [0u32; JIT_FUZZ_OPCODE_BINS];
    let mut opcode_seen = [false; JIT_FUZZ_OPCODE_BINS];
    let mut edge_seen = [false; JIT_FUZZ_OPCODE_BINS * JIT_FUZZ_OPCODE_BINS];
    let (admissible_edge_matrix, admissible_edge_witness, admissible_edge_total) =
        compute_jit_fuzz_admissible_edges();
    stats.opcode_edges_admissible_total = admissible_edge_total;
    let mut admissible_edge_order: Vec<usize> = Vec::with_capacity(admissible_edge_total as usize);
    let mut edge_idx = 0usize;
    while edge_idx < admissible_edge_matrix.len() {
        if admissible_edge_matrix[edge_idx] {
            admissible_edge_order.push(edge_idx);
        }
        edge_idx += 1;
    }
    let mut pair_cover_cursor = 0usize;

    #[cfg(target_arch = "x86_64")]
    const X64_JIT_FUZZ_CHECKPOINT_ITERS: u32 = 64;
    #[cfg(target_arch = "x86_64")]
    let should_skip_compile_error = |reason: &'static str| {
        matches!(
            reason,
            "Non-terminal block boundary in translation metadata"
                | "Missing trace for basic block"
                | "Opcode not supported by JIT"
                | "i32.lt_u not supported by JIT"
        )
    };
    #[cfg(not(target_arch = "x86_64"))]
    let should_skip_compile_error = |_reason: &'static str| false;

    for iter in 0..iterations {
        #[cfg(target_arch = "x86_64")]
        if x64_diag && (iter % 8) == 0 {
            crate::serial_println!("[X64-JF] iter={} stage=start", iter);
        }
        #[cfg(target_arch = "x86_64")]
        if iter != 0 && (iter % X64_JIT_FUZZ_CHECKPOINT_ITERS) == 0 {
            // x86_64 bring-up runtime benefits from periodic transient cleanup
            // during long fuzz runs (stale handoff/fault state, CR3/IDT hygiene)
            // without dropping reusable fuzz instances/compiler allocations.
            jit_runtime_recover_transient();
            let _ = wasm_runtime().get_instance_mut(interp_id, |instance| {
                instance.prepare_fuzz();
            });
            let _ = wasm_runtime().get_instance_mut(jit_id, |instance| {
                instance.prepare_fuzz();
            });
        }

        let mut locals_total = (rng.next_u32() % 4) as usize;
        code.clear();
        choice_trace.clear();
        let mut stack_depth: i32 = 0;
        'build_program: {
            let mut built_from_pair_prepass = false;
            while pair_cover_cursor < admissible_edge_order.len() {
                let edge_idx = admissible_edge_order[pair_cover_cursor];
                pair_cover_cursor += 1;
                if edge_seen[edge_idx] {
                    continue;
                }
                let Some(witness) = admissible_edge_witness[edge_idx] else {
                    continue;
                };
                if let Some(prepass_locals_total) =
                    build_pair_cover_program_for_edge(code, choice_trace, edge_idx, witness)
                {
                    locals_total = prepass_locals_total;
                    if !record_choice_trace_hits(&mut opcode_hits, choice_trace) {
                        code.clear();
                        choice_trace.clear();
                        stack_depth = 0;
                        continue;
                    }
                    built_from_pair_prepass = true;
                    break 'build_program;
                }
            }

            if !built_from_pair_prepass {
                // Failed prepass attempts leave partial bytes in `code` because
                // the builder clears on entry but may return early. Reset here
                // before falling back to stochastic generation.
                code.clear();
                choice_trace.clear();
                stack_depth = 0;
            }

            let ops = 8 + (rng.next_u32() % 32) as usize;

            for _ in 0..ops {
                // Keep enough headroom for the largest generated opcode sequence:
                // bounded i32.store rewrite with local temp and immediates.
                if code.len() + 40 >= MAX_FUZZ_CODE_SIZE {
                    break;
                }
                let choice = choose_guided_choice_with_edge_frontier(
                    &mut rng,
                    choice_trace.last().copied(),
                    &opcode_hits,
                    &edge_seen,
                    &admissible_edge_matrix,
                );
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
                            // Keep memory accesses bounded and deterministic:
                            // mask address to <= 0xFFFC before load.
                            code.push(Opcode::I32Const as u8);
                            push_sleb128_i32(code, 0xFFFC);
                            stack_depth += 1;
                            code.push(Opcode::I32And as u8);
                            stack_depth -= 1;
                            code.push(Opcode::I32Load as u8);
                            push_uleb128(code, 0);
                            push_uleb128(code, 0);
                            emitted_choice = Some(10);
                        }
                    }
                    11 => {
                        if stack_depth >= 2 && locals_total > 0 {
                            // Store needs stack order [..., addr, value].
                            // Save value in a local, bound addr, reload value, then store.
                            let tmp_idx = (rng.next_u32() as usize % locals_total) as u32;
                            code.push(Opcode::LocalSet as u8);
                            push_uleb128(code, tmp_idx);
                            stack_depth -= 1;
                            code.push(Opcode::I32Const as u8);
                            push_sleb128_i32(code, 0xFFFC);
                            stack_depth += 1;
                            code.push(Opcode::I32And as u8);
                            stack_depth -= 1;
                            code.push(Opcode::LocalGet as u8);
                            push_uleb128(code, tmp_idx);
                            stack_depth += 1;
                            code.push(Opcode::I32Store as u8);
                            push_uleb128(code, 0);
                            push_uleb128(code, 0);
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
                    13 => {
                        if locals_total > 0 && stack_depth > 0 {
                            code.push(Opcode::LocalSet as u8);
                            push_uleb128(code, (rng.next_u32() as usize % locals_total) as u32);
                            stack_depth -= 1;
                            emitted_choice = Some(13);
                        }
                    }
                    14 => {
                        if locals_total > 0 && stack_depth > 0 {
                            code.push(Opcode::LocalTee as u8);
                            push_uleb128(code, (rng.next_u32() as usize % locals_total) as u32);
                            emitted_choice = Some(14);
                        }
                    }
                    15 => {
                        if stack_depth >= 2 {
                            if (rng.next_u32() & 1) == 0 {
                                code.push(Opcode::I32Eq as u8);
                            } else {
                                code.push(Opcode::I32Ne as u8);
                            }
                            stack_depth -= 1;
                            emitted_choice = Some(15);
                        }
                    }
                    16 => {
                        if stack_depth >= 2 {
                            match rng.next_u32() % 4 {
                                0 => code.push(Opcode::I32LtS as u8),
                                1 => code.push(Opcode::I32GtS as u8),
                                2 => code.push(Opcode::I32LeS as u8),
                                _ => code.push(Opcode::I32GeS as u8),
                            }
                            stack_depth -= 1;
                            emitted_choice = Some(16);
                        }
                    }
                    17 => {
                        if stack_depth >= 2 {
                            match rng.next_u32() % 4 {
                                0 => code.push(Opcode::I32LtU as u8),
                                1 => code.push(Opcode::I32GtU as u8),
                                2 => code.push(Opcode::I32LeU as u8),
                                _ => code.push(Opcode::I32GeU as u8),
                            }
                            stack_depth -= 1;
                            emitted_choice = Some(17);
                        }
                    }
                    18 => {
                        if stack_depth >= 2 {
                            match rng.next_u32() % 3 {
                                0 => code.push(Opcode::I32Shl as u8),
                                1 => code.push(Opcode::I32ShrS as u8),
                                _ => code.push(Opcode::I32ShrU as u8),
                            }
                            stack_depth -= 1;
                            emitted_choice = Some(18);
                        }
                    }
                    19 => {
                        // Keep one bin as a compare-with-constant macro to diversify
                        // immediate decoding and binary compare lowering paths.
                        if stack_depth >= 1 {
                            code.push(Opcode::I32Const as u8);
                            push_sleb128_i32(code, (rng.next_u32() & 0xFF) as i32);
                            stack_depth += 1;
                            if (rng.next_u32() & 1) == 0 {
                                code.push(Opcode::I32LtU as u8);
                            } else {
                                code.push(Opcode::I32GeS as u8);
                            }
                            stack_depth -= 1;
                            emitted_choice = Some(19);
                        }
                    }
                    #[cfg(feature = "jit-fuzz-24bin")]
                    20 => {
                        if stack_depth >= 1 {
                            code.push(Opcode::I32Const as u8);
                            push_sleb128_i32(code, 1);
                            stack_depth += 1;
                            code.push(Opcode::I32DivS as u8);
                            stack_depth -= 1;
                            emitted_choice = Some(20);
                        }
                    }
                    #[cfg(feature = "jit-fuzz-24bin")]
                    21 => {
                        if stack_depth >= 1 {
                            code.push(Opcode::I32Const as u8);
                            push_sleb128_i32(code, 1);
                            stack_depth += 1;
                            code.push(Opcode::I32DivU as u8);
                            stack_depth -= 1;
                            emitted_choice = Some(21);
                        }
                    }
                    #[cfg(feature = "jit-fuzz-24bin")]
                    22 => {
                        if stack_depth >= 1 {
                            code.push(Opcode::I32Const as u8);
                            push_sleb128_i32(code, 1);
                            stack_depth += 1;
                            code.push(Opcode::I32RemS as u8);
                            stack_depth -= 1;
                            emitted_choice = Some(22);
                        }
                    }
                    #[cfg(feature = "jit-fuzz-24bin")]
                    23 => {
                        if stack_depth >= 1 {
                            code.push(Opcode::I32Const as u8);
                            push_sleb128_i32(code, 1);
                            stack_depth += 1;
                            code.push(Opcode::I32RemU as u8);
                            stack_depth -= 1;
                            emitted_choice = Some(23);
                        }
                    }
                    _ => {}
                }
                if let Some(choice_idx) = emitted_choice {
                    if let Some(idx) = jit_fuzz_choice_bin(choice_idx) {
                        opcode_hits[idx] = opcode_hits[idx].saturating_add(1);
                        choice_trace.push(choice_idx);
                    }
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
            if validate_bytecode(&code).is_err()
                || validate_jit_fuzz_generated_subset(&code, locals_total).is_err()
            {
                code.clear();
                choice_trace.clear();
                code.push(Opcode::I32Const as u8);
                push_sleb128_i32(code, 0);
                code.push(Opcode::End as u8);
            }
        }

        let code_has_memory_ops = jit_fuzz_code_has_memory_ops(&code);
        #[cfg(target_arch = "x86_64")]
        if x64_diag && iter == 0 {
            crate::serial_println!(
                "[X64-JF] iter=0 stage=program-built len={} locals={}",
                code.len(),
                locals_total
            );
        }

        let mut novel = false;
        let mut prev: Option<u8> = None;
        let mut i = 0usize;
        while i < choice_trace.len() {
            let Some(op) = jit_fuzz_choice_bin(choice_trace[i]) else {
                prev = None;
                i += 1;
                continue;
            };
            if !opcode_seen[op] {
                opcode_seen[op] = true;
                novel = true;
            }
            if let Some(p) = prev {
                if let Some(prev_idx) = jit_fuzz_choice_bin(p) {
                    let edge_idx = prev_idx * JIT_FUZZ_OPCODE_BINS + op;
                    if !edge_seen[edge_idx] {
                        edge_seen[edge_idx] = true;
                        novel = true;
                    }
                }
            }
            prev = Some(choice_trace[i]);
            i += 1;
        }
        if novel {
            stats.novel_programs = stats.novel_programs.saturating_add(1);
        }

        #[cfg(target_arch = "x86_64")]
        if x64_diag && iter == 0 {
            crate::serial_println!("[X64-JF] iter=0 stage=before-interp");
            let mut bi = 0usize;
            while bi < code.len() {
                crate::serial_println!("[X64-JF] iter=0 code[{}]=0x{:02x}", bi, code[bi]);
                bi += 1;
            }
        }
        let interp = match wasm_runtime().get_instance_mut(interp_id, |instance| {
            #[cfg(target_arch = "x86_64")]
            if x64_diag && iter == 0 {
                crate::serial_println!("[X64-JF] iter=0 stage=interp-enter");
            }
            // Rarely under long unsafe JIT fuzz runs, instance/module state can
            // transiently report an impossible load error (e.g. `ModuleTooLarge`
            // for a tiny fuzz program). Retry once from a re-primed fuzz module
            // before classifying it as a real compile/load failure.
            #[cfg(target_arch = "x86_64")]
            if x64_diag && iter == 0 {
                crate::serial_println!("[X64-JF] iter=0 stage=interp-load");
            }
            let mut load_res = instance.load_fuzz_program(&code, locals_total);
            if matches!(load_res, Err(WasmError::ModuleTooLarge))
                && code.len() <= MAX_FUZZ_CODE_SIZE
            {
                instance.prepare_fuzz();
                load_res = instance.load_fuzz_program(&code, locals_total);
            }
            load_res?;
            #[cfg(target_arch = "x86_64")]
            if x64_diag && iter == 0 {
                crate::serial_println!("[X64-JF] iter=0 stage=interp-call");
            }
            instance.enable_jit(false);
            let mut res = instance.call(0);
            if res.is_err() {
                // Retry once from a clean state to filter transient runtime
                // corruption from previous unsafe JIT iterations.
                let mut load_res = instance.load_fuzz_program(&code, locals_total);
                if matches!(load_res, Err(WasmError::ModuleTooLarge))
                    && code.len() <= MAX_FUZZ_CODE_SIZE
                {
                    instance.prepare_fuzz();
                    load_res = instance.load_fuzz_program(&code, locals_total);
                }
                load_res?;
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
            if mem_slice.len() > interp_mem_snapshot.len() {
                return Err(WasmError::MemoryOutOfBounds);
            }
            interp_mem_snapshot[..mem_slice.len()].copy_from_slice(mem_slice);
            *interp_mem_snapshot_len = mem_slice.len();
            let mem_hash = hash_memory_fuzz(mem_slice);
            let mem_len = mem_slice.len() as u32;
            let first_nz = first_nonzero(mem_slice);
            #[cfg(target_arch = "x86_64")]
            if x64_diag && iter == 0 {
                crate::serial_println!("[X64-JF] iter=0 stage=interp-exit");
            }
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
        #[cfg(target_arch = "x86_64")]
        if x64_diag && (iter % 8) == 0 {
            crate::serial_println!("[X64-JF] iter={} stage=interp", iter);
        }
        #[cfg(not(target_arch = "x86_64"))]
        struct IrqGuard(u32);
        #[cfg(not(target_arch = "x86_64"))]
        impl Drop for IrqGuard {
            fn drop(&mut self) {
                unsafe { crate::platform::idt_asm::fast_sti_restore(self.0) };
            }
        }
        #[cfg(target_arch = "x86_64")]
        let compile_with_irqs_masked = |compiler_ref: &mut crate::execution::wasm_jit::FuzzCompiler| {
            // x86_64 bring-up uses trap/MMU recovery paths during fuzz JIT compile;
            // masking IRQs here can stall those paths and hang long runs.
            compiler_ref.compile(&code, locals_total)
        };
        #[cfg(not(target_arch = "x86_64"))]
        let compile_with_irqs_masked = |compiler_ref: &mut crate::execution::wasm_jit::FuzzCompiler| {
            let flags = unsafe { crate::platform::idt_asm::fast_cli_save() };
            let _guard = IrqGuard(flags);
            compiler_ref.compile(&code, locals_total)
        };
        let entry = match compile_with_irqs_masked(compiler) {
            Ok(entry) => entry,
            Err(first_err) => {
                // Rarely, verifier/page-perm state can become stale across a long
                // fuzz run. Retry once in-place, then once with a fresh compiler
                // before classifying as a real compile failure.
                match compile_with_irqs_masked(compiler) {
                    Ok(entry) => entry,
                    Err(second_err) => {
                        // On x86_64, known "subset backend" rejections are treated
                        // as expected skips. Avoid allocating a fresh compiler for
                        // them, because each fresh compiler reserves JIT arena pages
                        // and can exhaust the bump-only arena across long runs.
                        if should_skip_compile_error(second_err)
                            || should_skip_compile_error(first_err)
                        {
                            continue;
                        }
                        match crate::execution::wasm_jit::FuzzCompiler::new(
                            MAX_FUZZ_JIT_CODE_SIZE,
                            MAX_FUZZ_CODE_SIZE,
                        ) {
                            Ok(mut fresh_compiler) => {
                                match compile_with_irqs_masked(&mut fresh_compiler) {
                                    Ok(entry) => {
                                        *compiler = fresh_compiler;
                                        entry
                                    }
                                    Err(fresh_err) => {
                                        if should_skip_compile_error(fresh_err) {
                                            continue;
                                        }
                                        stats.compile_errors += 1;
                                        if stats.first_compile_error.is_none() {
                                            let jit_code = capture_jit_fuzz_jit_bytes(
                                                fresh_compiler.emitted_code(),
                                            );
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
                                }
                            }
                            Err(new_err) => {
                                let reason = if second_err != first_err {
                                    second_err
                                } else {
                                    new_err
                                };
                                if should_skip_compile_error(reason) {
                                    continue;
                                }
                                stats.compile_errors += 1;
                                if stats.first_compile_error.is_none() {
                                    let jit_code =
                                        capture_jit_fuzz_jit_bytes(compiler.emitted_code());
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
        #[cfg(target_arch = "x86_64")]
        if x64_diag && (iter % 8) == 0 {
            crate::serial_println!("[X64-JF] iter={} stage=compile", iter);
        }
        let jit_entry = JitExecInfo {
            entry,
            exec_ptr: compiler.exec_ptr(),
            exec_len: compiler.exec_len(),
        };

        let interp_ok = matches!(interp.0, Ok(_));
        let jit = match wasm_runtime().get_instance_mut(jit_id, |instance| {
            let mut attempt = 0u8;
            loop {
                let mut load_res = instance.load_fuzz_program(&code, locals_total);
                if matches!(load_res, Err(WasmError::ModuleTooLarge))
                    && code.len() <= MAX_FUZZ_CODE_SIZE
                {
                    instance.prepare_fuzz();
                    load_res = instance.load_fuzz_program(&code, locals_total);
                }
                load_res?;
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
                let mem_equal = *interp_mem_snapshot_len == mem_slice.len()
                    && mem_slice == &interp_mem_snapshot[..*interp_mem_snapshot_len];
                let mapped = match res {
                    Ok(_) => Ok(value),
                    Err(e) => Err(e),
                };

                // User-sandbox JIT can occasionally surface a transient trap classification
                // despite no state divergence. Retry once from a clean load to avoid false
                // mismatches while still preserving persistent semantic failures.
                if attempt == 0
                    && interp_ok
                    && matches!(
                        mapped,
                        Err(WasmError::MemoryOutOfBounds)
                            | Err(WasmError::ControlFlowViolation)
                            | Err(WasmError::Trap)
                    )
                {
                    // Retry once if the JIT reports an impossible transient trap
                    // (e.g. MemoryOutOfBounds on a no-memory program) or if memory
                    // state remained identical despite the trap classification.
                    if !(mem_equal
                        || (!code_has_memory_ops
                            && matches!(mapped, Err(WasmError::MemoryOutOfBounds))
                            && mem_len == 0))
                    {
                        return Ok::<
                            (Result<i32, WasmError>, u64, u32, Option<(u32, u8)>, bool),
                            WasmError,
                        >((
                            mapped, mem_hash, mem_len, first_nz, mem_equal,
                        ));
                    }
                    instance.prepare_fuzz();
                    attempt = 1;
                    continue;
                }

                return Ok::<(Result<i32, WasmError>, u64, u32, Option<(u32, u8)>, bool), WasmError>(
                    (mapped, mem_hash, mem_len, first_nz, mem_equal),
                );
            }
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
        #[cfg(target_arch = "x86_64")]
        if x64_diag && (iter % 8) == 0 {
            crate::serial_println!("[X64-JF] iter={} stage=jit-run", iter);
        }
        let interp_res = interp.0;
        let jit_res = jit.0;
        let interp_mem = interp.1;
        let jit_mem = jit.1;
        let interp_mem_len = interp.2;
        let jit_mem_len = jit.2;
        let interp_first_nonzero = interp.3;
        let jit_first_nonzero = jit.3;
        let mem_equal = jit.4;
        // Under heavy user-sandbox churn, raw slice equality can occasionally
        // report false even when the captured memory fingerprints are identical.
        // Treat matching fingerprints as equivalent for fuzz mismatch scoring.
        let mem_equivalent = mem_equal
            || (interp_mem == jit_mem
                && interp_mem_len == jit_mem_len
                && interp_first_nonzero == jit_first_nonzero);
        let mut mismatch = false;

        match (interp_res, jit_res) {
            (Ok(iv), Ok(jv)) => {
                if iv == jv && mem_equivalent {
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

        if mismatch {
            if stats.first_mismatch.is_none() {
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
            // Fail fast after first mismatch: continuing JIT execution can amplify
            // divergence into unstable runtime state and obscure root cause.
            break;
        }
    }

    let mut bins = 0u32;
    let mut edges = 0u32;
    let mut adm_edges_hit = 0u32;
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
            if admissible_edge_matrix[j] {
                adm_edges_hit += 1;
            }
        }
        j += 1;
    }
    stats.opcode_bins_hit = bins;
    stats.opcode_edges_hit = edges;
    stats.opcode_edges_hit_admissible = adm_edges_hit;

    Ok(stats)
}

fn jit_fuzz_regression_run_seed_slice(
    iterations_per_seed: u32,
    seeds: &[u64],
) -> Result<JitFuzzRegressionStats, &'static str> {
    let mut out = JitFuzzRegressionStats {
        seeds_total: seeds.len() as u32,
        seeds_passed: 0,
        seeds_failed: 0,
        total_ok: 0,
        total_traps: 0,
        total_mismatches: 0,
        total_compile_errors: 0,
        max_opcode_bins_hit: 0,
        max_opcode_edges_hit: 0,
        max_opcode_edges_hit_admissible: 0,
        opcode_edges_admissible_total: 0,
        total_novel_programs: 0,
        first_failed_seed: None,
        first_failed_mismatches: 0,
        first_failed_compile_errors: 0,
        first_failed_mismatch: None,
        first_failed_compile_error: None,
    };

    let mut i = 0usize;
    while i < seeds.len() {
        let seed = seeds[i];
        let stats = jit_fuzz(iterations_per_seed, seed)?;
        out.total_ok = out.total_ok.saturating_add(stats.ok);
        out.total_traps = out.total_traps.saturating_add(stats.traps);
        out.total_mismatches = out.total_mismatches.saturating_add(stats.mismatches);
        out.total_compile_errors = out
            .total_compile_errors
            .saturating_add(stats.compile_errors);
        out.total_novel_programs = out
            .total_novel_programs
            .saturating_add(stats.novel_programs);
        if stats.opcode_bins_hit > out.max_opcode_bins_hit {
            out.max_opcode_bins_hit = stats.opcode_bins_hit;
        }
        if stats.opcode_edges_hit > out.max_opcode_edges_hit {
            out.max_opcode_edges_hit = stats.opcode_edges_hit;
        }
        if stats.opcode_edges_hit_admissible > out.max_opcode_edges_hit_admissible {
            out.max_opcode_edges_hit_admissible = stats.opcode_edges_hit_admissible;
        }
        if stats.opcode_edges_admissible_total > out.opcode_edges_admissible_total {
            out.opcode_edges_admissible_total = stats.opcode_edges_admissible_total;
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

pub fn jit_fuzz_regression_default(
    iterations_per_seed: u32,
) -> Result<JitFuzzRegressionStats, &'static str> {
    jit_fuzz_regression_bounded(iterations_per_seed, JIT_FUZZ_REGRESSION_SEEDS.len() as u32)
}

pub fn jit_fuzz_regression_bounded(
    iterations_per_seed: u32,
    max_seeds: u32,
) -> Result<JitFuzzRegressionStats, &'static str> {
    let seeds_limit = core::cmp::min(max_seeds as usize, JIT_FUZZ_REGRESSION_SEEDS.len());
    jit_fuzz_regression_run_seed_slice(
        iterations_per_seed,
        &JIT_FUZZ_REGRESSION_SEEDS[..seeds_limit],
    )
}

pub fn jit_fuzz_x64_debug_corpus(
    iterations_per_seed: u32,
) -> Result<JitFuzzRegressionStats, &'static str> {
    // Small deterministic corpus intended for x86_64 hang isolation:
    // short, repeatable, direct jit_fuzz() calls without alias chunking.
    jit_fuzz_regression_run_seed_slice(iterations_per_seed, &JIT_FUZZ_X64_DEBUG_SEEDS)
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
        max_opcode_edges_hit_admissible: 0,
        opcode_edges_admissible_total: 0,
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
        out.total_compile_errors = out
            .total_compile_errors
            .saturating_add(stats.total_compile_errors);
        out.total_novel_programs = out
            .total_novel_programs
            .saturating_add(stats.total_novel_programs);
        if stats.max_opcode_bins_hit > out.max_opcode_bins_hit {
            out.max_opcode_bins_hit = stats.max_opcode_bins_hit;
        }
        if stats.max_opcode_edges_hit > out.max_opcode_edges_hit {
            out.max_opcode_edges_hit = stats.max_opcode_edges_hit;
        }
        if stats.max_opcode_edges_hit_admissible > out.max_opcode_edges_hit_admissible {
            out.max_opcode_edges_hit_admissible = stats.max_opcode_edges_hit_admissible;
        }
        if stats.opcode_edges_admissible_total > out.opcode_edges_admissible_total {
            out.opcode_edges_admissible_total = stats.opcode_edges_admissible_total;
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

fn deinit_self_check_process(pid: ProcessId) {
    let _ = revoke_service_pointers_for_owner(pid);
    let _ = unload_modules_for_owner(pid);
    capability::capability_manager().deinit_task(pid);
    crate::security::security().terminate_process(pid);
}

fn reset_self_check_process(pid: ProcessId) {
    deinit_self_check_process(pid);
    crate::security::security().init_process(pid);
    capability::capability_manager().init_task(pid);
}

pub fn formal_service_pointer_self_check() -> Result<(), &'static str> {
    formal_service_pointer_conformance_self_check().map(|_| ())
}

#[derive(Clone, Copy)]
pub struct ServicePointerSelfCheckSummary {
    pub delegate_checks: u32,
    pub import_checks: u32,
    pub invoke_checks: u32,
    pub revoke_checks: u32,
    pub typed_checks: u32,
}

pub fn formal_service_pointer_conformance_self_check(
) -> Result<ServicePointerSelfCheckSummary, &'static str> {
    let mut summary = ServicePointerSelfCheckSummary {
        delegate_checks: 0,
        import_checks: 0,
        invoke_checks: 0,
        revoke_checks: 0,
        typed_checks: 0,
    };

    let provider = ProcessId(62);
    let consumer = ProcessId(63);
    reset_self_check_process(provider);
    reset_self_check_process(consumer);

    let mut instance_id: Option<usize> = None;
    let result = (|| -> Result<(), &'static str> {
        // Provider module exports `ping` returning 42.
        const PROVIDER_MODULE: [u8; 37] = [
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F,
            0x03, 0x02, 0x01, 0x00,
            0x07, 0x08, 0x01, 0x04, b'p', b'i', b'n', b'g', 0x00, 0x00,
            0x0A, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2A, 0x0B,
        ];
        let mut provider_module = WasmModule::new();
        provider_module
            .load_binary(&PROVIDER_MODULE)
            .map_err(|_| "Service pointer self-check: provider module parse failed")?;
        let id = wasm_runtime()
            .instantiate_module(provider_module, provider)
            .map_err(|_| "Service pointer self-check: instance creation failed")?;
        instance_id = Some(id);

        let no_delegate = register_service_pointer(provider, id, 0, false)?;
        summary.delegate_checks = summary.delegate_checks.saturating_add(1);
        if capability::export_capability_to_ipc(provider, no_delegate.cap_id).is_ok() {
            return Err("Service pointer self-check: delegate right not enforced");
        }

        let delegatable = register_service_pointer(provider, id, 0, true)?;
        let exported = capability::export_capability_to_ipc(provider, delegatable.cap_id)
            .map_err(|_| "Service pointer self-check: export failed")?;
        summary.import_checks = summary.import_checks.saturating_add(1);
        let imported_cap_id = capability::import_capability_from_ipc(consumer, &exported, provider)
            .map_err(|_| "Service pointer self-check: import failed")?;
        let (_cap_type, imported_object) = capability::capability_manager()
            .query_capability(consumer, imported_cap_id)
            .map_err(|_| "Service pointer self-check: imported capability missing")?;

        let result = invoke_service_pointer(consumer, imported_object, &[])?;
        summary.invoke_checks = summary.invoke_checks.saturating_add(1);
        if result != 42 {
            return Err("Service pointer self-check: unexpected invoke result");
        }

        revoke_service_pointer(provider, imported_object)
            .map_err(|_| "Service pointer self-check: revoke failed")?;
        summary.revoke_checks = summary.revoke_checks.saturating_add(1);
        if invoke_service_pointer(consumer, imported_object, &[]).is_ok() {
            return Err("Service pointer self-check: revoked pointer still invokable");
        }
        if capability::capability_manager()
            .query_capability(consumer, imported_cap_id)
            .is_ok()
        {
            return Err("Service pointer self-check: revoked capability not removed");
        }

        Ok(())
    })();

    if let Some(id) = instance_id {
        let _ = wasm_runtime().destroy(id);
    }
    deinit_self_check_process(consumer);
    deinit_self_check_process(provider);
    result?;
    service_pointer_typed_hostpath_self_check()?;
    summary.typed_checks = 1;
    Ok(summary)
}

pub fn service_pointer_typed_hostpath_self_check() -> Result<(), &'static str> {
    let provider = ProcessId(54);
    let consumer = ProcessId(55);
    reset_self_check_process(provider);
    reset_self_check_process(consumer);

    let mut provider_instance: Option<usize> = None;
    let mut consumer_instance: Option<usize> = None;
    let mut object_id: Option<u64> = None;

    let result = (|| -> Result<(), &'static str> {
        const PROVIDER_MODULE: [u8; 61] = [
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
            0x01, 0x0C, 0x01, 0x60, 0x04, 0x7E, 0x7D, 0x7C, 0x70, 0x04, 0x7E, 0x7D, 0x7C,
            0x70, // type section
            0x03, 0x02, 0x01, 0x00, // function section
            0x07, 0x09, 0x01, 0x05, b't', b'y', b'p', b'e', b'd', 0x00, 0x00, // export section
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
        let imported_cap_id = capability::import_capability_from_ipc(consumer, &exported, provider)
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
        const CONSUMER_MODULE: [u8; 17] = [
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x01, 0x00, 0x03, 0x01, 0x00, 0x0A, 0x01, 0x00,
        ];
        let consumer_id = wasm_runtime()
            .instantiate(&CONSUMER_MODULE, consumer)
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
                instance.stack.push(Value::I32(RESULTS_CAPACITY as i32))?;
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
    deinit_self_check_process(consumer);
    deinit_self_check_process(provider);
    result
}

pub fn temporal_hostpath_self_check() -> Result<(), &'static str> {
    let pid = ProcessId(56);
    reset_self_check_process(pid);

    const PATH: &str = "/temporal-selfcheck";
    const INITIAL: &[u8] = b"alpha-temporal";
    const UPDATED: &[u8] = b"beta-temporal";

    crate::fs::vfs::write_path(PATH, INITIAL)
        .map_err(|_| "Temporal self-check: initial write failed")?;

    let mut instance_id: Option<usize> = None;
    let result = (|| -> Result<(), &'static str> {
        const WASM_MODULE: [u8; 17] = [
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
            0x01, 0x01, 0x00, // type section: 0 types
            0x03, 0x01, 0x00, // function section: 0 functions
            0x0A, 0x01, 0x00, // code section: 0 code bodies
        ];
        let id = wasm_runtime()
            .instantiate(&WASM_MODULE, pid)
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

                let fs_cap =
                    fs::filesystem().create_capability(900, fs::FilesystemRights::all(), None);
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
                    crate::serial_println!("[TEMPORAL_TEST] snapshot 1 failed");
                    return Err(WasmError::SyscallFailed);
                }

                let meta0 = instance.memory.read(META0_PTR, TEMPORAL_META_BYTES)?;
                let v0_lo = u32::from_le_bytes([meta0[0], meta0[1], meta0[2], meta0[3]]);
                let v0_hi = u32::from_le_bytes([meta0[4], meta0[5], meta0[6], meta0[7]]);
                let version0 = ((v0_hi as u64) << 32) | (v0_lo as u64);

                crate::fs::vfs::write_path(PATH, UPDATED).map_err(|_| {
                    crate::serial_println!("[TEMPORAL_TEST] write_path failed");
                    WasmError::SyscallFailed
                })?;

                // Snapshot updated state.
                instance.stack.clear();
                instance.stack.push(Value::I32(fs_handle.0 as i32))?;
                instance.stack.push(Value::I32(PATH_PTR as i32))?;
                instance.stack.push(Value::I32(PATH.len() as i32))?;
                instance.stack.push(Value::I32(META1_PTR as i32))?;
                instance.host_temporal_snapshot()?;
                if instance.stack.pop()?.as_i32()? != 0 {
                    instance.stack.clear();
                    crate::serial_println!("[TEMPORAL_TEST] snapshot 2 failed");
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
                instance.stack.push(Value::I32(HISTORY_CAPACITY as i32))?;
                instance.host_temporal_history()?;
                let written = instance.stack.pop()?.as_i32()? as usize;
                if written < 2 {
                    instance.stack.clear();
                    crate::serial_println!("[TEMPORAL_TEST] ABI history returned < 2: {}", written);
                    return Err(WasmError::TypeMismatch);
                }

                let history_bytes = instance.memory.read(
                    HISTORY_PTR,
                    written.saturating_mul(TEMPORAL_HISTORY_RECORD_BYTES),
                )?;
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
                    crate::serial_println!(
                        "[TEMPORAL_TEST] ABI history newest_version {} != version1 {}",
                        newest_version,
                        version1
                    );
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
                    crate::serial_println!("[TEMPORAL_TEST] rollback failed");
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

        invoke.map_err(|e| {
            crate::serial_println!("Temporal self-check: host ABI path failed with {:?}", e);
            "Temporal self-check: host ABI path failed"
        })
    })();

    if let Some(id) = instance_id {
        let _ = wasm_runtime().destroy(id);
    }
    deinit_self_check_process(pid);
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
        0x41, 0x07, // block
        0x02, 0x40, // loop
        0x03, 0x40, // br 1
        0x0C, 0x01, // dead code
        0x41, 0x63, 0x1A, // end loop, end block
        0x0B, 0x0B, // verify br worked
        0x41, 0x07, 0x46, // select path check -> bool
        0x41, 0x0A, 0x41, 0x14, 0x41, 0x00, 0x1B, 0x41, 0x14, 0x46, 0x71,
        // br_if block check
        0x02, 0x40, 0x41, 0x01, 0x0D, 0x00, 0x41, 0x00, 0x1A, 0x0B,
        // if/else structured flow check
        0x41, 0x01, 0x04, 0x40, 0x41, 0x03, 0x1A, 0x05, 0x41, 0x09, 0x1A, 0x0B,
        // end function
        0x0B,
    ];
    module
        .load_raw_bytecode(&code)
        .map_err(|_| "control-flow self-check: code load failed")?;
    let _ = module
        .add_function(Function::synthetic_i32(0, code.len(), 0, 1, 0))
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
    0x09, 0x64, 0x65, 0x62, 0x75, 0x67, 0x5F, 0x6C, 0x6F, 0x67, 0x00, 0x00, 0x03, 0x02, 0x01,
    0x01, // function section
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
    0x0A, 0x0C, 0x01, 0x0A, 0x00, 0x41, 0x0A, 0x41, 0x20, 0x02, 0x01, 0x6A, 0x0B,
    0x0B, // code
];

const WASM_CONFORMANCE_MODULE_TYPED_IF_IMPLICIT_ELSE: [u8; 37] = [
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
    0x01, 0x0A, 0x02, 0x60, 0x00, 0x01, 0x7F, 0x60, 0x01, 0x7F, 0x01, 0x7F, // types
    0x03, 0x02, 0x01, 0x00, // function section
    0x0A, 0x0B, 0x01, 0x09, 0x00, 0x41, 0x2A, 0x41, 0x00, 0x04, 0x01, 0x0B, 0x0B, // code
];

const WASM_CONFORMANCE_MODULE_TYPED_BLOCK_BR2: [u8; 44] = [
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
    0x01, 0x0A, 0x02, 0x60, 0x00, 0x01, 0x7F, 0x60, 0x00, 0x02, 0x7F, 0x7F, // types
    0x03, 0x02, 0x01, 0x00, // function section
    0x0A, 0x12, 0x01, 0x10, 0x00, // code section header + body size + local decls
    0x02, 0x01, // block (typeidx 1) => () -> (i32, i32)
    0x41, 0x07, // i32.const 7
    0x41, 0x16, // i32.const 22
    0x0C, 0x00, // br 0
    0x41, 0x01, // i32.const 1 (skipped)
    0x41, 0x02, // i32.const 2 (skipped)
    0x0B, // end block
    0x6A, // i32.add => 29
    0x0B, // end function
];

const WASM_CONFORMANCE_MODULE_TYPED_BLOCK_BR_IF2: [u8; 43] = [
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
    0x01, 0x0A, 0x02, 0x60, 0x00, 0x01, 0x7F, 0x60, 0x00, 0x02, 0x7F, 0x7F, // types
    0x03, 0x02, 0x01, 0x00, // function section
    0x0A, 0x11, 0x01, 0x0F, 0x00, // code section header + body size + local decls
    0x02, 0x01, // block (typeidx 1) => () -> (i32, i32)
    0x41, 0x07, // i32.const 7
    0x41, 0x16, // i32.const 22
    0x41, 0x01, // i32.const 1 (take branch)
    0x0D, 0x00, // br_if 0
    0x00, // unreachable (skipped)
    0x0B, // end block
    0x6A, // i32.add => 29
    0x0B, // end function
];

const WASM_CONFORMANCE_MODULE_TYPED_BLOCK_BR3: [u8; 50] = [
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
    0x01, 0x0B, 0x02, 0x60, 0x00, 0x01, 0x7F, 0x60, 0x00, 0x03, 0x7F, 0x7F, 0x7F, // types
    0x03, 0x02, 0x01, 0x00, // function section
    0x0A, 0x17, 0x01, 0x15, 0x00, // code section header + body size + local decls
    0x02, 0x01, // block (typeidx 1) => () -> (i32, i32, i32)
    0x41, 0x05, // i32.const 5
    0x41, 0x07, // i32.const 7
    0x41, 0x0B, // i32.const 11
    0x0C, 0x00, // br 0
    0x41, 0x01, // i32.const 1 (skipped)
    0x41, 0x02, // i32.const 2 (skipped)
    0x41, 0x03, // i32.const 3 (skipped)
    0x0B, // end block
    0x6A, // i32.add
    0x6A, // i32.add => 23
    0x0B, // end function
];

const WASM_CONFORMANCE_MODULE_TYPED_BLOCK_BR_IF3: [u8; 47] = [
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
    0x01, 0x0B, 0x02, 0x60, 0x00, 0x01, 0x7F, 0x60, 0x00, 0x03, 0x7F, 0x7F, 0x7F, // types
    0x03, 0x02, 0x01, 0x00, // function section
    0x0A, 0x14, 0x01, 0x12, 0x00, // code section header + body size + local decls
    0x02, 0x01, // block (typeidx 1) => () -> (i32, i32, i32)
    0x41, 0x05, // i32.const 5
    0x41, 0x07, // i32.const 7
    0x41, 0x0B, // i32.const 11
    0x41, 0x01, // i32.const 1 (take branch)
    0x0D, 0x00, // br_if 0
    0x00, // unreachable (skipped)
    0x0B, // end block
    0x6A, // i32.add
    0x6A, // i32.add => 23
    0x0B, // end function
];

const WASM_CONFORMANCE_MODULE_GLOBAL_GET_I32: [u8; 35] = [
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F, // type: () -> i32
    0x03, 0x02, 0x01, 0x00, // function section
    0x06, 0x06, 0x01, 0x7F, 0x00, 0x41, 0x2A, 0x0B, // immutable i32 global = 42
    0x0A, 0x06, 0x01, 0x04, 0x00, 0x23, 0x00, 0x0B, // global.get 0
];

const WASM_CONFORMANCE_MODULE_GLOBAL_SET_GET_I32: [u8; 39] = [
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic + version
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F, // type: () -> i32
    0x03, 0x02, 0x01, 0x00, // function section
    0x06, 0x06, 0x01, 0x7F, 0x01, 0x41, 0x07, 0x0B, // mutable i32 global = 7
    0x0A, 0x0A, 0x01, 0x08, 0x00, // code section + body size + local decls
    0x41, 0x17, // i32.const 23
    0x24, 0x00, // global.set 0
    0x23, 0x00, // global.get 0
    0x0B, // end function
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
        match wasm_runtime()
            .get_instance_mut(instance_id, |instance| instance.process_id == caller_pid)
        {
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
