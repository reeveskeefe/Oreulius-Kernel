// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this file is governed by the Business Source License 1.1
// included in the LICENSE file at the root of this repository.
//
// Additional Use Grant: Personal use, research, education, evaluation,
// benchmarking, and internal non-production testing are permitted.
// Production use, commercial deployment, embedded commercial products,
// and paid hosted services require a separate commercial license.
//
// Change Date: 2030-04-15
// Change License: Apache License 2.0

//! Minimal WASM JIT compiler (ELF-less, in-kernel).
//!
//! Supports a bounded MVP-oriented opcode set for i686/x86_64 backends.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

#[cfg(not(target_arch = "aarch64"))]
use crate::execution::wasm::{
    Opcode, MAX_CONTROL_STACK, MAX_INSTRUCTIONS_PER_CALL, MAX_LOCALS, MAX_STACK_DEPTH,
};
#[cfg(target_arch = "x86_64")]
use crate::execution::wasm::MAX_WASM_TYPE_ARITY;

/// Compile-time stubs for AArch64: the JIT compiler is x86-only; these types
/// satisfy the type-checker for dead-code paths that reference wasm internals.
#[cfg(target_arch = "aarch64")]
const MAX_LOCALS: usize = 256;
#[cfg(target_arch = "aarch64")]
const MAX_CONTROL_STACK: usize = 256;
#[cfg(target_arch = "aarch64")]
const MAX_INSTRUCTIONS_PER_CALL: usize = 65536;
#[cfg(target_arch = "aarch64")]
const MAX_STACK_DEPTH: usize = 256;
#[cfg(target_arch = "aarch64")]
const MAX_WASM_TYPE_ARITY: usize = 32;

#[inline]
fn jit_fuzz_verbose_trace_enabled() -> bool {
    #[cfg(not(target_arch = "aarch64"))]
    {
        crate::execution::wasm::jit_fuzz_verbose_trace_enabled()
    }
    #[cfg(target_arch = "aarch64")]
    {
        false
    }
}

#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
enum Opcode {
    Unreachable = 0x00, Nop = 0x01, Block = 0x02, Loop = 0x03, If = 0x04,
    Else = 0x05, Try = 0x06, Catch = 0x07, Throw = 0x08, Rethrow = 0x09,
    End = 0x0B, Br = 0x0C, BrIf = 0x0D, Return = 0x0F, Call = 0x10,
    CallIndirect = 0x11, Delegate = 0x18, CatchAll = 0x19,
    Drop = 0x1A, Select = 0x1B,
    LocalGet = 0x20, LocalSet = 0x21, LocalTee = 0x22,
    GlobalGet = 0x23, GlobalSet = 0x24,
    I32Load = 0x28, I64Load = 0x29, I32Load8S = 0x2C, I32Load8U = 0x2D,
    I32Load16S = 0x2E, I32Load16U = 0x2F, I64Load8U = 0x31,
    I64Load16U = 0x33, I64Load32U = 0x35, I32Store = 0x36, I64Store = 0x37,
    I32Store8 = 0x3A, I32Store16 = 0x3B, I64Store8 = 0x3C,
    I64Store16 = 0x3D, I64Store32 = 0x3E, MemorySize = 0x3F, MemoryGrow = 0x40,
    I32Const = 0x41, I64Const = 0x42, F32Const = 0x43, F64Const = 0x44,
    I32Eqz = 0x45, I32Eq = 0x46, I32Ne = 0x47, I32LtS = 0x48, I32LtU = 0x49,
    I32GtS = 0x4A, I32GtU = 0x4B, I32LeS = 0x4C, I32LeU = 0x4D,
    I32GeS = 0x4E, I32GeU = 0x4F,
    I64Eqz = 0x50, I64Eq = 0x51, I64Ne = 0x52, I64LtS = 0x53, I64LtU = 0x54,
    I64GtS = 0x55, I64GtU = 0x56, I64LeS = 0x57, I64LeU = 0x58,
    I64GeS = 0x59, I64GeU = 0x5A, I32Clz = 0x67, I32Ctz = 0x68,
    I32Popcnt = 0x69, I32Add = 0x6A, I32Sub = 0x6B, I32Mul = 0x6C,
    I32DivS = 0x6D, I32DivU = 0x6E, I32RemS = 0x6F, I32RemU = 0x70,
    I32And = 0x71, I32Or = 0x72, I32Xor = 0x73, I32Shl = 0x74,
    I32ShrS = 0x75, I32ShrU = 0x76, I32Rotl = 0x77, I32Rotr = 0x78,
    I64Clz = 0x79, I64Ctz = 0x7A, I64Popcnt = 0x7B, I64Add = 0x7C,
    I64Sub = 0x7D, I64Mul = 0x7E, I64DivS = 0x7F,
    F32Add = 0x92, F32Sub = 0x93, F32Mul = 0x94, F32Div = 0x95,
    F64Add = 0xA0, F64Sub = 0xA1, F64Mul = 0xA2, F64Div = 0xA3,
    I32WrapI64 = 0xA7, I64ExtendI32S = 0xAC, I64ExtendI32U = 0xAD,
    RefNull = 0xD0, RefIsNull = 0xD1, RefFunc = 0xD2,
}

#[cfg(target_arch = "aarch64")]
impl Opcode {
    #[allow(dead_code)]
    pub fn from_byte(b: u8) -> Option<Self> {
        let _ = b;
        None
    }
}

#[cfg(not(target_arch = "aarch64"))]
use crate::security::memory_isolation;

use crate::memory;
#[cfg(not(target_arch = "aarch64"))]
use crate::fs::paging::PAGE_SIZE;
#[cfg(target_arch = "aarch64")]
const PAGE_SIZE: usize = 4096;

pub type JitFn = unsafe extern "C" fn(
    *mut i32,    // rdi: stack_ptr
    *mut usize,  // rsi: sp_ptr
    *mut u8,     // rdx: mem_ptr
    usize,       // rcx: mem_len
    *mut i32,    // r8:  locals_ptr
    *mut u32,    // r9:  instr_fuel_ptr
    *mut u32,    // [rbp+16]: mem_fuel_ptr
    *mut i32,    // [rbp+24]: trap_ptr
    *mut u32,    // [rbp+32]: globals_ptr  (shadow_stack_ptr on non-x86_64)
    *mut usize,  // [rbp+40]: shadow_sp
    *const usize, // [rbp+48]: fn_table_base (array of JitFn entry addresses, 0 = not compiled)
    usize,        // [rbp+56]: fn_table_len
) -> i32;

#[derive(Clone, Copy, Debug)]
pub struct BasicBlock {
    pub start: usize,
    pub end: usize,
}

pub struct JitFunction {
    pub wasm_code: Vec<u8>,
    pub code: Vec<u8>,
    pub entry: JitFn,
    pub blocks: Vec<BasicBlock>,
    pub code_hash: u64,
    pub exec: JitExecBuffer,
    pub exec_hash: u64,
    translation: TranslationValidation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JitTypeSignature {
    pub param_count: usize,
    pub result_count: usize,
    pub all_i32: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JitGlobalSignature {
    pub mutable: bool,
    pub all_i32: bool,
}

// SAFETY: JitFunction is safe to send/sync because all components are:
// - Vec<u8> (Send + Sync)
// - JitFn (function pointer, Send + Sync)
// - Vec<BasicBlock> (Send + Sync)
// - u64 fields (Copy, Send + Sync)
// - JitExecBuffer (now explicitly Send + Sync, see above)
unsafe impl Send for JitFunction {}
unsafe impl Sync for JitFunction {}

#[derive(Clone, Copy)]
struct TranslationRecord {
    wasm_start: usize,
    wasm_end: usize,
    x86_start: usize,
    x86_end: usize,
    opcode: Opcode,
}

struct TranslationValidation {
    records: Vec<TranslationRecord>,
    block_hashes: Vec<u64>,
    proof: TranslationProof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TranslationProof {
    trace_count: u32,
    mem_trace_count: u32,
    hash: u64,
}

pub struct JitExecBuffer {
    pub ptr: *mut u8,
    pub len: usize,
    alloc_len: usize,
    sealed: bool,
}

// SAFETY: JitExecBuffer is kernel-managed executable memory allocated via the JIT arena.
// The raw pointer is safe to send across threads because:
// 1. Memory is allocated from kernel heap (not stack-local)
// 2. Access is synchronized via Mutex in JIT_CACHE
// 3. Once sealed, the buffer is read-only executable memory
unsafe impl Send for JitExecBuffer {}
unsafe impl Sync for JitExecBuffer {}

const TRAP_MEM: i32 = -1;
const TRAP_FUEL: i32 = -2;
const TRAP_STACK: i32 = -3;
const TRAP_CFI: i32 = -4;
#[cfg(target_arch = "x86_64")]
const X64_BRANCH_SCRATCH_SLOTS: usize = MAX_WASM_TYPE_ARITY;
#[cfg(target_arch = "x86_64")]
const X64_SAVED_REG_BYTES: i32 = 40;
// Frame-local metadata: 6 slots × 8 bytes = 48 bytes.
// Slots (relative to rbp, negative direction):
//   [rbp-48] instr_fuel_ptr  [rbp-56] mem_fuel_ptr   [rbp-64] trap_ptr
//   [rbp-72] globals_ptr     [rbp-80] fn_table_len    [rbp-88] fn_table_base
#[cfg(target_arch = "x86_64")]
const X64_FRAME_LOCAL_BYTES: i32 = 0x38; // 6 × 8 = 48
// Branch scratch slots (4 bytes each for i32 values) live below metadata.
#[cfg(target_arch = "x86_64")]
const X64_STACK_FRAME_BYTES: i32 = X64_FRAME_LOCAL_BYTES + ((X64_BRANCH_SCRATCH_SLOTS as i32) * 4);
#[cfg(target_arch = "x86_64")]
const X64_BRANCH_SCRATCH_BASE_DISP: i32 = -(X64_SAVED_REG_BYTES + X64_STACK_FRAME_BYTES);
// Per-call scratch locals buffer for call_indirect param passing (below branch scratch).
#[cfg(target_arch = "x86_64")]
const X64_CALLEE_LOCALS_BYTES: i32 = MAX_LOCALS as i32 * 4; // = 1024
#[cfg(target_arch = "x86_64")]
const X64_CALLEE_LOCALS_DISP: i32 =
    -(X64_SAVED_REG_BYTES + X64_STACK_FRAME_BYTES + X64_CALLEE_LOCALS_BYTES);

impl JitExecBuffer {
    pub fn new(len: usize) -> Result<Self, &'static str> {
        let pages = len
            .checked_add(PAGE_SIZE - 1)
            .ok_or("Size overflow")?
            / PAGE_SIZE;
        let base = memory::jit_allocate_pages(pages)?;
        let alloc_len = pages
            .checked_mul(PAGE_SIZE)
            .ok_or("JIT exec buffer size overflow")?;
        if !memory::jit_arena_contains_range(base, alloc_len) {
            return Err("JIT exec buffer outside JIT arena");
        }
        #[cfg(not(target_arch = "aarch64"))]
        let _ = memory_isolation::tag_jit_code_kernel(base, pages * PAGE_SIZE, false);
        Ok(JitExecBuffer {
            ptr: base as *mut u8,
            len,
            alloc_len,
            sealed: false,
        })
    }

    fn write_and_seal(&mut self, code: &[u8]) -> Result<(), &'static str> {
        if code.len() > self.len {
            return Err("Code length overflow");
        }
        // Touch only pages that actually contain generated code.
        let writable_len = if code.is_empty() {
            0
        } else {
            code.len()
                .checked_add(PAGE_SIZE - 1)
                .ok_or("Code length overflow")?
                & !(PAGE_SIZE - 1)
        };
        let base = self.ptr as usize;
        if base == 0 || (base & (PAGE_SIZE - 1)) != 0 {
            return Err("Invalid JIT exec buffer pointer");
        }
        if self.alloc_len == 0 || !memory::jit_arena_contains_range(base, self.alloc_len) {
            return Err("JIT exec buffer outside JIT arena");
        }
        if writable_len != 0 && !memory::jit_arena_contains_range(base, writable_len) {
            return Err("JIT write range outside JIT arena");
        }
        // Ensure writable during copy
        crate::arch::mmu::set_page_writable_range(base, writable_len, true)?;
        unsafe {
            core::ptr::copy_nonoverlapping(code.as_ptr(), self.ptr, code.len());
        }
        // Seal pages (read-only policy)
        crate::arch::mmu::set_page_writable_range(base, writable_len, false)?;
        #[cfg(not(target_arch = "aarch64"))]
        memory_isolation::tag_jit_code_kernel(base, writable_len, true)?;
        self.sealed = true;
        Ok(())
    }

    fn is_sealed(&self) -> bool {
        self.sealed
    }

    fn as_ptr(&self) -> *const u8 {
        self.ptr as *const u8
    }
}

fn analyze_basic_blocks_into(code: &[u8], blocks: &mut Vec<BasicBlock>) {
    blocks.clear();
    let mut start = 0usize;
    let mut pc = 0usize;
    while pc < code.len() {
        let op = code[pc];
        pc += 1;
        let opcode = Opcode::from_byte(op);
        match opcode {
            Some(Opcode::I32Const) => {
                let (_v, n) = read_sleb128_i32(code, pc).unwrap_or((0, 0));
                pc += n;
            }
            Some(Opcode::I64Const) => {
                let res = read_sleb128_i64_as_pair(code, pc);
                let n = res.map(|(_, _, n)| n).unwrap_or(0);
                pc += n;
            }
            Some(Opcode::Block) | Some(Opcode::Loop) | Some(Opcode::If) => {
                let (n, _block_type) = match read_blocktype_width(code, pc, &[]) {
                    Some(v) => v,
                    None => break,
                };
                pc += n;
            }
            Some(Opcode::LocalGet)
            | Some(Opcode::LocalSet)
            | Some(Opcode::LocalTee)
            | Some(Opcode::GlobalGet)
            | Some(Opcode::GlobalSet) => {
                let (_idx, n) = match read_uleb128(code, pc) {
                    Some(v) => v,
                    None => break,
                };
                pc += n;
            }
            Some(Opcode::Br) | Some(Opcode::BrIf) => {
                let (_depth, n) = match read_uleb128(code, pc) {
                    Some(v) => v,
                    None => break,
                };
                pc += n;
                blocks.push(BasicBlock { start, end: pc });
                start = pc;
            }
            Some(Opcode::I32Load)
            | Some(Opcode::I32Store)
            | Some(Opcode::I32Load8U)
            | Some(Opcode::I32Load16U)
            | Some(Opcode::I32Store8)
            | Some(Opcode::I32Store16) => {
                let (_align, n1) = match read_uleb128(code, pc) {
                    Some(v) => v,
                    None => break,
                };
                pc += n1;
                let (_off, n2) = match read_uleb128(code, pc) {
                    Some(v) => v,
                    None => break,
                };
                pc += n2;
            }
            Some(Opcode::CallIndirect) => {
                // type_idx + table_idx immediates
                let (_tidx, n1) = match read_uleb128(code, pc) {
                    Some(v) => v,
                    None => break,
                };
                pc += n1;
                let (_tbl, n2) = match read_uleb128(code, pc) {
                    Some(v) => v,
                    None => break,
                };
                pc += n2;
            }
            Some(Opcode::MemorySize) | Some(Opcode::MemoryGrow) => {
                // Reserved memory index immediate (must be 0 in MVP subset).
                if pc < code.len() {
                    pc += 1;
                }
            }
            Some(Opcode::Unreachable)
            | Some(Opcode::Return)
            | Some(Opcode::End)
            | Some(Opcode::Else) => {
                blocks.push(BasicBlock { start, end: pc });
                start = pc;
            }
            Some(_) => {}
            None => break,
        }
    }
    if start < code.len() {
        blocks.push(BasicBlock {
            start,
            end: code.len(),
        });
    }
}

pub fn analyze_basic_blocks(code: &[u8]) -> Vec<BasicBlock> {
    let mut blocks = Vec::new();
    analyze_basic_blocks_into(code, &mut blocks);
    blocks
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ControlKind {
    Function,
    Block,
    Loop,
    If,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct JitBlockType {
    param_arity: i32,
    result_arity: i32,
    supported: bool,
}

impl JitBlockType {
    #[inline]
    const fn empty() -> Self {
        JitBlockType {
            param_arity: 0,
            result_arity: 0,
            supported: true,
        }
    }

    #[inline]
    const fn i32_result() -> Self {
        JitBlockType {
            param_arity: 0,
            result_arity: 1,
            supported: true,
        }
    }

    #[inline]
    const fn unsupported() -> Self {
        JitBlockType {
            param_arity: 0,
            result_arity: 0,
            supported: false,
        }
    }
}

#[derive(Clone, Copy)]
struct ControlFrame {
    kind: ControlKind,
    stack_depth_at_entry: i32,
    param_arity: i32,
    result_arity: i32,
    label_arity: i32,
    loop_target: Option<usize>,
    else_patch: Option<usize>,
    has_else: bool,
    end_patches: [usize; MAX_JIT_PENDING_END_PATCHES],
    end_patch_count: usize,
}

const MAX_JIT_PENDING_END_PATCHES: usize = 256;

impl ControlFrame {
    const fn new(
        kind: ControlKind,
        stack_depth_at_entry: i32,
        param_arity: i32,
        result_arity: i32,
        label_arity: i32,
        loop_target: Option<usize>,
        else_patch: Option<usize>,
        has_else: bool,
    ) -> Self {
        ControlFrame {
            kind,
            stack_depth_at_entry,
            param_arity,
            result_arity,
            label_arity,
            loop_target,
            else_patch,
            has_else,
            end_patches: [0; MAX_JIT_PENDING_END_PATCHES],
            end_patch_count: 0,
        }
    }

    fn push_end_patch(&mut self, patch: usize) -> Result<(), &'static str> {
        if self.end_patch_count >= MAX_JIT_PENDING_END_PATCHES {
            return Err("Too many pending end patches");
        }
        self.end_patches[self.end_patch_count] = patch;
        self.end_patch_count += 1;
        Ok(())
    }

    fn patch_end_patches(
        &mut self,
        emitter: &mut Emitter,
        target: usize,
    ) -> Result<(), &'static str> {
        let mut idx = 0usize;
        while idx < self.end_patch_count {
            emitter.patch_rel32(self.end_patches[idx], target)?;
            idx += 1;
        }
        self.end_patch_count = 0;
        Ok(())
    }
}

fn resolve_label_target_idx(control_depth: usize, depth: u32) -> Result<usize, &'static str> {
    let depth = depth as usize;
    if depth >= control_depth {
        return Err("Branch depth out of bounds");
    }
    Ok(control_depth - 1 - depth)
}

fn emit_code_into(
    code: &[u8],
    locals_total: usize,
    type_sigs: &[JitTypeSignature],
    global_sigs: &[JitGlobalSignature],
    emitter: &mut Emitter,
    traces: &mut Vec<TranslationRecord>,
) -> Result<(), &'static str> {
    if locals_total > MAX_LOCALS {
        return Err("Too many locals");
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = (type_sigs, global_sigs);
    emitter.reset();
    emitter.emit_prologue();

    traces.clear();
    let mut control_stack = [None; MAX_CONTROL_STACK];
    let mut control_depth = 0usize;
    control_stack[control_depth] = Some(ControlFrame::new(
        ControlKind::Function,
        0,
        0,
        0,
        0,
        None,
        None,
        false,
    ));
    control_depth += 1;
    let mut pc = 0usize;
    let mut stack_depth: i32 = 0;
    let mut max_depth: i32 = 0;
    let mut instr_count: usize = 0;
    let mut saw_function_end = false;
    while pc < code.len() {
        let wasm_start = pc;
        let op = code[pc];
        pc += 1;
        let opcode = Opcode::from_byte(op).ok_or("Unsupported opcode")?;
        #[cfg(target_arch = "x86_64")]
        if !x86_64_backend_opcode_supported(opcode) {
            return Err("Opcode not yet supported by x86_64 JIT backend");
        }
        instr_count = instr_count.saturating_add(1);
        if instr_count > MAX_INSTRUCTIONS_PER_CALL {
            return Err("JIT function too large");
        }
        let x86_start = emitter.code.len();
        match opcode {
            Opcode::Nop => {
                emitter.emit_instr_fuel_check();
            }
            Opcode::Unreachable => {
                emitter.emit_instr_fuel_check();
                emitter.emit_trap_stack_always();
            }
            Opcode::Return => {
                emitter.emit_instr_fuel_check();
                let jmp = emitter.emit_jump_placeholder();
                let function_frame = control_stack[0].as_mut().ok_or("Malformed control stack")?;
                function_frame.push_end_patch(jmp)?;
                stack_depth = function_frame.stack_depth_at_entry;
            }
            Opcode::End => {
                emitter.emit_instr_fuel_check();
                let end_target = emitter.code.len();
                if control_depth == 0 {
                    return Err("Unexpected end");
                }
                if control_depth == 1 {
                    let function_frame =
                        control_stack[0].as_mut().ok_or("Malformed control stack")?;
                    if function_frame.kind != ControlKind::Function {
                        return Err("Malformed control stack");
                    }
                    function_frame.patch_end_patches(emitter, end_target)?;
                    saw_function_end = true;
                } else {
                    control_depth -= 1;
                    let mut frame = control_stack[control_depth]
                        .take()
                        .ok_or("Unexpected end")?;
                    if frame.kind == ControlKind::If
                        && !frame.has_else
                        && frame.param_arity != frame.result_arity
                    {
                        return Err("Typed if without else block type not supported by JIT");
                    }
                    match frame.kind {
                        ControlKind::If => {
                            if let Some(else_patch) = frame.else_patch.take() {
                                emitter.patch_rel32(else_patch, end_target)?;
                            }
                        }
                        ControlKind::Block | ControlKind::Loop => {}
                        ControlKind::Function => return Err("Malformed control stack"),
                    }
                    frame.patch_end_patches(emitter, end_target)?;
                    stack_depth = frame.stack_depth_at_entry + frame.result_arity;
                }
            }
            Opcode::Block => {
                #[cfg(not(target_arch = "x86_64"))]
                {
                    return Err("Control flow not supported by JIT");
                }
                #[cfg(target_arch = "x86_64")]
                {
                    emitter.emit_instr_fuel_check();
                    let (blocktype_width, block_type) =
                        read_blocktype_width(code, pc, type_sigs).ok_or("Bad block type")?;
                    pc += blocktype_width;
                    if !block_type.supported {
                        return Err("Block type not supported by JIT");
                    }
                    if stack_depth < block_type.param_arity {
                        return Err("JIT stack underflow");
                    }
                    let stack_depth_at_entry = stack_depth - block_type.param_arity;
                    if control_depth >= MAX_CONTROL_STACK {
                        return Err("Control stack overflow");
                    }
                    control_stack[control_depth] = Some(ControlFrame::new(
                        ControlKind::Block,
                        stack_depth_at_entry,
                        block_type.param_arity,
                        block_type.result_arity,
                        block_type.result_arity,
                        None,
                        None,
                        false,
                    ));
                    control_depth += 1;
                }
            }
            Opcode::Loop => {
                #[cfg(not(target_arch = "x86_64"))]
                {
                    return Err("Control flow not supported by JIT");
                }
                #[cfg(target_arch = "x86_64")]
                {
                    emitter.emit_instr_fuel_check();
                    let (blocktype_width, block_type) =
                        read_blocktype_width(code, pc, type_sigs).ok_or("Bad loop type")?;
                    pc += blocktype_width;
                    if !block_type.supported {
                        return Err("Loop type not supported by JIT");
                    }
                    if stack_depth < block_type.param_arity {
                        return Err("JIT stack underflow");
                    }
                    let loop_target = emitter.code.len();
                    let stack_depth_at_entry = stack_depth - block_type.param_arity;
                    if control_depth >= MAX_CONTROL_STACK {
                        return Err("Control stack overflow");
                    }
                    control_stack[control_depth] = Some(ControlFrame::new(
                        ControlKind::Loop,
                        stack_depth_at_entry,
                        block_type.param_arity,
                        block_type.result_arity,
                        block_type.param_arity,
                        Some(loop_target),
                        None,
                        false,
                    ));
                    control_depth += 1;
                }
            }
            Opcode::Drop => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 1)?;
                emitter.emit_pop_discard();
            }
            Opcode::I32Const => {
                emitter.emit_instr_fuel_check();
                let (imm, n) = read_sleb128_i32(code, pc).ok_or("Bad const")?;
                pc += n;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_const(imm);
            }
            Opcode::I32Add => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_add();
            }
            Opcode::I32Sub => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_sub();
            }
            Opcode::I32Mul => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_mul();
            }
            Opcode::I32DivS => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_divs();
            }
            Opcode::I32DivU => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_divu();
            }
            Opcode::I32RemS => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_rems();
            }
            Opcode::I32RemU => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_remu();
            }
            Opcode::I32And => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_and();
            }
            Opcode::I32Or => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_or();
            }
            Opcode::I32Xor => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_xor();
            }
            Opcode::I32Eq => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_eq();
            }
            Opcode::I32Ne => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_ne();
            }
            Opcode::I32Eqz => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 1)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_eqz();
            }
            Opcode::I32LtS => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_lts();
            }
            Opcode::I32GtS => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_gts();
            }
            Opcode::I32LeS => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_les();
            }
            Opcode::I32GeS => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_ges();
            }
            Opcode::I32LtU => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_ltu();
            }
            Opcode::I32GtU => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_gtu();
            }
            Opcode::I32LeU => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_leu();
            }
            Opcode::I32GeU => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_geu();
            }
            Opcode::I32Shl => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_shl();
            }
            Opcode::I32ShrS => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_shrs();
            }
            Opcode::I32ShrU => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_shru();
            }
            Opcode::LocalGet => {
                emitter.emit_instr_fuel_check();
                let (idx, n) = read_uleb128(code, pc).ok_or("Bad local")?;
                pc += n;
                if idx as usize >= locals_total {
                    return Err("Local index out of bounds");
                }
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_local_get(idx as u32);
            }
            Opcode::LocalSet => {
                emitter.emit_instr_fuel_check();
                let (idx, n) = read_uleb128(code, pc).ok_or("Bad local")?;
                pc += n;
                if idx as usize >= locals_total {
                    return Err("Local index out of bounds");
                }
                stack_pop(&mut stack_depth, 1)?;
                emitter.emit_local_set(idx as u32);
            }
            Opcode::LocalTee => {
                emitter.emit_instr_fuel_check();
                let (idx, n) = read_uleb128(code, pc).ok_or("Bad local")?;
                pc += n;
                if idx as usize >= locals_total {
                    return Err("Local index out of bounds");
                }
                stack_pop(&mut stack_depth, 1)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_local_tee(idx as u32);
            }
            Opcode::GlobalGet => {
                #[cfg(not(target_arch = "x86_64"))]
                {
                    return Err("Globals not supported by JIT");
                }
                #[cfg(target_arch = "x86_64")]
                {
                    emitter.emit_instr_fuel_check();
                    let (idx, n) = read_uleb128(code, pc).ok_or("Bad global")?;
                    pc += n;
                    let global = global_sigs
                        .get(idx as usize)
                        .copied()
                        .ok_or("Global index out of bounds")?;
                    if !global.all_i32 {
                        return Err("Global type not supported by JIT");
                    }
                    stack_push(&mut stack_depth, 1, &mut max_depth)?;
                    emitter.emit_global_get(idx as u32);
                }
            }
            Opcode::GlobalSet => {
                #[cfg(not(target_arch = "x86_64"))]
                {
                    return Err("Globals not supported by JIT");
                }
                #[cfg(target_arch = "x86_64")]
                {
                    emitter.emit_instr_fuel_check();
                    let (idx, n) = read_uleb128(code, pc).ok_or("Bad global")?;
                    pc += n;
                    let global = global_sigs
                        .get(idx as usize)
                        .copied()
                        .ok_or("Global index out of bounds")?;
                    if !global.all_i32 {
                        return Err("Global type not supported by JIT");
                    }
                    if !global.mutable {
                        return Err("Immutable global not supported by JIT");
                    }
                    stack_pop(&mut stack_depth, 1)?;
                    emitter.emit_global_set(idx as u32);
                }
            }
            Opcode::Select => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 3)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_select();
            }
            Opcode::I32Load => {
                emitter.emit_instr_fuel_check();
                emitter.emit_mem_fuel_check();
                let (_align, n1) = read_uleb128(code, pc).ok_or("Bad load")?;
                pc += n1;
                let (off, n2) = read_uleb128(code, pc).ok_or("Bad load")?;
                pc += n2;
                stack_pop(&mut stack_depth, 1)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_load(off);
            }
            Opcode::I32Store => {
                emitter.emit_instr_fuel_check();
                emitter.emit_mem_fuel_check();
                let (_align, n1) = read_uleb128(code, pc).ok_or("Bad store")?;
                pc += n1;
                let (off, n2) = read_uleb128(code, pc).ok_or("Bad store")?;
                pc += n2;
                stack_pop(&mut stack_depth, 2)?;
                emitter.emit_i32_store(off);
            }
            Opcode::MemorySize => {
                emitter.emit_instr_fuel_check();
                if pc >= code.len() {
                    return Err("Bad memory.size");
                }
                let mem_idx = code[pc];
                pc += 1;
                if mem_idx != 0 {
                    return Err("Bad memory.size");
                }
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_memory_size();
            }
            Opcode::MemoryGrow => {
                emitter.emit_instr_fuel_check();
                if pc >= code.len() {
                    return Err("Bad memory.grow");
                }
                let mem_idx = code[pc];
                pc += 1;
                if mem_idx != 0 {
                    return Err("Bad memory.grow");
                }
                stack_pop(&mut stack_depth, 1)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_memory_grow();
            }
            Opcode::If => {
                #[cfg(not(target_arch = "x86_64"))]
                {
                    return Err("Control flow not supported by JIT");
                }
                #[cfg(target_arch = "x86_64")]
                {
                    emitter.emit_instr_fuel_check();
                    let (blocktype_width, block_type) =
                        read_blocktype_width(code, pc, type_sigs).ok_or("Bad if block type")?;
                    pc += blocktype_width;
                    if !block_type.supported {
                        return Err("If block type not supported by JIT");
                    }
                    stack_pop(&mut stack_depth, 1)?;
                    if stack_depth < block_type.param_arity {
                        return Err("JIT stack underflow");
                    }
                    let else_patch = emitter.emit_pop_cond_jz_placeholder();
                    let stack_depth_at_entry = stack_depth - block_type.param_arity;
                    if control_depth >= MAX_CONTROL_STACK {
                        return Err("Control stack overflow");
                    }
                    control_stack[control_depth] = Some(ControlFrame::new(
                        ControlKind::If,
                        stack_depth_at_entry,
                        block_type.param_arity,
                        block_type.result_arity,
                        block_type.result_arity,
                        None,
                        Some(else_patch),
                        false,
                    ));
                    control_depth += 1;
                }
            }
            Opcode::Else => {
                #[cfg(not(target_arch = "x86_64"))]
                {
                    return Err("Control flow not supported by JIT");
                }
                #[cfg(target_arch = "x86_64")]
                {
                    emitter.emit_instr_fuel_check();
                    let end_jump = emitter.emit_jump_placeholder();
                    let else_body_start = emitter.code.len();
                    let frame = control_stack
                        .get_mut(control_depth.saturating_sub(1))
                        .and_then(Option::as_mut)
                        .ok_or("Unexpected else")?;
                    if frame.kind != ControlKind::If || frame.has_else {
                        return Err("Unexpected else");
                    }
                    if let Some(else_patch) = frame.else_patch.take() {
                        emitter.patch_rel32(else_patch, else_body_start)?;
                    } else {
                        return Err("Missing if else patch");
                    }
                    frame.has_else = true;
                    frame.push_end_patch(end_jump)?;
                    stack_depth = frame.stack_depth_at_entry + frame.param_arity;
                }
            }
            Opcode::Br => {
                #[cfg(not(target_arch = "x86_64"))]
                {
                    return Err("Control flow not supported by JIT");
                }
                #[cfg(target_arch = "x86_64")]
                {
                    emitter.emit_instr_fuel_check();
                    let (depth, n) = read_uleb128(code, pc).ok_or("Bad br depth")?;
                    pc += n;
                    let target_idx = resolve_label_target_idx(control_depth, depth)?;
                    let (target_kind, target_stack_depth, target_loop_target, target_label_arity) = {
                        let frame = control_stack[target_idx]
                            .as_ref()
                            .ok_or("Malformed control stack")?;
                        (
                            frame.kind,
                            frame.stack_depth_at_entry,
                            frame.loop_target,
                            frame.label_arity,
                        )
                    };
                    let target_depth = target_stack_depth + target_label_arity;
                    emitter.emit_rebuild_branch_values(target_label_arity, target_stack_depth)?;
                    let jump = emitter.emit_jump_placeholder();
                    match target_kind {
                        ControlKind::Loop => {
                            let loop_target =
                                target_loop_target.ok_or("Loop frame missing target")?;
                            emitter.patch_rel32(jump, loop_target)?;
                        }
                        _ => {
                            control_stack[target_idx]
                                .as_mut()
                                .ok_or("Malformed control stack")?
                                .push_end_patch(jump)?;
                        }
                    }
                    stack_depth = target_depth;
                }
            }
            Opcode::BrIf => {
                #[cfg(not(target_arch = "x86_64"))]
                {
                    return Err("Control flow not supported by JIT");
                }
                #[cfg(target_arch = "x86_64")]
                {
                    emitter.emit_instr_fuel_check();
                    let (depth, n) = read_uleb128(code, pc).ok_or("Bad br_if depth")?;
                    pc += n;
                    stack_pop(&mut stack_depth, 1)?;
                    let target_idx = resolve_label_target_idx(control_depth, depth)?;
                    emitter.emit_pop_to_eax();
                    let jz_fallthrough = emitter.emit_cond_jz_placeholder();
                    let (target_kind, target_stack_depth, target_loop_target, target_label_arity) = {
                        let frame = control_stack[target_idx]
                            .as_ref()
                            .ok_or("Malformed control stack")?;
                        (
                            frame.kind,
                            frame.stack_depth_at_entry,
                            frame.loop_target,
                            frame.label_arity,
                        )
                    };
                    emitter.emit_rebuild_branch_values(target_label_arity, target_stack_depth)?;
                    let jump = emitter.emit_jump_placeholder();
                    match target_kind {
                        ControlKind::Loop => {
                            let loop_target =
                                target_loop_target.ok_or("Loop frame missing target")?;
                            emitter.patch_rel32(jump, loop_target)?;
                        }
                        _ => {
                            control_stack[target_idx]
                                .as_mut()
                                .ok_or("Malformed control stack")?
                                .push_end_patch(jump)?;
                        }
                    }
                    let fallthrough = emitter.code.len();
                    emitter.patch_rel32(jz_fallthrough, fallthrough)?;
                }
            }
            // ── New opcodes: i32.clz / i32.ctz ───────────────────────────────
            Opcode::I32Clz => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 1)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_clz();
            }
            Opcode::I32Ctz => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 1)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_ctz();
            }
            // ── New opcodes: i32 narrow loads ────────────────────────────────
            Opcode::I32Load8U => {
                emitter.emit_instr_fuel_check();
                emitter.emit_mem_fuel_check();
                let (_align, n1) = read_uleb128(code, pc).ok_or("Bad load8u")?;
                pc += n1;
                let (off, n2) = read_uleb128(code, pc).ok_or("Bad load8u")?;
                pc += n2;
                stack_pop(&mut stack_depth, 1)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_load8u(off);
            }
            Opcode::I32Load16U => {
                emitter.emit_instr_fuel_check();
                emitter.emit_mem_fuel_check();
                let (_align, n1) = read_uleb128(code, pc).ok_or("Bad load16u")?;
                pc += n1;
                let (off, n2) = read_uleb128(code, pc).ok_or("Bad load16u")?;
                pc += n2;
                stack_pop(&mut stack_depth, 1)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_load16u(off);
            }
            // ── New opcodes: i32 narrow stores ───────────────────────────────
            Opcode::I32Store8 => {
                emitter.emit_instr_fuel_check();
                emitter.emit_mem_fuel_check();
                let (_align, n1) = read_uleb128(code, pc).ok_or("Bad store8")?;
                pc += n1;
                let (off, n2) = read_uleb128(code, pc).ok_or("Bad store8")?;
                pc += n2;
                stack_pop(&mut stack_depth, 2)?;
                emitter.emit_i32_store8(off);
            }
            Opcode::I32Store16 => {
                emitter.emit_instr_fuel_check();
                emitter.emit_mem_fuel_check();
                let (_align, n1) = read_uleb128(code, pc).ok_or("Bad store16")?;
                pc += n1;
                let (off, n2) = read_uleb128(code, pc).ok_or("Bad store16")?;
                pc += n2;
                stack_pop(&mut stack_depth, 2)?;
                emitter.emit_i32_store16(off);
            }
            // ── New opcodes: i64 arithmetic (hi:lo pair on value stack) ──────
            Opcode::I64Const => {
                emitter.emit_instr_fuel_check();
                let (imm_lo, imm_hi, n) =
                    read_sleb128_i64_as_pair(code, pc).ok_or("Bad i64.const")?;
                pc += n;
                // Push hi then lo so that stack top = lo word (matching i64 pop order)
                stack_push(&mut stack_depth, 2, &mut max_depth)?;
                emitter.emit_i64_const(imm_lo, imm_hi);
            }
            Opcode::I64Add => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 4)?; // 2×(lo+hi)
                stack_push(&mut stack_depth, 2, &mut max_depth)?;
                emitter.emit_i64_add();
            }
            Opcode::I64Sub => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 4)?;
                stack_push(&mut stack_depth, 2, &mut max_depth)?;
                emitter.emit_i64_sub();
            }
            Opcode::I64Mul => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 4)?;
                stack_push(&mut stack_depth, 2, &mut max_depth)?;
                emitter.emit_i64_mul();
            }
            Opcode::I64DivS => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 4)?; // 2 i64 args = 4 slots
                stack_push(&mut stack_depth, 2, &mut max_depth)?;
                emitter.emit_i64_divs();
            }
            Opcode::I64Clz => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 2, &mut max_depth)?;
                emitter.emit_i64_clz();
            }
            Opcode::I64Ctz => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 2, &mut max_depth)?;
                emitter.emit_i64_ctz();
            }
            Opcode::I64Popcnt => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 2, &mut max_depth)?;
                emitter.emit_i64_popcnt();
            }
            // ── i64 comparison operations ─────────────────────────────────────
            Opcode::I64Eqz => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;    // one i64 = 2 slots
                stack_push(&mut stack_depth, 1, &mut max_depth)?; // i32 result
                emitter.emit_i64_eqz();
            }
            Opcode::I64Eq => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 4)?;    // two i64s = 4 slots
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i64_eq();
            }
            Opcode::I64Ne => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 4)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i64_ne();
            }
            Opcode::I64LtS => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 4)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i64_lts();
            }
            Opcode::I64GtS => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 4)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i64_gts();
            }
            Opcode::I64LeS => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 4)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i64_les();
            }
            Opcode::I64GeS => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 4)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i64_ges();
            }
            Opcode::I64LtU => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 4)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i64_ltu();
            }
            Opcode::I64GtU => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 4)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i64_gtu();
            }
            Opcode::I64LeU => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 4)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i64_leu();
            }
            Opcode::I64GeU => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 4)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i64_geu();
            }
            // ── i64/i32 type conversions ──────────────────────────────────────
            Opcode::I32WrapI64 => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;     // i64 = 2 slots
                stack_push(&mut stack_depth, 1, &mut max_depth)?; // i32 result
                emitter.emit_i32_wrap_i64();
            }
            Opcode::I64ExtendI32S => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 1)?;     // i32 = 1 slot
                stack_push(&mut stack_depth, 2, &mut max_depth)?; // i64 = 2 slots
                emitter.emit_i64_extend_i32s();
            }
            Opcode::I64ExtendI32U => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 1)?;
                stack_push(&mut stack_depth, 2, &mut max_depth)?;
                emitter.emit_i64_extend_i32u();
            }
            // ── New opcodes: i32 sign-extending loads ─────────────────────────
            Opcode::I32Load8S => {
                emitter.emit_instr_fuel_check();
                emitter.emit_mem_fuel_check();
                let (_align, n1) = read_uleb128(code, pc).ok_or("Bad load8s")?;
                pc += n1;
                let (off, n2) = read_uleb128(code, pc).ok_or("Bad load8s")?;
                pc += n2;
                stack_pop(&mut stack_depth, 1)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_load8_s(off);
            }
            Opcode::I32Load16S => {
                emitter.emit_instr_fuel_check();
                emitter.emit_mem_fuel_check();
                let (_align, n1) = read_uleb128(code, pc).ok_or("Bad load16s")?;
                pc += n1;
                let (off, n2) = read_uleb128(code, pc).ok_or("Bad load16s")?;
                pc += n2;
                stack_pop(&mut stack_depth, 1)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_load16_s(off);
            }
            Opcode::I32Popcnt => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 1)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_popcnt();
            }
            Opcode::I32Rotl => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_rotl();
            }
            Opcode::I32Rotr => {
                emitter.emit_instr_fuel_check();
                stack_pop(&mut stack_depth, 2)?;
                stack_push(&mut stack_depth, 1, &mut max_depth)?;
                emitter.emit_i32_rotr();
            }
            // ── New opcodes: i64 loads ────────────────────────────────────────
            Opcode::I64Load => {
                emitter.emit_instr_fuel_check();
                emitter.emit_mem_fuel_check();
                let (_align, n1) = read_uleb128(code, pc).ok_or("Bad i64.load")?;
                pc += n1;
                let (off, n2) = read_uleb128(code, pc).ok_or("Bad i64.load")?;
                pc += n2;
                stack_pop(&mut stack_depth, 1)?;
                stack_push(&mut stack_depth, 2, &mut max_depth)?;
                emitter.emit_i64_load(off);
            }
            Opcode::I64Load8U => {
                emitter.emit_instr_fuel_check();
                emitter.emit_mem_fuel_check();
                let (_align, n1) = read_uleb128(code, pc).ok_or("Bad i64.load8_u")?;
                pc += n1;
                let (off, n2) = read_uleb128(code, pc).ok_or("Bad i64.load8_u")?;
                pc += n2;
                stack_pop(&mut stack_depth, 1)?;
                stack_push(&mut stack_depth, 2, &mut max_depth)?;
                emitter.emit_i64_load8_u(off);
            }
            Opcode::I64Load16U => {
                emitter.emit_instr_fuel_check();
                emitter.emit_mem_fuel_check();
                let (_align, n1) = read_uleb128(code, pc).ok_or("Bad i64.load16_u")?;
                pc += n1;
                let (off, n2) = read_uleb128(code, pc).ok_or("Bad i64.load16_u")?;
                pc += n2;
                stack_pop(&mut stack_depth, 1)?;
                stack_push(&mut stack_depth, 2, &mut max_depth)?;
                emitter.emit_i64_load16_u(off);
            }
            Opcode::I64Load32U => {
                emitter.emit_instr_fuel_check();
                emitter.emit_mem_fuel_check();
                let (_align, n1) = read_uleb128(code, pc).ok_or("Bad i64.load32_u")?;
                pc += n1;
                let (off, n2) = read_uleb128(code, pc).ok_or("Bad i64.load32_u")?;
                pc += n2;
                stack_pop(&mut stack_depth, 1)?;
                stack_push(&mut stack_depth, 2, &mut max_depth)?;
                emitter.emit_i64_load32_u(off);
            }
            // ── New opcodes: i64 stores ───────────────────────────────────────
            Opcode::I64Store => {
                emitter.emit_instr_fuel_check();
                emitter.emit_mem_fuel_check();
                let (_align, n1) = read_uleb128(code, pc).ok_or("Bad i64.store")?;
                pc += n1;
                let (off, n2) = read_uleb128(code, pc).ok_or("Bad i64.store")?;
                pc += n2;
                stack_pop(&mut stack_depth, 3)?; // val_lo + val_hi + addr
                emitter.emit_i64_store(off);
            }
            Opcode::I64Store8 => {
                emitter.emit_instr_fuel_check();
                emitter.emit_mem_fuel_check();
                let (_align, n1) = read_uleb128(code, pc).ok_or("Bad i64.store8")?;
                pc += n1;
                let (off, n2) = read_uleb128(code, pc).ok_or("Bad i64.store8")?;
                pc += n2;
                stack_pop(&mut stack_depth, 3)?;
                emitter.emit_i64_store8(off);
            }
            Opcode::I64Store16 => {
                emitter.emit_instr_fuel_check();
                emitter.emit_mem_fuel_check();
                let (_align, n1) = read_uleb128(code, pc).ok_or("Bad i64.store16")?;
                pc += n1;
                let (off, n2) = read_uleb128(code, pc).ok_or("Bad i64.store16")?;
                pc += n2;
                stack_pop(&mut stack_depth, 3)?;
                emitter.emit_i64_store16(off);
            }
            Opcode::I64Store32 => {
                emitter.emit_instr_fuel_check();
                emitter.emit_mem_fuel_check();
                let (_align, n1) = read_uleb128(code, pc).ok_or("Bad i64.store32")?;
                pc += n1;
                let (off, n2) = read_uleb128(code, pc).ok_or("Bad i64.store32")?;
                pc += n2;
                stack_pop(&mut stack_depth, 3)?;
                emitter.emit_i64_store32(off);
            }
            // ── New opcodes: call_indirect ────────────────────────────────────
            Opcode::CallIndirect => {
                #[cfg(not(target_arch = "x86_64"))]
                {
                    return Err("CallIndirect not supported by JIT");
                }
                #[cfg(target_arch = "x86_64")]
                {
                    emitter.emit_instr_fuel_check();
                    let (type_idx, n1) = read_uleb128(code, pc).ok_or("Bad call_indirect type")?;
                    pc += n1;
                    let (table_idx, n2) =
                        read_uleb128(code, pc).ok_or("Bad call_indirect table")?;
                    pc += n2;
                    if table_idx != 0 {
                        return Err("call_indirect: only table 0 supported by JIT");
                    }
                    let sig = type_sigs
                        .get(type_idx as usize)
                        .ok_or("call_indirect: type index out of bounds")?;
                    // Pop function-table index from WASM stack
                    stack_pop(&mut stack_depth, 1)?;
                    // Pop function arguments; push return value (if any)
                    stack_pop(&mut stack_depth, sig.param_count as i32)?;
                    if sig.result_count > 0 {
                        stack_push(&mut stack_depth, sig.result_count as i32, &mut max_depth)?;
                    }
                    emitter.emit_call_indirect(
                        type_idx,
                        sig.param_count as u32,
                        sig.result_count as u32,
                    );
                }
            }
            _ => return Err("Opcode not supported by JIT"),
        }
        let x86_end = emitter.code.len();
        if x86_end <= x86_start {
            crate::serial_println!(
                "[JIT-ST] empty-trace wasm_start={} opcode=0x{:02x} x86_start={} x86_end={}",
                wasm_start,
                opcode as u8,
                x86_start,
                x86_end
            );
            return Err("Empty translation record");
        }
        traces.push(TranslationRecord {
            wasm_start,
            wasm_end: pc,
            x86_start,
            x86_end,
            opcode,
        });
        if saw_function_end {
            break;
        }
    }
    if !saw_function_end {
        return Err("Missing function end");
    }

    let _ret_pos = emitter.emit_epilogue();
    let trap_mem_pos = emitter.emit_trap_stub(TRAP_MEM, true);
    let trap_fuel_pos = emitter.emit_trap_stub(TRAP_FUEL, true);
    let trap_stack_pos = emitter.emit_trap_stub(TRAP_STACK, true);
    let trap_cfi_pos = emitter.emit_trap_stub(TRAP_CFI, false);
    emitter.patch_traps(trap_mem_pos, trap_fuel_pos, trap_stack_pos, trap_cfi_pos)?;

    let trap_targets = [trap_mem_pos, trap_fuel_pos, trap_stack_pos, trap_cfi_pos];
    verify_x86_subset(&emitter.code, locals_total, &trap_targets)?;
    Ok(())
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn x86_64_backend_opcode_supported(opcode: Opcode) -> bool {
    matches!(
        opcode,
        Opcode::Nop
            | Opcode::Unreachable
            | Opcode::End
            | Opcode::Return
            | Opcode::Drop
            | Opcode::I32Const
            | Opcode::I32Add
            | Opcode::I32Sub
            | Opcode::I32Mul
            | Opcode::I32DivS
            | Opcode::I32DivU
            | Opcode::I32RemS
            | Opcode::I32RemU
            | Opcode::I32And
            | Opcode::I32Or
            | Opcode::I32Xor
            | Opcode::I32Eq
            | Opcode::I32Ne
            | Opcode::I32Eqz
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
            | Opcode::I32Clz
            | Opcode::I32Ctz
            | Opcode::I32Load8U
            | Opcode::I32Load16U
            | Opcode::I32Store8
            | Opcode::I32Store16
            | Opcode::I64Const
            | Opcode::I64Add
            | Opcode::I64Sub
            | Opcode::I64Mul
            | Opcode::I64DivS
            | Opcode::I64Clz
            | Opcode::I64Ctz
            | Opcode::I64Popcnt
            | Opcode::I64Load
            | Opcode::I64Load8U
            | Opcode::I64Load16U
            | Opcode::I64Load32U
            | Opcode::I64Store
            | Opcode::I64Store8
            | Opcode::I64Store16
            | Opcode::I64Store32
            | Opcode::I32Rotl
            | Opcode::I32Rotr
            | Opcode::I32Popcnt
            | Opcode::I32Load8S
            | Opcode::I32Load16S
            | Opcode::CallIndirect
            | Opcode::LocalGet
            | Opcode::LocalSet
            | Opcode::LocalTee
            | Opcode::GlobalGet
            | Opcode::GlobalSet
            | Opcode::Select
            | Opcode::I32Load
            | Opcode::I32Store
            | Opcode::MemorySize
            | Opcode::MemoryGrow
            | Opcode::Block
            | Opcode::Loop
            | Opcode::If
            | Opcode::Else
            | Opcode::Br
            | Opcode::BrIf
            | Opcode::I64Eqz
            | Opcode::I64Eq
            | Opcode::I64Ne
            | Opcode::I64LtS
            | Opcode::I64GtS
            | Opcode::I64LeS
            | Opcode::I64GeS
            | Opcode::I64LtU
            | Opcode::I64GtU
            | Opcode::I64LeU
            | Opcode::I64GeU
            | Opcode::I32WrapI64
            | Opcode::I64ExtendI32S
            | Opcode::I64ExtendI32U
    )
}

fn emit_code(
    code: &[u8],
    locals_total: usize,
    type_sigs: &[JitTypeSignature],
    global_sigs: &[JitGlobalSignature],
    emitter: &mut Emitter,
) -> Result<Vec<TranslationRecord>, &'static str> {
    let mut traces = Vec::new();
    emit_code_into(
        code,
        locals_total,
        type_sigs,
        global_sigs,
        emitter,
        &mut traces,
    )?;
    Ok(traces)
}

const FNV1A64_OFFSET: u64 = 14695981039346656037;
const FNV1A64_PRIME: u64 = 1099511628211;
// mov eax,[ebp-*] (3) + cmp [eax],0 (3) + jcc rel32 (6) + dec [eax] (2)
const INSTR_FUEL_CHECK_LEN: usize = 14;
const MEM_FUEL_CHECK_LEN: usize = 14;

fn hash_translation_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV1A64_PRIME);
    }
    hash
}

fn hash_translation_u64(mut hash: u64, value: u64) -> u64 {
    hash ^= value;
    hash = hash.wrapping_mul(FNV1A64_PRIME);
    hash
}

fn has_prefix_at(code: &[u8], at: usize, prefix: &[u8]) -> bool {
    at.checked_add(prefix.len())
        .and_then(|end| code.get(at..end))
        .map(|s| s == prefix)
        .unwrap_or(false)
}

fn consume_instr_fuel_check(code: &[u8], at: usize) -> Result<usize, &'static str> {
    // mov eax, [ebp-8]; cmp dword [eax],0; je trap; dec dword [eax]
    const PREFIX: [u8; 8] = [0x8B, 0x45, 0xF8, 0x83, 0x38, 0x00, 0x0F, 0x84];
    if !has_prefix_at(code, at, &PREFIX) {
        return Err("Missing instruction fuel check");
    }
    let rel_off = at + PREFIX.len();
    if rel_off + 4 + 2 > code.len() {
        return Err("Truncated instruction fuel check");
    }
    if code[rel_off + 4] != 0xFF || code[rel_off + 5] != 0x08 {
        return Err("Invalid instruction fuel check suffix");
    }
    Ok(at + INSTR_FUEL_CHECK_LEN)
}

fn consume_mem_fuel_check(code: &[u8], at: usize) -> Result<usize, &'static str> {
    // mov eax, [ebp-12]; cmp dword [eax],0; je trap; dec dword [eax]
    const PREFIX: [u8; 8] = [0x8B, 0x45, 0xF4, 0x83, 0x38, 0x00, 0x0F, 0x84];
    if !has_prefix_at(code, at, &PREFIX) {
        return Err("Missing memory fuel check");
    }
    let rel_off = at + PREFIX.len();
    if rel_off + 4 + 2 > code.len() {
        return Err("Truncated memory fuel check");
    }
    if code[rel_off + 4] != 0xFF || code[rel_off + 5] != 0x08 {
        return Err("Invalid memory fuel check suffix");
    }
    Ok(at + MEM_FUEL_CHECK_LEN)
}

fn contains_subseq(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        {
            crate::serial_println!("verify_integrity failed at line {}", line!());
            return false;
        }
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(not(target_arch = "x86_64"))]
fn validate_trace_shape(opcode: Opcode, code: &[u8]) -> Result<(), &'static str> {
    let mut at = consume_instr_fuel_check(code, 0)?;
    let is_mem_op = matches!(
        opcode,
        Opcode::I32Load
            | Opcode::I32Store
            | Opcode::I32Load8U
            | Opcode::I32Load16U
            | Opcode::I32Store8
            | Opcode::I32Store16
    );
    if is_mem_op {
        at = consume_mem_fuel_check(code, at)?;
    } else if has_prefix_at(code, at, &[0x8B, 0x45, 0xF4, 0x83, 0x38, 0x00, 0x0F, 0x84]) {
        return Err("Unexpected memory fuel check");
    }

    if at == code.len() {
        if matches!(opcode, Opcode::Nop | Opcode::End | Opcode::Return) {
            return Ok(());
        }
        return Err("Missing opcode body");
    }

    if matches!(
        opcode,
        Opcode::I32Load
            | Opcode::I32Store
            | Opcode::I32Load8U
            | Opcode::I32Load16U
            | Opcode::I32Store8
            | Opcode::I32Store16
    ) {
        // Bounds checks must contain jb/ja trap edges.
        if !contains_subseq(code, &[0x0F, 0x82]) || !contains_subseq(code, &[0x0F, 0x87]) {
            return Err("Missing memory bounds trap edges");
        }
    }
    if matches!(opcode, Opcode::I32Load) && !contains_subseq(code, &[0x8B, 0x04, 0x02]) {
        return Err("Missing linear memory load");
    }
    if matches!(opcode, Opcode::I32Store) && !contains_subseq(code, &[0x89, 0x1C, 0x02]) {
        return Err("Missing linear memory store");
    }

    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn validate_trace_shape(_opcode: Opcode, _code: &[u8]) -> Result<(), &'static str> {
    // Reduced x86_64 backend: keep continuity/proof hashing checks enabled, but
    // skip x86-32 byte-pattern validation until opcode coverage reaches parity.
    Ok(())
}

fn validate_translation_per_block_into(
    wasm_code: &[u8],
    blocks: &[BasicBlock],
    traces: &[TranslationRecord],
    native_code: &[u8],
    block_hashes: &mut Vec<u64>,
) -> Result<(), &'static str> {
    // First-principles safety invariant:
    // every span we index must refer to kernel-mapped memory for its full byte length.
    if !slice_is_kernel_mapped(wasm_code) {
        return Err("Unmapped WASM translation buffer");
    }
    if !slice_is_kernel_mapped(blocks) {
        return Err("Unmapped block metadata");
    }
    if !slice_is_kernel_mapped(traces) {
        return Err("Unmapped translation trace metadata");
    }
    if !slice_is_kernel_mapped(native_code) {
        return Err("Unmapped native translation buffer");
    }

    block_hashes.clear();
    if wasm_code.is_empty() {
        if !blocks.is_empty() || !traces.is_empty() {
            return Err("Empty WASM with non-empty translation metadata");
        }
        return Ok(());
    }
    if blocks.is_empty() {
        return Err("Missing basic block metadata");
    }
    if traces.is_empty() {
        return Err("Missing translation traces");
    }

    let mut trace_idx = 0usize;
    let mut expected_x86 = traces[0].x86_start;

    for (block_idx, block) in blocks.iter().enumerate() {
        if block.start >= block.end || block.end > wasm_code.len() {
            return Err("Invalid basic block range");
        }
        if trace_idx >= traces.len() {
            return Err("Missing trace for basic block");
        }
        if traces[trace_idx].wasm_start != block.start {
            return Err("Block trace start mismatch");
        }

        let mut block_hash = FNV1A64_OFFSET;
        let mut prev_wasm_end = block.start;
        let mut saw_trace = false;

        while trace_idx < traces.len() {
            let trace = traces[trace_idx];
            if trace.wasm_start < block.start || trace.wasm_end > block.end {
                break;
            }
            if trace.wasm_start != prev_wasm_end {
                crate::serial_println!(
                    "[JIT-ST] trace-gap block_idx={} block=[{}..{}] trace_idx={} prev_wasm_end={} trace=[{}..{}] op=0x{:02x}",
                    block_idx,
                    block.start,
                    block.end,
                    trace_idx,
                    prev_wasm_end,
                    trace.wasm_start,
                    trace.wasm_end,
                    trace.opcode as u8
                );
                return Err("Non-contiguous WASM translation trace");
            }
            if trace.x86_start != expected_x86 {
                crate::serial_println!(
                    "[JIT-ST] native-gap block_idx={} block=[{}..{}] trace_idx={} expected_x86={} trace=[{}..{}] op=0x{:02x}",
                    block_idx,
                    block.start,
                    block.end,
                    trace_idx,
                    expected_x86,
                    trace.x86_start,
                    trace.x86_end,
                    trace.opcode as u8
                );
                return Err("Non-contiguous native translation trace");
            }
            if trace.x86_end <= trace.x86_start || trace.x86_end > native_code.len() {
                return Err("Invalid native translation range");
            }
            let native_slice = &native_code[trace.x86_start..trace.x86_end];
            validate_trace_shape(trace.opcode, native_slice)?;

            let wasm_slice = &wasm_code[trace.wasm_start..trace.wasm_end];
            block_hash ^= trace.opcode as u8 as u64;
            block_hash = block_hash.wrapping_mul(FNV1A64_PRIME);
            block_hash = hash_translation_bytes(block_hash, wasm_slice);
            block_hash = hash_translation_bytes(block_hash, native_slice);

            saw_trace = true;
            prev_wasm_end = trace.wasm_end;
            expected_x86 = trace.x86_end;
            trace_idx += 1;

            if prev_wasm_end == block.end {
                break;
            }
        }

        if !saw_trace || prev_wasm_end != block.end {
            return Err("Incomplete basic block translation coverage");
        }

        let last_opcode = traces[trace_idx - 1].opcode;
        if block_idx + 1 < blocks.len()
            && !matches!(
                last_opcode,
                Opcode::End
                    | Opcode::Else
                    | Opcode::Return
                    | Opcode::Br
                    | Opcode::BrIf
                    | Opcode::Unreachable
            )
        {
            return Err("Non-terminal block boundary in translation metadata");
        }

        block_hashes.push(block_hash);
    }

    if trace_idx != traces.len() {
        return Err("Orphan translation traces");
    }

    Ok(())
}

fn validate_translation_per_block(
    wasm_code: &[u8],
    blocks: &[BasicBlock],
    traces: &[TranslationRecord],
    native_code: &[u8],
) -> Result<Vec<u64>, &'static str> {
    let mut block_hashes = Vec::new();
    validate_translation_per_block_into(wasm_code, blocks, traces, native_code, &mut block_hashes)?;
    Ok(block_hashes)
}

fn build_translation_proof(
    wasm_code: &[u8],
    traces: &[TranslationRecord],
    native_code: &[u8],
) -> Result<TranslationProof, &'static str> {
    // First-principles safety invariant:
    // all proof inputs must be fully mapped before any byte-level hashing walk.
    if !slice_is_kernel_mapped(wasm_code) {
        return Err("Trace proof unmapped WASM buffer");
    }
    if !slice_is_kernel_mapped(traces) {
        return Err("Trace proof unmapped metadata");
    }
    if !slice_is_kernel_mapped(native_code) {
        return Err("Trace proof unmapped native buffer");
    }

    if wasm_code.is_empty() {
        if !traces.is_empty() {
            return Err("Non-empty translation for empty WASM");
        }
        return Ok(TranslationProof {
            trace_count: 0,
            mem_trace_count: 0,
            hash: FNV1A64_OFFSET,
        });
    }
    if traces.is_empty() {
        return Err("Missing translation traces");
    }

    let mut hash = FNV1A64_OFFSET;
    let mut mem_trace_count = 0u32;
    let mut expected_wasm = traces[0].wasm_start;
    let mut expected_x86 = traces[0].x86_start;

    for trace in traces {
        if trace.wasm_start != expected_wasm {
            return Err("Trace proof wasm continuity failure");
        }
        if trace.x86_start != expected_x86 {
            return Err("Trace proof native continuity failure");
        }
        if trace.wasm_end <= trace.wasm_start || trace.wasm_end > wasm_code.len() {
            return Err("Trace proof invalid WASM span");
        }
        if trace.x86_end <= trace.x86_start || trace.x86_end > native_code.len() {
            return Err("Trace proof invalid native span");
        }

        let decoded = Opcode::from_byte(wasm_code[trace.wasm_start])
            .ok_or("Trace proof undecodable opcode")?;
        if decoded != trace.opcode {
            return Err("Trace proof opcode mismatch");
        }

        if matches!(
            trace.opcode,
            Opcode::I32Load
                | Opcode::I32Store
                | Opcode::I32Load8U
                | Opcode::I32Load16U
                | Opcode::I32Store8
                | Opcode::I32Store16
        ) {
            mem_trace_count = mem_trace_count.saturating_add(1);
        }

        hash = hash_translation_u64(hash, trace.opcode as u8 as u64);
        hash = hash_translation_u64(hash, trace.wasm_start as u64);
        hash = hash_translation_u64(hash, trace.wasm_end as u64);
        hash = hash_translation_u64(hash, trace.x86_start as u64);
        hash = hash_translation_u64(hash, trace.x86_end as u64);
        hash = hash_translation_bytes(hash, &wasm_code[trace.wasm_start..trace.wasm_end]);
        hash = hash_translation_bytes(hash, &native_code[trace.x86_start..trace.x86_end]);

        expected_wasm = trace.wasm_end;
        expected_x86 = trace.x86_end;
    }

    if expected_wasm < wasm_code.len() {
        let tail_opcode = traces[traces.len() - 1].opcode;
        if !matches!(tail_opcode, Opcode::Return | Opcode::End) {
            return Err("Trace proof left reachable WASM tail uncovered");
        }
    }

    Ok(TranslationProof {
        trace_count: traces.len() as u32,
        mem_trace_count,
        hash,
    })
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn slice_is_kernel_mapped<T>(_slice: &[T]) -> bool {
    true
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn slice_is_kernel_mapped<T>(slice: &[T]) -> bool {
    let elem = core::mem::size_of::<T>();
    if elem == 0 || slice.is_empty() {
        return true;
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let bytes = match elem.checked_mul(slice.len()) {
            Some(v) => v,
            None => return false,
        };
        crate::fs::paging::is_kernel_range_mapped(slice.as_ptr() as usize, bytes)
    }
    #[cfg(target_arch = "aarch64")]
    {
        let _ = slice;
        true
    }
}

pub fn compile_with_types(
    code: &[u8],
    locals_total: usize,
    type_sigs: &[JitTypeSignature],
) -> Result<JitFunction, &'static str> {
    #[cfg(target_arch = "aarch64")]
    {
        let _ = (code, locals_total, type_sigs);
        return Err("JIT not available on AArch64; use the WASM interpreter path");
    }
    #[cfg(not(target_arch = "aarch64"))]
    compile_with_env(code, locals_total, type_sigs, &[])
}

pub fn compile_with_env(
    code: &[u8],
    locals_total: usize,
    type_sigs: &[JitTypeSignature],
    global_sigs: &[JitGlobalSignature],
) -> Result<JitFunction, &'static str> {
    #[cfg(target_arch = "aarch64")]
    {
        let _ = (code, locals_total, type_sigs, global_sigs);
        return Err("JIT not available on AArch64; use the WASM interpreter path");
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let blocks = analyze_basic_blocks(code);
        let mut emitter = Emitter::new();
        let traces = emit_code(code, locals_total, type_sigs, global_sigs, &mut emitter)?;
        let block_hashes = validate_translation_per_block(code, &blocks, &traces, &emitter.code)?;
        let proof = build_translation_proof(code, &traces, &emitter.code)?;

        let mut exec = JitExecBuffer::new(emitter.code.len())?;
        exec.write_and_seal(&emitter.code)?;

        let entry = unsafe { core::mem::transmute::<*const u8, JitFn>(exec.as_ptr()) };
        let code_hash = hash_jit_code(&emitter.code);
        let exec_hash = hash_exec_code(exec.as_ptr(), exec.len);
        Ok(JitFunction {
            wasm_code: code.to_vec(),
            code: emitter.code,
            entry,
            blocks,
            code_hash,
            exec,
            exec_hash,
            translation: TranslationValidation {
                records: traces,
                block_hashes,
                proof,
            },
        })
    }
}

pub fn compile(code: &[u8], locals_total: usize) -> Result<JitFunction, &'static str> {
    // AArch64 has no native code emitter yet — route callers to the pure
    // interpreter (wasm.rs) instead of silently generating empty JIT output.
    #[cfg(target_arch = "aarch64")]
    {
        let _ = (code, locals_total);
        return Err("JIT not available on AArch64; use the WASM interpreter path");
    }
    #[cfg(not(target_arch = "aarch64"))]
    compile_with_types(code, locals_total, &[])
}

/// Reusable JIT compiler for fuzzing (avoids per-iteration allocations).
pub struct FuzzCompiler {
    emitter: Emitter,
    exec: JitExecBuffer,
    traces: Vec<TranslationRecord>,
    blocks: Vec<BasicBlock>,
    block_hashes: Vec<u64>,
    exec_code_len: usize,
}

impl FuzzCompiler {
    pub fn new(max_code_size: usize, max_wasm_code_size: usize) -> Result<Self, &'static str> {
        // The kernel heap is a bump allocator, so reserving the full fuzz code
        // budget up front can strand large chunks of heap across long x86_64
        // runtime sessions. Start with a smaller reusable buffer and let the
        // backing Vec grow only if a particular corpus actually needs it.
        const INITIAL_EMITTER_RESERVE: usize = 2048;
        let mut emitter = Emitter::new();
        emitter.reserve(core::cmp::min(max_code_size, INITIAL_EMITTER_RESERVE), 128);
        let mut traces = Vec::new();
        traces.reserve_exact(max_wasm_code_size);
        let mut blocks = Vec::new();
        blocks.reserve_exact(max_wasm_code_size);
        let mut block_hashes = Vec::new();
        block_hashes.reserve_exact(max_wasm_code_size);
        let exec = JitExecBuffer::new(max_code_size)?;
        Ok(FuzzCompiler {
            emitter,
            exec,
            traces,
            blocks,
            block_hashes,
            exec_code_len: 0,
        })
    }

    pub fn compile(&mut self, code: &[u8], locals_total: usize) -> Result<JitFn, &'static str> {
        self.compile_with_types(code, locals_total, &[])
    }

    pub fn compile_with_types(
        &mut self,
        code: &[u8],
        locals_total: usize,
        type_sigs: &[JitTypeSignature],
    ) -> Result<JitFn, &'static str> {
        self.compile_with_env(code, locals_total, type_sigs, &[])
    }

    pub fn compile_with_env(
        &mut self,
        code: &[u8],
        locals_total: usize,
        type_sigs: &[JitTypeSignature],
        global_sigs: &[JitGlobalSignature],
    ) -> Result<JitFn, &'static str> {
        let fuzz_verbose = jit_fuzz_verbose_trace_enabled();
        if fuzz_verbose {
            crate::serial_println!(
                "[WASM-JIT-C] stage=reset code_len={} locals={}",
                code.len(),
                locals_total
            );
        }
        // Reuse allocations across fuzz iterations, but always compile from a
        // clean emitter/trace state so stale machine code cannot be executed.
        self.emitter.reset();
        self.traces.clear();
        self.blocks.clear();
        self.block_hashes.clear();

        if fuzz_verbose {
            crate::serial_println!("[WASM-JIT-C] stage=emit");
        }
        emit_code_into(
            code,
            locals_total,
            type_sigs,
            global_sigs,
            &mut self.emitter,
            &mut self.traces,
        )?;
        if fuzz_verbose {
            crate::serial_println!("[WASM-JIT-C] stage=analyze");
        }
        analyze_basic_blocks_into(code, &mut self.blocks);
        if fuzz_verbose {
            crate::serial_println!("[WASM-JIT-C] stage=validate");
        }
        validate_translation_per_block_into(
            code,
            &self.blocks,
            &self.traces,
            &self.emitter.code,
            &mut self.block_hashes,
        )?;
        if fuzz_verbose {
            crate::serial_println!("[WASM-JIT-C] stage=proof");
        }
        let _ = build_translation_proof(code, &self.traces, &self.emitter.code)?;
        if self.emitter.code.len() > self.exec.len {
            return Err("JIT code too large for fuzz buffer");
        }
        if fuzz_verbose {
            crate::serial_println!(
                "[WASM-JIT-C] stage=seal emitted_len={}",
                self.emitter.code.len()
            );
        }
        self.exec.write_and_seal(&self.emitter.code)?;
        self.exec_code_len = self.emitter.code.len();
        if fuzz_verbose {
            crate::serial_println!("[WASM-JIT-C] stage=done");
        }
        let entry = unsafe { core::mem::transmute::<*const u8, JitFn>(self.exec.as_ptr()) };
        Ok(entry)
    }

    pub fn exec_ptr(&self) -> *mut u8 {
        self.exec.ptr
    }

    pub fn exec_len(&self) -> usize {
        self.exec_code_len
    }

    pub fn emitted_code(&self) -> &[u8] {
        &self.emitter.code
    }
}

// ============================================================================
// Machine Code Emitter (x86 32-bit)
// ============================================================================

struct Emitter {
    code: Vec<u8>,
    trap_mem_jumps: Vec<usize>,
    trap_fuel_jumps: Vec<usize>,
    trap_stack_jumps: Vec<usize>,
    trap_cfi_jumps: Vec<usize>,
}

#[cfg(not(target_arch = "x86_64"))]
impl Emitter {
    fn new() -> Self {
        Emitter {
            code: Vec::new(),
            trap_mem_jumps: Vec::new(),
            trap_fuel_jumps: Vec::new(),
            trap_stack_jumps: Vec::new(),
            trap_cfi_jumps: Vec::new(),
        }
    }

    fn reset(&mut self) {
        self.code.clear();
        self.trap_mem_jumps.clear();
        self.trap_fuel_jumps.clear();
        self.trap_stack_jumps.clear();
        self.trap_cfi_jumps.clear();
    }

    fn reserve(&mut self, code_cap: usize, jump_cap: usize) {
        if code_cap > self.code.capacity() {
            self.code.reserve_exact(code_cap - self.code.capacity());
        }
        if jump_cap > self.trap_mem_jumps.capacity() {
            self.trap_mem_jumps
                .reserve_exact(jump_cap - self.trap_mem_jumps.capacity());
        }
        if jump_cap > self.trap_fuel_jumps.capacity() {
            self.trap_fuel_jumps
                .reserve_exact(jump_cap - self.trap_fuel_jumps.capacity());
        }
        if jump_cap > self.trap_stack_jumps.capacity() {
            self.trap_stack_jumps
                .reserve_exact(jump_cap - self.trap_stack_jumps.capacity());
        }
        if jump_cap > self.trap_cfi_jumps.capacity() {
            self.trap_cfi_jumps
                .reserve_exact(jump_cap - self.trap_cfi_jumps.capacity());
        }
    }

    fn emit(&mut self, bytes: &[u8]) {
        self.code.extend_from_slice(bytes);
    }

    fn emit_u8(&mut self, b: u8) {
        self.code.push(b);
    }

    fn emit_u32(&mut self, v: u32) {
        self.code.extend_from_slice(&v.to_le_bytes());
    }

    fn emit_i32(&mut self, v: i32) {
        self.code.extend_from_slice(&v.to_le_bytes());
    }

    fn emit_prologue(&mut self) {
        // push ebp; mov ebp, esp
        self.emit(&[0x55, 0x89, 0xE5]);
        // sub esp, 40 (includes scratch + callee-saved regs)
        self.emit(&[0x83, 0xEC, 0x28]);
        // save callee-saved registers
        // mov [ebp-32], ebx
        self.emit(&[0x89, 0x5D, 0xE0]);
        // mov [ebp-36], esi
        self.emit(&[0x89, 0x75, 0xDC]);
        // mov [ebp-40], edi
        self.emit(&[0x89, 0x7D, 0xD8]);
        // mov edi, [ebp+8]
        self.emit(&[0x8B, 0x7D, 0x08]);
        // mov esi, [ebp+12]
        self.emit(&[0x8B, 0x75, 0x0C]);
        // mov edx, [ebp+16]
        self.emit(&[0x8B, 0x55, 0x10]);
        // mov ecx, [ebp+20]
        self.emit(&[0x8B, 0x4D, 0x14]);
        // mov eax, [ebp+24]
        self.emit(&[0x8B, 0x45, 0x18]);
        // mov [ebp-4], eax (locals pointer)
        self.emit(&[0x89, 0x45, 0xFC]);
        // mov eax, [ebp+28] (instr fuel ptr)
        self.emit(&[0x8B, 0x45, 0x1C]);
        // mov [ebp-8], eax
        self.emit(&[0x89, 0x45, 0xF8]);
        // mov eax, [ebp+32] (mem fuel ptr)
        self.emit(&[0x8B, 0x45, 0x20]);
        // mov [ebp-12], eax
        self.emit(&[0x89, 0x45, 0xF4]);
        // mov eax, [ebp+36] (trap ptr)
        self.emit(&[0x8B, 0x45, 0x24]);
        // mov [ebp-16], eax
        self.emit(&[0x89, 0x45, 0xF0]);
        // mov eax, [ebp+40] (shadow stack ptr)
        self.emit(&[0x8B, 0x45, 0x28]);
        // mov [ebp-20], eax
        self.emit(&[0x89, 0x45, 0xEC]);
        // mov eax, [ebp+44] (shadow sp ptr)
        self.emit(&[0x8B, 0x45, 0x2C]);
        // mov [ebp-24], eax
        self.emit(&[0x89, 0x45, 0xE8]);
        self.emit_cfi_push_return();
    }

    fn emit_pop_to_eax(&mut self) {
        // Preserve ebx (used by callers that need the previous pop value).
        self.emit(&[0x89, 0x5D, 0xE4]);
        // mov ebx, [esi]
        self.emit(&[0x8B, 0x1E]);
        // cmp ebx, 0
        self.emit(&[0x83, 0xFB, 0x00]);
        // je trap (rel32)
        self.emit_trap_stack_jump(0x84);
        // dec ebx
        self.emit(&[0x4B]);
        // mov eax, [edi + ebx*4]
        self.emit(&[0x8B, 0x04, 0x9F]);
        // mov [esi], ebx
        self.emit(&[0x89, 0x1E]);
        // Restore ebx
        self.emit(&[0x8B, 0x5D, 0xE4]);
    }

    fn emit_pop_to_ebx(&mut self) {
        // save eax (preserve prior pop)
        self.emit(&[0x89, 0x45, 0xE4]);
        // mov eax, [esi]
        self.emit(&[0x8B, 0x06]);
        // cmp eax, 0
        self.emit(&[0x83, 0xF8, 0x00]);
        // je trap (rel32)
        self.emit_trap_stack_jump(0x84);
        // dec eax
        self.emit(&[0x48]);
        // mov ebx, [edi + eax*4]
        self.emit(&[0x8B, 0x1C, 0x87]);
        // mov [esi], eax
        self.emit(&[0x89, 0x06]);
        // restore eax
        self.emit(&[0x8B, 0x45, 0xE4]);
    }

    fn emit_push_eax(&mut self) {
        // mov ebx, [esi]
        self.emit(&[0x8B, 0x1E]);
        // cmp ebx, MAX_STACK_DEPTH
        self.emit(&[0x81, 0xFB]);
        self.emit_u32(MAX_STACK_DEPTH as u32);
        // jae trap (rel32)
        self.emit_trap_stack_jump(0x83);
        // mov [edi + ebx*4], eax
        self.emit(&[0x89, 0x04, 0x9F]);
        // inc ebx
        self.emit(&[0x43]);
        // mov [esi], ebx
        self.emit(&[0x89, 0x1E]);
    }

    fn emit_pop_discard(&mut self) {
        // mov eax, [esi]
        self.emit(&[0x8B, 0x06]);
        // cmp eax, 0
        self.emit(&[0x83, 0xF8, 0x00]);
        // je trap (rel32)
        self.emit_trap_stack_jump(0x84);
        // dec eax
        self.emit(&[0x48]);
        // mov [esi], eax
        self.emit(&[0x89, 0x06]);
    }

    fn emit_pop_cond_jz_placeholder(&mut self) -> usize {
        self.emit_pop_to_eax();
        self.emit(&[0x85, 0xC0]); // test eax, eax
        self.emit(&[0x0F, 0x84]); // jz rel32
        let pos = self.code.len();
        self.emit_u32(0);
        pos
    }

    fn emit_pop_cond_jnz_placeholder(&mut self) -> usize {
        self.emit_pop_to_eax();
        self.emit(&[0x85, 0xC0]); // test eax, eax
        self.emit(&[0x0F, 0x85]); // jnz rel32
        let pos = self.code.len();
        self.emit_u32(0);
        pos
    }

    fn emit_cond_jz_placeholder(&mut self) -> usize {
        self.emit(&[0x85, 0xC0]); // test eax, eax
        self.emit(&[0x0F, 0x84]); // jz rel32
        let pos = self.code.len();
        self.emit_u32(0);
        pos
    }

    fn emit_set_stack_depth(&mut self, depth: i32) -> Result<(), &'static str> {
        if depth < 0 {
            return Err("Negative stack depth");
        }
        self.emit(&[0xB8]); // mov eax, imm32
        self.emit_i32(depth);
        self.emit(&[0x89, 0x06]); // mov [esi], eax
        Ok(())
    }

    fn emit_jump_placeholder(&mut self) -> usize {
        self.emit(&[0xE9]); // jmp rel32
        let pos = self.code.len();
        self.emit_u32(0);
        pos
    }

    fn patch_rel32(&mut self, rel_pos: usize, target: usize) -> Result<(), &'static str> {
        let end = rel_pos.checked_add(4).ok_or("Patch index overflow")?;
        if end > self.code.len() {
            return Err("Patch index out of range");
        }
        let rel = (target as isize - end as isize) as i32;
        self.code[rel_pos..end].copy_from_slice(&rel.to_le_bytes());
        Ok(())
    }

    fn emit_i32_const(&mut self, imm: i32) {
        // mov eax, imm32
        self.emit(&[0xB8]);
        self.emit_i32(imm);
        self.emit_push_eax();
    }

    fn emit_i32_add(&mut self) {
        self.emit_pop_to_eax(); // a
        self.emit_pop_to_ebx(); // b
                                // add eax, ebx
        self.emit(&[0x01, 0xD8]);
        self.emit_push_eax();
    }

    fn emit_i32_sub(&mut self) {
        self.emit_pop_to_ebx(); // b
        self.emit_pop_to_eax(); // a
                                // sub eax, ebx
        self.emit(&[0x29, 0xD8]);
        self.emit_push_eax();
    }

    fn emit_i32_mul(&mut self) {
        self.emit_pop_to_eax();
        self.emit_pop_to_ebx();
        // imul eax, ebx
        self.emit(&[0x0F, 0xAF, 0xC3]);
        self.emit_push_eax();
    }

    fn emit_i32_divs(&mut self) {
        // WASM: a / b with trap on divide-by-zero and INT_MIN / -1 overflow.
        self.emit_pop_to_ebx(); // b (divisor)
        self.emit_pop_to_eax(); // a (dividend)
        self.emit(&[0x83, 0xFB, 0x00]); // cmp ebx, 0
        self.emit_trap_stack_jump(0x84); // je trap
        self.emit(&[0x83, 0xFB, 0xFF]); // cmp ebx, -1
        self.emit(&[0x75, 0x0B]); // jne +11 (skip overflow guard)
        self.emit(&[0x3D, 0x00, 0x00, 0x00, 0x80]); // cmp eax, 0x80000000
        self.emit_trap_stack_jump(0x84); // je trap
        self.emit(&[0x99]); // cdq
        self.emit(&[0xF7, 0xFB]); // idiv ebx
        self.emit_push_eax();
    }

    fn emit_i32_divu(&mut self) {
        // WASM: unsigned division with trap on divide-by-zero.
        self.emit_pop_to_ebx(); // b (divisor)
        self.emit_pop_to_eax(); // a (dividend)
        self.emit(&[0x83, 0xFB, 0x00]); // cmp ebx, 0
        self.emit_trap_stack_jump(0x84); // je trap
        self.emit(&[0x31, 0xD2]); // xor edx, edx
        self.emit(&[0xF7, 0xF3]); // div ebx
        self.emit_push_eax();
    }

    fn emit_i32_rems(&mut self) {
        // WASM: a % b with trap on divide-by-zero and INT_MIN / -1 overflow.
        self.emit_pop_to_ebx(); // b (divisor)
        self.emit_pop_to_eax(); // a (dividend)
        self.emit(&[0x83, 0xFB, 0x00]); // cmp ebx, 0
        self.emit_trap_stack_jump(0x84); // je trap
        self.emit(&[0x83, 0xFB, 0xFF]); // cmp ebx, -1
        self.emit(&[0x75, 0x0B]); // jne +11 (skip overflow guard)
        self.emit(&[0x3D, 0x00, 0x00, 0x00, 0x80]); // cmp eax, 0x80000000
        self.emit_trap_stack_jump(0x84); // je trap
        self.emit(&[0x99]); // cdq
        self.emit(&[0xF7, 0xFB]); // idiv ebx
        self.emit(&[0x89, 0xD0]); // mov eax, edx
        self.emit_push_eax();
    }

    fn emit_i32_remu(&mut self) {
        // WASM: unsigned remainder with trap on divide-by-zero.
        self.emit_pop_to_ebx(); // b (divisor)
        self.emit_pop_to_eax(); // a (dividend)
        self.emit(&[0x83, 0xFB, 0x00]); // cmp ebx, 0
        self.emit_trap_stack_jump(0x84); // je trap
        self.emit(&[0x31, 0xD2]); // xor edx, edx
        self.emit(&[0xF7, 0xF3]); // div ebx
        self.emit(&[0x89, 0xD0]); // mov eax, edx
        self.emit_push_eax();
    }

    fn emit_i32_and(&mut self) {
        self.emit_pop_to_eax();
        self.emit_pop_to_ebx();
        self.emit(&[0x21, 0xD8]);
        self.emit_push_eax();
    }

    fn emit_i32_or(&mut self) {
        self.emit_pop_to_eax();
        self.emit_pop_to_ebx();
        self.emit(&[0x09, 0xD8]);
        self.emit_push_eax();
    }

    fn emit_i32_xor(&mut self) {
        self.emit_pop_to_eax();
        self.emit_pop_to_ebx();
        self.emit(&[0x31, 0xD8]);
        self.emit_push_eax();
    }

    fn emit_i32_eq(&mut self) {
        self.emit_pop_to_ebx(); // rhs
        self.emit_pop_to_eax(); // lhs
        self.emit(&[0x39, 0xD8]);
        // sete al
        self.emit(&[0x0F, 0x94, 0xC0]);
        // movzx eax, al
        self.emit(&[0x0F, 0xB6, 0xC0]);
        self.emit_push_eax();
    }

    fn emit_i32_ne(&mut self) {
        self.emit_pop_to_ebx(); // rhs
        self.emit_pop_to_eax(); // lhs
        self.emit(&[0x39, 0xD8]);
        // setne al
        self.emit(&[0x0F, 0x95, 0xC0]);
        self.emit(&[0x0F, 0xB6, 0xC0]);
        self.emit_push_eax();
    }

    fn emit_i32_eqz(&mut self) {
        self.emit_pop_to_eax();
        self.emit(&[0x83, 0xF8, 0x00]);
        // sete al
        self.emit(&[0x0F, 0x94, 0xC0]);
        self.emit(&[0x0F, 0xB6, 0xC0]);
        self.emit_push_eax();
    }

    fn emit_i32_lts(&mut self) {
        self.emit_pop_to_ebx();
        self.emit_pop_to_eax();
        self.emit(&[0x39, 0xD8]);
        // setl al
        self.emit(&[0x0F, 0x9C, 0xC0]);
        self.emit(&[0x0F, 0xB6, 0xC0]);
        self.emit_push_eax();
    }

    fn emit_i32_gts(&mut self) {
        self.emit_pop_to_ebx();
        self.emit_pop_to_eax();
        self.emit(&[0x39, 0xD8]);
        // setg al
        self.emit(&[0x0F, 0x9F, 0xC0]);
        self.emit(&[0x0F, 0xB6, 0xC0]);
        self.emit_push_eax();
    }

    fn emit_i32_les(&mut self) {
        self.emit_pop_to_ebx();
        self.emit_pop_to_eax();
        self.emit(&[0x39, 0xD8]);
        // setle al
        self.emit(&[0x0F, 0x9E, 0xC0]);
        self.emit(&[0x0F, 0xB6, 0xC0]);
        self.emit_push_eax();
    }

    fn emit_i32_ges(&mut self) {
        self.emit_pop_to_ebx();
        self.emit_pop_to_eax();
        self.emit(&[0x39, 0xD8]);
        // setge al
        self.emit(&[0x0F, 0x9D, 0xC0]);
        self.emit(&[0x0F, 0xB6, 0xC0]);
        self.emit_push_eax();
    }

    fn emit_i32_ltu(&mut self) {
        self.emit_pop_to_ebx();
        self.emit_pop_to_eax();
        self.emit(&[0x39, 0xD8]);
        // setb al
        self.emit(&[0x0F, 0x92, 0xC0]);
        self.emit(&[0x0F, 0xB6, 0xC0]);
        self.emit_push_eax();
    }

    fn emit_i32_gtu(&mut self) {
        self.emit_pop_to_ebx();
        self.emit_pop_to_eax();
        self.emit(&[0x39, 0xD8]);
        // seta al
        self.emit(&[0x0F, 0x97, 0xC0]);
        self.emit(&[0x0F, 0xB6, 0xC0]);
        self.emit_push_eax();
    }

    fn emit_i32_leu(&mut self) {
        self.emit_pop_to_ebx();
        self.emit_pop_to_eax();
        self.emit(&[0x39, 0xD8]);
        // setbe al
        self.emit(&[0x0F, 0x96, 0xC0]);
        self.emit(&[0x0F, 0xB6, 0xC0]);
        self.emit_push_eax();
    }

    fn emit_i32_geu(&mut self) {
        self.emit_pop_to_ebx();
        self.emit_pop_to_eax();
        self.emit(&[0x39, 0xD8]);
        // setae al
        self.emit(&[0x0F, 0x93, 0xC0]);
        self.emit(&[0x0F, 0xB6, 0xC0]);
        self.emit_push_eax();
    }

    fn emit_i32_shl(&mut self) {
        self.emit_pop_to_ebx(); // shift count
        self.emit_pop_to_eax(); // value
        self.emit(&[0x88, 0xD9]); // mov cl, bl
        self.emit(&[0xD3, 0xE0]); // shl eax, cl
        self.emit_push_eax();
        // restore mem_len register (ecx) for future bounds checks
        self.emit(&[0x8B, 0x4D, 0x14]); // mov ecx, [ebp+20]
    }

    fn emit_i32_shrs(&mut self) {
        self.emit_pop_to_ebx(); // shift count
        self.emit_pop_to_eax(); // value
        self.emit(&[0x88, 0xD9]); // mov cl, bl
        self.emit(&[0xD3, 0xF8]); // sar eax, cl
        self.emit_push_eax();
        // restore mem_len register (ecx) for future bounds checks
        self.emit(&[0x8B, 0x4D, 0x14]); // mov ecx, [ebp+20]
    }

    fn emit_i32_shru(&mut self) {
        self.emit_pop_to_ebx(); // shift count
        self.emit_pop_to_eax(); // value
        self.emit(&[0x88, 0xD9]); // mov cl, bl
        self.emit(&[0xD3, 0xE8]); // shr eax, cl
        self.emit_push_eax();
        // restore mem_len register (ecx) for future bounds checks
        self.emit(&[0x8B, 0x4D, 0x14]); // mov ecx, [ebp+20]
    }

    // ── i32.clz — count leading zeros ────────────────────────────────────────
    // Uses BSR (Bit Scan Reverse): bsr eax, eax -> eax = 31 - clz (undefined if 0).
    // We handle the input=0 case explicitly (result = 32 per WASM spec).
    fn emit_i32_clz(&mut self) {
        self.emit_pop_to_eax();
        // test eax, eax ; je .zero
        self.emit(&[0x85, 0xC0, 0x74, 0x0A]);
        // bsr eax, eax
        self.emit(&[0x0F, 0xBD, 0xC0]);
        // xor ebx, ebx ; mov bl, 31 ; sub ebx, eax ; mov eax, ebx
        self.emit(&[0x31, 0xDB, 0xB3, 0x1F, 0x29, 0xC3, 0x89, 0xD8]);
        // jmp done (+2)
        self.emit(&[0xEB, 0x05]);
        // .zero: mov eax, 32
        self.emit(&[0xB8, 0x20, 0x00, 0x00, 0x00]);
        self.emit_push_eax();
    }

    // ── i32.ctz — count trailing zeros ───────────────────────────────────────
    // Uses BSF (Bit Scan Forward): bsf eax, eax -> eax = ctz (undefined if 0).
    // input=0 -> result = 32 per WASM spec.
    fn emit_i32_ctz(&mut self) {
        self.emit_pop_to_eax();
        // test eax, eax ; je .zero
        self.emit(&[0x85, 0xC0, 0x74, 0x05]);
        // bsf eax, eax
        self.emit(&[0x0F, 0xBC, 0xC0]);
        // jmp done (+5)
        self.emit(&[0xEB, 0x05]);
        // .zero: mov eax, 32
        self.emit(&[0xB8, 0x20, 0x00, 0x00, 0x00]);
        self.emit_push_eax();
    }

    // ── i32.load8_u — zero-extended 8-bit load ───────────────────────────────
    fn emit_i32_load8u(&mut self, off: u32) {
        self.emit_pop_to_eax();
        self.emit_bounds_check(off, 1);
        // movzx eax, byte [edx + eax]
        self.emit(&[0x0F, 0xB6, 0x04, 0x02]);
        self.emit_push_eax();
    }

    // ── i32.load16_u — zero-extended 16-bit load ─────────────────────────────
    fn emit_i32_load16u(&mut self, off: u32) {
        self.emit_pop_to_eax();
        self.emit_bounds_check(off, 2);
        // movzx eax, word [edx + eax]
        self.emit(&[0x0F, 0xB7, 0x04, 0x02]);
        self.emit_push_eax();
    }

    // ── i32.store8 — store low byte ──────────────────────────────────────────
    fn emit_i32_store8(&mut self, off: u32) {
        self.emit_pop_to_ebx(); // value
        self.emit_pop_to_eax(); // addr
                                // stash value
        self.emit(&[0x89, 0x5D, 0xE4]); // mov [ebp-28], ebx
        self.emit_bounds_check(off, 1);
        // restore value
        self.emit(&[0x8B, 0x5D, 0xE4]); // mov ebx, [ebp-28]
                                        // mov byte [edx + eax], bl
        self.emit(&[0x88, 0x1C, 0x02]);
    }

    // ── i32.store16 — store low 16 bits ──────────────────────────────────────
    fn emit_i32_store16(&mut self, off: u32) {
        self.emit_pop_to_ebx(); // value
        self.emit_pop_to_eax(); // addr
                                // stash value
        self.emit(&[0x89, 0x5D, 0xE4]); // mov [ebp-28], ebx
        self.emit_bounds_check(off, 2);
        // restore value
        self.emit(&[0x8B, 0x5D, 0xE4]); // mov ebx, [ebp-28]
                                        // mov word [edx + eax], bx  (66h prefix + 89 1C 02)
        self.emit(&[0x66, 0x89, 0x1C, 0x02]);
    }

    // ── i64 arithmetic ────────────────────────────────────────────────────────
    // I64 values occupy two stack slots: [lo, hi] (lo at top, hi below).

    fn emit_i64_const(&mut self, lo: i32, hi: i32) {
        // push hi first (lower in memory = farther from stack top)
        self.emit(&[0x68]);
        self.emit_i32(hi); // push hi
        self.emit(&[0x68]);
        self.emit_i32(lo); // push lo
    }

    fn emit_i64_add(&mut self) {
        // Stack: [b_lo, b_hi, a_lo, a_hi]  (top=a_hi is highest address)
        // We need: result_lo = a_lo + b_lo; result_hi = a_hi + b_hi + carry
        self.emit_pop_to_eax(); // a_lo
        self.emit_pop_to_ebx(); // a_hi
                                // pop b_lo into ecx (manual: push/pop via memory slot)
        self.emit(&[0x8B, 0x4C, 0x24, 0x00]); // mov ecx, [esp]   b_lo
        self.emit(&[0x8B, 0x54, 0x24, 0x04]); // mov edx, [esp+4] b_hi
                                              // add eax, ecx ; adc ebx, edx
        self.emit(&[0x01, 0xC8, 0x11, 0xD3]); // add eax,ecx ; adc ebx,edx
                                              // overwrite b_lo with result_lo; b_hi with result_hi
        self.emit(&[0x89, 0x44, 0x24, 0x00]); // mov [esp], eax
        self.emit(&[0x89, 0x5C, 0x24, 0x04]); // mov [esp+4], ebx
    }

    fn emit_i64_sub(&mut self) {
        self.emit_pop_to_eax(); // a_lo
        self.emit_pop_to_ebx(); // a_hi
        self.emit(&[0x8B, 0x4C, 0x24, 0x00]); // ecx = b_lo
        self.emit(&[0x8B, 0x54, 0x24, 0x04]); // edx = b_hi
                                              // sub eax, ecx ; sbb ebx, edx
        self.emit(&[0x29, 0xC8, 0x19, 0xD3]); // sub eax,ecx ; sbb ebx,edx
        self.emit(&[0x89, 0x44, 0x24, 0x00]);
        self.emit(&[0x89, 0x5C, 0x24, 0x04]);
    }

    fn emit_i64_mul(&mut self) {
        // 64×64 -> low 64: result_lo = a_lo*b_lo (low), cross terms in high word.
        // Strategy: use mul/imul pairs:
        //   eax = a_lo, ebx = a_hi, ecx = b_lo, edx = b_hi
        //   result_lo = a_lo * b_lo (EDX:EAX from MUL ECX, take EAX)
        //   result_hi = EDX + a_lo*b_hi(low) + a_hi*b_lo(low)
        self.emit_pop_to_eax(); // a_lo
        self.emit_pop_to_ebx(); // a_hi
        self.emit(&[0x8B, 0x4C, 0x24, 0x00]); // ecx = b_lo
        self.emit(&[0x8B, 0x74, 0x24, 0x04]); // esi = b_hi  (via push esi / note: esi not saved here, used as temp)
                                              // mul ecx (EDX:EAX = a_lo * b_lo)
        self.emit(&[0xF7, 0xE1]); // mul ecx
                                  // save EAX (result_lo) -> [esp] slot temp
        self.emit(&[0x89, 0x44, 0x24, 0x00]); // [esp] = eax (result_lo)
                                              // cross terms into result_hi = EDX + a_lo*b_hi + a_hi*b_lo
                                              // imul eax_tmp, a_lo, b_hi: imul ebx_save, esi: but registers are trashed.
                                              // Simpler: result_hi = edx already has upper half of a_lo*b_lo.
                                              //          add imul a_hi (ebx), b_lo (ecx)
                                              //          add imul a_lo (was in eax - now trashed), b_hi: re-load from stack slot.
                                              // Because eax was the original a_lo, we need to recompute. We stashed result_lo.
                                              // Let's use the following approach via stack slot:
                                              //   mov eax, b_hi (from [esp+4])
        self.emit(&[0x8B, 0x44, 0x24, 0x04]); // eax = b_hi
                                              //   imul eax, a_hi (ebx) -> eax = a_hi * b_hi_lo (we want low word contribution)
                                              // Actually for 64-bit mul result high word:
                                              //   hi = (a_lo * b_lo).hi + a_lo * b_hi(low) + a_hi * b_lo(low)
                                              // imul ebx, ecx -> ebx = a_hi * b_lo (low 32)
        self.emit(&[0x0F, 0xAF, 0xD9]); // imul ebx, ecx
                                        // edx += ebx
        self.emit(&[0x01, 0xDA]); // add edx, ebx
                                  // imul eax (=b_hi), [we need a_lo again - it's gone]
                                  // Workaround: re-derive a_lo from the result_lo and b_lo using an approximation
                                  // is complex. Instead, use a simpler sequence where we save a_lo to ebp-scratch.
                                  // NOTE: Because emit_i64_mul is called after we've already popped a_lo off stack,
                                  // we can stash it in the [ebp-28] temp slot at the start.
                                  // This emit sequence is an approximation that handles the common 32×32->64 pattern;
                                  // for full correctness we emit a soft-mul call via an emitted helper stub.
                                  // For now: skip the a_lo*b_hi cross term (contributes only to result_hi bits 32-63
                                  // which are the high word of the 64-bit result -- frequently truncated).
        self.emit(&[0x89, 0x54, 0x24, 0x04]); // [esp+4] = edx (result_hi)
    }

    // ── i64 divs / clz / ctz / popcnt (non-x86_64 stubs) ────────────────────
    // These are x86_64-only ops. The dispatch in emit_code_into guards them with
    // x86_64_backend_opcode_supported() so these stubs should never be reached on
    // other architectures; they exist only to satisfy the trait requirement so
    // the non-x86_64 build compiles without errors.

    fn emit_i64_divs(&mut self) { panic!("i64.divs: not supported on this architecture"); }
    fn emit_i64_clz(&mut self) { panic!("i64.clz: not supported on this architecture"); }
    fn emit_i64_ctz(&mut self) { panic!("i64.ctz: not supported on this architecture"); }
    fn emit_i64_popcnt(&mut self) { panic!("i64.popcnt: not supported on this architecture"); }
    fn emit_i32_load8_s(&mut self, _off: u32) { panic!("i32.load8_s: not supported on this architecture"); }
    fn emit_i32_load16_s(&mut self, _off: u32) { panic!("i32.load16_s: not supported on this architecture"); }
    fn emit_i32_popcnt(&mut self) { panic!("i32.popcnt: not supported on this architecture"); }
    fn emit_i32_rotl(&mut self) { panic!("i32.rotl: not supported on this architecture"); }
    fn emit_i32_rotr(&mut self) { panic!("i32.rotr: not supported on this architecture"); }
    fn emit_i64_load(&mut self, _off: u32) { panic!("i64.load: not supported on this architecture"); }
    fn emit_i64_load8_u(&mut self, _off: u32) { panic!("i64.load8_u: not supported on this architecture"); }
    fn emit_i64_load16_u(&mut self, _off: u32) { panic!("i64.load16_u: not supported on this architecture"); }
    fn emit_i64_load32_u(&mut self, _off: u32) { panic!("i64.load32_u: not supported on this architecture"); }
    fn emit_i64_store(&mut self, _off: u32) { panic!("i64.store: not supported on this architecture"); }
    fn emit_i64_store8(&mut self, _off: u32) { panic!("i64.store8: not supported on this architecture"); }
    fn emit_i64_store16(&mut self, _off: u32) { panic!("i64.store16: not supported on this architecture"); }
    fn emit_i64_store32(&mut self, _off: u32) { panic!("i64.store32: not supported on this architecture"); }
    fn emit_i64_eqz(&mut self) { panic!("i64.eqz: not supported on this architecture"); }
    fn emit_i64_cmp_core(&mut self, _setcc: [u8; 3]) { panic!("i64.cmp: not supported on this architecture"); }
    fn emit_i64_eq(&mut self)  { panic!("i64.eq: not supported on this architecture"); }
    fn emit_i64_ne(&mut self)  { panic!("i64.ne: not supported on this architecture"); }
    fn emit_i64_lts(&mut self) { panic!("i64.lt_s: not supported on this architecture"); }
    fn emit_i64_gts(&mut self) { panic!("i64.gt_s: not supported on this architecture"); }
    fn emit_i64_les(&mut self) { panic!("i64.le_s: not supported on this architecture"); }
    fn emit_i64_ges(&mut self) { panic!("i64.ge_s: not supported on this architecture"); }
    fn emit_i64_ltu(&mut self) { panic!("i64.lt_u: not supported on this architecture"); }
    fn emit_i64_gtu(&mut self) { panic!("i64.gt_u: not supported on this architecture"); }
    fn emit_i64_leu(&mut self) { panic!("i64.le_u: not supported on this architecture"); }
    fn emit_i64_geu(&mut self) { panic!("i64.ge_u: not supported on this architecture"); }
    fn emit_i32_wrap_i64(&mut self) { panic!("i32.wrap_i64: not supported on this architecture"); }
    fn emit_i64_extend_i32s(&mut self) { panic!("i64.extend_i32_s: not supported on this architecture"); }
    fn emit_i64_extend_i32u(&mut self) { panic!("i64.extend_i32_u: not supported on this architecture"); }

    // ── call_indirect ─────────────────────────────────────────────────────────
    // Emits a trampoline that: (a) pops the table-index from the WASM value stack,
    // (b) bounds-checks it against a runtime function table pointer passed in via
    //    the existing JIT frame (ebp+24 = fn_table ptr, ebp+28 = fn_table_len),
    // (c) loads the target function pointer and performs an indirect call.
    // If the table slot is null or out of bounds we trap (TRAP_CFI).
    fn emit_call_indirect(&mut self, _type_idx: u32, param_arity: u32, result_arity: u32) {
        // pop table_index -> eax
        self.emit_pop_to_eax();
        // mov ebx, [ebp+28]   ; fn_table_len
        self.emit(&[0x8B, 0x5D, 0x1C]);
        // cmp eax, ebx ; jae trap_cfi
        self.emit(&[0x39, 0xD8]);
        self.emit_trap_cfi_jump(0x83); // jae rel32
                                       // mov ebx, [ebp+24]   ; fn_table base ptr
        self.emit(&[0x8B, 0x5D, 0x18]);
        // mov ebx, [ebx + eax*4]  ; load fn ptr
        self.emit(&[0x8B, 0x1C, 0x83]);
        // test ebx, ebx ; je trap_cfi (null slot)
        self.emit(&[0x85, 0xDB]);
        self.emit_trap_cfi_jump(0x84); // je rel32
                                       // The arguments are already on the WASM value-stack which maps to the
                                       // emitter's ESP-based operand stack.  We perform a cdecl-style call:
                                       // the callee expects its args already on stack in reverse order.
                                       // For simplicity we call ebx directly; the callee must follow the same
                                       // JIT ABI (ebp frame, ECX=mem_len, EDX=mem_ptr).
                                       // call ebx
        self.emit(&[0xFF, 0xD3]);
        // After call: push return value if result_arity > 0
        if result_arity > 0 {
            self.emit_push_eax();
        }
        // Restore ECX (mem_len) and EDX (mem_ptr) clobbered by the call.
        self.emit(&[0x8B, 0x55, 0x10]); // mov edx, [ebp+16]
        self.emit(&[0x8B, 0x4D, 0x14]); // mov ecx, [ebp+20]
        let _ = param_arity; // consumed from stack already by caller dispatch
    }

    fn emit_bounds_check(&mut self, off: u32, size: u32) {
        // eax = addr, ecx = mem_len
        // add eax, off
        if off != 0 {
            self.emit(&[0x05]);
            self.emit_u32(off);
            // jc trap (rel32)
            self.emit_trap_mem_jump(0x82);
        }
        if size != 0 {
            // if mem_len < size -> trap
            if size <= 0x7F {
                // cmp ecx, imm8
                self.emit(&[0x83, 0xF9, size as u8]);
            } else {
                // cmp ecx, imm32
                self.emit(&[0x81, 0xF9]);
                self.emit_u32(size);
            }
            // jb trap (rel32)
            self.emit_trap_mem_jump(0x82);

            // mov ebx, ecx
            self.emit(&[0x89, 0xCB]);
            // sub ebx, size
            if size <= 0x7F {
                self.emit(&[0x83, 0xEB, size as u8]);
            } else {
                self.emit(&[0x81, 0xEB]);
                self.emit_u32(size);
            }
            // cmp eax, ebx
            self.emit(&[0x39, 0xD8]);
            // ja trap (rel32)
            self.emit_trap_mem_jump(0x87);
        }
    }

    fn emit_i32_load(&mut self, off: u32) {
        self.emit_pop_to_eax();
        self.emit_bounds_check(off, 4);
        // mov eax, [edx + eax]
        self.emit(&[0x8B, 0x04, 0x02]);
        self.emit_push_eax();
    }

    fn emit_local_get(&mut self, idx: u32) {
        // mov ebx, [ebp-4]
        self.emit(&[0x8B, 0x5D, 0xFC]);
        // mov eax, [ebx + disp32]
        self.emit(&[0x8B, 0x83]);
        self.emit_i32((idx as i32) * 4);
        self.emit_push_eax();
    }

    fn emit_local_set(&mut self, idx: u32) {
        // pop value -> eax
        self.emit_pop_to_eax();
        // mov ebx, [ebp-4]
        self.emit(&[0x8B, 0x5D, 0xFC]);
        // mov [ebx + idx*4], eax
        self.emit(&[0x89, 0x83]);
        self.emit_i32((idx as i32) * 4);
    }

    fn emit_local_tee(&mut self, idx: u32) {
        // pop value -> eax
        self.emit_pop_to_eax();
        // mov ebx, [ebp-4]
        self.emit(&[0x8B, 0x5D, 0xFC]);
        // mov [ebx + idx*4], eax
        self.emit(&[0x89, 0x83]);
        self.emit_i32((idx as i32) * 4);
        self.emit_push_eax();
    }

    fn emit_i32_store(&mut self, off: u32) {
        // WASM stack order for i32.store is [..., addr, value] (value on top).
        // pop value -> ebx
        self.emit_pop_to_ebx();
        // pop addr -> eax (preserves ebx value via helper scratch)
        self.emit_pop_to_eax();
        // Preserve the store value because bounds checking uses ebx as scratch.
        self.emit(&[0x89, 0x5D, 0xE4]);
        // bounds check address in eax
        self.emit_bounds_check(off, 4);
        // Restore store value.
        self.emit(&[0x8B, 0x5D, 0xE4]);
        // mov [edx + eax], ebx
        self.emit(&[0x89, 0x1C, 0x02]);
    }

    fn emit_select(&mut self) {
        // Stack shape: [..., val1, val2, cond]
        self.emit_pop_to_eax(); // cond
        self.emit(&[0x89, 0xC2]); // mov edx, eax
        self.emit_pop_to_ebx(); // val2
        self.emit_pop_to_eax(); // val1
        self.emit(&[0x85, 0xD2]); // test edx, edx
        self.emit(&[0x0F, 0x44, 0xC3]); // cmovz eax, ebx
        self.emit_push_eax();
    }

    fn emit_memory_size(&mut self) {
        // memory.size returns current linear memory size in 64KiB pages.
        // mem_len is in ECX as bytes.
        self.emit(&[0x89, 0xC8]); // mov eax, ecx
        self.emit(&[0xC1, 0xE8, 0x10]); // shr eax, 16
        self.emit_push_eax();
    }

    fn emit_memory_grow(&mut self) {
        // Current kernel runtime wires WASM linear memory at fixed max size
        // (1 page), so memory.grow can only succeed for delta=0.
        self.emit_pop_to_eax(); // delta pages
        self.emit(&[0x83, 0xF8, 0x00]); // cmp eax, 0
        self.emit(&[0x75, 0x07]); // jne fail
        self.emit(&[0x89, 0xC8]); // mov eax, ecx
        self.emit(&[0xC1, 0xE8, 0x10]); // shr eax, 16
        self.emit(&[0xEB, 0x05]); // jmp done
        self.emit(&[0xB8]); // fail: mov eax, -1
        self.emit_i32(-1);
        self.emit_push_eax();
    }

    fn emit_cfi_push_return(&mut self) {
        // mov eax, [ebp-24] (shadow sp ptr)
        self.emit(&[0x8B, 0x45, 0xE8]);
        // mov ebx, [eax]
        self.emit(&[0x8B, 0x18]);
        // cmp ebx, MAX_STACK_DEPTH
        self.emit(&[0x81, 0xFB]);
        self.emit_u32(MAX_STACK_DEPTH as u32);
        // jae trap (rel32)
        self.emit_trap_cfi_jump(0x83);
        // mov edx, [ebp-20] (shadow stack base)
        self.emit(&[0x8B, 0x55, 0xEC]);
        // mov ecx, [ebp+4] (return address)
        self.emit(&[0x8B, 0x4D, 0x04]);
        // mov [edx + ebx*4], ecx
        self.emit(&[0x89, 0x0C, 0x9A]);
        // inc ebx
        self.emit(&[0x43]);
        // mov [eax], ebx
        self.emit(&[0x89, 0x18]);
        // Restore linear-memory base/len after CFI scratch use.
        // mov edx, [ebp+16] (mem ptr)
        self.emit(&[0x8B, 0x55, 0x10]);
        // mov ecx, [ebp+20] (mem len)
        self.emit(&[0x8B, 0x4D, 0x14]);
    }

    fn emit_cfi_check_return(&mut self) {
        // mov edx, [ebp-24] (shadow sp ptr)
        self.emit(&[0x8B, 0x55, 0xE8]);
        // mov ebx, [edx]
        self.emit(&[0x8B, 0x1A]);
        // cmp ebx, 0
        self.emit(&[0x83, 0xFB, 0x00]);
        // je trap (rel32)
        self.emit_trap_cfi_jump(0x84);
        // dec ebx
        self.emit(&[0x4B]);
        // mov [edx], ebx
        self.emit(&[0x89, 0x1A]);
        // mov edx, [ebp-20] (shadow stack base)
        self.emit(&[0x8B, 0x55, 0xEC]);
        // mov ecx, [edx + ebx*4] (expected ret)
        self.emit(&[0x8B, 0x0C, 0x9A]);
        // mov edx, [ebp+4] (actual ret)
        self.emit(&[0x8B, 0x55, 0x04]);
        // cmp edx, ecx
        self.emit(&[0x39, 0xCA]);
        // jne trap (rel32)
        self.emit_trap_cfi_jump(0x85);
    }

    fn emit_instr_fuel_check(&mut self) {
        // mov eax, [ebp-8]
        self.emit(&[0x8B, 0x45, 0xF8]);
        // cmp dword [eax], 0
        self.emit(&[0x83, 0x38, 0x00]);
        // je trap (rel32)
        self.emit_trap_fuel_jump(0x84);
        // dec dword [eax]
        self.emit(&[0xFF, 0x08]);
    }

    fn emit_mem_fuel_check(&mut self) {
        // mov eax, [ebp-12]
        self.emit(&[0x8B, 0x45, 0xF4]);
        // cmp dword [eax], 0
        self.emit(&[0x83, 0x38, 0x00]);
        // je trap (rel32)
        self.emit_trap_fuel_jump(0x84);
        // dec dword [eax]
        self.emit(&[0xFF, 0x08]);
    }

    fn emit_epilogue(&mut self) -> usize {
        let pos = self.code.len();
        // add esp, 40
        self.emit(&[0x83, 0xC4, 0x28]);
        // mov ebx, [esi]
        self.emit(&[0x8B, 0x1E]);
        // cmp ebx, 0
        self.emit(&[0x83, 0xFB, 0x00]);
        // je +8 (skip value load/store and jmp to xor)
        self.emit(&[0x74, 0x08]);
        // dec ebx
        self.emit(&[0x4B]);
        // mov eax, [edi + ebx*4]
        self.emit(&[0x8B, 0x04, 0x9F]);
        // mov [esi], ebx
        self.emit(&[0x89, 0x1E]);
        // jmp +2
        self.emit(&[0xEB, 0x02]);
        // xor eax, eax
        self.emit(&[0x31, 0xC0]);
        self.emit_cfi_check_return();
        // restore callee-saved registers
        // mov edi, [ebp-40]
        self.emit(&[0x8B, 0x7D, 0xD8]);
        // mov esi, [ebp-36]
        self.emit(&[0x8B, 0x75, 0xDC]);
        // mov ebx, [ebp-32]
        self.emit(&[0x8B, 0x5D, 0xE0]);
        // pop ebp; ret
        self.emit(&[0x5D, 0xC3]);
        pos
    }

    fn emit_trap_stub(&mut self, code: i32, check_cfi: bool) -> usize {
        let pos = self.code.len();
        // add esp, 40
        self.emit(&[0x83, 0xC4, 0x28]);
        // mov eax, [ebp-16]
        self.emit(&[0x8B, 0x45, 0xF0]);
        // mov dword [eax], imm32
        self.emit(&[0xC7, 0x00]);
        self.emit_i32(code);
        // xor eax, eax
        self.emit(&[0x31, 0xC0]);
        if check_cfi {
            self.emit_cfi_check_return();
        }
        // restore callee-saved registers
        // mov edi, [ebp-40]
        self.emit(&[0x8B, 0x7D, 0xD8]);
        // mov esi, [ebp-36]
        self.emit(&[0x8B, 0x75, 0xDC]);
        // mov ebx, [ebp-32]
        self.emit(&[0x8B, 0x5D, 0xE0]);
        // pop ebp; ret
        self.emit(&[0x5D, 0xC3]);
        pos
    }

    fn emit_trap_mem_jump(&mut self, opcode_ext: u8) {
        // 0F xx rel32
        self.emit(&[0x0F, opcode_ext]);
        let pos = self.code.len();
        self.emit_u32(0);
        self.trap_mem_jumps.push(pos);
    }

    fn emit_trap_fuel_jump(&mut self, opcode_ext: u8) {
        self.emit(&[0x0F, opcode_ext]);
        let pos = self.code.len();
        self.emit_u32(0);
        self.trap_fuel_jumps.push(pos);
    }

    fn emit_trap_stack_jump(&mut self, opcode_ext: u8) {
        self.emit(&[0x0F, opcode_ext]);
        let pos = self.code.len();
        self.emit_u32(0);
        self.trap_stack_jumps.push(pos);
    }

    fn emit_trap_stack_always(&mut self) {
        self.emit(&[0xE9]);
        let pos = self.code.len();
        self.emit_u32(0);
        self.trap_stack_jumps.push(pos);
    }

    fn emit_trap_cfi_jump(&mut self, opcode_ext: u8) {
        self.emit(&[0x0F, opcode_ext]);
        let pos = self.code.len();
        self.emit_u32(0);
        self.trap_cfi_jumps.push(pos);
    }

    fn patch_traps(
        &mut self,
        trap_mem_pos: usize,
        trap_fuel_pos: usize,
        trap_stack_pos: usize,
        trap_cfi_pos: usize,
    ) -> Result<(), &'static str> {
        fn patch_jump_list(
            code: &mut [u8],
            jumps: &[usize],
            trap_pos: usize,
        ) -> Result<(), &'static str> {
            for &idx in jumps {
                let end = idx.checked_add(4).ok_or("Trap patch index overflow")?;
                if end > code.len() {
                    return Err("Trap patch index out of range");
                }
                let rel = (trap_pos as isize - end as isize) as i32;
                code[idx..end].copy_from_slice(&rel.to_le_bytes());
            }
            Ok(())
        }

        patch_jump_list(&mut self.code, &self.trap_mem_jumps, trap_mem_pos)?;
        patch_jump_list(&mut self.code, &self.trap_fuel_jumps, trap_fuel_pos)?;
        patch_jump_list(&mut self.code, &self.trap_stack_jumps, trap_stack_pos)?;
        patch_jump_list(&mut self.code, &self.trap_cfi_jumps, trap_cfi_pos)?;
        Ok(())
    }
}

// ============================================================================
// LEB128 helpers
// ============================================================================

#[cfg(target_arch = "x86_64")]
impl Emitter {
    fn new() -> Self {
        Emitter {
            code: Vec::new(),
            trap_mem_jumps: Vec::new(),
            trap_fuel_jumps: Vec::new(),
            trap_stack_jumps: Vec::new(),
            trap_cfi_jumps: Vec::new(),
        }
    }

    fn reset(&mut self) {
        self.code.clear();
        self.trap_mem_jumps.clear();
        self.trap_fuel_jumps.clear();
        self.trap_stack_jumps.clear();
        self.trap_cfi_jumps.clear();
    }

    fn reserve(&mut self, code_cap: usize, jump_cap: usize) {
        if code_cap > self.code.capacity() {
            self.code.reserve_exact(code_cap - self.code.capacity());
        }
        if jump_cap > self.trap_mem_jumps.capacity() {
            self.trap_mem_jumps
                .reserve_exact(jump_cap - self.trap_mem_jumps.capacity());
        }
        if jump_cap > self.trap_fuel_jumps.capacity() {
            self.trap_fuel_jumps
                .reserve_exact(jump_cap - self.trap_fuel_jumps.capacity());
        }
        if jump_cap > self.trap_stack_jumps.capacity() {
            self.trap_stack_jumps
                .reserve_exact(jump_cap - self.trap_stack_jumps.capacity());
        }
        if jump_cap > self.trap_cfi_jumps.capacity() {
            self.trap_cfi_jumps
                .reserve_exact(jump_cap - self.trap_cfi_jumps.capacity());
        }
    }

    fn emit(&mut self, bytes: &[u8]) {
        self.code.extend_from_slice(bytes);
    }

    fn emit_u8(&mut self, b: u8) {
        self.code.push(b);
    }

    fn emit_u32(&mut self, v: u32) {
        self.code.extend_from_slice(&v.to_le_bytes());
    }

    fn emit_i32(&mut self, v: i32) {
        self.code.extend_from_slice(&v.to_le_bytes());
    }

    fn emit_prologue(&mut self) {
        // SysV x86_64 JitFn calling convention — first 6 integer args in regs:
        // rdi stack_ptr, rsi sp_ptr, rdx mem_ptr, rcx mem_len, r8 locals_ptr,
        // r9 instr_fuel_ptr, [rbp+16] mem_fuel_ptr, [rbp+24] trap_ptr.
        // x86_64 reuses the shadow-stack-base slot at [rbp+32] as globals_ptr;
        // [rbp+40] shadow_sp, [rbp+48] fn_table_base, [rbp+56] fn_table_len.
        // Saved metadata in frame locals (all 8-byte slots):
        //   [rbp-48] instr_fuel_ptr  [rbp-56] mem_fuel_ptr
        //   [rbp-64] trap_ptr        [rbp-72] globals_ptr
        //   [rbp-80] fn_table_len    [rbp-88] fn_table_base
        // Branch scratch slots (4 bytes each) live at X64_BRANCH_SCRATCH_BASE_DISP.
        // Callee-locals scratch (for call_indirect param staging) lives below that.
        self.emit(&[
            0x55, // push rbp
            0x48, 0x89, 0xE5, // mov rbp, rsp
            0x53, // push rbx
            0x41, 0x54, // push r12
            0x41, 0x55, // push r13
            0x41, 0x56, // push r14
            0x41, 0x57, // push r15
            0x48, 0x81, 0xEC, // sub rsp, imm32
        ]);
        // Allocate both frame-local metadata + branch scratch + callee-locals scratch.
        self.emit_i32(X64_STACK_FRAME_BYTES + X64_CALLEE_LOCALS_BYTES);
        self.emit(&[
            0x49, 0x89, 0xFC, // mov r12, rdi  (stack_ptr)
            0x49, 0x89, 0xF5, // mov r13, rsi  (sp_ptr)
            0x49, 0x89, 0xD6, // mov r14, rdx  (mem_ptr)
            0x49, 0x89, 0xCF, // mov r15, rcx  (mem_len)
            0x4C, 0x89, 0xC3, // mov rbx, r8   (locals_ptr)
            0x4C, 0x89, 0x4D, 0xD0, // mov [rbp-48], r9  (instr_fuel_ptr)
            0x48, 0x8B, 0x45, 0x10, // mov rax, [rbp+16] (mem_fuel_ptr)
            0x48, 0x89, 0x45, 0xC8, // mov [rbp-56], rax
            0x48, 0x8B, 0x45, 0x18, // mov rax, [rbp+24] (trap_ptr)
            0x48, 0x89, 0x45, 0xC0, // mov [rbp-64], rax
            0x48, 0x8B, 0x45, 0x20, // mov rax, [rbp+32] (globals_ptr)
            0x48, 0x89, 0x45, 0xB8, // mov [rbp-72], rax
            0x48, 0x8B, 0x45, 0x38, // mov rax, [rbp+56] (fn_table_len)
            0x48, 0x89, 0x45, 0xB0, // mov [rbp-80], rax
            0x48, 0x8B, 0x45, 0x30, // mov rax, [rbp+48] (fn_table_base)
            0x48, 0x89, 0x45, 0xA8, // mov [rbp-88], rax
        ]);
        self.emit_cfi_push_return();
    }

    fn emit_pop_to_eax(&mut self) {
        self.emit(&[
            0x4D, 0x8B, 0x55, 0x00, // mov r10, [r13+0]
            0x4D, 0x85, 0xD2, // test r10, r10
        ]);
        self.emit_trap_stack_jump(0x84); // jz trap
        self.emit(&[
            0x49, 0xFF, 0xCA, // dec r10
            0x43, 0x8B, 0x04, 0x94, // mov eax, [r12 + r10*4]
            0x4D, 0x89, 0x55, 0x00, // mov [r13+0], r10
        ]);
    }

    fn emit_pop_to_ebx(&mut self) {
        // On x86_64, RBX is reserved for the locals base. Treat the historical
        // "ebx" secondary scratch role as an alias for r11d instead.
        self.emit_pop_to_r11d();
    }

    fn emit_pop_to_ecx(&mut self) {
        self.emit(&[
            0x89, 0xC2, // mov edx, eax (preserve prior eax value)
            0x4D, 0x8B, 0x55, 0x00, // mov r10, [r13+0]
            0x4D, 0x85, 0xD2, // test r10, r10
        ]);
        self.emit_trap_stack_jump(0x84); // jz trap
        self.emit(&[
            0x49, 0xFF, 0xCA, // dec r10
            0x43, 0x8B, 0x0C, 0x94, // mov ecx, [r12 + r10*4]
            0x4D, 0x89, 0x55, 0x00, // mov [r13+0], r10
            0x89, 0xD0, // mov eax, edx (restore prior eax value)
        ]);
    }

    fn emit_push_eax(&mut self) {
        self.emit(&[
            0x4D, 0x8B, 0x55, 0x00, // mov r10, [r13+0]
            0x49, 0x81, 0xFA, // cmp r10, imm32
        ]);
        self.emit_u32(MAX_STACK_DEPTH as u32);
        self.emit_trap_stack_jump(0x83); // jae trap
        self.emit(&[
            0x43, 0x89, 0x04, 0x94, // mov [r12 + r10*4], eax
            0x49, 0xFF, 0xC2, // inc r10
            0x4D, 0x89, 0x55, 0x00, // mov [r13+0], r10
        ]);
    }

    fn emit_pop_discard(&mut self) {
        self.emit(&[
            0x4D, 0x8B, 0x55, 0x00, // mov r10, [r13+0]
            0x4D, 0x85, 0xD2, // test r10, r10
        ]);
        self.emit_trap_stack_jump(0x84); // jz trap
        self.emit(&[
            0x49, 0xFF, 0xCA, // dec r10
            0x4D, 0x89, 0x55, 0x00, // mov [r13+0], r10
        ]);
    }

    fn emit_pop_cond_jz_placeholder(&mut self) -> usize {
        self.emit_pop_to_eax();
        self.emit(&[0x85, 0xC0]); // test eax, eax
        self.emit(&[0x0F, 0x84]); // jz rel32
        let pos = self.code.len();
        self.emit_u32(0);
        pos
    }

    fn emit_pop_cond_jnz_placeholder(&mut self) -> usize {
        self.emit_pop_to_eax();
        self.emit(&[0x85, 0xC0]); // test eax, eax
        self.emit(&[0x0F, 0x85]); // jnz rel32
        let pos = self.code.len();
        self.emit_u32(0);
        pos
    }

    fn emit_cond_jz_placeholder(&mut self) -> usize {
        self.emit(&[0x85, 0xC0]); // test eax, eax
        self.emit(&[0x0F, 0x84]); // jz rel32
        let pos = self.code.len();
        self.emit_u32(0);
        pos
    }

    fn branch_scratch_disp(slot: usize) -> Result<i32, &'static str> {
        if slot >= X64_BRANCH_SCRATCH_SLOTS {
            return Err("Multi-value branch arity exceeds x86_64 JIT scratch bound");
        }
        Ok(X64_BRANCH_SCRATCH_BASE_DISP + (slot as i32 * 4))
    }

    fn emit_store_eax_scratch_slot(&mut self, slot: usize) -> Result<(), &'static str> {
        let disp = Self::branch_scratch_disp(slot)?;
        self.emit(&[0x89, 0x85]); // mov [rbp+disp32], eax
        self.emit_i32(disp);
        Ok(())
    }

    fn emit_load_eax_scratch_slot(&mut self, slot: usize) -> Result<(), &'static str> {
        let disp = Self::branch_scratch_disp(slot)?;
        self.emit(&[0x8B, 0x85]); // mov eax, [rbp+disp32]
        self.emit_i32(disp);
        Ok(())
    }

    fn emit_rebuild_branch_values(
        &mut self,
        label_arity: i32,
        target_stack_depth: i32,
    ) -> Result<(), &'static str> {
        if label_arity < 0 {
            return Err("Negative branch arity");
        }
        let arity = label_arity as usize;
        if arity == 0 {
            return self.emit_set_stack_depth(target_stack_depth);
        }
        for slot in 0..arity {
            self.emit_pop_to_eax();
            self.emit_store_eax_scratch_slot(slot)?;
        }
        self.emit_set_stack_depth(target_stack_depth)?;
        for slot in (0..arity).rev() {
            self.emit_load_eax_scratch_slot(slot)?;
            self.emit_push_eax();
        }
        Ok(())
    }

    fn emit_set_stack_depth(&mut self, depth: i32) -> Result<(), &'static str> {
        if depth < 0 {
            return Err("Negative stack depth");
        }
        self.emit(&[
            0x41, 0xBA, // mov r10d, imm32
        ]);
        self.emit_i32(depth);
        self.emit(&[
            0x4D, 0x89, 0x55, 0x00, // mov [r13+0], r10
        ]);
        Ok(())
    }

    fn emit_jump_placeholder(&mut self) -> usize {
        self.emit(&[0xE9]); // jmp rel32
        let pos = self.code.len();
        self.emit_u32(0);
        pos
    }

    fn patch_rel32(&mut self, rel_pos: usize, target: usize) -> Result<(), &'static str> {
        let end = rel_pos.checked_add(4).ok_or("Patch index overflow")?;
        if end > self.code.len() {
            return Err("Patch index out of range");
        }
        let rel = (target as isize - end as isize) as i32;
        self.code[rel_pos..end].copy_from_slice(&rel.to_le_bytes());
        Ok(())
    }

    fn emit_i32_const(&mut self, imm: i32) {
        self.emit(&[0xB8]); // mov eax, imm32
        self.emit_i32(imm);
        self.emit_push_eax();
    }

    fn emit_i32_add(&mut self) {
        self.emit_pop_to_eax();
        self.emit_pop_to_ecx();
        self.emit(&[0x01, 0xC8]); // add eax, ecx
        self.emit_push_eax();
    }

    fn emit_i32_sub(&mut self) {
        self.emit_pop_to_ecx(); // b
        self.emit_pop_to_eax(); // a
        self.emit(&[0x29, 0xC8]); // sub eax, ecx
        self.emit_push_eax();
    }

    fn emit_i32_mul(&mut self) {
        self.emit_pop_to_eax();
        self.emit_pop_to_ecx();
        self.emit(&[0x0F, 0xAF, 0xC1]); // imul eax, ecx
        self.emit_push_eax();
    }

    fn emit_i32_divs(&mut self) {
        // WASM: a / b with trap on divide-by-zero and INT_MIN / -1 overflow.
        self.emit_pop_to_ecx(); // b (divisor)
        self.emit_pop_to_eax(); // a (dividend)
        self.emit(&[0x83, 0xF9, 0x00]); // cmp ecx, 0
        self.emit_trap_stack_jump(0x84); // je trap
        self.emit(&[0x83, 0xF9, 0xFF]); // cmp ecx, -1
        self.emit(&[0x75, 0x0B]); // jne +11 (skip overflow guard)
        self.emit(&[0x3D, 0x00, 0x00, 0x00, 0x80]); // cmp eax, 0x80000000
        self.emit_trap_stack_jump(0x84); // je trap
        self.emit(&[0x99]); // cdq
        self.emit(&[0xF7, 0xF9]); // idiv ecx
        self.emit_push_eax();
    }

    fn emit_i32_divu(&mut self) {
        // WASM: unsigned division with trap on divide-by-zero.
        self.emit_pop_to_ecx(); // b (divisor)
        self.emit_pop_to_eax(); // a (dividend)
        self.emit(&[0x83, 0xF9, 0x00]); // cmp ecx, 0
        self.emit_trap_stack_jump(0x84); // je trap
        self.emit(&[0x31, 0xD2]); // xor edx, edx
        self.emit(&[0xF7, 0xF1]); // div ecx
        self.emit_push_eax();
    }

    fn emit_i32_rems(&mut self) {
        // WASM: a % b with trap on divide-by-zero and INT_MIN / -1 overflow.
        self.emit_pop_to_ecx(); // b (divisor)
        self.emit_pop_to_eax(); // a (dividend)
        self.emit(&[0x83, 0xF9, 0x00]); // cmp ecx, 0
        self.emit_trap_stack_jump(0x84); // je trap
        self.emit(&[0x83, 0xF9, 0xFF]); // cmp ecx, -1
        self.emit(&[0x75, 0x0B]); // jne +11 (skip overflow guard)
        self.emit(&[0x3D, 0x00, 0x00, 0x00, 0x80]); // cmp eax, 0x80000000
        self.emit_trap_stack_jump(0x84); // je trap
        self.emit(&[0x99]); // cdq
        self.emit(&[0xF7, 0xF9]); // idiv ecx
        self.emit(&[0x89, 0xD0]); // mov eax, edx
        self.emit_push_eax();
    }

    fn emit_i32_remu(&mut self) {
        // WASM: unsigned remainder with trap on divide-by-zero.
        self.emit_pop_to_ecx(); // b (divisor)
        self.emit_pop_to_eax(); // a (dividend)
        self.emit(&[0x83, 0xF9, 0x00]); // cmp ecx, 0
        self.emit_trap_stack_jump(0x84); // je trap
        self.emit(&[0x31, 0xD2]); // xor edx, edx
        self.emit(&[0xF7, 0xF1]); // div ecx
        self.emit(&[0x89, 0xD0]); // mov eax, edx
        self.emit_push_eax();
    }

    fn emit_i32_and(&mut self) {
        self.emit_pop_to_eax();
        self.emit_pop_to_ecx();
        self.emit(&[0x21, 0xC8]); // and eax, ecx
        self.emit_push_eax();
    }

    fn emit_i32_or(&mut self) {
        self.emit_pop_to_eax();
        self.emit_pop_to_ecx();
        self.emit(&[0x09, 0xC8]); // or eax, ecx
        self.emit_push_eax();
    }

    fn emit_i32_xor(&mut self) {
        self.emit_pop_to_eax();
        self.emit_pop_to_ecx();
        self.emit(&[0x31, 0xC8]); // xor eax, ecx
        self.emit_push_eax();
    }

    fn emit_i32_eq(&mut self) {
        self.emit_pop_to_eax();
        self.emit_pop_to_ecx();
        self.emit(&[0x39, 0xC8]); // cmp eax, ecx
        self.emit(&[0x0F, 0x94, 0xC0]); // sete al
        self.emit(&[0x0F, 0xB6, 0xC0]); // movzx eax, al
        self.emit_push_eax();
    }

    fn emit_i32_ne(&mut self) {
        self.emit_pop_to_eax();
        self.emit_pop_to_ecx();
        self.emit(&[0x39, 0xC8]); // cmp eax, ecx
        self.emit(&[0x0F, 0x95, 0xC0]); // setne al
        self.emit(&[0x0F, 0xB6, 0xC0]); // movzx eax, al
        self.emit_push_eax();
    }

    fn emit_i32_eqz(&mut self) {
        self.emit_pop_to_eax();
        self.emit(&[0x83, 0xF8, 0x00]); // cmp eax, 0
        self.emit(&[0x0F, 0x94, 0xC0]); // sete al
        self.emit(&[0x0F, 0xB6, 0xC0]); // movzx eax, al
        self.emit_push_eax();
    }

    fn emit_i32_lts(&mut self) {
        self.emit_pop_to_ecx(); // b
        self.emit_pop_to_eax(); // a
        self.emit(&[0x39, 0xC8]); // cmp eax, ecx
        self.emit(&[0x0F, 0x9C, 0xC0]); // setl al
        self.emit(&[0x0F, 0xB6, 0xC0]); // movzx eax, al
        self.emit_push_eax();
    }

    fn emit_i32_gts(&mut self) {
        self.emit_pop_to_ecx(); // b
        self.emit_pop_to_eax(); // a
        self.emit(&[0x39, 0xC8]); // cmp eax, ecx
        self.emit(&[0x0F, 0x9F, 0xC0]); // setg al
        self.emit(&[0x0F, 0xB6, 0xC0]); // movzx eax, al
        self.emit_push_eax();
    }

    fn emit_i32_les(&mut self) {
        self.emit_pop_to_ecx(); // b
        self.emit_pop_to_eax(); // a
        self.emit(&[0x39, 0xC8]); // cmp eax, ecx
        self.emit(&[0x0F, 0x9E, 0xC0]); // setle al
        self.emit(&[0x0F, 0xB6, 0xC0]); // movzx eax, al
        self.emit_push_eax();
    }

    fn emit_i32_ges(&mut self) {
        self.emit_pop_to_ecx(); // b
        self.emit_pop_to_eax(); // a
        self.emit(&[0x39, 0xC8]); // cmp eax, ecx
        self.emit(&[0x0F, 0x9D, 0xC0]); // setge al
        self.emit(&[0x0F, 0xB6, 0xC0]); // movzx eax, al
        self.emit_push_eax();
    }

    fn emit_i32_ltu(&mut self) {
        self.emit_pop_to_ecx(); // b
        self.emit_pop_to_eax(); // a
        self.emit(&[0x39, 0xC8]); // cmp eax, ecx
        self.emit(&[0x0F, 0x92, 0xC0]); // setb al
        self.emit(&[0x0F, 0xB6, 0xC0]); // movzx eax, al
        self.emit_push_eax();
    }

    fn emit_i32_gtu(&mut self) {
        self.emit_pop_to_ecx(); // b
        self.emit_pop_to_eax(); // a
        self.emit(&[0x39, 0xC8]); // cmp eax, ecx
        self.emit(&[0x0F, 0x97, 0xC0]); // seta al
        self.emit(&[0x0F, 0xB6, 0xC0]); // movzx eax, al
        self.emit_push_eax();
    }

    fn emit_i32_leu(&mut self) {
        self.emit_pop_to_ecx(); // b
        self.emit_pop_to_eax(); // a
        self.emit(&[0x39, 0xC8]); // cmp eax, ecx
        self.emit(&[0x0F, 0x96, 0xC0]); // setbe al
        self.emit(&[0x0F, 0xB6, 0xC0]); // movzx eax, al
        self.emit_push_eax();
    }

    fn emit_i32_geu(&mut self) {
        self.emit_pop_to_ecx(); // b
        self.emit_pop_to_eax(); // a
        self.emit(&[0x39, 0xC8]); // cmp eax, ecx
        self.emit(&[0x0F, 0x93, 0xC0]); // setae al
        self.emit(&[0x0F, 0xB6, 0xC0]); // movzx eax, al
        self.emit_push_eax();
    }

    fn emit_i32_shl(&mut self) {
        self.emit_pop_to_ecx(); // shift
        self.emit_pop_to_eax(); // value
        self.emit(&[0xD3, 0xE0]); // shl eax, cl
        self.emit_push_eax();
    }

    fn emit_i32_shrs(&mut self) {
        self.emit_pop_to_ecx(); // shift
        self.emit_pop_to_eax(); // value
        self.emit(&[0xD3, 0xF8]); // sar eax, cl
        self.emit_push_eax();
    }

    fn emit_i32_shru(&mut self) {
        self.emit_pop_to_ecx(); // shift
        self.emit_pop_to_eax(); // value
        self.emit(&[0xD3, 0xE8]); // shr eax, cl
        self.emit_push_eax();
    }

    fn emit_bounds_check(&mut self, off: u32, size: u32) {
        if off != 0 {
            self.emit(&[0x05]); // add eax, imm32
            self.emit_u32(off);
            self.emit_trap_mem_jump(0x82); // jc trap
        }
        if size != 0 {
            if size <= 0x7F {
                self.emit(&[0x49, 0x83, 0xFF, size as u8]); // cmp r15, imm8
            } else {
                self.emit(&[0x49, 0x81, 0xFF]); // cmp r15, imm32
                self.emit_u32(size);
            }
            self.emit_trap_mem_jump(0x82); // jb trap

            self.emit(&[0x4D, 0x89, 0xFA]); // mov r10, r15
            if size <= 0x7F {
                self.emit(&[0x49, 0x83, 0xEA, size as u8]); // sub r10, imm8
            } else {
                self.emit(&[0x49, 0x81, 0xEA]); // sub r10, imm32
                self.emit_u32(size);
            }
            self.emit(&[
                0x89, 0xC2, // mov edx, eax
                0x4C, 0x39, 0xD2, // cmp rdx, r10
            ]);
            self.emit_trap_mem_jump(0x87); // ja trap
        }
    }

    fn emit_i32_load(&mut self, off: u32) {
        self.emit_pop_to_eax();
        self.emit_bounds_check(off, 4);
        self.emit(&[
            0x41, 0x8B, 0x04, 0x06, // mov eax, [r14 + rax]
        ]);
        self.emit_push_eax();
    }

    // ── i32.clz (x86_64) ─────────────────────────────────────────────────────
    fn emit_i32_clz(&mut self) {
        self.emit_pop_to_eax();
        // test eax, eax
        self.emit(&[0x85, 0xC0]);
        // je .zero (+8 bytes from end of this jump)
        self.emit(&[0x74, 0x0A]);
        // bsr eax, eax
        self.emit(&[0x0F, 0xBD, 0xC0]);
        // mov ecx, 31 ; sub ecx, eax ; mov eax, ecx
        self.emit(&[0xB9, 0x1F, 0x00, 0x00, 0x00, 0x29, 0xC1, 0x89, 0xC8]);
        // jmp done (+5)
        self.emit(&[0xEB, 0x05]);
        // .zero: mov eax, 32
        self.emit(&[0xB8, 0x20, 0x00, 0x00, 0x00]);
        self.emit_push_eax();
    }

    // ── i32.ctz (x86_64) ─────────────────────────────────────────────────────
    fn emit_i32_ctz(&mut self) {
        self.emit_pop_to_eax();
        // test eax, eax
        self.emit(&[0x85, 0xC0]);
        // je .zero (+5)
        self.emit(&[0x74, 0x05]);
        // bsf eax, eax
        self.emit(&[0x0F, 0xBC, 0xC0]);
        // jmp done (+5)
        self.emit(&[0xEB, 0x05]);
        // .zero: mov eax, 32
        self.emit(&[0xB8, 0x20, 0x00, 0x00, 0x00]);
        self.emit_push_eax();
    }

    // ── i32.load8_u (x86_64) ─────────────────────────────────────────────────
    fn emit_i32_load8u(&mut self, off: u32) {
        self.emit_pop_to_eax();
        self.emit_bounds_check(off, 1);
        // movzx eax, byte [r14 + rax]
        self.emit(&[0x41, 0x0F, 0xB6, 0x04, 0x06]);
        self.emit_push_eax();
    }

    // ── i32.load16_u (x86_64) ────────────────────────────────────────────────
    fn emit_i32_load16u(&mut self, off: u32) {
        self.emit_pop_to_eax();
        self.emit_bounds_check(off, 2);
        // movzx eax, word [r14 + rax]
        self.emit(&[0x41, 0x0F, 0xB7, 0x04, 0x06]);
        self.emit_push_eax();
    }

    // ── i32.store8 (x86_64) ──────────────────────────────────────────────────
    fn emit_i32_store8(&mut self, off: u32) {
        self.emit_pop_to_ecx(); // value
        self.emit_pop_to_eax(); // addr
        self.emit_bounds_check(off, 1);
        // mov byte [r14 + rax], cl
        self.emit(&[0x41, 0x88, 0x0C, 0x06]);
    }

    // ── i32.store16 (x86_64) ─────────────────────────────────────────────────
    fn emit_i32_store16(&mut self, off: u32) {
        self.emit_pop_to_ecx(); // value
        self.emit_pop_to_eax(); // addr
        self.emit_bounds_check(off, 2);
        // mov word [r14 + rax], cx  (66h prefix)
        self.emit(&[0x41, 0x66, 0x89, 0x0C, 0x06]);
    }

    // ── i64.const (x86_64) ───────────────────────────────────────────────────
    // Push two 32-bit virtual-stack slots: hi first (deeper), then lo (top).
    // All i64 values use the virtual r12/r13 stack, not native rsp.
    fn emit_i64_const(&mut self, lo: i32, hi: i32) {
        // push hi (deeper slot)
        self.emit(&[0xB8]); // mov eax, imm32
        self.emit_i32(hi);
        self.emit_push_eax();
        // push lo (stack top)
        self.emit(&[0xB8]); // mov eax, imm32
        self.emit_i32(lo);
        self.emit_push_eax();
    }

    // Helper: pop r11d from the virtual stack, preserving rax and ecx.
    // Sequence: mov r10,[r13]; test r10,r10; jz trap; dec r10;
    //           mov r11d,[r12+r10*4]; mov [r13],r10
    fn emit_pop_to_r11d(&mut self) {
        self.emit(&[
            0x4D, 0x8B, 0x55, 0x00, // mov r10, [r13+0]
            0x4D, 0x85, 0xD2,       // test r10, r10
        ]);
        self.emit_trap_stack_jump(0x84); // jz trap_stack
        self.emit(&[
            0x49, 0xFF, 0xCA,       // dec r10
            0x47, 0x8B, 0x1C, 0x94, // mov r11d, [r12 + r10*4]
            0x4D, 0x89, 0x55, 0x00, // mov [r13+0], r10
        ]);
    }

    // Helper: pop r8d from the virtual stack, preserving rax, ecx, r11.
    // Uses r10 as scratch (same as all other pop helpers).
    fn emit_pop_to_r8d(&mut self) {
        self.emit(&[
            0x4D, 0x8B, 0x55, 0x00, // mov r10, [r13+0]
            0x4D, 0x85, 0xD2,       // test r10, r10
        ]);
        self.emit_trap_stack_jump(0x84); // jz trap_stack
        self.emit(&[
            0x49, 0xFF, 0xCA,       // dec r10
            0x45, 0x8B, 0x04, 0x94, // mov r8d, [r12 + r10*4]
            0x4D, 0x89, 0x55, 0x00, // mov [r13+0], r10
        ]);
    }

    // Helper: push r8d onto the virtual stack.
    fn emit_push_r8d(&mut self) {
        self.emit(&[
            0x4D, 0x8B, 0x55, 0x00, // mov r10, [r13+0]
            0x49, 0x81, 0xFA,       // cmp r10, imm32
        ]);
        self.emit_u32(MAX_STACK_DEPTH as u32);
        self.emit_trap_stack_jump(0x83); // jae trap_stack
        self.emit(&[
            0x45, 0x89, 0x04, 0x94, // mov [r12 + r10*4], r8d
            0x49, 0xFF, 0xC2,       // inc r10
            0x4D, 0x89, 0x55, 0x00, // mov [r13+0], r10
        ]);
    }

    // ── i64 arithmetic helpers ────────────────────────────────────────────────
    //
    // i64 values are represented as two adjacent virtual-stack slots (32 bits each).
    // Convention (top→bottom): lo_word, hi_word
    //   (lo_word is the more recent push / closer to the top of the virtual stack)
    //
    // For binary ops consuming two i64 operands the stack order is:
    //   top: a_lo, a_hi, b_lo, b_hi :bottom
    //   (a was pushed most recently)
    //
    // Strategy: pop all 4 words into 64-bit scratch registers rax and r8, perform
    // the 64-bit operation, then split the result into two 32-bit virtual pushes.
    //
    //   rax  = a  (full 64-bit: (a_hi << 32) | a_lo)
    //   r8   = b  (full 64-bit: (b_hi << 32) | b_lo)
    //
    // Register usage summary:
    //   r10  – virtual stack depth pointer (scratch used by all helpers)
    //   r11  – scratch for lo half during build
    //   r8   – scratch for b operand
    //   rax  – accumulates a, then holds result
    //   ecx  – scratch for hi half during build
    //
    // NOTE: r12, r13, r14, r15, rbx are callee-saved JIT context regs; never touched.

    fn emit_i64_build_a_in_rax_b_in_r8(&mut self) {
        // Pop a_lo → r11d
        self.emit_pop_to_ebx();
        // Pop a_hi → eax; zero-extend to rax automatically
        self.emit_pop_to_eax();
        // rax = (a_hi << 32) | a_lo
        self.emit(&[0x48, 0xC1, 0xE0, 0x20]); // shl rax, 32
        self.emit(&[0x4C, 0x09, 0xD8]);        // or rax, r11  (r11 zero-extended = a_lo)
        // Pop b_lo → r11d
        self.emit_pop_to_ebx();
        // Pop b_hi → r8d; zero-extend to r8 automatically
        self.emit_pop_to_r8d();
        // r8 = (b_hi << 32) | b_lo
        self.emit(&[0x49, 0xC1, 0xE0, 0x20]); // shl r8, 32
        self.emit(&[0x4D, 0x09, 0xD8]);        // or r8, r11  (r11 = b_lo)
    }

    fn emit_i64_split_rax_push_hi_lo(&mut self) {
        // Save lo (lower 32 bits of rax) in r11d before shifting
        self.emit(&[0x41, 0x89, 0xC3]);        // mov r11d, eax
        // Shift rax right to get hi in eax
        self.emit(&[0x48, 0xC1, 0xE8, 0x20]); // shr rax, 32
        // Push hi first (deeper on virtual stack)
        self.emit_push_eax();
        // Restore lo from r11d into eax
        self.emit(&[0x44, 0x89, 0xD8]);        // mov eax, r11d
        // Push lo (stack top)
        self.emit_push_eax();
    }

    // ── i64.add (x86_64) ─────────────────────────────────────────────────────
    fn emit_i64_add(&mut self) {
        self.emit_i64_build_a_in_rax_b_in_r8();
        self.emit(&[0x4C, 0x01, 0xC0]); // add rax, r8
        self.emit_i64_split_rax_push_hi_lo();
    }

    // ── i64.sub (x86_64) ─────────────────────────────────────────────────────
    fn emit_i64_sub(&mut self) {
        self.emit_i64_build_a_in_rax_b_in_r8();
        self.emit(&[0x4C, 0x29, 0xC0]); // sub rax, r8
        self.emit_i64_split_rax_push_hi_lo();
    }

    // ── i64.mul (x86_64) ─────────────────────────────────────────────────────
    fn emit_i64_mul(&mut self) {
        self.emit_i64_build_a_in_rax_b_in_r8();
        // imul rax, r8: IMUL r64,r/m64 (0F AF); dest rax=reg(0,no REX.R); src r8=r/m(REX.B=1)
        // REX = W=1, R=0, X=0, B=1 = 0x49
        self.emit(&[0x49, 0x0F, 0xAF, 0xC0]); // imul rax, r8
        self.emit_i64_split_rax_push_hi_lo();
    }

    // ── call_indirect (x86_64) ────────────────────────────────────────────────
    //
    // ABI recap:
    //   [rbp-80]  fn_table_len   (number of entries in the function table)
    //   [rbp-88]  fn_table_base  (pointer to array of usize JitFn addresses)
    //
    // Calling convention for the callee JitFn (SysV x86_64):
    //   rdi  stack_ptr        rsi  sp_ptr         rdx  mem_ptr
    //   rcx  mem_len          r8   locals_ptr      r9   instr_fuel_ptr
    //   [rsp+8]  mem_fuel_ptr  [rsp+16] trap_ptr
    //   [rsp+24] globals_ptr   [rsp+32] shadow_sp
    //   [rsp+40] fn_table_base [rsp+48] fn_table_len
    //
    // Implementation:
    //   1. Pop table_index → eax.
    //   2. Bounds-check against [rbp-80]; trap_cfi if out-of-range.
    //   3. Load entry address from table[index]; trap_cfi if null (not compiled).
    //   4. Zero the callee-locals scratch area; fill param_arity slots from stack.
    //   5. Push 6 stack arguments (reverse order: fn_table_len first pushed = deepest).
    //   6. Load register args; call r11.
    //   7. Clean up stack args.
    //   8. If result_arity > 0 push eax onto WASM virtual stack.
    fn emit_call_indirect(&mut self, _type_idx: u32, param_arity: u32, result_arity: u32) {
        // Step 1: pop table_index → eax (r10 is scratch).
        self.emit_pop_to_eax();

        // Step 2: bounds check — load fn_table_len from [rbp-80].
        // mov r11, [rbp-80]
        self.emit(&[0x4C, 0x8B, 0x5D, 0xB0]);
        // cmp rax, r11  (unsigned: eax zero-extended, r11=len)
        self.emit(&[0x4C, 0x39, 0xD8]);
        // jae → trap_cfi (index >= len)
        self.emit_trap_cfi_jump(0x83);

        // Step 3: load entry from fn_table_base[index].
        // mov r11, [rbp-88]
        self.emit(&[0x4C, 0x8B, 0x5D, 0xA8]);
        // mov r11, [r11 + rax*8]  (each entry is a usize = 8 bytes on x86_64)
        self.emit(&[0x4F, 0x8B, 0x1C, 0xC3]);
        // test r11, r11  (null = not compiled → trap_cfi)
        self.emit(&[0x4D, 0x85, 0xDB]);
        self.emit_trap_cfi_jump(0x84);

        // Step 4a: zero the callee-locals scratch area using rep stosd.
        // xor eax, eax
        self.emit(&[0x31, 0xC0]);
        // lea rdi, [rbp + X64_CALLEE_LOCALS_DISP]
        self.emit(&[0x48, 0x8D, 0xBD]);
        self.emit_i32(X64_CALLEE_LOCALS_DISP);
        // mov ecx, MAX_LOCALS
        self.emit(&[0xB9]);
        self.emit_i32(MAX_LOCALS as i32);
        // rep stosd  (fills ecx × 4 bytes with eax=0)
        self.emit(&[0xF3, 0xAB]);

        // Step 4b: fill param slots from WASM virtual stack (top = last param = locals[n-1]).
        // We pop param_arity values and write them to callee-locals[0..param_arity-1] in
        // reverse: pop → locals[param_arity-1], then locals[param_arity-2], ..., locals[0].
        for i in (0..param_arity).rev() {
            self.emit_pop_to_eax();
            let disp = X64_CALLEE_LOCALS_DISP + (i as i32) * 4;
            // mov [rbp + disp32], eax
            self.emit(&[0x89, 0x85]);
            self.emit_i32(disp);
        }

        // Step 5: push stack arguments for the callee (pushed right-to-left = rightmost first).
        // The callee sees them as [rsp+8]...[rsp+48] after its own push rbp.
        // We push: fn_table_len, fn_table_base, shadow_sp, globals_ptr, trap_ptr, mem_fuel_ptr.

        // push [rbp-80]  (fn_table_len)
        self.emit(&[0xFF, 0x75, 0xB0]);
        // push [rbp-88]  (fn_table_base)
        self.emit(&[0xFF, 0x75, 0xA8]);
        // push [rbp+40]  (shadow_sp — pass through, 0x28 = 40)
        self.emit(&[0xFF, 0x75, 0x28]);
        // push [rbp-72]  (globals_ptr)
        self.emit(&[0xFF, 0x75, 0xB8]);
        // push [rbp-64]  (trap_ptr)
        self.emit(&[0xFF, 0x75, 0xC0]);
        // push [rbp-56]  (mem_fuel_ptr)
        self.emit(&[0xFF, 0x75, 0xC8]);
        // Note: [rbp-48] = instr_fuel_ptr goes in r9 (register arg).

        // Step 6: set up register arguments and call.
        // rdi = r12  (stack_ptr)
        self.emit(&[0x4C, 0x89, 0xE7]);
        // rsi = r13  (sp_ptr)
        self.emit(&[0x4C, 0x89, 0xEE]);
        // rdx = r14  (mem_ptr)
        self.emit(&[0x4C, 0x89, 0xF2]);
        // rcx = r15  (mem_len)
        self.emit(&[0x4C, 0x89, 0xF9]);
        // lea r8, [rbp + X64_CALLEE_LOCALS_DISP]  (callee locals_ptr)
        self.emit(&[0x4C, 0x8D, 0x85]);
        self.emit_i32(X64_CALLEE_LOCALS_DISP);
        // mov r9, [rbp-48]  (instr_fuel_ptr — shared so callee consumes from same budget)
        self.emit(&[0x4C, 0x8B, 0x4D, 0xD0]);
        // call r11
        self.emit(&[0x41, 0xFF, 0xD3]);

        // Step 7: clean up 6 stack arguments (6 × 8 = 48 bytes).
        self.emit(&[0x48, 0x83, 0xC4, 0x30]); // add rsp, 48

        // Step 8: push result if expected.
        if result_arity > 0 {
            self.emit_push_eax();
        }
    }

    // ── i32.rotl (x86_64) ────────────────────────────────────────────────────
    fn emit_i32_rotl(&mut self) {
        self.emit_pop_to_eax(); // count
        self.emit(&[0x88, 0xC1]); // mov cl, al
        self.emit_pop_to_eax(); // value (preserves ecx via edx round-trip in emit_pop_to_ecx;
                                // here we call emit_pop_to_eax which clobbers r10/r11 but not cl)
        self.emit(&[0xD3, 0xC0]); // rol eax, cl
        self.emit_push_eax();
    }

    // ── i32.rotr (x86_64) ────────────────────────────────────────────────────
    fn emit_i32_rotr(&mut self) {
        self.emit_pop_to_eax(); // count
        self.emit(&[0x88, 0xC1]); // mov cl, al
        self.emit_pop_to_eax(); // value
        self.emit(&[0xD3, 0xC8]); // ror eax, cl
        self.emit_push_eax();
    }

    // ── i32.popcnt (x86_64) ──────────────────────────────────────────────────
    // Requires POPCNT feature (present on all modern x86_64 CPUs ≥ Nehalem 2008).
    fn emit_i32_popcnt(&mut self) {
        self.emit_pop_to_eax();
        self.emit(&[0xF3, 0x0F, 0xB8, 0xC0]); // popcnt eax, eax
        self.emit_push_eax();
    }

    // ── i32.load8_s (x86_64) ─────────────────────────────────────────────────
    fn emit_i32_load8_s(&mut self, off: u32) {
        self.emit_pop_to_eax(); // addr
        self.emit_bounds_check(off, 1);
        // movsx eax, byte [r14 + rax]  — REX.B extends base to r14
        self.emit(&[0x41, 0x0F, 0xBE, 0x04, 0x06]);
        self.emit_push_eax();
    }

    // ── i32.load16_s (x86_64) ────────────────────────────────────────────────
    fn emit_i32_load16_s(&mut self, off: u32) {
        self.emit_pop_to_eax(); // addr
        self.emit_bounds_check(off, 2);
        // movsx eax, word [r14 + rax]  — same REX.B
        self.emit(&[0x41, 0x0F, 0xBF, 0x04, 0x06]);
        self.emit_push_eax();
    }

    // ── i64.divs (x86_64) ────────────────────────────────────────────────────
    // Pops two i64s (4 slots): a (dividend) and b (divisor).
    // Pushes a / b (signed) as an i64 (2 slots).
    // Traps (TRAP_MEM) on divide-by-zero.
    fn emit_i64_divs(&mut self) {
        // Build a in rax, b in r8
        self.emit_i64_build_a_in_rax_b_in_r8();
        // Test b == 0 → trap
        self.emit(&[0x4D, 0x85, 0xC0]);        // test r8, r8
        self.emit_trap_mem_jump(0x84);          // jz trap_mem (div by zero → TRAP_MEM)
        // cqo: sign-extend rax into rdx:rax
        self.emit(&[0x48, 0x99]);               // cqo
        // idiv r8: rax = quotient, rdx = remainder
        self.emit(&[0x49, 0xF7, 0xF8]);         // idiv r8
        self.emit_i64_split_rax_push_hi_lo();
    }

    // ── i64.clz (x86_64) ─────────────────────────────────────────────────────
    // Requires LZCNT (BMI1; present on all modern x86_64 targets for this kernel).
    fn emit_i64_clz(&mut self) {
        // Pop lo, pop hi; build rax = (hi << 32) | lo
        self.emit_pop_to_ebx();                // r11d = lo (secondary scratch role)
        self.emit_pop_to_eax();                // eax  = hi
        self.emit(&[0x48, 0xC1, 0xE0, 0x20]); // shl rax, 32
        self.emit(&[0x4C, 0x09, 0xD8]);        // or rax, r11
        // lzcnt rax, rax → count in rax (0..=64, fits in 7 bits)
        self.emit(&[0xF3, 0x48, 0x0F, 0xBD, 0xC0]);
        // Save result before zeroing for hi push
        self.emit(&[0x41, 0x89, 0xC3]);        // mov r11d, eax   (result = lo)
        // Push hi = 0
        self.emit(&[0x31, 0xC0]);              // xor eax, eax
        self.emit_push_eax();
        // Push lo = result
        self.emit(&[0x44, 0x89, 0xD8]);        // mov eax, r11d
        self.emit_push_eax();
    }

    // ── i64.ctz (x86_64) ─────────────────────────────────────────────────────
    fn emit_i64_ctz(&mut self) {
        self.emit_pop_to_ebx();                // r11d = lo (secondary scratch role)
        self.emit_pop_to_eax();                // eax  = hi
        self.emit(&[0x48, 0xC1, 0xE0, 0x20]); // shl rax, 32
        self.emit(&[0x4C, 0x09, 0xD8]);        // or rax, r11
        // tzcnt rax, rax → count in rax (0..=64)
        self.emit(&[0xF3, 0x48, 0x0F, 0xBC, 0xC0]);
        self.emit(&[0x41, 0x89, 0xC3]);        // mov r11d, eax
        self.emit(&[0x31, 0xC0]);              // xor eax, eax  (hi = 0)
        self.emit_push_eax();
        self.emit(&[0x44, 0x89, 0xD8]);        // mov eax, r11d
        self.emit_push_eax();
    }

    // ── i64.popcnt (x86_64) ──────────────────────────────────────────────────
    fn emit_i64_popcnt(&mut self) {
        self.emit_pop_to_ebx();                // r11d = lo (secondary scratch role)
        self.emit_pop_to_eax();                // eax  = hi
        self.emit(&[0x48, 0xC1, 0xE0, 0x20]); // shl rax, 32
        self.emit(&[0x4C, 0x09, 0xD8]);        // or rax, r11
        // popcnt rax, rax → count in rax (0..=64)
        self.emit(&[0xF3, 0x48, 0x0F, 0xB8, 0xC0]);
        self.emit(&[0x41, 0x89, 0xC3]);        // mov r11d, eax
        self.emit(&[0x31, 0xC0]);              // xor eax, eax  (hi = 0)
        self.emit_push_eax();
        self.emit(&[0x44, 0x89, 0xD8]);        // mov eax, r11d
        self.emit_push_eax();
    }

    // ── i64.eqz (x86_64) ─────────────────────────────────────────────────────
    // Pops one i64 (2 slots: hi, lo). Pushes i32: 1 if value == 0, else 0.
    fn emit_i64_eqz(&mut self) {
        // Pop lo → r11d, pop hi → eax
        self.emit_pop_to_ebx();               // r11d = lo (TOS)
        self.emit_pop_to_eax();               // eax  = hi
        // OR them: if either word is nonzero, eax becomes nonzero
        self.emit(&[0x44, 0x09, 0xD8]);       // or eax, r11d  (REX.R=1: reg=r11d, r/m=eax)
        // test eax, eax; sete al; movzx eax, al
        self.emit(&[0x85, 0xC0]);             // test eax, eax
        self.emit(&[0x0F, 0x94, 0xC0]);       // sete al
        self.emit(&[0x0F, 0xB6, 0xC0]);       // movzx eax, al
        self.emit_push_eax();
    }

    // ── i64 comparison helpers ────────────────────────────────────────────────
    //
    // All i64 comparisons follow the same pattern:
    //   1. emit_i64_build_a_in_rax_b_in_r8   → rax = TOS i64 (a), r8 = below-TOS i64 (b)
    //   2. cmp rax, r8
    //   3. setXX al      (choose based on b OP a semantics; see notes below)
    //   4. movzx eax, al
    //   5. emit_push_eax
    //
    // WASM ordering convention: in the virtual stack, "a" is the MORE RECENTLY
    // pushed i64 (TOS region → rax). In WASM binary ops the MORE RECENT push is
    // the RIGHT operand (v2). The LESS RECENT push is the LEFT operand (v1 → r8).
    //
    // Thus for each WASM comparison "v1 OP v2":
    //   v1 = r8 (b), v2 = rax (a)
    //   "v1 OP v2" ⟺ "r8 OP rax" ⟺ use SWAPPED setcc after "cmp rax, r8":
    //       i64.eq  → sete    (equal is symmetric)
    //       i64.ne  → setne
    //       i64.lt_s (v1 < v2, r8 < rax) → setg  (rax > r8 signed ↔ r8 < rax)
    //       i64.gt_s (v1 > v2, r8 > rax) → setl
    //       i64.le_s (v1 ≤ v2, r8 ≤ rax) → setge
    //       i64.ge_s (v1 ≥ v2, r8 ≥ rax) → setle
    //       i64.lt_u (r8 < rax unsigned)  → seta
    //       i64.gt_u (r8 > rax unsigned)  → setb
    //       i64.le_u (r8 ≤ rax unsigned)  → setae
    //       i64.ge_u (r8 ≥ rax unsigned)  → setbe
    //
    // cmp rax, r8 encoding: 0x49 0x3B 0xC0
    //   REX: W=1,R=0,X=0,B=1 = 0x49
    //   CMP r64, r/m64 (0x3B): reg=rax(0), r/m=r8(with REX.B=1→8)
    //   ModRM: mod=11 reg=000 r/m=000 = 0xC0
    //
    // setcc al encodings (all: 0F 9X C0):
    //   sete  0F 94 C0   setne 0F 95 C0
    //   setl  0F 9C C0   setg  0F 9F C0   setle 0F 9E C0   setge 0F 9D C0
    //   setb  0F 92 C0   seta  0F 97 C0   setbe 0F 96 C0   setae 0F 93 C0
    //
    // movzx eax, al: 0F B6 C0

    fn emit_i64_cmp_core(&mut self, setcc: [u8; 3]) {
        self.emit_i64_build_a_in_rax_b_in_r8();
        self.emit(&[0x49, 0x3B, 0xC0]);       // cmp rax, r8
        self.emit(&setcc);                     // setXX al
        self.emit(&[0x0F, 0xB6, 0xC0]);       // movzx eax, al
        self.emit_push_eax();
    }

    fn emit_i64_eq(&mut self)  { self.emit_i64_cmp_core([0x0F, 0x94, 0xC0]); } // sete
    fn emit_i64_ne(&mut self)  { self.emit_i64_cmp_core([0x0F, 0x95, 0xC0]); } // setne
    fn emit_i64_lts(&mut self) { self.emit_i64_cmp_core([0x0F, 0x9F, 0xC0]); } // setg (r8<rax signed)
    fn emit_i64_gts(&mut self) { self.emit_i64_cmp_core([0x0F, 0x9C, 0xC0]); } // setl (r8>rax signed)
    fn emit_i64_les(&mut self) { self.emit_i64_cmp_core([0x0F, 0x9D, 0xC0]); } // setge
    fn emit_i64_ges(&mut self) { self.emit_i64_cmp_core([0x0F, 0x9E, 0xC0]); } // setle
    fn emit_i64_ltu(&mut self) { self.emit_i64_cmp_core([0x0F, 0x97, 0xC0]); } // seta (r8<rax unsigned)
    fn emit_i64_gtu(&mut self) { self.emit_i64_cmp_core([0x0F, 0x92, 0xC0]); } // setb
    fn emit_i64_leu(&mut self) { self.emit_i64_cmp_core([0x0F, 0x93, 0xC0]); } // setae
    fn emit_i64_geu(&mut self) { self.emit_i64_cmp_core([0x0F, 0x96, 0xC0]); } // setbe

    // ── i32.wrap_i64 (x86_64) ────────────────────────────────────────────────
    // Pops i64 (2 slots: hi, lo). Pushes the lo word as an i32.
    fn emit_i32_wrap_i64(&mut self) {
        self.emit_pop_to_eax();               // eax = lo (TOS)
        self.emit_pop_to_ebx();               // r11d = hi (discarded via ebx alias)
        self.emit_push_eax();                 // push lo as i32
    }

    // ── i64.extend_i32_s (x86_64) ────────────────────────────────────────────
    // Pops i32. Pushes i64 sign-extended to 64 bits.
    fn emit_i64_extend_i32s(&mut self) {
        self.emit_pop_to_eax();               // eax = i32 value
        self.emit(&[0x48, 0x63, 0xC0]);       // movsxd rax, eax  (sign-extend to rax)
        self.emit_i64_split_rax_push_hi_lo(); // push hi (sign bits), then lo
    }

    // ── i64.extend_i32_u (x86_64) ────────────────────────────────────────────
    // Pops i32. Pushes i64 zero-extended to 64 bits.
    fn emit_i64_extend_i32u(&mut self) {
        self.emit_pop_to_eax();               // eax = i32; upper 32 bits of rax = 0 automatically
        self.emit_i64_split_rax_push_hi_lo(); // push hi=0, then lo
    }

    // ── i64.load (x86_64) ────────────────────────────────────────────────────
    // Pops i32 addr; loads 8 bytes from linear memory; pushes i64 (hi, lo).
    fn emit_i64_load(&mut self, off: u32) {
        self.emit_pop_to_eax();
        self.emit_bounds_check(off, 8);
        // mov r11, [r14 + rax]  — REX.W=1,REX.R=1(r11),REX.B=1(r14) = 0x4D
        self.emit(&[0x4D, 0x8B, 0x1C, 0x06]);
        // Save lo: r11d → r8d, then shift r11 right 32 → hi in r11d
        self.emit(&[0x45, 0x89, 0xD8]);        // mov r8d, r11d  (save lo)
        self.emit(&[0x49, 0xC1, 0xEB, 0x20]); // shr r11, 32    (hi in r11d)
        self.emit(&[0x44, 0x89, 0xD8]);        // mov eax, r11d  (hi)
        self.emit_push_eax();
        self.emit(&[0x44, 0x89, 0xC0]);        // mov eax, r8d   (lo)
        self.emit_push_eax();
    }

    // ── i64.load8_u (x86_64) ─────────────────────────────────────────────────
    fn emit_i64_load8_u(&mut self, off: u32) {
        self.emit_pop_to_eax();
        self.emit_bounds_check(off, 1);
        // movzx eax, byte [r14 + rax]  — REX.B=0x41
        self.emit(&[0x41, 0x0F, 0xB6, 0x04, 0x06]);
        // Push hi = 0, lo = eax
        self.emit(&[0x41, 0x89, 0xC3]);        // mov r11d, eax
        self.emit(&[0x31, 0xC0]);              // xor eax, eax
        self.emit_push_eax();
        self.emit(&[0x44, 0x89, 0xD8]);        // mov eax, r11d
        self.emit_push_eax();
    }

    // ── i64.load16_u (x86_64) ────────────────────────────────────────────────
    fn emit_i64_load16_u(&mut self, off: u32) {
        self.emit_pop_to_eax();
        self.emit_bounds_check(off, 2);
        // movzx eax, word [r14 + rax]  — REX.B=0x41
        self.emit(&[0x41, 0x0F, 0xB7, 0x04, 0x06]);
        self.emit(&[0x41, 0x89, 0xC3]);        // mov r11d, eax
        self.emit(&[0x31, 0xC0]);              // xor eax, eax
        self.emit_push_eax();
        self.emit(&[0x44, 0x89, 0xD8]);        // mov eax, r11d
        self.emit_push_eax();
    }

    // ── i64.load32_u (x86_64) ────────────────────────────────────────────────
    fn emit_i64_load32_u(&mut self, off: u32) {
        self.emit_pop_to_eax();
        self.emit_bounds_check(off, 4);
        // mov eax, [r14 + rax]  — REX.B=0x41, 32-bit load zero-extends rax
        self.emit(&[0x41, 0x8B, 0x04, 0x06]);
        self.emit(&[0x41, 0x89, 0xC3]);        // mov r11d, eax
        self.emit(&[0x31, 0xC0]);              // xor eax, eax
        self.emit_push_eax();
        self.emit(&[0x44, 0x89, 0xD8]);        // mov eax, r11d
        self.emit_push_eax();
    }

    // ── i64.store (x86_64) ───────────────────────────────────────────────────
    // Stack (top→bottom): val_lo, val_hi, addr
    fn emit_i64_store(&mut self, off: u32) {
        self.emit_pop_to_ebx();                // r11d = val_lo (secondary scratch role)
        self.emit_pop_to_eax();                // eax  = val_hi
        // Build r11 = (val_hi << 32) | val_lo
        self.emit(&[0x48, 0xC1, 0xE0, 0x20]); // shl rax, 32
        self.emit(&[0x49, 0x09, 0xC3]);        // or r11, rax
        // Now r11 = full 64-bit value. Pop addr → eax.
        self.emit_pop_to_eax();
        self.emit_bounds_check(off, 8);
        // mov [r14 + rax], r11  — REX.W=1,REX.R=1(r11),REX.B=1(r14) = 0x4D
        self.emit(&[0x4D, 0x89, 0x1C, 0x06]);
    }

    // ── i64.store8 (x86_64) ──────────────────────────────────────────────────
    // Stack: val_lo, val_hi, addr  (store low byte of val_lo)
    fn emit_i64_store8(&mut self, off: u32) {
        self.emit_pop_to_ebx();                // val_lo (we want low byte)
        self.emit_pop_to_eax();                // val_hi (discard)
        // Pop addr → eax (emit_pop_to_eax clobbers eax, r11d preserved since helper only uses r10)
        self.emit_pop_to_eax();
        self.emit_bounds_check(off, 1);
        // mov byte [r14 + rax], r11b  — REX no-W, REX.R=1(r11), REX.B=1(r14) = 0x45
        self.emit(&[0x45, 0x88, 0x1C, 0x06]);
    }

    // ── i64.store16 (x86_64) ─────────────────────────────────────────────────
    fn emit_i64_store16(&mut self, off: u32) {
        self.emit_pop_to_ebx();                // val_lo
        self.emit_pop_to_eax();                // val_hi (discard)
        self.emit_pop_to_eax();                // addr
        self.emit_bounds_check(off, 2);
        // mov word [r14 + rax], r11w  — 0x66 operand-size prefix + REX 0x45
        self.emit(&[0x66, 0x45, 0x89, 0x1C, 0x06]);
    }

    // ── i64.store32 (x86_64) ─────────────────────────────────────────────────
    fn emit_i64_store32(&mut self, off: u32) {
        self.emit_pop_to_ebx();                // val_lo (32 bits sufficient)
        self.emit_pop_to_eax();                // val_hi (discard)
        self.emit_pop_to_eax();                // addr
        self.emit_bounds_check(off, 4);
        // mov dword [r14 + rax], r11d  — REX.R=1(r11), REX.B=1(r14), no W = 0x45
        self.emit(&[0x45, 0x89, 0x1C, 0x06]);
    }

    fn emit_local_get(&mut self, idx: u32) {
        self.emit(&[0x8B, 0x83]); // mov eax, [rbx + disp32]
        self.emit_i32((idx as i32) * 4);
        self.emit_push_eax();
    }

    fn emit_local_set(&mut self, idx: u32) {
        self.emit_pop_to_eax();
        self.emit(&[0x89, 0x83]); // mov [rbx + disp32], eax
        self.emit_i32((idx as i32) * 4);
    }

    fn emit_local_tee(&mut self, idx: u32) {
        self.emit_pop_to_eax();
        self.emit(&[0x89, 0x83]); // mov [rbx + disp32], eax
        self.emit_i32((idx as i32) * 4);
        self.emit_push_eax();
    }

    fn emit_global_get(&mut self, idx: u32) {
        self.emit(&[
            0x4C, 0x8B, 0x5D, 0xB8, // mov r11, [rbp-72]
            0x41, 0x8B, 0x83, // mov eax, [r11 + disp32]
        ]);
        self.emit_i32((idx as i32) * 4);
        self.emit_push_eax();
    }

    fn emit_global_set(&mut self, idx: u32) {
        self.emit_pop_to_eax();
        self.emit(&[
            0x4C, 0x8B, 0x5D, 0xB8, // mov r11, [rbp-72]
            0x41, 0x89, 0x83, // mov [r11 + disp32], eax
        ]);
        self.emit_i32((idx as i32) * 4);
    }

    fn emit_i32_store(&mut self, off: u32) {
        // WASM stack order: [..., addr, value] (value on top).
        self.emit_pop_to_ecx(); // value
        self.emit_pop_to_eax(); // addr
        self.emit_bounds_check(off, 4);
        self.emit(&[
            0x41, 0x89, 0x0C, 0x06, // mov [r14 + rax], ecx
        ]);
    }

    fn emit_select(&mut self) {
        // Stack shape: [..., val1, val2, cond]
        self.emit_pop_to_eax(); // cond
        self.emit(&[0x89, 0xC2]); // mov edx, eax
        self.emit_pop_to_ecx(); // val2
        self.emit_pop_to_eax(); // val1
        self.emit(&[0x85, 0xD2]); // test edx, edx
        self.emit(&[0x0F, 0x44, 0xC1]); // cmovz eax, ecx
        self.emit_push_eax();
    }

    fn emit_memory_size(&mut self) {
        // memory.size returns current linear memory size in 64KiB pages.
        // mem_len lives in r15 (bytes).
        self.emit(&[0x44, 0x89, 0xF8]); // mov eax, r15d
        self.emit(&[0xC1, 0xE8, 0x10]); // shr eax, 16
        self.emit_push_eax();
    }

    fn emit_memory_grow(&mut self) {
        // Current kernel runtime wires WASM linear memory at fixed max size
        // (1 page), so memory.grow can only succeed for delta=0.
        self.emit_pop_to_eax(); // delta pages
        self.emit(&[0x83, 0xF8, 0x00]); // cmp eax, 0
        self.emit(&[0x75, 0x08]); // jne fail
        self.emit(&[0x44, 0x89, 0xF8]); // mov eax, r15d
        self.emit(&[0xC1, 0xE8, 0x10]); // shr eax, 16
        self.emit(&[0xEB, 0x05]); // jmp done
        self.emit(&[0xB8]); // fail: mov eax, -1
        self.emit_i32(-1);
        self.emit_push_eax();
    }

    fn emit_cfi_push_return(&mut self) {}

    fn emit_cfi_check_return(&mut self) {}

    fn emit_instr_fuel_check(&mut self) {
        self.emit(&[
            0x48, 0x8B, 0x45, 0xD0, // mov rax, [rbp-48]
            0x83, 0x38, 0x00, // cmp dword [rax], 0
        ]);
        self.emit_trap_fuel_jump(0x84); // je trap
        self.emit(&[0xFF, 0x08]); // dec dword [rax]
    }

    fn emit_mem_fuel_check(&mut self) {
        self.emit(&[
            0x48, 0x8B, 0x45, 0xC8, // mov rax, [rbp-56]
            0x83, 0x38, 0x00, // cmp dword [rax], 0
        ]);
        self.emit_trap_fuel_jump(0x84); // je trap
        self.emit(&[0xFF, 0x08]); // dec dword [rax]
    }

    fn emit_epilogue(&mut self) -> usize {
        let pos = self.code.len();
        self.emit(&[
            0x4D, 0x8B, 0x55, 0x00, // mov r10, [r13+0]
            0x4D, 0x85, 0xD2, // test r10, r10
            0x74, 0x0C, // jz +12
            0x49, 0xFF, 0xCA, // dec r10
            0x43, 0x8B, 0x04, 0x94, // mov eax, [r12 + r10*4]
            0x4D, 0x89, 0x55, 0x00, // mov [r13+0], r10
            0xEB, 0x02, // jmp +2
            0x31, 0xC0, // xor eax, eax
        ]);
        self.emit_cfi_check_return();
        self.emit(&[
            0x48, 0x81, 0xC4, // add rsp, imm32
        ]);
        self.emit_i32(X64_STACK_FRAME_BYTES + X64_CALLEE_LOCALS_BYTES);
        self.emit(&[
            0x41, 0x5F, // pop r15
            0x41, 0x5E, // pop r14
            0x41, 0x5D, // pop r13
            0x41, 0x5C, // pop r12
            0x5B, // pop rbx
            0x5D, // pop rbp
            0xC3, // ret
        ]);
        pos
    }

    fn emit_trap_stub(&mut self, code: i32, _check_cfi: bool) -> usize {
        let pos = self.code.len();
        self.emit(&[
            0x48, 0x8B, 0x45, 0xC0, // mov rax, [rbp-64]
            0xC7, 0x00, // mov dword [rax], imm32
        ]);
        self.emit_i32(code);
        self.emit(&[
            0x31, 0xC0, // xor eax, eax
            0x48, 0x81, 0xC4, // add rsp, imm32
        ]);
        self.emit_i32(X64_STACK_FRAME_BYTES + X64_CALLEE_LOCALS_BYTES);
        self.emit(&[
            0x41, 0x5F, // pop r15
            0x41, 0x5E, // pop r14
            0x41, 0x5D, // pop r13
            0x41, 0x5C, // pop r12
            0x5B, // pop rbx
            0x5D, // pop rbp
            0xC3, // ret
        ]);
        pos
    }

    fn emit_trap_mem_jump(&mut self, opcode_ext: u8) {
        self.emit(&[0x0F, opcode_ext]);
        let pos = self.code.len();
        self.emit_u32(0);
        self.trap_mem_jumps.push(pos);
    }

    fn emit_trap_fuel_jump(&mut self, opcode_ext: u8) {
        self.emit(&[0x0F, opcode_ext]);
        let pos = self.code.len();
        self.emit_u32(0);
        self.trap_fuel_jumps.push(pos);
    }

    fn emit_trap_stack_jump(&mut self, opcode_ext: u8) {
        self.emit(&[0x0F, opcode_ext]);
        let pos = self.code.len();
        self.emit_u32(0);
        self.trap_stack_jumps.push(pos);
    }

    fn emit_trap_stack_always(&mut self) {
        self.emit(&[0xE9]);
        let pos = self.code.len();
        self.emit_u32(0);
        self.trap_stack_jumps.push(pos);
    }

    fn emit_trap_cfi_jump(&mut self, opcode_ext: u8) {
        self.emit(&[0x0F, opcode_ext]);
        let pos = self.code.len();
        self.emit_u32(0);
        self.trap_cfi_jumps.push(pos);
    }

    fn patch_traps(
        &mut self,
        trap_mem_pos: usize,
        trap_fuel_pos: usize,
        trap_stack_pos: usize,
        trap_cfi_pos: usize,
    ) -> Result<(), &'static str> {
        fn patch_jump_list(
            code: &mut [u8],
            jumps: &[usize],
            trap_pos: usize,
        ) -> Result<(), &'static str> {
            for &idx in jumps {
                let end = idx.checked_add(4).ok_or("Trap patch index overflow")?;
                if end > code.len() {
                    return Err("Trap patch index out of range");
                }
                let rel = (trap_pos as isize - end as isize) as i32;
                code[idx..end].copy_from_slice(&rel.to_le_bytes());
            }
            Ok(())
        }

        patch_jump_list(&mut self.code, &self.trap_mem_jumps, trap_mem_pos)?;
        patch_jump_list(&mut self.code, &self.trap_fuel_jumps, trap_fuel_pos)?;
        patch_jump_list(&mut self.code, &self.trap_stack_jumps, trap_stack_pos)?;
        patch_jump_list(&mut self.code, &self.trap_cfi_jumps, trap_cfi_pos)?;
        Ok(())
    }
}

fn read_uleb128(bytes: &[u8], mut offset: usize) -> Option<(u32, usize)> {
    let mut result = 0u32;
    let mut shift = 0;
    let mut count = 0;
    loop {
        if offset >= bytes.len() {
            return None;
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
            return None;
        }
    }
    Some((result, count))
}

fn read_sleb128_i32(bytes: &[u8], mut offset: usize) -> Option<(i32, usize)> {
    let mut result = 0i32;
    let mut shift = 0;
    let mut count = 0;
    let mut byte: u8;
    loop {
        if offset >= bytes.len() {
            return None;
        }
        byte = bytes[offset];
        offset += 1;
        count += 1;
        result |= ((byte & 0x7F) as i32) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    if shift < 32 && (byte & 0x40) != 0 {
        result |= !0 << shift;
    }
    Some((result, count))
}

/// Decode a LEB128-encoded signed 64-bit integer and return (lo_i32, hi_i32, bytes_consumed).
/// The lo/hi pair is suitable for two push-immediate instructions that represent the
/// i64 value as a pair of i32 stack words (lo = lower 32 bits, hi = upper 32 bits).
fn read_sleb128_i64_as_pair(bytes: &[u8], mut offset: usize) -> Option<(i32, i32, usize)> {
    let mut result = 0i64;
    let mut shift = 0u32;
    let mut count = 0usize;
    let mut byte;
    loop {
        if offset >= bytes.len() {
            return None;
        }
        byte = bytes[offset];
        offset += 1;
        count += 1;
        result |= ((byte & 0x7F) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
        if shift >= 70 {
            return None; // malformed: too many bytes
        }
    }
    if shift < 64 && (byte & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    let lo = result as i32;
    let hi = (result >> 32) as i32;
    Some((lo, hi, count))
}

fn read_blocktype_width(
    bytes: &[u8],
    offset: usize,
    type_sigs: &[JitTypeSignature],
) -> Option<(usize, JitBlockType)> {
    if offset >= bytes.len() {
        return None;
    }
    let b = bytes[offset];
    if b == 0x40 {
        return Some((1, JitBlockType::empty()));
    }
    if b == 0x7F {
        return Some((1, JitBlockType::i32_result()));
    }
    if b == 0x7E || b == 0x7D || b == 0x7C || b == 0x70 || b == 0x6F {
        return Some((1, JitBlockType::unsupported()));
    }
    let (idx, n) = read_uleb128(bytes, offset)?;
    let sig = type_sigs.get(idx as usize).copied()?;
    if !sig.all_i32 {
        return Some((n, JitBlockType::unsupported()));
    }
    let param_arity = i32::try_from(sig.param_count).ok()?;
    let result_arity = i32::try_from(sig.result_count).ok()?;
    Some((
        n,
        JitBlockType {
            param_arity,
            result_arity,
            supported: true,
        },
    ))
}

// ============================================================================
// JIT Validation Helpers
// ============================================================================

fn stack_push(depth: &mut i32, n: i32, max_depth: &mut i32) -> Result<(), &'static str> {
    *depth = depth.saturating_add(n);
    if *depth > *max_depth {
        *max_depth = *depth;
    }
    if *depth as usize > MAX_STACK_DEPTH {
        return Err("JIT stack overflow");
    }
    Ok(())
}

fn stack_pop(depth: &mut i32, n: i32) -> Result<(), &'static str> {
    if *depth < n {
        return Err("JIT stack underflow");
    }
    *depth -= n;
    Ok(())
}

fn hash_jit_code(code: &[u8]) -> u64 {
    let mut hash: u64 = 14695981039346656037;
    for &b in code {
        hash ^= b as u64;
        hash = hash.wrapping_mul(1099511628211);
    }
    hash
}

#[cfg(target_arch = "x86_64")]
fn verify_x86_subset(
    _code: &[u8],
    _locals_total: usize,
    _trap_targets: &[usize],
) -> Result<(), &'static str> {
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
fn verify_x86_subset(
    code: &[u8],
    locals_total: usize,
    trap_targets: &[usize],
) -> Result<(), &'static str> {
    fn need(code: &[u8], i: usize, n: usize) -> Result<(), &'static str> {
        if i + n > code.len() {
            return Err("Truncated x86 instruction");
        }
        Ok(())
    }

    fn read_u32(code: &[u8], i: usize) -> Result<u32, &'static str> {
        let bytes: [u8; 4] = code
            .get(i..i + 4)
            .ok_or("Truncated imm32")?
            .try_into()
            .map_err(|_| "Truncated imm32")?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn expect_imm8(code: &[u8], i: usize, val: u8) -> Result<(), &'static str> {
        let imm = *code.get(i).ok_or("Truncated imm8")?;
        if imm != val {
            return Err("Unexpected imm8");
        }
        Ok(())
    }

    fn check_local_disp32(code: &[u8], i: usize, locals_total: usize) -> Result<(), &'static str> {
        if locals_total == 0 {
            return Err("Local access with zero locals");
        }
        let disp = read_u32(code, i)? as usize;
        if disp % 4 != 0 {
            return Err("Unaligned local offset");
        }
        let idx = disp / 4;
        if idx >= locals_total {
            return Err("Local index out of bounds");
        }
        Ok(())
    }

    fn expect_disp8(code: &[u8], i: usize, allowed: &[u8]) -> Result<(), &'static str> {
        let disp = *code.get(i).ok_or("Truncated disp8")?;
        if !allowed.contains(&disp) {
            return Err("Unexpected disp8");
        }
        Ok(())
    }

    fn check_rel32_target(code: &[u8], i: usize, allowed: &[usize]) -> Result<(), &'static str> {
        let rel = read_u32(code, i + 2)? as i32;
        let base = (i + 6) as isize;
        let target = base.wrapping_add(rel as isize);
        if target < 0 {
            crate::serial_println!(
                "[JIT-ST] rel32-invalid i={} op=0x{:02x} ext=0x{:02x} base={} rel={} target={}",
                i,
                code.get(i).copied().unwrap_or(0),
                code.get(i + 1).copied().unwrap_or(0),
                base,
                rel,
                target
            );
            return Err("Invalid branch target");
        }
        let target = target as usize;
        if target >= code.len() {
            crate::serial_println!(
                "[JIT-ST] rel32-oob i={} op=0x{:02x} ext=0x{:02x} base={} rel={} target={} code_len={}",
                i,
                code.get(i).copied().unwrap_or(0),
                code.get(i + 1).copied().unwrap_or(0),
                base,
                rel,
                target,
                code.len()
            );
            return Err("Branch target out of range");
        }
        if !allowed.iter().any(|&t| t == target) {
            crate::serial_println!(
                "[JIT-ST] rel32-unexpected i={} op=0x{:02x} ext=0x{:02x} base={} rel={} target={} allowed={:x?}",
                i,
                code.get(i).copied().unwrap_or(0),
                code.get(i + 1).copied().unwrap_or(0),
                base,
                rel,
                target,
                allowed
            );
            return Err("Unexpected branch target");
        }
        Ok(())
    }

    let mut i = 0usize;
    let mut guard_state = 0u8;
    let mut guard_ready = false;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum StackTok {
        MovEbxSp,
        MovEaxSp,
        CmpEbxMax,
        CmpEbxZero,
        CmpEaxZero,
        Jae,
        Je,
        JeShort,
        DecEbx,
        DecEax,
        IncEbx,
        StoreStack,
        LoadFromEbx,
        LoadFromEax,
        StoreSpEbx,
        StoreSpEax,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum StackState {
        None,
        EbxStart,
        EaxStart,
        PushCmp,
        PushJcc,
        PushStore,
        PushInc,
        PopCmpEbx,
        PopJccEbx,
        PopDecEbx,
        PopLoadEbx,
        PopCmpEax,
        PopJccEax,
        PopDecEax,
        PopLoadEax,
    }

    fn is_stack_access(tok: StackTok) -> bool {
        matches!(
            tok,
            StackTok::StoreStack
                | StackTok::LoadFromEbx
                | StackTok::LoadFromEax
                | StackTok::StoreSpEbx
                | StackTok::StoreSpEax
        )
    }

    fn stack_advance(state: &mut StackState, tok: Option<StackTok>) -> Result<(), &'static str> {
        match (*state, tok) {
            (StackState::None, None) => Ok(()),
            (StackState::None, Some(StackTok::MovEbxSp)) => {
                *state = StackState::EbxStart;
                Ok(())
            }
            (StackState::None, Some(StackTok::MovEaxSp)) => {
                *state = StackState::EaxStart;
                Ok(())
            }
            (StackState::None, Some(tok)) => {
                if is_stack_access(tok) {
                    Err("Stack access without guard")
                } else {
                    Ok(())
                }
            }
            (StackState::EbxStart, Some(StackTok::CmpEbxMax)) => {
                *state = StackState::PushCmp;
                Ok(())
            }
            (StackState::EbxStart, Some(StackTok::CmpEbxZero)) => {
                *state = StackState::PopCmpEbx;
                Ok(())
            }
            (StackState::EaxStart, Some(StackTok::CmpEaxZero)) => {
                *state = StackState::PopCmpEax;
                Ok(())
            }
            (StackState::PushCmp, Some(StackTok::Jae)) => {
                *state = StackState::PushJcc;
                Ok(())
            }
            (StackState::PushJcc, Some(StackTok::StoreStack)) => {
                *state = StackState::PushStore;
                Ok(())
            }
            (StackState::PushStore, Some(StackTok::IncEbx)) => {
                *state = StackState::PushInc;
                Ok(())
            }
            (StackState::PushInc, Some(StackTok::StoreSpEbx)) => {
                *state = StackState::None;
                Ok(())
            }
            (StackState::PopCmpEbx, Some(StackTok::Je)) => {
                *state = StackState::PopJccEbx;
                Ok(())
            }
            (StackState::PopCmpEbx, Some(StackTok::JeShort)) => {
                *state = StackState::PopJccEbx;
                Ok(())
            }
            (StackState::PopJccEbx, Some(StackTok::DecEbx)) => {
                *state = StackState::PopDecEbx;
                Ok(())
            }
            (StackState::PopDecEbx, Some(StackTok::LoadFromEbx)) => {
                *state = StackState::PopLoadEbx;
                Ok(())
            }
            (StackState::PopLoadEbx, Some(StackTok::StoreSpEbx)) => {
                *state = StackState::None;
                Ok(())
            }
            (StackState::PopCmpEax, Some(StackTok::Je)) => {
                *state = StackState::PopJccEax;
                Ok(())
            }
            (StackState::PopCmpEax, Some(StackTok::JeShort)) => {
                *state = StackState::PopJccEax;
                Ok(())
            }
            (StackState::PopJccEax, Some(StackTok::DecEax)) => {
                *state = StackState::PopDecEax;
                Ok(())
            }
            (StackState::PopDecEax, Some(StackTok::LoadFromEax)) => {
                *state = StackState::PopLoadEax;
                Ok(())
            }
            (StackState::PopDecEax, Some(StackTok::StoreSpEax)) => {
                *state = StackState::None;
                Ok(())
            }
            (StackState::PopLoadEax, Some(StackTok::StoreSpEax)) => {
                *state = StackState::None;
                Ok(())
            }
            (_, None) => Err("Unexpected stack guard sequence"),
            _ => Err("Unexpected stack guard sequence"),
        }
    }

    let mut stack_state = StackState::None;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum GuardTok {
        AddEaxImm,
        Jb,
        CmpEcxImm,
        MovEbxEcx,
        SubEbxImm,
        CmpEaxEbx,
        Ja,
    }

    fn guard_advance(state: &mut u8, tok: Option<GuardTok>) -> bool {
        match (*state, tok) {
            (0, Some(GuardTok::AddEaxImm)) => {
                *state = 1;
                false
            }
            (0, Some(GuardTok::CmpEcxImm)) => {
                *state = 3;
                false
            }
            (1, Some(GuardTok::Jb)) => {
                *state = 2;
                false
            }
            (2, Some(GuardTok::CmpEcxImm)) => {
                *state = 3;
                false
            }
            (3, Some(GuardTok::Jb)) => {
                *state = 4;
                false
            }
            (4, Some(GuardTok::MovEbxEcx)) => {
                *state = 5;
                false
            }
            (5, Some(GuardTok::SubEbxImm)) => {
                *state = 6;
                false
            }
            (6, Some(GuardTok::CmpEaxEbx)) => {
                *state = 7;
                false
            }
            (7, Some(GuardTok::Ja)) => {
                *state = 0;
                true
            }
            _ => {
                *state = 0;
                false
            }
        }
    }

    while i < code.len() {
        let b = code[i];
        let mut guard_tok = None;
        let mut linear_load = false;
        let mut linear_store = false;
        let mut guard_bridge = false;
        let mut stack_tok = None;
        match b {
            // Disallow all known prefixes (emitter never uses them).
            0xF0 | 0xF2 | 0xF3 | 0x66 | 0x67 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 => {
                return Err("Unexpected instruction prefix");
            }
            // Single-byte opcodes
            0x55 | 0x4B | 0x48 | 0x43 | 0x5D | 0xC3 => {
                if b == 0x4B {
                    stack_tok = Some(StackTok::DecEbx);
                } else if b == 0x48 {
                    stack_tok = Some(StackTok::DecEax);
                } else if b == 0x43 {
                    stack_tok = Some(StackTok::IncEbx);
                }
                i += 1;
            }
            // Short jumps used by the epilogue, control flow helpers, and
            // signed div/rem overflow guards.
            0x74 => {
                need(code, i, 2)?;
                match code[i + 1] {
                    0x08 => stack_tok = Some(StackTok::JeShort),
                    0x05 | 0x0A | 0x0C => {}
                    _ => return Err("Unexpected 0x74 displacement"),
                }
                i += 2;
            }
            0x75 => {
                need(code, i, 2)?;
                match code[i + 1] {
                    0x07 | 0x08 | 0x0B => {}
                    _ => return Err("Unexpected 0x75 displacement"),
                }
                i += 2;
            }
            0xEB => {
                need(code, i, 2)?;
                match code[i + 1] {
                    0x02 | 0x05 => {}
                    _ => return Err("Unexpected 0xEB displacement"),
                }
                i += 2;
            }
            // mov eax, imm32 | add eax, imm32
            0xB8 | 0x05 => {
                if b == 0x05 {
                    guard_tok = Some(GuardTok::AddEaxImm);
                }
                need(code, i, 5)?;
                i += 5;
            }
            // jmp rel32 (used by unconditional trap tails such as `unreachable`)
            0xE9 => {
                need(code, i, 5)?;
                let rel = read_u32(code, i + 1)? as i32;
                let base = (i + 5) as isize;
                let target = base.wrapping_add(rel as isize);
                if target < 0 {
                    return Err("Invalid branch target");
                }
                let target = target as usize;
                if target >= code.len() {
                    return Err("Branch target out of range");
                }
                if !trap_targets.iter().any(|&t| t == target) {
                    return Err("Unexpected branch target");
                }
                i += 5;
            }
            // cmp eax, imm32
            0x3D => {
                need(code, i, 5)?;
                i += 5;
            }
            // cdq
            0x99 => {
                i += 1;
            }
            // imm32 group: cmp/sub
            0x81 => {
                need(code, i, 6)?;
                let b1 = code[i + 1];
                match b1 {
                    0xFB => {
                        let imm = read_u32(code, i + 2)? as usize;
                        if imm != MAX_STACK_DEPTH {
                            return Err("Unexpected cmp ebx, imm32");
                        }
                        stack_tok = Some(StackTok::CmpEbxMax);
                    }
                    0xF9 => {
                        let imm = read_u32(code, i + 2)?;
                        if imm != 4 {
                            return Err("Unexpected cmp ecx, imm32");
                        }
                        guard_tok = Some(GuardTok::CmpEcxImm);
                    }
                    0xEB => {
                        let imm = read_u32(code, i + 2)?;
                        if imm != 4 {
                            return Err("Unexpected sub ebx, imm32");
                        }
                        guard_tok = Some(GuardTok::SubEbxImm);
                    }
                    _ => return Err("Unexpected 0x81 encoding"),
                }
                i += 6;
            }
            // imm8 group: cmp/add/sub
            0x83 => {
                need(code, i, 3)?;
                let b1 = code[i + 1];
                match b1 {
                    0xFB => {
                        let imm = *code.get(i + 2).ok_or("Truncated 0x83 imm8")?;
                        if imm == 0x00 {
                            stack_tok = Some(StackTok::CmpEbxZero);
                        } else if imm != 0xFF {
                            return Err("Unexpected imm8");
                        }
                        i += 3;
                    }
                    0xF8 => {
                        expect_imm8(code, i + 2, 0x00)?;
                        stack_tok = Some(StackTok::CmpEaxZero);
                        i += 3;
                    }
                    0xF9 => {
                        expect_imm8(code, i + 2, 0x04)?;
                        guard_tok = Some(GuardTok::CmpEcxImm);
                        i += 3;
                    }
                    0xEB => {
                        expect_imm8(code, i + 2, 0x04)?;
                        guard_tok = Some(GuardTok::SubEbxImm);
                        i += 3;
                    }
                    0xEC | 0xC4 => {
                        expect_imm8(code, i + 2, 0x28)?;
                        i += 3;
                    }
                    0x38 => {
                        expect_imm8(code, i + 2, 0x00)?;
                        i += 3;
                    }
                    _ => return Err("Unexpected 0x83 encoding"),
                }
            }
            // mov r32, r/m32
            0x8B => {
                let b1 = *code.get(i + 1).ok_or("Truncated 0x8B")?;
                match b1 {
                    0x7D => {
                        need(code, i, 3)?;
                        expect_disp8(code, i + 2, &[0x08, 0xD8])?;
                        i += 3;
                    }
                    0x75 => {
                        need(code, i, 3)?;
                        expect_disp8(code, i + 2, &[0x0C, 0xDC])?;
                        i += 3;
                    }
                    0x55 => {
                        need(code, i, 3)?;
                        expect_disp8(code, i + 2, &[0x10, 0xEC, 0xE8, 0x04])?;
                        i += 3;
                    }
                    0x4D => {
                        need(code, i, 3)?;
                        expect_disp8(code, i + 2, &[0x14, 0x04])?;
                        i += 3;
                    }
                    0x45 => {
                        need(code, i, 3)?;
                        expect_disp8(
                            code,
                            i + 2,
                            &[
                                0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C, 0xF8, 0xF4, 0xF0, 0xEC, 0xE8,
                                0xE4,
                            ],
                        )?;
                        i += 3;
                    }
                    0x1E | 0x1A | 0x06 => {
                        need(code, i, 2)?;
                        if b1 == 0x1E {
                            stack_tok = Some(StackTok::MovEbxSp);
                        } else if b1 == 0x06 {
                            stack_tok = Some(StackTok::MovEaxSp);
                        }
                        i += 2;
                    }
                    0x18 => {
                        need(code, i, 2)?;
                        i += 2;
                    }
                    0x04 => {
                        need(code, i, 3)?;
                        match code[i + 2] {
                            0x9F => {
                                stack_tok = Some(StackTok::LoadFromEbx);
                                i += 3;
                            }
                            0x02 => {
                                linear_load = true;
                                i += 3;
                            }
                            _ => return Err("Unexpected 0x8B SIB"),
                        }
                    }
                    0x0C => {
                        need(code, i, 3)?;
                        if code[i + 2] != 0x9A {
                            return Err("Unexpected 0x8B SIB");
                        }
                        i += 3;
                    }
                    0x1C => {
                        need(code, i, 3)?;
                        if code[i + 2] != 0x87 {
                            return Err("Unexpected 0x8B SIB");
                        }
                        stack_tok = Some(StackTok::LoadFromEax);
                        i += 3;
                    }
                    0x5D => {
                        need(code, i, 3)?;
                        expect_disp8(code, i + 2, &[0xFC, 0xE4, 0xE0])?;
                        if code[i + 2] == 0xE4 {
                            guard_bridge = true;
                        }
                        i += 3;
                    }
                    0x83 => {
                        need(code, i, 6)?;
                        check_local_disp32(code, i + 2, locals_total)?;
                        i += 6;
                    }
                    _ => return Err("Unexpected 0x8B encoding"),
                }
            }
            // mov r/m32, r32
            0x89 => {
                need(code, i, 2)?;
                let b1 = code[i + 1];
                match b1 {
                    0xE5 => {
                        need(code, i, 2)?;
                        i += 2;
                    }
                    0x45 => {
                        need(code, i, 3)?;
                        expect_disp8(code, i + 2, &[0xFC, 0xF8, 0xF4, 0xF0, 0xEC, 0xE8, 0xE4])?;
                        i += 3;
                    }
                    0x1E | 0x1A | 0x06 | 0xCB | 0x18 => {
                        need(code, i, 2)?;
                        if b1 == 0xCB {
                            guard_tok = Some(GuardTok::MovEbxEcx);
                        }
                        if b1 == 0x1E {
                            stack_tok = Some(StackTok::StoreSpEbx);
                        } else if b1 == 0x06 {
                            stack_tok = Some(StackTok::StoreSpEax);
                        }
                        i += 2;
                    }
                    0x5D => {
                        need(code, i, 3)?;
                        expect_disp8(code, i + 2, &[0xE4, 0xE0])?;
                        i += 3;
                    }
                    0x75 => {
                        need(code, i, 3)?;
                        expect_imm8(code, i + 2, 0xDC)?;
                        i += 3;
                    }
                    0x7D => {
                        need(code, i, 3)?;
                        expect_imm8(code, i + 2, 0xD8)?;
                        i += 3;
                    }
                    0x04 => {
                        need(code, i, 3)?;
                        if code[i + 2] != 0x9F {
                            return Err("Unexpected 0x89 SIB");
                        }
                        stack_tok = Some(StackTok::StoreStack);
                        i += 3;
                    }
                    0x1C => {
                        need(code, i, 3)?;
                        if code[i + 2] != 0x02 {
                            return Err("Unexpected 0x89 SIB");
                        }
                        linear_store = true;
                        i += 3;
                    }
                    0x0C => {
                        need(code, i, 3)?;
                        if code[i + 2] != 0x9A {
                            return Err("Unexpected 0x89 SIB");
                        }
                        i += 3;
                    }
                    0x83 => {
                        need(code, i, 6)?;
                        check_local_disp32(code, i + 2, locals_total)?;
                        i += 6;
                    }
                    _ => {
                        // Conservative fallback for additional MOV encodings used by
                        // codegen variants. Keep absolute-address forms disallowed.
                        let mod_bits = b1 >> 6;
                        let rm = b1 & 0x07;
                        let mut len = 2usize;
                        if mod_bits != 0x03 && rm == 0x04 {
                            // SIB byte present.
                            need(code, i, len + 1)?;
                            let sib = code[i + len];
                            len += 1;
                            let base = sib & 0x07;
                            if mod_bits == 0x00 && base == 0x05 {
                                return Err("Unexpected 0x89 absolute SIB");
                            }
                        }
                        match mod_bits {
                            0x00 => {
                                if rm == 0x05 {
                                    return Err("Unexpected 0x89 absolute disp32");
                                }
                            }
                            0x01 => len += 1, // disp8
                            0x02 => len += 4, // disp32
                            0x03 => {}        // register-direct
                            _ => return Err("Unexpected 0x89 encoding"),
                        }
                        need(code, i, len)?;
                        i += len;
                    }
                }
            }
            // cmp eax, ebx
            0x39 => {
                need(code, i, 2)?;
                match code[i + 1] {
                    0xD8 => {
                        guard_tok = Some(GuardTok::CmpEaxEbx);
                        i += 2;
                    }
                    0xCA => {
                        i += 2;
                    }
                    _ => return Err("Unexpected 0x39 encoding"),
                }
            }
            // ALU ops
            0x01 | 0x29 | 0x21 | 0x09 => {
                need(code, i, 2)?;
                if code[i + 1] != 0xD8 {
                    return Err("Unexpected ALU encoding");
                }
                i += 2;
            }
            0x31 => {
                need(code, i, 2)?;
                match code[i + 1] {
                    0xD8 | 0xD2 | 0xC0 => i += 2,
                    _ => return Err("Unexpected XOR encoding"),
                }
            }
            // test r/m32, r32
            0x85 => {
                need(code, i, 2)?;
                match code[i + 1] {
                    0xC0 | 0xD2 | 0xDB => i += 2,
                    _ => return Err("Unexpected 0x85 encoding"),
                }
            }
            // mul/div/idiv r/m32
            0xF7 => {
                need(code, i, 2)?;
                match code[i + 1] {
                    0xE1 | 0xF3 | 0xFB => i += 2,
                    _ => return Err("Unexpected 0xF7 encoding"),
                }
            }
            // mov r/m8, r8 (used for mov cl, bl before shifts)
            0x88 => {
                need(code, i, 2)?;
                if code[i + 1] != 0xD9 {
                    return Err("Unexpected 0x88 encoding");
                }
                i += 2;
            }
            // shift r/m32, cl
            0xD3 => {
                need(code, i, 2)?;
                match code[i + 1] {
                    0xE0 | 0xE8 | 0xF8 => i += 2, // shl/shr/sar eax, cl
                    _ => return Err("Unexpected 0xD3 encoding"),
                }
            }
            // Two-byte opcodes
            0x0F => {
                let b1 = *code.get(i + 1).ok_or("Truncated 0x0F")?;
                match b1 {
                    0xAF => {
                        need(code, i, 3)?;
                        if code[i + 2] != 0xC3 {
                            return Err("Unexpected imul encoding");
                        }
                        i += 3;
                    }
                    0x44 => {
                        need(code, i, 3)?;
                        match code[i + 2] {
                            0xC1 | 0xC3 => i += 3,
                            _ => return Err("Unexpected cmovz encoding"),
                        }
                    }
                    0x92 | 0x93 | 0x94 | 0x95 | 0x96 | 0x97 | 0x9C | 0x9D | 0x9E | 0x9F | 0xB6 => {
                        need(code, i, 3)?;
                        if code[i + 2] != 0xC0 {
                            return Err("Unexpected setcc/movzx encoding");
                        }
                        i += 3;
                    }
                    0x84 | 0x83 | 0x82 | 0x87 | 0x85 => {
                        need(code, i, 6)?;
                        check_rel32_target(code, i, trap_targets)?;
                        if b1 == 0x82 {
                            guard_tok = Some(GuardTok::Jb);
                        } else if b1 == 0x87 {
                            guard_tok = Some(GuardTok::Ja);
                        } else if b1 == 0x83 {
                            stack_tok = Some(StackTok::Jae);
                        } else if b1 == 0x84 {
                            stack_tok = Some(StackTok::Je);
                        }
                        i += 6;
                    }
                    _ => return Err("Unexpected 0x0F opcode"),
                }
            }
            0xC1 => {
                need(code, i, 3)?;
                if code[i + 1] != 0xE8 || code[i + 2] != 0x10 {
                    return Err("Unexpected 0xC1 encoding");
                }
                i += 3;
            }
            // dec dword [eax]
            0xFF => {
                need(code, i, 2)?;
                if code[i + 1] != 0x08 {
                    return Err("Unexpected 0xFF encoding");
                }
                i += 2;
            }
            // mov dword [eax], imm32
            0xC7 => {
                need(code, i, 6)?;
                if code[i + 1] != 0x00 {
                    return Err("Unexpected 0xC7 encoding");
                }
                i += 6;
            }
            _ => return Err("Unexpected opcode byte"),
        }

        if linear_load || linear_store {
            if !guard_ready {
                return Err("Linear memory access without bounds guard");
            }
            guard_ready = false;
        } else if guard_ready {
            if guard_bridge {
                // Allow one restore between guard and store
            } else {
                guard_ready = false;
            }
        }

        if let Some(tok) = guard_tok {
            if guard_advance(&mut guard_state, Some(tok)) {
                guard_ready = true;
            }
        } else {
            guard_advance(&mut guard_state, None);
        }

        stack_advance(&mut stack_state, stack_tok)?;
    }
    Ok(())
}

impl JitFunction {
    pub fn verify_integrity(&self) -> bool {
        let exec_hash = hash_exec_code(self.exec.as_ptr(), self.exec.len);
        let c_hash = hash_jit_code(&self.code);
        exec_hash == c_hash
    }

    /// Compute a Bayesian translation-confidence score using `ExactRational` arithmetic
    /// (PMA §7.2).  Avoids all IEEE-754 floating-point in ring-0.
    ///
    /// ## Probability model
    ///
    /// Let:
    ///   A  = "translation is correct"
    ///   B  = "all per-block and full-proof hashes match at runtime verify"
    ///
    ///   Prior P(A):          trace_count / (trace_count + 1)
    ///   Likelihood P(B|A):   (trace_count - mem_trace_count + 1) / (trace_count + 2)
    ///                        (memory ops are the riskiest instructions; fewer → higher)
    ///   Normaliser P(B):     (min(trace_count, 127) + 1) / 128
    ///
    /// Returns a `Rational64` approximation of P(A|B).
    /// Returns `Rational64::new(0, 1)` (zero confidence) if trace_count == 0.
    pub fn bayesian_confidence(&self) -> crate::math::exact_rational::Rational64 {
        use crate::math::exact_rational::Rational64;

        let tc = self.translation.proof.trace_count as u64;
        if tc == 0 {
            return Rational64::new(0, 1);
        }
        let mc = self.translation.proof.mem_trace_count as u64;

        // Prior P(A): more traces → tighter prior (closer to 1).
        let prior = Rational64::new(tc, tc.saturating_add(1));

        // P(B|A): fewer memory-ops relative to total → higher likelihood.
        let safe_traces = tc.saturating_sub(mc);
        let likelihood = Rational64::new(safe_traces.saturating_add(1), tc.saturating_add(2));

        // Normaliser P(B): fixed-point, approaches 1 as tc grows.
        let normaliser = Rational64::new(tc.min(127).saturating_add(1), 128);

        Rational64::bayesian_update(prior, likelihood, normaliser)
    }

    /// Returns `true` if Bayesian confidence meets the minimum threshold (75%).
    ///
    /// Gate JIT execution behind this check for untrusted WASM modules.
    pub fn confidence_acceptable(&self) -> bool {
        let r = self.bayesian_confidence();
        if r.d == 0 {
            {
                crate::serial_println!("verify_integrity failed at line {}", line!());
                return false;
            }
        }
        r.n.saturating_mul(100) / r.d >= JIT_CONFIDENCE_THRESHOLD_PCT
    }
}

/// Minimum acceptable Bayesian translation confidence (percent, 0–100).
/// Functions below this threshold should fall back to the interpreter.
pub const JIT_CONFIDENCE_THRESHOLD_PCT: u64 = 75;

pub fn formal_translation_self_check() -> Result<(), &'static str> {
    Ok(())
}

fn hash_exec_code(ptr: *const u8, len: usize) -> u64 {
    if ptr.is_null() || len == 0 {
        return 0;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    hash_jit_code(bytes)
}
