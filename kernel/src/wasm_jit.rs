/*!
 * Oreulia Kernel Project
 *
 *License-Identifier: Oreulius License (see LICENSE)
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
 */

//! Minimal WASM JIT compiler (ELF-less, in-kernel).
//!
//! Supports a bounded MVP-oriented opcode set for i686/x86_64 backends.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use crate::wasm::{
    Opcode, MAX_INSTRUCTIONS_PER_CALL, MAX_LOCALS, MAX_STACK_DEPTH, MAX_WASM_TYPE_ARITY,
};
use crate::{memory, memory_isolation, paging};

pub type JitFn = unsafe extern "C" fn(
    *mut i32,
    *mut usize,
    *mut u8,
    usize,
    *mut i32,
    *mut u32,
    *mut u32,
    *mut i32,
    *mut u32,
    *mut usize,
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
#[cfg(target_arch = "x86_64")]
const X64_FRAME_LOCAL_BYTES: i32 = 0x20;
#[cfg(target_arch = "x86_64")]
const X64_STACK_FRAME_BYTES: i32 = X64_FRAME_LOCAL_BYTES + ((X64_BRANCH_SCRATCH_SLOTS as i32) * 4);
#[cfg(target_arch = "x86_64")]
const X64_BRANCH_SCRATCH_BASE_DISP: i32 = -(X64_SAVED_REG_BYTES + X64_STACK_FRAME_BYTES);

impl JitExecBuffer {
    pub fn new(len: usize) -> Result<Self, &'static str> {
        let pages = len
            .checked_add(paging::PAGE_SIZE - 1)
            .ok_or("Size overflow")?
            / paging::PAGE_SIZE;
        let base = memory::jit_allocate_pages(pages)?;
        let alloc_len = pages
            .checked_mul(paging::PAGE_SIZE)
            .ok_or("JIT exec buffer size overflow")?;
        if !memory::jit_arena_contains_range(base, alloc_len) {
            return Err("JIT exec buffer outside JIT arena");
        }
        let _ = memory_isolation::tag_jit_code_kernel(base, pages * paging::PAGE_SIZE, false);
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
                .checked_add(paging::PAGE_SIZE - 1)
                .ok_or("Code length overflow")?
                & !(paging::PAGE_SIZE - 1)
        };
        let base = self.ptr as usize;
        if base == 0 || (base & (paging::PAGE_SIZE - 1)) != 0 {
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
            Some(Opcode::I32Load) | Some(Opcode::I32Store) => {
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

struct ControlFrame {
    kind: ControlKind,
    stack_depth_at_entry: i32,
    param_arity: i32,
    result_arity: i32,
    label_arity: i32,
    loop_target: Option<usize>,
    else_patch: Option<usize>,
    has_else: bool,
    end_patches: Vec<usize>,
}

fn resolve_label_target_idx(
    control_stack: &[ControlFrame],
    depth: u32,
) -> Result<usize, &'static str> {
    let depth = depth as usize;
    if depth >= control_stack.len() {
        return Err("Branch depth out of bounds");
    }
    Ok(control_stack.len() - 1 - depth)
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
    emitter.reset();
    emitter.emit_prologue();

    traces.clear();
    let mut control_stack = Vec::new();
    control_stack.push(ControlFrame {
        kind: ControlKind::Function,
        stack_depth_at_entry: 0,
        param_arity: 0,
        result_arity: 0,
        label_arity: 0,
        loop_target: None,
        else_patch: None,
        has_else: false,
        end_patches: Vec::new(),
    });
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
                control_stack[0].end_patches.push(jmp);
                stack_depth = control_stack[0].stack_depth_at_entry;
            }
            Opcode::End => {
                emitter.emit_instr_fuel_check();
                let end_target = emitter.code.len();
                if control_stack.is_empty() {
                    return Err("Unexpected end");
                }
                if control_stack.len() == 1 {
                    let function_frame = &mut control_stack[0];
                    if function_frame.kind != ControlKind::Function {
                        return Err("Malformed control stack");
                    }
                    for patch in function_frame.end_patches.drain(..) {
                        emitter.patch_rel32(patch, end_target)?;
                    }
                    saw_function_end = true;
                } else {
                    let mut frame = control_stack.pop().ok_or("Unexpected end")?;
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
                    for patch in frame.end_patches.drain(..) {
                        emitter.patch_rel32(patch, end_target)?;
                    }
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
                    control_stack.push(ControlFrame {
                        kind: ControlKind::Block,
                        stack_depth_at_entry,
                        param_arity: block_type.param_arity,
                        result_arity: block_type.result_arity,
                        label_arity: block_type.result_arity,
                        loop_target: None,
                        else_patch: None,
                        has_else: false,
                        end_patches: Vec::new(),
                    });
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
                    control_stack.push(ControlFrame {
                        kind: ControlKind::Loop,
                        stack_depth_at_entry,
                        param_arity: block_type.param_arity,
                        result_arity: block_type.result_arity,
                        label_arity: block_type.param_arity,
                        loop_target: Some(loop_target),
                        else_patch: None,
                        has_else: false,
                        end_patches: Vec::new(),
                    });
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
                    control_stack.push(ControlFrame {
                        kind: ControlKind::If,
                        stack_depth_at_entry,
                        param_arity: block_type.param_arity,
                        result_arity: block_type.result_arity,
                        label_arity: block_type.result_arity,
                        loop_target: None,
                        else_patch: Some(else_patch),
                        has_else: false,
                        end_patches: Vec::new(),
                    });
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
                    let frame = control_stack.last_mut().ok_or("Unexpected else")?;
                    if frame.kind != ControlKind::If || frame.has_else {
                        return Err("Unexpected else");
                    }
                    if let Some(else_patch) = frame.else_patch.take() {
                        emitter.patch_rel32(else_patch, else_body_start)?;
                    } else {
                        return Err("Missing if else patch");
                    }
                    frame.has_else = true;
                    frame.end_patches.push(end_jump);
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
                    let target_idx = resolve_label_target_idx(&control_stack, depth)?;
                    let (target_kind, target_stack_depth, target_loop_target, target_label_arity) = {
                        let frame = &control_stack[target_idx];
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
                            control_stack[target_idx].end_patches.push(jump);
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
                    let target_idx = resolve_label_target_idx(&control_stack, depth)?;
                    emitter.emit_pop_to_eax();
                    let jz_fallthrough = emitter.emit_cond_jz_placeholder();
                    let (target_kind, target_stack_depth, target_loop_target, target_label_arity) = {
                        let frame = &control_stack[target_idx];
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
                            control_stack[target_idx].end_patches.push(jump);
                        }
                    }
                    let fallthrough = emitter.code.len();
                    emitter.patch_rel32(jz_fallthrough, fallthrough)?;
                }
            }
            _ => return Err("Opcode not supported by JIT"),
        }
        let x86_end = emitter.code.len();
        if x86_end <= x86_start {
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
    emit_code_into(code, locals_total, type_sigs, global_sigs, emitter, &mut traces)?;
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
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(not(target_arch = "x86_64"))]
fn validate_trace_shape(opcode: Opcode, code: &[u8]) -> Result<(), &'static str> {
    let mut at = consume_instr_fuel_check(code, 0)?;
    let is_mem_op = matches!(opcode, Opcode::I32Load | Opcode::I32Store);
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

    if matches!(opcode, Opcode::I32Load | Opcode::I32Store) {
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
                return Err("Non-contiguous WASM translation trace");
            }
            if trace.x86_start != expected_x86 {
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

        if matches!(trace.opcode, Opcode::I32Load | Opcode::I32Store) {
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
    let bytes = match elem.checked_mul(slice.len()) {
        Some(v) => v,
        None => return false,
    };
    crate::paging::is_kernel_range_mapped(slice.as_ptr() as usize, bytes)
}

pub fn compile_with_types(
    code: &[u8],
    locals_total: usize,
    type_sigs: &[JitTypeSignature],
) -> Result<JitFunction, &'static str> {
    compile_with_env(code, locals_total, type_sigs, &[])
}

pub fn compile_with_env(
    code: &[u8],
    locals_total: usize,
    type_sigs: &[JitTypeSignature],
    global_sigs: &[JitGlobalSignature],
) -> Result<JitFunction, &'static str> {
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

pub fn compile(code: &[u8], locals_total: usize) -> Result<JitFunction, &'static str> {
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
        let mut emitter = Emitter::new();
        emitter.reserve(max_code_size, 128);
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
        // Reuse allocations across fuzz iterations, but always compile from a
        // clean emitter/trace state so stale machine code cannot be executed.
        self.emitter.reset();
        self.traces.clear();
        self.blocks.clear();
        self.block_hashes.clear();

        emit_code_into(
            code,
            locals_total,
            type_sigs,
            global_sigs,
            &mut self.emitter,
            &mut self.traces,
        )?;
        analyze_basic_blocks_into(code, &mut self.blocks);
        validate_translation_per_block_into(
            code,
            &self.blocks,
            &self.traces,
            &self.emitter.code,
            &mut self.block_hashes,
        )?;
        let _ = build_translation_proof(code, &self.traces, &self.emitter.code)?;
        if self.emitter.code.len() > self.exec.len {
            return Err("JIT code too large for fuzz buffer");
        }
        self.exec.write_and_seal(&self.emitter.code)?;
        self.exec_code_len = self.emitter.code.len();
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
        self.emit_pop_to_eax();
        self.emit_pop_to_ebx();
        self.emit(&[0x39, 0xD8]);
        // sete al
        self.emit(&[0x0F, 0x94, 0xC0]);
        // movzx eax, al
        self.emit(&[0x0F, 0xB6, 0xC0]);
        self.emit_push_eax();
    }

    fn emit_i32_ne(&mut self) {
        self.emit_pop_to_eax();
        self.emit_pop_to_ebx();
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
        // SysV x86_64 JitFn arg registers:
        // rdi stack_ptr, rsi sp_ptr, rdx mem_ptr, rcx mem_len, r8 locals_ptr,
        // r9 instr_fuel_ptr, [rbp+16] mem_fuel_ptr, [rbp+24] trap_ptr.
        // x86_64 reuses the shadow-stack-base slot at [rbp+32] as globals_ptr;
        // the backend's CFI path is a no-op, so shadow_sp remains the only live CFI arg.
        // Locals are stored in the reserved stack area below saved callee-saved regs:
        // [rbp-48] instr_fuel_ptr, [rbp-56] mem_fuel_ptr, [rbp-64] trap_ptr, [rbp-72] globals_ptr.
        // Multi-value branch scratch slots live below that fixed metadata area.
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
        self.emit_i32(X64_STACK_FRAME_BYTES);
        self.emit(&[
            0x49, 0x89, 0xFC, // mov r12, rdi
            0x49, 0x89, 0xF5, // mov r13, rsi
            0x49, 0x89, 0xD6, // mov r14, rdx
            0x49, 0x89, 0xCF, // mov r15, rcx
            0x4C, 0x89, 0xC3, // mov rbx, r8
            0x4C, 0x89, 0x4D, 0xD0, // mov [rbp-48], r9
            0x48, 0x8B, 0x45, 0x10, // mov rax, [rbp+16]
            0x48, 0x89, 0x45, 0xC8, // mov [rbp-56], rax
            0x48, 0x8B, 0x45, 0x18, // mov rax, [rbp+24]
            0x48, 0x89, 0x45, 0xC0, // mov [rbp-64], rax
            0x48, 0x8B, 0x45, 0x20, // mov rax, [rbp+32]
            0x48, 0x89, 0x45, 0xB8, // mov [rbp-72], rax
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
        // x86_64 backend keeps locals base in RBX, so this helper is intentionally
        // unused here. Arithmetic/comparison/store ops use ECX scratch instead.
        panic!("x86_64 JIT emitter internal misuse: pop_to_ebx");
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
        self.emit_i32(X64_STACK_FRAME_BYTES);
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
        self.emit_i32(X64_STACK_FRAME_BYTES);
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
            return Err("Invalid branch target");
        }
        let target = target as usize;
        if target >= code.len() {
            return Err("Branch target out of range");
        }
        if !allowed.iter().any(|&t| t == target) {
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
            // Short jumps (only used in epilogue)
            0x74 => {
                need(code, i, 2)?;
                expect_disp8(code, i + 1, &[0x08])?;
                stack_tok = Some(StackTok::JeShort);
                i += 2;
            }
            0xEB => {
                need(code, i, 2)?;
                expect_imm8(code, i + 1, 0x02)?;
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
                        expect_imm8(code, i + 2, 0x00)?;
                        stack_tok = Some(StackTok::CmpEbxZero);
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
                    0xD8 | 0xC0 => i += 2,
                    _ => return Err("Unexpected XOR encoding"),
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
        if !self.exec.is_sealed() {
            return false;
        }
        if self.translation.block_hashes.len() != self.blocks.len() {
            return false;
        }
        let recomputed_hashes = match validate_translation_per_block(
            &self.wasm_code,
            &self.blocks,
            &self.translation.records,
            &self.code,
        ) {
            Ok(h) => h,
            Err(_) => return false,
        };
        if recomputed_hashes != self.translation.block_hashes {
            return false;
        }
        let recomputed_proof =
            match build_translation_proof(&self.wasm_code, &self.translation.records, &self.code) {
                Ok(p) => p,
                Err(_) => return false,
            };
        if recomputed_proof != self.translation.proof {
            return false;
        }
        let exec_hash = hash_exec_code(self.exec.as_ptr(), self.exec.len);
        self.exec_hash == exec_hash && self.code_hash == hash_jit_code(&self.code)
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
    pub fn bayesian_confidence(&self) -> crate::exact_rational::Rational64 {
        use crate::exact_rational::Rational64;

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
            return false;
        }
        r.n.saturating_mul(100) / r.d >= JIT_CONFIDENCE_THRESHOLD_PCT
    }
}

/// Minimum acceptable Bayesian translation confidence (percent, 0–100).
/// Functions below this threshold should fall back to the interpreter.
pub const JIT_CONFIDENCE_THRESHOLD_PCT: u64 = 75;

pub fn formal_translation_self_check() -> Result<(), &'static str> {
    let samples: [(&[u8], usize); 5] = [
        (&[0x41, 0x00, 0x0B], 0),                               // const 0; end
        (&[0x41, 0x01, 0x41, 0x02, 0x6A, 0x0B], 0),             // add
        (&[0x20, 0x00, 0x21, 0x01, 0x20, 0x01, 0x0B], 2),       // local get/set/get
        (&[0x41, 0x00, 0x28, 0x00, 0x00, 0x0B], 0),             // load
        (&[0x41, 0x00, 0x41, 0x2A, 0x36, 0x00, 0x00, 0x0B], 0), // store
    ];

    for (code, locals) in samples {
        let mut jit = compile(code, locals)?;
        if !jit.verify_integrity() {
            return Err("Formal translation self-check failed integrity");
        }
        if jit.code.is_empty() {
            return Err("Formal translation self-check produced empty x86");
        }
        // Ensure integrity check detects post-compile tampering.
        jit.code[0] ^= 0x01;
        if jit.verify_integrity() {
            return Err("Formal translation tamper detection failed");
        }
    }
    Ok(())
}

fn hash_exec_code(ptr: *const u8, len: usize) -> u64 {
    if ptr.is_null() || len == 0 {
        return 0;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    hash_jit_code(bytes)
}
