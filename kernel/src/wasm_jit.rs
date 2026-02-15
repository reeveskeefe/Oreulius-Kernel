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
 */


//! Minimal WASM JIT compiler (ELF-less, in-kernel).
//!
//! Supports a small subset of opcodes and translates to 32-bit x86 machine code.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use crate::wasm::{Opcode, MAX_STACK_DEPTH, MAX_INSTRUCTIONS_PER_CALL, MAX_LOCALS};
use crate::{memory, paging};

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
    pub code: Vec<u8>,
    pub entry: JitFn,
    pub blocks: Vec<BasicBlock>,
    pub code_hash: u64,
    pub exec: JitExecBuffer,
    pub exec_hash: u64,
}

// SAFETY: JitFunction is safe to send/sync because all components are:
// - Vec<u8> (Send + Sync)
// - JitFn (function pointer, Send + Sync)
// - Vec<BasicBlock> (Send + Sync)
// - u64 fields (Copy, Send + Sync)
// - JitExecBuffer (now explicitly Send + Sync, see above)
unsafe impl Send for JitFunction {}
unsafe impl Sync for JitFunction {}

pub struct JitExecBuffer {
    pub ptr: *mut u8,
    pub len: usize,
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

impl JitExecBuffer {
    pub fn new(len: usize) -> Result<Self, &'static str> {
        let pages = len
            .checked_add(paging::PAGE_SIZE - 1)
            .ok_or("Size overflow")?
            / paging::PAGE_SIZE;
        let base = memory::jit_allocate_pages(pages)?;
        Ok(JitExecBuffer {
            ptr: base as *mut u8,
            len,
            sealed: false,
        })
    }

    fn write_and_seal(&mut self, code: &[u8]) -> Result<(), &'static str> {
        if code.len() > self.len {
            return Err("Code length overflow");
        }
        // Ensure writable during copy
        paging::set_page_writable_range(self.ptr as usize, self.len, true)?;
        unsafe {
            core::ptr::copy_nonoverlapping(code.as_ptr(), self.ptr, code.len());
        }
        // Seal pages (read-only policy)
        paging::set_page_writable_range(self.ptr as usize, self.len, false)?;
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

pub fn analyze_basic_blocks(code: &[u8]) -> Vec<BasicBlock> {
    let mut blocks = Vec::new();
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
            Some(Opcode::I32Load) | Some(Opcode::I32Store) => {
                let (_align, n1) = read_uleb128(code, pc).unwrap_or((0, 0));
                pc += n1;
                let (_off, n2) = read_uleb128(code, pc).unwrap_or((0, 0));
                pc += n2;
            }
            Some(Opcode::Return) | Some(Opcode::End) | Some(Opcode::Br) | Some(Opcode::BrIf) => {
                blocks.push(BasicBlock { start, end: pc });
                start = pc;
            }
            Some(_) => {}
            None => break,
        }
    }
    if start < code.len() {
        blocks.push(BasicBlock { start, end: code.len() });
    }
    blocks
}

fn emit_code(code: &[u8], locals_total: usize, emitter: &mut Emitter) -> Result<(), &'static str> {
    if locals_total > MAX_LOCALS {
        return Err("Too many locals");
    }
    emitter.reset();
    emitter.emit_prologue();

    let mut pc = 0usize;
    let mut stack_depth: i32 = 0;
    let mut max_depth: i32 = 0;
    let mut instr_count: usize = 0;
    while pc < code.len() {
        let op = code[pc];
        pc += 1;
        let opcode = Opcode::from_byte(op).ok_or("Unsupported opcode")?;
        instr_count = instr_count.saturating_add(1);
        if instr_count > MAX_INSTRUCTIONS_PER_CALL {
            return Err("JIT function too large");
        }
        match opcode {
            Opcode::Nop => {
                emitter.emit_instr_fuel_check();
            }
            Opcode::End | Opcode::Return => {
                emitter.emit_instr_fuel_check();
                break;
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
            Opcode::I32DivS => return Err("i32.div_s not supported by JIT"),
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
            Opcode::If | Opcode::Else | Opcode::Br | Opcode::BrIf => {
                return Err("Control flow not supported by JIT");
            }
            _ => return Err("Opcode not supported by JIT"),
        }
    }

    let _ret_pos = emitter.emit_epilogue();
    let trap_mem_pos = emitter.emit_trap_stub(TRAP_MEM);
    let trap_fuel_pos = emitter.emit_trap_stub(TRAP_FUEL);
    let trap_stack_pos = emitter.emit_trap_stub(TRAP_STACK);
    let trap_cfi_pos = emitter.emit_trap_stub(TRAP_CFI);
    emitter.patch_traps(trap_mem_pos, trap_fuel_pos, trap_stack_pos, trap_cfi_pos);

    verify_x86_subset(&emitter.code, locals_total)?;
    Ok(())
}

pub fn compile(code: &[u8], locals_total: usize) -> Result<JitFunction, &'static str> {
    let blocks = analyze_basic_blocks(code);
    let mut emitter = Emitter::new();
    emit_code(code, locals_total, &mut emitter)?;

    let mut exec = JitExecBuffer::new(emitter.code.len())?;
    exec.write_and_seal(&emitter.code)?;

    let entry = unsafe { core::mem::transmute::<*const u8, JitFn>(exec.as_ptr()) };
    let code_hash = hash_jit_code(&emitter.code);
    let exec_hash = hash_exec_code(exec.as_ptr(), exec.len);
    Ok(JitFunction {
        code: emitter.code,
        entry,
        blocks,
        code_hash,
        exec,
        exec_hash,
    })
}

/// Reusable JIT compiler for fuzzing (avoids per-iteration allocations).
pub struct FuzzCompiler {
    emitter: Emitter,
    exec: JitExecBuffer,
}

impl FuzzCompiler {
    pub fn new(max_code_size: usize) -> Result<Self, &'static str> {
        let mut emitter = Emitter::new();
        emitter.reserve(max_code_size, 128);
        let exec = JitExecBuffer::new(max_code_size)?;
        Ok(FuzzCompiler { emitter, exec })
    }

    pub fn compile(&mut self, code: &[u8], locals_total: usize) -> Result<JitFn, &'static str> {
        emit_code(code, locals_total, &mut self.emitter)?;
        if self.emitter.code.len() > self.exec.len {
            return Err("JIT code too large for fuzz buffer");
        }
        self.exec.write_and_seal(&self.emitter.code)?;
        let entry = unsafe { core::mem::transmute::<*const u8, JitFn>(self.exec.as_ptr()) };
        Ok(entry)
    }

    pub fn exec_ptr(&self) -> *mut u8 {
        self.exec.ptr
    }

    pub fn exec_len(&self) -> usize {
        self.exec.len
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
        // pop addr -> eax
        self.emit_pop_to_eax();
        // pop value -> ebx
        self.emit_pop_to_ebx();
        // mov [ebp-28], ebx (save value)
        self.emit(&[0x89, 0x5D, 0xE4]);
        // bounds check using ebx temp
        self.emit_bounds_check(off, 4);
        // mov ebx, [ebp-28] (restore value)
        self.emit(&[0x8B, 0x5D, 0xE4]);
        // mov [edx + eax], ebx
        self.emit(&[0x89, 0x1C, 0x02]);
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

    fn emit_trap_stub(&mut self, code: i32) -> usize {
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
    ) {
        for &idx in &self.trap_mem_jumps {
            let next = idx + 4;
            let rel = (trap_mem_pos as isize - next as isize) as i32;
            self.code[idx..idx + 4].copy_from_slice(&rel.to_le_bytes());
        }
        for &idx in &self.trap_fuel_jumps {
            let next = idx + 4;
            let rel = (trap_fuel_pos as isize - next as isize) as i32;
            self.code[idx..idx + 4].copy_from_slice(&rel.to_le_bytes());
        }
        for &idx in &self.trap_stack_jumps {
            let next = idx + 4;
            let rel = (trap_stack_pos as isize - next as isize) as i32;
            self.code[idx..idx + 4].copy_from_slice(&rel.to_le_bytes());
        }
        for &idx in &self.trap_cfi_jumps {
            let next = idx + 4;
            let rel = (trap_cfi_pos as isize - next as isize) as i32;
            self.code[idx..idx + 4].copy_from_slice(&rel.to_le_bytes());
        }
    }
}

// ============================================================================
// LEB128 helpers
// ============================================================================

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

fn verify_x86_subset(code: &[u8], locals_total: usize) -> Result<(), &'static str> {
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
                            &[0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C, 0xF8, 0xF4, 0xF0, 0xEC, 0xE8, 0xE4],
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
                let b1 = *code.get(i + 1).ok_or("Truncated 0x89")?;
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
                    _ => return Err("Unexpected 0x89 encoding"),
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
                    0x94 | 0x95 | 0x9C | 0x9F | 0x9E | 0x9D | 0xB6 => {
                        need(code, i, 3)?;
                        if code[i + 2] != 0xC0 {
                            return Err("Unexpected setcc/movzx encoding");
                        }
                        i += 3;
                    }
                    0x84 | 0x83 | 0x82 | 0x87 | 0x85 => {
                        need(code, i, 6)?;
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
        let exec_hash = hash_exec_code(self.exec.as_ptr(), self.exec.len);
        self.exec_hash == exec_hash && self.code_hash == hash_jit_code(&self.code)
    }
}

fn hash_exec_code(ptr: *const u8, len: usize) -> u64 {
    if ptr.is_null() || len == 0 {
        return 0;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    hash_jit_code(bytes)
}
