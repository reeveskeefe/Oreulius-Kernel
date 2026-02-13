//! Minimal WASM JIT compiler (ELF-less, in-kernel).
//!
//! Supports a small subset of opcodes and translates to 32-bit x86 machine code.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use crate::wasm::Opcode;

pub type JitFn = unsafe extern "C" fn(*mut i32, *mut usize, *mut u8, usize, *mut i32) -> i32;

#[derive(Clone, Copy, Debug)]
pub struct BasicBlock {
    pub start: usize,
    pub end: usize,
}

pub struct JitFunction {
    pub code: Vec<u8>,
    pub entry: JitFn,
    pub blocks: Vec<BasicBlock>,
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

pub fn compile(code: &[u8]) -> Result<JitFunction, &'static str> {
    let blocks = analyze_basic_blocks(code);
    let mut emitter = Emitter::new();
    emitter.emit_prologue();

    let mut pc = 0usize;
    while pc < code.len() {
        let op = code[pc];
        pc += 1;
        let opcode = Opcode::from_byte(op).ok_or("Unsupported opcode")?;
        match opcode {
            Opcode::Nop => {}
            Opcode::End | Opcode::Return => break,
            Opcode::Drop => {
                emitter.emit_pop_discard();
            }
            Opcode::I32Const => {
                let (imm, n) = read_sleb128_i32(code, pc).ok_or("Bad const")?;
                pc += n;
                emitter.emit_i32_const(imm);
            }
            Opcode::I32Add => emitter.emit_i32_add(),
            Opcode::I32Sub => emitter.emit_i32_sub(),
            Opcode::I32Mul => emitter.emit_i32_mul(),
            Opcode::I32DivS => return Err("i32.div_s not supported by JIT"),
            Opcode::I32And => emitter.emit_i32_and(),
            Opcode::I32Or => emitter.emit_i32_or(),
            Opcode::I32Xor => emitter.emit_i32_xor(),
            Opcode::I32Eq => emitter.emit_i32_eq(),
            Opcode::I32Ne => emitter.emit_i32_ne(),
            Opcode::I32Eqz => emitter.emit_i32_eqz(),
            Opcode::I32LtS => emitter.emit_i32_lts(),
            Opcode::I32GtS => emitter.emit_i32_gts(),
            Opcode::I32LeS => emitter.emit_i32_les(),
            Opcode::I32GeS => emitter.emit_i32_ges(),
            Opcode::LocalGet => {
                let (idx, n) = read_uleb128(code, pc).ok_or("Bad local")?;
                pc += n;
                emitter.emit_local_get(idx as i32);
            }
            Opcode::LocalSet => {
                let (idx, n) = read_uleb128(code, pc).ok_or("Bad local")?;
                pc += n;
                emitter.emit_local_set(idx as i32);
            }
            Opcode::LocalTee => {
                let (idx, n) = read_uleb128(code, pc).ok_or("Bad local")?;
                pc += n;
                emitter.emit_local_tee(idx as i32);
            }
            Opcode::I32Load => {
                let (_align, n1) = read_uleb128(code, pc).ok_or("Bad load")?;
                pc += n1;
                let (off, n2) = read_uleb128(code, pc).ok_or("Bad load")?;
                pc += n2;
                emitter.emit_i32_load(off as i32);
            }
            Opcode::I32Store => {
                let (_align, n1) = read_uleb128(code, pc).ok_or("Bad store")?;
                pc += n1;
                let (off, n2) = read_uleb128(code, pc).ok_or("Bad store")?;
                pc += n2;
                emitter.emit_i32_store(off as i32);
            }
            Opcode::If | Opcode::Else | Opcode::Br | Opcode::BrIf => {
                return Err("Control flow not supported by JIT");
            }
            _ => return Err("Opcode not supported by JIT"),
        }
    }

    let trap_pos = emitter.emit_trap();
    let ret_pos = emitter.emit_epilogue();
    emitter.patch_traps(trap_pos, ret_pos);

    let entry = unsafe { core::mem::transmute::<*const u8, JitFn>(emitter.code.as_ptr()) };
    Ok(JitFunction {
        code: emitter.code,
        entry,
        blocks,
    })
}

// ============================================================================
// Machine Code Emitter (x86 32-bit)
// ============================================================================

struct Emitter {
    code: Vec<u8>,
    trap_jumps: Vec<usize>,
}

impl Emitter {
    fn new() -> Self {
        Emitter {
            code: Vec::new(),
            trap_jumps: Vec::new(),
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
        // sub esp, 4
        self.emit(&[0x83, 0xEC, 0x04]);
        // mov [ebp-4], eax (locals pointer)
        self.emit(&[0x89, 0x45, 0xFC]);
    }

    fn emit_pop_to_eax(&mut self) {
        // mov ebx, [esi]
        self.emit(&[0x8B, 0x1E]);
        // dec ebx
        self.emit(&[0x4B]);
        // mov eax, [edi + ebx*4]
        self.emit(&[0x8B, 0x04, 0x9F]);
        // mov [esi], ebx
        self.emit(&[0x89, 0x1E]);
    }

    fn emit_pop_to_ebx(&mut self) {
        // mov eax, [esi]
        self.emit(&[0x8B, 0x06]);
        // dec eax
        self.emit(&[0x48]);
        // mov ebx, [edi + eax*4]
        self.emit(&[0x8B, 0x1C, 0x87]);
        // mov [esi], eax
        self.emit(&[0x89, 0x06]);
    }

    fn emit_push_eax(&mut self) {
        // mov ebx, [esi]
        self.emit(&[0x8B, 0x1E]);
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

    fn emit_bounds_check(&mut self, off: i32) {
        // eax = addr, ecx = mem_len
        // add eax, off
        if off != 0 {
            self.emit(&[0x05]);
            self.emit_i32(off);
        }
        // mov ebx, eax
        self.emit(&[0x89, 0xC3]);
        // add ebx, 4
        self.emit(&[0x83, 0xC3, 0x04]);
        // cmp ebx, ecx
        self.emit(&[0x39, 0xCB]);
        // ja trap (rel8)
        self.emit(&[0x77, 0x00]);
        self.trap_jumps.push(self.code.len() - 1);
    }

    fn emit_i32_load(&mut self, off: i32) {
        self.emit_pop_to_eax();
        self.emit_bounds_check(off);
        // mov eax, [edx + eax]
        self.emit(&[0x8B, 0x04, 0x02]);
        self.emit_push_eax();
    }

    fn emit_local_get(&mut self, idx: i32) {
        // mov ebx, [ebp-4]
        self.emit(&[0x8B, 0x5D, 0xFC]);
        // mov eax, [ebx + disp32]
        self.emit(&[0x8B, 0x83]);
        self.emit_i32(idx * 4);
        self.emit_push_eax();
    }

    fn emit_local_set(&mut self, idx: i32) {
        // pop value -> eax
        self.emit_pop_to_eax();
        // mov ebx, [ebp-4]
        self.emit(&[0x8B, 0x5D, 0xFC]);
        // mov [ebx + idx*4], eax
        self.emit(&[0x89, 0x83]);
        self.emit_i32(idx * 4);
    }

    fn emit_local_tee(&mut self, idx: i32) {
        // pop value -> eax
        self.emit_pop_to_eax();
        // mov ebx, [ebp-4]
        self.emit(&[0x8B, 0x5D, 0xFC]);
        // mov [ebx + idx*4], eax
        self.emit(&[0x89, 0x83]);
        self.emit_i32(idx * 4);
        self.emit_push_eax();
    }

    fn emit_i32_store(&mut self, off: i32) {
        // pop addr -> eax
        self.emit_pop_to_eax();
        // push eax (save addr)
        self.emit(&[0x50]);
        // pop value -> ebx
        self.emit_pop_to_ebx();
        // pop eax (restore addr)
        self.emit(&[0x58]);
        // push ebx (save value)
        self.emit(&[0x53]);
        // bounds check using ebx temp
        // mov ebx, eax
        self.emit(&[0x89, 0xC3]);
        if off != 0 {
            // add ebx, imm32
            self.emit(&[0x81, 0xC3]);
            self.emit_i32(off);
        }
        // add ebx, 4
        self.emit(&[0x83, 0xC3, 0x04]);
        // cmp ebx, ecx
        self.emit(&[0x39, 0xCB]);
        // ja trap
        self.emit(&[0x77, 0x00]);
        self.trap_jumps.push(self.code.len() - 1);
        // pop ebx (restore value)
        self.emit(&[0x5B]);
        // add eax, off
        if off != 0 {
            self.emit(&[0x05]);
            self.emit_i32(off);
        }
        // mov [edx + eax], ebx
        self.emit(&[0x89, 0x1C, 0x02]);
    }

    fn emit_trap(&mut self) -> usize {
        let pos = self.code.len();
        // mov eax, 0xFFFFFFFF
        self.emit(&[0xB8]);
        self.emit_u32(0xFFFF_FFFF);
        pos
    }

    fn emit_epilogue(&mut self) -> usize {
        let pos = self.code.len();
        // add esp, 4
        self.emit(&[0x83, 0xC4, 0x04]);
        // mov ebx, [esi]
        self.emit(&[0x8B, 0x1E]);
        // cmp ebx, 0
        self.emit(&[0x83, 0xFB, 0x00]);
        // je +6
        self.emit(&[0x74, 0x06]);
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
        // pop ebp; ret
        self.emit(&[0x5D, 0xC3]);
        pos
    }

    fn patch_traps(&mut self, trap_pos: usize, _ret_pos: usize) {
        for &idx in &self.trap_jumps {
            let rel = (trap_pos as isize - (idx as isize + 1)) as i8;
            self.code[idx] = rel as u8;
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
