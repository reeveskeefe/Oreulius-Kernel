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

use core::fmt;
use spin::Mutex;
use crate::ipc::{ProcessId, ChannelId};
use crate::fs;

// ============================================================================
// WASM Types & Constants
// ============================================================================

/// Maximum linear memory size (1 MiB for v0)
pub const MAX_MEMORY_SIZE: usize = 1024 * 1024;

/// Maximum stack depth
pub const MAX_STACK_DEPTH: usize = 1024;

/// Maximum number of local variables
pub const MAX_LOCALS: usize = 256;

/// Maximum number of injected capabilities
pub const MAX_INJECTED_CAPS: usize = 32;

/// Maximum module size (256 KiB)
pub const MAX_MODULE_SIZE: usize = 256 * 1024;

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

// ============================================================================
// Linear Memory
// ============================================================================

/// WASM linear memory (isolated per-module)
pub struct LinearMemory {
    /// Memory buffer
    data: [u8; MAX_MEMORY_SIZE],
    /// Current size in pages (64 KiB each)
    pages: usize,
    /// Maximum pages allowed
    max_pages: Option<usize>,
}

impl LinearMemory {
    /// Create new linear memory with initial size
    pub const fn new(initial_pages: usize) -> Self {
        LinearMemory {
            data: [0u8; MAX_MEMORY_SIZE],
            pages: initial_pages,
            max_pages: Some(MAX_MEMORY_SIZE / (64 * 1024)),
        }
    }

    /// Get current size in pages
    pub fn size(&self) -> usize {
        self.pages
    }

    /// Grow memory by delta pages
    pub fn grow(&mut self, delta: usize) -> Result<usize, WasmError> {
        let old_size = self.pages;
        let new_size = old_size + delta;

        if let Some(max) = self.max_pages {
            if new_size > max {
                return Err(WasmError::MemoryGrowFailed);
            }
        }

        if new_size * 64 * 1024 > MAX_MEMORY_SIZE {
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
        Ok(&self.data[offset..end])
    }

    /// Write bytes to memory
    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), WasmError> {
        let end = offset.checked_add(data.len()).ok_or(WasmError::MemoryOutOfBounds)?;
        if end > self.pages * 64 * 1024 {
            return Err(WasmError::MemoryOutOfBounds);
        }
        self.data[offset..end].copy_from_slice(data);
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

// ============================================================================
// Execution Stack
// ============================================================================

/// Value stack for WASM execution
pub struct Stack {
    values: [Value; MAX_STACK_DEPTH],
    top: usize,
}

impl Stack {
    pub const fn new() -> Self {
        Stack {
            values: [Value::I32(0); MAX_STACK_DEPTH],
            top: 0,
        }
    }

    pub fn push(&mut self, value: Value) -> Result<(), WasmError> {
        if self.top >= MAX_STACK_DEPTH {
            return Err(WasmError::StackOverflow);
        }
        self.values[self.top] = value;
        self.top += 1;
        Ok(())
    }

    pub fn pop(&mut self) -> Result<Value, WasmError> {
        if self.top == 0 {
            return Err(WasmError::StackUnderflow);
        }
        self.top -= 1;
        Ok(self.values[self.top])
    }

    pub fn peek(&self) -> Result<Value, WasmError> {
        if self.top == 0 {
            return Err(WasmError::StackUnderflow);
        }
        Ok(self.values[self.top - 1])
    }

    pub fn len(&self) -> usize {
        self.top
    }

    pub fn is_empty(&self) -> bool {
        self.top == 0
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
pub struct WasmModule {
    /// Module bytecode
    bytecode: [u8; MAX_MODULE_SIZE],
    /// Bytecode length
    bytecode_len: usize,
    /// Functions in the module
    functions: [Option<Function>; 64],
    /// Number of functions
    function_count: usize,
}

impl WasmModule {
    /// Create a new empty module
    pub const fn new() -> Self {
        WasmModule {
            bytecode: [0u8; MAX_MODULE_SIZE],
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

        self.bytecode[..bytecode.len()].copy_from_slice(bytecode);
        self.bytecode_len = bytecode.len();

        // For v0, we'll use a simplified function format
        // Real implementation would parse WASM binary format
        Ok(())
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
}

impl WasmInstance {
    /// Create a new instance
    pub fn new(module: WasmModule, process_id: ProcessId) -> Self {
        WasmInstance {
            module,
            memory: LinearMemory::new(1), // 1 page = 64 KiB
            stack: Stack::new(),
            locals: [Value::I32(0); MAX_LOCALS],
            pc: 0,
            capabilities: CapabilityTable::new(),
            process_id,
        }
    }

    /// Inject a capability into the instance
    pub fn inject_capability(&mut self, cap: WasmCapability) -> Result<CapHandle, WasmError> {
        self.capabilities.inject(cap)
    }

    /// Execute a function
    pub fn call(&mut self, func_idx: usize) -> Result<(), WasmError> {
        let func = self.module.get_function(func_idx)?;
        
        // Set up locals from stack parameters
        for i in (0..func.param_count).rev() {
            self.locals[i] = self.stack.pop()?;
        }

        // Execute function body
        self.pc = func.code_offset;
        let end_pc = func.code_offset + func.code_len;

        while self.pc < end_pc {
            self.step()?;
        }

        Ok(())
    }

    /// Execute one instruction
    fn step(&mut self) -> Result<(), WasmError> {
        if self.pc >= self.module.bytecode_len {
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
                // End of block/function - handled by caller
            }

            Opcode::Return => {
                // Return from function - handled by caller
                return Ok(());
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
                let _align = self.read_uleb128()?; // Alignment hint (ignored for now)
                let offset = self.read_uleb128()? as usize;
                let addr = self.stack.pop()?.as_u32()? as usize;
                let effective_addr = addr.checked_add(offset)
                    .ok_or(WasmError::MemoryOutOfBounds)?;
                let value = self.memory.read_i32(effective_addr)?;
                self.stack.push(Value::I32(value))?;
            }

            Opcode::I32Store => {
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

        Ok(())
    }

    /// Read unsigned LEB128
    fn read_uleb128(&mut self) -> Result<u32, WasmError> {
        let mut result = 0u32;
        let mut shift = 0;

        loop {
            if self.pc >= self.module.bytecode_len {
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

        loop {
            if self.pc >= self.module.bytecode_len {
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

    // ========================================================================
    // Oreulia Syscalls
    // ========================================================================

    /// oreulia_log(msg_ptr: i32, msg_len: i32)
    fn host_log(&mut self) -> Result<(), WasmError> {
        let msg_len = self.stack.pop()?.as_i32()? as usize;
        let msg_ptr = self.stack.pop()?.as_i32()? as usize;

        let msg_bytes = self.memory.read(msg_ptr, msg_len)?;
        if let Ok(msg_str) = core::str::from_utf8(msg_bytes) {
            crate::vga::print_str("[WASM] ");
            crate::vga::print_str(msg_str);
            crate::vga::print_char('\n');
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
            }
            fs::ResponseStatus::Error(_) => {
                self.stack.push(Value::I32(-1))?;
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
        let key_str = core::str::from_utf8(key_bytes)
            .map_err(|_| WasmError::InvalidUtf8)?;
        let key = fs::FileKey::new(key_str)
            .map_err(|_| WasmError::SyscallFailed)?;

        let data = self.memory.read(data_ptr, data_len)?;

        // Call filesystem
        let request = fs::Request::write(key, data, fs_cap)
            .map_err(|_| WasmError::SyscallFailed)?;
        let response = fs::filesystem().handle_request(request);

        match response.status {
            fs::ResponseStatus::Ok => {
                self.stack.push(Value::I32(0))?;
            }
            fs::ResponseStatus::Error(_) => {
                self.stack.push(Value::I32(-1))?;
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

        // Send message via IPC
        let channel_cap = crate::ipc::ChannelCapability::new(
            0, // cap_id (not used for sending)
            channel_id,
            crate::ipc::ChannelRights::send_only(),
            self.process_id,
        );
        
        let msg = crate::ipc::Message::with_data(self.process_id, msg_data)
            .map_err(|_| WasmError::SyscallFailed)?;
        
        crate::ipc::ipc().send(msg, &channel_cap)
            .map_err(|_| WasmError::SyscallFailed)?;

        self.stack.push(Value::I32(0))?;
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
            }
            Err(_) => {
                // No message available
                self.stack.push(Value::I32(0))?;
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
        let url_str = core::str::from_utf8(url_bytes)
            .map_err(|_| WasmError::InvalidUtf8)?;

        // Get network service
        let net = crate::net::network();
        let mut net_lock = net.lock();

        // Perform GET request
        let response = net_lock.http_get(url_str)
            .map_err(|_| WasmError::SyscallFailed)?;

        // Copy to WASM memory
        let copy_len = response.body_len.min(buf_len);
        self.memory.write(buf_ptr, &response.body[..copy_len])?;
        
        self.stack.push(Value::I32(copy_len as i32))?;
        Ok(())
    }

    /// oreulia_net_connect(host_ptr: i32, host_len: i32, port: i32) -> i32
    fn host_net_connect(&mut self) -> Result<(), WasmError> {
        let _port = self.stack.pop()?.as_i32()? as u16;
        let host_len = self.stack.pop()?.as_i32()? as usize;
        let host_ptr = self.stack.pop()?.as_i32()? as usize;

        // Read host from memory
        let host_bytes = self.memory.read(host_ptr, host_len)?;
        let _host_str = core::str::from_utf8(host_bytes)
            .map_err(|_| WasmError::InvalidUtf8)?;

        // For v1, return success (real socket implementation would happen here)
        self.stack.push(Value::I32(1))?; // Simulated socket ID
        Ok(())
    }

    /// oreulia_dns_resolve(domain_ptr: i32, domain_len: i32) -> i32 (returns IP as u32)
    fn host_dns_resolve(&mut self) -> Result<(), WasmError> {
        let domain_len = self.stack.pop()?.as_i32()? as usize;
        let domain_ptr = self.stack.pop()?.as_i32()? as usize;

        // Read domain from memory
        let domain_bytes = self.memory.read(domain_ptr, domain_len)?;
        let domain_str = core::str::from_utf8(domain_bytes)
            .map_err(|_| WasmError::InvalidUtf8)?;

        // Get network service
        let net = crate::net::network();
        let mut net_lock = net.lock();

        // Resolve via DNS
        let ip = net_lock.dns_resolve(domain_str)
            .map_err(|_| WasmError::SyscallFailed)?;

        self.stack.push(Value::I32(ip.to_u32() as i32))?;
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
            WasmError::SyscallFailed => write!(f, "Syscall failed"),
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

        let instance = WasmInstance::new(module, process_id);
        
        let mut instances = self.instances.lock();
        for (i, slot) in instances.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(instance);
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
