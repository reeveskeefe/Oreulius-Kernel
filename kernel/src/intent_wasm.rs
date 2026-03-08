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

//! Lightweight WASM-style intent model used by the security intent graph.
//!
//! This is intentionally tiny and deterministic:
//! - fixed feature vector
//! - fixed model bytecode (subset of WASM ops)
//! - no dynamic allocation

#![allow(dead_code)]

use crate::tensor_core::{ScalarTensor, SimdTensor};

/// Number of model input features.
pub const INTENT_MODEL_FEATURES: usize = 10;

/// Score floor for centering the raw weighted sum.
const MODEL_CENTER: i32 = 48;

/// Scale applied after centering.
const MODEL_SCALE: i32 = 3;

/// Trained (hand-tuned) feature weights packed into tiny WASM-style bytecode.
///
/// Program:
///   acc = 0
///   acc += f0 * 1
///   acc += f1 * 6
///   acc += f2 * 8
///   acc += f3 * 2
///   acc += f4 * 3
///   acc += f5 * 5
///   acc += f6 * 3
///   acc += f7 * 4
///   acc += f8 * 2
///   acc += f9 * 5
///   end
const MODEL_BYTECODE: [u8; 63] = [
    0x41, 0x00, // i32.const 0
    0x20, 0x00, 0x41, 0x01, 0x6C, 0x6A, // f0 * 1
    0x20, 0x01, 0x41, 0x06, 0x6C, 0x6A, // f1 * 6
    0x20, 0x02, 0x41, 0x08, 0x6C, 0x6A, // f2 * 8
    0x20, 0x03, 0x41, 0x02, 0x6C, 0x6A, // f3 * 2
    0x20, 0x04, 0x41, 0x03, 0x6C, 0x6A, // f4 * 3
    0x20, 0x05, 0x41, 0x05, 0x6C, 0x6A, // f5 * 5
    0x20, 0x06, 0x41, 0x03, 0x6C, 0x6A, // f6 * 3
    0x20, 0x07, 0x41, 0x04, 0x6C, 0x6A, // f7 * 4
    0x20, 0x08, 0x41, 0x02, 0x6C, 0x6A, // f8 * 2
    0x20, 0x09, 0x41, 0x05, 0x6C, 0x6A, // f9 * 5
    0x0B, // end
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VmError {
    InvalidOpcode,
    StackUnderflow,
    StackOverflow,
    InvalidLocal,
    UnexpectedEof,
    Leb128Overflow,
}

#[inline]
fn push(stack: &mut [i32; 32], sp: &mut usize, value: i32) -> Result<(), VmError> {
    if *sp >= stack.len() {
        return Err(VmError::StackOverflow);
    }
    stack[*sp] = value;
    *sp += 1;
    Ok(())
}

#[inline]
fn pop(stack: &[i32; 32], sp: &mut usize) -> Result<i32, VmError> {
    if *sp == 0 {
        return Err(VmError::StackUnderflow);
    }
    *sp -= 1;
    Ok(stack[*sp])
}

fn read_uleb32(code: &[u8], pc: &mut usize) -> Result<u32, VmError> {
    let mut result = 0u32;
    let mut shift = 0u32;
    loop {
        if *pc >= code.len() {
            return Err(VmError::UnexpectedEof);
        }
        let byte = code[*pc];
        *pc += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if (byte & 0x80) == 0 {
            break;
        }
        shift = shift.saturating_add(7);
        if shift > 28 {
            return Err(VmError::Leb128Overflow);
        }
    }
    Ok(result)
}

fn read_sleb32(code: &[u8], pc: &mut usize) -> Result<i32, VmError> {
    let mut result = 0i32;
    let mut shift = 0u32;
    let byte = loop {
        if *pc >= code.len() {
            return Err(VmError::UnexpectedEof);
        }
        let b = code[*pc];
        *pc += 1;
        result |= ((b & 0x7F) as i32) << shift;
        shift = shift.saturating_add(7);
        if (b & 0x80) == 0 {
            break b;
        }
        if shift > 35 {
            return Err(VmError::Leb128Overflow);
        }
    };

    if shift < 32 && (byte & 0x40) != 0 {
        result |= !0 << shift;
    }
    Ok(result)
}

fn eval_model(features: &[u32; INTENT_MODEL_FEATURES]) -> Result<i32, VmError> {
    let mut locals = [0i32; INTENT_MODEL_FEATURES];
    let mut i = 0usize;
    while i < INTENT_MODEL_FEATURES {
        locals[i] = features[i].min(255) as i32;
        i += 1;
    }

    let mut stack = [0i32; 32];
    let mut sp = 0usize;
    let mut pc = 0usize;

    while pc < MODEL_BYTECODE.len() {
        let op = MODEL_BYTECODE[pc];
        pc += 1;
        match op {
            0x0B => break, // end
            0x20 => {
                let idx = read_uleb32(&MODEL_BYTECODE, &mut pc)? as usize;
                if idx >= locals.len() {
                    return Err(VmError::InvalidLocal);
                }
                push(&mut stack, &mut sp, locals[idx])?;
            }
            0x41 => {
                let imm = read_sleb32(&MODEL_BYTECODE, &mut pc)?;
                push(&mut stack, &mut sp, imm)?;
            }
            0x6A => {
                let b = pop(&stack, &mut sp)?;
                let a = pop(&stack, &mut sp)?;
                push(&mut stack, &mut sp, a.saturating_add(b))?;
            }
            0x6C => {
                let b = pop(&stack, &mut sp)?;
                let a = pop(&stack, &mut sp)?;
                push(&mut stack, &mut sp, a.saturating_mul(b))?;
            }
            _ => return Err(VmError::InvalidOpcode),
        }
    }

    pop(&stack, &mut sp)
}

/// Infer anomaly score from intent graph features.
///
/// Returns a bounded score in range [0, 255].
pub fn infer_score(features: &[u32; INTENT_MODEL_FEATURES]) -> u32 {
    let raw = eval_model(features).unwrap_or_else(|_| {
        let mut f_data = [0i32; 10];
        for i in 0..10 { f_data[i] = features[i] as i32; }
        
        let feature_tensor = ScalarTensor::<i32, 10> { data: f_data };
        let weight_tensor = ScalarTensor::<i32, 10> { data: [1, 6, 8, 2, 3, 5, 3, 4, 2, 5] };
        
        feature_tensor.dot_product(&weight_tensor)
    });

    if raw <= MODEL_CENTER {
        return 0;
    }

    let centered = raw.saturating_sub(MODEL_CENTER);
    let scaled = centered.saturating_mul(MODEL_SCALE);
    (scaled as u32).min(255)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infer_score_increases_with_risk_signals() {
        let low = [1, 0, 0, 0, 0, 0, 0, 1, 0, 0];
        let medium = [8, 2, 1, 2, 1, 1, 2, 2, 6, 4];
        let high = [32, 8, 8, 6, 4, 6, 8, 4, 48, 24];

        let s_low = infer_score(&low);
        let s_medium = infer_score(&medium);
        let s_high = infer_score(&high);

        assert!(s_low <= s_medium);
        assert!(s_medium <= s_high);
    }
}
