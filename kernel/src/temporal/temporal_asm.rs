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

//! Temporal Objects assembly bindings.
//! Provides hashing and Merkle reduction primitives used by the temporal state manager.

#![allow(dead_code)]

#[cfg(not(target_arch = "aarch64"))]
extern "C" {
    fn temporal_fnv1a32(data: *const u8, len: u32, seed: u32) -> u32;
    fn temporal_hash_pair(left: u32, right: u32) -> u32;
    fn temporal_merkle_root_u32(words: *mut u32, count: u32) -> u32;
    fn temporal_copy_bytes(dst: *mut u8, src: *const u8, len: u32);
    fn temporal_zero_bytes(dst: *mut u8, len: u32);
}

#[inline]
#[cfg(not(target_arch = "aarch64"))]
pub fn fnv1a32(data: &[u8], seed: u32) -> u32 {
    unsafe { temporal_fnv1a32(data.as_ptr(), data.len() as u32, seed) }
}

#[inline]
#[cfg(target_arch = "aarch64")]
pub fn fnv1a32(data: &[u8], seed: u32) -> u32 {
    let mut hash = seed;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

#[inline]
#[cfg(not(target_arch = "aarch64"))]
pub fn hash_pair(left: u32, right: u32) -> u32 {
    unsafe { temporal_hash_pair(left, right) }
}

#[inline]
#[cfg(target_arch = "aarch64")]
pub fn hash_pair(left: u32, right: u32) -> u32 {
    let mixed = (left ^ 0x9E37_79B9).rotate_left(5).wrapping_add(right) ^ 0x85EB_CA6B;
    mixed.wrapping_mul(0xC2B2_AE35)
}

#[inline]
#[cfg(not(target_arch = "aarch64"))]
pub fn merkle_root(words: &mut [u32]) -> u32 {
    unsafe { temporal_merkle_root_u32(words.as_mut_ptr(), words.len() as u32) }
}

#[inline]
#[cfg(target_arch = "aarch64")]
pub fn merkle_root(words: &mut [u32]) -> u32 {
    if words.is_empty() {
        return 0;
    }
    let mut count = words.len();
    while count > 1 {
        let mut dst = 0usize;
        let mut src = 0usize;
        while src < count {
            let left = words[src];
            let right = if src + 1 < count {
                words[src + 1]
            } else {
                left
            };
            words[dst] = hash_pair(left, right);
            dst += 1;
            src += 2;
        }
        count = dst;
    }
    words[0]
}

#[inline]
#[cfg(not(target_arch = "aarch64"))]
pub fn copy_bytes(dst: &mut [u8], src: &[u8]) {
    let len = core::cmp::min(dst.len(), src.len());
    if len == 0 {
        return;
    }
    unsafe {
        temporal_copy_bytes(dst.as_mut_ptr(), src.as_ptr(), len as u32);
    }
}

#[inline]
#[cfg(target_arch = "aarch64")]
pub fn copy_bytes(dst: &mut [u8], src: &[u8]) {
    let len = core::cmp::min(dst.len(), src.len());
    if len == 0 {
        return;
    }
    dst[..len].copy_from_slice(&src[..len]);
}

#[inline]
#[cfg(not(target_arch = "aarch64"))]
pub fn zero_bytes(dst: &mut [u8]) {
    if dst.is_empty() {
        return;
    }
    unsafe {
        temporal_zero_bytes(dst.as_mut_ptr(), dst.len() as u32);
    }
}

#[inline]
#[cfg(target_arch = "aarch64")]
pub fn zero_bytes(dst: &mut [u8]) {
    if dst.is_empty() {
        return;
    }
    dst.fill(0);
}
