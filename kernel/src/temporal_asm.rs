/*!
 * Oreulia Kernel Project
 *
 * SPDX-License-Identifier: MIT
 */

//! Temporal Objects assembly bindings.
//! Provides hashing and Merkle reduction primitives used by the temporal state manager.

#![allow(dead_code)]

extern "C" {
    fn temporal_fnv1a32(data: *const u8, len: u32, seed: u32) -> u32;
    fn temporal_hash_pair(left: u32, right: u32) -> u32;
    fn temporal_merkle_root_u32(words: *mut u32, count: u32) -> u32;
    fn temporal_copy_bytes(dst: *mut u8, src: *const u8, len: u32);
    fn temporal_zero_bytes(dst: *mut u8, len: u32);
}

#[inline]
pub fn fnv1a32(data: &[u8], seed: u32) -> u32 {
    unsafe { temporal_fnv1a32(data.as_ptr(), data.len() as u32, seed) }
}

#[inline]
pub fn hash_pair(left: u32, right: u32) -> u32 {
    unsafe { temporal_hash_pair(left, right) }
}

#[inline]
pub fn merkle_root(words: &mut [u32]) -> u32 {
    unsafe { temporal_merkle_root_u32(words.as_mut_ptr(), words.len() as u32) }
}

#[inline]
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
pub fn zero_bytes(dst: &mut [u8]) {
    if dst.is_empty() {
        return;
    }
    unsafe {
        temporal_zero_bytes(dst.as_mut_ptr(), dst.len() as u32);
    }
}
