/*!
 * Oreulius Kernel Project
 *
 *License-Identifier: Oreulius Community License v1.0 (see LICENSE)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulius Contributors
 */

//! Cryptographic primitives used by the kernel.
//!
//! This module is `no_std` friendly and avoids external dependencies.

#![allow(dead_code)]

extern crate alloc;
use core::sync::atomic::{AtomicU32, Ordering};

pub mod aes_gcm_nist_sp800_38d;
pub mod ed25519_twisted_edwards;
pub mod ghash_gf128;
pub mod hkdf_rfc5869;
pub mod merkle_damgard_domain;
pub mod sha512;
pub mod signing_formats;
pub mod x25519_montgomery;

pub use aes_gcm_nist_sp800_38d::{aes128_gcm_decrypt, aes128_gcm_encrypt};
pub use ed25519_twisted_edwards::ed25519_verify;
pub use hkdf_rfc5869::{hkdf_expand, hkdf_expand_label_sha256, hkdf_extract};
pub use merkle_damgard_domain::{
    merkle_damgard_domain_hash, merkle_damgard_leaf_hash, merkle_damgard_node_hash,
};
pub use sha512::{sha512, Sha512};
pub use signing_formats::{
    build_fleet_attestation_signed_message, build_ota_manifest_signed_message, import_hex_file,
    read_hex_file, read_small_vfs_file, verify_detached_ed25519, DetachedSignatureStatus,
};
pub use x25519_montgomery::{x25519, x25519_public_key, x25519_shared_secret};

static AES128_CTR_TRACE_COUNT: AtomicU32 = AtomicU32::new(0);

// =============================================================================
// Constant-Time Helpers
// =============================================================================

#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// =============================================================================
// SHA-256 (FIPS 180-4)
// =============================================================================

const SHA256_BLOCK_BYTES: usize = 64;

const SHA256_H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[inline]
fn rotr32(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((!x) & z)
}

#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline]
fn big_sigma0(x: u32) -> u32 {
    rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22)
}

#[inline]
fn big_sigma1(x: u32) -> u32 {
    rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25)
}

#[inline]
fn small_sigma0(x: u32) -> u32 {
    rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3)
}

#[inline]
fn small_sigma1(x: u32) -> u32 {
    rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10)
}

#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; SHA256_BLOCK_BYTES],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256 {
    pub const fn new() -> Self {
        Self {
            state: SHA256_H0,
            buffer: [0u8; SHA256_BLOCK_BYTES],
            buffer_len: 0,
            total_len: 0,
        }
    }

    pub fn reset(&mut self) {
        self.state = SHA256_H0;
        self.buffer.fill(0);
        self.buffer_len = 0;
        self.total_len = 0;
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if data.is_empty() {
            return;
        }

        self.total_len = self.total_len.saturating_add(data.len() as u64);

        if self.buffer_len != 0 {
            let need = SHA256_BLOCK_BYTES - self.buffer_len;
            let take = need.min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];

            if self.buffer_len == SHA256_BLOCK_BYTES {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }

        while data.len() >= SHA256_BLOCK_BYTES {
            let block = &data[..SHA256_BLOCK_BYTES];
            self.compress(block.try_into().unwrap());
            data = &data[SHA256_BLOCK_BYTES..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        // Padding: 0x80, then zeros, then length in bits as u64 big-endian.
        let bit_len = self.total_len.saturating_mul(8);

        let mut pad = [0u8; 128];
        pad[0] = 0x80;

        let len_mod = (self.buffer_len + 1) % SHA256_BLOCK_BYTES;
        let pad_zeros = if len_mod <= 56 {
            56 - len_mod
        } else {
            56 + (SHA256_BLOCK_BYTES - len_mod)
        };

        self.update(&pad[..1 + pad_zeros]);

        let len_bytes = bit_len.to_be_bytes();
        self.update(&len_bytes);

        let mut out = [0u8; 32];
        for (i, &w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            let j = i * 4;
            w[i] = u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
        }
        for i in 16..64 {
            w[i] = small_sigma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(small_sigma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

// =============================================================================
// HMAC-SHA256 (RFC 2104)
// =============================================================================

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k0 = [0u8; 64];

    if key.len() > 64 {
        k0[..32].copy_from_slice(&sha256(key));
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k0[i];
        opad[i] ^= k0[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

pub fn hmac_sha256_trunc16(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mac = hmac_sha256(key, data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac[..16]);
    out
}

pub struct HmacSha256 {
    inner: Sha256,
    opad: [u8; 64],
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut k0 = [0u8; 64];
        if key.len() > 64 {
            k0[..32].copy_from_slice(&sha256(key));
        } else {
            k0[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= k0[i];
            opad[i] ^= k0[i];
        }

        let mut inner = Sha256::new();
        inner.update(&ipad);

        Self { inner, opad }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let inner_hash = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(&self.opad);
        outer.update(&inner_hash);
        outer.finalize()
    }

    pub fn finalize_trunc16(self) -> [u8; 16] {
        let mac = self.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&mac[..16]);
        out
    }
}

// =============================================================================
// AES-128 (Software) + CTR Mode
// =============================================================================

const AES128_ROUNDS: usize = 10;
const AES128_EXPANDED_KEY_BYTES: usize = 16 * (AES128_ROUNDS + 1);

// AES S-box (FIPS-197)
const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const AES_RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

pub fn aes128_expand_key(key: &[u8; 16]) -> [u8; AES128_EXPANDED_KEY_BYTES] {
    let mut expanded = [0u8; AES128_EXPANDED_KEY_BYTES];
    expanded[..16].copy_from_slice(key);

    let mut bytes_generated = 16usize;
    let mut rcon_idx = 0usize;
    let mut temp = [0u8; 4];

    while bytes_generated < AES128_EXPANDED_KEY_BYTES {
        temp.copy_from_slice(&expanded[bytes_generated - 4..bytes_generated]);

        if (bytes_generated % 16) == 0 {
            // RotWord
            let t0 = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t0;

            // SubWord
            for b in temp.iter_mut() {
                *b = AES_SBOX[*b as usize];
            }

            // Rcon
            temp[0] ^= AES_RCON[rcon_idx];
            rcon_idx += 1;
        }

        for i in 0..4 {
            expanded[bytes_generated] = expanded[bytes_generated - 16] ^ temp[i];
            bytes_generated += 1;
        }
    }

    expanded
}

#[inline]
fn gf_mul2(x: u8) -> u8 {
    let hi = x & 0x80;
    let mut out = x << 1;
    if hi != 0 {
        out ^= 0x1B;
    }
    out
}

#[inline]
fn aes_add_round_key(
    state: &mut [u8; 16],
    round_keys: &[u8; AES128_EXPANDED_KEY_BYTES],
    round: usize,
) {
    let start = round * 16;
    for i in 0..16 {
        state[i] ^= round_keys[start + i];
    }
}

#[inline]
fn aes_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = AES_SBOX[*b as usize];
    }
}

#[inline]
fn aes_shift_rows(state: &mut [u8; 16]) {
    let tmp = *state;

    // Row 0 (no shift)
    state[0] = tmp[0];
    state[4] = tmp[4];
    state[8] = tmp[8];
    state[12] = tmp[12];

    // Row 1 (shift left 1)
    state[1] = tmp[5];
    state[5] = tmp[9];
    state[9] = tmp[13];
    state[13] = tmp[1];

    // Row 2 (shift left 2)
    state[2] = tmp[10];
    state[6] = tmp[14];
    state[10] = tmp[2];
    state[14] = tmp[6];

    // Row 3 (shift left 3)
    state[3] = tmp[15];
    state[7] = tmp[3];
    state[11] = tmp[7];
    state[15] = tmp[11];
}

#[inline]
fn aes_mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];

        let t = a0 ^ a1 ^ a2 ^ a3;
        let u0 = a0;
        state[i] ^= t ^ gf_mul2(a0 ^ a1);
        state[i + 1] ^= t ^ gf_mul2(a1 ^ a2);
        state[i + 2] ^= t ^ gf_mul2(a2 ^ a3);
        state[i + 3] ^= t ^ gf_mul2(a3 ^ u0);
    }
}

pub fn aes128_encrypt_block_in_place(
    block: &mut [u8; 16],
    round_keys: &[u8; AES128_EXPANDED_KEY_BYTES],
) {
    aes_add_round_key(block, round_keys, 0);

    for round in 1..AES128_ROUNDS {
        aes_sub_bytes(block);
        aes_shift_rows(block);
        aes_mix_columns(block);
        aes_add_round_key(block, round_keys, round);
    }

    aes_sub_bytes(block);
    aes_shift_rows(block);
    aes_add_round_key(block, round_keys, AES128_ROUNDS);
}

#[cfg(target_arch = "x86_64")]
fn kernel_buffer_is_mapped(virt_addr: usize, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let page_size = crate::runtime_page_size();
    let last = match virt_addr.checked_add(len - 1) {
        Some(v) => v,
        None => return false,
    };
    let mut page = virt_addr & !(page_size - 1);
    let end_page = last & !(page_size - 1);
    loop {
        if crate::arch::mmu::x86_64_debug_virt_to_phys(page).is_none() {
            return false;
        }
        if page == end_page {
            break;
        }
        page = match page.checked_add(page_size) {
            Some(v) => v,
            None => return false,
        };
    }
    true
}

#[cfg(target_arch = "x86")]
#[inline]
fn kernel_buffer_is_mapped(virt_addr: usize, len: usize) -> bool {
    crate::paging::is_kernel_range_mapped(virt_addr, len)
}

pub fn aes128_ctr_xor(key: &[u8; 16], nonce: u64, data: &mut [u8]) {
    #[cfg(not(target_arch = "aarch64"))]
    struct IrqGuard(u32);
    #[cfg(not(target_arch = "aarch64"))]
    impl Drop for IrqGuard {
        fn drop(&mut self) {
            unsafe { crate::idt_asm::fast_sti_restore(self.0) };
        }
    }

    let call_idx = AES128_CTR_TRACE_COUNT
        .fetch_add(1, Ordering::SeqCst)
        .wrapping_add(1);
    if call_idx <= 64 || data.len() > (1024 * 1024) {
        crate::serial::_print(format_args!(
            "[CRYPTO-DBG] aes128_ctr_xor call={} ptr=0x{:08x} len={} nonce=0x{:016x}\n",
            call_idx,
            data.as_ptr() as u32,
            data.len(),
            nonce,
        ));
    }

    #[cfg(not(target_arch = "aarch64"))]
    if !kernel_buffer_is_mapped(data.as_ptr() as usize, data.len()) {
        crate::serial::_print(format_args!(
            "[CRYPTO-DBG] aes128_ctr_xor invalid-buffer call={} ptr=0x{:08x} len={}\n",
            call_idx,
            data.as_ptr() as u32,
            data.len(),
        ));
        return;
    }

    #[cfg(not(target_arch = "aarch64"))]
    let irq_flags = unsafe { crate::idt_asm::fast_cli_save() };
    #[cfg(not(target_arch = "aarch64"))]
    let _irq_guard = IrqGuard(irq_flags);

    let mut round_keys = aes128_expand_key(key);

    let mut counter = 0u64;
    for chunk in data.chunks_mut(16) {
        let mut block = [0u8; 16];
        block[0..8].copy_from_slice(&nonce.to_le_bytes());
        block[8..16].copy_from_slice(&counter.to_le_bytes());
        aes128_encrypt_block_in_place(&mut block, &round_keys);

        for i in 0..chunk.len() {
            chunk[i] ^= block[i];
        }

        counter = counter.wrapping_add(1);
    }

    // Best-effort wipe of expanded key material.
    round_keys.fill(0);
}
