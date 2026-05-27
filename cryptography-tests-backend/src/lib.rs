// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Standalone host-side crate: AES-128 + `ct_eq` live in this file.  Everything else
// (kernel-mirrored primitives + derivation vectors) lives under `src/crypto_math/`.
// The top-level `tests/` entry is a tiny `harness = false` binary so `cargo test`
// prints the report.  See `README.md`.
//
// WHY A SEPARATE CRATE?
//
// The kernel crate is `no_std` + `staticlib` and its .cargo/config.toml sets
// `[build] target = "x86_64-unknown-none"` together with
// `[unstable] build-std = ["core", "compiler_builtins", "alloc"]`.  When
// `cargo test` is invoked inside kernel/ it tries to link std against a
// build-std-compiled core, producing duplicate lang-item errors before any
// user-level test code is reached.
//
// This crate lives outside kernel/ so the problematic config.toml is not in
// scope.  It copies only the pure-math AES functions (no arch-specific
// intrinsics, no kernel allocator) and re-runs the identical assertions.

// ============================================================
// AES-128 primitives  (verbatim from kernel/src/crypto/mod.rs)
// ============================================================

pub const AES128_ROUNDS: usize = 10;
pub const AES128_EXPANDED_KEY_BYTES: usize = 16 * (AES128_ROUNDS + 1);

#[rustfmt::skip]
pub const AES_SBOX: [u8; 256] = [
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

pub const AES_RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

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
pub(crate) fn gf_mul2(x: u8) -> u8 {
    let hi = x & 0x80;
    let mut out = x << 1;
    if hi != 0 {
        out ^= 0x1b;
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
pub(crate) fn aes_shift_rows(state: &mut [u8; 16]) {
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
pub(crate) fn aes_mix_columns(state: &mut [u8; 16]) {
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

// =============================================================================
// Host re-exports for other primitive implementations (copied from kernel)
// =============================================================================

// Constant-time equality helper (same shape as kernel's ct_eq)
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

mod crypto_math;

pub use crypto_math::primitives::*;
pub use crypto_math::run_mathematical_derivation_tests;
