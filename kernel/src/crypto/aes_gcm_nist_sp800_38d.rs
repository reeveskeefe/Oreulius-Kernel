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


/*!
 * AES-128-GCM built from the kernel AES core and GHASH.
 */

use crate::crypto::ghash_gf128::ghash;
use crate::crypto::{aes128_encrypt_block_in_place, aes128_expand_key, ct_eq};

fn ctr_block(rk: &[u8; 176], iv: &[u8; 12], ctr: u32) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..12].copy_from_slice(iv);
    b[12..].copy_from_slice(&ctr.to_be_bytes());
    aes128_encrypt_block_in_place(&mut b, rk);
    b
}

pub fn aes128_gcm_encrypt(
    key: &[u8; 16],
    iv: &[u8; 12],
    aad: &[u8],
    pt: &[u8],
    out: &mut [u8],
) -> [u8; 16] {
    let rk = aes128_expand_key(key);
    let h = {
        let mut z = [0u8; 16];
        aes128_encrypt_block_in_place(&mut z, &rk);
        z
    };
    let j0 = ctr_block(&rk, iv, 1);
    let mut ctr = 2u32;
    let mut i = 0usize;
    while i + 16 <= pt.len() {
        let ks = ctr_block(&rk, iv, ctr);
        for j in 0..16 {
            out[i + j] = pt[i + j] ^ ks[j];
        }
        ctr = ctr.wrapping_add(1);
        i += 16;
    }
    if i < pt.len() {
        let ks = ctr_block(&rk, iv, ctr);
        for j in 0..(pt.len() - i) {
            out[i + j] = pt[i + j] ^ ks[j];
        }
    }
    let mut tag = ghash(&h, aad, &out[..pt.len()]);
    for j in 0..16 {
        tag[j] ^= j0[j];
    }
    tag
}

pub fn aes128_gcm_decrypt(
    key: &[u8; 16],
    iv: &[u8; 12],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; 16],
    out: &mut [u8],
) -> Result<(), ()> {
    let rk = aes128_expand_key(key);
    let h = {
        let mut z = [0u8; 16];
        aes128_encrypt_block_in_place(&mut z, &rk);
        z
    };
    let j0 = ctr_block(&rk, iv, 1);
    let mut expected = ghash(&h, aad, ct);
    for j in 0..16 {
        expected[j] ^= j0[j];
    }
    if !ct_eq(&expected, tag) {
        return Err(());
    }

    let mut ctr = 2u32;
    let mut i = 0usize;
    while i + 16 <= ct.len() {
        let ks = ctr_block(&rk, iv, ctr);
        for j in 0..16 {
            out[i + j] = ct[i + j] ^ ks[j];
        }
        ctr = ctr.wrapping_add(1);
        i += 16;
    }
    if i < ct.len() {
        let ks = ctr_block(&rk, iv, ctr);
        for j in 0..(ct.len() - i) {
            out[i + j] = ct[i + j] ^ ks[j];
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{aes128_gcm_decrypt, aes128_gcm_encrypt};

    #[test]
    fn aes128_gcm_nist_empty_message_vector() {
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let aad = [];
        let pt = [];
        let mut out = [];
        let tag = aes128_gcm_encrypt(&key, &iv, &aad, &pt, &mut out);
        assert_eq!(
            tag,
            [
                0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
                0x45, 0x5a,
            ]
        );

        let mut dec = [];
        assert!(aes128_gcm_decrypt(&key, &iv, &aad, &[], &tag, &mut dec).is_ok());
    }

    #[test]
    fn aes128_gcm_nist_single_block_vector() {
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let aad = [];
        let pt = [0u8; 16];
        let mut ct = [0u8; 16];
        let tag = aes128_gcm_encrypt(&key, &iv, &aad, &pt, &mut ct);
        assert_eq!(
            ct,
            [
                0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
                0xfe, 0x78,
            ]
        );
        assert_eq!(
            tag,
            [
                0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
                0xbd, 0xdf,
            ]
        );

        let mut dec = [0u8; 16];
        aes128_gcm_decrypt(&key, &iv, &aad, &ct, &tag, &mut dec).unwrap();
        assert_eq!(dec, pt);
    }
}
