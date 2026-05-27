use super::ghash::ghash;
use crate::{aes128_encrypt_block_in_place, aes128_expand_key, ct_eq};

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
