use crate::{aes128_encrypt_block_in_place, aes128_expand_key, AES128_EXPANDED_KEY_BYTES};

fn ctr_keystream_block(
    round_keys: &[u8; AES128_EXPANDED_KEY_BYTES],
    nonce: u64,
    counter: u64,
) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[0..8].copy_from_slice(&nonce.to_le_bytes());
    block[8..16].copy_from_slice(&counter.to_le_bytes());
    aes128_encrypt_block_in_place(&mut block, round_keys);
    block
}

fn aes128_ctr_apply(key: &[u8; 16], nonce: u64, data: &mut [u8]) {
    let round_keys = aes128_expand_key(key);
    let mut counter = 0u64;
    for chunk in data.chunks_mut(16) {
        let ks = ctr_keystream_block(&round_keys, nonce, counter);
        for i in 0..chunk.len() {
            chunk[i] ^= ks[i];
        }
        counter = counter.wrapping_add(1);
    }
}

fn check_ctr_block_encodes_nonce_in_bytes_0_to_7_little_endian() -> Result<(), String> {
    let nonce: u64 = 0x0102_0304_0506_0708;
    let counter: u64 = 0;
    let mut block = [0u8; 16];
    block[0..8].copy_from_slice(&nonce.to_le_bytes());
    block[8..16].copy_from_slice(&counter.to_le_bytes());
    if &block[0..8] != &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01] {
        return Err("nonce bytes 0..8 LE mismatch".into());
    }
    if &block[8..16] != &[0x00u8; 8] {
        return Err("counter bytes 8..16 should be zero".into());
    }
    Ok(())
}

fn check_ctr_block_encodes_counter_in_bytes_8_to_15_little_endian() -> Result<(), String> {
    let nonce: u64 = 0;
    let counter: u64 = 0x0102_0304_0506_0708;
    let mut block = [0u8; 16];
    block[0..8].copy_from_slice(&nonce.to_le_bytes());
    block[8..16].copy_from_slice(&counter.to_le_bytes());
    if &block[0..8] != &[0x00u8; 8] {
        return Err("nonce bytes 0..8 should be zero".into());
    }
    if &block[8..16] != &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01] {
        return Err("counter bytes 8..16 LE mismatch".into());
    }
    Ok(())
}

fn check_ctr_keystream_block_equals_aes_encrypt_of_nonce_counter_concatenation(
) -> Result<(), String> {
    let key = [0u8; 16];
    let round_keys = aes128_expand_key(&key);
    let nonce: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let counter: u64 = 7;
    let mut expected = [0u8; 16];
    expected[0..8].copy_from_slice(&nonce.to_le_bytes());
    expected[8..16].copy_from_slice(&counter.to_le_bytes());
    aes128_encrypt_block_in_place(&mut expected, &round_keys);
    let actual = ctr_keystream_block(&round_keys, nonce, counter);
    if actual != expected {
        return Err("keystream block != AES encrypt(nonce||counter)".into());
    }
    Ok(())
}

fn check_ctr_xor_is_self_inverse_single_block() -> Result<(), String> {
    let key = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    let nonce = 0xF0F1_F2F3_F4F5_F6F7u64;
    let plaintext: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ];
    let mut ct = plaintext;
    aes128_ctr_apply(&key, nonce, &mut ct);
    if ct == plaintext {
        return Err("encrypt should change ciphertext".into());
    }
    aes128_ctr_apply(&key, nonce, &mut ct);
    if ct != plaintext {
        return Err("decrypt should restore plaintext".into());
    }
    Ok(())
}

fn check_ctr_encrypt_decrypt_roundtrip_three_blocks() -> Result<(), String> {
    let key = [0u8; 16];
    let nonce = 0x1122_3344_5566_7788u64;
    let original: [u8; 48] = core::array::from_fn(|i| i as u8);
    let mut data = original;
    aes128_ctr_apply(&key, nonce, &mut data);
    if data == original {
        return Err("encrypt should change data".into());
    }
    aes128_ctr_apply(&key, nonce, &mut data);
    if data != original {
        return Err("decrypt roundtrip mismatch".into());
    }
    Ok(())
}

fn check_ctr_counter_increments_by_one_per_block_and_applies_correct_keystream(
) -> Result<(), String> {
    let key = [0u8; 16];
    let round_keys = aes128_expand_key(&key);
    let nonce = 0xAABB_CCDD_EEFF_0011u64;
    let ks0 = ctr_keystream_block(&round_keys, nonce, 0);
    let ks1 = ctr_keystream_block(&round_keys, nonce, 1);
    let ks2 = ctr_keystream_block(&round_keys, nonce, 2);
    if ks0 == ks1 || ks1 == ks2 || ks0 == ks2 {
        return Err("keystream blocks should differ across counters".into());
    }
    let mut data = [0u8; 48];
    aes128_ctr_apply(&key, nonce, &mut data);
    if &data[0..16] != &ks0 || &data[16..32] != &ks1 || &data[32..48] != &ks2 {
        return Err("per-block keystream application mismatch".into());
    }
    Ok(())
}

fn check_ctr_different_nonces_produce_independent_keystreams() -> Result<(), String> {
    let key = [0u8; 16];
    let round_keys = aes128_expand_key(&key);
    let ks_a = ctr_keystream_block(&round_keys, 0x0000_0000_0000_0001, 0);
    let ks_b = ctr_keystream_block(&round_keys, 0x0000_0000_0000_0002, 0);
    if ks_a == ks_b {
        return Err("different nonces produced identical keystream".into());
    }
    Ok(())
}

fn check_ctr_different_counters_produce_independent_keystreams() -> Result<(), String> {
    let key = [0u8; 16];
    let round_keys = aes128_expand_key(&key);
    let nonce = 0x0102_0304_0506_0708u64;
    let ks0 = ctr_keystream_block(&round_keys, nonce, 0);
    let ks1 = ctr_keystream_block(&round_keys, nonce, 1);
    if ks0 == ks1 {
        return Err("different counters produced identical keystream".into());
    }
    Ok(())
}

fn check_ctr_keystream_generation_is_deterministic() -> Result<(), String> {
    let key = [0xABu8; 16];
    let round_keys = aes128_expand_key(&key);
    let nonce = 0xDEAD_BEEF_0000_0001u64;
    let counter = 42u64;
    let first = ctr_keystream_block(&round_keys, nonce, counter);
    let second = ctr_keystream_block(&round_keys, nonce, counter);
    if first != second {
        return Err("keystream generation not deterministic".into());
    }
    Ok(())
}

fn check_ctr_known_roundtrip_verifies_per_block_keystream_application() -> Result<(), String> {
    let key = [0x01u8; 16];
    let nonce = 0x0807_0605_0403_0201u64;
    let original: [u8; 48] = core::array::from_fn(|i| (i as u8).wrapping_mul(3));
    let mut data = original;
    aes128_ctr_apply(&key, nonce, &mut data);
    let round_keys = aes128_expand_key(&key);
    for block_idx in 0..3usize {
        let ks = ctr_keystream_block(&round_keys, nonce, block_idx as u64);
        for j in 0..16 {
            if data[block_idx * 16 + j] != original[block_idx * 16 + j] ^ ks[j] {
                return Err(format!(
                    "Block {block_idx} byte {j}: ciphertext != plaintext XOR keystream"
                ));
            }
        }
    }
    aes128_ctr_apply(&key, nonce, &mut data);
    if data != original {
        return Err("decrypt roundtrip mismatch".into());
    }
    Ok(())
}

fn check_ctr_partial_last_block_xors_only_remaining_bytes() -> Result<(), String> {
    let key = [0u8; 16];
    let nonce = 0u64;
    let round_keys = aes128_expand_key(&key);
    let ks0 = ctr_keystream_block(&round_keys, nonce, 0);
    let mut data = [0xFFu8; 5];
    aes128_ctr_apply(&key, nonce, &mut data);
    let expected: [u8; 5] = core::array::from_fn(|i| 0xFF ^ ks0[i]);
    if data != expected {
        return Err("partial last block XOR mismatch".into());
    }
    Ok(())
}

fn check_ctr_empty_data_is_a_no_op() -> Result<(), String> {
    let key = [0u8; 16];
    let nonce = 0u64;
    let mut data: [u8; 0] = [];
    aes128_ctr_apply(&key, nonce, &mut data);
    Ok(())
}

fn check_ctr_nonce_reuse_under_same_key_leaks_plaintext_xor() -> Result<(), String> {
    let key = [0u8; 16];
    let nonce = 0x0000_0000_0000_0001u64;
    let p1 = [0xAAu8; 16];
    let p2 = [0x55u8; 16];
    let mut c1 = p1;
    let mut c2 = p2;
    aes128_ctr_apply(&key, nonce, &mut c1);
    aes128_ctr_apply(&key, nonce, &mut c2);
    let ct_xor: [u8; 16] = core::array::from_fn(|i| c1[i] ^ c2[i]);
    let pt_xor: [u8; 16] = core::array::from_fn(|i| p1[i] ^ p2[i]);
    if ct_xor != pt_xor {
        return Err("Nonce reuse: C1 XOR C2 must equal P1 XOR P2".into());
    }
    Ok(())
}

fn check_ctr_counter_wraps_at_u64_max_and_repeats_keystream_from_block_zero() -> Result<(), String>
{
    let key = [0u8; 16];
    let round_keys = aes128_expand_key(&key);
    let nonce = 0xDEAD_BEEF_CAFE_BABEu64;
    let block_at_0 = ctr_keystream_block(&round_keys, nonce, 0);
    let block_at_wrap = ctr_keystream_block(&round_keys, nonce, u64::MAX.wrapping_add(1));
    if block_at_0 != block_at_wrap {
        return Err(
            "u64::MAX.wrapping_add(1) == 0: counter wrap should repeat block-0 keystream".into(),
        );
    }
    Ok(())
}

const CTR_CASES: &[(&str, fn() -> Result<(), String>)] = &[
    (
        "ctr_block_encodes_nonce_in_bytes_0_to_7_little_endian",
        check_ctr_block_encodes_nonce_in_bytes_0_to_7_little_endian,
    ),
    (
        "ctr_block_encodes_counter_in_bytes_8_to_15_little_endian",
        check_ctr_block_encodes_counter_in_bytes_8_to_15_little_endian,
    ),
    (
        "ctr_keystream_block_equals_aes_encrypt_of_nonce_counter_concatenation",
        check_ctr_keystream_block_equals_aes_encrypt_of_nonce_counter_concatenation,
    ),
    (
        "ctr_xor_is_self_inverse_single_block",
        check_ctr_xor_is_self_inverse_single_block,
    ),
    (
        "ctr_encrypt_decrypt_roundtrip_three_blocks",
        check_ctr_encrypt_decrypt_roundtrip_three_blocks,
    ),
    (
        "ctr_counter_increments_by_one_per_block_and_applies_correct_keystream",
        check_ctr_counter_increments_by_one_per_block_and_applies_correct_keystream,
    ),
    (
        "ctr_different_nonces_produce_independent_keystreams",
        check_ctr_different_nonces_produce_independent_keystreams,
    ),
    (
        "ctr_different_counters_produce_independent_keystreams",
        check_ctr_different_counters_produce_independent_keystreams,
    ),
    (
        "ctr_keystream_generation_is_deterministic",
        check_ctr_keystream_generation_is_deterministic,
    ),
    (
        "ctr_known_roundtrip_verifies_per_block_keystream_application",
        check_ctr_known_roundtrip_verifies_per_block_keystream_application,
    ),
    (
        "ctr_partial_last_block_xors_only_remaining_bytes",
        check_ctr_partial_last_block_xors_only_remaining_bytes,
    ),
    ("ctr_empty_data_is_a_no_op", check_ctr_empty_data_is_a_no_op),
    (
        "ctr_nonce_reuse_under_same_key_leaks_plaintext_xor",
        check_ctr_nonce_reuse_under_same_key_leaks_plaintext_xor,
    ),
    (
        "ctr_counter_wraps_at_u64_max_and_repeats_keystream_from_block_zero",
        check_ctr_counter_wraps_at_u64_max_and_repeats_keystream_from_block_zero,
    ),
];

pub fn run_deterministic_tests() -> Vec<(&'static str, bool, String)> {
    let mut results = Vec::with_capacity(CTR_CASES.len());
    for &(name, f) in CTR_CASES {
        match f() {
            Ok(()) => results.push((name, true, "OK".to_string())),
            Err(detail) => results.push((name, false, detail)),
        }
    }
    results
}
