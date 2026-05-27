use crate::{
    aes128_encrypt_block_in_place, aes128_expand_key, aes_mix_columns, aes_shift_rows, gf_mul2,
    AES128_EXPANDED_KEY_BYTES, AES128_ROUNDS, AES_RCON, AES_SBOX,
};

const FIPS_197_AES128_KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

#[rustfmt::skip]
const FIPS_197_AES128_EXPANDED_KEY: [u8; 176] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0xd6, 0xaa, 0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa, 0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab, 0x76, 0xfe,
    0xb6, 0x92, 0xcf, 0x0b, 0x64, 0x3d, 0xbd, 0xf1, 0xbe, 0x9b, 0xc5, 0x00, 0x68, 0x30, 0xb3, 0xfe,
    0xb6, 0xff, 0x74, 0x4e, 0xd2, 0xc2, 0xc9, 0xbf, 0x6c, 0x59, 0x0c, 0xbf, 0x04, 0x69, 0xbf, 0x41,
    0x47, 0xf7, 0xf7, 0xbc, 0x95, 0x35, 0x3e, 0x03, 0xf9, 0x6c, 0x32, 0xbc, 0xfd, 0x05, 0x8d, 0xfd,
    0x3c, 0xaa, 0xa3, 0xe8, 0xa9, 0x9f, 0x9d, 0xeb, 0x50, 0xf3, 0xaf, 0x57, 0xad, 0xf6, 0x22, 0xaa,
    0x5e, 0x39, 0x0f, 0x7d, 0xf7, 0xa6, 0x92, 0x96, 0xa7, 0x55, 0x3d, 0xc1, 0x0a, 0xa3, 0x1f, 0x6b,
    0x14, 0xf9, 0x70, 0x1a, 0xe3, 0x5f, 0xe2, 0x8c, 0x44, 0x0a, 0xdf, 0x4d, 0x4e, 0xa9, 0xc0, 0x26,
    0x47, 0x43, 0x87, 0x35, 0xa4, 0x1c, 0x65, 0xb9, 0xe0, 0x16, 0xba, 0xf4, 0xae, 0xbf, 0x7a, 0xd2,
    0x54, 0x99, 0x32, 0xd1, 0xf0, 0x85, 0x57, 0x68, 0x10, 0x93, 0xed, 0x9c, 0xbe, 0x2c, 0x97, 0x4e,
    0x13, 0x11, 0x1d, 0x7f, 0xe3, 0x94, 0x4a, 0x17, 0xf3, 0x07, 0xa7, 0x8b, 0x4d, 0x2b, 0x30, 0xc5,
];

fn check_aes128_oreulius_constants_match_aes128_shape() -> Result<(), String> {
    if AES128_ROUNDS != 10 {
        return Err(format!("AES128_ROUNDS: expected 10, got {}", AES128_ROUNDS));
    }
    if AES128_EXPANDED_KEY_BYTES != 176 {
        return Err(format!(
            "AES128_EXPANDED_KEY_BYTES: expected 176, got {}",
            AES128_EXPANDED_KEY_BYTES
        ));
    }
    let expected_rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    if AES_RCON != expected_rcon {
        return Err("AES_RCON does not match expected FIPS round constants".into());
    }
    Ok(())
}

fn check_aes_sbox_matches_standard_sample_points() -> Result<(), String> {
    if AES_SBOX[0x00] != 0x63 {
        return Err("AES_SBOX[0x00]".into());
    }
    if AES_SBOX[0x01] != 0x7c {
        return Err("AES_SBOX[0x01]".into());
    }
    if AES_SBOX[0x53] != 0xed {
        return Err("AES_SBOX[0x53]".into());
    }
    if AES_SBOX[0x7c] != 0x10 {
        return Err("AES_SBOX[0x7c]".into());
    }
    if AES_SBOX[0xff] != 0x16 {
        return Err("AES_SBOX[0xff]".into());
    }
    Ok(())
}

fn check_aes_key_expansion_matches_fips_197_appendix_a1() -> Result<(), String> {
    let expanded = aes128_expand_key(&FIPS_197_AES128_KEY);
    if expanded != FIPS_197_AES128_EXPANDED_KEY {
        return Err("expanded key != FIPS-197 Appendix A.1 vector".into());
    }
    if &expanded[..16] != &FIPS_197_AES128_KEY {
        return Err("first round key slice != original key".into());
    }
    let tail = &expanded[160..176];
    let expected_tail = [
        0x13, 0x11, 0x1d, 0x7f, 0xe3, 0x94, 0x4a, 0x17, 0xf3, 0x07, 0xa7, 0x8b, 0x4d, 0x2b, 0x30,
        0xc5,
    ];
    if tail != expected_tail {
        return Err("final 16 bytes of expanded key mismatch".into());
    }
    Ok(())
}

fn check_aes_shift_rows_uses_column_major_state_layout() -> Result<(), String> {
    let mut state = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    aes_shift_rows(&mut state);
    let expected = [
        0x00, 0x05, 0x0a, 0x0f, 0x04, 0x09, 0x0e, 0x03, 0x08, 0x0d, 0x02, 0x07, 0x0c, 0x01, 0x06,
        0x0b,
    ];
    if state != expected {
        return Err("ShiftRows column-major layout mismatch".into());
    }
    Ok(())
}

fn check_aes_mix_columns_matches_fips_197_column_example() -> Result<(), String> {
    let mut state = [
        0xdb, 0x13, 0x53, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    aes_mix_columns(&mut state);
    let expected = [
        0x8e, 0x4d, 0xa1, 0xbc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    if state != expected {
        return Err("MixColumns FIPS-197 column example mismatch".into());
    }
    Ok(())
}

fn check_aes_gf_mul2_reduces_by_the_aes_polynomial() -> Result<(), String> {
    if gf_mul2(0x57) != 0xae {
        return Err("gf_mul2(0x57)".into());
    }
    if gf_mul2(0x83) != 0x1d {
        return Err("gf_mul2(0x83)".into());
    }
    Ok(())
}

fn check_aes128_encrypt_block_matches_fips_197_appendix_c1() -> Result<(), String> {
    let mut block = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let round_keys = aes128_expand_key(&FIPS_197_AES128_KEY);
    aes128_encrypt_block_in_place(&mut block, &round_keys);
    let expected = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ];
    if block != expected {
        return Err("AES-128 encrypt block != FIPS-197 Appendix C.1 ciphertext".into());
    }
    Ok(())
}

fn check_aes_block_encryption_is_deterministic_for_same_key_and_block() -> Result<(), String> {
    let round_keys = aes128_expand_key(&FIPS_197_AES128_KEY);
    let mut left = [0x42u8; 16];
    let mut right = [0x42u8; 16];
    aes128_encrypt_block_in_place(&mut left, &round_keys);
    aes128_encrypt_block_in_place(&mut right, &round_keys);
    if left != right {
        return Err("two encrypt calls with same key/block produced different outputs".into());
    }
    Ok(())
}

const AES_PRIMITIVE_CASES: &[(&str, fn() -> Result<(), String>)] = &[
    (
        "aes128_oreulius_constants_match_aes128_shape",
        check_aes128_oreulius_constants_match_aes128_shape,
    ),
    (
        "aes_sbox_matches_standard_sample_points",
        check_aes_sbox_matches_standard_sample_points,
    ),
    (
        "aes_key_expansion_matches_fips_197_appendix_a1",
        check_aes_key_expansion_matches_fips_197_appendix_a1,
    ),
    (
        "aes_shift_rows_uses_column_major_state_layout",
        check_aes_shift_rows_uses_column_major_state_layout,
    ),
    (
        "aes_mix_columns_matches_fips_197_column_example",
        check_aes_mix_columns_matches_fips_197_column_example,
    ),
    (
        "aes_gf_mul2_reduces_by_the_aes_polynomial",
        check_aes_gf_mul2_reduces_by_the_aes_polynomial,
    ),
    (
        "aes128_encrypt_block_matches_fips_197_appendix_c1",
        check_aes128_encrypt_block_matches_fips_197_appendix_c1,
    ),
    (
        "aes_block_encryption_is_deterministic_for_same_key_and_block",
        check_aes_block_encryption_is_deterministic_for_same_key_and_block,
    ),
];

pub fn run_deterministic_tests() -> Vec<(&'static str, bool, String)> {
    let mut results = Vec::with_capacity(AES_PRIMITIVE_CASES.len());
    for &(name, f) in AES_PRIMITIVE_CASES {
        match f() {
            Ok(()) => results.push((name, true, "OK".to_string())),
            Err(detail) => results.push((name, false, detail)),
        }
    }
    results
}
