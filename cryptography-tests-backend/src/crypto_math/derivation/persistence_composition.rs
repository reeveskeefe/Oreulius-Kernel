use crate::{
    aes128_encrypt_block_in_place, aes128_expand_key, ct_eq, hkdf_expand_label_sha256,
    hkdf_extract, hmac_sha256,
};

struct SnapshotKeys {
    enc_key: [u8; 16],
    mac_key: [u8; 32],
    nonce: u64,
}

fn append_decimal_u64(out: &mut Vec<u8>, mut value: u64) {
    if value == 0 {
        out.push(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut len = 0usize;
    while value > 0 {
        buf[len] = b'0' + (value % 10) as u8;
        value /= 10;
        len += 1;
    }
    while len > 0 {
        len -= 1;
        out.push(buf[len]);
    }
}

fn snapshot_context(purpose: &[u8], generation: u64, slot: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"purpose=");
    out.extend_from_slice(purpose);
    out.extend_from_slice(b"\ngeneration=");
    append_decimal_u64(&mut out, generation);
    out.extend_from_slice(b"\nslot=");
    out.extend_from_slice(slot);
    out.push(b'\n');
    out
}

fn derive_snapshot_keys(
    seal_key: &[u8],
    purpose: &[u8],
    generation: u64,
    slot: &[u8],
) -> SnapshotKeys {
    let salt = b"oreulius-persistence-seal:v1";
    let prk = hkdf_extract(salt, seal_key);
    let context = snapshot_context(purpose, generation, slot);
    let enc_key: [u8; 16] = hkdf_expand_label_sha256(&prk, b"snapshot enc", &context);
    let mac_key: [u8; 32] = hkdf_expand_label_sha256(&prk, b"snapshot mac", &context);
    let nonce_bytes: [u8; 8] = hkdf_expand_label_sha256(&prk, b"snapshot nonce", &context);
    SnapshotKeys {
        enc_key,
        mac_key,
        nonce: u64::from_le_bytes(nonce_bytes),
    }
}

fn ctr_keystream_block(key: &[u8; 16], nonce: u64, counter: u64) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[0..8].copy_from_slice(&nonce.to_le_bytes());
    block[8..16].copy_from_slice(&counter.to_le_bytes());
    let round_keys = aes128_expand_key(key);
    aes128_encrypt_block_in_place(&mut block, &round_keys);
    block
}

fn aes128_ctr_apply(key: &[u8; 16], nonce: u64, data: &mut [u8]) {
    for (counter, chunk) in data.chunks_mut(16).enumerate() {
        let ks = ctr_keystream_block(key, nonce, counter as u64);
        for i in 0..chunk.len() {
            chunk[i] ^= ks[i];
        }
    }
}

fn seal_record_mac(keys: &SnapshotKeys, header: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(header);
    mac_input.extend_from_slice(ciphertext);
    hmac_sha256(&keys.mac_key, &mac_input)
}

fn check_snapshot_key_derivation_separates_purpose_labels() -> Result<(), String> {
    let seal = b"root seal key for persistence tests";
    let generic = derive_snapshot_keys(seal, b"generic-state", 7, b"slot-a");
    let vfs = derive_snapshot_keys(seal, b"vfs-state", 7, b"slot-a");
    if generic.enc_key == vfs.enc_key
        || generic.mac_key == vfs.mac_key
        || generic.nonce == vfs.nonce
    {
        return Err("snapshot keys were not separated by purpose label".into());
    }
    Ok(())
}

fn check_snapshot_key_derivation_binds_generation() -> Result<(), String> {
    let seal = b"root seal key for persistence tests";
    let gen7 = derive_snapshot_keys(seal, b"generic-state", 7, b"slot-a");
    let gen8 = derive_snapshot_keys(seal, b"generic-state", 8, b"slot-a");
    if gen7.enc_key == gen8.enc_key || gen7.mac_key == gen8.mac_key || gen7.nonce == gen8.nonce {
        return Err("snapshot keys were not separated by rollback generation".into());
    }
    Ok(())
}

fn check_aes_ctr_snapshot_roundtrip_restores_plaintext() -> Result<(), String> {
    let keys = derive_snapshot_keys(b"seal", b"temporal-state", 1, b"slot-a");
    let original = b"snapshot bytes that represent kernel state".to_vec();
    let mut data = original.clone();
    aes128_ctr_apply(&keys.enc_key, keys.nonce, &mut data);
    if data == original {
        return Err("AES-CTR snapshot encryption did not change plaintext".into());
    }
    aes128_ctr_apply(&keys.enc_key, keys.nonce, &mut data);
    if data != original {
        return Err("AES-CTR snapshot decryption did not restore plaintext".into());
    }
    Ok(())
}

fn check_snapshot_hmac_detects_ciphertext_tamper() -> Result<(), String> {
    let keys = derive_snapshot_keys(b"seal", b"generic-state", 2, b"slot-a");
    let header = snapshot_context(b"generic-state", 2, b"slot-a");
    let mut ciphertext = b"sealed snapshot body".to_vec();
    aes128_ctr_apply(&keys.enc_key, keys.nonce, &mut ciphertext);
    let tag = seal_record_mac(&keys, &header, &ciphertext);
    ciphertext[0] ^= 1;
    let tampered_tag = seal_record_mac(&keys, &header, &ciphertext);
    if ct_eq(&tag, &tampered_tag) {
        return Err("snapshot HMAC did not change after ciphertext tamper".into());
    }
    Ok(())
}

fn check_snapshot_hmac_detects_metadata_tamper() -> Result<(), String> {
    let keys = derive_snapshot_keys(b"seal", b"generic-state", 2, b"slot-a");
    let header = snapshot_context(b"generic-state", 2, b"slot-a");
    let ciphertext = b"sealed snapshot body".to_vec();
    let tag = seal_record_mac(&keys, &header, &ciphertext);
    let tampered_header = snapshot_context(b"generic-state", 3, b"slot-a");
    let tampered_tag = seal_record_mac(&keys, &tampered_header, &ciphertext);
    if ct_eq(&tag, &tampered_tag) {
        return Err("snapshot HMAC did not change after metadata tamper".into());
    }
    Ok(())
}

fn check_rollback_generation_prevents_old_record_acceptance_under_new_keys() -> Result<(), String> {
    let seal = b"root seal key for persistence tests";
    let old_keys = derive_snapshot_keys(seal, b"generic-state", 4, b"slot-a");
    let new_keys = derive_snapshot_keys(seal, b"generic-state", 5, b"slot-a");
    let old_header = snapshot_context(b"generic-state", 4, b"slot-a");
    let ciphertext = b"old encrypted snapshot".to_vec();
    let old_tag = seal_record_mac(&old_keys, &old_header, &ciphertext);
    let new_tag = seal_record_mac(&new_keys, &old_header, &ciphertext);
    if ct_eq(&old_tag, &new_tag) {
        return Err("old snapshot MAC verified under new rollback generation keys".into());
    }
    Ok(())
}

const CASES: &[(&str, fn() -> Result<(), String>)] = &[
    (
        "snapshot_key_derivation_separates_purpose_labels",
        check_snapshot_key_derivation_separates_purpose_labels,
    ),
    (
        "snapshot_key_derivation_binds_generation",
        check_snapshot_key_derivation_binds_generation,
    ),
    (
        "aes_ctr_snapshot_roundtrip_restores_plaintext",
        check_aes_ctr_snapshot_roundtrip_restores_plaintext,
    ),
    (
        "snapshot_hmac_detects_ciphertext_tamper",
        check_snapshot_hmac_detects_ciphertext_tamper,
    ),
    (
        "snapshot_hmac_detects_metadata_tamper",
        check_snapshot_hmac_detects_metadata_tamper,
    ),
    (
        "rollback_generation_prevents_old_record_acceptance_under_new_keys",
        check_rollback_generation_prevents_old_record_acceptance_under_new_keys,
    ),
];

pub fn run_deterministic_tests() -> Vec<(&'static str, bool, String)> {
    let mut results = Vec::with_capacity(CASES.len());
    for &(name, f) in CASES {
        match f() {
            Ok(()) => results.push((name, true, "OK".to_string())),
            Err(detail) => results.push((name, false, detail)),
        }
    }
    results
}
