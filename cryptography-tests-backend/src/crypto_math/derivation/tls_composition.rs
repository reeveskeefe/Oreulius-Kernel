use crate::{
    aes128_gcm_decrypt, aes128_gcm_encrypt, ct_eq, hkdf_expand_label_sha256, hkdf_extract,
    hmac_sha256, sha256, x25519_public_key, x25519_shared_secret,
};

fn tls13_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    nonce
}

fn derive_handshake_secret(client_private: &[u8; 32], server_private: &[u8; 32]) -> [u8; 32] {
    let server_public = x25519_public_key(server_private);
    let shared = x25519_shared_secret(client_private, &server_public);
    hkdf_extract(&[0u8; 32], &shared)
}

fn check_x25519_shared_secret_matches_both_tls_sides() -> Result<(), String> {
    let client_private = [0x11u8; 32];
    let server_private = [0x22u8; 32];
    let client_public = x25519_public_key(&client_private);
    let server_public = x25519_public_key(&server_private);
    let client_shared = x25519_shared_secret(&client_private, &server_public);
    let server_shared = x25519_shared_secret(&server_private, &client_public);
    if client_shared != server_shared {
        return Err("client and server did not derive the same X25519 shared secret".into());
    }
    Ok(())
}

fn check_tls_hkdf_traffic_secrets_are_direction_separated() -> Result<(), String> {
    let secret = derive_handshake_secret(&[0x11u8; 32], &[0x22u8; 32]);
    let transcript = sha256(b"clienthello||serverhello");
    let client_hs: [u8; 32] = hkdf_expand_label_sha256(&secret, b"c hs traffic", &transcript);
    let server_hs: [u8; 32] = hkdf_expand_label_sha256(&secret, b"s hs traffic", &transcript);
    if client_hs == server_hs {
        return Err("client and server handshake traffic secrets matched".into());
    }
    let client_key: [u8; 16] = hkdf_expand_label_sha256(&client_hs, b"key", b"");
    let server_key: [u8; 16] = hkdf_expand_label_sha256(&server_hs, b"key", b"");
    let client_iv: [u8; 12] = hkdf_expand_label_sha256(&client_hs, b"iv", b"");
    let server_iv: [u8; 12] = hkdf_expand_label_sha256(&server_hs, b"iv", b"");
    if client_key == server_key || client_iv == server_iv {
        return Err("derived TLS keys or IVs were not separated by direction".into());
    }
    Ok(())
}

fn check_tls_transcript_hash_changes_finished_key_path() -> Result<(), String> {
    let secret = derive_handshake_secret(&[0x12u8; 32], &[0x34u8; 32]);
    let th1 = sha256(b"clienthello||serverhello");
    let th2 = sha256(b"clienthello||serverhello!");
    let s1: [u8; 32] = hkdf_expand_label_sha256(&secret, b"s hs traffic", &th1);
    let s2: [u8; 32] = hkdf_expand_label_sha256(&secret, b"s hs traffic", &th2);
    if s1 == s2 {
        return Err("changing the transcript did not change the handshake traffic secret".into());
    }
    Ok(())
}

fn check_tls_finished_verify_data_is_hmac_over_transcript_hash() -> Result<(), String> {
    let secret = derive_handshake_secret(&[0x21u8; 32], &[0x43u8; 32]);
    let th = sha256(b"full-handshake-transcript");
    let server_hs: [u8; 32] = hkdf_expand_label_sha256(&secret, b"s hs traffic", &th);
    let finished_key: [u8; 32] = hkdf_expand_label_sha256(&server_hs, b"finished", b"");
    let verify_data = hmac_sha256(&finished_key, &th);
    let expected = hmac_sha256(&finished_key, &th);
    if !ct_eq(&verify_data, &expected) {
        return Err(
            "Finished verify data did not match HMAC(finished_key, transcript_hash)".into(),
        );
    }
    let tampered = sha256(b"full-handshake-transcript!");
    if ct_eq(&verify_data, &hmac_sha256(&finished_key, &tampered)) {
        return Err("Finished verify data accepted a different transcript hash".into());
    }
    Ok(())
}

fn check_tls_record_aes_gcm_roundtrip_with_record_aad() -> Result<(), String> {
    let key = [0x31u8; 16];
    let iv = [0x42u8; 12];
    let nonce = tls13_nonce(&iv, 0);
    let plaintext = b"record payload";
    let aad = [23u8, 0x03, 0x03, 0x00, (plaintext.len() + 16) as u8];
    let mut ciphertext = vec![0u8; plaintext.len()];
    let tag = aes128_gcm_encrypt(&key, &nonce, &aad, plaintext, &mut ciphertext);
    let mut out = vec![0u8; plaintext.len()];
    aes128_gcm_decrypt(&key, &nonce, &aad, &ciphertext, &tag, &mut out)
        .map_err(|_| "AES-GCM record decrypt rejected valid record")?;
    if out != plaintext {
        return Err("AES-GCM record plaintext mismatch".into());
    }
    Ok(())
}

fn check_tls_record_aad_tamper_is_rejected() -> Result<(), String> {
    let key = [0x31u8; 16];
    let iv = [0x42u8; 12];
    let nonce = tls13_nonce(&iv, 0);
    let plaintext = b"record payload";
    let aad = [23u8, 0x03, 0x03, 0x00, (plaintext.len() + 16) as u8];
    let mut ciphertext = vec![0u8; plaintext.len()];
    let tag = aes128_gcm_encrypt(&key, &nonce, &aad, plaintext, &mut ciphertext);
    let mut tampered_aad = aad;
    tampered_aad[4] ^= 1;
    let mut out = vec![0u8; plaintext.len()];
    if aes128_gcm_decrypt(&key, &nonce, &tampered_aad, &ciphertext, &tag, &mut out).is_ok() {
        return Err("AES-GCM accepted a record with tampered associated data".into());
    }
    Ok(())
}

fn check_tls_nonce_xors_sequence_number_into_last_eight_bytes() -> Result<(), String> {
    let iv = [
        0x10, 0x11, 0x12, 0x13, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x55,
    ];
    let nonce = tls13_nonce(&iv, 0x0102_0304_0506_0708);
    if nonce[0..4] != iv[0..4] {
        return Err("TLS nonce changed prefix bytes outside the sequence XOR area".into());
    }
    let expected_tail: [u8; 8] =
        core::array::from_fn(|i| iv[4 + i] ^ (0x0102_0304_0506_0708u64.to_be_bytes()[i]));
    if nonce[4..12] != expected_tail {
        return Err("TLS nonce tail did not equal static IV tail XOR big-endian sequence".into());
    }
    Ok(())
}

const CASES: &[(&str, fn() -> Result<(), String>)] = &[
    (
        "x25519_shared_secret_matches_both_tls_sides",
        check_x25519_shared_secret_matches_both_tls_sides,
    ),
    (
        "tls_hkdf_traffic_secrets_are_direction_separated",
        check_tls_hkdf_traffic_secrets_are_direction_separated,
    ),
    (
        "tls_transcript_hash_changes_finished_key_path",
        check_tls_transcript_hash_changes_finished_key_path,
    ),
    (
        "tls_finished_verify_data_is_hmac_over_transcript_hash",
        check_tls_finished_verify_data_is_hmac_over_transcript_hash,
    ),
    (
        "tls_record_aes_gcm_roundtrip_with_record_aad",
        check_tls_record_aes_gcm_roundtrip_with_record_aad,
    ),
    (
        "tls_record_aad_tamper_is_rejected",
        check_tls_record_aad_tamper_is_rejected,
    ),
    (
        "tls_nonce_xors_sequence_number_into_last_eight_bytes",
        check_tls_nonce_xors_sequence_number_into_last_eight_bytes,
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
