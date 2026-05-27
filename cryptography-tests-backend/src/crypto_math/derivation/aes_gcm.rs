use crate::{aes128_gcm_decrypt, aes128_gcm_encrypt};

pub fn run_deterministic_tests() -> Vec<(&'static str, bool, String)> {
    let mut results = Vec::new();

    let key = [0u8; 16];
    let iv = [0u8; 12];
    let aad: &[u8] = &[];
    let pt = b"deterministic plaintext for AES-GCM";

    let mut ct = vec![0u8; pt.len()];
    let tag = aes128_gcm_encrypt(&key, &iv, aad, pt, &mut ct);

    let mut out = vec![0u8; pt.len()];
    match aes128_gcm_decrypt(&key, &iv, aad, &ct, &tag, &mut out) {
        Ok(()) => {
            if out.as_slice() == pt {
                results.push(("aes_gcm_encrypt_decrypt_roundtrip", true, "OK".to_string()));
            } else {
                results.push((
                    "aes_gcm_roundtrip",
                    false,
                    "plaintext mismatch after decrypt".to_string(),
                ));
            }
        }
        Err(()) => results.push((
            "aes_gcm_decrypt_fail",
            false,
            "decryption reported tag mismatch".to_string(),
        )),
    }

    results
}
