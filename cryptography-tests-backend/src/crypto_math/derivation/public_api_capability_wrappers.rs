use crate::{aes128_gcm_decrypt, aes128_gcm_encrypt};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Right {
    TlsRead,
    TlsWrite,
    OtaVerify,
    OtaActivate,
    SnapshotSeal,
    SnapshotUnseal,
    FleetAttest,
    KeyImport,
}

#[derive(Clone, Copy)]
struct Capability {
    object: &'static str,
    generation: u64,
    rights: &'static [Right],
}

impl Capability {
    fn has(self, right: Right) -> bool {
        self.rights.iter().any(|r| *r == right)
    }
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

fn capability_aad(cap: Capability, seq: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"oreulius-capability-wrapper:v1\nobject=");
    out.extend_from_slice(cap.object.as_bytes());
    out.extend_from_slice(b"\ngeneration=");
    append_decimal_u64(&mut out, cap.generation);
    out.extend_from_slice(b"\nseq=");
    append_decimal_u64(&mut out, seq);
    out.push(b'\n');
    out
}

fn safe_tls_write(
    cap: Capability,
    key: &[u8; 16],
    iv: &[u8; 12],
    seq: u64,
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), &'static str> {
    if !cap.has(Right::TlsWrite) {
        return Err("TLS_WRITE required");
    }
    let aad = capability_aad(cap, seq);
    let mut ciphertext = vec![0u8; plaintext.len()];
    let tag = aes128_gcm_encrypt(key, iv, &aad, plaintext, &mut ciphertext);
    Ok((ciphertext, tag))
}

fn safe_tls_read(
    cap: Capability,
    key: &[u8; 16],
    iv: &[u8; 12],
    seq: u64,
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, &'static str> {
    if !cap.has(Right::TlsRead) {
        return Err("TLS_READ required");
    }
    let aad = capability_aad(cap, seq);
    let mut plaintext = vec![0u8; ciphertext.len()];
    aes128_gcm_decrypt(key, iv, &aad, ciphertext, tag, &mut plaintext)
        .map_err(|_| "authenticated decrypt failed")?;
    Ok(plaintext)
}

fn require_right(cap: Capability, right: Right, message: &'static str) -> Result<(), &'static str> {
    if cap.has(right) {
        Ok(())
    } else {
        Err(message)
    }
}

fn check_raw_aes_gcm_still_computes_without_authority_context() -> Result<(), String> {
    let key = [0u8; 16];
    let iv = [0u8; 12];
    let plaintext = b"raw primitive";
    let mut ciphertext = vec![0u8; plaintext.len()];
    let tag = aes128_gcm_encrypt(&key, &iv, b"", plaintext, &mut ciphertext);
    let mut out = vec![0u8; plaintext.len()];
    aes128_gcm_decrypt(&key, &iv, b"", &ciphertext, &tag, &mut out)
        .map_err(|_| "raw AES-GCM roundtrip failed")?;
    if out != plaintext {
        return Err("raw AES-GCM roundtrip produced wrong plaintext".into());
    }
    Ok(())
}

fn check_tls_write_without_write_right_is_denied() -> Result<(), String> {
    let cap = Capability {
        object: "tls-session-1",
        generation: 1,
        rights: &[Right::TlsRead],
    };
    if safe_tls_write(cap, &[0u8; 16], &[0u8; 12], 0, b"payload").is_ok() {
        return Err("TLS write wrapper allowed a read-only capability".into());
    }
    Ok(())
}

fn check_tls_read_write_rights_do_not_cross_directions() -> Result<(), String> {
    let write_cap = Capability {
        object: "tls-session-1",
        generation: 1,
        rights: &[Right::TlsWrite],
    };
    let read_cap = Capability {
        object: "tls-session-1",
        generation: 1,
        rights: &[Right::TlsRead],
    };
    let key = [1u8; 16];
    let iv = [2u8; 12];
    let (ciphertext, tag) = safe_tls_write(write_cap, &key, &iv, 0, b"payload")
        .map_err(|e| format!("TLS write wrapper rejected write capability: {e}"))?;
    if safe_tls_read(write_cap, &key, &iv, 0, &ciphertext, &tag).is_ok() {
        return Err("TLS read wrapper allowed a write-only capability".into());
    }
    let plaintext = safe_tls_read(read_cap, &key, &iv, 0, &ciphertext, &tag)
        .map_err(|e| format!("TLS read wrapper rejected read capability: {e}"))?;
    if plaintext != b"payload" {
        return Err("TLS wrapper read produced wrong plaintext".into());
    }
    Ok(())
}

fn check_capability_context_is_authenticated_by_aad() -> Result<(), String> {
    let writer = Capability {
        object: "tls-session-1",
        generation: 1,
        rights: &[Right::TlsWrite],
    };
    let wrong_reader = Capability {
        object: "tls-session-2",
        generation: 1,
        rights: &[Right::TlsRead],
    };
    let key = [3u8; 16];
    let iv = [4u8; 12];
    let (ciphertext, tag) = safe_tls_write(writer, &key, &iv, 0, b"payload")
        .map_err(|e| format!("TLS write failed unexpectedly: {e}"))?;
    if safe_tls_read(wrong_reader, &key, &iv, 0, &ciphertext, &tag).is_ok() {
        return Err("capability wrapper accepted ciphertext under the wrong session object".into());
    }
    Ok(())
}

fn check_ota_activate_requires_activate_not_only_verify() -> Result<(), String> {
    let verify_only = Capability {
        object: "ota-slot-b",
        generation: 2,
        rights: &[Right::OtaVerify],
    };
    if require_right(
        verify_only,
        Right::OtaActivate,
        "OTA_SLOT_ACTIVATE required",
    )
    .is_ok()
    {
        return Err("OTA activate decision accepted verify-only authority".into());
    }
    Ok(())
}

fn check_snapshot_seal_unseal_rights_are_separate() -> Result<(), String> {
    let seal_only = Capability {
        object: "snapshot-vfs",
        generation: 5,
        rights: &[Right::SnapshotSeal],
    };
    if require_right(seal_only, Right::SnapshotUnseal, "SNAPSHOT_UNSEAL required").is_ok() {
        return Err("snapshot unseal accepted seal-only authority".into());
    }
    Ok(())
}

fn check_fleet_attestation_and_key_import_rights_are_separate() -> Result<(), String> {
    let attest_only = Capability {
        object: "fleet",
        generation: 1,
        rights: &[Right::FleetAttest],
    };
    if require_right(attest_only, Right::KeyImport, "KEY_IMPORT required").is_ok() {
        return Err("Fleet key import accepted attestation-only authority".into());
    }
    Ok(())
}

const CASES: &[(&str, fn() -> Result<(), String>)] = &[
    (
        "raw_aes_gcm_still_computes_without_authority_context",
        check_raw_aes_gcm_still_computes_without_authority_context,
    ),
    (
        "tls_write_without_write_right_is_denied",
        check_tls_write_without_write_right_is_denied,
    ),
    (
        "tls_read_write_rights_do_not_cross_directions",
        check_tls_read_write_rights_do_not_cross_directions,
    ),
    (
        "capability_context_is_authenticated_by_aad",
        check_capability_context_is_authenticated_by_aad,
    ),
    (
        "ota_activate_requires_activate_not_only_verify",
        check_ota_activate_requires_activate_not_only_verify,
    ),
    (
        "snapshot_seal_unseal_rights_are_separate",
        check_snapshot_seal_unseal_rights_are_separate,
    ),
    (
        "fleet_attestation_and_key_import_rights_are_separate",
        check_fleet_attestation_and_key_import_rights_are_separate,
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
