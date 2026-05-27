use crate::{ct_eq, sha256};

fn append_hex(out: &mut Vec<u8>, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize]);
        out.push(DIGITS[(b & 0x0f) as usize]);
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

fn build_ota_manifest_signed_message(hash: &[u8; 32], version: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 64 + version.len());
    out.extend_from_slice(b"oreulius-ota-manifest:v1\nhash=");
    append_hex(&mut out, hash);
    out.extend_from_slice(b"\nversion=");
    out.extend_from_slice(version.as_bytes());
    out.push(b'\n');
    out
}

fn build_mature_ota_metadata_record(
    image_hash: &[u8; 32],
    version: &str,
    target_slot: &str,
    rollback_generation: u64,
    key_identity: &str,
    policy_mode: &str,
    slot_state: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"oreulius-ota-metadata:v1\nimage_hash=");
    append_hex(&mut out, image_hash);
    out.extend_from_slice(b"\nversion=");
    out.extend_from_slice(version.as_bytes());
    out.extend_from_slice(b"\ntarget_slot=");
    out.extend_from_slice(target_slot.as_bytes());
    out.extend_from_slice(b"\nrollback_generation=");
    append_decimal_u64(&mut out, rollback_generation);
    out.extend_from_slice(b"\nkey_identity=");
    out.extend_from_slice(key_identity.as_bytes());
    out.extend_from_slice(b"\npolicy_mode=");
    out.extend_from_slice(policy_mode.as_bytes());
    out.extend_from_slice(b"\nslot_state=");
    out.extend_from_slice(slot_state.as_bytes());
    out.push(b'\n');
    out
}

fn build_commit_state_record(target_slot: &str, phase: &str, image_hash: &[u8; 32]) -> [u8; 32] {
    let mut out = Vec::new();
    out.extend_from_slice(b"oreulius-ota-commit-state:v1\nslot=");
    out.extend_from_slice(target_slot.as_bytes());
    out.extend_from_slice(b"\nphase=");
    out.extend_from_slice(phase.as_bytes());
    out.extend_from_slice(b"\nimage_hash=");
    append_hex(&mut out, image_hash);
    out.push(b'\n');
    sha256(&out)
}

fn production_signature_policy(status: &str, production: bool) -> Result<(), &'static str> {
    match (status, production) {
        ("verified", _) => Ok(()),
        ("unsigned", false) => Ok(()),
        ("unsigned", true) => Err("unsigned OTA manifest rejected in production"),
        _ => Err("invalid OTA signature status"),
    }
}

fn check_image_hash_binds_manifest_bytes() -> Result<(), String> {
    let image = b"new inactive slot image bytes";
    let image_hash = sha256(image);
    let manifest = build_ota_manifest_signed_message(&image_hash, "v1.0.0");
    if !manifest.starts_with(b"oreulius-ota-manifest:v1\nhash=") {
        return Err("OTA manifest did not start with expected domain header".into());
    }
    let tampered_image_hash = sha256(b"new inactive slot image bytes!");
    if ct_eq(&image_hash, &tampered_image_hash) {
        return Err("tampered image produced same SHA-256 hash".into());
    }
    Ok(())
}

fn check_current_ota_canonical_manifest_exact_bytes() -> Result<(), String> {
    let hash = [0xabu8; 32];
    let msg = build_ota_manifest_signed_message(&hash, "v1.2.3");
    let expected = b"oreulius-ota-manifest:v1\nhash=abababababababababababababababababababababababababababababababab\nversion=v1.2.3\n";
    if msg != expected {
        return Err("current OTA canonical message bytes changed".into());
    }
    Ok(())
}

fn check_constant_time_hash_decision_accepts_exact_rejects_tamper() -> Result<(), String> {
    let expected = sha256(b"slot image");
    let actual = sha256(b"slot image");
    let tampered = sha256(b"slot image!");
    if !ct_eq(&expected, &actual) {
        return Err("ct_eq rejected identical OTA image hashes".into());
    }
    if ct_eq(&expected, &tampered) {
        return Err("ct_eq accepted different OTA image hashes".into());
    }
    Ok(())
}

fn check_mature_metadata_record_binds_target_slot() -> Result<(), String> {
    let hash = sha256(b"slot image");
    let slot_a = build_mature_ota_metadata_record(
        &hash,
        "v2",
        "A",
        9,
        "root-key-1",
        "production",
        "verified",
    );
    let slot_b = build_mature_ota_metadata_record(
        &hash,
        "v2",
        "B",
        9,
        "root-key-1",
        "production",
        "verified",
    );
    if sha256(&slot_a) == sha256(&slot_b) {
        return Err("mature OTA metadata hash did not change when target slot changed".into());
    }
    Ok(())
}

fn check_commit_state_phase_changes_digest() -> Result<(), String> {
    let hash = sha256(b"slot image");
    let staged = build_commit_state_record("B", "staged", &hash);
    let committed = build_commit_state_record("B", "committed", &hash);
    if staged == committed {
        return Err("commit state digest did not change across staged and committed phases".into());
    }
    Ok(())
}

fn check_production_policy_rejects_unsigned_manifest() -> Result<(), String> {
    if production_signature_policy("unsigned", true).is_ok() {
        return Err("production OTA policy accepted an unsigned manifest".into());
    }
    if production_signature_policy("unsigned", false).is_err() {
        return Err("non-production OTA policy rejected unsigned manifest unexpectedly".into());
    }
    if production_signature_policy("verified", true).is_err() {
        return Err("production OTA policy rejected verified manifest".into());
    }
    Ok(())
}

const CASES: &[(&str, fn() -> Result<(), String>)] = &[
    (
        "image_hash_binds_manifest_bytes",
        check_image_hash_binds_manifest_bytes,
    ),
    (
        "current_ota_canonical_manifest_exact_bytes",
        check_current_ota_canonical_manifest_exact_bytes,
    ),
    (
        "constant_time_hash_decision_accepts_exact_rejects_tamper",
        check_constant_time_hash_decision_accepts_exact_rejects_tamper,
    ),
    (
        "mature_metadata_record_binds_target_slot",
        check_mature_metadata_record_binds_target_slot,
    ),
    (
        "commit_state_phase_changes_digest",
        check_commit_state_phase_changes_digest,
    ),
    (
        "production_policy_rejects_unsigned_manifest",
        check_production_policy_rejects_unsigned_manifest,
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
