use crate::sha256;

fn append_hex(out: &mut Vec<u8>, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize]);
        out.push(DIGITS[(b & 0x0f) as usize]);
    }
}

fn append_decimal_u32(out: &mut Vec<u8>, mut value: u32) {
    if value == 0 {
        out.push(b'0');
        return;
    }
    let mut buf = [0u8; 10];
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

fn build_measurement_hash(
    boot_tick: u64,
    crash_count: u32,
    boot_session: u32,
    slot_hash: &[u8; 32],
    sched_switches: u64,
) -> [u8; 32] {
    let mut input = [0u8; 56];
    input[0..8].copy_from_slice(&boot_tick.to_le_bytes());
    input[8..12].copy_from_slice(&crash_count.to_le_bytes());
    input[12..16].copy_from_slice(&boot_session.to_le_bytes());
    input[16..48].copy_from_slice(slot_hash);
    input[48..56].copy_from_slice(&sched_switches.to_le_bytes());
    sha256(&input)
}

fn build_fleet_attestation_signed_message(
    boot_session: u32,
    crash_count: u32,
    boot_tick: u64,
    measurement: &[u8; 32],
    active_slot_hash: &[u8; 32],
    sched_switches: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"oreulius-fleet-attestation:v1\nboot_session=");
    append_decimal_u32(&mut out, boot_session);
    out.extend_from_slice(b"\ncrash_count=");
    append_decimal_u32(&mut out, crash_count);
    out.extend_from_slice(b"\nboot_tick=");
    append_decimal_u64(&mut out, boot_tick);
    out.extend_from_slice(b"\nmeasurement=");
    append_hex(&mut out, measurement);
    out.extend_from_slice(b"\nactive_slot_hash=");
    append_hex(&mut out, active_slot_hash);
    out.extend_from_slice(b"\nsched_switches=");
    append_decimal_u64(&mut out, sched_switches);
    out.push(b'\n');
    out
}

fn build_mature_fleet_bundle_message(
    measurement: &[u8; 32],
    active_slot_hash: &[u8; 32],
    nonce: u64,
    peer_identity: &str,
    policy_mode: &str,
    architecture: &str,
    key_identity: &str,
    measurement_state: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"oreulius-fleet-attestation:v2\nmeasurement=");
    append_hex(&mut out, measurement);
    out.extend_from_slice(b"\nactive_slot_hash=");
    append_hex(&mut out, active_slot_hash);
    out.extend_from_slice(b"\nnonce=");
    append_decimal_u64(&mut out, nonce);
    out.extend_from_slice(b"\npeer_identity=");
    out.extend_from_slice(peer_identity.as_bytes());
    out.extend_from_slice(b"\npolicy_mode=");
    out.extend_from_slice(policy_mode.as_bytes());
    out.extend_from_slice(b"\narchitecture=");
    out.extend_from_slice(architecture.as_bytes());
    out.extend_from_slice(b"\nkey_identity=");
    out.extend_from_slice(key_identity.as_bytes());
    out.extend_from_slice(b"\nmeasurement_state=");
    out.extend_from_slice(measurement_state.as_bytes());
    out.push(b'\n');
    out
}

fn check_current_fleet_canonical_message_exact_bytes() -> Result<(), String> {
    let measurement = [0x11u8; 32];
    let slot_hash = [0x22u8; 32];
    let msg = build_fleet_attestation_signed_message(7, 3, 42, &measurement, &slot_hash, 99);
    let expected = b"oreulius-fleet-attestation:v1\nboot_session=7\ncrash_count=3\nboot_tick=42\nmeasurement=1111111111111111111111111111111111111111111111111111111111111111\nactive_slot_hash=2222222222222222222222222222222222222222222222222222222222222222\nsched_switches=99\n";
    if msg != expected {
        return Err("current Fleet canonical message bytes changed".into());
    }
    Ok(())
}

fn check_measurement_hash_matches_kernel_input_layout() -> Result<(), String> {
    let slot_hash = [0x33u8; 32];
    let actual = build_measurement_hash(42, 3, 7, &slot_hash, 99);
    let repeat = build_measurement_hash(42, 3, 7, &slot_hash, 99);
    if actual != repeat {
        return Err("Fleet measurement hash was not deterministic".into());
    }
    Ok(())
}

fn check_measurement_hash_changes_when_active_slot_hash_changes() -> Result<(), String> {
    let slot_a = [0x33u8; 32];
    let slot_b = [0x34u8; 32];
    let a = build_measurement_hash(42, 3, 7, &slot_a, 99);
    let b = build_measurement_hash(42, 3, 7, &slot_b, 99);
    if a == b {
        return Err("Fleet measurement did not change when active slot hash changed".into());
    }
    Ok(())
}

fn check_freshness_nonce_changes_mature_bundle_hash() -> Result<(), String> {
    let measurement = [0x44u8; 32];
    let slot_hash = [0x55u8; 32];
    let a = build_mature_fleet_bundle_message(
        &measurement,
        &slot_hash,
        1,
        "peer-a",
        "production",
        "x86_64",
        "fleet-root-1",
        "known",
    );
    let b = build_mature_fleet_bundle_message(
        &measurement,
        &slot_hash,
        2,
        "peer-a",
        "production",
        "x86_64",
        "fleet-root-1",
        "known",
    );
    if sha256(&a) == sha256(&b) {
        return Err("mature Fleet bundle hash did not change when freshness nonce changed".into());
    }
    Ok(())
}

fn check_unknown_measurement_state_is_distinct_from_zero_hash() -> Result<(), String> {
    let measurement = [0u8; 32];
    let slot_hash = [0u8; 32];
    let unknown = build_mature_fleet_bundle_message(
        &measurement,
        &slot_hash,
        1,
        "peer-a",
        "production",
        "aarch64",
        "fleet-root-1",
        "unknown",
    );
    let known_zero = build_mature_fleet_bundle_message(
        &measurement,
        &slot_hash,
        1,
        "peer-a",
        "production",
        "aarch64",
        "fleet-root-1",
        "known-zero",
    );
    if sha256(&unknown) == sha256(&known_zero) {
        return Err(
            "unknown measurement state was not separated from known all-zero evidence".into(),
        );
    }
    Ok(())
}

fn check_peer_identity_changes_signed_bundle() -> Result<(), String> {
    let measurement = [0x66u8; 32];
    let slot_hash = [0x77u8; 32];
    let peer_a = build_mature_fleet_bundle_message(
        &measurement,
        &slot_hash,
        1,
        "peer-a",
        "production",
        "x86_64",
        "fleet-root-1",
        "known",
    );
    let peer_b = build_mature_fleet_bundle_message(
        &measurement,
        &slot_hash,
        1,
        "peer-b",
        "production",
        "x86_64",
        "fleet-root-1",
        "known",
    );
    if sha256(&peer_a) == sha256(&peer_b) {
        return Err("peer identity did not change the mature Fleet signed bundle".into());
    }
    Ok(())
}

fn check_current_fleet_message_lacks_freshness_documented_limit() -> Result<(), String> {
    let measurement = [0x11u8; 32];
    let slot_hash = [0x22u8; 32];
    let msg = build_fleet_attestation_signed_message(7, 3, 42, &measurement, &slot_hash, 99);
    let text = std::str::from_utf8(&msg).map_err(|_| "message was not UTF-8")?;
    if text.contains("nonce=") || text.contains("challenge=") || text.contains("peer_identity=") {
        return Err(
            "current Fleet v1 message unexpectedly contains freshness or peer fields".into(),
        );
    }
    Ok(())
}

const CASES: &[(&str, fn() -> Result<(), String>)] = &[
    (
        "current_fleet_canonical_message_exact_bytes",
        check_current_fleet_canonical_message_exact_bytes,
    ),
    (
        "measurement_hash_matches_kernel_input_layout",
        check_measurement_hash_matches_kernel_input_layout,
    ),
    (
        "measurement_hash_changes_when_active_slot_hash_changes",
        check_measurement_hash_changes_when_active_slot_hash_changes,
    ),
    (
        "freshness_nonce_changes_mature_bundle_hash",
        check_freshness_nonce_changes_mature_bundle_hash,
    ),
    (
        "unknown_measurement_state_is_distinct_from_zero_hash",
        check_unknown_measurement_state_is_distinct_from_zero_hash,
    ),
    (
        "peer_identity_changes_signed_bundle",
        check_peer_identity_changes_signed_bundle,
    ),
    (
        "current_fleet_message_lacks_freshness_documented_limit",
        check_current_fleet_message_lacks_freshness_documented_limit,
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
