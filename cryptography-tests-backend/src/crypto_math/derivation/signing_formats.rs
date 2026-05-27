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

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_hex_bytes_kernel_shape<const N: usize>(bytes: &[u8]) -> Result<[u8; N], &'static str> {
    if bytes.len() < N * 2 {
        return Err("hex payload too short");
    }
    let mut out = [0u8; N];
    for i in 0..N {
        let hi = hex_nibble(bytes[i * 2]).ok_or("invalid hex")?;
        let lo = hex_nibble(bytes[i * 2 + 1]).ok_or("invalid hex")?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn parse_hex_bytes_strict<const N: usize>(bytes: &[u8]) -> Result<[u8; N], &'static str> {
    if bytes.len() != N * 2 {
        return Err("hex payload wrong length");
    }
    parse_hex_bytes_kernel_shape(bytes)
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

fn check_ota_manifest_signed_message_exact_bytes() -> Result<(), String> {
    let hash = [0xabu8; 32];
    let msg = build_ota_manifest_signed_message(&hash, "v1.2.3");
    let expected = b"oreulius-ota-manifest:v1\nhash=abababababababababababababababababababababababababababababababab\nversion=v1.2.3\n";
    if msg != expected {
        return Err("OTA canonical message bytes do not match kernel format".into());
    }
    Ok(())
}

fn check_fleet_attestation_signed_message_exact_bytes() -> Result<(), String> {
    let measurement = [0x11u8; 32];
    let slot_hash = [0x22u8; 32];
    let msg = build_fleet_attestation_signed_message(7, 3, 42, &measurement, &slot_hash, 99);
    let expected = b"oreulius-fleet-attestation:v1\nboot_session=7\ncrash_count=3\nboot_tick=42\nmeasurement=1111111111111111111111111111111111111111111111111111111111111111\nactive_slot_hash=2222222222222222222222222222222222222222222222222222222222222222\nsched_switches=99\n";
    if msg != expected {
        return Err("Fleet canonical message bytes do not match kernel format".into());
    }
    Ok(())
}

fn check_hex_encoding_is_lowercase_and_fixed_width() -> Result<(), String> {
    let hash = [0xAFu8; 32];
    let msg = build_ota_manifest_signed_message(&hash, "v");
    let text = std::str::from_utf8(&msg).map_err(|_| "message was not UTF-8")?;
    if !text.contains("hash=afafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafaf") {
        return Err("hash was not lowercase fixed-width hex".into());
    }
    Ok(())
}

fn check_decimal_encoding_has_no_padding() -> Result<(), String> {
    let measurement = [0u8; 32];
    let slot_hash = [1u8; 32];
    let msg = build_fleet_attestation_signed_message(0, 5, 10, &measurement, &slot_hash, u64::MAX);
    let text = std::str::from_utf8(&msg).map_err(|_| "message was not UTF-8")?;
    if !text.contains("boot_session=0\ncrash_count=5\nboot_tick=10") {
        return Err("decimal fields were not written in plain no-padding form".into());
    }
    if !text.contains("sched_switches=18446744073709551615\n") {
        return Err("u64 decimal encoding did not preserve full value".into());
    }
    Ok(())
}

fn check_current_hex_parser_accepts_trailing_data_documented_limit() -> Result<(), String> {
    let mut input = vec![b'a'; 64];
    input.extend_from_slice(b"trailing-data");
    let parsed = parse_hex_bytes_kernel_shape::<32>(&input)
        .map_err(|e| format!("kernel-shaped parser rejected trailing data unexpectedly: {e}"))?;
    if parsed != [0xaau8; 32] {
        return Err("kernel-shaped parser did not parse the first exact hex payload".into());
    }
    Ok(())
}

fn check_strict_parser_rejects_trailing_data_future_rule() -> Result<(), String> {
    let mut input = vec![b'a'; 64];
    input.push(b'0');
    if parse_hex_bytes_strict::<32>(&input).is_ok() {
        return Err("strict parser accepted trailing data".into());
    }
    Ok(())
}

fn check_ota_version_bytes_are_currently_unescaped_documented_limit() -> Result<(), String> {
    let hash = [0x11u8; 32];
    let msg = build_ota_manifest_signed_message(&hash, "v1\npolicy=debug");
    let text = std::str::from_utf8(&msg).map_err(|_| "message was not UTF-8")?;
    if !text.contains("version=v1\npolicy=debug\n") {
        return Err("test expected current writer to preserve raw version bytes".into());
    }
    Ok(())
}

fn check_current_ota_message_lacks_target_slot_metadata_documented_limit() -> Result<(), String> {
    let hash = [0x22u8; 32];
    let msg = build_ota_manifest_signed_message(&hash, "v2");
    let text = std::str::from_utf8(&msg).map_err(|_| "message was not UTF-8")?;
    if text.contains("target_slot=") || text.contains("rollback_generation=") {
        return Err("current OTA message unexpectedly contains mature metadata fields".into());
    }
    Ok(())
}

const CASES: &[(&str, fn() -> Result<(), String>)] = &[
    (
        "ota_manifest_signed_message_exact_bytes",
        check_ota_manifest_signed_message_exact_bytes,
    ),
    (
        "fleet_attestation_signed_message_exact_bytes",
        check_fleet_attestation_signed_message_exact_bytes,
    ),
    (
        "hex_encoding_is_lowercase_and_fixed_width",
        check_hex_encoding_is_lowercase_and_fixed_width,
    ),
    (
        "decimal_encoding_has_no_padding",
        check_decimal_encoding_has_no_padding,
    ),
    (
        "current_hex_parser_accepts_trailing_data_documented_limit",
        check_current_hex_parser_accepts_trailing_data_documented_limit,
    ),
    (
        "strict_parser_rejects_trailing_data_future_rule",
        check_strict_parser_rejects_trailing_data_future_rule,
    ),
    (
        "ota_version_bytes_are_currently_unescaped_documented_limit",
        check_ota_version_bytes_are_currently_unescaped_documented_limit,
    ),
    (
        "current_ota_message_lacks_target_slot_metadata_documented_limit",
        check_current_ota_message_lacks_target_slot_metadata_documented_limit,
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
