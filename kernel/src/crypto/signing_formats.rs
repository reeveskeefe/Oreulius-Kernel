/*!
 * Shared detached-signature and canonical message helpers for signed artifacts.
 */

extern crate alloc;

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DetachedSignatureStatus {
    Unsigned,
    Verified,
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn append_hex(out: &mut Vec<u8>, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize]);
        out.push(DIGITS[(b & 0x0f) as usize]);
    }
}

pub fn read_small_vfs_file(path: &str, max_len: usize) -> Result<Vec<u8>, &'static str> {
    let size = crate::vfs::path_size(path).map_err(|_| "stat failed")?;
    if size == 0 {
        return Err("file is empty");
    }
    let mut buf = Vec::new();
    buf.resize(size.min(max_len), 0u8);
    let n = crate::vfs::read_path(path, &mut buf).map_err(|_| "read failed")?;
    buf.truncate(n);
    Ok(buf)
}

pub fn parse_hex_bytes<const N: usize>(bytes: &[u8]) -> Result<[u8; N], &'static str> {
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

pub fn read_hex_file<const N: usize>(path: &str) -> Result<[u8; N], &'static str> {
    let hex = read_small_vfs_file(path, N * 2 + 16)?;
    parse_hex_bytes::<N>(&hex)
}

pub fn import_hex_file<const N: usize>(src: &str, dst: &str) -> Result<(), &'static str> {
    let buf = read_small_vfs_file(src, N * 2 + 16)?;
    let parsed = parse_hex_bytes::<N>(&buf)?;
    let mut hex = Vec::with_capacity(N * 2);
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for i in 0..N {
        hex.push(DIGITS[(parsed[i] >> 4) as usize]);
        hex.push(DIGITS[(parsed[i] & 0x0f) as usize]);
    }
    crate::vfs::write_path(dst, &hex).map(|_| ())
}

pub fn verify_detached_ed25519(
    pubkey_path: &str,
    signature_path: &str,
    message: &[u8],
) -> Result<DetachedSignatureStatus, &'static str> {
    let pubkey = match read_hex_file::<32>(pubkey_path) {
        Ok(key) => Some(key),
        Err(_) => None,
    };
    let signature = match read_hex_file::<64>(signature_path) {
        Ok(sig) => Some(sig),
        Err(_) => None,
    };

    match (pubkey, signature) {
        (None, None) => Ok(DetachedSignatureStatus::Unsigned),
        (Some(_), None) => Err("trusted public key configured but detached signature missing"),
        (None, Some(_)) => Err("detached signature present but trusted public key missing"),
        (Some(pk), Some(sig)) => {
            if crate::crypto::ed25519_verify(&pk, message, &sig) {
                Ok(DetachedSignatureStatus::Verified)
            } else {
                Err("Ed25519 detached signature verification failed")
            }
        }
    }
}

pub fn build_ota_manifest_signed_message(hash: &[u8; 32], version: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 64 + version.len());
    out.extend_from_slice(b"oreulia-ota-manifest:v1\nhash=");
    append_hex(&mut out, hash);
    out.extend_from_slice(b"\nversion=");
    out.extend_from_slice(version.as_bytes());
    out.push(b'\n');
    out
}

pub fn build_fleet_attestation_signed_message(
    boot_session: u32,
    crash_count: u32,
    boot_tick: u64,
    measurement: &[u8; 32],
    active_slot_hash: &[u8; 32],
    sched_switches: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"oreulia-fleet-attestation:v1\nboot_session=");
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

#[cfg(test)]
mod tests {
    use super::{build_fleet_attestation_signed_message, build_ota_manifest_signed_message};

    #[test]
    fn fleet_message_is_stable() {
        let measurement = [0x11u8; 32];
        let slot_hash = [0x22u8; 32];
        let msg = build_fleet_attestation_signed_message(7, 3, 42, &measurement, &slot_hash, 99);
        assert_eq!(
            core::str::from_utf8(&msg).unwrap(),
            "oreulia-fleet-attestation:v1\nboot_session=7\ncrash_count=3\nboot_tick=42\nmeasurement=1111111111111111111111111111111111111111111111111111111111111111\nactive_slot_hash=2222222222222222222222222222222222222222222222222222222222222222\nsched_switches=99\n"
        );
    }

    #[test]
    fn ota_message_is_stable() {
        let hash = [0xabu8; 32];
        let msg = build_ota_manifest_signed_message(&hash, "v1.2.3");
        assert_eq!(
            core::str::from_utf8(&msg).unwrap(),
            "oreulia-ota-manifest:v1\nhash=abababababababababababababababababababababababababababababababab\nversion=v1.2.3\n"
        );
    }
}
