/*!
 * Oreulia Kernel — Fleet Operations & Attestation
 *
 * Provides two capabilities:
 *
 * 1. **Attestation** — builds a measurement bundle that summarises the current
 *    runtime state (boot tick, crash count, active OTA slot hash, scheduler
 *    context-switch count).  The bundle is a SHA-256 measurement hash over
 *    those inputs, stored as an `AttestationRecord` in the persistence log and
 *    printed to the operator console.  A CapNet `Attest` frame can be sent to a
 *    registered peer with `fleet-attest <peer-id>`.
 *
 *    Bundle layout (input to SHA-256):
 *      [0..8]   boot_tick   (u64 LE)
 *      [8..12]  crash_count (u32 LE)
 *      [12..16] boot_session(u32 LE)
 *      [16..48] active_slot_hash ([u8; 32])
 *      [48..56] sched_switches (u64 LE)
 *
 *    Total input: 56 bytes  →  32-byte SHA-256 measurement hash.
 *
 *    Persistence payload (AttestationRecord, 40 bytes):
 *      [0..4]   session      (u32 LE)
 *      [4..8]   crash_count  (u32 LE)
 *      [8..16]  boot_tick    (u64 LE)
 *      [16..48] measurement  ([u8; 32])
 *
 * 2. **Remote diagnostics** — `fleet-diag` prints a compact one-screen
 *    summary of CapNet peer state, crash ring, health snapshot, and active
 *    OTA slot.  Intended for a serial console session by a remote operator.
 */

extern crate alloc;

use crate::capnet;
use crate::crypto::{
    build_fleet_attestation_signed_message, import_hex_file, read_small_vfs_file,
    verify_detached_ed25519, DetachedSignatureStatus,
};
use crate::net_reactor;
use crate::persistence;
use crate::vga;

// ============================================================================
// Internal helpers
// ============================================================================

const PATH_FLEET_DIR: &str = "/fleet";
const PATH_ATTEST_PUBKEY: &str = "/fleet/attest.pub";
const PATH_ATTEST_SIG: &str = "/fleet/attest.sig";
const PATH_ATTEST_MSG: &str = "/fleet/attest.msg";
const PATH_ATTEST_TXT: &str = "/fleet/attest.txt";

#[derive(Clone, Copy)]
struct FleetAttestationBundle {
    boot_session: u32,
    crash_count: u32,
    boot_tick: u64,
    measurement: [u8; 32],
    active_slot_hash: [u8; 32],
    sched_switches: u64,
}

pub fn init_store() {
    let _ = crate::vfs::mkdir(PATH_FLEET_DIR);
}

fn read_active_slot_hash() -> [u8; 32] {
    // Read the manifest hash (SHA-256 of the active OTA slot image).
    // The manifest lives at /ota/manifest as 64 hex bytes.  If it cannot be
    // read we return all-zeros, which is an honest "unknown" measurement.
    let mut hex = [0u8; 64];
    match crate::vfs::read_path("/ota/manifest", &mut hex) {
        Ok(n) if n >= 64 => {}
        _ => return [0u8; 32],
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = nibble(hex[i * 2]).unwrap_or(0);
        let lo = nibble(hex[i * 2 + 1]).unwrap_or(0);
        out[i] = (hi << 4) | lo;
    }
    out
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn record_attestation(session: u32, crash_count: u32, boot_tick: u64, measurement: &[u8; 32]) {
    let cap = persistence::StoreCapability::new(0xF1F1, persistence::StoreRights::all());
    // Payload: session(4) + crash_count(4) + boot_tick(8) + measurement(32) = 48 bytes
    let mut payload = [0u8; 48];
    payload[0..4].copy_from_slice(&session.to_le_bytes());
    payload[4..8].copy_from_slice(&crash_count.to_le_bytes());
    payload[8..16].copy_from_slice(&boot_tick.to_le_bytes());
    payload[16..48].copy_from_slice(measurement);
    if let Ok(record) =
        persistence::LogRecord::new(persistence::RecordType::AttestationRecord, &payload)
    {
        let mut svc = persistence::persistence().lock();
        let _ = svc.append_log(&cap, record);
    }
}

fn build_measurement_hash(
    boot_tick: u64,
    crash_count: u32,
    boot_session: u32,
    slot_hash: &[u8; 32],
    sched_switches: u64,
) -> [u8; 32] {
    // Assemble input buffer.
    let mut input = [0u8; 56];
    input[0..8].copy_from_slice(&boot_tick.to_le_bytes());
    input[8..12].copy_from_slice(&crash_count.to_le_bytes());
    input[12..16].copy_from_slice(&boot_session.to_le_bytes());
    input[16..48].copy_from_slice(slot_hash);
    input[48..56].copy_from_slice(&sched_switches.to_le_bytes());

    crate::crypto::sha256(&input)
}

fn build_current_bundle() -> FleetAttestationBundle {
    let boot_tick = crate::asm_bindings::rdtsc_begin();
    let crash_count = crate::crash_log::crash_count();
    let boot_session = crate::crash_log::boot_session();
    let slot_hash = read_active_slot_hash();

    let sched_switches: u64 = {
        let overview = crate::quantum_scheduler::scheduler()
            .lock()
            .snapshot_overview();
        overview.total_switches
    };

    let measurement = build_measurement_hash(
        boot_tick,
        crash_count,
        boot_session,
        &slot_hash,
        sched_switches,
    );

    FleetAttestationBundle {
        boot_session,
        crash_count,
        boot_tick,
        measurement,
        active_slot_hash: slot_hash,
        sched_switches,
    }
}

/// Build the 32-byte measurement hash.
pub fn build_measurement() -> [u8; 32] {
    build_current_bundle().measurement
}

fn canonical_message_for_bundle(bundle: &FleetAttestationBundle) -> alloc::vec::Vec<u8> {
    build_fleet_attestation_signed_message(
        bundle.boot_session,
        bundle.crash_count,
        bundle.boot_tick,
        &bundle.measurement,
        &bundle.active_slot_hash,
        bundle.sched_switches,
    )
}

fn bundle_text_summary(bundle: &FleetAttestationBundle) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(256);
    out.extend_from_slice(b"Fleet Attestation Bundle\n");
    out.extend_from_slice(b"boot_session=");
    append_u32_ascii(&mut out, bundle.boot_session);
    out.extend_from_slice(b"\ncrash_count=");
    append_u32_ascii(&mut out, bundle.crash_count);
    out.extend_from_slice(b"\nboot_tick=");
    append_u64_ascii(&mut out, bundle.boot_tick);
    out.extend_from_slice(b"\nmeasurement=");
    append_hex_ascii(&mut out, &bundle.measurement);
    out.extend_from_slice(b"\nactive_slot_hash=");
    append_hex_ascii(&mut out, &bundle.active_slot_hash);
    out.extend_from_slice(b"\nsched_switches=");
    append_u64_ascii(&mut out, bundle.sched_switches);
    out.push(b'\n');
    out
}

fn write_bundle_exports(bundle: &FleetAttestationBundle) -> Result<(), &'static str> {
    init_store();
    let canonical = canonical_message_for_bundle(bundle);
    let summary = bundle_text_summary(bundle);
    crate::vfs::write_path(PATH_ATTEST_MSG, &canonical).map(|_| ())?;
    crate::vfs::write_path(PATH_ATTEST_TXT, &summary).map(|_| ())
}

fn verify_exported_bundle_signature() -> Result<DetachedSignatureStatus, &'static str> {
    let msg = read_small_vfs_file(PATH_ATTEST_MSG, 1024)?;
    verify_detached_ed25519(PATH_ATTEST_PUBKEY, PATH_ATTEST_SIG, &msg)
}

fn print_signature_state(prefix: &str, status: Result<DetachedSignatureStatus, &'static str>) {
    vga::print_str(prefix);
    match status {
        Ok(DetachedSignatureStatus::Unsigned) => vga::print_str("unsigned"),
        Ok(DetachedSignatureStatus::Verified) => vga::print_str("verified"),
        Err(e) => {
            vga::print_str("invalid: ");
            vga::print_str(e);
        }
    }
    vga::print_str("\n");
}

fn print_bundle(bundle: &FleetAttestationBundle) {
    vga::print_str("\n=== Fleet Attestation Bundle ===\n");
    vga::print_str("Boot session : ");
    print_u32(bundle.boot_session);
    vga::print_str("\nCrash count  : ");
    print_u32(bundle.crash_count);
    vga::print_str("\nBoot tick    : ");
    print_u64(bundle.boot_tick);
    vga::print_str("\nMeasurement  : ");
    print_hash(&bundle.measurement);
    vga::print_str("\nSlot hash    : ");
    print_hash(&bundle.active_slot_hash);
    vga::print_str("\nSched switch : ");
    print_u64(bundle.sched_switches);
    vga::print_str("\n");
}

fn append_u32_ascii(out: &mut alloc::vec::Vec<u8>, value: u32) {
    if value == 0 {
        out.push(b'0');
        return;
    }
    let mut v = value;
    let mut buf = [0u8; 10];
    let mut len = 0usize;
    while v > 0 {
        buf[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    while len > 0 {
        len -= 1;
        out.push(buf[len]);
    }
}

fn append_u64_ascii(out: &mut alloc::vec::Vec<u8>, value: u64) {
    if value == 0 {
        out.push(b'0');
        return;
    }
    let mut v = value;
    let mut buf = [0u8; 20];
    let mut len = 0usize;
    while v > 0 {
        buf[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    while len > 0 {
        len -= 1;
        out.push(buf[len]);
    }
}

fn append_hex_ascii(out: &mut alloc::vec::Vec<u8>, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize]);
        out.push(DIGITS[(b & 0xF) as usize]);
    }
}

fn print_hash(hash: &[u8; 32]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for &b in hash.iter() {
        vga::print_char(DIGITS[(b >> 4) as usize] as char);
        vga::print_char(DIGITS[(b & 0xF) as usize] as char);
    }
}

fn print_u32(n: u32) {
    if n == 0 {
        vga::print_char('0');
        return;
    }
    let mut buf = [0u8; 10];
    let mut i = 0;
    let mut v = n;
    while v > 0 {
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        vga::print_char(buf[i] as char);
    }
}

fn print_u64(n: u64) {
    if n == 0 {
        vga::print_char('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    let mut v = n;
    while v > 0 {
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        vga::print_char(buf[i] as char);
    }
}

// ============================================================================
// Shell commands
// ============================================================================

/// Parse a dotted-decimal IPv4 address string into a `[u8; 4]` array,
/// then convert to `smoltcp::wire::Ipv4Address` (which is just a newtype).
fn parse_ipv4(s: &str) -> Option<crate::netstack::Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut idx = 0usize;
    let mut acc: u32 = 0;
    let mut digits = 0usize;
    for ch in s.bytes() {
        if ch == b'.' {
            if idx >= 3 || digits == 0 || acc > 255 {
                return None;
            }
            octets[idx] = acc as u8;
            idx += 1;
            acc = 0;
            digits = 0;
        } else if ch >= b'0' && ch <= b'9' {
            acc = acc * 10 + (ch - b'0') as u32;
            digits += 1;
        } else {
            return None;
        }
    }
    if idx != 3 || digits == 0 || acc > 255 {
        return None;
    }
    octets[3] = acc as u8;
    Some(crate::netstack::Ipv4Addr::new(
        octets[0], octets[1], octets[2], octets[3],
    ))
}

/// `fleet-attest [peer-id <ip> <port>]`
///
/// Builds the measurement hash, records it in persistence, prints it, and
/// optionally sends a CapNet Attest frame to `peer-id` at `<ip>:<port>`.
///
/// Usage:
///   fleet-attest                          — print + record only
///   fleet-attest <peer-id> <ip> <port>    — also transmit via UDP
pub fn cmd_fleet_attest(mut parts: core::str::SplitWhitespace) {
    let bundle = build_current_bundle();
    print_bundle(&bundle);
    match write_bundle_exports(&bundle) {
        Ok(()) => {
            vga::print_str("Canonical message exported to ");
            vga::print_str(PATH_ATTEST_MSG);
            vga::print_str("\nHuman summary exported to ");
            vga::print_str(PATH_ATTEST_TXT);
            vga::print_str("\n");
        }
        Err(e) => {
            vga::print_str("fleet-attest: export failed: ");
            vga::print_str(e);
            vga::print_str("\n\n");
            return;
        }
    }

    record_attestation(
        bundle.boot_session,
        bundle.crash_count,
        bundle.boot_tick,
        &bundle.measurement,
    );
    vga::print_str("Attestation record written to persistence.\n");
    print_signature_state("Signature   : ", verify_exported_bundle_signature());

    // Optionally send CapNet Attest frame: fleet-attest <peer-id> <ip> <port>
    let peer_str = match parts.next() {
        Some(s) => s,
        None => {
            vga::print_str("Detached signature status applies to local export only.\n\n");
            vga::print_str("\n");
            return;
        }
    };

    // Parse peer-id as decimal u64.
    let mut peer_id: u64 = 0;
    let mut valid = true;
    for ch in peer_str.bytes() {
        if ch >= b'0' && ch <= b'9' {
            peer_id = peer_id
                .saturating_mul(10)
                .saturating_add((ch - b'0') as u64);
        } else {
            valid = false;
            break;
        }
    }
    if !valid || peer_id == 0 {
        vga::print_str("fleet-attest: invalid peer-id '");
        vga::print_str(peer_str);
        vga::print_str("'\n\n");
        return;
    }

    // Parse dotted-decimal IP (a.b.c.d).
    let ip_str = match parts.next() {
        Some(s) => s,
        None => {
            vga::print_str("Usage: fleet-attest <peer-id> <ip> <port>\n\n");
            return;
        }
    };
    let dest_ip = match parse_ipv4(ip_str) {
        Some(ip) => ip,
        None => {
            vga::print_str("fleet-attest: invalid IP '");
            vga::print_str(ip_str);
            vga::print_str("'\n\n");
            return;
        }
    };

    // Parse port.
    let port_str = match parts.next() {
        Some(s) => s,
        None => {
            vga::print_str("Usage: fleet-attest <peer-id> <ip> <port>\n\n");
            return;
        }
    };
    let mut port: u32 = 0;
    for ch in port_str.bytes() {
        if ch >= b'0' && ch <= b'9' {
            port = port.saturating_mul(10).saturating_add((ch - b'0') as u32);
        } else {
            vga::print_str("fleet-attest: invalid port\n\n");
            return;
        }
    }
    if port == 0 || port > 65535 {
        vga::print_str("fleet-attest: port out of range\n\n");
        return;
    }

    match net_reactor::capnet_send_attest(peer_id, dest_ip, port as u16, 0) {
        Ok(seq) => {
            vga::print_str("CapNet Attest frame sent to peer ");
            print_u64(peer_id);
            vga::print_str(" seq=");
            print_u32(seq);
            vga::print_str("\nNote: the signed bundle remains local/exported at ");
            vga::print_str(PATH_ATTEST_MSG);
            vga::print_str(
                "; the CapNet Attest frame does not carry the detached signature in this phase.\n",
            );
        }
        Err(e) => {
            vga::print_str("CapNet Attest TX failed: ");
            vga::print_str(e);
            vga::print_str("\n");
        }
    }
    vga::print_str("\n");
}

pub fn cmd_fleet_attest_export() {
    let bundle = build_current_bundle();
    print_bundle(&bundle);
    match write_bundle_exports(&bundle) {
        Ok(()) => {
            vga::print_str("Canonical message exported to ");
            vga::print_str(PATH_ATTEST_MSG);
            vga::print_str("\nHuman summary exported to ");
            vga::print_str(PATH_ATTEST_TXT);
            vga::print_str("\n");
            print_signature_state("Signature   : ", verify_exported_bundle_signature());
        }
        Err(e) => {
            vga::print_str("fleet-attest-export: ");
            vga::print_str(e);
            vga::print_str("\n");
        }
    }
    vga::print_str("\n");
}

pub fn cmd_fleet_attest_verify() {
    init_store();
    vga::print_str("fleet-attest-verify: ");
    match verify_exported_bundle_signature() {
        Ok(DetachedSignatureStatus::Unsigned) => {
            vga::print_str("bundle is unsigned\n\n");
        }
        Ok(DetachedSignatureStatus::Verified) => {
            vga::print_str("detached signature verified for ");
            vga::print_str(PATH_ATTEST_MSG);
            vga::print_str("\n\n");
        }
        Err(e) => {
            vga::print_str(e);
            vga::print_str("\n\n");
        }
    }
}

pub fn cmd_fleet_trust_key(mut parts: core::str::SplitWhitespace) {
    let src = match parts.next() {
        Some(p) => p,
        None => {
            vga::print_str("Usage: fleet-trust-key <vfs-path>\n");
            return;
        }
    };
    init_store();
    match import_hex_file::<32>(src, PATH_ATTEST_PUBKEY) {
        Ok(()) => vga::print_str("fleet-trust-key: imported trusted fleet Ed25519 public key\n"),
        Err(e) => {
            vga::print_str("fleet-trust-key: ");
            vga::print_str(e);
            vga::print_str("\n");
        }
    }
}

pub fn cmd_fleet_set_signature(mut parts: core::str::SplitWhitespace) {
    let src = match parts.next() {
        Some(p) => p,
        None => {
            vga::print_str("Usage: fleet-set-signature <vfs-path>\n");
            return;
        }
    };
    init_store();
    match import_hex_file::<64>(src, PATH_ATTEST_SIG) {
        Ok(()) => vga::print_str("fleet-set-signature: imported detached fleet signature\n"),
        Err(e) => {
            vga::print_str("fleet-set-signature: ");
            vga::print_str(e);
            vga::print_str("\n");
        }
    }
}

/// `fleet-diag` — compact remote-diagnostics dump for serial console operators.
pub fn cmd_fleet_diag() {
    vga::print_str("\n====== Fleet Remote Diagnostics ======\n");

    // --- Crash ring ---
    vga::print_str("[Crash log]\n");
    let cnt = crate::crash_log::crash_count();
    vga::print_str("  Total crashes recorded  : ");
    print_u32(cnt);
    vga::print_str("\n");
    vga::print_str("  Boot session            : ");
    print_u32(crate::crash_log::boot_session());
    vga::print_str("\n");

    let mut printed = 0u32;
    crate::crash_log::for_each_crash(|_idx, _tick, _session, _loc, _msg| {
        printed += 1;
    });
    vga::print_str("  Live ring entries       : ");
    print_u32(printed);
    vga::print_str("\n");

    // --- OTA status ---
    vga::print_str("[OTA]\n");
    let mut active_buf = [0u8; 4];
    let active = match crate::vfs::read_path("/ota/active", &mut active_buf) {
        Ok(n) if n > 0 && active_buf[0] == b'b' => "b",
        Ok(_) => "a",
        Err(_) => "unknown",
    };
    vga::print_str("  Active slot             : ");
    vga::print_str(active);
    vga::print_str("\n");

    let slot_a_sz = crate::vfs::path_size("/ota/slot_a").unwrap_or(0);
    let slot_b_sz = crate::vfs::path_size("/ota/slot_b").unwrap_or(0);
    vga::print_str("  Slot A size             : ");
    print_u64(slot_a_sz as u64);
    vga::print_str(" B\n");
    vga::print_str("  Slot B size             : ");
    print_u64(slot_b_sz as u64);
    vga::print_str(" B\n");

    // --- Measurement ---
    vga::print_str("[Attestation]\n");
    let bundle = build_current_bundle();
    vga::print_str("  Measurement hash        : ");
    print_hash(&bundle.measurement);
    vga::print_str("\n  Slot hash               : ");
    print_hash(&bundle.active_slot_hash);
    vga::print_str("\n  Signed bundle           : ");
    match verify_exported_bundle_signature() {
        Ok(DetachedSignatureStatus::Unsigned) => vga::print_str("unsigned"),
        Ok(DetachedSignatureStatus::Verified) => vga::print_str("verified"),
        Err(_) => vga::print_str("invalid"),
    }
    vga::print_str("\n");

    // --- Scheduler overview ---
    vga::print_str("[Scheduler]\n");
    let overview = crate::quantum_scheduler::scheduler()
        .lock()
        .snapshot_overview();
    vga::print_str("  Total processes         : ");
    print_u32(overview.total_processes as u32);
    vga::print_str("\n");
    vga::print_str("  Running processes       : ");
    print_u32(overview.running_processes as u32);
    vga::print_str("\n");
    vga::print_str("  Context switches        : ");
    print_u64(overview.total_switches);
    vga::print_str("\n");

    // --- Persistence log ---
    vga::print_str("[Persistence]\n");
    let (log_used, log_cap) = persistence::persistence().lock().log_stats();
    vga::print_str("  Log records             : ");
    print_u64(log_used as u64);
    vga::print_str(" / ");
    print_u64(log_cap as u64);
    vga::print_str("\n");

    // --- CapNet peer count ---
    vga::print_str("[CapNet]\n");
    let snapshots = capnet::peer_snapshots();
    let peer_count = snapshots.iter().filter(|s| s.is_some()).count();
    vga::print_str("  Registered peers        : ");
    print_u32(peer_count as u32);
    vga::print_str("\n");

    vga::print_str("======================================\n\n");
}
