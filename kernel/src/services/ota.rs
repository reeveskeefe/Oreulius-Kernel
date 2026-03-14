/*!
 * Oreulia Kernel — OTA Update Manager
 *
 * Implements A/B image slot management for over-the-air firmware updates:
 *
 *   Slot A  — VFS path `/ota/slot_a`
 *   Slot B  — VFS path `/ota/slot_b`
 *   Active  — VFS path `/ota/active`   (contains "a" or "b")
 *   Manifest— VFS path `/ota/manifest` (contains the expected SHA-256 hex of
 *                                        the pending slot image, 64 ASCII bytes)
 *
 * Lifecycle:
 *   1. `ota-apply <vfs-path>` — copy image from `<vfs-path>` into the inactive
 *      slot, compute SHA-256, store it in `/ota/manifest`, mark slot `Pending`.
 *      Writes an `OtaUpdate` persistence record (phase = Apply).
 *   2. Next boot (manual here): `ota-commit` — verify the pending slot against
 *      the manifest hash, switch active pointer, write OtaUpdate(Commit).
 *   3. `ota-rollback` — revert the active pointer to the other slot, write
 *      OtaUpdate(Rollback).
 *   4. `ota-status` — show current slot state and manifest hash.
 *
 * Note: actual device reboot / flash write is out-of-scope for this kernel
 * profile.  This module manages the slot metadata and integrity check; a
 * real production system would additionally write to a persistent flash sector
 * or EEPROM and trigger a hardware reset.
 */

extern crate alloc;

use crate::persistence;
use crate::vfs;
use crate::vga;

// ============================================================================
// Constants
// ============================================================================

const PATH_SLOT_A: &str = "/ota/slot_a";
const PATH_SLOT_B: &str = "/ota/slot_b";
const PATH_ACTIVE: &str = "/ota/active";
const PATH_MANIFEST: &str = "/ota/manifest";
const PATH_OTA_DIR: &str = "/ota";
/// Stores the staged image version string (up to 32 ASCII bytes).
const PATH_VERSION: &str = "/ota/version";
/// Rollback sentinel: written by init_slots when a crash is detected at boot.
const PATH_ROLLBACK_SENTINEL: &str = "/ota/rollback_needed";

/// Phase tag stored in the OtaUpdate persistence record.
#[repr(u8)]
enum OtaPhase {
    Apply = 1,
    Commit = 2,
    Rollback = 3,
    Verify = 4,
}

// ============================================================================
// Slot state
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotId {
    A,
    B,
}

impl SlotId {
    pub fn as_str(self) -> &'static str {
        match self {
            SlotId::A => "a",
            SlotId::B => "b",
        }
    }
    pub fn vfs_path(self) -> &'static str {
        match self {
            SlotId::A => PATH_SLOT_A,
            SlotId::B => PATH_SLOT_B,
        }
    }
    pub fn other(self) -> SlotId {
        match self {
            SlotId::A => SlotId::B,
            SlotId::B => SlotId::A,
        }
    }
}

// ============================================================================
// Module init
// ============================================================================

/// Ensure the `/ota` directory and active pointer file exist.
///
/// Crash-rollback guard: if the crash_log recorded at least one panic since
/// the previous `on_boot()` flush and a rollback sentinel exists, revert the
/// active slot pointer.  This catches boot-loop scenarios where a committed
/// OTA image causes an immediate kernel panic.
pub fn init_slots() {
    let _ = vfs::mkdir(PATH_OTA_DIR);

    // If no active pointer exists, default to slot A.
    let mut buf = [0u8; 4];
    if vfs::read_path(PATH_ACTIVE, &mut buf).is_err() {
        let _ = vfs::write_path(PATH_ACTIVE, b"a");
    }

    // Crash-rollback: if crash_count > 0 at boot and a sentinel is present,
    // the previous slot caused a crash — revert before continuing.
    let crash_count = crate::crash_log::crash_count();
    let mut sentinel_buf = [0u8; 1];
    let sentinel_present = vfs::read_path(PATH_ROLLBACK_SENTINEL, &mut sentinel_buf).is_ok();

    if crash_count > 0 && sentinel_present {
        // Determine the current (crashing) slot and revert.
        let bad_slot = active_slot();
        let safe_slot = bad_slot.other();
        crate::serial_println!(
            "[OTA] crash detected at boot (count={}) — reverting slot {} -> {}",
            crash_count,
            bad_slot.as_str(),
            safe_slot.as_str()
        );
        let _ = set_active_slot(safe_slot);
        // Remove the sentinel so we don't loop.
        let _ = vfs::unlink(PATH_ROLLBACK_SENTINEL);
        record_ota_event(OtaPhase::Rollback, safe_slot, &[0u8; 32]);
    } else if sentinel_present {
        // Clean boot with sentinel — remove it (previous boot was fine).
        let _ = vfs::unlink(PATH_ROLLBACK_SENTINEL);
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

fn active_slot() -> SlotId {
    let mut buf = [0u8; 4];
    match vfs::read_path(PATH_ACTIVE, &mut buf) {
        Ok(n) if n > 0 && buf[0] == b'b' => SlotId::B,
        _ => SlotId::A,
    }
}

fn set_active_slot(slot: SlotId) -> Result<(), &'static str> {
    vfs::write_path(PATH_ACTIVE, slot.as_str().as_bytes()).map(|_| ())
}

fn read_manifest() -> Option<[u8; 32]> {
    // Manifest is stored as 64 hex ASCII bytes (lowercase) = 32 raw bytes.
    let mut hex = [0u8; 64];
    let n = vfs::read_path(PATH_MANIFEST, &mut hex).ok()?;
    if n < 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(hex[i * 2])?;
        let lo = hex_nibble(hex[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn write_manifest(hash: &[u8; 32], version: &str) -> Result<(), &'static str> {
    let mut hex = [0u8; 64];
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for i in 0..32 {
        hex[i * 2] = DIGITS[(hash[i] >> 4) as usize];
        hex[i * 2 + 1] = DIGITS[(hash[i] & 0xF) as usize];
    }
    vfs::write_path(PATH_MANIFEST, &hex).map(|_| ())?;
    // Also store the version tag (truncated to 32 bytes).
    let vbytes = version.as_bytes();
    let vlen = vbytes.len().min(32);
    let _ = vfs::write_path(PATH_VERSION, &vbytes[..vlen]);
    Ok(())
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Write an OtaUpdate persistence record.
fn record_ota_event(phase: OtaPhase, slot: SlotId, hash: &[u8; 32]) {
    let cap = persistence::StoreCapability::new(0xF0F0, persistence::StoreRights::all());
    // Payload: [phase:u8, slot:u8, hash:32 bytes] = 34 bytes
    let mut payload = [0u8; 34];
    payload[0] = phase as u8;
    payload[1] = match slot {
        SlotId::A => 0,
        SlotId::B => 1,
    };
    payload[2..34].copy_from_slice(hash);
    if let Ok(record) =
        persistence::LogRecord::new(persistence::RecordType::OtaUpdate, &payload)
    {
        let mut svc = persistence::persistence().lock();
        let _ = svc.append_log(&cap, record);
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

fn print_hash(hash: &[u8; 32]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for &b in hash.iter() {
        vga::print_char(DIGITS[(b >> 4) as usize] as char);
        vga::print_char(DIGITS[(b & 0xF) as usize] as char);
    }
}

// ============================================================================
// Shell commands
// ============================================================================

/// `ota-status` — show active slot, pending slot, and manifest hash.
pub fn cmd_ota_status() {
    let active = active_slot();
    let pending = active.other();

    vga::print_str("\n=== OTA Slot Status ===\n");
    vga::print_str("Active slot  : ");
    vga::print_str(active.as_str());
    vga::print_str("\nPending slot : ");
    vga::print_str(pending.as_str());
    vga::print_str("\n");

    // Check if each slot has content.
    let mut dummy = [0u8; 1];
    let a_has = vfs::read_path(PATH_SLOT_A, &mut dummy).map(|n| n).unwrap_or(0);
    let b_has = vfs::read_path(PATH_SLOT_B, &mut dummy).map(|n| n).unwrap_or(0);

    vga::print_str("Slot A size  : ");
    match vfs::path_size(PATH_SLOT_A) {
        Ok(n) => { print_u32(n as u32); vga::print_str(" bytes"); }
        Err(_) => vga::print_str("(empty)"),
    }
    let _ = a_has;
    vga::print_str("\nSlot B size  : ");
    match vfs::path_size(PATH_SLOT_B) {
        Ok(n) => { print_u32(n as u32); vga::print_str(" bytes"); }
        Err(_) => vga::print_str("(empty)"),
    }
    let _ = b_has;

    vga::print_str("\nManifest hash: ");
    match read_manifest() {
        Some(hash) => print_hash(&hash),
        None => vga::print_str("(none)"),
    }
    vga::print_str("\n\n");
}

/// `ota-apply <vfs-path> [version]` — stage an image from VFS into the inactive slot.
pub fn cmd_ota_apply(mut parts: core::str::SplitWhitespace) {
    let src = match parts.next() {
        Some(p) => p,
        None => {
            vga::print_str("Usage: ota-apply <vfs-path> [version]\n");
            return;
        }
    };
    // Optional version string (defaults to "unknown").
    let version = parts.next().unwrap_or("unknown");

    // Determine inactive slot.
    let target_slot = active_slot().other();

    vga::print_str("ota-apply: staging ");
    vga::print_str(src);
    vga::print_str(" -> slot ");
    vga::print_str(target_slot.as_str());
    vga::print_str(" ...\n");

    // Read the image from VFS.
    let size = match vfs::path_size(src) {
        Ok(n) => n,
        Err(e) => {
            vga::print_str("ota-apply: stat failed: ");
            vga::print_str(e);
            vga::print_str("\n");
            return;
        }
    };

    if size == 0 {
        vga::print_str("ota-apply: source file is empty\n");
        return;
    }

    let mut buf = alloc::vec::Vec::new();
    buf.resize(size, 0u8);
    let n = match vfs::read_path(src, &mut buf) {
        Ok(n) => n,
        Err(e) => {
            vga::print_str("ota-apply: read failed: ");
            vga::print_str(e);
            vga::print_str("\n");
            return;
        }
    };
    buf.truncate(n);

    // Compute SHA-256 of the image.
    let hash = crate::crypto::sha256(&buf);

    vga::print_str("ota-apply: SHA-256 = ");
    print_hash(&hash);
    vga::print_str("\n");

    // Write image to inactive slot.
    match vfs::write_path(target_slot.vfs_path(), &buf) {
        Ok(_) => {}
        Err(e) => {
            vga::print_str("ota-apply: write to slot failed: ");
            vga::print_str(e);
            vga::print_str("\n");
            return;
        }
    }

    // Store manifest hash.
    if let Err(e) = write_manifest(&hash, version) {
        vga::print_str("ota-apply: manifest write failed: ");
        vga::print_str(e);
        vga::print_str("\n");
        return;
    }

    // Record lifecycle event.
    record_ota_event(OtaPhase::Apply, target_slot, &hash);

    vga::print_str("ota-apply: slot ");
    vga::print_str(target_slot.as_str());
    vga::print_str(" staged OK (");
    print_u32(n as u32);
    vga::print_str(" bytes)\n");
    vga::print_str("  Run 'ota-commit' to verify and activate.\n");
}

/// `ota-commit` — verify the inactive slot and switch the active pointer.
pub fn cmd_ota_commit() {
    let target_slot = active_slot().other();

    vga::print_str("ota-commit: verifying slot ");
    vga::print_str(target_slot.as_str());
    vga::print_str(" ...\n");

    // Read the manifest hash.
    let expected = match read_manifest() {
        Some(h) => h,
        None => {
            vga::print_str("ota-commit: no manifest found — run ota-apply first\n");
            return;
        }
    };

    // Read the pending slot image.
    let size = match vfs::path_size(target_slot.vfs_path()) {
        Ok(n) => n,
        Err(_) => {
            vga::print_str("ota-commit: pending slot is empty\n");
            return;
        }
    };

    let mut buf = alloc::vec::Vec::new();
    buf.resize(size, 0u8);
    let n = match vfs::read_path(target_slot.vfs_path(), &mut buf) {
        Ok(n) => n,
        Err(e) => {
            vga::print_str("ota-commit: read failed: ");
            vga::print_str(e);
            vga::print_str("\n");
            return;
        }
    };
    buf.truncate(n);

    // Compute and compare hash.
    let actual = crate::crypto::sha256(&buf);
    if !crate::crypto::ct_eq(&actual, &expected) {
        vga::print_str("ota-commit: INTEGRITY FAILURE — hash mismatch!\n");
        vga::print_str("  Expected: ");
        print_hash(&expected);
        vga::print_str("\n  Actual  : ");
        print_hash(&actual);
        vga::print_str("\n");
        record_ota_event(OtaPhase::Verify, target_slot, &actual);
        return;
    }

    vga::print_str("ota-commit: integrity OK — switching active to slot ");
    vga::print_str(target_slot.as_str());
    vga::print_str(" ...\n");

    if let Err(e) = set_active_slot(target_slot) {
        vga::print_str("ota-commit: failed to write active pointer: ");
        vga::print_str(e);
        vga::print_str("\n");
        return;
    }

    // Write rollback sentinel so init_slots can auto-revert if the new slot panics.
    let _ = vfs::write_path(PATH_ROLLBACK_SENTINEL, b"1");

    record_ota_event(OtaPhase::Commit, target_slot, &actual);
    vga::print_str("ota-commit: committed. Reboot to boot from slot ");
    vga::print_str(target_slot.as_str());
    vga::print_str(".\n");
}

// ============================================================================
// Verified boot stub
// ============================================================================

/// Boot-time integrity check: compare the active slot image against the stored
/// manifest hash.  Non-fatal — logs to serial and persistence if mismatched
/// but does not halt.  A real verified-boot implementation would perform this
/// in the bootloader; this stub provides a software-level sanity check.
pub fn verify_boot_image() {
    let active = active_slot();

    // Read manifest hash.
    let expected = match read_manifest() {
        Some(h) => h,
        None => {
            crate::serial_println!("[VerifiedBoot] no manifest — skipping image check");
            return;
        }
    };

    // Read active slot image.
    let size = match vfs::path_size(active.vfs_path()) {
        Ok(n) if n > 0 => n,
        _ => {
            crate::serial_println!("[VerifiedBoot] slot {} is empty — skipping", active.as_str());
            return;
        }
    };

    let mut buf = alloc::vec::Vec::new();
    buf.resize(size, 0u8);
    let n = match vfs::read_path(active.vfs_path(), &mut buf) {
        Ok(n) => n,
        Err(e) => {
            crate::serial_println!("[VerifiedBoot] read failed: {}", e);
            return;
        }
    };
    buf.truncate(n);

    let actual = crate::crypto::sha256(&buf);

    if crate::crypto::ct_eq(&actual, &expected) {
        crate::serial_println!("[VerifiedBoot] slot {} integrity OK", active.as_str());
    } else {
        crate::serial_println!(
            "[VerifiedBoot] INTEGRITY MISMATCH on slot {} — image may be corrupted!",
            active.as_str()
        );
        // Record the verification failure in persistence.
        record_ota_event(OtaPhase::Verify, active, &actual);
    }
}

/// `ota-rollback` — switch active pointer back to the other slot.
pub fn cmd_ota_rollback() {
    let current = active_slot();
    let fallback = current.other();

    vga::print_str("ota-rollback: reverting from slot ");
    vga::print_str(current.as_str());
    vga::print_str(" to slot ");
    vga::print_str(fallback.as_str());
    vga::print_str(" ...\n");

    if let Err(e) = set_active_slot(fallback) {
        vga::print_str("ota-rollback: failed: ");
        vga::print_str(e);
        vga::print_str("\n");
        return;
    }

    let dummy_hash = [0u8; 32];
    record_ota_event(OtaPhase::Rollback, fallback, &dummy_hash);
    vga::print_str("ota-rollback: active slot is now ");
    vga::print_str(fallback.as_str());
    vga::print_str(". Reboot to take effect.\n");
}
