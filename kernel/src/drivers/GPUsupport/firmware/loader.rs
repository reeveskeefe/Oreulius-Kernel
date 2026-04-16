// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this file is governed by the Business Source License 1.1
// included in the LICENSE file at the root of this repository.
//
// Additional Use Grant: Personal use, research, education, evaluation,
// benchmarking, and internal non-production testing are permitted.
// Production use, commercial deployment, embedded commercial products,
// and paid hosted services require a separate commercial license.
//
// Change Date: 2030-04-15
// Change License: Apache License 2.0


/*!
 * GPU firmware loader — VFS-backed loading path.
 *
 * Firmware blobs are loaded from `/firmware/gpu/<vendor_id>_<device_id>.bin`
 * via the kernel VFS (`crate::fs::vfs::read_path`), then validated with
 * `super::verify::verify_blob` and `FirmwareManifest` version checks.
 *
 * # Fallback chain
 * 1. Try exact-match path: `/firmware/gpu/<vendor_id>_<device_id>.bin`
 * 2. Try vendor-wildcard path: `/firmware/gpu/<vendor_id>_any.bin`
 * 3. Return `GpuError::FirmwareRequired` (driver may still work without it)
 *
 * # Path conventions
 * Vendor/device IDs are formatted as 4-digit lowercase hex (e.g. `8086_1234`).
 */

use super::manifest::FirmwareManifest;
use super::verify;
use crate::drivers::x86::gpu_support::errors::GpuError;
use crate::fs::vfs;

// ---------------------------------------------------------------------------
// FirmwareBlob
// ---------------------------------------------------------------------------

/// A loaded, validated firmware image.
pub struct FirmwareBlob {
    /// Raw bytes of the validated blob.
    ///
    /// On the heap via `alloc::vec::Vec`; the caller owns this allocation.
    pub bytes: alloc::vec::Vec<u8>,
    /// Manifest the blob was validated against.
    pub manifest: FirmwareManifest,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum firmware blob size we're willing to load into kernel memory.
const MAX_FIRMWARE_SIZE: usize = 1024 * 1024; // 1 MiB

/// VFS base directory for GPU firmware.
const FIRMWARE_BASE: &str = "/firmware/gpu";

// ---------------------------------------------------------------------------
// Path formatting helpers
// ---------------------------------------------------------------------------

fn exact_path(buf: &mut [u8; 64], vendor: u16, device: u16) -> &str {
    // Format: /firmware/gpu/VVVV_DDDD.bin  (14 chars base + 13 = 27)
    let vendor_hi = (vendor >> 8) as u8;
    let vendor_lo = (vendor & 0xFF) as u8;
    let device_hi = (device >> 8) as u8;
    let device_lo = (device & 0xFF) as u8;

    let bytes = [
        b'/',
        b'f',
        b'i',
        b'r',
        b'm',
        b'w',
        b'a',
        b'r',
        b'e',
        b'/',
        b'g',
        b'p',
        b'u',
        b'/',
        hex_nibble(vendor_hi >> 4),
        hex_nibble(vendor_hi & 0xF),
        hex_nibble(vendor_lo >> 4),
        hex_nibble(vendor_lo & 0xF),
        b'_',
        hex_nibble(device_hi >> 4),
        hex_nibble(device_hi & 0xF),
        hex_nibble(device_lo >> 4),
        hex_nibble(device_lo & 0xF),
        b'.',
        b'b',
        b'i',
        b'n',
    ];
    let n = bytes.len();
    buf[..n].copy_from_slice(&bytes);
    core::str::from_utf8(&buf[..n]).unwrap_or(FIRMWARE_BASE)
}

fn vendor_path(buf: &mut [u8; 64], vendor: u16) -> &str {
    // Format: /firmware/gpu/VVVV_any.bin
    let vendor_hi = (vendor >> 8) as u8;
    let vendor_lo = (vendor & 0xFF) as u8;
    let bytes = [
        b'/',
        b'f',
        b'i',
        b'r',
        b'm',
        b'w',
        b'a',
        b'r',
        b'e',
        b'/',
        b'g',
        b'p',
        b'u',
        b'/',
        hex_nibble(vendor_hi >> 4),
        hex_nibble(vendor_hi & 0xF),
        hex_nibble(vendor_lo >> 4),
        hex_nibble(vendor_lo & 0xF),
        b'_',
        b'a',
        b'n',
        b'y',
        b'.',
        b'b',
        b'i',
        b'n',
    ];
    let n = bytes.len();
    buf[..n].copy_from_slice(&bytes);
    core::str::from_utf8(&buf[..n]).unwrap_or(FIRMWARE_BASE)
}

#[inline]
fn hex_nibble(n: u8) -> u8 {
    match n & 0xF {
        0..=9 => b'0' + (n & 0xF),
        _ => b'a' + (n & 0xF) - 10,
    }
}

// ---------------------------------------------------------------------------
// Internal loader
// ---------------------------------------------------------------------------

fn try_load_path(path: &str, manifest: &FirmwareManifest) -> Result<FirmwareBlob, GpuError> {
    // Query file size first (avoid over-allocating).
    let size = vfs::path_size(path).map_err(|_| GpuError::FirmwareRequired)?;
    if size == 0 || size > MAX_FIRMWARE_SIZE {
        return Err(GpuError::FirmwareRequired);
    }

    let mut bytes = alloc::vec![0u8; size];
    let n = vfs::read_path(path, &mut bytes).map_err(|_| GpuError::FirmwareRequired)?;
    bytes.truncate(n);

    // Validate blob integrity.
    verify::verify_blob(&bytes).map_err(|_| GpuError::FirmwareRequired)?;

    Ok(FirmwareBlob {
        bytes,
        manifest: *manifest,
    })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load GPU firmware for the device described by `manifest`.
///
/// Tries the exact-match path first, then the vendor-wildcard path.
/// Returns `GpuError::FirmwareRequired` if neither is present or valid.
pub fn load_external(manifest: &FirmwareManifest) -> Result<FirmwareBlob, GpuError> {
    let mut exact_buf = [0u8; 64];
    let mut vendor_buf = [0u8; 64];

    let exact = exact_path(&mut exact_buf, manifest.vendor_id, manifest.device_id);
    let vendor = vendor_path(&mut vendor_buf, manifest.vendor_id);

    if let Ok(blob) = try_load_path(exact, manifest) {
        return Ok(blob);
    }
    if let Ok(blob) = try_load_path(vendor, manifest) {
        return Ok(blob);
    }
    Err(GpuError::FirmwareRequired)
}

/// Returns `true` if firmware is available for `manifest` without loading it.
pub fn firmware_available(manifest: &FirmwareManifest) -> bool {
    let mut exact_buf = [0u8; 64];
    let mut vendor_buf = [0u8; 64];
    let exact = exact_path(&mut exact_buf, manifest.vendor_id, manifest.device_id);
    let vendor = vendor_path(&mut vendor_buf, manifest.vendor_id);
    vfs::path_size(exact).is_ok() || vfs::path_size(vendor).is_ok()
}
