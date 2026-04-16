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
 * EDID v1.x parser.
 *
 * # References
 * - VESA Enhanced Extended Display Identification Data (E-EDID) Standard,
 *   Release A, Revision 2 (September 25, 2006).
 * - https://glenwing.github.io/docs/VESA-EEDID-A2.pdf
 *
 * ## EDID 128-byte block layout (EDID 1.3/1.4)
 * | Bytes | Content |
 * |-------|---------|
 * | 0-7   | Header `\x00\xff\xff\xff\xff\xff\xff\x00` |
 * | 8-9   | Manufacturer ID |
 * | 10-11 | Product code |
 * | 12-15 | Serial number |
 * | 16    | Week of manufacture |
 * | 17    | Year of manufacture |
 * | 18    | EDID version |
 * | 19    | EDID revision |
 * | 20    | Video input definition |
 * | 21    | Horizontal screen size (cm) |
 * | 22    | Vertical screen size (cm) |
 * | 23    | Display gamma |
 * | 24    | Supported features |
 * | 25-34 | Chromaticity coordinates |
 * | 35-37 | Established timings |
 * | 38-53 | Standard timing information (8 × 2 bytes) |
 * | 54-71 | Descriptor 1 (usually Preferred Timing Descriptor) |
 * | 72-89 | Descriptor 2 |
 * | 90-107| Descriptor 3 |
 * |108-125| Descriptor 4 |
 * | 126   | Extension block count |
 * | 127   | Checksum |
 *
 * ## Detailed Timing Descriptor (Preferred Timing) — bytes 54–71
 * | Byte | Content |
 * |------|---------|
 * | 0-1  | Pixel clock / 10 kHz (little-endian, zero = not a timing block) |
 * | 2    | H active pixels [7:0] |
 * | 3    | H blanking [7:0] |
 * | 4    | H active [11:8] in bits[7:4], H blanking [11:8] in bits[3:0] |
 * | 5    | V active lines [7:0] |
 * | 6    | V blanking [7:0] |
 * | 7    | V active [11:8] in bits[7:4], V blanking [11:8] in bits[3:0] |
 * | 8-17 | Sync / border / interlace fields (not needed for resolution) |
 */

// ---------------------------------------------------------------------------
// EdidInfo
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdidInfo {
    /// Physical screen width in millimetres (from Basic Display Parameters).
    pub width_mm: u16,
    /// Physical screen height in millimetres.
    pub height_mm: u16,
    /// Preferred horizontal resolution in pixels (from Descriptor 1 DTD).
    pub preferred_width: u16,
    /// Preferred vertical resolution in lines (from Descriptor 1 DTD).
    pub preferred_height: u16,
    /// Pixel clock in kHz (from Descriptor 1 DTD, 0 = not parsed).
    pub pixel_clock_khz: u32,
}

impl EdidInfo {
    pub const fn empty() -> Self {
        EdidInfo {
            width_mm: 0,
            height_mm: 0,
            preferred_width: 0,
            preferred_height: 0,
            pixel_clock_khz: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// Extract the Detailed Timing Descriptor at `start` (18-byte window).
///
/// Returns `(h_active, v_active, pixel_clock_khz)` or `None` if the
/// descriptor is not a timing block (pixel clock bytes are both zero).
fn parse_dtd(block: &[u8], start: usize) -> Option<(u16, u16, u32)> {
    // A non-timing descriptor has pixel_clock == 0 (both bytes zero).
    let pclk_raw = (block[start] as u16) | ((block[start + 1] as u16) << 8);
    if pclk_raw == 0 {
        return None;
    }

    // H active: byte 2 low byte + bits[7:4] of byte 4 as high nibble.
    let h_lo = block[start + 2] as u16;
    let h_hi = ((block[start + 4] >> 4) & 0x0F) as u16;
    let h_active = h_lo | (h_hi << 8);

    // V active: byte 5 low byte + bits[7:4] of byte 7 as high nibble.
    let v_lo = block[start + 5] as u16;
    let v_hi = ((block[start + 7] >> 4) & 0x0F) as u16;
    let v_active = v_lo | (v_hi << 8);

    // Pixel clock: value × 10 kHz.
    let pclk_khz = (pclk_raw as u32) * 10;

    Some((h_active, v_active, pclk_khz))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a 128-byte EDID block.
///
/// Returns `None` if the magic header is missing or the block is too short.
pub fn parse_edid(block: &[u8]) -> Option<EdidInfo> {
    if block.len() < 128 {
        return None;
    }
    // Validate EDID magic header.
    if &block[..8] != b"\x00\xff\xff\xff\xff\xff\xff\x00" {
        return None;
    }

    // Bytes 21/22 hold screen size in cm; multiply by 10 for mm.
    let width_mm = (block[21] as u16).saturating_mul(10);
    let height_mm = (block[22] as u16).saturating_mul(10);

    // Try the four 18-byte descriptor slots (bytes 54, 72, 90, 108).
    let descriptor_offsets = [54usize, 72, 90, 108];
    let mut preferred_width: u16 = 0;
    let mut preferred_height: u16 = 0;
    let mut pixel_clock_khz: u32 = 0;

    for &offset in &descriptor_offsets {
        if offset + 18 > block.len() {
            break;
        }
        if let Some((w, h, pclk)) = parse_dtd(block, offset) {
            if w > 0 && h > 0 {
                preferred_width = w;
                preferred_height = h;
                pixel_clock_khz = pclk;
                break; // First valid timing descriptor wins.
            }
        }
    }

    Some(EdidInfo {
        width_mm,
        height_mm,
        preferred_width,
        preferred_height,
        pixel_clock_khz,
    })
}
