/*!
 * Oreulius Kernel Project
 *
 * License-Identifier: Oreulius Community License v1.0 (see LICENSE)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulius Contributors
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

//! Audio subsystem: Intel HDA + AC'97 fallback
//!
//! # Architecture
//!
//! ```text
//!  PCI scan → probe()
//!       ├─ class 0x04/sub 0x03 → HDA controller  (Intel HD Audio, ICH6+)
//!       └─ 0x8086:0x2415        → AC'97 controller (QEMU / ICH0/ICH2)
//!
//!  HdaController::init()
//!       ├─ GCTL reset
//!       ├─ CORB/RIRB allocation and start
//!       ├─ codec enumeration: PARAMETERS, GET_AUDIO_WIDGET_CAP
//!       └─ output stream setup: BDLC (Buffer Descriptor List)
//!
//!  Ac97Controller::init()
//!       ├─ NAM/NABM base address detection
//!       ├─ AC_RESET
//!       └─ PCM OUT buffer setup (ping-pong)
//! ```
//!
//! # Public API
//!
//! After `audio::init()`:
//!   - [`write_samples`]  — push i16 stereo PCM at 48 kHz
//!   - [`is_playing`]     — true when hardware DMA is active
//!   - [`set_volume`]     — 0–255 master volume

#![allow(dead_code)] // hardware register table — constants reserved for full HDA/AC97 implementation

use crate::pci::PciDevice;
use spin::Mutex;

// ============================================================================
// PCI class constants
// ============================================================================

const PCI_CLASS_MULTIMEDIA: u8 = 0x04;
const PCI_SUBCLASS_HDA: u8 = 0x03;
const PCI_VENDOR_INTEL: u16 = 0x8086;
const PCI_DEV_AC97: u16 = 0x2415;
const PCI_DEV_ICH6_HDA: u16 = 0x2668;

// ============================================================================
// HDA register offsets (from MMIO BAR0)
// ============================================================================

const HDA_GCAP: usize = 0x00; // Global Capabilities
const HDA_VMIN: usize = 0x02; // Minor version
const HDA_VMAJ: usize = 0x03; // Major version
const HDA_GCTL: usize = 0x08; // Global Control
const HDA_WAKEEN: usize = 0x0C; // Wake Enable
const HDA_STATESTS: usize = 0x0E; // State Change Status
const HDA_INTCTL: usize = 0x20; // Interrupt Control
const HDA_INTSTS: usize = 0x24; // Interrupt Status

// CORB registers
const HDA_CORBLBASE: usize = 0x40;
const HDA_CORBUBASE: usize = 0x44;
const HDA_CORBWP: usize = 0x48;
const HDA_CORBRP: usize = 0x4A;
const HDA_CORBCTL: usize = 0x4C;
const HDA_CORBSIZE: usize = 0x4E;

// RIRB registers
const HDA_RIRBLBASE: usize = 0x50;
const HDA_RIRBUBASE: usize = 0x54;
const HDA_RIRBWP: usize = 0x58;
const HDA_RINTCNT: usize = 0x5A;
const HDA_RIRBCTL: usize = 0x5C;
const HDA_RIRBSIZE: usize = 0x5E;

// Stream descriptor 0 (output) at offset 0x80
const HDA_SD0_CTL: usize = 0x80; // Stream Descriptor Control (24-bit)
const HDA_SD0_STS: usize = 0x83; // Status
const HDA_SD0_LPIB: usize = 0x84; // Link Position in Buffer
const HDA_SD0_CBL: usize = 0x88; // Cyclic Buffer Length
const HDA_SD0_LVI: usize = 0x8C; // Last Valid Index
const HDA_SD0_FMT: usize = 0x92; // Format
const HDA_SD0_BDLPL: usize = 0x98; // BDL Physical Lower
const HDA_SD0_BDLPU: usize = 0x9C; // BDL Physical Upper

// GCTL bits
const HDA_GCTL_CRST: u32 = 1 << 0;
const HDA_GCTL_FCNTRL: u32 = 1 << 1;
const HDA_GCTL_UNSOL: u32 = 1 << 8;

// CORBCTL bits
const HDA_CORB_RUN: u8 = 1 << 1;

// RIRBCTL bits
const HDA_RIRB_RUN: u8 = 1 << 1;

// Stream descriptor control bits
const HDA_SD_CTL_SRST: u32 = 1 << 0;
const HDA_SD_CTL_RUN: u32 = 1 << 1;
const HDA_SD_CTL_IOCE: u32 = 1 << 2;
const HDA_SD_CTL_DEIE: u32 = 1 << 3;
const HDA_SD_CTL_FEIE: u32 = 1 << 4;
const HDA_SD_CTL_STRIPE: u32 = 0 << 16; // single channel
const HDA_SD_CTL_TP: u32 = 1 << 18;
const HDA_SD_CTL_DIR: u32 = 1 << 19; // 1 = output
const HDA_SD_CTL_STRM: u32 = 1 << 20; // stream number field

// HDA 16-bit PCM format word: 48 kHz, 16-bit stereo
// BASE=48 kHz (bit14=1), MULT=1 (bits12:11=00), DIV=1 (bits10:8=000),
// BITS=16 (bits6:4=001), CHAN=2 (bits3:0=0001)
const HDA_FMT_48K_S16_STEREO: u16 = (1 << 14) | (0b001 << 4) | 0b0001;

// HDA codec verbs (12-bit verb | 8-bit payload)
const HDA_VERB_GET_PARAM: u32 = 0xF00;
const HDA_VERB_GET_CONN_LIST: u32 = 0xF02;
const HDA_VERB_SET_STREAM_CH: u32 = 0x706;
const HDA_VERB_SET_AMP_GAIN: u32 = 0x300; // Set Amplifier Gain/Mute
const HDA_VERB_SET_POWER: u32 = 0x705;
const HDA_VERB_SET_EAPD: u32 = 0x70C;
const HDA_VERB_WIDGET_CONTROL: u32 = 0x707;

const HDA_PARAM_VENDOR: u8 = 0x00;
const HDA_PARAM_SUB_NODE_CNT: u8 = 0x04;
const HDA_PARAM_FUNC_GRP_TYPE: u8 = 0x05;
const HDA_PARAM_AUDIO_WIDGET: u8 = 0x09;

// Number of CORB/RIRB entries (must be 16, 64, or 256 — we use 256)
const HDA_CORB_SIZE: usize = 256;
const HDA_RIRB_SIZE: usize = 256;

// Number of BDL entries (Buffer Descriptor List)
const HDA_BDL_ENTRIES: usize = 2; // ping-pong

// Audio PCM buffer: 4096 samples × 2 channels × 2 bytes = 16 KB per buffer
const HDA_PERIOD_BYTES: usize = 4096 * 4; // 16384 bytes

// ============================================================================
// Static DMA buffers (identity-mapped, no heap)
// ============================================================================

/// HDA Command Output Ring Buffer (256 × 4 bytes).
#[repr(C, align(128))]
struct HdaCorbBuf {
    data: [u32; HDA_CORB_SIZE],
}
static mut HDA_CORB: HdaCorbBuf = HdaCorbBuf {
    data: [0u32; HDA_CORB_SIZE],
};

/// HDA Response Input Ring Buffer (256 × 8 bytes).
#[repr(C, align(128))]
struct HdaRirbBuf {
    data: [u64; HDA_RIRB_SIZE],
}
static mut HDA_RIRB: HdaRirbBuf = HdaRirbBuf {
    data: [0u64; HDA_RIRB_SIZE],
};

/// HDA Buffer Descriptor List (2 entries × 16 bytes).
#[repr(C, align(128))]
struct HdaBdl {
    entries: [HdaBdlEntry; HDA_BDL_ENTRIES],
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct HdaBdlEntry {
    addr_lo: u32,
    addr_hi: u32,
    length: u32,
    ioc: u32, // interrupt on completion flag
}
static mut HDA_BDL: HdaBdl = HdaBdl {
    entries: [HdaBdlEntry {
        addr_lo: 0,
        addr_hi: 0,
        length: 0,
        ioc: 0,
    }; HDA_BDL_ENTRIES],
};

/// Two PCM output buffers (ping-pong).
#[repr(C, align(4096))]
struct HdaPcmBuf {
    data: [[u8; HDA_PERIOD_BYTES]; HDA_BDL_ENTRIES],
}
static mut HDA_PCM: HdaPcmBuf = HdaPcmBuf {
    data: [[0u8; HDA_PERIOD_BYTES]; HDA_BDL_ENTRIES],
};

// ============================================================================
// Intel HDA Controller
// ============================================================================

pub struct HdaController {
    pub mmio_base: usize,
    pub pci: PciDevice,
    pub initialised: bool,
    /// CORB write pointer (shadow; hardware maintains read pointer)
    corb_wp: usize,
    /// RIRB read pointer (shadow)
    rirb_rp: usize,
    /// Codec address and node ID of the first output DAC (stored during init)
    dac_cad: u8,
    dac_nid: u8,
}

impl HdaController {
    pub fn new(mmio_base: usize, pci: PciDevice) -> Self {
        HdaController {
            mmio_base,
            pci,
            initialised: false,
            corb_wp: 0,
            rirb_rp: 0,
            dac_cad: 0,
            dac_nid: 0,
        }
    }

    // ----------------------------------------------------------------
    // MMIO helpers
    // ----------------------------------------------------------------

    unsafe fn read8(&self, off: usize) -> u8 {
        core::ptr::read_volatile((self.mmio_base + off) as *const u8)
    }
    unsafe fn read16(&self, off: usize) -> u16 {
        core::ptr::read_volatile((self.mmio_base + off) as *const u16)
    }
    unsafe fn read32(&self, off: usize) -> u32 {
        core::ptr::read_volatile((self.mmio_base + off) as *const u32)
    }
    unsafe fn write8(&self, off: usize, v: u8) {
        core::ptr::write_volatile((self.mmio_base + off) as *mut u8, v);
    }
    unsafe fn write16(&self, off: usize, v: u16) {
        core::ptr::write_volatile((self.mmio_base + off) as *mut u16, v);
    }
    unsafe fn write32(&self, off: usize, v: u32) {
        core::ptr::write_volatile((self.mmio_base + off) as *mut u32, v);
    }

    fn delay(&self) {
        for _ in 0..10_000u32 {
            unsafe {
                core::arch::asm!("nop");
            }
        }
    }

    // ----------------------------------------------------------------
    // CORB/RIRB
    // ----------------------------------------------------------------

    /// Send a HDA codec verb and return the 32-bit response.
    ///
    /// `cad` = codec address (0–14), `nid` = node ID, `verb` = 12-bit verb,
    /// `payload` = 8-bit (or 16-bit for Set verbs) parameter.
    pub fn send_verb(&mut self, cad: u8, nid: u8, verb: u32, payload: u32) -> u32 {
        // Build 32-bit command: CAD[31:28] | NID[27:20] | Verb[19:8] | Payload[7:0]
        let cmd: u32 = ((cad as u32 & 0xF) << 28)
            | ((nid as u32 & 0x7F) << 20)
            | ((verb & 0xFFF) << 8)
            | (payload & 0xFF);
        unsafe {
            // Write command to CORB
            let wp = (self.corb_wp + 1) % HDA_CORB_SIZE;
            HDA_CORB.data[wp] = cmd;
            self.corb_wp = wp;
            self.write16(HDA_CORBWP, wp as u16);

            // Wait for RIRB to have a response (RIRBWP advances)
            for _ in 0..100_000u32 {
                let rirbwp = self.read16(HDA_RIRBWP) as usize & (HDA_RIRB_SIZE - 1);
                if rirbwp != self.rirb_rp {
                    break;
                }
            }

            let rp = (self.rirb_rp + 1) % HDA_RIRB_SIZE;
            let resp = HDA_RIRB.data[rp] as u32; // lower 32 bits = response data
            self.rirb_rp = rp;
            resp
        }
    }

    // ----------------------------------------------------------------
    // Initialisation
    // ----------------------------------------------------------------

    pub fn init(&mut self) -> bool {
        unsafe {
            // Enable bus mastering
            self.pci.enable_bus_mastering();

            // Global Controller Reset
            self.write32(HDA_GCTL, 0);
            self.delay();
            self.write32(HDA_GCTL, HDA_GCTL_CRST);
            // Wait for CRST to clear
            for _ in 0..100_000u32 {
                if self.read32(HDA_GCTL) & HDA_GCTL_CRST != 0 {
                    break;
                }
            }
            self.delay();

            // Enable unsolicited responses
            self.write32(HDA_GCTL, self.read32(HDA_GCTL) | HDA_GCTL_UNSOL);

            // Wait for codec to appear (STATESTS bit set)
            for _ in 0..200_000u32 {
                if self.read16(HDA_STATESTS) & 0x01 != 0 {
                    break;
                }
            }

            // Disable CORB/RIRB DMA
            self.write8(HDA_CORBCTL, 0);
            self.write8(HDA_RIRBCTL, 0);
            self.delay();

            // Set CORB size = 256 entries (bits 1:0 = 0b10)
            self.write8(HDA_CORBSIZE, 0b10);
            // Set RIRB size = 256 entries
            self.write8(HDA_RIRBSIZE, 0b10);

            // Set CORB physical address
            let corb_phys = HDA_CORB.data.as_ptr() as u64;
            self.write32(HDA_CORBLBASE, corb_phys as u32);
            self.write32(HDA_CORBUBASE, (corb_phys >> 32) as u32);

            // Set RIRB physical address
            let rirb_phys = HDA_RIRB.data.as_ptr() as u64;
            self.write32(HDA_RIRBLBASE, rirb_phys as u32);
            self.write32(HDA_RIRBUBASE, (rirb_phys >> 32) as u32);

            // Reset CORB read pointer and write pointer
            self.write16(HDA_CORBRP, 1 << 15); // CORBRPRST
            self.write16(HDA_CORBRP, 0);
            self.write16(HDA_CORBWP, 0);
            self.corb_wp = 0;

            // Reset RIRB write pointer
            self.write16(HDA_RIRBWP, 1 << 15); // RIRBWPRST
            self.rirb_rp = 0;

            // Set RIRB interrupt count = 1
            self.write16(HDA_RINTCNT, 1);

            // Start CORB and RIRB
            self.write8(HDA_CORBCTL, HDA_CORB_RUN);
            self.write8(HDA_RIRBCTL, HDA_RIRB_RUN);

            crate::serial_println!(
                "[HDA] Controller init: GCAP=0x{:04X} VMAJ={} VMIN={}",
                self.read16(HDA_GCAP),
                self.read8(HDA_VMAJ),
                self.read8(HDA_VMIN)
            );

            // Enumerate codecs
            let statests = self.read16(HDA_STATESTS);
            for cad in 0..15u8 {
                if statests & (1 << cad) == 0 {
                    continue;
                }
                let vendor = self.send_verb(cad, 0, HDA_VERB_GET_PARAM, HDA_PARAM_VENDOR as u32);
                crate::serial_println!("[HDA] Codec {}: VendorID=0x{:08X}", cad, vendor);
                // Walk function groups
                let sub = self.send_verb(cad, 0, HDA_VERB_GET_PARAM, HDA_PARAM_SUB_NODE_CNT as u32);
                let fg_start = ((sub >> 16) & 0xFF) as u8;
                let fg_count = (sub & 0xFF) as u8;
                for fg in fg_start..(fg_start + fg_count) {
                    let ftype =
                        self.send_verb(cad, fg, HDA_VERB_GET_PARAM, HDA_PARAM_FUNC_GRP_TYPE as u32);
                    if ftype & 0xFF == 0x01 {
                        // Audio Function Group
                        self.setup_output_stream(cad, fg);
                        break;
                    }
                }
            }
        }

        self.initialised = true;
        true
    }

    // ----------------------------------------------------------------
    // Output stream setup
    // ----------------------------------------------------------------

    fn setup_output_stream(&mut self, cad: u8, fg: u8) {
        unsafe {
            // Power up the function group
            let _ = self.send_verb(cad, fg, HDA_VERB_SET_POWER, 0x00);
            self.delay();

            // Walk audio widgets; find DAC (type 0x00) and pin (type 0x04)
            let sub = self.send_verb(cad, fg, HDA_VERB_GET_PARAM, HDA_PARAM_SUB_NODE_CNT as u32);
            let wgt_start = ((sub >> 16) & 0xFF) as u8;
            let wgt_count = (sub & 0xFF) as u8;
            let mut dac_nid = 0u8;

            for nid in wgt_start..(wgt_start + wgt_count) {
                let cap =
                    self.send_verb(cad, nid, HDA_VERB_GET_PARAM, HDA_PARAM_AUDIO_WIDGET as u32);
                let wtype = (cap >> 20) & 0xF;
                if wtype == 0x00 && dac_nid == 0 {
                    // Output converter (DAC)
                    dac_nid = nid;
                    self.dac_cad = cad;
                    self.dac_nid = nid;
                    // Assign stream 1, channel 0
                    let _ = self.send_verb(cad, nid, HDA_VERB_SET_STREAM_CH, (1 << 4) | 0);
                    // Set output amplifier: unmute, max gain (0x7F)
                    let _ = self.send_verb(
                        cad,
                        nid,
                        HDA_VERB_SET_AMP_GAIN,
                        (1 << 15) | (1 << 13) | (1 << 12) | 0x7F,
                    );
                    let _ = self.send_verb(cad, nid, HDA_VERB_SET_POWER, 0x00);
                    crate::serial_println!("[HDA] DAC nid={}", nid);
                }
                if wtype == 0x04 {
                    // Pin widget — enable output + EAPD
                    let _ = self.send_verb(cad, nid, HDA_VERB_WIDGET_CONTROL, 0x40); // PIN_OUT
                    let _ = self.send_verb(cad, nid, HDA_VERB_SET_EAPD, 0x02);
                    let _ = self.send_verb(
                        cad,
                        nid,
                        HDA_VERB_SET_AMP_GAIN,
                        (1 << 15) | (1 << 13) | (1 << 12) | 0x7F,
                    );
                }
            }

            if dac_nid == 0 {
                return;
            }

            // ---- Set up BDL ----
            for i in 0..HDA_BDL_ENTRIES {
                let buf_phys = HDA_PCM.data[i].as_ptr() as u64;
                HDA_BDL.entries[i].addr_lo = buf_phys as u32;
                HDA_BDL.entries[i].addr_hi = (buf_phys >> 32) as u32;
                HDA_BDL.entries[i].length = HDA_PERIOD_BYTES as u32;
                HDA_BDL.entries[i].ioc = 1; // interrupt on completion
            }

            // ---- Reset stream descriptor 0 ----
            self.write32(HDA_SD0_CTL, HDA_SD_CTL_SRST);
            self.delay();
            self.write32(HDA_SD0_CTL, 0);
            self.delay();

            // Set format: 48 kHz, 16-bit stereo
            self.write16(HDA_SD0_FMT, HDA_FMT_48K_S16_STEREO);

            // Set cyclic buffer length
            self.write32(HDA_SD0_CBL, (HDA_PERIOD_BYTES * HDA_BDL_ENTRIES) as u32);

            // Set last valid index (BDL entry count - 1)
            self.write32(HDA_SD0_LVI, (HDA_BDL_ENTRIES - 1) as u32);

            // Set BDL address
            let bdl_phys = HDA_BDL.entries.as_ptr() as u64;
            self.write32(HDA_SD0_BDLPL, bdl_phys as u32);
            self.write32(HDA_SD0_BDLPU, (bdl_phys >> 32) as u32);

            // Set stream number = 1 (bits 23:20), DIR=output, enable IOC
            let ctl: u32 = (1 << 20) | HDA_SD_CTL_IOCE | HDA_SD_CTL_DIR;
            self.write32(HDA_SD0_CTL, ctl);

            crate::serial_println!("[HDA] Output stream configured (48kHz 16-bit stereo)");
        }
    }

    // ----------------------------------------------------------------
    // PCM output
    // ----------------------------------------------------------------

    /// Write stereo 16-bit PCM samples into the next available DMA buffer.
    ///
    /// `samples` is interleaved L/R i16 pairs at 48 kHz.
    /// Returns the number of sample-pairs written.
    pub fn write_samples(&self, samples: &[i16]) -> usize {
        if !self.initialised {
            return 0;
        }
        unsafe {
            let lpib = self.read32(HDA_SD0_LPIB) as usize;
            // Choose buffer half based on current DMA position
            let half = if lpib < HDA_PERIOD_BYTES { 1 } else { 0 };
            let dst = HDA_PCM.data[half].as_mut_ptr() as *mut i16;
            let max = HDA_PERIOD_BYTES / 2; // max sample-pairs
            let count = core::cmp::min(samples.len(), max);
            core::ptr::copy_nonoverlapping(samples.as_ptr(), dst, count);
            count
        }
    }

    /// Start DMA playback.
    pub fn start(&self) {
        unsafe {
            let ctl = self.read32(HDA_SD0_CTL);
            self.write32(HDA_SD0_CTL, ctl | HDA_SD_CTL_RUN);
        }
    }

    /// Stop DMA playback.
    pub fn stop(&self) {
        unsafe {
            let ctl = self.read32(HDA_SD0_CTL);
            self.write32(HDA_SD0_CTL, ctl & !HDA_SD_CTL_RUN);
        }
    }

    /// Set the output DAC amplifier gain.  `level` 0=silence, 255=maximum.
    pub fn set_volume(&mut self, level: u8) {
        if self.dac_nid == 0 {
            return;
        }
        let gain = (level as u32) >> 1; // 0-255 → 0-127
        let payload = (1 << 15)        // Output amp
                    | (1 << 13)        // Left channel
                    | (1 << 12)        // Right channel
                    | (gain & 0x7F);
        let _ = self.send_verb(self.dac_cad, self.dac_nid, HDA_VERB_SET_AMP_GAIN, payload);
    }

    pub fn is_playing(&self) -> bool {
        unsafe { self.read32(HDA_SD0_CTL) & HDA_SD_CTL_RUN != 0 }
    }
}
// ============================================================================
//
// The AC'97 controller exposes two PCI I/O BARs:
//   BAR0 = NAM (Native Audio Mixer)  — codec registers, 256 bytes
//   BAR1 = NABM (Native Audio Bus Master) — DMA control, 256 bytes
//
// We use NABM PCM OUT channel (0x10 base).

// NABM PCM-OUT channel registers (relative to NABM base)
const NABM_POBDBAR: u16 = 0x10; // PCM Out BDL Base Address
const NABM_POCIV: u16 = 0x14; // PCM Out Current Index Value
const NABM_POLVI: u16 = 0x15; // PCM Out Last Valid Index
const NABM_POSR: u16 = 0x16; // PCM Out Status
const NABM_POPIV: u16 = 0x18; // PCM Out Prefetched Index Value
const NABM_POCTLB: u16 = 0x1B; // PCM Out Transfer Control Byte

// NABM global control
const NABM_GLOB_CNT: u16 = 0x2C;
const NABM_GLOB_STS: u16 = 0x30;

// PCM OUT control bits
const NABM_CTL_RPBM: u8 = 1 << 0; // Run/Pause Bus Master
const NABM_CTL_RR: u8 = 1 << 1; // Reset Registers
const NABM_CTL_LVBIE: u8 = 1 << 2; // Last Valid Buffer Interrupt Enable
const NABM_CTL_IOCE: u8 = 1 << 4; // Interrupt on Completion Enable

// NAM mixer registers
const NAM_MASTER_VOL: u16 = 0x02;
const NAM_PCM_VOL: u16 = 0x18;
const NAM_POWERDOWN: u16 = 0x26;

// AC'97 BDL entry count
const AC97_BDL_ENTRIES: usize = 2;
const AC97_PERIOD_BYTES: usize = 4096; // ~23 ms at 44.1 kHz stereo 16-bit

#[repr(C, align(8))]
#[derive(Clone, Copy, Default)]
struct Ac97BdlEntry {
    addr: u32,
    count: u16, // number of 16-bit samples (not bytes!)
    flags: u16, // bit 15 = IOC, bit 14 = BUP (buffer underrun policy)
}

#[repr(C, align(64))]
struct Ac97Bdl {
    entries: [Ac97BdlEntry; AC97_BDL_ENTRIES],
}
static mut AC97_BDL: Ac97Bdl = Ac97Bdl {
    entries: [Ac97BdlEntry {
        addr: 0,
        count: 0,
        flags: 0,
    }; AC97_BDL_ENTRIES],
};

#[repr(C, align(4096))]
struct Ac97PcmBuf {
    data: [[u8; AC97_PERIOD_BYTES]; AC97_BDL_ENTRIES],
}
static mut AC97_PCM: Ac97PcmBuf = Ac97PcmBuf {
    data: [[0u8; AC97_PERIOD_BYTES]; AC97_BDL_ENTRIES],
};

pub struct Ac97Controller {
    pub nam_base: u16,  // I/O port base for NAM
    pub nabm_base: u16, // I/O port base for NABM
    pub pci: PciDevice,
    pub initialised: bool,
}

impl Ac97Controller {
    pub fn new(pci: PciDevice) -> Option<Self> {
        // BAR0 = NAM I/O, BAR1 = NABM I/O
        let bar0 = unsafe { pci.read_bar(0) };
        let bar1 = unsafe { pci.read_bar(1) };
        if bar0 == 0 || bar1 == 0 {
            return None;
        }
        // I/O BARs have bit 0 set
        if bar0 & 1 == 0 || bar1 & 1 == 0 {
            return None;
        }
        Some(Ac97Controller {
            nam_base: (bar0 & !3) as u16,
            nabm_base: (bar1 & !3) as u16,
            pci,
            initialised: false,
        })
    }

    #[inline(always)]
    unsafe fn nam_write16(&self, reg: u16, val: u16) {
        core::arch::asm!("out dx, ax", in("dx") self.nam_base + reg, in("ax") val);
    }
    #[inline(always)]
    unsafe fn nam_read16(&self, reg: u16) -> u16 {
        let v: u16;
        core::arch::asm!("in ax, dx", out("ax") v, in("dx") self.nam_base + reg);
        v
    }
    #[inline(always)]
    unsafe fn nabm_write8(&self, reg: u16, val: u8) {
        core::arch::asm!("out dx, al", in("dx") self.nabm_base + reg, in("al") val);
    }
    #[inline(always)]
    unsafe fn nabm_write32(&self, reg: u16, val: u32) {
        core::arch::asm!("out dx, eax", in("dx") self.nabm_base + reg, in("eax") val);
    }
    #[inline(always)]
    unsafe fn nabm_read8(&self, reg: u16) -> u8 {
        let v: u8;
        core::arch::asm!("in al, dx", out("al") v, in("dx") self.nabm_base + reg);
        v
    }

    fn delay(&self) {
        for _ in 0..10_000u32 {
            unsafe {
                core::arch::asm!("nop");
            }
        }
    }

    pub fn init(&mut self) -> bool {
        unsafe {
            self.pci.enable_bus_mastering();

            // Cold reset via NABM Global Control bit 1
            let gc = 0u32;
            self.nabm_write32(NABM_GLOB_CNT, gc);
            self.delay();
            self.nabm_write32(NABM_GLOB_CNT, 0x00000002); // warm reset
            self.delay();
            self.nabm_write32(NABM_GLOB_CNT, 0x00000000);
            self.delay();

            // Wait for codec ready (bit 8 in Global Status)
            for _ in 0..200_000u32 {
                let s = {
                    let v: u32;
                    core::arch::asm!("in eax, dx", out("eax") v, in("dx") self.nabm_base + NABM_GLOB_STS);
                    v
                };
                if s & (1 << 8) != 0 {
                    break;
                }
            }

            // Set master and PCM volumes to max (0x0000 = no attenuation)
            self.nam_write16(NAM_MASTER_VOL, 0x0000);
            self.nam_write16(NAM_PCM_VOL, 0x0000);

            // Set up BDL
            for i in 0..AC97_BDL_ENTRIES {
                let phys = AC97_PCM.data[i].as_ptr() as u32;
                AC97_BDL.entries[i].addr = phys;
                // count = number of 16-bit samples; period_bytes / 2
                AC97_BDL.entries[i].count = (AC97_PERIOD_BYTES / 2) as u16;
                AC97_BDL.entries[i].flags = 1 << 15; // IOC
            }

            // Write BDL physical address to PCM OUT BDLBAR
            let bdl_phys = AC97_BDL.entries.as_ptr() as u32;
            self.nabm_write32(NABM_POBDBAR, bdl_phys);

            // Reset PCM OUT channel
            self.nabm_write8(NABM_POCTLB, NABM_CTL_RR);
            self.delay();

            // Set last valid index
            self.nabm_write8(NABM_POLVI, (AC97_BDL_ENTRIES - 1) as u8);

            crate::serial_println!(
                "[AC97] Controller initialised (NAM=0x{:04X} NABM=0x{:04X})",
                self.nam_base,
                self.nabm_base
            );
        }

        self.initialised = true;
        true
    }

    pub fn write_samples(&self, samples: &[i16]) -> usize {
        if !self.initialised {
            return 0;
        }
        unsafe {
            let civ = self.nabm_read8(NABM_POCIV) as usize;
            let half = 1 - civ % AC97_BDL_ENTRIES;
            let dst = AC97_PCM.data[half].as_mut_ptr() as *mut i16;
            let max = AC97_PERIOD_BYTES / 2;
            let count = core::cmp::min(samples.len(), max);
            core::ptr::copy_nonoverlapping(samples.as_ptr(), dst, count);
            count
        }
    }

    pub fn start(&self) {
        unsafe {
            self.nabm_write8(NABM_POCTLB, NABM_CTL_RPBM | NABM_CTL_IOCE);
        }
    }

    pub fn stop(&self) {
        unsafe {
            self.nabm_write8(NABM_POCTLB, 0);
        }
    }

    /// Set master volume. `level` 0=silence, 255=maximum.
    pub fn set_volume(&self, level: u8) {
        // NAM master volume: 5-bit stereo attenuation (0=max, 31=mute) + bit15=mute
        let (mute, atten) = if level == 0 {
            (0x8000u16, 31u16)
        } else {
            let a = (31u16 * (255u16 - level as u16)) / 255;
            (0u16, a)
        };
        let val = mute | (atten << 8) | atten;
        unsafe {
            self.nam_write16(NAM_MASTER_VOL, val);
        }
    }

    pub fn is_playing(&self) -> bool {
        unsafe { self.nabm_read8(NABM_POCTLB) & NABM_CTL_RPBM != 0 }
    }
}

// ============================================================================
// Unified audio subsystem
// ============================================================================

pub enum AudioBackend {
    Hda(HdaController),
    Ac97(Ac97Controller),
}

/// Global audio backend.
pub static AUDIO: Mutex<Option<AudioBackend>> = Mutex::new(None);

/// Probe PCI bus for audio devices and initialise the best available backend.
///
/// Prefers HDA (ICH6+) over AC'97.  Call once during kernel startup.
pub fn init(pci_devices: &[PciDevice]) {
    // Try HDA first
    for &dev in pci_devices {
        if dev.class_code == PCI_CLASS_MULTIMEDIA && dev.subclass == PCI_SUBCLASS_HDA {
            let bar0 = unsafe { dev.read_bar(0) };
            if bar0 == 0 {
                continue;
            }
            let mmio_base = (bar0 & !0xF) as usize;
            let mut ctrl = HdaController::new(mmio_base, dev);
            if ctrl.init() {
                ctrl.start();
                *AUDIO.lock() = Some(AudioBackend::Hda(ctrl));
                crate::serial_println!("[AUDIO] HDA backend active");
                return;
            }
        }
    }
    // Fall back to AC'97
    for &dev in pci_devices {
        if dev.vendor_id == PCI_VENDOR_INTEL && dev.device_id == PCI_DEV_AC97 {
            if let Some(mut ctrl) = Ac97Controller::new(dev) {
                if ctrl.init() {
                    ctrl.start();
                    *AUDIO.lock() = Some(AudioBackend::Ac97(ctrl));
                    crate::serial_println!("[AUDIO] AC97 backend active");
                    return;
                }
            }
        }
    }
    crate::serial_println!("[AUDIO] No audio hardware found");
}

/// Push stereo 16-bit PCM samples at 48 kHz into the DMA buffer.
/// Returns the number of sample-pairs accepted.
pub fn write_samples(samples: &[i16]) -> usize {
    match AUDIO.lock().as_ref() {
        Some(AudioBackend::Hda(c)) => c.write_samples(samples),
        Some(AudioBackend::Ac97(c)) => c.write_samples(samples),
        None => 0,
    }
}

pub fn is_playing() -> bool {
    match AUDIO.lock().as_ref() {
        Some(AudioBackend::Hda(c)) => c.is_playing(),
        Some(AudioBackend::Ac97(c)) => c.is_playing(),
        None => false,
    }
}

pub fn set_volume(level: u8) {
    match AUDIO.lock().as_mut() {
        Some(AudioBackend::Hda(c)) => c.set_volume(level),
        Some(AudioBackend::Ac97(c)) => c.set_volume(level),
        None => {}
    }
}
