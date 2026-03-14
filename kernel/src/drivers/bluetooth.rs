/*!
 * Oreulia Kernel Project
 *
 * License-Identifier: Oreulia Community License v1.0 (see LICENSE)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

//! Bluetooth subsystem — USB HCI transport (Bluetooth USB class 0xE0/0x01/0x01)
//!
//! # Architecture
//!
//! ```text
//!  USB device scan (usb.rs USB_BUS)
//!       └─ class 0xE0, subclass 0x01, proto 0x01 → BluetoothController
//!
//!  HCI transport over USB:
//!       EP0  = HCI commands  (host → device)
//!       EP1  = HCI events    (device → host, interrupt IN)
//!       EP2  = HCI ACL data  (bidirectional, bulk)
//!
//!  Startup sequence:
//!       hci_reset()
//!       └─ waits for HCI_EVENT_CMD_COMPLETE (0x0E) with OCF=Reset (0x03/0x0C)
//!
//!  LE scanning:
//!       hci_le_set_scan_parameters()
//!       hci_le_set_scan_enable(true)
//!       loop { hci_poll() → BluetoothEvent::LeAdvertReport }
//! ```
//!
//! # Note
//!
//! This implementation uses the UHCI bulk-transfer path from `usb.rs` for
//! all endpoints.  When a full xHCI device stack is connected, the same
//! control-transfer API is available via `UsbBus::control_transfer`.

#![allow(dead_code)] // hardware register table — constants reserved for full HCI implementation

use spin::Mutex;

// ============================================================================
// HCI packet types (USB framing)
// ============================================================================

const HCI_CMD_PKT:   u8 = 0x01;
const HCI_ACL_PKT:   u8 = 0x02;
const HCI_EVENT_PKT: u8 = 0x04;

// HCI opcode groups (OGF/OCF encoded as 16-bit LE)
// opcode = (OGF << 10) | OCF
const HCI_OGF_LINK_CTRL:  u16 = 0x01;
const HCI_OGF_CTRL_BB:    u16 = 0x03;
const HCI_OGF_INFO:        u16 = 0x04;
const HCI_OGF_LE:          u16 = 0x08;

// Common OCFs
const HCI_OCF_RESET:              u16 = 0x0003;
const HCI_OCF_READ_BD_ADDR:       u16 = 0x0009;
const HCI_OCF_INQUIRY:            u16 = 0x0001;
const HCI_OCF_LE_SET_SCAN_PARAM:  u16 = 0x000B;
const HCI_OCF_LE_SET_SCAN_EN:     u16 = 0x000C;
const HCI_OCF_LE_READ_BD_ADDR:    u16 = 0x0009;

// HCI event codes
const HCI_EVENT_INQUIRY_RESULT:     u8 = 0x02;
const HCI_EVENT_CMD_COMPLETE:       u8 = 0x0E;
const HCI_EVENT_CMD_STATUS:         u8 = 0x0F;
const HCI_EVENT_LE_META:            u8 = 0x3E;

// LE sub-event codes
const HCI_LE_SUBEVENT_ADV_REPORT:   u8 = 0x02;

fn hci_opcode(ogf: u16, ocf: u16) -> u16 {
    (ogf << 10) | (ocf & 0x03FF)
}

// ============================================================================
// Static HCI buffers
// ============================================================================

const HCI_CMD_BUF_LEN:   usize = 258; // 1 (type) + 3 (hdr) + 254 (params)
const HCI_EVENT_BUF_LEN: usize = 258;
const HCI_ACL_BUF_LEN:   usize = 1028;

static mut HCI_CMD_BUF:   [u8; HCI_CMD_BUF_LEN]   = [0u8; HCI_CMD_BUF_LEN];
static mut HCI_EVENT_BUF: [u8; HCI_EVENT_BUF_LEN] = [0u8; HCI_EVENT_BUF_LEN];
static mut HCI_ACL_BUF:   [u8; HCI_ACL_BUF_LEN]   = [0u8; HCI_ACL_BUF_LEN];

// ============================================================================
// BD_ADDR type
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct BdAddr(pub [u8; 6]);

impl BdAddr {
    pub fn from_bytes(b: &[u8]) -> Self {
        let mut a = [0u8; 6];
        let n = core::cmp::min(b.len(), 6);
        a[..n].copy_from_slice(&b[..n]);
        BdAddr(a)
    }
    pub fn is_zero(&self) -> bool { self.0 == [0u8; 6] }
}

// ============================================================================
// Discovered device record
// ============================================================================

const BT_MAX_DEVICES: usize = 16;

#[derive(Clone, Copy, Debug, Default)]
pub struct BluetoothDevice {
    pub addr:    BdAddr,
    pub rssi:    i8,
    pub is_le:   bool,
    /// First 8 bytes of advertising data / EIR (if available)
    pub adv_data: [u8; 8],
}

// ============================================================================
// Event produced by `poll()`
// ============================================================================

#[derive(Clone, Copy, Debug)]
pub enum BluetoothEvent {
    None,
    CommandComplete { opcode: u16, status: u8 },
    InquiryResult(BluetoothDevice),
    LeAdvertReport(BluetoothDevice),
    AclData { handle: u16, len: u16 },
}

// ============================================================================
// Bluetooth controller
// ============================================================================

/// USB device identifiers we need from `usb.rs`.
#[derive(Clone, Copy)]
pub struct UsbHandle {
    pub dev_addr:   u8,
    pub ctrl_idx:   usize,
    pub ep_event:   u8,   // interrupt-IN endpoint (HCI events), usually 0x81
    pub ep_acl_in:  u8,   // bulk-IN  endpoint (HCI ACL data)
    pub ep_acl_out: u8,   // bulk-OUT endpoint (HCI ACL data)
    pub speed:      u8,   // 0=LS 1=FS 2=HS
    /// Controller kind + BAR for reconstructing a UHCI/EHCI handle.
    pub ctrl_kind:  BtCtrlKind,
    pub bar_value:  u32, // BAR0 (MMIO) for EHCI, or BAR4 (I/O) for UHCI
    /// PCI device record for the host controller (needed to construct UHCI/EHCI).
    pub pci:        crate::pci::PciDevice,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BtCtrlKind { Uhci, Ehci, Other }

pub struct BluetoothController {
    pub usb:      UsbHandle,
    pub bd_addr:  BdAddr,
    pub ready:    bool,
    pub devices:  [BluetoothDevice; BT_MAX_DEVICES],
    pub dev_count: usize,
    /// Pending ACL connection handle (0 = none)
    pub acl_handle: u16,
}

impl BluetoothController {
    pub fn new(usb: UsbHandle) -> Self {
        BluetoothController {
            usb,
            bd_addr: BdAddr::default(),
            ready: false,
            devices: [BluetoothDevice::default(); BT_MAX_DEVICES],
            dev_count: 0,
            acl_handle: 0,
        }
    }

    // ----------------------------------------------------------------
    // Low-level HCI command submission
    // ----------------------------------------------------------------

    /// Send an HCI command via USB EP0 control transfer.
    ///
    /// Bluetooth HCI commands use:
    ///   bmRequestType = 0x20 (class | host→device | interface)
    ///   bRequest      = 0x00
    ///   wValue/wIndex = 0
    ///   wLength       = total command length
    unsafe fn send_command(&mut self, opcode: u16, params: &[u8]) -> bool {
        let total = 3 + params.len();
        if total > HCI_CMD_BUF_LEN { return false; }
        HCI_CMD_BUF[0] = (opcode & 0xFF) as u8;
        HCI_CMD_BUF[1] = ((opcode >> 8) & 0xFF) as u8;
        HCI_CMD_BUF[2] = params.len() as u8;
        HCI_CMD_BUF[3..3 + params.len()].copy_from_slice(params);

        let setup = crate::usb::UsbSetupPacket {
            bm_request_type: 0x20, // class | host→device | interface
            b_request: 0x00,
            w_value: 0,
            w_index: 0,
            w_length: total as u16,
        };

        let dev   = self.usb.dev_addr;
        let ls    = self.usb.speed == 0;
        let hs    = self.usb.speed == 2;
        let pci   = self.usb.pci;

        match self.usb.ctrl_kind {
            BtCtrlKind::Uhci => {
                let io_base = (self.usb.bar_value & !0x1F) as u16;
                let mut ctrl = crate::usb::UhciController::new(io_base, pci);
                ctrl.init();
                let res = ctrl.control_transfer(dev, ls, &setup,
                                                Some(&mut HCI_CMD_BUF[..total]), false);
                res == crate::usb::UhciXferResult::Ok
            }
            BtCtrlKind::Ehci => {
                let mmio = (self.usb.bar_value & !0x0F) as usize;
                let mut ctrl = crate::usb::EhciController::new(mmio, pci);
                ctrl.init();
                ctrl.control_transfer(dev, hs, ls, &setup,
                                      Some(&mut HCI_CMD_BUF[..total]), false)
            }
            BtCtrlKind::Other => false,
        }
    }

    /// Poll the interrupt-IN endpoint (EP1) for an HCI event packet.
    /// Returns the number of bytes received (0 = no data).
    unsafe fn recv_event(&mut self) -> usize {
        let dev = self.usb.dev_addr;
        let ep  = self.usb.ep_event & 0x0F;
        let ls  = self.usb.speed == 0;
        let hs  = self.usb.speed == 2;
        let pci = self.usb.pci;
        let mut toggle = false;

        match self.usb.ctrl_kind {
            BtCtrlKind::Uhci => {
                let io_base = (self.usb.bar_value & !0x1F) as u16;
                let mut ctrl = crate::usb::UhciController::new(io_base, pci);
                ctrl.init();
                let res = ctrl.bulk_transfer(dev, ep, ls, true,
                                             64, &mut HCI_EVENT_BUF, &mut toggle);
                if res == crate::usb::UhciXferResult::Ok {
                    HCI_EVENT_BUF[1] as usize + 2
                } else { 0 }
            }
            BtCtrlKind::Ehci => {
                let mmio = (self.usb.bar_value & !0x0F) as usize;
                let mut ctrl = crate::usb::EhciController::new(mmio, pci);
                ctrl.init();
                if ctrl.bulk_transfer(dev, ep, hs, true,
                                      64, &mut HCI_EVENT_BUF, &mut toggle)
                {
                    HCI_EVENT_BUF[1] as usize + 2
                } else { 0 }
            }
            BtCtrlKind::Other => 0,
        }
    }

    // ----------------------------------------------------------------
    // HCI command helpers
    // ----------------------------------------------------------------

    pub fn hci_reset(&mut self) -> bool {
        let opcode = hci_opcode(HCI_OGF_CTRL_BB, HCI_OCF_RESET);
        unsafe {
            if !self.send_command(opcode, &[]) { return false; }
            // Wait for Command Complete event
            for _ in 0..500_000u32 {
                let n = self.recv_event();
                if n >= 6
                    && HCI_EVENT_BUF[0] == HCI_EVENT_CMD_COMPLETE
                    && HCI_EVENT_BUF[2] == (opcode & 0xFF) as u8
                    && HCI_EVENT_BUF[3] == ((opcode >> 8) & 0xFF) as u8
                {
                    return HCI_EVENT_BUF[4] == 0x00; // status 0 = success
                }
            }
        }
        false
    }

    pub fn hci_read_bd_addr(&mut self) -> BdAddr {
        let opcode = hci_opcode(HCI_OGF_INFO, HCI_OCF_READ_BD_ADDR);
        unsafe {
            if !self.send_command(opcode, &[]) { return BdAddr::default(); }
            for _ in 0..500_000u32 {
                let n = self.recv_event();
                if n >= 10
                    && HCI_EVENT_BUF[0] == HCI_EVENT_CMD_COMPLETE
                    && HCI_EVENT_BUF[2] == (opcode & 0xFF) as u8
                    && HCI_EVENT_BUF[3] == ((opcode >> 8) & 0xFF) as u8
                    && HCI_EVENT_BUF[4] == 0x00 // success
                {
                    return BdAddr::from_bytes(&HCI_EVENT_BUF[5..11]);
                }
            }
        }
        BdAddr::default()
    }

    /// Initiate a classic BR/EDR inquiry (General Inquiry Access Code).
    ///
    /// `duration` in units of 1.28 s (max 0x30).  `max_responses` 0 = unlimited.
    pub fn hci_inquiry(&mut self, duration: u8, max_responses: u8) -> bool {
        let opcode = hci_opcode(HCI_OGF_LINK_CTRL, HCI_OCF_INQUIRY);
        // GIAC = 0x9E8B33
        let params = [0x33u8, 0x8B, 0x9E, duration, max_responses];
        unsafe { self.send_command(opcode, &params) }
    }

    pub fn hci_le_set_scan_parameters(
        &mut self,
        scan_type: u8,     // 0=passive 1=active
        interval: u16,     // in 0.625 ms units, e.g. 0x0010 = 10 ms
        window: u16,       // in 0.625 ms units, ≤ interval
        own_addr_type: u8, // 0=public 1=random
        filter_policy: u8, // 0=accept all
    ) -> bool {
        let opcode = hci_opcode(HCI_OGF_LE, HCI_OCF_LE_SET_SCAN_PARAM);
        let params = [
            scan_type,
            (interval & 0xFF) as u8, ((interval >> 8) & 0xFF) as u8,
            (window   & 0xFF) as u8, ((window   >> 8) & 0xFF) as u8,
            own_addr_type,
            filter_policy,
        ];
        unsafe { self.send_command(opcode, &params) }
    }

    pub fn hci_le_set_scan_enable(&mut self, enable: bool, filter_dups: bool) -> bool {
        let opcode = hci_opcode(HCI_OGF_LE, HCI_OCF_LE_SET_SCAN_EN);
        let params = [enable as u8, filter_dups as u8];
        unsafe { self.send_command(opcode, &params) }
    }

    // ----------------------------------------------------------------
    // Event poll
    // ----------------------------------------------------------------

    /// Poll for one HCI event.  Call this repeatedly in your main loop or
    /// interrupt handler.
    pub fn poll(&mut self) -> BluetoothEvent {
        let n = unsafe { self.recv_event() };
        if n < 2 { return BluetoothEvent::None; }
        let evt_code = unsafe { HCI_EVENT_BUF[0] };
        match evt_code {
            HCI_EVENT_CMD_COMPLETE => {
                if n < 6 { return BluetoothEvent::None; }
                let opcode = unsafe {
                    (HCI_EVENT_BUF[2] as u16) | ((HCI_EVENT_BUF[3] as u16) << 8)
                };
                let status = unsafe { HCI_EVENT_BUF[4] };
                BluetoothEvent::CommandComplete { opcode, status }
            }
            HCI_EVENT_INQUIRY_RESULT => {
                if n < 15 { return BluetoothEvent::None; }
                let addr = unsafe { BdAddr::from_bytes(&HCI_EVENT_BUF[3..9]) };
                // RSSI not available in standard inquiry result; use 0
                let dev = BluetoothDevice { addr, rssi: 0, is_le: false, adv_data: [0u8; 8] };
                if self.dev_count < BT_MAX_DEVICES {
                    self.devices[self.dev_count] = dev;
                    self.dev_count += 1;
                }
                BluetoothEvent::InquiryResult(dev)
            }
            HCI_EVENT_LE_META => {
                if n < 3 { return BluetoothEvent::None; }
                let subevent = unsafe { HCI_EVENT_BUF[1] };
                if subevent == HCI_LE_SUBEVENT_ADV_REPORT && n >= 14 {
                    // Subevent + num_reports + event_type + addr_type + addr[6] + data_len + data + RSSI
                    // Offset: [1]=subevent [2]=num_reports [3]=event_type [4]=addr_type [5..11]=addr [11]=data_len
                    let addr = unsafe { BdAddr::from_bytes(&HCI_EVENT_BUF[5..11]) };
                    let rssi = unsafe { HCI_EVENT_BUF[n - 1] as i8 };
                    let data_len = unsafe { HCI_EVENT_BUF[11] as usize };
                    let mut adv_data = [0u8; 8];
                    let copy_len = core::cmp::min(data_len, 8);
                    if n >= 12 + copy_len {
                        unsafe {
                            adv_data[..copy_len].copy_from_slice(&HCI_EVENT_BUF[12..12 + copy_len]);
                        }
                    }
                    let dev = BluetoothDevice { addr, rssi, is_le: true, adv_data };
                    if self.dev_count < BT_MAX_DEVICES {
                        self.devices[self.dev_count] = dev;
                        self.dev_count += 1;
                    }
                    BluetoothEvent::LeAdvertReport(dev)
                } else {
                    BluetoothEvent::None
                }
            }
            _ => BluetoothEvent::None,
        }
    }

    // ----------------------------------------------------------------
    // Full initialisation sequence
    // ----------------------------------------------------------------

    pub fn init(&mut self) -> bool {
        if !self.hci_reset() {
            crate::serial_println!("[BT] HCI reset failed");
            return false;
        }
        self.bd_addr = self.hci_read_bd_addr();
        crate::serial_println!(
            "[BT] Local BD_ADDR: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.bd_addr.0[5], self.bd_addr.0[4], self.bd_addr.0[3],
            self.bd_addr.0[2], self.bd_addr.0[1], self.bd_addr.0[0]
        );

        // Start passive LE scan (10 ms interval, 10 ms window)
        let _ = self.hci_le_set_scan_parameters(0, 0x0010, 0x0010, 0, 0);
        let _ = self.hci_le_set_scan_enable(true, true);

        self.ready = true;
        true
    }
}

// ============================================================================
// Global Bluetooth controller
// ============================================================================

pub static BLUETOOTH: Mutex<Option<BluetoothController>> = Mutex::new(None);

/// Scan the USB bus for a Bluetooth HCI adapter and initialise it.
///
/// Call once during kernel startup after `usb::init()`.
pub fn init() {
    use crate::usb::{USB_BUS, UsbControllerKind};

    // Collect matching device info without holding the lock.
    let found = {
        let usb = USB_BUS.lock();
        let mut result: Option<UsbHandle> = None;
        for d in usb.devices[..usb.device_count].iter().filter_map(|d| d.as_ref()) {
            // Bluetooth USB class 0xE0 / subclass 0x01 / protocol 0x01
            if d.descriptor.b_device_class    != 0xE0 { continue; }
            if d.descriptor.b_device_sub_class != 0x01 { continue; }
            if d.descriptor.b_device_protocol  != 0x01 { continue; }

            let ci = d.controller_index;
            let (ctrl_kind, bar_value, pci) = match usb.controllers[ci] {
                Some(ref info) => {
                    let (kind, bv) = unsafe {
                        match info.kind {
                            UsbControllerKind::Uhci => {
                                let bar4 = info.pci.read_bar(4);
                                (BtCtrlKind::Uhci, bar4)
                            }
                            UsbControllerKind::Ehci => {
                                let bar0 = info.pci.read_bar(0);
                                (BtCtrlKind::Ehci, bar0)
                            }
                            _ => (BtCtrlKind::Other, 0u32),
                        }
                    };
                    (kind, bv, info.pci)
                }
                None => continue,
            };

            let speed = match d.speed {
                crate::usb::UsbSpeed::Low  => 0u8,
                crate::usb::UsbSpeed::Full => 1u8,
                crate::usb::UsbSpeed::High => 2u8,
                crate::usb::UsbSpeed::Super | crate::usb::UsbSpeed::Super20 => 2u8,
            };
            result = Some(UsbHandle {
                dev_addr:   d.address,
                ctrl_idx:   ci,
                ep_event:   0x81,
                ep_acl_in:  0x82,
                ep_acl_out: 0x02,
                speed,
                ctrl_kind,
                bar_value,
                pci,
            });
            break;
        }
        result
    };

    if let Some(handle) = found {
        let mut ctrl = BluetoothController::new(handle);
        if ctrl.init() {
            *BLUETOOTH.lock() = Some(ctrl);
            crate::serial_println!("[BT] Bluetooth HCI adapter initialised");
            return;
        }
    }
    crate::serial_println!("[BT] No Bluetooth adapter found");
}

/// Poll for the next Bluetooth event.  Returns `BluetoothEvent::None` if
/// nothing is pending.
pub fn poll() -> BluetoothEvent {
    match BLUETOOTH.lock().as_mut() {
        Some(c) => c.poll(),
        None    => BluetoothEvent::None,
    }
}

/// Return all discovered devices since the last call to `clear_devices()`.
pub fn discovered_devices(out: &mut [BluetoothDevice]) -> usize {
    match BLUETOOTH.lock().as_ref() {
        Some(c) => {
            let n = core::cmp::min(c.dev_count, out.len());
            out[..n].copy_from_slice(&c.devices[..n]);
            n
        }
        None => 0,
    }
}

pub fn clear_devices() {
    if let Some(c) = BLUETOOTH.lock().as_mut() {
        c.dev_count = 0;
    }
}
