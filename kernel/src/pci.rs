/*!
 * Oreulia Kernel Project
 *
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Contributing:
 * - By contributing to this file, you agree to license your work under the same terms.
 * - Please see CONTRIBUTING.md for code style and review guidelines.
 *
 * ---------------------------------------------------------------------------
 */

//! PCI Bus Enumeration and Device Detection
//!
//! Provides low-level PCI configuration space access and device enumeration.
//! Used to detect and configure network cards (Ethernet, WiFi).

#![allow(dead_code)]

// ============================================================================
// PCI Configuration Space Access (x86)
// ============================================================================

const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

/// Read from PCI configuration space
#[inline]
unsafe fn pci_config_read_u32(bus: u8, slot: u8, func: u8, offset: u8) -> u32 {
    let address: u32 = ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC)
        | 0x80000000;

    // Write address
    x86::io::outl(PCI_CONFIG_ADDRESS, address);

    // Read data
    x86::io::inl(PCI_CONFIG_DATA)
}

/// Write to PCI configuration space
#[inline]
unsafe fn pci_config_write_u32(bus: u8, slot: u8, func: u8, offset: u8, value: u32) {
    let address: u32 = ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC)
        | 0x80000000;

    x86::io::outl(PCI_CONFIG_ADDRESS, address);
    x86::io::outl(PCI_CONFIG_DATA, value);
}

/// Read 16-bit value from PCI config space
#[inline]
unsafe fn pci_config_read_u16(bus: u8, slot: u8, func: u8, offset: u8) -> u16 {
    let val = pci_config_read_u32(bus, slot, func, offset);
    ((val >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

/// Read 8-bit value from PCI config space
#[inline]
unsafe fn pci_config_read_u8(bus: u8, slot: u8, func: u8, offset: u8) -> u8 {
    let val = pci_config_read_u32(bus, slot, func, offset);
    ((val >> ((offset & 3) * 8)) & 0xFF) as u8
}

// ============================================================================
// PCI Device Structure
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct PciDevice {
    pub bus: u8,
    pub slot: u8,
    pub func: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
}

impl PciDevice {
    /// Check if this device exists (vendor_id != 0xFFFF)
    pub fn exists(&self) -> bool {
        self.vendor_id != 0xFFFF
    }

    /// Check if this is a network controller
    pub fn is_network_controller(&self) -> bool {
        self.class_code == 0x02 // Network controller
    }

    /// Check if this is an Ethernet controller
    pub fn is_ethernet(&self) -> bool {
        self.class_code == 0x02 && self.subclass == 0x00
    }

    /// Check if this is a WiFi controller (802.11)
    pub fn is_wifi(&self) -> bool {
        self.class_code == 0x02 && self.subclass == 0x80
    }

    /// Check if this is a VirtIO block device
    pub fn is_virtio_block(&self) -> bool {
        self.vendor_id == 0x1AF4 && (self.device_id == 0x1001 || self.device_id == 0x1042)
    }

    /// Check if this is a display / GPU controller (PCI class 0x03)
    pub fn is_display_controller(&self) -> bool {
        self.class_code == 0x03
    }

    /// Check if this is a mass-storage controller (PCI class 0x01)
    pub fn is_storage_controller(&self) -> bool {
        self.class_code == 0x01
    }

    /// Check if this is a USB host controller (PCI class 0x0C, subclass 0x03)
    pub fn is_usb_controller(&self) -> bool {
        self.class_code == 0x0C && self.subclass == 0x03
    }

    /// Check if this is an audio / multimedia controller (PCI class 0x04)
    pub fn is_audio_controller(&self) -> bool {
        self.class_code == 0x04
    }

    /// Check if this is an NVMe controller (class 0x01 / subclass 0x08 / prog-if 0x02)
    pub fn is_nvme_controller(&self) -> bool {
        self.class_code == 0x01 && self.subclass == 0x08 && self.prog_if == 0x02
    }

    /// Check if this is a Realtek RTL8139 Fast Ethernet (vendor 0x10EC / device 0x8139)
    pub fn is_rtl8139(&self) -> bool {
        self.vendor_id == 0x10EC && self.device_id == 0x8139
    }

    /// Get device name based on vendor/device ID
    pub fn name(&self) -> &'static str {
        match (self.vendor_id, self.device_id) {
            // Intel
            (0x8086, 0x100E) => "Intel 82540EM Gigabit Ethernet",
            (0x8086, 0x100F) => "Intel 82545EM Gigabit Ethernet",
            (0x8086, 0x10D3) => "Intel 82574L Gigabit Ethernet",
            (0x8086, 0x4222) => "Intel PRO/Wireless 3945ABG",
            (0x8086, 0x4229) => "Intel PRO/Wireless 4965AGN",
            (0x8086, 0x4232) => "Intel WiFi Link 5100",
            (0x8086, 0x4237) => "Intel WiFi Link 5100 AGN",
            (0x8086, 0x0085) => "Intel Centrino Advanced-N 6205",
            (0x8086, 0x08B1) => "Intel Wireless 7260",
            (0x8086, 0x095A) => "Intel Wireless 7265",
            (0x8086, 0x24FD) => "Intel Wireless 8265",

            // Realtek
            (0x10EC, 0x8139) => "Realtek RTL8139 Fast Ethernet",
            (0x10EC, 0x8168) => "Realtek RTL8168 Gigabit Ethernet",
            (0x10EC, 0x8169) => "Realtek RTL8169 Gigabit Ethernet",
            (0x10EC, 0x8176) => "Realtek RTL8188CE WiFi",
            (0x10EC, 0x8179) => "Realtek RTL8188EE WiFi",

            // Broadcom
            (0x14E4, 0x4311) => "Broadcom BCM4311 802.11b/g WiFi",
            (0x14E4, 0x4312) => "Broadcom BCM4312 802.11b/g WiFi",
            (0x14E4, 0x4315) => "Broadcom BCM4312 802.11b/g LP WiFi",
            (0x14E4, 0x4318) => "Broadcom BCM4318 AirForce WiFi",
            (0x14E4, 0x4328) => "Broadcom BCM4321 802.11a/b/g/n WiFi",
            (0x14E4, 0x432B) => "Broadcom BCM4322 802.11a/b/g/n WiFi",
            (0x14E4, 0x4353) => "Broadcom BCM43224 WiFi",

            // Atheros
            (0x168C, 0x0013) => "Atheros AR5212 802.11abg WiFi",
            (0x168C, 0x001C) => "Atheros AR242x 802.11abg WiFi",
            (0x168C, 0x0024) => "Atheros AR5418 802.11abgn WiFi",
            (0x168C, 0x002A) => "Atheros AR928X 802.11n WiFi",
            (0x168C, 0x002B) => "Atheros AR9285 802.11n WiFi",
            (0x168C, 0x0030) => "Atheros AR93xx 802.11n WiFi",

            // VirtIO (QEMU/KVM)
            (0x1AF4, 0x1000) => "VirtIO Network Device",
            (0x1AF4, 0x1001) => "VirtIO Block Device",
            (0x1AF4, 0x1041) => "VirtIO Network Device (modern)",
            (0x1AF4, 0x1042) => "VirtIO Block Device (modern)",

            // GPU / Display controllers
            (0x1002, 0x4752) => "AMD/ATI Radeon RV100 (VE/M6/A11)",
            (0x1002, 0x6759) => "AMD Radeon HD 6900 Series",
            (0x1002, 0x687F) => "AMD Radeon RX Vega 64",
            (0x10DE, 0x1180) => "NVIDIA GeForce GTX 680",
            (0x10DE, 0x1E04) => "NVIDIA GeForce RTX 2080",
            (0x10DE, 0x2204) => "NVIDIA GeForce RTX 3090",
            (0x8086, 0x0412) => "Intel HD Graphics 4600",
            (0x8086, 0x1912) => "Intel HD Graphics 530",
            (0x8086, 0x3EA0) => "Intel UHD Graphics 620",
            (0x15AD, 0x0405) => "VMware SVGA II Adapter",
            (0x1234, 0x1111) => "QEMU Standard VGA",
            (0x1B36, 0x0100) => "QEMU QXL Paravirtual GPU",

            // USB host controllers
            (0x8086, 0x7020) => "Intel PIIX4 USB UHCI",
            (0x8086, 0x24CD) => "Intel ICH4 USB EHCI",
            (0x8086, 0x1C26) => "Intel 6 Series/C200 USB EHCI",
            (0x8086, 0x1E26) => "Intel 7 Series/C210 USB EHCI",
            (0x8086, 0x8C26) => "Intel 8 Series/C220 USB EHCI",
            (0x8086, 0x8C31) => "Intel 8 Series/C220 USB xHCI",
            (0x1B21, 0x1042) => "ASMedia ASM1042 USB 3.0 xHCI",
            (0x1B21, 0x1142) => "ASMedia ASM1042A USB 3.1 xHCI",

            // ATA / SATA storage
            (0x8086, 0x7010) => "Intel PIIX3 IDE",
            (0x8086, 0x7111) => "Intel PIIX4 IDE",
            (0x8086, 0x2828) => "Intel ICH8M SATA AHCI",
            (0x8086, 0x1C02) => "Intel 6 Series/C200 SATA AHCI",
            (0x8086, 0x8C02) => "Intel 8 Series/C220 SATA AHCI",
            (0x1022, 0x7800) => "AMD FCH SATA AHCI",
            (0x1022, 0x43B8) => "AMD 300 Series SATA AHCI",

            // Audio
            (0x8086, 0x2668) => "Intel ICH6 HD Audio",
            (0x8086, 0x1C20) => "Intel 6 Series/C200 HD Audio",
            (0x8086, 0x8C20) => "Intel 8 Series/C220 HD Audio",
            (0x1002, 0xAAB0) => "AMD Oland/Hainan HDMI Audio",
            (0x10DE, 0x0E0F) => "NVIDIA GK208 HDMI/DP Audio",

            _ => "Unknown PCI Device",
        }
    }

    /// Read BAR (Base Address Register)
    pub unsafe fn read_bar(&self, bar: u8) -> u32 {
        if bar > 5 {
            return 0;
        }
        pci_config_read_u32(self.bus, self.slot, self.func, 0x10 + (bar * 4))
    }

    /// Enable bus mastering (required for DMA)
    pub unsafe fn enable_bus_mastering(&self) {
        let command = pci_config_read_u16(self.bus, self.slot, self.func, 0x04);
        pci_config_write_u32(
            self.bus,
            self.slot,
            self.func,
            0x04,
            (command | 0x04) as u32, // Set bit 2 (Bus Master)
        );
    }

    /// Enable memory space access
    pub unsafe fn enable_memory_space(&self) {
        let command = pci_config_read_u16(self.bus, self.slot, self.func, 0x04);
        pci_config_write_u32(
            self.bus,
            self.slot,
            self.func,
            0x04,
            (command | 0x02) as u32, // Set bit 1 (Memory Space)
        );
    }

    /// Enable I/O space access
    pub unsafe fn enable_io_space(&self) {
        let command = pci_config_read_u16(self.bus, self.slot, self.func, 0x04);
        pci_config_write_u32(
            self.bus,
            self.slot,
            self.func,
            0x04,
            (command | 0x01) as u32, // Set bit 0 (I/O Space)
        );
    }

    /// Get human-readable device type string
    pub fn device_type_str(&self) -> &'static str {
        match self.class_code {
            0x00 => "Unclassified",
            0x01 => "Mass Storage Controller",
            0x02 => match self.subclass {
                0x00 => "Ethernet Controller",
                0x80 => "Network Controller (Other)",
                _ => "Network Controller",
            },
            0x03 => "Display Controller",
            0x04 => "Multimedia Controller",
            0x05 => "Memory Controller",
            0x06 => "Bridge Device",
            0x07 => "Communication Controller",
            0x08 => "System Peripheral",
            0x09 => "Input Device",
            0x0A => "Docking Station",
            0x0B => "Processor",
            0x0C => match self.subclass {
                0x03 => "USB Controller",
                _ => "Serial Bus Controller",
            },
            0x0D => "Wireless Controller",
            _ => "Unknown Device",
        }
    }

    /// Get vendor name
    pub fn vendor_name(&self) -> &'static str {
        match self.vendor_id {
            0x1002 => "Advanced Micro Devices (AMD)",
            0x1022 => "AMD",
            0x10B9 => "ALi Corporation",
            0x10DE => "NVIDIA Corporation",
            0x10EC => "Realtek Semiconductor",
            0x1106 => "VIA Technologies",
            0x1234 => "QEMU / Bochs (emulated)",
            0x1283 => "Integrated Technology Express",
            0x1414 => "Microsoft Corporation",
            0x14E4 => "Broadcom Corporation",
            0x15AD => "VMware Inc.",
            0x168C => "Qualcomm Atheros",
            0x1AF4 => "Red Hat (VirtIO)",
            0x1B21 => "ASMedia Technology",
            0x1B36 => "QEMU paravirtual",
            0x8086 => "Intel Corporation",
            _ => "Unknown Vendor",
        }
    }
}

// ============================================================================
// PCI Bus Scanner
// ============================================================================

pub const MAX_PCI_DEVICES: usize = 32;

pub struct PciScanner {
    devices: [Option<PciDevice>; MAX_PCI_DEVICES],
    device_count: usize,
}

impl PciScanner {
    pub const fn new() -> Self {
        PciScanner {
            devices: [None; MAX_PCI_DEVICES],
            device_count: 0,
        }
    }

    /// Scan all PCI buses for devices
    pub fn scan(&mut self) {
        self.device_count = 0;

        unsafe {
            // Scan bus 0 (most systems only have bus 0)
            for slot in 0..32 {
                if let Some(device) = self.probe_device(0, slot, 0) {
                    if self.device_count < MAX_PCI_DEVICES {
                        self.devices[self.device_count] = Some(device);
                        self.device_count += 1;
                    }
                }
            }
        }
    }

    /// Probe a specific PCI device
    unsafe fn probe_device(&self, bus: u8, slot: u8, func: u8) -> Option<PciDevice> {
        let vendor_id = pci_config_read_u16(bus, slot, func, 0x00);

        if vendor_id == 0xFFFF {
            return None; // No device
        }

        let device_id = pci_config_read_u16(bus, slot, func, 0x02);
        let class_code = pci_config_read_u8(bus, slot, func, 0x0B);
        let subclass = pci_config_read_u8(bus, slot, func, 0x0A);
        let prog_if = pci_config_read_u8(bus, slot, func, 0x09);
        let revision = pci_config_read_u8(bus, slot, func, 0x08);
        let interrupt_line = pci_config_read_u8(bus, slot, func, 0x3C);
        let interrupt_pin = pci_config_read_u8(bus, slot, func, 0x3D);

        Some(PciDevice {
            bus,
            slot,
            func,
            vendor_id,
            device_id,
            class_code,
            subclass,
            prog_if,
            revision,
            interrupt_line,
            interrupt_pin,
        })
    }

    /// Get all detected devices
    pub fn devices(&self) -> &[Option<PciDevice>] {
        &self.devices[..self.device_count]
    }

    /// Find first network device (Ethernet or WiFi)
    pub fn find_network_device(&self) -> Option<PciDevice> {
        for device_opt in self.devices().iter() {
            if let Some(device) = device_opt {
                if device.is_network_controller() {
                    return Some(*device);
                }
            }
        }
        None
    }

    /// Find first WiFi device
    pub fn find_wifi_device(&self) -> Option<PciDevice> {
        for device_opt in self.devices().iter() {
            if let Some(device) = device_opt {
                if device.is_wifi() {
                    return Some(*device);
                }
            }
        }
        None
    }

    /// Find first Ethernet device
    pub fn find_ethernet_device(&self) -> Option<PciDevice> {
        for device_opt in self.devices().iter() {
            if let Some(device) = device_opt {
                if device.is_ethernet() {
                    return Some(*device);
                }
            }
        }
        None
    }

    /// Find first VirtIO block device
    pub fn find_virtio_block(&self) -> Option<PciDevice> {
        for device_opt in self.devices().iter() {
            if let Some(device) = device_opt {
                if device.is_virtio_block() {
                    return Some(*device);
                }
            }
        }
        None
    }

    /// Find the first display / GPU controller (PCI class 0x03)
    pub fn find_display_device(&self) -> Option<PciDevice> {
        for device_opt in self.devices().iter() {
            if let Some(device) = device_opt {
                if device.is_display_controller() {
                    return Some(*device);
                }
            }
        }
        None
    }

    /// Find all display / GPU controllers
    pub fn find_all_display_devices(&self) -> [Option<PciDevice>; 4] {
        let mut result = [None; 4];
        let mut count = 0usize;
        for device_opt in self.devices().iter() {
            if let Some(device) = device_opt {
                if device.is_display_controller() && count < 4 {
                    result[count] = Some(*device);
                    count += 1;
                }
            }
        }
        result
    }

    /// Find the first mass-storage controller (PCI class 0x01)
    pub fn find_storage_controller(&self) -> Option<PciDevice> {
        for device_opt in self.devices().iter() {
            if let Some(device) = device_opt {
                if device.is_storage_controller() {
                    return Some(*device);
                }
            }
        }
        None
    }

    /// Find all mass-storage controllers
    pub fn find_all_storage_controllers(&self) -> [Option<PciDevice>; 4] {
        let mut result = [None; 4];
        let mut count = 0usize;
        for device_opt in self.devices().iter() {
            if let Some(device) = device_opt {
                if device.is_storage_controller() && count < 4 {
                    result[count] = Some(*device);
                    count += 1;
                }
            }
        }
        result
    }

    /// Find the first USB host controller (PCI class 0x0C, subclass 0x03)
    pub fn find_usb_controller(&self) -> Option<PciDevice> {
        for device_opt in self.devices().iter() {
            if let Some(device) = device_opt {
                if device.is_usb_controller() {
                    return Some(*device);
                }
            }
        }
        None
    }

    /// Find all USB host controllers
    pub fn find_all_usb_controllers(&self) -> [Option<PciDevice>; MAX_PCI_DEVICES] {
        let mut result = [None; MAX_PCI_DEVICES];
        let mut count = 0usize;
        for device_opt in self.devices().iter() {
            if let Some(device) = device_opt {
                if device.is_usb_controller() && count < MAX_PCI_DEVICES {
                    result[count] = Some(*device);
                    count += 1;
                }
            }
        }
        result
    }

    /// Find the first audio / multimedia controller (PCI class 0x04)
    pub fn find_audio_controller(&self) -> Option<PciDevice> {
        for device_opt in self.devices().iter() {
            if let Some(device) = device_opt {
                if device.is_audio_controller() {
                    return Some(*device);
                }
            }
        }
        None
    }

    /// Find the first NVMe controller (class 0x01 / subclass 0x08 / prog-if 0x02)
    pub fn find_nvme_controller(&self) -> Option<PciDevice> {
        for device_opt in self.devices().iter() {
            if let Some(device) = device_opt {
                if device.is_nvme_controller() {
                    return Some(*device);
                }
            }
        }
        None
    }

    /// Find all NVMe controllers (up to 4)
    pub fn find_all_nvme_controllers(&self) -> [Option<PciDevice>; 4] {
        let mut result = [None; 4];
        let mut count = 0usize;
        for device_opt in self.devices().iter() {
            if let Some(device) = device_opt {
                if device.is_nvme_controller() && count < 4 {
                    result[count] = Some(*device);
                    count += 1;
                }
            }
        }
        result
    }

    /// Find a Realtek RTL8139 Fast Ethernet controller
    pub fn find_rtl8139(&self) -> Option<PciDevice> {
        for device_opt in self.devices().iter() {
            if let Some(device) = device_opt {
                if device.is_rtl8139() {
                    return Some(*device);
                }
            }
        }
        None
    }
}

// ============================================================================
// x86 I/O port access helpers
// ============================================================================

mod x86 {
    pub mod io {
        #[inline]
        pub unsafe fn outl(port: u16, value: u32) {
            core::arch::asm!(
                "out dx, eax",
                in("dx") port,
                in("eax") value,
                options(nomem, nostack, preserves_flags)
            );
        }

        #[inline]
        pub unsafe fn inl(port: u16) -> u32 {
            let value: u32;
            core::arch::asm!(
                "in eax, dx",
                out("eax") value,
                in("dx") port,
                options(nomem, nostack, preserves_flags)
            );
            value
        }

        #[inline]
        pub unsafe fn outw(port: u16, value: u16) {
            core::arch::asm!(
                "out dx, ax",
                in("dx") port,
                in("ax") value,
                options(nomem, nostack, preserves_flags)
            );
        }

        #[inline]
        pub unsafe fn inw(port: u16) -> u16 {
            let value: u16;
            core::arch::asm!(
                "in ax, dx",
                out("ax") value,
                in("dx") port,
                options(nomem, nostack, preserves_flags)
            );
            value
        }

        #[inline]
        pub unsafe fn outb(port: u16, value: u8) {
            core::arch::asm!(
                "out dx, al",
                in("dx") port,
                in("al") value,
                options(nomem, nostack, preserves_flags)
            );
        }

        #[inline]
        pub unsafe fn inb(port: u16) -> u8 {
            let value: u8;
            core::arch::asm!(
                "in al, dx",
                out("al") value,
                in("dx") port,
                options(nomem, nostack, preserves_flags)
            );
            value
        }
    }
}

pub use x86::io;
