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

// ACPI Assembly Bindings
// Power management and thermal monitoring

use core::fmt;

/// ACPI RSDP structure
#[repr(C, packed)]
pub struct Rsdp {
    pub signature: [u8; 8],
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    pub rsdt_address: u32,
}

/// ACPI table header
#[repr(C, packed)]
pub struct AcpiTableHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

/// ACPI FADT (Fixed ACPI Description Table) — "FACP" signature.
///
/// We only model the fields we actually need through offset 56.
/// All multi-byte fields are little-endian.
///
/// ACPI §5.2.9 layout:
///   +0   Header (36 bytes)
///   +36  FIRMWARE_CTRL  u32
///   +40  DSDT           u32
///   +44  Reserved       u8
///   +45  Preferred_PM_Profile u8
///   +46  SCI_INT        u16
///   +48  SMI_CMD        u32
///   +52  ACPI_ENABLE    u8
///   +53  ACPI_DISABLE   u8
///   +54  S4BIOS_REQ     u8
///   +55  PSTATE_CNT     u8
///   +56  PM1a_EVT_BLK   u32
///   +60  PM1b_EVT_BLK   u32
///   +64  PM1a_CNT_BLK   u32   ← what we need for power management
///   +68  PM1b_CNT_BLK   u32
#[repr(C, packed)]
pub struct FadtTable {
    pub header: AcpiTableHeader, // 0..36
    pub firmware_ctrl: u32,      // 36
    pub dsdt: u32,               // 40
    pub _reserved: u8,           // 44
    pub preferred_pm: u8,        // 45
    pub sci_int: u16,            // 46
    pub smi_cmd: u32,            // 48
    pub acpi_enable: u8,         // 52
    pub acpi_disable: u8,        // 53
    pub s4bios_req: u8,          // 54
    pub pstate_cnt: u8,          // 55
    pub pm1a_evt_blk: u32,       // 56
    pub pm1b_evt_blk: u32,       // 60
    pub pm1a_cnt_blk: u32,       // 64  ← PM1a Control Block I/O port
    pub pm1b_cnt_blk: u32,       // 68
}

/// Power states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SleepState {
    S0 = 0, // Working
    S1 = 1, // Sleep
    S2 = 2, // Sleep
    S3 = 3, // Suspend to RAM
    S4 = 4, // Suspend to disk
    S5 = 5, // Soft off
}

/// CPU C-states
#[derive(Debug, Clone, Copy)]
pub enum CState {
    C0, // Active
    C1, // Halt
    C2, // Stop clock
    C3, // Deep sleep
}

/// Cooling policy
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum CoolingPolicy {
    Active = 0,
    Passive = 1,
}

/// ACPI statistics
#[derive(Debug, Default)]
pub struct AcpiStats {
    pub sleeps: u32,
    pub wakes: u32,
    pub thermal_events: u32,
}

extern "C" {
    // Table discovery
    pub fn acpi_find_rsdp() -> u32;
    pub fn acpi_checksum(table: *const u8, length: u32) -> u8;
    pub fn acpi_find_table(rsdt_addr: u32, signature: u32) -> u32;

    // Register access
    pub fn acpi_read_pm1_control(pm1a_base: u16) -> u16;
    pub fn acpi_write_pm1_control(pm1a_base: u16, value: u16);
    pub fn acpi_read_pm1_status(pm1a_base: u16) -> u16;
    pub fn acpi_write_pm1_status(pm1a_base: u16, value: u16);

    // Power state transitions
    pub fn acpi_enter_sleep_state(pm1a_base: u16, sleep_type: u8, sleep_enable: u8);
    pub fn acpi_shutdown(pm1a_base: u16);
    pub fn acpi_reboot(reset_reg_addr: u8);

    // Thermal monitoring
    pub fn acpi_read_thermal_zone(ec_data_port: u16, register: u8) -> u32;
    pub fn acpi_set_cooling_policy(policy: u8);

    // C-states
    pub fn acpi_enter_c1();
    pub fn acpi_enter_c2(p_lvl2_port: u16);
    pub fn acpi_enter_c3(p_lvl3_port: u16);

    // P-states
    pub fn acpi_set_pstate(pstate: u8);
    pub fn acpi_get_pstate() -> u8;

    // Battery
    pub fn acpi_get_battery_status() -> u32;
    pub fn acpi_get_battery_capacity() -> u8;

    // Events
    pub fn acpi_enable_events(pm1a_base: u16, event_mask: u16);
    pub fn acpi_get_event_status(pm1a_base: u16) -> u16;
    pub fn acpi_clear_event(pm1a_base: u16, event_bits: u16);

    // Statistics
    pub fn get_acpi_stats(sleeps: *mut u32, wakes: *mut u32, thermal: *mut u32);
}

/// ACPI manager
pub struct Acpi {
    rsdp_addr: u32,
    rsdt_addr: u32,
    pm1a_base: u16,
}

impl Acpi {
    pub fn init() -> Option<Self> {
        let rsdp_addr = unsafe { acpi_find_rsdp() };
        if rsdp_addr == 0 {
            return None;
        }

        let rsdp = unsafe { &*(rsdp_addr as *const Rsdp) };

        // Verify checksum
        let sum = unsafe { acpi_checksum(rsdp_addr as *const u8, 20) };
        if sum != 0 {
            return None;
        }

        crate::serial_println!("[ACPI] RSDP found at address: 0x{:08X}", rsdp_addr);
        crate::serial_println!(
            "[ACPI] RSDP signature: {}",
            core::str::from_utf8(&rsdp.signature).unwrap_or("<invalid>")
        );

        // Copy packed field to avoid unaligned reference
        let rsdt_addr = rsdp.rsdt_address;
        crate::serial_println!("[ACPI] RSDT address: 0x{:08X}", rsdt_addr);

        let acpi = Self {
            rsdp_addr,
            rsdt_addr: rsdp.rsdt_address,
            pm1a_base: {
                // Read PM1a_CNT_BLK from FADT ("FACP") at FADT offset 64.
                //
                // acpi_find_table() expects a u32 of the 4-byte signature as
                // little-endian bytes; "FACP" LE = 0x50_43_41_46.
                let fadt_addr = unsafe { acpi_find_table(rsdt_addr, 0x5043_4146u32) };
                if fadt_addr != 0 {
                    let fadt = unsafe { &*(fadt_addr as *const FadtTable) };
                    // pm1a_cnt_blk is a packed u32 — copy through a raw pointer
                    // to avoid an unaligned reference.
                    let blk: u32 = unsafe {
                        core::ptr::read_unaligned(core::ptr::addr_of!(fadt.pm1a_cnt_blk))
                    };
                    crate::serial_println!(
                        "[ACPI] FADT found at 0x{:08X}, PM1a_CNT_BLK=0x{:04X}",
                        fadt_addr,
                        blk
                    );
                    blk as u16
                } else {
                    crate::serial_println!("[ACPI] FADT not found — pm1a_base defaulting to 0");
                    0
                }
            },
        };

        // Log ACPI initialization details using rsdp_addr
        crate::serial_println!("[ACPI] Initialized successfully");
        crate::serial_println!(
            "[ACPI] Memory map: RSDP=0x{:08X}, RSDT=0x{:08X}",
            acpi.rsdp_address(),
            acpi.rsdt_address()
        );

        Some(acpi)
    }

    /// Get RSDP address for diagnostics
    pub fn rsdp_address(&self) -> u32 {
        self.rsdp_addr
    }

    /// Get RSDT address
    pub fn rsdt_address(&self) -> u32 {
        self.rsdt_addr
    }

    /// Print ACPI table information for diagnostics
    pub fn print_info(&self) {
        crate::serial_println!("[ACPI] Table Addresses:");
        crate::serial_println!("[ACPI]   RSDP: 0x{:08X}", self.rsdp_addr);
        crate::serial_println!("[ACPI]   RSDT: 0x{:08X}", self.rsdt_addr);
        crate::serial_println!("[ACPI]   PM1a Control: 0x{:04X}", self.pm1a_base);
    }

    pub fn find_table(&self, signature: &[u8; 4]) -> Option<u32> {
        let sig = u32::from_le_bytes(*signature);
        let addr = unsafe { acpi_find_table(self.rsdt_addr, sig) };
        if addr == 0 {
            None
        } else {
            Some(addr)
        }
    }

    pub fn shutdown(&self) {
        unsafe { acpi_shutdown(self.pm1a_base) }
    }

    pub fn reboot(&self) {
        unsafe { acpi_reboot(0) }
    }

    pub fn enter_sleep(&self, state: SleepState) {
        unsafe {
            acpi_enter_sleep_state(self.pm1a_base, state as u8, 1);
        }
    }
}

/// CPU power management
pub struct CpuPower;

impl CpuPower {
    pub fn enter_c1() {
        unsafe { acpi_enter_c1() }
    }

    pub fn enter_c2(port: u16) {
        unsafe { acpi_enter_c2(port) }
    }

    pub fn enter_c3(port: u16) {
        unsafe { acpi_enter_c3(port) }
    }

    pub fn set_pstate(state: u8) {
        unsafe { acpi_set_pstate(state) }
    }

    pub fn get_pstate() -> u8 {
        unsafe { acpi_get_pstate() }
    }
}

/// Battery information
pub struct Battery;

impl Battery {
    pub fn status() -> BatteryStatus {
        let status = unsafe { acpi_get_battery_status() };
        BatteryStatus {
            charging: (status & 1) != 0,
            critical: (status & 2) != 0,
        }
    }

    pub fn capacity() -> u8 {
        unsafe { acpi_get_battery_capacity() }
    }
}

#[derive(Debug)]
pub struct BatteryStatus {
    pub charging: bool,
    pub critical: bool,
}

impl fmt::Display for BatteryStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.critical {
            write!(f, "CRITICAL - ")?;
        }
        if self.charging {
            write!(f, "Charging")
        } else {
            write!(f, "Discharging")
        }
    }
}

/// ACPI statistics accessor
pub struct AcpiStatsAccessor;

impl AcpiStatsAccessor {
    pub fn get() -> AcpiStats {
        let mut stats = AcpiStats::default();
        unsafe {
            get_acpi_stats(
                &mut stats.sleeps,
                &mut stats.wakes,
                &mut stats.thermal_events,
            );
        }
        stats
    }
}
