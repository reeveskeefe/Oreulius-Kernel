/*!
 * Firmware metadata for device-family plugins.
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareManifest {
    pub vendor_id: u16,
    pub device_id: u16,
    pub min_version: u32,
}

