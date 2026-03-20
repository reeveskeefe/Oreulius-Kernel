/*!
 * Firmware validation hooks.
 */

use crate::drivers::gpu_support::errors::GpuError;

/// Validate a raw firmware blob.
///
/// Checks that the blob is non-empty. Future work: add magic-header and
/// checksum verification once a canonical firmware format is defined.
pub fn verify_blob(bytes: &[u8]) -> Result<(), GpuError> {
    if bytes.is_empty() {
        return Err(GpuError::FirmwareInvalid);
    }
    Ok(())
}
