/*!
 * GPU error taxonomy.
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuError {
    Unsupported,
    ProbeFailed,
    ActivationFailed,
    NoScanout,
    NoCompute,
    InvalidPacket,
    InvalidMapping,
    FirmwareRequired,
    FirmwareInvalid,
    FenceTimeout,
}

