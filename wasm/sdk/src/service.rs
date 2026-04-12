//! Service-pointer capability helpers.
//!
//! This module wraps the typed service-pointer ABI surface:
//!
//! - host id `9`: `service_register`
//! - host id `11`: `last_service_cap`
//! - host id `12`: `service_invoke_typed`
//!
//! The kernel encodes typed service arguments/results as fixed-size slots:
//! one tag byte followed by eight payload bytes.

use crate::raw::oreulius as raw;

/// Maximum number of typed values accepted by the runtime per call.
pub const MAX_SERVICE_VALUES: usize = 64;

/// Size of one encoded service value slot in bytes.
pub const SERVICE_SLOT_BYTES: usize = 9;

/// The type tag stored in the first byte of each typed service slot.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueKind {
    I32 = 0,
    I64 = 1,
    F32 = 2,
    F64 = 3,
    FuncRef = 4,
    ExternRef = 5,
}

/// A typed value accepted by the service-pointer ABI.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ServiceValue {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    FuncRef(Option<u32>),
    ExternRef(Option<u32>),
}

impl ServiceValue {
    /// Encode this value into one 9-byte service slot.
    #[inline]
    pub fn encode_into(self, out: &mut [u8; SERVICE_SLOT_BYTES]) {
        let (tag, payload) = match self {
            ServiceValue::I32(v) => (ValueKind::I32 as u8, v as u32 as u64),
            ServiceValue::I64(v) => (ValueKind::I64 as u8, v as u64),
            ServiceValue::F32(v) => (ValueKind::F32 as u8, v.to_bits() as u64),
            ServiceValue::F64(v) => (ValueKind::F64 as u8, v.to_bits()),
            ServiceValue::FuncRef(Some(idx)) => (ValueKind::FuncRef as u8, idx as u64),
            ServiceValue::FuncRef(None) => (ValueKind::FuncRef as u8, u64::MAX),
            ServiceValue::ExternRef(Some(id)) => (ValueKind::ExternRef as u8, id as u64),
            ServiceValue::ExternRef(None) => (ValueKind::ExternRef as u8, u64::MAX),
        };
        out[0] = tag;
        out[1..9].copy_from_slice(&payload.to_le_bytes());
    }

    /// Decode one 9-byte service slot.
    #[inline]
    pub fn decode_from(slot: &[u8; SERVICE_SLOT_BYTES]) -> Option<Self> {
        let mut payload = [0u8; 8];
        payload.copy_from_slice(&slot[1..9]);
        let raw = u64::from_le_bytes(payload);
        match slot[0] {
            x if x == ValueKind::I32 as u8 => {
                if raw <= u32::MAX as u64 {
                    Some(ServiceValue::I32(raw as u32 as i32))
                } else {
                    None
                }
            }
            x if x == ValueKind::I64 as u8 => Some(ServiceValue::I64(raw as i64)),
            x if x == ValueKind::F32 as u8 => {
                if raw <= u32::MAX as u64 {
                    Some(ServiceValue::F32(f32::from_bits(raw as u32)))
                } else {
                    None
                }
            }
            x if x == ValueKind::F64 as u8 => Some(ServiceValue::F64(f64::from_bits(raw))),
            x if x == ValueKind::FuncRef as u8 => {
                if raw == u64::MAX {
                    Some(ServiceValue::FuncRef(None))
                } else if raw <= u32::MAX as u64 {
                    Some(ServiceValue::FuncRef(Some(raw as u32)))
                } else {
                    None
                }
            }
            x if x == ValueKind::ExternRef as u8 => {
                if raw == u64::MAX {
                    Some(ServiceValue::ExternRef(None))
                } else if raw <= u32::MAX as u64 {
                    Some(ServiceValue::ExternRef(Some(raw as u32)))
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// The typed result of a service-pointer invocation.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ServiceResult {
    values: [ServiceValue; MAX_SERVICE_VALUES],
    len: usize,
}

impl ServiceResult {
    /// Return the values that were actually produced.
    #[inline]
    pub fn as_slice(&self) -> &[ServiceValue] {
        &self.values[..self.len]
    }

    /// Number of values produced by the call.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` when the call produced no values.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return the typed value at `index`, if any.
    #[inline]
    pub fn get(&self, index: usize) -> Option<ServiceValue> {
        self.as_slice().get(index).copied()
    }

    /// Iterate over the produced typed values.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, ServiceValue> {
        self.as_slice().iter()
    }
}

/// A capability-scoped service-pointer handle.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServicePointer {
    cap: u32,
}

impl ServicePointer {
    /// Wrap a raw capability handle.
    #[inline]
    pub const fn from_handle(cap: u32) -> Self {
        Self { cap }
    }

    /// Return the raw capability handle.
    #[inline]
    pub const fn handle(&self) -> u32 {
        self.cap
    }

    /// Invoke this service pointer with typed arguments.
    #[inline]
    pub fn invoke_typed(&self, args: &[ServiceValue]) -> Result<ServiceResult, i32> {
        invoke_typed(self.cap, args)
    }
}

/// Return the most recently auto-imported service capability handle.
#[inline]
pub fn last_service_cap() -> Option<u32> {
    let rc = unsafe { raw::last_service_cap() };
    if rc >= 0 { Some(rc as u32) } else { None }
}

/// Invoke a service-pointer capability using typed slots.
///
/// The runtime accepts up to 64 typed input values and writes up to 64 typed
/// result values. Results are returned as a fixed-size `ServiceResult` so the
/// caller does not need heap allocation.
#[inline]
pub fn invoke_typed(cap_handle: u32, args: &[ServiceValue]) -> Result<ServiceResult, i32> {
    if args.len() > MAX_SERVICE_VALUES {
        return Err(-1);
    }

    let mut encoded_args = [0u8; MAX_SERVICE_VALUES * SERVICE_SLOT_BYTES];
    let mut i = 0usize;
    while i < args.len() {
        let mut slot = [0u8; SERVICE_SLOT_BYTES];
        args[i].encode_into(&mut slot);
        let base = i * SERVICE_SLOT_BYTES;
        encoded_args[base..base + SERVICE_SLOT_BYTES].copy_from_slice(&slot);
        i += 1;
    }

    let mut encoded_results = [0u8; MAX_SERVICE_VALUES * SERVICE_SLOT_BYTES];
    let rc = unsafe {
        raw::service_invoke_typed(
            cap_handle,
            encoded_args.as_ptr() as u32,
            args.len() as u32,
            encoded_results.as_mut_ptr() as u32,
            MAX_SERVICE_VALUES as u32,
        )
    };
    if rc < 0 {
        return Err(rc);
    }

    let len = rc as usize;
    if len > MAX_SERVICE_VALUES {
        return Err(-2);
    }

    let mut values = [ServiceValue::I32(0); MAX_SERVICE_VALUES];
    let mut j = 0usize;
    while j < len {
        let base = j * SERVICE_SLOT_BYTES;
        let slot = [
            encoded_results[base],
            encoded_results[base + 1],
            encoded_results[base + 2],
            encoded_results[base + 3],
            encoded_results[base + 4],
            encoded_results[base + 5],
            encoded_results[base + 6],
            encoded_results[base + 7],
            encoded_results[base + 8],
        ];
        values[j] = ServiceValue::decode_from(&slot).ok_or(-3)?;
        j += 1;
    }

    Ok(ServiceResult { values, len })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_value_encode_decode_round_trip() {
        let cases = [
            ServiceValue::I32(-42),
            ServiceValue::I64(-0x1234_5678_9ABC_DEF0),
            ServiceValue::F32(3.5),
            ServiceValue::F64(-12.25),
            ServiceValue::FuncRef(Some(17)),
            ServiceValue::FuncRef(None),
            ServiceValue::ExternRef(Some(23)),
            ServiceValue::ExternRef(None),
        ];

        for value in cases {
            let mut slot = [0u8; SERVICE_SLOT_BYTES];
            value.encode_into(&mut slot);
            assert_eq!(ServiceValue::decode_from(&slot), Some(value));
        }
    }

    #[test]
    fn service_value_decode_rejects_malformed_slots() {
        let mut slot = [0u8; SERVICE_SLOT_BYTES];
        slot[0] = ValueKind::I32 as u8;
        slot[1..9].copy_from_slice(&(u64::from(u32::MAX) + 1).to_le_bytes());
        assert_eq!(ServiceValue::decode_from(&slot), None);

        slot[0] = ValueKind::FuncRef as u8;
        slot[1..9].copy_from_slice(&(u64::from(u32::MAX) + 2).to_le_bytes());
        assert_eq!(ServiceValue::decode_from(&slot), None);
    }

    #[test]
    fn service_result_accessors_expose_values() {
        let mut values = [ServiceValue::I32(0); MAX_SERVICE_VALUES];
        values[0] = ServiceValue::I32(1);
        values[1] = ServiceValue::I32(2);

        let result = ServiceResult {
            values,
            len: 2,
        };

        assert_eq!(result.len(), 2);
        assert!(!result.is_empty());
        assert_eq!(result.get(0), Some(ServiceValue::I32(1)));
        assert_eq!(result.get(1), Some(ServiceValue::I32(2)));
        assert_eq!(result.get(2), None);
        assert_eq!(result.iter().copied().count(), 2);
    }
}
