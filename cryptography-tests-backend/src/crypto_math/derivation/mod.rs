// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Mathematical derivation checks (vectors / properties) for host-side crypto.
// Implementations live in `crate::crypto_math::primitives`; this tree is **only** assertions and
// reporting — not duplicate primitives.

pub mod aes_ctr;
pub mod aes_gcm;
pub mod aes_primitives;
pub mod fleet_composition;
pub mod ghash;
pub mod hkdf;
pub mod hmac;
pub mod ota_composition;
pub mod persistence_composition;
pub mod public_api_capability_wrappers;
pub mod report;
pub mod sha256;
pub mod sha512;
pub mod signing_formats;
pub mod tls_composition;
pub mod x25519;
