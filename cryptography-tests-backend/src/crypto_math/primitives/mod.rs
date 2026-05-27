// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Host-side mirrors of kernel crypto primitives (see crate README).
// This module is **code under test**, not derivation vectors.  Those live in
// `crate::crypto_math::derivation`.

mod aes_gcm;
mod ghash;
mod hkdf;
mod hmac;
mod sha256;
mod sha512;
mod x25519;

pub use aes_gcm::{aes128_gcm_decrypt, aes128_gcm_encrypt};
pub use ghash::ghash;
pub use hkdf::{hkdf_expand, hkdf_expand_label_sha256, hkdf_extract};
pub use hmac::{hmac_sha256, hmac_sha256_trunc16, HmacSha256};
pub use sha256::{sha256, Sha256};
pub use sha512::{sha512, Sha512};
pub use x25519::{x25519, x25519_public_key, x25519_shared_secret, BASE_U};
