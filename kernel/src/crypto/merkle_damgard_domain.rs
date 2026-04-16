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


/*!
 * Domain-separated hashing helpers for transcript binding and Merkle-style trees.
 */

use crate::crypto::{sha256, Sha256};

pub fn merkle_damgard_domain_hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    let dlen = core::cmp::min(domain.len(), u8::MAX as usize) as u8;
    h.update(&[0xA5, dlen]);
    h.update(&domain[..dlen as usize]);
    h.update(&(payload.len() as u64).to_be_bytes());
    h.update(payload);
    h.finalize()
}

pub fn merkle_damgard_leaf_hash(domain: &[u8], leaf: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 33];
    buf[0] = 0;
    let leaf_hash = sha256(leaf);
    buf[1..].copy_from_slice(&leaf_hash);
    merkle_damgard_domain_hash(domain, &buf)
}

pub fn merkle_damgard_node_hash(domain: &[u8], left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 65];
    buf[0] = 1;
    buf[1..33].copy_from_slice(left);
    buf[33..65].copy_from_slice(right);
    merkle_damgard_domain_hash(domain, &buf)
}
