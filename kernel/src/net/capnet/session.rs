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
 * CapNet session facade.
 */

#![allow(dead_code)]

pub use super::legacy::{
    establish_peer_session, init, install_peer_session_key, journal_stats, local_device_id,
    peer_snapshot, peer_snapshots, process_incoming_control_payload, register_peer,
    sign_outgoing_token_for_peer, verify_incoming_token, CapNetJournalStats, PeerSessionSnapshot,
    PeerTrustPolicy,
};
