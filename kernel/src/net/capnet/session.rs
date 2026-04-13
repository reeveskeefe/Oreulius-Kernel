/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


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
