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
 * CapNet encoding facade.
 */

#![allow(dead_code)]

pub use super::legacy::{
    build_attest_frame, build_heartbeat_frame, build_hello_frame, build_token_accept_frame,
    build_token_offer_frame, build_token_revoke_frame, decode_control_frame, CapNetControlFrame,
    CapNetControlType, CapNetError, CapabilityTokenV1, ControlRxResult, EncodedControlFrame,
    SplitCap, CAPNET_ALG_RESERVED_ED25519, CAPNET_ALG_SIPHASH24_KERNEL,
    CAPNET_CONSTRAINT_MEASUREMENT_BOUND, CAPNET_CONSTRAINT_REQUIRE_BOUNDED_USE,
    CAPNET_CONSTRAINT_REQUIRE_BYTE_QUOTA, CAPNET_CONSTRAINT_SESSION_BOUND,
    CAPNET_CONTROL_PORT, CAPNET_CTRL_MAX_FRAME_LEN, CAPNET_CTRL_MAX_PAYLOAD, CAPNET_MAX_DELEGATION_DEPTH,
    CAPNET_MAX_PEERS, CAPNET_TOKEN_MAGIC, CAPNET_TOKEN_VERSION_V1, CAPNET_TOKEN_V1_LEN,
};
