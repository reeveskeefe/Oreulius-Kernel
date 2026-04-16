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

//! Minimal AArch64 driver root.
//!
//! The current hardware-driver tree is intentionally x86-family only. This
//! module exists so the top-level `drivers` facade has an explicit AArch64
//! backend root without pretending that legacy x86 hardware drivers exist on
//! this target.
