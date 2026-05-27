// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Everything in this crate besides AES-128-in-lib.rs: kernel-mirrored **primitives**
// plus **derivation** vectors/checks.  Keeps `src/` sidebar to one folder.

pub mod derivation;
pub mod primitives;

use derivation::report::TestCaseResult;

/// Runs all mathematical derivation suites (see `derivation/`).
pub fn run_mathematical_derivation_tests() -> Result<(), Vec<(&'static str, &'static str, String)>>
{
    use derivation::{
        aes_ctr, aes_gcm, aes_primitives, fleet_composition, ghash, hkdf, hmac, ota_composition,
        persistence_composition, public_api_capability_wrappers, report, sha256, sha512,
        signing_formats, tls_composition, x25519,
    };

    report::emit_banner("OREULIUS CRYPTO MATHEMATICAL DERIVATION TESTS");

    let mut total_passed = 0usize;
    let mut total_failed = 0usize;
    let mut failed_cases: Vec<(&'static str, &'static str, String)> = Vec::new();

    let suites: [(&str, Vec<TestCaseResult>); 15] = [
        (
            "AES-128 Primitives And Oreulius Constants",
            aes_primitives::run_deterministic_tests(),
        ),
        (
            "AES-128 CTR Counter Mode",
            aes_ctr::run_deterministic_tests(),
        ),
        ("SHA-256", sha256::run_deterministic_tests()),
        ("SHA-512", sha512::run_deterministic_tests()),
        ("HMAC-SHA256", hmac::run_deterministic_tests()),
        ("HKDF-SHA256", hkdf::run_deterministic_tests()),
        ("GHASH over GF(2^128)", ghash::run_deterministic_tests()),
        ("AES-128-GCM", aes_gcm::run_deterministic_tests()),
        ("X25519 Key Agreement", x25519::run_deterministic_tests()),
        (
            "Signing Formats And Canonical Messages",
            signing_formats::run_deterministic_tests(),
        ),
        (
            "TLS Primitive Composition",
            tls_composition::run_deterministic_tests(),
        ),
        (
            "Persistence Primitive Composition",
            persistence_composition::run_deterministic_tests(),
        ),
        (
            "OTA Primitive Composition",
            ota_composition::run_deterministic_tests(),
        ),
        (
            "Fleet Attestation Primitive Composition",
            fleet_composition::run_deterministic_tests(),
        ),
        (
            "Public API And Capability-Safe Wrappers",
            public_api_capability_wrappers::run_deterministic_tests(),
        ),
    ];

    for (suite, results) in suites {
        let (passed, failed) = report::emit_suite_results(suite, &results);
        total_passed += passed;
        total_failed += failed;
        for (name, ok, detail) in results {
            if !ok {
                failed_cases.push((suite, name, detail));
            }
        }
    }

    report::emit_summary(total_passed, total_failed);

    if failed_cases.is_empty() {
        Ok(())
    } else {
        report::emit_line("Failed cases:");
        for (suite, name, detail) in &failed_cases {
            report::emit_line(&format!("  - {suite} :: {name} — {detail}"));
        }
        Err(failed_cases)
    }
}
