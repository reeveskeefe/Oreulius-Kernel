/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


/*!
 * CapNet metrics and fuzz facade.
 */

#![allow(dead_code)]

pub use super::legacy::{
    capnet_fuzz, capnet_fuzz_regression_default, capnet_fuzz_regression_soak_default,
    CapNetFuzzFailure, CapNetFuzzRegressionStats, CapNetFuzzSoakStats, CapNetFuzzStats,
    CAPNET_FUZZ_REGRESSION_SEEDS,
};
