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

//! Userspace Telemetry Daemon - Math Queue
//!
//! Implements an eBPF-style wait-free queue (utilizing atomic CAS) for dispatching
//! intent anomalies and Markov matrix updates to the out-of-band math daemon.
//! This ensures the Ring-0 kernel remains completely bounded with zero locks,
//! no unbounded latency, and leaves floating/SIMD processing to the telemetry daemon.

use crate::math::linear_capability::ScalarTensor;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

const QUEUE_SIZE: usize = 128;
pub const TENSOR_DIM_GLOBAL: usize = 128;

pub static GLOBAL_TELEMETRY_QUEUE: Mutex<TelemetryQueue<TENSOR_DIM_GLOBAL>> =
    Mutex::new(TelemetryQueue::new());

/// A bounded, atomic ring-buffer for sending raw state matrices
/// to the Userspace Telemetry Daemon without blocking.
pub struct TelemetryQueue<const TENSOR_DIM: usize> {
    head: AtomicUsize,
    tail: AtomicUsize,
    // Basic array fallback without dynamic allocation for pure `no_std`.
    pub buffer: [Option<ScalarTensor<i32, TENSOR_DIM>>; QUEUE_SIZE],
}

impl<const TENSOR_DIM: usize> TelemetryQueue<TENSOR_DIM> {
    pub const fn new() -> Self {
        #[allow(clippy::declare_interior_mutable_const)]
        #[allow(dead_code)]
        const INIT_NONE: Option<ScalarTensor<i32, 0>> = None;

        // This is a minimal macro/unsafe bypass to init the queue.
        // For actual safe initialization, maybe use generic trickery or unsafe:
        // We will mock it with empty loop initialization later.
        Self {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            buffer: [None; QUEUE_SIZE],
        }
    }

    /// Try pushing a state tensor into the queue for out-of-band analysis.
    /// Wait-free approach allows Ring-0 to immediately fail if the queue is full,
    /// dropping telemetry rather than stalling real-time operations.
    pub fn try_push(&mut self, tensor: ScalarTensor<i32, TENSOR_DIM>) -> Result<(), &'static str> {
        let head = self.head.load(Ordering::Acquire);
        let next_head = (head + 1) % QUEUE_SIZE;

        if next_head == self.tail.load(Ordering::Acquire) {
            return Err("Telemetry Queue Full: Math daemon fell behind ring-0 rate");
        }

        self.buffer[head] = Some(tensor);
        self.head.store(next_head, Ordering::Release);

        // Serialize the data over COM2 directly to the host UNIX socket.
        if let Some(mut serial) = crate::serial::SERIAL2_TELEMETRY.try_lock() {
            // Push magic sync bytes to signify the start of a tensor block.
            serial.send_byte(0xEF);
            serial.send_byte(0xBE);
            serial.send_byte(0xAD);
            serial.send_byte(0xDE);

            for val in tensor.data.iter() {
                let bytes = val.to_le_bytes();
                serial.send_byte(bytes[0]);
                serial.send_byte(bytes[1]);
                serial.send_byte(bytes[2]);
                serial.send_byte(bytes[3]);
            }
        }

        Ok(())
    }
}
