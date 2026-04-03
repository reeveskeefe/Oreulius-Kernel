//! Oreulius Userspace Telemetry Daemon
//!
//! Consumes `TelemetryEvent` frames from the kernel's wait-free `TELEMETRY_RING`
//! (forwarded over QEMU COM2 → UNIX socket) and performs out-of-band CTMC
//! mathematics as specified in PMA §3 and §6:
//!
//!   * Builds the empirical infinitesimal generator matrix Q (9×9, one per PID).
//!   * Computes P(t) = P(0)·e^(Qt) via a [3/3] Padé approximant (§3.1).
//!   * Estimates the stationary distribution via warm-started power iteration (§11.2).
//!   * On anomaly detection issues a `CapabilityRevokeForPid` syscall (43) back to
//!     the kernel to revoke capabilities from the offending process (§6.2).
use nalgebra::{DMatrix, DVector};
use std::collections::HashMap;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

mod uds_queue;
use uds_queue::{TelemetryEvent, UdsTelemetryQueue};

// ---------------------------------------------------------------------------
// Constants — must stay in sync with kernel/src/intent_graph.rs
// ---------------------------------------------------------------------------

/// Number of CTMC states — mirrors `INTENT_NODE_COUNT = 9` in the kernel.
const STATE_DIM: usize = 9;

/// PID assigned to the Math Daemon at boot — kernel enforces this in the
/// privileged `CapabilityRevokeForPid` syscall gate.
const MATH_DAEMON_PID: u32 = 2;

/// Minimum number of observations before anomaly detection fires for a PID.
const WARMUP_THRESHOLD: usize = 200;

/// Probability threshold above which a PID is considered anomalous.
const ANOMALY_PROB_THRESHOLD: f64 = 0.60;

/// Stationary-distribution threshold (eigenvector concentration on state 0).
const STATIONARY_THRESHOLD: f64 = 0.50;

/// Minimum acceptable spectral gap — mirrors `EPSILON_SAFE` in `build.rs`.
const EPSILON_SAFE: f64 = 0.05;

/// Reserved `cap_type` tag used by the kernel for compact VFS watch summaries.
const TELEMETRY_CAP_TYPE_VFS_WATCH: u8 = 0xFE;

/// Compute the daemon's polling interval from the spectral gap γ (PMA §11.2).
///
/// Mixing time ∝ 1/γ — the smaller γ is, the longer the CTMC takes to mix
/// and the more frequently we must sample to catch transient anomalies.
///
/// interval_ms = clamp(1000 / γ, 10, 500)
///
/// The init process sets `OREULIA_SPECTRAL_GAP` from the boot log; we fall
/// back to `EPSILON_SAFE` if the variable is absent.
fn polling_interval_ms() -> u64 {
    let gamma = std::env::var("OREULIA_SPECTRAL_GAP")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(EPSILON_SAFE);
    let raw_ms = if gamma > 1e-9 { 1000.0 / gamma } else { 500.0 };
    (raw_ms as u64).clamp(10, 500)
}

fn vfs_watch_kind_name(code: u8) -> &'static str {
    match code {
        0 => "read",
        1 => "write",
        2 => "list",
        3 => "create",
        4 => "delete",
        5 => "rename",
        6 => "link",
        7 => "symlink",
        8 => "readlink",
        9 => "mkdir",
        10 => "rmdir",
        11 => "mount",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Revocation request packet — kernel serial IRQ handler parses this.
//
// Layout (10 bytes, little-endian):
//   [0..2]  magic     : [0xCA, 0xFE]
//   [2..6]  target_pid: u32
//   [6..10] cap_id    : u32  (0 = revoke all capabilities for this PID)
// ---------------------------------------------------------------------------
const REVOKE_MAGIC: [u8; 2] = [0xCA, 0xFE];

fn send_revocation_request(stream: &mut UnixStream, target_pid: u32, cap_id: u32) {
    let mut pkt = [0u8; 10];
    pkt[0] = REVOKE_MAGIC[0];
    pkt[1] = REVOKE_MAGIC[1];
    pkt[2..6].copy_from_slice(&target_pid.to_le_bytes());
    pkt[6..10].copy_from_slice(&cap_id.to_le_bytes());
    let _ = stream.write_all(&pkt);
}

// ---------------------------------------------------------------------------
// Per-PID CTMC state
// ---------------------------------------------------------------------------

struct ProcessCtmcState {
    /// Empirical Q matrix (STATE_DIM × STATE_DIM), updated incrementally.
    q: DMatrix<f64>,
    /// Last observed IntentNode index (0-8).
    prev_node: usize,
    /// Total observations accumulated for this PID.
    observations: usize,
    /// Warm-started dominant left eigenvector of P(t)^T (stationary estimate).
    dominant_eigenvector: DVector<f64>,
}

impl ProcessCtmcState {
    fn new(initial_node: usize) -> Self {
        Self {
            q: DMatrix::zeros(STATE_DIM, STATE_DIM),
            prev_node: initial_node,
            observations: 0,
            dominant_eigenvector: DVector::from_element(STATE_DIM, 1.0 / (STATE_DIM as f64).sqrt()),
        }
    }

    /// Ingest a new event for this PID: update Q using the `node` field as the
    /// current CTMC state (0-8), then step `prev_node` forward.
    fn update(&mut self, event: &TelemetryEvent) {
        let cur = (event.node as usize).min(STATE_DIM - 1);
        let prev = self.prev_node;

        if prev != cur {
            // Stochastic increment on the off-diagonal transition rate.
            self.q[(prev, cur)] += 0.05;

            // Enforce CTMC row-sum constraint: q_ii = -Σ_{j≠i} q_ij
            let mut row_sum = 0.0f64;
            for j in 0..STATE_DIM {
                if j != prev {
                    row_sum += self.q[(prev, j)];
                }
            }
            self.q[(prev, prev)] = -row_sum;
        }

        self.prev_node = cur;
        self.observations += 1;
    }

    /// Compute P(t) = e^(Q·t) via a [3/3] Padé approximant with
    /// scaling-and-squaring.  Returns the identity matrix as a safe fallback
    /// if the LU solve is singular.
    fn compute_matrix_exponential(&self, t: f64) -> DMatrix<f64> {
        let id = DMatrix::identity(STATE_DIM, STATE_DIM);
        let mut q_scaled = &self.q * t;

        // Scaling: divide by 2^s so ||q_scaled|| ≤ 1.
        let norm = q_scaled.amax();
        let scale_power = if norm > 1.0 {
            norm.log2().ceil() as i32
        } else {
            0
        };
        if scale_power > 0 {
            q_scaled *= 1.0 / (2.0f64.powi(scale_power));
        }

        let a2 = &q_scaled * &q_scaled;
        let a3 = &a2 * &q_scaled;

        // [3/3] Padé numerator N and denominator D
        let n33 = &id + &q_scaled * 0.5 + &a2 * 0.1 + &a3 * (1.0 / 120.0);
        let d33 = &id - &q_scaled * 0.5 + &a2 * 0.1 - &a3 * (1.0 / 120.0);

        let mut p_t = d33.lu().solve(&n33).unwrap_or_else(|| id.clone());

        // Squaring phase: undo the scaling.
        for _ in 0..scale_power {
            let tmp = p_t.clone();
            p_t = &tmp * &tmp;
        }

        // Clamp to [0, 1] — probabilities cannot leave this range.
        for v in p_t.iter_mut() {
            *v = v.clamp(0.0, 1.0);
        }

        p_t
    }

    /// Three steps of warm-started power iteration on P(t)^T to track the
    /// stationary distribution (PMA §11.2 "1-3 steps of warm-started power
    /// iteration").
    fn update_dominant_eigenvector(&mut self, p_t: &DMatrix<f64>) {
        let p_t_t = p_t.transpose();
        for _ in 0..3 {
            let next = &p_t_t * &self.dominant_eigenvector;
            let norm = next.norm();
            if norm > 1e-12 {
                self.dominant_eigenvector = next / norm;
            }
        }
    }

    /// Returns `true` if this PID's CTMC state suggests anomalous behaviour
    /// after the warmup period.
    fn is_anomalous(&self, p_t: &DMatrix<f64>) -> bool {
        if self.observations < WARMUP_THRESHOLD {
            return false;
        }
        // P(current_state → state 0 "CPU hogging / no-yields") > threshold
        let prob_worst = p_t[(self.prev_node, 0)];
        // Stationary eigenvector concentration on state 0
        let stationary_mass = self.dominant_eigenvector[0].abs();

        prob_worst > ANOMALY_PROB_THRESHOLD || stationary_mass > STATIONARY_THRESHOLD
    }
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

fn main() {
    println!(
        "Oreulius Telemetry Daemon booting (PID={})...",
        MATH_DAEMON_PID
    );
    println!(
        "CTMC state dimension: {} (matches kernel INTENT_NODE_COUNT)",
        STATE_DIM
    );
    println!("Connecting to kernel telemetry stream...");

    let sleep_ms = polling_interval_ms();
    println!(
        "Polling interval: {}ms  (spectral gap γ={:.4}, mixing bound 1/γ)",
        sleep_ms,
        std::env::var("OREULIA_SPECTRAL_GAP")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(EPSILON_SAFE)
    );

    let mut queue = UdsTelemetryQueue::new();
    let mut states: HashMap<u32, ProcessCtmcState> = HashMap::new();

    // Open a second connection to the kernel's serial socket for writing
    // revocation packets back.  We use the same UNIX socket path — the kernel's
    // serial IRQ handler demultiplexes incoming bytes by magic header.
    let mut revoke_stream: Option<UnixStream> = None;

    loop {
        // ---- 1. Drain all available TelemetryEvents from the ring ----------------
        while let Some(event) = queue.poll_event() {
            if event.cap_type == TELEMETRY_CAP_TYPE_VFS_WATCH {
                println!(
                    "VFS-WATCH pid={} kind={} score={} tick={}",
                    event.pid,
                    vfs_watch_kind_name(event.node),
                    event.score,
                    event.tick
                );
                continue;
            }
            let state = states
                .entry(event.pid)
                .or_insert_with(|| ProcessCtmcState::new(event.node as usize));
            state.update(&event);
        }

        // ---- 2. For each PID: compute P(t), update eigenvector, check anomaly ----
        let dt = 0.1_f64; // forward projection time step (seconds)
        let mut anomalous_pids: Vec<u32> = Vec::new();

        for (&pid, state) in states.iter_mut() {
            let p_t = state.compute_matrix_exponential(dt);
            state.update_dominant_eigenvector(&p_t);

            if state.is_anomalous(&p_t) {
                anomalous_pids.push(pid);
            }
        }

        // ---- 3. Async revocation callback (PMA §6.2) -----------------------------
        if !anomalous_pids.is_empty() {
            // Lazily open / reconnect the revocation back-channel.
            if revoke_stream.is_none() {
                revoke_stream = UnixStream::connect("/tmp/oreulius_ebpf_telemetry").ok();
            }

            if let Some(ref mut sock) = revoke_stream {
                for pid in &anomalous_pids {
                    println!(
                        "CRITICAL [Daemon]: Anomaly confirmed for PID {}. \
                         Issuing CapabilityRevokeForPid (syscall 43) via kernel back-channel.",
                        pid
                    );
                    // cap_id = 0 ⇒ revoke all capabilities for this PID.
                    send_revocation_request(sock, *pid, 0);
                }
            } else {
                // Back-channel not yet available — log only, will retry next cycle.
                eprintln!(
                    "WARNING [Daemon]: Anomaly detected for PIDs {:?} but \
                     revocation back-channel not connected yet.",
                    anomalous_pids
                );
            }
        }

        thread::sleep(Duration::from_millis(sleep_ms));
    }
}
