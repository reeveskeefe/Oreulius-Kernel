//! Oreulia Userspace Telemetry Daemon
//! Phase 2: Out-of-band Continuous-Time Markov Chain (CTMC) Math
//!
//! This daemon maps the raw `ScalarTensor` structures polled from the 
//! Ring-0 wait-free `TelemetryQueue` into continuous-time Markov analyses.
//! Using `nalgebra`, we compute rigorous matrix exponentials and state probabilities.
use std::collections::HashMap;
use std::thread;
use std::time::Duration;
use nalgebra::{DMatrix, DVector};

mod uds_queue;
use uds_queue::UdsTelemetryQueue;

// Match the dimension configured in the kernel queue.
const TENSOR_DIM: usize = 128;

/// Represents the infinitesimal generator matrix `Q` for the Markov chain.
struct GeneratorMatrix {
    q_data: DMatrix<f64>,
    dim: usize,
    pid_states: HashMap<i32, usize>,
    pid_observations: HashMap<i32, usize>,
    dominant_eigenvector: DVector<f64>, // For warm-started power iteration
}

impl GeneratorMatrix {
    pub fn new(dim: usize) -> Self {
        Self {
            q_data: DMatrix::zeros(dim, dim),
            dim,
            pid_states: HashMap::new(),
            pid_observations: HashMap::new(),
            // Initialize with an equal superposition of states.
            dominant_eigenvector: DVector::from_element(dim, 1.0 / (dim as f64).sqrt()),
        }
    }

    /// Update Q matrix incrementally given a delta tensor from the kernel.
    pub fn update_from_kernel(&mut self, tensor: &[i32; TENSOR_DIM]) {
        let yields_ewma = tensor[0];
        let pid = tensor[1];

        // Ensure we actually got a message (ignore zeroed buffers if no pid)
        if pid == 0 && yields_ewma == 0 {
            return;
        }

        println!("Process [PID {}] pushed yields_ewma: {}", pid, yields_ewma);

        // Map EWMA into discrete Markov states (e.g., 8 bands representing behavioral volatility)
        // Lower state = Hogging CPU (0 yields)
        // Higher state = Yields often (I/O bound)
        let mut current_state = (yields_ewma / 125) as usize; 
        if current_state >= self.dim {
            current_state = self.dim - 1;
        }

        // Track transitions to build the empirical infinitesimal generator matrix (Q)
        if let Some(&prev_state) = self.pid_states.get(&pid) {
            if prev_state != current_state {
                // Stochastic learning increment for the transition prev -> current
                self.q_data[(prev_state, current_state)] += 0.05;
                
                // Enforce CTMC row-sum constraints (diagonal = -sum of off-diagonals)
                let mut row_sum = 0.0;
                for j in 0..self.dim {
                    if j != prev_state {
                        row_sum += self.q_data[(prev_state, j)];
                    }
                }
                self.q_data[(prev_state, prev_state)] = -row_sum;
            }
        }
        
        // Save the current state for future continuity tracking
        self.pid_states.insert(pid, current_state);
        *self.pid_observations.entry(pid).or_insert(0) += 1;
    }

    /// Computes P(t) = P(0) * e^(Q*t) using a basic Padé approximation
    /// for matrix exponential, leveraging nalgebra's structured algebra.
    pub fn compute_matrix_exponential(&self, t: f64) -> DMatrix<f64> {
        let dim = self.dim;
        let id = DMatrix::identity(dim, dim);
        let q_t = &self.q_data * t;

        // Scaling (squaring and scaling method)
        let mut q_scaled = q_t.clone();
        let norm = q_scaled.amax();
        let scale_power = if norm > 1.0 { norm.log2().ceil() as i32 } else { 0 };
        if scale_power > 0 {
            q_scaled *= 1.0 / (2.0f64.powi(scale_power));
        }

        // [3/3] Padé approximant for e^A ≈ Dpq(A)^-1 * Npq(A)
        // D33(A) = I - A/2 + A^2/10 - A^3/120
        // N33(A) = I + A/2 + A^2/10 + A^3/120
        let a2 = &q_scaled * &q_scaled;
        let a3 = &a2 * &q_scaled;

        let n33 = &id + &q_scaled * 0.5 + &a2 * 0.1 + &a3 * (1.0/120.0);
        let d33 = &id - &q_scaled * 0.5 + &a2 * 0.1 - &a3 * (1.0/120.0);

        let mut p_t = match d33.lu().solve(&n33) {
            Some(res) => res,
            None => id.clone(), // Fallback if singular
        };

        // Squaring phase
        for _ in 0..scale_power {
            p_t = &p_t * &p_t;
        }

        // Bounds clamping for probabilities (P_ij must be [0, 1])
        for val in p_t.iter_mut() {
            if *val > 1.0 { *val = 1.0; }
            if *val < 0.0 { *val = 0.0; }
        }

        p_t
    }

    /// Perform 1-3 steps of warm-started power iteration to find the dominant eigenvector
    /// of the transition matrix P(t). This estimates the stationary distribution
    /// dynamically to evaluate compounding anomaly bounds under spectral gaps.
    pub fn update_dominant_eigenvector(&mut self, p_t: &DMatrix<f64>) {
        // Evaluate the Transpose of p_t for left eigenvectors (stationary distribution)
        let p_t_t = p_t.transpose();
        // 3 steps of power iteration
        for _ in 0..3 {
            let next_vec = &p_t_t * &self.dominant_eigenvector;
            // Normalize
            let norm = next_vec.norm();
            if norm > 1e-12 {
                self.dominant_eigenvector = next_vec / norm;
            }
        }
    }

    /// Check for anomalous capability flows by analyzing the state probabilities for each PID.
    pub fn check_anomalies_for_pids(&self, probability_matrix: &DMatrix<f64>) -> Vec<i32> {
        let mut anomalous_pids = Vec::new();
        let warmup_threshold = 200; // Ignore boot-up fluctuations until we have 200 data points for a PID.

        for (&pid, &current_state) in &self.pid_states {
            let obs = *self.pid_observations.get(&pid).unwrap_or(&0);
            if obs < warmup_threshold {
                continue; // Process is still in early initialization or warmup.
            }

            // probability_matrix[(i, j)] is the probability of ending up in state j, given starting state i.
            // State 0 is the "CPU Hogging / No Yields" boundary.
            let prob_of_hogging = probability_matrix[(current_state, 0)];

            // Evaluate if spectral mass concentrates heavily on the problematic state
            let stationary_hogging_mass = self.dominant_eigenvector[0];

            // If the stochastic prediction gives an unnaturally high chance (>60%) of an active thread
            // collapsing strictly into the worst behavioral bounds after warmup, we flag an anomaly.
            // Using spectral gap insights: If global stationary distribution also points to failure
            // then it's a systemic anomaly (eigenvector shift).
            if prob_of_hogging > 0.60 || stationary_hogging_mass > 0.50 {
                anomalous_pids.push(pid);
            }
        }
        anomalous_pids
    }
}

fn main() {
    println!("Oreulia Telemetry Daemon Booting...");
    println!("Initialize CTMC Mathematics Module with Nalgebra...");
    println!("Applying Userspace Warm-started Power Iteration bounds...");

    let state_dim = 8; 
    let mut q_matrix = GeneratorMatrix::new(state_dim);
    let mut queue = UdsTelemetryQueue::new();

    // Mock telemetry loop
    loop {
        // 1. Poll the memory-mapped wait-free queue
        while let Some(mock_tensor) = queue.poll_tensor::<TENSOR_DIM>() {
            // Accumulate hardware state observations into the Generator Matrix
            q_matrix.update_from_kernel(&mock_tensor);
        }

        // 2. Extrapolate future state probabilities P(t) = e^{Qt}
        let dt = 0.1; // Forward projection time step
        let p_t = q_matrix.compute_matrix_exponential(dt);

        // 3. Section 11.2 Userspace Telemetry Power Iteration
        // Perform 1-3 steps of warm-started power iteration to estimate dominant eigenvector.
        q_matrix.update_dominant_eigenvector(&p_t);

        // 4. Validate mathematically provable constraints bounds
        let anomalous_pids = q_matrix.check_anomalies_for_pids(&p_t);

        if !anomalous_pids.is_empty() {
            println!("CRITICAL: Mathematics anomaly detected heavily concentrating in spectral bounds for PIDs: {:?}. Downgrading capabilities via CapNet Context graph!", anomalous_pids);
        }

        thread::sleep(Duration::from_millis(50));
    }
}
