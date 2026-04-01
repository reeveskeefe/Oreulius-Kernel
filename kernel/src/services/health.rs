/*!
 * Oreulia Kernel — System Health Telemetry
 *
 * Aggregates health data from the scheduler, filesystem, IPC, network, and
 * persistence subsystems into a single `HealthSnapshot` struct.
 *
 * Commands exposed:
 *   `health`           — print a live health snapshot to VGA/serial
 *   `health-history`   — list HealthSnapshot records from persistence log
 */

extern crate alloc;

use crate::persistence;
// Cross-arch console output: VGA on x86/x86_64, PL011 on AArch64.
mod vga {
    pub fn print_str(s: &str) { crate::serial::kprint_str(s); }
    pub fn print_char(c: char) { crate::serial::kprint_char(c); }
}

// ============================================================================
// HealthSnapshot
// ============================================================================

/// A point-in-time snapshot of kernel subsystem health.
#[derive(Debug, Clone, Copy)]
pub struct HealthSnapshot {
    /// Monotonic tick when this snapshot was taken.
    pub tick: u64,
    /// Current boot session number.
    pub boot_session: u32,

    // --- Scheduler ---
    pub total_processes: u32,
    pub running_processes: u32,
    pub ready_processes: u32,
    pub sleeping_processes: u32,
    pub total_context_switches: u64,
    pub preemptions: u64,
    pub voluntary_yields: u64,

    // --- Crash log ---
    pub crash_count: u32,

    // --- Filesystem (flat FS) ---
    pub fs_file_count: u32,
    pub fs_total_bytes: u64,
    pub fs_total_ops: u64,
    pub fs_perm_denials: u64,

    // --- IPC ---
    pub ipc_channel_count: u32,
    pub ipc_channel_max: u32,

    // --- Network ---
    pub net_tcp_connections: u32,
    pub net_dns_cache: u32,

    // --- Persistence log ---
    pub persist_record_count: u32,
    pub persist_capacity: u32,
}

impl HealthSnapshot {
    pub fn take() -> Self {
        // Scheduler
        let sched = crate::quantum_scheduler::scheduler()
            .lock()
            .snapshot_overview();

        // Crash log
        #[cfg(not(target_arch = "aarch64"))]
        let crash_count = crate::crash_log::crash_count();
        #[cfg(target_arch = "aarch64")]
        let crash_count = 0u32;
        #[cfg(not(target_arch = "aarch64"))]
        let boot_session = crate::crash_log::boot_session();
        #[cfg(target_arch = "aarch64")]
        let boot_session = 0u32;

        // Flat FS
        let fs = crate::fs::filesystem().health();

        // IPC
        let (ipc_chan, ipc_max) = crate::ipc::ipc().stats();

        // Network (best-effort; skip if lock contended)
        let (tcp_conns, dns_cache) = {
            let net = crate::net::network().lock();
            let s = net.stats();
            (s.tcp_connections as u32, s.dns_cache_entries as u32)
        };

        // Persistence log stats
        let (persist_count, persist_cap) = {
            let svc = persistence::persistence().lock();
            let (c, cap) = svc.log_stats();
            (c as u32, cap as u32)
        };

        // Tick
        #[cfg(not(target_arch = "aarch64"))]
        let tick = crate::asm_bindings::rdtsc_begin();
        #[cfg(target_arch = "aarch64")]
        let tick = 0u64;

        HealthSnapshot {
            tick,
            boot_session,
            total_processes: sched.total_processes as u32,
            running_processes: sched.running_processes as u32,
            ready_processes: sched.ready_processes as u32,
            sleeping_processes: sched.sleeping_processes as u32,
            total_context_switches: sched.total_switches,
            preemptions: sched.preemptions,
            voluntary_yields: sched.voluntary_yields,
            crash_count,
            fs_file_count: fs.file_count as u32,
            fs_total_bytes: fs.total_bytes as u64,
            fs_total_ops: fs.total_operations,
            fs_perm_denials: fs.permission_denials,
            ipc_channel_count: ipc_chan as u32,
            ipc_channel_max: ipc_max as u32,
            net_tcp_connections: tcp_conns,
            net_dns_cache: dns_cache,
            persist_record_count: persist_count,
            persist_capacity: persist_cap,
        }
    }

    /// Serialise to a fixed 80-byte little-endian payload.
    /// Layout (all little-endian):
    ///   [0..8]   tick
    ///   [8..12]  boot_session
    ///   [12..16] total_processes
    ///   [16..20] running_processes
    ///   [20..24] ready_processes
    ///   [24..28] sleeping_processes
    ///   [28..36] total_context_switches
    ///   [36..44] preemptions
    ///   [44..52] voluntary_yields
    ///   [52..56] crash_count
    ///   [56..60] fs_file_count
    ///   [60..68] fs_total_bytes
    ///   [68..76] fs_total_ops
    ///   [76..84] fs_perm_denials
    ///   [84..88] ipc_channel_count
    ///   [88..92] ipc_channel_max
    ///   [92..96] net_tcp_connections
    ///   [96..100] net_dns_cache
    ///   [100..104] persist_record_count
    ///   [104..108] persist_capacity
    pub fn to_bytes(&self) -> [u8; 108] {
        let mut b = [0u8; 108];
        b[0..8].copy_from_slice(&self.tick.to_le_bytes());
        b[8..12].copy_from_slice(&self.boot_session.to_le_bytes());
        b[12..16].copy_from_slice(&self.total_processes.to_le_bytes());
        b[16..20].copy_from_slice(&self.running_processes.to_le_bytes());
        b[20..24].copy_from_slice(&self.ready_processes.to_le_bytes());
        b[24..28].copy_from_slice(&self.sleeping_processes.to_le_bytes());
        b[28..36].copy_from_slice(&self.total_context_switches.to_le_bytes());
        b[36..44].copy_from_slice(&self.preemptions.to_le_bytes());
        b[44..52].copy_from_slice(&self.voluntary_yields.to_le_bytes());
        b[52..56].copy_from_slice(&self.crash_count.to_le_bytes());
        b[56..60].copy_from_slice(&self.fs_file_count.to_le_bytes());
        b[60..68].copy_from_slice(&self.fs_total_bytes.to_le_bytes());
        b[68..76].copy_from_slice(&self.fs_total_ops.to_le_bytes());
        b[76..84].copy_from_slice(&self.fs_perm_denials.to_le_bytes());
        b[84..88].copy_from_slice(&self.ipc_channel_count.to_le_bytes());
        b[88..92].copy_from_slice(&self.ipc_channel_max.to_le_bytes());
        b[92..96].copy_from_slice(&self.net_tcp_connections.to_le_bytes());
        b[96..100].copy_from_slice(&self.net_dns_cache.to_le_bytes());
        b[100..104].copy_from_slice(&self.persist_record_count.to_le_bytes());
        b[104..108].copy_from_slice(&self.persist_capacity.to_le_bytes());
        b
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Take a health snapshot and emit it as a `HealthSnapshot` persistence record.
pub fn emit_snapshot() {
    let snap = HealthSnapshot::take();
    let payload = snap.to_bytes();
    let cap = persistence::StoreCapability::new(0xAAAA, persistence::StoreRights::all());
    if let Ok(record) =
        persistence::LogRecord::new(persistence::RecordType::HealthSnapshot, &payload)
    {
        let mut svc = persistence::persistence().lock();
        let _ = svc.append_log(&cap, record);
    }
}

// ============================================================================
// Shell commands
// ============================================================================

fn print_u64(n: u64) {
    if n == 0 {
        vga::print_char('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    let mut v = n;
    while v > 0 {
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        vga::print_char(buf[i] as char);
    }
}

fn print_u32(n: u32) {
    print_u64(n as u64);
}

pub fn cmd_health() {
    let s = HealthSnapshot::take();

    vga::print_str("\n=== System Health Snapshot ===\n");
    vga::print_str("Tick              : ");
    print_u64(s.tick);
    vga::print_str("\nBoot session      : ");
    print_u32(s.boot_session);
    vga::print_str("\nCrash count       : ");
    print_u32(s.crash_count);

    vga::print_str("\n\n-- Scheduler --\n");
    vga::print_str("  Processes       : total=");
    print_u32(s.total_processes);
    vga::print_str(" running=");
    print_u32(s.running_processes);
    vga::print_str(" ready=");
    print_u32(s.ready_processes);
    vga::print_str(" sleeping=");
    print_u32(s.sleeping_processes);
    vga::print_str("\n  Context switches: ");
    print_u64(s.total_context_switches);
    vga::print_str("\n  Preemptions     : ");
    print_u64(s.preemptions);
    vga::print_str("\n  Voluntary yields: ");
    print_u64(s.voluntary_yields);

    vga::print_str("\n\n-- Filesystem --\n");
    vga::print_str("  Files           : ");
    print_u32(s.fs_file_count);
    vga::print_str("\n  Total bytes     : ");
    print_u64(s.fs_total_bytes);
    vga::print_str("\n  Total ops       : ");
    print_u64(s.fs_total_ops);
    vga::print_str("\n  Perm denials    : ");
    print_u64(s.fs_perm_denials);

    vga::print_str("\n\n-- IPC --\n");
    vga::print_str("  Channels        : ");
    print_u32(s.ipc_channel_count);
    vga::print_str(" / ");
    print_u32(s.ipc_channel_max);

    vga::print_str("\n\n-- Network --\n");
    vga::print_str("  TCP connections : ");
    print_u32(s.net_tcp_connections);
    vga::print_str("\n  DNS cache       : ");
    print_u32(s.net_dns_cache);

    vga::print_str("\n\n-- Persistence log --\n");
    vga::print_str("  Records         : ");
    print_u32(s.persist_record_count);
    vga::print_str(" / ");
    print_u32(s.persist_capacity);
    vga::print_str("\n\n");

    // Persist this snapshot.
    emit_snapshot();
    vga::print_str("[health] snapshot written to persistence log\n");

    // Emit a TelemetryEvent so the userspace CTMC daemon sees the health probe.
    let tick = crate::vfs_platform::ticks_now();
    let ev = crate::wait_free_ring::TelemetryEvent::new(
        0,    // kernel pid
        8,    // node 8 = Observe (highest-index IntentNode)
        0xFD, // cap_type 0xFD = reserved for health-probe events
        0,    // score = 0 (informational, not an anomaly signal)
        tick,
    );
    let _ = crate::wait_free_ring::TELEMETRY_RING.push(ev);
}

pub fn cmd_crash_log_show() {
    vga::print_str("\n=== Crash Log ===\n");
    #[cfg(not(target_arch = "aarch64"))]
    {
        vga::print_str("Total panics this session: ");
        print_u32(crate::crash_log::crash_count());
        vga::print_str("\n\n");
        let mut found = 0usize;
        crate::crash_log::for_each_crash(|seq, tick, session, loc, msg| {
            found += 1;
            vga::print_str("--- Crash #");
            print_u64(seq as u64);
            vga::print_str(" (session ");
            print_u32(session);
            vga::print_str(", tick ");
            print_u64(tick);
            vga::print_str(") ---\n");
            vga::print_str("  Location: ");
            for &b in &loc {
                if b == 0 { break; }
                vga::print_char(b as char);
            }
            vga::print_str("\n  Message : ");
            for &b in &msg {
                if b == 0 { break; }
                vga::print_char(b as char);
            }
            vga::print_str("\n");
        });
        if found == 0 {
            vga::print_str("(no crash records in ring buffer)\n");
        }
    }
    #[cfg(target_arch = "aarch64")]
    vga::print_str("(crash log not available on this architecture)\n");
    vga::print_str("\n");
}

pub fn cmd_crash_log_clear() {
    vga::print_str("crash-clear: the ring buffer is written by atomic index.\n");
    vga::print_str("  Slots will be overwritten as new panics occur.\n");
    vga::print_str("  Crash count: ");
    #[cfg(not(target_arch = "aarch64"))]
    print_u32(crate::crash_log::crash_count());
    #[cfg(target_arch = "aarch64")]
    vga::print_str("(n/a on AArch64)");
    vga::print_str("\n");
}

/// `health-history` — replay HealthSnapshot records from the persistence log.
pub fn cmd_health_history() {
    vga::print_str("\n=== Health Snapshot History ===\n");

    let cap = persistence::StoreCapability::new(0xF2F2, persistence::StoreRights::all());
    let svc = persistence::persistence().lock();
    let total = svc.log_stats().0;
    if total == 0 {
        vga::print_str("(persistence log is empty)\n\n");
        return;
    }

    let iter = match svc.read_log(&cap, 0, total) {
        Ok(it) => it,
        Err(_) => {
            vga::print_str("(permission denied reading log)\n\n");
            return;
        }
    };

    let mut count = 0u32;
    for record in iter {
        if record.header.record_type != persistence::RecordType::HealthSnapshot as u16 {
            continue;
        }
        count += 1;
        let p = record.payload();
        // Layout: tick(8) + boot_session(4) + crash_count(4) + ...
        if p.len() < 16 {
            continue;
        }
        let tick = u64::from_le_bytes(p[0..8].try_into().unwrap_or([0u8; 8]));
        let session = u32::from_le_bytes(p[8..12].try_into().unwrap_or([0u8; 4]));
        let crashes = u32::from_le_bytes(p[12..16].try_into().unwrap_or([0u8; 4]));
        vga::print_str("  #");
        print_u32(count);
        vga::print_str(" tick=");
        print_u64(tick);
        vga::print_str(" session=");
        print_u32(session);
        vga::print_str(" crashes=");
        print_u32(crashes);
        vga::print_str("\n");
    }

    if count == 0 {
        vga::print_str("(no HealthSnapshot records yet — run 'health' first)\n");
    }
    vga::print_str("\n");
}
