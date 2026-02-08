# Oreulia — Core Specification (MVP & Beyond)

**Status:** Delivered / Surpassed (Feb 8, 2026)

This document originally outlined the Minimum Viable Product (MVP) for Oreulia. The project has since met and significantly exceeded these initial goals.

**Current State:** A bootable `i686` kernel with advanced networking, a hierarchical filesystem, and a JIT-enabled implementation of WebAssembly.

---

## 0. Scope & Achievements

| Feature Area | Original MVP Goal (QEMU-only) | Current Implementation Status |
| :--- | :--- | :--- |
| **Boot** | Boot to serial console | **Done** (Multiboot compliant, GRUB2) |
| **Architecture** | Basic x86/Sched | **Done** (i686, Preemptive Priority Sched) |
| **Wasm** | Interpreter / Simple Loader | **Exceeded** (In-Kernel JIT Compiler) |
| **Networking** | **Out of Scope** | **Exceeded** (Full TCP/IP Stack, Drivers) |
| **Filesystem** | Minimal/Flat Store | **Exceeded** (Unix-like VFS, Mounts, Inodes) |
| **Security** | Capability Table | **Done** (Handle-based, ACLs) |

---

## 1. Platform Target

- **Architecture**: `i686` (32-bit x86 Protected Mode).
- **Environment**: QEMU (primary dev), Bochs, Real Hardware (via ISO).
- **Drivers**:
  - **Serial**: 16550 UART (Logging/Console).
  - **Timer**: 8253 PIT (Scheduling).
  - **Network**: E1000 (Intel), RTL8139 (Realtek), VirtIO-Net.
  - **Storage**: VirtIO-Blk, IDE/ATA (Basic).

---

## 2. Kernel Features

### 2.1 Networking Subsystem (New)
The MVP was originally offline-only. The kernel now includes a complete **Network Stack**:
- **Protocols**: Ethernet II, ARP, IPv4, ICMP, UDP, TCP.
- **Services**: DNS Resolver, DHCP Client, HTTP (Client & Server).
- **Abstractions**: Socket-like interface for kernel services, capability-gated for Wasm.

### 2.2 Virtual File System (New)
Moved beyond simple object storage to a full **VFS**:
- **Structure**: Hierarchical directory tree (`/`, `/dev`, `/mnt`).
- ** operations**: `open`, `read`, `write`, `close`, `mkdir`, `stat`.
- **Drivers**: RamFS (initial), FAT (partial), Ext2 (planned).

### 2.3 WebAssembly Runtime
- **Execution**: JIT (Just-In-Time) compilation of Wasm opcodes to x86 native code.
- **Performance**: Significant speedup over interpretation.
- **Integration**: Wasm modules can import kernel functions like properties.

### 2.4 Scheduler & Processes
- **Algorithm**: Quantum-based round-robin with priority levels.
- **Concurrency**: Kernel threads and user processes.
- **Synchronization**: Spinlocks, Atomics, and Wait Queues.

---

## 3. Deliverables

### 3.1 Bootable Artifacts
- **File**: `oreulia.iso` (Hybrid ISO9660).
- **Build System**: `build.sh` (Auto-compiles Rust, Assembles startup, Links, and Generates ISO).

### 3.2 Interaction
- **Shell**: A rich command-line interface (`>`) with 50+ commands.
    - `help`, `cpu-info`, `net-info`, `ls`, `wasm-run`, etc.
- **Demo Capability**:
    - **`wasm-demo`**: Runs a Wasm module to prove execution.
    - **`http-get`**: Demonstrates live networking.
    - **`vfs-ls`**: Demonstrates filesystem hierarchy.

---

## 4. Next Steps (Post-MVP)

With the core "OS" features (Net, FS, Sched, JIT) in place, the focus shifts to:
1. **User Mode Hardening**: Strictly enforcing Ring 3 isolation for Wasm payloads.
2. **SMP**: Multicore support.
3. **Advanced Persistence**: Completing the snapshot/restore logic.
4. **GUI**: Framebuffer-based windowing capability.


- Kernel provides:
  - per-task capability table
  - unforgeable handles (integers referencing kernel objects)
  - rights/permissions associated with handles
  - enforcement on any privileged operation

---

## 4. User-space MVP requirements (supervisor + services)

### 4.1 Supervisor responsibilities

- Create initial component graph.
- Create per-component capability sets (principle of least privilege).
- Provide a “time service” abstraction usable by determinism.
- Start Wasm loader service.

### 4.2 Services (MVP set)

**Console service**

- Provides `Console.Write` capability.
- Writes to serial.

**Clock service (virtual)**

- Provides `Clock.ReadMonotonic` capability.
- In record/replay, it reads from a log rather than the live timer.

**Persistence service (log + snapshot)**

- Provides `Store.AppendLog`, `Store.ReadLog`, `Store.WriteSnapshot`, `Store.ReadSnapshot`.
- Storage backend may start as RAM-backed (for quick bring-up) but must have a path to virtio block.

**Filesystem service**

- Provides `Filesystem.Read`, `Filesystem.Write`, `Filesystem.Delete`.
- Uses persistence service for durable file storage; no ambient paths.

**Wasm loader**

- Loads a prepackaged module.
- Instantiates with injected capabilities.

---

## 5. Determinism v0 (record/replay)

### 5.1 What counts as “external input” in MVP

- clock ticks (or clock reads)
- console input (optional)

### 5.2 Record mode

- Supervisor writes a log of external inputs to the persistence service.
- Module outputs are deterministic given the recorded inputs.

### 5.3 Replay mode

- Supervisor replays the same external inputs.
- The module output must match (byte-for-byte) for the same boot seed.

### 5.4 Seed and randomness

- Randomness is not required for MVP.
- If present, it must be capability-gated and recordable.

---

## 6. Acceptance tests (human-verifiable)

MVP is acceptable when:

- QEMU boots to a promptless demo where logs show:
  - supervisor start
  - loader start
  - module start
  - module printed output
- In record mode, a log is produced.
- In replay mode, the same output is produced.
- A module without `Console.Write` cannot print.

---

## 7. Repo structure recommendation

Suggested structure (non-binding):

- `kernel/` — kernel crate/project
- `services/` — supervisor + services
- `wasm/` — demo modules
- `docs/` — design docs

---

## 8. Next after MVP

- user mode isolation
- virtio block integration for durable logs
- richer IPC schemas
- capability revocation model
- additional Wasm host calls (net, storage, spawn)

---

## 9. Risks & mitigations

Oreulia’s v0 is ambitious. The MVP mitigates risk by keeping the initial surface area small (QEMU-first, small capability taxonomy, minimal nondeterminism sources).

### 9.1 Performance risks

- **Copy-based IPC overhead**: bounded messages (e.g., 4 KiB data, 16 caps/message) are correct and simple, but can increase latency/CPU for high-throughput pipelines.
- **Wasm call frequency**: if every interaction funnels through `channel_send`/`channel_recv`, “syscall-like” chatter can become the bottleneck under load.

Mitigations (MVP):

- Treat IPC limits as **prototype defaults**, not promises.
- Keep demo workloads small; optimize later with shared memory capabilities and/or scatter-gather.
- Prefer coarse-grained messages for MVP demo modules.

### 9.2 Implementation complexity

- **Capability correctness bugs (high impact)**: unforgeability/attenuation/transfer mistakes can leak authority.
- **Determinism correctness bugs (high impact)**: subtle nondeterminism leaks (clock use, device jitter, scheduler effects) can break byte-for-byte replay.
- **No revocation in MVP**: relies on restarts and careful grants; long-lived leaks remain until a revocation mechanism exists.

Mitigations (MVP):

- Keep a **small capability taxonomy** and enforce checks centrally.
- Add tests for:
  - cap table invariants (no raw object IDs)
  - attenuation (`derived ⊆ original`)
  - transfer semantics (sender/receiver rights)
- Make determinism scope explicit: record/replay only **clock** and optional **console input**.

### 9.3 Scope and portability limits

- **No POSIX / Wasm-only apps**: limits early adoption and “real” app testing.
- **QEMU/virtio only**: limits device coverage.
- **At-least-once replay**: component idempotency bugs can appear until stronger semantics are added.

Mitigations (MVP):

- Treat MVP as a concept-proving prototype; add a WASI layer later if desired.
- Keep components small and replay-safe; store a replay cursor/sequence in durable state.

### 9.4 Summary table

| Risk category | Impact on MVP | Mitigation |
|---|---:|---|
| IPC performance | Medium | Keep demo-scale; defer zero-copy/shared memory |
| Capability bugs | High | Small taxonomy; central enforcement; invariant tests |
| Determinism correctness | High | Limit nondeterminism sources; log clock (+ console) only |
| No POSIX / Wasm-only | Low | Prototype goal; consider layering WASI later |
