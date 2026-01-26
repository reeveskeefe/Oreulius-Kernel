# Oreulia — MVP Spec (QEMU-first)

**Status:** Draft (Jan 24, 2026)

This document turns `docs/oreulia-vision.md` into a concrete, implementable “first bootable” scope.

**MVP definition:** A QEMU-bootable Oreulia image that can start a supervisor, run a Wasm module, and demonstrate capability-gated I/O plus record/replay of external inputs.

---

## 0. Scope boundaries

**In-scope (MVP):**

- QEMU-first (virt machine, virtio devices), serial console output
- Kernel: scheduling, basic memory management, IPC channels, capability table/enforcement
- Supervisor/init: creates system graph and spawns at least one Wasm module
- Wasm loader: validates and instantiates a module with injected capabilities
- Persistence v0: append-only log + snapshot v0 (minimum workable)
- Determinism v0: “record mode” and “replay mode” for external inputs

**Out-of-scope (MVP):**

- Real hardware (UEFI laptops, Wi‑Fi, GPUs)
- POSIX compatibility, ELF processes, fork/exec
- Full networking
- Graphical UI
- Complex filesystems

---

## 1. Deliverables

### 1.1 Bootable artifacts

- A bootable disk image or ISO that runs in QEMU.
- A default build/run command documented in `README.md`.

### 1.2 Visible demo behavior

On boot, the system must:

1. Print a deterministic boot banner to serial.
2. Start the supervisor.
3. Start a Wasm module named `hello_flow.wasm`.
4. The Wasm module prints to console *only* via an injected `Console.Write` capability.
5. The supervisor runs in one of two modes:
   - **Record mode:** logs external inputs (time ticks, console input if present)
   - **Replay mode:** replays those inputs to reproduce the same outputs

---

## 2. Platform target (QEMU)

### 2.1 Architecture

- Target: `x86_64` or `aarch64`.
- Recommendation: start `x86_64` because tooling/debugging is widely documented.

### 2.2 Devices

- Required: serial console
- Later in MVP (optional but recommended): virtio block for persistence

---

## 3. Kernel MVP requirements

### 3.1 Boot + early logging

- Kernel boots and initializes a serial logger.
- Kernel has a panic path that prints error + halts.

### 3.2 Interrupts + time

- Timer interrupt provides a monotonic tick source.
- Kernel supports `yield` and `sleep_until` primitives (sleep uses a virtual clock capability exposed via supervisor service, or a kernel tick v0).

### 3.3 Tasks and scheduling

- Kernel supports at least:
  - multiple kernel tasks (threads)
  - run queue
  - cooperative `yield` at minimum; preemption optional in v0

### 3.4 Memory

- Kernel can allocate memory dynamically (heap allocator v0).
- Virtual memory: minimum needed to run kernel safely.
- User mode isolation is allowed to be deferred, but the design should not block adding it.

### 3.5 IPC channels

- Kernel provides `Channel` object(s) with:
  - bounded queue
  - send/receive
  - ability to transfer capabilities with messages

### 3.6 Capabilities

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
