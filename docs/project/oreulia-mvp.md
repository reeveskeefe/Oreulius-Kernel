# Oreulia — MVP Status and Current Boundary

**Status:** The original MVP has been passed. This document now describes what that means and where the current project boundary actually is.

The old MVP definition assumed a much smaller kernel: boot, a shell, basic capability handling, and an early WASM runtime. The current tree has moved well beyond that. It now includes real networking, a broader temporal model, a richer IPC layer, service registration and typed invocation, multiple architecture bring-up paths, and a dedicated regression workflow set.

So the useful question is no longer “has the MVP shipped?” It has. The useful question is “what has the project already proven, and what still separates it from a production-ready platform?”

---

## 1. The original MVP is complete

The original minimum bar has already been exceeded in several directions.

### Landed beyond the original MVP

- bootable kernels across multiple architectures
- serial shell and broad command surface
- capability management rather than only a placeholder handle table
- a real IPC subsystem with diagnostics and selftests
- a temporal subsystem with snapshot/history/rollback/branch/merge operations
- persistence and restore machinery
- a richer filesystem stack than the original flat-store story
- in-kernel network stack and dedicated network regression lanes
- WebAssembly runtime with typed service invocation and JIT regression coverage

That means the project should stop speaking about “the MVP” as if it were still the target state of the codebase.

---

## 2. What the project has already demonstrated

Oreulia has already demonstrated a coherent kernel-shaped system with these properties:

### 2.1 Boot and runtime bring-up

- `i686` full runtime path
- `x86_64` Multiboot2 QEMU bring-up
- `AArch64` QEMU `virt` bring-up

### 2.2 Core subsystem presence

- capability enforcement
- IPC channels and service introduction
- scheduler/runtime coordination
- temporal state and persistence
- WASM execution and typed service-pointer model
- network stack and HTTP/DNS command surface
- CapNet and related capability-network control surfaces

### 2.3 Verification posture

- dedicated GitHub workflow gates for key regressions
- shell-driven selftests and verification commands
- fuzz and proof surfaces present in tree

This is a real project boundary. Oreulia is not merely a kernel sketch anymore.

---

## 3. What the current minimum credible platform is

If the original MVP is retired, the current minimum credible Oreulia platform looks like this:

### Required properties

- all three public-facing regression-critical lanes remain green:
  - `i686-network-regression`
  - `x86_64-network-regression`
  - `aarch64-network-regression`
- CapNet and WASM JIT regression lanes remain green
- the public docs accurately reflect the current implementation
- the multi-arch shell/runtime surfaces remain bootable and inspectable

This is the right floor to defend publicly today, not the much smaller 2026-02 “boot plus demo” floor.

---

## 4. Current non-goals and limits

Oreulia still does **not** claim:

- POSIX or Linux ABI compatibility
- broad native software support
- full architecture parity
- production-hardened hardware validation
- complete replay fidelity across every subsystem
- complete formal closure of every security property

That matters because the project is stronger than its old MVP docs suggested, but weaker than a productized OS.

---

## 5. What still blocks “production-ready”

The gap between current Oreulia and a production-ready platform is not bootability. It is operational and semantic depth.

### 5.1 Hardware and platform validation

Still needed:

- broader hardware driver coverage
- non-QEMU validation
- sustained soak testing beyond the current CI lanes

### 5.2 Runtime parity and consistency

Still needed:

- narrower feature-gap between `i686`, `x86_64`, and `AArch64`
- more even JIT/runtime support across architectures
- continued cleanup of stale SDK and documentation surfaces

### 5.3 Hardening

Still needed:

- more proof-aligned documentation across subsystems
- more aggressive fuzz and replay coverage
- broader negative testing of authority transfer, policy, and temporal rollback paths

### 5.4 Operational tooling

Still needed:

- stronger fleet/OTA/ops stories beyond the current kernel-facing hooks
- better external observability and incident-handling ergonomics
- more mature release discipline and compatibility guarantees

---

## 6. Revised acceptance standard

The old “human-verifiable MVP” acceptance test is outdated. A more realistic current acceptance standard is:

### Project is in a healthy current state when:

- main regression workflows stay green on the same SHA
- docs do not materially overstate subsystem behavior
- the three architecture bring-up paths still work in QEMU
- the core authority model remains capability-mediated and inspectable
- temporal, IPC, and WASM service surfaces still compose coherently

That is a better description of the current engineering target.

---

## 7. Near-term roadmap after MVP

The right post-MVP work is not “add basic OS features.” Those already exist. The right work is:

- tighten architecture parity
- deepen capability-transfer semantics
- improve replay completeness
- expand hardware and runtime validation
- keep docs honest as fast-moving subsystems evolve

The project has crossed the threshold where accuracy and cohesion matter more than simply adding one more subsystem headline.

---

## 8. Bottom line

Oreulia has already surpassed its original MVP. The old MVP language is still useful as history, but it is no longer a good description of the project’s current state.

The accurate public position is:

- the kernel already has a meaningful execution, authority, temporal, and network story
- it is still alpha-quality research software
- the current work is about hardening, parity, and semantic completion rather than proving the kernel can exist at all

That is a stronger and more credible statement than the older MVP framing.
