# Oreulius Kernel

A security-hardened, bare-metal kernel source tree with target-specific bring-up paths in Rust and assembly.

**Architecture**: multi-target kernel tree (default `i686` boot path; `x86_64` and `AArch64` code paths present)  
**Boot Protocol**: default `i686` bring-up uses Multiboot 1 (GRUB-compatible)  
**Documentation Style**: capability- and target-oriented, with explicit implemented / partial / planned status

---

## Formal Security Papers

Oreulius's formal security records are documented in four companion papers:

- [`../docs/runtime/oreulius-jit-security-resolution.md`](../docs/runtime/oreulius-jit-security-resolution.md)
- [`../docs/capability/capnet.md`](../docs/capability/capnet.md)
- [`../docs/capability/oreulius-intent-graph-predictive-revocation.md`](../docs/capability/oreulius-intent-graph-predictive-revocation.md)
- [`../docs/services/oreulius-service-pointer-capabilities.md`](../docs/services/oreulius-service-pointer-capabilities.md)

These papers include:
- formal model, assumptions, definitions, lemmas/theorems/corollaries
- proof-obligation structure and release-gate equations
- threat-control matrix and compositional security arguments
- implementation-to-invariant mappings for JIT hardening, networked capability transfer, behavior-aware predictive capability control, and directly callable WASM service-pointer capabilities

---

## Capability and Target Matrix

This section is the source of truth for architecture and documentation status. It separates what is implemented today from what is partial or still planned.

Status legend:
- Implemented: present and wired into the current tree.
- Partial: present, but target-gated, backend-limited, or missing one or more production edges.
- Planned: documented intent only.

| Capability / subsystem | i686 | x86_64 | AArch64 | Status | Notes |
|---|---|---|---|---|---|
| Core bring-up, shell, scheduler, IPC, capability model, temporal objects | Yes | Yes | Yes | Implemented | Shared kernel services are target-aware. |
| Security policy and telemetry (intent graph, predictive revocation) | Yes | Yes | Yes | Implemented | Shared policy model with target-specific plumbing where needed. |
| CapNet control plane | Yes | Yes | Yes | Implemented | Token, replay, and delegation semantics are shared; transports are target-gated. |
| Filesystem and storage | Yes | Yes | Yes | Implemented | VFS and RAM-backed paths are shared; device backends vary by target. |
| WebAssembly runtime / JIT | Yes | Yes | Partial | Partial | The x86-family backend is the most mature. |
| VirtIO block and network paths | Yes | Yes | Yes | Implemented | Preferred cross-target I/O path. |
| Legacy x86 device drivers | Yes | Yes | No | Partial | E1000, RTL8139, Wi-Fi, VGA, PS/2, and some PCI helpers remain x86-centric. |
| Enclave / SGX / TrustZone controls | Partial | Partial | Partial | Partial | Fail-closed gating exists where hardware support is available. |
| Verification, fuzzing, soak, and proof surfaces | Yes | Yes | Yes | Implemented | Coverage is expanding, but this is not a blanket whole-system claim. |

Planned work remains in:
- broader legacy-driver parity on AArch64 beyond VirtIO
- tighter proof coverage across target-specific assembly boundaries
- conversion of the remaining aspirational checks into explicit verification gates

---

## Technical Architecture

### Core Design Principles

Oreulius implements a **capability-oriented kernel architecture** with explicit isolation boundaries around high-risk execution paths (JIT, user transitions, enclave/session lifecycle, and capability transfer). The kernel emphasizes deterministic scheduling behavior, strict privilege transitions, and measurable hardening invariants over broad userspace abstraction.

Read the matrix above first if you need to know whether a subsystem is implemented, partial, or still planned on a given target.

### Features

#### **Quantum Scheduler with MLFQ**
- Status: implemented across the current target matrix.
- **O(1) constant-time** task scheduling using multi-level feedback queues
- Three-tier priority system (High/Normal/Low) with queue-level dispatch ordering
- Preemptive multitasking with configurable quantum slices (default: 10ms)
- Context switching optimized in Assembly with explicit general-register, EFLAGS, and control-context save/restore
- Process capability tracking integrated into scheduler state
- Real-time interrupt state verification with EFLAGS monitoring

#### **WebAssembly JIT Compiler**
- Status: partial across the target matrix; the x86-family backend is the most mature.
- **Runtime code generation**: Translates WebAssembly bytecode to native machine code on the active backend
- **Register allocation**: Sophisticated register allocator mapping Wasm locals to x86 registers (EAX, EBX, ECX, EDX, ESI, EDI)
- **Instruction selection**: Direct translation of Wasm opcodes to optimal x86 instruction sequences
- **Memory safety**: Bounds checking on every memory access, prevents buffer overflows
- **Type safety**: Static verification of Wasm type constraints before execution
- **Security isolation**: User-mode (ring 3) execution path with `IRET` transition and sandbox CR3, plus deterministic kernel-mode execution mode for fuzz/replay diagnostics
- **Translation assurance**: Per-block translation certificates and decoder/whitelist validation before execution

#### **IEEE 802.11i WPA2 Security Stack**
- Status: implemented where the target's network and crypto drivers are available.
- **4-way handshake path**: EAPOL key exchange implementation (Messages 1-4)
- **Cryptographic primitives** (all implemented from specification, no external dependencies):
  - **PBKDF2-HMAC-SHA1**: 4096 iterations for Pairwise Master Key (PMK) derivation
  - **SHA-1**: 512-bit block processing, full message schedule expansion
  - **HMAC-SHA1**: Keyed-hash message authentication with IPAD/OPAD construction
  - **PRF-512**: Pseudo-random function for Pairwise Transient Key (PTK) generation
  - **AES-128**: Hardware-accelerated decryption using AES-NI instructions (with software fallback)
- **Key hierarchy**: PMK → PTK → {KCK, KEK, TK} derivation chain
- **MIC verification**: Message Integrity Codes validated before accepting EAPOL frames
- **GTK decryption**: Group Temporal Key extracted and decrypted using KEK from PTK
- **CPUID feature detection**: Runtime verification of AES-NI support with automatic fallback
- **Constant-time operations**: Timing-attack resistant cryptographic implementations
- **802.11 frame handling**: Management frame (authentication, association) and data frame transmission via hardware registers

#### **Driver Capability Matrix**

| Driver | Arch | Transport | Capability Required | Status |
|---|---|---|---|---|
| `virtio_blk` | x86, x86\_64, AArch64 | VirtIO PCI/MMIO | `BlockRead` / `BlockWrite` | Active |
| `virtio_net` | x86\_64, AArch64 | VirtIO MMIO | `NetworkSend` / `NetworkRecv` | Active |
| `e1000` | x86, x86\_64 | PCI | `NetworkSend` / `NetworkRecv` | x86 only |
| `rtl8139` | x86, x86\_64 | PCI | `NetworkSend` / `NetworkRecv` | x86 only |
| `wifi` (802.11i) | x86, x86\_64 | PCI/MMIO | `NetworkSend` / `NetworkRecv` | x86 only |
| `virtio_blk` shell bench | x86, x86\_64, AArch64 | — | `BlockRead` | `blk-bench` command |

> **AArch64 note**: `e1000`/`rtl8139`/`wifi` are not compiled on AArch64 targets.
> Use `virtio_net` (MMIO base `0x0a000000` on QEMU `virt` board) for network access.
> `virtio_blk` and the `blk-bench` shell command work on all architectures.

#### **Full TCP/IP Network Stack**
- Status: implemented, with target-specific hardware backends.
- **Layer 2**: Ethernet II framing, ARP resolution with caching
- **Layer 3**: IPv4 packet handling, ICMP echo (ping)
- **Layer 4**: UDP and TCP (three-way handshake, window/state tracking, retransmit timers)
- **Application**: DNS query/response parsing with cache; DHCP scaffolding present in network stack
- **Hardware drivers**: 
  - **VirtIO MMIO net** (`virtio_net`): capability-gated TX/RX, works on x86\_64 and AArch64 QEMU
  - **Intel E1000**: PCI-based Gigabit Ethernet with descriptor ring management (x86 only)
  - **Realtek RTL8139**: Legacy 10/100 Fast Ethernet support (x86 only)
- **Zero-copy I/O**: DMA buffers accessed directly, no intermediate copying
- **Asynchronous I/O reactor**: Event-driven packet processing with IRQ/timer signaling

#### **Virtual File System (VFS)**
- Status: implemented.
- **Unix-like hierarchy**: Root directory (`/`) with full path resolution (`../`, `./` support)
- **Inode architecture**: Unique file identifiers, metadata (size, type, permissions)
- **Directory operations**: `mkdir`, `ls`, `cd`, `pwd` with recursive directory listing
- **File operations**: `create`, `read`, `write`, `delete`, `stat`
- **Mount points**: Multiple filesystem types mountable at arbitrary paths
- **RAMFS**: In-memory filesystem backed by kernel heap, O(1) lookup via hash tables
- **Block device abstraction**: Uniform interface for real/virtual storage devices

#### **Capability-Based Security Model**
- Status: implemented.
- **No ambient authority**: Processes cannot access resources without explicit capabilities
- **Unforgeable tokens**: Capabilities are cryptographically-sealed kernel objects
- **Fine-grained permissions**: Separate caps for read/write/execute/network/filesystem
- **Delegation**: Capabilities can be passed between processes via IPC (with attenuation)
- **Revocation**: Central authority can invalidate capability groups instantly
- **Prevents confused deputy**: System services validate caps on every operation
- **Predictive gating**: Intent graph risk state can preemptively restrict or quarantine capabilities before escalation
- **Direct callable service pointers**: Service capabilities can target live WASM functions with full signature checks at invoke time
- **Typed service ABI**: Mixed-type invocation (`i32/i64/f32/f64/funcref/externref`) encoded and validated through `service_invoke_typed`

#### **CapNet: Decentralized Capability Networking**
- Status: implemented.
- **Portable authority objects**: `CapabilityTokenV1` encodes capability semantics into a fixed-width network token
- **Per-peer cryptographic context**: Tokens and control frames are authenticated using session keys installed from attestation exchange
- **Replay-safe control channel**: Frame sequence windows and token nonce windows enforce deterministic stale/duplicate rejection
- **Delegation-chain enforcement**: Parent token linkage, max-depth checks, and rights-subset attenuation are validated before lease install
- **Local enforcement bridge**: Accepted remote tokens map to `RemoteCapabilityLease` entries and are checked on capability-use paths
- **Persistent revocation safety**: Epoch-ordered tombstones survive reboot and are replayed at init for fail-closed semantics
- **Verification surface**: In-kernel fuzz, corpus replay, soak loops, and formal checks gate parser and enforcer regressions

#### **Hardware-Optimized Assembly Modules**
- Status: partial across the target matrix; these modules are x86-family specific.

All performance-critical kernel operations are hand-coded in NASM Assembly:

- **`atomic.asm`**: Lock-free atomic operations (CAS, fetch-add, memory barriers)
- **`context_switch.asm`**: Register/EFLAGS context save-restore and thread trampoline transitions
- **`syscall_entry.asm`**: INT 0x80 handler with register preservation, SYSENTER/SYSEXIT fast path
- **`idt.asm`**: Interrupt Descriptor Table setup, 256 exception/interrupt vectors
- **`gdt.asm`**: Global Descriptor Table with flat memory model (kernel/user code/data segments)
- **`memopt.asm`**: SIMD-accelerated memory operations (SSE2 `movdqa` for bulk copy), AES-NI wrappers
- **`crypto.asm`**: Constant-time comparison, secure memory wiping
- **`dma.asm`**: Direct Memory Access setup for network/disk I/O
- **`acpi.asm`**: Power management (CPU halt, C-states)
- **`sgx.asm`**: SGX primitive wrappers (`ECREATE/EADD/EEXTEND/EINIT/EENTER`) on supported targets

#### **Memory Management**
- Status: implemented.
- **Paging**: 4KB pages with Page Directory and Page Tables
- **Copy-on-Write (CoW)**: Deferred page copying on fork() for efficiency
- **Fault-driven CoW resolution**: write-fault handler allocates/remaps private pages on first write
- **Explicit user mapping APIs**: checked range mapping with user/kernel boundary enforcement
- **Heap allocator**: Hardened bump allocator with overflow detection, alignment enforcement
- **Guard-page instrumentation**: JIT user stack/code/data/memory windows and allocator guard sentinels
- **Memory barriers**: Compiler and hardware fences ensuring memory ordering

---

## Scientific Foundations

### Scheduling Theory
The quantum scheduler implements a **multi-level feedback queue (MLFQ)** with per-priority quantum budgets and deterministic FIFO ordering inside each priority level. Dispatch selection is constant-time over three queues, and per-task accounting tracks CPU time, wait time, preemptions, and voluntary yields.

Interrupt-state correctness is treated as a scheduling invariant: context handoff preserves saved EFLAGS semantics, and cooperative/preemptive transitions restore prior interrupt state on resume paths.

### Cryptographic Security
The WPA2 path implements the core **IEEE 802.11i-2004** handshake phases and in-tree crypto primitives:

1. **PMK derivation**: `PBKDF2(password, SSID, 4096, 256)` applies iterated hashing to resist brute-force attacks
2. **PTK generation**: `PRF-512(PMK, "Pairwise key expansion", AA || SPA || ANonce || SNonce)` creates 512-bit key material
3. **Key hierarchy split**: PTK[0:15] = KCK (MIC), PTK[16:31] = KEK (GTK encryption), PTK[32:47] = TK (data encryption)
4. **MIC computation**: `HMAC-SHA1(KCK, EAPOL-frame)` binds keys to specific frames, preventing replay attacks
5. **GTK handling**: KEK-backed GTK decode/install path is implemented with hardware AES acceleration when available (with explicit fallback path)

**Constant-time implementations** prevent side-channel attacks: all comparison operations execute the same number of instructions regardless of input values.

### WebAssembly Compilation
The JIT compiler implements **single-pass translation** with **linear-time complexity**:

1. **Parsing**: Wasm binary decoded into intermediate representation (IR)
2. **Validation**: Type checking ensures stack safety, control flow integrity, memory bounds
3. **Code generation**: Each Wasm opcode mapped to x86 instruction sequence(s):
   - `i32.add` → `add eax, ebx`
   - `i32.load` → `mov eax, [base + offset]` (with bounds check)
   - `br_if` → `cmp eax, 0` + `jne label`
4. **Linking**: Generated code patched with correct jump addresses, function call sites
5. **Execution**: CPU executes native code directly, no interpretation overhead

**Memory safety** preserved through:
- **Guard pages**: Unmapped memory before/after Wasm linear memory traps out-of-bounds access
- **Bounds checks**: Every `load`/`store` validates address before dereferencing
- **Type enforcement**: Wasm values tagged with types, mismatches caught at validation

### CapNet Protocol Semantics
CapNet acceptance is defined as a conjunction of cryptographic, temporal, replay, attenuation, and revocation predicates:

\[
\operatorname{Accept}(\tau, p, R) =
\operatorname{MACValid}_{k_p}(\tau)
\land \operatorname{TemporalValid}(\tau)
\land \operatorname{FreshSeq}(p)
\land \operatorname{FreshNonce}(p,\tau)
\land \operatorname{DelegationValid}(\tau)
\land \neg \operatorname{Revoked}(\tau, R)
\]

Rights monotonicity is enforced by attenuation:

\[
\operatorname{rights}(\tau_{child}) \subseteq \operatorname{rights}(\tau_{parent})
\]

Acceptance installs a lease only when all predicates hold, and every lease-use path re-checks lease activity/revocation and budget constraints.

---

## Building

The commands below exercise the default `i686` bring-up path. The tree also contains `x86_64` and `AArch64` code paths, but their boot flows are documented in [../README.md](../README.md).

**Prerequisites**:
- `rustup` with nightly toolchain (for `asm!()` macro, unstable features)
- `nasm` (Netwide Assembler for x86 Assembly)
- `qemu-system-i386` (x86 emulation/virtualization)
- `xorriso` / `grub-mkrescue` (ISO image generation)

**Build Commands**:
```bash
# Full build: Rust → Assembly → Linking → ISO
./build.sh

# Quick iteration (skips ISO generation)
./quick-rebuild.sh

# Build and run immediately
./build.sh && ./run.sh
```

Active root entrypoints are limited to the current build, run, and verification
scripts. Superseded helpers and boot experiments live under `kernel/archive/`.
Generated outputs should come from `target/` or be regenerated locally, not
stored long-term in the kernel root.

**Build Process**:
1. Rust compiler (`rustc`) builds the kernel as a static library for the default `i686` target (`i686-oreulius.json`, with `i686-oreulia.json` fallback)
2. NASM assembles all `.asm` files to `.o` object files
3. GNU `ld` links Rust library + Assembly objects using `kernel.ld` linker script
4. Resulting `oreulius-kernel` ELF binary embedded in ISO with GRUB bootloader

---

## Running & Debugging

**Launch in QEMU**:
```bash
./run.sh  # Serial console on stdio, default virtual NIC profile
```

These commands exercise the default `i686` boot path.

**Advanced QEMU Options**:
```bash
# Enable KVM acceleration (Linux host)
qemu-system-i386 -cdrom oreulius.iso -enable-kvm -cpu host

# Network tap device (bridge to host network)
qemu-system-i386 -cdrom oreulius.iso -netdev tap,id=net0 -device e1000,netdev=net0

# Increase RAM
qemu-system-i386 -cdrom oreulius.iso -m 512M

# Multiple CPU cores
qemu-system-i386 -cdrom oreulius.iso -smp 4
```

**Debug Output**:
- Kernel logs written to **serial port COM1** (UART 0x3F8)
- QEMU's `-serial stdio` redirects serial to terminal
- Verbose diagnostics include: process table state, interrupt verification, memory operations, network packets, WPA2 handshake progress

**Testing**:
```bash
# Filesystem operations
./test-filesystem.sh

# Boot verification
./test-boot.sh
```

### Security Validation Commands (In-Kernel Shell)

Use these commands from the Oreulius shell to validate current security posture:

- `formal-verify`
  - Executes JIT translation proof checks, capability proof checks, CapNet formal self-checks, intent graph policy checks, and mechanized model checks.
- `wasm-jit-fuzz <iters> [seed]`
  - Differential fuzzing of interpreter vs JIT with mismatch/compile-error reporting.
- `wasm-jit-fuzz-corpus <iters>`
  - Replays the built-in regression seed corpus and aggregates failure metrics.
- `wasm-jit-fuzz-soak <iters> <rounds>`
  - Repeats full corpus rounds to detect residual non-determinism.
- `security-stats`
  - Shows security event counters and current enforcement limits.
- `security-anomaly`
  - Prints anomaly detector window counters, score, and alert totals.
- `security-intent [pid]`
  - Shows per-process intent graph snapshot (scores, counters, restrictions, escalation state).
- `security-intent-clear <pid>`
  - Clears active intent restriction/recommendation and force-restores quarantined capabilities for that process.
- `security-intent-policy [show|set|reset]`
  - Displays or updates runtime intent graph thresholds, cooldowns, and duration policy without rebuild.
- `sched-net-soak <seconds> [probe_ms]`
  - Runs scheduler/network stress verification with progress and error deltas.
- `capnet-fuzz <iters> [seed]`
  - Fuzzes CapNet parser/enforcement transitions with deterministic seed control.
- `capnet-fuzz-corpus <iters>`
  - Replays the CapNet external regression seed set and reports aggregate pass/fail metrics.
- `capnet-fuzz-soak <iters> <rounds>`
  - Repeats full corpus replay to detect residual non-determinism and long-run drift.
- `capnet-demo`
  - Runs an end-to-end lend/use/revoke loopback verification path.
- `svcptr-demo`
  - End-to-end service-pointer register/transfer/invoke verification path.
- `svcptr-demo-crosspid`
  - Cross-process transfer/invoke proof path.
- `svcptr-typed-demo`
  - Mixed-type typed invoke host-path verification (`i64`, `f32`, `f64`, `funcref`).
- `temporal-abi-selftest`
  - Temporal-object ABI host-path verification plus VFS FD-write capture and temporal IPC service consistency checks.
- `temporal-ipc-demo`
  - Demonstrates binary-framed `SNAPSHOT/LATEST/HISTORY/STATS` temporal-object operations over the IPC service dispatcher path.

---

## Continuous Verification (CI)

Kernel security regression checks are now integrated into repository CI:

- Workflow: `../.github/workflows/wasm-jit-regression.yml`
- External runner: `fuzz/run_wasm_jit_corpus.expect`
- CI parser/gate: `fuzz/ci_regression_check.sh`
- Workflow: `../.github/workflows/capnet-regression.yml`
- External runner: `fuzz/run_capnet_corpus.expect`
- CI parser/gate: `fuzz/ci_capnet_check.sh`

CI fails on:
- any corpus seed replay failure
- non-zero corpus mismatches
- non-zero corpus compile errors
- failed soak rounds
- CapNet corpus mismatch/compile-error or soak failure

This converts fuzz/corpus confidence into a merge-time admission policy.

---

## Performance Characteristics

- **Scheduler dispatch complexity**: O(1) queue selection with fixed three-level MLFQ
- **Syscall entry path**: INT 0x80 + SYSENTER/SYSEXIT support with assembly fast paths
- **Network path**: DMA-backed descriptor rings on E1000/RTL8139-class drivers
- **Memory path**: SSE2-optimized primitives for hot memcpy/memset routines
- **Wasm path**: JIT and interpreter dual execution with differential replay/fuzz controls
- **CapNet path**: fixed-width control parser + lease enforcement with replay-window and tombstone checks
- **Intent graph path**: bounded per-process scoring windows with incremental edge/counter updates and deterministic escalation checks
- **Note**: absolute latency/throughput depends on QEMU host configuration and CPU virtualization mode

---

## Security Model

**Threat Model**: Protects against malicious userspace processes attempting privilege escalation, memory corruption, resource exhaustion, or capability forgery.

**Mitigations**:
- **Ring separation**: Kernel (ring 0), user processes (ring 3), no ring 1/2 used
- **W^X publish discipline**: writable-then-sealed executable pages for JIT outputs
- **Kernel section protection**: `.text`/`.rodata` mapped read-only; mutable segments isolated
- **Capability MAC integrity**: SipHash-backed token/object validation for IPC and core capability tables
- **CapNet control security**: Session-key MAC validation, sequence/nonce replay windows, and delegation-chain attenuation checks
- **Intent-graph predictive revocation**: Capability use is dynamically restricted/quarantined when behavioral risk crosses policy thresholds
- **CPU hardening**: SMEP/SMAP/KPTI enabled where hardware supports those controls
- **Interrupt validation**: EFLAGS checked before HLT (prevents deadlock attacks)
- **Bounds enforcement**: Every array access validated, panics on out-of-bounds

### Additional Defense-in-Depth Controls (Current State)

- **JIT page permission sealing** with explicit RW->RX transitions and post-run cleanup policy
- **Guard-page-backed fault containment** for JIT stack/code/data/memory windows
- **Instruction whitelist + decoder verifier** rejecting unsafe or malformed emitted x86 forms
- **SFI and CFI enforcement** on memory/control-flow edges in generated code
- **Fuel-bounded execution** (instruction and memory operation budgets)
- **Deterministic replay gates** with corpus + soak pass criteria
- **Anomaly score monitoring** with thresholded alert events in audit stream
- **Attestation interoperability checks** (vendor roots, signer linkage, token freshness)
- **Fail-closed key lifecycle rules** for enclave session open/enter/close
- **Persistent revocation journal replay** for cross-reboot denial of revoked remote capability tokens
- **Quarantine/restore automaton** for intent-driven capability rollback with bounded hysteresis and explicit override paths

### Security Posture Summary

Oreulius now treats security as a composition of enforceable invariants and deterministic acceptance gates rather than one-time hardening claims. The canonical formal statement and theorem-level structure are maintained in the linked security paper.

---

## Research Contributions

This kernel demonstrates several novel implementations:

1. **WebAssembly in bare-metal context**: bare-metal kernel source tree with in-kernel Wasm JIT, translation certificates, and formalized proof obligations
2. **WPA2 handshake stack from scratch**: In-tree 802.11i-oriented cryptographic and EAPOL flow implementation
3. **Quantum scheduling**: Deterministic priority-aware scheduling with MLFQ + quantum accounting on embedded systems
4. **Assembly-accelerated cryptography**: AES-NI integration with CPUID detection and fallback paths
5. **Decentralized kernel capability networking**: CapNet portable token protocol with attestation-bound sessions, replay-safe control frames, lease bridging, and persistent revocation semantics
6. **Kernel-native behavior-aware capability control**: Intent graph scoring and predictive revocation integrated directly into capability enforcement
7. **Directly callable capability composition model**: Function/service pointer capabilities for typed WASM service dispatch with delegate-safe transfer, runtime lock hardening, and hot-swap continuity

The codebase serves as educational reference for:
- Systems programming in Rust without `std` library
- Hand-coding Assembly for performance-critical paths
- Implementing cryptographic protocols to specification
- Building network stacks from Ethernet frames upward
- JIT compiler design and code generation

---

## License

See `LICENSE` and `COMMERCIAL.md` in the repository root.
