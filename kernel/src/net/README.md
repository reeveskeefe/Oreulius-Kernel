# The Network Subsystem and CapNet

## Network Architecture and Trust Boundary Audit

### Network subsystem responsibilities

The network folder spans substantially more than device-independent packet transport. It contains Ethernet drivers, Wi-Fi support, address and packet types, ARP, IPv4, ICMP, UDP, TCP, DNS, HTTP support, TLS, the network reactor, CapNet authority transport, diagnostics, and temporal state restoration. It also supplies network operations to the shell, fetch service, WASM runtime, fleet service, and temporal replay system.

This breadth makes the folder a kernel trust boundary rather than a conventional protocol library. It accepts untrusted device input, mutates DMA-visible state, interprets remote protocol fields, holds cryptographic and capability material, and exposes operations to callers with different privilege models. Correctness therefore depends on packet validation, authenticated caller identity, resource bounds, driver ownership, and restore policy being enforced together.

The current implementation does not assign those responsibilities to one narrow public contract. Low-level drivers, the universal stack, the reactor, the legacy service, TLS, Wi-Fi, and CapNet each own part of the policy. That distribution is workable during development, but it makes it difficult to prove that every route into the network applies the same authorization, accounting, error, and lifecycle rules.

### Active networking implementations

The folder contains several implementations at different maturity levels, and their presence must not be read as equal runtime support. The reactor-owned NetworkStack with E1000 on x86 and VirtIO on AArch64 is the common path. RTL8139 is initialized separately and is used directly by the standalone TLS transport. The legacy NetworkService remains a compatibility facade, while Wi-Fi includes substantial protocol code around hardware access that is explicitly illustrative in places.

The mismatch affects feature discovery and failure handling. Broad Wi-Fi vendor matches can set the driver enabled after handlers that only enable PCI access and print a chipset name. The standalone TLS API can allocate sessions even though the compatibility HTTP path blocks HTTPS, and its AArch64 transmitter intentionally emits no frame. A runtime support query must therefore report backend, architecture, validation level, and operational readiness rather than infer support from compiled symbols.

### Legacy network service and universal stack overlap

The legacy NetworkService duplicates connection, DNS, HTTP, statistics, and persistence concepts while delegating selected live operations to the reactor. The overlap is deeper than duplicate data structures: compatibility state can outlive or disagree with the reactor resource it describes, and both layers expose independent temporal schemas.

The two layers can disagree after partial failure. A legacy record may retain an owner, remote endpoint, or DNS result after the reactor connection has timed out or closed, while temporal restoration can reconstruct compatibility records independently of the live stack. HTTPS adds a third state domain through its private TLS sessions. Until these identities share one generation and cleanup transaction, stale compatibility objects can refer to absent or unrelated transport resources.

### Network reactor ownership model

The reactor owns the common NetworkStack and keeps protocol mutation out of interrupt context. That ownership does not cover every network implementation. TLS owns a separate TCP connection object and static session table, RTL8139 can be called directly, Wi-Fi performs synchronous MMIO loops, and compatibility state remains behind another global mutex.

The receive loop weakens its own ownership guarantee by erasing outcomes. Burst processing ignores frame-dispatch results; dispatch ignores ARP and IPv4 handler results; AArch64 marks polling as productive whenever a callback runs, even if parsing failed. Timer and request progress then continue without a record of the rejected transition. Structured ingress outcomes must return to the reactor so scheduling, counters, reset policy, and attack detection observe the same event.

### Device backend selection

Backend selection is compiled into helper functions rather than performed through the declared NetworkInterface abstraction. AArch64 uses VirtIO when available. Other targets route universal stack transmission, link state, and MAC lookup to E1000 globals. RTL8139 remains present for other paths, particularly the standalone TLS implementation, but is not selected by the common backend helpers.

This creates a difference between the architectural interface and the operational implementation. The trait suggests runtime substitution, while live code reaches concrete module globals. A detected RTL8139 device cannot transparently replace E1000 in the universal stack, and a failed active backend cannot be exchanged without changing higher-level state.

Initialization, readiness, and recovery are also architecture-specific. The reactor seeds QEMU defaults, enables E1000 interrupts on x86, and initializes discovered VirtIO MMIO on AArch64. Link loss, reset, MAC changes, and driver reinitialization do not pass through one backend lifecycle that can invalidate ARP, TCP, DNS, and CapNet state consistently.

### Packet ingress trust boundary

Ingress begins in hardware-controlled descriptor rings or device receive buffers. Driver code converts device status and lengths into a frame slice, the reactor copies or exposes that frame through bounded staging storage, and NetworkStack dispatches it by Ethernet type into ARP or IPv4 handling. IPv4 then routes traffic into ICMP, UDP, TCP, DNS, HTTP, or the CapNet control port.

Every byte after the driver descriptor is attacker-controlled unless a later protocol authenticates it. Frame length, header length, total length, offsets, ports, checksums, sequence values, DNS counts, TCP options, TLS record sizes, Wi-Fi management fields, and CapNet control fields must be validated before indexing, allocation, state mutation, logging, or cryptographic use.

The top-level dispatcher rejects frames shorter than an Ethernet header, and lower layers contain many additional bounds checks. That is necessary but not sufficient as one proof of safety because parsing is distributed across protocol modules and some handlers intentionally discard their returned errors. A malformed packet may therefore be ignored safely, logged differently, or partially affect diagnostics depending on its route.

Ingress authority has two layers. Network packets are not authorized merely because a local process has network access; remote authenticity must come from TCP state, TLS verification, Wi-Fi protection, or CapNet session and token checks. The current folder does not define one table identifying which remote fields are trusted at each layer and which state changes require authenticated protocol context.

### Packet egress trust boundary

Egress commonly begins with a shell command, fetch operation, WASM host call, fleet operation, compatibility service call, or internal protocol timer. The reactor translates these requests into DNS, TCP, HTTP, or CapNet operations, while the stack resolves link-layer destinations, constructs headers and checksums, and submits complete frames to the selected driver.

The universal egress functions do not receive an authenticated principal or a network authority object. Authorization must therefore have occurred in the caller, but this is neither expressed in the reactor request nor revalidated at the commit point. Direct kernel callers can invoke the same public functions under different security assumptions.

VirtIO exposes a separate capability_send helper, but it currently checks for a Channel capability with no required rights because no dedicated network capability type exists. The common stack transmit path does not use that helper. Consequently, the presence of one capability-aware driver function does not establish a system-wide no-send-without-authority invariant.

Egress also owns resource and information boundaries. Payload size, staging capacity, source address selection, retransmission limits, ARP resolution, queue saturation, and diagnostic redaction should be decided before a frame reaches the driver. Today those decisions are spread across the caller, reactor, protocol implementation, and backend.

### Kernel service and userspace exposure

Network access is exposed through several kernel-facing surfaces rather than one canonical contract: reactor requests, legacy service methods, TLS session functions, Wi-Fi methods, CapNet calls, shell commands, fetch transport, and WASM adapters. These paths do not share a principal-bearing request type or one capability check at the state-changing boundary.

This creates path-dependent authority. A WASM adapter may validate guest memory and handles before submitting reactor work, while a kernel caller can invoke a public TLS or Wi-Fi function without carrying the same principal. The network layer cannot later prove who initiated traffic, which rights were checked, or whether revocation occurred during blocking work. The canonical operation must carry principal, capability generation, resource budget, and cancellation identity to commit.

### Capability enforcement boundaries

Capability enforcement is strongest inside CapNet, where tokens, rights attenuation, peer sessions, replay windows, delegation, revocation, and temporal validity are modeled explicitly. That protects CapNet authority messages, but it does not automatically authorize ordinary DNS, TCP, HTTP, raw frame, Wi-Fi, or TLS operations.

The general network path lacks a canonical Network capability type and commit-time check. Reactor requests carry operation data but no caller capability. The legacy service accepts direct method calls. Driver send functions primarily assume that their caller has already been authorized. The VirtIO capability helper uses Channel authority as a placeholder and asks for no operation right.

These boundaries also use different identities. CapNet has device and peer identities, the legacy service stores process owners, WASM has instance-local handles, drivers have no principal, and temporal restoration can recreate state through privileged entry points. No shared generation-bearing principal binds all of these identities to the current execution context.

The result is policy by call path. A security review must inspect every caller rather than proving one invariant at the network boundary. Revocation is similarly incomplete because removing one caller-side handle does not necessarily cancel queued reactor work, close protocol state, erase retransmissions, or invalidate restored records.

### Temporal persistence boundaries

NetworkService, NetworkStack, Wi-Fi, and CapNet record independent temporal objects. Several recording functions discard persistence errors, and some return early when encoding exceeds capacity without emitting diagnostic evidence. Callers can mutate live state and receive success even though the corresponding recovery record was never committed.

Failure ordering is especially dangerous for revocation and secrets. CapNet can update in-memory tombstones before a journal append that may fail, while Wi-Fi can publish live connection state and then silently lose its snapshot. Conversely, restoration can load a PMK before hardware identity and trusted time are reconciled. A recovery transaction must stage decoded objects, authenticate their shared epoch, validate external dependencies, and publish all related state only after durability requirements succeed.

### Cross-module dependency direction

The network folder depends on architecture discovery, PCI and MMIO support, scheduler timing and yielding, security logging and signing, capabilities, IPC process identifiers, temporal storage, cryptography, and kernel diagnostics. Higher-level modules including the shell, fetch service, fleet service, WASM runtime, and temporal replay depend back on network APIs.

Some dependencies follow the intended layering: drivers provide frames, the stack provides protocols, and services consume reactor operations. Others cross those boundaries. TLS reaches a concrete RTL8139 transport, the stack emits security events directly, CapNet combines transport and authority policy, and temporal code calls network-specific mutation functions.

These crossings make initialization and lock ordering harder to reason about. Network progress may require scheduler ticks and driver locks while security, capability, temporal, or service code can call back into networking. The README and code do not define one dependency rule or lock-order table that prevents a low-level packet path from acquiring a higher-level policy dependency.

Narrow interfaces are needed at four boundaries: device frames, authenticated network operations, cryptographic services, and persistence transactions. Without those interfaces, changing a driver, authority model, or restore format can require edits across unrelated protocol code.

### Active code, compatibility code, and scaffolding

The source tree mixes live runtime code with compatibility layers, partially integrated abstractions, and forward-looking interfaces.

| Classification | Examples | Audit consequence |
| --- | --- | --- |
| Active runtime path | Reactor, universal stack, E1000 on supported x86 paths, VirtIO on AArch64, shell and fetch reactor callers | Must satisfy production ownership, bounds, authorization, and recovery invariants |
| Active specialized path | CapNet control traffic, Wi-Fi operations, standalone TLS where invoked | Must document how its authority and lifecycle connect to the common stack |
| Compatibility code | Legacy NetworkService and duplicate protocol types | Must not gain new ownership or silently define public semantics |
| Partial abstraction | NetworkInterface trait and backend-neutral claims | Must not be treated as implemented portability until live backends use it |
| Structural facade | CapNet submodules that primarily re-export the monolithic implementation | Improves navigation but does not yet establish independent ownership boundaries |
| Scaffolding or dormant behavior | Disabled temporal recording paths, broad dead-code allowances, unselected backend paths | Must be classified and tested before activation or removed from the supported contract |

The distinction matters because unused code in a kernel can still affect maintenance, feature activation, layout assumptions, and security review. Broad dead-code suppression makes it difficult to tell whether an item is intentionally dormant, target-specific, test support, or abandoned.

Each public item should have a declared status, owner, supported targets, entry points, tests, and removal or activation condition. Until that inventory exists, documentation should avoid presenting every implemented type or function as part of one operational network contract.

## Explicit Risk Register

The detailed audit below names many local gaps. This register pulls the highest cross-cutting risks into one place so the next development pass can decide what must be true before the network subsystem becomes a stable kernel facility. The important distinction is not whether code exists, but whether the runtime path has one authority model, one state owner, one recovery rule, and one way to observe failure.

### Runtime support versus compiled surface

The net folder compiles more networking surface area than it can currently present as one supported runtime stack. That is normal during kernel bring-up, but it must be visible to readers and callers. A symbol that compiles may still be architecture-specific, compatibility-only, experimental, blocked behind validation policy, or disconnected from the common reactor.

| Surface | Current code state | Active runtime path | Support risk | Maturity gate |
| --- | --- | --- | --- | --- |
| Common Ethernet, ARP, IPv4, UDP, DNS, TCP, and HTTP | Implemented in the universal stack and driven by the reactor | E1000 on supported x86 paths, VirtIO on AArch64 | Protocol behavior is active, but ingress errors, checksum policy, and authority checks are not yet unified | Backend-neutral driver object, typed ingress outcomes, authenticated request envelope, and protocol conformance tests |
| Legacy network service | Still exported from the module root with duplicate connection, DNS, HTTP, and temporal state | Some calls delegate to the reactor while keeping compatibility records | Compatibility state can describe resources no longer owned by the reactor | Migration plan that makes compatibility records views over reactor-owned generations |
| TLS | Standalone TLS and private TCP transport exist | Not the same path as the legacy HTTP client, which rejects HTTPS without strict validation | A TLS module can look like HTTPS support even when the public HTTP path intentionally blocks it | TLS over the reactor TCP contract with certificate-chain, hostname, alert, and secret-lifetime policy |
| Wi-Fi | Broad subsystem with scan, authentication, association, WPA2, and temporal reconnect code | Experimental hardware paths and illustrative MMIO behavior | Device enablement can be confused with a supported data plane | Device-family support matrix, firmware and DMA contract, protected data path, and end-to-end hardware tests |
| CapNet | Active security prototype with token, peer, control, revocation, persistence, audit, and metrics code | Control traffic is transported over UDP in the universal stack | CapNet has a stronger authority model than ordinary networking, but can become a parallel capability system | Canonical integration with central capability identity, revocation, quotas, and principal attribution |
| VirtIO capability send | Dedicated helper checks an existing Channel capability placeholder | Not used by the common stack transmit path | A capability-aware helper can be mistaken for system-wide network send enforcement | Dedicated network capability type and commit-time checks on all transmit paths |
| CapNet facade modules | Separate files re-export the monolithic implementation | Organizational only | File layout can imply decomposed ownership that does not exist | Move state and invariants behind private module boundaries before presenting ownership claims |

### Commit-boundary map

The safest way to reason about this subsystem is to identify where untrusted input or caller intent becomes committed state. Several current paths validate enough to avoid obvious bounds failures, but they do not always validate enough before caching, queueing, acknowledging, retransmitting, logging, or returning success.

| Boundary | Current commit point | Missing proof | First hardening pass |
| --- | --- | --- | --- |
| Device ingress to protocol dispatch | Driver supplies a frame slice and the reactor calls the stack dispatcher | Dispatch results are often ignored, so malformed traffic may not produce a structured drop reason | Return a packet disposition from every parser and count it at the reactor |
| ARP observation to cache update | ARP handling can learn peer address mappings from received packets | Spoofing policy, gratuitous behavior, and replacement rules are not one authenticated cache contract | Separate validation, policy decision, and cache mutation |
| IPv4 packet to transport state | IPv4 dispatch reaches ICMP, UDP, TCP, DNS, or CapNet after header checks | Header checksum, fragmentation policy, local-address policy, and error propagation need one documented admission rule | Make IPv4 admission return accepted, dropped, unsupported, or suspicious with counters |
| UDP datagram to receive queue | Matching and nonmatching datagrams enter bounded slots | Checksum enforcement, per-principal quotas, and overflow diagnostics are incomplete | Enforce checksum policy and return overflow outcome without losing unrelated queued traffic |
| TCP segment to connection state | Sequence, acknowledgement, and state logic can mutate connection records | Checksum verification, out-of-window handling, reset policy, and time-wait behavior are not complete enough for hostile networks | Gate state mutation behind a validated segment object |
| DNS response to cache | Response matching checks transaction identity and selected fields | Source-port entropy, spoofing resistance, negative caching, and stale removal remain limited | Bind response matching to randomized source port, resolver address, transaction identity, and outstanding query generation |
| TLS record to application bytes | TLS decrypts and buffers application data in a session table | Certificate trust, hostname validation, alert semantics, and secret zeroization are not complete public guarantees | Treat TLS as experimental until strict validation is enforced before application data is released |
| CapNet token to remote lease | Accepted tokens can install central capability leases | Cryptographic strength, session binding, tombstone retention, and journal durability need release-grade policy | Require modern token authentication, durable revocation, and lease cleanup on session loss |
| Temporal restore to live state | Restore functions rebuild compatibility, stack, Wi-Fi, or CapNet records | Restored state is not always staged, cross-checked, and published atomically against hardware and trusted time | Use a restore transaction per subsystem generation |

### Support matrix for risky backend assumptions

Driver and architecture assumptions should be explicit because they decide whether the rest of the stack can trust DMA buffers, memory ordering, link state, and frame lengths. The current implementation has useful emulator-oriented paths, but production maturity requires separate evidence for hardware and weakly ordered targets.

| Backend | Primary target today | Main assumption | What must be proven before broader support |
| --- | --- | --- | --- |
| Intel E1000 | x86 and x86-64 style PCI paths | Static buffers and descriptor addresses fit the device DMA model | Physical addressing, descriptor ownership, receive error bits, reset recovery, and non-QEMU behavior |
| Realtek RTL8139 | Compatibility and specialized transport | Port I/O and static rings are sufficient for direct send and receive | Common-stack selection, receive-ring recovery, transmit timeout failure, and exact hardware conformance |
| VirtIO network | AArch64 MMIO path | Heap-backed queue memory is usable as device-visible memory | DMA-safe allocation, cache maintenance, queue-size negotiation, used-ring validation, and reset sequencing |
| Wi-Fi MMIO paths | Experimental PCI device families | Register offsets and frame paths model expected hardware behavior | Firmware loading, descriptor rings, management-frame authentication, protected data path, and secret lifetime |
| Standalone TLS transport | RTL8139-oriented path | Private TCP transport can coexist with the universal stack | Replacement with reactor TCP or an explicit compatibility quarantine |

### Audit command backlog

The subsystem needs read-only diagnostic commands before it can be debugged safely under load. These are not current commands; they are the command surfaces that should exist once the underlying counters and snapshots are implemented. They should expose state without packet payloads, secrets, session keys, PMKs, token MAC material, or raw peer measurements unless a privileged diagnostic mode explicitly authorizes that view.

| Command surface | Purpose | Required data source | Redaction rule |
| --- | --- | --- | --- |
| net status | Show selected backend, link state, local addressing, readiness, and reactor generation | Backend lifecycle state and reactor state | No packet payloads or secrets |
| net drops | Show packet drop reasons by layer and backend | Structured ingress dispositions | Aggregate counters only |
| net sockets | Show TCP listeners, connections, states, queues, and owner generations | Reactor-owned TCP tables | Redact payload bytes and remote identity where policy requires |
| net dns | Show outstanding queries, cache occupancy, positive and negative entries, and expiry | DNS cache and query table | Redact queried names when caller lacks DNS diagnostic authority |
| net drivers | Show ring occupancy, interrupt counts, reset counts, and last device error | Driver-owned diagnostics | No DMA buffer contents |
| net tls | Show session handles, states, validation mode, alerts, and buffer occupancy | TLS session table | No keys, transcript hashes, or certificate private material |
| net wifi | Show scan state, association state, replay counters, and supported device path | Wi-Fi driver state | No passwords, PMKs, PTKs, GTKs, or raw management payloads |
| net capnet peers | Show peer sessions, epochs, replay-window state, and trust policy | CapNet peer table | Redact session keys and raw token bodies |
| net capnet journal | Show revocation epochs, tombstone occupancy, and journal health | CapNet revocation and persistence state | Redact token secrets and only expose token identifiers |

### Highest priority gaps made explicit

The next code pass should not start by adding more protocol features. The most important work is making the active boundary measurable and enforceable. More HTTP, TLS, Wi-Fi, or CapNet behavior will be easier to trust once the shared transport path reports why it accepted, rejected, queued, retried, or dropped work.

| Priority | Gap | Consequence if ignored | Best first owner |
| --- | --- | --- | --- |
| Critical | No canonical network authority at transmit commit | Send permission depends on the caller path rather than the network boundary | Capability manager and reactor request layer |
| Critical | Protocol parse errors disappear before diagnostics | Attack traffic cannot be distinguished from benign unsupported traffic | NetworkStack and reactor ingress loop |
| Critical | DMA and backend memory assumptions are architecture-local | A supported emulator path may not imply safe hardware operation | Driver layer and memory manager |
| High | TLS exists outside the common transport contract | HTTPS claims can become ambiguous and validation policy can diverge | TLS and reactor TCP integration |
| High | Temporal restore can publish stale or externally inconsistent state | Recovery may resurrect resources without matching hardware, time, or revocation state | Temporal and subsystem owners |
| High | CapNet authority is stronger than general network authority | Remote capability transport can outrun local network policy | CapNet and central capability manager |
| Medium | Compatibility state duplicates reactor state | Debugging and cleanup can follow the wrong object generation | Legacy service migration |
| Medium | Diagnostic commands are not backed by unified counters | Operators cannot safely inspect failures without reading logs or adding ad hoc prints | Diagnostics and observability |

## File and Component Audit

### Network module root

The module root is both a namespace and a compatibility implementation. It exports the drivers, reactor, universal stack, TLS, Wi-Fi, and CapNet, while also defining a separate NetworkService with duplicate address, connection, DNS, HTTP, error, statistics, and temporal types. Its active HTTP and DNS methods delegate part of their work to the reactor, but the global service retains independent records and locking.

The module-level dead-code allowance hides the distinction between active runtime code and dormant compatibility code. The root is therefore mature as an integration point but not as a clean ownership boundary. It should become a small export and initialization module after callers migrate away from NetworkService.

### Universal network stack

NetworkStack implements the common Ethernet, ARP, IPv4, ICMP, UDP, DNS, TCP, HTTP server, and CapNet transport path. It uses fixed-capacity tables for protocol state and static staging buffers for packet construction, which makes its principal resource bounds visible. The x86 path sends through E1000, while AArch64 sends through VirtIO.

The stack is active and substantial, but its advertised universality is incomplete. Backend helpers call concrete global drivers, DHCP is named but not integrated as a working configuration path, IPv4 fragmentation is unsupported, and several protocol errors are discarded by dispatch. Future maturity requires a backend object, typed protocol outcomes, authenticated operation requests, and explicit support boundaries.

### Network reactor

The reactor owns the live NetworkStack, converts interrupts into pending work, drains receive bursts, advances timers, and serializes service requests. Runtime startup code on supported architectures launches it as a dedicated kernel task, and shell, fetch, WASM, fleet, and temporal code call its public functions.

Its single-owner design is the correct concurrency center, but the implementation relies on static mutable storage and one global request slot. It has no request queue, principal, operation identifier, cancellation acknowledgement, shutdown state, or safe restart protocol. The reactor is active infrastructure with a clear direction and an incomplete multi-client contract.

### Intel E1000 driver

The E1000 driver is the common non-AArch64 backend used by NetworkStack. It owns static aligned descriptor and packet pools, configures PCI bus mastering and MMIO rings, supports burst receive, batches transmit work, acknowledges interrupts, and adapts interrupt throttling to observed receive depth.

The driver is active in x86 and x86-64 startup paths, although the common stack assumes its presence even when RTL8139 is also detected. Its maturity gap lies in DMA address validation, reset recovery, device removal, hardware-family coverage, and test evidence outside QEMU. It also needs a backend lifecycle that can invalidate protocol state after reset.

### Realtek RTL8139 driver

The RTL8139 driver probes PCI I/O BARs, programs one receive ring and four transmit buffers, performs port I/O, and exposes global send, receive, availability, and link functions. Runtime probing initializes it when the matching device is found.

The universal stack does not select it through the common backend helpers, while the TLS implementation uses RTL8139-oriented transport directly. The driver is therefore active specialized or compatibility code rather than a peer backend to E1000. It needs explicit ownership, error-returning APIs, recovery behavior, and integration tests before it can serve as a supported failover device.

### VirtIO network driver

The VirtIO driver implements the modern MMIO status sequence, negotiates version, MAC, and link features, creates split receive and transmit queues, publishes descriptors with fences, and exposes polling-based frame delivery. The AArch64 reactor discovers and initializes it directly.

The driver is active on AArch64, but queue memory is heap-backed and the code does not establish a platform DMA mapping or cache-coherency contract. Receive polling allocates vectors and copies frames, mergeable receive buffers are not negotiated, and the capability-aware send helper is outside the normal send path. Production maturity requires DMA-safe memory, bounded allocation-free polling, reset handling, and architecture conformance tests.

### Wi-Fi subsystem

The Wi-Fi subsystem contains PCI and MMIO initialization paths, scanning, management-frame parsing, authentication and association state, open-network connection, WPA2 key handling, temporal reconnect data, and local AES support for key unwrap. A global mutex owns the driver, and the legacy NetworkService is its primary facade.

The implementation is broad but only partially connected to the universal packet stack. Hardware-family behavior, data-plane integration, cryptographic validation, secret lifetime, and replay handling need target-specific evidence. It should be treated as experimental until supported devices and successful end-to-end connection paths are documented and tested.

### TLS implementation

The TLS module implements a TLS 1.3-oriented handshake, X25519 key exchange, transcript hashing, AES-GCM traffic protection, records, application buffering, and a fixed four-session table. It also contains its own Ethernet, IPv4, TCP, address, and gateway state and sends through RTL8139-oriented transport.

This separate transport makes TLS an independent stack rather than a secure layer over NetworkStack TCP. Certificate-chain and hostname validation are not established as a complete trust decision, while the legacy HTTP client explicitly blocks HTTPS because strict validation is unavailable. The future path should retain one TLS engine but place it over the reactor TCP contract with a kernel trust store, verified names, typed alerts, and secret zeroization.

### CapNet implementation

CapNet is a monolithic implementation of portable capability tokens, peer trust, session keys, delegation records, replay windows, control messages, revocation tombstones, persistence, audit, metrics, fuzzing, and formal self-checks. NetworkStack transports its control frames over a reserved UDP port and retains a bounded retransmission table.

CapNet has the strongest explicit authority model in the network folder, but its cryptographic and lifecycle guarantees remain kernel-local. SipHash-based authentication, trust-on-first-use options, persisted session keys, bounded tombstone replacement, and separate transport retransmission require a documented threat model. Maturity depends on tying tokens to the central capability manager and authenticated principals without allowing CapNet to become a parallel authority system.

### CapNet facade modules

The CapNet subdirectory is an organizational facade, not a decomposed implementation. Its module root includes the monolithic parent file through a path override, and audit, encoding, metrics, persistence, and session modules only re-export selected legacy symbols while suppressing dead-code warnings.

The apparent split can mislead dependency and concurrency review. Session operations, persistence, encoding, metrics, fuzzing, and formal checks still share the same legacy globals and locks, but their facade files hide those relationships from a file-level inventory. Real decomposition should begin at state ownership: move one lock and its invariants behind a private module, expose only operations that preserve them, then repeat without changing the wire format.

### CapNet test support

The main CapNet file includes token round-trip, control-frame, fuzz, regression, and formal self-check logic. The separate capnet_test file contains only a small affine capability sketch and is not a comprehensive test harness for the active implementation.

Current tests provide useful deterministic checks, but they share production globals and do not establish concurrency, persistence rollback, cross-device interoperability, or capability-manager integration. Test support should move toward isolated state objects and retained malformed-input corpora rather than adding more global self-check entry points.

### Component ownership and maturity

The component maturity picture is uneven.

| Component | Active owner | Maturity | Primary gap |
| --- | --- | --- | --- |
| NetworkStack | Network reactor | Active development | Backend abstraction, protocol completeness, authority |
| NetworkService | Global compatibility mutex | Compatibility | Duplicate state and public semantics |
| E1000 | Global driver mutex | Active on x86 targets | DMA, reset, hardware validation |
| RTL8139 | Global driver mutex | Specialized | Common-stack integration and recovery |
| VirtIO | Global driver mutex | Active on AArch64 | DMA-safe memory and interrupt integration |
| Wi-Fi | Global driver mutex | Experimental | Hardware evidence, data plane, key lifecycle |
| TLS | Static session table | Experimental | Trust validation and universal-stack integration |
| CapNet | Several global tables | Active security prototype | Central authority integration and cryptographic maturity |

No component table in code or documentation currently names a maintainer, supported targets, required capabilities, startup dependency, test gate, and deprecation condition. That inventory is required before the folder can claim one stable network subsystem.
## Network Initialization and Runtime Audit

### Boot-time initialization order

Boot order differs by architecture. x86 and x86-64 initialize CapNet and detected PCI network drivers during architecture runtime setup, then the scheduler starts the dedicated network task. AArch64 starts the reactor task, which discovers and initializes VirtIO itself. This means device readiness may precede or occur inside reactor startup depending on the target.

The order is functional for current boot paths but not encoded as one dependency graph. Security, capability, temporal, scheduler, interrupt, timer, and device prerequisites should be explicit before the reactor accepts requests or restore operations.

### Device probing and backend selection

PCI runtime code detects E1000 and RTL8139 separately, while AArch64 obtains a discovered VirtIO MMIO base. NetworkStack nevertheless selects E1000 for every non-AArch64 operation and VirtIO for AArch64. Detection does not produce a general backend registration result.

Backend selection is therefore compile-time and architecture-driven rather than based on a validated device inventory. A common selection transaction should choose one owner, reject conflicting claims, record capabilities, and expose a typed reason when no supported backend becomes available.

### Static network configuration

The reactor accepts a static IPv4 address and gateway and NetworkStack stores a DNS server alongside interface state. Configuration is applied to reactor-owned state and can be represented by a temporal payload. The public configure operation does not carry a caller identity or administrative capability.

Static configuration is usable but incomplete as a managed system. It needs validation for address classes, gateway reachability, duplicate addresses, DNS choice, configuration generation, and atomic invalidation of dependent ARP and connection state.

### Legacy QEMU defaults

NetworkStack contains fixed QEMU user-network values for address, gateway, DNS, and an initial MAC. On x86, the reactor seeds those defaults when E1000 is present and configuration is missing. The method marks the interface available and replaces the MAC when the driver reports one.

These defaults are development policy embedded in protocol state. They should be enabled only by an explicit boot profile or test configuration, because silently applying emulator addresses on hardware can create incorrect routing and misleading readiness.

### AArch64 QEMU defaults

The AArch64 reactor initializes discovered VirtIO and seeds the same QEMU address, gateway, and DNS values with the device MAC. The seed path does not immediately establish the same interface-ready state used by the x86 compatibility path.

This target-specific behavior should be replaced by one configuration policy after backend initialization. QEMU defaults belong in platform configuration, while the stack should consume a validated configuration regardless of architecture.

### DHCP support and active integration

The stack records a DHCP-enabled flag and advertises DHCP in its module documentation, but the reviewed active path seeds fixed QEMU values or accepts static configuration. No complete DHCP discovery, offer validation, request, lease, renewal, conflict detection, or expiry state machine is connected to reactor startup.

DHCP is therefore planned or partial behavior, not active configuration. The documentation should state that limitation until a bounded client runs under reactor ownership with authenticated administrative policy and lease lifecycle tests.

### Link readiness detection

Readiness combines configured addresses with backend MAC and link checks. The x86 compatibility branch can treat a configured E1000 interface as operational even when the direct link helper does not report ready. VirtIO uses its negotiated status feature when available and otherwise assumes link availability after initialization.

This policy is sufficient for emulator startup but does not model link transitions consistently. Link state needs a generation, debounce policy, driver reset signal, and defined effects on routes, requests, TCP connections, TLS sessions, and CapNet peers.

### Network readiness state

The reactor marks NetworkStack ready once configuration and operational link prerequisites pass. The marker is set once and is not visibly cleared by later link loss or configuration invalidation. Callers also use weaker checks, such as nonzero address fields, to decide whether DNS or TCP is usable.

There is no single readiness contract. The future state machine should distinguish driver initialized, link available, address configured, route usable, DNS configured, and externally reachable, then expose the minimum state required by each operation.

### Runtime interrupt enablement

E1000 runtime interrupts are enabled after the reactor obtains stack ownership. The interrupt hook acknowledges the device and increments an atomic pending counter; frame processing occurs later in task context. AArch64 VirtIO currently relies primarily on polling through the reactor rather than an equivalent interrupt path.

The sequencing avoids protocol work in interrupt context, but interrupt registration, masking, reset, and shutdown are not represented by one lifecycle. Each backend needs a common enable, quiesce, acknowledge, and drain contract.

### Reactor startup ordering

The reactor rejects requests until its started flag is set. During startup it initializes or checks the target backend, seeds target-specific configuration, enables runtime link behavior, then publishes the started state and enters its loop.

The started flag indicates that the loop can receive requests, not that the network is fully usable. Callers need a typed startup and readiness result instead of relying on static strings and repeated information requests.

### Initialization failure rollback

E1000 constructs a driver locally and publishes it only after initialization succeeds, which limits partial global publication. VirtIO performs device status and queue setup before publishing its global object, but queue setup failures can leave the hardware in a partially negotiated state. Wi-Fi and compatibility initialization report errors without one cross-component rollback.

The subsystem lacks a transaction that quiesces interrupts, resets hardware, releases DMA resources, clears readiness, and invalidates dependent state after any initialization failure.

### Reinitialization behavior

Global drivers and the reactor do not expose a supported reinitialization contract. Recalling driver initialization can replace global state, while the reactor and protocol tables may continue to reference assumptions from the previous device generation.

Reinitialization should be rejected unless the network has entered a quiesced state. A future reset transaction must assign a new backend generation and either migrate or terminate every dependent object.

### Device removal and reset behavior

The code checks some hardware reset and link conditions, but it does not implement hot removal or a subsystem-wide reset notification. Static DMA memory and global driver objects assume a device remains present after successful boot initialization.

Device loss can therefore leave the reactor operational while transmission fails and connections remain allocated. The backend contract needs a terminal device-lost event, protocol cleanup, request cancellation, and controlled reprobe.
## Network Interface Abstraction Audit

### Network interface trait contract

NetworkInterface defines send, nonblocking receive, MAC lookup, and link status with an associated fixed packet type. E1000 implements it, but NetworkStack does not store or call a trait object. The contract is descriptive rather than the active dispatch mechanism.

The trait should either become the actual backend boundary or be removed. Keeping an unused abstraction creates false confidence that drivers are substitutable.

### Send-frame semantics

The trait returns success or a static error, while RTL8139 returns a Boolean and VirtIO uses its own static errors. The contract does not define ownership after failure, queueing, completion, minimum frame padding, maximum length, retryability, or whether success means descriptor publication or wire transmission.

A common send result must distinguish accepted, completed, temporarily full, device lost, invalid frame, and authorization failure.

### Receive-frame semantics

The trait describes nonblocking receive into a caller buffer. E1000 returns a typed length result, RTL8139 uses zero for absence and failure, and VirtIO has polling callbacks plus a separate truncating receive helper.

The interface does not define whether a too-small buffer preserves or discards a frame. A mature contract needs explicit absence, required length, malformed descriptor, device fault, and ownership transition results.

### Link-state semantics

Each driver reports link differently. E1000 reads hardware status, RTL8139 reads its media status register, and VirtIO uses the negotiated status feature or assumes link up when that feature is absent.

The Boolean interface loses unknown, initializing, down, reset, and removed states. It also carries no generation or transition event for invalidating higher-level state.

### MAC-address reporting

The trait returns a MAC value unconditionally, while global helpers use optional results or all-zero fallback values. E1000 validates a cached address, VirtIO may return zeros when the feature is absent, and target defaults can supply an emulator value before hardware identity is established.

MAC reporting should reject zero, broadcast, and invalid addresses and identify whether the value came from hardware, platform configuration, or a generated local address.

### Runtime backend dispatch

Runtime dispatch is not implemented through NetworkInterface. Architecture conditionals call E1000 globals on non-AArch64 targets and VirtIO globals on AArch64. RTL8139 and Wi-Fi do not become common stack backends.

One selected backend handle should replace concrete helper branches. Selection must occur once under initialization authority and remain generation-bound until a controlled reset.

### Driver capability differences

The drivers differ in interrupt support, polling, batching, queue depth, link reporting, DMA assumptions, error types, and capability-aware helpers. The current abstraction exposes only the smallest common operations and does not advertise optional features.

Feature differences should be represented as backend metadata used by policy, not inferred from architecture or concrete type checks.

### Error normalization across drivers

Driver errors use static strings, Booleans, zero lengths, and silent no-device fallbacks. These forms merge temporary queue pressure, absence, invalid input, timeout, reset, and hardware failure.

The backend boundary needs one typed error taxonomy with stable retry and recovery classifications. Human-readable strings should remain formatting only.

### Polled and interrupt-driven operation

The reactor both polls NetworkStack and processes E1000 interrupt bursts. VirtIO receive is polled, and RTL8139 exposes polling helpers without common reactor integration. This hybrid approach provides progress but can duplicate device checks and consume CPU when idle.

Backends should declare whether they require polling, interrupts, or both, and the reactor should schedule work through one budgeted mechanism.

### Interface replacement and failover

There is no supported replacement or failover operation. Protocol state stores addresses and assumes one backend, while the common helpers choose a concrete global on every call.

Failover requires a new interface generation, address and route reconciliation, cancellation or migration rules, and capability checks for administrative replacement. Until those exist, replacement should fail closed.
## Network Reactor Audit

### Single-owner stack design

The reactor holds the only intended mutable reference to NetworkStack and performs protocol work in task context. This avoids broad stack locking and keeps interrupt handlers small.

The invariant is not type-enforced because the stack and staging arrays are static mutable values and one x86 helper accesses the stack directly to seed defaults. Ownership remains credible only while all call sites follow an undocumented discipline.

### Request slot state machine

The request slot uses four atomic states: idle, claim in progress, pending, and response ready. One caller writes a request, the reactor writes a response, and the caller returns the slot to idle.

The state machine admits only one in-flight request and has no generation counter. A timeout can reset the state while the reactor still holds a reference to the old request, creating a late-completion and slot-reuse hazard.

### Request publication and completion ordering

Acquire and release operations plus an explicit release fence publish request and response memory around state changes. This is a reasonable low-level publication pattern for one producer and one consumer.

The proof is incomplete because UnsafeCell contents, timeout reset, and shared staging arrays participate in the protocol but are not represented by one atomic generation. A formal state table and concurrency tests are required.

### Inline request fallback

The current request function does not execute requests inline. It returns an error when the reactor has not started and otherwise waits for the dedicated task.

The heading reflects an earlier or intended design rather than active behavior. Inline fallback should remain absent because it would violate single ownership unless the reactor explicitly delegated its state.

### Reactor task lifecycle

The scheduler starts a kernel thread whose entry point never returns. The reactor publishes a started flag and loops through request handling, polling, interrupt work, timers, and cooperative yielding.

There is no stopping, failed, quiescing, or restarting state. Task death or panic would leave the started flag and callers without a recovery path.

### IRQ notification path

The platform interrupt route calls the reactor hook, which acknowledges E1000 and increments the pending counter. The reactor later drains frames under the driver lock and parses them after releasing it.

The hook is E1000-specific on non-AArch64 targets and does not carry interrupt cause, backend generation, or overflow evidence. Shared IRQ and reset behavior need an explicit contract.

### Atomic pending-work flags

The pending IRQ counter uses relaxed increments and an acquire-release swap. It coalesces interrupts while preserving evidence that work exists, then re-arms itself when a receive burst reaches the budget.

The counter can wrap and does not distinguish receive, link, transmit, or error causes. Saturating cause bits or bounded counters would produce clearer recovery and diagnostics.

### Receive burst processing

E1000 receive processing copies up to sixty-four frames into static two-kilobyte buffers under one driver lock, then dispatches them without holding that lock. This reduces lock churn and avoids parsing in interrupt context.

Frame lengths come from the driver and are used after the lock is released. The code skips frames shorter than Ethernet headers, but the static buffers and lengths rely on exclusive reactor access rather than encapsulated ownership.

### Receive processing budget

The receive budget is fixed at sixty-four frames and equals the number of burst buffers. Reaching the ceiling increments pending work so the next reactor iteration continues draining.

The budget is bounded but not tied to timer latency, request latency, or observed load. Adaptive budgeting should remain unnecessary until measurements show starvation, but latency counters are needed to make that decision.

### Timer-driven progress

The reactor compares the current scheduler tick with its last processed tick and calls the stack timer once for every missed tick. Timers drive TCP and CapNet retransmission and other protocol maintenance.

A long scheduling delay can trigger an unbounded catch-up loop proportional to missed ticks. Timer processing needs elapsed-time semantics or a capped catch-up policy so delayed execution cannot monopolize the reactor.

### Request fairness

The global slot uses first-successful atomic acquisition. Callers that lose receive Network busy immediately, so scheduling order and retry behavior determine who progresses.

There is no FIFO service, reservation, priority, or starvation measurement. A bounded queue is required once multiple concurrent consumers become part of the supported contract.

### Request cancellation

The request path waits up to five seconds and then writes the global request state directly back to idle. The reactor does not observe a cancellation flag, acknowledge abandonment, or bind its response to a request generation. A DNS lookup or TCP connection attempt can still be executing when the caller releases the slot.

That timeout behavior creates a concrete reuse race. A second caller can claim the idle slot and replace its request while the reactor still holds a shared reference to the previous request. The original reactor operation can then publish a response into storage now associated with another caller. Shared TCP staging buffers introduce the same cross-request risk for timed-out send and receive operations.

Cancellation needs a generation-bearing operation record with separate requested, running, cancelling, completed, and abandoned states. Only the reactor should return a slot to reusable state. Operation-specific policy must also decide whether cancellation closes a newly allocated connection, preserves received data, removes retransmission state, and records a terminal audit event.

### Reactor shutdown and restart

The reactor has no shutdown or restart API. It assumes a boot-lifetime task, backend, stack, and staging allocation.

This is acceptable for early boot operation but incompatible with device reset, module recovery, controlled shutdown, or temporal replay isolation. A quiesce transaction is needed before restart can be supported.

### Static send and receive staging buffers

DNS, UDP, TCP, burst receive, and reactor TCP transfer paths use static staging arrays to avoid large kernel task stacks. Fixed storage makes memory use predictable.

The arrays are accessed through unsafe references and are safe only under single-owner and single-request assumptions. They should be fields of the reactor state so Rust borrowing enforces exclusivity.

### Shared mutable state safety

The reactor stores its request and response in UnsafeCell, marks the container as Sync manually, and keeps NetworkStack, TCP staging, and receive burst storage in static mutable arrays. The intended safety rule is one reactor owner and one in-flight request, but the type system does not encode either condition.

The implementation already has an exception to sole ownership: the x86 QEMU seeding helper obtains a mutable reference to the global stack outside the reactor loop. Caller-side TCP send also writes the global transmit staging array, and TCP receive reads global staging after completion. The timeout race can overlap those accesses with a reused slot.

The safe shape is one private reactor state containing the stack, request queue, responses, and all staging buffers. Other contexts should communicate through owned bounded messages. Driver DMA globals require a separate ownership proof because a mutex protects CPU access but does not establish when the device may read or write the same memory.

### Stack-size constraints

Large packet and protocol buffers were deliberately moved to static storage because kernel task stacks are small. This prevents immediate stack overflow in DNS, TCP, and receive burst paths.

The implementation does not publish a measured worst-case stack bound. Parser locals, nested protocol calls, logging, and cryptography still need target-specific stack analysis.

### Temporal replay requests

Temporal replay submits listener, connection, and network configuration mutation requests through the reactor. This preserves reactor ownership during restoration and validates selected field widths before request construction.

Replay requests do not carry an authenticated replay capability, snapshot epoch, transaction identifier, or rollback context. Objects can become visible incrementally if a later restoration step fails.

### Reactor deadlock and starvation risks

The reactor avoids holding the NIC lock while parsing and yields when idle. These choices reduce obvious lock inversion and CPU monopolization.

Long synchronous DNS or TCP dispatch, timer catch-up, a full request slot, driver spin waits, and callers waiting on the same scheduling domain can still delay progress. The code lacks lock-order assertions, latency metrics, and deterministic interleaving tests.
## Ethernet Frame Audit

### Ethernet header parsing

The audit of ethernet header parsing follows the active data and control path rather than module comments. The active dispatcher accepts Ethernet frames from the selected driver, rejects frames shorter than fourteen bytes, and dispatches only ARP and IPv4 EtherTypes. E1000 strips the frame check sequence, while VLAN parsing and a common receive policy are not implemented. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

The parser treats the Ethernet header as an admission gate rather than a full link-layer policy engine. It proves that the destination and source fields can be read safely, then hands the payload to higher protocols. It does not yet return a structured reason for unsupported EtherTypes, local-address mismatch, multicast policy, or driver-level truncation, so the reactor cannot distinguish harmless background traffic from malformed or suspicious input.

### Source and destination MAC validation

source and destination mac validation is implemented only to the extent supported by the section evidence. The active dispatcher accepts Ethernet frames from the selected driver, rejects frames shorter than fourteen bytes, and dispatches only ARP and IPv4 EtherTypes. E1000 strips the frame check sequence, while VLAN parsing and a common receive policy are not implemented. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

The driver path can admit frames beyond the local unicast address, especially where promiscuous receive is enabled for development convenience. That makes MAC filtering a backend and policy question, not a parser detail. The stack should eventually record whether a frame was local unicast, broadcast, multicast, or promiscuously observed before any protocol handler updates ARP, TCP, DNS, or CapNet state.

### EtherType dispatch

ethertype dispatch is implemented only to the extent supported by the section evidence. The active dispatcher accepts Ethernet frames from the selected driver, rejects frames shorter than fourteen bytes, and dispatches only ARP and IPv4 EtherTypes. E1000 strips the frame check sequence, while VLAN parsing and a common receive policy are not implemented. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

Dispatch is deliberately narrow, which is a reasonable early-kernel choice. The missing piece is not support for every EtherType. The missing piece is an explicit unsupported-path result, with counters and rate-limited diagnostics, so later protocol additions do not silently change what traffic reaches privileged state.

### Minimum and maximum frame lengths

The audit of minimum and maximum frame lengths follows the active data and control path rather than module comments. The active dispatcher accepts Ethernet frames from the selected driver, rejects frames shorter than fourteen bytes, and dispatches only ARP and IPv4 EtherTypes. E1000 strips the frame check sequence, while VLAN parsing and a common receive policy are not implemented. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

Minimum-length rejection is present at the Ethernet boundary, but maximum-length policy is split between the driver buffer, the burst staging buffer, and protocol-specific total-length checks. That split is easy to get wrong after a driver change. The supported contract should define one maximum accepted frame size per backend and one packet disposition for oversized, truncated, and multi-descriptor input.

### MTU enforcement

mtu enforcement is implemented only to the extent supported by the section evidence. The active dispatcher accepts Ethernet frames from the selected driver, rejects frames shorter than fourteen bytes, and dispatches only ARP and IPv4 EtherTypes. E1000 strips the frame check sequence, while VLAN parsing and a common receive policy are not implemented. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

Transmit code generally assumes the caller and protocol builder respect the Ethernet payload budget. Receive code accepts whatever the backend presents within its buffer limit. A mature stack needs MTU as a shared interface property so TCP segmentation, UDP send, ARP, ICMP, and driver submission all reject impossible frames before touching device state.

### Broadcast handling

Current support for broadcast handling must be read together with the stated subsystem boundary. The active dispatcher accepts Ethernet frames from the selected driver, rejects frames shorter than fourteen bytes, and dispatches only ARP and IPv4 EtherTypes. E1000 strips the frame check sequence, while VLAN parsing and a common receive policy are not implemented. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

Broadcast is necessary for ARP and some IPv4 behavior, but it is also an amplification and cache-poisoning path. The stack should treat broadcast reception as a packet attribute that later handlers can inspect. ARP replies, ICMP responses, and CapNet control traffic should not inherit the same trust assumptions as traffic addressed directly to the local interface.

### Multicast handling

Current support for multicast handling must be read together with the stated subsystem boundary. The active dispatcher accepts Ethernet frames from the selected driver, rejects frames shorter than fourteen bytes, and dispatches only ARP and IPv4 EtherTypes. E1000 strips the frame check sequence, while VLAN parsing and a common receive policy are not implemented. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

The current stack does not implement a multicast membership model. That is acceptable if multicast is unsupported, but unsupported multicast should be explicit. Otherwise a backend running in a permissive receive mode can feed multicast packets into IPv4 paths without a subscription check or diagnostic trail.

### Promiscuous receive behavior

Current support for promiscuous receive behavior must be read together with the stated subsystem boundary. The active dispatcher accepts Ethernet frames from the selected driver, rejects frames shorter than fourteen bytes, and dispatches only ARP and IPv4 EtherTypes. E1000 strips the frame check sequence, while VLAN parsing and a common receive policy are not implemented. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

Promiscuous mode is useful while bringing up a driver, but it changes the threat model. The stack sees traffic that was not addressed to the host and may update caches or counters from it. Production support should either disable promiscuous receive by default or tag those frames so higher layers can refuse state changes derived from observed-only traffic.

### VLAN and tagged-frame support

The audit of vlan and tagged-frame support follows the active data and control path rather than module comments. The active dispatcher accepts Ethernet frames from the selected driver, rejects frames shorter than fourteen bytes, and dispatches only ARP and IPv4 EtherTypes. E1000 strips the frame check sequence, while VLAN parsing and a common receive policy are not implemented. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

Tagged frames are currently unsupported rather than partially supported. The risk is accidental interpretation: a tagged IPv4 packet has a different EtherType at the outer header, so it should be dropped as unsupported with a clear counter. Support should only be added with an explicit VLAN policy, per-interface membership, and tests for stacked or malformed tags.

### Frame padding and checksum handling

For frame padding and checksum handling, the relevant behavior is distributed across the implementation described here. The active dispatcher accepts Ethernet frames from the selected driver, rejects frames shorter than fourteen bytes, and dispatches only ARP and IPv4 EtherTypes. E1000 strips the frame check sequence, while VLAN parsing and a common receive policy are not implemented. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

Padding belongs to Ethernet framing and should not become application data by accident. The current code relies on higher-level total-length fields to bound IPv4 payload interpretation, which is the right direction. The missing audit evidence is a cross-driver rule for whether frame check sequence bytes, padding, and descriptor status are removed or reported before protocol parsing begins.

### Malformed frame rejection

Current support for malformed frame rejection must be read together with the stated subsystem boundary. The active dispatcher accepts Ethernet frames from the selected driver, rejects frames shorter than fourteen bytes, and dispatches only ARP and IPv4 EtherTypes. E1000 strips the frame check sequence, while VLAN parsing and a common receive policy are not implemented. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

Malformed rejection is presently a local safety property, not a full observability property. The stack avoids reading below the Ethernet header, but unsupported, truncated, wrong-destination, tagged, and backend-error frames do not all produce distinct outcomes. That distinction matters once the kernel needs rate limits, intrusion evidence, or automated device recovery.

## ARP Audit

### ARP request generation

For arp request generation, the relevant behavior is distributed across the implementation described here. NetworkStack implements request and reply construction, a fixed sixteen-entry direct-mapped cache, gateway resolution, and tick-based waits. Entries have no authenticated neighbor identity, robust expiry policy, or collision chain. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### ARP reply generation

The review treats arp reply generation as a distinct contract within this section. NetworkStack implements request and reply construction, a fixed sixteen-entry direct-mapped cache, gateway resolution, and tick-based waits. Entries have no authenticated neighbor identity, robust expiry policy, or collision chain. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### ARP packet validation

The receive path accepts any packet of at least twenty-eight bytes as an ARP packet. It reads the opcode, sender hardware address, sender protocol address, and target protocol address at fixed offsets, but it does not validate the Ethernet and IPv4 hardware types, address lengths, supported opcode, target hardware address, or consistency between the Ethernet source and ARP sender address.

The sender mapping enters the cache before the opcode or target address receives any policy check. An unknown opcode, a reply directed at another host, or a packet with inconsistent link-layer identity can therefore alter neighbor state. Bounds safety exists for the fields that are read, but protocol validity and authority over the claimed address do not.

### ARP cache structure

The review treats arp cache structure as a distinct contract within this section. NetworkStack implements request and reply construction, a fixed sixteen-entry direct-mapped cache, gateway resolution, and tick-based waits. Entries have no authenticated neighbor identity, robust expiry policy, or collision chain. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Cache hashing and collision behavior

For cache hashing and collision behavior, the relevant behavior is distributed across the implementation described here. NetworkStack implements request and reply construction, a fixed sixteen-entry direct-mapped cache, gateway resolution, and tick-based waits. Entries have no authenticated neighbor identity, robust expiry policy, or collision chain. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Cache replacement policy

For cache replacement policy, the relevant behavior is distributed across the implementation described here. NetworkStack implements request and reply construction, a fixed sixteen-entry direct-mapped cache, gateway resolution, and tick-based waits. Entries have no authenticated neighbor identity, robust expiry policy, or collision chain. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Cache lifetime and expiry

For cache lifetime and expiry, the relevant behavior is distributed across the implementation described here. NetworkStack implements request and reply construction, a fixed sixteen-entry direct-mapped cache, gateway resolution, and tick-based waits. Entries have no authenticated neighbor identity, robust expiry policy, or collision chain. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Gateway resolution

gateway resolution is implemented only to the extent supported by the section evidence. NetworkStack implements request and reply construction, a fixed sixteen-entry direct-mapped cache, gateway resolution, and tick-based waits. Entries have no authenticated neighbor identity, robust expiry policy, or collision chain. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Resolution timeout behavior

The audit of resolution timeout behavior follows the active data and control path rather than module comments. NetworkStack implements request and reply construction, a fixed sixteen-entry direct-mapped cache, gateway resolution, and tick-based waits. Entries have no authenticated neighbor identity, robust expiry policy, or collision chain. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Concurrent resolution requests

The audit of concurrent resolution requests follows the active data and control path rather than module comments. NetworkStack implements request and reply construction, a fixed sixteen-entry direct-mapped cache, gateway resolution, and tick-based waits. Entries have no authenticated neighbor identity, robust expiry policy, or collision chain. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### ARP spoofing and poisoning resistance

The ARP cache trusts the sender address pair in every minimally sized ARP packet and stores it in a direct-mapped sixteen-entry table. No pending-resolution record, interface binding, freshness state, duplicate-address detection, or conflict policy limits which packets may replace an existing mapping.

This permits an on-link sender to redirect gateway or peer traffic by announcing a chosen IPv4-to-MAC association. Cache collisions also let unrelated addresses evict one another, so poisoning and ordinary contention are indistinguishable. Capability checks on local network operations do not defend this boundary because the untrusted claim arrives from the network before a local principal is involved.

### Gratuitous ARP handling

gratuitous arp handling is implemented only to the extent supported by the section evidence. NetworkStack implements request and reply construction, a fixed sixteen-entry direct-mapped cache, gateway resolution, and tick-based waits. Entries have no authenticated neighbor identity, robust expiry policy, or collision chain. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

## IPv4 Audit

### IPv4 header parsing

The review treats ipv4 header parsing as a distinct contract within this section. The stack parses conventional IPv4 headers and routes ICMP, UDP, and TCP locally. Fragment reassembly, IP options, a general routing table, and a documented broadcast or multicast policy are absent. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Header-length validation

For header-length validation, the relevant behavior is distributed across the implementation described here. The stack parses conventional IPv4 headers and routes ICMP, UDP, and TCP locally. Fragment reassembly, IP options, a general routing table, and a documented broadcast or multicast policy are absent. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Total-length validation

The IPv4 parser rejects a declared total length greater than the received frame payload, then slices transport data from the computed header length through the declared total. It does not reject a total length smaller than the header length. In that case the later range from header length to total length is inverted and can panic in kernel context.

The parser also does not verify the IPv4 version, header checksum, or fragment flags before transport dispatch. A fragment can therefore be interpreted as a complete TCP or UDP segment, and packets with options are accepted based only on their header length without validating option structure.

Ingress validation must establish version four, a header length within the frame, total length greater than or equal to that header, a valid checksum, an explicit fragmentation policy, and an accepted destination before any transport slice is formed. Rejection should increment a bounded reason counter rather than disappear through the top-level ignored result.

### Version validation

For version validation, the relevant behavior is distributed across the implementation described here. The stack parses conventional IPv4 headers and routes ICMP, UDP, and TCP locally. Fragment reassembly, IP options, a general routing table, and a documented broadcast or multicast policy are absent. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Header checksum verification

IPv4 transmission computes a header checksum, but receive never verifies it. The parser trusts version-independent header bytes, source and destination addresses, protocol, header length, and total length before dispatching transport payloads. A corrupted header can therefore select the wrong transport parser or alter addressing without rejection. Checksum verification must cover exactly the declared header, including options, before any field drives policy or state.

### Source and destination address policy

Current support for source and destination address policy must be read together with the stated subsystem boundary. The stack parses conventional IPv4 headers and routes ICMP, UDP, and TCP locally. Fragment reassembly, IP options, a general routing table, and a documented broadcast or multicast policy are absent. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Local-address detection

Current support for local-address detection must be read together with the stated subsystem boundary. The stack parses conventional IPv4 headers and routes ICMP, UDP, and TCP locally. Fragment reassembly, IP options, a general routing table, and a documented broadcast or multicast policy are absent. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Gateway routing

The review treats gateway routing as a distinct contract within this section. The stack parses conventional IPv4 headers and routes ICMP, UDP, and TCP locally. Fragment reassembly, IP options, a general routing table, and a documented broadcast or multicast policy are absent. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Time-to-live handling

time-to-live handling is implemented only to the extent supported by the section evidence. The stack parses conventional IPv4 headers and routes ICMP, UDP, and TCP locally. Fragment reassembly, IP options, a general routing table, and a documented broadcast or multicast policy are absent. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Fragmentation and reassembly support

The IPv4 receive path does not inspect the flags and fragment-offset field. It passes every accepted packet payload directly to TCP or UDP as though it begins with a complete transport header. Noninitial fragments can therefore be misparsed as fresh transport segments, while overlapping and incomplete fragment sets have no lifecycle or memory policy. Until bounded reassembly exists, all fragmented packets should be rejected before transport dispatch.

### IP option handling

The IPv4 path recognizes the declared header length, but it does not implement an option parser or an option policy. Packets with options therefore occupy a risky middle ground: they can influence where the transport payload begins, while the option bytes themselves are not interpreted, rejected, or counted as unsupported.

The parser accepts a header length larger than the base IPv4 header but does not validate option structure or enforce an option policy. If options remain unsupported, packets with options should be rejected before transport dispatch. Accepting them without interpretation creates a misleading middle state where the header length is honored but the semantics that affected routing or security are ignored.

### Broadcast and multicast addressing

Broadcast and multicast addressing are not yet first-class IPv4 admission categories. The stack has local address handling for the conventional path, but it does not publish a policy for directed broadcast, limited broadcast, multicast groups, or packets that arrive through permissive Ethernet receive modes.

Broadcast and multicast should not be treated as ordinary local unicast. They affect amplification, service discovery, and cache behavior. The stack needs an explicit address-class decision before ICMP replies, UDP queue insertion, TCP rejection, or CapNet processing can be considered policy-complete.

### Malformed packet rejection

Malformed IPv4 rejection is spread across local checks rather than one admission object. Header size, total length, checksum, fragment policy, destination class, and transport dispatch should be decided together so later handlers never receive an invalid packet shape.

Malformed IPv4 handling currently mixes safe rejection with silent loss and a few paths that can still form invalid slices. The goal should be a single IPv4 admission function that returns a validated packet object. Transport handlers should never see a packet whose version, checksum, header length, total length, destination class, and fragmentation policy have not already been resolved.

## ICMP Audit

### Echo request handling

Echo request handling is the ICMP path that matters most during bring-up. It proves that ingress, IPv4 parsing, ICMP parsing, reply construction, ARP resolution, and transmit can cooperate. The implementation should keep that scope explicit rather than implying a complete ICMP control-plane implementation.

Echo support is useful for bring-up because it proves receive, parse, reply construction, ARP, and transmit all work together. It should remain narrow until rate limiting and destination policy exist. A kernel that replies to every valid echo request can become an amplifier even when all memory accesses are safe.

### Echo reply generation

For echo reply generation, the relevant behavior is distributed across the implementation described here. ICMP support is centered on echo traffic and checksum construction. The code does not provide a complete error-message model, rate limiter, or per-source abuse accounting. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### ICMP checksum validation

ICMP checksum validation is the integrity gate for type, code, identifier, sequence, and payload. A bad checksum should prevent reply generation and should be counted separately from unsupported type or rate-limited traffic.

Checksum validation is the minimum integrity check before the stack trusts ICMP type, code, identifier, sequence, or payload. Echo handling should reject bad checksums before deciding whether to reply. Diagnostics should count checksum failure separately from unsupported type and rate-limited traffic.

### Error-message handling

ICMP error-message handling is not a completed transport feedback path. That conservative posture is safer than partially trusting hostile error packets, but it means TCP, UDP, and DNS do not yet receive structured path failure evidence from ICMP.

ICMP errors are not just notifications; they can influence TCP, UDP, DNS, and path discovery behavior. Ignoring them is safer than partially trusting them, but the documentation should say that clearly. If error handling is added, it needs connection matching, quote validation, source policy, and rate limits before mutating transport state.

### Rate limiting

ICMP rate limiting is not yet enforced at the response decision. The parser can bound memory use and still permit excessive outbound work if every valid echo request receives a reply.

Rate limiting belongs at the response decision, not only in logging. The stack needs to decide how many ICMP replies it will emit per source, per destination class, and per time window. Without that gate, a remote sender can turn valid parsing into unbounded outbound work.

### Amplification resistance

Amplification resistance depends on destination class, response size, source behavior, and rate policy. The current echo-centered implementation does not yet publish that policy, so it should be treated as a bring-up feature rather than an Internet-facing ICMP service.

Amplification resistance requires more than bounding packet size. Replies should never exceed the request class policy, should avoid broadcast and multicast destinations unless explicitly allowed, and should produce counters when suppressed. This gives operators evidence without allowing the network stack to become a reflector.

### Malformed ICMP rejection

The audit of malformed icmp rejection follows the active data and control path rather than module comments. ICMP support is centered on echo traffic and checksum construction. The code does not provide a complete error-message model, rate limiter, or per-source abuse accounting. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

## UDP Audit

### UDP packet construction

udp packet construction is implemented only to the extent supported by the section evidence. UDP uses bounded packet buffers and an eight-entry receive queue with payloads capped at 512 bytes. DNS and CapNet depend on this path, while queue pressure, checksum policy, and source-port allocation remain limited. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

Construction is bounded and allocation-free in the common path: headers and payload are assembled into fixed staging storage before device submission. That keeps memory pressure predictable. The remaining weakness is not the packet layout; it is that UDP send does not receive one canonical principal, authority, quota, and cancellation context at the final transmit boundary.

### UDP header validation

For udp header validation, the relevant behavior is distributed across the implementation described here. UDP uses bounded packet buffers and an eight-entry receive queue with payloads capped at 512 bytes. DNS and CapNet depend on this path, while queue pressure, checksum policy, and source-port allocation remain limited. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

Header validation protects the obvious length fields, then stores accepted datagrams in the shared receive queue. It should also feed a structured admission result back to the reactor. Without that result, a packet rejected for bad length, unsupported checksum policy, full queue, or stale consumer state disappears as the same kind of absence.

### UDP checksum generation

For udp checksum generation, the relevant behavior is distributed across the implementation described here. UDP uses bounded packet buffers and an eight-entry receive queue with payloads capped at 512 bytes. DNS and CapNet depend on this path, while queue pressure, checksum policy, and source-port allocation remain limited. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### UDP checksum verification

UDP receive validates the minimum header size and checks that the declared datagram length lies between eight bytes and the available IPv4 payload. It then extracts ports and payload without reading or validating the checksum field.

IPv4 permits a zero UDP checksum, but every nonzero checksum must be verified against the pseudo-header, UDP header, and payload. The current path accepts corrupted or forged nonzero-checksum datagrams and passes them to DNS, CapNet, and ordinary receive queues as if integrity had succeeded. CapNet authenticates its own control frames, but DNS and other UDP consumers do not gain equivalent protection.

### Source-port allocation

source-port allocation is implemented only to the extent supported by the section evidence. UDP uses bounded packet buffers and an eight-entry receive queue with payloads capped at 512 bytes. DNS and CapNet depend on this path, while queue pressure, checksum policy, and source-port allocation remain limited. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Receive queue structure

Current support for receive queue structure must be read together with the stated subsystem boundary. UDP uses bounded packet buffers and an eight-entry receive queue with payloads capped at 512 bytes. DNS and CapNet depend on this path, while queue pressure, checksum policy, and source-port allocation remain limited. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

The queue favors fixed memory over throughput, which is the right early-kernel tradeoff. The cost is shared fate. DNS, CapNet, and future UDP consumers contend for the same small pool, so a busy port can create failure that looks like unrelated packet loss unless occupancy and drops are reported per destination.

### Receive queue capacity

For receive queue capacity, the relevant behavior is distributed across the implementation described here. UDP uses bounded packet buffers and an eight-entry receive queue with payloads capped at 512 bytes. DNS and CapNet depend on this path, while queue pressure, checksum policy, and source-port allocation remain limited. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Port matching behavior

For port matching behavior, the relevant behavior is distributed across the implementation described here. UDP uses bounded packet buffers and an eight-entry receive queue with payloads capped at 512 bytes. DNS and CapNet depend on this path, while queue pressure, checksum policy, and source-port allocation remain limited. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

The receive path preserves datagrams for other destination ports instead of letting one reader drain all UDP traffic. That is a useful correctness property. It is not an availability policy, because preserved datagrams still occupy global capacity until their owner consumes or expires them.

### Nonmatching datagram preservation

The audit of nonmatching datagram preservation follows the active data and control path rather than module comments. UDP uses bounded packet buffers and an eight-entry receive queue with payloads capped at 512 bytes. DNS and CapNet depend on this path, while queue pressure, checksum policy, and source-port allocation remain limited. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

Preservation should eventually be paired with age and ownership. A stale datagram for one port should not permanently reduce service for every other port. The minimal fix is per-port drop and stale counters before adding more complex queue policy.

### Payload truncation behavior

For payload truncation behavior, the relevant behavior is distributed across the implementation described here. UDP uses bounded packet buffers and an eight-entry receive queue with payloads capped at 512 bytes. DNS and CapNet depend on this path, while queue pressure, checksum policy, and source-port allocation remain limited. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Queue overflow behavior in UDP

UDP uses eight fixed receive slots with payloads capped at 512 bytes. Oversized datagrams and datagrams arriving when every slot is occupied are silently dropped, apart from optional DNS debug output. There is no drop counter, per-port reservation, oldest-entry policy, or backpressure signal. One busy or hostile destination can consume the shared queue and starve DNS or unrelated consumers.

### CapNet control-port dispatch

The review treats capnet control-port dispatch as a distinct contract within this section. UDP uses bounded packet buffers and an eight-entry receive queue with payloads capped at 512 bytes. DNS and CapNet depend on this path, while queue pressure, checksum policy, and source-port allocation remain limited. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

CapNet control traffic is security-sensitive because accepted frames can affect sessions, token offers, revocation, retransmission, and remote leases. UDP should therefore report whether the datagram passed checksum policy and source validation before CapNet reports whether its own frame authentication and replay checks passed.

### UDP denial-of-service resistance

Every checksum-eligible UDP datagram reaches either CapNet processing or the shared receive queue. The path has no per-source or per-port rate limit, no capability-linked receive budget, and no work budget for authenticated CapNet failures. Fixed storage bounds memory but does not bound CPU, logging, queue displacement, or latency. A flood can repeatedly fill all slots and force legitimate datagrams to disappear without observable admission results.

## DNS Audit

### DNS query construction

DNS query construction is intentionally narrow. The resolver builds one bounded A-record question and sends it through UDP with a small retry policy. It does not try to be a general resolver with DNSSEC, multiple outstanding question classes, or broad record support.

The query builder is deliberately small: one question, one A-record target, and bounded name encoding. That is enough for simple bootstrapping. The security problem is that the request identity is weak because the source port is fixed and the transaction identifier is predictable.

### Transaction identifier allocation

DNS initializes its sixteen-bit transaction identifier from low timer bits plus a constant, then increments it sequentially. Queries also use one fixed source port. An observer or on-path sender can predict the next identifier after seeing one query, and an off-path attacker has only a small combined search space. Identifiers and source ports need cryptographic randomization with collision avoidance among outstanding queries.

### Source-port policy

The resolver uses a fixed client source port. That makes response matching depend mostly on a predictable sixteen-bit transaction identifier and the configured server address.

DNS source ports should be part of the response authenticator for this lightweight resolver. A fixed port collapses the search space for forged replies. Randomizing the port is not a substitute for DNSSEC, but it is a cheap hardening step that should happen before the resolver is treated as hostile-network ready.

### Response matching

The UDP queue requires DNS responses to come from the configured server address, port 53, and the fixed client port. The resolver then checks only the transaction identifier before parsing. It does not verify the question name, question type, class, opcode, response bit, or that the response corresponds to the active attempt. A matching forged identifier can therefore answer a different question under the current parser.

### Name encoding

Name encoding is limited to the simple hostname form the kernel currently needs. That is a reasonable constraint, but it should be enforced deliberately through label length, total length, empty-label, and character-policy checks before bytes are placed on the wire.

Name encoding should reject labels that exceed DNS label limits, names that exceed the full wire-name limit, empty labels outside the terminal root, and characters the kernel policy does not intend to send. The current constrained path should keep that contract small. Supporting broader host syntax belongs in a separate URL or resolver normalization layer.

### Compressed-name decoding

DNS parsing skips names using local cursor movement and compression-pointer recognition, but it does not perform a full bounded decompression with loop detection, pointer-depth limits, or canonical name comparison. Compression pointers can target arbitrary offsets in the message, and malformed chains are not represented as a structured parse tree. The implementation should use one checked name walker shared by questions and records.

### Record parsing

Record parsing currently targets the first useful IPv4 answer rather than a complete DNS data model. That keeps the code small, but it also means unsupported records, malformed compression, unexpected classes, and conflicting answers need strict skip or reject behavior.

Record parsing should be strict because accepted answers change where later network traffic goes. The resolver should validate section counts, class, type, owner name, data length, and TTL before selecting an address. Unknown records can be skipped, but skipping must use the same bounded name walker and length checks as accepted records.

### IPv4 answer selection

Current support for ipv4 answer selection must be read together with the stated subsystem boundary. The resolver constructs queries, uses one fixed client source port, matches transaction identifiers, retries twice, and keeps a small negative cache. It does not provide DNSSEC, randomized source ports, a positive cache, or a full compressed-name and record model. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Positive cache behavior

Positive DNS caching is not the current resolver's main optimization path. That is acceptable while response authentication is weak, because caching a forged answer would extend its lifetime.

A missing positive cache is acceptable for correctness but expensive for repeated requests. Adding one before response authenticity improves would make poisoned answers last longer. Positive caching should therefore wait until response matching includes randomized ports, question validation, TTL handling, and clear stale-entry removal.

### Negative cache behavior

Negative caching exists as a small availability optimization, but it needs careful error classification. A timeout, malformed packet, server refusal, and authenticated absence should not all suppress future lookups in the same way.

Negative caching changes availability behavior because a transient or forged failure can suppress future lookups. It needs an expiry policy, a reason code, and a way to distinguish timeout, malformed response, refused response, and authenticated absence. Without that distinction, callers cannot know whether retrying is useful.

### Cache expiry

The audit of cache expiry follows the active data and control path rather than module comments. The resolver constructs queries, uses one fixed client source port, matches transaction identifiers, retries twice, and keeps a small negative cache. It does not provide DNSSEC, randomized source ports, a positive cache, or a full compressed-name and record model. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Query retry policy

The review treats query retry policy as a distinct contract within this section. The resolver constructs queries, uses one fixed client source port, matches transaction identifiers, retries twice, and keeps a small negative cache. It does not provide DNSSEC, randomized source ports, a positive cache, or a full compressed-name and record model. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Response timeout

Current support for response timeout must be read together with the stated subsystem boundary. The resolver constructs queries, uses one fixed client source port, matches transaction identifiers, retries twice, and keeps a small negative cache. It does not provide DNSSEC, randomized source ports, a positive cache, or a full compressed-name and record model. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Stale response removal

For stale response removal, the relevant behavior is distributed across the implementation described here. The resolver constructs queries, uses one fixed client source port, matches transaction identifiers, retries twice, and keeps a small negative cache. It does not provide DNSSEC, randomized source ports, a positive cache, or a full compressed-name and record model. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Malformed response handling

The DNS parser checks the minimum header, response code, answer count, and selected record bounds, but it accepts an incomplete header policy and returns static strings for all malformed classes. It does not validate the response bit, opcode, reserved flags, declared question count against the active query, or complete section traversal. Rejected packets do not expose stable reason counters, making parser faults and spoofing attempts operationally indistinguishable.

### Spoofed response resistance

Source address and port checks provide a useful first filter, but DNS authentication still rests on a predictable sixteen-bit identifier and fixed client port. The parser does not bind the echoed question to the requested name and has no DNSSEC or authenticated resolver channel. Capabilities authorize who may request resolution locally; they do not authenticate remote DNS data. The current resolver is vulnerable to forged replies that win the race.

### Resolver readiness requirements

The audit of resolver readiness requirements follows the active data and control path rather than module comments. The resolver constructs queries, uses one fixed client source port, matches transaction identifiers, retries twice, and keeps a small negative cache. It does not provide DNSSEC, randomized source ports, a positive cache, or a full compressed-name and record model. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

## TCP Audit

### Connection table structure

The TCP connection table is fixed at sixteen live records. That makes memory use predictable, but it also makes exhaustion cheap and deterministic. The table stores connection state, sequence accounting, receive buffers, retransmission metadata, and ownership-adjacent information, so allocation must eventually be tied to a principal and quota rather than first free slot.

### Listener table structure

The listener table is smaller than the connection table and uses fixed backlog storage. That is appropriate for a kernel stack with explicit capacity goals. The missing contract is admission: which principal may bind which port, how backlog entries are charged, and what happens when a listener is revoked or the owning process exits.

### Accept backlog

Accept backlog storage is bounded, but it is not protected by a SYN-cookie, per-source, or per-principal admission policy. Half-open and pending accepted connections can therefore consume scarce records before the application has a chance to drain them.

### Connection identifier allocation

Connection identifiers are small table-derived handles. Without a generation, a stale identifier can refer to a different connection after cleanup and reuse. The handle space should include a generation or opaque token before it becomes a stable userspace or service-facing ABI.

### Active open

Active open allocates connection state, chooses local sequencing, sends SYN traffic, and waits for the peer to answer. That operation should be cancellable and authority-bound because it can hold scarce table entries while the remote network is slow or hostile.

### Passive open

Passive open accepts unauthenticated remote SYN traffic and converts it into kernel state. That makes it the main TCP denial-of-service boundary. It needs separate accounting from established connections and a clear rule for backlog overflow, retransmission, and listener ownership.

### TCP state transitions

TCP state transitions are implemented for the common connection lifecycle, but they are not yet governed by one complete segment-acceptability function. State changes still depend on scattered flag, sequence, acknowledgement, and buffer checks. That structure makes it easy for rare flag combinations to bypass the intended policy.

### Sequence and acknowledgement validation

TCP performs only narrow sequence checks. In established state it accepts an acknowledgement whenever it is numerically greater than the oldest unacknowledged sequence, then assigns that value directly to the send state. It does not reject acknowledgements beyond the next sequence actually sent, and handshake transitions do not consistently require the exact acknowledgement expected for the SYN.

Receive data is accepted only when its sequence equals the next expected byte, but FIN processing and acknowledgement updates are not governed by a complete segment-acceptability test. A peer can therefore advance sender accounting with an impossible acknowledgement or drive state transitions with fields that would be rejected by a conforming TCP implementation.

### Receive-window accounting

The connection advertises free space from a fixed receive buffer and copies only the portion of an in-order segment that fits. It nevertheless advances the next receive sequence by the full payload length, including bytes that were not stored.

This acknowledges data the application can never read and permanently creates a hole between protocol state and buffered state. The implementation also lacks a zero-window recovery contract and does not derive segment acceptance from the advertised window. Fixed capacity bounds memory, but the current overflow behavior violates reliable byte-stream semantics.

### Window scaling

Window scaling is present as selected option handling, but it is not yet part of a complete receive-window contract. The stack must ensure that advertised windows, buffered bytes, accepted segments, and acknowledged bytes never disagree.

### Maximum segment size negotiation

Maximum segment size negotiation should decide how large a TCP payload the stack will transmit over the current path MTU. Today it is best read as partial option support, not a full path-MTU or segmentation policy.

### SYN option parsing

SYN option parsing is the only chance to negotiate several connection-wide assumptions before state is established. Unknown or malformed options should not create partially initialized connection metadata. Parsing should produce a normalized option record before any listener or connection table update depends on it.

### Payload receive buffering

Payload receive buffering uses fixed per-connection storage. That bounds memory, but the overflow behavior currently matters more than the capacity. The stack must not acknowledge bytes that were not actually stored for the application.

### Send segmentation

Send segmentation should be driven by peer MSS, local MTU, available window, and retransmission state. The current fixed-buffer approach is a workable bring-up path, but it should not be described as a complete segmentation strategy until those inputs are unified.

### Retransmission state

Retransmission state exists, but it is not yet tied to congestion control, revocation, or per-connection work budgets. A hostile peer can force repeated timer work even when memory remains bounded.

### Retransmission timeout policy

Retransmission timeout policy decides how long the kernel will spend trying to complete remote work. It should expose terminal failure distinctly from temporary delay, and it should stop immediately when the owning authority is revoked.

### Delayed acknowledgement policy

Delayed acknowledgement reduces reply traffic, but it also changes latency and retransmission behavior. The policy should be measured and bounded so receive bursts cannot defer acknowledgements long enough to trigger avoidable retransmissions.

### Duplicate and out-of-order segments

The receive path processes payload only when the segment sequence exactly equals the next expected sequence. Earlier duplicates and later out-of-order segments are silently discarded, with no reassembly queue, overlap policy, selective acknowledgement, or explicit duplicate acknowledgement strategy.

Dropping out-of-order data is a valid constrained design only if the stack reliably emits cumulative acknowledgements that prompt retransmission and handles FIN and overlapping data consistently. The current code does not define those guarantees, so reordering can cause avoidable stalls and crafted overlaps can exercise state transitions that lack a single normalization rule.

### FIN handling

FIN handling is a lifecycle boundary, not just another flag check. It should preserve unread data, report end-of-stream exactly once, and distinguish remote half-close from local close.

### Reset handling

Reset handling must be conservative because a spoofed reset can tear down a live connection. The stack should only accept resets that pass checksum, tuple, sequence-window, and state checks, and it should report reset separately from timeout or orderly close.

### Half-closed connections

Half-closed connections require the send and receive sides to progress independently. The public API needs to expose that distinction instead of collapsing it into generic closed or failed states.

### End-of-stream reporting

End-of-stream reporting should be a stable receive outcome. Returning an empty read, a closed error, and a temporary absence must not mean the same thing.

### Time-wait handling

Time-wait protects new connections from old duplicate segments. The small fixed connection table makes that state expensive, but skipping it entirely risks tuple reuse confusion.

### Connection cleanup

Connection cleanup must release table slots, retransmission records, receive buffers, listener backlog references, diagnostics, and ownership records as one generation change.

### Port reuse and collision handling

Port reuse and collision handling decide whether two sockets can claim overlapping local identities. The current small-table design needs explicit rules for active opens, listeners, time-wait state, and process ownership before ports become stable public resources.

### TCP checksum validation

TCP transmission constructs a checksum over the IPv4 pseudo-header, TCP header, and payload. The receive path parses segments without recomputing that checksum and therefore accepts damaged headers, payloads, flags, sequence numbers, and acknowledgements.

This omission sits before the connection lookup and state machine, so every TCP transition depends on unauthenticated transport fields. Link-layer checksums are not a substitute because they may be absent, offloaded, or cover a different fault domain. Receive-side checksum validation must precede all connection-state mutation.

### Malformed segment rejection

TCP derives the data offset from the incoming header and checks only that the segment length is not smaller than that value. It does not require a minimum twenty-byte header after conversion, verify reserved bits, reject contradictory flag combinations, or validate checksum and segment acceptability before state mutation. A zero or undersized data offset can cause header bytes to be interpreted as payload.

### Connection exhaustion

TCP has sixteen connection records, four listeners, and fixed accept backlogs. Allocation scans for a free record and returns a generic failure when full. Half-open passive connections consume the same table as established connections, with no per-principal quota, SYN backlog separation, eviction policy, or capability reservation. A small number of incomplete handshakes can deny all further local and remote connections.

### TCP denial-of-service resistance

The stack lacks SYN cookies, handshake rate limits, per-source accounting, retransmission work budgets, and a bounded malformed-segment response policy. Fixed tables cap memory but make exhaustion cheap and deterministic. Attack traffic can also amplify CPU through repeated lookup, acknowledgement, and retransmission activity. Network capabilities constrain local callers but do not limit unauthenticated peers reaching listeners.

## HTTP Client and Server Audit

### URL parsing

For url parsing, the relevant behavior is distributed across the implementation described here. The compatibility client parses URLs and HTTP/1.1 responses over reactor TCP, while NetworkStack contains a small HTTP server. Buffer limits are explicit, but parsing, redirects, message framing, and ambiguity handling cover only a constrained subset. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

The client should be read as a constrained kernel fetch helper, not a general URL library. It is reasonable to support only simple HTTP URLs while the transport is still hardening. Broader URL semantics such as percent-decoding, IPv6 literals, userinfo, path normalization, and proxy behavior should stay out until a caller needs them and tests define the exact contract.

### Scheme and port handling

The review treats scheme and port handling as a distinct contract within this section. The compatibility client parses URLs and HTTP/1.1 responses over reactor TCP, while NetworkStack contains a small HTTP server. Buffer limits are explicit, but parsing, redirects, message framing, and ambiguity handling cover only a constrained subset. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

HTTPS is intentionally rejected by the compatibility client because strict validation is unavailable in that path. That fail-closed behavior should remain. The separate TLS module must not be used as evidence that public HTTPS is supported until it shares the reactor TCP path and enforces certificate and hostname policy.

### Host and path encoding

The review treats host and path encoding as a distinct contract within this section. The compatibility client parses URLs and HTTP/1.1 responses over reactor TCP, while NetworkStack contains a small HTTP server. Buffer limits are explicit, but parsing, redirects, message framing, and ambiguity handling cover only a constrained subset. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Request construction

The review treats request construction as a distinct contract within this section. The compatibility client parses URLs and HTTP/1.1 responses over reactor TCP, while NetworkStack contains a small HTTP server. Buffer limits are explicit, but parsing, redirects, message framing, and ambiguity handling cover only a constrained subset. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Header-size limits

The audit of header-size limits follows the active data and control path rather than module comments. The compatibility client parses URLs and HTTP/1.1 responses over reactor TCP, while NetworkStack contains a small HTTP server. Buffer limits are explicit, but parsing, redirects, message framing, and ambiguity handling cover only a constrained subset. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

The current limits protect kernel memory, but they do not yet give callers enough information to recover. A response can fail because the header is too large, the body is too large, the connection closed early, or the framing is unsupported. Those need different errors before fetch, shell, or WASM callers can make correct retry decisions.

### Status-line parsing

For status-line parsing, the relevant behavior is distributed across the implementation described here. The compatibility client parses URLs and HTTP/1.1 responses over reactor TCP, while NetworkStack contains a small HTTP server. Buffer limits are explicit, but parsing, redirects, message framing, and ambiguity handling cover only a constrained subset. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Content-length parsing

For content-length parsing, the relevant behavior is distributed across the implementation described here. The compatibility client parses URLs and HTTP/1.1 responses over reactor TCP, while NetworkStack contains a small HTTP server. Buffer limits are explicit, but parsing, redirects, message framing, and ambiguity handling cover only a constrained subset. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

Content length is the value that turns a stream into a bounded body copy. The parser should reject duplicate, conflicting, overflowing, negative, or whitespace-ambiguous values before the body is trusted. Until that is tested, the client should accept only the simple form it can prove.

### Chunked transfer detection

The audit of chunked transfer detection follows the active data and control path rather than module comments. The compatibility client parses URLs and HTTP/1.1 responses over reactor TCP, while NetworkStack contains a small HTTP server. Buffer limits are explicit, but parsing, redirects, message framing, and ambiguity handling cover only a constrained subset. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Chunked body decoding

Current support for chunked body decoding must be read together with the stated subsystem boundary. The compatibility client parses URLs and HTTP/1.1 responses over reactor TCP, while NetworkStack contains a small HTTP server. Buffer limits are explicit, but parsing, redirects, message framing, and ambiguity handling cover only a constrained subset. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

Chunked transfer is best treated as unsupported until it has a bounded state machine. Supporting it correctly means handling split chunk headers, extensions, trailers, oversized chunks, zero-length termination, and early close. A precise unsupported-framing error is safer than a partial decoder.

### Response body capacity

response body capacity is implemented only to the extent supported by the section evidence. The compatibility client parses URLs and HTTP/1.1 responses over reactor TCP, while NetworkStack contains a small HTTP server. Buffer limits are explicit, but parsing, redirects, message framing, and ambiguity handling cover only a constrained subset. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Connection-close behavior

Current support for connection-close behavior must be read together with the stated subsystem boundary. The compatibility client parses URLs and HTTP/1.1 responses over reactor TCP, while NetworkStack contains a small HTTP server. Buffer limits are explicit, but parsing, redirects, message framing, and ambiguity handling cover only a constrained subset. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Partial response handling

partial response handling is implemented only to the extent supported by the section evidence. The compatibility client parses URLs and HTTP/1.1 responses over reactor TCP, while NetworkStack contains a small HTTP server. Buffer limits are explicit, but parsing, redirects, message framing, and ambiguity handling cover only a constrained subset. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### HTTP timeout behavior

http timeout behavior is implemented only to the extent supported by the section evidence. The compatibility client parses URLs and HTTP/1.1 responses over reactor TCP, while NetworkStack contains a small HTTP server. Buffer limits are explicit, but parsing, redirects, message framing, and ambiguity handling cover only a constrained subset. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Redirect support

redirect support is implemented only to the extent supported by the section evidence. The compatibility client parses URLs and HTTP/1.1 responses over reactor TCP, while NetworkStack contains a small HTTP server. Buffer limits are explicit, but parsing, redirects, message framing, and ambiguity handling cover only a constrained subset. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### HTTP server listener lifecycle

The audit of http server listener lifecycle follows the active data and control path rather than module comments. The compatibility client parses URLs and HTTP/1.1 responses over reactor TCP, while NetworkStack contains a small HTTP server. Buffer limits are explicit, but parsing, redirects, message framing, and ambiguity handling cover only a constrained subset. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### HTTP server request parsing

http server request parsing is implemented only to the extent supported by the section evidence. The compatibility client parses URLs and HTTP/1.1 responses over reactor TCP, while NetworkStack contains a small HTTP server. Buffer limits are explicit, but parsing, redirects, message framing, and ambiguity handling cover only a constrained subset. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### HTTP server response generation

For http server response generation, the relevant behavior is distributed across the implementation described here. The compatibility client parses URLs and HTTP/1.1 responses over reactor TCP, while NetworkStack contains a small HTTP server. Buffer limits are explicit, but parsing, redirects, message framing, and ambiguity handling cover only a constrained subset. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Malformed HTTP handling

The review treats malformed http handling as a distinct contract within this section. The compatibility client parses URLs and HTTP/1.1 responses over reactor TCP, while NetworkStack contains a small HTTP server. Buffer limits are explicit, but parsing, redirects, message framing, and ambiguity handling cover only a constrained subset. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Protocol smuggling and ambiguity risks

The review treats protocol smuggling and ambiguity risks as a distinct contract within this section. The compatibility client parses URLs and HTTP/1.1 responses over reactor TCP, while NetworkStack contains a small HTTP server. Buffer limits are explicit, but parsing, redirects, message framing, and ambiguity handling cover only a constrained subset. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

Smuggling risk comes from parser disagreement about where a message ends. Even this small HTTP implementation needs one rule for duplicate length headers, transfer encoding, connection-close bodies, and unread bytes after a response. Ambiguous framing should be rejected rather than normalized silently.

## TLS Audit

### TLS implementation boundaries

TLS is not layered over the reactor-owned TCP implementation. It contains its own Ethernet frame builder, IPv4 and TCP checksum code, TCP state machine, retransmission buffers, source-port selection, global address configuration, and session scheduler. On x86 it transmits and receives directly through RTL8139; on AArch64 transmission is compiled into a no-op.

The duplicate transport also repeats defects independently of NetworkStack repairs. Its private TCP parser derives header offsets without complete IPv4 and TCP validation, accepts handshake acknowledgements without the common connection table, chooses source ports and initial sequence values from ticks, and polls one concrete driver. Fixing checksum, sequence, capability, or reset behavior in NetworkStack therefore does not protect TLS until the private transport is removed.

### TLS record framing

TLS record framing exists inside the standalone TLS transport rather than the reactor TCP path. Record parsing, buffering, alerts, and authentication errors therefore do not yet integrate with the common network diagnostics or capability model.

### TLS record size enforcement

The record header carries a sixteen-bit length, while the receive array is smaller than the protocol maximum plus framing. The stream parser waits for the declared total and copies it without first enforcing either the TLS limit or local capacity. Encryption helpers also assume caller output is large enough. Record size must be checked once at ingress and again against each destination buffer before slicing or cryptographic processing.

### Handshake state machine

The TLS handshake state machine recognizes the main message sequence, but authentication-critical transitions are incomplete. It can advance past certificate and certificate-verify stages without proving the peer identity, so it must remain experimental.

### Client hello construction

ClientHello construction is bounded and includes the requested host as server-name input. That only selects the server's virtual identity; it does not authenticate the peer.

### Server hello parsing

ServerHello parsing should lock in the negotiated protocol version, cipher suite, key share, and transcript inputs. The current code is useful as a parser skeleton, but it needs stricter failure outcomes before any negotiated value can be treated as security policy.

### Supported version negotiation

Supported-version negotiation should fail closed on anything outside the implemented TLS 1.3 profile. Compatibility fallback is not useful here because the rest of the authentication path is not release-ready.

### Cipher-suite negotiation

Cipher-suite negotiation must select only suites the record layer, key schedule, transcript hash, and certificate verification paths fully support. Accepting a suite is a promise that every later cryptographic step has matching validation.

### X25519 key exchange

X25519 key exchange provides secrecy only if the random private key is unpredictable and the peer is authenticated. The current time-derived randomness and missing certificate validation mean the exchange should be treated as a cryptographic scaffold, not secure TLS.

### Handshake transcript hashing

Handshake transcript hashing is present, but a transcript hash only helps when every authenticated message is parsed and verified. Until certificate and CertificateVerify validation are real, transcript tracking cannot establish peer identity.

### Traffic secret derivation

Traffic secret derivation follows the TLS 1.3 shape, but its inputs inherit the weaknesses of the current key exchange and authentication path. It should not release application data until peer identity and transcript validation are complete.

### Record encryption and authentication

Record encryption and authentication use AES-GCM style traffic protection, but sequence-number exhaustion, record-size limits, alert behavior, and secret zeroization remain unfinished. Cryptographic framing is not the same as a complete secure channel.

### Certificate message parsing

Certificate message parsing is currently only a state transition point. The implementation does not yet parse the certificate list into bounded DER objects that can feed chain validation and hostname checks.

### Certificate chain validation

Certificate-chain validation is absent from the active handshake. When an encrypted Certificate message arrives in the expected state, the implementation updates the transcript and advances directly to CertificateVerify without parsing the certificate list, decoding X.509, selecting a trust anchor, checking validity time, enforcing key usage, or building a chain.

The following CertificateVerify message is also accepted by state transition alone. Its signature scheme, signed transcript context, public key, and signature are not verified. The server Finished check proves possession of handshake traffic secrets derived from the unauthenticated X25519 exchange, but it does not authenticate which server supplied the key.

The current handshake is therefore vulnerable to an active network attacker and must not be used as authenticated TLS. A mature path needs bounded DER parsing, a kernel trust store, chain construction limits, signature verification, validity and usage policy, revocation policy, and a fail-closed result before application traffic keys become usable.

### Hostname validation

The requested host is copied into session storage and encoded into the ClientHello server-name extension. No later handshake step compares that host with certificate subject alternative names or a common name. IP literals, wildcard labels, case normalization, internationalized names, trailing dots, and embedded null or malformed name encodings have no validation policy.

Sending a server name only selects a virtual host; it does not authenticate that host. Even after certificate-chain validation is added, omitting identity matching would allow any certificate trusted by the kernel store to impersonate any requested service.

Hostname validation should consume the original canonical request identity, not a value supplied by the server or reconstructed after redirects. It must prefer DNS subject alternative names, apply restricted wildcard rules, handle IP address identities separately, and fail before the session reaches Connected.

### Certificate verify validation

The TLS handshake recognizes CertificateVerify in the expected state, appends the message to the transcript, and advances directly to waiting for Finished. It does not parse the signature scheme, extract the signature, construct the TLS 1.3 verification context, or verify the signature with the authenticated certificate public key.

Finished proves possession of handshake traffic secrets, not possession of the private key named by the certificate. Without CertificateVerify validation, the certificate message has no cryptographic binding to the endpoint that completed the key exchange. This remains a critical authentication failure even after certificate-chain and hostname validation are implemented.

### Finished-message validation

The review treats finished-message validation as a distinct contract within this section. The TLS module implements a TLS 1.3-oriented handshake and AES-GCM records over its own static TCP and RTL8139-oriented path. Strict certificate-chain and hostname validation, common-stack integration, secret lifecycle proof, and broad interoperability are incomplete. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Alert handling

The audit of alert handling follows the active data and control path rather than module comments. The TLS module implements a TLS 1.3-oriented handshake and AES-GCM records over its own static TCP and RTL8139-oriented path. Strict certificate-chain and hostname validation, common-stack integration, secret lifecycle proof, and broad interoperability are incomplete. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Application-data buffering

Current support for application-data buffering must be read together with the stated subsystem boundary. The TLS module implements a TLS 1.3-oriented handshake and AES-GCM records over its own static TCP and RTL8139-oriented path. Strict certificate-chain and hostname validation, common-stack integration, secret lifecycle proof, and broad interoperability are incomplete. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Sequence-number exhaustion

TLS traffic keys increment read and write sequence numbers with ordinary addition after each authenticated record. There is no pre-increment exhaustion check, key update, connection close, or error result. In release builds the counter can wrap and reuse an AEAD nonce under the same key, which destroys GCM security. The session must terminate or update keys before the final valid sequence number.

### Session allocation and handle reuse

TLS exposes sessions through small array indices. Freeing a session marks its slot inactive, and a later allocation reuses the same index without a generation. A stale handle can therefore refer to an unrelated new connection. Session access also returns a global mutable reference from an unsynchronized static array, permitting aliases between callers and the global tick loop.

### Session cleanup and secret zeroization

Session cleanup sends a close alert and clears the active flag, but it does not overwrite handshake secrets, traffic keys, transcript state, application data, host data, or TCP buffers. Slot reuse eventually replaces the structure, yet secrets remain resident between free and reuse and may survive diagnostic memory exposure. Cleanup needs explicit zeroization before publication of the slot as free.

### Randomness requirements

TLS key generation derives the X25519 private key and client random from scheduler timer ticks through hashing. The Wi-Fi handshake similarly seeds a local generator from the timestamp counter and uses a fixed constant on architectures without that counter.

These values are observable or guessable and do not meet cryptographic unpredictability requirements. Repeating boot timing, virtual-machine scheduling, snapshots, or replay can reproduce key material and nonces. Network cryptography needs a kernel entropy service with explicit readiness, failure, reseeding, and replay policy rather than subsystem-local time-derived generators.

### Network-stack integration

TLS does not currently integrate with NetworkStack. Each session polls RTL8139 itself, feeds matching frames into a private TCP object, and advances independently when the global TLS tick runs. Frames consumed by this path are not coordinated with reactor receive ownership, and the private transport cannot use VirtIO on AArch64.

Receive ownership can conflict as well as diverge. The reactor and TLS both poll network devices through separate loops, so whichever path consumes a frame first determines whether the other observes it. TLS matches destination ports only after direct device receipt and cannot return unrelated frames to the common stack. Integrating at the TCP byte-stream boundary removes this packet-stealing risk and lets one owner perform demultiplexing, retransmission, reset, and accounting.

### Static mutable TLS state

TLS stores local addressing, gateway identity, and the complete session pool in mutable statics. Session lookup returns a global mutable reference with static lifetime, while the global tick loop independently obtains mutable references through raw pointers. No lock, interrupt exclusion, owner token, or borrow-scoped guard prevents simultaneous access.

A stale reference can cross both memory and protocol generations. Free marks a slot inactive without invalidating an already returned reference, and allocation may overwrite that slot with a new host, keys, and TCP connection. The old reference can then mutate the new session while tick_all holds another mutable reference to the same storage. Generation-bearing handles are insufficient alone; access must also be scoped under one lock or reactor command.

### Malformed TLS record handling

The stream parser reads the record length from the five-byte header and computes a total length without first proving that the total fits the receive array. Once enough bytes are considered present, it copies that total into a fixed receive-sized local array. A declared length larger than the array can therefore reach an out-of-bounds slice and panic.

Encrypted handshake records are decrypted into a smaller handshake scratch buffer even though the record layer permits larger plaintext. Decryption errors are often dropped without an alert or terminal state, and unknown record types are ignored. The parser needs one enforced record-size contract before buffering, copying, decryption, or transcript mutation.

### TLS interoperability testing

tls interoperability testing is implemented only to the extent supported by the section evidence. The TLS module implements a TLS 1.3-oriented handshake and AES-GCM records over its own static TCP and RTL8139-oriented path. Strict certificate-chain and hostname validation, common-stack integration, secret lifecycle proof, and broad interoperability are incomplete. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

## Wi-Fi Audit

### Supported device families

Supported Wi-Fi device families are not established by PCI vendor matches alone. The code names several families, but a supported family needs firmware, register maps, DMA rings, interrupts, scan, association, data-plane, and reset evidence.

### Hardware initialization paths

Wi-Fi selects initialization by broad PCI vendor identifiers. Several vendor handlers only print that a chipset was detected and return success after enabling PCI access. The generated MAC address is synthetic rather than read from hardware, and no firmware loading, chipset-specific queue setup, interrupt configuration, calibration, regulatory setup, or verified link bring-up establishes a working device.

The current success path can enable later unsafe operations without proving the prerequisites those operations assume. A synthetic MAC is installed, connection state becomes idle, and scanning may write guessed registers even though firmware, DMA rings, regulatory state, and interrupt delivery were never established. Initialization should be a typed state machine whose final Ready state is reachable only after chipset-specific identity, memory, firmware, radio, and receive-path checks complete.

### PCI and MMIO access

Wi-Fi treats the raw BAR value as a directly usable pointer and accesses fixed offsets for channel control, transmit status, transmit buffers, receive status, receive length, receive buffers, key banks, and packet-number state. Source comments acknowledge that offsets are illustrative or device-specific, yet the same values drive active volatile reads and writes across generic Intel, Realtek, Broadcom, Atheros, and VirtIO matches.

Raw BAR use also confuses address classes. PCI BAR values describe bus resources and include attribute bits; they are not automatically valid kernel virtual pointers. Adding fixed offsets to them can address unmapped or unrelated memory, and enabling bus mastering allows the device to initiate DMA before an IOMMU or pinned-buffer policy exists. Each supported driver needs an owned mapped region with checked offsets and a separately established DMA domain.

### Bus mastering and DMA

Wi-Fi bus mastering is enabled before the driver proves a safe DMA domain, descriptor layout, or device-specific ownership protocol. That is too much trust for an experimental backend. The driver should not enable DMA until mapped buffers and firmware state are known.

### Scan lifecycle

Scan lifecycle moves the radio across channels, emits probe requests, reads management frames, and stores bounded results. The current path is useful for modeling, but it does not yet prove hardware timing, regulatory constraints, duplicate suppression, or exact receive lengths.

### Channel selection

Channel selection is currently a simple scan policy over expected channels. Production support needs regulatory-domain policy, device capability checks, dwell timing, and a clear relationship between selected channel, AP identity, and later association.

### Probe request construction

Probe request construction should control what local identity and capabilities the kernel broadcasts. Randomized MAC behavior, SSID selection, supported rates, and privacy policy should be explicit before active scanning is treated as production behavior.

### Beacon and probe-response parsing

Beacon and probe-response parsing is a hostile-input path. Every information element length, capability bit, channel claim, security suite, and SSID field can be forged by nearby devices. Accepted scan results should therefore record which fields were validated and which were only observed.

### Information-element bounds

Information-element bounds are the main memory-safety gate for management frames. The parser must prove that each element lies fully inside the received frame and that trailing storage beyond the exact hardware length cannot affect parsing.

### Scan result capacity

The review treats scan result capacity as a distinct contract within this section. The Wi-Fi module includes scanning, management parsing, association, WPA2 handshake logic, local cryptographic primitives, and temporal reconnect data. Hardware support and data-plane integration are not demonstrated as one production path. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Duplicate network handling

duplicate network handling is implemented only to the extent supported by the section evidence. The Wi-Fi module includes scanning, management parsing, association, WPA2 handshake logic, local cryptographic primitives, and temporal reconnect data. Hardware support and data-plane integration are not demonstrated as one production path. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Authentication state

Current support for authentication state must be read together with the stated subsystem boundary. The Wi-Fi module includes scanning, management parsing, association, WPA2 handshake logic, local cryptographic primitives, and temporal reconnect data. Hardware support and data-plane integration are not demonstrated as one production path. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Association state

For association state, the relevant behavior is distributed across the implementation described here. The Wi-Fi module includes scanning, management parsing, association, WPA2 handshake logic, local cryptographic primitives, and temporal reconnect data. Hardware support and data-plane integration are not demonstrated as one production path. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Open-network connection

Current support for open-network connection must be read together with the stated subsystem boundary. The Wi-Fi module includes scanning, management parsing, association, WPA2 handshake logic, local cryptographic primitives, and temporal reconnect data. Hardware support and data-plane integration are not demonstrated as one production path. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### WPA2 four-way handshake

wpa2 four-way handshake is implemented only to the extent supported by the section evidence. The Wi-Fi module includes scanning, management parsing, association, WPA2 handshake logic, local cryptographic primitives, and temporal reconnect data. Hardware support and data-plane integration are not demonstrated as one production path. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### EAPOL frame parsing

eapol frame parsing is implemented only to the extent supported by the section evidence. The Wi-Fi module includes scanning, management parsing, association, WPA2 handshake logic, local cryptographic primitives, and temporal reconnect data. Hardware support and data-plane integration are not demonstrated as one production path. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Replay-counter validation

The WPA2 path requires message three to carry exactly the replay counter received in message one and verifies the ANonce before accepting key data. This blocks a simple substitution within one locally tracked handshake.

The counter is not maintained as durable per-peer monotonic state across reconnects, resets, suspend, or temporal restoration. Message one itself is accepted without comparison against a previously accepted counter, and equality alone does not define retransmission handling. A replayed earlier handshake can therefore become acceptable when local connection state is reset.

### MIC verification

Message three MIC verification copies the complete EAPOL packet, zeros the MIC field, computes HMAC-SHA1 with the derived key-confirmation key, and compares the first sixteen bytes with an accumulated difference. The comparison is constant-time with respect to the first mismatch.

The implementation fixes descriptor version two and HMAC-SHA1 without negotiating the pairwise cipher or authentication suite from the selected network. Its helper truncates input to a fixed internal HMAC buffer for sufficiently large data, while the parser permits variable key-data lengths. A validly framed large EAPOL message can therefore be authenticated over less data than the protocol presents.

### PBKDF2 and HMAC processing

The audit of pbkdf2 and hmac processing follows the active data and control path rather than module comments. The Wi-Fi module includes scanning, management parsing, association, WPA2 handshake logic, local cryptographic primitives, and temporal reconnect data. Hardware support and data-plane integration are not demonstrated as one production path. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Pairwise key derivation

For pairwise key derivation, the relevant behavior is distributed across the implementation described here. The Wi-Fi module includes scanning, management parsing, association, WPA2 handshake logic, local cryptographic primitives, and temporal reconnect data. Hardware support and data-plane integration are not demonstrated as one production path. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Group key extraction

group key extraction is implemented only to the extent supported by the section evidence. The Wi-Fi module includes scanning, management parsing, association, WPA2 handshake logic, local cryptographic primitives, and temporal reconnect data. Hardware support and data-plane integration are not demonstrated as one production path. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### AES key unwrap

Current support for aes key unwrap must be read together with the stated subsystem boundary. The Wi-Fi module includes scanning, management parsing, association, WPA2 handshake logic, local cryptographic primitives, and temporal reconnect data. Hardware support and data-plane integration are not demonstrated as one production path. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Key installation

key installation is implemented only to the extent supported by the section evidence. The Wi-Fi module includes scanning, management parsing, association, WPA2 handshake logic, local cryptographic primitives, and temporal reconnect data. Hardware support and data-plane integration are not demonstrated as one production path. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Nonce generation

The WPA2 supplicant nonce is generated by seeding SecureRandom with the processor timestamp counter. Non-x86 targets use a fixed constant. The generated local MAC address follows the same pattern. A timestamp is observable and often predictable, while a fixed fallback repeats across boots.

WPA2 security depends on a fresh unpredictable supplicant nonce. Reuse or prediction reduces the handshake assumptions and can repeat derived key material when the remaining inputs repeat. Wrapping a weak seed in a pseudorandom generator does not add entropy.

Nonce generation must use the kernel cryptographic random service only after it reports sufficient entropy. The call should fail closed when entropy is unavailable, include a boot generation or persistent monotonic input as defense in depth, and never persist or restore a future nonce stream position from unauthenticated state.

### Password and key lifetime

The review treats password and key lifetime as a distinct contract within this section. The Wi-Fi module includes scanning, management parsing, association, WPA2 handshake logic, local cryptographic primitives, and temporal reconnect data. Hardware support and data-plane integration are not demonstrated as one production path. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Disconnect behavior

Current support for disconnect behavior must be read together with the stated subsystem boundary. The Wi-Fi module includes scanning, management parsing, association, WPA2 handshake logic, local cryptographic primitives, and temporal reconnect data. Hardware support and data-plane integration are not demonstrated as one production path. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Retry and timeout policy

The audit of retry and timeout policy follows the active data and control path rather than module comments. The Wi-Fi module includes scanning, management parsing, association, WPA2 handshake logic, local cryptographic primitives, and temporal reconnect data. Hardware support and data-plane integration are not demonstrated as one production path. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Temporal PMK caching

Current support for temporal pmk caching must be read together with the stated subsystem boundary. The Wi-Fi module includes scanning, management parsing, association, WPA2 handshake logic, local cryptographic primitives, and temporal reconnect data. Hardware support and data-plane integration are not demonstrated as one production path. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Temporal reconnect behavior

Current support for temporal reconnect behavior must be read together with the stated subsystem boundary. The Wi-Fi module includes scanning, management parsing, association, WPA2 handshake logic, local cryptographic primitives, and temporal reconnect data. Hardware support and data-plane integration are not demonstrated as one production path. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Secret persistence risks

Wi-Fi temporal snapshots serialize the cached PMK directly beside the SSID and restore it into live driver memory. The record receives no subsystem-level encryption, sealing, device binding, freshness proof, or rollback protection in this path. Anyone who can read or replay persistence records can recover a long-lived network secret or restore an older credential. Disconnect also leaves cached key material intact.

### Management-frame spoofing resistance

The review treats management-frame spoofing resistance as a distinct contract within this section. The Wi-Fi module includes scanning, management parsing, association, WPA2 handshake logic, local cryptographic primitives, and temporal reconnect data. Hardware support and data-plane integration are not demonstrated as one production path. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Malformed wireless frame handling

Management and EAPOL parsing contain useful length checks, but the receive boundary trusts frame lengths read from illustrative MMIO registers. One scan path allocates a 2048-byte array, fills only the reported prefix, then passes the entire array to management parsing rather than the received slice. Trailing zeros can consequently be interpreted as part of the frame.

Passing the entire scan array changes parser semantics because zero-filled storage can supply artificial terminators and length bytes beyond the hardware frame. A malformed truncated information element may therefore appear safely terminated instead of rejected. The receive API must carry exact length plus hardware status, and every parser must prove that accepted state is identical whether the backing allocation contains zeros, stale bytes, or randomized data after the received prefix.

## Intel E1000 Driver Audit

### PCI identification and BAR handling

E1000 PCI identification and BAR handling establish the common x86 backend. The audit concern is not whether a matching device can be found, but whether the BAR is mapped with the right memory attributes and whether DMA is enabled only after safe buffers exist.

### MMIO mapping and register access

E1000 MMIO access is direct register programming through the mapped BAR. That path needs one ownership rule for reset, interrupt acknowledgement, descriptor updates, and link changes so register writes do not race protocol assumptions in the reactor.

### Device reset in Intel E1000 Driver

E1000 reset is currently a driver-local recovery action. It should become a backend generation change that tells the reactor to reconcile ARP, TCP, DNS, and CapNet state before traffic continues.

### EEPROM access and MAC discovery

The review treats eeprom access and mac discovery as a distinct contract within this section. E1000 is the active common x86 backend with static descriptor pools, MMIO, burst receive, batching, interrupts, and adaptive throttling. DMA mapping, reset recovery, removal, and representative hardware conformance remain unresolved. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Bus mastering

The review treats bus mastering as a distinct contract within this section. E1000 is the active common x86 backend with static descriptor pools, MMIO, burst receive, batching, interrupts, and adaptive throttling. DMA mapping, reset recovery, removal, and representative hardware conformance remain unresolved. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Receive descriptor ring

The review treats receive descriptor ring as a distinct contract within this section. E1000 is the active common x86 backend with static descriptor pools, MMIO, burst receive, batching, interrupts, and adaptive throttling. DMA mapping, reset recovery, removal, and representative hardware conformance remain unresolved. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Transmit descriptor ring

The audit of transmit descriptor ring follows the active data and control path rather than module comments. E1000 is the active common x86 backend with static descriptor pools, MMIO, burst receive, batching, interrupts, and adaptive throttling. DMA mapping, reset recovery, removal, and representative hardware conformance remain unresolved. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### DMA address width in Intel E1000 Driver

E1000 descriptor entries store buffer addresses as 64-bit values, but ring base addresses are cast directly to 32 bits and the high address registers are written as zero. Register verification repeats the same truncated expectation. The driver also treats kernel virtual addresses as device-visible physical addresses without using a DMA mapping API.

This can work only when the kernel uses identity-mapped, physically contiguous, DMA-accessible storage below four gigabytes. The code does not validate those conditions. On a higher-half kernel, an IOMMU system, or memory allocated above the device aperture, the NIC can access an unrelated physical location and corrupt memory.

The driver needs architecture DMA allocation that returns CPU and device addresses separately, validates the device mask, writes both ring base halves, and maps every packet buffer for the required direction. Initialization must fail before bus mastering if any descriptor or buffer cannot be represented safely.

### Descriptor alignment

For descriptor alignment, the relevant behavior is distributed across the implementation described here. E1000 is the active common x86 backend with static descriptor pools, MMIO, burst receive, batching, interrupts, and adaptive throttling. DMA mapping, reset recovery, removal, and representative hardware conformance remain unresolved. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Static DMA buffer ownership

static dma buffer ownership is implemented only to the extent supported by the section evidence. E1000 is the active common x86 backend with static descriptor pools, MMIO, burst receive, batching, interrupts, and adaptive throttling. DMA mapping, reset recovery, removal, and representative hardware conformance remain unresolved. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Receive frame validation

E1000 receive checks descriptor ownership and returns a length bounded by the caller buffer. The burst path clamps a device-reported length to the static packet-buffer size, but it does not require end-of-packet, inspect descriptor error bits, reject impossible lengths, or distinguish truncation from a valid frame.

A corrupt descriptor or multi-descriptor packet can therefore become a shortened frame presented to the network parser. The receive control register also enables unicast and multicast promiscuous acceptance, increasing the volume of hostile traffic that reaches this weak validation path.

### Transmit frame validation

Current support for transmit frame validation must be read together with the stated subsystem boundary. E1000 is the active common x86 backend with static descriptor pools, MMIO, burst receive, batching, interrupts, and adaptive throttling. DMA mapping, reset recovery, removal, and representative hardware conformance remain unresolved. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Descriptor timeout behavior

descriptor timeout behavior is implemented only to the extent supported by the section evidence. E1000 is the active common x86 backend with static descriptor pools, MMIO, burst receive, batching, interrupts, and adaptive throttling. DMA mapping, reset recovery, removal, and representative hardware conformance remain unresolved. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Transmit batching

Current support for transmit batching must be read together with the stated subsystem boundary. E1000 is the active common x86 backend with static descriptor pools, MMIO, burst receive, batching, interrupts, and adaptive throttling. DMA mapping, reset recovery, removal, and representative hardware conformance remain unresolved. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Interrupt acknowledgement in Intel E1000 Driver

interrupt acknowledgement is implemented only to the extent supported by the section evidence. E1000 is the active common x86 backend with static descriptor pools, MMIO, burst receive, batching, interrupts, and adaptive throttling. DMA mapping, reset recovery, removal, and representative hardware conformance remain unresolved. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Adaptive interrupt throttling

For adaptive interrupt throttling, the relevant behavior is distributed across the implementation described here. E1000 is the active common x86 backend with static descriptor pools, MMIO, burst receive, batching, interrupts, and adaptive throttling. DMA mapping, reset recovery, removal, and representative hardware conformance remain unresolved. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Link-state change handling

The audit of link-state change handling follows the active data and control path rather than module comments. E1000 is the active common x86 backend with static descriptor pools, MMIO, burst receive, batching, interrupts, and adaptive throttling. DMA mapping, reset recovery, removal, and representative hardware conformance remain unresolved. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Driver reset and recovery in Intel E1000 Driver

E1000 initialization and re-enable paths reconstruct descriptor rings and registers in place. The recovery helper ignores failures from receive and transmit initialization and marks the device enabled even when hardware setup did not complete.

There is no quiesce protocol with the reactor, no cancellation of in-flight transmit ownership, no generation change for stale completions, and no link-level notification that protocol state should be reconciled. Recovery can therefore expose partially initialized rings while TCP and higher layers continue to treat the interface as continuous.

### Memory ordering and device visibility

For memory ordering and device visibility, the relevant behavior is distributed across the implementation described here. E1000 is the active common x86 backend with static descriptor pools, MMIO, burst receive, batching, interrupts, and adaptive throttling. DMA mapping, reset recovery, removal, and representative hardware conformance remain unresolved. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### QEMU and hardware conformance

Current support for qemu and hardware conformance must be read together with the stated subsystem boundary. E1000 is the active common x86 backend with static descriptor pools, MMIO, burst receive, batching, interrupts, and adaptive throttling. DMA mapping, reset recovery, removal, and representative hardware conformance remain unresolved. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

## Realtek RTL8139 Driver Audit

### PCI probing and I/O BAR handling

Current support for pci probing and i/o bar handling must be read together with the stated subsystem boundary. RTL8139 uses PCI I/O space, four static transmit buffers, and a wrapped receive ring. It is initialized on matching hardware but is not the universal stack backend and reports several failures through Boolean or zero values. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Port I/O safety in Realtek RTL8139 Driver

For port i/o safety, the relevant behavior is distributed across the implementation described here. RTL8139 uses PCI I/O space, four static transmit buffers, and a wrapped receive ring. It is initialized on matching hardware but is not the universal stack backend and reports several failures through Boolean or zero values. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Device reset in Realtek RTL8139 Driver

For device reset, the relevant behavior is distributed across the implementation described here. RTL8139 uses PCI I/O space, four static transmit buffers, and a wrapped receive ring. It is initialized on matching hardware but is not the universal stack backend and reports several failures through Boolean or zero values. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Transmit descriptor rotation

For transmit descriptor rotation, the relevant behavior is distributed across the implementation described here. RTL8139 uses PCI I/O space, four static transmit buffers, and a wrapped receive ring. It is initialized on matching hardware but is not the universal stack backend and reports several failures through Boolean or zero values. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Static transmit buffers

For static transmit buffers, the relevant behavior is distributed across the implementation described here. RTL8139 uses PCI I/O space, four static transmit buffers, and a wrapped receive ring. It is initialized on matching hardware but is not the universal stack backend and reports several failures through Boolean or zero values. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Receive ring layout

The audit of receive ring layout follows the active data and control path rather than module comments. RTL8139 uses PCI I/O space, four static transmit buffers, and a wrapped receive ring. It is initialized on matching hardware but is not the universal stack backend and reports several failures through Boolean or zero values. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Receive ring wraparound

RTL8139 copies packet headers and payload through modulo indexing over the receive ring, which handles ordinary wraparound. On an invalid packet, however, it advances the receive offset using the untrusted device-reported length before normalizing that offset to the ring size.

The resulting arithmetic can publish a nonsensical consumer position to hardware and desynchronize software from the ring. The path also lacks a bounded resynchronization scan and does not prove that a wrapped packet, its trailing checksum, and alignment padding are all resident before advancing.

### Packet status validation

packet status validation is implemented only to the extent supported by the section evidence. RTL8139 uses PCI I/O space, four static transmit buffers, and a wrapped receive ring. It is initialized on matching hardware but is not the universal stack backend and reports several failures through Boolean or zero values. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### CRC and alignment error handling

For crc and alignment error handling, the relevant behavior is distributed across the implementation described here. RTL8139 uses PCI I/O space, four static transmit buffers, and a wrapped receive ring. It is initialized on matching hardware but is not the universal stack backend and reports several failures through Boolean or zero values. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Receive overflow recovery

Current support for receive overflow recovery must be read together with the stated subsystem boundary. RTL8139 uses PCI I/O space, four static transmit buffers, and a wrapped receive ring. It is initialized on matching hardware but is not the universal stack backend and reports several failures through Boolean or zero values. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Transmit completion and timeout

RTL8139 waits for the selected transmit descriptor to become host-owned, but exhaustion of the spin limit does not return an error. The function continues by overwriting the static transmit buffer, programming the descriptor, rotating to the next slot, and reporting success.

A stalled device can therefore cause software to reuse memory still owned by hardware and lose the previous frame without any diagnostic. Boolean success also prevents callers from distinguishing completion, queue pressure, timeout, reset requirement, and permanent device failure.

### Interrupt mask and acknowledgement

For interrupt mask and acknowledgement, the relevant behavior is distributed across the implementation described here. RTL8139 uses PCI I/O space, four static transmit buffers, and a wrapped receive ring. It is initialized on matching hardware but is not the universal stack backend and reports several failures through Boolean or zero values. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Link-state detection

Current support for link-state detection must be read together with the stated subsystem boundary. RTL8139 uses PCI I/O space, four static transmit buffers, and a wrapped receive ring. It is initialized on matching hardware but is not the universal stack backend and reports several failures through Boolean or zero values. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### DMA address assumptions

The audit of dma address assumptions follows the active data and control path rather than module comments. RTL8139 uses PCI I/O space, four static transmit buffers, and a wrapped receive ring. It is initialized on matching hardware but is not the universal stack backend and reports several failures through Boolean or zero values. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Driver reset and recovery in Realtek RTL8139 Driver

Current support for driver reset and recovery must be read together with the stated subsystem boundary. RTL8139 uses PCI I/O space, four static transmit buffers, and a wrapped receive ring. It is initialized on matching hardware but is not the universal stack backend and reports several failures through Boolean or zero values. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Hardware and emulator conformance

The audit of hardware and emulator conformance follows the active data and control path rather than module comments. RTL8139 uses PCI I/O space, four static transmit buffers, and a wrapped receive ring. It is initialized on matching hardware but is not the universal stack backend and reports several failures through Boolean or zero values. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

## VirtIO Network Driver Audit

### MMIO device discovery

VirtIO MMIO discovery is the active AArch64 network-device path. It locates version two MMIO devices and prepares split queues, but the queue memory and reset story are still development-grade.

Discovery should prove more than a matching device signature. It must bind the MMIO range to one mapped device, reject unsupported versions, validate queue geometry, and publish a backend generation only after the status sequence reaches driver OK. Higher layers need that generation to decide whether ARP, TCP, DNS, and CapNet state survived reset.

### VirtIO version validation

VirtIO version validation should define the supported device contract before queue setup begins. The current AArch64 path targets MMIO version two and should reject anything else as unsupported rather than attempting compatibility by accident.

Version validation must fail closed before the driver touches queue registers. A different VirtIO layout can share enough shape to look usable while changing ownership or feature semantics. The supported contract should name exactly which version is accepted and which register behavior is assumed.

### Device-status state machine

The VirtIO status state machine is partially represented during initialization. It is not yet a full lifecycle contract that covers failed setup, reset, queue teardown, and stale completion rejection.

The status state machine is the device-side commit protocol. The backend should not become visible until acknowledgement, driver ownership, feature acceptance, queue setup, and driver OK have all completed in order. Reset must withdraw that publication and invalidate outstanding descriptors before software reuses queue memory.

### Feature negotiation

VirtIO feature negotiation selects the assumptions that the rest of the driver relies on. MAC reporting, link status, checksum behavior, and mergeable-buffer support should all become explicit inputs to the backend readiness state.

Feature negotiation defines what the stack may assume about frame layout, MAC discovery, checksum handling, mergeable buffers, and link readiness. The negotiated set should be stored in diagnostics and used by tests. Otherwise failures look like generic driver trouble instead of a mismatch between requested and supported device behavior.

### MAC feature negotiation

For mac feature negotiation, the relevant behavior is distributed across the implementation described here. VirtIO MMIO version two is active on AArch64 with split queues and selected feature negotiation. Queue memory uses ordinary heap storage, receive polling allocates and copies, and reset and interrupt integration are incomplete. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Link-status feature handling

The audit of link-status feature handling follows the active data and control path rather than module comments. VirtIO MMIO version two is active on AArch64 with split queues and selected feature negotiation. Queue memory uses ordinary heap storage, receive polling allocates and copies, and reset and interrupt integration are incomplete. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Unsupported mergeable-buffer behavior

For unsupported mergeable-buffer behavior, the relevant behavior is distributed across the implementation described here. VirtIO MMIO version two is active on AArch64 with split queues and selected feature negotiation. Queue memory uses ordinary heap storage, receive polling allocates and copies, and reset and interrupt integration are incomplete. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Split virtqueue layout

The review treats split virtqueue layout as a distinct contract within this section. VirtIO MMIO version two is active on AArch64 with split queues and selected feature negotiation. Queue memory uses ordinary heap storage, receive polling allocates and copies, and reset and interrupt integration are incomplete. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Descriptor allocation and free list

Each VirtIO queue keeps a singly linked free list in an array and tracks a free-count. Allocation removes the current head, while completion inserts the supplied descriptor identifier back at the head.

The free operation does not validate the identifier, detect duplicate completion, prove that the descriptor was outstanding, or cap the free-count. A repeated or out-of-range used entry can corrupt the list, index outside the array, and allow one descriptor to be allocated concurrently to multiple operations. Device input must not be trusted as allocator metadata without ownership validation.

### Available-ring publication

Available-ring publication is the point where CPU-owned descriptors become device-owned descriptors. That handoff needs one local ownership record and one memory-ordering rule, because later completion handling depends on proving the descriptor was genuinely outstanding.

Publishing an available descriptor transfers ownership to the device. The descriptor address, length, flags, buffer contents, and local outstanding record must all be complete before the available-ring update becomes visible. That rule should be represented in code, not just implied by fences.

### Used-ring consumption

VirtIO reads the device-owned used index and consumes every intervening ring element. It casts each device-supplied identifier to the local descriptor type and forwards it to receive or transmit completion without first checking that it names an outstanding descriptor in the corresponding queue.

Receive later guards some packet-buffer access, but descriptor release still uses the unchecked identifier. Transmit completion has no equivalent guard. The loop also trusts an arbitrarily advanced used index, so a faulty or malicious device can force repeated consumption of stale ring slots and corrupt queue ownership.

### Receive-buffer replenishment

Receive-buffer replenishment currently assumes the queue's backing memory remains device-visible and valid. That assumption should be moved into the DMA allocator and backend descriptor instead of living inside queue mechanics.

Receive buffers remain device-owned until a valid used-ring completion returns them. Replenishment should repost only descriptors whose identity, ownership, and buffer length were checked. A malformed completion should lead to quarantine or reset, not blind reuse.

### Transmit completion

Transmit completion currently depends on the device returning descriptor identifiers that match software expectations. A production driver must treat those identifiers as untrusted until they are checked against an outstanding transmit set.

Transmit completion should release exactly one outstanding descriptor and update transmit diagnostics with the outcome. The current path relies too much on device-supplied identifiers. A faulty device or emulator bug can corrupt the free list unless completion checks the outstanding set first.

### Queue-size validation

Initialization reads the device maximum and programs the smaller of that value and the compile-time queue size. The in-memory queue implementation nevertheless allocates, indexes, replenishes, and advertises descriptors according to the compile-time size.

If a device exposes fewer entries, software can publish descriptor heads and available-ring positions outside the negotiated queue. A zero or non-power-of-two maximum is not rejected through one explicit contract. Queue geometry must be represented by one validated runtime value used by every ring and descriptor operation.

### DMA-visible memory requirements

VirtIO allocates descriptor, available, used, and packet storage from ordinary Box and Vec allocations, then writes their pointer values into device queue registers and descriptors. The code assumes those virtual addresses are valid device addresses, physically contiguous where required, stable for the queue lifetime, and coherent with the device.

Memory fences order CPU operations but do not translate virtual addresses, pin pages, clean or invalidate noncoherent caches, or establish DMA permissions. The source comment acknowledges that production memory should come from an MMIO-visible region, but the active initialization still publishes heap pointers to hardware.

Queue creation must use the platform DMA allocator and preserve separate CPU and device addresses. The allocator must guarantee alignment, contiguity, lifetime pinning, cache policy, and address width. Queue initialization should remain unpublished until every region is mapped and the device has accepted the complete layout.

### Physical and virtual address assumptions

The audit of physical and virtual address assumptions follows the active data and control path rather than module comments. VirtIO MMIO version two is active on AArch64 with split queues and selected feature negotiation. Queue memory uses ordinary heap storage, receive polling allocates and copies, and reset and interrupt integration are incomplete. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Memory fences on weakly ordered systems

The VirtIO path uses fences in places where queue visibility matters, which is necessary on AArch64. Fences are only one part of the contract; they do not make heap pointers DMA-safe or validate device ownership.

Fences order CPU memory operations, but they do not translate addresses, pin pages, enforce cache coherency, or prove descriptor ownership. The driver needs an explicit rule for each transition between CPU-owned descriptor, device-owned descriptor, device-written buffer, CPU-observed completion, and reusable descriptor.

### Interrupt acknowledgement in VirtIO Network Driver

interrupt acknowledgement is implemented only to the extent supported by the section evidence. VirtIO MMIO version two is active on AArch64 with split queues and selected feature negotiation. Queue memory uses ordinary heap storage, receive polling allocates and copies, and reset and interrupt integration are incomplete. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Polled receive behavior

Current support for polled receive behavior must be read together with the stated subsystem boundary. VirtIO MMIO version two is active on AArch64 with split queues and selected feature negotiation. Queue memory uses ordinary heap storage, receive polling allocates and copies, and reset and interrupt integration are incomplete. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Pending receive buffering

Current support for pending receive buffering must be read together with the stated subsystem boundary. VirtIO MMIO version two is active on AArch64 with split queues and selected feature negotiation. Queue memory uses ordinary heap storage, receive polling allocates and copies, and reset and interrupt integration are incomplete. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Capability-gated send path

The VirtIO capability send helper is not the system network authorization boundary. It exists beside the common transmit path and uses a placeholder authority type.

The helper is a placeholder, not a real network authority boundary. It checks a Channel capability and the common transmit path does not call it. Real send gating belongs at the reactor request boundary and again at transmit commit, using a dedicated network capability with rights for the requested operation.

### Incorrect capability-type substitution

The current placeholder substitutes channel authority for network authority. That should be documented as an incorrect stand-in, not as a supported access-control model.

Substituting channel authority for network authority weakens the capability story and makes audit results misleading. A caller with unrelated IPC access should not gain network transmit power. The fix is not another driver helper; it is a real network capability taxonomy enforced by the shared network entry path.

### AArch64 and x86-64 conformance

The review treats aarch64 and x86-64 conformance as a distinct contract within this section. VirtIO MMIO version two is active on AArch64 with split queues and selected feature negotiation. Queue memory uses ordinary heap storage, receive polling allocates and copies, and reset and interrupt integration are incomplete. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

## Capability-Based Network Access Audit

### Network-send authority

The active DNS, TCP, HTTP, configuration, and CapNet reactor requests contain operation data but no authenticated principal, capability identifier, rights, namespace, or destination policy. NetworkStack eventually calls the selected backend directly, so no authority is revalidated when protocol or device state changes.

VirtIO contains a separate capability_send wrapper, but it checks for a Channel capability on wildcard object zero with Rights::NONE. Any matching channel grant satisfies that query, and the universal stack does not call the wrapper. The comment claiming that NetworkSend authority was checked by the reactor does not match active code.

Network send authority should be a dedicated capability resolved when a request enters the reactor and revalidated before connection creation, configuration, raw transmission, or control-message publication. Rights should distinguish resolve, connect, listen, send, raw frame, CapNet control, and administration. The resolved authority must be bound to the current process generation and request generation so revocation can cancel queued work.

### Network-receive authority

Network receive authority is not yet carried through the reactor as a principal-bound object. The active stack can create and consume receive state without one canonical capability identity at the commit point.

Receive authority covers more than reading bytes. It includes binding listeners, accepting connections, consuming UDP ports, reading DNS answers, and observing CapNet control state. The reactor should know which principal owns each receive endpoint and should reject reads after capability revocation, process exit, or process-generation reuse.

### Socket creation authority

Socket creation authority is currently implied by caller path rather than represented in the network request itself. That makes resource ownership and later cleanup harder to prove.

Socket creation is where resource accounting should attach. Connections and listeners consume table slots, retransmission state, buffers, local ports, and diagnostic identity. Creating them without a principal-bound authority makes cleanup and revocation depend on caller discipline rather than kernel ownership.

### DNS and HTTP authority

DNS and HTTP authority are not separated from generic network use in the current reactor contract. They should be, because name resolution and remote content fetches create different policy and audit requirements.

DNS and HTTP are security-relevant operations. DNS chooses future remote endpoints, and HTTP can fetch untrusted data into kernel-managed buffers. The capability model should distinguish name resolution, outbound connection, response-body reads, redirects, and raw network administration instead of treating them as ambient network use.

### Raw-frame authority

Raw-frame authority is not currently exposed as a clean, dedicated right. If it is added, it should be treated as device-administrative power rather than ordinary socket access.

Raw-frame access is a device-level power because it bypasses TCP, UDP, DNS, and CapNet admission. It should be an administrative right, not a side effect of ordinary socket access. Any future raw path should carry explicit destination, EtherType, size, and rate limits.

### Device-administration authority

Device-administration authority is not yet separated from other network operations. Reset, backend selection, Wi-Fi association, interrupt tuning, and diagnostic state need stronger rights than connecting to a remote port.

Device administration includes reset, backend selection, MAC configuration, interrupt tuning, Wi-Fi association, and diagnostic views that may expose sensitive topology. Those operations should not share the same authority as opening a TCP connection. They need their own right because mistakes at this layer can invalidate every protocol object above the driver.

### Use of channel capability as network authority

Using channel authority as network authority is a placeholder and should not survive into a stable ABI. IPC access and network access protect different resources and need separate revocation stories.

Channel authority and network authority protect different objects. A channel grant proves something about IPC, not about remote traffic, device transmission, or DNS. Keeping them separate makes later revocation understandable: closing an IPC channel should not accidentally remove or preserve network access.

### Process ownership checks

The review treats process ownership checks as a distinct contract within this section. Ordinary reactor operations do not carry a principal or network capability to the commit point. CapNet has a richer authority model, while one VirtIO helper substitutes a Channel capability with no required rights and is not used by the common send path. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Rights attenuation in Capability-Based Network Access

The audit of rights attenuation follows the active data and control path rather than module comments. Ordinary reactor operations do not carry a principal or network capability to the commit point. CapNet has a richer authority model, while one VirtIO helper substitutes a Channel capability with no required rights and is not used by the common send path. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Revocation during active connections

Revocation during active connections is not yet enforced by the reactor request model. Work already queued or retransmitting can outlive the authority check that originally allowed it.

Revocation must affect work already in flight. A revoked principal should not receive a connection handle after a pending DNS query or TCP connect completes, and retransmission state should not continue sending under revoked authority. The reactor needs request generations and cancellation outcomes to enforce that rule.

### Capability inheritance and delegation

The audit of capability inheritance and delegation follows the active data and control path rather than module comments. Ordinary reactor operations do not carry a principal or network capability to the commit point. CapNet has a richer authority model, while one VirtIO helper substitutes a Channel capability with no required rights and is not used by the common send path. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Service and syscall authorization consistency

Service and syscall authorization consistency depends on one shared operation contract. The current code has several entry paths that can make their own assumptions before reaching the network stack.

Services, syscalls, shell helpers, WASM host calls, and temporal replay should adapt one canonical network operation contract. If each surface performs its own partial check, behavior will drift and bugs will depend on the entry path. The network boundary should be the final authority check before state changes.

## CapNet Architecture Audit

### CapNet purpose and trust model

CapNet is the network-facing capability transport, not a general packet protocol. Its trust model is stronger than the ordinary network stack because it carries rights, object identity, peer identity, replay state, revocation, and persistence through one bounded design. That strength also makes it dangerous if it drifts away from the central capability manager.

### Portable capability-token model

The portable token model encodes rights so they can cross device boundaries. That is useful only if the remote token remains a constrained representation of the local capability model. Any mismatch in rights, object generations, revocation, or delegation depth can turn CapNet into a parallel authority system.

### Device identity

Device identity anchors token issuer and subject fields. The current code models those identities, but the trust source and lifecycle of each identity still need a stronger contract. A restored or rekeyed device identity must not silently validate tokens issued under an older or unrelated trust epoch.

### Peer registration

Peer registration creates the local record that later token, control, replay, and revocation checks depend on. It should therefore be treated as an authority transition. Duplicate peers, changed measurements, and reused device identifiers need explicit outcomes before the peer table becomes a stable trust database.

### Peer trust policy

Peer trust policy currently exists as kernel-managed state rather than a complete enrollment and attestation framework. Trust-on-first-use and pinned measurements have different security meanings, and the system must say which one is active for each peer.

### Peer-session establishment

Peer-session establishment binds transport messages to a peer record, session key, epoch, replay window, and control sequence space. That binding must be complete before token offers or revocations are accepted. A partially established session should not install leases or update durable trust state.

### Session-key installation

Session-key installation is a publication event. Old keys, replay windows, retransmission entries, and accepted token offers must be invalidated or generation-tagged when a key changes. Otherwise messages from one session epoch can be interpreted under another.

### Token signing and verification

Token signing and verification currently use a session-bound symmetric authenticator. That can protect transport integrity between peers, but it is not the same as offline issuer provenance. The audit should keep those claims separate so future asymmetric signing work has a clear purpose.

### Control-frame transport

Control-frame transport carries security state over UDP. The bounded frame format is useful, but delivery remains lossy, reorderable, and floodable. CapNet must authenticate and replay-check each frame before it affects leases, revocations, or peer state.

### Integration with UDP

UDP integration gives CapNet a simple transport, but it inherits UDP queue pressure, checksum policy, source validation, and drop observability gaps. CapNet frame authentication narrows some risk after delivery; it does not remove the need for transport-level counters and admission results.

### Integration with the capability manager

Integration with the capability manager is the central maturity gate for CapNet. Remote leases, revocation, rights attenuation, and object identity must resolve to the same authority model used by local kernel code. Anything else creates two security systems that can disagree.

### Integration with temporal persistence

Temporal persistence lets CapNet survive restart, but it also gives attackers a rollback target if records are not authenticated and freshness-checked. Peer sessions, tombstones, keys, and epochs should restore as one generation or not at all.

### Monolithic implementation and facade split

The facade split improves navigation but does not yet split ownership. Most state still belongs to the monolithic implementation, so file boundaries should not be mistaken for lock, persistence, or invariant boundaries.

### Facade ownership boundaries

Facade ownership boundaries should eventually follow the data: peer sessions, token encoding, revocation, persistence, metrics, and fuzz support each need private state or clear read-only access. Re-exporting names alone does not create those boundaries.

### Dead-code suppression and maturity

Dead-code suppression makes CapNet maturity harder to read. Dormant test helpers, future algorithm paths, and active security code should be marked by role rather than hidden behind broad allowance. Security review needs to know which paths are live.

## CapNet Token Format Audit

### Token magic and version

Token magic and version identify the serialized format before any authority fields are trusted. The version-one format is fixed width, which simplifies bounds checking and canonical hashing. Unsupported versions should fail before rights, object identity, or constraints are interpreted.

### Fixed serialized size

The fixed serialized size makes token decoding predictable and avoids allocation. It also means forward compatibility must be explicit; new fields cannot be appended without a new version or a reserved-field rule that old kernels enforce.

### Canonical byte encoding

Canonical byte encoding is what makes token identifiers and authenticators stable across devices. Every integer, reserved field, constraint flag, and identity byte must have exactly one serialized form. If two encodings can describe the same authority, replay and revocation tracking become ambiguous.

### Byte-order contract

The token byte-order contract is little-endian and should be treated as wire format, not host layout. Cross-architecture support depends on never decoding token bytes through native structure layout or pointer casts.

### Algorithm identifier

The algorithm identifier exists, but the active format effectively depends on the current SipHash path. Algorithm agility is therefore structural rather than mature. A future asymmetric or wider MAC algorithm needs downgrade prevention and a clear unsupported-algorithm result.

### Issuer and subject device identity

Issuer and subject device identity define who created the token and who may use it. Those fields only have security value if device identity is authenticated, stable across restore, and tied to the active peer session or offline trust policy.

### Capability type and rights

Capability type and rights must remain a subset of the parent authority and must map back to the central capability manager. Unknown types or rights should not be preserved as opaque power, because that would let remote tokens express authority local code cannot audit.

### Object identity

Object identity must include enough generation information to avoid stale grants. A numeric object alone is not sufficient if the local object can be deleted and recreated while an old token remains valid.

### Parent-token hash

The parent-token hash gives delegations an ancestry anchor. It is only useful if parent lookup, revocation, and descendant checks all use the same canonical token identity. Otherwise ancestry can be recorded but not enforced.

### Delegation depth

Delegation depth bounds how far authority can be attenuated. The depth field must be checked during every delegation and preserved during decode so a remote peer cannot reset the chain length by reserializing a token.

### Temporal validity window

Temporal validity windows depend on trusted time. A kernel that restores from a snapshot or runs without synchronized time cannot treat not-before and not-after fields as complete protection. The token verifier needs a clear unavailable-time result.

### Nonce and token identity

Nonce and token identity separate otherwise similar grants. They are also the anchor for replay, revocation, and audit correlation. Nonces must come from a real entropy source and must not repeat across issuer epochs.

### Measurement binding

Measurement binding says a token is valid only for a measured peer or runtime state. That requires a trustworthy measurement source and comparison policy. A field in the token is not enough unless the verifier knows which measurement was established for the current peer.

### Session binding in CapNet Token Format

Session binding prevents a token observed in one peer session from being replayed in another. It must be checked before lease installation and again during restore, because restored sessions can otherwise accept stale tokens from an earlier epoch.

### Use-count constraint

Use-count constraints describe consumable authority. They only matter if every accepted operation decrements the same durable counter before the protected effect becomes visible. A token that carries a use count but installs as ordinary reusable authority weakens the contract from affine authority to advisory metadata.

The count also needs replay protection. Retransmitted offers, restored snapshots, and duplicated control frames should not reset or double-spend the remaining uses. A production design should store consumption by token identity and issuer epoch, then reject attempts to reuse an exhausted grant.

### Byte-quota constraint

Byte quotas limit how much traffic a delegated authority can cause. The token format can carry that limit, but enforcement belongs at the send or receive boundary that actually counts bytes. Quota checks must run after authority resolution and before packet publication, otherwise the network path can transmit more data than the token allowed.

Quota accounting should use canonical token identity rather than peer identity alone. Two different tokens from the same peer may carry different budgets, and a descendant token should never regain bytes already consumed by its parent unless the delegation model explicitly permits a split budget.

### Resource quota

Resource quota gives a token authority over bounded kernel state rather than only bytes or calls. That can cover sockets, queued control frames, retransmission entries, peer leases, or service objects. The field needs a resource namespace, a unit definition, and an enforcement point for each resource class.

Without those definitions, resource quota is not comparable across subsystems. A quota that means packets in one path and sockets in another path cannot be safely delegated or audited as one capability property.

### Constraint flag consistency

Constraint flags need canonical meaning. A flag that marks a quota, session binding, measurement binding, or temporal bound as active should require the corresponding field to contain a valid value. The verifier should reject contradictory combinations rather than silently treating one field as dominant.

This matters because constraints are attenuation rules. If a child token can clear a flag while leaving a field populated, or set a flag whose field is ignored, parent and child authority can no longer be compared mechanically.

### Reserved fields and forward compatibility

Reserved fields are part of the security contract. Old kernels should require them to be zero unless a versioned extension says otherwise. Accepting arbitrary reserved bytes creates multiple encodings for the same authority and lets future fields be smuggled through old verifiers.

Forward compatibility should therefore be version-gated. A future token format can add fields, algorithms, or constraints, but version-one decoders should not preserve unknown authority state they cannot interpret.

### Token MAC coverage

CapNet serializes every version-one token field except the authenticator into canonical little-endian bytes, then computes a keyed sixty-four-bit SipHash value. Verification covers issuer, subject, object, rights, temporal bounds, constraints, delegation metadata, measurement, session, and quotas, so field substitution is detected when the correct session key is used.

The authenticator is only sixty-four bits and the format accepts no active algorithm other than the kernel SipHash identifier. This is a symmetric per-session MAC, not a portable issuer signature: any holder of the peer session key can mint tokens attributed to that session. The design therefore cannot provide offline provenance, multi-hop issuer authentication, or durable verification after session-key replacement.

### Canonical token identifier hashing

Canonical token identifier hashing gives revocation, delegation, replay rejection, and audit records one shared handle. The identifier should derive from the canonical token bytes in a way that excludes mutable transport details and includes every authority-bearing field.

The identifier must also remain stable across decode, restore, and retransmission. If one path hashes decoded fields and another hashes original bytes, reserved fields or noncanonical encodings can split one grant into multiple identities.

### Decode bounds and trailing bytes

Decode bounds are simple because the token is fixed width. A decoder should require the exact byte count, reject trailing bytes, and avoid interpreting partially available fields. That rule prevents concatenated tokens, smuggled extensions, and truncated authority records.

Exact-length decoding also makes fuzzing and conformance easier. Every accepted token should round-trip to the same canonical byte string, and every rejected token should fail before any lease, metric, or revocation state changes.

### Unknown version and algorithm handling

Unknown versions and algorithms should fail closed. A verifier that cannot authenticate the token format cannot safely inspect rights, object identity, or constraints, because those fields may have different meanings under the unsupported version.

Algorithm handling also needs downgrade protection. When stronger algorithms are added, peers should not be able to force the verifier back to the weaker version-one symmetric authenticator unless policy explicitly allows it for that peer and session.

## CapNet Delegation Audit

### Delegation-chain construction

Delegation-chain construction records how authority moved from parent to child. The important property is not the presence of a record; it is that every child remains a strict subset of its parent across rights, type, object, time, depth, and constraints.

### Parent lookup

Parent lookup must use canonical token identity and must fail closed when the parent is missing, expired, revoked, or outside the current trust epoch. A child token that cannot prove its parent should not install a lease.

### Rights attenuation in CapNet Delegation

Rights attenuation is the core delegation rule. The child may have fewer rights, never more, and unknown rights should be stripped or rejected rather than carried forward. The central capability manager needs to enforce the same rule when consuming remote leases.

### Capability-type preservation

Capability-type preservation prevents a grant for one object class from becoming power over another class. Delegation should reject type changes unless a specific, audited conversion exists.

### Object identity preservation

Object identity preservation prevents a delegated token from being retargeted. The child should refer to the same object generation as the parent, or to a strictly narrower subobject if the capability model explicitly supports that form.

### Temporal-window narrowing

Temporal-window narrowing means a child cannot outlive its parent. The verifier needs trusted time and snapshot rollback protection, otherwise a narrowed window can still be replayed under an older clock.

### Constraint inheritance

Constraint inheritance should be monotonic. Use limits, byte quotas, measurement bindings, session bindings, and resource quotas may become stricter, but should not disappear during delegation.

### Maximum delegation depth

Maximum delegation depth bounds delegation graph growth and verification work. The limit must be enforced at construction, decode, restore, and lease installation, not only at one local helper.

### Delegation record capacity

Delegation record capacity is fixed, which protects memory but creates an admission policy problem. When the table is full, the kernel must reject new delegation or evict only records that can no longer affect revocation or lease validity.

### Affine split representation

Affine split representation expresses the idea that authority can be divided into local and delegated claims. That representation only becomes enforceable when consuming either half updates the same central authority ledger.

### Linear capability claims

Linear capability claims promise single-use or exclusive authority. A type-level wrapper helps local code, but remote claims also need durable consumption records and replay protection.

### Duplicate delegation

Duplicate delegation should be detected by canonical parent, child, object, and nonce identity. Without duplicate handling, retransmission and replay can consume table capacity or create confusing audit trails.

### Delegation rollback

Delegation rollback matters when a child record is created but lease installation, persistence, or acknowledgement fails. The operation should either publish every related state change or leave no usable child authority behind.

### Cross-device delegation

Cross-device delegation is where CapNet leaves the local trust domain. It requires issuer identity, subject identity, session binding, measurement policy, and revocation propagation to agree before the receiving device installs authority.

### Descendant revocation

Descendant revocation must walk or index the delegation graph reliably. A parent revocation that misses one descendant leaves a valid-looking child token with no trusted ancestor.

## CapNet Peer Session Audit

### Peer table capacity

The peer table is fixed size, which gives CapNet a clear memory ceiling. That bound becomes a policy question when the table fills: a new peer should be rejected or should replace only a quiescent peer whose leases, retransmissions, replay windows, and revocation state can be retired safely.

Peer capacity also affects denial-of-service resistance. An attacker that can register or provoke many peer identities can occupy table slots and block legitimate devices unless admission requires authority, trust policy, or rate control.

### Duplicate peer registration

Duplicate peer registration must distinguish refresh from conflict. The same device identity with the same pinned measurement and a newer session epoch can update liveness or rotate keys. The same identity with a different measurement, trust mode, or active session binding should be treated as a possible impersonation or restore collision.

The registry should not silently overwrite an active peer slot. Replacement must either prove continuity or publish a clean session reset that invalidates outstanding retransmissions, leases, and replay windows.

### Trust-on-first-use policy

Trust on first use is a convenience policy, not a proof of device identity. It can help local development and closed test networks, but the first observed peer can become the trusted peer even if that observation was made during an attack or misconfiguration.

The implementation should label this mode explicitly and keep it separate from pinned or certified trust. A production deployment needs a way to disable first-use enrollment and require preexisting measurement or certificate evidence.

### Pinned-measurement policy

Pinned measurements are useful only when the measurement source is authenticated and freshness-bound. A byte array stored in a peer slot does not prove anything by itself; it must be tied to attestation input that the verifier trusts for the current session.

Restore makes this harder. A stale pinned value can preserve trust in an obsolete peer image unless the persistence layer records when the measurement was learned and whether policy requires reattestation after reboot or rollback.

### Session epoch

Session epoch separates old keys and replay windows from new ones. Every control frame, token binding, lease, retransmission entry, and persisted peer record should either carry the epoch or be invalidated when the epoch changes.

Epoch handling is the guard against cross-session replay. A valid token offer from yesterday should not become valid again because a peer reused a device identity after reconnecting.

### Session key derivation

Session key derivation needs authenticated inputs, nonces from both peers, and a transcript that binds the key to the intended device identity. A key derived before identity or measurement is validated can protect packets but cannot prove which peer is behind them.

The key schedule should also state which keys authenticate control frames, token MACs, retransmissions, and persistence. Reusing one symmetric key for every role is simple, but it weakens separation between transport integrity and authority issuance.

### Key replacement

Key replacement is a session transition, not a field update. Replacing the key should advance the epoch, reset or preserve replay windows according to an explicit rule, and mark old retransmission entries as invalid unless they were authenticated under a still-accepted previous epoch.

The transition should fail atomically. A peer must not be left with a new key and old replay state, or old key material and new sequence expectations.

### Key zeroization

Key zeroization should run when a peer slot is evicted, a session is reset, a restore fails, or secret state is replaced. Clearing only the logical validity flag leaves old key bytes available to later bugs, dumps, or accidental serialization.

Zeroization needs to be explicit because fixed tables and static storage do not naturally drop secrets. The code should overwrite the key material before reusing or publishing the slot.

### Peer liveness tracking

Peer liveness tracking records whether a session is still useful, but it should not be confused with authorization. A live peer may still be revoked, expired, over quota, or bound to the wrong measurement.

Liveness should be updated only by authenticated traffic or explicit local policy. Unauthenticated heartbeats would let an attacker keep stale peer slots alive and delay eviction.

### Incoming nonce replay window

Incoming nonce replay windows reject repeated token and control material. The window should be checked before state-changing payloads install leases, revoke tokens, or update peer metadata.

Persistence determines whether replay protection survives restart. If accepted tokens survive restore but their nonce window does not, an old accepted offer can be replayed into a fresh session record.

### Control sequence replay window

The control sequence replay window protects ordered protocol traffic from duplication. It should bind sequence numbers to peer identity, session epoch, message type, and acknowledgement state so a frame from one context cannot satisfy another.

The window also needs a policy for gaps. UDP can drop frames, so strict monotonic acceptance may stall the protocol, while overly broad windows can admit replay. The acceptable range should be documented and fuzzed.

### Outgoing sequence allocation

Outgoing sequence allocation should be monotonic within a peer session epoch. Retransmissions should reuse the original sequence number, while new messages should never reuse a number until the epoch changes.

Concurrent callers need one allocator path. If control frames can be queued from multiple contexts, sequence assignment must happen under the same lock or through the same reactor owner.

### Sequence wraparound

Sequence wraparound should terminate or rekey the session before numbers repeat. Reusing a sequence number under the same key and epoch weakens replay protection and can confuse acknowledgement-driven retransmission removal.

The safe rule is simple: reserve a maximum sequence value below the integer limit, force a rekey or reconnect before crossing it, and test the boundary directly.

### Session reset and reconnect

Session reset and reconnect must decide what survives. Trust policy and pinned identity may persist, but keys, replay windows, retransmissions, pending offers, and unauthenticated liveness should normally be discarded or generation-tagged.

Reconnect is also where peer identity can be confused after device replacement or snapshot restore. The new session should prove continuity or be treated as a separate peer generation.

### Peer eviction

Peer eviction frees a bounded slot, but it can also orphan leases, retransmissions, and revocation context. Eviction should be allowed only after dependent state is revoked, expired, or moved to a durable tombstone.

An eviction policy based only on age or liveness can break security history. A quiet peer may still be the ancestor of active delegated authority.

### Concurrent peer operations

Concurrent peer operations include receiving control frames, sending retransmissions, restoring state, rotating keys, and evicting peers. Those operations touch the same session slot and should have one serialization rule.

The safest direction is to route peer mutation through a single owner or a narrow lock order. Mixed direct mutation from IRQ, timer, and service paths makes replay windows and key replacement hard to reason about.

## CapNet Control Protocol Audit

### Control-frame header

The CapNet control-frame header is the admission point for every peer message. It must bind message type, sequence, acknowledgement, payload length, session, issuer, and authenticator before the payload is interpreted.

### Control message types

Control message types are deliberately few: hello, attestation, heartbeat, token offer, acceptance, revocation, and acknowledgement. Unknown types should be rejected with counters and no state mutation, because treating them as ignorable can hide downgrade or version-skew failures.

### Hello exchange

The hello exchange starts peer liveness and session negotiation. It should not by itself establish trust. Trust requires identity policy, measurement or pinned peer state, session-key agreement, and replay-window initialization.

### Attestation exchange

The attestation exchange carries measurement evidence, but evidence is useful only if the verifier knows the trust source and freshness rule. A measurement value without provenance should not authorize token acceptance.

### Heartbeat exchange

Heartbeat exchange tracks peer liveness and sequence progress. It should not refresh trust blindly; a heartbeat under a stale key or old epoch should fail before extending session lifetime.

### Token offer

A token offer is the remote authority handoff. It should be accepted only after frame authentication, replay rejection, token verification, delegation checks, revocation checks, and central lease installation all agree.

### Token acceptance

Token acceptance acknowledges that a peer processed an offer. It should not be treated as proof that the remote authority became durable unless the protocol defines persistence and replay behavior for accepted tokens.

### Token revocation

Token revocation is security-critical traffic. It must be authenticated, replay-resistant, durable enough for restart, and applied before any future token use or descendant delegation succeeds.

### Acknowledgement fields

Acknowledgement fields remove retransmission state and therefore affect reliability. They must identify the correct peer, session epoch, sequence, and message class before deleting a pending entry.

### Acknowledgement-only flag

Acknowledgement-only frames should be cheap but not trusted cheaply. They still need frame authentication and replay checks because they can remove retransmission obligations.

### Payload-length validation in CapNet Control Protocol

Payload-length validation should happen before any message-specific parser runs. Each control type has a different legal payload shape, and accepting a generic bounded length is not enough for token or revocation messages.

### Frame MAC construction

Frame MAC construction authenticates the control header and payload under the active session key. The security claim is only as strong as session-key establishment and epoch separation.

### Session and issuer binding

Session and issuer binding prevents a valid frame from one peer context from mutating another. The frame authenticator should cover the session epoch, issuer identity, message type, acknowledgement fields, sequence, and payload bytes.

Issuer identity must be checked against the peer slot selected by the transport and session. If the frame says one issuer but arrives under another peer's session key, the kernel should reject it before queueing or acknowledgement processing.

### Replay rejection

Replay rejection must cover control sequences, token nonces, revocation epochs, and restored session state. A frame rejected as replay should be observable without leaking token bodies or keys.

### Unknown control-type handling

Unknown control types should be rejected without acknowledgement-driven side effects. That keeps future protocol versions from being accidentally treated as successful no-ops by older kernels.

### Incoming queue capacity

Incoming queue capacity is fixed, which bounds memory but creates a peer fairness problem. A noisy or hostile peer can occupy slots unless admission is partitioned or eviction policy considers peer identity and message class.

### Retransmission queue

The retransmission queue holds security messages that may still matter after packet loss. Dropping an old token offer and dropping a revocation do not have the same risk. The queue policy should distinguish those classes.

### Retransmission interval and retry limit

Retransmission interval and retry limits decide whether security traffic eventually succeeds, fails loudly, or consumes queue space forever. Revocations, token offers, heartbeats, and acknowledgements do not deserve the same retry policy.

The retry policy should expose terminal failure. A revocation that exhausts retries without acknowledgement is not merely a dropped packet; it is an unresolved security state that may require local tombstone retention, peer quarantine, or service-visible diagnostics.

### Acknowledgement-driven removal

Acknowledgement-driven removal should delete only the exact retransmission entry acknowledged by the authenticated peer. The match should include peer identity, session epoch, message sequence, and message class.

Removing by sequence alone is too weak once reconnects, retries, and different control message classes share a bounded queue. A forged or stale acknowledgement could otherwise suppress delivery of a later revocation or token offer.

### Duplicate delivery behavior

Duplicate delivery is normal over a retrying UDP control protocol. Duplicate heartbeats can be harmless, duplicate token offers must not install additional authority, and duplicate revocations should remain idempotent.

Each message class needs its own idempotence rule. The receiver should record enough canonical identity to distinguish safe replay from a second attempt to consume capacity, renew authority, or remove retransmission state.

### Queue overflow behavior in CapNet Control Protocol

Queue overflow should preserve the messages with the highest security consequence. Dropping an unauthenticated heartbeat is not equivalent to dropping an authenticated revocation or an acknowledgement that would stop retransmission pressure.

The incoming queue should also avoid letting one peer consume every slot. Partitioning by peer, reserving space for revocations, or applying per-peer pressure counters would make overflow behavior easier to reason about.

### Malformed control-frame handling

Malformed control frames should fail before they enter queues or mutate peer state. Header length, payload length, message type, reserved fields, epoch, issuer, sequence, and authenticator should be validated in that order.

Rejected frames still need bounded observability. Counters should identify the peer when authenticated enough to do so, but should not log token bodies, keys, nonces, or measurement secrets.

## CapNet Attestation Audit

### Device measurement representation

Device measurement representation gives CapNet a fixed value to compare, but the value is not the same as an attestation claim. The representation needs to state what was measured, which hash or measurement algorithm produced it, and which boot or runtime boundary it describes.

Without that context, two devices can exchange equal-length measurement bytes while disagreeing about their meaning. The verifier should treat the measurement as opaque evidence until policy assigns it a source and interpretation.

### Measurement trust source

The measurement trust source is the missing root of the attestation story. A peer can send measurement bytes over an authenticated session, but that proves only possession of the session key unless a trusted component produced or signed the measurement.

CapNet should distinguish local test measurements, pinned measurements, and measurements backed by a hardware or certificate chain. Those modes carry different security claims and should not share one success result.

### Attestation frame construction

Attestation frames should bind measurement bytes to the session, issuer, nonce, epoch, and policy mode. That prevents an old measurement from being copied into a new session without proving freshness.

Frame construction also needs a size and algorithm contract. A bounded payload protects the parser, but a verifier still needs to know which measurement algorithm and evidence format the payload represents.

### Attestation verification

Attestation verification should be a policy decision, not only a byte comparison. The verifier needs to check session binding, freshness, allowed algorithms, known measurements, certificate evidence where available, and whether the peer is permitted to enroll through the selected trust mode.

A failed verification should block token acceptance and authority installation for that peer. Liveness can remain separate, but unverified liveness should not become authorization.

### Session binding in CapNet Attestation

Session binding ensures attestation evidence was produced for the current exchange. The measurement should cover or accompany a nonce, epoch, or transcript value chosen during session setup.

This protects against replay across reconnects. A peer that once had an acceptable measurement should not be able to reuse that evidence after its key, epoch, or runtime image changes.

### Replay resistance

Replay resistance requires more than a session MAC. An attacker can replay a previously authenticated attestation if the session accepts old nonces, old epochs, or restored replay windows.

The verifier should remember recent attestation nonces or derive freshness from a current transcript. Restored sessions should require reattestation unless replay state and freshness evidence are restored with equivalent strength.

### Freshness policy

Freshness policy defines how long an attestation remains useful. It can be nonce-based, epoch-based, time-based, or tied to a device reset event, but it should be explicit.

If freshness is absent, attestation degrades into a cached identity hint. That may be acceptable for development, but not for granting remote capabilities in a hostile network.

### Algorithm agility

Algorithm agility should allow the measurement and signature format to evolve without downgrade. The frame needs an algorithm identifier, a supported-version policy, and a failure mode for unknown or deprecated algorithms.

Agility should not mean accepting any known algorithm. Each peer policy should specify the algorithms strong enough for the authority it may receive.

### Reserved Ed25519 path

The reserved Ed25519 path is a signpost for offline provenance, not an active security claim. Until signing keys, certificate binding, transcript coverage, and verification errors are wired, the system should not describe attestation as asymmetric or certificate-backed.

Keeping the placeholder is useful if the README is clear about its status. Tests should assert that the inactive path fails closed rather than silently accepting unsigned material as future-ready evidence.

### Offline certificate role

Offline certificates would let a verifier trust a peer before or outside an existing session key. They need a root trust store, certificate lifetime, device identity binding, measurement binding, revocation policy, and a way to reject certificates not authorized for CapNet.

That role is different from a session MAC. A session MAC proves continuity after key agreement, while an offline certificate can prove who was allowed to create that session.

### Certificate generation trust

Certificate generation trust depends on where signing keys live and who may issue device identities. Test-generated certificates can exercise parsing, but they should not be treated as production trust anchors.

The intended maturity point is a documented enrollment path. A device should either ship with trusted identity material, enroll through an authenticated administrator, or remain limited to development-only trust modes.

### Cross-device interoperability in CapNet Attestation

Cross-device interoperability requires both sides to agree on byte order, measurement algorithms, evidence shape, trust roots, session transcript fields, and failure codes. The current bounded frame model is a useful base, but it is not a complete interop contract.

Interop tests should use independently generated vectors rather than only local round trips. Otherwise both encoder and decoder can share the same mistaken assumption.

## CapNet Revocation Audit

### Token revocation processing

Token revocation processing must stop future use of the token and any descendants covered by policy. The check belongs at lease installation, token acceptance, delegation, restore, and every state-changing operation that consumes a remote grant.

Revocation should be treated as durable security state. If journal append fails or remote propagation cannot be confirmed, the operation should report a degraded state instead of presenting the revocation as fully complete.

### Revocation epoch allocation

Revocation epochs order security decisions. They should increase monotonically across runtime, restore, journal reconstruction, and remote propagation.

Epoch allocation should fail closed near wraparound. Reusing an epoch lets old revocation evidence collide with new authority and makes replay windows ambiguous.

### Tombstone capacity

Tombstone capacity bounds memory but limits how long revocation can be enforced in RAM. Once the table is full, replacement policy decides which revoked authority can become forgettable.

That policy needs to consider token expiry, descendant relationships, active leases, and journal durability. Oldest-first eviction is easy, but it is not automatically safe.

### Tombstone replacement policy

CapNet stores revocations in a fixed tombstone table. When full, insertion overwrites the entry with the oldest revocation time regardless of token expiry, descendant reachability, active remote leases, or journal reconstruction needs. A still-valid revoked token can consequently become acceptable again in memory after enough newer revocations, even though its log record remains persistent.

### Parent and descendant revocation

Parent and descendant revocation requires a reliable delegation graph. Revoking a parent should invalidate every child whose authority depends on that parent, even if the child was received through a different peer or restored from persistence.

The graph should be indexed by canonical token identity, not by table position. Slot reuse and tombstone eviction must not detach a descendant from the revoked ancestor it depends on.

### Remote lease revocation

Remote lease revocation is complete only when local use stops and peers that may hold the lease receive authenticated revocation evidence. UDP retransmission makes delivery probabilistic, so the sender must retain local tombstones even when remote acknowledgement is missing.

The service should expose unresolved remote revocations. Silent best-effort propagation is not enough for code that wants to reason about authority removal.

### Revocation precedence

Revocation should win over acceptance, delegation, restore, and cached liveness. Once a token identity or ancestor is revoked, later duplicate offers should not reinstall it unless a new issuer epoch and policy explicitly allow replacement authority.

Precedence should be checked before resource allocation. That keeps revoked grants from consuming queue, peer, or lease capacity before they are rejected.

### Revocation control-frame authentication

Revocation control frames must be authenticated under the correct peer session and issuer identity. An unauthenticated revocation can become a denial-of-service tool, while a stale authenticated revocation can corrupt a newer authority epoch.

The frame should bind token identity, revocation epoch, issuer, target peer, session epoch, and acknowledgement behavior. Missing any of those fields makes revocation replay or misdelivery harder to detect.

### Persistent revocation journal

Each revocation appends an unauthenticated component-event payload using a broadly constructed persistence capability. Append failure records an audit event but does not fail or roll back the revocation operation. The in-memory denial may therefore appear successful while restart durability is absent. The journal lacks an authenticated chain, commit marker, compaction contract, and explicit authority tied to the CapNet principal.

### Journal reconstruction

Journal reconstruction should rebuild the same revocation set that existed before shutdown, subject only to documented retention limits. Skipping malformed entries may keep boot moving, but it should also mark CapNet recovery as degraded.

Reconstruction needs ordering, integrity, and completeness checks. A bounded read that misses older records can be acceptable only if the journal also records a compaction point that proves omitted records no longer matter.

### Duplicate revocation

Duplicate revocation should be idempotent. Repeating the same revocation must not advance epochs unnecessarily, overflow the journal, or evict unrelated tombstones.

The duplicate check should use canonical token identity and issuer epoch. A retransmitted remote revocation is expected traffic, not a new security event.

### Revocation after restart

Initialization clears the tombstone table and rebuilds it from at most the persistence service log records returned by one bounded read. Decode failures are silently skipped, and table overflow again evicts the oldest restored tombstone. The next epoch derives only from records that survived decoding and the read bound. Restart can therefore forget revocations or reuse ordering state without reporting an unsafe recovery mode.

### Tombstone retention duration

Tombstone retention duration should be at least as long as the maximum lifetime of any token or descendant the tombstone can affect. If retention is shorter, an attacker can wait for eviction and replay an otherwise valid old token.

Retention can be bounded, but the bound must be part of token issuance policy. Long-lived tokens require long-lived revocation evidence or a different validation model.

### Revocation epoch wraparound

Revocation epoch wraparound should be treated as a fatal or rekey-required condition. Once epochs repeat, ordering comparisons can no longer prove whether a revocation is newer than an accepted grant.

The implementation should reserve the maximum value as exhausted and require journal compaction or device identity rotation before issuing another epoch.

## CapNet Persistence Audit

### Temporal state schema

The review treats temporal state schema as a distinct contract within this section. CapNet serializes peers, session keys, replay state, delegation records, tombstones, device identity, and epochs into a fixed schema. Structural validation exists, but secret protection, authenticated rollback defense, and atomic publication need a stronger persistence boundary. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Peer-session serialization

For peer-session serialization, the relevant behavior is distributed across the implementation described here. CapNet serializes peers, session keys, replay state, delegation records, tombstones, device identity, and epochs into a fixed schema. Structural validation exists, but secret protection, authenticated rollback defense, and atomic publication need a stronger persistence boundary. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Session-key persistence

The review treats session-key persistence as a distinct contract within this section. CapNet serializes peers, session keys, replay state, delegation records, tombstones, device identity, and epochs into a fixed schema. Structural validation exists, but secret protection, authenticated rollback defense, and atomic publication need a stronger persistence boundary. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Replay-window persistence

For replay-window persistence, the relevant behavior is distributed across the implementation described here. CapNet serializes peers, session keys, replay state, delegation records, tombstones, device identity, and epochs into a fixed schema. Structural validation exists, but secret protection, authenticated rollback defense, and atomic publication need a stronger persistence boundary. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Delegation-record serialization

delegation-record serialization is implemented only to the extent supported by the section evidence. CapNet serializes peers, session keys, replay state, delegation records, tombstones, device identity, and epochs into a fixed schema. Structural validation exists, but secret protection, authenticated rollback defense, and atomic publication need a stronger persistence boundary. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Revocation-tombstone serialization

The review treats revocation-tombstone serialization as a distinct contract within this section. CapNet serializes peers, session keys, replay state, delegation records, tombstones, device identity, and epochs into a fixed schema. Structural validation exists, but secret protection, authenticated rollback defense, and atomic publication need a stronger persistence boundary. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Local device identity restoration

The review treats local device identity restoration as a distinct contract within this section. CapNet serializes peers, session keys, replay state, delegation records, tombstones, device identity, and epochs into a fixed schema. Structural validation exists, but secret protection, authenticated rollback defense, and atomic publication need a stronger persistence boundary. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Revocation epoch restoration

For revocation epoch restoration, the relevant behavior is distributed across the implementation described here. CapNet serializes peers, session keys, replay state, delegation records, tombstones, device identity, and epochs into a fixed schema. Structural validation exists, but secret protection, authenticated rollback defense, and atomic publication need a stronger persistence boundary. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Slot-count validation

Slot-count validation prevents a restored payload from claiming more peers, delegations, or tombstones than the fixed tables can hold. The count check should run before any record is decoded into live state.

Counts also need semantic checks. A payload can stay within table limits while containing duplicate peers, disconnected delegation children, or tombstones that refer to unknown token identities.

### Payload-length validation in CapNet Persistence

Payload-length validation should prove that every declared record has enough bytes and that no parser can advance past the saved buffer. The outer schema length is only the first check; each nested table and record type needs its own bound.

Length validation should complete before publication. A malformed tombstone near the end of the payload should not leave a restored peer table visible with old revocation state.

### Trailing-byte rejection

Trailing-byte rejection keeps the schema canonical. If a payload contains extra bytes after the declared records, the restore path should reject it before touching live state.

This prevents future or attacker-controlled fields from being smuggled through old code. A new schema should use a new version, not hidden bytes appended to the old one.

### Restore-time semantic validation

Restore-time semantic validation should rebuild the security graph in private memory before it becomes active. Structural validity is not enough; the candidate state must satisfy peer identity uniqueness, session epoch ordering, replay-window monotonicity, delegation ancestry, rights attenuation, token expiry, and revocation precedence.

The restore path should also verify that saved scalar counters cannot move backward. Revocation epochs, sequence allocators, and session epochs are security clocks, and rollback can make old traffic valid again.

### Restore collision handling

Restore collision handling covers duplicate peers, duplicate token identities, reused nonces, repeated revocation epochs, and delegation records that point at the same child through different parents. These should be explicit errors, not last-writer-wins behavior.

Collision policy matters for rollback defense. A stale snapshot can reintroduce a peer identity or token identity that the live system already rotated away.

### Restore publication atomicity

CapNet validates the outer payload size, type, schema, and slot counts before restoration, but then decodes directly into the live peer table, delegation table, and tombstone table under separate locks. Local device identity and the next revocation epoch are updated afterward.

An error while decoding a later record returns after earlier global tables have already been replaced. Concurrent readers can also observe a restored peer table with old delegation and revocation state between lock scopes. The final trailing-byte check occurs only after all three live tables have been mutated.

Restoration must decode and semantically validate a complete candidate state in private memory, including duplicate identities, trust values, key epochs, replay windows, delegation ancestry, rights, temporal ranges, revocation precedence, and allocator monotonicity. One authenticated replay transaction should then publish all tables and scalar state under a single generation change or leave the previous state untouched.

### Persistence authority

Persistence authority should be a real capability decision. Writing CapNet state means preserving device identity, session keys, replay windows, and revocation history; restoring it means accepting that state as security-relevant input.

The persistence caller should prove authority to save and restore CapNet state specifically. A broad kernel persistence path is convenient, but it does not show which principal was allowed to alter remote-capability history.

### Revocation journal consistency

Revocation journal consistency requires the journal, tombstone table, and next epoch to describe the same history. If a tombstone exists without a durable journal record, restart may forget it. If a journal record exists but reconstruction skips it, the in-memory state understates revoked authority.

The journal should include integrity, ordering, and commit markers. Recovery should report whether it restored a complete prefix, a compacted summary, or a degraded partial view.

### Secret material at rest

Secret material at rest is the largest persistence risk in CapNet. Session keys and replay state are useful to an attacker if they can read, roll back, or transplant the saved blob.

The mature contract should encrypt or wrap secrets, authenticate the full snapshot, bind it to the local device identity, and reject rollback unless policy explicitly restores an offline image. If those protections are absent, persistence should avoid storing live session keys and force rekey on restore.

## CapNet Audit and Metrics Audit

### Security event coverage

Security event coverage should follow the authority lifecycle: peer enrollment, attestation result, token offer, token acceptance, delegation, revocation, replay rejection, key replacement, restore, and audit loss. Missing any of those events makes post-incident reconstruction incomplete.

Events should be compact and structured. Logging full tokens, measurements, keys, or payloads would improve debugging while creating a second secret channel.

### Event principal attribution

Event principal attribution should identify the local principal, remote peer identity, issuer identity, subject identity, and object identity when they are known. Kernel-context attribution alone is too coarse for a distributed capability system.

Attribution must respect the authentication stage. Before a frame is authenticated, the claimed issuer is untrusted input and should be recorded as such or omitted.

### Event context quality

Useful event context ties a decision to its reason without leaking secrets. For example, a token rejection should say whether the cause was expiry, rights expansion, revoked ancestor, replay, unsupported algorithm, or failed session binding.

The context should also include generation data where possible. Peer epoch, revocation epoch, and token identity are enough to correlate events without copying the entire token body.

### Token lifecycle correlation

Token lifecycle correlation should connect issuance, offer, acceptance, delegation, use, quota exhaustion, revocation, and restore decisions through one canonical token identity. Without that link, a reviewer can see isolated events but not the authority chain.

Correlation also helps detect inconsistencies. A token used after revocation or delegated after expiry should stand out as a broken invariant, not as two unrelated log lines.

### Peer-session correlation

Peer-session correlation should group hello, attestation, key derivation, heartbeats, replay failures, token traffic, and disconnect under one peer session epoch. That makes reconnect and impersonation analysis possible.

Events from an old epoch should not be merged with events from a new session simply because the device identity matches. Epoch separation is part of the security story.

### Replay rejection counters

Replay rejection counters should be split by source: token nonce, control sequence, attestation freshness, revocation epoch, and restored replay window. One aggregate counter hides which defense is doing work.

Counters should saturate safely, but saturation should itself be visible. A saturated replay counter is evidence of either sustained attack or insufficient diagnostic width.

### Decode success and failure counters

Decode success and failure counters should distinguish token, control-frame, attestation, persistence, and journal decoding. These paths have different threat models and remediation paths.

Failure counters should preserve the broad failure class, such as length, version, reserved field, authenticator, semantic invariant, or unsupported algorithm. That gives fuzzing and operations a way to identify which parser is weak without logging sensitive inputs.

### Saturating metric behavior

Saturating counters avoid wraparound, which is the right default for security metrics. A wrapped replay counter can look like recovery when it actually indicates sustained pressure.

The metric API should expose when a counter saturated. That flag helps distinguish normal bounded activity from lost diagnostic precision.

### Fuzz failure capture

Fuzz failure capture should preserve the minimized input class, parser stage, and invariant that failed. It does not need to store raw secrets or full random corpora in the main audit stream.

The useful output is a stable regression handle: token decode failure, control frame replay bug, restore collision, delegation attenuation failure, or revocation precedence error.

### Sensitive field redaction

Sensitive field redaction should be default behavior. Session keys, token authenticators, nonces, full measurements, payload bytes, and certificate material should not enter ordinary logs.

Redaction should not erase correlation. Hashes or canonical identifiers can connect events while keeping the authority material out of diagnostics.

### Audit loss behavior

Network auditing and temporal recording are generally best effort. CapNet suppresses audit output during fuzzing, revocation append failures emit another audit event without changing the operation result, and network and Wi-Fi temporal record calls discard their return values. If the audit or persistence sink is itself unavailable, the secondary evidence may also disappear.

Secondary logging cannot repair primary loss when both use the same unavailable infrastructure. For example, a failed revocation append attempts to emit an integrity event, but that event has no durable acknowledgement and the revocation still returns normally. The subsystem needs an independent monotonic health indicator or reserved emergency record path so later diagnostics can prove that evidence was dropped even when the normal audit sink failed.

### Concurrent metric consistency

Concurrent metric consistency matters because CapNet events can come from receive, retransmission, restore, and service paths. Counters should be atomic or updated under the same owner that mutates the related security state.

Snapshots should describe one observation generation. A peer snapshot from one moment and a journal statistic from another can mislead readers about whether revocation and session state agree.

## Error Taxonomy and Mapping Audit

### Network service errors

Network service errors should describe the operation result, not only the subsystem that failed. A caller needs to know whether it should retry, reconfigure, request authority, close a handle, or report protocol corruption.

The current mix of typed values, strings, booleans, zero-length results, and silent drops makes those decisions inconsistent. A common network error type should preserve retryability, authorization state, resource exhaustion, malformed input, timeout, reset, and unsupported operation.

### Driver errors

Driver errors come from hardware readiness, descriptor ownership, link state, MMIO or port I/O assumptions, DMA visibility, and transmit timeouts. These failures should not collapse into the same result as a malformed packet or unauthorized send.

The driver layer also needs to distinguish recoverable reset conditions from permanent unsupported-device conditions. That distinction controls whether initialization should retry, fall back to another backend, or mark networking unavailable.

### Reactor errors

Reactor errors describe publication, queueing, completion, cancellation, timeout, and inline fallback failures. They should preserve whether the stack owner processed the request, whether the request was never admitted, or whether completion was lost.

This matters because reactor failure is not the same as protocol failure. A DNS request can fail because the packet was malformed, because ARP never resolved, or because the reactor request slot was unavailable.

### Protocol parsing errors

Protocol parsing errors should identify the layer and broad failure class. Ethernet length, IPv4 checksum, UDP length, DNS compression, TCP option, HTTP header, TLS record, Wi-Fi information element, and CapNet token failures need different counters and tests.

Dropping malformed packets is often correct, but silent drops are weak diagnostics. The parser should return enough information for bounded counters without exposing packet bodies or secret material.

### TCP and DNS string errors

TCP and DNS string errors are easy to write and hard to audit. They cannot be exhaustively matched by the compiler, and callers tend to treat unrelated failures the same way once the error becomes text.

Those paths should move to typed results before they become stable user-facing contracts. Human-readable text can be formatting layered over a structured error, not the programmatic identity.

### TLS errors

TLS errors carry security meaning. Unsupported version, bad certificate, hostname mismatch, failed Finished validation, record authentication failure, malformed record, alert, and closed session should not collapse into a generic network failure.

The caller also needs to distinguish peer-authentication failure from transport loss. Retrying a failed certificate validation is not equivalent to retrying a dropped packet.

### Wi-Fi errors

Wi-Fi errors span device initialization, scan exhaustion, malformed management frames, authentication failure, association failure, EAPOL replay, MIC failure, key unwrap failure, timeout, and disconnect. Those failures affect both security and user-visible connection state.

The implementation should classify them by phase. A bad password, spoofed handshake, missing hardware, and temporary scan timeout should not produce the same recovery behavior.

### CapNet errors

CapNet errors should preserve authority semantics. Expired token, revoked token, rights expansion, bad delegation parent, replayed frame, unauthenticated peer, unsupported algorithm, quota exhaustion, and persistence rollback are different security outcomes.

The error type should also say whether state changed. A rejected token offer, a partially persisted revocation, and a failed remote acknowledgement require different cleanup.

### Initialization errors

Initialization errors should identify which stage failed: configuration, driver probe, MMIO mapping, DMA setup, MAC discovery, reactor startup, static address assignment, CapNet initialization, or temporal restore.

That stage information controls rollback. If driver initialization fails after bus mastering is enabled, the cleanup path is different from a configuration parse failure before hardware mutation.

### Temporary and terminal failures

Temporary and terminal failures should be a first-class classification. Queue pressure, ARP timeout, DNS retry, TCP retransmission, and link-not-ready are temporary under some policies. Revoked authority, malformed token, unsupported TLS version, and certificate failure are not.

When those categories merge, callers either retry terminal failures forever or give up on work that could have completed after backoff.

### Resource exhaustion

Resource exhaustion should name the exhausted resource. TCP connection slots, UDP receive queues, DNS cache entries, CapNet peers, retransmission entries, driver descriptors, and heap allocation all imply different recovery actions.

The error should also say whether the operation was admitted before exhaustion was detected. Partial admission determines whether cleanup or rollback is required.

### Timeout and cancellation

Timeout and cancellation should not be inferred from absence of data. A timed-out DNS query, cancelled TCP connect, expired CapNet retransmission, and user-cancelled request need distinct results.

Cancellation should also define cleanup. A cancelled request may need to remove reactor slots, retransmission entries, socket state, or queued receive records.

### Error conversion across layers

Error conversion across layers should be exhaustive and documented. Driver, reactor, protocol, service, TLS, Wi-Fi, and CapNet errors can collapse only when the caller truly does not need the distinction.

The current pattern loses too much information at boundaries. Once an error becomes a boolean or static string, downstream code cannot decide whether retry, revocation, reset, or user-visible failure is correct.

### Static string error identity

Static string error identity should be removed from program logic. Strings are presentation, not ABI, and changing punctuation or wording should not affect behavior.

Where text remains useful, it should be generated from a typed error code. That keeps documentation, tests, and call sites aligned.

### User-visible error mapping

User-visible error mapping should stabilize only after the internal taxonomy is stable. Socket APIs, service calls, WASM host functions, and kernel clients may need different presentations, but they should all derive from the same canonical result.

The mapping should preserve security-relevant distinctions. Unauthorized, revoked, malformed, unsupported, exhausted, timeout, reset, and closed should not all appear as generic failure.

### Diagnostic specificity

Diagnostic specificity lets operators understand failure without exposing sensitive packets or keys. The subsystem should report the layer, operation, failure class, peer or socket identity where safe, and whether state changed.

That information should be available even when the public API intentionally returns a coarse result. Security policy can hide detail from untrusted callers while preserving it for privileged diagnostics.

## Concurrency and Synchronization Audit

### Global network service lock

The global network service lock protects legacy service state, but it is not the same as a complete network concurrency model. Drivers, the reactor, CapNet, temporal recording, and IRQ paths also mutate shared state.

The lock contract should identify which data it owns and which data belongs to the reactor or driver locks. Without that map, nested calls can accidentally rely on lock ordering that is not documented.

### Reactor single-owner invariant

The reactor single-owner invariant is the strongest concurrency idea in the network stack. It keeps protocol state mutation on one task and lets other contexts publish requests rather than directly editing TCP, UDP, DNS, and ARP tables.

The invariant weakens whenever a path mutates stack state outside the reactor. Those exceptions should be listed and either removed, locked behind the same owner, or tested as deliberate escape hatches.

### IRQ and task-context interaction

IRQ and task-context interaction should be limited to acknowledgement, pending-work publication, and wakeup. The interrupt path should not parse untrusted packets deeply or acquire locks that can be held by the reactor while interrupts are enabled.

The documentation should state which atomics bridge the two contexts and what memory ordering they require. That is especially important on weakly ordered targets.

### Atomic memory ordering

Atomic memory ordering must match the data it publishes. A pending-work flag that only wakes a task can be weaker than a flag that publishes descriptor or request-slot contents.

The stack should document every atomic as notification-only, data-publishing, or synchronization-with-device. That classification drives whether relaxed, acquire, release, or stronger ordering is required.

### Static mutable packet buffers

Static mutable packet buffers avoid allocation and keep early boot networking simple. They also concentrate aliasing risk because several call paths can want staging memory at once.

Each buffer should have a named owner and lifetime: driver DMA, reactor staging, CapNet control frame, TLS record, or temporary parser scratch. Shared reuse should be proven by serialization, not by convention.

### Driver global state

Driver global state represents hardware that is effectively singleton in the current kernel. That matches early bring-up, but it makes hotplug, failover, multiple NICs, and per-interface isolation harder.

The ownership model should eventually move from global driver state to interface instances with explicit DMA buffers, interrupt lines, and capability-scoped administration.

### DMA and CPU ownership transitions

DMA and CPU ownership transitions are the main safety boundary in the drivers. A descriptor or buffer should be owned either by hardware or by the kernel, never both.

The transition needs memory fences and descriptor status checks that match the target architecture. x86 testing alone does not prove visibility on AArch64.

### Nested lock ordering

Nested lock ordering should be written as a small table rather than left implicit. Network service, reactor request slots, driver locks, CapNet peer locks, revocation journal locks, temporal persistence, and audit recording can interact during error paths.

The dangerous cases are secondary effects under lock, especially temporal recording or audit emission after a state change. Those calls can reenter services or block on infrastructure the caller already depends on.

### CapNet peer and journal locks

capnet peer and journal locks is implemented only to the extent supported by the section evidence. The reactor intends single stack ownership, drivers and CapNet use spin mutexes, and interrupts publish atomic work. Static mutable buffers, global tables, timeout reuse, and implicit lock order prevent a complete race and deadlock proof. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Temporal recording under locks

For temporal recording under locks, the relevant behavior is distributed across the implementation described here. The reactor intends single stack ownership, drivers and CapNet use spin mutexes, and interrupts publish atomic work. Static mutable buffers, global tables, timeout reuse, and implicit lock order prevent a complete race and deadlock proof. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Reentrancy

For reentrancy, the relevant behavior is distributed across the implementation described here. The reactor intends single stack ownership, drivers and CapNet use spin mutexes, and interrupts publish atomic work. Static mutable buffers, global tables, timeout reuse, and implicit lock order prevent a complete race and deadlock proof. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Interrupt-disable critical sections

For interrupt-disable critical sections, the relevant behavior is distributed across the implementation described here. The reactor intends single stack ownership, drivers and CapNet use spin mutexes, and interrupts publish atomic work. Static mutable buffers, global tables, timeout reuse, and implicit lock order prevent a complete race and deadlock proof. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Deadlock resistance

For deadlock resistance, the relevant behavior is distributed across the implementation described here. The reactor intends single stack ownership, drivers and CapNet use spin mutexes, and interrupts publish atomic work. Static mutable buffers, global tables, timeout reuse, and implicit lock order prevent a complete race and deadlock proof. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Data-race resistance

Current support for data-race resistance must be read together with the stated subsystem boundary. The reactor intends single stack ownership, drivers and CapNet use spin mutexes, and interrupts publish atomic work. Static mutable buffers, global tables, timeout reuse, and implicit lock order prevent a complete race and deadlock proof. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

## Memory Safety Audit

### Packet length validation

The audit of packet length validation follows the active data and control path rather than module comments. The implementation uses Rust bounds checks around many parsers but also relies on volatile MMIO, port I/O, DMA, UnsafeCell, static mutable arrays, and unchecked hardware assumptions. Safety depends on invariants that are not consistently represented by types. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Header offset arithmetic

header offset arithmetic is implemented only to the extent supported by the section evidence. The implementation uses Rust bounds checks around many parsers but also relies on volatile MMIO, port I/O, DMA, UnsafeCell, static mutable arrays, and unchecked hardware assumptions. Safety depends on invariants that are not consistently represented by types. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Fixed-array bounds

fixed-array bounds is implemented only to the extent supported by the section evidence. The implementation uses Rust bounds checks around many parsers but also relies on volatile MMIO, port I/O, DMA, UnsafeCell, static mutable arrays, and unchecked hardware assumptions. Safety depends on invariants that are not consistently represented by types. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Receive-buffer bounds

Current support for receive-buffer bounds must be read together with the stated subsystem boundary. The implementation uses Rust bounds checks around many parsers but also relies on volatile MMIO, port I/O, DMA, UnsafeCell, static mutable arrays, and unchecked hardware assumptions. Safety depends on invariants that are not consistently represented by types. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Transmit-buffer bounds

transmit-buffer bounds is implemented only to the extent supported by the section evidence. The implementation uses Rust bounds checks around many parsers but also relies on volatile MMIO, port I/O, DMA, UnsafeCell, static mutable arrays, and unchecked hardware assumptions. Safety depends on invariants that are not consistently represented by types. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Ring index arithmetic

For ring index arithmetic, the relevant behavior is distributed across the implementation described here. The implementation uses Rust bounds checks around many parsers but also relies on volatile MMIO, port I/O, DMA, UnsafeCell, static mutable arrays, and unchecked hardware assumptions. Safety depends on invariants that are not consistently represented by types. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Descriptor index validation

descriptor index validation is implemented only to the extent supported by the section evidence. The implementation uses Rust bounds checks around many parsers but also relies on volatile MMIO, port I/O, DMA, UnsafeCell, static mutable arrays, and unchecked hardware assumptions. Safety depends on invariants that are not consistently represented by types. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### DMA buffer lifetime

The review treats dma buffer lifetime as a distinct contract within this section. The implementation uses Rust bounds checks around many parsers but also relies on volatile MMIO, port I/O, DMA, UnsafeCell, static mutable arrays, and unchecked hardware assumptions. Safety depends on invariants that are not consistently represented by types. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### MMIO pointer validity

Current support for mmio pointer validity must be read together with the stated subsystem boundary. The implementation uses Rust bounds checks around many parsers but also relies on volatile MMIO, port I/O, DMA, UnsafeCell, static mutable arrays, and unchecked hardware assumptions. Safety depends on invariants that are not consistently represented by types. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Port I/O safety in Memory Safety

For port i/o safety, the relevant behavior is distributed across the implementation described here. The implementation uses Rust bounds checks around many parsers but also relies on volatile MMIO, port I/O, DMA, UnsafeCell, static mutable arrays, and unchecked hardware assumptions. Safety depends on invariants that are not consistently represented by types. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Volatile access correctness

volatile access correctness is implemented only to the extent supported by the section evidence. The implementation uses Rust bounds checks around many parsers but also relies on volatile MMIO, port I/O, DMA, UnsafeCell, static mutable arrays, and unchecked hardware assumptions. Safety depends on invariants that are not consistently represented by types. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Shared static mutable aliases

shared static mutable aliases is implemented only to the extent supported by the section evidence. The implementation uses Rust bounds checks around many parsers but also relies on volatile MMIO, port I/O, DMA, UnsafeCell, static mutable arrays, and unchecked hardware assumptions. Safety depends on invariants that are not consistently represented by types. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Unsafe synchronization assumptions

Unsafe synchronization assumptions should be documented next to the state they protect. Static mutable buffers, device rings, UnsafeCell storage, and lock-protected global tables each rely on a different access rule.

The audit gap is not that unsafe code exists. The gap is that several safety arguments live as conventions rather than type-level ownership, scoped guards, or checked state transitions.

### Integer conversion and truncation

Integer conversion and truncation appear wherever packet lengths, descriptor indexes, DMA addresses, port numbers, sequence numbers, and schema sizes cross type boundaries. Each conversion should state the accepted range and reject values that cannot round-trip.

This is especially important for native-size integers in protocol-facing or persistence-facing code. A value that fits on one target can truncate on another target and create a different wire or restore interpretation.

### Sequence-number wraparound

Sequence-number wraparound affects TCP, DNS identifiers, CapNet control sequences, token nonces, revocation epochs, and driver rings. Some wraparound is protocol-defined, while other wraparound should force a new epoch or fail closed.

The document should distinguish modular arithmetic from exhausted identifiers. Treating every counter as naturally wrapping is unsafe for replay protection and revocation ordering.

### Parser panic resistance

Parser panic resistance means malformed network input should return a rejection, not unwind through kernel code. Bounds checks help, but explicit length guards and checked cursor movement make the intended failure mode clear.

Every parser that handles attacker-controlled bytes should have negative tests for short headers, oversized lengths, trailing bytes, invalid compression pointers, unsupported options, and repeated boundary values.

### Secret zeroization

Secret zeroization applies to TLS traffic secrets, Wi-Fi passphrases and keys, CapNet session keys, token authenticators, and temporary key-derivation material. Fixed arrays and static storage will retain bytes until explicitly overwritten.

Zeroization should run on session close, failed handshake, restore rejection, peer eviction, key replacement, and driver teardown where secrets may have passed through staging memory.

### Uninitialized memory exposure

Uninitialized memory exposure can occur when transmit buffers, TLS records, control frames, driver descriptors, or persistence payloads advertise more bytes than were intentionally written. The safe rule is to zero staging buffers or track initialized length separately from capacity.

DMA buffers deserve special care because hardware can read or write them outside normal Rust aliasing rules. Ownership transitions should prove that only initialized bytes are transmitted.

### Stack usage

Stack usage matters because packet, TLS, DNS, HTTP, and Wi-Fi parsing often needs temporary arrays. Large fixed buffers should not appear on interrupt stacks or narrow kernel stacks.

The audit should keep a short inventory of large locals and move long-lived staging to owned buffers with clear synchronization. Stack budget tests are useful once target stack sizes are fixed.

### Heap allocation failure

Heap allocation failure should be an explicit result where allocation remains in network paths. Many structures are fixed-capacity, but HTTP bodies, dynamic helpers, or future certificate parsing can still allocate.

The kernel should not rely on panic or implicit allocation success for untrusted network input. Allocation failure is a resource condition, not protocol corruption.

## Resource and Capacity Audit

### Maximum network connections

Maximum network connections should be one documented capacity contract rather than a collection of table lengths. TCP connections, listeners, accepted sockets, DNS state, TLS sessions, CapNet peers, and driver rings all contribute to the practical ceiling.

The limit should also define refusal behavior. A new connection can be rejected before state allocation, reset after partial setup, or queued for later acceptance, and each path has different cleanup requirements.

### TCP connection capacity

TCP connection capacity bounds active state machines. Exhaustion should reject new active opens and passive accepts without corrupting existing connections.

The stack should expose how many slots are used, how many are closing, and how many are stuck in retransmission or time-wait. Without that split, a SYN flood and a cleanup leak can look identical.

### TCP listener capacity

TCP listener capacity bounds how many ports can accept inbound connections. Listener admission should check port collision, authority, backlog capacity, and table space before publishing a listening endpoint.

If listener creation partially succeeds and later fails, the port should not remain reserved invisibly. That cleanup path needs direct tests.

### Accept backlog capacity

Accept backlog capacity is the buffer between passive open and application acceptance. When it fills, the stack must decide whether to drop the SYN, reset the connection, leave it half-open, or apply backpressure.

That policy is security-sensitive because backlog exhaustion is a common denial-of-service path. Backlog counters and refusal reasons should be observable.

### DNS cache capacity

DNS cache capacity bounds positive and negative knowledge. Eviction should consider expiry, query name, record type, and whether an entry came from an authenticated or merely matched response.

A full cache should not accept attacker-controlled churn that evicts useful entries without counters. Cache pressure is part of DNS spoofing resistance.

### UDP receive capacity

UDP receive capacity should be partitioned by port or socket when possible. A noisy port should not be able to starve CapNet control traffic or unrelated application traffic.

Overflow behavior should preserve the final drop reason and payload length without storing the payload. That gives diagnostics enough information to identify floods.

### ARP cache capacity

ARP cache capacity bounds local-neighbor knowledge. Replacement policy should prefer expired or unconfirmed entries over actively used gateway or local peer entries.

Cache pressure should be visible because an attacker on the same link can churn sender addresses and degrade routing.

### HTTP buffer capacity

HTTP buffer capacity controls header parsing, response body storage, and server request handling. The implementation should reject oversized headers and bodies before copying more data than the configured limit.

The HTTP layer should also report whether truncation happened. Silent truncation is dangerous because it can turn protocol failure into apparently valid application data.

### TLS session capacity

TLS session capacity bounds both memory and secret lifetime. A full session table should reject new handshakes cleanly and zero any temporary secrets from failed admission.

Session reuse or handle reuse should carry a generation so stale handles cannot address a new session after cleanup.

### Wi-Fi scan capacity

Wi-Fi scan capacity bounds discovered networks. Duplicate network handling, signal ordering, SSID length, and security mode should be part of the replacement policy.

A full scan table should not let spoofed beacons hide a known network without recording that scan pressure occurred.

### Driver ring capacity

Driver ring capacity bounds hardware-visible work. Receive rings need replenishment guarantees, while transmit rings need completion and timeout handling.

Ring-full behavior should distinguish normal pressure from stuck descriptors. A full transmit ring after completions stop is a recovery signal, not ordinary backpressure.

### Reactor request capacity

Reactor request capacity controls how many callers can publish work to the stack owner. When slots fill, callers need a typed refusal that distinguishes temporary pressure from a stopped reactor.

Inline fallback should be documented as an exception to single-owner flow. It can keep progress moving, but it must not mutate state concurrently with the reactor.

### CapNet peer capacity

CapNet peer capacity limits distributed trust relationships. Admission should consider peer authority, trust mode, pinned measurement, and active leases before consuming a slot.

Eviction should not discard revocation or delegation history needed to validate existing tokens.

### CapNet delegation capacity

CapNet delegation capacity bounds the graph of remote authority. A full delegation table should reject new children rather than dropping ancestors that are still needed for revocation checks.

The table should expose occupancy by issuer or peer so one remote device cannot monopolize delegation space.

### CapNet revocation capacity

CapNet revocation capacity determines how long revoked tokens remain rejected in memory. Tombstones are security state, not ordinary cache entries.

When the revocation table fills, the eviction rule should prove that removed tombstones can no longer affect valid tokens or that the persistent journal will still reject them on restore.

### CapNet incoming queue capacity

CapNet incoming queue capacity protects memory but can suppress security traffic under load. Queue policy should prioritize authenticated revocations and acknowledgements over low-value liveness traffic.

The queue should also account by peer. A hostile peer should not be able to prevent another peer's revocation frame from being processed.

### CapNet retransmission capacity

CapNet retransmission capacity bounds how many reliable control messages can be outstanding over UDP. Revocations, token offers, and handshakes should not compete as equal entries.

When the retransmission table fills, new security messages should receive a typed refusal or replace only lower-priority messages according to documented policy.

### Aggregate network memory bound

The aggregate network memory bound should add together static buffers, driver rings, protocol tables, TLS sessions, Wi-Fi scan records, CapNet tables, caches, and dynamic allocation ceilings. Individual fixed tables do not prove the whole subsystem is bounded.

A single configuration summary would make target sizing and denial-of-service review much easier.

### Exhaustion behavior

Exhaustion behavior should be deterministic. Every fixed table and queue needs a documented result for full, including whether the oldest entry is evicted, the newest request is rejected, or a priority rule applies.

The result should include a diagnostic counter and rollback rule. Exhaustion should not create partially visible sockets, tokens, peer records, or descriptors.

## Temporal and Recovery Audit

### Network configuration snapshots

The review treats network configuration snapshots as a distinct contract within this section. Legacy networking, NetworkStack, Wi-Fi, and CapNet have separate restore schemas and entry points. Recording is disabled in several paths, while authenticated epochs, hardware reconciliation, atomic publication, and rollback are incomplete. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Legacy network service snapshots

Current support for legacy network service snapshots must be read together with the stated subsystem boundary. Legacy networking, NetworkStack, Wi-Fi, and CapNet have separate restore schemas and entry points. Recording is disabled in several paths, while authenticated epochs, hardware reconciliation, atomic publication, and rollback are incomplete. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### TCP listener restoration

The review treats tcp listener restoration as a distinct contract within this section. Legacy networking, NetworkStack, Wi-Fi, and CapNet have separate restore schemas and entry points. Recording is disabled in several paths, while authenticated epochs, hardware reconciliation, atomic publication, and rollback are incomplete. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### TCP connection restoration

tcp connection restoration is implemented only to the extent supported by the section evidence. Legacy networking, NetworkStack, Wi-Fi, and CapNet have separate restore schemas and entry points. Recording is disabled in several paths, while authenticated epochs, hardware reconciliation, atomic publication, and rollback are incomplete. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### DNS cache restoration

The audit of dns cache restoration follows the active data and control path rather than module comments. Legacy networking, NetworkStack, Wi-Fi, and CapNet have separate restore schemas and entry points. Recording is disabled in several paths, while authenticated epochs, hardware reconciliation, atomic publication, and rollback are incomplete. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Wi-Fi state restoration

For wi-fi state restoration, the relevant behavior is distributed across the implementation described here. Legacy networking, NetworkStack, Wi-Fi, and CapNet have separate restore schemas and entry points. Recording is disabled in several paths, while authenticated epochs, hardware reconciliation, atomic publication, and rollback are incomplete. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Live Wi-Fi reconnect requirements

The review treats live wi-fi reconnect requirements as a distinct contract within this section. Legacy networking, NetworkStack, Wi-Fi, and CapNet have separate restore schemas and entry points. Recording is disabled in several paths, while authenticated epochs, hardware reconciliation, atomic publication, and rollback are incomplete. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### TLS state persistence policy

Current support for tls state persistence policy must be read together with the stated subsystem boundary. Legacy networking, NetworkStack, Wi-Fi, and CapNet have separate restore schemas and entry points. Recording is disabled in several paths, while authenticated epochs, hardware reconciliation, atomic publication, and rollback are incomplete. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Driver state restoration policy

driver state restoration policy is implemented only to the extent supported by the section evidence. Legacy networking, NetworkStack, Wi-Fi, and CapNet have separate restore schemas and entry points. Recording is disabled in several paths, while authenticated epochs, hardware reconciliation, atomic publication, and rollback are incomplete. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### CapNet state restoration

The review treats capnet state restoration as a distinct contract within this section. Legacy networking, NetworkStack, Wi-Fi, and CapNet have separate restore schemas and entry points. Recording is disabled in several paths, while authenticated epochs, hardware reconciliation, atomic publication, and rollback are incomplete. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Replay-time network I/O suppression

replay-time network i/o suppression is implemented only to the extent supported by the section evidence. Legacy networking, NetworkStack, Wi-Fi, and CapNet have separate restore schemas and entry points. Recording is disabled in several paths, while authenticated epochs, hardware reconciliation, atomic publication, and rollback are incomplete. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Hardware reconciliation

hardware reconciliation is implemented only to the extent supported by the section evidence. Legacy networking, NetworkStack, Wi-Fi, and CapNet have separate restore schemas and entry points. Recording is disabled in several paths, while authenticated epochs, hardware reconciliation, atomic publication, and rollback are incomplete. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Restored identifier collisions

The review treats restored identifier collisions as a distinct contract within this section. Legacy networking, NetworkStack, Wi-Fi, and CapNet have separate restore schemas and entry points. Recording is disabled in several paths, while authenticated epochs, hardware reconciliation, atomic publication, and rollback are incomplete. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Restore failure rollback

The review treats restore failure rollback as a distinct contract within this section. Legacy networking, NetworkStack, Wi-Fi, and CapNet have separate restore schemas and entry points. Recording is disabled in several paths, while authenticated epochs, hardware reconciliation, atomic publication, and rollback are incomplete. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Recovery after device reset

Current support for recovery after device reset must be read together with the stated subsystem boundary. Legacy networking, NetworkStack, Wi-Fi, and CapNet have separate restore schemas and entry points. Recording is disabled in several paths, while authenticated epochs, hardware reconciliation, atomic publication, and rollback are incomplete. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

## Diagnostics and Observability Audit

### Link status reporting

Current support for link status reporting must be read together with the stated subsystem boundary. The subsystem prints selected startup and debugging information and exposes some stack, driver, peer, and journal state. It lacks one coherent metrics model with generations, timestamps, drop reasons, queue occupancy, and redaction policy. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Interface identity reporting

interface identity reporting is implemented only to the extent supported by the section evidence. The subsystem prints selected startup and debugging information and exposes some stack, driver, peer, and journal state. It lacks one coherent metrics model with generations, timestamps, drop reasons, queue occupancy, and redaction policy. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Packet transmit and receive counters

Current support for packet transmit and receive counters must be read together with the stated subsystem boundary. The subsystem prints selected startup and debugging information and exposes some stack, driver, peer, and journal state. It lacks one coherent metrics model with generations, timestamps, drop reasons, queue occupancy, and redaction policy. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Packet drop counters

Most drop paths have no counter. The reactor skips short frames, discards dispatch errors, NetworkStack suppresses ARP and IPv4 handler failures, UDP silently drops oversized and full-queue datagrams, and drivers often return zero or Boolean failure without a reason.

Counters must follow the point where the decision becomes final. Driver rejection should record descriptor or hardware cause; Ethernet and IP should record structural validation; transport should record checksum, state, and capacity; service dispatch should record authentication and policy. Counting only at the reactor would merge these causes, while counting at every layer without a disposition identifier would double-count one packet. A bounded ingress correlation value can preserve one final disposition without retaining payload data.

### Driver error counters

E1000, RTL8139, VirtIO, and Wi-Fi expose inconsistent failure shapes and almost no persistent error accounting. Timeouts, invalid descriptors, ring overflow, bad status, reset attempts, MMIO failures, and dropped transmissions may become false, zero, a generic error, or ignored return values.

Recovery decisions need trends rather than isolated return values. Repeated transmit ownership timeouts, invalid used-ring identifiers, receive overflows, or MMIO read failures should increment generation-scoped counters and capture the last transition time. Reset should begin a new generation while retaining prior totals, allowing diagnostics to distinguish a healthy replacement from a device that repeatedly re-enters the same fault cycle.

### Queue occupancy

Current support for queue occupancy must be read together with the stated subsystem boundary. The subsystem prints selected startup and debugging information and exposes some stack, driver, peer, and journal state. It lacks one coherent metrics model with generations, timestamps, drop reasons, queue occupancy, and redaction policy. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### TCP connection statistics

For tcp connection statistics, the relevant behavior is distributed across the implementation described here. The subsystem prints selected startup and debugging information and exposes some stack, driver, peer, and journal state. It lacks one coherent metrics model with generations, timestamps, drop reasons, queue occupancy, and redaction policy. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### DNS cache statistics

dns cache statistics is implemented only to the extent supported by the section evidence. The subsystem prints selected startup and debugging information and exposes some stack, driver, peer, and journal state. It lacks one coherent metrics model with generations, timestamps, drop reasons, queue occupancy, and redaction policy. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Reactor request statistics

The review treats reactor request statistics as a distinct contract within this section. The subsystem prints selected startup and debugging information and exposes some stack, driver, peer, and journal state. It lacks one coherent metrics model with generations, timestamps, drop reasons, queue occupancy, and redaction policy. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Interrupt and polling statistics

interrupt and polling statistics is implemented only to the extent supported by the section evidence. The subsystem prints selected startup and debugging information and exposes some stack, driver, peer, and journal state. It lacks one coherent metrics model with generations, timestamps, drop reasons, queue occupancy, and redaction policy. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Retransmission statistics

For retransmission statistics, the relevant behavior is distributed across the implementation described here. The subsystem prints selected startup and debugging information and exposes some stack, driver, peer, and journal state. It lacks one coherent metrics model with generations, timestamps, drop reasons, queue occupancy, and redaction policy. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Wi-Fi state diagnostics

wi-fi state diagnostics is implemented only to the extent supported by the section evidence. The subsystem prints selected startup and debugging information and exposes some stack, driver, peer, and journal state. It lacks one coherent metrics model with generations, timestamps, drop reasons, queue occupancy, and redaction policy. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### TLS session diagnostics

The review treats tls session diagnostics as a distinct contract within this section. The subsystem prints selected startup and debugging information and exposes some stack, driver, peer, and journal state. It lacks one coherent metrics model with generations, timestamps, drop reasons, queue occupancy, and redaction policy. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### CapNet peer snapshots

The audit of capnet peer snapshots follows the active data and control path rather than module comments. The subsystem prints selected startup and debugging information and exposes some stack, driver, peer, and journal state. It lacks one coherent metrics model with generations, timestamps, drop reasons, queue occupancy, and redaction policy. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### CapNet journal statistics

capnet journal statistics is implemented only to the extent supported by the section evidence. The subsystem prints selected startup and debugging information and exposes some stack, driver, peer, and journal state. It lacks one coherent metrics model with generations, timestamps, drop reasons, queue occupancy, and redaction policy. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Sensitive network logging

Current support for sensitive network logging must be read together with the stated subsystem boundary. The subsystem prints selected startup and debugging information and exposes some stack, driver, peer, and journal state. It lacks one coherent metrics model with generations, timestamps, drop reasons, queue occupancy, and redaction policy. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Diagnostic consistency under concurrency

Current support for diagnostic consistency under concurrency must be read together with the stated subsystem boundary. The subsystem prints selected startup and debugging information and exposes some stack, driver, peer, and journal state. It lacks one coherent metrics model with generations, timestamps, drop reasons, queue occupancy, and redaction policy. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

## Attack Surface Audit

### Malformed Ethernet frames

malformed ethernet frames is implemented only to the extent supported by the section evidence. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

This boundary should become the first hostile-input choke point. A rejected frame should leave behind one final disposition, such as invalid length, unsupported EtherType, failed validation, or accepted for protocol dispatch, without retaining payload data.

### ARP poisoning

For arp poisoning, the relevant behavior is distributed across the implementation described here. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

ARP cache updates should be policy decisions rather than passive learning. Gateway entries, local peer entries, and unsolicited replies need separate rules once service traffic or CapNet authority depends on stable peer routing.

### ICMP amplification

The review treats icmp amplification as a distinct contract within this section. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### UDP flooding

The review treats udp flooding as a distinct contract within this section. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

UDP pressure matters because CapNet control frames ride on UDP. The stack should reserve or prioritize space for authenticated security traffic so ordinary datagram floods cannot suppress revocations, acknowledgements, or peer-session maintenance.

### DNS spoofing and cache poisoning

The review treats dns spoofing and cache poisoning as a distinct contract within this section. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

DNS hardening needs matching beyond transaction identifier alone. Source address, source port, queried name, record type, response shape, cache lifetime, and stale-response handling should be checked together before Fetch or HTTP consumes the result.

### TCP SYN flooding

The review treats tcp syn flooding as a distinct contract within this section. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

SYN pressure should be measured at listener admission, backlog occupancy, half-open state, and final accept. Without that split, hostile connection pressure, slow application accept, and leaked connection state look the same.

### TCP state exhaustion

For tcp state exhaustion, the relevant behavior is distributed across the implementation described here. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Sequence-number attacks

The audit of sequence-number attacks follows the active data and control path rather than module comments. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Fragmentation attacks

The audit of fragmentation attacks follows the active data and control path rather than module comments. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### HTTP response smuggling

For http response smuggling, the relevant behavior is distributed across the implementation described here. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### TLS downgrade and certificate attacks

The review treats tls downgrade and certificate attacks as a distinct contract within this section. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

TLS should fail closed on unsupported versions, unexpected cipher suites, bad certificate chains, hostname mismatch, transcript mismatch, and Finished failure. Those failures should remain distinguishable internally even if a public caller sees a coarse connection failure.

### Wi-Fi management-frame spoofing

For wi-fi management-frame spoofing, the relevant behavior is distributed across the implementation described here. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### WPA2 replay and key attacks

For wpa2 replay and key attacks, the relevant behavior is distributed across the implementation described here. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Driver MMIO and DMA corruption

The review treats driver mmio and dma corruption as a distinct contract within this section. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

Driver compromise risk is different from parser risk because hardware can mutate memory through DMA. Mitigation depends on descriptor ownership discipline, physical range constraints, strict ring bounds, and reset paths that quarantine suspect devices before buffers are reused.

### Interrupt flooding

The review treats interrupt flooding as a distinct contract within this section. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Network capability forgery

Current support for network capability forgery must be read together with the stated subsystem boundary. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

Capability forgery should be mitigated once at the authority boundary rather than separately in every protocol. Socket creation, raw send, DNS, HTTP, CapNet token acceptance, and device administration should all reject copied numeric identifiers without current rights.

### CapNet token forgery

For capnet token forgery, the relevant behavior is distributed across the implementation described here. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### CapNet token replay

The audit of capnet token replay follows the active data and control path rather than module comments. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

Replay defense must survive reconnect and restore. Token nonces, session epochs, revocation epochs, accepted-offer records, and replay windows need one persistence story or old authority can become valid again after restart.

### CapNet delegation escalation

For capnet delegation escalation, the relevant behavior is distributed across the implementation described here. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### CapNet peer impersonation

Current support for capnet peer impersonation must be read together with the stated subsystem boundary. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### CapNet revocation suppression

Current support for capnet revocation suppression must be read together with the stated subsystem boundary. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

Revocation suppression is the highest-risk CapNet availability attack. Local tombstones should remain authoritative even when remote acknowledgement is missing, and repeated delivery failure should mark the peer degraded instead of treating revocation as quiet best effort.

### CapNet persistence rollback

For capnet persistence rollback, the relevant behavior is distributed across the implementation described here. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Resource-exhaustion attacks

The review treats resource-exhaustion attacks as a distinct contract within this section. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

The defense should be capacity-specific. TCP slots, UDP queues, DNS cache entries, TLS sessions, CapNet peers, retransmission entries, and driver rings each need their own refusal reason and counter so pressure can be attributed.

### Timing and traffic-analysis leakage

For timing and traffic-analysis leakage, the relevant behavior is distributed across the implementation described here. The network boundary accepts attacker-controlled frames, protocol state, timing, resource pressure, and authority messages. Defenses are distributed among parsers and CapNet checks rather than expressed as one admission and rate-control policy. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

## ABI and Portability Audit

### Network structure layout

Current support for network structure layout must be read together with the stated subsystem boundary. Wire protocols use a mixture of explicit byte order and native Rust layouts, while drivers depend on target MMIO, port I/O, DMA, and memory ordering. Cross-target support is active in selected QEMU paths but not established as a uniform ABI. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

Wire and persistence layouts should stay byte-oriented and versioned. Native Rust layout should remain internal unless a type has an explicit representation, padding policy, and cross-target test vector.

### Byte-order assumptions

The audit of byte-order assumptions follows the active data and control path rather than module comments. Wire protocols use a mixture of explicit byte order and native Rust layouts, while drivers depend on target MMIO, port I/O, DMA, and memory ordering. Cross-target support is active in selected QEMU paths but not established as a uniform ABI. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Alignment assumptions

For alignment assumptions, the relevant behavior is distributed across the implementation described here. Wire protocols use a mixture of explicit byte order and native Rust layouts, while drivers depend on target MMIO, port I/O, DMA, and memory ordering. Cross-target support is active in selected QEMU paths but not established as a uniform ABI. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Native-size integer fields

The audit of native-size integer fields follows the active data and control path rather than module comments. Wire protocols use a mixture of explicit byte order and native Rust layouts, while drivers depend on target MMIO, port I/O, DMA, and memory ordering. Cross-target support is active in selected QEMU paths but not established as a uniform ABI. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

Native-size integers should not cross wire, persistence, or userspace boundaries. Lengths, object IDs, counters, and offsets need fixed-width encodings with checked conversion at the edge.

### DMA address width in ABI and Portability

The review treats dma address width as a distinct contract within this section. Wire protocols use a mixture of explicit byte order and native Rust layouts, while drivers depend on target MMIO, port I/O, DMA, and memory ordering. Cross-target support is active in selected QEMU paths but not established as a uniform ABI. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

DMA address width should be negotiated or constrained per backend. A driver that works with low physical addresses in QEMU can fail on hardware that requires wider addresses, bounce buffers, or an IOMMU mapping layer.

### Thirty-two-bit target behavior

The audit of thirty-two-bit target behavior follows the active data and control path rather than module comments. Wire protocols use a mixture of explicit byte order and native Rust layouts, while drivers depend on target MMIO, port I/O, DMA, and memory ordering. Cross-target support is active in selected QEMU paths but not established as a uniform ABI. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### x86 port I/O paths

x86 port i/o paths is implemented only to the extent supported by the section evidence. Wire protocols use a mixture of explicit byte order and native Rust layouts, while drivers depend on target MMIO, port I/O, DMA, and memory ordering. Cross-target support is active in selected QEMU paths but not established as a uniform ABI. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### x86-64 MMIO paths

The review treats x86-64 mmio paths as a distinct contract within this section. Wire protocols use a mixture of explicit byte order and native Rust layouts, while drivers depend on target MMIO, port I/O, DMA, and memory ordering. Cross-target support is active in selected QEMU paths but not established as a uniform ABI. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### AArch64 MMIO paths

aarch64 mmio paths is implemented only to the extent supported by the section evidence. Wire protocols use a mixture of explicit byte order and native Rust layouts, while drivers depend on target MMIO, port I/O, DMA, and memory ordering. Cross-target support is active in selected QEMU paths but not established as a uniform ABI. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Weak memory-ordering behavior

weak memory-ordering behavior is implemented only to the extent supported by the section evidence. Wire protocols use a mixture of explicit byte order and native Rust layouts, while drivers depend on target MMIO, port I/O, DMA, and memory ordering. Cross-target support is active in selected QEMU paths but not established as a uniform ABI. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

Weak ordering is a release blocker for AArch64 driver confidence. Descriptor publication, used-ring consumption, interrupt acknowledgement, and DMA buffer visibility should have explicit fences or volatile ordering rules tested on that target path.

### Driver portability

The review treats driver portability as a distinct contract within this section. Wire protocols use a mixture of explicit byte order and native Rust layouts, while drivers depend on target MMIO, port I/O, DMA, and memory ordering. Cross-target support is active in selected QEMU paths but not established as a uniform ABI. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### CapNet wire stability

The review treats capnet wire stability as a distinct contract within this section. Wire protocols use a mixture of explicit byte order and native Rust layouts, while drivers depend on target MMIO, port I/O, DMA, and memory ordering. Cross-target support is active in selected QEMU paths but not established as a uniform ABI. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

CapNet needs stable external vectors before it becomes a real cross-device protocol. Token bytes, control frames, attestation evidence, revocation records, and persistence records should round-trip across targets without relying on native alignment or host integer size.

### Temporal schema stability

For temporal schema stability, the relevant behavior is distributed across the implementation described here. Wire protocols use a mixture of explicit byte order and native Rust layouts, while drivers depend on target MMIO, port I/O, DMA, and memory ordering. Cross-target support is active in selected QEMU paths but not established as a uniform ABI. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Cross-device interoperability in ABI and Portability

cross-device interoperability is implemented only to the extent supported by the section evidence. Wire protocols use a mixture of explicit byte order and native Rust layouts, while drivers depend on target MMIO, port I/O, DMA, and memory ordering. Cross-target support is active in selected QEMU paths but not established as a uniform ABI. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

## Self-Test and Unit Test Audit

### HTTP URL parsing tests

The audit of http url parsing tests follows the active data and control path rather than module comments. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### HTTP request encoding tests

The review treats http request encoding tests as a distinct contract within this section. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Chunked-transfer detection tests

For chunked-transfer detection tests, the relevant behavior is distributed across the implementation described here. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### UDP queue tests

Current support for udp queue tests must be read together with the stated subsystem boundary. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### DNS transaction tests

For dns transaction tests, the relevant behavior is distributed across the implementation described here. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### DNS stale-response tests

dns stale-response tests is implemented only to the extent supported by the section evidence. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### TCP retransmission tests

The review treats tcp retransmission tests as a distinct contract within this section. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### IPv4 checksum tests

For ipv4 checksum tests, the relevant behavior is distributed across the implementation described here. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### Wi-Fi reconnect self-check

The audit of wi-fi reconnect self-check follows the active data and control path rather than module comments. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### CapNet token round-trip tests

Current support for capnet token round-trip tests must be read together with the stated subsystem boundary. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### CapNet control-frame round-trip tests

For capnet control-frame round-trip tests, the relevant behavior is distributed across the implementation described here. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### CapNet fuzz smoke test

For capnet fuzz smoke test, the relevant behavior is distributed across the implementation described here. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### CapNet formal self-check

capnet formal self-check is implemented only to the extent supported by the section evidence. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Driver tests

The review treats driver tests as a distinct contract within this section. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### TLS tests

The audit of tls tests follows the active data and control path rather than module comments. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Reactor concurrency tests

reactor concurrency tests is implemented only to the extent supported by the section evidence. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Fault-injection tests

For fault-injection tests, the relevant behavior is distributed across the implementation described here. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### Negative security tests

Current support for negative security tests must be read together with the stated subsystem boundary. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

The missing tests should assert refusal, not only successful parsing. Revoked CapNet tokens, replayed control frames, forged capabilities, malformed DNS compression, bad TLS certificates, WPA2 replay counters, and unauthorized raw sends should all fail with typed outcomes.

### Cross-architecture tests

The review treats cross-architecture tests as a distinct contract within this section. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### QEMU integration tests

qemu integration tests is implemented only to the extent supported by the section evidence. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

QEMU should become the minimum integration gate for driver initialization, link readiness, packet send and receive, interrupt handling, DNS over UDP, TCP connect, and CapNet control traffic. Unit tests cannot prove those device and scheduler boundaries.

### Hardware integration tests

Current support for hardware integration tests must be read together with the stated subsystem boundary. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

Hardware tests should be reserved for claims QEMU cannot prove: DMA address limits, interrupt timing, EEPROM behavior, Wi-Fi management traffic, link-change handling, reset recovery, and weak memory-ordering effects.

### Coverage gaps

For coverage gaps, the relevant behavior is distributed across the implementation described here. Existing tests cover selected HTTP helpers, UDP queueing, DNS matching, TCP retransmission, checksums, Wi-Fi reconnect failure, and CapNet encoding and self-checks. Driver, TLS, concurrency, fault, architecture, QEMU, and hardware coverage remains sparse. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

## Fuzzing and Property-Test Audit

### Ethernet parser fuzzing

Current support for ethernet parser fuzzing must be read together with the stated subsystem boundary. CapNet contains an in-kernel fuzz routine and regression seeds, but the remaining packet parsers and state machines do not have dedicated retained-corpus fuzz targets. Stateful transitions and restore paths need model-based properties. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### IPv4 parser fuzzing

For ipv4 parser fuzzing, the relevant behavior is distributed across the implementation described here. CapNet contains an in-kernel fuzz routine and regression seeds, but the remaining packet parsers and state machines do not have dedicated retained-corpus fuzz targets. Stateful transitions and restore paths need model-based properties. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### ARP parser fuzzing

The review treats arp parser fuzzing as a distinct contract within this section. CapNet contains an in-kernel fuzz routine and regression seeds, but the remaining packet parsers and state machines do not have dedicated retained-corpus fuzz targets. Stateful transitions and restore paths need model-based properties. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### UDP parser fuzzing

For udp parser fuzzing, the relevant behavior is distributed across the implementation described here. CapNet contains an in-kernel fuzz routine and regression seeds, but the remaining packet parsers and state machines do not have dedicated retained-corpus fuzz targets. Stateful transitions and restore paths need model-based properties. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### DNS parser fuzzing

dns parser fuzzing is implemented only to the extent supported by the section evidence. CapNet contains an in-kernel fuzz routine and regression seeds, but the remaining packet parsers and state machines do not have dedicated retained-corpus fuzz targets. Stateful transitions and restore paths need model-based properties. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### TCP stateful fuzzing

The audit of tcp stateful fuzzing follows the active data and control path rather than module comments. CapNet contains an in-kernel fuzz routine and regression seeds, but the remaining packet parsers and state machines do not have dedicated retained-corpus fuzz targets. Stateful transitions and restore paths need model-based properties. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### HTTP parser fuzzing

The audit of http parser fuzzing follows the active data and control path rather than module comments. CapNet contains an in-kernel fuzz routine and regression seeds, but the remaining packet parsers and state machines do not have dedicated retained-corpus fuzz targets. Stateful transitions and restore paths need model-based properties. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### TLS record and handshake fuzzing

The audit of tls record and handshake fuzzing follows the active data and control path rather than module comments. CapNet contains an in-kernel fuzz routine and regression seeds, but the remaining packet parsers and state machines do not have dedicated retained-corpus fuzz targets. Stateful transitions and restore paths need model-based properties. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Wi-Fi management-frame fuzzing

The audit of wi-fi management-frame fuzzing follows the active data and control path rather than module comments. CapNet contains an in-kernel fuzz routine and regression seeds, but the remaining packet parsers and state machines do not have dedicated retained-corpus fuzz targets. Stateful transitions and restore paths need model-based properties. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### EAPOL parser fuzzing

eapol parser fuzzing is implemented only to the extent supported by the section evidence. CapNet contains an in-kernel fuzz routine and regression seeds, but the remaining packet parsers and state machines do not have dedicated retained-corpus fuzz targets. Stateful transitions and restore paths need model-based properties. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Driver ring state fuzzing

Current support for driver ring state fuzzing must be read together with the stated subsystem boundary. CapNet contains an in-kernel fuzz routine and regression seeds, but the remaining packet parsers and state machines do not have dedicated retained-corpus fuzz targets. Stateful transitions and restore paths need model-based properties. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### CapNet token fuzzing

For capnet token fuzzing, the relevant behavior is distributed across the implementation described here. CapNet contains an in-kernel fuzz routine and regression seeds, but the remaining packet parsers and state machines do not have dedicated retained-corpus fuzz targets. Stateful transitions and restore paths need model-based properties. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### CapNet control-frame fuzzing

The audit of capnet control-frame fuzzing follows the active data and control path rather than module comments. CapNet contains an in-kernel fuzz routine and regression seeds, but the remaining packet parsers and state machines do not have dedicated retained-corpus fuzz targets. Stateful transitions and restore paths need model-based properties. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### CapNet replay-window properties

The audit of capnet replay-window properties follows the active data and control path rather than module comments. CapNet contains an in-kernel fuzz routine and regression seeds, but the remaining packet parsers and state machines do not have dedicated retained-corpus fuzz targets. Stateful transitions and restore paths need model-based properties. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### CapNet delegation properties

The audit of capnet delegation properties follows the active data and control path rather than module comments. CapNet contains an in-kernel fuzz routine and regression seeds, but the remaining packet parsers and state machines do not have dedicated retained-corpus fuzz targets. Stateful transitions and restore paths need model-based properties. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### CapNet revocation properties

The audit of capnet revocation properties follows the active data and control path rather than module comments. CapNet contains an in-kernel fuzz routine and regression seeds, but the remaining packet parsers and state machines do not have dedicated retained-corpus fuzz targets. Stateful transitions and restore paths need model-based properties. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Temporal restore fuzzing

The audit of temporal restore fuzzing follows the active data and control path rather than module comments. CapNet contains an in-kernel fuzz routine and regression seeds, but the remaining packet parsers and state machines do not have dedicated retained-corpus fuzz targets. Stateful transitions and restore paths need model-based properties. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

Restore fuzzing should be transactional. It should generate valid and invalid snapshots, attempt restore, and assert that failed restore leaves the previous peer, delegation, revocation, DNS, TCP, and Wi-Fi state untouched.

### Regression corpus retention

The audit of regression corpus retention follows the active data and control path rather than module comments. CapNet contains an in-kernel fuzz routine and regression seeds, but the remaining packet parsers and state machines do not have dedicated retained-corpus fuzz targets. Stateful transitions and restore paths need model-based properties. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

Every minimized crash, invariant failure, parser disagreement, or restore rollback bug should become a permanent corpus entry. Without corpus retention, fuzzing becomes a one-time confidence exercise instead of a regression guard.

## Formal Verification and Invariant Audit

### Packet bounds invariant

packet bounds invariant is implemented only to the extent supported by the section evidence. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Network reactor single-owner invariant

The audit of network reactor single-owner invariant follows the active data and control path rather than module comments. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### Descriptor ownership invariant

descriptor ownership invariant is implemented only to the extent supported by the section evidence. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Queue capacity invariant

Current support for queue capacity invariant must be read together with the stated subsystem boundary. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### TCP state-transition invariant

For tcp state-transition invariant, the relevant behavior is distributed across the implementation described here. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### TCP sequence monotonicity invariant

The review treats tcp sequence monotonicity invariant as a distinct contract within this section. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### No send without network authority

The review treats no send without network authority as a distinct contract within this section. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### No receive without network authority

The audit of no receive without network authority follows the active data and control path rather than module comments. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### DNS response matching invariant

Current support for dns response matching invariant must be read together with the stated subsystem boundary. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### TLS record authentication invariant

Current support for tls record authentication invariant must be read together with the stated subsystem boundary. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Wi-Fi replay-counter invariant

Current support for wi-fi replay-counter invariant must be read together with the stated subsystem boundary. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### CapNet token authenticity invariant

For capnet token authenticity invariant, the relevant behavior is distributed across the implementation described here. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### CapNet rights attenuation invariant

capnet rights attenuation invariant is implemented only to the extent supported by the section evidence. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### CapNet temporal validity invariant

capnet temporal validity invariant is implemented only to the extent supported by the section evidence. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### CapNet replay rejection invariant

The review treats capnet replay rejection invariant as a distinct contract within this section. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. The present design is usable within its tested path, but it does not establish a complete production guarantee for this topic.

### CapNet revocation precedence invariant

Current support for capnet revocation precedence invariant must be read together with the stated subsystem boundary. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. The active implementation should therefore be described as partial until target-specific tests prove the intended property.

### CapNet single-session binding invariant

Current support for capnet single-session binding invariant must be read together with the stated subsystem boundary. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. This leaves a maturity gap where unsupported input, lifecycle change, or concurrent use can produce behavior outside the documented contract.

### Persistence round-trip invariant

persistence round-trip invariant is implemented only to the extent supported by the section evidence. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. Capability alignment remains incomplete unless the operation is authorized with a principal and minimum right at its state-changing boundary.

### No deadlock invariant

The audit of no deadlock invariant follows the active data and control path rather than module comments. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

### Bounded memory invariant

For bounded memory invariant, the relevant behavior is distributed across the implementation described here. The code documents and tests selected bounds and CapNet properties but has no machine-checked end-to-end model of reactor ownership, packet admission, TCP transitions, DMA ownership, capability enforcement, recovery, or bounded memory. The code provides a bounded starting point, while full assurance still depends on explicit policy, typed outcomes, and adversarial tests.

## Known Limitations

### Known issues/TODOS in Cross-device interoperability in ABI and Portability

Issue: Cross-device interoperability in ABI and Portability has an implementation-specific contract that is not interchangeable with the similarly named behavior in another network component. The active code does not yet prove complete lifecycle, failure, capability, and portability behavior for this boundary.

Required fixes:

1. Define the component-specific state, ownership, and error contract.
2. Enforce administrative or operation authority before state changes.
3. Add target-specific boundary, failure, reset, and recovery tests.
4. Add runtime evidence that distinguishes unsupported state from transient failure.

### Known issues/TODOS in DMA address width in ABI and Portability

Issue: DMA address width in ABI and Portability has an implementation-specific contract that is not interchangeable with the similarly named behavior in another network component. The active code does not yet prove complete lifecycle, failure, capability, and portability behavior for this boundary.

Required fixes:

1. Define the component-specific state, ownership, and error contract.
2. Enforce administrative or operation authority before state changes.
3. Add target-specific boundary, failure, reset, and recovery tests.
4. Gate production enablement on the target-specific verification results.

### Known issues/TODOS in Port I/O safety in Memory Safety

Issue: Port I/O safety in Memory Safety has an implementation-specific contract that is not interchangeable with the similarly named behavior in another network component. The active code does not yet prove complete lifecycle, failure, capability, and portability behavior for this boundary.

Required fixes:

1. Define the component-specific state, ownership, and error contract.
2. Enforce administrative or operation authority before state changes.
3. Add target-specific boundary, failure, reset, and recovery tests.
4. Keep minimized failures in the permanent regression corpus.
5. Require this property to pass before enabling the affected feature.

### Known issues/TODOS in Payload-length validation in CapNet Persistence

Issue: Payload-length validation in CapNet Persistence has an implementation-specific contract that is not interchangeable with the similarly named behavior in another network component. The active code does not yet prove complete lifecycle, failure, capability, and portability behavior for this boundary.

Required fixes:

1. Define the component-specific state, ownership, and error contract.
2. Enforce administrative or operation authority before state changes.
3. Add target-specific boundary, failure, reset, and recovery tests.
4. Gate production enablement on the target-specific verification results.

### Known issues/TODOS in Cross-device interoperability in CapNet Attestation

Issue: Cross-device interoperability in CapNet Attestation has an implementation-specific contract that is not interchangeable with the similarly named behavior in another network component. The active code does not yet prove complete lifecycle, failure, capability, and portability behavior for this boundary.

Required fixes:

1. Define the component-specific state, ownership, and error contract.
2. Enforce administrative or operation authority before state changes.
3. Add target-specific boundary, failure, reset, and recovery tests.
4. Gate production enablement on the target-specific verification results.

### Known issues/TODOS in Session binding in CapNet Attestation

Issue: Session binding in CapNet Attestation has an implementation-specific contract that is not interchangeable with the similarly named behavior in another network component. The active code does not yet prove complete lifecycle, failure, capability, and portability behavior for this boundary.

Required fixes:

1. Define the component-specific state, ownership, and error contract.
2. Enforce administrative or operation authority before state changes.
3. Add target-specific boundary, failure, reset, and recovery tests.

### Known issues/TODOS in Queue overflow behavior in CapNet Control Protocol

Issue: Queue overflow behavior in CapNet Control Protocol has an implementation-specific contract that is not interchangeable with the similarly named behavior in another network component. The active code does not yet prove complete lifecycle, failure, capability, and portability behavior for this boundary.

Required fixes:

1. Define the component-specific state, ownership, and error contract.
2. Enforce administrative or operation authority before state changes.
3. Add target-specific boundary, failure, reset, and recovery tests.
4. Add runtime evidence that distinguishes unsupported state from transient failure.

### Known issues/TODOS in Payload-length validation in CapNet Control Protocol

Issue: Payload-length validation in CapNet Control Protocol has an implementation-specific contract that is not interchangeable with the similarly named behavior in another network component. The active code does not yet prove complete lifecycle, failure, capability, and portability behavior for this boundary.

Required fixes:

1. Define the component-specific state, ownership, and error contract.
2. Enforce administrative or operation authority before state changes.
3. Add target-specific boundary, failure, reset, and recovery tests.

### Known issues/TODOS in Rights attenuation in CapNet Delegation

Issue: Rights attenuation in CapNet Delegation has an implementation-specific contract that is not interchangeable with the similarly named behavior in another network component. The active code does not yet prove complete lifecycle, failure, capability, and portability behavior for this boundary.

Required fixes:

1. Define the component-specific state, ownership, and error contract.
2. Enforce administrative or operation authority before state changes.
3. Add target-specific boundary, failure, reset, and recovery tests.

### Known issues/TODOS in Session binding in CapNet Token Format

Issue: Session binding in CapNet Token Format has an implementation-specific contract that is not interchangeable with the similarly named behavior in another network component. The active code does not yet prove complete lifecycle, failure, capability, and portability behavior for this boundary.

Required fixes:

1. Define the component-specific state, ownership, and error contract.
2. Enforce administrative or operation authority before state changes. Add target-specific boundary, failure, reset, and recovery tests.

### Known issues/TODOS in Rights attenuation in Capability-Based Network Access

Issue: Rights attenuation in Capability-Based Network Access has an implementation-specific contract that is not interchangeable with the similarly named behavior in another network component. The active code does not yet prove complete lifecycle, failure, capability, and portability behavior for this boundary.

Required fixes:

1. Define the component-specific state, ownership, and error contract.
2. Enforce administrative or operation authority before state changes.
3. Add target-specific boundary, failure, reset, and recovery tests.
4. Define rollback behavior for failure after partial state mutation.

### Known issues/TODOS in Interrupt acknowledgement in VirtIO Network Driver

Issue: Interrupt acknowledgement in VirtIO Network Driver has an implementation-specific contract that is not interchangeable with the similarly named behavior in another network component. The active code does not yet prove complete lifecycle, failure, capability, and portability behavior for this boundary.

Required fixes:

1. Define the component-specific state, ownership, and error contract.
2. Enforce administrative or operation authority before state changes.
3. Add target-specific boundary, failure, reset, and recovery tests.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in Driver reset and recovery in Realtek RTL8139 Driver

Issue: Driver reset and recovery in Realtek RTL8139 Driver has an implementation-specific contract that is not interchangeable with the similarly named behavior in another network component. The active code does not yet prove complete lifecycle, failure, capability, and portability behavior for this boundary.

Required fixes:

1. Define the component-specific state, ownership, and error contract.
2. Enforce administrative or operation authority before state changes.
3. Add target-specific boundary, failure, reset, and recovery tests.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in Device reset in Realtek RTL8139 Driver

Issue: Device reset in Realtek RTL8139 Driver has an implementation-specific contract that is not interchangeable with the similarly named behavior in another network component. The active code does not yet prove complete lifecycle, failure, capability, and portability behavior for this boundary.

Required fixes:

1. Define the component-specific state, ownership, and error contract.
2. Enforce administrative or operation authority before state changes.
3. Add target-specific boundary, failure, reset, and recovery tests.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in Port I/O safety in Realtek RTL8139 Driver

Issue: Port I/O safety in Realtek RTL8139 Driver has an implementation-specific contract that is not interchangeable with the similarly named behavior in another network component. The active code does not yet prove complete lifecycle, failure, capability, and portability behavior for this boundary.

Required fixes:

1. Define the component-specific state, ownership, and error contract.
2. Enforce administrative or operation authority before state changes.
3. Add target-specific boundary, failure, reset, and recovery tests.
4. Define rollback behavior for failure after partial state mutation.

### Known issues/TODOS in Driver reset and recovery in Intel E1000 Driver

Issue: E1000 recovery ignores ring initialization failures and republishes the device without coordinating in-flight network state.

Required fixes:

1. Introduce a quiesce, reset, reinitialize, validate, and publish state machine with typed failure results.
2. Invalidate stale descriptor generations and notify the reactor and protocol layers when connectivity is discontinuous.
3. Test reset during receive, transmit, interrupt handling, link change, queue pressure, and initialization failure.
4. Document the supported boundary and reject operation outside it.

### Known issues/TODOS in Interrupt acknowledgement in Intel E1000 Driver

Issue: Interrupt acknowledgement in Intel E1000 Driver has an implementation-specific contract that is not interchangeable with the similarly named behavior in another network component. The active code does not yet prove complete lifecycle, failure, capability, and portability behavior for this boundary.

Required fixes:

1. Define the component-specific state, ownership, and error contract.
2. Enforce administrative or operation authority before state changes.
3. Add target-specific boundary, failure, reset, and recovery tests.
4. Define rollback behavior for failure after partial state mutation.
5. Test high memory, nonidentity mapping, IOMMU translation, reset, and mapping failure.

### Known issues/TODOS in Device reset in Intel E1000 Driver

Issue: Device reset in Intel E1000 Driver has an implementation-specific contract that is not interchangeable with the similarly named behavior in another network component. The active code does not yet prove complete lifecycle, failure, capability, and portability behavior for this boundary.

Required fixes:

1. Define the component-specific state, ownership, and error contract.
2. Enforce administrative or operation authority before state changes.
3. Add target-specific boundary, failure, reset, and recovery tests.
4. Document the supported boundary and reject operation outside it.

### Known issues/TODOS in Queue overflow behavior in UDP

Issue: A full or oversized UDP queue silently drops traffic without policy, counters, or caller-visible pressure.

Required fixes:

1. Record structured drop reasons and expose queue occupancy.
2. Partition or reserve capacity for critical consumers such as DNS and authenticated control traffic.
3. Test saturation, mixed ports, oversize payloads, dequeue races, and recovery.
4. Record enough bounded diagnostics to identify recurrence without exposing sensitive data.

### Known issues/TODOS in Network subsystem responsibilities

Issue: Network subsystem responsibilities is only partially established by the active network architecture and trust boundary audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in Active networking implementations

Issue: Compiled network modules are presented more uniformly than their runtime maturity supports, especially TLS and Wi-Fi.

Required fixes:

1. Publish a support matrix that separates compiled, initialized, interoperable, authenticated, and production-supported paths.
2. Make unsupported Wi-Fi chipsets and AArch64 TLS fail before state or traffic setup.
3. Gate public APIs by verified backend and security capability rather than module presence.

### Known issues/TODOS in Legacy network service and universal stack overlap

Issue: Compatibility, reactor, and standalone TLS paths expose overlapping features with different security and lifecycle guarantees.

Required fixes:

1. Select the reactor-owned stack as the canonical transport and freeze new compatibility behavior.
2. Route TLS and HTTP through the canonical path before exposing HTTPS.
3. Remove or strictly gate duplicate state and restore formats after caller migration.

### Known issues/TODOS in Network reactor ownership model

Issue: The reactor owns only the common stack and discards nested ingress failures, while other network paths mutate state independently.

Required fixes:

1. Return structured dispatch outcomes through the receive loop and count every rejection reason.
2. Move direct TLS and driver consumers under reactor ownership.
3. Test concurrent ingress, timeout reuse, parser failure, and backend reset under one owner.

### Known issues/TODOS in Device backend selection

Issue: Device backend selection is only partially established by the active network architecture and trust boundary audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in Kernel service and userspace exposure

Issue: Public network entry paths do not share authority, backend-support, blocking, or error contracts.

Required fixes:

1. Define one principal-bearing network operation contract for kernel services and userspace adapters.
2. Require commit-time capabilities for DNS, TCP, HTTP, TLS, raw frames, and device administration.
3. Conformance-test every exposed entry path against the same authorization and lifecycle cases.

### Known issues/TODOS in Capability enforcement boundaries

Issue: Capability enforcement boundaries is only partially established by the active network architecture and trust boundary audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.
4. Add runtime evidence that distinguishes unsupported state from transient failure.

### Known issues/TODOS in Temporal persistence boundaries

Issue: Network state changes can succeed while temporal or security records fail silently across independent schemas.

Required fixes:

1. Return or record persistence failure at each security-sensitive mutation.
2. Commit related network, authority, and secret state under one authenticated epoch.
3. Test partial recording, capacity failure, replay rollback, and cross-object restoration.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in Cross-module dependency direction

Issue: Cross-module dependency direction is only partially established by the active network architecture and trust boundary audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in Active code, compatibility code, and scaffolding

Issue: Active code, compatibility code, and scaffolding is only partially established by the active network architecture and trust boundary audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in Network module root

Issue: Network module root is only partially established by the active file and component audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in Universal network stack

Issue: Universal network stack is only partially established by the active file and component audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in Network reactor

Issue: Network reactor is only partially established by the active file and component audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in Intel E1000 driver

Issue: Intel E1000 driver is only partially established by the active file and component audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.
4. Define rollback behavior for failure after partial state mutation.

### Known issues/TODOS in Realtek RTL8139 driver

Issue: Realtek RTL8139 driver is only partially established by the active file and component audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.
4. Record enough bounded diagnostics to identify recurrence without exposing sensitive data.

### Known issues/TODOS in VirtIO network driver

Issue: VirtIO network driver is only partially established by the active file and component audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.
4. Gate production enablement on the target-specific verification results.

### Known issues/TODOS in Wi-Fi subsystem

Issue: Wi-Fi subsystem is only partially established by the active file and component audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in TLS implementation

Issue: TLS implementation is only partially established by the active file and component audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in CapNet implementation

Issue: CapNet implementation is only partially established by the active file and component audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in CapNet facade modules

Issue: CapNet submodules only re-export a monolithic legacy implementation and do not enforce ownership boundaries.

Required fixes:

1. Move one responsibility at a time into the named module with private state and narrow APIs.
2. Remove dead-code suppression once each facade has real callers. Keep wire-format tests shared while adding module-level lock and invariant tests.

### Known issues/TODOS in Component ownership and maturity

Issue: Component ownership and maturity is only partially established by the active file and component audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in Boot-time initialization order

Issue: Boot-time initialization order is only partially established by the active network initialization and runtime audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in Device probing and backend selection

Issue: Device probing and backend selection is only partially established by the active network initialization and runtime audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in Legacy QEMU defaults

Issue: Legacy QEMU defaults is only partially established by the active network initialization and runtime audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in AArch64 QEMU defaults

Issue: AArch64 QEMU defaults is only partially established by the active network initialization and runtime audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in DHCP support and active integration

Issue: DHCP support and active integration is only partially established by the active network initialization and runtime audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in Reinitialization behavior

Issue: Reinitialization behavior is only partially established by the active network initialization and runtime audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in Device removal and reset behavior

Issue: Device removal and reset behavior is only partially established by the active network initialization and runtime audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in Network interface trait contract

Issue: Network interface trait contract is only partially established by the active network interface abstraction audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in Error normalization across drivers

Issue: Error normalization across drivers is only partially established by the active network interface abstraction audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in Polled and interrupt-driven operation

Issue: Polled and interrupt-driven operation is only partially established by the active network interface abstraction audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in Interface replacement and failover

Issue: Interface replacement and failover is only partially established by the active network interface abstraction audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in Single-owner stack design

Issue: Single-owner stack design is only partially established by the active network reactor audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.

### Known issues/TODOS in Request slot state machine

Issue: Request slot state machine is only partially established by the active network reactor audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.
4. Add a request generation so late completion cannot satisfy a reused slot.
5. Prove timeout and cancellation with deterministic reactor interleavings.

### Known issues/TODOS in Request publication and completion ordering

Issue: Request publication and completion ordering is only partially established by the active network reactor audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.
4. Model the UnsafeCell payload, atomic states, staging buffers, and timeout reset as one ordering protocol.

### Known issues/TODOS in Inline request fallback

Issue: Inline request fallback is only partially established by the active network reactor audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.
4. Prevent fallback execution from reentering the stack while a reactor-owned operation is active.

### Known issues/TODOS in IRQ notification path

Issue: IRQ notification path is only partially established by the active network reactor audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.
4. Carry backend generation and interrupt cause into deferred processing so stale notifications can be rejected.

### Known issues/TODOS in Receive processing budget

Issue: Receive processing budget is only partially established by the active network reactor audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.
4. Measure starvation of requests and timers under sustained receive load, then reserve progress for each class.

### Known issues/TODOS in Timer-driven progress

Issue: Timer-driven progress is only partially established by the active network reactor audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.
4. Bound catch-up work after long scheduler pauses and record skipped or delayed deadlines.

### Known issues/TODOS in Request fairness

Issue: Request fairness is only partially established by the active network reactor audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.
4. Test timeout before dispatch, during dispatch, during completion, and immediately before slot reuse.

### Known issues/TODOS in Static send and receive staging buffers

Issue: Static send and receive staging buffers is only partially established by the active network reactor audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.
4. Add weak-ordering and adverse-interleaving tests for timeout, IRQ, replay, and reset.

### Known issues/TODOS in Stack-size constraints

Issue: Stack-size constraints is only partially established by the active network reactor audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.
4. Measure worst-case stack use for protocol parsing, TLS, Wi-Fi cryptography, and nested diagnostics on every target.

### Known issues/TODOS in Temporal replay requests

Issue: Temporal replay requests is only partially established by the active network reactor audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported behavior and ownership contract.
2. Enforce capability and lifecycle rules at the mutation boundary.
3. Add deterministic boundary, failure, and recovery tests.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in Ethernet header parsing

Issue: Ethernet header parsing is only partially established by the active ethernet frame audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define and enforce the accepted Ethernet frame contract.
2. Reject malformed and unsupported frames before protocol dispatch.
3. Add driver-to-parser boundary and adversarial frame tests.
4. Validate exact frame disposition before any protocol handler mutates state.

### Known issues/TODOS in Source and destination MAC validation

Issue: Source and destination MAC validation is only partially established by the active ethernet frame audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define and enforce the accepted Ethernet frame contract.
2. Reject malformed and unsupported frames before protocol dispatch.
3. Add driver-to-parser boundary and adversarial frame tests.
4. Define acceptance rules for local unicast, broadcast, multicast, and promiscuous traffic per interface mode.

### Known issues/TODOS in EtherType dispatch

Issue: EtherType dispatch is only partially established by the active ethernet frame audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define and enforce the accepted Ethernet frame contract.
2. Reject malformed and unsupported frames before protocol dispatch.
3. Add driver-to-parser boundary and adversarial frame tests.

### Known issues/TODOS in Minimum and maximum frame lengths

Issue: Minimum and maximum frame lengths is only partially established by the active ethernet frame audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define and enforce the accepted Ethernet frame contract.
2. Reject malformed and unsupported frames before protocol dispatch.
3. Add driver-to-parser boundary and adversarial frame tests.
4. Distinguish padding, frame check sequence handling, truncation, jumbo frames, and descriptor chaining.

### Known issues/TODOS in MTU enforcement

Issue: MTU enforcement is only partially established by the active ethernet frame audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define and enforce the accepted Ethernet frame contract.
2. Reject malformed and unsupported frames before protocol dispatch.
3. Add driver-to-parser boundary and adversarial frame tests.
4. Apply the same MTU contract on construction, receive, fragmentation policy, and every backend.

### Known issues/TODOS in Broadcast handling

Issue: Broadcast handling is only partially established by the active ethernet frame audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define and enforce the accepted Ethernet frame contract.
2. Reject malformed and unsupported frames before protocol dispatch.
3. Add driver-to-parser boundary and adversarial frame tests.

### Known issues/TODOS in Multicast handling

Issue: Multicast handling is only partially established by the active ethernet frame audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define and enforce the accepted Ethernet frame contract.
2. Reject malformed and unsupported frames before protocol dispatch.
3. Add driver-to-parser boundary and adversarial frame tests.

### Known issues/TODOS in Promiscuous receive behavior

Issue: Promiscuous receive behavior is only partially established by the active ethernet frame audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define and enforce the accepted Ethernet frame contract.
2. Reject malformed and unsupported frames before protocol dispatch.
3. Add driver-to-parser boundary and adversarial frame tests.
4. Require administrative authority and expose the active mode through redacted diagnostics.

### Known issues/TODOS in VLAN and tagged-frame support

Issue: VLAN and tagged-frame support is only partially established by the active ethernet frame audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define and enforce the accepted Ethernet frame contract.
2. Reject malformed and unsupported frames before protocol dispatch.
3. Add driver-to-parser boundary and adversarial frame tests.
4. Reject tagged frames explicitly until VLAN parsing, policy, and MTU accounting are implemented.

### Known issues/TODOS in Frame padding and checksum handling

Issue: Frame padding and checksum handling is only partially established by the active ethernet frame audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define and enforce the accepted Ethernet frame contract.
2. Reject malformed and unsupported frames before protocol dispatch.
3. Add driver-to-parser boundary and adversarial frame tests.
4. Normalize whether drivers retain or strip the frame check sequence before common parsing.

### Known issues/TODOS in Malformed frame rejection

Issue: Malformed frame rejection is only partially established by the active ethernet frame audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define and enforce the accepted Ethernet frame contract.
2. Reject malformed and unsupported frames before protocol dispatch.
3. Add driver-to-parser boundary and adversarial frame tests.
4. Prove that every rejection leaves ARP, transport, diagnostics, and queue state unchanged.

### Known issues/TODOS in ARP request generation

Issue: ARP request generation is only partially established by the active arp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define cache lifetime, replacement, and concurrent resolution rules.
2. Apply neighbor validation and poisoning resistance appropriate to the trust model. Add timeout, collision, spoofing, and gateway tests.

### Known issues/TODOS in ARP reply generation

Issue: ARP reply generation is only partially established by the active arp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define cache lifetime, replacement, and concurrent resolution rules.
2. Apply neighbor validation and poisoning resistance appropriate to the trust model. Add timeout, collision, spoofing, and gateway tests.

### Known issues/TODOS in ARP packet validation

Issue: ARP packets update neighbor state before the implementation validates their protocol fields, target relevance, opcode, or link-layer identity consistency.

Required fixes:

1. Parse ARP through a checked structure that validates hardware type, protocol type, address lengths, opcode, and exact packet size before reading semantic fields.
2. Require Ethernet source and ARP sender identity consistency, then admit cache updates only under an explicit request, reply, and gratuitous-ARP policy.
3. Add malformed-packet and state-atomicity tests proving that every rejected packet leaves the cache unchanged.
4. Delay cache mutation until the complete packet and update policy have both succeeded.
5. Count rejected claims by reason without reflecting attacker-controlled data into logs.

### Known issues/TODOS in ARP cache structure

Issue: ARP cache structure is only partially established by the active arp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define cache lifetime, replacement, and concurrent resolution rules.
2. Apply neighbor validation and poisoning resistance appropriate to the trust model. Add timeout, collision, spoofing, and gateway tests.

### Known issues/TODOS in Cache hashing and collision behavior

Issue: Cache hashing and collision behavior is only partially established by the active arp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define cache lifetime, replacement, and concurrent resolution rules.
2. Apply neighbor validation and poisoning resistance appropriate to the trust model.
3. Add timeout, collision, spoofing, and gateway tests.
4. Measure adversarial collisions and choose a replacement scheme that does not let one address evict an unrelated gateway mapping.

### Known issues/TODOS in Cache replacement policy

Issue: Cache replacement policy is only partially established by the active arp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define cache lifetime, replacement, and concurrent resolution rules.
2. Apply neighbor validation and poisoning resistance appropriate to the trust model.
3. Add timeout, collision, spoofing, and gateway tests.

### Known issues/TODOS in Cache lifetime and expiry

Issue: Cache lifetime and expiry is only partially established by the active arp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define cache lifetime, replacement, and concurrent resolution rules.
2. Apply neighbor validation and poisoning resistance appropriate to the trust model.
3. Add timeout, collision, spoofing, and gateway tests.

### Known issues/TODOS in Gateway resolution

Issue: Gateway resolution is only partially established by the active arp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define cache lifetime, replacement, and concurrent resolution rules.
2. Apply neighbor validation and poisoning resistance appropriate to the trust model.
3. Add timeout, collision, spoofing, and gateway tests.
4. Bind a resolved gateway mapping to interface generation and invalidate it on link or configuration change.

### Known issues/TODOS in Resolution timeout behavior

Issue: Resolution timeout behavior is only partially established by the active arp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define cache lifetime, replacement, and concurrent resolution rules.
2. Apply neighbor validation and poisoning resistance appropriate to the trust model. Add timeout, collision, spoofing, and gateway tests.

### Known issues/TODOS in Concurrent resolution requests

Issue: Concurrent resolution requests is only partially established by the active arp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define cache lifetime, replacement, and concurrent resolution rules.
2. Apply neighbor validation and poisoning resistance appropriate to the trust model.
3. Add timeout, collision, spoofing, and gateway tests.
4. Gate production enablement on the target-specific verification results.

### Known issues/TODOS in ARP spoofing and poisoning resistance

Issue: Any on-link sender can replace gateway or peer mappings because cache insertion authenticates neither the claimant nor the resolution context.

Required fixes:

1. Track pending resolutions and prefer solicited replies that match interface, target, and request generation.
2. Add conflict detection, entry states, expiry, replacement policy, and rate limits without treating ARP as cryptographically authenticated.
3. Test unsolicited replies, conflicting announcements, cache-collision pressure, gateway poisoning, and recovery after a legitimate mapping returns.
4. Replay every discovered failure against all supported targets.
5. Block production support when the invariant cannot be demonstrated.

### Known issues/TODOS in Gratuitous ARP handling

Issue: Gratuitous ARP handling is only partially established by the active arp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define cache lifetime, replacement, and concurrent resolution rules.
2. Apply neighbor validation and poisoning resistance appropriate to the trust model.
3. Add timeout, collision, spoofing, and gateway tests.
4. Define duplicate-address detection separately from ordinary neighbor-cache updates.

### Known issues/TODOS in IPv4 header parsing

Issue: IPv4 header parsing is only partially established by the active ipv4 audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document supported IPv4 header and routing behavior.
2. Reject unsupported fragmentation, options, and address classes explicitly.
3. Fuzz header lengths, totals, checksums, and routing decisions.
4. Validate version, checksum, flags, options, and destination policy before transport dispatch.

### Known issues/TODOS in Header-length validation

Issue: Header-length validation is only partially established by the active ipv4 audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document supported IPv4 header and routing behavior.
2. Reject unsupported fragmentation, options, and address classes explicitly.
3. Fuzz header lengths, totals, checksums, and routing decisions.
4. Fuzz every relationship among frame length, header length, total length, flags, and offsets.

### Known issues/TODOS in Version validation

Issue: Version validation is only partially established by the active ipv4 audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document supported IPv4 header and routing behavior.
2. Reject unsupported fragmentation, options, and address classes explicitly.
3. Fuzz header lengths, totals, checksums, and routing decisions.
4. Reject non-IPv4 version fields before deriving any IPv4 offsets.

### Known issues/TODOS in Header checksum verification

Issue: IPv4 receive does not verify the header checksum before trusting addressing, lengths, and protocol fields.

Required fixes:

1. Verify the checksum over the exact declared header before destination policy or transport dispatch.
2. Reject invalid checksums with bounded counters and no response amplification.
3. Add bit-flip, option-header, odd-length, truncation, and checksum-zero tests.

### Known issues/TODOS in Source and destination address policy

Issue: Source and destination address policy is only partially established by the active ipv4 audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document supported IPv4 header and routing behavior.
2. Reject unsupported fragmentation, options, and address classes explicitly.
3. Fuzz header lengths, totals, checksums, and routing decisions.
4. Reject invalid, unspecified, loopback, multicast, and broadcast sources according to interface context.

### Known issues/TODOS in Local-address detection

Issue: Local-address detection is only partially established by the active ipv4 audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document supported IPv4 header and routing behavior.
2. Reject unsupported fragmentation, options, and address classes explicitly. Fuzz header lengths, totals, checksums, and routing decisions.

### Known issues/TODOS in Gateway routing

Issue: Gateway routing is only partially established by the active ipv4 audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document supported IPv4 header and routing behavior.
2. Reject unsupported fragmentation, options, and address classes explicitly.
3. Fuzz header lengths, totals, checksums, and routing decisions.

### Known issues/TODOS in Time-to-live handling

Issue: Time-to-live handling is only partially established by the active ipv4 audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document supported IPv4 header and routing behavior.
2. Reject unsupported fragmentation, options, and address classes explicitly.
3. Fuzz header lengths, totals, checksums, and routing decisions.
4. Define local delivery and forwarding behavior explicitly and never route packets with an exhausted lifetime.

### Known issues/TODOS in Fragmentation and reassembly support

Issue: IPv4 fragments are passed directly to transport parsers as complete packets.

Required fixes:

1. Reject every fragmented packet until a bounded reassembly design is implemented.
2. If reassembly is added, bound bytes, fragments, timers, principals, overlaps, and concurrent datagrams.
3. Test noninitial, overlapping, duplicate, incomplete, timeout, and resource-exhaustion fragment sets.

### Known issues/TODOS in IP option handling

Issue: IP option handling is only partially established by the active ipv4 audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document supported IPv4 header and routing behavior.
2. Reject unsupported fragmentation, options, and address classes explicitly.
3. Fuzz header lengths, totals, checksums, and routing decisions.
4. Reject unsupported options before transport parsing and audit malformed option lengths.

### Known issues/TODOS in Broadcast and multicast addressing

Issue: Broadcast and multicast addressing is only partially established by the active ipv4 audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document supported IPv4 header and routing behavior.
2. Reject unsupported fragmentation, options, and address classes explicitly.
3. Fuzz header lengths, totals, checksums, and routing decisions.

### Known issues/TODOS in Malformed packet rejection

Issue: Malformed packet rejection is only partially established by the active ipv4 audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document supported IPv4 header and routing behavior.
2. Reject unsupported fragmentation, options, and address classes explicitly.
3. Fuzz header lengths, totals, checksums, and routing decisions.
4. Return one structured disposition to the reactor instead of discarding the parser error.

### Known issues/TODOS in Echo request handling

Issue: Echo request handling is only partially established by the active icmp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported ICMP message set.
2. Add rate limits and amplification controls.
3. Test checksum, malformed input, and error-message handling.

### Known issues/TODOS in Echo reply generation

Issue: Echo reply generation is only partially established by the active icmp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported ICMP message set.
2. Add rate limits and amplification controls. Test checksum, malformed input, and error-message handling.

### Known issues/TODOS in ICMP checksum validation

Issue: ICMP checksum validation is only partially established by the active icmp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported ICMP message set.
2. Add rate limits and amplification controls.
3. Test checksum, malformed input, and error-message handling.
4. Verify the complete message checksum before interpreting type, code, or embedded headers.

### Known issues/TODOS in Error-message handling

Issue: Error-message handling is only partially established by the active icmp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported ICMP message set.
2. Add rate limits and amplification controls.
3. Test checksum, malformed input, and error-message handling.

### Known issues/TODOS in Rate limiting

Issue: Rate limiting is only partially established by the active icmp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported ICMP message set.
2. Add rate limits and amplification controls.
3. Test checksum, malformed input, and error-message handling.
4. Use per-source and global token buckets with bounded state and monotonic expiry.

### Known issues/TODOS in Amplification resistance

Issue: Amplification resistance is only partially established by the active icmp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported ICMP message set.
2. Add rate limits and amplification controls.
3. Test checksum, malformed input, and error-message handling.
4. Suppress replies to broadcast, multicast, invalid-source, and error-on-error traffic.

### Known issues/TODOS in Malformed ICMP rejection

Issue: Malformed ICMP rejection is only partially established by the active icmp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported ICMP message set.
2. Add rate limits and amplification controls.
3. Test checksum, malformed input, and error-message handling.
4. Reject malformed error messages before reading their embedded packet headers.

### Known issues/TODOS in UDP packet construction

Issue: UDP packet construction is only partially established by the active udp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define checksum, truncation, queue, and overflow semantics.
2. Apply per-principal authority and resource limits. Test saturation, port matching, malformed datagrams, and CapNet dispatch.

### Known issues/TODOS in UDP header validation

Issue: UDP header validation is only partially established by the active udp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define checksum, truncation, queue, and overflow semantics.
2. Apply per-principal authority and resource limits.
3. Test saturation, port matching, malformed datagrams, and CapNet dispatch.
4. Reject trailing or truncated length relationships consistently before control-port dispatch.

### Known issues/TODOS in UDP checksum generation

Issue: UDP checksum generation is only partially established by the active udp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define checksum, truncation, queue, and overflow semantics.
2. Apply per-principal authority and resource limits. Test saturation, port matching, malformed datagrams, and CapNet dispatch.

### Known issues/TODOS in UDP checksum verification

Issue: Receive ignores the UDP checksum field and accepts corrupted nonzero-checksum datagrams into security-sensitive consumers.

Required fixes:

1. Verify every nonzero checksum against the IPv4 pseudo-header and exact declared UDP length before dispatch.
2. Define whether zero checksums are accepted per interface and consumer, with stricter policy available for control protocols.
3. Add bit-flip, odd-length, zero-checksum, truncation, and pseudo-header mismatch tests.
4. Perform checksum validation before DNS, CapNet, or receive-queue state changes.

### Known issues/TODOS in Source-port allocation

Issue: Source-port allocation is only partially established by the active udp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define checksum, truncation, queue, and overflow semantics.
2. Apply per-principal authority and resource limits. Test saturation, port matching, malformed datagrams, and CapNet dispatch.

### Known issues/TODOS in Receive queue structure

Issue: Receive queue structure is only partially established by the active udp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define checksum, truncation, queue, and overflow semantics.
2. Apply per-principal authority and resource limits. Test saturation, port matching, malformed datagrams, and CapNet dispatch.

### Known issues/TODOS in Receive queue capacity

Issue: Receive queue capacity is only partially established by the active udp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define checksum, truncation, queue, and overflow semantics.
2. Apply per-principal authority and resource limits.
3. Test saturation, port matching, malformed datagrams, and CapNet dispatch.

### Known issues/TODOS in Port matching behavior

Issue: Port matching behavior is only partially established by the active udp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define checksum, truncation, queue, and overflow semantics.
2. Apply per-principal authority and resource limits.
3. Test saturation, port matching, malformed datagrams, and CapNet dispatch.
4. Bind queued datagrams to socket generation so port reuse cannot consume stale traffic.

### Known issues/TODOS in Nonmatching datagram preservation

Issue: Nonmatching datagram preservation is only partially established by the active udp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define checksum, truncation, queue, and overflow semantics.
2. Apply per-principal authority and resource limits.
3. Test saturation, port matching, malformed datagrams, and CapNet dispatch.

### Known issues/TODOS in Payload truncation behavior

Issue: Payload truncation behavior is only partially established by the active udp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define checksum, truncation, queue, and overflow semantics.
2. Apply per-principal authority and resource limits.
3. Test saturation, port matching, malformed datagrams, and CapNet dispatch.
4. Return required length without consuming the datagram, or define explicit truncating receive semantics.

### Known issues/TODOS in CapNet control-port dispatch

Issue: CapNet control-port dispatch is only partially established by the active udp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define checksum, truncation, queue, and overflow semantics.
2. Apply per-principal authority and resource limits.
3. Test saturation, port matching, malformed datagrams, and CapNet dispatch.
4. Apply a receive work budget before cryptographic verification to limit unauthenticated CPU pressure.

### Known issues/TODOS in UDP denial-of-service resistance

Issue: Fixed storage bounds memory but does not limit per-source CPU, queue displacement, or control-protocol work.

Required fixes:

1. Apply per-source and per-port packet and byte budgets before expensive dispatch.
2. Bind local receive reservations to explicit network capabilities and quotas.
3. Stress floods, malformed CapNet traffic, logging pressure, and legitimate-flow latency.

### Known issues/TODOS in DNS query construction

Issue: DNS query construction is only partially established by the active dns audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Randomize query identifiers and source ports with trusted entropy.
2. Harden response matching and compressed-name parsing. Add spoofing, timeout, cache, and malformed-response tests.
3. Canonicalize and validate empty labels, trailing dots, and total encoded length before writing the query.

### Known issues/TODOS in Transaction identifier allocation

Issue: DNS identifiers are timer-seeded and sequential, while every query uses one fixed source port.

Required fixes:

1. Generate identifiers and ephemeral source ports from approved kernel randomness.
2. Track outstanding tuples and avoid reuse until timeout. Test prediction resistance, collision handling, wraparound, retries, and concurrent queries.

### Known issues/TODOS in Source-port policy

Issue: Source-port policy is only partially established by the active dns audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Randomize query identifiers and source ports with trusted entropy.
2. Harden response matching and compressed-name parsing.
3. Add spoofing, timeout, cache, and malformed-response tests.

### Known issues/TODOS in Response matching

Issue: DNS responses are matched by endpoint tuple and transaction identifier without validating the echoed question.

Required fixes:

1. Match name, type, class, opcode, response bit, and active query generation.
2. Discard mismatches without terminating the active attempt.
3. Test same-identifier answers for different names, stale retries, duplicate responses, and mixed record types.

### Known issues/TODOS in Name encoding

Issue: Name encoding is only partially established by the active dns audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Randomize query identifiers and source ports with trusted entropy.
2. Harden response matching and compressed-name parsing. Add spoofing, timeout, cache, and malformed-response tests.
3. Reject ambiguous presentation forms and preserve the canonical queried identity for response matching.

### Known issues/TODOS in Compressed-name decoding

Issue: DNS compression parsing lacks a common loop-safe, depth-bounded name decoder.

Required fixes:

1. Implement one checked decoder with visited-offset or bounded-depth protection.
2. Reject reserved label forms, out-of-range pointers, loops, and expanded names above protocol limits. Fuzz nested pointers, cycles, boundary offsets, maximum names, and truncated labels.

### Known issues/TODOS in Record parsing

Issue: Record parsing is only partially established by the active dns audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Randomize query identifiers and source ports with trusted entropy.
2. Harden response matching and compressed-name parsing.
3. Add spoofing, timeout, cache, and malformed-response tests.
4. Walk every declared section with one checked cursor and reject count or length inconsistencies.

### Known issues/TODOS in IPv4 answer selection

Issue: IPv4 answer selection is only partially established by the active dns audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Randomize query identifiers and source ports with trusted entropy.
2. Harden response matching and compressed-name parsing. Add spoofing, timeout, cache, and malformed-response tests.
3. Define CNAME traversal, answer ownership, duplicate records, and address policy before selecting an address.

### Known issues/TODOS in Positive cache behavior

Issue: Positive cache behavior is only partially established by the active dns audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Randomize query identifiers and source ports with trusted entropy.
2. Harden response matching and compressed-name parsing.
3. Add spoofing, timeout, cache, and malformed-response tests.
4. Bind cache entries to canonical names, record type, resolver identity, and expiry source.

### Known issues/TODOS in Negative cache behavior

Issue: Negative cache behavior is only partially established by the active dns audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Randomize query identifiers and source ports with trusted entropy.
2. Harden response matching and compressed-name parsing.
3. Add spoofing, timeout, cache, and malformed-response tests.
4. Cache authoritative negative answers separately from local timeout failures.

### Known issues/TODOS in Cache expiry

Issue: Cache expiry is only partially established by the active dns audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Randomize query identifiers and source ports with trusted entropy.
2. Harden response matching and compressed-name parsing. Add spoofing, timeout, cache, and malformed-response tests.

### Known issues/TODOS in Query retry policy

Issue: Query retry policy is only partially established by the active dns audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Randomize query identifiers and source ports with trusted entropy.
2. Harden response matching and compressed-name parsing.
3. Add spoofing, timeout, cache, and malformed-response tests.
4. Use a fresh unpredictable query tuple for each retry and reject stale-attempt responses.

### Known issues/TODOS in Response timeout

Issue: Response timeout is only partially established by the active dns audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Randomize query identifiers and source ports with trusted entropy.
2. Harden response matching and compressed-name parsing.
3. Add spoofing, timeout, cache, and malformed-response tests.

### Known issues/TODOS in Stale response removal

Issue: Stale response removal is only partially established by the active dns audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Randomize query identifiers and source ports with trusted entropy.
2. Harden response matching and compressed-name parsing.
3. Add spoofing, timeout, cache, and malformed-response tests.
4. Tag queued replies with query generation instead of clearing every datagram on the shared DNS port.

### Known issues/TODOS in Malformed response handling

Issue: DNS validates selected fields but not the complete response header and section structure.

Required fixes:

1. Parse all required header semantics and section counts with checked cursor arithmetic.
2. Return typed parse failures and increment bounded reason counters.
3. Fuzz truncation and malformed records while asserting no cache or query-state mutation.
4. Keep the active DNS query alive after unrelated malformed responses until its deadline.

### Known issues/TODOS in Spoofed response resistance

Issue: Predictable query tuples and incomplete question binding permit forged DNS replies to win a race.

Required fixes:

1. Randomize query tuples and bind every accepted response to the complete outstanding question.
2. Support an authenticated resolver transport or DNSSEC policy before treating DNS as trusted naming.
3. Run off-path injection, on-path alteration, stale response, and cache-poisoning tests.
4. Keep minimized failures in the permanent regression corpus.
5. Require this property to pass before enabling the affected feature.

### Known issues/TODOS in Resolver readiness requirements

Issue: Resolver readiness requirements is only partially established by the active dns audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Randomize query identifiers and source ports with trusted entropy.
2. Harden response matching and compressed-name parsing.
3. Add spoofing, timeout, cache, and malformed-response tests.

### Known issues/TODOS in Connection table structure

Issue: Connection table structure is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely. Add stateful model, exhaustion, and adversarial segment tests.

### Known issues/TODOS in Listener table structure

Issue: Listener table structure is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely. Add stateful model, exhaustion, and adversarial segment tests.

### Known issues/TODOS in Accept backlog

Issue: Accept backlog is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely.
3. Add stateful model, exhaustion, and adversarial segment tests.

### Known issues/TODOS in Connection identifier allocation

Issue: Connection identifier allocation is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely. Add stateful model, exhaustion, and adversarial segment tests.

### Known issues/TODOS in Active open

Issue: Active open is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely.
3. Add stateful model, exhaustion, and adversarial segment tests.

### Known issues/TODOS in Passive open

Issue: Passive open is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely.
3. Add stateful model, exhaustion, and adversarial segment tests.

### Known issues/TODOS in TCP state transitions

Issue: TCP state transitions is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely.
3. Add stateful model, exhaustion, and adversarial segment tests.
4. Reject transitions that are not valid for the exact flag, sequence, acknowledgement, and connection generation.

### Known issues/TODOS in Sequence and acknowledgement validation

Issue: TCP can accept acknowledgements beyond transmitted data and transition handshake state without exact sequence-space validation.

Required fixes:

1. Implement RFC-style segment acceptability and serial-number comparisons for every state.
2. Reject acknowledgements outside the valid sent range and require exact SYN acknowledgement during active and passive opens.
3. Add stateful tests for forged future acknowledgements, wrapped sequence numbers, stale segments, FIN ordering, and simultaneous transitions.

### Known issues/TODOS in Receive-window accounting

Issue: TCP advances its receive sequence across bytes it drops when the fixed receive buffer is full.

Required fixes:

1. Advance receive state only for bytes actually retained, or reject the segment and advertise the remaining window without acknowledging discarded data.
2. Implement zero-window advertisement and recovery with consistent application-read updates.
3. Test full-buffer delivery, partial overlap, window reopening, retransmission, and sequence wraparound.

### Known issues/TODOS in Window scaling

Issue: Window scaling is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely.
3. Add stateful model, exhaustion, and adversarial segment tests.

### Known issues/TODOS in Maximum segment size negotiation

Issue: Maximum segment size negotiation is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely.
3. Add stateful model, exhaustion, and adversarial segment tests.

### Known issues/TODOS in SYN option parsing

Issue: SYN option parsing is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely.
3. Add stateful model, exhaustion, and adversarial segment tests.
4. Reject malformed option lengths and duplicate or unsupported negotiation values before establishing state.

### Known issues/TODOS in Payload receive buffering

Issue: Payload receive buffering is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely.
3. Add stateful model, exhaustion, and adversarial segment tests.
4. Keep acknowledgement state consistent with bytes actually retained under every capacity condition.

### Known issues/TODOS in Send segmentation

Issue: Send segmentation is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely.
3. Add stateful model, exhaustion, and adversarial segment tests.

### Known issues/TODOS in Retransmission state

Issue: Retransmission state is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely.
3. Add stateful model, exhaustion, and adversarial segment tests.

### Known issues/TODOS in Retransmission timeout policy

Issue: Retransmission timeout policy is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely.
3. Add stateful model, exhaustion, and adversarial segment tests.
4. Bound retries, apply backoff, and close connections whose progress cannot be demonstrated.

### Known issues/TODOS in Delayed acknowledgement policy

Issue: Delayed acknowledgement policy is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely.
3. Add stateful model, exhaustion, and adversarial segment tests.

### Known issues/TODOS in Duplicate and out-of-order segments

Issue: TCP silently discards reordered and duplicate data without a complete cumulative-acknowledgement, overlap, or FIN policy.

Required fixes:

1. Define a bounded reassembly policy or a deliberate no-reassembly contract with immediate duplicate acknowledgements.
2. Normalize overlaps, duplicate FINs, and retransmitted SYN data before state mutation.
3. Run deterministic reorder, duplication, overlap, loss, and retransmission scenarios against a reference peer.

### Known issues/TODOS in FIN handling

Issue: FIN handling is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely.
3. Add stateful model, exhaustion, and adversarial segment tests.
4. Process FIN only at the correct sequence position and preserve unread data through half-close.

### Known issues/TODOS in Reset handling

Issue: Reset handling is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely.
3. Add stateful model, exhaustion, and adversarial segment tests.
4. Validate reset sequence acceptability before destroying a connection.

### Known issues/TODOS in Half-closed connections

Issue: Half-closed connections is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely.
3. Add stateful model, exhaustion, and adversarial segment tests.

### Known issues/TODOS in End-of-stream reporting

Issue: End-of-stream reporting is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely. Add stateful model, exhaustion, and adversarial segment tests.

### Known issues/TODOS in Time-wait handling

Issue: Time-wait handling is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely.
3. Add stateful model, exhaustion, and adversarial segment tests.

### Known issues/TODOS in Connection cleanup

Issue: Connection cleanup is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely.
3. Add stateful model, exhaustion, and adversarial segment tests.
4. Define rollback behavior for failure after partial state mutation.
5. Invalidate handles, listener backlog entries, timers, retransmissions, and restored records atomically.

### Known issues/TODOS in Port reuse and collision handling

Issue: Port reuse and collision handling is only partially established by the active tcp audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify the supported TCP state and congestion model.
2. Validate sequence, window, option, and teardown transitions completely.
3. Add stateful model, exhaustion, and adversarial segment tests.
4. Use connection generations and full endpoint tuples to prevent stale segments reaching a replacement connection.

### Known issues/TODOS in TCP checksum validation

Issue: TCP receive mutates connection state without verifying the transport checksum.

Required fixes:

1. Compute and validate the pseudo-header checksum before connection lookup or state changes.
2. Reject malformed data with counters that separate checksum failure from length and state failure.
3. Test header, payload, pseudo-header, odd-length, option, and offload-related checksum cases.
4. Share one verified checksum routine between construction, receive, tests, and architecture paths.

### Known issues/TODOS in Malformed segment rejection

Issue: TCP accepts malformed header lengths and flags before a complete validation gate.

Required fixes:

1. Require a valid minimum data offset, bounded options, checksum, and segment acceptability before lookup mutation.
2. Define rejection behavior for reserved bits and contradictory flags without amplification.
3. Fuzz all header fields, option lengths, truncations, overlaps, and state combinations.
4. Rate-limit reset or acknowledgement responses to malformed traffic.

### Known issues/TODOS in Connection exhaustion

Issue: A small shared TCP table lets half-open handshakes consume all established-connection capacity.

Required fixes:

1. Separate bounded half-open and established pools with timeouts and per-source limits.
2. Reserve or quota local connection creation by capability-bearing principal.
3. Test SYN floods, backlog saturation, timeout cleanup, listener closure, and fair recovery.
4. Add runtime evidence that distinguishes unsupported state from transient failure.

### Known issues/TODOS in TCP denial-of-service resistance

Issue: TCP lacks rate limits and work budgets for unauthenticated handshake and malformed-segment traffic.

Required fixes:

1. Add per-source admission limits and bounded processing per reactor cycle.
2. Introduce SYN-cookie or equivalent stateless defense where listener exposure requires it.
3. Measure legitimate connection latency under SYN, ACK, reset, and retransmission floods.
4. Expose half-open, established, retransmission, and rejection pressure separately.

### Known issues/TODOS in URL parsing

Issue: URL parsing is only partially established by the active http client and server audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported HTTP grammar and framing limits.
2. Reject ambiguous lengths, transfer encodings, and partial messages.
3. Add parser, timeout, smuggling, and interoperability tests.

### Known issues/TODOS in Scheme and port handling

Issue: Scheme and port handling is only partially established by the active http client and server audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported HTTP grammar and framing limits.
2. Reject ambiguous lengths, transfer encodings, and partial messages.
3. Add parser, timeout, smuggling, and interoperability tests.

### Known issues/TODOS in Host and path encoding

Issue: Host and path encoding is only partially established by the active http client and server audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported HTTP grammar and framing limits.
2. Reject ambiguous lengths, transfer encodings, and partial messages. Add parser, timeout, smuggling, and interoperability tests.

### Known issues/TODOS in Request construction

Issue: Request construction is only partially established by the active http client and server audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported HTTP grammar and framing limits.
2. Reject ambiguous lengths, transfer encodings, and partial messages. Add parser, timeout, smuggling, and interoperability tests.

### Known issues/TODOS in Header-size limits

Issue: Header-size limits is only partially established by the active http client and server audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported HTTP grammar and framing limits.
2. Reject ambiguous lengths, transfer encodings, and partial messages.
3. Add parser, timeout, smuggling, and interoperability tests.

### Known issues/TODOS in Status-line parsing

Issue: Status-line parsing is only partially established by the active http client and server audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported HTTP grammar and framing limits.
2. Reject ambiguous lengths, transfer encodings, and partial messages.
3. Add parser, timeout, smuggling, and interoperability tests.

### Known issues/TODOS in Content-length parsing

Issue: Content-length parsing is only partially established by the active http client and server audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported HTTP grammar and framing limits.
2. Reject ambiguous lengths, transfer encodings, and partial messages.
3. Add parser, timeout, smuggling, and interoperability tests.

### Known issues/TODOS in Chunked transfer detection

Issue: Chunked transfer detection is only partially established by the active http client and server audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported HTTP grammar and framing limits.
2. Reject ambiguous lengths, transfer encodings, and partial messages. Add parser, timeout, smuggling, and interoperability tests.

### Known issues/TODOS in Chunked body decoding

Issue: Chunked body decoding is only partially established by the active http client and server audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported HTTP grammar and framing limits.
2. Reject ambiguous lengths, transfer encodings, and partial messages. Add parser, timeout, smuggling, and interoperability tests.

### Known issues/TODOS in Response body capacity

Issue: Response body capacity is only partially established by the active http client and server audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported HTTP grammar and framing limits.
2. Reject ambiguous lengths, transfer encodings, and partial messages.
3. Add parser, timeout, smuggling, and interoperability tests.

### Known issues/TODOS in Connection-close behavior

Issue: Connection-close behavior is only partially established by the active http client and server audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported HTTP grammar and framing limits.
2. Reject ambiguous lengths, transfer encodings, and partial messages.
3. Add parser, timeout, smuggling, and interoperability tests.

### Known issues/TODOS in Partial response handling

Issue: Partial response handling is only partially established by the active http client and server audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported HTTP grammar and framing limits.
2. Reject ambiguous lengths, transfer encodings, and partial messages.
3. Add parser, timeout, smuggling, and interoperability tests.

### Known issues/TODOS in HTTP timeout behavior

Issue: HTTP timeout behavior is only partially established by the active http client and server audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported HTTP grammar and framing limits.
2. Reject ambiguous lengths, transfer encodings, and partial messages. Add parser, timeout, smuggling, and interoperability tests.

### Known issues/TODOS in Redirect support

Issue: Redirect support is only partially established by the active http client and server audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported HTTP grammar and framing limits.
2. Reject ambiguous lengths, transfer encodings, and partial messages.
3. Add parser, timeout, smuggling, and interoperability tests.

### Known issues/TODOS in HTTP server listener lifecycle

Issue: HTTP server listener lifecycle is only partially established by the active http client and server audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported HTTP grammar and framing limits.
2. Reject ambiguous lengths, transfer encodings, and partial messages.
3. Add parser, timeout, smuggling, and interoperability tests.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in HTTP server request parsing

Issue: HTTP server request parsing is only partially established by the active http client and server audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported HTTP grammar and framing limits.
2. Reject ambiguous lengths, transfer encodings, and partial messages.
3. Add parser, timeout, smuggling, and interoperability tests.

### Known issues/TODOS in HTTP server response generation

Issue: HTTP server response generation is only partially established by the active http client and server audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported HTTP grammar and framing limits.
2. Reject ambiguous lengths, transfer encodings, and partial messages. Add parser, timeout, smuggling, and interoperability tests.

### Known issues/TODOS in Malformed HTTP handling

Issue: Malformed HTTP handling is only partially established by the active http client and server audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported HTTP grammar and framing limits.
2. Reject ambiguous lengths, transfer encodings, and partial messages.
3. Add parser, timeout, smuggling, and interoperability tests.
4. Parse bytes without assuming UTF-8 and return a bounded protocol error instead of panicking.

### Known issues/TODOS in Protocol smuggling and ambiguity risks

Issue: Protocol smuggling and ambiguity risks is only partially established by the active http client and server audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define the supported HTTP grammar and framing limits.
2. Reject ambiguous lengths, transfer encodings, and partial messages.
3. Add parser, timeout, smuggling, and interoperability tests.

### Known issues/TODOS in TLS implementation boundaries

Issue: TLS runs over a duplicate weaker TCP and driver path that bypasses the reactor and common network policy.

Required fixes:

1. Replace the private TCP and frame implementation with reactor-owned byte-stream operations.
2. Block direct TLS traffic until certificate, transport, and capability checks are complete.
3. Run the shared TCP validation and fault corpus through TLS transport integration.

### Known issues/TODOS in TLS record framing

Issue: TLS record framing is only partially established by the active tls audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Integrate TLS with reactor-owned TCP and network authority.
2. Implement strict chain, hostname, transcript, and alert validation.
3. Add secret zeroization, malformed-record, and interoperability tests.
4. Support records split or coalesced across arbitrary TCP reads without transcript ambiguity.

### Known issues/TODOS in TLS record size enforcement

Issue: Peer-controlled record lengths can exceed local arrays and cryptographic output buffers.

Required fixes:

1. Reject lengths beyond TLS and local limits before buffering or copying.
2. Make encryption and decryption return typed capacity errors instead of assuming output size.
3. Test every boundary around header, tag, plaintext, ciphertext, and maximum record sizes.

### Known issues/TODOS in Handshake state machine

Issue: Handshake state machine is only partially established by the active tls audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Integrate TLS with reactor-owned TCP and network authority.
2. Implement strict chain, hostname, transcript, and alert validation.
3. Add secret zeroization, malformed-record, and interoperability tests.
4. Reject duplicate, skipped, reordered, and unexpected handshake messages as terminal protocol errors.

### Known issues/TODOS in Client hello construction

Issue: Client hello construction is only partially established by the active tls audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Integrate TLS with reactor-owned TCP and network authority.
2. Implement strict chain, hostname, transcript, and alert validation. Add secret zeroization, malformed-record, and interoperability tests.

### Known issues/TODOS in Server hello parsing

Issue: Server hello parsing is only partially established by the active tls audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Integrate TLS with reactor-owned TCP and network authority.
2. Implement strict chain, hostname, transcript, and alert validation.
3. Add secret zeroization, malformed-record, and interoperability tests.
4. Validate legacy version, session identifier, cipher suite, compression byte, extensions, and exact trailing length.

### Known issues/TODOS in Supported version negotiation

Issue: Supported version negotiation is only partially established by the active tls audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Integrate TLS with reactor-owned TCP and network authority.
2. Implement strict chain, hostname, transcript, and alert validation.
3. Add secret zeroization, malformed-record, and interoperability tests.
4. Require an authenticated TLS 1.3 selection and reject downgrade sentinels or unsupported fallback.

### Known issues/TODOS in Cipher-suite negotiation

Issue: Cipher-suite negotiation is only partially established by the active tls audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Integrate TLS with reactor-owned TCP and network authority.
2. Implement strict chain, hostname, transcript, and alert validation.
3. Add secret zeroization, malformed-record, and interoperability tests.
4. Accept only suites implemented by the selected key schedule and certificate policy.

### Known issues/TODOS in X25519 key exchange

Issue: X25519 key exchange is only partially established by the active tls audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Integrate TLS with reactor-owned TCP and network authority.
2. Implement strict chain, hostname, transcript, and alert validation.
3. Add secret zeroization, malformed-record, and interoperability tests.
4. Reject invalid or low-order peer public keys and all-zero shared secrets.

### Known issues/TODOS in Handshake transcript hashing

Issue: Handshake transcript hashing is only partially established by the active tls audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Integrate TLS with reactor-owned TCP and network authority.
2. Implement strict chain, hostname, transcript, and alert validation.
3. Add secret zeroization, malformed-record, and interoperability tests.
4. Hash exact encoded handshake messages across record boundaries without truncation or synthetic normalization.

### Known issues/TODOS in Traffic secret derivation

Issue: Traffic secret derivation is only partially established by the active tls audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Integrate TLS with reactor-owned TCP and network authority.
2. Implement strict chain, hostname, transcript, and alert validation.
3. Add secret zeroization, malformed-record, and interoperability tests.
4. Replay every discovered failure against all supported targets.
5. Block production support when the invariant cannot be demonstrated.

### Known issues/TODOS in Record encryption and authentication

Issue: Record encryption and authentication is only partially established by the active tls audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Integrate TLS with reactor-owned TCP and network authority.
2. Implement strict chain, hostname, transcript, and alert validation.
3. Add secret zeroization, malformed-record, and interoperability tests.
4. Treat authentication failure as terminal and never advance keys or expose partial plaintext.

### Known issues/TODOS in Certificate message parsing

Issue: Certificate message parsing is only partially established by the active tls audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Integrate TLS with reactor-owned TCP and network authority.
2. Implement strict chain, hostname, transcript, and alert validation.
3. Add secret zeroization, malformed-record, and interoperability tests.
4. Keep minimized failures in the permanent regression corpus.
5. Require this property to pass before enabling the affected feature.

### Known issues/TODOS in Certificate verify validation

Issue: TLS accepts CertificateVerify based only on message ordering and never verifies the endpoint signature.

Required fixes:

1. Parse the negotiated signature scheme and verify the TLS 1.3 CertificateVerify transcript context with the leaf certificate key.
2. Reject unsupported schemes, malformed signatures, key-type mismatches, and signatures made over any other transcript state.
3. Add positive vectors and negative tests for altered transcripts, wrong keys, wrong contexts, and skipped CertificateVerify.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in Finished-message validation

Issue: Finished-message validation is only partially established by the active tls audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Integrate TLS with reactor-owned TCP and network authority.
2. Implement strict chain, hostname, transcript, and alert validation.
3. Add secret zeroization, malformed-record, and interoperability tests.
4. Verify transcript timing before appending Finished and derive application keys only after success.

### Known issues/TODOS in Alert handling

Issue: Alert handling is only partially established by the active tls audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Integrate TLS with reactor-owned TCP and network authority.
2. Implement strict chain, hostname, transcript, and alert validation.
3. Add secret zeroization, malformed-record, and interoperability tests.
4. Parse alert level and description under encryption state and preserve a stable terminal reason.

### Known issues/TODOS in Application-data buffering

Issue: Application-data buffering is only partially established by the active tls audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Integrate TLS with reactor-owned TCP and network authority.
2. Implement strict chain, hostname, transcript, and alert validation.
3. Add secret zeroization, malformed-record, and interoperability tests.
4. Report required capacity or backpressure instead of silently truncating authenticated plaintext.

### Known issues/TODOS in Sequence-number exhaustion

Issue: TLS record sequence counters can wrap and reuse an AEAD nonce.

Required fixes:

1. Check exhaustion before every encryption and decryption operation.
2. Close the connection or perform a verified TLS key update before the limit.
3. Add near-limit tests proving no wrapped record is emitted or accepted.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in Session allocation and handle reuse

Issue: TLS index handles can become valid for unrelated reused sessions, and global mutable access is unsynchronized.

Required fixes:

1. Use generation-bearing handles and validate generation on every operation.
2. Place allocation, ticking, lookup, and free under one ownership or locking model. Test stale handles, concurrent tick and free, pool exhaustion, and rapid reuse.

### Known issues/TODOS in Session cleanup and secret zeroization

Issue: Freeing a TLS session leaves keys, secrets, plaintext, and peer data resident.

Required fixes:

1. Zeroize cryptographic and application buffers before marking a slot free.
2. Prevent compiler removal of secret clearing with an established volatile or zeroization primitive.
3. Inspect freed slots in tests and cover error, alert, timeout, and normal-close cleanup.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in Randomness requirements

Issue: TLS and Wi-Fi derive cryptographic secrets or nonces from timers and a fixed fallback rather than approved kernel entropy.

Required fixes:

1. Route all network cryptographic randomness through one entropy service with an explicit ready and failure state.
2. Separate deterministic replay randomness from live security randomness and prevent snapshots from repeating live keys or nonces.
3. Add boot-entropy, reseed, fork or restore, failure-injection, and repetition tests on every supported architecture.
4. Define entropy readiness during early boot and fail closed before key or nonce generation.

### Known issues/TODOS in Network-stack integration

Issue: TLS uses RTL8139 and static addressing instead of current backend, routing, ARP, and reactor state.

Required fixes:

1. Pass an authorized reactor connection into TLS rather than letting TLS create frames.
2. Remove static network identity from the TLS module.
3. Test reconfiguration, link loss, backend reset, AArch64 VirtIO, and gateway changes.

### Known issues/TODOS in Static mutable TLS state

Issue: TLS exposes unsynchronized static mutable sessions and static-lifetime mutable references.

Required fixes:

1. Put sessions behind one lock or reactor owner and never return static mutable references.
2. Use generation-bearing handles with scoped access.
3. Run concurrency and aliasing checks for tick, lookup, close, free, and reuse.

### Known issues/TODOS in Malformed TLS record handling

Issue: A peer-controlled TLS record length can exceed fixed arrays and reach panicking slice operations, while oversized encrypted handshakes lack one enforced bound.

Required fixes:

1. Reject records above the protocol and local buffer limits immediately after reading the header and before any copy.
2. Make decrypt output capacity explicit and return a typed fatal alert when plaintext cannot fit.
3. Fuzz fragmented, coalesced, oversized, truncated, unknown-type, padding, and authentication-failure records while asserting panic freedom and atomic state.
4. Send an appropriate fatal alert only when doing so cannot amplify unauthenticated traffic.

### Known issues/TODOS in TLS interoperability testing

Issue: TLS interoperability testing is only partially established by the active tls audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Integrate TLS with reactor-owned TCP and network authority.
2. Implement strict chain, hostname, transcript, and alert validation.
3. Add secret zeroization, malformed-record, and interoperability tests.
4. Record enough bounded diagnostics to identify recurrence without exposing sensitive data.

### Known issues/TODOS in Supported device families

Issue: Supported device families is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. List exact PCI identifiers and firmware revisions rather than broad vendor families.

### Known issues/TODOS in Hardware initialization paths

Issue: Wi-Fi reports success for broad vendor matches without implementing a verified chipset bring-up.

Required fixes:

1. Replace generic vendor success with exact supported device identifiers.
2. Fail unsupported hardware before enabling the driver state.
3. Require firmware, queue, interrupt, MAC, calibration, and link validation tests per supported chipset.

### Known issues/TODOS in PCI and MMIO access

Issue: Wi-Fi performs active volatile access through unvalidated BAR pointers and illustrative offsets.

Required fixes:

1. Map validated BAR resources through architecture memory APIs and mask BAR attributes correctly.
2. Use chipset-specific register definitions and verify mapped range sizes before access.
3. Do not enable bus mastering until DMA memory and ownership are established and tested.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in Bus mastering and DMA

Issue: Bus mastering and DMA is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Gate production enablement on the target-specific verification results.

### Known issues/TODOS in Scan lifecycle

Issue: Scan lifecycle is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Gate production enablement on the target-specific verification results.

### Known issues/TODOS in Channel selection

Issue: Channel selection is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.

### Known issues/TODOS in Probe request construction

Issue: Probe request construction is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.

### Known issues/TODOS in Beacon and probe-response parsing

Issue: Beacon and probe-response parsing is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Bind parsed information elements to the transmitting BSSID and received channel metadata.

### Known issues/TODOS in Information-element bounds

Issue: Information-element bounds is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.

### Known issues/TODOS in Scan result capacity

Issue: Scan result capacity is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Define deterministic replacement and aging when the bounded scan table is full.

### Known issues/TODOS in Duplicate network handling

Issue: Duplicate network handling is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Merge duplicates by BSSID and security identity rather than SSID text alone.

### Known issues/TODOS in Authentication state

Issue: Authentication state is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Tie every response to the current BSSID, attempt generation, sequence, and timeout window.

### Known issues/TODOS in Association state

Issue: Association state is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Validate status, association identifier, negotiated rates, and RSN parameters before advancing.

### Known issues/TODOS in Open-network connection

Issue: Open-network connection is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Keep open-network support behind explicit policy because association provides no peer authentication.

### Known issues/TODOS in WPA2 four-way handshake

Issue: WPA2 four-way handshake is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Zeroize all intermediate PMK, PTK, nonce, MIC, and unwrapped key buffers on every exit path.

### Known issues/TODOS in EAPOL frame parsing

Issue: EAPOL frame parsing is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Require the EAPOL payload to begin at the expected data-frame location instead of scanning arbitrary bytes for a marker.

### Known issues/TODOS in Replay-counter validation

Issue: Wi-Fi replay counters are checked only inside one transient four-way handshake and reset with local connection state.

Required fixes:

1. Maintain monotonic per-peer replay state across reconnect and define safe restoration behavior.
2. Distinguish legitimate retransmission from stale handshake replay while requiring counter progression for new handshakes.
3. Test repeated message one and three frames, reconnects, resets, restored state, counter wrap, and cross-BSSID substitution.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in MIC verification

Issue: The WPA2 MIC helper can truncate large EAPOL input through its fixed HMAC staging buffer and does not bind verification to negotiated suite parameters.

Required fixes:

1. Implement streaming HMAC without silent input truncation and enforce the maximum EAPOL size before allocation.
2. Derive the descriptor version and MIC algorithm from authenticated RSN negotiation rather than fixed assumptions.
3. Test maximum key-data messages, altered bytes beyond the old truncation boundary, suite mismatch, and constant-time rejection.
4. Verify descriptor-version and negotiated cipher consistency before selecting the MIC algorithm.

### Known issues/TODOS in PBKDF2 and HMAC processing

Issue: PBKDF2 and HMAC processing is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Replace fixed staging buffers with streaming primitives that cannot truncate input silently.

### Known issues/TODOS in Pairwise key derivation

Issue: Pairwise key derivation is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Validate the exact negotiated WPA2 suite before applying the fixed PTK layout.

### Known issues/TODOS in Group key extraction

Issue: Group key extraction is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Validate GTK key index, cipher-specific length, and KDE uniqueness before installation.

### Known issues/TODOS in AES key unwrap

Issue: AES key unwrap is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Zeroize the unwrapped buffer immediately when integrity or KDE validation fails.

### Known issues/TODOS in Key installation

Issue: Key installation is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Add deterministic fault tests for unavailable entropy and repetition tests across boots and reconnects.

### Known issues/TODOS in Password and key lifetime

Issue: Password and key lifetime is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Ensure compiler-resistant clearing of password-derived and installed-key staging memory.

### Known issues/TODOS in Disconnect behavior

Issue: Disconnect behavior is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Disable hardware encryption, clear key slots, reset packet numbers, and invalidate cached connection generations.

### Known issues/TODOS in Retry and timeout policy

Issue: Retry and timeout policy is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Use attempt generations so late authentication or association frames cannot complete a newer retry.

### Known issues/TODOS in Temporal PMK caching

Issue: Temporal PMK caching is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in Temporal reconnect behavior

Issue: Temporal reconnect behavior is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Gate production enablement on the target-specific verification results.

### Known issues/TODOS in Secret persistence risks

Issue: Wi-Fi snapshots persist and restore plaintext PMKs without sealing, freshness, or rollback protection.

Required fixes:

1. Stop persisting PMKs by default and reconnect through fresh credential acquisition.
2. If credential caching is required, seal it to device identity and boot policy with authenticated freshness.
3. Zeroize cached PMK, PTK, GTK, and password-derived intermediates on disconnect, replacement, and failure.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in Management-frame spoofing resistance

Issue: Management-frame spoofing resistance is only partially established by the active wi-fi audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Declare verified hardware and security modes.
2. Separate hardware, management, key, and data-plane ownership.
3. Add replay, malformed-frame, timeout, secret-lifetime, and hardware tests.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in Malformed wireless frame handling

Issue: Wi-Fi can parse trailing zero storage beyond the received frame and lacks trusted receive metadata.

Required fixes:

1. Pass only the exact validated received slice to every parser.
2. Reject hardware error, truncation, checksum, and decryption status before parsing.
3. Fuzz management and EAPOL parsers with exact-length and trailing-storage differential tests.

### Known issues/TODOS in PCI identification and BAR handling

Issue: PCI identification and BAR handling is only partially established by the active intel e1000 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Prove descriptor and DMA ownership on supported targets.
2. Implement reset, timeout, link-loss, and removal recovery.
3. Run QEMU and representative hardware conformance tests.

### Known issues/TODOS in MMIO mapping and register access

Issue: MMIO mapping and register access is only partially established by the active intel e1000 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Prove descriptor and DMA ownership on supported targets.
2. Implement reset, timeout, link-loss, and removal recovery.
3. Run QEMU and representative hardware conformance tests.
4. Add runtime evidence that distinguishes unsupported state from transient failure.

### Known issues/TODOS in EEPROM access and MAC discovery

Issue: EEPROM access and MAC discovery is only partially established by the active intel e1000 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Prove descriptor and DMA ownership on supported targets.
2. Implement reset, timeout, link-loss, and removal recovery.
3. Run QEMU and representative hardware conformance tests.

### Known issues/TODOS in Bus mastering

Issue: Bus mastering is only partially established by the active intel e1000 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Prove descriptor and DMA ownership on supported targets.
2. Implement reset, timeout, link-loss, and removal recovery.
3. Run QEMU and representative hardware conformance tests.
4. Disable bus mastering during teardown and every initialization failure path.

### Known issues/TODOS in Receive descriptor ring

Issue: Receive descriptor ring is only partially established by the active intel e1000 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Prove descriptor and DMA ownership on supported targets.
2. Implement reset, timeout, link-loss, and removal recovery.
3. Run QEMU and representative hardware conformance tests.
4. Track CPU and device ownership transitions explicitly and reject stale completion generations.

### Known issues/TODOS in Transmit descriptor ring

Issue: Transmit descriptor ring is only partially established by the active intel e1000 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Prove descriptor and DMA ownership on supported targets.
2. Implement reset, timeout, link-loss, and removal recovery.
3. Run QEMU and representative hardware conformance tests.
4. Do not reuse descriptors or packet buffers until verified hardware completion.

### Known issues/TODOS in Descriptor alignment

Issue: Descriptor alignment is only partially established by the active intel e1000 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Prove descriptor and DMA ownership on supported targets.
2. Implement reset, timeout, link-loss, and removal recovery. Run QEMU and representative hardware conformance tests.

### Known issues/TODOS in Static DMA buffer ownership

Issue: Static DMA buffer ownership is only partially established by the active intel e1000 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Prove descriptor and DMA ownership on supported targets.
2. Implement reset, timeout, link-loss, and removal recovery.
3. Run QEMU and representative hardware conformance tests.
4. Gate production enablement on the target-specific verification results.

### Known issues/TODOS in Receive frame validation

Issue: E1000 can return truncated, multi-descriptor, or error-marked receive data as a valid frame.

Required fixes:

1. Require descriptor completion, end-of-packet, acceptable length, and clear error status before exposing a frame.
2. Drop and count unsupported multi-descriptor packets instead of clamping them into valid-looking frames.
3. Add descriptor fault injection for oversized lengths, missing end markers, error bits, ring wrap, and reset races.

### Known issues/TODOS in Transmit frame validation

Issue: Transmit frame validation is only partially established by the active intel e1000 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Prove descriptor and DMA ownership on supported targets.
2. Implement reset, timeout, link-loss, and removal recovery.
3. Run QEMU and representative hardware conformance tests.

### Known issues/TODOS in Descriptor timeout behavior

Issue: Descriptor timeout behavior is only partially established by the active intel e1000 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Prove descriptor and DMA ownership on supported targets.
2. Implement reset, timeout, link-loss, and removal recovery. Run QEMU and representative hardware conformance tests.

### Known issues/TODOS in Transmit batching

Issue: Transmit batching is only partially established by the active intel e1000 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Prove descriptor and DMA ownership on supported targets.
2. Implement reset, timeout, link-loss, and removal recovery.
3. Run QEMU and representative hardware conformance tests.

### Known issues/TODOS in Adaptive interrupt throttling

Issue: Adaptive interrupt throttling is only partially established by the active intel e1000 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Prove descriptor and DMA ownership on supported targets.
2. Implement reset, timeout, link-loss, and removal recovery.
3. Run QEMU and representative hardware conformance tests.

### Known issues/TODOS in Link-state change handling

Issue: Link-state change handling is only partially established by the active intel e1000 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Prove descriptor and DMA ownership on supported targets.
2. Implement reset, timeout, link-loss, and removal recovery.
3. Run QEMU and representative hardware conformance tests.

### Known issues/TODOS in Memory ordering and device visibility

Issue: Memory ordering and device visibility is only partially established by the active intel e1000 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Prove descriptor and DMA ownership on supported targets.
2. Implement reset, timeout, link-loss, and removal recovery.
3. Run QEMU and representative hardware conformance tests.
4. Use architecture-appropriate DMA barriers and cache maintenance rather than CPU fences alone.

### Known issues/TODOS in QEMU and hardware conformance

Issue: QEMU and hardware conformance is only partially established by the active intel e1000 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Prove descriptor and DMA ownership on supported targets.
2. Implement reset, timeout, link-loss, and removal recovery.
3. Run QEMU and representative hardware conformance tests.

### Known issues/TODOS in PCI probing and I/O BAR handling

Issue: PCI probing and I/O BAR handling is only partially established by the active realtek rtl8139 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Normalize driver errors and common-backend semantics.
2. Prove receive-ring wraparound and DMA assumptions.
3. Add overflow, timeout, reset, emulator, and hardware tests.

### Known issues/TODOS in Transmit descriptor rotation

Issue: Transmit descriptor rotation is only partially established by the active realtek rtl8139 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Normalize driver errors and common-backend semantics.
2. Prove receive-ring wraparound and DMA assumptions.
3. Add overflow, timeout, reset, emulator, and hardware tests.
4. Bind rotation to verified completion instead of advancing solely by software index.

### Known issues/TODOS in Static transmit buffers

Issue: Static transmit buffers is only partially established by the active realtek rtl8139 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Normalize driver errors and common-backend semantics.
2. Prove receive-ring wraparound and DMA assumptions.
3. Add overflow, timeout, reset, emulator, and hardware tests.

### Known issues/TODOS in Receive ring layout

Issue: Receive ring layout is only partially established by the active realtek rtl8139 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Normalize driver errors and common-backend semantics.
2. Prove receive-ring wraparound and DMA assumptions. Add overflow, timeout, reset, emulator, and hardware tests.

### Known issues/TODOS in Receive ring wraparound

Issue: RTL8139 advances its consumer offset with an untrusted invalid packet length before normalizing or resynchronizing the ring.

Required fixes:

1. Validate packet status and length against hardware and ring limits before changing the consumer position.
2. Use checked modulo arithmetic for headers, payload, checksum, and alignment, with a bounded overflow recovery path.
3. Add wrap-boundary, corrupt-length, incomplete-packet, overflow, and repeated-error tests.

### Known issues/TODOS in Packet status validation

Issue: Packet status validation is only partially established by the active realtek rtl8139 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Normalize driver errors and common-backend semantics.
2. Prove receive-ring wraparound and DMA assumptions.
3. Add overflow, timeout, reset, emulator, and hardware tests.

### Known issues/TODOS in CRC and alignment error handling

Issue: CRC and alignment error handling is only partially established by the active realtek rtl8139 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Normalize driver errors and common-backend semantics.
2. Prove receive-ring wraparound and DMA assumptions. Add overflow, timeout, reset, emulator, and hardware tests.

### Known issues/TODOS in Receive overflow recovery

Issue: Receive overflow recovery is only partially established by the active realtek rtl8139 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Normalize driver errors and common-backend semantics.
2. Prove receive-ring wraparound and DMA assumptions.
3. Add overflow, timeout, reset, emulator, and hardware tests.
4. Add runtime evidence that distinguishes unsupported state from transient failure.

### Known issues/TODOS in Transmit completion and timeout

Issue: RTL8139 overwrites and reuses a transmit buffer after its ownership wait expires, then reports success.

Required fixes:

1. Return a typed timeout without touching the buffer or descriptor when hardware ownership does not clear.
2. Track descriptor generations and require reset or verified completion before reuse.
3. Test stalled ownership, late completion, descriptor rotation, reset during transmit, and recovery.

### Known issues/TODOS in Interrupt mask and acknowledgement

Issue: Interrupt mask and acknowledgement is only partially established by the active realtek rtl8139 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Normalize driver errors and common-backend semantics.
2. Prove receive-ring wraparound and DMA assumptions.
3. Add overflow, timeout, reset, emulator, and hardware tests.

### Known issues/TODOS in Link-state detection

Issue: Link-state detection is only partially established by the active realtek rtl8139 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Normalize driver errors and common-backend semantics.
2. Prove receive-ring wraparound and DMA assumptions. Add overflow, timeout, reset, emulator, and hardware tests.

### Known issues/TODOS in DMA address assumptions

Issue: DMA address assumptions is only partially established by the active realtek rtl8139 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Normalize driver errors and common-backend semantics.
2. Prove receive-ring wraparound and DMA assumptions.
3. Add overflow, timeout, reset, emulator, and hardware tests.
4. Document the supported boundary and reject operation outside it.

### Known issues/TODOS in Hardware and emulator conformance

Issue: Hardware and emulator conformance is only partially established by the active realtek rtl8139 driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Normalize driver errors and common-backend semantics.
2. Prove receive-ring wraparound and DMA assumptions.
3. Add overflow, timeout, reset, emulator, and hardware tests.

### Known issues/TODOS in MMIO device discovery

Issue: MMIO device discovery is only partially established by the active virtio network driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use DMA-safe queue and packet memory.
2. Complete feature, reset, interrupt, and queue validation.
3. Run weak-ordering and cross-architecture conformance tests.
4. Define rollback behavior for failure after partial state mutation.

### Known issues/TODOS in VirtIO version validation

Issue: VirtIO version validation is only partially established by the active virtio network driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use DMA-safe queue and packet memory.
2. Complete feature, reset, interrupt, and queue validation.
3. Run weak-ordering and cross-architecture conformance tests.

### Known issues/TODOS in Device-status state machine

Issue: Device-status state machine is only partially established by the active virtio network driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use DMA-safe queue and packet memory.
2. Complete feature, reset, interrupt, and queue validation.
3. Run weak-ordering and cross-architecture conformance tests.

### Known issues/TODOS in Feature negotiation

Issue: Feature negotiation is only partially established by the active virtio network driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use DMA-safe queue and packet memory.
2. Complete feature, reset, interrupt, and queue validation.
3. Run weak-ordering and cross-architecture conformance tests.

### Known issues/TODOS in MAC feature negotiation

Issue: MAC feature negotiation is only partially established by the active virtio network driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use DMA-safe queue and packet memory.
2. Complete feature, reset, interrupt, and queue validation.
3. Run weak-ordering and cross-architecture conformance tests.

### Known issues/TODOS in Link-status feature handling

Issue: Link-status feature handling is only partially established by the active virtio network driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use DMA-safe queue and packet memory.
2. Complete feature, reset, interrupt, and queue validation.
3. Run weak-ordering and cross-architecture conformance tests.

### Known issues/TODOS in Unsupported mergeable-buffer behavior

Issue: Unsupported mergeable-buffer behavior is only partially established by the active virtio network driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use DMA-safe queue and packet memory.
2. Complete feature, reset, interrupt, and queue validation.
3. Run weak-ordering and cross-architecture conformance tests.

### Known issues/TODOS in Split virtqueue layout

Issue: Split virtqueue layout is only partially established by the active virtio network driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use DMA-safe queue and packet memory.
2. Complete feature, reset, interrupt, and queue validation. Run weak-ordering and cross-architecture conformance tests.

### Known issues/TODOS in Descriptor allocation and free list

Issue: VirtIO accepts unchecked and duplicate descriptor identifiers into allocator state, permitting out-of-bounds access and double allocation.

Required fixes:

1. Track each descriptor as free, available, device-owned, or completed and validate every transition.
2. Reject out-of-range, duplicate, and queue-mismatched completions before modifying the free list. Property-test arbitrary allocation and completion sequences while asserting unique ownership and bounded free count.

### Known issues/TODOS in Available-ring publication

Issue: Available-ring publication is only partially established by the active virtio network driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use DMA-safe queue and packet memory.
2. Complete feature, reset, interrupt, and queue validation.
3. Run weak-ordering and cross-architecture conformance tests.
4. Publish descriptor contents before the ring index with the required device-visible barrier.

### Known issues/TODOS in Used-ring consumption

Issue: VirtIO trusts the device used index and element identifiers without bounding progress or proving descriptor ownership.

Required fixes:

1. Bound each poll by negotiated queue size and reject used-index advances that imply more outstanding completions than exist.
2. Validate each identifier against the queue and outstanding generation before accessing buffers or freeing descriptors.
3. Fault-inject stale slots, duplicate identifiers, invalid lengths, index wrap, and arbitrary used-index jumps.

### Known issues/TODOS in Receive-buffer replenishment

Issue: Receive-buffer replenishment is only partially established by the active virtio network driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use DMA-safe queue and packet memory.
2. Complete feature, reset, interrupt, and queue validation.
3. Run weak-ordering and cross-architecture conformance tests.

### Known issues/TODOS in Transmit completion

Issue: Transmit completion is only partially established by the active virtio network driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use DMA-safe queue and packet memory.
2. Complete feature, reset, interrupt, and queue validation.
3. Run weak-ordering and cross-architecture conformance tests.

### Known issues/TODOS in Queue-size validation

Issue: VirtIO programs a negotiated queue size but continues to operate internal rings as if every queue had the compile-time maximum.

Required fixes:

1. Reject zero and unsupported queue geometry, then store one validated runtime queue size.
2. Use that size for descriptor initialization, ring modulo operations, receive replenishment, publication, and completion.
3. Test every supported size, smaller device maxima, wraparound, full queues, and invalid nonconforming values.
4. Test queue publication above four gigabytes, under an IOMMU, and on weakly ordered AArch64 systems.

### Known issues/TODOS in Physical and virtual address assumptions

Issue: Physical and virtual address assumptions is only partially established by the active virtio network driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use DMA-safe queue and packet memory.
2. Complete feature, reset, interrupt, and queue validation.
3. Run weak-ordering and cross-architecture conformance tests.

### Known issues/TODOS in Memory fences on weakly ordered systems

Issue: Memory fences on weakly ordered systems is only partially established by the active virtio network driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use DMA-safe queue and packet memory.
2. Complete feature, reset, interrupt, and queue validation.
3. Run weak-ordering and cross-architecture conformance tests.

### Known issues/TODOS in Polled receive behavior

Issue: Polled receive behavior is only partially established by the active virtio network driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use DMA-safe queue and packet memory.
2. Complete feature, reset, interrupt, and queue validation.
3. Run weak-ordering and cross-architecture conformance tests.

### Known issues/TODOS in Pending receive buffering

Issue: Pending receive buffering is only partially established by the active virtio network driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use DMA-safe queue and packet memory.
2. Complete feature, reset, interrupt, and queue validation.
3. Run weak-ordering and cross-architecture conformance tests.
4. Bound queued copied frames and report truncation instead of returning a shortened packet as complete.

### Known issues/TODOS in Capability-gated send path

Issue: Capability-gated send path is only partially established by the active virtio network driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use DMA-safe queue and packet memory.
2. Complete feature, reset, interrupt, and queue validation.
3. Run weak-ordering and cross-architecture conformance tests.
4. Record enough bounded diagnostics to identify recurrence without exposing sensitive data.

### Known issues/TODOS in Incorrect capability-type substitution

Issue: Incorrect capability-type substitution is only partially established by the active virtio network driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use DMA-safe queue and packet memory.
2. Complete feature, reset, interrupt, and queue validation.
3. Run weak-ordering and cross-architecture conformance tests.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in AArch64 and x86-64 conformance

Issue: AArch64 and x86-64 conformance is only partially established by the active virtio network driver audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use DMA-safe queue and packet memory.
2. Complete feature, reset, interrupt, and queue validation.
3. Run weak-ordering and cross-architecture conformance tests.
4. Remove the Channel and Rights::NONE substitution and test every public entry path.

### Known issues/TODOS in Network-receive authority

Issue: Network-receive authority is only partially established by the active capability-based network access audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define dedicated network capability types and minimum rights.
2. Carry principal and authority through the reactor to commit.
3. Test denial, attenuation, revocation, inheritance, and entry-path consistency.
4. Revalidate authority after wakeup and immediately before consuming queued data.

### Known issues/TODOS in Socket creation authority

Issue: Socket creation authority is only partially established by the active capability-based network access audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define dedicated network capability types and minimum rights.
2. Carry principal and authority through the reactor to commit.
3. Test denial, attenuation, revocation, inheritance, and entry-path consistency.
4. Bind each created socket to principal and capability generation for its full lifecycle.

### Known issues/TODOS in DNS and HTTP authority

Issue: DNS and HTTP authority is only partially established by the active capability-based network access audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define dedicated network capability types and minimum rights.
2. Carry principal and authority through the reactor to commit.
3. Test denial, attenuation, revocation, inheritance, and entry-path consistency.
4. Separate name-resolution and outbound-connect rights so one does not imply the other.

### Known issues/TODOS in Raw-frame authority

Issue: Raw-frame authority is only partially established by the active capability-based network access audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define dedicated network capability types and minimum rights.
2. Carry principal and authority through the reactor to commit.
3. Test denial, attenuation, revocation, inheritance, and entry-path consistency.
4. Restrict source-address, EtherType, interface, and rate under a dedicated raw-network capability.

### Known issues/TODOS in Device-administration authority

Issue: Device-administration authority is only partially established by the active capability-based network access audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define dedicated network capability types and minimum rights.
2. Carry principal and authority through the reactor to commit.
3. Test denial, attenuation, revocation, inheritance, and entry-path consistency.
4. Require separate rights for configuration, promiscuous mode, reset, and key installation.

### Known issues/TODOS in Use of channel capability as network authority

Issue: Use of channel capability as network authority is only partially established by the active capability-based network access audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define dedicated network capability types and minimum rights.
2. Carry principal and authority through the reactor to commit.
3. Test denial, attenuation, revocation, inheritance, and entry-path consistency.
4. Add runtime evidence that distinguishes unsupported state from transient failure.

### Known issues/TODOS in Process ownership checks

Issue: Process ownership checks is only partially established by the active capability-based network access audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define dedicated network capability types and minimum rights.
2. Carry principal and authority through the reactor to commit.
3. Test denial, attenuation, revocation, inheritance, and entry-path consistency.
4. Use process generations so PID reuse cannot inherit sockets, queues, or restored authority.

### Known issues/TODOS in Revocation during active connections

Issue: Revocation during active connections is only partially established by the active capability-based network access audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define dedicated network capability types and minimum rights.
2. Carry principal and authority through the reactor to commit.
3. Test denial, attenuation, revocation, inheritance, and entry-path consistency.
4. Document the supported boundary and reject operation outside it.

### Known issues/TODOS in Capability inheritance and delegation

Issue: Capability inheritance and delegation is only partially established by the active capability-based network access audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define dedicated network capability types and minimum rights.
2. Carry principal and authority through the reactor to commit.
3. Test denial, attenuation, revocation, inheritance, and entry-path consistency.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in Service and syscall authorization consistency

Issue: Service and syscall authorization consistency is only partially established by the active capability-based network access audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define dedicated network capability types and minimum rights.
2. Carry principal and authority through the reactor to commit.
3. Test denial, attenuation, revocation, inheritance, and entry-path consistency.
4. Define rollback behavior for failure after partial state mutation.

### Known issues/TODOS in CapNet purpose and trust model

Issue: CapNet purpose and trust model is only partially established by the active capnet architecture audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define CapNet trust and its relationship to central capabilities.
2. Separate state only along enforceable ownership boundaries.
3. Test peer, transport, persistence, and authority integration.

### Known issues/TODOS in Portable capability-token model

Issue: Portable capability-token model is only partially established by the active capnet architecture audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define CapNet trust and its relationship to central capabilities.
2. Separate state only along enforceable ownership boundaries.
3. Test peer, transport, persistence, and authority integration.
4. Document the supported boundary and reject operation outside it.

### Known issues/TODOS in Device identity

Issue: Device identity is only partially established by the active capnet architecture audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define CapNet trust and its relationship to central capabilities.
2. Separate state only along enforceable ownership boundaries.
3. Test peer, transport, persistence, and authority integration.
4. Persist identity only when protected by device-rooted integrity and rollback resistance.

### Known issues/TODOS in Peer registration

Issue: Peer registration is only partially established by the active capnet architecture audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define CapNet trust and its relationship to central capabilities.
2. Separate state only along enforceable ownership boundaries.
3. Test peer, transport, persistence, and authority integration.
4. Require authenticated administrative authority to add, replace, or weaken peer trust policy.

### Known issues/TODOS in Peer trust policy

Issue: Peer trust policy is only partially established by the active capnet architecture audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define CapNet trust and its relationship to central capabilities.
2. Separate state only along enforceable ownership boundaries.
3. Test peer, transport, persistence, and authority integration.
4. Prevent Audit policy from silently becoming equivalent to Enforce for one check and permissive for another.

### Known issues/TODOS in Peer-session establishment

Issue: Peer-session establishment is only partially established by the active capnet architecture audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define CapNet trust and its relationship to central capabilities.
2. Separate state only along enforceable ownership boundaries.
3. Test peer, transport, persistence, and authority integration.
4. Authenticate the handshake that supplies nonces and measurement before deriving session keys.

### Known issues/TODOS in Session-key installation

Issue: Session-key installation is only partially established by the active capnet architecture audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define CapNet trust and its relationship to central capabilities.
2. Separate state only along enforceable ownership boundaries.
3. Test peer, transport, persistence, and authority integration.
4. Reject stale epochs and zeroize replaced keys before resetting replay windows.

### Known issues/TODOS in Token signing and verification

Issue: Token signing and verification is only partially established by the active capnet architecture audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define CapNet trust and its relationship to central capabilities.
2. Separate state only along enforceable ownership boundaries.
3. Test peer, transport, persistence, and authority integration.
4. Bind algorithm, key epoch, and peer session into one downgrade-resistant verification decision.

### Known issues/TODOS in Control-frame transport

Issue: Control-frame transport is only partially established by the active capnet architecture audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define CapNet trust and its relationship to central capabilities.
2. Separate state only along enforceable ownership boundaries.
3. Test peer, transport, persistence, and authority integration.
4. Separate transport acknowledgement from semantic acceptance of the enclosed authority operation.

### Known issues/TODOS in Integration with UDP

Issue: Integration with UDP is only partially established by the active capnet architecture audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define CapNet trust and its relationship to central capabilities.
2. Separate state only along enforceable ownership boundaries.
3. Test peer, transport, persistence, and authority integration.
4. Bind a peer session to expected network endpoints without treating mutable IP addresses as identity.

### Known issues/TODOS in Integration with the capability manager

Issue: Integration with the capability manager is only partially established by the active capnet architecture audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define CapNet trust and its relationship to central capabilities.
2. Separate state only along enforceable ownership boundaries.
3. Test peer, transport, persistence, and authority integration.
4. Define rollback behavior for failure after partial state mutation.

### Known issues/TODOS in Integration with temporal persistence

Issue: Integration with temporal persistence is only partially established by the active capnet architecture audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define CapNet trust and its relationship to central capabilities.
2. Separate state only along enforceable ownership boundaries.
3. Test peer, transport, persistence, and authority integration.
4. Gate production enablement on the target-specific verification results.

### Known issues/TODOS in Monolithic implementation and facade split

Issue: Monolithic implementation and facade split is only partially established by the active capnet architecture audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define CapNet trust and its relationship to central capabilities.
2. Separate state only along enforceable ownership boundaries.
3. Test peer, transport, persistence, and authority integration.

### Known issues/TODOS in Facade ownership boundaries

Issue: Facade ownership boundaries is only partially established by the active capnet architecture audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define CapNet trust and its relationship to central capabilities.
2. Separate state only along enforceable ownership boundaries.
3. Test peer, transport, persistence, and authority integration.

### Known issues/TODOS in Dead-code suppression and maturity

Issue: Dead-code suppression and maturity is only partially established by the active capnet architecture audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define CapNet trust and its relationship to central capabilities.
2. Separate state only along enforceable ownership boundaries.
3. Test peer, transport, persistence, and authority integration.

### Known issues/TODOS in Token magic and version

Issue: Token magic and version is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use.
3. Add golden vectors, mutation tests, and cross-device interoperability.
4. Reject reserved fields that are nonzero unless a negotiated version defines them.

### Known issues/TODOS in Fixed serialized size

Issue: Fixed serialized size is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use.
3. Add golden vectors, mutation tests, and cross-device interoperability.

### Known issues/TODOS in Canonical byte encoding

Issue: Canonical byte encoding is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use. Add golden vectors, mutation tests, and cross-device interoperability.

### Known issues/TODOS in Byte-order contract

Issue: Byte-order contract is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use. Add golden vectors, mutation tests, and cross-device interoperability.

### Known issues/TODOS in Algorithm identifier

Issue: Algorithm identifier is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use.
3. Add golden vectors, mutation tests, and cross-device interoperability.
4. Prevent algorithm downgrade when a stronger token version or peer policy is required.

### Known issues/TODOS in Issuer and subject device identity

Issue: Issuer and subject device identity is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use.
3. Add golden vectors, mutation tests, and cross-device interoperability.
4. Resolve both identities through the authenticated peer session rather than trusting encoded numbers alone.

### Known issues/TODOS in Capability type and rights

Issue: Capability type and rights is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use.
3. Add golden vectors, mutation tests, and cross-device interoperability.
4. Define rollback behavior for failure after partial state mutation.

### Known issues/TODOS in Object identity

Issue: Object identity is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use.
3. Add golden vectors, mutation tests, and cross-device interoperability.

### Known issues/TODOS in Parent-token hash

Issue: Parent-token hash is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use.
3. Add golden vectors, mutation tests, and cross-device interoperability.

### Known issues/TODOS in Delegation depth

Issue: Delegation depth is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use.
3. Add golden vectors, mutation tests, and cross-device interoperability.
4. Detect cycles independently of the depth field and parent hash claims.

### Known issues/TODOS in Temporal validity window

Issue: Temporal validity window is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use.
3. Add golden vectors, mutation tests, and cross-device interoperability.
4. Define rollback behavior for failure after partial state mutation.

### Known issues/TODOS in Nonce and token identity

Issue: Nonce and token identity is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use.
3. Add golden vectors, mutation tests, and cross-device interoperability.

### Known issues/TODOS in Measurement binding

Issue: Measurement binding is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use.
3. Add golden vectors, mutation tests, and cross-device interoperability.
4. Define the measurement algorithm, provenance, freshness, and update policy as part of trust.

### Known issues/TODOS in Use-count constraint

Issue: Use-count constraint is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use.
3. Add golden vectors, mutation tests, and cross-device interoperability.

### Known issues/TODOS in Byte-quota constraint

Issue: Byte-quota constraint is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use.
3. Add golden vectors, mutation tests, and cross-device interoperability.

### Known issues/TODOS in Resource quota

Issue: Resource quota is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use.
3. Add golden vectors, mutation tests, and cross-device interoperability.

### Known issues/TODOS in Constraint flag consistency

Issue: Constraint flag consistency is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use.
3. Add golden vectors, mutation tests, and cross-device interoperability.

### Known issues/TODOS in Reserved fields and forward compatibility

Issue: Reserved fields and forward compatibility is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use.
3. Add golden vectors, mutation tests, and cross-device interoperability.

### Known issues/TODOS in Token MAC coverage

Issue: CapNet field coverage is canonical, but the sixty-four-bit symmetric authenticator cannot establish portable issuer provenance or long-term multi-hop trust.

Required fixes:

1. Document the current MAC as session-local authentication and set issuance and forgery budgets appropriate to sixty-four-bit tags.
2. Add a versioned asymmetric signature algorithm for portable delegation while retaining canonical field coverage and downgrade resistance.
3. Test field mutation, cross-session replay, key replacement, algorithm confusion, multi-hop verification, and forgery-rate limits.

### Known issues/TODOS in Canonical token identifier hashing

Issue: Canonical token identifier hashing is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use.
3. Add golden vectors, mutation tests, and cross-device interoperability.

### Known issues/TODOS in Decode bounds and trailing bytes

Issue: Decode bounds and trailing bytes is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use.
3. Add golden vectors, mutation tests, and cross-device interoperability.
4. Guarantee failed decoding cannot mutate replay, peer, lease, or revocation state.

### Known issues/TODOS in Unknown version and algorithm handling

Issue: Unknown version and algorithm handling is only partially established by the active capnet token format audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Version the canonical encoding and algorithm policy.
2. Validate every field and constraint before authority use.
3. Add golden vectors, mutation tests, and cross-device interoperability.
4. Return explicit incompatibility without attempting permissive fallback.

### Known issues/TODOS in Delegation-chain construction

Issue: Delegation-chain construction is only partially established by the active capnet delegation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Enforce attenuation and ancestry through manager-recognized state.
2. Make delegation transactional with rollback. Test depth, duplicates, splits, revocation, and cross-device use.

### Known issues/TODOS in Parent lookup

Issue: Parent lookup is only partially established by the active capnet delegation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Enforce attenuation and ancestry through manager-recognized state.
2. Make delegation transactional with rollback.
3. Test depth, duplicates, splits, revocation, and cross-device use.
4. Bind parent records to issuer, token generation, and unexpired authenticated state.

### Known issues/TODOS in Capability-type preservation

Issue: Capability-type preservation is only partially established by the active capnet delegation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Enforce attenuation and ancestry through manager-recognized state.
2. Make delegation transactional with rollback.
3. Test depth, duplicates, splits, revocation, and cross-device use.
4. Record enough bounded diagnostics to identify recurrence without exposing sensitive data.

### Known issues/TODOS in Object identity preservation

Issue: Object identity preservation is only partially established by the active capnet delegation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Enforce attenuation and ancestry through manager-recognized state.
2. Make delegation transactional with rollback.
3. Test depth, duplicates, splits, revocation, and cross-device use.

### Known issues/TODOS in Temporal-window narrowing

Issue: Temporal-window narrowing is only partially established by the active capnet delegation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Enforce attenuation and ancestry through manager-recognized state.
2. Make delegation transactional with rollback.
3. Test depth, duplicates, splits, revocation, and cross-device use.
4. Define rollback behavior for failure after partial state mutation.

### Known issues/TODOS in Constraint inheritance

Issue: Constraint inheritance is only partially established by the active capnet delegation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Enforce attenuation and ancestry through manager-recognized state.
2. Make delegation transactional with rollback.
3. Test depth, duplicates, splits, revocation, and cross-device use.
4. Require every parent constraint to survive delegation unless an explicit stronger form replaces it.

### Known issues/TODOS in Maximum delegation depth

Issue: Maximum delegation depth is only partially established by the active capnet delegation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Enforce attenuation and ancestry through manager-recognized state.
2. Make delegation transactional with rollback.
3. Test depth, duplicates, splits, revocation, and cross-device use.

### Known issues/TODOS in Delegation record capacity

Issue: Delegation record capacity is only partially established by the active capnet delegation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Enforce attenuation and ancestry through manager-recognized state.
2. Make delegation transactional with rollback.
3. Test depth, duplicates, splits, revocation, and cross-device use.
4. Never evict a parent record while an unexpired descendant depends on it.

### Known issues/TODOS in Affine split representation

Issue: Affine split representation is only partially established by the active capnet delegation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Enforce attenuation and ancestry through manager-recognized state.
2. Make delegation transactional with rollback.
3. Test depth, duplicates, splits, revocation, and cross-device use.

### Known issues/TODOS in Linear capability claims

Issue: Linear capability claims is only partially established by the active capnet delegation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Enforce attenuation and ancestry through manager-recognized state.
2. Make delegation transactional with rollback.
3. Test depth, duplicates, splits, revocation, and cross-device use.
4. Document the supported boundary and reject operation outside it.

### Known issues/TODOS in Duplicate delegation

Issue: Duplicate delegation is only partially established by the active capnet delegation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Enforce attenuation and ancestry through manager-recognized state.
2. Make delegation transactional with rollback.
3. Test depth, duplicates, splits, revocation, and cross-device use.
4. Make repeated delivery idempotent without reinstalling leases or resetting use accounting.

### Known issues/TODOS in Delegation rollback

Issue: Delegation rollback is only partially established by the active capnet delegation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Enforce attenuation and ancestry through manager-recognized state.
2. Make delegation transactional with rollback.
3. Test depth, duplicates, splits, revocation, and cross-device use.
4. Publish parent accounting and child creation atomically or preserve the parent unchanged.

### Known issues/TODOS in Cross-device delegation

Issue: Cross-device delegation is only partially established by the active capnet delegation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Enforce attenuation and ancestry through manager-recognized state.
2. Make delegation transactional with rollback.
3. Test depth, duplicates, splits, revocation, and cross-device use.
4. Require each hop to authenticate the next subject and preserve the original issuer chain.

### Known issues/TODOS in Descendant revocation

Issue: Descendant revocation is only partially established by the active capnet delegation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Enforce attenuation and ancestry through manager-recognized state.
2. Make delegation transactional with rollback.
3. Test depth, duplicates, splits, revocation, and cross-device use.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in Peer table capacity

Issue: Peer table capacity is only partially established by the active capnet peer session audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate peer establishment and key replacement.
2. Bind replay state and sequence allocation to session generations.
3. Test eviction, reconnect, wraparound, concurrency, and zeroization.
4. Apply an explicit trusted eviction policy rather than letting registration order decide availability.

### Known issues/TODOS in Duplicate peer registration

Issue: Duplicate peer registration is only partially established by the active capnet peer session audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate peer establishment and key replacement.
2. Bind replay state and sequence allocation to session generations.
3. Test eviction, reconnect, wraparound, concurrency, and zeroization.
4. Reject trust-policy weakening and key replacement without authenticated reconfiguration.

### Known issues/TODOS in Trust-on-first-use policy

Issue: Trust-on-first-use policy is only partially established by the active capnet peer session audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate peer establishment and key replacement.
2. Bind replay state and sequence allocation to session generations.
3. Test eviction, reconnect, wraparound, concurrency, and zeroization.
4. Record first binding durably and require explicit authority to replace it.

### Known issues/TODOS in Pinned-measurement policy

Issue: Pinned-measurement policy is only partially established by the active capnet peer session audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate peer establishment and key replacement.
2. Bind replay state and sequence allocation to session generations.
3. Test eviction, reconnect, wraparound, concurrency, and zeroization.
4. Fail closed when the measurement is unavailable rather than accepting an unmeasured peer.

### Known issues/TODOS in Session epoch

Issue: Session epoch is only partially established by the active capnet peer session audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate peer establishment and key replacement.
2. Bind replay state and sequence allocation to session generations.
3. Test eviction, reconnect, wraparound, concurrency, and zeroization.
4. Persist or derive epochs so restart cannot reuse a prior key and replay window combination.

### Known issues/TODOS in Session key derivation

Issue: Session key derivation is only partially established by the active capnet peer session audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate peer establishment and key replacement.
2. Bind replay state and sequence allocation to session generations.
3. Test eviction, reconnect, wraparound, concurrency, and zeroization.
4. Include ordered identities, transcript context, nonces, measurement, and epoch in domain-separated input.

### Known issues/TODOS in Key replacement

Issue: Key replacement is only partially established by the active capnet peer session audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate peer establishment and key replacement.
2. Bind replay state and sequence allocation to session generations.
3. Test eviction, reconnect, wraparound, concurrency, and zeroization.
4. Stage the new key and replay state before atomically retiring the old generation.

### Known issues/TODOS in Key zeroization

Issue: Key zeroization is only partially established by the active capnet peer session audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate peer establishment and key replacement.
2. Bind replay state and sequence allocation to session generations.
3. Test eviction, reconnect, wraparound, concurrency, and zeroization.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in Peer liveness tracking

Issue: Peer liveness tracking is only partially established by the active capnet peer session audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate peer establishment and key replacement.
2. Bind replay state and sequence allocation to session generations.
3. Test eviction, reconnect, wraparound, concurrency, and zeroization.
4. Do not treat unauthenticated traffic or local time restoration as proof of peer liveness.

### Known issues/TODOS in Incoming nonce replay window

Issue: Incoming nonce replay window is only partially established by the active capnet peer session audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate peer establishment and key replacement.
2. Bind replay state and sequence allocation to session generations.
3. Test eviction, reconnect, wraparound, concurrency, and zeroization.
4. Keep minimized failures in the permanent regression corpus.
5. Require this property to pass before enabling the affected feature.

### Known issues/TODOS in Control sequence replay window

Issue: Control sequence replay window is only partially established by the active capnet peer session audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate peer establishment and key replacement.
2. Bind replay state and sequence allocation to session generations.
3. Test eviction, reconnect, wraparound, concurrency, and zeroization.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in Outgoing sequence allocation

Issue: Outgoing sequence allocation is only partially established by the active capnet peer session audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate peer establishment and key replacement.
2. Bind replay state and sequence allocation to session generations. Test eviction, reconnect, wraparound, concurrency, and zeroization.

### Known issues/TODOS in Sequence wraparound

Issue: Sequence wraparound is only partially established by the active capnet peer session audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate peer establishment and key replacement.
2. Bind replay state and sequence allocation to session generations.
3. Test eviction, reconnect, wraparound, concurrency, and zeroization.
4. Require session rekey before control or replay sequence space can wrap.

### Known issues/TODOS in Session reset and reconnect

Issue: Session reset and reconnect is only partially established by the active capnet peer session audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate peer establishment and key replacement.
2. Bind replay state and sequence allocation to session generations.
3. Test eviction, reconnect, wraparound, concurrency, and zeroization.
4. Reject old-session frames after reset even when network endpoints and token fields match.

### Known issues/TODOS in Peer eviction

Issue: Peer eviction is only partially established by the active capnet peer session audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate peer establishment and key replacement.
2. Bind replay state and sequence allocation to session generations.
3. Test eviction, reconnect, wraparound, concurrency, and zeroization.
4. Revoke or quarantine installed remote leases before removing the peer verification state.

### Known issues/TODOS in Concurrent peer operations

Issue: Concurrent peer operations is only partially established by the active capnet peer session audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate peer establishment and key replacement.
2. Bind replay state and sequence allocation to session generations.
3. Test eviction, reconnect, wraparound, concurrency, and zeroization.
4. Gate production enablement on the target-specific verification results.

### Known issues/TODOS in Control-frame header

Issue: Control-frame header is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message.
3. Test queue pressure, replay, loss, mutation, and retransmission.

### Known issues/TODOS in Control message types

Issue: Control message types is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message.
3. Test queue pressure, replay, loss, mutation, and retransmission.

### Known issues/TODOS in Hello exchange

Issue: Hello exchange is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message.
3. Test queue pressure, replay, loss, mutation, and retransmission.

### Known issues/TODOS in Attestation exchange

Issue: Attestation exchange is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message.
3. Test queue pressure, replay, loss, mutation, and retransmission.

### Known issues/TODOS in Heartbeat exchange

Issue: Heartbeat exchange is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message.
3. Test queue pressure, replay, loss, mutation, and retransmission.

### Known issues/TODOS in Token offer

Issue: Token offer is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message.
3. Test queue pressure, replay, loss, mutation, and retransmission.

### Known issues/TODOS in Token acceptance

Issue: Token acceptance is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message.
3. Test queue pressure, replay, loss, mutation, and retransmission.

### Known issues/TODOS in Token revocation

Issue: Token revocation is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message.
3. Test queue pressure, replay, loss, mutation, and retransmission.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in Acknowledgement fields

Issue: Acknowledgement fields is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message.
3. Test queue pressure, replay, loss, mutation, and retransmission.

### Known issues/TODOS in Acknowledgement-only flag

Issue: Acknowledgement-only flag is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message.
3. Test queue pressure, replay, loss, mutation, and retransmission.

### Known issues/TODOS in Frame MAC construction

Issue: Frame MAC construction is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message. Test queue pressure, replay, loss, mutation, and retransmission.

### Known issues/TODOS in Session and issuer binding

Issue: Session and issuer binding is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message.
3. Test queue pressure, replay, loss, mutation, and retransmission.

### Known issues/TODOS in Replay rejection

Issue: Replay rejection is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message.
3. Test queue pressure, replay, loss, mutation, and retransmission.
4. Keep minimized failures in the permanent regression corpus.
5. Require this property to pass before enabling the affected feature.

### Known issues/TODOS in Unknown control-type handling

Issue: Unknown control-type handling is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message.
3. Test queue pressure, replay, loss, mutation, and retransmission.

### Known issues/TODOS in Incoming queue capacity

Issue: Incoming queue capacity is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message.
3. Test queue pressure, replay, loss, mutation, and retransmission.

### Known issues/TODOS in Retransmission queue

Issue: Retransmission queue is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message.
3. Test queue pressure, replay, loss, mutation, and retransmission.

### Known issues/TODOS in Retransmission interval and retry limit

Issue: Retransmission interval and retry limit is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message.
3. Test queue pressure, replay, loss, mutation, and retransmission.

### Known issues/TODOS in Acknowledgement-driven removal

Issue: Acknowledgement-driven removal is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message.
3. Test queue pressure, replay, loss, mutation, and retransmission.

### Known issues/TODOS in Duplicate delivery behavior

Issue: Duplicate delivery behavior is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message.
3. Test queue pressure, replay, loss, mutation, and retransmission.

### Known issues/TODOS in Malformed control-frame handling

Issue: Malformed control-frame handling is only partially established by the active capnet control protocol audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Specify delivery, acknowledgement, duplicate, and retry semantics.
2. Authenticate every state-changing control message.
3. Test queue pressure, replay, loss, mutation, and retransmission.
4. Authenticate fixed header semantics before allocating or copying variable payload state.

### Known issues/TODOS in Device measurement representation

Issue: Device measurement representation is only partially established by the active capnet attestation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define trusted measurement production and verification.
2. Bind freshness and session identity cryptographically.
3. Add algorithm, certificate, replay, and interoperability tests.

### Known issues/TODOS in Measurement trust source

Issue: Measurement trust source is only partially established by the active capnet attestation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define trusted measurement production and verification.
2. Bind freshness and session identity cryptographically.
3. Add algorithm, certificate, replay, and interoperability tests.

### Known issues/TODOS in Attestation frame construction

Issue: Attestation frame construction is only partially established by the active capnet attestation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define trusted measurement production and verification.
2. Bind freshness and session identity cryptographically. Add algorithm, certificate, replay, and interoperability tests.

### Known issues/TODOS in Attestation verification

Issue: Attestation verification is only partially established by the active capnet attestation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define trusted measurement production and verification.
2. Bind freshness and session identity cryptographically.
3. Add algorithm, certificate, replay, and interoperability tests.
4. Bind verified measurement evidence to peer identity, session transcript, freshness, and algorithm policy.

### Known issues/TODOS in Replay resistance

Issue: Replay resistance is only partially established by the active capnet attestation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define trusted measurement production and verification.
2. Bind freshness and session identity cryptographically.
3. Add algorithm, certificate, replay, and interoperability tests.
4. Replay every discovered failure against all supported targets.
5. Block production support when the invariant cannot be demonstrated.

### Known issues/TODOS in Freshness policy

Issue: Freshness policy is only partially established by the active capnet attestation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define trusted measurement production and verification.
2. Bind freshness and session identity cryptographically.
3. Add algorithm, certificate, replay, and interoperability tests.
4. Use nonces or trusted monotonic epochs rather than local receipt time alone.

### Known issues/TODOS in Algorithm agility

Issue: Algorithm agility is only partially established by the active capnet attestation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define trusted measurement production and verification.
2. Bind freshness and session identity cryptographically.
3. Add algorithm, certificate, replay, and interoperability tests.

### Known issues/TODOS in Reserved Ed25519 path

Issue: Reserved Ed25519 path is only partially established by the active capnet attestation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define trusted measurement production and verification.
2. Bind freshness and session identity cryptographically.
3. Add algorithm, certificate, replay, and interoperability tests.

### Known issues/TODOS in Offline certificate role

Issue: Offline certificate role is only partially established by the active capnet attestation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define trusted measurement production and verification.
2. Bind freshness and session identity cryptographically.
3. Add algorithm, certificate, replay, and interoperability tests.
4. Keep minimized failures in the permanent regression corpus.
5. Require this property to pass before enabling the affected feature.

### Known issues/TODOS in Certificate generation trust

Issue: Certificate generation trust is only partially established by the active capnet attestation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define trusted measurement production and verification.
2. Bind freshness and session identity cryptographically.
3. Add algorithm, certificate, replay, and interoperability tests.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in Token revocation processing

Issue: Token revocation processing is only partially established by the active capnet revocation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define durable retention and replacement policy.
2. Apply revocation before any token use or restoration.
3. Test descendants, duplicates, restart, suppression, and epoch exhaustion.
4. Add runtime evidence that distinguishes unsupported state from transient failure.

### Known issues/TODOS in Revocation epoch allocation

Issue: Revocation epoch allocation is only partially established by the active capnet revocation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define durable retention and replacement policy.
2. Apply revocation before any token use or restoration.
3. Test descendants, duplicates, restart, suppression, and epoch exhaustion.
4. Gate production enablement on the target-specific verification results.

### Known issues/TODOS in Tombstone capacity

Issue: Tombstone capacity is only partially established by the active capnet revocation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define durable retention and replacement policy.
2. Apply revocation before any token use or restoration.
3. Test descendants, duplicates, restart, suppression, and epoch exhaustion.
4. Fail closed or expand durable lookup when all in-memory revocation slots remain security-relevant.

### Known issues/TODOS in Tombstone replacement policy

Issue: CapNet evicts the oldest tombstone even when the revoked token may remain valid.

Required fixes:

1. Never evict an unexpired security tombstone merely to admit a newer one.
2. Compact only with proof that the token and all descendants can no longer authorize access.
3. Test capacity exhaustion, long-lived tokens, descendant revocation, lease state, and restart.

### Known issues/TODOS in Parent and descendant revocation

Issue: Parent and descendant revocation is only partially established by the active capnet revocation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define durable retention and replacement policy.
2. Apply revocation before any token use or restoration.
3. Test descendants, duplicates, restart, suppression, and epoch exhaustion.
4. Add runtime evidence that distinguishes unsupported state from transient failure.

### Known issues/TODOS in Remote lease revocation

Issue: Remote lease revocation is only partially established by the active capnet revocation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define durable retention and replacement policy.
2. Apply revocation before any token use or restoration.
3. Test descendants, duplicates, restart, suppression, and epoch exhaustion.
4. Add runtime evidence that distinguishes unsupported state from transient failure.

### Known issues/TODOS in Revocation precedence

Issue: Revocation precedence is only partially established by the active capnet revocation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define durable retention and replacement policy.
2. Apply revocation before any token use or restoration.
3. Test descendants, duplicates, restart, suppression, and epoch exhaustion.
4. Add runtime evidence that distinguishes unsupported state from transient failure.

### Known issues/TODOS in Revocation control-frame authentication

Issue: Revocation control-frame authentication is only partially established by the active capnet revocation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define durable retention and replacement policy.
2. Apply revocation before any token use or restoration.
3. Test descendants, duplicates, restart, suppression, and epoch exhaustion.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in Persistent revocation journal

Issue: Revocation reports success even when durable journal append fails, and journal records lack authenticated continuity.

Required fixes:

1. Return or retain a pending-durability state when append fails.
2. Authenticate journal records and ordering under a narrowly scoped CapNet persistence authority.
3. Test append failure, torn records, rollback, reordering, duplication, compaction, and audit loss.
4. Document the supported boundary and reject operation outside it.

### Known issues/TODOS in Journal reconstruction

Issue: Journal reconstruction is only partially established by the active capnet revocation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define durable retention and replacement policy.
2. Apply revocation before any token use or restoration. Test descendants, duplicates, restart, suppression, and epoch exhaustion.

### Known issues/TODOS in Duplicate revocation

Issue: Duplicate revocation is only partially established by the active capnet revocation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define durable retention and replacement policy.
2. Apply revocation before any token use or restoration.
3. Test descendants, duplicates, restart, suppression, and epoch exhaustion.
4. Gate production enablement on the target-specific verification results.

### Known issues/TODOS in Revocation after restart

Issue: Bounded and lossy journal reconstruction can forget revoked tokens without entering a fail-closed state.

Required fixes:

1. Rebuild from a complete authenticated checkpoint and journal sequence.
2. Fail closed when records are missing, corrupt, truncated, or exceed tombstone capacity.
3. Test logs beyond read limits, malformed records, epoch recovery, table overflow, and rollback snapshots.
4. Record enough bounded diagnostics to identify recurrence without exposing sensitive data.

### Known issues/TODOS in Tombstone retention duration

Issue: Tombstone retention duration is only partially established by the active capnet revocation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define durable retention and replacement policy.
2. Apply revocation before any token use or restoration.
3. Test descendants, duplicates, restart, suppression, and epoch exhaustion.
4. Retain denial state through the maximum token and descendant lifetime plus recovery margin.

### Known issues/TODOS in Revocation epoch wraparound

Issue: Revocation epoch wraparound is only partially established by the active capnet revocation audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define durable retention and replacement policy.
2. Apply revocation before any token use or restoration.
3. Test descendants, duplicates, restart, suppression, and epoch exhaustion.
4. Add runtime evidence that distinguishes unsupported state from transient failure.

### Known issues/TODOS in Temporal state schema

Issue: Temporal state schema is only partially established by the active capnet persistence audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate and encrypt persisted authority state.
2. Validate all records before atomic publication.
3. Test rollback, collision, truncation, secret handling, and recovery.
4. Document the supported boundary and reject operation outside it.

### Known issues/TODOS in Peer-session serialization

Issue: Peer-session serialization is only partially established by the active capnet persistence audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate and encrypt persisted authority state.
2. Validate all records before atomic publication.
3. Test rollback, collision, truncation, secret handling, and recovery.
4. Do not persist raw session keys without device sealing and authenticated rollback protection.

### Known issues/TODOS in Session-key persistence

Issue: Session-key persistence is only partially established by the active capnet persistence audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate and encrypt persisted authority state.
2. Validate all records before atomic publication.
3. Test rollback, collision, truncation, secret handling, and recovery.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in Replay-window persistence

Issue: Replay-window persistence is only partially established by the active capnet persistence audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate and encrypt persisted authority state.
2. Validate all records before atomic publication.
3. Test rollback, collision, truncation, secret handling, and recovery.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in Delegation-record serialization

Issue: Delegation-record serialization is only partially established by the active capnet persistence audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate and encrypt persisted authority state.
2. Validate all records before atomic publication.
3. Test rollback, collision, truncation, secret handling, and recovery.
4. Restore parent and descendant records only after validating the complete graph.

### Known issues/TODOS in Revocation-tombstone serialization

Issue: Revocation-tombstone serialization is only partially established by the active capnet persistence audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate and encrypt persisted authority state.
2. Validate all records before atomic publication.
3. Test rollback, collision, truncation, secret handling, and recovery.
4. Define rollback behavior for failure after partial state mutation.

### Known issues/TODOS in Local device identity restoration

Issue: Local device identity restoration is only partially established by the active capnet persistence audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate and encrypt persisted authority state.
2. Validate all records before atomic publication.
3. Test rollback, collision, truncation, secret handling, and recovery.
4. Reject restored identity when it conflicts with device-rooted identity or current boot policy.

### Known issues/TODOS in Revocation epoch restoration

Issue: Revocation epoch restoration is only partially established by the active capnet persistence audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate and encrypt persisted authority state.
2. Validate all records before atomic publication.
3. Test rollback, collision, truncation, secret handling, and recovery.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in Slot-count validation

Issue: Slot-count validation is only partially established by the active capnet persistence audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate and encrypt persisted authority state.
2. Validate all records before atomic publication.
3. Test rollback, collision, truncation, secret handling, and recovery.
4. Validate aggregate decoded size before allocating or iterating any restored table.

### Known issues/TODOS in Trailing-byte rejection

Issue: Trailing-byte rejection is only partially established by the active capnet persistence audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate and encrypt persisted authority state.
2. Validate all records before atomic publication.
3. Test rollback, collision, truncation, secret handling, and recovery.
4. Require exact schema consumption before publishing any restored state.

### Known issues/TODOS in Restore-time semantic validation

Issue: Restore-time semantic validation is only partially established by the active capnet persistence audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate and encrypt persisted authority state.
2. Validate all records before atomic publication.
3. Test rollback, collision, truncation, secret handling, and recovery.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in Restore collision handling

Issue: Restore collision handling is only partially established by the active capnet persistence audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate and encrypt persisted authority state.
2. Validate all records before atomic publication.
3. Test rollback, collision, truncation, secret handling, and recovery.
4. Gate production enablement on the target-specific verification results.
5. Test failure at every record boundary and prove the previous live state remains unchanged.

### Known issues/TODOS in Persistence authority

Issue: Persistence authority is only partially established by the active capnet persistence audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate and encrypt persisted authority state.
2. Validate all records before atomic publication.
3. Test rollback, collision, truncation, secret handling, and recovery.
4. Document the supported boundary and reject operation outside it.

### Known issues/TODOS in Revocation journal consistency

Issue: Revocation journal consistency is only partially established by the active capnet persistence audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate and encrypt persisted authority state.
2. Validate all records before atomic publication.
3. Test rollback, collision, truncation, secret handling, and recovery.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in Secret material at rest

Issue: Secret material at rest is only partially established by the active capnet persistence audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Authenticate and encrypt persisted authority state.
2. Validate all records before atomic publication.
3. Test rollback, collision, truncation, secret handling, and recovery.
4. Keep minimized failures in the permanent regression corpus.
5. Require this property to pass before enabling the affected feature.

### Known issues/TODOS in Security event coverage

Issue: Security event coverage is only partially established by the active capnet audit and metrics audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Record authenticated principals and correlation identifiers.
2. Define counter consistency, loss, and redaction policy.
3. Test concurrent updates, saturation, and audit failure.

### Known issues/TODOS in Event principal attribution

Issue: Event principal attribution is only partially established by the active capnet audit and metrics audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Record authenticated principals and correlation identifiers.
2. Define counter consistency, loss, and redaction policy.
3. Test concurrent updates, saturation, and audit failure.

### Known issues/TODOS in Event context quality

Issue: Event context quality is only partially established by the active capnet audit and metrics audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Record authenticated principals and correlation identifiers.
2. Define counter consistency, loss, and redaction policy.
3. Test concurrent updates, saturation, and audit failure.

### Known issues/TODOS in Token lifecycle correlation

Issue: Token lifecycle correlation is only partially established by the active capnet audit and metrics audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Record authenticated principals and correlation identifiers.
2. Define counter consistency, loss, and redaction policy.
3. Test concurrent updates, saturation, and audit failure.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in Peer-session correlation

Issue: Peer-session correlation is only partially established by the active capnet audit and metrics audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Record authenticated principals and correlation identifiers.
2. Define counter consistency, loss, and redaction policy.
3. Test concurrent updates, saturation, and audit failure.

### Known issues/TODOS in Replay rejection counters

Issue: Replay rejection counters is only partially established by the active capnet audit and metrics audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Record authenticated principals and correlation identifiers.
2. Define counter consistency, loss, and redaction policy.
3. Test concurrent updates, saturation, and audit failure.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in Decode success and failure counters

Issue: Decode success and failure counters is only partially established by the active capnet audit and metrics audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Record authenticated principals and correlation identifiers.
2. Define counter consistency, loss, and redaction policy.
3. Test concurrent updates, saturation, and audit failure.

### Known issues/TODOS in Saturating metric behavior

Issue: Saturating metric behavior is only partially established by the active capnet audit and metrics audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Record authenticated principals and correlation identifiers.
2. Define counter consistency, loss, and redaction policy.
3. Test concurrent updates, saturation, and audit failure.

### Known issues/TODOS in Fuzz failure capture

Issue: Fuzz failure capture is only partially established by the active capnet audit and metrics audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Record authenticated principals and correlation identifiers.
2. Define counter consistency, loss, and redaction policy.
3. Test concurrent updates, saturation, and audit failure.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in Sensitive field redaction

Issue: Sensitive field redaction is only partially established by the active capnet audit and metrics audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Record authenticated principals and correlation identifiers.
2. Define counter consistency, loss, and redaction policy.
3. Test concurrent updates, saturation, and audit failure.

### Known issues/TODOS in Audit loss behavior

Issue: Security evidence and temporal records can be lost without changing operation results or leaving a durable loss marker.

Required fixes:

1. Classify operations as fail closed, pending durability, or best effort.
2. Maintain a durable monotonic audit-loss indicator independent of the failing sink.
3. Inject sink failures across revocation, token transfer, Wi-Fi secrets, and network restore.

### Known issues/TODOS in Concurrent metric consistency

Issue: Concurrent metric consistency is only partially established by the active capnet audit and metrics audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Record authenticated principals and correlation identifiers.
2. Define counter consistency, loss, and redaction policy.
3. Test concurrent updates, saturation, and audit failure.
4. Record enough bounded diagnostics to identify recurrence without exposing sensitive data.

### Known issues/TODOS in Network service errors

Issue: Network service errors is only partially established by the active error taxonomy and mapping audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Create typed errors with retry and recovery classes.
2. Preserve error identity across drivers, protocols, reactor, and services.
3. Add exhaustive conversion and user-visible mapping tests.

### Known issues/TODOS in Driver errors

Issue: Driver errors is only partially established by the active error taxonomy and mapping audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Create typed errors with retry and recovery classes.
2. Preserve error identity across drivers, protocols, reactor, and services.
3. Add exhaustive conversion and user-visible mapping tests.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in Reactor errors

Issue: Reactor errors is only partially established by the active error taxonomy and mapping audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Create typed errors with retry and recovery classes.
2. Preserve error identity across drivers, protocols, reactor, and services.
3. Add exhaustive conversion and user-visible mapping tests.

### Known issues/TODOS in Protocol parsing errors

Issue: Protocol parsing errors is only partially established by the active error taxonomy and mapping audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Create typed errors with retry and recovery classes.
2. Preserve error identity across drivers, protocols, reactor, and services.
3. Add exhaustive conversion and user-visible mapping tests.

### Known issues/TODOS in TCP and DNS string errors

Issue: TCP and DNS string errors is only partially established by the active error taxonomy and mapping audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Create typed errors with retry and recovery classes.
2. Preserve error identity across drivers, protocols, reactor, and services.
3. Add exhaustive conversion and user-visible mapping tests.

### Known issues/TODOS in TLS errors

Issue: TLS errors is only partially established by the active error taxonomy and mapping audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Create typed errors with retry and recovery classes.
2. Preserve error identity across drivers, protocols, reactor, and services.
3. Add exhaustive conversion and user-visible mapping tests.

### Known issues/TODOS in Wi-Fi errors

Issue: Wi-Fi errors is only partially established by the active error taxonomy and mapping audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Create typed errors with retry and recovery classes.
2. Preserve error identity across drivers, protocols, reactor, and services.
3. Add exhaustive conversion and user-visible mapping tests.

### Known issues/TODOS in CapNet errors

Issue: CapNet errors is only partially established by the active error taxonomy and mapping audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Create typed errors with retry and recovery classes.
2. Preserve error identity across drivers, protocols, reactor, and services.
3. Add exhaustive conversion and user-visible mapping tests.

### Known issues/TODOS in Initialization errors

Issue: Initialization errors is only partially established by the active error taxonomy and mapping audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Create typed errors with retry and recovery classes.
2. Preserve error identity across drivers, protocols, reactor, and services.
3. Add exhaustive conversion and user-visible mapping tests.

### Known issues/TODOS in Temporary and terminal failures

Issue: Temporary and terminal failures is only partially established by the active error taxonomy and mapping audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Create typed errors with retry and recovery classes.
2. Preserve error identity across drivers, protocols, reactor, and services.
3. Add exhaustive conversion and user-visible mapping tests.

### Known issues/TODOS in Timeout and cancellation

Issue: Timeout and cancellation is only partially established by the active error taxonomy and mapping audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Create typed errors with retry and recovery classes.
2. Preserve error identity across drivers, protocols, reactor, and services.
3. Add exhaustive conversion and user-visible mapping tests.

### Known issues/TODOS in Error conversion across layers

Issue: Error conversion across layers is only partially established by the active error taxonomy and mapping audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Create typed errors with retry and recovery classes.
2. Preserve error identity across drivers, protocols, reactor, and services.
3. Add exhaustive conversion and user-visible mapping tests.

### Known issues/TODOS in Static string error identity

Issue: Static string error identity is only partially established by the active error taxonomy and mapping audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Create typed errors with retry and recovery classes.
2. Preserve error identity across drivers, protocols, reactor, and services.
3. Add exhaustive conversion and user-visible mapping tests.

### Known issues/TODOS in User-visible error mapping

Issue: User-visible error mapping is only partially established by the active error taxonomy and mapping audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Create typed errors with retry and recovery classes.
2. Preserve error identity across drivers, protocols, reactor, and services.
3. Add exhaustive conversion and user-visible mapping tests.

### Known issues/TODOS in Diagnostic specificity

Issue: Diagnostic specificity is only partially established by the active error taxonomy and mapping audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Create typed errors with retry and recovery classes.
2. Preserve error identity across drivers, protocols, reactor, and services.
3. Add exhaustive conversion and user-visible mapping tests.

### Known issues/TODOS in Global network service lock

Issue: Global network service lock is only partially established by the active concurrency and synchronization audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document ownership, atomic ordering, and lock order.
2. Encapsulate shared mutable and DMA state.
3. Add race, deadlock, interrupt, timeout, and reset tests.

### Known issues/TODOS in Reactor single-owner invariant

Issue: Reactor single-owner invariant is only partially established by the active concurrency and synchronization audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document ownership, atomic ordering, and lock order.
2. Encapsulate shared mutable and DMA state.
3. Add race, deadlock, interrupt, timeout, and reset tests.
4. Replay every discovered failure against all supported targets.
5. Block production support when the invariant cannot be demonstrated.

### Known issues/TODOS in IRQ and task-context interaction

Issue: IRQ and task-context interaction is only partially established by the active concurrency and synchronization audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document ownership, atomic ordering, and lock order.
2. Encapsulate shared mutable and DMA state.
3. Add race, deadlock, interrupt, timeout, and reset tests.

### Known issues/TODOS in Atomic memory ordering

Issue: Atomic memory ordering is only partially established by the active concurrency and synchronization audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document ownership, atomic ordering, and lock order.
2. Encapsulate shared mutable and DMA state.
3. Add race, deadlock, interrupt, timeout, and reset tests.

### Known issues/TODOS in Static mutable packet buffers

Issue: Static mutable packet buffers is only partially established by the active concurrency and synchronization audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document ownership, atomic ordering, and lock order.
2. Encapsulate shared mutable and DMA state.
3. Add race, deadlock, interrupt, timeout, and reset tests.

### Known issues/TODOS in Driver global state

Issue: Driver global state is only partially established by the active concurrency and synchronization audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document ownership, atomic ordering, and lock order.
2. Encapsulate shared mutable and DMA state.
3. Add race, deadlock, interrupt, timeout, and reset tests.
4. Document the supported boundary and reject operation outside it.

### Known issues/TODOS in DMA and CPU ownership transitions

Issue: DMA and CPU ownership transitions is only partially established by the active concurrency and synchronization audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document ownership, atomic ordering, and lock order.
2. Encapsulate shared mutable and DMA state.
3. Add race, deadlock, interrupt, timeout, and reset tests.
4. Define rollback behavior for failure after partial state mutation.

### Known issues/TODOS in Nested lock ordering

Issue: Nested lock ordering is only partially established by the active concurrency and synchronization audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document ownership, atomic ordering, and lock order.
2. Encapsulate shared mutable and DMA state.
3. Add race, deadlock, interrupt, timeout, and reset tests.

### Known issues/TODOS in CapNet peer and journal locks

Issue: CapNet peer and journal locks is only partially established by the active concurrency and synchronization audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document ownership, atomic ordering, and lock order.
2. Encapsulate shared mutable and DMA state.
3. Add race, deadlock, interrupt, timeout, and reset tests.

### Known issues/TODOS in Temporal recording under locks

Issue: Temporal recording under locks is only partially established by the active concurrency and synchronization audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document ownership, atomic ordering, and lock order.
2. Encapsulate shared mutable and DMA state.
3. Add race, deadlock, interrupt, timeout, and reset tests.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in Reentrancy

Issue: Reentrancy is only partially established by the active concurrency and synchronization audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document ownership, atomic ordering, and lock order.
2. Encapsulate shared mutable and DMA state.
3. Add race, deadlock, interrupt, timeout, and reset tests.

### Known issues/TODOS in Interrupt-disable critical sections

Issue: Interrupt-disable critical sections is only partially established by the active concurrency and synchronization audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document ownership, atomic ordering, and lock order.
2. Encapsulate shared mutable and DMA state.
3. Add race, deadlock, interrupt, timeout, and reset tests.

### Known issues/TODOS in Deadlock resistance

Issue: Deadlock resistance is only partially established by the active concurrency and synchronization audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document ownership, atomic ordering, and lock order.
2. Encapsulate shared mutable and DMA state.
3. Add race, deadlock, interrupt, timeout, and reset tests.
4. Keep minimized failures in the permanent regression corpus.
5. Require this property to pass before enabling the affected feature.

### Known issues/TODOS in Data-race resistance

Issue: Data-race resistance is only partially established by the active concurrency and synchronization audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Document ownership, atomic ordering, and lock order.
2. Encapsulate shared mutable and DMA state.
3. Add race, deadlock, interrupt, timeout, and reset tests.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in Packet length validation

Issue: Packet length validation is only partially established by the active memory safety audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State and enforce every unsafe boundary invariant.
2. Use checked arithmetic, bounded parsers, and DMA-safe memory.
3. Add sanitizer-equivalent, fuzz, fault, and stack-usage tests where supported.

### Known issues/TODOS in Header offset arithmetic

Issue: Header offset arithmetic is only partially established by the active memory safety audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State and enforce every unsafe boundary invariant.
2. Use checked arithmetic, bounded parsers, and DMA-safe memory.
3. Add sanitizer-equivalent, fuzz, fault, and stack-usage tests where supported.

### Known issues/TODOS in Fixed-array bounds

Issue: Fixed-array bounds is only partially established by the active memory safety audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State and enforce every unsafe boundary invariant.
2. Use checked arithmetic, bounded parsers, and DMA-safe memory.
3. Add sanitizer-equivalent, fuzz, fault, and stack-usage tests where supported.

### Known issues/TODOS in Receive-buffer bounds

Issue: Receive-buffer bounds is only partially established by the active memory safety audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State and enforce every unsafe boundary invariant.
2. Use checked arithmetic, bounded parsers, and DMA-safe memory.
3. Add sanitizer-equivalent, fuzz, fault, and stack-usage tests where supported.

### Known issues/TODOS in Transmit-buffer bounds

Issue: Transmit-buffer bounds is only partially established by the active memory safety audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State and enforce every unsafe boundary invariant.
2. Use checked arithmetic, bounded parsers, and DMA-safe memory.
3. Add sanitizer-equivalent, fuzz, fault, and stack-usage tests where supported.

### Known issues/TODOS in Ring index arithmetic

Issue: Ring index arithmetic is only partially established by the active memory safety audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State and enforce every unsafe boundary invariant.
2. Use checked arithmetic, bounded parsers, and DMA-safe memory.
3. Add sanitizer-equivalent, fuzz, fault, and stack-usage tests where supported.

### Known issues/TODOS in Descriptor index validation

Issue: Descriptor index validation is only partially established by the active memory safety audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State and enforce every unsafe boundary invariant.
2. Use checked arithmetic, bounded parsers, and DMA-safe memory.
3. Add sanitizer-equivalent, fuzz, fault, and stack-usage tests where supported.

### Known issues/TODOS in DMA buffer lifetime

Issue: DMA buffer lifetime is only partially established by the active memory safety audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State and enforce every unsafe boundary invariant.
2. Use checked arithmetic, bounded parsers, and DMA-safe memory.
3. Add sanitizer-equivalent, fuzz, fault, and stack-usage tests where supported.
4. Gate production enablement on the target-specific verification results.

### Known issues/TODOS in MMIO pointer validity

Issue: MMIO pointer validity is only partially established by the active memory safety audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State and enforce every unsafe boundary invariant.
2. Use checked arithmetic, bounded parsers, and DMA-safe memory.
3. Add sanitizer-equivalent, fuzz, fault, and stack-usage tests where supported.
4. Record enough bounded diagnostics to identify recurrence without exposing sensitive data.

### Known issues/TODOS in Volatile access correctness

Issue: Volatile access correctness is only partially established by the active memory safety audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State and enforce every unsafe boundary invariant.
2. Use checked arithmetic, bounded parsers, and DMA-safe memory.
3. Add sanitizer-equivalent, fuzz, fault, and stack-usage tests where supported.

### Known issues/TODOS in Shared static mutable aliases

Issue: Shared static mutable aliases is only partially established by the active memory safety audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State and enforce every unsafe boundary invariant.
2. Use checked arithmetic, bounded parsers, and DMA-safe memory.
3. Add sanitizer-equivalent, fuzz, fault, and stack-usage tests where supported.

### Known issues/TODOS in Unsafe synchronization assumptions

Issue: Unsafe synchronization assumptions is only partially established by the active memory safety audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State and enforce every unsafe boundary invariant.
2. Use checked arithmetic, bounded parsers, and DMA-safe memory.
3. Add sanitizer-equivalent, fuzz, fault, and stack-usage tests where supported.
4. Document the supported boundary and reject operation outside it.

### Known issues/TODOS in Integer conversion and truncation

Issue: Integer conversion and truncation is only partially established by the active memory safety audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State and enforce every unsafe boundary invariant.
2. Use checked arithmetic, bounded parsers, and DMA-safe memory.
3. Add sanitizer-equivalent, fuzz, fault, and stack-usage tests where supported.

### Known issues/TODOS in Sequence-number wraparound

Issue: Sequence-number wraparound is only partially established by the active memory safety audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State and enforce every unsafe boundary invariant.
2. Use checked arithmetic, bounded parsers, and DMA-safe memory.
3. Add sanitizer-equivalent, fuzz, fault, and stack-usage tests where supported.

### Known issues/TODOS in Parser panic resistance

Issue: Parser panic resistance is only partially established by the active memory safety audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State and enforce every unsafe boundary invariant.
2. Use checked arithmetic, bounded parsers, and DMA-safe memory.
3. Add sanitizer-equivalent, fuzz, fault, and stack-usage tests where supported.

### Known issues/TODOS in Secret zeroization

Issue: Secret zeroization is only partially established by the active memory safety audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State and enforce every unsafe boundary invariant.
2. Use checked arithmetic, bounded parsers, and DMA-safe memory.
3. Add sanitizer-equivalent, fuzz, fault, and stack-usage tests where supported.
4. Keep minimized failures in the permanent regression corpus.
5. Require this property to pass before enabling the affected feature.

### Known issues/TODOS in Uninitialized memory exposure

Issue: Uninitialized memory exposure is only partially established by the active memory safety audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State and enforce every unsafe boundary invariant.
2. Use checked arithmetic, bounded parsers, and DMA-safe memory.
3. Add sanitizer-equivalent, fuzz, fault, and stack-usage tests where supported.

### Known issues/TODOS in Stack usage

Issue: Stack usage is only partially established by the active memory safety audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State and enforce every unsafe boundary invariant.
2. Use checked arithmetic, bounded parsers, and DMA-safe memory.
3. Add sanitizer-equivalent, fuzz, fault, and stack-usage tests where supported.

### Known issues/TODOS in Heap allocation failure

Issue: Heap allocation failure is only partially established by the active memory safety audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State and enforce every unsafe boundary invariant.
2. Use checked arithmetic, bounded parsers, and DMA-safe memory. Add sanitizer-equivalent, fuzz, fault, and stack-usage tests where supported.

### Known issues/TODOS in Maximum network connections

Issue: Maximum network connections is only partially established by the active resource and capacity audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Publish one aggregate capacity and memory contract.
2. Return typed exhaustion without corrupting existing state.
3. Test exact limits, overflow, sustained pressure, and recovery.

### Known issues/TODOS in TCP connection capacity

Issue: TCP connection capacity is only partially established by the active resource and capacity audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Publish one aggregate capacity and memory contract.
2. Return typed exhaustion without corrupting existing state.
3. Test exact limits, overflow, sustained pressure, and recovery.

### Known issues/TODOS in TCP listener capacity

Issue: TCP listener capacity is only partially established by the active resource and capacity audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Publish one aggregate capacity and memory contract.
2. Return typed exhaustion without corrupting existing state.
3. Test exact limits, overflow, sustained pressure, and recovery.

### Known issues/TODOS in Accept backlog capacity

Issue: Accept backlog capacity is only partially established by the active resource and capacity audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Publish one aggregate capacity and memory contract.
2. Return typed exhaustion without corrupting existing state.
3. Test exact limits, overflow, sustained pressure, and recovery.

### Known issues/TODOS in DNS cache capacity

Issue: DNS cache capacity is only partially established by the active resource and capacity audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Publish one aggregate capacity and memory contract.
2. Return typed exhaustion without corrupting existing state.
3. Test exact limits, overflow, sustained pressure, and recovery.

### Known issues/TODOS in UDP receive capacity

Issue: UDP receive capacity is only partially established by the active resource and capacity audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Publish one aggregate capacity and memory contract.
2. Return typed exhaustion without corrupting existing state.
3. Test exact limits, overflow, sustained pressure, and recovery.

### Known issues/TODOS in ARP cache capacity

Issue: ARP cache capacity is only partially established by the active resource and capacity audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Publish one aggregate capacity and memory contract.
2. Return typed exhaustion without corrupting existing state.
3. Test exact limits, overflow, sustained pressure, and recovery.

### Known issues/TODOS in HTTP buffer capacity

Issue: HTTP buffer capacity is only partially established by the active resource and capacity audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Publish one aggregate capacity and memory contract.
2. Return typed exhaustion without corrupting existing state.
3. Test exact limits, overflow, sustained pressure, and recovery.

### Known issues/TODOS in TLS session capacity

Issue: TLS session capacity is only partially established by the active resource and capacity audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Publish one aggregate capacity and memory contract.
2. Return typed exhaustion without corrupting existing state.
3. Test exact limits, overflow, sustained pressure, and recovery.

### Known issues/TODOS in Wi-Fi scan capacity

Issue: Wi-Fi scan capacity is only partially established by the active resource and capacity audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Publish one aggregate capacity and memory contract.
2. Return typed exhaustion without corrupting existing state.
3. Test exact limits, overflow, sustained pressure, and recovery.

### Known issues/TODOS in Driver ring capacity

Issue: Driver ring capacity is only partially established by the active resource and capacity audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Publish one aggregate capacity and memory contract.
2. Return typed exhaustion without corrupting existing state.
3. Test exact limits, overflow, sustained pressure, and recovery.
4. Document the supported boundary and reject operation outside it.

### Known issues/TODOS in Reactor request capacity

Issue: Reactor request capacity is only partially established by the active resource and capacity audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Publish one aggregate capacity and memory contract.
2. Return typed exhaustion without corrupting existing state.
3. Test exact limits, overflow, sustained pressure, and recovery.

### Known issues/TODOS in CapNet peer capacity

Issue: CapNet peer capacity is only partially established by the active resource and capacity audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Publish one aggregate capacity and memory contract.
2. Return typed exhaustion without corrupting existing state.
3. Test exact limits, overflow, sustained pressure, and recovery.

### Known issues/TODOS in CapNet delegation capacity

Issue: CapNet delegation capacity is only partially established by the active resource and capacity audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Publish one aggregate capacity and memory contract.
2. Return typed exhaustion without corrupting existing state.
3. Test exact limits, overflow, sustained pressure, and recovery.

### Known issues/TODOS in CapNet revocation capacity

Issue: CapNet revocation capacity is only partially established by the active resource and capacity audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Publish one aggregate capacity and memory contract.
2. Return typed exhaustion without corrupting existing state.
3. Test exact limits, overflow, sustained pressure, and recovery.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in CapNet incoming queue capacity

Issue: CapNet incoming queue capacity is only partially established by the active resource and capacity audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Publish one aggregate capacity and memory contract.
2. Return typed exhaustion without corrupting existing state.
3. Test exact limits, overflow, sustained pressure, and recovery.

### Known issues/TODOS in CapNet retransmission capacity

Issue: CapNet retransmission capacity is only partially established by the active resource and capacity audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Publish one aggregate capacity and memory contract.
2. Return typed exhaustion without corrupting existing state.
3. Test exact limits, overflow, sustained pressure, and recovery.

### Known issues/TODOS in Aggregate network memory bound

Issue: Aggregate network memory bound is only partially established by the active resource and capacity audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Publish one aggregate capacity and memory contract.
2. Return typed exhaustion without corrupting existing state.
3. Test exact limits, overflow, sustained pressure, and recovery.

### Known issues/TODOS in Exhaustion behavior

Issue: Exhaustion behavior is only partially established by the active resource and capacity audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Publish one aggregate capacity and memory contract.
2. Return typed exhaustion without corrupting existing state.
3. Test exact limits, overflow, sustained pressure, and recovery.
4. Document the supported boundary and reject operation outside it.

### Known issues/TODOS in Network configuration snapshots

Issue: Network configuration snapshots is only partially established by the active temporal and recovery audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use authenticated generation-bearing restore transactions.
2. Reconcile hardware, time, identity, capability, and protocol state before publication.
3. Test partial failure, rollback, collision, reset, and replay suppression.

### Known issues/TODOS in Legacy network service snapshots

Issue: Legacy network service snapshots is only partially established by the active temporal and recovery audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use authenticated generation-bearing restore transactions.
2. Reconcile hardware, time, identity, capability, and protocol state before publication.
3. Test partial failure, rollback, collision, reset, and replay suppression.

### Known issues/TODOS in TCP listener restoration

Issue: TCP listener restoration is only partially established by the active temporal and recovery audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use authenticated generation-bearing restore transactions.
2. Reconcile hardware, time, identity, capability, and protocol state before publication.
3. Test partial failure, rollback, collision, reset, and replay suppression.

### Known issues/TODOS in TCP connection restoration

Issue: TCP connection restoration is only partially established by the active temporal and recovery audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use authenticated generation-bearing restore transactions.
2. Reconcile hardware, time, identity, capability, and protocol state before publication.
3. Test partial failure, rollback, collision, reset, and replay suppression.

### Known issues/TODOS in DNS cache restoration

Issue: DNS cache restoration is only partially established by the active temporal and recovery audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use authenticated generation-bearing restore transactions.
2. Reconcile hardware, time, identity, capability, and protocol state before publication.
3. Test partial failure, rollback, collision, reset, and replay suppression.

### Known issues/TODOS in Wi-Fi state restoration

Issue: Wi-Fi state restoration is only partially established by the active temporal and recovery audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use authenticated generation-bearing restore transactions.
2. Reconcile hardware, time, identity, capability, and protocol state before publication.
3. Test partial failure, rollback, collision, reset, and replay suppression.

### Known issues/TODOS in Live Wi-Fi reconnect requirements

Issue: Live Wi-Fi reconnect requirements is only partially established by the active temporal and recovery audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use authenticated generation-bearing restore transactions.
2. Reconcile hardware, time, identity, capability, and protocol state before publication.
3. Test partial failure, rollback, collision, reset, and replay suppression.

### Known issues/TODOS in TLS state persistence policy

Issue: TLS state persistence policy is only partially established by the active temporal and recovery audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use authenticated generation-bearing restore transactions.
2. Reconcile hardware, time, identity, capability, and protocol state before publication.
3. Test partial failure, rollback, collision, reset, and replay suppression.
4. Record enough bounded diagnostics to identify recurrence without exposing sensitive data.

### Known issues/TODOS in Driver state restoration policy

Issue: Driver state restoration policy is only partially established by the active temporal and recovery audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use authenticated generation-bearing restore transactions.
2. Reconcile hardware, time, identity, capability, and protocol state before publication.
3. Test partial failure, rollback, collision, reset, and replay suppression.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in CapNet state restoration

Issue: CapNet state restoration is only partially established by the active temporal and recovery audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use authenticated generation-bearing restore transactions.
2. Reconcile hardware, time, identity, capability, and protocol state before publication.
3. Test partial failure, rollback, collision, reset, and replay suppression.

### Known issues/TODOS in Replay-time network I/O suppression

Issue: Replay-time network I/O suppression is only partially established by the active temporal and recovery audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use authenticated generation-bearing restore transactions.
2. Reconcile hardware, time, identity, capability, and protocol state before publication.
3. Test partial failure, rollback, collision, reset, and replay suppression.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in Hardware reconciliation

Issue: Hardware reconciliation is only partially established by the active temporal and recovery audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use authenticated generation-bearing restore transactions.
2. Reconcile hardware, time, identity, capability, and protocol state before publication.
3. Test partial failure, rollback, collision, reset, and replay suppression.

### Known issues/TODOS in Restored identifier collisions

Issue: Restored identifier collisions is only partially established by the active temporal and recovery audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use authenticated generation-bearing restore transactions.
2. Reconcile hardware, time, identity, capability, and protocol state before publication.
3. Test partial failure, rollback, collision, reset, and replay suppression.
4. Add runtime evidence that distinguishes unsupported state from transient failure.

### Known issues/TODOS in Restore failure rollback

Issue: Restore failure rollback is only partially established by the active temporal and recovery audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use authenticated generation-bearing restore transactions.
2. Reconcile hardware, time, identity, capability, and protocol state before publication.
3. Test partial failure, rollback, collision, reset, and replay suppression.
4. Add runtime evidence that distinguishes unsupported state from transient failure.

### Known issues/TODOS in Recovery after device reset

Issue: Recovery after device reset is only partially established by the active temporal and recovery audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use authenticated generation-bearing restore transactions.
2. Reconcile hardware, time, identity, capability, and protocol state before publication.
3. Test partial failure, rollback, collision, reset, and replay suppression.
4. Define rollback behavior for failure after partial state mutation.

### Known issues/TODOS in Link status reporting

Issue: Link status reporting is only partially established by the active diagnostics and observability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define stable metrics with identity, generation, and observation time.
2. Redact sensitive packet, address, key, and capability data. Test counter consistency, loss behavior, and concurrent sampling.

### Known issues/TODOS in Interface identity reporting

Issue: Interface identity reporting is only partially established by the active diagnostics and observability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define stable metrics with identity, generation, and observation time.
2. Redact sensitive packet, address, key, and capability data. Test counter consistency, loss behavior, and concurrent sampling.

### Known issues/TODOS in Packet transmit and receive counters

Issue: Packet transmit and receive counters is only partially established by the active diagnostics and observability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define stable metrics with identity, generation, and observation time.
2. Redact sensitive packet, address, key, and capability data.
3. Test counter consistency, loss behavior, and concurrent sampling.

### Known issues/TODOS in Packet drop counters

Issue: Packet rejection and queue loss are mostly invisible because nested errors are discarded.

Required fixes:

1. Add saturating reason counters at driver, Ethernet, IP, transport, and service boundaries.
2. Propagate structured dispatch results to the reactor.
3. Test counter accuracy under malformed traffic, saturation, and concurrent sampling.

### Known issues/TODOS in Driver error counters

Issue: Driver faults collapse into incompatible Boolean, zero, generic error, or ignored outcomes without persistent accounting.

Required fixes:

1. Define common diagnostic reasons while retaining backend-specific detail.
2. Bind counters to interface identity, generation, and observation time.
3. Fault-inject timeout, descriptor, MMIO, DMA, overflow, link, and reset failures.
4. Gate production enablement on the target-specific verification results.

### Known issues/TODOS in Queue occupancy

Issue: Queue occupancy is only partially established by the active diagnostics and observability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define stable metrics with identity, generation, and observation time.
2. Redact sensitive packet, address, key, and capability data.
3. Test counter consistency, loss behavior, and concurrent sampling.

### Known issues/TODOS in TCP connection statistics

Issue: TCP connection statistics is only partially established by the active diagnostics and observability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define stable metrics with identity, generation, and observation time.
2. Redact sensitive packet, address, key, and capability data. Test counter consistency, loss behavior, and concurrent sampling.

### Known issues/TODOS in DNS cache statistics

Issue: DNS cache statistics is only partially established by the active diagnostics and observability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define stable metrics with identity, generation, and observation time.
2. Redact sensitive packet, address, key, and capability data. Test counter consistency, loss behavior, and concurrent sampling.

### Known issues/TODOS in Reactor request statistics

Issue: Reactor request statistics is only partially established by the active diagnostics and observability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define stable metrics with identity, generation, and observation time.
2. Redact sensitive packet, address, key, and capability data. Test counter consistency, loss behavior, and concurrent sampling.

### Known issues/TODOS in Interrupt and polling statistics

Issue: Interrupt and polling statistics is only partially established by the active diagnostics and observability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define stable metrics with identity, generation, and observation time.
2. Redact sensitive packet, address, key, and capability data. Test counter consistency, loss behavior, and concurrent sampling.

### Known issues/TODOS in Retransmission statistics

Issue: Retransmission statistics is only partially established by the active diagnostics and observability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define stable metrics with identity, generation, and observation time.
2. Redact sensitive packet, address, key, and capability data. Test counter consistency, loss behavior, and concurrent sampling.

### Known issues/TODOS in Wi-Fi state diagnostics

Issue: Wi-Fi state diagnostics is only partially established by the active diagnostics and observability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define stable metrics with identity, generation, and observation time.
2. Redact sensitive packet, address, key, and capability data.
3. Test counter consistency, loss behavior, and concurrent sampling.

### Known issues/TODOS in TLS session diagnostics

Issue: TLS session diagnostics is only partially established by the active diagnostics and observability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define stable metrics with identity, generation, and observation time.
2. Redact sensitive packet, address, key, and capability data.
3. Test counter consistency, loss behavior, and concurrent sampling.

### Known issues/TODOS in CapNet peer snapshots

Issue: CapNet peer snapshots is only partially established by the active diagnostics and observability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define stable metrics with identity, generation, and observation time.
2. Redact sensitive packet, address, key, and capability data.
3. Test counter consistency, loss behavior, and concurrent sampling.

### Known issues/TODOS in CapNet journal statistics

Issue: CapNet journal statistics is only partially established by the active diagnostics and observability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define stable metrics with identity, generation, and observation time.
2. Redact sensitive packet, address, key, and capability data. Test counter consistency, loss behavior, and concurrent sampling.

### Known issues/TODOS in Sensitive network logging

Issue: Sensitive network logging is only partially established by the active diagnostics and observability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define stable metrics with identity, generation, and observation time.
2. Redact sensitive packet, address, key, and capability data.
3. Test counter consistency, loss behavior, and concurrent sampling.

### Known issues/TODOS in Diagnostic consistency under concurrency

Issue: Diagnostic consistency under concurrency is only partially established by the active diagnostics and observability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Define stable metrics with identity, generation, and observation time.
2. Redact sensitive packet, address, key, and capability data.
3. Test counter consistency, loss behavior, and concurrent sampling.
4. Add runtime evidence that distinguishes unsupported state from transient failure.

### Known issues/TODOS in Malformed Ethernet frames

Issue: Malformed Ethernet frames is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.

### Known issues/TODOS in ARP poisoning

Issue: ARP poisoning is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in ICMP amplification

Issue: ICMP amplification is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.

### Known issues/TODOS in UDP flooding

Issue: UDP flooding is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.

### Known issues/TODOS in DNS spoofing and cache poisoning

Issue: DNS spoofing and cache poisoning is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in TCP SYN flooding

Issue: TCP SYN flooding is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.

### Known issues/TODOS in TCP state exhaustion

Issue: TCP state exhaustion is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.
4. Define rollback behavior for failure after partial state mutation.

### Known issues/TODOS in Sequence-number attacks

Issue: Sequence-number attacks is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.
4. Replay every discovered failure against all supported targets.
5. Block production support when the invariant cannot be demonstrated.

### Known issues/TODOS in Fragmentation attacks

Issue: Fragmentation attacks is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.
4. Replay every discovered failure against all supported targets.
5. Block production support when the invariant cannot be demonstrated.

### Known issues/TODOS in HTTP response smuggling

Issue: HTTP response smuggling is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.

### Known issues/TODOS in TLS downgrade and certificate attacks

Issue: TLS downgrade and certificate attacks is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in Wi-Fi management-frame spoofing

Issue: Wi-Fi management-frame spoofing is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.
4. Replay every discovered failure against all supported targets.
5. Block production support when the invariant cannot be demonstrated.

### Known issues/TODOS in WPA2 replay and key attacks

Issue: WPA2 replay and key attacks is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.
4. Replay every discovered failure against all supported targets.
5. Block production support when the invariant cannot be demonstrated.

### Known issues/TODOS in Driver MMIO and DMA corruption

Issue: Driver MMIO and DMA corruption is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.
4. Define rollback behavior for failure after partial state mutation.

### Known issues/TODOS in Interrupt flooding

Issue: Interrupt flooding is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.

### Known issues/TODOS in Network capability forgery

Issue: Network capability forgery is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.
4. Replay every discovered failure against all supported targets.
5. Block production support when the invariant cannot be demonstrated.

### Known issues/TODOS in CapNet token forgery

Issue: CapNet token forgery is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.
4. Replay every discovered failure against all supported targets.
5. Block production support when the invariant cannot be demonstrated.

### Known issues/TODOS in CapNet token replay

Issue: CapNet token replay is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in CapNet delegation escalation

Issue: CapNet delegation escalation is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.

### Known issues/TODOS in CapNet peer impersonation

Issue: CapNet peer impersonation is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.

### Known issues/TODOS in CapNet revocation suppression

Issue: CapNet revocation suppression is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.
4. Define rollback behavior for failure after partial state mutation.

### Known issues/TODOS in CapNet persistence rollback

Issue: CapNet persistence rollback is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.
4. Add runtime evidence that distinguishes unsupported state from transient failure.

### Known issues/TODOS in Resource-exhaustion attacks

Issue: Resource-exhaustion attacks is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.
4. Keep minimized failures in the permanent regression corpus.
5. Require this property to pass before enabling the affected feature.

### Known issues/TODOS in Timing and traffic-analysis leakage

Issue: Timing and traffic-analysis leakage is only partially established by the active attack surface audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Apply validation, authority, rate, and resource controls at admission.
2. Record security outcomes without exposing sensitive state.
3. Add adversarial and denial-of-service regression tests.

### Known issues/TODOS in Network structure layout

Issue: Network structure layout is only partially established by the active abi and portability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use explicit fixed-width wire and persistence layouts.
2. Define DMA, alignment, byte-order, and memory-order contracts per target. Run identical protocol and driver suites on supported architectures.

### Known issues/TODOS in Byte-order assumptions

Issue: Byte-order assumptions is only partially established by the active abi and portability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use explicit fixed-width wire and persistence layouts.
2. Define DMA, alignment, byte-order, and memory-order contracts per target. Run identical protocol and driver suites on supported architectures.

### Known issues/TODOS in Alignment assumptions

Issue: Alignment assumptions is only partially established by the active abi and portability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use explicit fixed-width wire and persistence layouts.
2. Define DMA, alignment, byte-order, and memory-order contracts per target. Run identical protocol and driver suites on supported architectures.

### Known issues/TODOS in Native-size integer fields

Issue: Native-size integer fields is only partially established by the active abi and portability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use explicit fixed-width wire and persistence layouts.
2. Define DMA, alignment, byte-order, and memory-order contracts per target.
3. Run identical protocol and driver suites on supported architectures.

### Known issues/TODOS in Thirty-two-bit target behavior

Issue: Thirty-two-bit target behavior is only partially established by the active abi and portability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use explicit fixed-width wire and persistence layouts.
2. Define DMA, alignment, byte-order, and memory-order contracts per target.
3. Run identical protocol and driver suites on supported architectures.

### Known issues/TODOS in x86 port I/O paths

Issue: x86 port I/O paths is only partially established by the active abi and portability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use explicit fixed-width wire and persistence layouts.
2. Define DMA, alignment, byte-order, and memory-order contracts per target.
3. Run identical protocol and driver suites on supported architectures.

### Known issues/TODOS in x86-64 MMIO paths

Issue: x86-64 MMIO paths is only partially established by the active abi and portability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use explicit fixed-width wire and persistence layouts.
2. Define DMA, alignment, byte-order, and memory-order contracts per target.
3. Run identical protocol and driver suites on supported architectures.
4. Record enough bounded diagnostics to identify recurrence without exposing sensitive data.

### Known issues/TODOS in AArch64 MMIO paths

Issue: AArch64 MMIO paths is only partially established by the active abi and portability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use explicit fixed-width wire and persistence layouts.
2. Define DMA, alignment, byte-order, and memory-order contracts per target.
3. Run identical protocol and driver suites on supported architectures.
4. Gate production enablement on the target-specific verification results.

### Known issues/TODOS in Weak memory-ordering behavior

Issue: Weak memory-ordering behavior is only partially established by the active abi and portability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use explicit fixed-width wire and persistence layouts.
2. Define DMA, alignment, byte-order, and memory-order contracts per target.
3. Run identical protocol and driver suites on supported architectures.

### Known issues/TODOS in Driver portability

Issue: Driver portability is only partially established by the active abi and portability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use explicit fixed-width wire and persistence layouts.
2. Define DMA, alignment, byte-order, and memory-order contracts per target.
3. Run identical protocol and driver suites on supported architectures.
4. Expose a typed failure when the required guarantee cannot be established.

### Known issues/TODOS in CapNet wire stability

Issue: CapNet wire stability is only partially established by the active abi and portability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use explicit fixed-width wire and persistence layouts.
2. Define DMA, alignment, byte-order, and memory-order contracts per target.
3. Run identical protocol and driver suites on supported architectures.

### Known issues/TODOS in Temporal schema stability

Issue: Temporal schema stability is only partially established by the active abi and portability audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Use explicit fixed-width wire and persistence layouts.
2. Define DMA, alignment, byte-order, and memory-order contracts per target.
3. Run identical protocol and driver suites on supported architectures.
4. Define rollback behavior for failure after partial state mutation.

### Known issues/TODOS in HTTP URL parsing tests

Issue: HTTP URL parsing tests is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths. Run target and QEMU integration tests in continuous verification.

### Known issues/TODOS in HTTP request encoding tests

Issue: HTTP request encoding tests is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths. Run target and QEMU integration tests in continuous verification.

### Known issues/TODOS in Chunked-transfer detection tests

Issue: Chunked-transfer detection tests is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths. Run target and QEMU integration tests in continuous verification.

### Known issues/TODOS in UDP queue tests

Issue: UDP queue tests is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths.
3. Run target and QEMU integration tests in continuous verification.

### Known issues/TODOS in DNS transaction tests

Issue: DNS transaction tests is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths.
3. Run target and QEMU integration tests in continuous verification.

### Known issues/TODOS in DNS stale-response tests

Issue: DNS stale-response tests is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths.
3. Run target and QEMU integration tests in continuous verification.

### Known issues/TODOS in TCP retransmission tests

Issue: TCP retransmission tests is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths.
3. Run target and QEMU integration tests in continuous verification.

### Known issues/TODOS in IPv4 checksum tests

Issue: IPv4 checksum tests is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths.
3. Run target and QEMU integration tests in continuous verification.

### Known issues/TODOS in Wi-Fi reconnect self-check

Issue: Wi-Fi reconnect self-check is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths.
3. Run target and QEMU integration tests in continuous verification.
4. Verify that reconnect never restores packet numbers, replay state, or keys into an unsafe earlier generation.

### Known issues/TODOS in CapNet token round-trip tests

Issue: CapNet token round-trip tests is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths.
3. Run target and QEMU integration tests in continuous verification.
4. Mutate every authenticated field independently and require verification failure.

### Known issues/TODOS in CapNet control-frame round-trip tests

Issue: CapNet control-frame round-trip tests is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths.
3. Run target and QEMU integration tests in continuous verification.
4. Cover unknown types, reserved bits, wrong sessions, stale acknowledgements, and maximum payloads.

### Known issues/TODOS in CapNet fuzz smoke test

Issue: CapNet fuzz smoke test is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths.
3. Run target and QEMU integration tests in continuous verification.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in CapNet formal self-check

Issue: CapNet formal self-check is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths.
3. Run target and QEMU integration tests in continuous verification.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in Driver tests

Issue: Driver tests is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths.
3. Run target and QEMU integration tests in continuous verification.
4. Gate production enablement on the target-specific verification results.

### Known issues/TODOS in TLS tests

Issue: TLS tests is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths.
3. Run target and QEMU integration tests in continuous verification.
4. Run known-answer cryptographic vectors and live interoperability tests against strict reference servers.
5. Include malformed handshake, stale handle, sequence exhaustion, and cleanup cases.

### Known issues/TODOS in Reactor concurrency tests

Issue: Reactor concurrency tests is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths.
3. Run target and QEMU integration tests in continuous verification.
4. Define rollback behavior for failure after partial state mutation.

### Known issues/TODOS in Fault-injection tests

Issue: Fault-injection tests is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths.
3. Run target and QEMU integration tests in continuous verification.
4. Inject allocator, persistence, MMIO, DMA, entropy, scheduler, and audit-sink failures at each commit boundary.

### Known issues/TODOS in Negative security tests

Issue: Negative security tests is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths.
3. Run target and QEMU integration tests in continuous verification.
4. Run equivalent unauthorized operations through reactor, legacy, TLS, Wi-Fi, WASM, and restore paths.

### Known issues/TODOS in Cross-architecture tests

Issue: Cross-architecture tests is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths.
3. Run target and QEMU integration tests in continuous verification.
4. Gate production enablement on the target-specific verification results.

### Known issues/TODOS in QEMU integration tests

Issue: QEMU integration tests is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths.
3. Run target and QEMU integration tests in continuous verification.
4. Exercise E1000 and VirtIO boot, link, DNS, TCP, reset, saturation, and shutdown in automated runs.

### Known issues/TODOS in Hardware integration tests

Issue: Hardware integration tests is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths.
3. Run target and QEMU integration tests in continuous verification.
4. Record exact device and firmware revisions and require repeatable reset, DMA, interrupt, and link-loss results.

### Known issues/TODOS in Coverage gaps

Issue: Coverage gaps is only partially established by the active self-test and unit test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Convert the stated behavior into runnable deterministic tests.
2. Cover negative, boundary, fault, concurrency, and cleanup paths.
3. Run target and QEMU integration tests in continuous verification.
4. Publish a traceable matrix from each documented invariant and limitation to its executable evidence.

### Known issues/TODOS in Ethernet parser fuzzing

Issue: Ethernet parser fuzzing is only partially established by the active fuzzing and property-test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Add a bounded harness for the named parser or state machine.
2. Assert safety, atomic failure, resource bounds, and authority invariants.
3. Retain minimized failures as permanent regression inputs.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in IPv4 parser fuzzing

Issue: IPv4 parser fuzzing is only partially established by the active fuzzing and property-test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Add a bounded harness for the named parser or state machine.
2. Assert safety, atomic failure, resource bounds, and authority invariants.
3. Retain minimized failures as permanent regression inputs.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in ARP parser fuzzing

Issue: ARP parser fuzzing is only partially established by the active fuzzing and property-test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Add a bounded harness for the named parser or state machine.
2. Assert safety, atomic failure, resource bounds, and authority invariants.
3. Retain minimized failures as permanent regression inputs.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in UDP parser fuzzing

Issue: UDP parser fuzzing is only partially established by the active fuzzing and property-test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Add a bounded harness for the named parser or state machine.
2. Assert safety, atomic failure, resource bounds, and authority invariants.
3. Retain minimized failures as permanent regression inputs.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in DNS parser fuzzing

Issue: DNS parser fuzzing is only partially established by the active fuzzing and property-test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Add a bounded harness for the named parser or state machine.
2. Assert safety, atomic failure, resource bounds, and authority invariants.
3. Retain minimized failures as permanent regression inputs.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in TCP stateful fuzzing

Issue: TCP stateful fuzzing is only partially established by the active fuzzing and property-test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Add a bounded harness for the named parser or state machine.
2. Assert safety, atomic failure, resource bounds, and authority invariants.
3. Retain minimized failures as permanent regression inputs.
4. Keep minimized failures in the permanent regression corpus.
5. Require this property to pass before enabling the affected feature.

### Known issues/TODOS in HTTP parser fuzzing

Issue: HTTP parser fuzzing is only partially established by the active fuzzing and property-test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Add a bounded harness for the named parser or state machine.
2. Assert safety, atomic failure, resource bounds, and authority invariants.
3. Retain minimized failures as permanent regression inputs.
4. Replay every discovered failure against all supported targets.
5. Block production support when the invariant cannot be demonstrated.

### Known issues/TODOS in TLS record and handshake fuzzing

Issue: TLS record and handshake fuzzing is only partially established by the active fuzzing and property-test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Add a bounded harness for the named parser or state machine.
2. Assert safety, atomic failure, resource bounds, and authority invariants.
3. Retain minimized failures as permanent regression inputs.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in Wi-Fi management-frame fuzzing

Issue: Wi-Fi management-frame fuzzing is only partially established by the active fuzzing and property-test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Add a bounded harness for the named parser or state machine.
2. Assert safety, atomic failure, resource bounds, and authority invariants.
3. Retain minimized failures as permanent regression inputs.
4. Replay every discovered failure against all supported targets.
5. Block production support when the invariant cannot be demonstrated.

### Known issues/TODOS in EAPOL parser fuzzing

Issue: EAPOL parser fuzzing is only partially established by the active fuzzing and property-test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Add a bounded harness for the named parser or state machine.
2. Assert safety, atomic failure, resource bounds, and authority invariants.
3. Retain minimized failures as permanent regression inputs.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in Driver ring state fuzzing

Issue: Driver ring state fuzzing is only partially established by the active fuzzing and property-test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Add a bounded harness for the named parser or state machine.
2. Assert safety, atomic failure, resource bounds, and authority invariants.
3. Retain minimized failures as permanent regression inputs.
4. Replay every discovered failure against all supported targets.
5. Block production support when the invariant cannot be demonstrated.

### Known issues/TODOS in CapNet token fuzzing

Issue: CapNet token fuzzing is only partially established by the active fuzzing and property-test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Add a bounded harness for the named parser or state machine.
2. Assert safety, atomic failure, resource bounds, and authority invariants.
3. Retain minimized failures as permanent regression inputs.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in CapNet control-frame fuzzing

Issue: CapNet control-frame fuzzing is only partially established by the active fuzzing and property-test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Add a bounded harness for the named parser or state machine.
2. Assert safety, atomic failure, resource bounds, and authority invariants.
3. Retain minimized failures as permanent regression inputs.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in CapNet replay-window properties

Issue: CapNet replay-window properties is only partially established by the active fuzzing and property-test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Add a bounded harness for the named parser or state machine.
2. Assert safety, atomic failure, resource bounds, and authority invariants.
3. Retain minimized failures as permanent regression inputs.
4. Replay every discovered failure against all supported targets.
5. Block production support when the invariant cannot be demonstrated.

### Known issues/TODOS in CapNet delegation properties

Issue: CapNet delegation properties is only partially established by the active fuzzing and property-test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Add a bounded harness for the named parser or state machine.
2. Assert safety, atomic failure, resource bounds, and authority invariants.
3. Retain minimized failures as permanent regression inputs.
4. Generate arbitrary valid delegation trees and prove monotonic rights, time, quota, depth, and revocation behavior.

### Known issues/TODOS in CapNet revocation properties

Issue: CapNet revocation properties is only partially established by the active fuzzing and property-test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Add a bounded harness for the named parser or state machine.
2. Assert safety, atomic failure, resource bounds, and authority invariants.
3. Retain minimized failures as permanent regression inputs.
4. Define rollback behavior for failure after partial state mutation.

### Known issues/TODOS in Temporal restore fuzzing

Issue: Temporal restore fuzzing is only partially established by the active fuzzing and property-test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Add a bounded harness for the named parser or state machine.
2. Assert safety, atomic failure, resource bounds, and authority invariants.
3. Retain minimized failures as permanent regression inputs.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in Regression corpus retention

Issue: Regression corpus retention is only partially established by the active fuzzing and property-test audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. Add a bounded harness for the named parser or state machine.
2. Assert safety, atomic failure, resource bounds, and authority invariants.
3. Retain minimized failures as permanent regression inputs.

### Known issues/TODOS in Packet bounds invariant

Issue: Packet bounds invariant is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in Network reactor single-owner invariant

Issue: Network reactor single-owner invariant is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Keep minimized failures in the permanent regression corpus.
5. Require this property to pass before enabling the affected feature.

### Known issues/TODOS in Descriptor ownership invariant

Issue: Descriptor ownership invariant is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Replay every discovered failure against all supported targets.
5. Block production support when the invariant cannot be demonstrated.

### Known issues/TODOS in Queue capacity invariant

Issue: Queue capacity invariant is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in TCP state-transition invariant

Issue: TCP state-transition invariant is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Keep minimized failures in the permanent regression corpus.
5. Require this property to pass before enabling the affected feature.

### Known issues/TODOS in TCP sequence monotonicity invariant

Issue: TCP sequence monotonicity invariant is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Keep minimized failures in the permanent regression corpus.
5. Require this property to pass before enabling the affected feature.

### Known issues/TODOS in No send without network authority

Issue: No send without network authority is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Prove that deferred, retransmitted, restored, TLS, and driver-direct sends retain valid authority at commit time.

### Known issues/TODOS in No receive without network authority

Issue: No receive without network authority is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Define whether receive authority controls queue admission, dequeue, or both, then test revocation races.

### Known issues/TODOS in DNS response matching invariant

Issue: DNS response matching invariant is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in TLS record authentication invariant

Issue: TLS record authentication invariant is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Replay every discovered failure against all supported targets.
5. Block production support when the invariant cannot be demonstrated.

### Known issues/TODOS in Wi-Fi replay-counter invariant

Issue: Wi-Fi replay-counter invariant is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Replay every discovered failure against all supported targets.
5. Block production support when the invariant cannot be demonstrated.

### Known issues/TODOS in CapNet token authenticity invariant

Issue: CapNet token authenticity invariant is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in CapNet rights attenuation invariant

Issue: CapNet rights attenuation invariant is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Keep minimized failures in the permanent regression corpus.
5. Require this property to pass before enabling the affected feature.

### Known issues/TODOS in CapNet temporal validity invariant

Issue: CapNet temporal validity invariant is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in CapNet replay rejection invariant

Issue: CapNet replay rejection invariant is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in CapNet revocation precedence invariant

Issue: CapNet revocation precedence invariant is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Turn counterexamples into deterministic tests before accepting the repair.
5. Run the proof or property suite continuously after relevant changes.

### Known issues/TODOS in CapNet single-session binding invariant

Issue: CapNet single-session binding invariant is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in Persistence round-trip invariant

Issue: Persistence round-trip invariant is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in No deadlock invariant

Issue: No deadlock invariant is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Keep minimized failures in the permanent regression corpus.
5. Require this property to pass before enabling the affected feature.

### Known issues/TODOS in Bounded memory invariant

Issue: Bounded memory invariant is only partially established by the active formal verification and invariant audit. The present implementation does not yet prove the complete security, lifecycle, failure, and portability contract implied by this heading.

Required fixes:

1. State the invariant in executable or machine-checkable form.
2. Model failure, exhaustion, concurrency, reset, and replay transitions.
3. Keep counterexamples as regression tests and gate relevant changes.
4. Replay every discovered failure against all supported targets.
5. Block production support when the invariant cannot be demonstrated.

### Known issues/TODOS in the network module root

Issue: The module root combines exports, compatibility services, protocol types, global state, HTTP logic, and persistence, while broad dead-code suppression obscures which contract remains active.

Required fixes:

1. Reduce the root to exports, shared configuration, and controlled initialization.
2. Migrate NetworkService callers and remove its duplicate state.
3. Replace the module-wide dead-code allowance with item-specific decisions.

### Known issues/TODOS in the universal network stack

Issue: NetworkStack is the active common protocol path, but it depends on concrete drivers, incomplete protocol behavior, static mutable staging, and unauthenticated operation calls.

Required fixes:

1. Route all packet I/O through one selected backend object.
2. Carry principal and network authority into every state-changing operation.
3. Publish and test explicit protocol support and rejection behavior.

### Known issues/TODOS in the network reactor component

Issue: The active reactor centralizes ownership but exposes only a single unversioned request slot without caller identity, cancellation, safe restart, or late-response protection.

Required fixes:

1. Introduce bounded generation-bearing requests with principals and deadlines.
2. Make cancellation and completion explicit state transitions.
3. Encapsulate all stack and staging memory in reactor-owned state.

### Known issues/TODOS in the Intel E1000 component

Issue: E1000 is the assumed common x86 backend without complete DMA, reset, removal, and physical-hardware conformance evidence.

Required fixes:

1. Validate DMA reachability, alignment, cache visibility, and address width.
2. Implement quiesce, reset, and device-loss transitions.
3. Add emulator and representative hardware regression tests.

### Known issues/TODOS in the Realtek RTL8139 component

Issue: RTL8139 is initialized and used by specialized code but is not a selectable universal-stack backend and collapses several failures into Boolean or zero results.

Required fixes:

1. Implement the common backend contract with typed errors.
2. Define whether RTL8139 is supported, compatibility-only, or removable.
3. Test receive wraparound, overflow recovery, timeout, and reset.

### Known issues/TODOS in the VirtIO network component

Issue: VirtIO is active on AArch64 but uses heap-backed queue memory and allocating receive paths without a proven DMA and cache-coherency contract.

Required fixes:

1. Allocate queues and buffers through architecture DMA primitives.
2. Make receive polling bounded and allocation-free.
3. Implement reset, interrupt, feature, and cross-architecture conformance tests.

### Known issues/TODOS in the Wi-Fi component

Issue: Wi-Fi combines hardware control, management parsing, WPA2 cryptography, connection policy, and temporal secrets without demonstrated end-to-end support for a declared device set.

Required fixes:

1. Publish the exact supported devices and verified connection modes.
2. Separate hardware, protocol, cryptography, and policy ownership.
3. Integrate the data plane and network capabilities through the reactor.

### Known issues/TODOS in the TLS component

Issue: TLS owns a separate TCP and RTL8139-oriented transport path, while complete certificate-chain and hostname validation are not established.

Required fixes:

1. Place TLS over reactor-owned TCP rather than raw driver transport.
2. Add a kernel trust-store and strict certificate and hostname validation.
3. Zeroize session secrets and add interoperability and malformed-record tests.

### Known issues/TODOS in the CapNet implementation component

Issue: CapNet provides a broad parallel authority system whose trust, cryptographic, persistence, and central capability-manager relationships are not yet one verified contract.

Required fixes:

1. Define the threat model and authoritative relationship with local capabilities.
2. Replace prototype authentication where cross-device security requires stronger algorithms.
3. Make session, delegation, revocation, and restore transactions generation-bound.

### Known issues/TODOS in the CapNet facade modules

Issue: The facade modules re-export one monolithic implementation and therefore do not create independent ownership, locking, or verification boundaries.

Required fixes:

1. Keep the facade minimal until a real dependency boundary exists.
2. Split state only where one owner and one invariant can be established. Remove broad dead-code allowances from facade modules.

### Known issues/TODOS in CapNet test support

Issue: CapNet self-checks exercise useful logic but share production globals and do not cover concurrency, rollback, central authority integration, or cross-device behavior.

Required fixes:

1. Make CapNet state instantiable for isolated tests.
2. Retain malformed and replay regression corpora.
3. Add concurrency, persistence-failure, and interoperability tests.

### Known issues/TODOS in network component ownership and maturity

Issue: Components lack one maintained record of owner, status, supported targets, authority requirements, test gates, and removal conditions.

Required fixes:

1. Add a component maturity table maintained with the source.
2. Gate active claims on target-specific tests. Prevent compatibility and experimental components from silently defining public behavior.

### Known issues/TODOS in network boot-time initialization order

Issue: Device, CapNet, reactor, scheduler, interrupt, capability, security, and temporal initialization order varies by architecture and is not expressed as one dependency graph.

Required fixes:

1. Define architecture-neutral initialization phases and prerequisites.
2. Publish readiness only after mandatory dependencies succeed.
3. Add boot-failure tests at each phase.

### Known issues/TODOS in network device probing and backend selection

Issue: Detection initializes several drivers, but the common stack selects one through architecture conditionals rather than a validated backend registration.

Required fixes:

1. Register discovered devices with capabilities and generations.
2. Select exactly one common backend through policy. Reject conflicting device ownership and report why selection failed.

### Known issues/TODOS in static network configuration

Issue: Static address and gateway configuration lacks administrative capability checks, full semantic validation, generation tracking, and atomic dependent-state invalidation.

Required fixes:

1. Require network-administration authority.
2. Validate address, route, DNS, and conflict conditions.
3. Apply configuration as one generation-changing transaction.

### Known issues/TODOS in legacy QEMU network defaults

Issue: Emulator-specific addresses are embedded in stack construction and can be seeded implicitly on x86.

Required fixes:

1. Move defaults into an explicit QEMU boot profile.
2. Disable implicit seeding on physical hardware.
3. Test configured, unconfigured, and profile-disabled boots.

### Known issues/TODOS in AArch64 QEMU network defaults

Issue: AArch64 applies target-specific QEMU configuration with readiness semantics that differ from the x86 path.

Required fixes:

1. Use the same validated configuration transaction on every architecture.
2. Keep platform defaults outside protocol state.
3. Verify identical readiness outcomes across QEMU targets.

### Known issues/TODOS in DHCP support and integration

Issue: DHCP is advertised and represented by a flag but is not an active lease acquisition and renewal state machine.

Required fixes:

1. Correct documentation until DHCP is implemented.
2. Add a bounded reactor-owned DHCP client only when required.
3. Test offer validation, lease expiry, renewal, conflict, and fallback.

### Known issues/TODOS in link readiness detection

Issue: Link readiness uses backend-specific Boolean rules and emulator exceptions without a generation-bearing transition model.

Required fixes:

1. Represent initializing, up, down, reset, removed, and unknown states.
2. Emit link-generation changes through the reactor. Define effects on every dependent protocol and capability.

### Known issues/TODOS in network readiness state

Issue: Readiness is marked once while callers use different weaker predicates and later link loss does not visibly clear the state.

Required fixes:

1. Define staged readiness with operation-specific requirements.
2. Recompute readiness after configuration and backend transitions.
3. Expose one typed readiness snapshot to all callers.

### Known issues/TODOS in runtime interrupt enablement

Issue: Interrupt enablement and processing are backend-specific, and VirtIO does not share the E1000 lifecycle.

Required fixes:

1. Add common enable, mask, acknowledge, drain, and quiesce operations.
2. Enable delivery only after reactor ownership is established.
3. Test interrupt arrival during startup, reset, and shutdown.

### Known issues/TODOS in reactor startup ordering

Issue: The started flag means the task loop exists, not that a usable backend, route, DNS service, or authorization context exists.

Required fixes:

1. Separate task-started from network-ready states.
2. Return typed prerequisite failures.
3. Block restore and administrative operations until their dependencies are ready.

### Known issues/TODOS in initialization failure rollback

Issue: Initialization failures do not trigger one subsystem transaction that resets hardware, releases DMA state, clears readiness, and invalidates dependent objects.

Required fixes:

1. Add staged initialization guards with rollback.
2. Quiesce interrupts and reset failed devices.
3. Verify no protocol or capability state remains published after failure.

### Known issues/TODOS in network reinitialization

Issue: Reinitialization can replace global driver state without coordinating reactor-owned protocol objects or backend generations.

Required fixes:

1. Reject reinitialization outside a quiesced state.
2. Allocate a new backend generation after reset.
3. Terminate or explicitly migrate all dependent objects.

### Known issues/TODOS in network device removal and reset

Issue: The subsystem assumes boot-lifetime devices and lacks hot-removal and reset propagation.

Required fixes:

1. Detect and publish terminal device-loss events.
2. Cancel requests and close or suspend dependent state.
3. Add controlled reprobe and recovery tests.

### Known issues/TODOS in the network interface trait contract

Issue: NetworkInterface is not the active dispatch boundary and omits lifecycle, capability, completion, and feature semantics.

Required fixes:

1. Either adopt the trait as the selected backend contract or remove it.
2. Add lifecycle and generation semantics if retained.
3. Keep authorization at the reactor operation boundary rather than inside one driver.

### Known issues/TODOS in send-frame semantics

Issue: Driver send APIs disagree on errors and do not define acceptance, completion, retry, queue pressure, or post-failure ownership.

Required fixes:

1. Define one typed send outcome.
2. Specify frame size, padding, queueing, and completion rules.
3. Test temporary saturation, timeout, reset, and device loss.

### Known issues/TODOS in receive-frame semantics

Issue: Receive APIs disagree on absence, failure, truncation, and whether an undersized destination consumes the frame.

Required fixes:

1. Define explicit empty, frame, required-size, malformed, and device-fault results.
2. Preserve frames when capacity reporting is supported.
3. Test every driver against the same receive contract.

### Known issues/TODOS in link-state semantics

Issue: A Boolean link value merges unknown, initialization, reset, removal, and negotiated status differences.

Required fixes:

1. Introduce a typed link state and generation.
2. Normalize driver transition events.
3. Connect transitions to readiness and cleanup.

### Known issues/TODOS in MAC-address reporting

Issue: MAC reporting can return optional, zero, cached, hardware, or emulator-derived values without provenance.

Required fixes:

1. Validate address classes before publication.
2. Record address provenance and generation. Reject networking that requires identity when no valid address exists.

### Known issues/TODOS in runtime backend dispatch

Issue: Concrete architecture branches bypass the intended interface abstraction and exclude detected backends.

Required fixes:

1. Store one selected backend behind a narrow object.
2. Remove protocol-layer concrete driver calls.
3. Verify dispatch selection in boot integration tests.

### Known issues/TODOS in driver capability differences

Issue: Backend differences are inferred from concrete code rather than represented as negotiated features.

Required fixes:

1. Publish backend feature metadata.
2. Make reactor policy consume those features.
3. Reject unsupported operations before touching device state.
4. Add runtime evidence that distinguishes unsupported state from transient failure.

### Known issues/TODOS in driver error normalization

Issue: Static strings, Booleans, zero lengths, and silent fallbacks erase retry and recovery meaning.

Required fixes:

1. Define typed backend errors.
2. Preserve temporary, terminal, malformed, and reset classifications.
3. Map errors consistently at service boundaries.
4. Gate production enablement on the target-specific verification results.

### Known issues/TODOS in polled and interrupt-driven network operation

Issue: Polling and interrupt work are combined without a backend-declared progress model or measured idle cost.

Required fixes:

1. Declare each backend progress mode.
2. Route work through one bounded reactor scheduler.
3. Measure latency, CPU cost, and missed-work behavior.

### Known issues/TODOS in network interface replacement and failover

Issue: No supported operation can replace a backend while preserving authority and protocol correctness.

Required fixes:

1. Fail closed on unexpected replacement today.
2. Define generation, migration, and termination rules before adding failover.
3. Require network-administration authority for replacement.

### Known issues/TODOS in reactor single-owner stack design

Issue: Single ownership is conventional rather than enforced because static mutable state remains reachable outside one reactor object.

Required fixes:

1. Place stack and buffers in one non-exported reactor state.
2. Remove direct mutable access helpers.
3. Add invariant checks for owner task and generation.

### Known issues/TODOS in the reactor request slot state machine

Issue: The one-slot state machine has no generation and can race timeout reset against late completion.

Required fixes:

1. Add request identifiers and terminal states.
2. Prevent reuse until reactor cancellation or completion is acknowledged.
3. Model and test every atomic transition.

### Known issues/TODOS in reactor request publication and completion ordering

Issue: Memory ordering covers state publication but not a complete proof involving timeout, UnsafeCell payloads, and shared staging arrays.

Required fixes:

1. Document the happens-before contract.
2. Bind payload and response to a request generation.
3. Run concurrency model tests on weak ordering.

### Known issues/TODOS in inline reactor request fallback

Issue: No inline fallback exists, while the heading and older design language can imply otherwise.

Required fixes:

1. Document that requests require the reactor task.
2. Keep direct execution prohibited under the single-owner model.
3. Remove stale references to fallback behavior.

### Known issues/TODOS in reactor task lifecycle

Issue: The reactor exposes only not-started and started states and cannot report failure, quiesce, stop, or restart.

Required fixes:

1. Add explicit lifecycle states and terminal failure reporting.
2. Reject requests during quiesce and failure.
3. Clear or replace readiness on task loss.
4. Record enough bounded diagnostics to identify recurrence without exposing sensitive data.

### Known issues/TODOS in the network IRQ notification path

Issue: IRQ notification is E1000-specific and loses cause, backend generation, and overflow context.

Required fixes:

1. Route interrupts through the selected backend.
2. Preserve bounded cause information.
3. Ignore stale interrupts from replaced generations.

### Known issues/TODOS in atomic pending-work flags

Issue: The pending counter can wrap and cannot distinguish receive, transmit, link, or error work.

Required fixes:

1. Use bounded cause bits or saturating counters.
2. Record overflow and coalescing diagnostics.
3. Test arrival during drain and reset.

### Known issues/TODOS in receive burst processing

Issue: Burst storage relies on unsafe global exclusivity and driver-provided lengths.

Required fixes:

1. Make burst buffers reactor-owned fields.
2. Validate every length against descriptor and buffer capacity.
3. Test full-budget, malformed, reset, and concurrent IRQ cases.

### Known issues/TODOS in the receive processing budget

Issue: The fixed receive budget is not connected to request and timer latency evidence.

Required fixes:

1. Add per-loop work and latency metrics.
2. Preserve the fixed budget until measurements justify adaptation.
3. Test sustained receive load for request starvation.

### Known issues/TODOS in timer-driven network progress

Issue: Processing one tick at a time after delay can create a long catch-up loop.

Required fixes:

1. Advance timers using bounded elapsed-time calculations.
2. Cap catch-up work per loop.
3. Test large tick jumps and counter wrap.

### Known issues/TODOS in reactor request fairness

Issue: Atomic first-winner acquisition provides no queueing or starvation guarantee.

Required fixes:

1. Add a bounded FIFO request queue when concurrent clients are supported.
2. Record wait and rejection counts by operation class.
3. Define whether administrative priority is permitted.

### Known issues/TODOS in reactor request cancellation

Issue: Timeout is not cancellation and can leave the reactor completing abandoned work.

Required fixes:

1. Add cancellation requests and acknowledgement.
2. Define cleanup for every cancellable operation.
3. Test timeout against connection, DNS, send, and restore work.

### Known issues/TODOS in reactor shutdown and restart

Issue: The reactor assumes boot-lifetime execution and provides no quiesce or restart transaction.

Required fixes:

1. Add quiesce only when reset or shutdown support is required.
2. Drain IRQ, request, timer, and driver work before stopping.
3. Start a new generation and reject stale handles after restart.

### Known issues/TODOS in static reactor staging buffers

Issue: Static staging reduces stack use but permits unsafe aliasing if ownership discipline changes.

Required fixes:

1. Move staging arrays into reactor state.
2. Keep capacities compile-time bounded.
3. Scrub buffers that hold secrets or private payloads where required.

### Known issues/TODOS in shared mutable network state safety

Issue: Safety depends on comments and distributed atomic conventions rather than compiler-enforced borrowing.

Required fixes:

1. Minimize and encapsulate unsafe cells and static mutation.
2. State each safety invariant beside the unsafe boundary.
3. Add race-focused tests for timeout, IRQ, reset, and replay.

### Known issues/TODOS in network stack-size constraints

Issue: Static buffers reduce known pressure, but no measured worst-case stack bound covers nested parsing, logging, and cryptography.

Required fixes:

1. Measure stack high-water marks on each target.
2. Test maximum packet and handshake paths.
3. Move only demonstrated large allocations out of task stacks.

### Known issues/TODOS in temporal replay reactor requests

Issue: Replay uses reactor ownership but lacks authenticated replay authority, snapshot generation, atomic publication, and rollback.

Required fixes:

1. Require a dedicated replay capability.
2. Carry snapshot epoch and transaction identity.
3. Validate all objects before publishing any restored state.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in reactor deadlock and starvation risks

Issue: Long synchronous operations, timer catch-up, driver waits, and scheduling dependencies can delay the sole owner without bounded latency evidence.

Required fixes:

1. Define lock ordering and maximum blocking work.
2. Instrument request, timer, IRQ, and driver latency.
3. Add deterministic adverse-interleaving tests.
4. Preserve adversarial cases that cross state, capacity, and lifecycle boundaries.
5. Make verification part of architecture and release conformance.

### Known issues/TODOS in resource exhaustion

Issue: Resource exhaustion is represented inconsistently across protocol tables, driver rings, reactor requests, CapNet records, dynamic allocations, and outer error conversions.

Required fixes:

1. Define typed exhaustion outcomes for every bounded resource.
2. Preserve existing state when admission fails and apply per-principal capability quotas.
3. Test exact capacity, one above capacity, sustained pressure, release, and recovery.
4. Add runtime evidence that distinguishes unsupported state from transient failure.

### Known issues/TODOS in runtime support versus compiled surface

Issue: The folder currently exposes compiled code, experimental code, compatibility code, and active runtime code through the same module boundary, so callers can infer support from symbol availability instead of an explicit readiness contract.

Required fixes:

1. Add a support matrix that is checked in code, not only documented.
2. Require every public network entry point to declare active, compatibility, experimental, test-only, or dormant status.
3. Make unsupported runtime paths fail closed with a typed unsupported-feature result.
4. Gate shell, fetch, WASM, and service access through the same readiness query.
5. Add target-specific conformance tests that prove which compiled surfaces are actually supported.

### Known issues/TODOS in commit-boundary map

Issue: Packet and state mutation boundaries are distributed across drivers, parsers, protocol handlers, the reactor, temporal restoration, TLS, Wi-Fi, and CapNet, and several paths mutate or discard state before a shared validation outcome is recorded.

Required fixes:

1. Define a small set of structured outcomes for accept, drop, defer, retry, unsupported, suspicious, and fatal failure.
2. Return those outcomes from driver ingress, Ethernet dispatch, IPv4 dispatch, transport handlers, DNS, TLS, Wi-Fi, and CapNet control parsing.
3. Move cache insertion, queue insertion, acknowledgement, retransmission, and restored-state publication behind validated transaction objects.
4. Add counters at the reactor boundary so every rejected packet has one recorded reason.
5. Test that malformed input never commits protocol state, capability leases, temporal records, or diagnostic claims unless the admission rule explicitly allows it.

### Known issues/TODOS in risky backend assumption matrix

Issue: E1000, RTL8139, VirtIO, Wi-Fi, and standalone TLS each depend on different device, DMA, memory-ordering, and transport assumptions, but the subsystem does not yet publish those assumptions as executable backend requirements.

Required fixes:

1. Create backend descriptors for DMA address width, coherency, interrupt mode, receive ownership, transmit ownership, reset support, and link-state reporting.
2. Reject backend activation when the memory manager or architecture layer cannot satisfy those requirements.
3. Add emulator and hardware test labels so QEMU success does not imply physical-device support.
4. Keep standalone TLS transport quarantined until it either moves onto reactor TCP or declares itself compatibility-only.

### Known issues/TODOS in audit command backlog

Issue: The proposed diagnostic command surfaces do not exist yet, and many required counters are not collected at the right ownership boundary.

Required fixes:

1. Build the underlying snapshots first: backend, reactor, protocol, DNS, TLS, Wi-Fi, and CapNet.
2. Require a diagnostic authority before exposing names, peer identifiers, connection ownership, or CapNet token identifiers.
3. Redact payloads and secrets by default.
4. Make every command read-only and generation-tagged.
5. Add command-output tests that prove unsupported, empty, saturated, failed, and reset states are visible without exposing sensitive material.

### Known issues/TODOS in highest priority gaps made explicit

Issue: The risk register ranks the next development pass, but the ranking is not connected to issue tracking, test gating, or release criteria.

Required fixes:

1. Convert the critical rows into tracked engineering tasks with owners and blocking tests.
2. Fail the network release checklist when canonical authority, ingress diagnostics, backend DMA proof, or restore transactions are absent.
3. Revisit the priority table after each completed hardening pass instead of letting it become stale documentation.
