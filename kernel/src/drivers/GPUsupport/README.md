# Oreulius GPU Support

## Current Implementation

The GPU subsystem is an in-progress x86 display substrate. It currently probes
Multiboot2 framebuffer information and a bounded set of PCI display devices,
classifies the results, selects one active backend, and exposes a software
scanout interface to the compositor service. The only operational presentation
path is the framebuffer-backed implementation in `drivers/simplefb.rs`.

## Universal GPU Contract

The word universal describes the intended common contract, not universal
hardware support. The subsystem provides shared vocabulary for discovery,
support tiers, scanout, buffers, queues, fences, firmware, isolation, and
health so that different GPU families can plug into one kernel-facing model.
It does not provide a brand-independent way to program arbitrary GPUs. Today
even that common contract is incomplete, x86-specific in its wiring, and
implemented far more deeply for software framebuffer scanout than for any
native GPU operation.

## Backend Status

### Virtual Display Backends

VirtIO GPU, QXL, and Bochs devices are recognized and ranked as distinct
backends, but their activation and drawing functions currently delegate to
`simplefb`. They do not implement their native device protocols, resource
creation, command queues, modesetting, cursor planes, or display interrupts.

### Vendor-Family Backends

Intel, AMD, and NVIDIA modules can classify device families and inspect a small
amount of display state, but they also depend on an already configured
framebuffer. They are not native vendor drivers.

### Transfer and Compute Models

The subsystem defines probe, capability, buffer-object, aperture, mapping,
firmware, DMA, interrupt, fence, transfer, compute, isolation, audit, and
telemetry types. Most of these are architectural scaffolding rather than
hardware-backed implementations. In particular, the transfer and compute
queues only validate minimal packet fields, increment counters, and allocate
software fences. They do not submit commands to a GPU. No active backend
currently provides proven transfer acceleration, compute execution, or an
optimized vendor tier.

## Display Model

The display directory defines models for EDID parsing, mode requests, mode
selection, cursor state, damage rectangles, scanout devices, and present
targets. These types establish the intended boundary between hardware display
state and compositor presentation. At present they do not form a complete
connector discovery, mode validation, atomic modesetting, page-flip, or
hotplug pipeline.

## Resource and Memory Model

The topology and memory directories describe apertures, resource graphs,
buffer objects, mappings, cache policy, and coherency. These models are
intended to bind every GPU-visible allocation and register range to an owner,
purpose, address range, access policy, and device generation. The current
implementation does not yet connect those records to a common physical-memory
allocator, hardware IOMMU, page-table mapper, or backend activation lifecycle.

## Scheduling and Completion Model

The engine scheduler, command packets, interrupt table, and fence table define
a bounded model for queued work and completion. The intended contract is that
accepted work receives an identity, owner, priority, device generation, and
terminal completed, failed, cancelled, or indeterminate result. Current queues
and fences are software bookkeeping and are not connected to hardware command
processors.

## Errors, Health, Audit, and Telemetry

The subsystem has GPU-specific errors, audit events, fault counters, fence
stall counters, and queue submission counters. These provide useful
development evidence, but they are not yet integrated with the kernel-wide
driver health and observability model. A production backend must preserve the
failure stage and device generation from discovery through teardown rather
than collapsing failures into unavailable output or a serial message.

## Known Limitations

### Known issues/TODOS in GPU Discovery, Mapping, and Ownership

Issue: Framebuffer discovery and ownership are not yet production-safe. PCI BARs are
not fully sized or reserved, 64-bit BAR reconstruction is incomplete, and the
kernel does not prove that a selected BAR is the active scanout surface.
Framebuffer fallback can rely on assumed geometry or an unverified address.
Mapping success, cache attributes, alias prevention, generation tracking, hot
removal, and mode replacement are not handled through one transactional
lifecycle.

Required fixes:

1. Validate complete boot framebuffer records and reject assumed addresses or geometry.
2. Size, reconstruct, reserve, and claim complete PCI BAR ranges before mapping.
3. Bind every mapping to its device, owner, cache policy, extent, and generation.
4. Publish discovery, mapping, activation, and rollback through one transaction.
5. Add tests for malformed records, overlap, mapping failure, replacement, and removal.

### Known issues/TODOS in GPU Presentation

Issue: Presentation is software-driven and has no vblank synchronization, present
fence, reliable completion result, or tearing prevention. Backend availability
is inferred largely from published framebuffer state and dimensions. The
registry and several supporting tables have fixed capacities with limited
overflow evidence.

Required fixes:

1. Return typed accepted, visible, failed, stale, and unavailable presentation results.
2. Add vblank-aware page flipping or backend-specific present synchronization.
3. Retain damage until successful presentation is established.
4. Bind presents to one scanout target, mapping, mode, and device generation.
5. Add tearing, failed-present, headless, and backend-replacement tests.

### Known issues/TODOS in GPU Display Discovery and Modesetting

Issue: EDID parsing, mode requests, cursor state, damage tracking, and mode-selection
types are not connected into one active display pipeline. The subsystem does
not enumerate connectors, validate complete EDID extension chains, negotiate
pixel clocks, program display links, perform atomic modesets, page-flip at
vblank, handle connector hotplug, or restore modes after reset and resume.

Required fixes:

1. Add connector and encoder discovery with validated EDID and mode provenance.
2. Validate clocks, timings, formats, link capacity, and scanout memory requirements.
3. Implement atomic mode validation, commit, rollback, and generation changes.
4. Handle hotplug, reset, suspend, resume, and connector loss explicitly.
5. Add parser, mode-selection, hotplug, and failed-modeset regression tests.

### Known issues/TODOS in Native GPU Backend Support

Issue: VirtIO GPU, QXL, and Bochs do not use their native device protocols. Intel,
AMD, and NVIDIA support does not perform native modesetting, memory management,
command submission, or accelerated rendering. All visible output currently
depends on an already configured framebuffer and software pixel operations.

Required fixes:

1. Implement each virtual device's negotiated transport, resources, queues, and display protocol.
2. Restrict vendor support to reviewed device families and revisions with explicit documentation.
3. Add native modesetting, memory management, interrupts, reset, and recovery per backend.
4. Publish only capabilities proven by the active hardware path.
5. Add positive and negative QEMU or hardware tests for every claimed backend.

### Known issues/TODOS in GPU Transfer, Compute, and Fences

Issue: Transfer and compute queues are software models rather than hardware execution
paths. Their fences do not prove device completion, memory visibility, command
retirement, cancellation, or recovery. No backend currently provides a proven
Transfer2D, Compute, or Optimized implementation.

Required fixes:

1. Connect queue submission to a real backend command processor and validated packets.
2. Bind every command and fence to its owner, buffers, queue, and device generation.
3. Define release, acquire, completion, timeout, cancellation, and reset ordering.
4. Preserve terminal completed, failed, cancelled, stale, and indeterminate outcomes.
5. Add hardware-backed completion, hang, reset, and stale-fence tests before tier promotion.

### Known issues/TODOS in GPU DMA and Isolation

Issue: The GPU memory and IOMMU modules do not yet provide complete hardware-enforced
DMA isolation. Buffer pinning, device-visible address translation, scatter and
gather validation, cache synchronization, per-device domains, fault handling,
and revocation are incomplete. GPU buffers must not be treated as isolated
from unrelated kernel or workload memory merely because software policy
objects exist.

Required fixes:

1. Integrate pinned physical memory, IOVA allocation, requester identity, and hardware domains.
2. Validate full DMA ranges, permissions, directions, masks, segments, and generations.
3. Implement coherent and noncoherent cache synchronization with architecture barriers.
4. Revoke and invalidate mappings before pages or addresses are reused.
5. Add fake-IOMMU, fault-injection, stale-DMA, and hardware isolation tests.

### Known issues/TODOS in GPU Buffer Objects, Apertures, and Cache Policy

Issue: Buffer-object and aperture types do not yet prove physical allocation,
contiguity or segment layout, device addressability, mapping lifetime, cache
attributes, coherency, CPU access exclusion, scanout suitability, or secure
reclamation. The fixed buffer slab and mapping records are not a complete GPU
virtual-memory manager and cannot safely support arbitrary workload buffers.

Required fixes:

1. Back buffer objects with owned physical pages and validated device mappings.
2. Track CPU, device, scanout, imported, exported, pinned, and revoked ownership states.
3. Enforce aperture extent, cache policy, coherency, alignment, and access permissions.
4. Add quotas, secure reclamation, generation-safe handles, and allocation rollback.
5. Test pressure, alias conflicts, stale mappings, cache transitions, and teardown.

### Known issues/TODOS in GPU Resource Topology and Shared Domains

Issue: The resource graph is not populated from complete PCI, firmware, connector,
engine, queue, interrupt, power, and reset-domain evidence. It cannot yet
express every dependency between functions or prevent one backend reset,
mapping, or power transition from affecting an uncoordinated sibling device.

Required fixes:

1. Build topology from authoritative bus, firmware, device, and display evidence.
2. Record parent, sibling, reset, power, interrupt, memory, connector, and engine relationships.
3. Serialize operations that affect shared domains or dependent resources.
4. Reconcile topology across rescan, hotplug, replacement, and removal.
5. Add shared-domain reset, power, conflict, and rollback tests.

### Known issues/TODOS in GPU Scheduling, Priorities, and Cancellation

Issue: The bounded scheduler does not dispatch hardware work or enforce time,
memory, bandwidth, fairness, or per-process quotas. Priority does not provide
preemption, and cancellation does not prove that a device has stopped reading
commands or writing buffers. Queue exhaustion, hung work, process exit, and
reset still need deterministic terminal outcomes.

Required fixes:

1. Connect scheduling to real backend queues with bounded admission and ownership.
2. Enforce per-owner time, memory, queue, bandwidth, and priority policy.
3. Define preemption support honestly for each engine and backend.
4. Retain kernel completion state until cancellation or hardware quiescence is proven.
5. Test starvation, exhaustion, hangs, process exit, reset, and multi-client fairness.

### Known issues/TODOS in GPU Interrupt Registration and Completion

Issue: The GPU interrupt table is a software registration and dispatch model rather
than a complete interrupt-controller integration. It does not establish MSI
or MSI-X allocation, shared-line ownership, masking and acknowledgement order,
storm containment, teardown synchronization, or generation-safe handling of
late and duplicate completions.

Required fixes:

1. Register routes through the platform interrupt allocator with explicit ownership.
2. Implement device cause decoding, masking, acknowledgement, and controller EOI ordering.
3. Bound interrupt work and hand longer processing to generation-bound deferred workers.
4. Synchronize unregister and teardown against in-flight and late handlers.
5. Add shared-line, storm, duplicate, lost, stale, and removal-race fixtures.

### Known issues/TODOS in GPU Lifecycle and Recovery

Issue: There is no complete common lifecycle for activation, suspend, resume, reset,
hot removal, driver replacement, or firmware replacement. Device generations
do not yet protect every mapping, buffer, queue, interrupt, fence, and
compositor target from stale use. Activation failure and device loss do not
have one proven reverse-order cleanup transaction.

Required fixes:

1. Define explicit discovered, claimed, initializing, ready, suspended, resetting, failed, removed, and retired states.
2. Allocate a new generation whenever hardware or software state continuity cannot be proved.
3. Quiesce submissions, DMA, interrupts, deferred work, and presentation before teardown.
4. Resolve every outstanding operation and release resources in reverse acquisition order.
5. Add activation-failure, reset, suspend, resume, replacement, and surprise-removal tests.

### Known issues/TODOS in GPU Capability and Service Publication

Issue: Capability descriptions can represent features that the surrounding model
expects, but publication is not yet backed by a complete activation proof.
Dimensions and framebuffer presence are still used as practical availability
signals. The compositor cannot obtain a reliable present completion result or
distinguish every mapping, backend, reset, removal, and publication failure.

Required fixes:

1. Publish capabilities only after resource, firmware, queue, interrupt, and completion validation.
2. Separate detected, supported, activated, healthy, degraded, and unavailable states.
3. Bind compositor publication to the active device and display generation.
4. Return typed service and present outcomes instead of inferring health from dimensions.
5. Test partial activation, false capability claims, stale publication, and backend loss.

### Known issues/TODOS in GPU Firmware and Device Revisions

Issue: Firmware manifests, loading, and verification are incomplete and are not
connected to a production firmware distribution mechanism. Vendor-family
classification is broad and does not prove support for every device ID,
revision, display engine, firmware combination, or board layout within that
family.

Required fixes:

1. Define signed manifests with device, revision, version, digest, size, and policy constraints.
2. Load firmware through an authenticated external distribution path.
3. Validate firmware before enabling dependent engines or capabilities.
4. Bind firmware identity to device generation, health, recovery, and audit evidence.
5. Add missing, malformed, wrong-device, rollback, replacement, and recovery tests.

### Known issues/TODOS in GPU Capacity and Diagnostics

Issue: The probe registry and several GPU tables use fixed capacities. Saturation,
replacement, loss, stale identifier use, and counter overflow are not reported
through one structured health and audit contract. Existing telemetry is useful
for development but is not sufficient to reconstruct a complete device
lifecycle or fault.

Required fixes:

1. Document the exact capacity and full policy for every registry, slab, queue, and ring.
2. Report rejected, overwritten, evicted, exhausted, live, free, and high-water counts.
3. Add generation-safe handles and tombstones for reused slots and late completions.
4. Correlate diagnostic loss with device, owner, operation, and sequence ranges.
5. Add exact-full, overflow, reuse, wrap, clear, and concurrent-access tests.

### Known issues/TODOS in GPU Error and Health Integration

Issue: GPU errors do not yet carry complete operation, backend, device, generation,
resource, recovery, and caller context. Audit storage and counters are bounded
and can lose history without one correlated loss record. Health is not
published through a common state machine for detected, initializing, ready,
degraded, recovering, failed, removed, and retired devices.

Required fixes:

1. Define structured errors with stage, cause, device, generation, resource, and recovery class.
2. Publish one common GPU health state synchronized with service availability.
3. Correlate probe, activation, submission, completion, reset, removal, and cleanup events.
4. Record audit and counter overflow without exposing sensitive addresses or workload data.
5. Add fault-injection tests for every transition and cleanup failure.

### Known issues/TODOS in GPU Architecture Support

Issue: The current implementation is wired under `drivers::x86`; it does not provide
visible GPU output on AArch64. Its use from x86-64 also inherits portions of
the shared x86 driver tree whose address-width, assembly ABI, and physical
mapping assumptions require further validation.

Required fixes:

1. Separate architecture-neutral GPU policy from x86-specific discovery and mapping.
2. Validate every x86-64 address, layout, foreign interface, and mapping assumption.
3. Add AArch64 platform-resource, MMIO, DMA, interrupt, and framebuffer backends.
4. Reject unsupported targets explicitly instead of selecting an unrelated driver root.
5. Require target-specific builds and display or headless integration tests.

### Known issues/TODOS in GPU Test Coverage

Issue: Current tests cover selected classification and software models, not complete
hardware behavior. There is no comprehensive proof for hostile boot records,
BAR sizing, mapping attributes, guarded framebuffer access, native virtual GPU
protocols, vendor hardware, DMA isolation, interrupt races, reset, suspend,
hot removal, teardown, or cross-architecture display behavior.

Required fixes:

1. Isolate pure parsers, validators, schedulers, and state machines for host unit tests.
2. Add fake MMIO, port, DMA, IOMMU, interrupt, firmware, and scanout fixtures.
3. Fuzz Multiboot2, EDID, PCI, firmware, packet, and completion parsing.
4. Add positive and negative QEMU cases for every supported virtual backend.
5. Maintain hardware matrices and permanent regression artifacts for every discovered defect.

## Limits of the Universal Model

Even when fully developed, the universal layer will have deliberate limits.
It can normalize ownership, capability reporting, synchronization, lifecycle,
errors, and a small set of portable operations, but it cannot erase differences
between GPU instruction sets, memory models, firmware, display engines, queue
formats, coherency rules, reset domains, or security behavior. Native
modesetting and acceleration will still require standards-based transports or
device-family-specific drivers with explicit hardware knowledge.

A completed universal layer also cannot guarantee that every detected GPU is
usable. Unsupported devices may remain probe-only; missing or unauthenticated
firmware may disable features; platform IOMMU, cache, interrupt, and memory
constraints may prevent safe activation; and some devices may expose only
scanout while others expose transfer or compute. Capability tiers describe
what Oreulius has proved for one device generation, not what the silicon is
theoretically capable of doing.

The common interface is not intended to be a lowest-common-denominator public
compute API, a compatibility implementation of vendor user-space stacks, or a
runtime hardware reverse-engineering system. Portable operations should remain
small and explicit. Vendor extensions may exist behind narrower capabilities,
but they must not weaken isolation or allow unsupported commands to pass
through a generic packet interface.

## When a GPU Does Not Pass a Tier

A GPU does not fail as one all-or-nothing device merely because it cannot prove
a requested tier. It remains at the highest lower tier whose complete contract
has been validated. A device that can be identified safely but cannot prove a
usable display surface remains ProbeOnly. A device that can present a verified
framebuffer but has no trustworthy copy engine remains Scanout. A device with a
validated transfer engine but no safe compute path remains Transfer2D.

Tier rejection must fail closed. The kernel must not create the queues, expose
the capabilities, accept the commands, or publish the service operations that
belong to the rejected tier. It should retain a typed reason such as unsupported
device revision, missing firmware, invalid BAR, mapping failure, unavailable
IOMMU isolation, failed reset, command timeout, or unverified completion path.
Detection alone must never be converted into permission to program hardware.

If the selected device cannot provide Scanout, backend selection should try
another independently validated display report. This may produce a boot or
firmware framebuffer, another virtual GPU, or a headless system using serial
output. A fabricated framebuffer address or assumed mode is not a valid
fallback. Failure to find scanout should leave the compositor backend
unavailable while allowing the rest of the kernel to continue when display
hardware is optional.

Raising a device to a higher tier requires implementing and proving the missing
contract in its standards-based or vendor-family backend. The probe path must
match supported device and revision identities, decode and reserve resources,
establish firmware requirements, and report only capabilities supported by
that exact hardware path. Activation must then map registers with correct
memory attributes, establish DMA isolation, reset and initialize the device,
construct owned queues and buffers, register interrupts, and validate a real
completion path before publication.

The backend should expose the new capability only after activation commits.
Failure at any intermediate step must unwind mappings, DMA access, interrupts,
queues, firmware state, and resource claims in reverse order. The registry
should retain the lower proven tier or mark the generation failed; it must not
leave a partially activated higher tier visible.

Implementation should be accompanied by deterministic tests for classification,
unsupported revisions, missing firmware, malformed resources, reset timeout,
queue validation, interrupt completion, cancellation, teardown, and fallback.
QEMU or hardware tests must then prove the actual protocol. Passing model-level
unit tests alone is not sufficient to promote a backend because those tests do
not establish that the real device obeys the expected ordering, DMA, reset, and
completion contracts.

## Remaining Work

The next required work is to make framebuffer discovery fail closed, validate
all boot records and BAR ranges, carry mapping and memory-type evidence, and
remove fabricated or assumed scanout success. After that, each virtual backend
needs a real transport and display protocol, while vendor support needs
device-family-specific modesetting, firmware policy, memory management,
interrupt handling, reset recovery, and command submission. DMA isolation,
buffer ownership, cancellation, device generations, health reporting, and
bounded teardown must be integrated before accelerated tiers can be claimed.

## Testing Status

Testing currently covers selected probe classification, scanout models,
software transfer-queue behavior, and fence allocation. It does not prove real
hardware initialization or presentation. Required coverage includes malformed
Multiboot2 and EDID data, BAR and MMIO validation, mapping failure, guarded
framebuffer access, backend activation rollback, headless boot, mode changes,
reset and removal, interrupt and DMA fixtures, QEMU protocol tests, and
hardware interoperability tests.

## Safety Boundary

The safety rule for this directory is strict: unknown hardware remains
probe-only, unsupported operations fail explicitly, and no backend may claim a
tier until its hardware path, synchronization, cleanup, and tests actually
support that claim. The compositor service is the application-facing display
authority; GPU code supplies validated scanout and future acceleration rather
than a second windowing interface.
