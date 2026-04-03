# Oreulius GPU Support

This folder is Oreulius's **universal GPU substrate**.

Its job is not to guess how every GPU works. Its job is to give every GPU the
highest **safe** level of support Oreulius can prove:

- safe probe and classification
- scanout for the compositor
- normalized transfer and compute models
- vendor or standards-backed acceleration where real implementations exist

If you are a company, contributor, or hardware partner and want to add GPU
support, this folder is the place to do it.

## What This Folder Is

`GPUsupport/` is the kernel layer between:

- raw display / GPU hardware
- the compositor and future higher-level graphics services

It is responsible for:

- detecting display controllers
- classifying them into safe support tiers
- selecting the active backend
- exposing a compositor-facing scanout target
- defining normalized buffer, engine, queue, and fence models
- enforcing a hard rule: **no unsafe "brandless MMIO command guessing"**

This means Oreulius can support unknown hardware conservatively, while still
allowing deep optimized support for devices that have standards-based or
vendor-specific implementations.

## Support Tiers

Every backend must honestly declare the highest tier it can support.

### `ProbeOnly`

The device can be discovered and described safely, but Oreulius does not claim
it can render or submit work to it.

### `Scanout`

The device can present pixels to the screen and act as a compositor backend.

This is the minimum tier for "real GPU/display support" in Oreulius.

### `Transfer2D`

The device can safely accelerate copy/fill/blit style operations beyond pure
CPU framebuffer writes.

### `Compute`

The device can accept normalized compute submissions through a real hardware or
standardized queue model.

### `Optimized`

The device has a mature vendor-family implementation with richer acceleration,
better scheduling, stronger memory handling, or firmware-assisted features.

## Current Layout

```text
GPUsupport/
├── mod.rs            # public facade and backend selection
├── core.rs           # GpuTier / GpuClass / GpuProbeReport
├── probe.rs          # safe device probing and classification
├── registry.rs       # global GPU registry and active selection
├── backend.rs        # ScanoutOps / TransferOps / ComputeOps
├── display/          # present target, modeset, cursor, EDID, damage
├── memory/           # buffer objects, mappings, apertures, cache policy
├── transport/        # MMIO, DMA, IRQ, fence helpers
├── engines/          # normalized transfer and compute packets/queues
├── firmware/         # external firmware hooks and validation
├── drivers/          # concrete backends and vendor-family plugins
├── security/         # isolation, DMA policy, IOMMU hooks, audit
├── telemetry/        # counters and health metrics
├── docs/             # subsystem documentation
└── tests/            # deterministic GPU tests
```

## Backend Selection Policy

Oreulius currently prefers scanout backends in this order:

1. `virtio_gpu`
2. `qxl`
3. `bochs`
4. `simplefb`
5. vendor-family plugin

That order is deliberate:

- standardized virtual backends first
- safe generic scanout fallback second
- vendor-specific deep support only when the implementation is real

## The Rule For Contributing GPU Support

If you are adding support for a GPU, do **not** start by writing raw register
pokes into random kernel code.

Start with this sequence:

1. Add or improve **probe classification** in `probe.rs`
2. Decide the **highest safe tier** the device can honestly claim
3. Add a backend or vendor plugin under `drivers/`
4. Hook it into the active selection path in `mod.rs`
5. Add tests proving the tier claim is correct
6. Document firmware, limitations, and safety assumptions

That keeps the architecture coherent.

## How To Add Support For A New GPU

### Case 1: Standardized or virtual backend

Examples:

- virtio-gpu style device
- QXL / SPICE class device
- Bochs / stdvga class device
- simple linear framebuffer path

Add or extend a backend in `drivers/`:

- `drivers/virtio_gpu.rs`
- `drivers/qxl.rs`
- `drivers/bochs.rs`
- `drivers/simplefb.rs`

Your backend should:

- expose scanout safely
- report correct width/height
- implement `put_pixel`, `fill_rect`, and `flush`
- never claim transfer or compute unless those paths are truly implemented

### Case 2: Vendor-family support

Examples:

- Intel integrated graphics family
- AMD display/GPU family
- NVIDIA family

Start in:

- `drivers/intel/`
- `drivers/amd/`
- `drivers/nvidia/`

A vendor-family plugin should first prove:

- PCI identity and family classification
- BAR interpretation
- MMIO safety
- required firmware policy
- safe scanout or queue bring-up

Do not claim native compute just because the device is powerful. Claim it only
when Oreulius can actually submit and synchronize work correctly.

## What "Finished" Means For A Backend

A backend is not finished when it "kind of draws pixels once."

A backend is finished for its claimed tier only when:

- the tier is correctly reported
- the backend initializes deterministically
- errors fail closed
- unsupported features return unsupported, not undefined behavior
- scanout dimensions are correct
- fence and queue semantics are stable
- firmware requirements are explicit
- tests cover the contract it claims

## Required Files For A Serious New Backend

At minimum, a meaningful new backend or family contribution should touch:

- `probe.rs`
- one file in `drivers/`
- relevant types in `core.rs` / `caps.rs` if needed
- tests in `tests/`
- docs in `docs/`

Optional but expected for deeper support:

- `memory/`
- `transport/`
- `engines/`
- `security/`
- `firmware/`
- `telemetry/`

## Build And Validation Expectations

Before calling a backend ready, contributors should validate at least:

### Basic build

```bash
bash kernel/build-x86_64-full.sh
```

### Expected validation areas

- probe classification is correct
- unknown devices stay conservative
- compositor scanout works
- headless fallback does not break boot
- transfer/compute claims are tested if exposed
- firmware-required devices fail safely when firmware is absent

If you add a backend that only works on a specific environment, say that
explicitly in the backend doc and code comments.

## Security And Safety Requirements

All GPU support in Oreulius must follow these rules:

- never guess native command submission on unknown hardware
- never claim a higher tier than the code really supports
- do not commit firmware blobs into the repository
- integrate DMA and buffer ownership with kernel policy
- prefer explicit unsupported errors over risky partial implementations

If a device needs firmware:

- describe it in `firmware/manifest.rs`
- load it through external hooks
- validate it before enabling advanced paths

## What Companies Should Do

If you are bringing a new GPU family to Oreulius inside a company:

1. Decide whether you want:
   - safe scanout only
   - transfer acceleration
   - compute
   - full optimized family support
2. Implement the smallest honest tier first
3. Land probe + scanout + tests before deeper acceleration
4. Add firmware handling only when required
5. Keep vendor knowledge isolated in the family plugin, not spread through the kernel

The right way to commercialize or upstream GPU support here is to keep the
universal substrate stable and put hardware-specific depth in the plugin layer.

## Non-Goals

This folder is not trying to:

- magically reverse-engineer every GPU at runtime
- ship vendor firmware blobs in-tree
- expose a stable public user-facing GPU compute ABI yet
- replace the compositor with ad hoc direct-to-hardware drawing

The compositor remains the first public consumer.

## Where To Start Reading

If you are new to this subsystem, read in this order:

1. `mod.rs`
2. `core.rs`
3. `probe.rs`
4. `display/scanout.rs`
5. `drivers/simplefb.rs`
6. `docs/universal-gpu-model.md`
7. `docs/tiering.md`

That is the shortest path to understanding how Oreulius expects GPU support to
be added.
