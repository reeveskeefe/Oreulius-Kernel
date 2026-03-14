# GPU Support 

**Status:** Planned / Future Work

This directory is reserved for Oreulia’s GPU enablement stack, including drivers, kernel interfaces, and API adapters. The goal is to provide a clean, modular place for GPU support across different vendors and execution models without mixing GPU‑specific code into core kernel subsystems.

The structure below is the **intended layout**. Files should be added in the appropriate section as work begins.

<table>
  <thead>
    <tr>
      <th>Area</th>
      <th>Purpose</th>
      <th>Examples / File Types</th>
      <th>Notes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>drivers/</strong></td>
      <td>Vendor and device‑specific GPU drivers</td>
      <td>Rust modules, PCI/ACPI hooks, firmware loaders</td>
      <td>One subfolder per vendor or device family</td>
    </tr>
    <tr>
      <td><strong>mm/</strong></td>
      <td>GPU memory management</td>
      <td>VRAM allocators, mappings, page‑table logic</td>
      <td>Keep architecture‑specific logic in submodules</td>
    </tr>
    <tr>
      <td><strong>scheduler/</strong></td>
      <td>GPU scheduling and queue management</td>
      <td>Command submission, preemption, QoS</td>
      <td>Designed to integrate with kernel scheduling</td>
    </tr>
    <tr>
      <td><strong>api/</strong></td>
      <td>GPU API adapters and compatibility layers</td>
      <td>Vulkan‑like, OpenCL‑like, or custom interfaces</td>
      <td>Keep user‑facing ABIs stable and versioned</td>
    </tr>
    <tr>
      <td><strong>firmware/</strong></td>
      <td>Firmware handling and validation</td>
      <td>Loaders, signatures, versioning</td>
      <td>No firmware blobs committed here</td>
    </tr>
    <tr>
      <td><strong>security/</strong></td>
      <td>Isolation and security controls</td>
      <td>Sandboxing, capability checks, DMA protections</td>
      <td>Coordinate with kernel security model</td>
    </tr>
    <tr>
      <td><strong>docs/</strong></td>
      <td>Design notes and standards</td>
      <td>Specs, integration notes, vendor docs</td>
      <td>Use Markdown or HTML; keep concise</td>
    </tr>
    <tr>
      <td><strong>tests/</strong></td>
      <td>GPU validation and conformance tests</td>
      <td>Kernel tests, simulators, stress tests</td>
      <td>Keep deterministic and reproducible</td>
    </tr>
  </tbody>
</table>

## File Placement Rules

<table>
  <thead>
    <tr>
      <th>Rule</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>One concern per folder</strong></td>
      <td>Do not mix driver code with scheduler or API adapters.</td>
    </tr>
    <tr>
      <td><strong>Vendor isolation</strong></td>
      <td>Each vendor or device family belongs in its own subfolder under <code>drivers/</code>.</td>
    </tr>
    <tr>
      <td><strong>Stable ABI boundary</strong></td>
      <td>Public interfaces live under <code>api/</code> and must be versioned.</td>
    </tr>
    <tr>
      <td><strong>No blobs</strong></td>
      <td>Firmware binaries should be fetched at build time, not committed.</td>
    </tr>
    <tr>
      <td><strong>Security first</strong></td>
      <td>Any DMA or isolation features must integrate with kernel capabilities.</td>
    </tr>
  </tbody>
</table>

## Directory Stubs (to be created when implementation begins)

<pre>
GPUsupport/
  drivers/
    vendor_name/
  mm/
  scheduler/
  api/
  firmware/
  security/
  docs/
  tests/
</pre>

## Contribution Notes

- Keep GPU code modular and behind clear interfaces.
- Avoid direct dependencies from core kernel subsystems into GPU modules.
- If a new API surface is introduced, update documentation in <code>docs/</code>.

## Future Targets

- Vendor‑agnostic core with vendor‑specific plugins.
- Unified memory management and scheduling primitives.
- Strict isolation for multi‑tenant GPU workloads.

