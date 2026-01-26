i# Oreulia — Filesystem v0 (Persistence Service)

**Status:** Draft (Jan 24, 2026)

Oreulia’s filesystem is a **persistence-first, capability-gated service** that provides durable storage without ambient paths or global namespaces.

It builds on the persistence primitives (`docs/oreulia-persistence.md`) and integrates with capabilities (`docs/oreulia-capabilities.md`) to make storage authority explicit.

---

## 1. Goals

- Provide a minimal, durable filesystem for MVP (QEMU-first).
- No ambient access: storage is only reachable via capabilities.
- Names are views: paths are provided by authority-bearing services, not a universal primitive.
- Persistence-first: files are durable by default; the filesystem is a thin layer over logs/snapshots.

Non-goals (v0):

- Complex hierarchies (nested directories).
- POSIX compatibility (no `open`, `read`, `write` syscalls).
- Performance optimizations (e.g., caching, indexing).

---

## 2. Model

### 2.1 Filesystem as a service

The filesystem runs as a user-space service that:

- Holds a `Store` capability for logs/snapshots.
- Provides `Filesystem` capabilities to authorized components.
- Manages a simple key-value store or flat file namespace.

### 2.2 File objects

A file is a durable object with:

- `key`: a string identifier (e.g., "config.json").
- `data`: bytes (bounded, e.g., 64 KiB v0).
- `metadata`: optional (timestamps, size).

Operations:

- Create, read, update, delete (CRUD) via message passing.

### 2.3 Namespace views

Paths are not global; they’re provided by services.

Example:

- A “config service” holds a `Filesystem` capability and provides a view like `/config/app.json`.
- The view is enforced by the service; the filesystem sees only keys.

This aligns with Oreulia’s “no ambient authority” principle.

---

## 3. Capabilities

### 3.1 Filesystem capabilities

- `Filesystem.Read`: read files by key.
- `Filesystem.Write`: create/update files by key.
- `Filesystem.Delete`: delete files by key.
- `Filesystem.List`: list keys (optional v0).

Rights are attenuated per component (e.g., a component gets `Read` only for its own keys).

### 3.2 Integration with persistence

The filesystem service uses `Store` capabilities to persist files:

- Files are stored as snapshot entries or log records.
- Recovery: filesystem reconstructs its state from the latest snapshot + replayed logs.

---

## 4. Message protocol (v0)

The filesystem service communicates via channels.

### 4.1 Request messages

Requests are typed messages sent to the filesystem channel.

Example schema (conceptual):

- `type: "read"`, `key: "config.json"`
- `type: "write"`, `key: "config.json"`, `data: bytes`
- `type: "delete"`, `key: "config.json"`

### 4.2 Response messages

Responses are sent back on a reply channel (capability-gated).

- Success: `status: "ok"`, `data: bytes` (for reads)
- Error: `status: "error"`, `code: "not_found"`

---

## 5. Implementation sketch (v0)

### 5.1 Storage backend

- Use RAM-backed for bring-up (as in persistence v0).
- Later: virtio block with a simple allocator.

### 5.2 Key management

- Flat namespace: keys are strings (e.g., "component/config").
- No directories; use prefixes for grouping (e.g., "app/").

### 5.3 Durability

- Writes append to log.
- Periodic snapshots capture the current file set.

---

## 6. Interaction with Wasm

Wasm modules access the filesystem via channels:

- Send requests to a filesystem channel capability.
- Receive responses asynchronously.

No direct host calls; everything through IPC.

---

## 7. Risks & mitigations

- **Performance**: Simple key-value may be slow for large files; mitigate by keeping MVP files small.
- **Authority leaks**: Ensure capabilities are attenuated; test enforcement.
- **Recovery complexity**: At-least-once replay may cause duplicates; use idempotent operations.

See also: `docs/oreulia-mvp.md` → “Risks & mitigations” for broader MVP tradeoffs.

---

## 8. Next (v1+)

- Hierarchical namespaces.
- Shared file capabilities.
- Quotas and access control.
- Integration with networking (e.g., remote filesystems).