# Oreulius — Filesystem Architecture

**Status:** Implemented (March 2026)

Oreulius's filesystem stack is a two-layer design: a lower **persistence service** (`fs.rs`) that provides a capability-gated key-value store over RAM-backed storage, and an upper **Virtual File System** (`vfs.rs`) that projects a Unix-like inode tree — with paths, directories, symlinks, hard links, mount points, file descriptors, and per-process capability inheritance — on top of it. The two layers are coupled but separated by a clean IPC-style message protocol, allowing the VFS to delegate file payload storage to `fs.rs` via `Request`/`Response` messages while keeping namespace structure in its own inode table.

A third thin shim, `vfs_platform.rs`, abstracts process management and tick queries so that the VFS core compiles identically on both `x86_64` (where it calls into `crate::process`) and `aarch64` (where process management differs).

---

## 1. Layer 0 — The Persistence Service (`fs.rs`)

### 1.1 Purpose and Design

`FilesystemService` is the authoritative low-level store. It is intentionally *not* path-aware: it knows nothing about directories, symlinks, or inodes. Its entire API is keyed by `FileKey`, a validated heap-allocated string with a minimum length of 1 and no length cap. The service is exposed as a kernel-global singleton via `spin::Once`:

```rust
static FILESYSTEM: Once<FilesystemService> = Once::new();
pub fn filesystem() -> &'static FilesystemService { ... }
```

All mutable state is held inside a `Mutex<FilesystemState>`, making every public method (`handle_read`, `handle_write`, `handle_delete`, `handle_list`) a single critical section with no interior locking.

### 1.2 FileKey and IPC Transfer

`FileKey` wraps a `Box<str>` to prevent accidental copying. On IPC transfer, the key is **packed into a `[u32; 4]`** (16 bytes) inline prefix via little-endian byte-to-word encoding:

```
word[i] |= byte[i*4 + j] << (j * 8)   for j in 0..4
```

The VFS uses this when conveying file payload keys to the persistence service across a logical IPC boundary. The `object_id` field of the transferred `Capability` carries the true key length so the receiver can unpack exactly the right number of bytes.

### 1.3 Capability Model

Every request to `FilesystemService` must carry a `FilesystemCapability`. A capability contains:

| Field | Type | Meaning |
|---|---|---|
| `cap_id` | `u32` | Opaque handle index |
| `rights` | `FilesystemRights` | Bitfield: READ `1<<0`, WRITE `1<<1`, DELETE `1<<2`, LIST `1<<3` |
| `key_prefix` | `Option<FileKey>` | If set, caps access to keys starting with this prefix |
| `quota` | `Option<FilesystemQuota>` | Optional per-capability resource budget |

`FilesystemRights::attenuate(&self, bits) -> Self` performs a bitwise AND, enforcing the *no-amplification* property: a delegated capability can only have rights that are a subset of its parent. Four constructor variants are provided:

- `FilesystemCapability::new(cap_id, rights)` — global access
- `FilesystemCapability::scoped(cap_id, rights, prefix)` — prefix-scoped
- `FilesystemCapability::with_quota(cap_id, rights, quota)` — budgeted
- `FilesystemCapability::scoped_with_quota(cap_id, rights, prefix, quota)` — both

Permission checks are a two-step gate inside `check_permission`: first the rights bitfield, then `can_access`, which verifies that the key starts with the capability's `key_prefix`. Both checks must pass before any storage mutation occurs.

### 1.4 Quota Enforcement

`FilesystemQuota` expresses three optional limits:

```rust
pub struct FilesystemQuota {
    pub max_total_bytes: Option<usize>,
    pub max_file_count: Option<usize>,
    pub max_single_file_bytes: Option<usize>,
}
```

`check_quota` is called on every write before `RamStorage::write`. It projects the new total from existing storage accounting: `projected_total = total_bytes - existing_size + new_len`. If any limit would be exceeded, `FilesystemError::QuotaExceeded` (or `FileTooLarge` for the single-file limit) is returned without touching storage.

### 1.5 RAM Storage Backend — `RamStorage`

`RamStorage` holds a `BTreeMap<FileKey, File>` and a `total_bytes: usize` accumulator. All keys are sorted, enabling efficient prefix-filtered listing. The `File` struct stores:

```
key: FileKey
data: Vec<u8>
metadata: FileMetadata { size, created, modified, accessed,
                          read_count, write_count, hot_score }
```

The `hot_score` field is an exponentially weighted activity metric. On every access (read or write), it is updated via the recurrence:

```
hot_score[t+1] = floor((7/8) * hot_score[t]) + delta
```

where `delta = data.len` for writes and `delta = 1` for reads. Saturating arithmetic prevents overflow. This score is used by `thermal_profile()` to classify each file as:

- **Hot** — `hot_score > 2 * average_hot_score`
- **Warm** — `hot_score >= average_hot_score`
- **Cold** — everything else

Thermal classification is reported via `FilesystemHealth` and can drive telemetry or eviction policy.

### 1.6 Observability

Every operation records a `FilesystemEvent` into a bounded `VecDeque<FilesystemEvent>`:

```rust
pub struct FilesystemEvent {
    pub sequence: u64,    // monotone counter
    pub tick: u64,        // PIT tick at time of operation
    pub operation: FilesystemOperation,
    pub key: Option<FileKey>,
    pub bytes: usize,
    pub detail: Option<String>,
}
```

The ring capacity is governed by `FilesystemRetentionPolicy`. The default, `page_sized_default()`, computes `PAGE_SIZE / sizeof::<FilesystemEvent>()` at runtime, giving a page-sized budget without a compile-time constant. The log is trimmed via `pop_front` whenever it exceeds capacity.

`FilesystemMetrics` accumulates 14 counters (reads, writes, creates, updates, deletes, lists, permission denials, quota denials, not-found, repairs, bytes read/written, net bytes added, bytes deleted) and is snapshottable without clearing.

`FilesystemService::scrub_and_repair()` iterates all files, recomputes `metadata.size = data.len()` for any file whose metadata has drifted, and corrects `total_bytes` if it is inconsistent with the sum of individual file sizes. Scrub events are recorded in the event log.

### 1.7 Message Protocol

The full request/response protocol allows callers that only hold a `Request` value to drive the service:

```rust
pub fn handle_request(&self, request: Request) -> Response
```

`Request` carries `req_type` (Read/Write/Delete/List), an optional `FileKey`, a `Vec<u8>` payload, and a `FilesystemCapability`. `Response` carries `ResponseStatus` (Ok or `Error(FilesystemError)`) plus an optional `detail: String` for diagnostic context. This design means the VFS can issue file-payload operations through the exact same code path as any other caller, with the same capability checks applied.

---

## 2. Layer 1 — The Virtual File System (`vfs.rs`)

### 2.1 Overview

`vfs.rs` (5,535 lines) implements a complete Unix-like namespace. Its global state is protected by a `DagSpinlock` at interrupt-DAG level `DAG_LEVEL_VFS = 5`. All public entry points acquire this lock through an `InterruptContext<DAG_LEVEL_THREAD>` (level 8), ensuring the acquire is always valid under Oreulius's acyclic lock ordering.

```rust
static VFS: DagSpinlock<DAG_LEVEL_VFS, Vfs> = DagSpinlock::new(Vfs::new());
```

The internal `Vfs` struct holds:

```rust
struct Vfs {
    inodes:                    Vec<Option<Inode>>,
    mounts:                    Vec<Mount>,
    handles:                   Vec<Option<Handle>>,
    policy:                    Option<VfsPolicy>,
    capability_mapper:         Option<CapabilityMapper>,
    storage_namespace:         u64,
    watches:                   BTreeMap<u64, VfsWatch>,
    watch_events:              VecDeque<VfsWatchEvent>,
    notify_channels:           BTreeMap<u32, VfsWatchSubscriber>,
    next_watch_id:             u64,
    next_watch_event_sequence: u64,
}
```

`Vfs::new()` is `const` — it allocates no memory and is safe to call at static init time. `Vfs::init()` is called inside every public entry point; it lazily allocates the root inode (inode 1, mode `0o755`) and initializes the policy and capability mapper exactly once. Inode 0 is permanently `None` as a sentinel.

### 2.2 Inode Model

```rust
pub enum InodeKind { File, Directory, Symlink }

pub struct InodeMetadata {
    pub size:                   u64,
    pub mode:                   u16,
    pub uid:                    u32,
    pub gid:                    u32,
    pub atime:                  u64,
    pub mtime:                  u64,
    pub ctime:                  u64,
    pub nlink:                  u32,
    pub direct_blocks:          [u32; 12],
    pub indirect_block:         u32,
    pub double_indirect_block:  u32,
    pub triple_indirect_block:  u32,
}
```

Block pointer fields (`direct_blocks`, `indirect_block`, etc.) mirror the traditional ext2/ext3 on-disk layout and are reserved for future block-device backed storage. Currently, file content is stored in `fs.rs` under a namespaced key, not via these block pointers.

`InodeId` is a `u64` index into `Vfs::inodes`. The `Vec<Option<Inode>>` structure allows slot reuse: when an inode's `nlink` drops to zero and no handles are open, `inodes[id] = None` and the slot becomes eligible for future `alloc_inode` calls.

**File payload storage:** For `InodeKind::File`, the actual bytes are *not* stored in the inode. Instead, a key of the form `system/vfs/<namespace>/<inode_id>` is computed by `inode_payload_key` and the data is stored via `crate::fs::filesystem().handle_request(Request::write(...))`. Reading a file issues a matching `Request::read`. This means the VFS has durable file contents even before a snapshot is written, because the persistence service (`fs.rs`) is itself always live.

For `InodeKind::Symlink`, the target path is stored inline in `inode.data` (a `Vec<u8>`) because symlink targets are short and do not benefit from persistence-service indirection.

### 2.3 Path Resolution

Path resolution is implemented as `resolve_path_internal(path, follow_final, depth)`. The algorithm:

1. Normalize the path (collapse `//`, strip trailing `/`, resolve `.`/`..`)
2. Start at inode 1 (root)
3. Iterate components; for `..`, pop the inode stack
4. For each intermediate symlink — or the final component if `follow_final = true` — read the symlink target and recurse, up to a depth limit of **16** before returning `Err("Symlink loop detected")`

Two public variants exist:
- `resolve_path` — follows all symlinks including the final component
- `resolve_path_nofollow` — follows intermediate symlinks but not the final one (used for `unlink`, `rmdir`, `readlink`)

A chain-building variant, `resolve_path_chain`, returns `Vec<InodeId>` representing every component from root to target. This chain is required for capability resolution (see section 2.5).

### 2.4 Handle Model

```rust
enum HandleKind {
    MemFile   { inode: InodeId, path: String },
    MemDir    { inode: InodeId },
    MountFile { mount_idx: usize, node_id: MountNodeId, path: String },
    MountDir  { mount_idx: usize, node_id: MountNodeId },
    VirtioRaw { path: String },
    VirtioPartitions { path: String },
}

struct Handle {
    kind:       HandleKind,
    pos:        usize,        // current seek position
    flags:      OpenFlags,
    owner:      Pid,
    capability: FilesystemCapability,
}
```

Handles are stored in `Vfs::handles: Vec<Option<Handle>>`. Allocation scans for the first `None` slot; if none exists, a new slot is pushed. The handle ID returned to userspace is `slot_index + 1` (1-based, so 0 is always invalid). `OpenFlags` is a `bitflags!` field: READ, WRITE, CREATE, TRUNC, APPEND.

The six `HandleKind` variants cover:
- **MemFile / MemDir** — in-memory inode tree
- **MountFile / MountDir** — delegated to a `MountedBackendContract` implementation
- **VirtioRaw** — direct byte access to the VirtIO block device via `virtio_blk`
- **VirtioPartitions** — a synthesized read-only text file listing detected MBR/GPT partitions

### 2.5 Capability Resolution and Access Control

The VFS maintains a `CapabilityMapper` inside each `Vfs` instance:

```rust
struct CapabilityMapper {
    directory_caps: BTreeMap<InodeId, FilesystemCapability>,
    process_caps:   BTreeMap<u32, FilesystemCapability>,
    default_capability: FilesystemCapability,
}
```

**Per-path access checks** proceed as follows:

1. `resolve_authority_chain(path)` returns the chain of inodes from root to the target
2. `resolve_capability_for_chain(pid, chain)` starts from the process capability (`process_caps[pid]` or `default_capability`) and applies each directory capability found along the chain via `attenuate_capability`, computing the *intersection* (most restricted set of rights) of all ancestors
3. `ensure_path_rights(pid, path, chain, required)` asserts that the resulting capability passes both the rights check and the prefix check

This means a directory-level capability can restrict all operations beneath it, even if the process-level capability is more permissive. Capability attenuation is monotone: rights can only decrease along a delegation chain, never increase.

**Quota enforcement at the VFS level** is performed by `ensure_quota_allows`, which:
1. Collects all `FilesystemQuota` scopes from the process capability and every ancestor directory capability along the chain
2. For each scope, calls `subtree_usage(root_id)` which performs a DFS over all reachable inodes to compute current file count and byte total
3. Checks all three quota dimensions (`max_single_file_bytes`, `max_total_bytes`, `max_file_count`) for each scope before allowing any mutation

**Process capability inheritance** is supported via `inherit_process_capability(parent_pid, child_pid, attenuate)`, which copies the parent's capability to the child and optionally narrows the rights further.

### 2.6 Mount Subsystem

Mounts are stored in `Vfs::mounts: Vec<Mount>`. Each `Mount` has:

```rust
struct Mount {
    path:    String,
    backend: MountBackend,    // currently only VirtioBlock
    state:   MountState,
    health:  MountHealthCounters,
}
```

**Path dispatch:** `find_mount(path)` scans all mounts and picks the one with the longest matching prefix (longest-prefix-wins, same as a routing table). If a mount is found, the VFS strips the mount prefix to compute a subpath and dispatches to the `MountedBackendContract` trait:

```rust
trait MountedBackendContract {
    fn mkdir(&mut self, subpath: &str) -> Result<(), &'static str>;
    fn create_file(&mut self, subpath: &str) -> Result<MountNodeId, &'static str>;
    fn unlink(&mut self, subpath: &str) -> Result<(), &'static str>;
    fn rmdir(&mut self, subpath: &str) -> Result<(), &'static str>;
    fn rename(&mut self, old: &str, new: &str) -> Result<(), &'static str>;
    fn link(&mut self, existing: &str, new: &str) -> Result<(), &'static str>;
    fn symlink(&mut self, target: &str, link: &str) -> Result<(), &'static str>;
    fn readlink(&mut self, subpath: &str) -> Result<String, &'static str>;
    fn open_kind(&mut self, mount_idx: usize, subpath: &str, flags: OpenFlags, full_path: &str) -> Result<HandleKind, &'static str>;
    fn list(&mut self, subpath: &str, out: &mut [u8]) -> Result<usize, &'static str>;
    fn read(&mut self, subpath: &str, out: &mut [u8]) -> Result<usize, &'static str>;
    fn write(&mut self, subpath: &str, data: &[u8]) -> Result<usize, &'static str>;
    fn write_at(&mut self, subpath: &str, offset: usize, data: &[u8]) -> Result<usize, &'static str>;
    fn path_size(&mut self, subpath: &str) -> Result<usize, &'static str>;
}
```

**VirtIO backend:** `VirtioMountState` is a self-contained inode-like tree of `MountNode` objects that mirrors the VFS inode design but is independent of it. On construction it always creates two special entries directly under the mount root:

- `raw` (`VirtioRaw`) — reading/writing this node calls `virtio_blk::read_at` / `virtio_blk::write_at` directly, giving raw sector-level access to the block device
- `partitions` (`VirtioPartitions`) — a synthesized read-only text file listing detected MBR/GPT partitions; writes return `Err("Partitions file is read-only")`

Symlinks in the VirtIO backend support loop detection (depth limit 16) using the same algorithm as the in-memory VFS. Cross-device renames and hard links are rejected with `Err("Cross-device rename")` or `Err("Cross-device link")`.

**Mount health counters** — `reads`, `writes`, `mutations`, `errors`, and `last_error` — are updated after every backend operation and are visible via `vfs::mounts()` which returns `Vec<MountStatus>` with both the contract info and the live counters.

### 2.7 Watch and Notification System

The VFS implements a filesystem watch system with two delivery mechanisms:

**Poll-based watches:**
```rust
pub fn watch(path: &str, recursive: bool) -> Result<u64, &'static str>
pub fn notify(limit: usize) -> Vec<VfsWatchEvent>
pub fn unwatch(id: u64) -> bool
```
`notify` returns the most recent `limit` (clamped to 256) events from a bounded `VecDeque`. The capacity is `PAGE_SIZE / sizeof::<VfsWatchEvent>()`, computed at runtime.

**Push-based IPC channels:**
```rust
pub fn subscribe_notify_channel(channel_id: ChannelId) -> Result<(), &'static str>
pub fn ack_notify_channel(channel_id: ChannelId, sequence: u64) -> Result<(), &'static str>
```
Each subscriber has a `VfsWatchSubscriber` with a per-subscriber backlog queue and an in-flight sequence tracker. The delivery protocol is:
1. A VFS mutation records an event via `record_watch_event` -> `broadcast_watch_event`
2. Each subscriber's backlog receives a copy
3. `drain_notify_backlogs` iterates subscribers; if `in_flight.is_none()`, it calls `ipc::send` with the front-of-queue event and marks it in-flight
4. The subscriber ACKs via `ack_notify_channel(sequence)`, which pops the front and advances `last_acked_sequence`, then triggers another drain

If a channel is stale (capability resolution fails or IPC returns `InvalidCap` / `Closed`), the subscriber is silently pruned.

`VfsWatchKind` enumerates 12 event types: Read, Write, List, Create, Delete, Rename, Link, Symlink, ReadLink, Mkdir, Rmdir, Mount.

Every watch event is also emitted into the wait-free telemetry ring:
```rust
crate::wait_free_ring::TELEMETRY_RING.push(summary)
```
The `score` field carries `min(detail.len(), 255)` as a coarse activity magnitude.

### 2.8 Persistence and Journal

The VFS persists its complete state (inode tree, mount table, capability map) by encoding it to a binary blob and writing it to the persistence service under `system/vfs/snapshot.bin`. The format is versioned:

```
Magic:   0x4F_56_46_53  ("OVFS")
Version: u16            (currently 3)
```

**Inode serialization** encodes each live inode as:
- `id (u64)`, `kind (u8)`, `mode (u16)`, `uid (u32)`, `gid (u32)`
- `atime (u64)`, `mtime (u64)`, `ctime (u64)`, `size (u64)` (added in v3), `nlink (u32)`
- inline data length `u32` (non-zero only for symlinks), entry count `u32`
- inline data bytes (symlink target), then directory entries as `name_len (u16)` + name bytes + `inode (u64)`

**Mount serialization** encodes the backend type byte, the path string, and then the full `VirtioMountState` node table including each node's kind, nlink, data, and directory entries.

**Capability map serialization** (added in v3) encodes `directory_caps` and `process_caps` as separate counted lists of `(inode_id, capability)` or `(pid, capability)` pairs, where each capability is encoded as `rights (u32)`, `prefix_len (u32)`, prefix bytes, and quota flags.

`decode_persistent_state` validates the magic and version and returns `None` on any parse error; it never panics. Version 1 snapshots are accepted and migrated: mount state is rebuilt as a fresh `VirtioMountState`, inline file data is migrated via `migrate_inline_file_payloads()`, and the storage namespace is freshly allocated.

**Mutation journal:** Every mutation (mkdir, write, rename, unlink, mount, capability change, fsck) appends a line to `system/vfs/journal.log`:
```
[<tick>] <op> <detail>
```
The journal is bounded to `PAGE_SIZE x 8` bytes. When it overflows, `drain` removes bytes from the front up to the next newline boundary, preserving line alignment. The journal is a diagnostic and recovery aid, not a WAL: it is not replayed on boot. `persist_local_state()` is called after every mutation that modifies the inode tree or mount/capability tables.

### 2.9 `fsck` and Repair

`fsck_and_repair()` performs a structural consistency pass:

1. Scans every live directory inode and builds a reference count `Vec<u32>` for all inodes
2. Detects **dangling directory entries** (entries pointing to `None` inode slots) and removes them
3. Detects **orphaned inodes** (live inodes not referenced by any directory) and re-links them under `/lost+found`, creating the directory if needed, with names `inode-<id>` or `inode-<id>-<n>` if there are collisions
4. Recomputes `nlink` for all inodes from the final reference count and repairs any discrepancies
5. Calls `read_file_payload` for every file inode to get the true size and repairs `meta.size` if it differs

Results are returned in `VfsFsckReport`:
```rust
pub struct VfsFsckReport {
    pub inodes_scanned:             usize,
    pub dangling_entries_removed:   usize,
    pub orphaned_inodes_relinked:   usize,
    pub nlink_repairs:              usize,
    pub size_repairs:               usize,
    pub lost_found_created:         bool,
}
```
After a successful fsck, the journal is updated and `persist_local_state()` is called.

### 2.10 `VfsPolicy` — Memory File Size Limit

```rust
pub struct VfsPolicy {
    pub max_mem_file_size: Option<usize>,
}
```

`VfsPolicy::runtime_default()` inspects the kernel heap bounds at call time and sets the limit to `max(heap_bytes / 8, PAGE_SIZE)`. This is a soft architectural guard: every in-memory file write calls `ensure_file_size_allowed(new_size)` before the payload is committed to the persistence service. If no heap information is available, the policy is unbounded.

---

## 3. Platform Abstraction (`vfs_platform.rs`)

`vfs_platform.rs` is a thin `#[cfg]` shim that decouples the VFS from architecture-specific process management. On `x86_64`:

- `Pid` = `crate::process::Pid` (a newtype over `u32`)
- `current_pid()` calls `crate::process::current_pid()`
- `alloc_fd(pid, handle_id)` calls `process_manager().alloc_fd(...)`
- `get_fd_handle(pid, fd)` calls `process_manager().get_fd_handle(...)`
- `ticks_now()` calls `crate::pit::get_ticks()`
- `temporal_record_write(path, payload)` calls `crate::temporal::record_write(...)`

On `aarch64`:
- `Pid` = `u32` (no newtype)
- `current_pid()` returns a boot-time fixed PID
- File descriptor and temporal hooks are stubs

This design means `vfs.rs` itself has zero `#[cfg(target_arch)]` blocks — all arch differences are contained in one 307-line file.

---

## 4. Public VFS API Summary

All functions acquire the `DagSpinlock<DAG_LEVEL_VFS>` and perform `vfs.init()` before any operation.

### 4.1 Core Path Operations

| Function | Description |
|---|---|
| `vfs::mkdir(path)` | Create directory; dispatches to mount backend if applicable |
| `vfs::create_file(path)` | Allocate file inode and register in parent directory |
| `vfs::write_path(path, data)` | Overwrite-or-create file; records temporal write |
| `vfs::write_path_untracked(path, data)` | Same, without temporal record |
| `vfs::read_path(path, buf)` | Read file content; dispatches to mount backend if applicable |
| `vfs::unlink(path)` | Delete file or symlink; checks `nlink` before freeing inode |
| `vfs::list_dir(path, buf)` | List directory entries as space-separated names |
| `vfs::rename(old, new)` | Atomic rename; enforces cross-device check; updates open handle paths |
| `vfs::link(existing, new)` | Hard link; increments `nlink`; rejects directory targets |
| `vfs::symlink(target, link)` | Create symlink with inline target |
| `vfs::readlink(path)` | Return symlink target without following |
| `vfs::stat(path)` | Return `InodeMetadata` for the inode |

### 4.2 File Descriptor Operations

| Function | Description |
|---|---|
| `vfs::open_for_pid(pid, path, flags)` | Allocate a `Handle` and return an fd via `vfs_platform::alloc_fd` |
| `vfs::open_for_current(path, flags)` | Convenience: calls `open_for_pid` with `current_pid()` |
| `vfs::read_fd(pid, fd, buf)` | Validate capability, read via handle kind |
| `vfs::write_fd(pid, fd, data)` | Validate capability, write via handle kind |
| `vfs::seek_fd(pid, fd, pos)` | Set absolute seek position on handle |
| `vfs::close_fd(pid, fd)` | Release handle; frees fd slot via `vfs_platform::close_fd` |

### 4.3 Mount Operations

| Function | Description |
|---|---|
| `vfs::mount_virtio_block(path)` | Mount a VirtIO block device at `path`; creates `raw` and `partitions` sub-entries |
| `vfs::umount(path)` | Remove mount and all associated handles |
| `vfs::mounts()` | Return `Vec<MountStatus>` with contract info and health counters |

### 4.4 Capability Management

| Function | Description |
|---|---|
| `vfs::set_directory_capability(path, cap)` | Attach a capability to a directory inode |
| `vfs::clear_directory_capability(path)` | Remove a directory-inode capability |
| `vfs::set_process_capability(pid, cap)` | Set the root capability for a process |
| `vfs::clear_process_capability(pid)` | Remove process capability |
| `vfs::inherit_process_capability(parent, child, attenuate)` | Copy-and-optionally-narrow from parent to child |
| `vfs::effective_capability_for_pid(pid, path)` | Compute the effective capability after full chain attenuation |

### 4.5 Health and Integrity

| Function | Description |
|---|---|
| `vfs::health()` | Return `VfsHealth` snapshot (inode counts, bytes, open handles, mount health) |
| `vfs::fsck_and_repair()` | Full structural consistency pass + repair |
| `vfs::policy()` / `set_policy` | Query or update `VfsPolicy` |
| `fs::filesystem().health()` | Persistence-layer health (file count, bytes, thermal profile, event log) |
| `fs::filesystem().scrub_and_repair()` | Persistence-layer metadata repair |
| `fs::filesystem().metrics()` | Aggregate operation counters |
| `fs::filesystem().recent_events(n)` | Return up to `n` most recent persistence events |

---

## 5. Syscall Wrappers

`fs.rs` exposes thin wrappers that route through the VFS:

```rust
pub fn open(path: &str)                      -> Result<usize, &'static str>
pub fn read(fd: usize, buffer: &mut [u8])    -> Result<usize, &'static str>
pub fn write(fd: usize, data: &[u8])         -> Result<usize, &'static str>
pub fn close(fd: usize)                      -> Result<(), &'static str>
pub fn delete(path: &str)                    -> Result<(), &'static str>
pub fn list_dir(path: &str, buf: &mut [u8])  -> Result<usize, &'static str>
```

These use `crate::process::current_pid()` to obtain the calling process PID and dispatch to `vfs::open_for_current`, `vfs::read_fd`, `vfs::write_fd`, `vfs::close_fd`, `vfs::unlink`, and `vfs::list_dir` respectively.

---

## 6. Data Flow: Write Path (end-to-end)

A call to `fs::write(fd, data)` with an open file descriptor follows this chain:

```
fs::write(fd, data)
  |
  +-- vfs::write_fd(pid, fd, data)
       |
       +-- VFS lock acquired (DagSpinlock<DAG_LEVEL_VFS>)
            |
            +-- get_handle_mut(handle_id) -> Handle { kind: MemFile { inode }, flags, owner, capability }
            +-- revalidate_handle_access(pid, kind, Write)
            |    +-- resolve_authority_chain(path) -> chain of InodeIds
            |    +-- ensure_path_rights(pid, path, chain, Write)
            |         +-- resolve_capability_for_chain(pid, chain)  [attenuates along ancestors]
            +-- ensure_file_size_allowed(data.len())    [VfsPolicy check]
            +-- ensure_quota_allows(pid, chain, old_size, new_size, false)
            +-- vfs::write_file_payload(inode_id, data)
            |    +-- inode_payload_key(inode_id) -> "system/vfs/<namespace>/<id>"
            |    +-- fs::filesystem().handle_request(Request::write(key, data, root_cap))
            |         +-- FilesystemService::handle_write(key, data, cap)
            |              +-- check_permission(cap, key, WRITE)
            |              +-- check_quota(storage, cap, key, new_len)
            |              +-- RamStorage::write(key, data, tick)
            |                   +-- File::write(data, tick)  [updates hot_score, metadata]
            +-- record_mutation_journal("write", ...)
            +-- record_watch_event(Write, path, ...)  -> broadcast to subscribers
            +-- persist_local_state()  -> snapshot.bin written to persistence service
```

---

## 7. Security Properties

**No ambient authority.** A process that has never been granted a `FilesystemCapability` cannot read or write any file. The VFS `default_capability` defaults to the root capability at init time, but this can be replaced per-process immediately after fork/spawn.

**Attenuation-only delegation.** `FilesystemRights::attenuate` is a bitwise AND; `attenuate_capability` applied along a directory chain can only restrict, never expand, the effective rights for a given path.

**Scope confinement.** `key_prefix` scoping means a capability granting write access to `"data/"` physically cannot be used to write `"system/"`, even if the rights bits would permit it.

**Quota as a capability property.** Resource budgets are carried by the capability itself (`FilesystemQuota`), not by a global policy table. A sandboxed process receives a capability with a byte budget; all quota checks are performed against that budget without any global namespace lock.

**Cross-device isolation.** The VFS rejects cross-device renames and hard links at the mount boundary. A file in the in-memory inode tree and a file in a VirtIO mount cannot be hard-linked.

**Symlink loop protection.** Both the main VFS and the VirtIO backend independently enforce a depth limit of 16 recursive symlink expansions before returning `Err("Symlink loop detected")`.

---

## 8. Interaction with Other Subsystems

| Subsystem | Relationship |
|---|---|
| `interrupt_dag` | VFS lock is at `DAG_LEVEL_VFS = 5`; acquired from `DAG_LEVEL_THREAD = 8` |
| `ipc` | Watch notifications sent via `ipc::send`; capability transfer via `to_ipc_capability` / `from_ipc_capability` |
| `temporal` | Every tracked `write_path` call invokes `temporal_record_write` for durable replay |
| `virtio_blk` | VirtIO backend calls `virtio_blk::read_at` / `write_at` for raw block I/O |
| `wait_free_ring` | Watch events pushed into `TELEMETRY_RING` for lock-free observability |
| `paging` | `PAGE_SIZE` used for retention policy and journal size budget |
| `pit` | `get_ticks()` provides timestamps for all events and journal entries |
| `capability` | Channel capability resolution for watch notification channels |
| `process` | `current_pid()`, `alloc_fd`, `get_fd_handle`, `close_fd` for fd lifecycle |

See also: `docs/capability/capnet.md` for capability theory, `docs/storage/oreulius-persistence.md` for the temporal adapter layer, `docs/ipc/oreulius-ipc.md` for the IPC channel model.