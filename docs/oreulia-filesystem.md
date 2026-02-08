# Oreulia — Virtual File System (VFS)

**Status:** Implemented Base (Feb 8, 2026)

Oreulia implements a hierarchical **Virtual File System (VFS)** that provides a unified interface for files, directories, and devices. Unlike the early "flat store" vision, the current implementation supports standard Unix-like operations (`open`, `read`, `write`, `mount`), enabling a familiar environment for users and applications.

---

## 1. Architecture

The VFS allows different filesystems to be mounted into a single global tree.

- **Unified Namespace**: All resources start from root `/`.
- **Mount Points**: Different filesystems (e.g., RamFS, VirtIO-Block) can be mounted at specific paths (e.g., `/mnt/disk`).
- **Inodes**: Internal representation of file metadata (type, size, permissions).

### 1.1 Supported Operations

The VFS primitive supports standard operations:
- `open(path, flags)` -> `fd`
- `read(fd, buffer)`
- `write(fd, buffer)`
- `close(fd)`
- `mkdir(path)`
- `list(path)`
- `stat(path)`

---

## 2. File Descriptors & Capabilities

While the kernel implements a standard VFS, access is still capability-gated:

- **Root Capability**: A process is given a `FileDescriptor` capability acting as its root or CWD.
- **Relative Paths**: Access is typically relative to an owned directory capability.
- **No Ambient Authority**: A purely sandboxed Wasm app cannot "guess" `/etc/passwd` unless explicitly granted a capability to that file or directory.

---

## 3. Implemented Filesystems

### 3.1 RamFS
The default in-memory filesystem used for root `/` on boot.
- Fast, non-persistent.
- Supports directories and files.

### 3.2 VirtIO-Block (Persistent)
Driver for VirtIO block devices (e.g., QEMU disk images).
- Allows mounting physical (virtual) disks.
- Supports reading partition tables (MBR/GPT).
- **Status**: Block driver implemented; filesystem logic (FAT/Ext2) in progress on top of block layer.

---

## 4. Usage

### 4.1 Shell Commands
The shell provides direct access to VFS operations:

```bash
> vfs-mkdir /data
> vfs-write /data/test.txt "Hello World"
> vfs-cat /data/test.txt
Hello World
> vfs-ls /data
test.txt  [File]  11 bytes
```

### 4.2 WebAssembly Interface
Wasm modules interact with the file system via imported host functions:
- `fs_open(path_ptr, path_len, flags) -> fd`
- `fs_read(fd, buf_ptr, len) -> bytes_read`

This mapping maintains the sandbox while offering powerful IO.

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