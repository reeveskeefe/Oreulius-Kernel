# Oreulia Filesystem Implementation

## Overview

This document describes the implementation of the Oreulia filesystem v0, a persistence-first, capability-gated filesystem service based on the specifications in `docs/oreulia-filesystem.md`.

## Implementation Status

✅ **Complete** - All core features from the v0 specification have been implemented.

## Architecture

### Core Modules

1. **`kernel/src/fs.rs`** - Filesystem implementation
   - File objects with bounded storage (64 KiB max)
   - Flat key-value namespace
   - Capability-based access control
   - Message-based request/response protocol
   - RAM-backed storage (for v0)

2. **`kernel/src/persistence.rs`** - Persistence layer
   - Append-only log with record structure
   - Snapshot support for point-in-time state
   - CRC32 integrity checking
   - Store capabilities with rights enforcement

3. **`kernel/src/commands.rs`** - User interface commands
   - `fs-write` - Create/update files
   - `fs-read` - Read file contents
   - `fs-delete` - Delete files
   - `fs-list` - List all files
   - `fs-stats` - Show filesystem statistics

## Key Features

### No Ambient Authority

All filesystem access requires explicit capabilities:

```rust
// Create a capability with specific rights
let cap = fs::filesystem().create_capability(
    cap_id,
    FilesystemRights::read_write(),
    Some(prefix),  // Optional key prefix for scoped access
);
```

### Capability Rights

- `READ` - Read files by key
- `WRITE` - Create/update files
- `DELETE` - Delete files
- `LIST` - List file keys

Rights can be attenuated (reduced) but never elevated.

### Flat Namespace

Keys are simple strings (e.g., "config/app.json", "data/state"):
- Maximum key length: 256 bytes
- No hierarchical directories
- Use prefixes for logical grouping

### Message Protocol

All operations use request/response messages:

```rust
// Create a write request
let request = Request::write(key, data, capability)?;

// Process the request
let response = filesystem().handle_request(request);

// Check the result
match response.status {
    ResponseStatus::Ok => { /* success */ }
    ResponseStatus::Error(e) => { /* handle error */ }
}
```

### Storage Constraints (v0)

- Maximum files: 256
- Maximum file size: 64 KiB
- RAM-backed (in-memory only)
- Fixed-size allocation

## Usage Examples

### Basic File Operations

```rust
use oreulia_kernel::fs::{self, FileKey, FilesystemRights, Request};

// Create a capability
let cap = fs::filesystem().create_capability(
    1,
    FilesystemRights::all(),
    None,
);

// Write a file
let key = FileKey::new("test.txt").unwrap();
let request = Request::write(key, b"Hello, Oreulia!", cap).unwrap();
let response = fs::filesystem().handle_request(request);

// Read the file
let request = Request::read(key, cap);
let response = fs::filesystem().handle_request(request);
println!("{}", core::str::from_utf8(response.get_data()).unwrap());

// Delete the file
let request = Request::delete(key, cap);
fs::filesystem().handle_request(request);
```

### Scoped Access

```rust
// Create a scoped capability (only access keys with prefix "app/")
let prefix = FileKey::new("app/").unwrap();
let scoped_cap = fs::filesystem().create_capability(
    2,
    FilesystemRights::read_only(),
    Some(prefix),
);

// This works
let key = FileKey::new("app/config.json").unwrap();
let request = Request::read(key, scoped_cap);
fs::filesystem().handle_request(request);

// This fails (wrong prefix)
let key = FileKey::new("system/state.dat").unwrap();
let request = Request::read(key, scoped_cap);
// Returns PermissionDenied
```

### Shell Commands

From the Oreulia shell:

```bash
# Write a file
> fs-write config.txt "server_port=8080"
File written successfully: config.txt

# Read a file
> fs-read config.txt
File contents: server_port=8080

# List all files
> fs-list
Files:
config.txt

# Show statistics
> fs-stats
Filesystem statistics:
  Files: 1 / 256

# Delete a file
> fs-delete config.txt
File deleted: config.txt
```

## Integration with Persistence

The filesystem integrates with the persistence layer for durability:

### Log Records

Filesystem operations can be logged for replay:

```rust
use oreulia_kernel::persistence::{self, LogRecord, RecordType};

// Log a filesystem operation
let payload = b"fs-write: config.txt";
let record = LogRecord::new(RecordType::FilesystemOp, payload)?;

let mut persistence = persistence::persistence().lock();
let offset = persistence.append_log(&capability, record)?;
```

### Snapshots

The filesystem state can be captured in snapshots:

```rust
// Serialize filesystem state (simplified)
let state_data = serialize_filesystem_state();

// Write a snapshot
let mut persistence = persistence::persistence().lock();
persistence.write_snapshot(&capability, &state_data, last_log_offset)?;
```

### Recovery

On boot, the filesystem can recover from snapshots + logs:

1. Load latest snapshot
2. Replay log records from `snapshot.last_offset`
3. Reconstruct filesystem state

## Design Decisions

### Why RAM-backed for v0?

- Simpler implementation to get MVP working
- No dependency on block device drivers
- Easy to test and debug
- Can be extended to disk-backed in v1

### Why fixed-size arrays?

- No heap allocation in kernel (no_std)
- Predictable memory usage
- Simple implementation
- Bounded resources prevent resource exhaustion

### Why message-based protocol?

- Aligns with Oreulia's capability model
- Enables async IPC (future)
- Clear authority boundaries
- Testable in isolation

### Why flat namespace?

- Keeps v0 simple
- Sufficient for MVP use cases
- Hierarchies can be layered on top
- Reduces complexity of permission checks

## Future Enhancements (v1+)

### Hierarchical Namespaces

Support directory structures:

```rust
// Create a directory
fs.mkdir("app/")?;

// Nested paths
let key = FileKey::new("app/config/server.json")?;
```

### Disk-backed Storage

Integrate with virtio block device:

```rust
// Persist to disk
fs.sync()?;

// Mount from disk
fs.mount("/dev/vda1")?;
```

### Quotas

Limit storage per capability:

```rust
let quota = Quota::new(10 * 1024 * 1024); // 10 MiB
let cap = fs.create_capability_with_quota(id, rights, quota);
```

### Shared File Capabilities

Share files between components:

```rust
// Component A creates a file
let file_cap = fs.create_file_capability(key, rights)?;

// Component B receives capability via IPC
send_capability(file_cap)?;
```

### Metadata

Enhanced file metadata:

```rust
pub struct FileMetadata {
    pub size: usize,
    pub created: Timestamp,
    pub modified: Timestamp,
    pub owner: CapabilityId,
    pub permissions: Permissions,
}
```

## Testing

### Manual Testing

Build and run the kernel:

```bash
cd kernel
./build.sh
qemu-system-i386 -cdrom oreulia.iso
```

Test filesystem commands:

```
> fs-write test.txt hello
> fs-read test.txt
> fs-list
> fs-stats
> fs-delete test.txt
```

### Integration Tests

Add to `kernel/src/fs.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filesystem_operations() {
        let fs = FilesystemService::new();
        let cap = fs.create_capability(1, FilesystemRights::all(), None);
        
        // Write
        let key = FileKey::new("test.txt").unwrap();
        let req = Request::write(key, b"data", cap).unwrap();
        let resp = fs.handle_request(req);
        assert!(matches!(resp.status, ResponseStatus::Ok));
        
        // Read
        let req = Request::read(key, cap);
        let resp = fs.handle_request(req);
        assert_eq!(resp.get_data(), b"data");
        
        // Delete
        let req = Request::delete(key, cap);
        let resp = fs.handle_request(req);
        assert!(matches!(resp.status, ResponseStatus::Ok));
    }
}
```

## Performance Characteristics

### v0 (RAM-backed)

- **Write**: O(n) where n = number of files (linear search)
- **Read**: O(n) linear search
- **Delete**: O(n) linear search
- **List**: O(n) iteration
- **Space**: Fixed 256 files × 64 KiB = 16 MiB maximum

### Future Optimizations

- Hash map for O(1) lookups
- B-tree for ordered keys
- Caching layer
- Indexed metadata

## Security Considerations

### Capability Enforcement

All operations check:
1. Required rights present in capability
2. Key prefix matches (if scoped)
3. No forging of capabilities

### Resource Limits

- Bounded file count (256)
- Bounded file size (64 KiB)
- No unbounded allocation
- Prevents denial of service

### Data Integrity

- CRC32 checksums in log records
- Atomic operations (write is all-or-nothing)
- Verification on log replay

## References

- [Oreulia Filesystem Specification](../docs/oreulia-filesystem.md)
- [Oreulia Persistence Specification](../docs/oreulia-persistence.md)
- [Oreulia Capabilities Specification](../docs/oreulia-capabilities.md)
- [Oreulia MVP](../docs/oreulia-mvp.md)

## Contributors

Implementation by the Oreulia team, January 2026.
