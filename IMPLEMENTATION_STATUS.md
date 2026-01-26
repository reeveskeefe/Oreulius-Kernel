# Oreulia OS - Implementation Status

## Overview

Oreulia is a capability-based operating system built from the ground up with security and explicit delegation as first principles. All system services operate through capabilities, with no ambient authority.

## Completed Components

### 1. Filesystem v0 ✅
**Status:** Complete (850 lines)  
**Location:** `kernel/src/fs.rs`

- Flat namespace with 256 files max
- 64 KiB per file (RAM-backed)
- Capability-gated access (READ/WRITE/DELETE/LIST rights)
- Request/Response message protocol
- CRUD operations with rights enforcement
- IPC integration for capability transfer

**Commands:** `fs-write`, `fs-read`, `fs-delete`, `fs-list`, `fs-stats`

### 2. Persistence v0 ✅
**Status:** Complete (430 lines)  
**Location:** `kernel/src/persistence.rs`

- Append-only logs (1024 records)
- Point-in-time snapshots (1 MiB max)
- CRC32 integrity verification
- StoreCapability with rights (READ/WRITE)
- Record versioning and magic numbers

### 3. IPC v0 ✅
**Status:** Complete (750 lines)  
**Location:** `kernel/src/ipc.rs`

- Bounded channels (32 messages per channel)
- Bidirectional message passing
- 4 KiB messages with 16 capability slots
- ChannelCapability with Send/Receive rights
- Non-blocking operations (WouldBlock error)
- 128 channels maximum

**Commands:** `ipc-create`, `ipc-send`, `ipc-recv`, `ipc-stats`

### 4. Capability Passing ✅
**Status:** Complete (~310 lines)  
**Location:** `kernel/src/ipc.rs`, `kernel/src/fs.rs`

- Type-safe capability transfer through IPC
- CapabilityType enum (Generic, Channel, Filesystem, Store)
- Filesystem capability serialization/deserialization
- Rights preservation across IPC boundaries
- Interactive demo with 9-step workflow

**Commands:** `cap-demo <key>`

### 5. Service Registry v0 ✅
**Status:** Complete (718 lines)  
**Location:** `kernel/src/registry.rs`

- **Introduction-based service discovery**
- No ambient authority (must have introducer capability)
- IntroducerCapability with hierarchical delegation
- ServiceType enum (Filesystem, Persistence, Network, Timer, Console, Custom)
- ServiceNamespace (Production, Test, Sandbox, Custom)
- IntroductionScope (Global, Namespaced, TypeRestricted)
- Auditable introductions with quota tracking
- 64 max services, 32 max introducers

**Commands:** `svc-register`, `svc-request`, `svc-list`, `svc-stats`, `intro-demo`

## Architecture Highlights

### Capability Model

Everything is a capability:
- **Filesystem operations** require FilesystemCapability
- **IPC communication** requires ChannelCapability
- **Service discovery** requires IntroducerCapability
- **Persistence access** requires StoreCapability

Rights are:
- **Enforceable** - Checked at operation time
- **Delegable** - Can be passed to other processes
- **Attenuatable** - Can reduce rights when delegating
- **Revocable** - Quota exhaustion, explicit revocation

### No Ambient Authority

Traditional OS:
```c
fd = open("/etc/passwd", O_RDWR);  // Ambient authority: FS namespace is global
```

Oreulia:
```rust
let req = Request::read(key, fs_cap)?;  // Must have capability!
let resp = filesystem().handle_request(req);
```

Can't even discover a file exists without a capability to access it.

### Introduction Protocol (New!)

Traditional service discovery:
```
Client → "Give me service X" → Global registry → Returns handle
```

Oreulia introduction protocol:
```
Client → "Introduce me to service X" → Introducer cap checks rights → Registry → Returns channel
```

Key properties:
- **No global lookup** - Services are hidden unless you're introduced
- **Hierarchical delegation** - Introducers create weaker introducers
- **Auditable** - Every introduction tracked
- **Resource limited** - Introducers have quotas
- **Namespace isolated** - Production/Test/Sandbox separation

## Build System

**Target:** i686 (32-bit x86)  
**Boot:** Multiboot via GRUB  
**Language:** Rust (no_std)  
**Build tools:** cargo, nasm, x86_64-elf-ld, genisoimage

Build steps:
```bash
cd kernel
./build.sh       # Builds ISO
./run.sh         # Runs in QEMU
```

## Documentation

1. **FILESYSTEM_IMPLEMENTATION.md** - Complete filesystem design and API
2. **FILESYSTEM_IMPLEMENTATION_SUMMARY.md** - Quick reference
3. **IPC_IMPLEMENTATION_SUMMARY.md** - IPC system overview
4. **CAPABILITY_PASSING_IMPLEMENTATION.md** - Capability transfer guide
5. **REGISTRY_IMPLEMENTATION.md** - Introduction protocol deep dive
6. **REGISTRY_IMPLEMENTATION_SUMMARY.md** - Service registry quick ref

## Shell Commands

### Filesystem
- `fs-write <key> <data>` - Create/update file
- `fs-read <key>` - Read file contents
- `fs-delete <key>` - Delete file
- `fs-list` - List all files
- `fs-stats` - Show filesystem statistics

### IPC
- `ipc-create` - Create new channel
- `ipc-send <chan> <msg>` - Send message
- `ipc-recv <chan>` - Receive message
- `ipc-stats` - Show IPC statistics

### Service Registry
- `svc-register <type>` - Register test service
- `svc-request <type>` - Request service introduction
- `svc-list` - List registered services
- `svc-stats` - Show registry statistics

### Demos
- `cap-demo <key>` - 9-step capability passing demonstration
- `intro-demo` - 7-step introduction protocol demonstration

### System
- `help` - Show all commands
- `clear` - Clear screen
- `echo <text>` - Echo text

## Code Statistics

```
Component              Lines    Purpose
----------------      ------    -------
fs.rs                    850    Filesystem with capabilities
persistence.rs           430    Logs and snapshots
ipc.rs                   750    Channel-based message passing
registry.rs              718    Introduction protocol
commands.rs            1,125    Shell interface and demos
Total Core            ~3,900    Core OS functionality
```

## Design Principles

### 1. Capability-Based Security
Every operation requires an explicit capability. No ambient authority.

### 2. Explicit Delegation
Rights are never acquired implicitly. Must be explicitly passed.

### 3. Principle of Least Authority (POLA)
Capabilities can be attenuated (reduced) when delegated.

### 4. Auditable Operations
All critical operations (file access, IPC, introductions) are trackable.

### 5. Resource Limits
Fixed-size arrays, bounded queues, quota-based access.

### 6. No_std Environment
No heap allocation, no standard library, runs on bare metal.

## Testing

Boot the system:
```bash
cd kernel
./run.sh
```

Try the demos:
```
> cap-demo myfile
> intro-demo
> fs-write test "Hello, Oreulia!"
> fs-read test
> svc-register fs
> svc-request fs
> svc-list
```

## What Makes This Different

### Compared to Linux/Unix
- **Linux:** Global namespaces (`/proc`, `/sys`, `systemd`)
- **Oreulia:** No global namespace, introduction protocol

### Compared to Plan 9
- **Plan 9:** Per-process namespaces
- **Oreulia:** No namespaces, capabilities only

### Compared to seL4
- **seL4:** Microkernel with capability passing
- **Oreulia:** Similar goals, but with service-level introduction protocol

### Compared to Genode
- **Genode:** Component-based, parent-child sessions
- **Oreulia:** Peer-to-peer via introducers, no hierarchy required

## Future Work

### Near-term
- [ ] Process manager (create/destroy processes)
- [ ] WASM runtime (run capability-aware WASM modules)
- [ ] Lazy service startup (start services on first introduction)
- [ ] Service versioning (multiple versions of same service)

### Medium-term
- [ ] Network stack (with NetworkCapability)
- [ ] Block device driver (with DeviceCapability)
- [ ] Virtual memory management
- [ ] Multi-core support

### Long-term
- [ ] Distributed introduction (network-transparent service discovery)
- [ ] Capability revocation (revoke delegation trees)
- [ ] Formal verification (prove security properties)
- [ ] WASM-based service isolation

## Key Insights

1. **Service discovery IS access control** - Can't discover what you're not introduced to
2. **Introduction is a capability operation** - First-class, delegable, auditable
3. **Hierarchical without hierarchy** - Peer-to-peer via introducer delegation
4. **Capability-native architecture** - Not bolted on, designed from the start

## Current Status

✅ **Filesystem:** Complete with capability-based access  
✅ **Persistence:** Complete with logs and snapshots  
✅ **IPC:** Complete with channel-based messaging  
✅ **Capability Transfer:** Complete with type-safe passing  
✅ **Service Registry:** Complete with introduction protocol  
✅ **Build System:** Working, produces bootable ISO  
✅ **Documentation:** Comprehensive guides for all components  
✅ **Shell Interface:** All features accessible via commands  
✅ **Demos:** Interactive demonstrations of key features

**Build:** ✅ Success  
**ISO:** oreulia.iso (42 MB)  
**Boot:** QEMU i386

## Repository Structure

```
oreulia/
├── kernel/
│   ├── src/
│   │   ├── fs.rs              # Filesystem v0
│   │   ├── persistence.rs     # Persistence v0
│   │   ├── ipc.rs             # IPC v0 + capability passing
│   │   ├── registry.rs        # Service registry v0 (NEW!)
│   │   ├── commands.rs        # Shell commands + demos
│   │   ├── lib.rs             # Kernel entry point
│   │   ├── vga.rs             # VGA text mode
│   │   ├── keyboard.rs        # PS/2 keyboard
│   │   └── memory.rs          # Memory management
│   ├── build.sh               # Build script
│   ├── run.sh                 # QEMU launcher
│   └── oreulia.iso            # Bootable ISO (42 MB)
├── docs/
│   └── *.md                   # Design documents
├── FILESYSTEM_IMPLEMENTATION.md
├── IPC_IMPLEMENTATION_SUMMARY.md
├── CAPABILITY_PASSING_IMPLEMENTATION.md
├── REGISTRY_IMPLEMENTATION.md         # (NEW!)
├── REGISTRY_IMPLEMENTATION_SUMMARY.md # (NEW!)
└── README.md
```

---

**Oreulia OS** - A capability-based operating system where service discovery is a first-class capability operation.
