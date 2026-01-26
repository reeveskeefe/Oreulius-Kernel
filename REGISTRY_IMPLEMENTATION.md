# Service Registry Implementation

## Overview

The Oreulia service registry implements **introduction-based service discovery** - a capability-native approach that eliminates ambient authority from service lookup.

## Core Innovation: Introduction Protocol

### Traditional Approach (What We Avoid)
```
Client → "Give me the filesystem service" → Global Registry → Returns capability
❌ Ambient authority: any process can discover any service
❌ No audit trail of who connects to what
❌ Services can't control who accesses them
```

### Our Approach: Capability-Based Introduction
```
Client → "Introduce me to filesystem" → Introducer Cap → Registry → Checks rights → Returns capability
✅ Explicit delegation: must have introducer capability
✅ Auditable: every introduction is tracked
✅ Revocable: introducers can be exhausted or revoked
✅ Attenuatable: introducers can have limited rights
```

## Architecture

### Service Types (registry.rs)
```rust
pub enum ServiceType {
    Filesystem,      // File storage
    Persistence,     // Logs and snapshots
    Network,         // Network I/O
    Timer,           // Clock and timers
    Console,         // Terminal I/O
    Custom(u32),     // Extensible user services
}
```

### Service Registration
```rust
pub struct ServiceOffer {
    service_type: ServiceType,
    channel: ChannelId,             // How to communicate with service
    namespace: ServiceNamespace,     // Production/Test/Sandbox
    metadata: ServiceMetadata,       // Version, max connections, provider PID
    active_connections: usize,       // Current connection count
}
```

Services register themselves with the registry, providing a channel for communication.

### Introducer Capabilities
```rust
pub struct IntroducerCapability {
    cap_id: u32,
    allowed_services: u32,           // Bitset of allowed service types
    max_introductions: usize,        // Introduction quota
    introductions_used: usize,       // Introductions performed
    scope: IntroductionScope,        // Global/Namespaced/TypeRestricted
    owner: ProcessId,                // Who owns this introducer
}
```

#### Introducer Types

**Root Introducer**
- Unlimited introductions
- All service types allowed
- Global scope
- Typically given to init process only

**Restricted Introducer**
- Limited number of introductions (e.g., 3)
- Subset of service types (e.g., only Filesystem + Timer)
- Scoped to specific namespace
- Delegated to applications

### Introduction Scope
```rust
pub enum IntroductionScope {
    Global,                              // Any namespace
    Namespaced(ServiceNamespace),        // Specific namespace only
    TypeRestricted(u32),                 // Bitset of allowed types
}
```

### Service Namespaces
```rust
pub enum ServiceNamespace {
    Production,      // Production services
    Test,            // Test/development
    Sandbox,         // Isolated sandbox
    Custom(u32),     // User-defined namespaces
}
```

Namespaces enable:
- Multiple service instances
- Test isolation
- Sandboxed execution
- Multi-tenant scenarios

## Protocol Flow

### 1. Service Registration
```rust
// Service provider creates a channel
let (cap1, cap2) = ipc::ipc().create_channel(ProcessId(100))?;

// Register the service
let metadata = ServiceMetadata::new(1, 10, ProcessId(100));
let offer = ServiceOffer::new(
    ServiceType::Filesystem,
    cap1.channel_id,
    ServiceNamespace::Production,
    metadata,
);
registry::registry().register_service(offer)?;
```

### 2. Creating Introducers
```rust
// Root introducer (unlimited)
let root = registry::registry().create_root_introducer(ProcessId(1))?;

// Restricted introducer
let allowed = (1 << ServiceType::Filesystem.as_u32())
            | (1 << ServiceType::Timer.as_u32());
let restricted = registry::registry().create_introducer(
    allowed,
    3,  // Max 3 introductions
    IntroductionScope::Global,
    ProcessId(201),
)?;
```

### 3. Requesting Introduction
```rust
// Create request
let request = IntroductionRequest::new(
    ServiceType::Filesystem,
    ProcessId(202),
);

// Perform introduction
let response = registry::registry().introduce(request, &mut introducer)?;

match response.status {
    IntroductionStatus::Success => {
        // Use response.service_channel to communicate
    }
    _ => {
        // Handle error
    }
}
```

## Security Properties

### No Ambient Authority
- Can't discover services without an introducer capability
- Initial introducer must be explicitly delegated
- Services are hidden unless you have introduction rights

### Hierarchical Delegation
```
Root Introducer (init process)
    ├── App Launcher Introducer (all services, 100 intros)
    │   ├── App A Introducer (fs+network, 10 intros)
    │   └── App B Introducer (fs only, 5 intros)
    └── System Monitor Introducer (all services, unlimited, read-only)
```

### Auditable Connections
- Each introduction is tracked
- `introductions_used` counter provides audit trail
- Can track who introduced whom to what

### Revocable Access
- Introducers can be exhausted (max_introductions)
- Services can limit connections (max_connections)
- Namespaces can be isolated

### Attestation Through Attenuation
```rust
// Attenuate introducer before delegation
let attenuated = introducer.attenuate(
    allowed_services & (1 << ServiceType::Filesystem.as_u32()),  // Reduce services
    5,  // Reduce quota
    IntroductionScope::Namespaced(ServiceNamespace::Test),  // Restrict scope
);
```

## Shell Commands

### `svc-register <type>`
Register a test service.
```
> svc-register fs
Service registered: Filesystem on channel 0
```

### `svc-request <type>`
Request an introduction to a service.
```
> svc-request fs
Introduction successful!
  Service: Filesystem
  Channel: 0
  Version: 1
  Max connections: 10
```

### `svc-list`
List all registered services.
```
> svc-list
Registered Services:
-------------------
  Filesystem (prod) - 2 connections
  Timer (prod) - 0 connections
```

### `svc-stats`
Show registry statistics.
```
> svc-stats
Service Registry Statistics:
---------------------------
Services: 2 / 64
Introducers: 3 / 32
```

### `intro-demo`
Full demonstration of introduction protocol.

#### Demo Steps:
1. **Register Filesystem service** - Creates channel and registers service
2. **Create root introducer** - Unlimited access for init process
3. **First introduction** - Process 201 connects to filesystem
4. **Create restricted introducer** - Max 3 introductions, limited service types
5. **Use restricted introducer** - Successfully introduces process 202
6. **Attempt forbidden service** - Correctly denied (not in allowed_services)
7. **Show statistics** - Display final registry state

## Implementation Details

### Resource Limits
```rust
const MAX_SERVICES: usize = 64;        // Maximum registered services
const MAX_INTRODUCERS: usize = 32;     // Maximum active introducers
const MAX_INTRODUCTIONS_DEFAULT: usize = 100;
```

### Service Metadata
```rust
pub struct ServiceMetadata {
    version: u32,                    // Service version
    max_connections: usize,          // Connection limit
    provider_pid: ProcessId,         // Provider process ID
}
```

### Error Handling
```rust
pub enum IntroductionStatus {
    Success,
    ServiceNotFound,         // No service of that type
    PermissionDenied,        // Introducer doesn't allow this service
    ServiceUnavailable,      // Max connections reached
    IntroducerExhausted,     // Introduction quota used up
    InvalidNamespace,        // Namespace not accessible
}
```

## Use Cases

### Application Launch
```rust
// App launcher has introducer for common services
let fs_intro = IntroductionRequest::new(ServiceType::Filesystem, app_pid);
let net_intro = IntroductionRequest::new(ServiceType::Network, app_pid);

registry.introduce(fs_intro, &mut launcher_introducer)?;
registry.introduce(net_intro, &mut launcher_introducer)?;

// Launcher's introducer quota decreased
assert!(launcher_introducer.introductions_used == 2);
```

### Service Isolation
```rust
// Production app gets production services
let prod_request = IntroductionRequest::with_namespace(
    ServiceType::Filesystem,
    ServiceNamespace::Production,
    app_pid,
);

// Test app gets test services (separate data)
let test_request = IntroductionRequest::with_namespace(
    ServiceType::Filesystem,
    ServiceNamespace::Test,
    test_app_pid,
);
```

### Resource Limiting
```rust
// Guest user gets limited introducer
let guest_introducer = registry.create_introducer(
    (1 << ServiceType::Filesystem.as_u32()),  // Filesystem only
    5,                                         // 5 introductions max
    IntroductionScope::Namespaced(ServiceNamespace::Sandbox),
    guest_pid,
)?;
```

## Comparison to Traditional Approaches

### Unix/Linux (ambient authority)
- `/etc/services`, `/proc`, `/sys` globally accessible
- No capability model
- Everything visible to all processes
- Access control via UID/GID (coarse-grained)

### Plan 9 (namespace-based)
- Per-process namespace
- Better than global namespace
- Still no explicit delegation
- Mount points are ambient within namespace

### Oreulia (introduction-based)
- No ambient authority
- Explicit capability delegation
- Auditable introductions
- Hierarchical attenuation
- Service discovery IS access control

## Future Enhancements

### Lazy Service Startup
Services registered as offers but not started until first introduction.

### Service Versioning
Multiple versions of same service type in same namespace.

### Introduction Callbacks
Services can accept/reject specific introduction requests.

### Capability Revocation
Track all introducers and revoke entire delegation trees.

### Distributed Registry
Introduction protocol works across machines (network transparency).

## Files Modified

1. **kernel/src/registry.rs** (718 lines)
   - ServiceRegistry with 64 service slots
   - IntroducerCapability with rights management
   - Introduction protocol implementation
   - ServiceType, ServiceNamespace, IntroductionScope enums

2. **kernel/src/commands.rs** (1125+ lines)
   - `svc-register`, `svc-request`, `svc-list`, `svc-stats` commands
   - `intro-demo` - Full introduction protocol demonstration
   - Helper implementations for error display

3. **kernel/src/lib.rs**
   - Added `registry` module
   - Initialize registry service in `rust_main()`

## Testing

Build and run:
```bash
cd kernel
./build.sh
qemu-system-i386 -cdrom oreulia.iso
```

Try the commands:
```
> intro-demo          # See full protocol demonstration
> svc-register fs     # Register a filesystem service
> svc-request fs      # Request introduction to filesystem
> svc-list            # List all services
> svc-stats           # Show registry statistics
```

## Summary

The service registry demonstrates that **service discovery can be a first-class capability operation**, not a privileged lookup in a global namespace. By treating introduction as a delegable, auditable, revocable operation, we:

1. **Eliminate ambient authority** - Can't discover what you're not introduced to
2. **Enable hierarchical delegation** - Introducers can create weaker introducers
3. **Provide audit trails** - Every introduction is tracked
4. **Support isolation** - Namespaces separate production/test/sandbox
5. **Allow resource limiting** - Services and introducers have quotas

This is more than a registry - it's a **capability-native approach to service architecture**.
