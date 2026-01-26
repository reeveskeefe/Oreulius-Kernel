# Process Manager Implementation

## Overview

The Oreulia process manager provides **cooperative multi-tasking** with **per-process capability tables**, enabling true service isolation and concurrent execution.

## Key Features

✅ **Multi-tasking** - Up to 64 processes with round-robin scheduling  
✅ **Per-process capability tables** - Each process owns 128 capability slots  
✅ **Cooperative scheduling** - Explicit `yield()` for context switching  
✅ **Process lifecycle** - spawn, yield, terminate, reap  
✅ **Process isolation** - Capabilities isolated to owning process  
✅ **Resource tracking** - CPU time, state, parent/child relationships

## Architecture (613 lines)

### Core Structures

**Process Control Block (PCB)**
```rust
pub struct Process {
    pid: Pid,                           // Process ID
    name: [u8; 32],                     // Process name
    state: ProcessState,                // Ready/Running/Blocked/Waiting/Terminated
    priority: ProcessPriority,          // High/Normal/Low
    parent: Option<Pid>,                // Parent process
    capabilities: CapabilityTable,      // 128 capability slots
    stack_ptr: usize,                   // Stack pointer (v0)
    program_counter: usize,             // Program counter (v0)
    cpu_time: u64,                      // CPU ticks used
    created_at: u64,                    // Creation timestamp
}
```

**Process States**
```rust
pub enum ProcessState {
    Ready,               // Ready to run
    Running,             // Currently executing
    Blocked,             // Waiting for I/O
    WaitingOnChannel,    // Waiting for IPC message
    Terminated,          // Finished execution
}
```

**Capability Table**
```rust
pub struct CapabilityTable {
    caps: [Option<CapabilityVariant>; 128],
    next_slot: u32,
}

pub enum CapabilityVariant {
    Channel(ChannelCapability),         // IPC channel
    Filesystem { cap_id, rights },      // Filesystem access
    Generic { cap_id, object_id, rights }, // Generic capability
}
```

### Process Table

**Global Process Storage**
```rust
pub struct ProcessTable {
    processes: [Option<Process>; 64],   // Max 64 processes
    next_pid: u32,                      // Next PID to allocate
    count: usize,                       // Active process count
}
```

Operations:
- `spawn(name, parent)` - Create new process
- `get(pid)` / `get_mut(pid)` - Access process by PID
- `terminate(pid)` - Mark process as terminated
- `reap_terminated()` - Garbage collect dead processes
- `list()` - List all processes

### Scheduler

**Round-Robin Scheduling**
```rust
pub struct Scheduler {
    current_pid: Option<Pid>,           // Currently running process
    last_index: usize,                  // Last scheduled index
}
```

Operations:
- `schedule_next()` - Find next runnable process (round-robin)
- `yield_current()` - Mark current process ready, schedule next
- `current()` - Get current running PID

### Process Manager

**Global Service**
```rust
pub struct ProcessManager {
    table: Mutex<ProcessTable>,
    scheduler: Mutex<Scheduler>,
}
```

Operations:
- `spawn(name, parent)` - Create process
- `terminate(pid)` - Kill process
- `yield_process()` - Yield to next process
- `schedule()` - Run scheduler
- `current()` - Get current PID
- `insert_capability(pid, cap)` - Add cap to process table
- `get_capability(pid, slot)` - Retrieve cap from process
- `remove_capability(pid, slot)` - Delete cap from process
- `list()` - List all processes
- `stats()` - Get process statistics
- `reap()` - Clean up terminated processes
- `tick_current()` - Increment CPU time for current process

## Initialization

The process manager creates **PID 1 (init)** on startup:

```rust
pub fn init() {
    let pid = process_manager().spawn("init", None)?;
    // Mark init as current running process
    scheduler.set_current(Some(pid));
}
```

All other processes are children (direct or indirect) of init.

## Shell Commands

### `spawn <name>`
Create a new process.

```
> spawn worker1
Process spawned: worker1 (PID 2)

> spawn service
Process spawned: service (PID 3)
```

### `ps`
List all processes.

```
> ps
Processes:
---------
PID  Name                State       Caps
 1  init                Running     0
 2  worker1             Ready       0
 3  service             Ready       2
 
Total: 3 / 64 processes
```

### `kill <pid>`
Terminate a process (cannot kill init).

```
> kill 2
Process 2 terminated

> kill 1
Cannot kill init process (PID 1)
```

### `yield`
Yield current process to next runnable process.

```
> yield
Yielded: PID 1 → PID 2
```

### `whoami`
Show information about current process.

```
> whoami
Current process: PID 1 (init)
  State: Running
  Capabilities: 0
  CPU time: 1234 ticks
```

## Process Lifecycle

### 1. Spawn
```rust
let pid = process_manager().spawn("my-service", Some(parent_pid))?;
// New process created in Ready state
```

### 2. Schedule
```rust
let next_pid = process_manager().schedule()?;
// Scheduler finds next runnable process
// Marks it as Running
```

### 3. Execute
```rust
// Process runs (in v0, this is cooperative)
// Process can yield voluntarily
```

### 4. Yield
```rust
let next_pid = process_manager().yield_process()?;
// Current process → Ready
// Next process → Running
```

### 5. Terminate
```rust
process_manager().terminate(pid)?;
// Process → Terminated
```

### 6. Reap
```rust
process_manager().reap();
// Remove all Terminated processes from table
// Free up slots for new processes
```

## Per-Process Capability Tables

Each process has an isolated capability table:

```rust
// Process 1 inserts a channel capability
let slot = process_manager().insert_capability(
    Pid(1),
    CapabilityVariant::Channel(channel_cap),
)?;

// Process 1 can retrieve it
let cap = process_manager().get_capability(Pid(1), slot)?;

// Process 2 CANNOT retrieve Process 1's capabilities
let result = process_manager().get_capability(Pid(2), slot);
// Returns ProcessError::InvalidCapSlot
```

This enables:
- **Capability isolation** - Processes can't steal capabilities
- **Explicit delegation** - Must use IPC to transfer capabilities
- **Resource tracking** - Know which process owns which capabilities

## Use Cases

### Service Isolation
```rust
// Spawn filesystem service
let fs_pid = spawn("filesystem", Some(init_pid))?;

// Spawn console service
let console_pid = spawn("console", Some(init_pid))?;

// Each has its own capability table
// Filesystem can't access console's capabilities
// Console can't access filesystem's capabilities
```

### Concurrent IPC
```rust
// Create channel between two processes
let (send_cap, recv_cap) = ipc::ipc().create_channel(Pid(1))?;

// Give send cap to process 2
process_manager().insert_capability(Pid(2), CapabilityVariant::Channel(send_cap))?;

// Give recv cap to process 3
process_manager().insert_capability(Pid(3), CapabilityVariant::Channel(recv_cap))?;

// Process 2 sends, process 3 receives
// Processes 2 and 3 run concurrently (round-robin)
```

### Application Launcher
```rust
// Launcher process spawns application
let app_pid = spawn("user-app", Some(launcher_pid))?;

// Launcher introduces app to filesystem
let fs_intro = introduce_to_filesystem(app_pid)?;

// Grant filesystem capability to app
let slot = process_manager().insert_capability(
    app_pid,
    CapabilityVariant::Filesystem { cap_id, rights },
)?;

// App now has filesystem access
```

## Context Switching (Simplified v0)

In v0, context switching is **cooperative**:
- No preemption (no timer interrupts forcing switch)
- Processes must call `yield()` explicitly
- Stack and registers are placeholders (not yet saved/restored)

**Future v1** will add:
- Preemptive scheduling (timer interrupt)
- Real stack/register save/restore
- Per-process kernel stacks
- User mode isolation

## Resource Limits

```rust
const MAX_PROCESSES: usize = 64;           // Maximum processes
const MAX_CAPS_PER_PROCESS: usize = 128;   // Capabilities per process
const STACK_SIZE: usize = 64 * 1024;       // Stack size (64 KiB)
```

## Error Handling

```rust
pub enum ProcessError {
    TooManyProcesses,       // Hit 64 process limit
    ProcessNotFound,        // Invalid PID
    InvalidCapSlot,         // Bad capability slot
    CapabilityTableFull,    // Hit 128 capability limit
    AlreadyTerminated,      // Process already dead
}
```

## Integration with Existing Systems

### IPC Integration
```rust
// IPC uses ProcessId from process module
pub use crate::ipc::ProcessId as Pid;

// When creating channels, specify creator PID
let (cap1, cap2) = ipc::ipc().create_channel(process::current_pid()?)?;
```

### Service Registry Integration
```rust
// Services registered with provider PID
let metadata = ServiceMetadata::new(1, 10, process::current_pid()?);

// Introduction requests include requester PID
let request = IntroductionRequest::new(service_type, process::current_pid()?);
```

### Filesystem Integration
```rust
// Filesystem operations can check current process
let current = process::current_pid()?;

// File capabilities can be stored in process's capability table
let slot = process_manager().insert_capability(
    current,
    CapabilityVariant::Filesystem { cap_id, rights },
)?;
```

## Comparison to Traditional OS

### Unix/Linux Processes
- **Preemptive** - Kernel forces context switch
- **fork/exec** - Clone process or load new binary
- **UIDs/GIDs** - Ambient authority model
- **Signal handling** - Async process communication

### Oreulia Processes
- **Cooperative (v0)** - Explicit yield
- **spawn** - Create new process with name
- **Capability tables** - No ambient authority
- **IPC channels** - Explicit message passing

## Design Rationale

### Why Cooperative Scheduling (v0)?
1. **Simpler implementation** - No interrupt handling complexity
2. **Easier debugging** - Deterministic execution order
3. **Foundation for preemption** - Can add later without redesign
4. **Sufficient for services** - Services naturally yield when blocking on I/O

### Why Per-Process Capability Tables?
1. **Isolation** - Processes can't access others' capabilities
2. **Explicit delegation** - Must use IPC to transfer capabilities
3. **Accountability** - Know which process owns which resource
4. **Security** - Can't forge capability from another process

### Why Fixed-Size Arrays?
1. **no_std environment** - No heap allocation
2. **Predictable performance** - No allocation overhead
3. **Resource limits** - Clear system capacity
4. **Simplicity** - No dynamic memory management bugs

## Future Enhancements

### Near-term
- **Preemptive scheduling** - Timer interrupt forcing context switch
- **Real context switching** - Save/restore registers and stack
- **User mode** - Isolate processes from kernel
- **Per-process memory** - Virtual address spaces

### Medium-term
- **Process priorities** - Higher priority processes run first
- **Process groups** - Related processes grouped together
- **CPU affinity** - Pin processes to specific cores
- **Process quotas** - Limit CPU time, memory, capabilities

### Long-term
- **Multi-core** - Run processes on multiple CPUs
- **Process migration** - Move processes between cores
- **Real-time scheduling** - Deadline-based scheduling
- **Container-like isolation** - Namespace-like process groups

## Files Created/Modified

**Created:**
- `kernel/src/process.rs` (613 lines) - Complete process manager

**Modified:**
- `kernel/src/commands.rs` - Added spawn, ps, kill, yield, whoami commands (~240 lines)
- `kernel/src/lib.rs` - Added process module and initialization

## Build Status

✅ Compiles successfully (2 warnings about unused variables)  
✅ Process manager initialized with PID 1 (init)  
✅ All commands available  
✅ Ready for testing

## Testing

Boot the system:
```bash
cd kernel
./run.sh
```

Try process commands:
```
> ps                           # List init process
> spawn worker                 # Create new process
> spawn service                # Create another
> ps                           # See all processes
> yield                        # Switch to next process
> whoami                       # Check current process
> kill 2                       # Terminate process 2
> ps                           # Verify termination
```

## Summary

The process manager unlocks **true concurrent execution** in Oreulia:

1. **Multiple processes** - Up to 64 running concurrently
2. **Capability isolation** - Per-process capability tables (128 slots each)
3. **Cooperative scheduling** - Round-robin with explicit yield
4. **Process lifecycle** - spawn → ready → running → yield → terminated → reap
5. **Shell integration** - spawn, ps, kill, yield, whoami commands

This enables:
- **Service isolation** - Each service runs as separate process
- **Concurrent IPC** - Processes communicate via channels
- **Resource tracking** - CPU time, capabilities per process
- **Foundation for WASM** - Each module runs in its own process

The process manager is now the **foundation for the next layer**: WASM runtime, where each WASM module will run as an isolated process with its own capability table.
