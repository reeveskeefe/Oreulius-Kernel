# Kernel Size Optimization - February 1, 2026

## Problem
The kernel binary was **46MB** and the bootable ISO was **54MB**, causing GRUB to fail loading the kernel. The boot process would start, display the GRUB menu, attempt to boot "Oreulia OS", then loop back to GRUB.

## Root Cause
Three global static structures had massive inline-initialized arrays:

- `WASM_RUNTIME`: **10.7MB** (1MB linear memory + 256KB bytecode buffers)
- `FILESYSTEM`: **16.7MB** (256 files × 64KB each)
- `IPC`: **18.8MB** (128 channels × 32 messages × 4KB each)

These were being placed in the `.data` section at compile time, bloating the binary.

## Solution
Reduced buffer size constants dramatically for initial boot:

### Filesystem (`src/fs.rs`)
- `MAX_FILE_SIZE`: 64KB → **4KB** (94% reduction)
- `MAX_FILES`: 256 → **32** (88% reduction)

### IPC (`src/ipc.rs`)  
- `MAX_MESSAGE_SIZE`: 4KB → **512 bytes** (88% reduction)
- `CHANNEL_CAPACITY`: 32 → **4** (88% reduction)
- `MAX_CHANNELS`: 128 → **16** (88% reduction)

### WASM (`src/wasm.rs`)
- `MAX_MEMORY_SIZE`: 1MB → **64KB** (94% reduction)
- `MAX_MODULE_SIZE`: 256KB → **16KB** (94% reduction)

## Results
- **Kernel**: 46MB → **3.0MB** (93% reduction)
- **ISO**: 54MB → **11MB** (80% reduction)
- **Status**: Kernel now boots successfully in QEMU

## Notes
These values can be increased later once we implement:
1. Lazy initialization for large structures
2. Dynamic heap allocation instead of static arrays
3. On-demand paging for memory regions
4. More efficient data structures (e.g., B-trees instead of arrays)

For now, these reduced sizes are sufficient for v0 development and testing.
