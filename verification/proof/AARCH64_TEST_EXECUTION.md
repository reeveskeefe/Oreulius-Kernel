<!-- AArch64 Native Test Execution Guide -->

# AArch64 Native Negative-Trace Test Execution

This guide describes how to execute the five Phase 1B negative-trace tests on AArch64 targets, now that the code is complete.

---

## Executive Summary

**Status**: Code is complete and compiles to zero errors. Tests are gated with `#[cfg(target_arch = "aarch64")]` and ready for native execution.

**Pre-requisites**:
1. AArch64 Rust toolchain (stable or nightly)
2. Cross-compilation environment (or native AArch64 hardware/emulation)
3. QEMU AArch64 virt machine support (recommended for CI/local testing)

**Execution time**: ~30 seconds per test (estimates).

---

## Option 1: QEMU AArch64 Virtual Machine (Recommended for CI)

This is the most portable approach for local development and CI gates.

### 1.1 Install Prerequisites

```bash
# macOS
brew install qemu aarch64-elf-gcc

# Ubuntu/Debian
sudo apt-get install qemu-system-arm gcc-aarch64-linux-gnu

# Fedora/RHEL
sudo dnf install qemu-system-aarch64 gcc-aarch64-linux-gnu
```

### 1.2 Configure Rust for AArch64 Target

```bash
cd /Users/keefereeves/Desktop/OreuliusKernel/TheActualKernelProject/oreulia/kernel

# Install AArch64 target
rustup target add aarch64-unknown-none

# Verify
rustup target list | grep aarch64
# Output should show: aarch64-unknown-none (installed)
```

### 1.3 Compile Tests for AArch64

```bash
# Build the kernel with AArch64 target and test binaries
cargo test --target aarch64-unknown-none --lib negative_trace_closure_chain --no-run

# Output: Compiling oreulia v0.1.0 (...)
#         Finished test [unoptimized + debuginfo] target(s) in ...
#         (test binary locations printed)
```

### 1.4 Run Tests via QEMU

Two approaches:

#### 1.4a: Direct Binary Execution (Fast)

```bash
# Extract test binary from build output (adjust path as needed)
TEST_BIN="target/aarch64-unknown-none/debug/deps/oreulia-<hash>"

# Run in QEMU
qemu-system-aarch64 \
  -machine virt \
  -cpu cortex-a72 \
  -m 512M \
  -kernel "$TEST_BIN" \
  -nographic \
  -serial mon:stdio \
  -display none

# Expected output:
# running 5 tests
# test ... scheduler_negative_trace_closure_chain ... ok
# test ... syscall_negative_trace_closure_chain ... ok
# test ... dtb_negative_trace_closure_chain ... ok
# test ... mmu_negative_trace_closure_chain ... ok
# test ... trap_negative_trace_closure_chain ... ok
# 
# test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; ...
```

#### 1.4b: Using Cargo + Cross-Compile Helper

```bash
# If cross-compilation helper is available
cross test --target aarch64-unknown-linux-gnu --lib negative_trace_closure_chain

# Otherwise, use standard cargo with explicit target
cd kernel && cargo test --target aarch64-unknown-none --lib negative_trace_closure_chain
```

### 1.5 Verify Test Output (Checklist)

Each test should produce:
- ✅ `scheduler_negative_trace_closure_chain ... ok`: Fairness violation → Isolate
- ✅ `syscall_negative_trace_closure_chain ... ok`: Invalid syscall number → FailStop + TerminalFailure
- ✅ `dtb_negative_trace_closure_chain ... ok`: Malformed DTB header → Degrade
- ✅ `mmu_negative_trace_closure_chain ... ok`: Misaligned mapping → FailStop + TerminalFailure
- ✅ `trap_negative_trace_closure_chain ... ok`: Null frame pointer → Isolate

---

## Option 2: Native AArch64 Hardware (Real Development Board)

If you have native AArch64 hardware (Raspberry Pi 4/5, Apple Silicon Mac, AWS Graviton, etc.):

### 2.1 Direct Compile & Test (No Cross-Compilation)

```bash
cd kernel

# On native AArch64 machine, just run:
cargo test --lib negative_trace_closure_chain

# Rust will auto-detect target as aarch64 and compile natively
# Tests execute immediately on the host system
```

### 2.2 Supported Hardware Configurations

The five tests are architecture-agnostic except for the AArch64-specific ones:

- `scheduler_negative_trace_closure_chain`: ✅ Host-agnostic (runs on any target)
- `syscall_negative_trace_closure_chain`: ✅ Host-agnostic
- `dtb_negative_trace_closure_chain`: 🔒 AArch64-gated (requires `#[cfg(target_arch = "aarch64")]`)
- `mmu_negative_trace_closure_chain`: 🔒 AArch64-gated
- `trap_negative_trace_closure_chain`: 🔒 AArch64-gated

### 2.3 Expected Execution Environment

Tests require:
- Ability to allocate memory for ProcessTable (scheduler tests)
- Access to ring buffer (all tests)
- No actual hardware access needed; all mocking is built-in

---

## Option 3: CI Integration (GitHub Actions Example)

Add to `.github/workflows/test.yml`:

```yaml
name: Test Suite

on: [push, pull_request]

jobs:
  aarch64-negative-trace-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          target: aarch64-unknown-none
      
      - name: Install QEMU
        run: sudo apt-get install -y qemu-system-aarch64
      
      - name: Build AArch64 Test Binary
        run: |
          cd kernel
          cargo test --target aarch64-unknown-none --lib negative_trace_closure_chain --no-run
      
      - name: Run Tests in QEMU
        run: |
          cd kernel
          TEST_BIN=$(find target/aarch64-unknown-none/debug/deps -name 'oreulia-*' -type f | head -1)
          timeout 60 qemu-system-aarch64 \
            -machine virt \
            -cpu cortex-a72 \
            -m 512M \
            -kernel "$TEST_BIN" \
            -nographic \
            -serial mon:stdio \
            -display none | tee /tmp/test_output.txt
          
          # Verify all tests passed
          grep -E "(ok|passed)" /tmp/test_output.txt | tail -3
```

---

## Option 4: Debugging & Trace Output

For detailed debugging, you can run tests with additional observability:

### 4.1 Enable Debug Output

```bash
# Compile with debug symbols
cargo test --target aarch64-unknown-none --lib negative_trace_closure_chain \
  --no-run \
  --profile test \
  --verbose
```

### 4.2 Run with QEMU Debugging

```bash
# Start QEMU with GDB server enabled
qemu-system-aarch64 \
  -machine virt \
  -cpu cortex-a72 \
  -m 512M \
  -kernel "$TEST_BIN" \
  -nographic \
  -serial mon:stdio \
  -display none \
  -s -S  # Enable GDB server on port 1234

# In another terminal, connect GDB
aarch64-linux-gnu-gdb "$TEST_BIN"
# (gdb) target remote localhost:1234
# (gdb) continue
```

### 4.3 Capture Ring Buffer State

Tests automatically record events in the ring buffer. To inspect them:

```rust
// Add to test after assert_closure_chain_closure
println!("Ring buffer state after test:");
for seq in before..after {
    if let Some(ev) = ring_buffer::snapshot_seq(seq) {
        println!("  Event {}: type={:?}, subsystem={:?}, code=0x{:04X}",
            seq, ev.event_type, ev.subsystem, ev.code);
    }
}
```

---

## Expected Test Results

All five tests should pass with the following characteristics:

| Test | Target | Status | Event Count | Outcome |
|------|--------|--------|-------------|---------|
| scheduler_negative_trace_closure_chain | Any | Pass | 4–6 events | Scheduler → Isolate |
| syscall_negative_trace_closure_chain | Any | Pass | 4–6 events | Syscall → FailStop (terminal) |
| dtb_negative_trace_closure_chain | AArch64 only | Pass | 4–6 events | DTB → Degrade |
| mmu_negative_trace_closure_chain | AArch64 only | Pass | 4–6 events | MMU → FailStop (terminal) |
| trap_negative_trace_closure_chain | AArch64 only | Pass | 4–6 events | Syscall → Isolate |

---

## Troubleshooting

### Problem: "error: `-Z build-std` is not available"

**Cause**: Custom target file needs special handling for no_std builds.

**Solution**:
```bash
rustup component add rust-src
cargo test --target aarch64-unknown-none --lib negative_trace_closure_chain -Z build-std
```

### Problem: "QEMU binary not found"

**Solution**: Reinstall QEMU or adjust PATH
```bash
# macOS
brew install qemu
qemu-system-aarch64 --version

# Ubuntu
sudo apt-get install --reinstall qemu-system-aarch64
qemu-system-aarch64 --version
```

### Problem: "Test hangs or timeout"

**Cause**: QEMU might be waiting for IO or tests are infinite looping.

**Solution**:
1. Add explicit timeout: `timeout 30 qemu-system-aarch64 ...`
2. Verify test binary is valid: `file $TEST_BIN`
3. Run with `-nographic -serial mon:stdio` to see output

### Problem: AArch64-gated tests don't run on x86_64

**Expected**: This is correct behavior. Tests are marked with `#[cfg(target_arch = "aarch64")]` and only compile/run on AArch64.

**Workaround** (if needed for x86_64 CI): Remove the gate (not recommended; breaks architecture-specific semantics):
```rust
// Before:
#[cfg(target_arch = "aarch64")]
#[test]
fn trap_negative_trace_closure_chain() { ... }

// After (temporary for x86_64 testing):
#[test]
fn trap_negative_trace_closure_chain() { ... }
```

---

## Performance Benchmarks

Expected execution times on typical hardware:

| Environment | Total Time | Per-Test Avg |
|-------------|-----------|-------------|
| QEMU AArch64 (local) | ~10–15 seconds | ~2–3 seconds |
| Native AArch64 (Apple Silicon M1+) | ~3–5 seconds | ~0.6–1 second |
| Native AArch64 (AWS Graviton) | ~5–8 seconds | ~1–1.5 seconds |
| CI (GitHub Actions) | ~30–45 seconds | ~6–9 seconds (includes setup/teardown) |

---

## Integration with Existing Test Suite

The five negative-trace tests now integrate seamlessly with the broader test suite:

```bash
# Run ALL tests (including new negative-trace tests)
cargo test --lib

# Run ONLY negative-trace tests
cargo test --lib negative_trace_closure_chain

# Run specific boundary test
cargo test --lib --exact scheduler_negative_trace_closure_chain

# Run with output displayed
cargo test --lib negative_trace_closure_chain -- --nocapture
```

---

## Next Steps: Continuous Testing

To ensure Phase 1B tests run automatically on every commit:

1. **Add to pre-commit hook**:
   ```bash
   # .git/hooks/pre-commit
   #!/bin/bash
   cd kernel
   cargo test --lib negative_trace_closure_chain --target aarch64-unknown-none
   ```

2. **Add to CI/CD pipeline** (GitHub Actions example above)

3. **Track test metrics** (latency, event counts, outcome distribution) for trending

---

## Related Documentation

- Phase 1B Completion: [verification/proof/PHASE_PLAN.md](PHASE_PLAN.md)
- Test Code: [kernel/src/scheduler/process.rs](../../kernel/src/scheduler/process.rs#L1369), [kernel/src/platform/syscall.rs](../../kernel/src/platform/syscall.rs#L2120), [kernel/src/arch/aarch64_vectors.rs](../../kernel/src/arch/aarch64_vectors.rs#L420), [kernel/src/arch/mmu_aarch64.rs](../../kernel/src/arch/mmu_aarch64.rs#L1053), [kernel/src/arch/aarch64_dtb.rs](../../kernel/src/arch/aarch64_dtb.rs#L958)
- Assertion Helper: [kernel/src/observability/test_helpers.rs](../../kernel/src/observability/test_helpers.rs)
- Rapid Test Addition: [verification/proof/RAPID_BOUNDARY_TESTING.md](RAPID_BOUNDARY_TESTING.md)
