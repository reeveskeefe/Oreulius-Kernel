# Oreulius Kernel Project Guide

## 1. Project Overview

Oreulius is a kernel designed to run isolated WASI workloads in a secure operating environment. It makes authority explicit and controls access through capabilities, enabling tight control and easy inspection of workload behavior.

**Key Technologies:**
- Rust (primary development language)
- WebAssembly (WASI) for workload execution
- QEMU for virtualization
- Multiboot2 for booting
- GRUB for bootloader configuration

**High-level Architecture:**
1. **Bootloader:** Supports i686 (legacy), x86_64 (Multiboot2), and AArch64 architectures
2. **Kernel Core:** Manages processes, memory, and capabilities
3. **WASI Runtime:** Executes WebAssembly workloads in isolated environments
4. **Capability System:** Controls resource access through explicit capabilities
5. **Filesystem:** Supports ISO-based filesystems for workload deployment

## 2. Getting Started

### Prerequisites
- Rust toolchain (nightly-2024-01-01)
- QEMU
- NASM
- xorriso
- GRUB

### Installation
```bash
# macOS
brew update
brew install qemu llvm binutils coreutils nasm xorriso grub

# Ubuntu/Debian
sudo apt update
sudo apt install -y qemu qemu-system-x86 qemu-system-aarch64 \
  gcc-aarch64-linux-gnu gcc-multilib binutils-aarch64-linux-gnu \
  llvm lld clang build-essential nasm xorriso grub-pc-bin

# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
rustup toolchain install nightly-2024-01-01
rustup component add rust-src --toolchain nightly-2024-01-01
rustup target add aarch64-unknown-none x86_64-unknown-none i686-unknown-none --toolchain nightly-2024-01-01
```

### Running the Kernel
```bash
# i686 architecture
cd kernel
./build.sh
./run.sh

# x86_64 architecture
cd kernel
./build-x86_64-mb2-iso.sh
./run-x86_64-mb2-grub.sh

# AArch64 architecture
cd kernel
./build-aarch64-virt.sh
./run-aarch64-virt-image.sh
```

### Running Tests
```bash
cd kernel
./test-boot.sh      # Basic boot test
./test-services.sh   # Service functionality test
./test-filesystem.sh # Filesystem operations test
```

## 3. Project Structure

```
oreulia/
├── .continue/          # Continue configuration
│   └── rules/          # Project documentation
├── .github/            # CI/CD workflows
├── .vscode/            # IDE configuration
├── ci/                 # Continuous integration scripts
├── cryptography-tests-backend/ # Cryptographic tests
├── docker/             # Container configurations
├── docs/               # Documentation
├── kernel/             # Kernel source code
│   ├── src/            # Rust source files
│   ├── build-*.sh      # Architecture-specific build scripts
│   ├── run-*.sh        # Architecture-specific run scripts
│   └── test-*.sh       # Test scripts
├── kernel-artifacts/   # Build outputs
├── services/           # Kernel services
├── target/             # Compilation artifacts
├── verification/       # Formal verification
└── wasm/               # WASM workload examples and SDK
    └── sdk/           # Rust SDK for WASM development
```

**Key Files:**
- `kernel/Cargo.toml`: Rust dependencies
- `kernel/src/`: Core kernel implementation
- `kernel/linker-*.ld`: Architecture-specific linker scripts
- `wasm/sdk/`: Guest application development SDK
- `kernel/grub.cfg`: GRUB boot configuration template

## 4. Development Workflow

### Coding Standards
- Follow Rust formatting with `cargo fmt`
- Use `#![deny(warnings)]` to treat warnings as errors
- Document public APIs with Rustdoc comments
- Prefer explicit capabilities over global state

### Testing Approach
1. Unit tests for core functionality
2. Integration tests using QEMU
3. Formal verification for critical components
4. Fuzz testing for security-critical modules

### Build and Deployment
1. Build architecture-specific kernel image
2. Package with WASM workloads into ISO
3. Test in QEMU
4. Deploy to production using virtualization or bare metal

### Contribution Guidelines
1. Fork the repository
2. Create feature branches
3. Submit pull requests with detailed descriptions
4. Include tests for new functionality

## 5. Key Concepts

### Capability-Based Security
- All resource access requires explicit capabilities
- Capabilities are unforgeable tokens
- Fine-grained control over permissions

### WASI Workloads
- WebAssembly System Interface standard
- Isolated execution environments
- Cross-platform compatibility

### Temporal Replay
- Record/replay functionality for debugging
- Enables deterministic execution

### CapNet
- Peer-to-peer capability network
- Secure communication between workloads

## 6. Common Tasks

### Running a WASM Workload
```bash
# Build WASM workload
cd wasm
./build.sh your_workload.wat

# Build kernel with workload
cd kernel
./build-x86_64-full.sh

# Create ISO with kernel and workload
mkdir -p target/x86_64-mb2/iso/boot/grub target/x86_64-mb2/iso/wasm
cp target/x86_64-mb2/oreulius-kernel-x86_64 target/x86_64-mb2/iso/boot/oreulius-kernel-x86_64
cp wasm/your_workload.wasm target/x86_64-mb2/iso/wasm/

# Generate GRUB config
cat > target/x86_64-mb2/iso/boot/grub/grub.cfg <<'EOF'
set timeout=0
set default=0
terminal_output console

menuentry "Oreulius x86_64 MB2" {
    multiboot2 /boot/oreulius-kernel-x86_64
    boot
}
EOF

# Create ISO
grub-mkrescue -o target/x86_64-mb2/oreulius-x86_64-mb2.iso target/x86_64-mb2/iso

# Run in QEMU
./run-x86_64-mb2-grub.sh

# Inside kernel, execute workload
wasm /wasm/your_workload.wasm
```

### Developing a New WASM Application
```bash
cd wasm/sdk
cargo new my_app
cd my_app

# Edit src/main.rs
cargo build --target wasm32-wasi --release

# Copy to kernel ISO
cp target/wasm32-wasi/release/my_app.wasm ../kernel/target/x86_64-mb2/iso/wasm/
```

### Adding a New Kernel Feature
1. Create feature branch
2. Implement in `kernel/src/`
3. Add tests in `kernel/tests/`
4. Update documentation
5. Submit pull request

## 7. Troubleshooting

**Issue:** Kernel fails to boot
- **Solution:** Verify bootloader configuration in `grub.cfg`
- Check architecture compatibility
- Ensure required dependencies are installed

**Issue:** WASM workload not executing
- **Solution:** Verify WASM file is included in ISO
- Check file path in kernel command
- Ensure WASM file is properly compiled

**Issue:** Capability errors
- **Solution:** Verify required capabilities are granted
- Check capability propagation in workload

**Issue:** Build failures
- **Solution:** Ensure correct Rust toolchain version
- Run `rustup update`
- Check `rust-toolchain` file in kernel directory

## 8. References

- [Official Documentation](https://www.oreulius.com/docs)
- [WebAssembly Specification](https://webassembly.org/)
- [WASI Documentation](https://wasi.dev/)
- [Rust Embedded Book](https://docs.rust-embedded.org/)
- [Multiboot Specification](https://www.gnu.org/software/grub/manual/multiboot/multiboot.html)

---

**Note:** This document provides a high-level overview. For detailed implementation, refer to source code comments and architecture-specific documentation in the `docs/` directory.

To keep this guide up-to-date:
1. Review after significant architectural changes
2. Update when adding new features
3. Verify installation instructions with each release

Create additional `rules.md` files in subdirectories for component-specific documentation.