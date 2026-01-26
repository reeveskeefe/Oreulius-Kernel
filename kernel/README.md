# Oreulia Kernel

Minimal Rust kernel for Oreulia OS.

## Building

```bash
cd kernel
cargo build --target x86_64-unknown-none
```

## Running in QEMU

The kernel is a placeholder. Full UEFI boot with bootloader coming.

For now, build succeeds, but QEMU requires proper ELF format.

Next: Integrate bootloader crate for UEFI boot.