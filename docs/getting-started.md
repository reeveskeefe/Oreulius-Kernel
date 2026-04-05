# Getting Started

This is the shortest recommended path from clone to a successful first run.

## Recommended First Target

Start with `i686`.

Reasons:

- it is the most complete runtime-rich path
- it has the least onboarding friction
- it exposes the shell surface used by the simplest demos and most direct bring-up flows

## Prerequisites

```bash
rustup toolchain install nightly-2023-11-01
rustup component add rust-src --toolchain nightly-2023-11-01
```

macOS example:

```bash
brew install nasm qemu xorriso grub
```

## Clone And Build

```bash
git clone https://github.com/reeveskeefe/Oreulius-Kernel.git
cd Oreulius-Kernel/kernel
./build.sh
```

## Boot

```bash
./run.sh
```

If you want a serial-first path:

```bash
qemu-system-i386 -cdrom oreulius.iso -serial stdio
```

## First Commands

Run these in the shell:

```text
help
cap-test-atten
temporal-write /tmp/demo alpha
temporal-snapshot /tmp/demo
temporal-history /tmp/demo
```

`/tmp` exists by default in a fresh boot, so the temporal demo path is ready immediately.

## Where To Go Next

- [First Demo](first-demo.md)
- [Architecture Overview](architecture-overview.md)
- [Verification Overview](verification-overview.md)
- [ABI Reference](abi-reference.md)
