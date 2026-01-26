# Oreulia

Oreulia is an experimental operating system concept focused on:

- capability-based security (no ambient authority)
- dataflow + message passing
- Wasm-native execution
- persistence-first design
- deterministic/replayable execution modes

Start here: `docs/oreulia-vision.md`

## Building

See `kernel/README.md` for kernel build instructions.

Docs:

- `docs/oreulia-mvp.md` — QEMU-first MVP spec
- `docs/oreulia-capabilities.md` — capability/authority model
- `docs/oreulia-ipc.md` — IPC + dataflow channels
- `docs/oreulia-persistence.md` — logs/snapshots/recovery
- `docs/oreulia-filesystem.md` — filesystem service v0
- `docs/oreulia-wasm-abi.md` — Wasm host ABI v0

## boot Commmand
```cd /Users/keefereeves/Desktop/oreulia/kernel
./build.sh
qemu-system-i386 -cdrom oreulia.iso```

