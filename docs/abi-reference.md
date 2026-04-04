# ABI Reference

Oreulius exposes a 132-function WASM host ABI across IDs `0–131`.

This page is the short entry point. Use the full runtime ABI document for the exhaustive function-by-function reference.

## Primary References

- [runtime/oreulius-wasm-abi.md](runtime/oreulius-wasm-abi.md)
- [../wasm/README.md](../wasm/README.md)
- [../kernel/src/execution/wasm.rs](../kernel/src/execution/wasm.rs)

## ABI Shape

The ABI is grouped by responsibility:

| Group | ID Range | Purpose |
|---|---|---|
| Core I/O, IPC, network, services | `0–12` | logging, files, channels, DNS, HTTP, service calls |
| Temporal objects | `13–22` | snapshot, history, rollback, branch, merge |
| Threading and UI/input | `23–44` | cooperative threads, compositor, input |
| WASI and TLS | `45–99` | WASI compatibility plus kernel TLS session controls |
| Process and advanced capability/runtime features | `100–131` | process ops, polyglot, observer, mesh, checkpoints, policy, entanglement, cap graph |

## SDK Mirror

The guest-side SDK mirrors the ABI through:

- `io`
- `fs`
- `ipc`
- `net`
- `temporal`
- `process`
- `thread`
- `observer`
- `policy`
- `mesh`
- `entangle`
- `capgraph`
- `polyglot`

See [../wasm/README.md](../wasm/README.md) for the guest-side view.
