# ABI Reference

Oreulius exposes a 143-function WASM host ABI across IDs `0–142`.

This page is the short entry point. Use the full runtime ABI document for the exhaustive function-by-function reference.

The frozen host dispatcher in [../kernel/src/execution/wasm.rs](../kernel/src/execution/wasm.rs) is the source of truth for host IDs, signatures, aliases, and result shapes.

## Primary References

- [runtime/oreulia-wasm-abi.md](runtime/oreulia-wasm-abi.md)
- [../wasm/README.md](../wasm/README.md)
- [../kernel/src/execution/wasm.rs](../kernel/src/execution/wasm.rs)

## ABI Shape

The ABI is grouped by responsibility:

| Group | ID Range | Purpose |
|---|---|---|
| Core I/O, IPC, network, services | `0–12` | logging, files, channels, DNS, HTTP, service calls |
| Temporal objects | `13–22` | snapshot, history, rollback, branch, merge |
| Threading and UI/input | `23–44` | cooperative threads, compositor, input |
| WASI Preview 1 compatibility | `45–90` | Fully implemented Oreulius-owned WASI Preview 1 compatibility surface |
| TLS session controls | `91–99` | Kernel TLS session lifecycle and error reporting |
| Process and advanced capability/runtime features | `100–142` | process ops, polyglot, observer, mesh, checkpoints, policy, entanglement, cap graph, lineage query, transition control, status query, event feed |

The main runtime ABI page now splits these responsibilities into family modes:

- temporal and policy are `status-first`
- observer is `event-first`
- cap graph is `query-and-verify`
- polyglot lineage is `snapshot/status/event`
- entanglement remains `query-first`

All dispatcher-owned WASI entries in `45–90` are implemented in the runtime.

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
