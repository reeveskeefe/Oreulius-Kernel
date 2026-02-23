# Code <-> Model Traceability

Correspondence obligations:

- CO-SYNTAX-001: TODO
- CO-SEM-001: TODO
- CO-BOUNDARY-001: TODO

Per-subsystem mapping:
- Capability: kernel/src/capability.rs -> spec/capability.*
- Temporal: kernel/src/temporal.rs -> spec/temporal.*
- CapNet: kernel/src/capnet.rs -> spec/capnet.*
- JIT: kernel/src/wasm_jit.rs -> spec/jit.*
- Privilege transitions: kernel/src/asm/*.asm, kernel/src/syscall.rs -> spec/priv.*
