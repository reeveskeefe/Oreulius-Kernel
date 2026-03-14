Archived kernel source files kept for reference only.

- `interrupts.rs`: superseded by `arch/x86_64_runtime.rs` trap and interrupt initialization.
- `timer.rs`: superseded by `pit.rs` on x86 and generic timer support in `arch/aarch64_virt.rs`.
- `qemu.rs`: standalone debug artifact, not integrated into the current library build.
- `main.rs`: dead binary entrypoint; `autobins = false` excludes it from the build.

Files in this directory are intentionally not declared from `lib.rs`.
