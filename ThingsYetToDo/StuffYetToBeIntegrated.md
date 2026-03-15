# Stuff Yet To Be Integrated

**Purpose**
This document tracks code that existed in the repository but was not integrated into the kernel build or runtime at the time it was first written. All items have now been resolved.

**Scope**
- Files that exist but are not compiled/linked into the kernel.
- Experimental or backup artifacts that are present but unused.
- Kernel modules that are present but not wired into `lib.rs` or the build system.

---

## A) Rust Modules Not Compiled Into the Kernel

These files were previously listed as unintegrated. They have since been removed from the repository — their functionality was either absorbed into existing modules or determined to be unnecessary.

- ~~`kernel/src/interrupts.rs`~~ — **Resolved**: IDT/PIC logic is fully handled by `kernel/src/arch/x86_64/idt.rs` and `kernel/src/arch/x86_64/pic.rs`. The standalone file was deleted.
- ~~`kernel/src/qemu.rs`~~ — **Resolved**: QEMU debug output is handled via the VGA driver and `qemu_exit` crate integration in `kernel/src/platform/`. Standalone file removed.
- ~~`kernel/src/timer.rs`~~ — **Resolved**: Timer logic is fully managed by `kernel/src/quantum_scheduler.rs` and `kernel/src/arch/x86_64/pit.rs`. Standalone file removed.
- ~~`kernel/src/main.rs`~~ — **Resolved**: `autobins = false` is set in `kernel/Cargo.toml`; the kernel has no standalone binary target. File removed.

---

## B) Assembly / Test Artifacts Not Linked Into the Kernel

- ~~`kernel/archive/boot-experiments/simpleboot.asm`~~ — **Resolved**: Archived as historical reference. No build integration needed.
- ~~`kernel/archive/boot-experiments/test-minimal.asm`~~ — **Resolved**: Archived as historical reference. No build integration needed.
- ~~`kernel/src/asm/context_switch.asm.bak`~~ — **Resolved**: Backup file cleaned up. Live context-switch logic is in `kernel/src/asm/context_switch.asm`.

---

## C) General Integration Notes

- `kernel/build.sh` assembles and links all `.asm` files under `kernel/src/asm/` (the live set is fully integrated).
- All Rust modules listed in `kernel/src/lib.rs` are compiled into the kernel static library.
- No orphaned or unintegrated modules remain as of this writing.

---

## D) Integration Checklist

- [x] Confirm whether `interrupts.rs` should replace or merge with existing IDT/PIC logic. → **Resolved**: removed; existing arch modules are canonical.
- [x] Determine if `timer.rs` is superseded by `pit.rs` and scheduler timer logic. → **Resolved**: yes, superseded and removed.
- [x] Decide the role of `qemu.rs` (debug utilities vs. production code). → **Resolved**: removed; platform layer handles debug I/O.
- [x] Decide whether `main.rs` should become a binary entrypoint or be removed. → **Resolved**: removed; kernel is a library crate.
- [x] Archive `simpleboot.asm` and `test-minimal.asm` under `kernel/archive/boot-experiments/`.
- [x] Clean up `context_switch.asm.bak` or move to `archive/`. → **Resolved**: deleted.
