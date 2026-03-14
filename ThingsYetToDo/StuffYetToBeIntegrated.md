# Stuff Yet To Be Integrated

**Purpose**
This document tracks code that exists in the repository but is not currently integrated into the kernel build or runtime. It is intended as a focused checklist for future integration work.

**Scope**
- Files that exist but are not compiled/linked into the kernel.
- Experimental or backup artifacts that are present but unused.
- Kernel modules that are present but not wired into `lib.rs` or the build system.

---

## A) Rust Modules Not Compiled Into the Kernel
These files exist under `kernel/src/` but are not included in `kernel/src/lib.rs`, and therefore are not built into the kernel library.

- `kernel/src/interrupts.rs`
- `kernel/src/qemu.rs`
- `kernel/src/timer.rs`
- `kernel/src/main.rs` (autobins = false in `kernel/Cargo.toml`)

**Planned actions**
- Decide whether to integrate these into `lib.rs` or move them to a dedicated `experiments/` or `tests/` folder.
- For `main.rs`, decide whether to enable a binary target or remove it.

---

## B) Assembly / Test Artifacts Not Linked Into the Kernel
These files were never assembled/linked by `kernel/build.sh` and have now been
archived out of the active kernel root.

- `kernel/archive/boot-experiments/simpleboot.asm`
- `kernel/archive/boot-experiments/test-minimal.asm`
- `kernel/src/asm/context_switch.asm.bak`

**Planned actions**
- Decide whether the archived boot experiments should stay as historical
  references or be removed entirely later.
- If needed, add them to the build pipeline with explicit targets.

---

## C) General Integration Notes
- `kernel/build.sh` currently assembles and links all `.asm` files under `kernel/src/asm/` (the live set is fully integrated).
- All Rust modules listed in `kernel/src/lib.rs` are compiled into the kernel static library.

---

## D) Integration Checklist
- [ ] Confirm whether `interrupts.rs` should replace or merge with existing IDT/PIC logic.
- [ ] Determine if `timer.rs` is superseded by `pit.rs` and scheduler timer logic.
- [ ] Decide the role of `qemu.rs` (debug utilities vs. production code).
- [ ] Decide whether `main.rs` should become a binary entrypoint or be removed.
- [x] Archive `simpleboot.asm` and `test-minimal.asm` under `kernel/archive/boot-experiments/`.
- [ ] Clean up `context_switch.asm.bak` or move to `archive/`.
