# Oreulia Kernel — Release Checklist

> **Purpose:** Every item in this checklist MUST be confirmed before a release tag is pushed.  
> CI enforcement is supplemental — human sign-off is required for items marked 🔐.

---

## 1 · Pre-Release CI Gates

| Gate | Command / Job | Must pass on |
|------|--------------|-------------|
| `cargo check` i686 | `cargo check --target i686-oreulia` | i686 builds |
| `cargo check` x86_64 | `cargo check --target x86_64-unknown-none` | x86_64 builds |
| `cargo check` AArch64 | `cargo check --target aarch64-unknown-none` | AArch64 builds |
| Smoke x86_64 | `kernel/ci/smoke-x86_64.sh` | every release |
| Smoke AArch64 | `kernel/ci/smoke-aarch64.sh` | every release |
| Extended all arches | `kernel/ci/extended-all.sh` | every major/minor release |
| Formal verification | `kernel/formal-verify.sh` | every release |
| Fuzz corpus | `cargo fuzz run --jobs 4 (5 min min)` | every release |

- [ ] All CI gates green on **main** branch at tagged commit

---

## 2 · Parity Matrix Review

- [ ] `verification/parity-matrix.json` is up to date with all subsystem changes in this release
- [ ] No subsystem is newly marked `true` without a corresponding CI gate passing (see §1)
- [ ] Any `partial` entry has an open tracking issue or `ThingsYetToDo/` note

---

## 3 · Security & Capabilities

🔐 **Requires security lead sign-off**

- [ ] `capability/mod.rs` — no new `CapabilityType` variants without formal specification doc in `docs/`
- [ ] Any new `check_capability` call site reviewed for correct `Rights` mask (not `ALL` in production paths)
- [ ] No `unsafe` blocks added without a safety comment (`// SAFETY: ...`)
- [ ] Crash telemetry (`crash_log.rs`) does not leak PII through `CrashClass` metadata
- [ ] CapNet intent-graph revocation paths exercised by at least one integration test

---

## 4 · Multi-Arch Validation

- [ ] Driver capability table in `kernel/README.md` matches `parity-matrix.json`
- [ ] AArch64 SPSR_EL1 context-switch test passes under QEMU virt (`run-aarch64-virt-image.sh`)
- [ ] ELF64 loader test (AArch64 + x86_64 static binary) passes
- [ ] WASM JIT extended opcodes test: narrow loads/stores, i64 arithmetic, `call_indirect` (`capnet_test.rs` or dedicated test)
- [ ] `blk-bench` command produces non-zero throughput on virtio-blk device in QEMU

---

## 5 · Documentation

- [ ] `kernel/README.md` Driver Capability Matrix reflects current driver status
- [ ] `CHANGELOG.md` (or equivalent) entry written for this release
- [ ] Any new shell commands documented in `docs/` or `kernel/README.md`
- [ ] API-breaking changes in `wasm_jit.rs` opcode dispatch noted in changelog

---

## 6 · Versioning

- [ ] `kernel/Cargo.toml` `version` field bumped per semver (MAJOR.MINOR.PATCH)
  - MAJOR: ABI-breaking changes to IPC, capability, or WASM bytecode handling
  - MINOR: new subsystem features, new drivers, new opcodes
  - PATCH: bug fixes, documentation, build system changes
- [ ] Git tag format: `v<MAJOR>.<MINOR>.<PATCH>` (e.g. `v0.4.0`)
- [ ] Tag is signed: `git tag -s v0.4.0 -m "Release v0.4.0"`

---

## 7 · Final Steps

- [ ] `git log --oneline origin/main..HEAD` — no stray WIP commits
- [ ] `verification/parity-matrix.json` committed and included in the release commit
- [ ] Release notes posted (GitHub Release, or equivalent)
- [ ] 🔐 Sign-off from at least one additional maintainer for MAJOR releases

---

*This checklist is enforced by convention. For automated enforcement, pipe through `kernel/ci/extended-all.sh` in your release workflow.*
